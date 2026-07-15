package forwardproxy

import (
	"bytes"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestRelayCopyPaddingRoundTrip(t *testing.T) {
	input := make([]byte, 600*1024)
	for i := range input {
		input[i] = byte(i)
	}

	var encoded bytes.Buffer
	if _, err := relayCopy(&encoded, bytes.NewReader(input), AddPadding); err != nil {
		t.Fatalf("add padding: %v", err)
	}
	if encoded.Len() <= len(input) {
		t.Fatalf("encoded length = %d, want more than input length %d", encoded.Len(), len(input))
	}

	var decoded bytes.Buffer
	written, err := relayCopy(&decoded, bytes.NewReader(encoded.Bytes()), RemovePadding)
	if err != nil {
		t.Fatalf("remove padding: %v", err)
	}
	if written != int64(len(input)) {
		t.Fatalf("decoded bytes written = %d, want %d", written, len(input))
	}
	if !bytes.Equal(decoded.Bytes(), input) {
		t.Fatal("decoded stream differs from input")
	}
}

func TestRelayCopyRejectsTruncatedPadding(t *testing.T) {
	tests := []struct {
		name   string
		stream []byte
	}{
		{name: "header", stream: []byte{0}},
		{name: "payload", stream: append([]byte{0, 3, 0}, "ab"...)},
		{name: "padding", stream: append([]byte{0, 2, 3}, []byte{'a', 'b', 0}...)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var dst bytes.Buffer
			_, err := relayCopy(&dst, bytes.NewReader(tt.stream), RemovePadding)
			if !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("relayCopy() error = %v, want io.ErrUnexpectedEOF", err)
			}
			if dst.Len() != 0 {
				t.Fatalf("forwarded %d bytes from a truncated record", dst.Len())
			}
		})
	}
}

func TestRelayCopyFlushesHTTPStream(t *testing.T) {
	dst := newFlushCountingWriter()
	src := &chunkReader{chunks: [][]byte{[]byte("first"), []byte("second"), []byte("third")}}

	written, err := relayCopy(dst, src, NoPadding)
	if err != nil {
		t.Fatal(err)
	}
	if written != int64(len("firstsecondthird")) {
		t.Fatalf("written = %d", written)
	}
	if dst.flushes != 3 {
		t.Fatalf("flushes = %d, want 3", dst.flushes)
	}
	if got := dst.String(); got != "firstsecondthird" {
		t.Fatalf("output = %q", got)
	}
}

func TestRelayCopyRawTCP(t *testing.T) {
	sourceListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer sourceListener.Close()
	destinationListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer destinationListener.Close()

	sourceClient, err := net.Dial("tcp", sourceListener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer sourceClient.Close()
	sourceRelay, err := sourceListener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer sourceRelay.Close()

	destinationRelay, err := net.Dial("tcp", destinationListener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer destinationRelay.Close()
	destinationClient, err := destinationListener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer destinationClient.Close()
	deadline := time.Now().Add(5 * time.Second)
	for _, conn := range []net.Conn{sourceClient, sourceRelay, destinationRelay, destinationClient} {
		if err := conn.SetDeadline(deadline); err != nil {
			t.Fatal(err)
		}
	}

	payload := bytes.Repeat([]byte("raw-tcp-relay"), 8192)
	writeDone := make(chan error, 1)
	go func() {
		_, writeErr := sourceClient.Write(payload)
		if writeErr == nil {
			writeErr = sourceClient.(*net.TCPConn).CloseWrite()
		}
		writeDone <- writeErr
	}()

	copyDone := make(chan error, 1)
	go func() {
		_, copyErr := relayCopy(destinationRelay, sourceRelay, NoPadding)
		if copyErr == nil {
			copyErr = destinationRelay.(*net.TCPConn).CloseWrite()
		}
		copyDone <- copyErr
	}()

	got, err := io.ReadAll(destinationClient)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	if err := <-copyDone; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("relayed %d bytes, want %d", len(got), len(payload))
	}
}

func TestDualStreamPreservesCleanHalfClose(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	target, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	if err := target.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}

	backendDone := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			backendDone <- acceptErr
			return
		}
		defer conn.Close()
		if deadlineErr := conn.SetDeadline(time.Now().Add(5 * time.Second)); deadlineErr != nil {
			backendDone <- deadlineErr
			return
		}
		request, readErr := io.ReadAll(conn)
		if readErr != nil {
			backendDone <- readErr
			return
		}
		if string(request) != "request" {
			backendDone <- errors.New("unexpected request")
			return
		}
		_, writeErr := conn.Write([]byte("response"))
		backendDone <- writeErr
	}()

	var response bytes.Buffer
	if err := dualStream(target, io.NopCloser(bytes.NewReader([]byte("request"))), &response, false); err != nil {
		t.Fatalf("dualStream: %v", err)
	}
	if err := <-backendDone; err != nil {
		t.Fatalf("backend: %v", err)
	}
	if got := response.String(); got != "response" {
		t.Fatalf("response = %q", got)
	}
}

func TestDualStreamReturnsUploadError(t *testing.T) {
	target, peer := net.Pipe()
	defer peer.Close()
	deadline := time.Now().Add(5 * time.Second)
	if err := target.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if err := peer.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}

	wantErr := errors.New("upload failed")
	err := dualStream(target, errorReadCloser{err: wantErr}, io.Discard, false)
	if !errors.Is(err, wantErr) {
		t.Fatalf("dualStream() error = %v, want %v", err, wantErr)
	}
}

func BenchmarkRelayCopyUnpadded(b *testing.B) {
	payload := make([]byte, 1024*1024)
	var src bytes.Reader
	// Warm the pool so the benchmark measures steady-state relay behavior.
	src.Reset(payload)
	if _, err := relayCopy(io.Discard, &src, NoPadding); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for range b.N {
		src.Reset(payload)
		if _, err := relayCopy(io.Discard, &src, NoPadding); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRelayCopyAddPadding(b *testing.B) {
	payload := make([]byte, 1024*1024)
	var src bytes.Reader
	src.Reset(payload)
	if _, err := relayCopy(io.Discard, &src, AddPadding); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for range b.N {
		src.Reset(payload)
		if _, err := relayCopy(io.Discard, &src, AddPadding); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRelayCopyRemovePadding(b *testing.B) {
	payload := make([]byte, 1024*1024)
	var encoded bytes.Buffer
	if _, err := relayCopy(&encoded, bytes.NewReader(payload), AddPadding); err != nil {
		b.Fatal(err)
	}
	encodedBytes := encoded.Bytes()
	var src bytes.Reader
	src.Reset(encodedBytes)
	if _, err := relayCopy(io.Discard, &src, RemovePadding); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for range b.N {
		src.Reset(encodedBytes)
		if _, err := relayCopy(io.Discard, &src, RemovePadding); err != nil {
			b.Fatal(err)
		}
	}
}

type chunkReader struct {
	chunks [][]byte
}

func (r *chunkReader) Read(p []byte) (int, error) {
	if len(r.chunks) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.chunks[0])
	r.chunks = r.chunks[1:]
	return n, nil
}

type flushCountingWriter struct {
	bytes.Buffer
	header  http.Header
	flushes int
}

func newFlushCountingWriter() *flushCountingWriter {
	return &flushCountingWriter{header: make(http.Header)}
}

func (w *flushCountingWriter) Header() http.Header { return w.header }
func (w *flushCountingWriter) WriteHeader(int)     {}
func (w *flushCountingWriter) Flush()              { w.flushes++ }

type errorReadCloser struct {
	err error
}

func (r errorReadCloser) Read([]byte) (int, error) { return 0, r.err }
func (errorReadCloser) Close() error               { return nil }
