package forwardproxy

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"golang.org/x/net/http2"
)

func TestQUICVarintRoundTrip(t *testing.T) {
	values := []uint64{0, 63, 64, 16383, 16384, 1<<30 - 1, 1 << 30, 1<<62 - 1}
	for _, value := range values {
		encoded := appendQUICVarint(nil, value)
		got, err := readQUICVarint(bytes.NewReader(encoded))
		if err != nil {
			t.Fatalf("readQUICVarint(%d): %v", value, err)
		}
		if got != value {
			t.Errorf("readQUICVarint(%d) = %d", value, got)
		}
	}
}

func TestConnectProtocol(t *testing.T) {
	h2 := &http.Request{Proto: "HTTP/2.0", ProtoMajor: 2, Header: http.Header{":protocol": {"connect-udp"}}}
	if got := connectProtocol(h2); got != connectUDPProtocol {
		t.Fatalf("HTTP/2 protocol = %q", got)
	}
	h3 := &http.Request{Proto: "connect-udp", ProtoMajor: 3, Header: make(http.Header)}
	if got := connectProtocol(h3); got != connectUDPProtocol {
		t.Fatalf("HTTP/3 protocol = %q", got)
	}
}

func TestExtendedConnectEnabledByDefault(t *testing.T) {
	t.Cleanup(func() { setHTTP2ExtendedConnectEnabled(true) })

	if http2DisableExtendedConnectProtocol {
		t.Fatal("HTTP/2 Extended CONNECT is disabled by default")
	}
}

func TestHTTP2ExtendedConnectSetting(t *testing.T) {
	for _, tt := range []struct {
		name    string
		enabled bool
	}{
		{name: "advertised", enabled: true},
		{name: "hidden", enabled: false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			setHTTP2ExtendedConnectEnabled(tt.enabled)
			t.Cleanup(func() { setHTTP2ExtendedConnectEnabled(true) })

			serverConn, clientConn := net.Pipe()
			defer clientConn.Close()
			go (&http2.Server{}).ServeConn(serverConn, &http2.ServeConnOpts{
				Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
			})

			frame, err := http2.NewFramer(clientConn, clientConn).ReadFrame()
			if err != nil {
				t.Fatalf("read initial HTTP/2 frame: %v", err)
			}
			settings, ok := frame.(*http2.SettingsFrame)
			if !ok {
				t.Fatalf("initial HTTP/2 frame is %T, want SETTINGS", frame)
			}
			advertised := false
			if err := settings.ForeachSetting(func(setting http2.Setting) error {
				if setting.ID == http2.SettingEnableConnectProtocol && setting.Val == 1 {
					advertised = true
				}
				return nil
			}); err != nil {
				t.Fatalf("read HTTP/2 settings: %v", err)
			}
			if advertised != tt.enabled {
				t.Fatalf("SETTINGS_ENABLE_CONNECT_PROTOCOL advertised = %t, want %t", advertised, tt.enabled)
			}
		})
	}
}

func TestHTTP2ExtendedConnectReachesHandler(t *testing.T) {
	setHTTP2ExtendedConnectEnabled(true)
	t.Cleanup(func() { setHTTP2ExtendedConnectEnabled(true) })

	type requestResult struct {
		request *http.Request
		target  string
		err     error
	}
	requestSeen := make(chan requestResult, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target, err := connectUDPTarget(r)
		requestSeen <- requestResult{request: r, target: target, err: err}
		w.WriteHeader(http.StatusNoContent)
	}))
	if err := http2.ConfigureServer(server.Config, &http2.Server{}); err != nil {
		t.Fatalf("configure HTTP/2 server: %v", err)
	}
	server.TLS = server.Config.TLSConfig
	server.StartTLS()
	defer server.Close()

	transport := &http2.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec
	defer transport.CloseIdleConnections()
	request, err := http.NewRequest(http.MethodConnect, server.URL+"/.well-known/masque/udp/example.com/443/", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set(":protocol", connectUDPProtocol)
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatalf("send HTTP/2 Extended CONNECT: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("response status = %d, want %d", response.StatusCode, http.StatusNoContent)
	}

	select {
	case result := <-requestSeen:
		if result.err != nil {
			t.Fatalf("parse HTTP/2 CONNECT-UDP target: %v", result.err)
		}
		if result.target != "example.com:443" {
			t.Fatalf("CONNECT-UDP target = %q, want %q", result.target, "example.com:443")
		}
		got := result.request
		if protocol := got.Header.Get(":protocol"); protocol != connectUDPProtocol {
			t.Fatalf("handler protocol = %q, want %q", protocol, connectUDPProtocol)
		}
	case <-time.After(time.Second):
		t.Fatal("Extended CONNECT did not reach the HTTP handler")
	}
}

func TestHideExtendedConnectSettingCaddyfile(t *testing.T) {
	var h Handler
	d := caddyfile.NewTestDispenser(`forward_proxy {
		hide_extended_connect_setting
	}`)
	if err := h.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("unmarshal Caddyfile: %v", err)
	}
	if !h.HideExtendedConnectSetting {
		t.Fatal("hide_extended_connect_setting was not set")
	}
}

func TestHideExtendedConnectSettingLifecycle(t *testing.T) {
	setHTTP2ExtendedConnectEnabled(true)
	t.Cleanup(func() { setHTTP2ExtendedConnectEnabled(true) })

	first := &Handler{HideExtendedConnectSetting: true}
	second := &Handler{HideExtendedConnectSetting: true}
	first.registerHiddenExtendedConnectSetting()
	second.registerHiddenExtendedConnectSetting()
	t.Cleanup(first.unregisterHiddenExtendedConnectSetting)
	t.Cleanup(second.unregisterHiddenExtendedConnectSetting)
	if !http2DisableExtendedConnectProtocol {
		t.Fatal("HTTP/2 Extended CONNECT was not disabled")
	}
	first.unregisterHiddenExtendedConnectSetting()
	if !http2DisableExtendedConnectProtocol {
		t.Fatal("HTTP/2 Extended CONNECT was enabled while an opt-out handler remains")
	}
	second.unregisterHiddenExtendedConnectSetting()
	if http2DisableExtendedConnectProtocol {
		t.Fatal("HTTP/2 Extended CONNECT was not restored after opt-out cleanup")
	}
}

func TestConnectUDPTarget(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		want    string
		wantErr bool
	}{
		{name: "domain", target: "/.well-known/masque/udp/example.com/443/", want: "example.com:443"},
		{name: "domain without trailing slash", target: "/.well-known/masque/udp/example.com/443", want: "example.com:443"},
		{name: "default with query", target: "/.well-known/masque/udp/example.com/443/?ignored=true", want: "example.com:443"},
		{name: "IPv4", target: "/.well-known/masque/udp/192.0.2.1/53/", want: "192.0.2.1:53"},
		{name: "IPv6", target: "/.well-known/masque/udp/2001%3Adb8%3A%3A1/443/", want: "[2001:db8::1]:443"},
		{name: "short query host first", target: "/masque?h=example.com&p=443", want: "example.com:443"},
		{name: "short query port first", target: "/masque?p=443&h=example.com", want: "example.com:443"},
		{name: "long query host first", target: "/masque?target_host=example.com&extra=x&target_port=443", want: "example.com:443"},
		{name: "long query port first", target: "/masque?target_port=443&extra=x&target_host=example.com", want: "example.com:443"},
		{name: "bad port", target: "/.well-known/masque/udp/example.com/0/", wantErr: true},
		{name: "missing port", target: "/.well-known/masque/udp/example.com/", wantErr: true},
		{name: "wrong template", target: "/udp/example.com/443/", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse("https://proxy.example" + tt.target)
			if err != nil {
				t.Fatal(err)
			}
			r := &http.Request{
				Method:     http.MethodConnect,
				ProtoMajor: 2,
				Host:       u.Host,
				URL:        u,
			}
			got, err := connectUDPTarget(r)
			if (err != nil) != tt.wantErr {
				t.Fatalf("connectUDPTarget() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("connectUDPTarget() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCapsulesToUDP(t *testing.T) {
	var stream []byte
	stream = appendCapsule(stream, 0x17, []byte("ignored"))
	stream = appendCapsule(stream, datagramCapsuleType, append(appendQUICVarint(nil, 2), []byte("unknown context")...))
	stream = appendCapsule(stream, datagramCapsuleType, append(appendQUICVarint(nil, connectUDPContextID), []byte("first")...))
	stream = appendCapsule(stream, datagramCapsuleType, append(appendQUICVarint(nil, connectUDPContextID), []byte("second")...))

	conn := newRecordingConn()
	err := capsulesToUDP(conn, bytes.NewReader(stream))
	if !errors.Is(err, io.EOF) {
		t.Fatalf("capsulesToUDP() error = %v", err)
	}
	want := [][]byte{[]byte("first"), []byte("second")}
	if !reflect.DeepEqual(conn.writes, want) {
		t.Fatalf("UDP writes = %q, want %q", conn.writes, want)
	}
}

func TestCapsulesToUDPRejectsTruncatedCapsule(t *testing.T) {
	stream := appendQUICVarint(nil, 0x17)
	stream = appendQUICVarint(stream, 10)
	stream = append(stream, "short"...)
	if err := capsulesToUDP(newRecordingConn(), bytes.NewReader(stream)); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("capsulesToUDP() error = %v, want unexpected EOF", err)
	}
}

func TestUDPToCapsules(t *testing.T) {
	conn := newRecordingConn()
	conn.reads = [][]byte{[]byte("reply")}
	w := httptest.NewRecorder()
	if err := udpToCapsules(w, conn); !errors.Is(err, io.EOF) {
		t.Fatalf("udpToCapsules() error = %v", err)
	}
	want := appendCapsule(nil, datagramCapsuleType, append(appendQUICVarint(nil, connectUDPContextID), []byte("reply")...))
	if !bytes.Equal(w.Body.Bytes(), want) {
		t.Fatalf("response capsules = %x, want %x", w.Body.Bytes(), want)
	}
}

func appendCapsule(dst []byte, capsuleType uint64, value []byte) []byte {
	dst = appendQUICVarint(dst, capsuleType)
	dst = appendQUICVarint(dst, uint64(len(value)))
	return append(dst, value...)
}

type recordingConn struct {
	reads  [][]byte
	writes [][]byte
}

func newRecordingConn() *recordingConn { return new(recordingConn) }

func (c *recordingConn) Read(p []byte) (int, error) {
	if len(c.reads) == 0 {
		return 0, io.EOF
	}
	n := copy(p, c.reads[0])
	c.reads = c.reads[1:]
	return n, nil
}

func (c *recordingConn) Write(p []byte) (int, error) {
	c.writes = append(c.writes, bytes.Clone(p))
	return len(p), nil
}

func (*recordingConn) Close() error                     { return nil }
func (*recordingConn) LocalAddr() net.Addr              { return testAddr("local") }
func (*recordingConn) RemoteAddr() net.Addr             { return testAddr("remote") }
func (*recordingConn) SetDeadline(time.Time) error      { return nil }
func (*recordingConn) SetReadDeadline(time.Time) error  { return nil }
func (*recordingConn) SetWriteDeadline(time.Time) error { return nil }

type testAddr string

func (a testAddr) Network() string { return string(a) }
func (a testAddr) String() string  { return string(a) }
