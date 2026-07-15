package forwardproxy

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

const (
	connectUDPProtocol  = "connect-udp"
	datagramCapsuleType = 0x00
	connectUDPContextID = 0x00

	maxUDPPayloadSize      = 65535
	maxDatagramCapsuleSize = maxUDPPayloadSize + 1 // one-byte context ID 0
	maxCapsuleHeaderSize   = 17                    // two eight-byte varints plus one-byte context ID

	defaultURITemplatePattern        = `^/\.well-known/masque/udp/([^/?#]+)/([0-9]{1,5})/?([?#].*)?$`
	shortHostFirstURITemplatePattern = `(^|[?&])h=([^&#]+)(&[^#]*)*&p=([0-9]{1,5})([&#]|$)`
	shortPortFirstURITemplatePattern = `(^|[?&])p=([0-9]{1,5})(&[^#]*)*&h=([^&#]+)([&#]|$)`
	hostFirstURITemplatePattern      = `(^|[?&])target_host=([^&#]+)(&[^#]*)*&target_port=([0-9]{1,5})([&#]|$)`
	portFirstURITemplatePattern      = `(^|[?&])target_port=([0-9]{1,5})(&[^#]*)*&target_host=([^&#]+)([&#]|$)`
)

type uriTemplate struct {
	regex     *regexp.Regexp
	hostIndex int
	portIndex int
}

var uriTemplates = [...]uriTemplate{
	{regexp.MustCompile(defaultURITemplatePattern), 1, 2},
	{regexp.MustCompile(shortHostFirstURITemplatePattern), 2, 4},
	{regexp.MustCompile(shortPortFirstURITemplatePattern), 4, 2},
	{regexp.MustCompile(hostFirstURITemplatePattern), 2, 4},
	{regexp.MustCompile(portFirstURITemplatePattern), 4, 2},
}

var datagramBufferPool = sync.Pool{
	New: func() any {
		// Header headroom lets udpToCapsules emit each capsule with a single
		// ResponseWriter.Write without copying the datagram payload.
		buffer := make([]byte, maxCapsuleHeaderSize+maxUDPPayloadSize)
		return &buffer
	},
}

var capsuleVarintScratchPool = sync.Pool{
	New: func() any {
		return new([8]byte)
	},
}

// connectProtocol returns the Extended CONNECT :protocol pseudo-header.
// x/net/http2 exposes it as a synthetic header, while quic-go exposes it in
// Request.Proto for HTTP/3.
func connectProtocol(r *http.Request) string {
	if protocol := r.Header.Get(":protocol"); protocol != "" {
		return protocol
	}
	if r.ProtoMajor == 3 && r.Proto != "" && r.Proto != "HTTP/3" && r.Proto != "HTTP/3.0" {
		return r.Proto
	}
	return ""
}

// connectUDPTarget extracts a target from the default RFC 9298 URI template
// and common query-based URI templates using h/p or target_host/target_port.
func connectUDPTarget(r *http.Request) (string, error) {
	if r.Method != http.MethodConnect || (r.ProtoMajor != 2 && r.ProtoMajor != 3) {
		return "", errors.New("CONNECT-UDP requires HTTP/2 or HTTP/3 Extended CONNECT")
	}
	if r.Host == "" || r.URL.Path == "" {
		return "", errors.New("CONNECT-UDP requires non-empty :scheme, :authority, and :path")
	}

	requestTarget := r.URL.EscapedPath()
	if r.URL.RawQuery != "" {
		requestTarget += "?" + r.URL.RawQuery
	}

	var hostSegment, portString string
	for _, template := range uriTemplates {
		matches := template.regex.FindStringSubmatch(requestTarget)
		if matches == nil {
			continue
		}
		hostSegment = matches[template.hostIndex]
		portString = matches[template.portIndex]
		break
	}
	if hostSegment == "" || portString == "" {
		return "", errors.New("CONNECT-UDP request target does not match a supported URI template")
	}

	host, err := url.PathUnescape(hostSegment)
	if err != nil || host == "" || strings.ContainsAny(host, "/[]") {
		return "", errors.New("invalid CONNECT-UDP target host")
	}
	if strings.Contains(host, "%") { // scoped IPv6 addresses are not supported by RFC 9298
		return "", errors.New("CONNECT-UDP target host must not contain a zone identifier")
	}
	if strings.Contains(host, ":") && net.ParseIP(host) == nil {
		return "", errors.New("invalid CONNECT-UDP IPv6 target host")
	}

	port, err := strconv.Atoi(portString)
	if err != nil || port < 1 || port > 65535 {
		return "", errors.New("CONNECT-UDP target port must be an integer between 1 and 65535")
	}

	return net.JoinHostPort(host, portString), nil
}

func (h *Handler) serveConnectUDP(w http.ResponseWriter, r *http.Request) error {
	target, err := connectUDPTarget(r)
	if err != nil {
		return caddyhttp.Error(http.StatusBadRequest, err)
	}
	if h.upstream != nil {
		return caddyhttp.Error(http.StatusNotImplemented, errors.New("CONNECT-UDP cannot be routed through an HTTP upstream proxy"))
	}

	udpConn, err := h.dialContextCheckACL(r.Context(), "udp", target)
	if err != nil {
		return err
	}
	if udpConn == nil {
		return caddyhttp.Error(http.StatusForbidden, fmt.Errorf("target %s is not allowed", target))
	}
	defer udpConn.Close()
	defer r.Body.Close()

	w.Header().Set("Capsule-Protocol", "?1")
	w.WriteHeader(http.StatusOK)
	if err := http.NewResponseController(w).Flush(); err != nil {
		return caddyhttp.Error(http.StatusInternalServerError, fmt.Errorf("ResponseWriter flush error: %v", err))
	}

	return relayConnectUDPCapsules(udpConn, r.Body, w)
}

// relayConnectUDPCapsules relays DATAGRAM capsules from the request stream to
// a connected UDP socket and encapsulates packets received from that socket in
// DATAGRAM capsules on the response stream.
func relayConnectUDPCapsules(udpConn net.Conn, requestBody io.Reader, w http.ResponseWriter) error {
	clientErr := make(chan error, 1)
	go func() {
		clientErr <- capsulesToUDP(udpConn, requestBody)
		_ = udpConn.Close() // unblock the UDP receive loop when the request stream ends
	}()

	responseErr := udpToCapsules(w, udpConn)
	if responseErr != nil && !errors.Is(responseErr, net.ErrClosed) {
		_ = udpConn.Close()
		return responseErr
	}

	err := <-clientErr
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func capsulesToUDP(udpConn net.Conn, r io.Reader) error {
	varintScratch := capsuleVarintScratchPool.Get().(*[8]byte)
	defer capsuleVarintScratchPool.Put(varintScratch)

	for {
		capsuleType, err := readQUICVarintWithScratch(r, varintScratch)
		if err != nil {
			return err
		}
		capsuleLen, err := readQUICVarintWithScratch(r, varintScratch)
		if err != nil {
			return fmt.Errorf("reading capsule length: %w", err)
		}
		if capsuleType != datagramCapsuleType {
			if err := discardCapsule(r, capsuleLen); err != nil {
				return fmt.Errorf("discarding unknown capsule: %w", err)
			}
			continue
		}
		if capsuleLen > maxDatagramCapsuleSize {
			return fmt.Errorf("DATAGRAM capsule length %d exceeds limit", capsuleLen)
		}

		remaining := capsuleLen
		contextID, err := readQUICVarintLimited(r, varintScratch, &remaining)
		if err != nil {
			return fmt.Errorf("reading CONNECT-UDP context ID: %w", err)
		}
		if contextID != connectUDPContextID {
			// Non-zero context IDs are extension points. RFC 9298 requires an
			// unknown context to be dropped or briefly buffered.
			if err := discardCapsule(r, remaining); err != nil {
				return fmt.Errorf("discarding unknown CONNECT-UDP context: %w", err)
			}
			continue
		}
		if err := writeCapsuleToUDP(udpConn, r, int(remaining)); err != nil {
			return err
		}
	}
}

func writeCapsuleToUDP(udpConn net.Conn, r io.Reader, payloadSize int) error {
	bufPtr := datagramBufferPool.Get().(*[]byte)
	storage := *bufPtr
	payload := storage[maxCapsuleHeaderSize : maxCapsuleHeaderSize+payloadSize]
	defer datagramBufferPool.Put(bufPtr)

	if _, err := io.ReadFull(r, payload); err != nil {
		return fmt.Errorf("reading DATAGRAM capsule: %w", err)
	}
	n, err := udpConn.Write(payload)
	if err != nil {
		return fmt.Errorf("writing UDP datagram: %w", err)
	}
	if n != len(payload) {
		return io.ErrShortWrite
	}
	return nil
}

func discardCapsule(r io.Reader, remaining uint64) error {
	bufPtr := datagramBufferPool.Get().(*[]byte)
	storage := *bufPtr
	buf := storage[maxCapsuleHeaderSize:]
	defer datagramBufferPool.Put(bufPtr)

	for remaining > 0 {
		readSize := uint64(len(buf))
		if remaining < readSize {
			readSize = remaining
		}
		if _, err := io.ReadFull(r, buf[:int(readSize)]); err != nil {
			return err
		}
		remaining -= readSize
	}
	return nil
}

func udpToCapsules(w http.ResponseWriter, udpConn net.Conn) error {
	bufPtr := datagramBufferPool.Get().(*[]byte)
	storage := *bufPtr
	buf := storage[maxCapsuleHeaderSize:]
	defer datagramBufferPool.Put(bufPtr)

	controller := http.NewResponseController(w)
	var header [maxCapsuleHeaderSize]byte
	for {
		n, err := udpConn.Read(buf)
		if err != nil {
			return err
		}

		capsuleHeader := appendQUICVarint(header[:0], datagramCapsuleType)
		capsuleHeader = appendQUICVarint(capsuleHeader, uint64(n+1)) // context ID 0 is one byte
		capsuleHeader = appendQUICVarint(capsuleHeader, connectUDPContextID)
		headerStart := maxCapsuleHeaderSize - len(capsuleHeader)
		copy(storage[headerStart:maxCapsuleHeaderSize], capsuleHeader)
		if err := writeFull(w, storage[headerStart:maxCapsuleHeaderSize+n]); err != nil {
			return fmt.Errorf("writing DATAGRAM capsule: %w", err)
		}
		if err := controller.Flush(); err != nil {
			return fmt.Errorf("flushing DATAGRAM capsule: %w", err)
		}
	}
}

func writeFull(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}

func readQUICVarint(r io.Reader) (uint64, error) {
	scratch := capsuleVarintScratchPool.Get().(*[8]byte)
	defer capsuleVarintScratchPool.Put(scratch)
	return readQUICVarintWithScratch(r, scratch)
}

func readQUICVarintWithScratch(r io.Reader, encoded *[8]byte) (uint64, error) {
	if _, err := io.ReadFull(r, encoded[:1]); err != nil {
		return 0, err
	}
	length := 1 << (encoded[0] >> 6)
	if _, err := io.ReadFull(r, encoded[1:length]); err != nil {
		return 0, err
	}
	encoded[0] &= 0x3f
	return decodeQUICVarint(encoded, length), nil
}

func readQUICVarintLimited(r io.Reader, encoded *[8]byte, remaining *uint64) (uint64, error) {
	if *remaining == 0 {
		return 0, io.EOF
	}
	if _, err := io.ReadFull(r, encoded[:1]); err != nil {
		return 0, err
	}
	*remaining -= 1

	length := 1 << (encoded[0] >> 6)
	rest := uint64(length - 1)
	if *remaining < rest {
		return 0, io.ErrUnexpectedEOF
	}
	if _, err := io.ReadFull(r, encoded[1:length]); err != nil {
		if err == io.EOF {
			return 0, io.ErrUnexpectedEOF
		}
		return 0, err
	}
	*remaining -= rest
	encoded[0] &= 0x3f
	return decodeQUICVarint(encoded, length), nil
}

func decodeQUICVarint(encoded *[8]byte, length int) uint64 {
	switch length {
	case 1:
		return uint64(encoded[0])
	case 2:
		return uint64(binary.BigEndian.Uint16(encoded[:2]))
	case 4:
		return uint64(binary.BigEndian.Uint32(encoded[:4]))
	case 8:
		return binary.BigEndian.Uint64(encoded[:])
	default:
		panic("invalid QUIC variable integer length")
	}
}

func appendQUICVarint(dst []byte, value uint64) []byte {
	switch {
	case value < 1<<6:
		return append(dst, byte(value))
	case value < 1<<14:
		return append(dst, byte(value>>8)|0x40, byte(value))
	case value < 1<<30:
		return append(dst, byte(value>>24)|0x80, byte(value>>16), byte(value>>8), byte(value))
	case value < 1<<62:
		return append(dst, byte(value>>56)|0xc0, byte(value>>48), byte(value>>40), byte(value>>32),
			byte(value>>24), byte(value>>16), byte(value>>8), byte(value))
	default:
		panic("QUIC variable integer overflow")
	}
}
