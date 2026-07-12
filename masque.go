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
		buffer := make([]byte, maxUDPPayloadSize)
		return &buffer
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
	bufPtr := datagramBufferPool.Get().(*[]byte)
	buf := *bufPtr
	defer datagramBufferPool.Put(bufPtr)

	for {
		capsuleType, err := readQUICVarint(r)
		if err != nil {
			return err
		}
		capsuleLen, err := readQUICVarint(r)
		if err != nil {
			return fmt.Errorf("reading capsule length: %w", err)
		}
		capsule := &io.LimitedReader{R: r, N: int64(capsuleLen)}
		if capsuleType != datagramCapsuleType {
			if err := discardCapsule(capsule, buf); err != nil {
				return fmt.Errorf("discarding unknown capsule: %w", err)
			}
			continue
		}
		if capsuleLen > maxDatagramCapsuleSize {
			return fmt.Errorf("DATAGRAM capsule length %d exceeds limit", capsuleLen)
		}

		contextID, err := readQUICVarint(capsule)
		if err != nil {
			return fmt.Errorf("reading CONNECT-UDP context ID: %w", err)
		}
		if contextID != connectUDPContextID {
			// Non-zero context IDs are extension points. RFC 9298 requires an
			// unknown context to be dropped or briefly buffered.
			if err := discardCapsule(capsule, buf); err != nil {
				return fmt.Errorf("discarding unknown CONNECT-UDP context: %w", err)
			}
			continue
		}
		payload := buf[:int(capsule.N)]
		if _, err := io.ReadFull(capsule, payload); err != nil {
			return fmt.Errorf("reading DATAGRAM capsule: %w", err)
		}
		n, err := udpConn.Write(payload)
		if err != nil {
			return fmt.Errorf("writing UDP datagram: %w", err)
		}
		if n != len(payload) {
			return io.ErrShortWrite
		}
	}
}

func discardCapsule(capsule *io.LimitedReader, buf []byte) error {
	for capsule.N > 0 {
		readSize := int64(len(buf))
		if capsule.N < readSize {
			readSize = capsule.N
		}
		if _, err := io.ReadFull(capsule, buf[:int(readSize)]); err != nil {
			return err
		}
	}
	return nil
}

func udpToCapsules(w http.ResponseWriter, udpConn net.Conn) error {
	bufPtr := datagramBufferPool.Get().(*[]byte)
	buf := *bufPtr
	defer datagramBufferPool.Put(bufPtr)

	controller := http.NewResponseController(w)
	var header [17]byte // two eight-byte varints plus the one-byte context ID
	for {
		n, err := udpConn.Read(buf)
		if err != nil {
			return err
		}

		capsuleHeader := appendQUICVarint(header[:0], datagramCapsuleType)
		capsuleHeader = appendQUICVarint(capsuleHeader, uint64(n+1)) // context ID 0 is one byte
		capsuleHeader = appendQUICVarint(capsuleHeader, connectUDPContextID)
		if err := writeFull(w, capsuleHeader); err != nil {
			return fmt.Errorf("writing DATAGRAM capsule header: %w", err)
		}
		if err := writeFull(w, buf[:n]); err != nil {
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
	var encoded [8]byte
	if _, err := io.ReadFull(r, encoded[:1]); err != nil {
		return 0, err
	}
	length := 1 << (encoded[0] >> 6)
	if _, err := io.ReadFull(r, encoded[1:length]); err != nil {
		return 0, err
	}
	encoded[0] &= 0x3f

	switch length {
	case 1:
		return uint64(encoded[0]), nil
	case 2:
		return uint64(binary.BigEndian.Uint16(encoded[:2])), nil
	case 4:
		return uint64(binary.BigEndian.Uint32(encoded[:4])), nil
	case 8:
		return binary.BigEndian.Uint64(encoded[:]), nil
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
