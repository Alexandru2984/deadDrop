package middleware

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Tor's onion listener connects from loopback for every visitor, so without
// more information all of them share one rate-limit bucket and one login
// lockout. A single visitor could exhaust the first and lock everyone out of an
// account through the second.
//
// With `HiddenServiceExportCircuitID haproxy` in torrc, tor opens each
// connection with a PROXY protocol v1 line whose source address encodes the
// rendezvous circuit: fc00:dead:beef:4dad::<32-bit circuit id>. A circuit is
// the closest thing to a visitor an onion service can see. It is not an
// identity — a client can build new circuits — so the onion listener also keeps
// a ceiling across all circuits (see OnionCeiling).

const (
	proxyHeaderTimeout = 5 * time.Second
	// "PROXY TCP6 " + two full IPv6 addresses + two ports + CRLF is 104 bytes;
	// the spec caps a v1 line at 107 plus CRLF.
	maxProxyLine = 108
)

var onionCircuitPrefix = net.ParseIP("fc00:dead:beef:4dad::")

// ProxyProtocolListener wraps a listener whose every connection must begin with
// a PROXY v1 header written by tor. A connection without a well-formed header,
// or claiming a source outside tor's circuit range, is closed: a header is
// only ever trusted because this listener is loopback-only and tor is the one
// connecting to it.
func ProxyProtocolListener(inner net.Listener) net.Listener {
	return &proxyListener{Listener: inner}
}

type proxyListener struct {
	net.Listener
}

func (l *proxyListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &proxyConn{Conn: conn}, nil
}

// proxyConn reads the header lazily, on the connection's own goroutine, so a
// silent client cannot stall Accept for everyone else.
type proxyConn struct {
	net.Conn
	once    sync.Once
	reader  *bufio.Reader
	circuit string
	err     error
}

func (c *proxyConn) init() {
	c.once.Do(func() {
		_ = c.Conn.SetReadDeadline(time.Now().Add(proxyHeaderTimeout))
		c.reader = bufio.NewReaderSize(c.Conn, 512)
		c.circuit, c.err = readProxyHeader(c.reader)
		_ = c.Conn.SetReadDeadline(time.Time{})
		if c.err != nil {
			_ = c.Conn.Close()
		}
	})
}

func (c *proxyConn) Read(p []byte) (int, error) {
	c.init()
	if c.err != nil {
		return 0, c.err
	}
	return c.reader.Read(p)
}

// Circuit returns tor's circuit identifier for this connection, reading the
// header first if nothing has yet.
func (c *proxyConn) Circuit() (string, error) {
	c.init()
	return c.circuit, c.err
}

var errProxyHeader = errors.New("missing or malformed PROXY header")

func readProxyHeader(r *bufio.Reader) (string, error) {
	var line []byte
	for len(line) < maxProxyLine {
		b, err := r.ReadByte()
		if err != nil {
			return "", errProxyHeader
		}
		line = append(line, b)
		if b == '\n' {
			break
		}
	}
	return parseProxyLine(string(line))
}

// parseProxyLine accepts exactly what tor writes and nothing else.
func parseProxyLine(line string) (string, error) {
	if !strings.HasSuffix(line, "\r\n") {
		return "", errProxyHeader
	}
	fields := strings.Split(strings.TrimSuffix(line, "\r\n"), " ")
	if len(fields) != 6 || fields[0] != "PROXY" || fields[1] != "TCP6" {
		return "", errProxyHeader
	}
	src := net.ParseIP(fields[2])
	dst := net.ParseIP(fields[3])
	if src == nil || dst == nil || src.To4() != nil || dst.To4() != nil {
		return "", errProxyHeader
	}
	for _, port := range fields[4:] {
		if n, err := strconv.Atoi(port); err != nil || n < 0 || n > 65535 || strconv.Itoa(n) != port {
			return "", errProxyHeader
		}
	}
	src16 := src.To16()
	for i := 0; i < 12; i++ {
		if src16[i] != onionCircuitPrefix[i] {
			return "", errProxyHeader
		}
	}
	id := uint32(src16[12])<<24 | uint32(src16[13])<<16 | uint32(src16[14])<<8 | uint32(src16[15])
	return strconv.FormatUint(uint64(id), 10), nil
}

type circuitKey struct{}

// OnionConnContext is an http.Server ConnContext that lets ExtractIP find
// tor's circuit for the connection. It must not read: net/http calls it on
// the accept loop, so blocking here would stall every other connection. By
// the time a request exists, its bytes — header first — have been read.
func OnionConnContext(ctx context.Context, conn net.Conn) context.Context {
	if pc, ok := conn.(*proxyConn); ok {
		return context.WithValue(ctx, circuitKey{}, pc)
	}
	return ctx
}

func circuitFrom(r *http.Request) (string, bool) {
	pc, ok := r.Context().Value(circuitKey{}).(*proxyConn)
	if !ok {
		return "", false
	}
	circuit, err := pc.Circuit()
	return circuit, err == nil && circuit != ""
}

// OnionCeiling caps unsafe requests across every circuit together. Per-circuit
// buckets stop one visitor crowding out the rest; this stops a client that
// keeps building circuits from multiplying its share without bound.
//
// Logout is exempt. The ceiling is shared, so anyone could fill it, and a
// panic wipe's logout refused with 429 would leave that session alive.
func OnionCeiling(rl *RateLimiter, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isUnsafeMethod(r.Method) && r.URL.Path != "/api/logout" && !rl.Allow("onion-ceiling") {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "60")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"too many requests"}`))
			return
		}
		next.ServeHTTP(w, r)
	})
}
