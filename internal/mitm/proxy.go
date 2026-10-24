// Package mitm implements an opt-in local TLS-terminating HTTP proxy. It is
// intentionally separate from capture: decrypted request/response messages are
// injected into the same store as synthetic HTTP packets, so the existing
// packet list, protocol tree and AI dissectors work without keylog files.
package mitm

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"

	"ebpfshark/internal/packet"
	"ebpfshark/internal/store"
)

// Config configures the local MITM proxy.
type Config struct {
	Addr   string
	CADir  string
	Store  *store.Store
	Logger *slog.Logger
}

// Status is safe to expose to the UI.
type Status struct {
	Enabled bool   `json:"enabled"`
	Addr    string `json:"addr,omitempty"`
	CAPath  string `json:"caPath,omitempty"`
}

// Proxy is a local HTTP/HTTPS CONNECT proxy.
type Proxy struct {
	cfg      Config
	ca       *authority
	listener net.Listener
	logger   *slog.Logger

	mu         sync.Mutex
	transports map[string]*http.Transport
	h2         *http2.Server
	closed     bool
}

// New prepares the CA and proxy without opening the listener.
func New(cfg Config) (*Proxy, error) {
	if cfg.Store == nil {
		return nil, fmt.Errorf("mitm store is required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.CADir == "" {
		cfg.CADir = "ebpfshark-mitm"
	}
	ca, err := loadOrCreateCA(cfg.CADir)
	if err != nil {
		return nil, fmt.Errorf("load MITM CA: %w", err)
	}
	return &Proxy{cfg: cfg, ca: ca, logger: cfg.Logger, transports: make(map[string]*http.Transport), h2: &http2.Server{}}, nil
}

// Start opens the proxy listener.
func (p *Proxy) Start() error {
	p.mu.Lock()
	p.closed = false
	addr := p.cfg.Addr
	p.mu.Unlock()
	if addr == "" {
		addr = "127.0.0.1:18080"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	p.mu.Lock()
	p.cfg.Addr = addr
	p.listener = ln
	p.mu.Unlock()
	go p.acceptLoop()
	p.logger.Info("MITM HTTPS proxy started",
		"addr", ln.Addr().String(), "ca", p.ca.dir+"/ca.crt")
	return nil
}

// Reconfigure restarts the proxy on a new address. It keeps the CA and any
// cached upstream transports.
func (p *Proxy) Reconfigure(addr string) error {
	p.Close()
	p.mu.Lock()
	p.cfg.Addr = addr
	p.mu.Unlock()
	return p.Start()
}

// Close stops accepting new proxy connections.
func (p *Proxy) Close() {
	p.mu.Lock()
	p.closed = true
	ln := p.listener
	p.listener = nil
	p.mu.Unlock()
	if ln != nil {
		_ = ln.Close()
	}
}

func (p *Proxy) Status() Status {
	p.mu.Lock()
	defer p.mu.Unlock()
	addr := p.cfg.Addr
	if p.listener != nil {
		addr = p.listener.Addr().String()
	}
	return Status{Enabled: p.listener != nil, Addr: addr, CAPath: p.ca.dir + "/ca.crt"}
}

func (p *Proxy) CACertPEM() []byte { return append([]byte(nil), p.ca.pem...) }

func (p *Proxy) acceptLoop() {
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			p.mu.Lock()
			closed := p.closed
			p.mu.Unlock()
			if !closed {
				p.logger.Warn("MITM accept failed", "err", err)
			}
			return
		}
		go p.handleConn(conn)
	}
}

func (p *Proxy) handleConn(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if req.Method == http.MethodConnect {
		p.handleConnect(conn, req)
		return
	}
	// Plain HTTP proxying is intentionally not terminated; HTTPS is the
	// target use case. Keep the proxy from becoming an open relay.
	_, _ = io.WriteString(conn, "HTTP/1.1 501 Not Implemented\r\nContent-Length: 0\r\n\r\n")
}

func (p *Proxy) handleConnect(conn net.Conn, req *http.Request) {
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	if !strings.Contains(host, ":") {
		host += ":443"
	}
	cert, err := p.ca.certificateFor(host)
	if err != nil {
		_, _ = io.WriteString(conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
	tlsConn := tls.Server(conn, &tls.Config{
		Certificates: []tls.Certificate{*cert},
		NextProtos:   []string{"h2", "http/1.1"},
		MinVersion:   tls.VersionTLS12,
	})
	if err := tlsConn.Handshake(); err != nil {
		p.logger.Debug("MITM TLS handshake failed", "host", host, "err", err)
		return
	}
	handler := p.handler(host)
	if tlsConn.ConnectionState().NegotiatedProtocol == "h2" {
		p.h2.ServeConn(tlsConn, &http2.ServeConnOpts{Handler: handler})
		return
	}
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 15 * time.Second}
	_ = srv.Serve(&oneConnListener{conn: tlsConn})
}

func (p *Proxy) handler(host string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.forward(w, r, host)
	})
}

func (p *Proxy) forward(w http.ResponseWriter, r *http.Request, host string) {
	target := *r.URL
	if host != "" {
		target.Scheme = "https"
		target.Host = host
	} else if target.Scheme == "" {
		target.Scheme = "http"
		target.Host = r.Host
	}
	if target.Host == "" {
		http.Error(w, "missing target host", http.StatusBadGateway)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 32<<20))
	if err != nil {
		http.Error(w, "read request body: "+err.Error(), http.StatusBadGateway)
		return
	}
	_ = r.Body.Close()

	rawReq := dumpRequest(r, body)
	out := r.Clone(r.Context())
	out.URL = &target
	out.RequestURI = ""
	out.Body = io.NopCloser(bytes.NewReader(body))
	out.ContentLength = int64(len(body))
	out.Host = target.Host
	removeHopHeaders(out.Header)

	client := p.transportFor(urlTarget{Scheme: target.Scheme, Host: target.Host})
	resp, err := client.RoundTrip(out)
	if err != nil {
		http.Error(w, "upstream request failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	removeHopHeaders(resp.Header)
	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)

	var captured bytes.Buffer
	capLimit := 8 << 20
	tee := io.TeeReader(resp.Body, &capWriter{w: &captured, max: capLimit})
	if _, err := io.Copy(w, tee); err != nil {
		p.logger.Debug("MITM response copy failed", "host", target.Host, "err", err)
	}

	rawResp := dumpResponse(resp, captured.Bytes())
	p.ingest(rawReq, target.Host, packet.Egress)
	p.ingest(rawResp, target.Host, packet.Ingress)
}

type capWriter struct {
	w   io.Writer
	max int
}

func (w *capWriter) Write(b []byte) (int, error) {
	if w.max <= 0 {
		return len(b), nil
	}
	if len(b) > w.max {
		b = b[:w.max]
	}
	n, err := w.w.Write(b)
	w.max -= n
	if err != nil {
		return n, err
	}
	return n, nil
}

func (p *Proxy) transportFor(target urlTarget) *http.Transport {
	key := target.Scheme + "://" + stripPort(target.Host)
	p.mu.Lock()
	defer p.mu.Unlock()
	if t := p.transports[key]; t != nil {
		return t
	}
	t := &http.Transport{
		Proxy:               nil,
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        32,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}
	if target.Scheme == "https" {
		t.TLSClientConfig = &tls.Config{ServerName: stripPort(target.Host), MinVersion: tls.VersionTLS12}
	}
	p.transports[key] = t
	return t
}

type urlTarget struct {
	Scheme string
	Host   string
}

func (p *Proxy) ingest(raw []byte, host string, direction packet.Direction) {
	if len(raw) == 0 {
		return
	}
	frame := syntheticHTTPFrame(raw)
	pkt := &packet.Packet{
		Time: time.Now(), IfName: "mitm", Direction: direction,
		WireLen: uint32(len(frame)), CapLen: uint32(len(frame)),
		LinkType: packet.LinkEthernet, Data: frame,
	}
	p.cfg.Store.Add(pkt)
}

func dumpRequest(r *http.Request, body []byte) []byte {
	var b bytes.Buffer
	uri := r.URL.RequestURI()
	if uri == "" {
		uri = "/"
	}
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", r.Method, uri)
	if r.Host != "" {
		fmt.Fprintf(&b, "Host: %s\r\n", r.Host)
	}
	r.Header.Write(&b)
	b.WriteString("\r\n")
	b.Write(body)
	return b.Bytes()
}

func dumpResponse(r *http.Response, body []byte) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "HTTP/1.1 %s\r\n", r.Status)
	r.Header.Write(&b)
	b.WriteString("\r\n")
	b.Write(body)
	return b.Bytes()
}

func removeHopHeaders(h http.Header) {
	for _, key := range []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade"} {
		h.Del(key)
	}
}

func copyHeaders(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

// oneConnListener exposes a single already-accepted connection to http.Server.
type oneConnListener struct {
	conn net.Conn
	once bool
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	if l.once {
		return nil, io.EOF
	}
	l.once = true
	return l.conn, nil
}
func (l *oneConnListener) Close() error   { return nil }
func (l *oneConnListener) Addr() net.Addr { return l.conn.LocalAddr() }

func syntheticHTTPFrame(payload []byte) []byte {
	const ethLen, ipLen, tcpLen = 14, 20, 20
	maxPayload := 60000
	if len(payload) > maxPayload {
		payload = payload[:maxPayload]
	}
	frame := make([]byte, ethLen+ipLen+tcpLen+len(payload))
	// Ethernet
	copy(frame[0:6], []byte{0x02, 0, 0, 0, 0, 1})
	copy(frame[6:12], []byte{0x02, 0, 0, 0, 0, 2})
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)
	// IPv4
	ip := frame[ethLen:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(ipLen+tcpLen+len(payload)))
	ip[8] = 64
	ip[9] = 6
	copy(ip[12:16], net.IPv4(10, 255, 0, 1).To4())
	copy(ip[16:20], net.IPv4(10, 255, 0, 2).To4())
	binary.BigEndian.PutUint16(ip[10:12], ipChecksum(ip[:ipLen]))
	// TCP
	tcp := ip[ipLen:]
	binary.BigEndian.PutUint16(tcp[0:2], 443)
	binary.BigEndian.PutUint16(tcp[2:4], 50000)
	binary.BigEndian.PutUint32(tcp[4:8], 1)
	tcp[12] = 5 << 4
	tcp[13] = 0x18
	binary.BigEndian.PutUint16(tcp[14:16], 65535)
	copy(tcp[tcpLen:], payload)
	return frame
}

func ipChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
