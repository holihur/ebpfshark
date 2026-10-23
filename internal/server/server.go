package server

import (
	"bytes"
	"container/list"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"ebpfshark/internal/auth"
	"ebpfshark/internal/capture"
	"ebpfshark/internal/decode"
	"ebpfshark/internal/filter"
	"ebpfshark/internal/packet"
	"ebpfshark/internal/pcapio"
	"ebpfshark/internal/probe"
	"ebpfshark/internal/store"
	"ebpfshark/internal/stream"
	"ebpfshark/internal/trace"
)

// Version is stamped at build time.
var Version = "0.1.0-dev"

// Server exposes the REST and SSE API plus the embedded web UI.
type Server struct {
	store *store.Store
	mgr   *capture.Manager
	log   *slog.Logger
	web   fs.FS

	start        time.Time
	importLock   chan struct{}
	instance     string
	selfPort     uint16
	auth         *auth.Service
	secureCookie bool
	mcpHandler   http.Handler
	updateStatus func() any

	detailMu    sync.Mutex
	detailLRU   *list.List
	detailCache map[detailKey]*list.Element
	detailBytes int

	traceMgr *trace.Manager
}

type detailKey struct {
	id   uint64
	time int64
}

type detailEntry struct {
	key    detailKey
	fields []*decode.Field
	bytes  int
}

// SetSecureCookie forces the Secure attribute on session cookies. Use it when
// TLS terminates in front of ebpfshark.
func (s *Server) SetSecureCookie(v bool) { s.secureCookie = v }

// SetMCPHandler mounts an MCP endpoint at /mcp. The handler is responsible for
// its own authentication.
func (s *Server) SetMCPHandler(h http.Handler) { s.mcpHandler = h }

// SetUpdateStatus exposes auto-update state through GET /api/update.
func (s *Server) SetUpdateStatus(fn func() any) { s.updateStatus = fn }

// New builds a Server. webFS should contain the built UI at its root.
func New(st *store.Store, mgr *capture.Manager, log *slog.Logger, webFS fs.FS, selfPort uint16, authSvc *auth.Service) *Server {
	var id [6]byte
	_, _ = rand.Read(id[:])
	return &Server{
		store:       st,
		mgr:         mgr,
		log:         log,
		web:         webFS,
		start:       time.Now(),
		importLock:  make(chan struct{}, 1),
		instance:    hex.EncodeToString(id[:]),
		selfPort:    selfPort,
		auth:        authSvc,
		detailLRU:   list.New(),
		detailCache: make(map[detailKey]*list.Element),
		traceMgr:    trace.NewManager(),
	}
}

// Handler returns the fully wired HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/health", s.handleHealth)
	mux.HandleFunc("GET /api/auth/session", s.handleAuthSession)
	mux.HandleFunc("POST /api/auth/login", s.handleAuthLogin)
	mux.HandleFunc("POST /api/auth/logout", s.handleAuthLogout)
	mux.HandleFunc("GET /api/status", s.handleStatus)
	mux.HandleFunc("GET /api/interfaces", s.handleInterfaces)
	mux.HandleFunc("POST /api/capture/start", s.handleStart)
	mux.HandleFunc("POST /api/capture/stop", s.handleStop)
	mux.HandleFunc("POST /api/capture/clear", s.handleClear)
	mux.HandleFunc("GET /api/packets", s.handlePackets)
	mux.HandleFunc("GET /api/packets/{id}", s.handlePacketDetail)
	mux.HandleFunc("GET /api/packets/{id}/stream", s.handlePacketStream)
	mux.HandleFunc("GET /api/stream", s.handleStream)
	mux.HandleFunc("GET /api/stats", s.handleStats)
	mux.HandleFunc("GET /api/conversations", s.handleConversations)
	mux.HandleFunc("POST /api/filter/validate", s.handleFilterValidate)
	mux.HandleFunc("GET /api/filter/fields", s.handleFilterFields)
	mux.HandleFunc("GET /api/filter/schema", s.handleFilterSchema)
	mux.HandleFunc("GET /api/export/pcap", s.handleExport)
	mux.HandleFunc("POST /api/import", s.handleImport)
	mux.HandleFunc("GET /api/version", s.handleVersion)
	mux.HandleFunc("GET /api/update", s.handleUpdate)
	mux.HandleFunc("GET /api/trace", s.handleTrace)
	mux.HandleFunc("POST /api/trace/start", s.handleTraceStart)
	mux.HandleFunc("POST /api/trace/stop", s.handleTraceStop)
	mux.Handle("/api/", http.NotFoundHandler())

	if s.mcpHandler != nil {
		mux.Handle("/mcp", s.mcpHandler)
	}

	mux.Handle("/", s.spaHandler())

	return withMiddleware(s.authGate(mux), s.log)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// authInfo is returned by the session/login endpoints.
type authInfo struct {
	Enabled       bool   `json:"enabled"`
	Authenticated bool   `json:"authenticated"`
	User          string `json:"user,omitempty"`
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Server) handleAuthSession(w http.ResponseWriter, r *http.Request) {
	info := authInfo{Enabled: s.auth.Enabled(), Authenticated: !s.auth.Enabled()}
	if s.auth.Enabled() {
		if c, err := r.Cookie(auth.CookieName); err == nil {
			if sess, ok := s.auth.Session(c.Value); ok {
				info.Authenticated = true
				info.User = sess.User
			}
		}
	}
	writeJSON(w, http.StatusOK, info)
}

func (s *Server) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	if !s.auth.Enabled() {
		writeJSON(w, http.StatusOK, authInfo{Enabled: false, Authenticated: true})
		return
	}
	var req loginRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Username == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "username and password are required")
		return
	}
	ip := clientIP(r)
	if !s.auth.AllowAttempt(ip) {
		writeError(w, http.StatusTooManyRequests, "too many login attempts, try again later")
		return
	}
	if !s.auth.Authenticate(req.Username, req.Password) {
		s.auth.RecordFailure(ip)
		s.log.Warn("failed login attempt", "ip", ip, "user", req.Username)
		writeError(w, http.StatusUnauthorized, "invalid username or password")
		return
	}
	s.auth.ResetAttempts(ip)
	token, expires := s.auth.CreateSession(req.Username)
	http.SetCookie(w, &http.Cookie{
		Name:     auth.CookieName,
		Value:    token,
		Path:     "/",
		Expires:  expires,
		MaxAge:   int(time.Until(expires).Seconds()),
		HttpOnly: true,
		Secure:   s.cookieSecure(r),
		SameSite: http.SameSiteLaxMode,
	})
	s.log.Info("login succeeded", "ip", ip, "user", req.Username)
	writeJSON(w, http.StatusOK, authInfo{Enabled: true, Authenticated: true, User: req.Username})
}

func (s *Server) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(auth.CookieName); err == nil {
		s.auth.DeleteSession(c.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     auth.CookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.cookieSecure(r),
		SameSite: http.SameSiteLaxMode,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// authGate requires a valid session for every /api endpoint except health and
// the auth endpoints themselves. Static assets stay public so the login page
// can load; all capture data is behind the API.
func (s *Server) authGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.auth.Enabled() || !strings.HasPrefix(r.URL.Path, "/api/") || publicAuthPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		if c, err := r.Cookie(auth.CookieName); err == nil && s.auth.Valid(c.Value) {
			next.ServeHTTP(w, r)
			return
		}
		writeError(w, http.StatusUnauthorized, "authentication required")
	})
}

func publicAuthPath(path string) bool {
	switch path {
	case "/api/health", "/api/auth/session", "/api/auth/login", "/api/auth/logout":
		return true
	}
	return false
}

func (s *Server) cookieSecure(r *http.Request) bool {
	return s.secureCookie || r.TLS != nil ||
		strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) handleUpdate(w http.ResponseWriter, r *http.Request) {
	if s.updateStatus == nil {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false})
		return
	}
	writeJSON(w, http.StatusOK, s.updateStatus())
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"version":    Version,
		"startedAt":  s.start.Unix(),
		"goRuntime":  runtimeVersion(),
		"kernelNote": "requires Linux 6.6+ (TCX)",
	})
}

type statusResponse struct {
	Capture     capture.Status      `json:"capture"`
	Store       store.Stats         `json:"store"`
	Interfaces  []capture.Interface `json:"interfaces"`
	Subscribers int                 `json:"subscribers"`
	ServerTime  int64               `json:"serverTime"`
	Version     string              `json:"version"`
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	ifaces, err := capture.ListInterfaces()
	if err != nil {
		s.log.Debug("list interfaces", "err", err)
		ifaces = []capture.Interface{}
	}
	ifaces = append(ifaces, s.importedInterface())
	writeJSON(w, http.StatusOK, statusResponse{
		Capture:     s.mgr.Status(),
		Store:       s.store.Stats(),
		Interfaces:  ifaces,
		Subscribers: s.store.SubscriberCount(),
		ServerTime:  time.Now().UnixNano(),
		Version:     Version,
	})
}

func (s *Server) importedInterface() capture.Interface {
	return capture.Interface{
		Name:  "import",
		Index: -1,
		Kind:  "file",
		Addrs: []string{},
	}
}

func (s *Server) handleInterfaces(w http.ResponseWriter, r *http.Request) {
	ifaces, err := capture.ListInterfaces()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"interfaces": ifaces})
}

type startRequest struct {
	Interfaces []string `json:"interfaces"`
	Snaplen    uint32   `json:"snaplen"`
	SampleRate uint32   `json:"sampleRate"`
	RingSize   uint32   `json:"ringSize"`
	Clear      bool     `json:"clear"`
	Cgroup     string   `json:"cgroup,omitempty"`
}

func (s *Server) handleStart(w http.ResponseWriter, r *http.Request) {
	var req startRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(req.Interfaces) == 0 {
		writeError(w, http.StatusBadRequest, "select at least one interface")
		return
	}
	if _, err := capture.ResolveIndexes(req.Interfaces); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var cgroupID uint64
	if req.Cgroup != "" {
		var err error
		cgroupID, err = capture.ResolveCgroup(req.Cgroup)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if req.Clear {
		s.store.Clear()
	}
	err := s.mgr.Start(capture.Options{
		Interfaces: req.Interfaces,
		Snaplen:    req.Snaplen,
		SampleRate: req.SampleRate,
		RingSize:   req.RingSize,
		// Exclude the analyzer's own HTTP API traffic from captures so the UI
		// polling and SSE stream do not feed back into the packet list.
		ExcludePort: uint32(s.selfPort),
		CgroupID:    cgroupID,
	})
	if err != nil {
		s.log.Error("start capture", "err", err)
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.mgr.Status())
}

func (s *Server) handleStop(w http.ResponseWriter, r *http.Request) {
	s.mgr.Stop()
	writeJSON(w, http.StatusOK, s.mgr.Status())
}

func (s *Server) handleClear(w http.ResponseWriter, r *http.Request) {
	s.store.Clear()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// packetJSON is the compact representation streamed to the UI.
type packetsResponse struct {
	Packets []packetJSON `json:"packets"`
	Count   int          `json:"count"`
	Stored  int          `json:"stored"`
}

type packetJSON struct {
	ID        uint64   `json:"id"`
	Time      int64    `json:"time"`
	Iface     string   `json:"iface"`
	Direction string   `json:"direction"`
	Len       uint32   `json:"len"`
	CapLen    uint32   `json:"capLen"`
	Truncated bool     `json:"truncated,omitempty"`
	Protocol  string   `json:"protocol"`
	Layers    []string `json:"layers"`
	Src       string   `json:"src"`
	Dst       string   `json:"dst"`
	SrcPort   uint16   `json:"srcPort,omitempty"`
	DstPort   uint16   `json:"dstPort,omitempty"`
	Info      string   `json:"info"`
	CgroupID  uint64   `json:"cgroupID,omitempty"`
}

func toPacketJSON(p *packet.Packet) packetJSON {
	layers := p.Summary.Layers
	if layers == nil {
		layers = []string{}
	}
	return packetJSON{
		ID:        p.ID,
		Time:      p.Time.UnixNano(),
		Iface:     p.IfName,
		Direction: p.Direction.String(),
		Len:       p.WireLen,
		CapLen:    p.CapLen,
		Truncated: p.Truncated,
		Protocol:  p.Summary.Protocol,
		Layers:    layers,
		Src:       p.Summary.Src,
		Dst:       p.Summary.Dst,
		SrcPort:   p.Summary.SrcPort,
		DstPort:   p.Summary.DstPort,
		Info:      p.Summary.Info,
		CgroupID:  p.CgroupID,
	}
}

func filterExpr(r *http.Request) string {
	expr := r.URL.Query().Get("filter")
	if expr == "" {
		expr = r.URL.Query().Get("q")
	}
	return expr
}

func (s *Server) parseFilter(r *http.Request) (filter.Filter, error) {
	return filter.Parse(filterExpr(r))
}

func (s *Server) handlePackets(w http.ResponseWriter, r *http.Request) {
	flt, err := s.parseFilter(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	limit := intQuery(r, "limit", 2000)
	if limit > 200000 {
		limit = 200000
	}
	pkts := s.store.Snapshot(flt, limit)
	out := make([]packetJSON, 0, len(pkts))
	for _, p := range pkts {
		out = append(out, toPacketJSON(p))
	}
	writeJSON(w, http.StatusOK, packetsResponse{
		Packets: out,
		Count:   len(out),
		Stored:  s.store.Stats().Stored,
	})
}

type detailResponse struct {
	Packet   packetJSON      `json:"packet"`
	Fields   []*decode.Field `json:"fields"`
	Data     string          `json:"data"` // base64 encoded frame bytes
	DataLen  int             `json:"dataLen"`
	LinkType uint32          `json:"linkType"`
}

func (s *Server) cachedDetail(key detailKey) ([]*decode.Field, bool) {
	s.detailMu.Lock()
	defer s.detailMu.Unlock()
	el, ok := s.detailCache[key]
	if !ok {
		return nil, false
	}
	s.detailLRU.MoveToFront(el)
	return decode.CloneFields(el.Value.(*detailEntry).fields), true
}

func (s *Server) putDetail(key detailKey, fields []*decode.Field) {
	const maxEntries = 256
	const maxBytes = 32 << 20
	size := decode.FieldTreeSize(fields)
	s.detailMu.Lock()
	defer s.detailMu.Unlock()
	if el, ok := s.detailCache[key]; ok {
		old := el.Value.(*detailEntry)
		s.detailBytes -= old.bytes
		decode.ReleaseFields(old.fields)
		old.fields, old.bytes = fields, size
		s.detailBytes += size
		s.detailLRU.MoveToFront(el)
		return
	}
	for s.detailLRU.Len() >= maxEntries || s.detailBytes+size > maxBytes {
		old := s.detailLRU.Back()
		if old == nil {
			break
		}
		entry := old.Value.(*detailEntry)
		delete(s.detailCache, entry.key)
		s.detailLRU.Remove(old)
		s.detailBytes -= entry.bytes
		decode.ReleaseFields(entry.fields)
	}
	entry := &detailEntry{key: key, fields: fields, bytes: size}
	s.detailCache[key] = s.detailLRU.PushFront(entry)
	s.detailBytes += size
}

func (s *Server) handlePacketDetail(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid packet id")
		return
	}
	p, ok := s.store.Get(id)
	if !ok {
		writeError(w, http.StatusNotFound, "packet not found (it may have been evicted)")
		return
	}
	key := detailKey{id: p.ID, time: p.Time.UnixNano()}
	fields, ok := s.cachedDetail(key)
	if !ok {
		res := decode.Decode(p.Data, p.LinkType, int(p.WireLen))
		fields = res.Fields
		s.putDetail(key, decode.CloneFields(fields))
	}
	defer decode.ReleaseFields(fields)
	writeJSON(w, http.StatusOK, detailResponse{
		Packet:   toPacketJSON(p),
		Fields:   fields,
		Data:     base64.StdEncoding.EncodeToString(p.Data),
		DataLen:  len(p.Data),
		LinkType: uint32(p.LinkType),
	})
}

type streamDirectionDTO struct {
	From      stream.Endpoint `json:"from"`
	To        stream.Endpoint `json:"to"`
	Bytes     int             `json:"bytes"`
	Truncated bool            `json:"truncated"`
	Gaps      int             `json:"gaps"`
	Data      string          `json:"data"` // base64
}

type streamDTO struct {
	Key   string             `json:"key"`
	A     stream.Endpoint    `json:"a"`
	B     stream.Endpoint    `json:"b"`
	AtoB  streamDirectionDTO `json:"aToB"`
	BtoA  streamDirectionDTO `json:"bToA"`
	First time.Time          `json:"first"`
	Last  time.Time          `json:"last"`
}

func toStreamDirection(d stream.Direction) streamDirectionDTO {
	return streamDirectionDTO{
		From:      d.From,
		To:        d.To,
		Bytes:     d.Bytes,
		Truncated: d.Truncated,
		Gaps:      d.Gaps,
		Data:      base64.StdEncoding.EncodeToString(d.Data),
	}
}

func (s *Server) handlePacketStream(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid packet id")
		return
	}
	p, ok := s.store.Get(id)
	if !ok {
		writeError(w, http.StatusNotFound, "packet not found (it may have been evicted)")
		return
	}
	if !p.Meta.HasLayer("tcp") {
		writeError(w, http.StatusBadRequest, "packet is not TCP")
		return
	}
	snap, ok := s.store.StreamForPacket(p)
	if !ok {
		writeError(w, http.StatusNotFound,
			"no reassembled stream for this packet (no payload captured or stream evicted)")
		return
	}
	writeJSON(w, http.StatusOK, streamDTO{
		Key:   snap.Key,
		A:     snap.A,
		B:     snap.B,
		AtoB:  toStreamDirection(snap.AtoB),
		BtoA:  toStreamDirection(snap.BtoA),
		First: snap.First,
		Last:  snap.Last,
	})
}

func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	flt, err := s.parseFilter(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}

	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache, no-transform")
	h.Set("Connection", "keep-alive")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	sub := s.store.SubscribeKey(flt, filterExpr(r), 4096)
	defer s.store.Unsubscribe(sub)

	fmt.Fprintf(w, "retry: 2000\n\n")
	fmt.Fprintf(w, "event: ready\ndata: {\"subscriber\":%d,\"instance\":%q}\n\n", sub.ID, s.instance)
	flusher.Flush()

	batch := make([]packetJSON, 0, 256)
	var jsonBuf bytes.Buffer
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		payload, err := json.Marshal(batch)
		if err != nil {
			return err
		}
		jsonBuf.Reset()
		jsonBuf.Grow(len(payload) + 16)
		jsonBuf.WriteString(`{"packets":`)
		jsonBuf.Write(payload)
		jsonBuf.WriteByte('}')
		if _, err := fmt.Fprintf(w, "event: packets\ndata: %s\n\n", jsonBuf.Bytes()); err != nil {
			return err
		}
		flusher.Flush()
		batch = batch[:0]
		return nil
	}

	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-heartbeat.C:
			// Do not let an expired session keep streaming packet data.
			if s.auth.Enabled() {
				c, err := r.Cookie(auth.CookieName)
				if err != nil || !s.auth.Valid(c.Value) {
					return
				}
			}
			if _, err := io.WriteString(w, ": ping\n\n"); err != nil {
				return
			}
			flusher.Flush()
		case <-ticker.C:
			if err := flush(); err != nil {
				return
			}
		case p, ok := <-sub.C:
			if !ok {
				return
			}
			batch = append(batch, toPacketJSON(p))
			// Drain quickly to keep up with bursts.
			for len(batch) < 512 {
				select {
				case p2, ok := <-sub.C:
					if !ok {
						_ = flush()
						return
					}
					batch = append(batch, toPacketJSON(p2))
				default:
					goto drained
				}
			}
		drained:
			if len(batch) >= 256 {
				if err := flush(); err != nil {
					return
				}
			}
		}
	}
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.store.Stats())
}

func (s *Server) handleConversations(w http.ResponseWriter, r *http.Request) {
	limit := intQuery(r, "limit", 200)
	flows := s.store.Flows(limit)
	writeJSON(w, http.StatusOK, map[string]any{"flows": flows, "count": len(flows)})
}

type filterRequest struct {
	Filter string `json:"filter"`
}

func (s *Server) handleTrace(w http.ResponseWriter, r *http.Request) {
	limit := intQuery(r, "limit", 500)
	after, _ := strconv.ParseUint(r.URL.Query().Get("after"), 10, 64)
	events, status := s.traceMgr.Events(limit, after)
	writeJSON(w, http.StatusOK, map[string]any{"events": events, "status": status})
}

func (s *Server) handleTraceStart(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PID       int    `json:"pid"`
		Functions string `json:"functions"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.StartTrace(req.PID, req.Functions); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.traceMgr.Status())
}

func (s *Server) handleTraceStop(w http.ResponseWriter, r *http.Request) {
	s.traceMgr.Stop()
	writeJSON(w, http.StatusOK, s.traceMgr.Status())
}

// StartTrace is shared with MCP.
func (s *Server) StartTrace(pid int, functions string) error {
	if pid < 0 {
		return fmt.Errorf("pid must be >= 0")
	}
	fns, err := probe.ParseFunctions(functions)
	if err != nil {
		return err
	}
	return s.traceMgr.Start(pid, fns)
}

func (s *Server) StopTrace()                { s.traceMgr.Stop() }
func (s *Server) TraceStatus() trace.Status { return s.traceMgr.Status() }
func (s *Server) TraceEvents(limit int, after uint64) ([]trace.Event, trace.Status) {
	return s.traceMgr.Events(limit, after)
}

func (s *Server) handleFilterValidate(w http.ResponseWriter, r *http.Request) {
	expr := r.URL.Query().Get("filter")
	if expr == "" {
		var req filterRequest
		if err := readJSON(r, &req); err == nil {
			expr = req.Filter
		}
	}
	if strings.TrimSpace(expr) == "" {
		writeJSON(w, http.StatusOK, map[string]any{"valid": true, "empty": true})
		return
	}
	_, err := filter.Parse(expr)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"valid": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"valid": true})
}

func (s *Server) handleFilterSchema(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"fields": filter.Schema()})
}

func (s *Server) handleFilterFields(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"fields": filter.KnownFields(),
		"protocols": []string{
			"tcp", "udp", "icmp", "icmpv6", "arp", "ip", "ipv6", "dns", "http", "tls", "dhcp", "vlan", "eth",
		},
	})
}

func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	flt, err := s.parseFilter(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	pkts := s.store.All(flt)
	from, to, err := exportTimeRange(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !from.IsZero() || !to.IsZero() {
		filtered := pkts[:0]
		for _, p := range pkts {
			if !from.IsZero() && p.Time.Before(from) {
				continue
			}
			if !to.IsZero() && p.Time.After(to) {
				continue
			}
			filtered = append(filtered, p)
		}
		pkts = filtered
	}
	format := strings.ToLower(r.URL.Query().Get("format"))
	nameExt, contentType := ".pcap", "application/vnd.tcpdump.pcap"
	if format == "pcapng" {
		nameExt, contentType = ".pcapng", "application/x-pcapng"
	}
	name := fmt.Sprintf("ebpfshark-%s%s", time.Now().Format("20060102-150405"), nameExt)
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name))
	w.Header().Set("X-Packet-Count", strconv.Itoa(len(pkts)))
	var writeErr error
	if format == "pcapng" {
		writeErr = pcapio.WriteNG(w, pkts)
	} else {
		writeErr = pcapio.Write(w, pkts)
	}
	if writeErr != nil {
		s.log.Warn("capture export failed", "format", format, "err", writeErr)
	}
}

func exportTimeRange(r *http.Request) (time.Time, time.Time, error) {
	parse := func(key string) (time.Time, error) {
		v := strings.TrimSpace(r.URL.Query().Get(key))
		if v == "" {
			return time.Time{}, nil
		}
		if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
			return t, nil
		}
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return time.Unix(n, 0), nil
		}
		return time.Time{}, fmt.Errorf("invalid %s time %q (use RFC3339 or Unix seconds)", key, v)
	}
	from, err := parse("from")
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	to, err := parse("to")
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	if !from.IsZero() && !to.IsZero() && to.Before(from) {
		return time.Time{}, time.Time{}, fmt.Errorf("to must not be before from")
	}
	return from, to, nil
}

func (s *Server) handleImport(w http.ResponseWriter, r *http.Request) {
	select {
	case s.importLock <- struct{}{}:
		defer func() { <-s.importLock }()
	default:
		writeError(w, http.StatusConflict, "another import is already running")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 512<<20)
	file, _, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "expected a multipart file field named \"file\": "+err.Error())
		return
	}
	defer file.Close()
	data, err := io.ReadAll(file)
	if err != nil {
		writeError(w, http.StatusBadRequest, "read upload: "+err.Error())
		return
	}
	pkts, err := pcapio.Read(data)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	wasRunning := s.mgr.Status().Running
	if wasRunning {
		s.mgr.Stop()
	}
	s.store.Clear()
	start := time.Now()
	for _, p := range pkts {
		if p.Time.IsZero() {
			p.Time = time.Now()
		}
		if p.IfName == "" {
			p.IfName = "import"
		}
		s.store.Add(p)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"imported":       len(pkts),
		"elapsedMs":      time.Since(start).Milliseconds(),
		"captureStopped": wasRunning,
	})
}

// spaHandler serves the embedded UI, falling back to index.html for client
// side routes.
func (s *Server) spaHandler() http.Handler {
	fileServer := http.FileServer(http.FS(s.web))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upath := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if upath == "" || upath == "." {
			upath = "index.html"
		}
		if upath == "index.html" {
			s.serveIndex(w)
			return
		}
		f, err := s.web.Open(upath)
		if err != nil {
			// Client-side route: serve the SPA shell.
			s.serveIndex(w)
			return
		}
		f.Close()
		if ct := mime.TypeByExtension(path.Ext(upath)); ct != "" {
			w.Header().Set("Content-Type", ct)
		}
		if strings.HasPrefix(upath, "assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		}
		fileServer.ServeHTTP(w, r)
	})
}

func (s *Server) serveIndex(w http.ResponseWriter) {
	index, err := fs.ReadFile(s.web, "index.html")
	if err != nil {
		writeError(w, http.StatusNotFound, "web UI not built (run `make web`)")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(index)
}

// ---------------------------------------------------------------- helpers

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"error": msg})
}

func readJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return fmt.Errorf("invalid JSON body: %w", err)
	}
	return nil
}

func intQuery(r *http.Request, key string, def int) int {
	v := r.URL.Query().Get(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return def
	}
	return n
}

func withMiddleware(next http.Handler, log *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		defer func() {
			if rec := recover(); rec != nil {
				log.Error("panic serving request", "path", r.URL.Path, "panic", rec)
				writeError(w, http.StatusInternalServerError, "internal server error")
			}
			if !strings.HasPrefix(r.URL.Path, "/api/stream") {
				log.Debug("http", "method", r.Method, "path", r.URL.Path, "dur", time.Since(start))
			}
		}()

		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Cache-Control", "no-store")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
