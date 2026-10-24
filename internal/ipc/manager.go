package ipc

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"
)

const metaRefreshInterval = 10 * time.Second

// Status describes the current or last UDS tracing session.
type Status struct {
	Running       bool        `json:"running"`
	PID           int         `json:"pid"`
	CgroupID      uint64      `json:"cgroupID,omitempty"`
	MaxPayload    uint32      `json:"maxPayload"`
	RingSize      uint32      `json:"ringSize"`
	StartedAt     time.Time   `json:"startedAt,omitempty"`
	UptimeSeconds float64     `json:"uptimeSeconds"`
	Store         Stats       `json:"store"`
	Kernel        KernelStats `json:"kernel"`
	AttachErrors  []string    `json:"attachErrors,omitempty"`
	LastError     string      `json:"lastError,omitempty"`
}

// Manager owns the UDS tracing lifecycle and the bounded event store. The HTTP
// API, MCP tools and UI share this single manager.
type Manager struct {
	log   *slog.Logger
	store *Store

	lifecycle sync.Mutex
	mu        sync.Mutex
	tracer    *Tracer
	opts      TraceOptions
	running   bool
	started   time.Time
	errText   string
	lastKern  KernelStats
	metaDone  chan struct{}
	wg        sync.WaitGroup

	defaultLogPath string
	logFile        *os.File

	metaMu sync.Mutex
	meta   map[uint64]Socket
}

// NewManager creates an idle UDS manager with a 20k-event store.
func NewManager(log *slog.Logger) *Manager {
	if log == nil {
		log = slog.Default()
	}
	return &Manager{
		log: log, store: NewStore(20000), meta: make(map[uint64]Socket),
		opts: NormalizeTraceOptions(TraceOptions{}),
	}
}

// Store exposes the bounded event/stream store for read-only queries and tests.
func (m *Manager) Store() *Store { return m.store }

// SetLogPath sets the default JSONL append log for future tracing sessions.
// It is intended for operator configuration (CLI/env), not the HTTP API.
func (m *Manager) SetLogPath(path string) {
	m.mu.Lock()
	m.defaultLogPath = path
	m.mu.Unlock()
}

// Start replaces any running UDS session.
func (m *Manager) Start(opts TraceOptions) error {
	m.lifecycle.Lock()
	defer m.lifecycle.Unlock()
	m.stopLocked()
	opts = NormalizeTraceOptions(opts)

	// Resolve the initial inode -> process/path map before enabling probes so
	// the common case has metadata immediately. New inodes are refreshed by
	// the background monitor.
	m.refreshSockets()

	m.mu.Lock()
	logPath := opts.LogPath
	if logPath == "" {
		logPath = m.defaultLogPath
	}
	m.mu.Unlock()
	var logFile *os.File
	var logEnc *json.Encoder
	if logPath != "" {
		f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return fmt.Errorf("open IPC event log: %w", err)
		}
		logFile = f
		logEnc = json.NewEncoder(f)
	}

	tracer, err := StartTracer(opts)
	if err != nil && logFile != nil {
		_ = logFile.Close()
	}
	m.mu.Lock()
	m.opts = opts
	m.running = err == nil
	m.errText = ""
	m.started = time.Now()
	if tracer != nil {
		m.tracer = tracer
		m.errText = tracer.LastError()
	}
	if err != nil {
		m.errText = err.Error()
		m.running = false
		m.mu.Unlock()
		return err
	}
	m.logFile = logFile
	done := make(chan struct{})
	m.metaDone = done
	m.mu.Unlock()

	// A new session starts with a clean event/stream window. IDs stay
	// monotonic so polling clients can continue from their previous cursor.
	m.store.Reset()

	m.wg.Add(2)
	go m.readLoop(tracer, logEnc)
	go m.monitorSockets(done)
	m.log.Info("uds tracing started", "pid", opts.PID, "cgroupID", opts.CgroupID,
		"maxPayload", opts.MaxPayload, "ringSize", opts.RingSize)
	return nil
}

// Stop ends the current UDS session. It is safe to call when idle.
func (m *Manager) Stop() {
	m.lifecycle.Lock()
	defer m.lifecycle.Unlock()
	m.stopLocked()
}

func (m *Manager) stopLocked() {
	m.mu.Lock()
	tracer := m.tracer
	done := m.metaDone
	m.tracer = nil
	m.metaDone = nil
	wasRunning := m.running
	m.running = false
	m.mu.Unlock()

	if !wasRunning && tracer == nil {
		return
	}
	if done != nil {
		close(done)
	}
	if tracer != nil {
		m.lastKern = tracer.Stats()
		_ = tracer.Close()
	}
	m.wg.Wait()
	m.mu.Lock()
	logFile := m.logFile
	m.logFile = nil
	m.mu.Unlock()
	if logFile != nil {
		_ = logFile.Close()
	}
	m.log.Info("uds tracing stopped")
}

// Clear drops retained events and streams without stopping the session.
func (m *Manager) Clear() { m.store.Reset() }

// Status returns a snapshot of the current or last session.
func (m *Manager) Status() Status {
	m.mu.Lock()
	tracer := m.tracer
	st := Status{
		Running:      m.running,
		PID:          m.opts.PID,
		CgroupID:     m.opts.CgroupID,
		MaxPayload:   m.opts.MaxPayload,
		RingSize:     m.opts.RingSize,
		StartedAt:    m.started,
		Store:        m.store.Stats(),
		Kernel:       m.lastKern,
		LastError:    m.errText,
		AttachErrors: nil,
	}
	if m.running {
		st.UptimeSeconds = time.Since(m.started).Seconds()
	}
	m.mu.Unlock()
	if tracer != nil {
		st.Kernel = tracer.Stats()
		st.AttachErrors = tracer.AttachErrors()
		if err := tracer.LastError(); err != "" {
			st.LastError = err
		}
	}
	return st
}

// Events returns at most limit events with id greater than after. Events that
// arrived before their socket metadata was refreshed are enriched on read.
func (m *Manager) Events(limit int, after uint64) []Event {
	events := m.store.EventsAfter(after, limit)
	for i := range events {
		if events[i].Path != "" && events[i].Type != "" {
			continue
		}
		path, typ := m.store.SocketMeta(events[i].Inode)
		if events[i].Path == "" {
			events[i].Path = path
		}
		if events[i].Type == "" {
			events[i].Type = typ
		}
	}
	return events
}

// Streams returns recent streams, most active first.
func (m *Manager) Streams(limit int) []Stream {
	streams := m.store.Streams()
	if limit > 0 && len(streams) > limit {
		streams = streams[:limit]
	}
	return streams
}

func (m *Manager) readLoop(tracer *Tracer, logEnc *json.Encoder) {
	defer m.wg.Done()
	for ev := range tracer.Events() {
		m.applyMeta(&ev)
		ev = m.store.Add(ev)
		if logEnc != nil {
			_ = logEnc.Encode(ev)
		}
	}
}

func (m *Manager) monitorSockets(done <-chan struct{}) {
	defer m.wg.Done()
	ticker := time.NewTicker(metaRefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			m.refreshSockets()
		}
	}
}

func (m *Manager) refreshSockets() {
	sockets, err := ListSockets()
	if err != nil {
		m.log.Debug("uds inventory refresh failed", "err", err)
		return
	}
	next := make(map[uint64]Socket, len(sockets))
	for _, s := range sockets {
		next[s.Inode] = s
		m.store.SetSocketMeta(s.Inode, s.Path, s.Type, uint32(s.PID), s.Comm)
	}
	m.metaMu.Lock()
	m.meta = next
	m.metaMu.Unlock()
}

func (m *Manager) applyMeta(ev *Event) {
	m.metaMu.Lock()
	s, ok := m.meta[ev.Inode]
	m.metaMu.Unlock()
	if !ok {
		return
	}
	if ev.Path == "" {
		ev.Path = s.Path
	}
	if ev.Type == "" {
		ev.Type = s.Type
	}
	if ev.PID == 0 && s.PID > 0 {
		ev.PID = uint32(s.PID)
	}
	if ev.Comm == "" {
		ev.Comm = s.Comm
	}
}

// ResolvePID is a small helper used by API handlers that accept pid:N.
func ResolvePID(raw string) (int, error) {
	var pid int
	if _, err := fmt.Sscanf(raw, "%d", &pid); err != nil || pid < 0 {
		return 0, fmt.Errorf("invalid pid %q", raw)
	}
	return pid, nil
}

// The IPC* methods let Manager satisfy the MCP controller contract directly.
// The HTTP server exposes the same operations for the browser API.

// IPCStatus returns the current tracing status.
func (m *Manager) IPCStatus() Status { return m.Status() }

// IPCSockets enumerates Unix-domain sockets.
func (m *Manager) IPCSockets() ([]Socket, error) { return ListSockets() }

// IPCEvents returns recent payload events.
func (m *Manager) IPCEvents(limit int, after uint64) []Event { return m.Events(limit, after) }

// IPCStreams returns recent bidirectional streams.
func (m *Manager) IPCStreams(limit int) []Stream { return m.Streams(limit) }

// StartIPC starts a tracing session.
func (m *Manager) StartIPC(opts TraceOptions) error { return m.Start(opts) }

// ClearIPC clears retained events and streams.
func (m *Manager) ClearIPC() { m.Clear() }

// StopIPC stops the current tracing session.
func (m *Manager) StopIPC() { m.Stop() }
