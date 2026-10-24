package ipc

import (
	"encoding/json"
	"sort"
	"strconv"
	"sync"
	"time"
)

// Direction is relative to the process owning the socket.
type Direction uint8

const (
	Send Direction = iota
	Receive
)

// String returns a stable lowercase direction name for APIs and the UI.
func (d Direction) String() string {
	if d == Receive {
		return "receive"
	}
	return "send"
}

// MarshalJSON emits direction as "send"/"receive" rather than a numeric enum.
func (d Direction) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.String())
}

// UnmarshalJSON accepts both the string form and the legacy numeric form.
func (d *Direction) UnmarshalJSON(b []byte) error {
	if len(b) > 0 && b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		if s == "receive" || s == "recv" {
			*d = Receive
		} else {
			*d = Send
		}
		return nil
	}
	var n uint8
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	*d = Direction(n)
	return nil
}

// Event is one payload chunk read from a Unix-domain socket.
type Event struct {
	ID        uint64    `json:"id"`
	Time      time.Time `json:"time"`
	Inode     uint64    `json:"inode"`
	PID       uint32    `json:"pid"`
	TID       uint32    `json:"tid"`
	CgroupID  uint64    `json:"cgroupID,omitempty"`
	Comm      string    `json:"comm,omitempty"`
	Direction Direction `json:"direction"`
	Type      string    `json:"type,omitempty"`
	TypeCode  uint8     `json:"-"`
	Path      string    `json:"path,omitempty"`
	Part      uint8     `json:"part"`
	Parts     uint8     `json:"parts,omitempty"`
	Truncated bool      `json:"truncated,omitempty"`
	Payload   []byte    `json:"payload,omitempty"`
}

// Stream is a bounded bidirectional Unix-socket conversation. BytesIn counts
// payload received by the owning process; BytesOut counts payload it sent.
type Stream struct {
	Key       string    `json:"key"`
	Inode     uint64    `json:"inode"`
	PID       uint32    `json:"pid"`
	Comm      string    `json:"comm,omitempty"`
	Type      string    `json:"type,omitempty"`
	Path      string    `json:"path,omitempty"`
	First     time.Time `json:"first"`
	Last      time.Time `json:"last"`
	BytesIn   uint64    `json:"bytesIn"`
	BytesOut  uint64    `json:"bytesOut"`
	Events    uint64    `json:"events"`
	Truncated bool      `json:"truncated"`
}

// Stats describes the bounded userspace IPC store.
type Stats struct {
	Events  int    `json:"events"`
	Streams int    `json:"streams"`
	Total   uint64 `json:"total"`
	Bytes   uint64 `json:"bytes"`
}

// Store keeps recent IPC events/streams independent of the network store.
// IDs are monotonic so clients can poll with after=<last id>. The event ring
// and stream table are both bounded.
type Store struct {
	mu         sync.Mutex
	max        int
	maxStreams int
	events     []Event
	streams    map[uint64]*Stream
	order      []uint64
	nextID     uint64
	total      uint64
	bytes      uint64
}

// NewStore creates an event store retaining at most maxEvents payload chunks.
func NewStore(maxEvents int) *Store {
	if maxEvents <= 0 {
		maxEvents = 5000
	}
	return &Store{
		max:        maxEvents,
		maxStreams: 4096,
		streams:    make(map[uint64]*Stream),
	}
}

// Add appends an event and updates its stream. It returns the event with its
// assigned ID. The caller may reuse or mutate ev.Payload afterwards; callers
// that need ownership must copy it before calling Add.
func (s *Store) Add(ev Event) Event {
	s.mu.Lock()
	defer s.mu.Unlock()

	if ev.ID == 0 {
		s.nextID++
		ev.ID = s.nextID
	} else if ev.ID > s.nextID {
		s.nextID = ev.ID
	}
	if ev.Time.IsZero() {
		ev.Time = time.Now()
	}
	if ev.Type == "" {
		ev.Type = socketTypeName(ev.TypeCode)
	}
	s.total++
	s.bytes += uint64(len(ev.Payload))
	s.events = append(s.events, ev)
	if len(s.events) > s.max {
		s.events = append([]Event(nil), s.events[len(s.events)-s.max:]...)
	}

	st := s.streams[ev.Inode]
	if st == nil {
		st = &Stream{Key: strconv.FormatUint(ev.Inode, 10), Inode: ev.Inode}
		s.streams[ev.Inode] = st
		s.order = append(s.order, ev.Inode)
		for len(s.order) > s.maxStreams {
			old := s.order[0]
			s.order = s.order[1:]
			delete(s.streams, old)
		}
	}
	if st.First.IsZero() {
		st.First = ev.Time
	}
	st.Last = ev.Time
	if ev.PID != 0 {
		st.PID = ev.PID
	}
	if ev.Comm != "" {
		st.Comm = ev.Comm
	}
	if ev.Type != "" {
		st.Type = ev.Type
	}
	if ev.Path != "" {
		st.Path = ev.Path
	}
	st.Events++
	if ev.Direction == Send {
		st.BytesOut += uint64(len(ev.Payload))
	} else {
		st.BytesIn += uint64(len(ev.Payload))
	}
	st.Truncated = st.Truncated || ev.Truncated
	return ev
}

// SetSocketMeta fills in inventory metadata for an inode, including for
// streams that were created before the owner could be resolved.
func (s *Store) SetSocketMeta(inode uint64, path, typ string, pid uint32, comm string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.streams[inode]
	if st == nil {
		return
	}
	if path != "" {
		st.Path = path
	}
	if typ != "" {
		st.Type = typ
	}
	if pid != 0 {
		st.PID = pid
	}
	if comm != "" {
		st.Comm = comm
	}
}

// Events returns a copy of all retained events, oldest first.
func (s *Store) Events() []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Event(nil), s.events...)
}

// EventsAfter returns at most limit events with ID greater than after.
func (s *Store) EventsAfter(after uint64, limit int) []Event {
	if limit <= 0 || limit > 5000 {
		limit = 500
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Event, 0, limit)
	for _, ev := range s.events {
		if ev.ID <= after {
			continue
		}
		out = append(out, ev)
		if len(out) >= limit {
			break
		}
	}
	return out
}

// Streams returns streams ordered by most recent activity.
func (s *Store) Streams() []Stream {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Stream, 0, len(s.streams))
	for _, st := range s.streams {
		out = append(out, *st)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Last.Equal(out[j].Last) {
			return out[i].Last.After(out[j].Last)
		}
		return out[i].Inode > out[j].Inode
	})
	return out
}

// SocketMeta returns the best-known path/type for an inode, if a stream has
// been observed for it.
func (s *Store) SocketMeta(inode uint64) (path, typ string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if st := s.streams[inode]; st != nil {
		return st.Path, st.Type
	}
	return "", ""
}

// Stats returns counters for the current store.
func (s *Store) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Stats{Events: len(s.events), Streams: len(s.streams), Total: s.total, Bytes: s.bytes}
}

// Reset clears payloads and streams. The ID sequence is intentionally not
// reset so polling clients do not silently miss new events.
func (s *Store) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = nil
	s.streams = make(map[uint64]*Stream)
	s.order = nil
	s.total = 0
	s.bytes = 0
}
