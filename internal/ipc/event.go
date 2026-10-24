package ipc

import (
	"sync"
	"time"
)

// Direction is relative to the process owning the socket.
type Direction uint8

const (
	Send Direction = iota
	Receive
)

// Event is one payload chunk read from a Unix-domain socket.
type Event struct {
	Time      time.Time
	Inode     uint64
	PID       uint32
	TID       uint32
	CgroupID  uint64
	Comm      string
	Direction Direction
	Payload   []byte
}

// Stream is a bounded bidirectional Unix-socket conversation.
type Stream struct {
	Key       string    `json:"key"`
	Inode     uint64    `json:"inode"`
	PID       uint32    `json:"pid"`
	Comm      string    `json:"comm"`
	Path      string    `json:"path,omitempty"`
	First     time.Time `json:"first"`
	Last      time.Time `json:"last"`
	BytesIn   uint64    `json:"bytesIn"`
	BytesOut  uint64    `json:"bytesOut"`
	Truncated bool      `json:"truncated"`
}

// Store keeps recent IPC events/streams independent of the network store.
type Store struct {
	mu      sync.Mutex
	max     int
	events  []Event
	streams map[string]*Stream
	order   []string
}

func NewStore(maxEvents int) *Store {
	if maxEvents <= 0 {
		maxEvents = 5000
	}
	return &Store{max: maxEvents, streams: make(map[string]*Stream)}
}

func (s *Store) Add(ev Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, ev)
	if len(s.events) > s.max {
		s.events = append([]Event(nil), s.events[len(s.events)-s.max:]...)
	}
	key := ev.Comm + "|" + itoa(ev.Inode)
	st := s.streams[key]
	if st == nil {
		st = &Stream{Key: key, Inode: ev.Inode, PID: ev.PID, Comm: ev.Comm, First: ev.Time}
		s.streams[key] = st
		s.order = append(s.order, key)
		if len(s.order) > 2048 {
			delete(s.streams, s.order[0])
			s.order = s.order[1:]
		}
	}
	st.Last = ev.Time
	if ev.Direction == Send {
		st.BytesIn += uint64(len(ev.Payload))
	} else {
		st.BytesOut += uint64(len(ev.Payload))
	}
}

func (s *Store) Events() []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Event(nil), s.events...)
}

func (s *Store) Streams() []Stream {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Stream, 0, len(s.streams))
	for _, st := range s.streams {
		out = append(out, *st)
	}
	return out
}

func itoa(v uint64) string {
	if v == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}
