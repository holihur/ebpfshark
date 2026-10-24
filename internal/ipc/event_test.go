package ipc

import (
	"encoding/json"
	"testing"
	"time"
)

func TestStoreAggregatesStreams(t *testing.T) {
	st := NewStore(3)
	now := time.Unix(100, 0)
	st.Add(Event{Time: now, Inode: 42, PID: 7, Comm: "svc", Direction: Send, Type: "stream", Payload: []byte("abc")})
	st.Add(Event{Time: now.Add(time.Second), Inode: 42, PID: 7, Comm: "svc", Direction: Receive, Type: "stream", Payload: []byte("hello")})

	streams := st.Streams()
	if len(streams) != 1 {
		t.Fatalf("streams = %d, want 1", len(streams))
	}
	s := streams[0]
	if s.Inode != 42 || s.BytesOut != 3 || s.BytesIn != 5 || s.Events != 2 {
		t.Fatalf("unexpected stream: %+v", s)
	}
	if s.Key != "42" || s.Path != "" || s.Type != "stream" {
		t.Fatalf("unexpected stream metadata: %+v", s)
	}
	st.SetSocketMeta(42, "/tmp/svc.sock", "stream", 8, "other")
	s = st.Streams()[0]
	if s.Path != "/tmp/svc.sock" || s.PID != 8 || s.Comm != "other" {
		t.Fatalf("metadata not applied: %+v", s)
	}
}

func TestStoreBoundsEventsAndKeepsIDsMonotonic(t *testing.T) {
	st := NewStore(2)
	for i := 0; i < 4; i++ {
		st.Add(Event{Time: time.Unix(int64(i), 0), Inode: uint64(i + 1), Direction: Send, Payload: []byte{byte(i)}})
	}
	events := st.Events()
	if len(events) != 2 {
		t.Fatalf("events = %d, want 2", len(events))
	}
	if events[0].ID != 3 || events[1].ID != 4 {
		t.Fatalf("unexpected retained IDs: %d %d", events[0].ID, events[1].ID)
	}
	if got := st.EventsAfter(2, 10); len(got) != 2 || got[0].ID != 3 || got[1].ID != 4 {
		t.Fatalf("EventsAfter(2) = %+v", got)
	}
	if got := st.EventsAfter(0, 1); len(got) != 1 || got[0].ID != 3 {
		t.Fatalf("EventsAfter(0,1) = %+v", got)
	}
	st.Reset()
	if len(st.Events()) != 0 || len(st.Streams()) != 0 {
		t.Fatal("reset did not clear the store")
	}
	ev := st.Add(Event{Inode: 99, Direction: Send})
	if ev.ID != 5 {
		t.Fatalf("id after reset = %d, want 5", ev.ID)
	}
}

func TestEventDirectionJSON(t *testing.T) {
	b, err := json.Marshal(Event{Direction: Receive})
	if err != nil {
		t.Fatal(err)
	}
	var decoded Event
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Direction != Receive {
		t.Fatalf("direction = %v, want receive", decoded.Direction)
	}
	var legacy Direction
	if err := json.Unmarshal([]byte("0"), &legacy); err != nil || legacy != Send {
		t.Fatalf("legacy direction = %v, %v", legacy, err)
	}
}
