package ipc

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestTracerCapturesUnixStream(t *testing.T) {
	if os.Getenv("EBPFSHARK_PRIVILEGED") != "1" {
		t.Skip("set EBPFSHARK_PRIVILEGED=1 to load eBPF programs")
	}
	tr, err := StartTracer(TraceOptions{PID: os.Getpid(), MaxPayload: 1024})
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()

	path := filepath.Join(t.TempDir(), "uds.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 64)
		_, _ = c.Read(buf)
		_, _ = c.Write([]byte("reply"))
	}()
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("hello-uds")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _ = c.Read(buf)
	<-done

	deadline := time.After(3 * time.Second)
	var gotSend, gotRecv bool
	for !(gotSend && gotRecv) {
		select {
		case ev := <-tr.Events():
			if string(ev.Payload) == "hello-uds" && ev.Direction == Send {
				gotSend = true
			}
			if string(ev.Payload) == "hello-uds" && ev.Direction == Receive {
				gotRecv = true
			}
		case <-deadline:
			// Receive-side capture is best effort across kernel versions.
			if gotSend {
				return
			}
			t.Fatalf("did not capture UDS payload (send=%v recv=%v)", gotSend, gotRecv)
		}
	}
}

func startTestTracer(t *testing.T) *Tracer {
	t.Helper()
	if os.Getenv("EBPFSHARK_PRIVILEGED") != "1" {
		t.Skip("set EBPFSHARK_PRIVILEGED=1 to load eBPF programs")
	}
	tr, err := StartTracer(TraceOptions{PID: os.Getpid(), MaxPayload: 4096})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tr.Close() })
	return tr
}

func collectEvents(t *testing.T, tr *Tracer, want func(Event) bool, timeout time.Duration) []Event {
	t.Helper()
	var out []Event
	deadline := time.After(timeout)
	for !want(Event{}) {
		select {
		case ev, ok := <-tr.Events():
			if !ok {
				return out
			}
			out = append(out, ev)
		case <-deadline:
			return out
		}
	}
	return out
}

func TestTracerCapturesDatagramAndSeqpacket(t *testing.T) {
	for _, family := range []struct {
		name string
		typ  int
	}{
		{"dgram", unix.SOCK_DGRAM},
		{"seqpacket", unix.SOCK_SEQPACKET},
	} {
		t.Run(family.name, func(t *testing.T) {
			tr := startTestTracer(t)
			fds, err := unix.Socketpair(unix.AF_UNIX, family.typ, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(fds[0])
			defer unix.Close(fds[1])

			payload := []byte("hello-" + family.name)
			if _, err := unix.Write(fds[0], payload); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 128)
			if _, err := unix.Read(fds[1], buf); err != nil {
				t.Fatal(err)
			}

			var send, recv bool
			deadline := time.After(3 * time.Second)
			for !(send && recv) {
				select {
				case ev := <-tr.Events():
					if string(ev.Payload) != string(payload) {
						continue
					}
					if ev.Direction == Send {
						send = true
					}
					if ev.Direction == Receive {
						recv = true
					}
				case <-deadline:
					t.Fatalf("missing %s events (send=%v recv=%v), attach errors=%v", family.name, send, recv, tr.AttachErrors())
				}
			}
		})
	}
}

func TestTracerCapturesMultiIovec(t *testing.T) {
	tr := startTestTracer(t)
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])

	parts := [][]byte{[]byte("abc"), []byte("def"), []byte("ghi")}
	if _, err := unix.Writev(fds[0], parts); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 32)
	if _, err := unix.Read(fds[1], buf); err != nil {
		t.Fatal(err)
	}

	got := map[uint8]string{}
	deadline := time.After(3 * time.Second)
	for len(got) < len(parts) {
		select {
		case ev := <-tr.Events():
			if ev.Direction == Send && ev.Parts >= uint8(len(parts)) {
				got[ev.Part] = string(ev.Payload)
			}
		case <-deadline:
			t.Fatalf("missing iovec events: %#v (attach errors=%v)", got, tr.AttachErrors())
		}
	}
	for i, part := range parts {
		if got[uint8(i)] != string(part) {
			t.Fatalf("part %d = %q, want %q (all=%#v)", i, got[uint8(i)], part, got)
		}
	}
}

func TestTracerCapturesDatagramMultiIovecReceive(t *testing.T) {
	tr := startTestTracer(t)
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])

	parts := [][]byte{[]byte("one"), []byte("two"), []byte("three")}
	if _, err := unix.Writev(fds[0], parts); err != nil {
		t.Fatal(err)
	}
	bufs := [][]byte{make([]byte, 3), make([]byte, 3), make([]byte, 5)}
	if _, err := unix.Readv(fds[1], bufs); err != nil {
		t.Fatal(err)
	}
	if string(bufs[0]) != "one" || string(bufs[1]) != "two" || string(bufs[2]) != "three" {
		t.Fatalf("unexpected readv buffers: %q", bufs)
	}

	sendParts := map[uint8]string{}
	recvParts := map[uint8]string{}
	deadline := time.After(3 * time.Second)
	for len(sendParts) < len(parts) || len(recvParts) < len(parts) {
		select {
		case ev := <-tr.Events():
			if ev.Parts < uint8(len(parts)) {
				continue
			}
			if ev.Direction == Send {
				sendParts[ev.Part] = string(ev.Payload)
			} else {
				recvParts[ev.Part] = string(ev.Payload)
			}
		case <-deadline:
			t.Fatalf("missing segmented events: send=%#v recv=%#v attach=%v", sendParts, recvParts, tr.AttachErrors())
		}
	}
	for i, part := range parts {
		if sendParts[uint8(i)] != string(part) || recvParts[uint8(i)] != string(part) {
			t.Fatalf("part %d: send=%q recv=%q want=%q", i, sendParts[uint8(i)], recvParts[uint8(i)], part)
		}
	}
}

func TestTracerBurst(t *testing.T) {
	tr := startTestTracer(t)
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])

	const messages = 200
	payloadLen := len(fmt.Sprintf("m-%04d\n", 0))
	readDone := make(chan error, 1)
	go func() {
		buf := make([]byte, 4096)
		remaining := 0
		for remaining < messages*payloadLen {
			n, err := unix.Read(fds[1], buf)
			if err != nil {
				readDone <- err
				return
			}
			remaining += n
		}
		readDone <- nil
	}()
	for i := 0; i < messages; i++ {
		payload := []byte(fmt.Sprintf("m-%04d\n", i))
		if _, err := unix.Write(fds[0], payload); err != nil {
			t.Fatal(err)
		}
	}
	if err := <-readDone; err != nil {
		t.Fatal(err)
	}

	seen := make(map[string]bool, messages)
	deadline := time.After(5 * time.Second)
	for len(seen) < messages {
		select {
		case ev := <-tr.Events():
			if ev.Direction == Send && len(ev.Payload) == payloadLen {
				seen[string(ev.Payload)] = true
			}
		case <-deadline:
			t.Fatalf("captured %d/%d burst send events (attach errors=%v)", len(seen), messages, tr.AttachErrors())
		}
	}
}

func TestManagerPersistsEventLog(t *testing.T) {
	if os.Getenv("EBPFSHARK_PRIVILEGED") != "1" {
		t.Skip("set EBPFSHARK_PRIVILEGED=1 to load eBPF programs")
	}
	logPath := filepath.Join(t.TempDir(), "ipc.jsonl")
	m := NewManager(nil)
	m.SetLogPath(logPath)
	if err := m.Start(TraceOptions{PID: os.Getpid(), MaxPayload: 1024}); err != nil {
		t.Fatal(err)
	}
	defer m.Stop()

	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])
	if _, err := unix.Write(fds[0], []byte("persist-me")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 32)
	if _, err := unix.Read(fds[1], buf); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		data, _ := os.ReadFile(logPath)
		if strings.Contains(string(data), "persist-me") || strings.Contains(string(data), "cGVyc2lzdC1tZQ==") {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	data, _ := os.ReadFile(logPath)
	t.Fatalf("event log did not contain the payload; %d bytes: %s", len(data), data)
}
