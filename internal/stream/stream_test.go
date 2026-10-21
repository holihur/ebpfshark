package stream

import (
	"net/netip"
	"testing"
	"time"

	"ebpfshark/internal/packet"
)

func tcpPacket(srcIP string, srcPort uint16, dstIP string, dstPort uint16, seq uint32, flags uint8, payload string) *packet.Packet {
	return &packet.Packet{
		Time: time.Unix(0, int64(seq)*int64(time.Millisecond)),
		Meta: packet.Meta{
			Layers:     []string{"eth", "ip", "tcp"},
			SrcIP:      netip.MustParseAddr(srcIP),
			DstIP:      netip.MustParseAddr(dstIP),
			SrcPort:    srcPort,
			DstPort:    dstPort,
			TCPSeq:     seq,
			TCPFlags:   flags,
			TCPPayload: []byte(payload),
		},
	}
}

func TestReassembleInOrder(t *testing.T) {
	m := NewManager(DefaultBudget)
	client, server := "10.0.0.1", "10.0.0.2"
	m.Add(tcpPacket(client, 12345, server, 80, 100, 0x02, "")) // SYN
	m.Add(tcpPacket(client, 12345, server, 80, 101, 0x18, "Hello "))
	m.Add(tcpPacket(client, 12345, server, 80, 107, 0x18, "world"))
	last := tcpPacket(client, 12345, server, 80, 112, 0x18, "!")
	m.Add(last)

	snap, ok := m.ForPacket(last)
	if !ok {
		t.Fatal("stream not found")
	}
	if got := string(snap.AtoB.Data); got != "Hello world!" {
		t.Fatalf("AtoB = %q", got)
	}
	if snap.BtoA.Bytes != 0 {
		t.Fatalf("BtoA bytes = %d", snap.BtoA.Bytes)
	}
	if snap.A.IP != client || snap.A.Port != 12345 || snap.B.IP != server || snap.B.Port != 80 {
		t.Fatalf("unexpected endpoints: %+v -> %+v", snap.A, snap.B)
	}
}

func TestOutOfOrderAndRetransmit(t *testing.T) {
	m := NewManager(DefaultBudget)
	c, s := "10.0.0.1", "10.0.0.2"
	m.Add(tcpPacket(c, 1234, s, 443, 100, 0x02, ""))
	m.Add(tcpPacket(c, 1234, s, 443, 112, 0x18, "!!!")) // out of order
	m.Add(tcpPacket(c, 1234, s, 443, 101, 0x18, "Hello "))
	m.Add(tcpPacket(c, 1234, s, 443, 107, 0x18, "world"))
	m.Add(tcpPacket(c, 1234, s, 443, 101, 0x18, "Hello ")) // retransmission

	snap, ok := m.Get("tcp|10.0.0.1|1234|10.0.0.2|443")
	if !ok {
		t.Fatal("stream not found")
	}
	if got := string(snap.AtoB.Data); got != "Hello world!!!" {
		t.Fatalf("AtoB = %q", got)
	}
	if snap.AtoB.Gaps != 0 || snap.AtoB.Truncated {
		t.Fatalf("unexpected flags: %+v", snap.AtoB)
	}
}

func TestGaps(t *testing.T) {
	m := NewManager(DefaultBudget)
	c, s := "10.0.0.1", "10.0.0.2"
	m.Add(tcpPacket(c, 1, s, 2, 100, 0x02, ""))
	m.Add(tcpPacket(c, 1, s, 2, 101, 0x18, "A"))
	m.Add(tcpPacket(c, 1, s, 2, 104, 0x18, "B"))
	m.Add(tcpPacket(c, 1, s, 2, 110, 0x18, "C"))

	snap, _ := m.Get("tcp|10.0.0.1|1|10.0.0.2|2")
	if got := string(snap.AtoB.Data); got != "A" {
		t.Fatalf("data = %q", got)
	}
	if snap.AtoB.Gaps != 2 {
		t.Fatalf("gaps = %d", snap.AtoB.Gaps)
	}

	m.Add(tcpPacket(c, 1, s, 2, 102, 0x18, "xx")) // fill A?xxB
	snap, _ = m.Get("tcp|10.0.0.1|1|10.0.0.2|2")
	if got := string(snap.AtoB.Data); got != "AxxB" {
		t.Fatalf("data = %q", got)
	}
	if snap.AtoB.Gaps != 1 {
		t.Fatalf("gaps = %d", snap.AtoB.Gaps)
	}
}

func TestReverseDirection(t *testing.T) {
	m := NewManager(DefaultBudget)
	c, s := "10.0.0.1", "10.0.0.2"
	m.Add(tcpPacket(c, 5555, s, 8080, 1000, 0x18, "req"))
	m.Add(tcpPacket(s, 8080, c, 5555, 9000, 0x18, "resp"))

	snap, ok := m.Get("tcp|10.0.0.1|5555|10.0.0.2|8080")
	if !ok {
		t.Fatal("stream not found")
	}
	if string(snap.AtoB.Data) != "req" || string(snap.BtoA.Data) != "resp" {
		t.Fatalf("directions: %q / %q", snap.AtoB.Data, snap.BtoA.Data)
	}
}

func TestAssemblerTruncation(t *testing.T) {
	a := newAssembler(5)
	a.start(1)
	a.add(1, []byte("abcdefgh"))
	if got := string(a.buf); got != "abcde" {
		t.Fatalf("buf = %q", got)
	}
	if !a.truncated {
		t.Fatal("expected truncation")
	}
	a.add(6, []byte("fgh"))
	if got := string(a.buf); got != "abcde" {
		t.Fatalf("buf after truncation = %q", got)
	}
}

func TestStatsAndReset(t *testing.T) {
	m := NewManager(DefaultBudget)
	m.Add(tcpPacket("10.0.0.1", 1, "10.0.0.2", 2, 100, 0x18, "hello"))
	st := m.Stats()
	if st.Flows != 1 || st.Bytes < 5 {
		t.Fatalf("stats = %+v", st)
	}
	m.Reset()
	if st := m.Stats(); st.Flows != 0 || st.Bytes != 0 {
		t.Fatalf("stats after reset = %+v", st)
	}
}

func TestEviction(t *testing.T) {
	m := NewManager(4 << 20)
	// dirLimit is 256 KiB for the minimum budget. Two directions per flow and
	// many flows should force eviction once the budget is exceeded.
	chunk := make([]byte, 200<<10)
	for i := 0; i < 30; i++ {
		src := "10.0." + string(rune('0'+i/10)) + "." + string(rune('0'+i%10))
		m.Add(tcpPacket(src, 1000, "10.9.9.9", 80, 100, 0x18, string(chunk)))
	}
	st := m.Stats()
	if st.Evicted == 0 {
		t.Fatalf("expected evictions, stats=%+v", st)
	}
	if st.Bytes > st.BudgetBytes {
		t.Fatalf("budget exceeded: %+v", st)
	}
}
