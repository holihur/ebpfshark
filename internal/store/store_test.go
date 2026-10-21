package store

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"ebpfshark/internal/filter"
	"ebpfshark/internal/packet"
)

func makePacket(i int, proto, sport, dport string) *packet.Packet {
	var sp, dp uint16
	fmt.Sscanf(sport, "%d", &sp)
	fmt.Sscanf(dport, "%d", &dp)
	p := &packet.Packet{
		Time:     time.Unix(0, int64(i)*int64(time.Millisecond)),
		IfName:   "test0",
		WireLen:  100,
		CapLen:   60,
		LinkType: packet.LinkEthernet,
		Summary: packet.Summary{
			Protocol: proto,
			Src:      "10.0.0.1:" + sport,
			Dst:      "10.0.0.2:" + dport,
			Info:     "packet",
		},
		Meta: packet.Meta{
			Layers:  []string{"eth", "ip", "tcp"},
			SrcIP:   netip.MustParseAddr("10.0.0.1"),
			DstIP:   netip.MustParseAddr("10.0.0.2"),
			SrcPort: sp,
			DstPort: dp,
		},
	}
	p.Meta.FrameLen = 100
	return p
}

func TestSnapshotAndFilter(t *testing.T) {
	st := New(1000)
	for i := 0; i < 5; i++ {
		proto := "TCP"
		if i%2 == 0 {
			proto = "HTTP"
		}
		st.Add(makePacket(i, proto, "12345", "443"))
	}
	all := st.Snapshot(nil, 0)
	if len(all) != 5 {
		t.Fatalf("snapshot len = %d", len(all))
	}
	if all[0].ID != 1 || all[4].ID != 5 {
		t.Fatalf("unexpected ids %d..%d", all[0].ID, all[4].ID)
	}
	if all[0].Time.UnixNano() != 0 {
		t.Fatalf("time = %v", all[0].Time)
	}
	f, err := filter.Parse("tcp port 443")
	if err != nil {
		t.Fatal(err)
	}
	if got := len(st.Snapshot(f, 0)); got != 5 {
		t.Fatalf("filtered snapshot = %d", got)
	}
	if _, ok := st.Get(3); !ok {
		t.Fatal("Get(3) failed")
	}
	if _, ok := st.Get(99); ok {
		t.Fatal("Get(99) should fail")
	}
}

func TestEviction(t *testing.T) {
	st := New(1000)
	for i := 0; i < 1005; i++ {
		st.Add(makePacket(i, "TCP", "1", "2"))
	}
	stats := st.Stats()
	if stats.Stored != 1000 || stats.Evicted != 5 || stats.Total != 1005 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
	last := st.Snapshot(nil, 3)
	if last[2].ID != 1005 {
		t.Fatalf("newest id = %d", last[2].ID)
	}
	st.Clear()
	if st.Stats().Stored != 0 {
		t.Fatal("clear did not reset store")
	}
}

func TestFlows(t *testing.T) {
	st := New(1000)
	for i := 0; i < 4; i++ {
		p := makePacket(i, "TCP", "50000", "443")
		p.WireLen = uint32(100 + i*100)
		st.Add(p)
	}
	flows := st.Flows(10)
	if len(flows) != 1 {
		t.Fatalf("flows = %d", len(flows))
	}
	f := flows[0]
	if f.Packets != 4 || f.Bytes != 100+200+300+400 {
		t.Fatalf("flow stats: packets=%d bytes=%d", f.Packets, f.Bytes)
	}
	if f.Src != "10.0.0.1" || f.SrcPort != 50000 || f.DstPort != 443 {
		t.Fatalf("endpoints: %+v", f)
	}
}

func TestStreamReassembly(t *testing.T) {
	st := New(1000)
	p := &packet.Packet{
		Time:     time.Unix(1, 0),
		Summary:  packet.Summary{Protocol: "TCP"},
		WireLen:  100,
		CapLen:   100,
		LinkType: packet.LinkEthernet,
		Meta: packet.Meta{
			Layers:     []string{"eth", "ip", "tcp"},
			SrcIP:      netip.MustParseAddr("10.0.0.1"),
			DstIP:      netip.MustParseAddr("10.0.0.2"),
			SrcPort:    12345,
			DstPort:    80,
			TCPSeq:     100,
			TCPFlags:   0x18,
			TCPPayload: []byte("GET / HTTP/1.1\r\n"),
		},
	}
	st.Add(p)
	snap, ok := st.StreamForPacket(p)
	if !ok {
		t.Fatal("stream not found")
	}
	if string(snap.AtoB.Data) != "GET / HTTP/1.1\r\n" {
		t.Fatalf("data = %q", snap.AtoB.Data)
	}
	if got := st.StreamStats().Flows; got != 1 {
		t.Fatalf("flows = %d", got)
	}
	st.Clear()
	if _, ok := st.StreamForPacket(p); ok {
		t.Fatal("stream still present after clear")
	}
}

func TestSubscriber(t *testing.T) {
	st := New(1000)
	f, _ := filter.Parse("tcp port 443")
	sub := st.Subscribe(f, 10)
	defer st.Unsubscribe(sub)
	st.Add(makePacket(0, "TCP", "1", "80"))
	select {
	case p := <-sub.C:
		t.Fatalf("unexpected packet %d", p.ID)
	default:
	}
	st.Add(makePacket(1, "TCP", "1", "443"))
	select {
	case p := <-sub.C:
		if p.ID != 2 {
			t.Fatalf("id = %d", p.ID)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for subscriber packet")
	}
}
