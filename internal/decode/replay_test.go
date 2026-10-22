package decode

import (
	"bytes"
	"testing"
	"time"

	"ebpfshark/internal/packet"
	"ebpfshark/internal/pcapio"
)

func TestPcapReplay(t *testing.T) {
	frames := [][]byte{
		buildEthernet(buildIPv4(6, buildTCP(49152, 80, 0x18, []byte("GET / HTTP/1.1\r\nHost: replay\r\n\r\n"))), 0x0800),
		buildEthernet(buildIPv4(17, buildUDP(53123, 53, buildDNSQuery(0x77, "replay.example", 1))), 0x0800),
		buildEthernet(buildIPv4(6, buildTCP(51000, 443, 0x18, buildClientHello("replay.example"))), 0x0800),
	}
	pkts := make([]*packet.Packet, 0, len(frames))
	for i, frame := range frames {
		pkts = append(pkts, &packet.Packet{
			Time:     time.Unix(int64(i), 0),
			LinkType: packet.LinkEthernet,
			WireLen:  uint32(len(frame)),
			CapLen:   uint32(len(frame)),
			Data:     frame,
		})
	}
	var buf bytes.Buffer
	if err := pcapio.Write(&buf, pkts); err != nil {
		t.Fatal(err)
	}
	got, err := pcapio.Read(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(frames) {
		t.Fatalf("read %d packets", len(got))
	}
	for i, p := range got {
		res := Decode(p.Data, p.LinkType, int(p.WireLen))
		if res.Summary.Protocol == "" {
			t.Fatalf("packet %d not decoded", i)
		}
		ReleaseFields(res.Fields)
	}
}
