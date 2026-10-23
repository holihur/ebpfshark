package pcapio

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"ebpfshark/internal/packet"
)

func ethFrame() []byte {
	f := make([]byte, 14+20)
	binary.BigEndian.PutUint16(f[12:14], 0x0800)
	f[14] = 0x45
	binary.BigEndian.PutUint16(f[16:18], 20)
	return f
}

func rawIPTCP() []byte {
	p := make([]byte, 40)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	p[9] = 6
	return p
}

func TestClassicRoundTrip(t *testing.T) {
	now := time.Unix(1700000000, 123456000)
	pkts := []*packet.Packet{
		{
			Time:     now,
			IfName:   "eth0",
			WireLen:  34,
			CapLen:   34,
			LinkType: packet.LinkEthernet,
			Data:     ethFrame(),
		},
		{
			Time:     now.Add(time.Millisecond),
			IfName:   "eth0",
			WireLen:  60,
			CapLen:   40,
			LinkType: packet.LinkEthernet,
			Data:     ethFrame(),
		},
	}
	var buf bytes.Buffer
	if err := Write(&buf, pkts); err != nil {
		t.Fatal(err)
	}
	got, err := Read(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("read %d packets", len(got))
	}
	if got[0].LinkType != packet.LinkEthernet {
		t.Fatalf("link type = %d", got[0].LinkType)
	}
	if got[0].Time.UnixMicro() != now.UnixMicro() {
		t.Fatalf("time = %v, want %v", got[0].Time, now)
	}
	if got[1].WireLen != 60 || got[1].CapLen != 34 {
		t.Fatalf("lengths = %d/%d", got[1].WireLen, got[1].CapLen)
	}
	if !bytes.Equal(got[1].Data, ethFrame()) {
		t.Fatal("payload mismatch")
	}
}

func TestRawToEthernetSynthesis(t *testing.T) {
	raw := rawIPTCP()
	pkts := []*packet.Packet{
		{Time: time.Unix(1, 0), LinkType: packet.LinkEthernet, WireLen: 34, CapLen: 34, Data: ethFrame()},
		{Time: time.Unix(2, 0), LinkType: packet.LinkRaw, WireLen: uint32(len(raw)), CapLen: uint32(len(raw)), Data: raw},
	}
	var buf bytes.Buffer
	if err := Write(&buf, pkts); err != nil {
		t.Fatal(err)
	}
	got, err := Read(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("read %d packets", len(got))
	}
	if len(got[1].Data) != 14+len(raw) {
		t.Fatalf("synthetic length = %d", len(got[1].Data))
	}
	if binary.BigEndian.Uint16(got[1].Data[12:14]) != 0x0800 {
		t.Fatal("synthetic ethertype is not IPv4")
	}
}

func pcapngBlock(typ uint32, body []byte, order binary.ByteOrder) []byte {
	pad := (4 - len(body)%4) % 4
	body = append(body, make([]byte, pad)...)
	total := 12 + len(body)
	out := make([]byte, total)
	order.PutUint32(out[0:4], typ)
	order.PutUint32(out[4:8], uint32(total))
	copy(out[8:8+len(body)], body)
	order.PutUint32(out[total-4:], uint32(total))
	return out
}

func TestPcapngRead(t *testing.T) {
	order := binary.LittleEndian
	var data []byte
	shb := make([]byte, 16)
	order.PutUint32(shb[0:4], 0x1a2b3c4d)
	order.PutUint16(shb[4:6], 1)
	order.PutUint64(shb[8:16], ^uint64(0))
	data = append(data, pcapngBlock(0x0A0D0D0A, shb, order)...)

	idb := make([]byte, 8)
	order.PutUint16(idb[0:2], 1) // LINKTYPE_ETHERNET
	order.PutUint32(idb[4:8], 262144)
	data = append(data, pcapngBlock(1, idb, order)...)

	frame := ethFrame()
	epb := make([]byte, 20)
	order.PutUint32(epb[0:4], 0)
	order.PutUint32(epb[4:8], 0)
	order.PutUint32(epb[8:12], 1000000) // 1 second in microseconds
	order.PutUint32(epb[12:16], uint32(len(frame)))
	order.PutUint32(epb[16:20], uint32(len(frame)))
	epb = append(epb, frame...)
	data = append(data, pcapngBlock(6, epb, order)...)

	got, err := Read(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("read %d packets", len(got))
	}
	if got[0].Time.Unix() != 1 {
		t.Fatalf("time = %v", got[0].Time)
	}
	if got[0].LinkType != packet.LinkEthernet {
		t.Fatalf("link type = %d", got[0].LinkType)
	}
	if !bytes.Equal(got[0].Data, frame) {
		t.Fatal("payload mismatch")
	}
}

func TestUnknownFormat(t *testing.T) {
	if _, err := Read([]byte("nope")); err == nil {
		t.Fatal("expected an error")
	}
}

func TestPcapngWriteRoundTrip(t *testing.T) {
	now := time.Unix(1700000000, 123456000)
	pkts := []*packet.Packet{{Time: now, LinkType: packet.LinkEthernet, WireLen: 34, CapLen: uint32(len(ethFrame())), Data: ethFrame()}}
	var buf bytes.Buffer
	if err := WriteNG(&buf, pkts); err != nil {
		t.Fatal(err)
	}
	got, err := Read(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].LinkType != packet.LinkEthernet || got[0].Time.UnixMicro() != now.UnixMicro() {
		t.Fatalf("got n=%d pkt=%+v time=%v want=%v", len(got), got[0], got[0].Time.UnixMicro(), now.UnixMicro())
	}
}
