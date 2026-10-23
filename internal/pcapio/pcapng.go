package pcapio

import (
	"encoding/binary"
	"fmt"
	"io"

	"ebpfshark/internal/packet"
)

// WriteNG serialises packets as pcapng (Section Header, Interface Description
// and Enhanced Packet blocks). It uses microsecond timestamps and a single
// interface, matching the classic pcap writer's link-type normalisation.
func WriteNG(w io.Writer, pkts []*packet.Packet) error {
	global := chooseGlobalLinkType(pkts)
	// Section Header Block.
	shb := make([]byte, 28)
	binary.LittleEndian.PutUint32(shb[0:4], 0x0a0d0d0a)
	binary.LittleEndian.PutUint32(shb[4:8], 28)
	binary.LittleEndian.PutUint32(shb[8:12], 0x1a2b3c4d)
	binary.LittleEndian.PutUint16(shb[12:14], 1)
	binary.LittleEndian.PutUint16(shb[14:16], 0)
	binary.LittleEndian.PutUint64(shb[16:24], ^uint64(0))
	binary.LittleEndian.PutUint32(shb[24:28], 28)
	if _, err := w.Write(shb); err != nil {
		return err
	}
	// Interface Description Block.
	idb := make([]byte, 20)
	binary.LittleEndian.PutUint32(idb[0:4], 1)
	binary.LittleEndian.PutUint32(idb[4:8], 20)
	binary.LittleEndian.PutUint16(idb[8:10], uint16(global))
	binary.LittleEndian.PutUint16(idb[10:12], 0)
	binary.LittleEndian.PutUint32(idb[12:16], 262144)
	binary.LittleEndian.PutUint32(idb[16:20], 20)
	if _, err := w.Write(idb); err != nil {
		return err
	}

	for _, p := range pkts {
		data, origLen := toGlobalLinkType(p, global)
		if data == nil {
			continue
		}
		pad := (4 - len(data)%4) % 4
		blockLen := 32 + len(data) + pad
		b := make([]byte, blockLen)
		binary.LittleEndian.PutUint32(b[0:4], 6)
		binary.LittleEndian.PutUint32(b[4:8], uint32(blockLen))
		binary.LittleEndian.PutUint32(b[8:12], 0)
		ts := uint64(p.Time.Unix())*1_000_000 + uint64(p.Time.Nanosecond()/1000)
		binary.LittleEndian.PutUint32(b[12:16], uint32(ts>>32))
		binary.LittleEndian.PutUint32(b[16:20], uint32(ts))
		binary.LittleEndian.PutUint32(b[20:24], uint32(len(data)))
		binary.LittleEndian.PutUint32(b[24:28], uint32(origLen))
		copy(b[28:], data)
		binary.LittleEndian.PutUint32(b[blockLen-4:], uint32(blockLen))
		if _, err := w.Write(b); err != nil {
			return fmt.Errorf("pcapng packet block: %w", err)
		}
	}
	return nil
}
