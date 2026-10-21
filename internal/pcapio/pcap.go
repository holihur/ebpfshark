// Package pcapio reads and writes packet captures (classic pcap and pcapng).
package pcapio

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	"ebpfshark/internal/packet"
)

// Write serialises packets as a classic pcap file. If the capture mixes link
// types everything is converted to Ethernet where possible.
func Write(w io.Writer, pkts []*packet.Packet) error {
	global := packet.LinkEthernet
	if len(pkts) > 0 {
		counts := map[packet.LinkType]int{}
		for _, p := range pkts {
			counts[p.LinkType]++
		}
		best := 0
		for lt, n := range counts {
			if n > best || (n == best && lt == packet.LinkEthernet) {
				best = n
				global = lt
			}
		}
	}

	var hdr [24]byte
	binary.LittleEndian.PutUint32(hdr[0:4], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(hdr[4:6], 2)
	binary.LittleEndian.PutUint16(hdr[6:8], 4)
	binary.LittleEndian.PutUint32(hdr[8:12], 0)
	binary.LittleEndian.PutUint32(hdr[12:16], 0)
	binary.LittleEndian.PutUint32(hdr[16:20], 262144)
	binary.LittleEndian.PutUint32(hdr[20:24], uint32(global))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}

	var rec [16]byte
	for _, p := range pkts {
		data, origLen := toGlobalLinkType(p, global)
		if data == nil {
			continue
		}
		binary.LittleEndian.PutUint32(rec[0:4], uint32(p.Time.Unix()))
		binary.LittleEndian.PutUint32(rec[4:8], uint32(p.Time.Nanosecond()/1000))
		binary.LittleEndian.PutUint32(rec[8:12], uint32(len(data)))
		binary.LittleEndian.PutUint32(rec[12:16], uint32(origLen))
		if _, err := w.Write(rec[:]); err != nil {
			return err
		}
		if _, err := w.Write(data); err != nil {
			return err
		}
	}
	return nil
}

func toGlobalLinkType(p *packet.Packet, global packet.LinkType) ([]byte, int) {
	orig := int(p.WireLen)
	if orig < len(p.Data) {
		orig = len(p.Data)
	}
	if p.LinkType == global {
		return p.Data, orig
	}
	if global == packet.LinkEthernet {
		switch p.LinkType {
		case packet.LinkRaw:
			if len(p.Data) == 0 {
				return nil, 0
			}
			ethType := uint16(0x0800)
			if p.Data[0]>>4 == 6 {
				ethType = 0x86dd
			}
			out := make([]byte, 14+len(p.Data))
			binary.BigEndian.PutUint16(out[12:14], ethType)
			copy(out[14:], p.Data)
			return out, orig + 14
		case packet.LinkLinuxSLL:
			if len(p.Data) < 16 {
				return nil, 0
			}
			proto := binary.BigEndian.Uint16(p.Data[14:16])
			out := make([]byte, 14+len(p.Data)-16)
			copy(out[0:6], p.Data[6:12])
			binary.BigEndian.PutUint16(out[12:14], proto)
			copy(out[14:], p.Data[16:])
			return out, orig + 14 - 16
		case packet.LinkLinuxSLL2:
			if len(p.Data) < 20 {
				return nil, 0
			}
			proto := binary.BigEndian.Uint16(p.Data[0:2])
			out := make([]byte, 14+len(p.Data)-20)
			copy(out[0:6], p.Data[12:18])
			binary.BigEndian.PutUint16(out[12:14], proto)
			copy(out[14:], p.Data[20:])
			return out, orig + 14 - 20
		}
	}
	if global == packet.LinkRaw && p.LinkType == packet.LinkEthernet {
		if len(p.Data) < 14 {
			return nil, 0
		}
		et := binary.BigEndian.Uint16(p.Data[12:14])
		off := 14
		for et == 0x8100 && len(p.Data) >= off+4 {
			et = binary.BigEndian.Uint16(p.Data[off+2 : off+4])
			off += 4
		}
		return p.Data[off:], orig - off
	}
	return p.Data, orig
}

// ErrUnknownFormat is returned when the file is neither pcap nor pcapng.
var ErrUnknownFormat = errors.New("unrecognised capture file format")

// Read parses a pcap or pcapng byte slice into packets.
func Read(data []byte) ([]*packet.Packet, error) {
	if len(data) < 4 {
		return nil, ErrUnknownFormat
	}
	if binary.BigEndian.Uint32(data[0:4]) == 0x0A0D0D0A {
		return readPcapng(data)
	}
	return readClassic(data)
}

func readClassic(data []byte) ([]*packet.Packet, error) {
	var order binary.ByteOrder
	nanos := false
	switch {
	case bytes.Equal(data[0:4], []byte{0xa1, 0xb2, 0xc3, 0xd4}):
		order, nanos = binary.BigEndian, false
	case bytes.Equal(data[0:4], []byte{0xd4, 0xc3, 0xb2, 0xa1}):
		order, nanos = binary.LittleEndian, false
	case bytes.Equal(data[0:4], []byte{0xa1, 0xb2, 0x3c, 0x4d}):
		order, nanos = binary.BigEndian, true
	case bytes.Equal(data[0:4], []byte{0x4d, 0x3c, 0xb2, 0xa1}):
		order, nanos = binary.LittleEndian, true
	default:
		return nil, ErrUnknownFormat
	}
	if len(data) < 24 {
		return nil, fmt.Errorf("truncated pcap header")
	}
	linkType := packet.LinkType(order.Uint32(data[20:24]))
	off := 24
	var out []*packet.Packet
	for off+16 <= len(data) {
		sec := int64(order.Uint32(data[off : off+4]))
		frac := int64(order.Uint32(data[off+4 : off+8]))
		incl := int(order.Uint32(data[off+8 : off+12]))
		orig := order.Uint32(data[off+12 : off+16])
		off += 16
		if incl < 0 || off+incl > len(data) {
			break
		}
		ns := sec * int64(time.Second)
		if nanos {
			ns += frac
		} else {
			ns += frac * 1000
		}
		buf := make([]byte, incl)
		copy(buf, data[off:off+incl])
		out = append(out, &packet.Packet{
			Time:     time.Unix(0, ns),
			IfName:   "import",
			WireLen:  orig,
			CapLen:   uint32(incl),
			LinkType: linkType,
			Data:     buf,
		})
		off += incl
	}
	return out, nil
}

func readPcapng(data []byte) ([]*packet.Packet, error) {
	var order binary.ByteOrder
	var linkTypes []packet.LinkType
	var tsUnits []int64
	off := 0
	var out []*packet.Packet

	for off+12 <= len(data) {
		if off == 0 {
			if binary.BigEndian.Uint32(data[0:4]) != 0x0A0D0D0A {
				return nil, ErrUnknownFormat
			}
			switch {
			case bytes.Equal(data[8:12], []byte{0x4d, 0x3c, 0x2b, 0x1a}):
				order = binary.LittleEndian
			case bytes.Equal(data[8:12], []byte{0x1a, 0x2b, 0x3c, 0x4d}):
				order = binary.BigEndian
			default:
				return nil, fmt.Errorf("invalid pcapng byte-order magic")
			}
		}
		if order == nil {
			break
		}
		btype := order.Uint32(data[off : off+4])
		blen := int(order.Uint32(data[off+4 : off+8]))
		if blen < 12 || off+blen > len(data) {
			break
		}
		body := data[off+8 : off+blen-4]
		switch btype {
		case 0x0A0D0D0A:
			linkTypes = nil
			tsUnits = nil
		case 1: // Interface Description Block
			if len(body) < 8 {
				break
			}
			linkType := packet.LinkType(order.Uint16(body[0:2]))
			linkTypes = append(linkTypes, linkType)
			units := int64(1000000)
			// options start at body[8], each: code, len, value, padding
			opts := body[8:]
			for len(opts) >= 4 {
				code := order.Uint16(opts[0:2])
				l := int(order.Uint16(opts[2:4]))
				if code == 0 || 4+l > len(opts) {
					break
				}
				if code == 9 && l >= 1 {
					v := opts[4]
					if v&0x80 != 0 {
						units = int64(1) << (v & 0x7f)
					} else {
						units = 1
						for i := byte(0); i < v && i < 18; i++ {
							units *= 10
						}
					}
				}
				pad := (4 - l%4) % 4
				opts = opts[4+l+pad:]
			}
			tsUnits = append(tsUnits, units)
			if units == 0 {
				tsUnits[len(tsUnits)-1] = 1000000
			}
		case 6: // Enhanced Packet Block
			if len(body) < 20 {
				break
			}
			iface := int(order.Uint32(body[0:4]))
			tsHigh := uint64(order.Uint32(body[4:8]))
			tsLow := uint64(order.Uint32(body[8:12]))
			caplen := int(order.Uint32(body[12:16]))
			origlen := order.Uint32(body[16:20])
			if caplen < 0 || 20+caplen > len(body) {
				break
			}
			units := int64(1000000)
			lt := packet.LinkEthernet
			if iface < len(linkTypes) {
				lt = linkTypes[iface]
			}
			if iface < len(tsUnits) {
				units = tsUnits[iface]
			}
			ts := int64(tsHigh<<32 | tsLow)
			ns := ts * int64(time.Second) / units
			buf := make([]byte, caplen)
			copy(buf, body[20:20+caplen])
			out = append(out, &packet.Packet{
				Time:     time.Unix(0, ns),
				IfName:   "import",
				WireLen:  origlen,
				CapLen:   uint32(caplen),
				LinkType: lt,
				Data:     buf,
			})
		case 3: // Simple Packet Block
			if len(body) < 4 {
				break
			}
			origlen := order.Uint32(body[0:4])
			caplen := len(body) - 4
			lt := packet.LinkEthernet
			if len(linkTypes) > 0 {
				lt = linkTypes[0]
			}
			buf := make([]byte, caplen)
			copy(buf, body[4:])
			out = append(out, &packet.Packet{
				Time:     time.Now(),
				IfName:   "import",
				WireLen:  origlen,
				CapLen:   uint32(caplen),
				LinkType: lt,
				Data:     buf,
			})
		case 2: // obsolete Packet Block
			if len(body) < 20 {
				break
			}
			iface := int(order.Uint16(body[0:2]))
			tsHigh := uint64(order.Uint32(body[4:8]))
			tsLow := uint64(order.Uint32(body[8:12]))
			caplen := int(order.Uint32(body[12:16]))
			origlen := order.Uint32(body[16:20])
			if caplen < 0 || 20+caplen > len(body) {
				break
			}
			units := int64(1000000)
			lt := packet.LinkEthernet
			if iface < len(linkTypes) {
				lt = linkTypes[iface]
			}
			if iface < len(tsUnits) {
				units = tsUnits[iface]
			}
			ns := int64(tsHigh<<32|tsLow) * int64(time.Second) / units
			buf := make([]byte, caplen)
			copy(buf, body[20:20+caplen])
			out = append(out, &packet.Packet{
				Time:     time.Unix(0, ns),
				IfName:   "import",
				WireLen:  origlen,
				CapLen:   uint32(caplen),
				LinkType: lt,
				Data:     buf,
			})
		}
		off += blen
	}
	if len(out) == 0 {
		return nil, ErrUnknownFormat
	}
	return out, nil
}
