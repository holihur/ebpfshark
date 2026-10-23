//go:build full

package decode

import (
	"encoding/binary"
	"fmt"
	"unicode/utf8"
)

func (c *ctx) dissectGRPC(b []byte, base int, parent *Field) (string, bool) {
	if len(b) < 5 || (b[0] != 0 && b[0] != 1) {
		return "", false
	}
	n := int(binary.BigEndian.Uint32(b[1:5]))
	if n <= 0 || n > len(b)-5 {
		return "", false
	}
	// A gRPC DATA frame normally contains exactly one length-prefixed message.
	if n != len(b)-5 {
		return "", false
	}
	c.addLayer("grpc")
	c.addLayer("protobuf")
	c.proto = "grpc"
	root := c.newField(fmt.Sprintf("gRPC message (%d bytes)", n), "", base, len(b))
	root.add(c.newField(fmt.Sprintf("Compressed: %d", b[0]), "", base, 1),
		c.newField(fmt.Sprintf("Message Length: %d", n), "", base+1, 4))
	msg := b[5:]
	pn := c.newField("Protobuf message", "", base+5, len(msg))
	parseProtobuf(c, msg, base+5, pn, 0, &[]int{0}[0])
	root.add(pn)
	parent.add(root)
	return fmt.Sprintf("gRPC %d bytes", n), true
}

func parseProtobuf(c *ctx, b []byte, base int, parent *Field, depth int, fields *int) {
	if depth > 3 || len(b) == 0 {
		return
	}
	off := 0
	for off < len(b) && *fields < 256 {
		start := off
		key, n := protoVarint(b[off:])
		if n <= 0 || key == 0 {
			return
		}
		off += n
		num, wire := key>>3, key&7
		if num == 0 {
			return
		}
		*fields = *fields + 1
		switch wire {
		case 0:
			v, n := protoVarint(b[off:])
			if n <= 0 {
				return
			}
			off += n
			parent.add(c.newField(fmt.Sprintf("Field %d (varint)", num), fmt.Sprintf("%d", v), base+start, off-start))
		case 1:
			if off+8 > len(b) {
				return
			}
			parent.add(c.newField(fmt.Sprintf("Field %d (fixed64)", num), fmt.Sprintf("0x%x", b[off:off+8]), base+off, 8))
			off += 8
		case 2:
			l, n := protoVarint(b[off:])
			if n <= 0 || l > uint64(len(b)-off-n) {
				return
			}
			off += n
			v := b[off : off+int(l)]
			text := ""
			if utf8.Valid(v) && printableRatio(v) > 0.9 {
				text = string(v)
			}
			f := c.newField(fmt.Sprintf("Field %d (bytes, %d)", num, len(v)), shorten(text, 120), base+off, len(v))
			parent.add(f)
			off += int(l)
			if len(v) > 0 && !utf8.Valid(v) {
				child := c.newField("Nested message", "", base+off-int(l), len(v))
				parseProtobuf(c, v, base+off-int(l), child, depth+1, fields)
				if len(child.Children) > 0 {
					f.add(child)
				}
			}
		case 5:
			if off+4 > len(b) {
				return
			}
			parent.add(c.newField(fmt.Sprintf("Field %d (fixed32)", num), fmt.Sprintf("0x%x", b[off:off+4]), base+off, 4))
			off += 4
		default:
			return
		}
	}
}

func protoVarint(b []byte) (uint64, int) {
	var v uint64
	for i := 0; i < len(b) && i < 10; i++ {
		v |= uint64(b[i]&0x7f) << (7 * i)
		if b[i]&0x80 == 0 {
			return v, i + 1
		}
	}
	return 0, 0
}

func printableRatio(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	ok := 0
	for _, c := range b {
		if c == '\n' || c == '\r' || c == '\t' || (c >= 32 && c < 127) {
			ok++
		}
	}
	return float64(ok) / float64(len(b))
}
