//go:build full

package decode

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
)

// ------------------------------------------------------------------ STUN

const stunMagic = 0x2112A442

var stunMethods = map[uint16]string{
	0x001: "Binding", 0x002: "Shared Secret", 0x003: "Allocate", 0x004: "Refresh",
	0x006: "Send", 0x007: "Data", 0x008: "CreatePermission", 0x009: "ChannelBind",
	0x00a: "Connect", 0x00b: "ConnectionBind", 0x00c: "ConnectionAttempt",
}

var stunAttrs = map[uint16]string{
	0x0001: "MAPPED-ADDRESS", 0x0002: "RESPONSE-ADDRESS", 0x0003: "CHANGE-REQUEST",
	0x0004: "SOURCE-ADDRESS", 0x0005: "CHANGED-ADDRESS", 0x0006: "USERNAME",
	0x0007: "PASSWORD", 0x0008: "MESSAGE-INTEGRITY", 0x0009: "ERROR-CODE",
	0x000a: "UNKNOWN-ATTRIBUTES", 0x000b: "REFLECTED-FROM", 0x0012: "XOR-PEER-ADDRESS",
	0x0013: "DATA", 0x0014: "REALM", 0x0015: "NONCE", 0x0016: "XOR-RELAYED-ADDRESS",
	0x0017: "REQUESTED-ADDRESS-FAMILY", 0x0018: "EVEN-PORT", 0x0019: "REQUESTED-TRANSPORT",
	0x001a: "DONT-FRAGMENT", 0x001c: "PASSWORD-ALGORITHMS", 0x001d: "USERHASH",
	0x001e: "PASSWORD-ALGORITHM", 0x0020: "XOR-MAPPED-ADDRESS", 0x0022: "RESERVATION-TOKEN",
	0x0024: "PRIORITY", 0x0025: "USE-CANDIDATE", 0x8022: "SOFTWARE",
	0x8023: "FINGERPRINT", 0x8028: "MESSAGE-INTEGRITY-SHA256",
	0x8029: "PASSWORD-ALGORITHM", 0x802a: "ICE-CONTROLLED", 0x802b: "ICE-CONTROLLING",
}

func stunClass(t uint16) uint16 { return ((t >> 4) & 1) | ((t >> 7) & 2) }
func stunMethod(t uint16) uint16 {
	return (t & 0x000f) | ((t >> 1) & 0x0070) | ((t >> 2) & 0x0f80)
}

func stunClassNames(class uint16) string {
	switch class {
	case 0:
		return "request"
	case 1:
		return "indication"
	case 2:
		return "success response"
	case 3:
		return "error response"
	}
	return "unknown"
}

func (c *ctx) dissectSTUN(b []byte, base int) bool {
	if len(b) < 20 || be32(b[4:8]) != stunMagic {
		return false
	}
	msgType := be16(b[0:2])
	method := stunMethod(msgType)
	class := stunClass(msgType)
	methodName := stunMethods[method]
	if methodName == "" {
		methodName = fmt.Sprintf("method 0x%03x", method)
	}
	length := int(be16(b[2:4]))
	if 20+length > len(b) {
		length = len(b) - 20
	}

	c.addLayer("stun")
	c.proto = "stun"
	root := c.newNode(fmt.Sprintf("Session Traversal Utilities for NAT (%s %s)", methodName, stunClassNames(class)), base, 20+length)
	root.add(
		c.newField(fmt.Sprintf("Message Type: 0x%04x", msgType), "", base, 2),
		c.newField(fmt.Sprintf("Method: %s (0x%03x)", methodName, method), "", base, 2),
		c.newField(fmt.Sprintf("Class: %s", stunClassNames(class)), "", base, 2),
		c.newField(fmt.Sprintf("Length: %d", length), "", base+2, 2),
		c.newField("Magic Cookie: 0x2112A442", "", base+4, 4),
		c.newField(fmt.Sprintf("Transaction ID: %x", b[8:20]), "", base+8, 12),
	)

	off := 20
	end := 20 + length
	var mapped, username, software string
	for off+4 <= end {
		atype := be16(b[off : off+2])
		alen := int(be16(b[off+2 : off+4]))
		if off+4+alen > end {
			break
		}
		value := b[off+4 : off+4+alen]
		name := stunAttrs[atype]
		if name == "" {
			name = fmt.Sprintf("Attribute 0x%04x", atype)
		}
		f := c.newField(fmt.Sprintf("%s (length %d)", name, alen), "", base+off, 4+alen)
		switch atype {
		case 0x0001:
			mapped = stunAddress(value, nil)
			f.add(c.newField("Address: "+mapped, "", base+off+4, alen))
		case 0x0020:
			mapped = stunAddress(value, b[8:20])
			f.add(c.newField("XOR Address: "+mapped, "", base+off+4, alen))
		case 0x0006:
			username = string(value)
			f.add(c.newField("Username: "+username, "", base+off+4, alen))
		case 0x8022:
			software = string(value)
			f.add(c.newField("Software: "+software, "", base+off+4, alen))
		case 0x0014:
			f.add(c.newField("Realm: "+string(value), "", base+off+4, alen))
		case 0x0015:
			f.add(c.newField("Nonce: "+string(value), "", base+off+4, alen))
		case 0x0012, 0x0016:
			addr := stunAddress(value, b[8:20])
			if atype == 0x0012 {
				f.add(c.newField("XOR Peer Address: "+addr, "", base+off+4, alen))
			} else {
				f.add(c.newField("XOR Relayed Address: "+addr, "", base+off+4, alen))
			}
		case 0x0009:
			if len(value) >= 4 {
				class := int(value[2] & 0x7)
				number := int(value[3])
				reason := string(value[4:])
				f.add(c.newField(fmt.Sprintf("Error: %d%02d %s", class, number, reason), "", base+off+4, alen))
			}
		case 0x0019:
			if len(value) >= 1 {
				proto := "UDP"
				if value[0] == 6 {
					proto = "TCP"
				}
				f.add(c.newField(fmt.Sprintf("Transport: %s (%d)", proto, value[0]), "", base+off+4, alen))
			}
		case 0x0024:
			if len(value) >= 4 {
				f.add(c.newField(fmt.Sprintf("Priority: %d", be32(value[0:4])), "", base+off+4, alen))
			}
		case 0x0025:
			f.add(c.newField("Use Candidate", "", base+off+4, alen))
		case 0x802a, 0x802b:
			f.add(c.newField("Tie-breaker: "+hexPreview(value, 8), "", base+off+4, alen))
		case 0x8023:
			if len(value) >= 4 {
				f.add(c.newField(fmt.Sprintf("Fingerprint: 0x%08x", be32(value[0:4])), "", base+off+4, alen))
			}
		case 0x0008, 0x8028:
			f.add(c.newField("Integrity: "+hexPreview(value, 32), "", base+off+4, alen))
		case 0x000a:
			var ids []string
			for i := 0; i+2 <= len(value); i += 2 {
				ids = append(ids, fmt.Sprintf("0x%04x", be16(value[i:i+2])))
			}
			f.add(c.newField("Unknown attributes: "+strings.Join(ids, ", "), "", base+off+4, alen))
		default:
			f.add(c.newField(hexPreview(value, 48), "", base+off+4, alen))
		}
		root.add(f)
		off += 4 + ((alen + 3) &^ 3)
	}
	c.addRoot(root)

	info := fmt.Sprintf("STUN %s %s", methodName, stunClassNames(class))
	if mapped != "" {
		info += " " + mapped
	}
	if username != "" {
		info += " user=" + username
	}
	if software != "" && !strings.Contains(info, " user=") {
		info += " (" + software + ")"
	}
	c.appInfo = shorten(info, 120)
	return true
}

func stunAddress(v []byte, txID []byte) string {
	if len(v) < 4 {
		return ""
	}
	family := v[1]
	port := be16(v[2:4])
	addr := append([]byte(nil), v[4:]...)
	if len(txID) == 12 {
		port ^= uint16(stunMagic >> 16)
		magic := make([]byte, 16)
		binary.BigEndian.PutUint32(magic[0:4], stunMagic)
		copy(magic[4:], txID)
		for i := 0; i < len(addr) && i < len(magic); i++ {
			addr[i] ^= magic[i]
		}
	}
	switch family {
	case 1:
		if len(addr) >= 4 {
			return netip.AddrFrom4([4]byte{addr[0], addr[1], addr[2], addr[3]}).String() + fmt.Sprintf(":%d", port)
		}
	case 2:
		if len(addr) >= 16 {
			var a [16]byte
			copy(a[:], addr)
			return netip.AddrFrom16(a).String() + fmt.Sprintf(":%d", port)
		}
	}
	return ""
}

func init() {
	RegisterPlugin(pluginSpec{Name: "stun", Priority: 60, Transport: TransportUDP,
		Match: portMatch(map[uint16]bool{3478: true, 3479: true}), Dissect: func(c *ctx, b []byte, base int) bool { return c.dissectSTUN(b, base) }})
}
