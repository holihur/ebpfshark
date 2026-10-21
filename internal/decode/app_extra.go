//go:build full

package decode

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"ebpfshark/internal/packet"
)

// ------------------------------------------------------------------- NTP

var ntpModes = []string{"reserved", "symmetric active", "symmetric passive", "client", "server", "broadcast", "control", "private"}

func ntpMode(mode uint8) string {
	if int(mode) < len(ntpModes) {
		return ntpModes[mode]
	}
	return fmt.Sprintf("mode %d", mode)
}

func ntpTimestamp(b []byte) string {
	if len(b) < 8 {
		return "0"
	}
	sec := be32(b[0:4])
	frac := be32(b[4:8])
	if sec == 0 && frac == 0 {
		return "0"
	}
	unix := int64(sec) - 2208988800
	ns := int64(float64(frac) / 4294967296.0 * 1e9)
	return time.Unix(unix, ns).UTC().Format("2006-01-02 15:04:05.000000 MST")
}

func (c *ctx) dissectNTP(b []byte, base int) bool {
	if len(b) < 48 {
		return false
	}
	vn := (b[0] >> 3) & 0x7
	if vn < 1 || vn > 4 {
		return false
	}
	li := b[0] >> 6
	mode := b[0] & 0x7
	stratum := b[1]
	poll := int8(b[2])
	precision := int8(b[3])

	c.addLayer("ntp")
	c.proto = "ntp"
	root := newNode(fmt.Sprintf("Network Time Protocol (%s, v%d)", ntpMode(mode), vn), base, len(b))
	root.add(
		newField(fmt.Sprintf("Leap Indicator: %d", li), "", base, 1),
		newField(fmt.Sprintf("Version: %d", vn), "", base, 1),
		newField(fmt.Sprintf("Mode: %d (%s)", mode, ntpMode(mode)), "", base, 1),
		newField(fmt.Sprintf("Stratum: %d", stratum), "", base+1, 1),
		newField(fmt.Sprintf("Poll: %d seconds", poll), "", base+2, 1),
		newField(fmt.Sprintf("Precision: %d", precision), "", base+3, 1),
		newField(fmt.Sprintf("Root Delay: %.6f s", float64(be32(b[4:8]))/65536), "", base+4, 4),
		newField(fmt.Sprintf("Root Dispersion: %.6f s", float64(be32(b[8:12]))/65536), "", base+8, 4),
		newField(fmt.Sprintf("Reference ID: 0x%08x", be32(b[12:16])), "", base+12, 4),
		newField("Reference Timestamp: "+ntpTimestamp(b[16:24]), "", base+16, 8),
		newField("Origin Timestamp: "+ntpTimestamp(b[24:32]), "", base+24, 8),
		newField("Receive Timestamp: "+ntpTimestamp(b[32:40]), "", base+32, 8),
		newField("Transmit Timestamp: "+ntpTimestamp(b[40:48]), "", base+40, 8),
	)
	if len(b) > 48 {
		ext := newNode(fmt.Sprintf("Extension Fields / MAC (%d bytes)", len(b)-48), base+48, len(b)-48)
		off := 48
		for off+4 <= len(b) {
			etype := be16(b[off : off+2])
			elen := int(be16(b[off+2 : off+4]))
			if elen < 4 || off+elen > len(b) {
				break
			}
			name := "Extension Field"
			switch etype {
			case 0x0104:
				name = "RATE"
			case 0x0204:
				name = "AUTOKEY"
			case 0x2005:
				name = "NTS Cookie"
			case 0x2006:
				name = "NTS Cookie Placeholder"
			case 0x2007:
				name = "NTS Authenticator and Encrypted Extension Fields"
			}
			ext.add(newField(fmt.Sprintf("%s (type 0x%04x, %d bytes)", name, etype, elen), hexPreview(b[off+4:off+elen], 48), base+off, elen))
			off += (elen + 3) &^ 3
		}
		if off < len(b) {
			ext.add(newField(fmt.Sprintf("MAC / trailing data (%d bytes)", len(b)-off), hexPreview(b[off:], 48), base+off, len(b)-off))
		}
		if len(ext.Children) > 0 {
			root.add(ext)
		}
	}
	c.addRoot(root)

	switch mode {
	case 3:
		c.appInfo = fmt.Sprintf("NTP client v%d", vn)
	case 4:
		c.appInfo = fmt.Sprintf("NTP server v%d, stratum %d", vn, stratum)
	case 1, 2:
		c.appInfo = fmt.Sprintf("NTP %s v%d", ntpMode(mode), vn)
	default:
		c.appInfo = fmt.Sprintf("NTP %s v%d", ntpMode(mode), vn)
	}
	return true
}

// ---------------------------------------------------------------- Syslog

var syslogFacilities = []string{"kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron", "authpriv", "ftp", "ntp", "audit", "alert", "clock", "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7"}
var syslogSeverities = []string{"emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"}

func (c *ctx) dissectSyslog(b []byte, base int) bool {
	if len(b) < 3 || b[0] != '<' {
		return false
	}
	end := bytes.IndexByte(b[:min(6, len(b))], '>')
	if end < 2 {
		return false
	}
	pri, err := strconv.Atoi(string(b[1:end]))
	if err != nil || pri < 0 || pri > 191 {
		return false
	}
	facility := pri / 8
	severity := pri % 8
	facName, sevName := fmt.Sprintf("facility%d", facility), fmt.Sprintf("severity%d", severity)
	if facility < len(syslogFacilities) {
		facName = syslogFacilities[facility]
	}
	if severity < len(syslogSeverities) {
		sevName = syslogSeverities[severity]
	}

	rest := b[end+1:]
	root := newNode(fmt.Sprintf("Syslog (%s.%s)", facName, sevName), base, len(b))
	root.add(newField(fmt.Sprintf("Priority: %d (%s.%s)", pri, facName, sevName), "", base, end+1))

	info := fmt.Sprintf("syslog %s.%s", facName, sevName)
	if len(rest) > 0 && rest[0] == '1' && len(rest) > 1 && rest[1] == ' ' {
		fields := bytes.SplitN(rest[2:], []byte(" "), 7)
		if len(fields) >= 6 {
			root.add(
				newField("Version: 1", "", base+end+1, 1),
				newField("Timestamp: "+string(fields[0]), "", base, 0),
				newField("Hostname: "+string(fields[1]), "", base, 0),
				newField("App Name: "+string(fields[2]), "", base, 0),
				newField("Process ID: "+string(fields[3]), "", base, 0),
				newField("Message ID: "+string(fields[4]), "", base, 0),
			)
			msg := ""
			if len(fields) >= 7 {
				msg = string(fields[6])
			}
			root.add(newField("Message: "+shorten(msg, 200), "", base, 0))
			info = fmt.Sprintf("syslog %s.%s %s %s: %s", facName, sevName, fields[1], fields[2], shorten(msg, 80))
		}
	} else {
		line := shorten(string(rest), 200)
		root.add(newField("Message: "+line, "", base+end+1, len(rest)))
		info += " " + shorten(line, 80)
	}
	c.addLayer("syslog")
	c.proto = "syslog"
	c.addRoot(root)
	c.appInfo = info
	return true
}

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
	root := newNode(fmt.Sprintf("Session Traversal Utilities for NAT (%s %s)", methodName, stunClassNames(class)), base, 20+length)
	root.add(
		newField(fmt.Sprintf("Message Type: 0x%04x", msgType), "", base, 2),
		newField(fmt.Sprintf("Method: %s (0x%03x)", methodName, method), "", base, 2),
		newField(fmt.Sprintf("Class: %s", stunClassNames(class)), "", base, 2),
		newField(fmt.Sprintf("Length: %d", length), "", base+2, 2),
		newField("Magic Cookie: 0x2112A442", "", base+4, 4),
		newField(fmt.Sprintf("Transaction ID: %x", b[8:20]), "", base+8, 12),
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
		f := newField(fmt.Sprintf("%s (length %d)", name, alen), "", base+off, 4+alen)
		switch atype {
		case 0x0001:
			mapped = stunAddress(value, nil)
			f.add(newField("Address: "+mapped, "", base+off+4, alen))
		case 0x0020:
			mapped = stunAddress(value, b[8:20])
			f.add(newField("XOR Address: "+mapped, "", base+off+4, alen))
		case 0x0006:
			username = string(value)
			f.add(newField("Username: "+username, "", base+off+4, alen))
		case 0x8022:
			software = string(value)
			f.add(newField("Software: "+software, "", base+off+4, alen))
		case 0x0014:
			f.add(newField("Realm: "+string(value), "", base+off+4, alen))
		case 0x0015:
			f.add(newField("Nonce: "+string(value), "", base+off+4, alen))
		case 0x0012, 0x0016:
			addr := stunAddress(value, b[8:20])
			if atype == 0x0012 {
				f.add(newField("XOR Peer Address: "+addr, "", base+off+4, alen))
			} else {
				f.add(newField("XOR Relayed Address: "+addr, "", base+off+4, alen))
			}
		case 0x0009:
			if len(value) >= 4 {
				class := int(value[2] & 0x7)
				number := int(value[3])
				reason := string(value[4:])
				f.add(newField(fmt.Sprintf("Error: %d%02d %s", class, number, reason), "", base+off+4, alen))
			}
		case 0x0019:
			if len(value) >= 1 {
				proto := "UDP"
				if value[0] == 6 {
					proto = "TCP"
				}
				f.add(newField(fmt.Sprintf("Transport: %s (%d)", proto, value[0]), "", base+off+4, alen))
			}
		case 0x0024:
			if len(value) >= 4 {
				f.add(newField(fmt.Sprintf("Priority: %d", be32(value[0:4])), "", base+off+4, alen))
			}
		case 0x0025:
			f.add(newField("Use Candidate", "", base+off+4, alen))
		case 0x802a, 0x802b:
			f.add(newField("Tie-breaker: "+hexPreview(value, 8), "", base+off+4, alen))
		case 0x8023:
			if len(value) >= 4 {
				f.add(newField(fmt.Sprintf("Fingerprint: 0x%08x", be32(value[0:4])), "", base+off+4, alen))
			}
		case 0x0008, 0x8028:
			f.add(newField("Integrity: "+hexPreview(value, 32), "", base+off+4, alen))
		case 0x000a:
			var ids []string
			for i := 0; i+2 <= len(value); i += 2 {
				ids = append(ids, fmt.Sprintf("0x%04x", be16(value[i:i+2])))
			}
			f.add(newField("Unknown attributes: "+strings.Join(ids, ", "), "", base+off+4, alen))
		default:
			f.add(newField(hexPreview(value, 48), "", base+off+4, alen))
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

// ------------------------------------------------------------------ MQTT

var mqttTypes = []string{"RESERVED", "CONNECT", "CONNACK", "PUBLISH", "PUBACK", "PUBREC", "PUBREL", "PUBCOMP", "SUBSCRIBE", "SUBACK", "UNSUBSCRIBE", "UNSUBACK", "PINGREQ", "PINGRESP", "DISCONNECT"}

func mqttTypeName(t byte) string {
	if int(t) < len(mqttTypes) {
		return mqttTypes[t]
	}
	return fmt.Sprintf("type %d", t)
}

func mqttRemainingLength(b []byte) (int, int, bool) {
	mult, value := 1, 0
	for i := 0; i < 4 && i < len(b); i++ {
		value += int(b[i]&0x7f) * mult
		mult *= 128
		if b[i]&0x80 == 0 {
			return value, i + 1, true
		}
	}
	return 0, 0, false
}

type mqttPropDef struct {
	name string
	kind byte // 1=byte 2=u16 4=u32 v=varint s=string b=binary p=pair
}

var mqttPropDefs = map[byte]mqttPropDef{
	0x01: {"Payload Format Indicator", 1}, 0x02: {"Message Expiry Interval", 4},
	0x03: {"Content Type", 's'}, 0x08: {"Response Topic", 's'},
	0x09: {"Correlation Data", 'b'}, 0x0b: {"Subscription Identifier", 'v'},
	0x11: {"Session Expiry Interval", 4}, 0x12: {"Assigned Client Identifier", 's'},
	0x13: {"Server Keep Alive", 2}, 0x15: {"Authentication Method", 's'},
	0x16: {"Authentication Data", 'b'}, 0x17: {"Request Problem Information", 1},
	0x18: {"Will Delay Interval", 4}, 0x19: {"Request Response Information", 1},
	0x1a: {"Response Information", 's'}, 0x1c: {"Server Reference", 's'},
	0x1f: {"Reason String", 's'}, 0x21: {"Receive Maximum", 2},
	0x22: {"Topic Alias Maximum", 2}, 0x23: {"Topic Alias", 2},
	0x24: {"Maximum QoS", 1}, 0x25: {"Retain Available", 1},
	0x26: {"User Property", 'p'}, 0x27: {"Maximum Packet Size", 4},
	0x28: {"Wildcard Subscription Available", 1}, 0x29: {"Subscription Identifier Available", 1},
	0x2a: {"Shared Subscription Available", 1},
}

func mqttVarint(b []byte, off int) (int, int, bool) {
	mult, value := 1, 0
	for i := 0; i < 4 && off+i < len(b); i++ {
		value += int(b[off+i]&0x7f) * mult
		mult *= 128
		if b[off+i]&0x80 == 0 {
			return value, off + i + 1, true
		}
	}
	return 0, off, false
}

func mqttString(b []byte, off int) (string, int, bool) {
	if off+2 > len(b) {
		return "", off, false
	}
	l := int(be16(b[off : off+2]))
	off += 2
	if off+l > len(b) {
		return "", off, false
	}
	return string(b[off : off+l]), off + l, true
}

func mqttBinary(b []byte, off int) ([]byte, int, bool) {
	if off+2 > len(b) {
		return nil, off, false
	}
	l := int(be16(b[off : off+2]))
	off += 2
	if off+l > len(b) {
		return nil, off, false
	}
	return b[off : off+l], off + l, true
}

func mqttLooksLikeProps(b []byte, off int) bool {
	l, n, ok := mqttVarint(b, off)
	if !ok {
		return false
	}
	if l == 0 {
		// Empty properties are valid in MQTT v5, but treating a v4 payload
		// starting with 0x00 as empty properties corrupts the payload. Require
		// a non-empty, known property for the stateless heuristic.
		return false
	}
	if n >= len(b) {
		return false
	}
	_, known := mqttPropDefs[b[n]]
	return known
}

func mqttParseProps(b []byte, off int) ([]*Field, int) {
	var out []*Field
	propsLen, next, ok := mqttVarint(b, off)
	if !ok || next+propsLen > len(b) {
		return out, off
	}
	end := next + propsLen
	p := next
	for p < end {
		id := b[p]
		p++
		def, ok := mqttPropDefs[id]
		if !ok {
			return out, end
		}
		f := newField(fmt.Sprintf("%s (id 0x%02x)", def.name, id), "", 0, 0)
		switch def.kind {
		case 1:
			if p >= end {
				return out, end
			}
			f.Value = strconv.Itoa(int(b[p]))
			p++
		case 2:
			if p+2 > end {
				return out, end
			}
			f.Value = strconv.Itoa(int(be16(b[p : p+2])))
			p += 2
		case 4:
			if p+4 > end {
				return out, end
			}
			f.Value = strconv.FormatUint(uint64(be32(b[p:p+4])), 10)
			p += 4
		case 'v':
			v, n, ok := mqttVarint(b[:end], p)
			if !ok {
				return out, end
			}
			f.Value = strconv.Itoa(v)
			p = n
		case 's':
			v, n, ok := mqttString(b[:end], p)
			if !ok {
				return out, end
			}
			f.Value = v
			p = n
		case 'b':
			v, n, ok := mqttBinary(b[:end], p)
			if !ok {
				return out, end
			}
			f.Value = hexPreview(v, 48)
			p = n
		case 'p':
			k, n, ok := mqttString(b[:end], p)
			if !ok {
				return out, end
			}
			v, n2, ok := mqttString(b[:end], n)
			if !ok {
				return out, end
			}
			f.Label = k
			f.Value = v
			p = n2
		}
		out = append(out, f)
	}
	return out, end
}

func mqttReason(code byte) string {
	switch code {
	case 0x00:
		return "Success"
	case 0x80:
		return "Unspecified error"
	case 0x81:
		return "Malformed Packet"
	case 0x82:
		return "Protocol Error"
	case 0x83:
		return "Implementation specific error"
	case 0x84:
		return "Unsupported Protocol Version"
	case 0x85:
		return "Client Identifier not valid"
	case 0x86:
		return "Bad User Name or Password"
	case 0x87:
		return "Not authorized"
	case 0x88:
		return "Server unavailable"
	case 0x89:
		return "Server busy"
	case 0x8a:
		return "Banned"
	case 0x8b:
		return "Server shutting down"
	case 0x8c:
		return "Bad authentication method"
	case 0x8d:
		return "Keep Alive timeout"
	case 0x8e:
		return "Session taken over"
	case 0x8f:
		return "Topic Filter invalid"
	case 0x90:
		return "Topic Name invalid"
	case 0x91:
		return "Packet Identifier in use"
	case 0x92:
		return "Packet Identifier not found"
	case 0x93:
		return "Receive Maximum exceeded"
	case 0x94:
		return "Topic Alias invalid"
	case 0x95:
		return "Packet too large"
	case 0x96:
		return "Message rate too high"
	case 0x97:
		return "Quota exceeded"
	case 0x98:
		return "Administrative action"
	case 0x99:
		return "Payload format invalid"
	case 0x9a:
		return "Retain not supported"
	case 0x9b:
		return "QoS not supported"
	case 0x9c:
		return "Use another server"
	case 0x9d:
		return "Server moved"
	case 0x9e:
		return "Shared Subscriptions not supported"
	case 0x9f:
		return "Connection rate exceeded"
	case 0xa0:
		return "Maximum connect time"
	case 0xa1:
		return "Subscription Identifiers not supported"
	case 0xa2:
		return "Wildcard Subscriptions not supported"
	}
	return fmt.Sprintf("Reason 0x%02x", code)
}

func (c *ctx) dissectMQTT(b []byte, base int) bool {
	if len(b) < 2 {
		return false
	}
	pktType := b[0] >> 4
	if pktType == 0 || pktType > 15 {
		return false
	}
	rem, hl, ok := mqttVarint(b, 1)
	if !ok {
		return false
	}
	off := hl
	if off+rem > len(b) {
		rem = len(b) - off
	}
	body := b[off : off+rem]
	c.addLayer("mqtt")
	c.proto = "mqtt"
	root := newNode(fmt.Sprintf("MQ Telemetry Transport (%s)", mqttTypeName(pktType)), base, off+rem)
	root.add(
		newField(fmt.Sprintf("Packet Type: %s (%d)", mqttTypeName(pktType), pktType), "", base, 1),
		newField(fmt.Sprintf("Flags: 0x%x", b[0]&0xf), "", base, 1),
		newField(fmt.Sprintf("Remaining Length: %d", rem), "", base+1, hl-1),
	)
	info := "MQTT " + mqttTypeName(pktType)
	p := 0

	switch pktType {
	case 1: // CONNECT
		proto, n, ok := mqttString(body, 0)
		if ok && n < len(body) {
			level := body[n]
			flags := body[n+1]
			keepalive := be16(body[n+2 : n+4])
			root.add(
				newField("Protocol Name: "+proto, "", base+off, n),
				newField(fmt.Sprintf("Protocol Level: %d", level), "", base+off+n, 1),
				newField(fmt.Sprintf("Connect Flags: 0x%02x (username=%d password=%d willRetain=%d willQoS=%d will=%d cleanStart=%d)",
					flags, (flags>>7)&1, (flags>>6)&1, (flags>>5)&1, (flags>>3)&3, (flags>>2)&1, (flags>>1)&1), "", base+off+n+1, 1),
				newField(fmt.Sprintf("Keep Alive: %d s", keepalive), "", base+off+n+2, 2),
			)
			p = n + 4
			if level >= 5 {
				props, np := mqttParseProps(body, p)
				if len(props) > 0 {
					pn := newField("Properties", "", 0, 0)
					pn.Children = props
					root.add(pn)
				}
				p = np
			}
			if id, np, ok := mqttString(body, p); ok {
				root.add(newField("Client ID: "+id, "", base+off+p, 2+len(id)))
				info += " client=" + id
				p = np
			}
			if flags&0x04 != 0 { // will
				wprops := []*Field(nil)
				if level >= 5 {
					var np int
					wprops, np = mqttParseProps(body, p)
					p = np
				}
				wtopic, np, ok := mqttString(body, p)
				if ok {
					wf := newField("Will Topic: "+wtopic, "", base+off+p, 2+len(wtopic))
					wf.Children = wprops
					p = np
					if wb, np2, ok := mqttBinary(body, p); ok {
						wf.add(newField(fmt.Sprintf("Will Payload (%d bytes)", len(wb)), hexPreview(wb, 32), base+off+p, len(wb)))
						p = np2
					}
					root.add(wf)
				}
			}
			if flags&0x80 != 0 {
				if u, np, ok := mqttString(body, p); ok {
					root.add(newField("Username: "+u, "", base+off+p, 2+len(u)))
					info += " user=" + u
					p = np
				}
			}
			if flags&0x40 != 0 {
				if pw, np, ok := mqttBinary(body, p); ok {
					root.add(newField(fmt.Sprintf("Password (%d bytes)", len(pw)), hexPreview(pw, 24), base+off+p, len(pw)))
					p = np
				}
			}
		}
	case 2: // CONNACK
		if len(body) >= 2 {
			root.add(newField(fmt.Sprintf("Session Present: %d", body[0]&1), "", base+off, 1))
			root.add(newField(fmt.Sprintf("Reason Code: %s", mqttReason(body[1])), "", base+off+1, 1))
			p = 2
			if mqttLooksLikeProps(body, p) {
				props, np := mqttParseProps(body, p)
				if len(props) > 0 {
					pn := newField("Properties", "", 0, 0)
					pn.Children = props
					root.add(pn)
				}
				p = np
			}
			info = fmt.Sprintf("MQTT CONNACK %s", mqttReason(body[1]))
		}
	case 3: // PUBLISH
		topic, n, ok := mqttString(body, 0)
		if ok {
			qos := (b[0] >> 1) & 3
			retain := b[0] & 1
			root.add(
				newField("Topic: "+topic, "", base+off, n),
				newField(fmt.Sprintf("QoS: %d", qos), "", base, 1),
				newField(fmt.Sprintf("Retain: %d", retain), "", base, 1),
			)
			p = n
			if qos > 0 && p+2 <= len(body) {
				root.add(newField(fmt.Sprintf("Packet ID: %d", be16(body[p:p+2])), "", base+off+p, 2))
				p += 2
			}
			if mqttLooksLikeProps(body, p) {
				props, np := mqttParseProps(body, p)
				if len(props) > 0 {
					pn := newField("Properties", "", 0, 0)
					pn.Children = props
					root.add(pn)
				}
				p = np
			}
			payload := body[min(p, len(body)):]
			root.add(newField(fmt.Sprintf("Payload (%d bytes)", len(payload)), hexPreview(payload, 48), base+off+p, len(payload)))
			info = fmt.Sprintf("MQTT PUBLISH topic=%s (%d bytes)", topic, len(payload))
		}
	case 4, 5, 6, 7, 9, 11: // PUBACK/PUBREC/PUBREL/PUBCOMP/SUBACK/UNSUBACK
		if len(body) >= 2 {
			root.add(newField(fmt.Sprintf("Packet ID: %d", be16(body[0:2])), "", base+off, 2))
			p = 2
			if p < len(body) {
				root.add(newField("Reason Code: "+mqttReason(body[p]), "", base+off+p, 1))
				p++
			}
			props, np := mqttParseProps(body, p)
			if len(props) > 0 {
				pn := newField("Properties", "", 0, 0)
				pn.Children = props
				root.add(pn)
			}
			p = np
			for i := 0; p < len(body); i++ {
				root.add(newField(fmt.Sprintf("Reason Code %d: %s", i+1, mqttReason(body[p])), "", base+off+p, 1))
				p++
			}
		}
	case 8, 10: // SUBSCRIBE / UNSUBSCRIBE
		if len(body) >= 2 {
			root.add(newField(fmt.Sprintf("Packet ID: %d", be16(body[0:2])), "", base+off, 2))
			p = 2
			if mqttLooksLikeProps(body, p) {
				props, np := mqttParseProps(body, p)
				if len(props) > 0 {
					pn := newField("Properties", "", 0, 0)
					pn.Children = props
					root.add(pn)
				}
				p = np
			}
			for i := 0; p+2 <= len(body); i++ {
				topic, np, ok := mqttString(body, p)
				if !ok {
					break
				}
				f := newField(fmt.Sprintf("Topic Filter %d: %s", i+1, topic), "", base+off+p, 2+len(topic))
				p = np
				if pktType == 8 && p < len(body) {
					f.add(newField(fmt.Sprintf("Options: 0x%02x (QoS %d)", body[p], body[p]&3), "", base+off+p, 1))
					p++
				}
				root.add(f)
			}
		}
	case 12, 13: // PINGREQ/PINGRESP
	case 14, 15: // DISCONNECT/AUTH
		if p < len(body) {
			root.add(newField("Reason Code: "+mqttReason(body[p]), "", base+off+p, 1))
			p++
		}
		props, np := mqttParseProps(body, p)
		if len(props) > 0 {
			pn := newField("Properties", "", 0, 0)
			pn.Children = props
			root.add(pn)
		}
		p = np
	}
	_ = p
	c.addRoot(root)
	c.appInfo = shorten(info, 120)
	return true
}

// ----------------------------------------------------------------- REDIS

var redisCommands = map[string]bool{
	"GET": true, "SET": true, "DEL": true, "EXISTS": true, "EXPIRE": true, "TTL": true,
	"INCR": true, "DECR": true, "MGET": true, "MSET": true, "KEYS": true, "SCAN": true,
	"LPUSH": true, "RPUSH": true, "LPOP": true, "RPOP": true, "LRANGE": true,
	"HSET": true, "HGET": true, "HGETALL": true, "HDEL": true, "SADD": true,
	"SMEMBERS": true, "ZADD": true, "ZRANGE": true, "PUBLISH": true, "SUBSCRIBE": true,
	"PING": true, "INFO": true, "AUTH": true, "SELECT": true, "MULTI": true, "EXEC": true,
	"TYPE": true, "CONFIG": true, "CLIENT": true, "EVAL": true, "SCRIPT": true,
}

func respLine(b []byte, off int) (string, int, bool) {
	if off >= len(b) {
		return "", off, false
	}
	if idx := bytes.Index(b[off:], []byte("\r\n")); idx >= 0 {
		return string(b[off : off+idx]), off + idx + 2, true
	}
	return "", off, false
}

func respValue(b []byte, off, depth int) (string, int, bool) {
	if depth > 6 || off >= len(b) {
		return "", off, false
	}
	switch b[off] {
	case '+', '-', ':':
		line, next, ok := respLine(b, off+1)
		return line, next, ok
	case '$':
		line, next, ok := respLine(b, off+1)
		if !ok {
			return "", off, false
		}
		n, err := strconv.Atoi(line)
		if err != nil || n < 0 {
			return line, next, true
		}
		if next+n > len(b) {
			return "", off, false
		}
		val := string(b[next : next+n])
		next += n
		if next+2 <= len(b) && b[next] == '\r' && b[next+1] == '\n' {
			next += 2
		}
		return val, next, true
	case '*', '~', '>', '%', '|':
		line, next, ok := respLine(b, off+1)
		if !ok {
			return "", off, false
		}
		n, err := strconv.Atoi(line)
		if err != nil || n < 0 {
			return line, next, true
		}
		count := n
		if b[off] == '%' || b[off] == '|' {
			count = n * 2
		}
		parts := make([]string, 0, count)
		for i := 0; i < count; i++ {
			val, p, ok := respValue(b, next, depth+1)
			if !ok {
				break
			}
			parts = append(parts, val)
			next = p
		}
		if b[off] == '%' || b[off] == '|' {
			pairs := make([]string, 0, n)
			for i := 0; i+1 < len(parts); i += 2 {
				pairs = append(pairs, parts[i]+"="+parts[i+1])
			}
			return strings.Join(pairs, " "), next, true
		}
		return strings.Join(parts, " "), next, true
	case '_':
		_, next, _ := respLine(b, off+1)
		return "null", next, true
	case '#':
		line, next, ok := respLine(b, off+1)
		if ok {
			if line == "t" {
				return "true", next, true
			}
			return "false", next, true
		}
	case ',':
		line, next, ok := respLine(b, off+1)
		return line, next, ok
	case '(':
		line, next, ok := respLine(b, off+1)
		return line, next, ok
	case '=':
		line, next, ok := respLine(b, off+1)
		if !ok {
			return "", off, false
		}
		n, err := strconv.Atoi(line)
		if err != nil || n < 0 || next+n > len(b) {
			return "", off, false
		}
		if n >= 4 {
			return string(b[next+4 : next+n]), next + n + 2, true
		}
		return string(b[next : next+n]), next + n, true
	case '!':
		line, next, ok := respLine(b, off+1)
		if !ok {
			return "", off, false
		}
		n, err := strconv.Atoi(line)
		if err != nil || n < 0 || next+n > len(b) {
			return "", off, false
		}
		return string(b[next : next+n]), next + n + 2, true
	}
	return "", off, false
}

func (c *ctx) dissectRedis(b []byte, base int) bool {
	if len(b) == 0 {
		return false
	}
	var args []string
	isRESP := strings.ContainsRune("*$+-:_#,(!%~>|=", rune(b[0]))
	val := ""
	if isRESP {
		v, _, ok := respValue(b, 0, 0)
		if !ok {
			return false
		}
		val = v
		args = strings.Split(v, " ")
	} else {
		line, _, ok := respLine(b, 0)
		if !ok {
			return false
		}
		args = strings.Fields(line)
	}
	if len(args) == 0 {
		return false
	}
	cmd := strings.ToUpper(args[0])
	if !redisCommands[cmd] {
		if !isRESP {
			return false
		}
		c.addLayer("redis")
		c.proto = "redis"
		root := newNode("Redis RESP3 Reply", base, len(b))
		root.add(newField(fmt.Sprintf("Response Type: %c", b[0]), "", base, 1), newField("Response: "+shorten(val, 240), "", base, len(b)))
		c.addRoot(root)
		c.appInfo = shorten("Redis reply: "+val, 140)
		return true
	}

	c.addLayer("redis")
	c.proto = "redis"
	root := newNode(fmt.Sprintf("Redis (%s)", cmd), base, len(b))
	root.add(newField("Command: "+cmd, "", base, len(args[0])))
	for i, arg := range args[1:] {
		root.add(newField(fmt.Sprintf("Argument %d: %s", i+1, shorten(arg, 120)), "", base, 0))
	}
	c.addRoot(root)
	c.appInfo = shorten("Redis "+strings.Join(args, " "), 120)
	return true
}

// ------------------------------------------------------------ PostgreSQL

func pgTypeName(t byte) string {
	switch t {
	case 'R':
		return "Authentication"
	case 'S':
		return "ParameterStatus / Sync"
	case 'K':
		return "BackendKeyData"
	case 'Z':
		return "ReadyForQuery"
	case 'T':
		return "RowDescription"
	case 'D':
		return "DataRow / Describe"
	case 'C':
		return "CommandComplete"
	case 'E':
		return "ErrorResponse / Execute"
	case 'N':
		return "NoticeResponse"
	case 'Q':
		return "Query"
	case 'P':
		return "Parse"
	case 'B':
		return "Bind"
	case 'A':
		return "NotificationResponse"
	case 'X':
		return "Terminate"
	case 'd':
		return "CopyData"
	case 'c':
		return "CopyDone"
	case 'f':
		return "CopyFail"
	case '1':
		return "ParseComplete"
	case '2':
		return "BindComplete"
	case '3':
		return "CloseComplete"
	case 'n':
		return "NoData"
	case 's':
		return "PortalSuspended"
	case 'I':
		return "EmptyQueryResponse"
	}
	return fmt.Sprintf("Message '%c'", t)
}

func pgCString(b []byte, off int) (string, int, bool) {
	if off >= len(b) {
		return "", off, false
	}
	end := bytes.IndexByte(b[off:], 0)
	if end < 0 {
		return string(b[off:]), len(b), true
	}
	return string(b[off : off+end]), off + end + 1, true
}

func pgErrorFields(b []byte) []*Field {
	var out []*Field
	names := map[byte]string{'S': "Severity", 'V': "Severity (non-localized)", 'C': "SQLSTATE Code", 'M': "Message", 'D': "Detail", 'H': "Hint", 'P': "Position", 'W': "Where", 's': "Schema", 't': "Table", 'c': "Column", 'd': "Data type", 'n': "Constraint", 'F': "File", 'L': "Line", 'R': "Routine"}
	for off := 0; off < len(b) && b[off] != 0; {
		code := b[off]
		off++
		val, next, ok := pgCString(b, off)
		if !ok {
			break
		}
		name := names[code]
		if name == "" {
			name = fmt.Sprintf("Field '%c'", code)
		}
		out = append(out, newField(name+": "+val, "", 0, 0))
		off = next
	}
	return out
}

func pgAuthName(code uint32) string {
	switch code {
	case 0:
		return "AuthenticationOk"
	case 2:
		return "KerberosV5"
	case 3:
		return "CleartextPassword"
	case 5:
		return "MD5Password"
	case 6:
		return "SCMCredential"
	case 7:
		return "GSS"
	case 8:
		return "GSSContinue"
	case 9:
		return "SSPI"
	case 10:
		return "SASL"
	case 11:
		return "SASLContinue"
	case 12:
		return "SASLFinal"
	}
	return fmt.Sprintf("Authentication %d", code)
}

func (c *ctx) dissectPostgreSQL(b []byte, base int) bool {
	if len(b) < 4 {
		return false
	}
	startupLen := 0
	if len(b) >= 8 {
		l := int(be32(b[0:4]))
		if l >= 8 && l <= 1<<20 {
			startupLen = l
		}
	}
	c.addLayer("postgresql")
	c.proto = "postgresql"
	info := "PostgreSQL"
	root := newNode("PostgreSQL", base, len(b))

	if startupLen > 0 && int(be32(b[4:8])) >= 196608 {
		length := startupLen
		code := be32(b[4:8])
		switch code {
		case 196608:
			root = newNode("PostgreSQL Startup Message", base, min(length, len(b)))
			root.add(newField(fmt.Sprintf("Length: %d", length), "", base, 4), newField("Protocol Version: 3.0", "", base+4, 4))
			off := 8
			kv := map[string]string{}
			for off < len(b) {
				key, n, ok := pgCString(b, off)
				if !ok || key == "" {
					break
				}
				val, n2, ok := pgCString(b, n)
				if !ok {
					break
				}
				kv[key] = val
				off = n2
			}
			info = "PostgreSQL startup"
			for _, k := range []string{"user", "database", "application_name", "client_encoding", "options"} {
				if v := kv[k]; v != "" {
					root.add(newField(k+": "+v, "", base, 0))
					if k == "user" {
						info += " user=" + v
					}
					if k == "database" {
						info += " db=" + v
					}
				}
			}
		case 80877103:
			root = newNode("PostgreSQL SSLRequest", base, min(length, len(b)))
			info = "PostgreSQL SSLRequest"
		case 80877102:
			root = newNode("PostgreSQL CancelRequest", base, min(length, len(b)))
			info = "PostgreSQL CancelRequest"
		}
	} else if len(b) >= 5 {
		typ := b[0]
		msgLen := int(be32(b[1:5]))
		if msgLen < 4 || 1+msgLen > len(b) {
			return false
		}
		name := pgTypeName(typ)
		root = newNode("PostgreSQL "+name, base, 1+msgLen)
		root.add(newField(fmt.Sprintf("Type: %c (%s)", typ, name), "", base, 1), newField(fmt.Sprintf("Length: %d", msgLen), "", base+1, 4))
		payload := b[5:min(1+msgLen, len(b))]
		info = "PostgreSQL " + name
		switch typ {
		case 'R':
			if len(payload) >= 4 {
				code := be32(payload[0:4])
				root.add(newField(fmt.Sprintf("Authentication: %s (%d)", pgAuthName(code), code), "", base+5, 4))
				info += ": " + pgAuthName(code)
			}
		case 'S':
			if key, n, ok := pgCString(payload, 0); ok {
				if val, _, ok := pgCString(payload, n); ok {
					root.add(newField("Parameter: "+key+" = "+val, "", base+5, len(payload)))
					info += ": " + key + "=" + val
				}
			}
		case 'K':
			if len(payload) >= 8 {
				root.add(newField(fmt.Sprintf("Backend PID: %d", be32(payload[0:4])), "", base+5, 4), newField(fmt.Sprintf("Secret Key: 0x%08x", be32(payload[4:8])), "", base+9, 4))
			}
		case 'Z':
			if len(payload) >= 1 {
				st := map[byte]string{'I': "idle", 'T': "in transaction", 'E': "failed transaction"}[payload[0]]
				root.add(newField("Transaction Status: "+st, "", base+5, 1))
			}
		case 'Q':
			q := trimNul(payload)
			root.add(newField("Query: "+shorten(q, 300), "", base+5, len(payload)))
			info += ": " + shorten(q, 80)
		case 'P':
			stmt, n, ok := pgCString(payload, 0)
			if ok {
				q, n2, ok := pgCString(payload, n)
				if ok {
					root.add(newField("Statement: "+stmt, "", base+5, n), newField("Query: "+shorten(q, 300), "", base+5+n, n2-n))
					info += ": " + shorten(q, 80)
					if n2+2 <= len(payload) {
						cnt := int(be16(payload[n2 : n2+2]))
						root.add(newField(fmt.Sprintf("Parameter Types: %d", cnt), "", base+5+n2, 2))
					}
				}
			}
		case 'B':
			portal, n, ok := pgCString(payload, 0)
			if ok {
				stmt, n2, ok := pgCString(payload, n)
				if ok {
					root.add(newField("Portal: "+portal, "", base+5, n), newField("Statement: "+stmt, "", base+5+n, n2-n))
					info += fmt.Sprintf(" portal=%s statement=%s", portal, stmt)
					if n2+2 <= len(payload) {
						fc := int(be16(payload[n2 : n2+2]))
						root.add(newField(fmt.Sprintf("Parameter Format Codes: %d", fc), "", base+5+n2, 2))
					}
				}
			}
		case 'T':
			if len(payload) >= 2 {
				nfields := int(be16(payload[0:2]))
				root.add(newField(fmt.Sprintf("Fields: %d", nfields), "", base+5, 2))
				p := 2
				for i := 0; i < nfields && p+18 <= len(payload); i++ {
					fname, n, ok := pgCString(payload, p)
					if !ok {
						break
					}
					p = n
					col := newField(fmt.Sprintf("Column %d: %s", i+1, fname), "", base+5+p, 18)
					if p+18 <= len(payload) {
						col.add(
							newField(fmt.Sprintf("Table OID: %d", be32(payload[p:p+4])), "", 0, 0),
							newField(fmt.Sprintf("Column ID: %d", be16(payload[p+4:p+6])), "", 0, 0),
							newField(fmt.Sprintf("Type OID: %d", be32(payload[p+6:p+10])), "", 0, 0),
							newField(fmt.Sprintf("Type Size: %d", int16(be16(payload[p+10:p+12]))), "", 0, 0),
							newField(fmt.Sprintf("Type Modifier: %d", int32(be32(payload[p+12:p+16]))), "", 0, 0),
							newField(fmt.Sprintf("Format: %d", be16(payload[p+16:p+18])), "", 0, 0),
						)
						p += 18
					}
					root.add(col)
				}
			}
		case 'D':
			// Ambiguous: backend DataRow or frontend Describe.
			if len(payload) >= 2 {
				cols := int(be16(payload[0:2]))
				if cols < 1024 && (cols == 0 || len(payload) > 2+4) {
					root.add(newField(fmt.Sprintf("Columns: %d", cols), "", base+5, 2))
					p := 2
					for i := 0; i < cols && p+4 <= len(payload); i++ {
						l := int(int32(be32(payload[p : p+4])))
						p += 4
						if l < 0 {
							root.add(newField(fmt.Sprintf("Column %d: NULL", i+1), "", 0, 0))
							continue
						}
						if p+l > len(payload) {
							break
						}
						v := payload[p : p+l]
						txt := string(v)
						if !isPrintable(v) {
							txt = hexPreview(v, 32)
						}
						root.add(newField(fmt.Sprintf("Column %d: %s", i+1, shorten(txt, 120)), "", base+5+p, l))
						p += l
					}
					info += fmt.Sprintf(" rows=%d", cols)
					break
				}
			}
			target := "S"
			if len(payload) > 0 {
				target = string(payload[0])
			}
			nm, _, _ := pgCString(payload, 1)
			root.add(newField("Describe Target: "+target, "", base+5, 1), newField("Name: "+nm, "", 0, 0))
			info += " target=" + target
		case 'E':
			// Ambiguous: backend ErrorResponse or frontend Execute.
			if len(payload) > 0 && strings.IndexByte("SVCMDHPWstcdnFLR", payload[0]) >= 0 {
				fields := pgErrorFields(payload)
				root.add(fields...)
				for _, f := range fields {
					if strings.HasPrefix(f.Label, "Message: ") {
						info += ": " + shorten(f.Label, 80)
						break
					}
				}
			} else {
				portal, _, _ := pgCString(payload, 0)
				root.add(newField("Portal: "+portal, "", 0, 0))
				info += " portal=" + portal
			}
		case 'N':
			root.add(pgErrorFields(payload)...)
		case 'C':
			s := trimNul(payload)
			root.add(newField("Tag: "+s, "", base+5, len(payload)))
			info += ": " + s
		case 'A':
			if len(payload) >= 4 {
				pid := be32(payload[0:4])
				ch, n, ok := pgCString(payload, 4)
				if ok {
					msg, _, _ := pgCString(payload, n)
					root.add(newField(fmt.Sprintf("PID: %d", pid), "", base+5, 4), newField("Channel: "+ch, "", base+9, n-4), newField("Payload: "+shorten(msg, 120), "", 0, 0))
					info = fmt.Sprintf("PostgreSQL NOTIFY %s: %s", ch, shorten(msg, 60))
				}
			}
		}
	} else {
		return false
	}

	c.addRoot(root)
	c.appInfo = shorten(info, 120)
	return true
}

func isPrintable(b []byte) bool {
	for _, c := range b {
		if c < 32 && c != 9 && c != 10 && c != 13 {
			return false
		}
		if c > 126 {
			return false
		}
	}
	return true
}

// -------------------------------------------------------------------- BGP

var bgpTypes = map[byte]string{1: "OPEN", 2: "UPDATE", 3: "NOTIFICATION", 4: "KEEPALIVE", 5: "ROUTE-REFRESH"}

func bgpPrefixList(data []byte, afi uint16, addPath bool) []string {
	var out []string
	for p := 0; p < len(data); {
		if addPath {
			if p+4 > len(data) {
				break
			}
			p += 4
		}
		if p >= len(data) {
			break
		}
		bits := int(data[p])
		p++
		max := 4
		if afi == 2 {
			max = 16
		}
		if bits > max*8 {
			break
		}
		n := (bits + 7) / 8
		if p+n > len(data) {
			break
		}
		var ip netip.Addr
		if afi == 2 {
			var a [16]byte
			copy(a[:], data[p:p+n])
			ip = netip.AddrFrom16(a)
		} else {
			var a [4]byte
			copy(a[:], data[p:p+n])
			ip = netip.AddrFrom4(a)
		}
		out = append(out, fmt.Sprintf("%s/%d", ip, bits))
		p += n
	}
	return out
}

func bgpASPath(v []byte) string {
	var segs []string
	for p := 0; p+2 <= len(v); {
		st, cnt := v[p], int(v[p+1])
		p += 2
		asnSize := 2
		if p+cnt*4 <= len(v) && (p+cnt*4 == len(v) || cnt == 0) {
			asnSize = 4
		}
		var asns []string
		for i := 0; i < cnt && p+asnSize <= len(v); i++ {
			if asnSize == 4 {
				asns = append(asns, strconv.Itoa(int(be32(v[p:p+4]))))
				p += 4
			} else {
				asns = append(asns, strconv.Itoa(int(be16(v[p:p+2]))))
				p += 2
			}
		}
		kind := map[byte]string{1: "AS_SET", 2: "AS_SEQUENCE", 3: "AS_CONFED_SEQUENCE", 4: "AS_CONFED_SET"}[st]
		if kind == "" {
			kind = fmt.Sprintf("Segment %d", st)
		}
		segs = append(segs, kind+" ["+strings.Join(asns, " ")+"]")
	}
	return strings.Join(segs, " ")
}

func bgpCommunity(v uint32) string {
	switch v {
	case 0xffffff01:
		return "NO_EXPORT"
	case 0xffffff02:
		return "NO_ADVERTISE"
	case 0xffffff03:
		return "NO_EXPORT_SUBCONFED"
	case 0xffffff04:
		return "NOPEER"
	}
	return fmt.Sprintf("%d:%d", v>>16, v&0xffff)
}

func bgpCapability(code byte, v []byte) string {
	switch code {
	case 1:
		if len(v) >= 4 {
			return fmt.Sprintf("Multiprotocol AFI=%d SAFI=%d", be16(v[0:2]), v[3])
		}
	case 2:
		return "Route Refresh"
	case 3:
		return "Outbound Route Filtering"
	case 5:
		if len(v) >= 6 {
			return fmt.Sprintf("Extended Next Hop AFI=%d SAFI=%d NH-AFI=%d", be16(v[0:2]), be16(v[2:4]), be16(v[4:6]))
		}
	case 6:
		return "Extended Message"
	case 7:
		return "BGPsec"
	case 8:
		return "Multiple Labels"
	case 9:
		if len(v) >= 1 {
			role := map[byte]string{0: "Provider", 1: "RS", 2: "RS-Client", 3: "Customer"}[v[0]]
			return "BGP Role: " + role
		}
	case 64:
		if len(v) >= 2 {
			restart := be16(v[0:2]) & 0x0fff
			return fmt.Sprintf("Graceful Restart %d s", restart)
		}
	case 65:
		if len(v) >= 4 {
			return fmt.Sprintf("4-octet ASN %d", be32(v[0:4]))
		}
	case 67:
		return "Dynamic Capability"
	case 69:
		return "Add-Path"
	case 70:
		return "Enhanced Route Refresh"
	case 71:
		return "Long-Lived Graceful Restart"
	case 72:
		if len(v) >= 1 {
			hl := int(v[0])
			if 1+hl <= len(v) {
				host := string(v[1 : 1+hl])
				rest := v[1+hl:]
				dom := ""
				if len(rest) >= 1 && 1+int(rest[0]) <= len(rest) {
					dom = string(rest[1 : 1+int(rest[0])])
				}
				return "FQDN " + host + " " + dom
			}
		}
	case 73:
		return "Software Version " + string(v)
	}
	return hexPreview(v, 32)
}

func bgpAttrs(data []byte, base int) []*Field {
	var out []*Field
	for p := 0; p+3 <= len(data); {
		flags, typ := data[p], data[p+1]
		p += 2
		l := int(data[p])
		p++
		if flags&0x10 != 0 {
			if p >= len(data) {
				break
			}
			l = int(be16(data[p-1 : p+1]))
			p++
		}
		if p+l > len(data) {
			break
		}
		v := data[p : p+l]
		name := map[byte]string{1: "ORIGIN", 2: "AS_PATH", 3: "NEXT_HOP", 4: "MULTI_EXIT_DISC", 5: "LOCAL_PREF", 6: "ATOMIC_AGGREGATE", 7: "AGGREGATOR", 8: "COMMUNITIES", 9: "ORIGINATOR_ID", 10: "CLUSTER_LIST", 14: "MP_REACH_NLRI", 15: "MP_UNREACH_NLRI", 16: "EXTENDED_COMMUNITIES", 17: "AS4_PATH", 18: "AS4_AGGREGATOR", 26: "AIGP", 32: "LARGE_COMMUNITIES", 35: "ONLY_TO_CUSTOMER"}[typ]
		if name == "" {
			name = fmt.Sprintf("Attribute %d", typ)
		}
		f := newField(fmt.Sprintf("%s (flags 0x%02x, %d bytes)", name, flags, l), "", base+p-l, l)
		switch typ {
		case 1:
			if len(v) > 0 {
				f.Value = map[byte]string{0: "IGP", 1: "EGP", 2: "INCOMPLETE"}[v[0]]
			}
		case 2, 17:
			f.Value = bgpASPath(v)
		case 3:
			if len(v) == 4 {
				f.Value = netip.AddrFrom4([4]byte{v[0], v[1], v[2], v[3]}).String()
			}
		case 4, 5:
			if len(v) == 4 {
				f.Value = strconv.Itoa(int(be32(v)))
			}
		case 6:
			f.Value = "Atomic aggregate"
		case 7, 18:
			if len(v) >= 6 {
				asnSize := 2
				if len(v) == 8 {
					asnSize = 4
				}
				ipOff := asnSize
				if ipOff+4 <= len(v) {
					if asnSize == 4 {
						f.Value = fmt.Sprintf("AS%d %s", be32(v[0:4]), netip.AddrFrom4([4]byte{v[4], v[5], v[6], v[7]}))
					} else {
						f.Value = fmt.Sprintf("AS%d %s", be16(v[0:2]), netip.AddrFrom4([4]byte{v[2], v[3], v[4], v[5]}))
					}
				}
			}
		case 8:
			var cs []string
			for i := 0; i+4 <= len(v); i += 4 {
				cs = append(cs, bgpCommunity(be32(v[i:i+4])))
			}
			f.Value = strings.Join(cs, " ")
		case 9:
			if len(v) == 4 {
				f.Value = netip.AddrFrom4([4]byte{v[0], v[1], v[2], v[3]}).String()
			}
		case 10:
			var ips []string
			for i := 0; i+4 <= len(v); i += 4 {
				ips = append(ips, netip.AddrFrom4([4]byte{v[i], v[i+1], v[i+2], v[i+3]}).String())
			}
			f.Value = strings.Join(ips, " ")
		case 14, 15:
			if len(v) >= 3 {
				afi := be16(v[0:2])
				safi := v[2]
				if typ == 14 && len(v) >= 5 {
					nhLen := int(v[3])
					if 5+nhLen <= len(v) {
						nh := v[4 : 4+nhLen]
						rest := v[5+nhLen:]
						if len(rest) > 0 {
							rest = rest[1:]
						}
						nhStr := hexPreview(nh, 16)
						if a, ok := netip.AddrFromSlice(nh); ok {
							nhStr = a.String()
						}
						f.Value = fmt.Sprintf("AFI=%d SAFI=%d next-hop=%s NLRI=%s", afi, safi, nhStr, strings.Join(bgpPrefixList(rest, afi, false), " "))
					}
				} else if typ == 15 {
					f.Value = fmt.Sprintf("AFI=%d SAFI=%d withdrawn=%s", afi, safi, strings.Join(bgpPrefixList(v[3:], afi, false), " "))
				}
			}
		case 16:
			f.Value = hexPreview(v, 64)
		case 32:
			var cs []string
			for i := 0; i+12 <= len(v); i += 12 {
				cs = append(cs, fmt.Sprintf("%d:%d:%d", be32(v[i:i+4]), be32(v[i+4:i+8]), be32(v[i+8:i+12])))
			}
			f.Value = strings.Join(cs, " ")
		}
		out = append(out, f)
		p += l
	}
	return out
}

func (c *ctx) dissectBGP(b []byte, base int) bool {
	if len(b) < 19 {
		return false
	}
	for i := 0; i < 16; i++ {
		if b[i] != 0xff {
			return false
		}
	}
	c.addLayer("bgp")
	c.proto = "bgp"
	root := newNode("Border Gateway Protocol", base, len(b))
	off := 0
	info := "BGP"
	for off+19 <= len(b) {
		length := int(be16(b[off+16 : off+18]))
		typ := b[off+18]
		if length < 19 || off+length > len(b) {
			break
		}
		msg := b[off : off+length]
		name := bgpTypes[typ]
		if name == "" {
			name = fmt.Sprintf("Type %d", typ)
		}
		f := newField(fmt.Sprintf("%s (length %d)", name, length), "", base+off, length)
		f.add(
			newField("Marker: 16 bytes", "", base+off, 16),
			newField(fmt.Sprintf("Length: %d", length), "", base+off+16, 2),
			newField(fmt.Sprintf("Type: %s (%d)", name, typ), "", base+off+18, 1),
		)
		switch typ {
		case 1: // OPEN
			if len(msg) >= 29 {
				asn := be16(msg[20:22])
				hold := be16(msg[22:24])
				routerID := netip.AddrFrom4([4]byte{msg[24], msg[25], msg[26], msg[27]}).String()
				optLen := int(msg[28])
				f.add(
					newField(fmt.Sprintf("Version: %d", msg[19]), "", base+off+19, 1),
					newField(fmt.Sprintf("My AS: %d", asn), "", base+off+20, 2),
					newField(fmt.Sprintf("Hold Time: %d s", hold), "", base+off+22, 2),
					newField("BGP Identifier: "+routerID, "", base+off+24, 4),
					newField(fmt.Sprintf("Optional Parameters Length: %d", optLen), "", base+off+28, 1),
				)
				info = fmt.Sprintf("BGP OPEN AS%d router=%s", asn, routerID)
				var caps []string
				for p := 29; p+2 <= len(msg) && p < 29+optLen; {
					pt, pl := msg[p], int(msg[p+1])
					p += 2
					if p+pl > len(msg) {
						break
					}
					pv := msg[p : p+pl]
					p += pl
					if pt != 2 {
						continue
					}
					for q := 0; q+2 <= len(pv); {
						code, cl := pv[q], int(pv[q+1])
						q += 2
						if q+cl > len(pv) {
							break
						}
						desc := bgpCapability(code, pv[q:q+cl])
						f.add(newField(fmt.Sprintf("Capability %d: %s", code, desc), hexPreview(pv[q:q+cl], 24), base+off+p-pl+q-2, cl))
						caps = append(caps, desc)
						q += cl
					}
				}
				if len(caps) > 0 {
					info += " caps=" + shorten(strings.Join(caps, ", "), 80)
				}
			}
		case 2: // UPDATE
			if len(msg) >= 23 {
				wlen := int(be16(msg[19:21]))
				alenOff := 21 + wlen
				f.add(newField(fmt.Sprintf("Withdrawn Routes Length: %d", wlen), "", base+off+19, 2))
				withdrawn := []string{}
				if wlen > 0 && 21+wlen <= len(msg) {
					withdrawn = bgpPrefixList(msg[21:21+wlen], 1, false)
					f.add(newField("Withdrawn Routes: "+strings.Join(withdrawn, " "), "", base+off+21, wlen))
				}
				if alenOff+2 <= len(msg) {
					alen := int(be16(msg[alenOff : alenOff+2]))
					f.add(newField(fmt.Sprintf("Path Attributes Length: %d", alen), "", base+off+alenOff, 2))
					attrStart := alenOff + 2
					if attrStart+alen <= len(msg) {
						attrs := bgpAttrs(msg[attrStart:attrStart+alen], base+off+attrStart)
						f.add(attrs...)
						nlri := msg[attrStart+alen:]
						prefixes := bgpPrefixList(nlri, 1, false)
						if len(prefixes) > 0 {
							f.add(newField("NLRI: "+strings.Join(prefixes, " "), "", base+off+attrStart+alen, len(nlri)))
						}
						info = fmt.Sprintf("BGP UPDATE withdrawn=%d prefixes=%d attrs=%d", len(withdrawn), len(prefixes), len(attrs))
					}
				}
			}
		case 3: // NOTIFICATION
			if len(msg) >= 21 {
				errCode, sub := msg[19], msg[20]
				codes := map[byte]string{1: "Message Header Error", 2: "OPEN Message Error", 3: "UPDATE Message Error", 4: "Hold Timer Expired", 5: "FSM Error", 6: "Cease", 7: "Route Refresh Error", 8: "Send Hold Timer Expired"}
				cname := codes[errCode]
				if cname == "" {
					cname = fmt.Sprintf("Code %d", errCode)
				}
				f.add(
					newField(fmt.Sprintf("Error Code: %s (%d)", cname, errCode), "", base+off+19, 1),
					newField(fmt.Sprintf("Error Subcode: %d", sub), "", base+off+20, 1),
					newField("Data: "+hexPreview(msg[21:], 48), "", base+off+21, len(msg)-21),
				)
				info = fmt.Sprintf("BGP NOTIFICATION %s sub=%d", cname, sub)
			}
		case 4:
			info = "BGP KEEPALIVE"
		case 5:
			if len(msg) >= 23 {
				afi := be16(msg[19:21])
				safi := msg[22]
				f.add(newField(fmt.Sprintf("AFI: %d", afi), "", base+off+19, 2), newField("Reserved: "+strconv.Itoa(int(msg[21])), "", base+off+21, 1), newField(fmt.Sprintf("SAFI: %d", safi), "", base+off+22, 1))
				info = fmt.Sprintf("BGP ROUTE-REFRESH AFI=%d SAFI=%d", afi, safi)
			}
		}
		root.add(f)
		off += length
	}
	c.addRoot(root)
	c.appInfo = shorten(info, 120)
	return true
}

// ------------------------------------------------------------- WireGuard

func (c *ctx) dissectWireGuard(b []byte, base int) bool {
	if len(b) < 4 {
		return false
	}
	typ := b[0]
	if typ < 1 || typ > 4 {
		return false
	}
	if b[1] != 0 || b[2] != 0 || b[3] != 0 {
		return false
	}
	names := []string{"", "handshake initiation", "handshake response", "cookie reply", "transport data"}
	c.addLayer("wireguard")
	c.proto = "wireguard"
	root := newNode("WireGuard ("+names[typ]+")", base, len(b))
	root.add(
		newField(fmt.Sprintf("Message Type: %d (%s)", typ, names[typ]), "", base, 1),
		newField("Reserved: 0", "", base+1, 3),
	)
	switch typ {
	case 1: // handshake initiation
		if len(b) >= 148 {
			root.add(
				newField(fmt.Sprintf("Sender Index: 0x%08x", be32(b[4:8])), "", base+4, 4),
				newField("Unencrypted Ephemeral: "+hexPreview(b[8:40], 32), "", base+8, 32),
				newField("Encrypted Static: "+hexPreview(b[40:88], 48), "", base+40, 48),
				newField("Encrypted Timestamp: "+hexPreview(b[88:116], 28), "", base+88, 28),
				newField("MAC1: "+hexPreview(b[116:132], 16), "", base+116, 16),
				newField("MAC2: "+hexPreview(b[132:148], 16), "", base+132, 16),
			)
		}
	case 2: // handshake response
		if len(b) >= 92 {
			root.add(
				newField(fmt.Sprintf("Sender Index: 0x%08x", be32(b[4:8])), "", base+4, 4),
				newField(fmt.Sprintf("Receiver Index: 0x%08x", be32(b[8:12])), "", base+8, 4),
				newField("Unencrypted Ephemeral: "+hexPreview(b[12:44], 32), "", base+12, 32),
				newField("Encrypted Nothing: "+hexPreview(b[44:60], 16), "", base+44, 16),
				newField("MAC1: "+hexPreview(b[60:76], 16), "", base+60, 16),
				newField("MAC2: "+hexPreview(b[76:92], 16), "", base+76, 16),
			)
		}
	case 3: // cookie reply
		if len(b) >= 64 {
			root.add(
				newField(fmt.Sprintf("Receiver Index: 0x%08x", be32(b[4:8])), "", base+4, 4),
				newField("Nonce: "+hexPreview(b[8:32], 24), "", base+8, 24),
				newField("Encrypted Cookie: "+hexPreview(b[32:64], 32), "", base+32, 32),
			)
		}
	case 4: // transport data
		if len(b) >= 16 {
			root.add(
				newField(fmt.Sprintf("Receiver Index: 0x%08x", be32(b[4:8])), "", base+4, 4),
				newField(fmt.Sprintf("Counter: %d", be64(b[8:16])), "", base+8, 8),
				newField(fmt.Sprintf("Encrypted Payload (%d bytes)", len(b)-16), hexPreview(b[16:], 48), base+16, len(b)-16),
			)
		}
	}
	c.addRoot(root)
	c.appInfo = "WireGuard " + names[typ]
	return true
}

// ---------------------------------------------------------------- SNMP BER

type berTLV struct {
	tag   byte
	value []byte
	next  int
}

func berRead(b []byte, off int) (berTLV, bool) {
	if off >= len(b) {
		return berTLV{}, false
	}
	tag := b[off]
	off++
	if off >= len(b) {
		return berTLV{}, false
	}
	l := int(b[off])
	off++
	if l&0x80 != 0 {
		n := l & 0x7f
		if n == 0 || n > 4 || off+n > len(b) {
			return berTLV{}, false
		}
		l = 0
		for i := 0; i < n; i++ {
			l = l<<8 | int(b[off+i])
		}
		off += n
	}
	if off+l > len(b) {
		l = len(b) - off
	}
	return berTLV{tag: tag, value: b[off : off+l], next: off + l}, true
}

func berInt(b []byte) int64 {
	var v int64
	for _, x := range b {
		v = v<<8 | int64(x)
	}
	return v
}

func berOID(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	parts := []int{int(b[0]) / 40, int(b[0]) % 40}
	v := 0
	for _, x := range b[1:] {
		v = v<<7 | int(x&0x7f)
		if x&0x80 == 0 {
			parts = append(parts, v)
			v = 0
		}
	}
	var sb strings.Builder
	for i, p := range parts {
		if i > 0 {
			sb.WriteByte('.')
		}
		sb.WriteString(strconv.Itoa(p))
	}
	return sb.String()
}

func berValue(t berTLV) string {
	switch t.tag {
	case 0x05:
		return "NULL"
	case 0x02:
		return strconv.FormatInt(berInt(t.value), 10)
	case 0x04:
		return shorten(string(t.value), 120)
	case 0x06:
		return berOID(t.value)
	case 0x40:
		if len(t.value) == 4 {
			return netip.AddrFrom4([4]byte{t.value[0], t.value[1], t.value[2], t.value[3]}).String()
		}
	case 0x41, 0x42, 0x43:
		return strconv.FormatInt(berInt(t.value), 10)
	}
	if len(t.value) == 0 {
		return ""
	}
	return hexPreview(t.value, 32)
}

var snmpPDUNames = map[byte]string{
	0xA0: "GET-REQUEST", 0xA1: "GET-NEXT-REQUEST", 0xA2: "GET-RESPONSE",
	0xA3: "SET-REQUEST", 0xA4: "TRAP-V1", 0xA5: "GET-BULK-REQUEST",
	0xA6: "INFORM-REQUEST", 0xA7: "TRAP-V2", 0xA8: "REPORT",
}

func snmpVersion(v int64) string {
	switch v {
	case 0:
		return "v1"
	case 1:
		return "v2c"
	case 3:
		return "v3"
	}
	return fmt.Sprintf("version %d", v)
}

func snmpErrorStatus(v int64) string {
	names := []string{"noError", "tooBig", "noSuchName", "badValue", "readOnly", "genErr", "noAccess", "wrongType", "wrongLength", "wrongEncoding", "wrongValue", "noCreation", "inconsistentValue", "resourceUnavailable", "commitFailed", "undoFailed", "authorizationError", "notWritable", "inconsistentName"}
	if int(v) >= 0 && int(v) < len(names) {
		return names[v]
	}
	return fmt.Sprintf("status %d", v)
}

func snmpVarbinds(list []byte, root *Field, base int) string {
	first := ""
	pos := 0
	for i := 0; i < 128; i++ {
		vb, ok := berRead(list, pos)
		if !ok || vb.tag != 0x30 {
			break
		}
		pos = vb.next
		o, ok := berRead(vb.value, 0)
		if !ok || o.tag != 0x06 {
			continue
		}
		oid := berOID(o.value)
		if first == "" {
			first = oid
		}
		val, ok := berRead(vb.value, o.next)
		if !ok {
			root.add(newField(oid+" = <missing>", "", base, 0))
			continue
		}
		switch val.tag {
		case 0x80:
			root.add(newField(oid+" = noSuchObject", "", base, 0))
		case 0x81:
			root.add(newField(oid+" = noSuchInstance", "", base, 0))
		case 0x82:
			root.add(newField(oid+" = endOfMibView", "", base, 0))
		default:
			root.add(newField(oid+" = "+berValue(val), "", base, 0))
		}
	}
	return first
}

func snmpPDU(pdu berTLV, root *Field, base int) (string, string) {
	name := snmpPDUNames[pdu.tag]
	if name == "" {
		return "", ""
	}
	info := name
	pos := 0
	if pdu.tag == 0xA4 { // SNMPv1 Trap-PDU
		ent, ok := berRead(pdu.value, pos)
		if ok && ent.tag == 0x06 {
			root.add(newField("Enterprise: "+berOID(ent.value), "", base, 0))
			pos = ent.next
		}
		agent, ok := berRead(pdu.value, pos)
		if ok && agent.tag == 0x40 {
			root.add(newField("Agent Address: "+berValue(agent), "", base, 0))
			pos = agent.next
		}
		gen, ok := berRead(pdu.value, pos)
		if ok {
			gn := map[int64]string{0: "coldStart", 1: "warmStart", 2: "linkDown", 3: "linkUp", 4: "authenticationFailure", 5: "egpNeighborLoss", 6: "enterpriseSpecific"}[berInt(gen.value)]
			root.add(newField(fmt.Sprintf("Generic Trap: %s (%d)", gn, berInt(gen.value)), "", base, 0))
			pos = gen.next
			info += " " + gn
		}
		spec, ok := berRead(pdu.value, pos)
		if ok {
			root.add(newField(fmt.Sprintf("Specific Trap: %d", berInt(spec.value)), "", base, 0))
			pos = spec.next
		}
		ts, ok := berRead(pdu.value, pos)
		if ok {
			root.add(newField(fmt.Sprintf("Time Stamp: %d", berInt(ts.value)), "", base, 0))
			pos = ts.next
		}
	} else {
		req, ok := berRead(pdu.value, pos)
		if ok {
			root.add(newField(fmt.Sprintf("Request ID: %d", berInt(req.value)), "", base, 0))
			pos = req.next
		}
		st, ok := berRead(pdu.value, pos)
		if ok {
			label := "Error Status"
			if pdu.tag == 0xA5 {
				label = "Non-repeaters"
			}
			root.add(newField(fmt.Sprintf("%s: %s (%d)", label, snmpErrorStatus(berInt(st.value)), berInt(st.value)), "", base, 0))
			pos = st.next
		}
		idx, ok := berRead(pdu.value, pos)
		if ok {
			label := "Error Index"
			if pdu.tag == 0xA5 {
				label = "Max Repetitions"
			}
			root.add(newField(fmt.Sprintf("%s: %d", label, berInt(idx.value)), "", base, 0))
			pos = idx.next
		}
	}
	vbs, ok := berRead(pdu.value, pos)
	if ok && vbs.tag == 0x30 {
		oid := snmpVarbinds(vbs.value, root, base)
		if oid != "" {
			info += " " + oid
		}
	}
	return name, info
}

func (c *ctx) dissectSNMP(b []byte, base int) bool {
	if len(b) < 4 || b[0] != 0x30 {
		return false
	}
	outer, ok := berRead(b, 0)
	if !ok {
		return false
	}
	ver, ok := berRead(outer.value, 0)
	if !ok || ver.tag != 0x02 {
		return false
	}
	version := berInt(ver.value)
	if version != 0 && version != 1 && version != 3 {
		return false
	}
	c.addLayer("snmp")
	c.proto = "snmp"
	root := newNode("Simple Network Management Protocol", base, len(b))
	root.add(newField(fmt.Sprintf("Version: %s (%d)", snmpVersion(version), version), "", base, 0))
	info := "SNMP " + snmpVersion(version)

	if version == 3 {
		header, ok := berRead(outer.value, ver.next)
		if !ok || header.tag != 0x30 {
			return false
		}
		hpos := 0
		msgID, ok := berRead(header.value, hpos)
		if ok {
			root.add(newField(fmt.Sprintf("Message ID: %d", berInt(msgID.value)), "", base, 0))
			hpos = msgID.next
		}
		maxSize, ok := berRead(header.value, hpos)
		if ok {
			root.add(newField(fmt.Sprintf("Max Message Size: %d", berInt(maxSize.value)), "", base, 0))
			hpos = maxSize.next
		}
		flags, ok := berRead(header.value, hpos)
		if ok {
			fv := byte(0)
			if len(flags.value) > 0 {
				fv = flags.value[0]
			}
			root.add(newField(fmt.Sprintf("Flags: 0x%02x (auth=%d priv=%d reportable=%d)", fv, (fv>>0)&1, (fv>>1)&1, (fv>>2)&1), "", base, 0))
			hpos = flags.next
		}
		secModel, ok := berRead(header.value, hpos)
		if ok {
			root.add(newField(fmt.Sprintf("Security Model: %d", berInt(secModel.value)), "", base, 0))
		}
		sec, ok := berRead(outer.value, header.next)
		if !ok || sec.tag != 0x04 {
			return false
		}
		usm, ok := berRead(sec.value, 0)
		if ok && usm.tag == 0x30 {
			up := 0
			names := []string{"Engine ID", "Engine Boots", "Engine Time", "User Name", "Authentication Parameters", "Privacy Parameters"}
			for i := 0; i < len(names); i++ {
				t, ok := berRead(usm.value, up)
				if !ok {
					break
				}
				up = t.next
				val := string(t.value)
				if i == 0 || i == 3 || i == 4 || i == 5 {
					val = hexPreview(t.value, 32)
					if t.tag == 0x04 && i == 3 {
						val = string(t.value)
					}
				}
				if i == 1 || i == 2 {
					val = strconv.FormatInt(berInt(t.value), 10)
				}
				root.add(newField(names[i]+": "+val, "", base, 0))
				if i == 3 {
					info += " user=" + string(t.value)
				}
			}
		}
		data, ok := berRead(outer.value, sec.next)
		if !ok || data.tag != 0x30 {
			return false
		}
		dpos := 0
		if ce, ok := berRead(data.value, dpos); ok {
			root.add(newField("Context Engine ID: "+hexPreview(ce.value, 32), "", base, 0))
			dpos = ce.next
		}
		if cn, ok := berRead(data.value, dpos); ok {
			root.add(newField("Context Name: "+string(cn.value), "", base, 0))
			dpos = cn.next
		}
		scoped, ok := berRead(data.value, dpos)
		if !ok {
			return false
		}
		if scoped.tag == 0x04 {
			root.add(newField("Encrypted PDU: "+hexPreview(scoped.value, 64), "", base, 0))
			info += " encrypted"
		} else if name, pduInfo := snmpPDU(scoped, root, base); name != "" {
			root.Label = "Simple Network Management Protocol (" + name + ")"
			root.add(newField(fmt.Sprintf("PDU: %s (0x%02x)", name, scoped.tag), "", base, 0))
			info += " " + pduInfo
		}
	} else {
		community, ok := berRead(outer.value, ver.next)
		if !ok || community.tag != 0x04 {
			return false
		}
		pdu, ok := berRead(outer.value, community.next)
		if !ok {
			return false
		}
		name, pduInfo := snmpPDU(pdu, root, base)
		if name == "" {
			return false
		}
		root.Label = "Simple Network Management Protocol (" + name + ")"
		root.add(newField("Community: "+string(community.value), "", base, 0), newField(fmt.Sprintf("PDU: %s (0x%02x)", name, pdu.tag), "", base, 0))
		info += " " + name + " community=" + string(community.value) + " " + pduInfo
	}
	c.addRoot(root)
	c.appInfo = shorten(info, 120)
	return true
}

// ------------------------------------------------------------------ SSDP

func (c *ctx) dissectSSDP(b []byte, base int) bool {
	line, rest, ok := bytes.Cut(b, []byte("\n"))
	if !ok {
		return false
	}
	first := strings.TrimRight(string(line), "\r")
	isRequest := strings.HasPrefix(first, "M-SEARCH ") || strings.HasPrefix(first, "NOTIFY ")
	isResponse := strings.HasPrefix(first, "HTTP/1.1 ")
	if !isRequest && !isResponse {
		return false
	}
	c.addLayer("ssdp")
	c.proto = "ssdp"
	root := newNode("Simple Service Discovery Protocol", base, len(b))
	root.add(newField(first, "", base, len(line)))
	headers := map[string]string{}
	for _, hl := range strings.Split(string(rest), "\n") {
		hl = strings.TrimRight(hl, "\r")
		if hl == "" {
			break
		}
		k, v, ok := strings.Cut(hl, ":")
		if ok {
			headers[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
			root.add(newField(hl, "", base, 0))
		}
	}
	info := "SSDP " + strings.Split(first, " ")[0]
	if isResponse {
		info = "SSDP " + first
	}
	if v := headers["st"]; v != "" {
		info += " ST=" + v
	}
	if v := headers["nt"]; v != "" {
		info += " NT=" + v
	}
	if v := headers["usn"]; v != "" {
		info += " USN=" + v
	}
	c.addRoot(root)
	c.appInfo = shorten(info, 120)
	return true
}

// ------------------------------------------------------------------- SIP

var sipMethods = map[string]bool{
	"INVITE": true, "ACK": true, "BYE": true, "CANCEL": true, "OPTIONS": true,
	"REGISTER": true, "SUBSCRIBE": true, "NOTIFY": true, "PUBLISH": true,
	"MESSAGE": true, "REFER": true, "INFO": true, "UPDATE": true, "PRACK": true,
}

func sipHeaderName(k string) string {
	k = strings.ToLower(strings.TrimSpace(k))
	names := map[string]string{"v": "via", "f": "from", "t": "to", "i": "call-id", "m": "contact", "l": "content-length", "c": "content-type", "s": "subject", "k": "supported"}
	if n := names[k]; n != "" {
		return n
	}
	return k
}

func sipSDP(body []byte, root *Field, base int) {
	sdp := newField("Session Description Protocol (SDP)", "", base, len(body))
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimRight(line, "\r")
		if len(line) < 2 || line[1] != '=' {
			continue
		}
		key, val := line[0], line[2:]
		label := map[byte]string{'v': "Version", 'o': "Origin", 's': "Session Name", 'i': "Session Information", 'u': "URI", 'e': "Email", 'p': "Phone", 'c': "Connection", 'b': "Bandwidth", 't': "Timing", 'r': "Repeat", 'z': "Time Zone", 'k': "Encryption Key", 'a': "Attribute", 'm': "Media"}[key]
		if label == "" {
			label = string(key)
		}
		field := newField(label+": "+val, "", base, 0)
		if key == 'm' {
			parts := strings.Fields(val)
			if len(parts) >= 3 {
				field.Value = ""
				field.add(newField("Media: "+parts[0], "", base, 0), newField("Port: "+parts[1], "", base, 0), newField("Protocol: "+parts[2], "", base, 0))
				if len(parts) > 3 {
					field.add(newField("Formats: "+strings.Join(parts[3:], " "), "", base, 0))
				}
			}
		} else if key == 'c' {
			parts := strings.Fields(val)
			if len(parts) >= 3 {
				field.Value = ""
				field.add(newField("Network Type: "+parts[0], "", base, 0), newField("Address Type: "+parts[1], "", base, 0), newField("Connection Address: "+strings.Join(parts[2:], " "), "", base, 0))
			}
		} else if key == 'a' {
			if k, v, ok := strings.Cut(val, ":"); ok {
				field.Label = "Attribute: " + k
				field.Value = v
			}
		}
		sdp.add(field)
	}
	root.add(sdp)
}

func (c *ctx) dissectSIP(b []byte, base int) bool {
	line, rest, ok := bytes.Cut(b, []byte("\n"))
	if !ok {
		return false
	}
	first := strings.TrimRight(string(line), "\r")
	parts := strings.Fields(first)
	if len(parts) < 3 {
		return false
	}
	isRequest := sipMethods[parts[0]] && parts[2] == "SIP/2.0"
	isResponse := parts[0] == "SIP/2.0" && len(parts) >= 2
	if !isRequest && !isResponse {
		return false
	}
	c.addLayer("sip")
	c.proto = "sip"
	root := newNode("Session Initiation Protocol", base, len(b))
	root.add(newField(first, "", base, len(line)))
	headers := map[string]string{}
	var body []byte
	headerText := rest
	if i := bytes.Index(rest, []byte("\r\n\r\n")); i >= 0 {
		headerText, body = rest[:i], rest[i+4:]
	} else if i := bytes.Index(rest, []byte("\n\n")); i >= 0 {
		headerText, body = rest[:i], rest[i+2:]
	}
	for _, hl := range strings.Split(string(headerText), "\n") {
		hl = strings.TrimRight(hl, "\r")
		if hl == "" {
			continue
		}
		k, v, ok := strings.Cut(hl, ":")
		if ok {
			key := sipHeaderName(k)
			headers[key] = strings.TrimSpace(v)
			root.add(newField(strings.TrimSpace(k)+": "+strings.TrimSpace(v), "", base, 0))
		}
	}
	info := first
	who := ""
	if v := headers["from"]; v != "" {
		who = v
	}
	if v := headers["to"]; v != "" {
		if who != "" {
			who += " -> "
		}
		who += v
	}
	if who != "" {
		info += " " + who
	}
	if v := headers["call-id"]; v != "" {
		info += " Call-ID=" + v
	}
	if v := headers["cseq"]; v != "" {
		info += " CSeq=" + v
	}
	ct := strings.ToLower(headers["content-type"])
	if len(body) > 0 && (strings.Contains(ct, "application/sdp") || bytes.HasPrefix(body, []byte("v="))) {
		sipSDP(body, root, base)
		info += " SDP"
	}
	c.addRoot(root)
	c.appInfo = shorten(info, 160)
	return true
}

// ------------------------------------------------------------------- SSH

var sshMessages = map[byte]string{
	1: "DISCONNECT", 2: "IGNORE", 3: "UNIMPLEMENTED", 4: "DEBUG",
	20: "KEXINIT", 21: "NEWKEYS",
	30: "KEXDH_INIT", 31: "KEXDH_REPLY",
	50: "USERAUTH_REQUEST", 51: "USERAUTH_FAILURE", 52: "USERAUTH_SUCCESS",
	53: "USERAUTH_BANNER", 60: "USERAUTH_PK_OK",
	80: "GLOBAL_REQUEST", 81: "REQUEST_SUCCESS", 82: "REQUEST_FAILURE",
	90: "CHANNEL_OPEN", 91: "CHANNEL_OPEN_CONFIRMATION", 92: "CHANNEL_OPEN_FAILURE",
	93: "CHANNEL_WINDOW_ADJUST", 94: "CHANNEL_DATA", 95: "CHANNEL_EXTENDED_DATA",
	96: "CHANNEL_EOF", 97: "CHANNEL_CLOSE", 98: "CHANNEL_REQUEST",
}

func sshString(b []byte, off int) (string, int, bool) {
	if off+4 > len(b) {
		return "", off, false
	}
	n := int(be32(b[off : off+4]))
	off += 4
	if n < 0 || off+n > len(b) {
		return "", off, false
	}
	return string(b[off : off+n]), off + n, true
}

func sshNameList(b []byte, off int) (string, int, bool) {
	v, n, ok := sshString(b, off)
	if !ok {
		return "", off, false
	}
	return strings.Join(strings.Split(v, ","), ", "), n, true
}

func sshAddStrings(f *Field, b []byte, off int, labels []string) {
	for _, label := range labels {
		v, n, ok := sshNameList(b, off)
		if !ok {
			return
		}
		f.add(newField(label+": "+v, "", 0, 0))
		off = n
	}
}

func (c *ctx) dissectSSH(b []byte, base int) bool {
	if bytes.HasPrefix(b, []byte("SSH-")) {
		line, _, ok := bytes.Cut(b, []byte("\n"))
		if !ok {
			line = b
		}
		ident := strings.TrimRight(string(line), "\r")
		parts := strings.SplitN(ident, "-", 3)
		c.addLayer("ssh")
		c.proto = "ssh"
		root := newNode("SSH Protocol", base, len(b))
		fields := []*Field{newField("Identification: "+ident, "", base, len(line))}
		if len(parts) >= 2 {
			fields = append(fields, newField("Protocol Version: SSH-"+parts[1], "", base, 0))
		}
		if len(parts) >= 3 {
			fields = append(fields, newField("Software Version: "+parts[2], "", base, 0))
		}
		root.add(fields...)
		c.addRoot(root)
		c.appInfo = "SSH identification: " + ident
		return true
	}
	if len(b) < 6 {
		return false
	}
	pktLen := int(be32(b[0:4]))
	if pktLen < 2 || pktLen > 1<<20 || pktLen+4 > len(b) {
		return false
	}
	padding := int(b[4])
	if padding < 4 || 5+padding > 4+pktLen {
		return false
	}
	payload := b[5 : 4+pktLen-padding]
	code := b[5]
	name := sshMessages[code]
	if name == "" {
		name = fmt.Sprintf("Unknown/Encrypted Message %d", code)
	}
	c.addLayer("ssh")
	c.proto = "ssh"
	root := newNode("SSH Protocol ("+name+")", base, 4+pktLen)
	root.add(
		newField(fmt.Sprintf("Packet Length: %d", pktLen), "", base, 4),
		newField(fmt.Sprintf("Padding Length: %d", padding), "", base+4, 1),
		newField(fmt.Sprintf("Message: %s (%d)", name, code), "", base+5, 1),
	)
	info := "SSH " + name
	p := 1

	switch code {
	case 1: // DISCONNECT
		if p+4 <= len(payload) {
			reason := be32(payload[p : p+4])
			p += 4
			desc, n, _ := sshString(payload, p)
			p = n
			lang, _, _ := sshString(payload, p)
			root.add(newField(fmt.Sprintf("Reason Code: %d", reason), "", 0, 0), newField("Description: "+desc, "", 0, 0), newField("Language: "+lang, "", 0, 0))
			info += " " + desc
		}
	case 2, 4: // IGNORE / DEBUG
		if code == 4 {
			always, n, ok := sshString(payload, p)
			if ok {
				root.add(newField("Always Display: "+always, "", 0, 0))
				p = n
			}
		}
		msg, _, _ := sshString(payload, p)
		root.add(newField("Message: "+shorten(msg, 160), "", 0, 0))
	case 3: // UNIMPLEMENTED
		if p+4 <= len(payload) {
			root.add(newField(fmt.Sprintf("Sequence Number: %d", be32(payload[p:p+4])), "", 0, 0))
		}
	case 5, 6: // SERVICE_REQUEST / SERVICE_ACCEPT
		svc, _, ok := sshString(payload, p)
		if ok {
			root.add(newField("Service: "+svc, "", 0, 0))
			info += " " + svc
		}
	case 7: // EXT_INFO
		if p+4 <= len(payload) {
			n := int(be32(payload[p : p+4]))
			p += 4
			for i := 0; i < n; i++ {
				k, np, ok := sshString(payload, p)
				if !ok {
					break
				}
				p = np
				v, np2, ok := sshString(payload, p)
				if !ok {
					break
				}
				p = np2
				root.add(newField(k+": "+v, "", 0, 0))
			}
		}
	case 20: // KEXINIT
		if len(payload) >= 17 {
			root.add(newField("Cookie: "+hexPreview(payload[1:17], 16), "", base+6, 16))
			p = 17
			sshAddStrings(root, payload, p, []string{
				"Key Exchange Algorithms", "Server Host Key Algorithms",
				"Encryption Client-to-Server", "Encryption Server-to-Client",
				"MAC Client-to-Server", "MAC Server-to-Client",
				"Compression Client-to-Server", "Compression Server-to-Client",
				"Languages Client-to-Server", "Languages Server-to-Client",
			})
			// Re-walk to find the trailing first_kex_packet_follows byte.
			q := 17
			for i := 0; i < 10; i++ {
				_, n, ok := sshString(payload, q)
				if !ok {
					break
				}
				q = n
			}
			if q < len(payload) {
				root.add(newField(fmt.Sprintf("First KEX Packet Follows: %d", payload[q]), "", 0, 0))
				q++
				if q+4 <= len(payload) {
					root.add(newField(fmt.Sprintf("Reserved: %d", be32(payload[q:q+4])), "", 0, 0))
				}
			}
			info += " KEX"
		}
	case 30: // KEXDH_INIT / KEX_ECDH_INIT
		if v, _, ok := sshString(payload, p); ok {
			root.add(newField("Client Ephemeral Public Key: "+hexPreview([]byte(v), 64), "", 0, 0))
		}
	case 31, 33: // KEXDH_REPLY / GEX_REPLY / ECDH_REPLY
		if code == 31 && p+12 <= len(payload) {
			min := be32(payload[p : p+4])
			pref := be32(payload[p+4 : p+8])
			max := be32(payload[p+8 : p+12])
			if min >= 1024 && min <= pref && pref <= max {
				root.add(newField(fmt.Sprintf("Min Group Size: %d", min), "", 0, 0), newField(fmt.Sprintf("Preferred Group Size: %d", pref), "", 0, 0), newField(fmt.Sprintf("Max Group Size: %d", max), "", 0, 0))
				p += 12
				if v, _, ok := sshString(payload, p); ok {
					root.add(newField("Prime: "+hexPreview([]byte(v), 64), "", 0, 0))
				}
				break
			}
		}
		hostKey, n, ok := sshString(payload, p)
		if ok {
			root.add(newField("Server Host Key: "+hexPreview([]byte(hostKey), 64), "", 0, 0))
			p = n
			if f, n2, ok := sshString(payload, p); ok {
				root.add(newField("Server Ephemeral Public Key: "+hexPreview([]byte(f), 64), "", 0, 0))
				p = n2
			}
			if sig, _, ok := sshString(payload, p); ok {
				root.add(newField("Signature: "+hexPreview([]byte(sig), 64), "", 0, 0))
			}
		}
	case 32: // GEX_REQUEST_OLD
		if p+4 <= len(payload) {
			root.add(newField(fmt.Sprintf("Preferred Group Size: %d", be32(payload[p:p+4])), "", 0, 0))
		}
	case 34: // GEX_INIT / GEX_REPLY handled above
		if v, _, ok := sshString(payload, p); ok {
			root.add(newField("Client Ephemeral Public Key: "+hexPreview([]byte(v), 64), "", 0, 0))
		}
	case 36: // GEX_REQUEST
		if p+12 <= len(payload) {
			root.add(newField(fmt.Sprintf("Min Group Size: %d", be32(payload[p:p+4])), "", 0, 0), newField(fmt.Sprintf("Preferred Group Size: %d", be32(payload[p+4:p+8])), "", 0, 0), newField(fmt.Sprintf("Max Group Size: %d", be32(payload[p+8:p+12])), "", 0, 0))
		}
	case 50: // USERAUTH_REQUEST
		user, n, ok := sshString(payload, p)
		if ok {
			root.add(newField("User Name: "+user, "", 0, 0))
			p = n
			svc, n2, ok := sshString(payload, p)
			if ok {
				root.add(newField("Service: "+svc, "", 0, 0))
				p = n2
				method, n3, ok := sshString(payload, p)
				if ok {
					root.add(newField("Method: "+method, "", 0, 0))
					p = n3
					info = fmt.Sprintf("SSH USERAUTH_REQUEST user=%s method=%s", user, method)
					switch method {
					case "password":
						if p < len(payload) {
							root.add(newField(fmt.Sprintf("Change Password: %d", payload[p]), "", 0, 0))
							p++
							if pw, _, ok := sshString(payload, p); ok {
								root.add(newField("Password: "+shorten(pw, 32), "", 0, 0))
							}
						}
					case "publickey":
						if p < len(payload) {
							root.add(newField(fmt.Sprintf("Has Signature: %d", payload[p]), "", 0, 0))
							p++
						}
						if alg, _, ok := sshString(payload, p); ok {
							root.add(newField("Public Key Algorithm: "+alg, "", 0, 0))
						}
					}
				}
			}
		}
	case 51: // USERAUTH_FAILURE
		if list, n, ok := sshNameList(payload, p); ok {
			root.add(newField("Authentications That Can Continue: "+list, "", 0, 0))
			p = n
			if p < len(payload) {
				root.add(newField(fmt.Sprintf("Partial Success: %d", payload[p]), "", 0, 0))
			}
		}
	case 52:
		info = "SSH USERAUTH_SUCCESS"
	case 53: // BANNER
		if msg, n, ok := sshString(payload, p); ok {
			root.add(newField("Message: "+shorten(msg, 160), "", 0, 0))
			p = n
			if lang, _, ok := sshString(payload, p); ok {
				root.add(newField("Language: "+lang, "", 0, 0))
			}
		}
	case 60: // PK_OK
		if alg, n, ok := sshString(payload, p); ok {
			root.add(newField("Public Key Algorithm: "+alg, "", 0, 0))
			p = n
			if blob, _, ok := sshString(payload, p); ok {
				root.add(newField("Public Key: "+hexPreview([]byte(blob), 48), "", 0, 0))
			}
		}
	case 80: // GLOBAL_REQUEST
		if req, n, ok := sshString(payload, p); ok {
			root.add(newField("Request Name: "+req, "", 0, 0))
			p = n
			if p < len(payload) {
				root.add(newField(fmt.Sprintf("Want Reply: %d", payload[p]), "", 0, 0))
				p++
			}
			if p < len(payload) {
				root.add(newField("Request Data: "+hexPreview(payload[p:], 64), "", 0, 0))
			}
			info += " " + req
		}
	case 81, 82:
		if len(payload) > 1 {
			root.add(newField("Response Data: "+hexPreview(payload[1:], 64), "", 0, 0))
		}
	case 90: // CHANNEL_OPEN
		if typ, n, ok := sshString(payload, p); ok {
			root.add(newField("Channel Type: "+typ, "", 0, 0))
			p = n
			if p+12 <= len(payload) {
				root.add(newField(fmt.Sprintf("Sender Channel: %d", be32(payload[p:p+4])), "", 0, 0), newField(fmt.Sprintf("Initial Window Size: %d", be32(payload[p+4:p+8])), "", 0, 0), newField(fmt.Sprintf("Maximum Packet Size: %d", be32(payload[p+8:p+12])), "", 0, 0))
			}
			info += " " + typ
		}
	case 91: // OPEN_CONFIRMATION
		if p+16 <= len(payload) {
			root.add(newField(fmt.Sprintf("Recipient Channel: %d", be32(payload[p:p+4])), "", 0, 0), newField(fmt.Sprintf("Sender Channel: %d", be32(payload[p+4:p+8])), "", 0, 0), newField(fmt.Sprintf("Initial Window Size: %d", be32(payload[p+8:p+12])), "", 0, 0), newField(fmt.Sprintf("Maximum Packet Size: %d", be32(payload[p+12:p+16])), "", 0, 0))
		}
	case 92: // OPEN_FAILURE
		if p+4 <= len(payload) {
			root.add(newField(fmt.Sprintf("Recipient Channel: %d", be32(payload[p:p+4])), "", 0, 0))
			p += 4
			if p+4 <= len(payload) {
				root.add(newField(fmt.Sprintf("Reason Code: %d", be32(payload[p:p+4])), "", 0, 0))
				p += 4
				if desc, n, ok := sshString(payload, p); ok {
					root.add(newField("Description: "+desc, "", 0, 0))
					p = n
					if lang, _, ok := sshString(payload, p); ok {
						root.add(newField("Language: "+lang, "", 0, 0))
					}
				}
			}
		}
	case 93: // WINDOW_ADJUST
		if p+8 <= len(payload) {
			root.add(newField(fmt.Sprintf("Recipient Channel: %d", be32(payload[p:p+4])), "", 0, 0), newField(fmt.Sprintf("Bytes to Add: %d", be32(payload[p+4:p+8])), "", 0, 0))
		}
	case 94: // DATA
		if p+4 <= len(payload) {
			root.add(newField(fmt.Sprintf("Recipient Channel: %d", be32(payload[p:p+4])), "", 0, 0))
			p += 4
			if data, _, ok := sshString(payload, p); ok {
				root.add(newField(fmt.Sprintf("Data (%d bytes): %s", len(data), hexPreview([]byte(data), 64)), "", 0, 0))
			}
		}
	case 95: // EXTENDED_DATA
		if p+8 <= len(payload) {
			root.add(newField(fmt.Sprintf("Recipient Channel: %d", be32(payload[p:p+4])), "", 0, 0), newField(fmt.Sprintf("Data Type Code: %d", be32(payload[p+4:p+8])), "", 0, 0))
			p += 8
			if data, _, ok := sshString(payload, p); ok {
				root.add(newField(fmt.Sprintf("Data (%d bytes): %s", len(data), hexPreview([]byte(data), 64)), "", 0, 0))
			}
		}
	case 96, 97, 98:
		if code == 98 {
			if p+4 <= len(payload) {
				root.add(newField(fmt.Sprintf("Recipient Channel: %d", be32(payload[p:p+4])), "", 0, 0))
				p += 4
				if req, n, ok := sshString(payload, p); ok {
					root.add(newField("Request Type: "+req, "", 0, 0))
					p = n
					if p < len(payload) {
						root.add(newField(fmt.Sprintf("Want Reply: %d", payload[p]), "", 0, 0))
						p++
					}
					if p < len(payload) {
						root.add(newField("Request Data: "+hexPreview(payload[p:], 64), "", 0, 0))
					}
				}
			}
		} else if p+4 <= len(payload) {
			root.add(newField(fmt.Sprintf("Recipient Channel: %d", be32(payload[p:p+4])), "", 0, 0))
		}
	}
	if name == fmt.Sprintf("Unknown/Encrypted Message %d", code) {
		root.add(newField("Payload: "+hexPreview(payload, 96), "", base+5, len(payload)))
		info = "SSH encrypted/unknown payload"
	}
	c.addRoot(root)
	c.appInfo = shorten(info, 140)
	return true
}

// ------------------------------------------------------------------ HTTP/2

var http2Types = []string{"DATA", "HEADERS", "PRIORITY", "RST_STREAM", "SETTINGS", "PUSH_PROMISE", "PING", "GOAWAY", "WINDOW_UPDATE", "CONTINUATION"}

var http2Preface = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

func http2SettingName(id uint16) string {
	names := map[uint16]string{1: "HEADER_TABLE_SIZE", 2: "ENABLE_PUSH", 3: "MAX_CONCURRENT_STREAMS", 4: "INITIAL_WINDOW_SIZE", 5: "MAX_FRAME_SIZE", 6: "MAX_HEADER_LIST_SIZE", 8: "ENABLE_CONNECT_PROTOCOL", 9: "NO_RFC7540_PRIORITIES"}
	if n := names[id]; n != "" {
		return n
	}
	return fmt.Sprintf("Setting 0x%04x", id)
}

func http2ErrorName(code uint32) string {
	names := map[uint32]string{0: "NO_ERROR", 1: "PROTOCOL_ERROR", 2: "INTERNAL_ERROR", 3: "FLOW_CONTROL_ERROR", 4: "SETTINGS_TIMEOUT", 5: "STREAM_CLOSED", 6: "FRAME_SIZE_ERROR", 7: "REFUSED_STREAM", 8: "CANCEL", 9: "COMPRESSION_ERROR", 10: "CONNECT_ERROR", 11: "ENHANCE_YOUR_CALM", 12: "INADEQUATE_SECURITY", 13: "HTTP_1_1_REQUIRED"}
	if n := names[code]; n != "" {
		return n
	}
	return fmt.Sprintf("Error %d", code)
}

func (c *ctx) dissectHTTP2(b []byte, base int) bool {
	hasPreface := bytes.HasPrefix(b, http2Preface)
	off := 0
	if hasPreface {
		off = len(http2Preface)
	}
	if !hasPreface && !looksLikeHTTP2Frame(b) {
		return false
	}
	flow := h2FlowFor(c)
	if hasPreface {
		flow.observeClient(c)
	}
	c.addLayer("http2")
	c.proto = "http2"
	root := newNode("HTTP/2", base, len(b))
	if hasPreface {
		root.add(newField("Client Connection Preface", "", base, len(http2Preface)))
	}
	info := "HTTP2"
	for i := 0; i < 128 && off+9 <= len(b); i++ {
		length := int(b[off])<<16 | int(b[off+1])<<8 | int(b[off+2])
		typ := b[off+3]
		flags := b[off+4]
		stream := be32(b[off+5:off+9]) & 0x7fffffff
		if off+9+length > len(b) {
			break
		}
		name := "UNKNOWN"
		if int(typ) < len(http2Types) {
			name = http2Types[typ]
		}
		f := newField(fmt.Sprintf("%s (stream %d, length %d)", name, stream, length), "", base+off, 9+length)
		f.add(
			newField(fmt.Sprintf("Length: %d", length), "", base+off, 3),
			newField(fmt.Sprintf("Type: %s (%d)", name, typ), "", base+off+3, 1),
			newField(fmt.Sprintf("Flags: 0x%02x", flags), "", base+off+4, 1),
			newField(fmt.Sprintf("Stream Identifier: %d", stream), "", base+off+5, 4),
		)
		body := b[off+9 : off+9+length]
		consumed := 0
		switch typ {
		case 4: // SETTINGS
			if flags&1 != 0 {
				f.add(newField("ACK: 1", "", base+off+4, 1))
			}
			for p := 0; p+6 <= len(body); p += 6 {
				id := be16(body[p : p+2])
				val := be32(body[p+2 : p+6])
				f.add(newField(fmt.Sprintf("%s: %d", http2SettingName(id), val), "", base+off+9+p, 6))
			}
		case 6: // PING
			if len(body) == 8 {
				f.add(newField("Opaque Data: "+hexPreview(body, 8), "", base+off+9, 8))
			}
			if flags&1 != 0 {
				f.add(newField("ACK: 1", "", base+off+4, 1))
			}
		case 7: // GOAWAY
			if len(body) >= 8 {
				f.add(newField(fmt.Sprintf("Last Stream ID: %d", be32(body[0:4])&0x7fffffff), "", base+off+9, 4))
				code := be32(body[4:8])
				f.add(newField(fmt.Sprintf("Error Code: %s (%d)", http2ErrorName(code), code), "", base+off+9+4, 4))
				if len(body) > 8 {
					f.add(newField("Debug Data: "+printablePreview(body[8:], 160), "", base+off+9+8, len(body)-8))
				}
			}
		case 3: // RST_STREAM
			if len(body) >= 4 {
				code := be32(body[0:4])
				f.add(newField(fmt.Sprintf("Error Code: %s (%d)", http2ErrorName(code), code), "", base+off+9, 4))
			}
		case 8: // WINDOW_UPDATE
			if len(body) >= 4 {
				f.add(newField(fmt.Sprintf("Window Size Increment: %d", be32(body[0:4])&0x7fffffff), "", base+off+9, 4))
			}
		case 2: // PRIORITY
			if len(body) >= 5 {
				f.add(newField(fmt.Sprintf("Exclusive: %d", body[0]>>7), "", base+off+9, 1), newField(fmt.Sprintf("Depends On: %d", be32(body[0:4])&0x7fffffff), "", base+off+9, 4), newField(fmt.Sprintf("Weight: %d", int(body[4])+1), "", base+off+9+4, 1))
			}
		case 0, 1, 9, 5: // DATA / HEADERS / CONTINUATION / PUSH_PROMISE
			hdrOff := 0
			block := body
			if typ == 1 {
				if flags&0x08 != 0 && len(block) > 0 {
					pad := int(block[0])
					hdrOff++
					if pad <= len(block)-1 {
						block = block[1 : len(block)-pad]
					}
				}
				if flags&0x20 != 0 && len(block) >= 5 {
					f.add(newField(fmt.Sprintf("Exclusive: %d", block[0]>>7), "", base+off+9+hdrOff, 1), newField(fmt.Sprintf("Stream Dependency: %d", be32(block[0:4])&0x7fffffff), "", base+off+9+hdrOff, 4), newField(fmt.Sprintf("Weight: %d", int(block[4])+1), "", base+off+9+hdrOff+4, 1))
					block = block[5:]
					hdrOff += 5
				}
			} else if typ == 5 {
				if len(block) < 4 {
					break
				}
				f.add(newField(fmt.Sprintf("Promised Stream ID: %d", be32(block[0:4])&0x7fffffff), "", base+off+9, 4))
				block = block[4:]
				hdrOff = 4
			}
			if typ == 0 || typ == 9 {
				f.add(newField(fmt.Sprintf("Payload (%d bytes)", len(body)), printablePreview(body, 300), base+off+9, len(body)))
				break
			}
			// HEADERS may be followed by CONTINUATION frames on the same stream.
			if typ == 1 {
				q := off + 9 + length
				for q+9 <= len(b) && b[q+3] == 9 {
					cl := int(b[q])<<16 | int(b[q+1])<<8 | int(b[q+2])
					cs := be32(b[q+5:q+9]) & 0x7fffffff
					if cs != stream || q+9+cl > len(b) {
						break
					}
					block = append(block, b[q+9:q+9+cl]...)
					f.add(newField(fmt.Sprintf("CONTINUATION (length %d)", cl), "", base+q, 9+cl))
					q += 9 + cl
				}
				consumed = q - off
			}
			fields, err := flow.decodeHeaders(c, block, c.m.TCPSeq, base+off+9+hdrOff)
			if err != nil {
				f.add(newField("HPACK decode error: "+err.Error(), hexPreview(block, 64), base+off+9+hdrOff, len(block)))
				break
			}
			hn := newField(fmt.Sprintf("Decoded Headers (%d)", len(fields)), "", base+off+9+hdrOff, len(block))
			for _, hf := range fields {
				hn.add(newField(hf.Name+": "+hf.Value, "", 0, 0))
				if hf.Name == ":method" || hf.Name == ":path" || hf.Name == ":status" || hf.Name == ":authority" {
					if info == "HTTP2" {
						info += " " + hf.Name + "=" + hf.Value
					}
				}
			}
			f.add(hn)
		}
		root.add(f)
		if i == 0 {
			info += " " + name
		}
		if consumed > 0 {
			off += consumed
		} else {
			off += 9 + length
		}
	}
	c.addRoot(root)
	c.appInfo = shorten(info, 160)
	return true
}

func looksLikeHTTP2Frame(b []byte) bool {
	if len(b) < 9 {
		return false
	}
	l := int(b[0])<<16 | int(b[1])<<8 | int(b[2])
	typ := b[3]
	stream := be32(b[5:9]) & 0x7fffffff
	if l > 1<<20 || typ > 9 {
		return false
	}
	if (typ == 4 || typ == 6) && stream != 0 {
		return false
	}
	if stream >= 1<<31 {
		return false
	}
	return b[4] < 0x40
}

// ------------------------------------------------------------------- QUIC

func quicVersionName(v uint32) string {
	switch v {
	case 0x00000001:
		return "v1"
	case 0x6b3343cf:
		return "v2"
	case 0:
		return "version negotiation"
	}
	if v&0xff000000 == 0xff000000 {
		return fmt.Sprintf("draft-%d", v&0x00ffffff)
	}
	return fmt.Sprintf("0x%08x", v)
}

func quicVarint(b []byte, off int) (uint64, int, bool) {
	if off >= len(b) {
		return 0, off, false
	}
	n := 1 << (b[off] >> 6)
	if off+n > len(b) {
		return 0, off, false
	}
	v := uint64(b[off] & 0x3f)
	for i := 1; i < n; i++ {
		v = v<<8 | uint64(b[off+i])
	}
	return v, off + n, true
}

func (c *ctx) dissectQUIC(b []byte, base int) bool {
	if len(b) < 7 {
		return false
	}
	first := b[0]
	long := first&0x80 != 0
	version := be32(b[1:5])
	c.addLayer("quic")
	c.proto = "quic"
	root := newNode("QUIC", base, len(b))
	root.add(
		newField(fmt.Sprintf("Header Form: %s", map[bool]string{true: "long", false: "short"}[long]), "", base, 1),
		newField(fmt.Sprintf("Fixed Bit: %d", (first>>6)&1), "", base, 1),
	)
	info := "QUIC"
	flow := tlsFlowFor(c)

	if long {
		root.Label = fmt.Sprintf("QUIC (%s)", quicVersionName(version))
		root.add(newField(fmt.Sprintf("Version: %s (0x%08x)", quicVersionName(version), version), "", base+1, 4))
		info += " " + quicVersionName(version)
		pktType := (first >> 4) & 0x3
		typeName := []string{"Initial", "0-RTT", "Handshake", "Retry"}[pktType]
		root.add(newField("Packet Type: "+typeName, "", base, 1))
		off := 5
		if off >= len(b) {
			return true
		}
		dcidLen := int(b[off])
		off++
		if off+dcidLen > len(b) {
			dcidLen = len(b) - off
		}
		dcid := b[off : off+dcidLen]
		off += dcidLen
		if off >= len(b) {
			return true
		}
		scidLen := int(b[off])
		off++
		if off+scidLen > len(b) {
			scidLen = len(b) - off
		}
		scid := b[off : off+scidLen]
		off += scidLen
		root.add(
			newField("Destination Connection ID: "+hexPreview(dcid, 20), "", base+6, dcidLen),
			newField("Source Connection ID: "+hexPreview(scid, 20), "", base+7+dcidLen, scidLen),
		)
		if pktType == 0 && off < len(b) {
			tokenLen, n, ok := quicVarint(b, off)
			if ok {
				root.add(newField(fmt.Sprintf("Token Length: %d", tokenLen), "", base+off, n))
				tokenOff := n
				off = n + int(tokenLen)
				if tokenLen > 0 && tokenOff+int(tokenLen) <= len(b) {
					root.add(newField("Token: "+hexPreview(b[tokenOff:tokenOff+int(tokenLen)], 32), "", base+tokenOff, int(tokenLen)))
				}
				if off < len(b) {
					if plen, n2, ok := quicVarint(b, off); ok {
						root.add(newField(fmt.Sprintf("Length: %d", plen), "", base+off, n2))
						pnOffset := n2
						if c.quicDecryptInitial(b, base, root, flow, off, dcid, scid, version, plen, pnOffset, first) {
							info += " decrypted"
						}
					}
				}
			}
		}
		if pktType != 0 && off < len(b) {
			if plen, n2, ok := quicVarint(b, off); ok {
				root.add(newField(fmt.Sprintf("Length: %d", plen), "", base+off, n2))
				random := flow.randomCopy()
				if len(random) > 0 {
					labels := []string{"CLIENT_HANDSHAKE_TRAFFIC_SECRET", "SERVER_HANDSHAKE_TRAFFIC_SECRET"}
					if pktType == 1 {
						labels = []string{"CLIENT_EARLY_TRAFFIC_SECRET"}
					}
					var secs []quicSecret
					for _, label := range labels {
						if v := keylogSecret(random, label); len(v) > 0 {
							secs = append(secs, quicSecret{label, v})
						}
					}
					if c.quicDecryptWithSecrets(b, base, root, flow, n2, n2+int(plen), first, true, secs) {
						info += " decrypted"
					}
				}
			}
		}
		info += " " + typeName
		if len(dcid) > 0 {
			info += " DCID=" + hexPreview(dcid, 8)
		}
	} else {
		root.Label = "QUIC (short header)"
		info += " short header"
		dcidLen := 8
		if len(b) >= 1+dcidLen+4+16 {
			dcid := b[1 : 1+dcidLen]
			root.add(newField("Destination Connection ID: "+hexPreview(dcid, 20), "", base+1, dcidLen))
			random := flow.randomCopy()
			if len(random) > 0 {
				var secs []quicSecret
				for _, label := range []string{"CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0"} {
					if v := keylogSecret(random, label); len(v) > 0 {
						secs = append(secs, quicSecret{label, v})
					}
				}
				if c.quicDecryptWithSecrets(b, base, root, flow, 1+dcidLen, len(b), first, false, secs) {
					info += " decrypted"
				}
			}
		}
	}

	c.addRoot(root)
	c.appInfo = shorten(info, 120)
	return true
}

// ------------------------------------------------------------------ VXLAN

func (c *ctx) dissectVXLAN(b []byte, base int) bool {
	if len(b) < 8 || b[0]&0x08 == 0 {
		return false
	}
	vni := be32(b[4:8]) >> 8
	c.addLayer("vxlan")
	c.proto = "vxlan"
	root := newNode(fmt.Sprintf("Virtual eXtensible LAN, VNI: %d", vni), base, len(b))
	root.add(
		newField(fmt.Sprintf("Flags: 0x%02x", b[0]), "", base, 1),
		newField(fmt.Sprintf("VXLAN Network Identifier: %d", vni), "", base+4, 4),
	)
	inner := b[8:]
	info := fmt.Sprintf("VXLAN VNI %d", vni)
	if len(inner) > 0 && c.depth < maxTunnelDepth {
		res := decode(inner, packet.LinkEthernet, len(inner), c.depth+1)
		if len(res.Fields) > 0 {
			group := newNode("Inner frame", base+8, len(inner))
			group.Children = shiftFields(res.Fields, base+8)
			innerRes := res
			root.add(group)
			info += fmt.Sprintf(", inner %s", innerRes.Summary.Protocol)
			if innerRes.Meta.SrcIP.IsValid() {
				info += fmt.Sprintf(" %s → %s", innerRes.Meta.SrcIP, innerRes.Meta.DstIP)
			}
		}
	} else if len(inner) > 0 {
		root.add(newField("Inner frame (tunnel depth limit)", "", base+8, len(inner)))
	}
	c.addRoot(root)
	c.appInfo = shorten(info, 120)
	return true
}

func looksLikeSSHBanner(b []byte) bool {
	return bytes.HasPrefix(b, []byte("SSH-"))
}

func looksLikeHTTP2(b []byte) bool {
	return bytes.HasPrefix(b, http2Preface)
}

func looksLikeQUIC(b []byte) bool {
	if len(b) < 7 {
		return false
	}
	if b[0]&0x80 != 0 {
		return be32(b[1:5]) != 0
	}
	return len(b) >= 20 && b[0]&0x40 != 0
}
