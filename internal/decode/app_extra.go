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

func shorten(s string, n int) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\r", ""))
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

func be64(b []byte) uint64 { return binary.BigEndian.Uint64(b) }

func trimNul(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

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

func (c *ctx) dissectMQTT(b []byte, base int) bool {
	if len(b) < 2 {
		return false
	}
	pktType := b[0] >> 4
	if pktType == 0 || pktType > 14 {
		return false
	}
	rem, hl, ok := mqttRemainingLength(b[1:])
	if !ok {
		return false
	}
	off := 1 + hl
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
		newField(fmt.Sprintf("Remaining Length: %d", rem), "", base+1, hl),
	)
	info := "MQTT " + mqttTypeName(pktType)

	switch pktType {
	case 1: // CONNECT
		if len(body) >= 4 {
			plen := int(be16(body[0:2]))
			if 2+plen+4 <= len(body) {
				proto := string(body[2 : 2+plen])
				ver := body[2+plen]
				flags := body[3+plen]
				idLenOff := 6 + plen
				root.add(
					newField("Protocol Name: "+proto, "", base+off, 2+plen),
					newField(fmt.Sprintf("Protocol Level: %d", ver), "", base+off+2+plen, 1),
					newField(fmt.Sprintf("Connect Flags: 0x%02x", flags), "", base+off+3+plen, 1),
					newField(fmt.Sprintf("Keep Alive: %d s", be16(body[4+plen:6+plen])), "", base+off+4+plen, 2),
				)
				if idLenOff+2 <= len(body) {
					idLen := int(be16(body[idLenOff : idLenOff+2]))
					if idLenOff+2+idLen <= len(body) {
						clientID := string(body[idLenOff+2 : idLenOff+2+idLen])
						root.add(newField("Client ID: "+clientID, "", base+off+idLenOff, 2+idLen))
						info += " client=" + clientID
					}
				}
			}
		}
	case 3: // PUBLISH
		if len(body) >= 2 {
			tlen := int(be16(body[0:2]))
			if 2+tlen <= len(body) {
				topic := string(body[2 : 2+tlen])
				pending := len(body) - 2 - tlen
				qos := (b[0] >> 1) & 0x3
				if qos > 0 && pending >= 2 {
					root.add(newField(fmt.Sprintf("Packet ID: %d", be16(body[2+tlen:4+tlen])), "", base+off+2+tlen, 2))
					pending -= 2
				}
				root.add(
					newField("Topic: "+topic, "", base+off, 2+tlen),
					newField(fmt.Sprintf("QoS: %d", qos), "", base, 1),
					newField(fmt.Sprintf("Payload (%d bytes)", pending), "", base+off+len(body)-pending, pending),
				)
				info = fmt.Sprintf("MQTT PUBLISH topic=%s (%d bytes)", topic, pending)
			}
		}
	case 8, 10: // SUBSCRIBE / UNSUBSCRIBE
		if len(body) >= 2 {
			root.add(newField(fmt.Sprintf("Packet ID: %d", be16(body[0:2])), "", base+off, 2))
			p := 2
			if p+2 <= len(body) {
				tlen := int(be16(body[p : p+2]))
				if p+2+tlen <= len(body) {
					topic := string(body[p+2 : p+2+tlen])
					root.add(newField("Topic Filter: "+topic, "", base+off+p, 2+tlen))
					info += " topic=" + topic
				}
			}
		}
	}
	c.addRoot(root)
	c.appInfo = info
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
	case '*':
		line, next, ok := respLine(b, off+1)
		if !ok {
			return "", off, false
		}
		n, err := strconv.Atoi(line)
		if err != nil || n < 0 {
			return line, next, true
		}
		parts := make([]string, 0, n)
		for i := 0; i < n; i++ {
			val, p, ok := respValue(b, next, depth+1)
			if !ok {
				break
			}
			parts = append(parts, val)
			next = p
		}
		return strings.Join(parts, " "), next, true
	}
	return "", off, false
}

func (c *ctx) dissectRedis(b []byte, base int) bool {
	if len(b) == 0 {
		return false
	}
	var args []string
	if b[0] == '*' || b[0] == '$' || b[0] == '+' || b[0] == '-' || b[0] == ':' {
		val, _, ok := respValue(b, 0, 0)
		if !ok {
			return false
		}
		args = strings.Split(val, " ")
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
		return false
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

var pgTypes = map[byte]string{
	'R': "Authentication", 'S': "Sync / ParameterStatus", 'K': "BackendKeyData", 'Z': "ReadyForQuery",
	'T': "RowDescription", 'D': "DataRow", 'C': "CommandComplete",
	'N': "NoticeResponse", 'Q': "Query", 'P': "Parse", 'B': "Bind", 'E': "Execute",
	'X': "Terminate", 'd': "CopyData", 'c': "CopyDone", 'f': "CopyFail",
}

func pgErrorFields(b []byte) string {
	var sev, msg string
	for off := 0; off < len(b) && b[off] != 0; {
		code := b[off]
		off++
		end := bytes.IndexByte(b[off:], 0)
		if end < 0 {
			break
		}
		val := string(b[off : off+end])
		off += end + 1
		if code == 'S' {
			sev = val
		} else if code == 'M' {
			msg = val
		}
	}
	return strings.TrimSpace(sev + ": " + msg)
}

func (c *ctx) dissectPostgreSQL(b []byte, base int) bool {
	if len(b) < 4 {
		return false
	}
	length := int(be32(b[0:4]))
	if length < 4 || length > 1<<20 {
		return false
	}

	c.addLayer("postgresql")
	c.proto = "postgresql"
	info := ""
	root := newNode("PostgreSQL", base, min(length, len(b)))

	if length >= 8 && int(be32(b[4:8])) >= 196608 {
		code := be32(b[4:8])
		switch code {
		case 196608:
			root = newNode("PostgreSQL Startup Message", base, min(length, len(b)))
			root.add(newField(fmt.Sprintf("Length: %d", length), "", base, 4))
			root.add(newField("Protocol Version: 3.0", "", base+4, 4))
			off := 8
			kv := map[string]string{}
			for off < len(b) && b[off] != 0 {
				kEnd := bytes.IndexByte(b[off:], 0)
				if kEnd < 0 {
					break
				}
				key := string(b[off : off+kEnd])
				off += kEnd + 1
				vEnd := bytes.IndexByte(b[off:], 0)
				if vEnd < 0 {
					break
				}
				kv[key] = string(b[off : off+vEnd])
				off += vEnd + 1
			}
			info = "PostgreSQL startup"
			if user := kv["user"]; user != "" {
				root.add(newField("User: "+user, "", base, 0))
				info += " user=" + user
			}
			if db := kv["database"]; db != "" {
				root.add(newField("Database: "+db, "", base, 0))
				info += " db=" + db
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
		name := pgTypes[typ]
		if name == "" {
			name = fmt.Sprintf("Message '%c'", typ)
		}
		root = newNode("PostgreSQL "+name, base, 1+msgLen)
		root.add(
			newField(fmt.Sprintf("Type: %c (%s)", typ, name), "", base, 1),
			newField(fmt.Sprintf("Length: %d", msgLen), "", base+1, 4),
		)
		payload := b[5:min(1+msgLen, len(b))]
		info = "PostgreSQL " + name
		switch typ {
		case 'Q':
			q := trimNul(payload)
			root.add(newField("Query: "+shorten(q, 300), "", base+5, len(payload)))
			info += ": " + shorten(q, 80)
		case 'P':
			if i := bytes.IndexByte(payload, 0); i >= 0 && i+1 < len(payload) {
				q := trimNul(payload[i+1:])
				root.add(newField("Query: "+shorten(q, 300), "", base+5+i+1, len(payload)-i-1))
				info += ": " + shorten(q, 80)
			}
		case 'C':
			s := trimNul(payload)
			root.add(newField("Tag: "+s, "", base+5, len(payload)))
			info += ": " + s
		case 'E':
			e := pgErrorFields(payload)
			root.add(newField("Error: "+shorten(e, 200), "", base+5, len(payload)))
			info += ": " + shorten(e, 80)
		case 'R':
			if len(payload) >= 4 {
				code := be32(payload[0:4])
				result := "AuthenticationOk"
				switch code {
				case 3:
					result = "AuthenticationCleartextPassword"
				case 5:
					result = "AuthenticationMD5Password"
				case 10:
					result = "AuthenticationSASL"
				}
				root.add(newField(fmt.Sprintf("Authentication: %s (%d)", result, code), "", base+5, 4))
				info += ": " + result
			}
		case 'T':
			if len(payload) >= 2 {
				root.add(newField(fmt.Sprintf("Fields: %d", be16(payload[0:2])), "", base+5, 2))
			}
		case 'D':
			if len(payload) >= 2 {
				root.add(newField(fmt.Sprintf("Columns: %d", be16(payload[0:2])), "", base+5, 2))
			}
		}
	} else {
		return false
	}

	c.addRoot(root)
	c.appInfo = shorten(info, 120)
	return true
}

// -------------------------------------------------------------------- BGP

var bgpTypes = map[byte]string{1: "OPEN", 2: "UPDATE", 3: "NOTIFICATION", 4: "KEEPALIVE", 5: "ROUTE-REFRESH"}

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
				f.add(
					newField(fmt.Sprintf("Version: %d", msg[19]), "", base+off+19, 1),
					newField(fmt.Sprintf("My AS: %d", asn), "", base+off+20, 2),
					newField(fmt.Sprintf("Hold Time: %d s", hold), "", base+off+22, 2),
					newField("BGP Identifier: "+routerID, "", base+off+24, 4),
				)
				info = fmt.Sprintf("BGP OPEN AS%d", asn)
			}
		case 2: // UPDATE
			if len(msg) >= 23 {
				wlen := int(be16(msg[19:21]))
				alenOff := 21 + wlen
				info = fmt.Sprintf("BGP UPDATE withdrawn=%d", wlen)
				if alenOff+2 <= len(msg) {
					alen := int(be16(msg[alenOff : alenOff+2]))
					f.add(
						newField(fmt.Sprintf("Withdrawn Routes Length: %d", wlen), "", base+off+19, 2),
						newField(fmt.Sprintf("Path Attributes Length: %d", alen), "", base+off+alenOff, 2),
					)
					info += fmt.Sprintf(" attributes=%d", alen)
				}
			}
		case 3: // NOTIFICATION
			if len(msg) >= 21 {
				f.add(
					newField(fmt.Sprintf("Error Code: %d", msg[19]), "", base+off+19, 1),
					newField(fmt.Sprintf("Error Subcode: %d", msg[20]), "", base+off+20, 1),
					newField("Data: "+hexPreview(msg[21:], 48), "", base+off+21, len(msg)-21),
				)
				info = fmt.Sprintf("BGP NOTIFICATION code=%d subcode=%d", msg[19], msg[20])
			}
		case 4:
			info = "BGP KEEPALIVE"
		case 5:
			info = "BGP ROUTE-REFRESH"
		}
		root.add(f)
		off += length
	}
	c.addRoot(root)
	c.appInfo = info
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
	community, ok := berRead(outer.value, ver.next)
	if !ok || community.tag != 0x04 {
		return false
	}
	pdu, ok := berRead(outer.value, community.next)
	if !ok {
		return false
	}
	name := snmpPDUNames[pdu.tag]
	if name == "" {
		return false
	}

	c.addLayer("snmp")
	c.proto = "snmp"
	root := newNode("Simple Network Management Protocol ("+name+")", base, len(b))
	root.add(
		newField(fmt.Sprintf("Version: %d", berInt(ver.value)), "", base, 0),
		newField("Community: "+string(community.value), "", base, 0),
		newField(fmt.Sprintf("PDU: %s (0x%02x)", name, pdu.tag), "", base, 0),
	)
	info := "SNMP " + name + " community=" + string(community.value)
	pos := 0
	var oid string
	for i := 0; i < 4; i++ {
		t, ok := berRead(pdu.value, pos)
		if !ok {
			break
		}
		pos = t.next
		switch i {
		case 0:
			root.add(newField(fmt.Sprintf("Request ID: %d", berInt(t.value)), "", base, 0))
		case 1:
			root.add(newField(fmt.Sprintf("Error Status: %d", berInt(t.value)), "", base, 0))
		case 2:
			root.add(newField(fmt.Sprintf("Error Index: %d", berInt(t.value)), "", base, 0))
		case 3:
			if t.tag != 0x30 {
				break
			}
			vbPos := 0
			for n := 0; n < 16; n++ {
				vb, ok := berRead(t.value, vbPos)
				if !ok || vb.tag != 0x30 {
					break
				}
				vbPos = vb.next
				o, ok := berRead(vb.value, 0)
				if !ok || o.tag != 0x06 {
					continue
				}
				val, ok := berRead(vb.value, o.next)
				if !ok {
					continue
				}
				oid = berOID(o.value)
				root.add(newField(oid+" = "+berValue(val), "", base, 0))
			}
		}
	}
	if oid != "" {
		info += " " + oid
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
	info := first
	if v := headers["call-id"]; v != "" {
		info += " Call-ID=" + v
	}
	if v := headers["cseq"]; v != "" {
		info += " CSeq=" + v
	}
	c.addRoot(root)
	c.appInfo = shorten(info, 120)
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
	if padding < 4 || 5+padding >= len(b) {
		return false
	}
	code := b[5]
	name := sshMessages[code]
	if name == "" {
		return false
	}
	c.addLayer("ssh")
	c.proto = "ssh"
	root := newNode("SSH Protocol ("+name+")", base, len(b))
	root.add(
		newField(fmt.Sprintf("Packet Length: %d", pktLen), "", base, 4),
		newField(fmt.Sprintf("Padding Length: %d", padding), "", base+4, 1),
		newField(fmt.Sprintf("Message: %s (%d)", name, code), "", base+5, 1),
	)
	c.addRoot(root)
	c.appInfo = "SSH " + name
	return true
}

// ------------------------------------------------------------------ HTTP/2

var http2Types = []string{"DATA", "HEADERS", "PRIORITY", "RST_STREAM", "SETTINGS", "PUSH_PROMISE", "PING", "GOAWAY", "WINDOW_UPDATE", "CONTINUATION"}

var http2Preface = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

func (c *ctx) dissectHTTP2(b []byte, base int) bool {
	if !bytes.HasPrefix(b, http2Preface) {
		return false
	}
	c.addLayer("http2")
	c.proto = "http2"
	root := newNode("HTTP/2", base, len(b))
	root.add(newField("Client Connection Preface", "", base, len(http2Preface)))
	off := len(http2Preface)
	info := "HTTP2"
	for i := 0; i < 32 && off+9 <= len(b); i++ {
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
		switch typ {
		case 4: // SETTINGS
			for p := 0; p+6 <= len(body); p += 6 {
				id := be16(body[p : p+2])
				val := be32(body[p+2 : p+6])
				f.add(newField(fmt.Sprintf("Setting 0x%04x: %d", id, val), "", base+off+9+p, 6))
			}
		case 6: // PING
			if len(body) == 8 {
				f.add(newField("Opaque Data: "+hexPreview(body, 8), "", base+off+9, 8))
			}
		case 7: // GOAWAY
			if len(body) >= 8 {
				f.add(newField(fmt.Sprintf("Last Stream ID: %d", be32(body[0:4])&0x7fffffff), "", base+off+9, 4))
				f.add(newField(fmt.Sprintf("Error Code: %d", be32(body[4:8])), "", base+off+9+4, 4))
			}
		case 0, 1, 9: // DATA / HEADERS / CONTINUATION
			f.add(newField(fmt.Sprintf("Payload (%d bytes)", len(body)), hexPreview(body, 48), base+off+9, len(body)))
			if typ == 1 {
				f.add(newField("Header block is HPACK encoded (not decoded)", "", base+off+9, 0))
			}
		}
		root.add(f)
		if i == 0 {
			info += " " + name
		}
		off += 9 + length
	}
	c.addRoot(root)
	c.appInfo = info
	return true
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
				off = n + int(tokenLen)
				if off <= len(b) {
					if plen, n2, ok := quicVarint(b, off); ok {
						root.add(newField(fmt.Sprintf("Length: %d", plen), "", base+off, n2))
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

// ------------------------------------------------------------ IGMP / MPLS / GRE

func igmpTypeName(t byte) string {
	switch t {
	case 0x11:
		return "Membership Query"
	case 0x12:
		return "V1 Membership Report"
	case 0x16:
		return "V2 Membership Report"
	case 0x17:
		return "Leave Group"
	case 0x22:
		return "V3 Membership Report"
	}
	return fmt.Sprintf("Type 0x%02x", t)
}

func igmpMaxResp(code byte) string {
	if code < 128 {
		return fmt.Sprintf("%d (0.1s)", code)
	}
	exp := (code >> 4) & 0x7
	mant := code & 0xf
	return fmt.Sprintf("%d (coded 0x%02x)", (mant|0x10)<<(exp+3), code)
}

var igmpRecordNames = map[byte]string{
	1: "MODE_IS_INCLUDE", 2: "MODE_IS_EXCLUDE", 3: "CHANGE_TO_INCLUDE_MODE",
	4: "CHANGE_TO_EXCLUDE_MODE", 5: "ALLOW_NEW_SOURCES", 6: "BLOCK_OLD_SOURCES",
}

func igmpSources(b []byte, base, off, count int) []string {
	var out []string
	for i := 0; i < count && off+4 <= len(b); i++ {
		out = append(out, netip.AddrFrom4([4]byte{b[off], b[off+1], b[off+2], b[off+3]}).String())
		off += 4
	}
	return out
}

func (c *ctx) dissectIGMP(b []byte, base int) {
	c.addLayer("igmp")
	c.proto = "igmp"
	if len(b) < 8 {
		c.addRoot(newNode("Internet Group Management Protocol (truncated)", base, len(b)))
		return
	}
	typ := b[0]
	name := igmpTypeName(typ)
	group := netip.AddrFrom4([4]byte{b[4], b[5], b[6], b[7]}).String()
	root := newNode("Internet Group Management Protocol ("+name+")", base, len(b))
	root.add(
		newField(fmt.Sprintf("Type: %s (0x%02x)", name, typ), "", base, 1),
		newField("Checksum: "+fmt.Sprintf("0x%04x", be16(b[2:4])), "", base+2, 2),
	)
	info := name + " " + group

	switch typ {
	case 0x11: // query
		root.add(newField("Max Response Time: "+igmpMaxResp(b[1]), "", base+1, 1))
		root.add(newField("Group Address: "+group, "", base+4, 4))
		if len(b) >= 12 {
			nsrc := int(be16(b[10:12]))
			root.add(
				newField(fmt.Sprintf("Reserved/Suppress: 0x%02x", b[8]), "", base+8, 1),
				newField(fmt.Sprintf("QQIC: %d", b[9]), "", base+9, 1),
				newField(fmt.Sprintf("Number of Sources: %d", nsrc), "", base+10, 2),
			)
			srcs := igmpSources(b, base, 12, nsrc)
			for i, src := range srcs {
				root.add(newField(fmt.Sprintf("Source %d: %s", i+1, src), "", base+12+i*4, 4))
			}
			if nsrc > 0 {
				info += fmt.Sprintf(" sources=%d", nsrc)
			}
		} else {
			root.add(newField("Max Response Time: "+igmpMaxResp(b[1]), "", base+1, 1))
		}
	case 0x22: // v3 report
		nrec := int(be16(b[6:8]))
		root.add(
			newField(fmt.Sprintf("Reserved: 0x%04x", be16(b[4:6])), "", base+4, 2),
			newField(fmt.Sprintf("Number of Group Records: %d", nrec), "", base+6, 2),
		)
		off := 8
		for i := 0; i < nrec && off+8 <= len(b); i++ {
			rtype := b[off]
			auxLen := int(b[off+1])
			nsrc := int(be16(b[off+2 : off+4]))
			grp := netip.AddrFrom4([4]byte{b[off+4], b[off+5], b[off+6], b[off+7]})
			rname := igmpRecordNames[rtype]
			if rname == "" {
				rname = fmt.Sprintf("Record Type %d", rtype)
			}
			f := newField(fmt.Sprintf("%s group=%s sources=%d", rname, grp, nsrc), "", base+off, 8+auxLen+nsrc*4)
			f.add(
				newField(fmt.Sprintf("Record Type: %s (%d)", rname, rtype), "", base+off, 1),
				newField(fmt.Sprintf("Auxiliary Data Length: %d", auxLen), "", base+off+1, 1),
				newField(fmt.Sprintf("Number of Sources: %d", nsrc), "", base+off+2, 2),
				newField("Multicast Group: "+grp.String(), "", base+off+4, 4),
			)
			p := off + 8
			if auxLen > 0 {
				if p+auxLen > len(b) {
					break
				}
				f.add(newField("Auxiliary Data: "+hexPreview(b[p:p+auxLen], 32), "", base+p, auxLen))
				p += auxLen
			}
			for j := 0; j < nsrc && p+4 <= len(b); j++ {
				src := netip.AddrFrom4([4]byte{b[p], b[p+1], b[p+2], b[p+3]})
				f.add(newField(fmt.Sprintf("Source %d: %s", j+1, src), "", base+p, 4))
				p += 4
			}
			root.add(f)
			off = p
		}
		info = fmt.Sprintf("IGMPv3 report records=%d", nrec)
	default:
		root.add(
			newField("Max Response Time: "+igmpMaxResp(b[1]), "", base+1, 1),
			newField("Group Address: "+group, "", base+4, 4),
		)
	}

	c.addRoot(root)
	c.appInfo = info
}

func (c *ctx) dissectMPLS(b []byte, base int) {
	c.addLayer("mpls")
	c.proto = "mpls"
	root := newNode("MultiProtocol Label Switching Header", base, len(b))
	off := 0
	firstLabel := -1
	for i := 0; i < 8 && off+4 <= len(b); i++ {
		entry := be32(b[off : off+4])
		label := (entry >> 12) & 0xfffff
		tc := (entry >> 9) & 0x7
		bos := (entry >> 8) & 1
		ttl := entry & 0xff
		if firstLabel < 0 {
			firstLabel = int(label)
		}
		root.add(newField(fmt.Sprintf("Label %d: %d, TC: %d, S: %d, TTL: %d", i, label, tc, bos, ttl), "", base+off, 4))
		off += 4
		if bos == 1 {
			break
		}
	}
	c.addRoot(root)
	if off < len(b) {
		switch b[off] >> 4 {
		case 4:
			c.dissectIPv4(b[off:], base+off)
		case 6:
			c.dissectIPv6(b[off:], base+off)
		default:
			c.dissectData(b[off:], base+off)
		}
	}
	if firstLabel >= 0 {
		c.appInfo = fmt.Sprintf("MPLS label %d", firstLabel)
	} else {
		c.appInfo = "MPLS"
	}
	c.proto = "mpls"
}

func (c *ctx) addInnerFrame(b []byte, base int, label string) {
	if len(b) == 0 {
		return
	}
	if c.depth >= maxTunnelDepth {
		c.addRoot(newField(label+" (tunnel depth limit)", "", base, len(b)))
		return
	}
	res := decode(b, packet.LinkEthernet, len(b), c.depth+1)
	group := newNode(label, base, len(b))
	group.Children = shiftFields(res.Fields, base)
	c.addRoot(group)
}

func (c *ctx) dissectGRE(b []byte, base int) {
	c.addLayer("gre")
	c.proto = "gre"
	if len(b) < 4 {
		c.addRoot(newNode("Generic Routing Encapsulation (truncated)", base, len(b)))
		return
	}
	flags := be16(b[0:2])
	version := flags & 0x7
	proto := be16(b[2:4])
	off := 4
	if flags&0x8000 != 0 { // checksum present
		off += 4
	}
	if flags&0x2000 != 0 { // key present
		off += 4
	}
	if flags&0x1000 != 0 { // sequence present
		off += 4
	}
	if off > len(b) {
		off = len(b)
	}
	root := newNode("Generic Routing Encapsulation", base, len(b))
	root.add(
		newField(fmt.Sprintf("Flags: 0x%04x", flags), "", base, 2),
		newField(fmt.Sprintf("Version: %d", version), "", base, 1),
		newField(fmt.Sprintf("Protocol Type: %s (0x%04x)", etherTypeName(proto), proto), "", base+2, 2),
	)
	c.addRoot(root)
	if off < len(b) {
		switch proto {
		case etherTypeIPv4:
			c.dissectIPv4(b[off:], base+off)
		case etherTypeIPv6:
			c.dissectIPv6(b[off:], base+off)
		case etherTypeARP:
			c.dissectARP(b[off:], base+off)
		case 0x6558: // transparent Ethernet bridging
			c.addInnerFrame(b[off:], base+off, "Inner Ethernet frame")
		default:
			c.dissectData(b[off:], base+off)
		}
	}
	c.proto = "gre"
	c.appInfo = "GRE " + etherTypeName(proto)
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

// ------------------------------------------------------- DHCP (full options)

var dhcpOptionNames = map[byte]string{
	1: "Subnet Mask", 2: "Time Offset", 3: "Router", 4: "Time Server", 5: "Name Server",
	6: "Domain Name Server", 7: "Log Server", 8: "Cookie Server", 9: "LPR Server",
	10: "Impress Server", 11: "Resource Location Server", 12: "Host Name", 13: "Boot File Size",
	14: "Merit Dump File", 15: "Domain Name", 16: "Swap Server", 17: "Root Path",
	18: "Extensions Path", 19: "IP Forwarding", 20: "Non-Local Source Routing",
	21: "Policy Filter", 22: "Maximum Datagram Reassembly Size", 23: "Default IP TTL",
	24: "Path MTU Aging Timeout", 25: "Path MTU Plateau Table", 26: "Interface MTU",
	27: "All Subnets Are Local", 28: "Broadcast Address", 29: "Perform Mask Discovery",
	30: "Mask Supplier", 31: "Perform Router Discovery", 32: "Router Solicitation Address",
	33: "Static Route", 34: "Trailer Encapsulation", 35: "ARP Cache Timeout",
	36: "Ethernet Encapsulation", 37: "TCP Default TTL", 38: "TCP Keepalive Interval",
	39: "TCP Keepalive Garbage", 40: "Network Information Service Domain",
	41: "Network Information Service Servers", 42: "NTP Servers", 43: "Vendor Specific",
	44: "NetBIOS over TCP/IP Name Server", 45: "NetBIOS over TCP/IP Datagram Distribution Server",
	46: "NetBIOS over TCP/IP Node Type", 47: "NetBIOS over TCP/IP Scope", 48: "X Window System Font Server",
	49: "X Window System Display Manager", 50: "Requested IP Address", 51: "IP Address Lease Time",
	52: "Option Overload", 53: "DHCP Message Type", 54: "Server Identifier", 55: "Parameter Request List",
	56: "Message", 57: "Maximum DHCP Message Size", 58: "Renewal Time Value", 59: "Rebinding Time Value",
	60: "Vendor Class Identifier", 61: "Client Identifier", 64: "NIS+ Domain", 65: "NIS+ Servers",
	66: "TFTP Server Name", 67: "Bootfile Name", 68: "Mobile IP Home Agent", 69: "SMTP Server",
	70: "POP3 Server", 71: "NNTP Server", 72: "WWW Server", 73: "Finger Server", 74: "IRC Server",
	75: "StreetTalk Server", 76: "StreetTalk Directory Assistance Server", 80: "Rapid Commit",
	81: "Client FQDN", 82: "Relay Agent Information", 91: "Client Last Transaction Time",
	93: "Client System Architecture", 94: "Client Network Interface Identifier", 97: "Client UUID/GUID",
	119: "Domain Search", 121: "Classless Static Route", 125: "Vendor-Identifying Vendor Options",
	208: "PXE Magic", 209: "PXE Configuration File", 210: "PXE Path Prefix", 211: "PXE Reboot Time",
	212: "PXE 6rd", 213: "PXE Boot Item", 249: "Microsoft Classless Static Route", 252: "WPAD",
}

func dhcpOptionName(opt byte) string {
	if n, ok := dhcpOptionNames[opt]; ok {
		return n
	}
	return fmt.Sprintf("Option %d", opt)
}

func dhcpIP(b []byte) string {
	if len(b) == 4 {
		return netip.AddrFrom4([4]byte{b[0], b[1], b[2], b[3]}).String()
	}
	return ""
}

func dhcpIPList(b []byte) string {
	var out []string
	for i := 0; i+4 <= len(b); i += 4 {
		out = append(out, netip.AddrFrom4([4]byte{b[i], b[i+1], b[i+2], b[i+3]}).String())
	}
	return strings.Join(out, ", ")
}

func dhcpUintList(b []byte, width int) string {
	var out []string
	for i := 0; i+width <= len(b); i += width {
		switch width {
		case 1:
			out = append(out, strconv.Itoa(int(b[i])))
		case 2:
			out = append(out, strconv.Itoa(int(be16(b[i:i+2]))))
		case 4:
			out = append(out, strconv.FormatUint(uint64(be32(b[i:i+4])), 10))
		}
	}
	return strings.Join(out, ", ")
}

func dhcpDomainSearch(b []byte) string {
	var names []string
	for i := 0; i < len(b); {
		var labels []string
		for i < len(b) && b[i] != 0 {
			l := int(b[i])
			i++
			if i+l > len(b) {
				return strings.Join(names, ", ")
			}
			labels = append(labels, string(b[i:i+l]))
			i += l
		}
		if i < len(b) && b[i] == 0 {
			i++
		}
		if len(labels) > 0 {
			names = append(names, strings.Join(labels, "."))
		}
	}
	return strings.Join(names, ", ")
}

func dhcpClasslessRoutes(b []byte) string {
	var out []string
	for i := 0; i < len(b); {
		width := int(b[i])
		i++
		if width < 1 || width > 32 || i+1+(width+7)/8+4 > len(b) {
			break
		}
		prefix := int(b[i])
		i++
		n := int((prefix + 7) / 8)
		if i+n+4 > len(b) {
			break
		}
		var dst [4]byte
		copy(dst[:], b[i:i+n])
		i += n
		router := netip.AddrFrom4([4]byte{b[i], b[i+1], b[i+2], b[i+3]})
		i += 4
		out = append(out, fmt.Sprintf("%s/%d via %s", netip.AddrFrom4(dst), prefix, router))
		_ = width
	}
	return strings.Join(out, "; ")
}

func dhcpRelaySuboptions(b []byte) string {
	var out []string
	for i := 0; i+2 <= len(b); {
		code := b[i]
		l := int(b[i+1])
		i += 2
		if i+l > len(b) {
			break
		}
		v := b[i : i+l]
		switch code {
		case 1:
			out = append(out, "Circuit-ID="+hexPreview(v, 32))
		case 2:
			out = append(out, "Remote-ID="+hexPreview(v, 32))
		default:
			out = append(out, fmt.Sprintf("sub-option %d=%s", code, hexPreview(v, 16)))
		}
		i += l
	}
	return strings.Join(out, ", ")
}

func dhcpOptionText(opt byte, v []byte) string {
	switch opt {
	case 1, 28, 50, 54:
		return dhcpIP(v)
	case 3, 4, 5, 6, 7, 8, 9, 10, 11, 41, 42, 44, 45, 48, 49, 65, 68, 69, 70, 71, 72, 73, 74, 75, 76:
		return dhcpIPList(v)
	case 26, 57:
		return fmt.Sprintf("%d", be16(v))
	case 51, 58, 59, 91:
		return fmt.Sprintf("%d seconds", be32(v))
	case 2, 13, 22, 24, 35, 38:
		return dhcpUintList(v, 4)
	case 23, 37, 39:
		return dhcpUintList(v, 1)
	case 52:
		return fmt.Sprintf("%d", v[0])
	case 53:
		if len(v) > 0 {
			return dhcpTypeName(v[0])
		}
	case 55:
		var names []string
		for _, b := range v {
			names = append(names, dhcpOptionName(b))
		}
		return strings.Join(names, ", ")
	case 81:
		return hexPreview(v, 64)
	case 82:
		return dhcpRelaySuboptions(v)
	case 119:
		return dhcpDomainSearch(v)
	case 121, 249:
		return dhcpClasslessRoutes(v)
	case 12, 15, 56, 60, 66, 67, 252:
		return string(v)
	case 61:
		return hexPreview(v, 32)
	case 43, 125:
		return hexPreview(v, 64)
	}
	if len(v) == 4 {
		return dhcpIP(v)
	}
	return hexPreview(v, 48)
}

func (c *ctx) dissectDHCP(b []byte, base int) bool {
	if len(b) < 240 || (b[0] != 1 && b[0] != 2) {
		return false
	}
	msgType := uint8(0)
	hostname := ""
	requestedIP := ""

	c.addLayer("dhcp")
	c.proto = "dhcp"
	root := newNode("Dynamic Host Configuration Protocol", base, len(b))
	root.add(
		newField(fmt.Sprintf("Message type: %s", map[byte]string{1: "BOOTREQUEST", 2: "BOOTREPLY"}[b[0]]), "", base, 1),
		newField("Hardware type: "+arpHwName(be16(b[1:3])), "", base+1, 2),
		newField(fmt.Sprintf("Hardware address length: %d", b[2]), "", base+2, 1),
		newField(fmt.Sprintf("Hops: %d", b[3]), "", base+3, 1),
		newField(fmt.Sprintf("Transaction ID: 0x%08x", be32(b[4:8])), "", base+4, 4),
		newField(fmt.Sprintf("Seconds elapsed: %d", be16(b[8:10])), "", base+8, 2),
		newField(fmt.Sprintf("Flags: 0x%04x%s", be16(b[10:12]), func() string {
			if be16(b[10:12])&0x8000 != 0 {
				return " (broadcast)"
			}
			return ""
		}()), "", base+10, 2),
		newField("Client IP address: "+ip4String(be32(b[12:16])), "", base+12, 4),
		newField("Your (client) IP address: "+ip4String(be32(b[16:20])), "", base+16, 4),
		newField("Next server IP address: "+ip4String(be32(b[20:24])), "", base+20, 4),
		newField("Relay agent IP address: "+ip4String(be32(b[24:28])), "", base+24, 4),
		newField("Client MAC address: "+macString(b[28:34]), "", base+28, 6),
	)
	if s := trimNul(b[44:108]); s != "" {
		root.add(newField("Server host name: "+s, "", base+44, 64))
	}
	if f := trimNul(b[108:236]); f != "" {
		root.add(newField("Boot file name: "+f, "", base+108, 128))
	}
	magic := be32(b[236:240])
	root.add(newField(fmt.Sprintf("Magic Cookie: 0x%08x", magic), "", base+236, 4))

	var parseOptions func(opts []byte, optBase int, section string)
	parseOptions = func(opts []byte, optBase int, section string) {
		for off := 0; off < len(opts); {
			opt := opts[off]
			if opt == 255 {
				root.add(newField("End Option", "", optBase+off, 1))
				break
			}
			if opt == 0 {
				off++
				continue
			}
			if off+2 > len(opts) {
				break
			}
			l := int(opts[off+1])
			if off+2+l > len(opts) {
				break
			}
			v := opts[off+2 : off+2+l]
			val := dhcpOptionText(opt, v)
			label := fmt.Sprintf("%s: %s", dhcpOptionName(opt), val)
			if section != "" {
				label = section + ": " + label
			}
			root.add(newField(label, "", optBase+off, 2+l))
			switch opt {
			case 53:
				if len(v) > 0 {
					msgType = v[0]
				}
			case 12:
				hostname = string(v)
			case 50:
				requestedIP = dhcpIP(v)
			case 52:
				if len(v) > 0 && section == "" {
					if v[0]&1 != 0 {
						parseOptions(b[108:236], base+108, "bootfile")
					}
					if v[0]&2 != 0 {
						parseOptions(b[44:108], base+44, "sname")
					}
				}
			}
			off += 2 + l
		}
	}
	parseOptions(b[240:], base+240, "")

	root.Label = fmt.Sprintf("Dynamic Host Configuration Protocol (%s)", dhcpTypeName(msgType))
	c.addRoot(root)
	c.appInfo = dhcpTypeName(msgType)
	if hostname != "" {
		c.appInfo += " (" + hostname + ")"
	}
	if requestedIP != "" && msgType == 3 {
		c.appInfo += " requested=" + requestedIP
	}
	return true
}
