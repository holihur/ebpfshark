//go:build full

package decode

import (
	"fmt"
	"strings"
)

// ---------------------------------------------------------------- MySQL

func le24(b []byte) int { return int(b[0]) | int(b[1])<<8 | int(b[2])<<16 }

func mysqlCString(b []byte, off int) (string, int, bool) {
	if off >= len(b) {
		return "", off, false
	}
	if i := strings.IndexByte(string(b[off:]), 0); i >= 0 {
		return string(b[off : off+i]), off + i + 1, true
	}
	return string(b[off:]), len(b), true
}

func mysqlLenEnc(b []byte, off int) (uint64, int, bool) {
	if off >= len(b) {
		return 0, off, false
	}
	switch b[off] {
	case 0xfc:
		if off+3 > len(b) {
			return 0, off, false
		}
		return uint64(be16(b[off+1 : off+3])), off + 3, true
	case 0xfd:
		if off+4 > len(b) {
			return 0, off, false
		}
		return uint64(le24(b[off+1 : off+4])), off + 4, true
	case 0xfe:
		if off+9 > len(b) {
			return 0, off, false
		}
		return be64(b[off+1 : off+9]), off + 9, true
	case 0xfb:
		return 0, off + 1, true
	}
	return uint64(b[off]), off + 1, true
}

func (c *ctx) dissectMySQL(b []byte, base int) bool {
	if len(b) < 5 {
		return false
	}
	l := le24(b)
	if l < 1 || l > 16<<20 || 4+l > len(b) {
		return false
	}
	seq := b[3]
	payload := b[4 : 4+l]
	c.addLayer("mysql")
	c.proto = "mysql"
	root := newNode("MySQL", base, 4+l)
	root.add(
		newField(fmt.Sprintf("Packet Length: %d", l), "", base, 3),
		newField(fmt.Sprintf("Sequence ID: %d", seq), "", base+3, 1),
	)
	info := "MySQL"
	p := 0
	switch payload[0] {
	case 0x00:
		root.add(newField("OK Packet", "", base+4, 1))
		info = "MySQL OK"
	case 0xff:
		code := be16(payload[1:3])
		msg, _, _ := mysqlCString(payload, 3)
		root.add(newField(fmt.Sprintf("Error Code: %d", code), "", base+5, 2), newField("SQL State / Message: "+shorten(msg, 120), "", 0, 0))
		info = fmt.Sprintf("MySQL Error %d", code)
	case 0x0a:
		ver, n, _ := mysqlCString(payload, 1)
		root.add(newField("Protocol Version: 10", "", base+4, 1), newField("Server Version: "+ver, "", base+5, n-1))
		if n+4+8+1+2 <= len(payload) {
			p = n + 4 + 8 + 1
			caps := be16(payload[p : p+2])
			root.add(newField(fmt.Sprintf("Capabilities: 0x%04x", caps), "", base+4+p, 2))
		}
		info = "MySQL Handshake " + ver
	case 0x03:
		q, _, _ := mysqlCString(payload, 1)
		root.add(newField("COM_QUERY: "+shorten(q, 200), "", base+4, len(payload)-1))
		info = "MySQL Query " + shorten(q, 80)
	case 0x02:
		q, _, _ := mysqlCString(payload, 1)
		root.add(newField("COM_INIT_DB: "+q, "", base+4, len(payload)-1))
		info = "MySQL Init DB " + q
	case 0x16:
		q, _, _ := mysqlCString(payload, 1)
		root.add(newField("COM_STMT_PREPARE: "+shorten(q, 200), "", base+4, len(payload)-1))
		info = "MySQL Prepare " + shorten(q, 80)
	case 0x17:
		root.add(newField(fmt.Sprintf("COM_STMT_EXECUTE (%d bytes)", len(payload)), "", base+4, len(payload)))
		info = "MySQL Execute"
	default:
		root.add(newField(fmt.Sprintf("Command: 0x%02x", payload[0]), hexPreview(payload[1:], 48), base+4, len(payload)))
	}
	c.addRoot(root)
	c.appInfo = shorten(info, 120)
	return true
}

func init() {
	RegisterPlugin(pluginSpec{Name: "mysql", Priority: 60, Transport: TransportTCP,
		Match: portMatch(map[uint16]bool{3306: true}), Dissect: func(c *ctx, b []byte, base int) bool { return c.dissectMySQL(b, base) }})
}
