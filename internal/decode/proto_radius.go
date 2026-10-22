//go:build full

package decode

import "fmt"

// ---------------------------------------------------------------- RADIUS

var radiusCodes = map[byte]string{1: "Access-Request", 2: "Access-Accept", 3: "Access-Reject", 4: "Accounting-Request", 5: "Accounting-Response", 11: "Access-Challenge", 12: "Status-Server", 13: "Status-Client"}

var radiusAttrs = map[byte]string{1: "User-Name", 2: "User-Password", 4: "NAS-IP-Address", 5: "NAS-Port", 6: "Service-Type", 7: "Framed-Protocol", 8: "Framed-IP-Address", 18: "Reply-Message", 24: "State", 25: "Class", 26: "Vendor-Specific", 27: "Session-Timeout", 28: "Idle-Timeout", 30: "Called-Station-Id", 31: "Calling-Station-Id", 32: "NAS-Identifier", 40: "Acct-Status-Type", 44: "Acct-Session-Id", 55: "Event-Timestamp", 79: "EAP-Message", 80: "Message-Authenticator"}

func (c *ctx) dissectRADIUS(b []byte, base int) bool {
	if len(b) < 20 {
		return false
	}
	code, id := b[0], b[1]
	l := int(be16(b[2:4]))
	if l < 20 || l > len(b) {
		return false
	}
	name := radiusCodes[code]
	if name == "" {
		return false
	}
	c.addLayer("radius")
	c.proto = "radius"
	root := newNode("RADIUS "+name, base, l)
	root.add(newField("Code: "+name, "", base, 1), newField(fmt.Sprintf("Identifier: %d", id), "", base+1, 1), newField(fmt.Sprintf("Length: %d", l), "", base+2, 2), newField("Authenticator: "+hexPreview(b[4:20], 16), "", base+4, 16))
	info := "RADIUS " + name
	for off := 20; off+2 <= l; {
		t, al := b[off], int(b[off+1])
		if al < 2 || off+al > l {
			break
		}
		v := b[off+2 : off+al]
		an := radiusAttrs[t]
		if an == "" {
			an = fmt.Sprintf("Attribute-%d", t)
		}
		val := string(v)
		if t == 1 || t == 18 || t == 30 || t == 31 || t == 44 {
			info += " " + val
		}
		if t == 2 || t == 4 || t == 8 {
			val = hexPreview(v, 16)
		}
		root.add(newField(an+": "+shorten(val, 120), "", base+off, al))
		off += al
	}
	c.addRoot(root)
	c.appInfo = shorten(info, 120)
	return true
}

func init() {
	RegisterPlugin(pluginSpec{Name: "radius", Priority: 110, Transport: TransportUDP | TransportTCP,
		Match: portMatch(map[uint16]bool{1812: true, 1813: true, 1645: true, 1646: true}), Dissect: func(c *ctx, b []byte, base int) bool { return c.dissectRADIUS(b, base) }})
}
