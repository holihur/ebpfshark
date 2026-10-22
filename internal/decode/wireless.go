package decode

import (
	"encoding/binary"
	"fmt"
)

const (
	linkIEEE80211 = 105
	linkRadiotap  = 127
)

func looksLikeRadiotap(b []byte) bool {
	if len(b) < 8 || b[0] != 0 || b[1] != 0 {
		return false
	}
	l := int(b[2]) | int(b[3])<<8
	return l >= 8 && l <= len(b)
}

func (c *ctx) dissectRadiotap(b []byte, base int) {
	if !looksLikeRadiotap(b) {
		c.dissectDot11(b, base)
		return
	}
	hlen := int(b[2]) | int(b[3])<<8
	c.addLayer("radiotap")
	root := c.newNode(fmt.Sprintf("Radiotap (%d bytes)", hlen), base, hlen)
	root.add(c.newField(fmt.Sprintf("Version: %d", b[0]), "", base, 1), c.newField(fmt.Sprintf("Header Length: %d", hlen), "", base+2, 2))
	// Common radiotap fields: flags(1), rate(2), channel(3), signal(5).
	off := 8
	if hlen >= off+1 {
		root.add(c.newField(fmt.Sprintf("Flags: 0x%02x", b[off]), "", base+off, 1))
	}
	c.addRoot(root)
	if hlen < len(b) {
		c.dissectDot11(b[hlen:], base+hlen)
	}
}

func dot11TypeName(fc uint16) string {
	typ, sub := (fc>>2)&3, (fc>>4)&0xf
	switch typ {
	case 0:
		names := []string{"Association Request", "Association Response", "Reassociation Request", "Reassociation Response", "Probe Request", "Probe Response", "Timing Advertisement", "Reserved", "Beacon", "ATIM", "Disassociation", "Authentication", "Deauthentication", "Action", "Action No Ack"}
		if int(sub) < len(names) && names[sub] != "" {
			return names[sub]
		}
		return "Management"
	case 1:
		return "Control"
	case 2:
		return "Data"
	case 3:
		return "Extension"
	}
	return "802.11"
}

func (c *ctx) dissectDot11(b []byte, base int) {
	if looksLikeRadiotap(b) {
		c.dissectRadiotap(b, base)
		return
	}
	if len(b) < 10 {
		c.addRoot(c.newNode("IEEE 802.11 (truncated)", base, len(b)))
		return
	}
	fc := binary.LittleEndian.Uint16(b[0:2])
	typ := (fc >> 2) & 3
	name := dot11TypeName(fc)
	c.addLayer("wifi")
	c.proto = "wifi"
	root := c.newNode("IEEE 802.11 "+name, base, len(b))
	root.add(c.newField(fmt.Sprintf("Frame Control: 0x%04x", fc), "", base, 2), c.newField("Type: "+name, "", base, 1))
	info := "802.11 " + name
	addr1 := macString(b[4:10])
	var addr2, addr3 string
	if len(b) >= 24 {
		addr2, addr3 = macString(b[10:16]), macString(b[16:22])
		root.add(c.newField("Destination: "+addr1, "", base+4, 6), c.newField("Source: "+addr2, "", base+10, 6), c.newField("BSSID: "+addr3, "", base+16, 6))
	}
	c.m.EthSrc, c.m.EthDst = addr2, addr1
	hdr := 24
	switch typ {
	case 0: // management
		if len(b) > 24 {
			switch (fc >> 4) & 0xf {
			case 5, 8: // probe response / beacon
				if len(b) >= 36 {
					ies := b[36:]
					if ssid, ok := dot11SSID(ies); ok {
						root.add(c.newField("SSID: "+ssid, "", base+36, len(ies)))
						info += " SSID=" + ssid
					}
				}
			case 0, 2, 4: // assoc/probe request
				if ssid, ok := dot11SSID(b[28:]); ok {
					root.add(c.newField("SSID: "+ssid, "", base+28, len(b)-28))
					info += " SSID=" + ssid
				}
			case 11: // authentication
				if len(b) >= 30 {
					root.add(c.newField(fmt.Sprintf("Auth Algorithm: %d", be16(b[24:26])), "", base+24, 2), c.newField(fmt.Sprintf("Auth Sequence: %d", be16(b[26:28])), "", base+26, 2))
				}
			}
		}
	case 1: // control
		if len(b) >= 16 {
			root.add(c.newField("Receiver: "+addr1, "", base+4, 6))
		}
	case 2: // data
		toDS, fromDS := fc&0x0100 != 0, fc&0x0200 != 0
		if toDS && fromDS {
			hdr = 30
		}
		if (fc>>4)&0x8 != 0 { // QoS data
			hdr += 2
		}
		if len(b) > hdr+8 && b[hdr] == 0xaa && b[hdr+1] == 0xaa && b[hdr+2] == 0x03 {
			et := be16(b[hdr+6 : hdr+8])
			payload := b[hdr+8:]
			root.add(c.newField(fmt.Sprintf("LLC/SNAP EtherType: 0x%04x", et), "", base+hdr+6, 2))
			c.addRoot(root)
			switch et {
			case etherTypeIPv4:
				c.dissectIPv4(payload, base+hdr+8)
			case etherTypeIPv6:
				c.dissectIPv6(payload, base+hdr+8)
			case etherTypeARP:
				c.dissectARP(payload, base+hdr+8)
			}
			if c.appInfo != "" {
				info += " " + c.appInfo
			}
			c.appInfo = info
			return
		}
	}
	c.addRoot(root)
	c.appInfo = info
}

func dot11SSID(ies []byte) (string, bool) {
	for p := 0; p+2 <= len(ies); {
		id, l := ies[p], int(ies[p+1])
		if p+2+l > len(ies) {
			return "", false
		}
		if id == 0 && l > 0 {
			return string(ies[p+2 : p+2+l]), true
		}
		p += 2 + l
	}
	return "", false
}
