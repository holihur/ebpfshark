package decode

import (
	"encoding/binary"
	"fmt"
	"strings"
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

func rtAlign(off, align int) int     { return (off + align - 1) &^ (align - 1) }
func rtU16(b []byte, off int) uint16 { return binary.LittleEndian.Uint16(b[off:]) }
func rtU32(b []byte, off int) uint32 { return binary.LittleEndian.Uint32(b[off:]) }
func rtU64(b []byte, off int) uint64 { return binary.LittleEndian.Uint64(b[off:]) }

func (c *ctx) dissectRadiotap(b []byte, base int) {
	if !looksLikeRadiotap(b) {
		c.dissectDot11(b, base)
		return
	}
	hlen := int(b[2]) | int(b[3])<<8
	c.addLayer("radiotap")
	root := c.newNode(fmt.Sprintf("Radiotap (%d bytes)", hlen), base, hlen)
	root.add(c.newField(fmt.Sprintf("Version: %d", b[0]), "", base, 1), c.newField("Pad: 0", "", base+1, 1), c.newField(fmt.Sprintf("Header Length: %d", hlen), "", base+2, 2))
	// Presence bitmaps; bit 31 of each word means another word follows.
	off := 4
	var present []uint32
	for off+4 <= hlen {
		w := rtU32(b, off)
		present = append(present, w)
		off += 4
		if w&0x80000000 == 0 {
			break
		}
	}
	if len(present) > 0 {
		root.add(c.newField(fmt.Sprintf("Present Flags: %d word(s)", len(present)), fmt.Sprintf("0x%08x", present[0]), base+4, 4*len(present)))
	}
	bit := func(n int) bool {
		if n < 0 || n/32 >= len(present) {
			return false
		}
		return present[n/32]&(1<<uint(n%32)) != 0
	}
	fieldOff := off
	next := func(align, size int) int {
		fieldOff = rtAlign(fieldOff, align)
		if fieldOff+size > hlen {
			return -1
		}
		p := fieldOff
		fieldOff += size
		return p
	}
	for n := 0; n < 32*len(present) && fieldOff < hlen; n++ {
		if !bit(n) {
			continue
		}
		switch n {
		case 0:
			if p := next(8, 8); p >= 0 {
				root.add(c.newField(fmt.Sprintf("TSFT: %d", rtU64(b, p)), "", base+p, 8))
			}
		case 1:
			if p := next(1, 1); p >= 0 {
				root.add(c.newField(fmt.Sprintf("Flags: 0x%02x", b[p]), "", base+p, 1))
			}
		case 2:
			if p := next(1, 1); p >= 0 {
				root.add(c.newField(fmt.Sprintf("Rate: %.1f Mbps", float64(b[p])/2), "", base+p, 1))
			}
		case 3:
			if p := next(2, 4); p >= 0 {
				freq, flags := rtU16(b, p), rtU16(b, p+2)
				root.add(c.newField(fmt.Sprintf("Channel: %d MHz, flags 0x%04x", freq, flags), "", base+p, 4))
			}
		case 4:
			if p := next(2, 3); p >= 0 {
				root.add(c.newField(fmt.Sprintf("FHSS: hop %d, pattern %d", rtU16(b, p), b[p+2]), "", base+p, 3))
			}
		case 5:
			if p := next(1, 1); p >= 0 {
				root.add(c.newField(fmt.Sprintf("Antenna Signal: %d dBm", int8(b[p])), "", base+p, 1))
			}
		case 6:
			if p := next(1, 1); p >= 0 {
				root.add(c.newField(fmt.Sprintf("Antenna Noise: %d dBm", int8(b[p])), "", base+p, 1))
			}
		case 7:
			if p := next(2, 2); p >= 0 {
				root.add(c.newField(fmt.Sprintf("Lock Quality: %d", rtU16(b, p)), "", base+p, 2))
			}
		case 8:
			if p := next(2, 2); p >= 0 {
				root.add(c.newField(fmt.Sprintf("TX Attenuation: %d", rtU16(b, p)), "", base+p, 2))
			}
		case 9:
			if p := next(2, 2); p >= 0 {
				root.add(c.newField(fmt.Sprintf("dB TX Attenuation: %d", rtU16(b, p)), "", base+p, 2))
			}
		case 10:
			if p := next(1, 1); p >= 0 {
				root.add(c.newField(fmt.Sprintf("dBm TX Power: %d", int8(b[p])), "", base+p, 1))
			}
		case 11:
			if p := next(1, 1); p >= 0 {
				root.add(c.newField(fmt.Sprintf("Antenna: %d", b[p]), "", base+p, 1))
			}
		case 12:
			if p := next(1, 1); p >= 0 {
				root.add(c.newField(fmt.Sprintf("dB Antenna Signal: %d", b[p]), "", base+p, 1))
			}
		case 13:
			if p := next(1, 1); p >= 0 {
				root.add(c.newField(fmt.Sprintf("dB Antenna Noise: %d", b[p]), "", base+p, 1))
			}
		case 14:
			if p := next(2, 2); p >= 0 {
				root.add(c.newField(fmt.Sprintf("RX Flags: 0x%04x", rtU16(b, p)), "", base+p, 2))
			}
		case 15:
			if p := next(2, 2); p >= 0 {
				root.add(c.newField(fmt.Sprintf("TX Flags: 0x%04x", rtU16(b, p)), "", base+p, 2))
			}
		case 16:
			if p := next(1, 1); p >= 0 {
				root.add(c.newField(fmt.Sprintf("RTS Retries: %d", b[p]), "", base+p, 1))
			}
		case 17:
			if p := next(1, 1); p >= 0 {
				root.add(c.newField(fmt.Sprintf("Data Retries: %d", b[p]), "", base+p, 1))
			}
		case 18:
			if p := next(4, 8); p >= 0 {
				root.add(c.newField(fmt.Sprintf("XChannel: flags 0x%08x freq %d channel %d maxpower %d", rtU32(b, p), rtU16(b, p+4), b[p+6], b[p+7]), "", base+p, 8))
			}
		case 19:
			if p := next(1, 3); p >= 0 {
				root.add(c.newField(fmt.Sprintf("MCS: known 0x%02x flags 0x%02x index %d", b[p], b[p+1], b[p+2]), "", base+p, 3))
			}
		case 20:
			if p := next(4, 8); p >= 0 {
				root.add(c.newField("A-MPDU Status", fmt.Sprintf("reference %d, flags 0x%04x, delimiter CRC %d", rtU32(b, p), rtU16(b, p+4), b[p+6]), base+p, 8))
			}
		case 21:
			if p := next(2, 12); p >= 0 {
				root.add(c.newField("VHT", fmt.Sprintf("known 0x%04x flags 0x%02x bandwidth %d", rtU16(b, p), b[p+2], b[p+3]), base+p, 12))
			}
		case 22:
			if p := next(8, 8); p >= 0 {
				root.add(c.newField(fmt.Sprintf("Timestamp: %d", rtU64(b, p)), "", base+p, 8))
			}
		case 23:
			if p := next(2, 12); p >= 0 {
				root.add(c.newField("HE", fmt.Sprintf("data1 0x%04x data2 0x%04x data3 0x%04x", rtU16(b, p), rtU16(b, p+2), rtU16(b, p+4)), base+p, 12))
			}
		case 24:
			if p := next(2, 12); p >= 0 {
				root.add(c.newField("HE-MU", fmt.Sprintf("0x%04x 0x%04x 0x%04x", rtU16(b, p), rtU16(b, p+2), rtU16(b, p+4)), base+p, 12))
			}
		case 25:
			root.add(c.newField("0-Length PSDU", "", base, 0))
		case 26:
			if p := next(4, 4); p >= 0 {
				root.add(c.newField(fmt.Sprintf("L-SIG: 0x%08x", rtU32(b, p)), "", base+p, 4))
			}
		case 27:
			if p := next(1, 4); p >= 0 {
				t, l := rtU16(b, p), int(rtU16(b, p+2))
				if p+4+l <= hlen {
					root.add(c.newField(fmt.Sprintf("TLV: type %d, length %d", t, l), hexPreview(b[p+4:p+4+l], 32), base+p, 4+l))
					fieldOff = p + 4 + l
				}
			}
		case 29:
			if p := next(1, 6); p >= 0 {
				oui := fmt.Sprintf("%02x:%02x:%02x", b[p], b[p+1], b[p+2])
				sub, l := b[p+3], int(rtU16(b, p+4))
				if p+6+l <= hlen {
					root.add(c.newField(fmt.Sprintf("Vendor Namespace %s/%d", oui, sub), hexPreview(b[p+6:p+6+l], 32), base+p, 6+l))
					fieldOff = p + 6 + l
				}
			}
		}
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
		names := map[uint16]string{7: "Control Wrapper", 8: "Block Ack Request", 9: "Block Ack", 10: "PS-Poll", 11: "RTS", 12: "CTS", 13: "ACK", 14: "CF-End", 15: "CF-End + CF-Ack"}
		if n := names[sub]; n != "" {
			return n
		}
		return "Control"
	case 2:
		return "Data"
	case 3:
		return "Extension"
	}
	return "802.11"
}

func dot11Flags(fc uint16) string {
	var f []string
	if fc&0x0100 != 0 {
		f = append(f, "ToDS")
	}
	if fc&0x0200 != 0 {
		f = append(f, "FromDS")
	}
	if fc&0x0400 != 0 {
		f = append(f, "MoreFrag")
	}
	if fc&0x0800 != 0 {
		f = append(f, "Retry")
	}
	if fc&0x1000 != 0 {
		f = append(f, "PowerMgmt")
	}
	if fc&0x2000 != 0 {
		f = append(f, "MoreData")
	}
	if fc&0x4000 != 0 {
		f = append(f, "Protected")
	}
	if fc&0x8000 != 0 {
		f = append(f, "Order")
	}
	if len(f) == 0 {
		return "none"
	}
	return strings.Join(f, ", ")
}

var dot11IENames = map[byte]string{0: "SSID", 1: "Supported Rates", 3: "DS Parameter Set", 5: "TIM", 7: "Country", 11: "BSS Load", 45: "HT Capabilities", 47: "ERP", 48: "RSN", 50: "Extended Supported Rates", 52: "Power Constraint", 61: "HT Operation", 74: "Overlapping BSS Scan", 107: "Interworking", 127: "Extended Capabilities", 191: "VHT Capabilities", 192: "VHT Operation", 221: "Vendor Specific", 255: "Element ID Extension"}

func (c *ctx) dot11IEs(ies []byte, base int, parent *Field) {
	for p := 0; p+2 <= len(ies); {
		id, l := ies[p], int(ies[p+1])
		if p+2+l > len(ies) {
			return
		}
		v := ies[p+2 : p+2+l]
		name := dot11IENames[id]
		if name == "" {
			name = fmt.Sprintf("IE %d", id)
		}
		f := c.newField(fmt.Sprintf("%s (%d)", name, l), "", base+p, 2+l)
		switch id {
		case 0:
			f.Value = string(v)
		case 1, 50:
			var rates []string
			for _, x := range v {
				rates = append(rates, fmt.Sprintf("%.1f", float64(x&0x7f)/2))
			}
			f.Value = strings.Join(rates, ", ") + " Mbps"
		case 3:
			if len(v) > 0 {
				f.Value = fmt.Sprintf("Channel %d", v[0])
			}
		case 5:
			if len(v) >= 4 {
				f.Value = fmt.Sprintf("DTIM Count %d, Period %d, Bitmap 0x%02x", v[2], v[3], v[4:])
			}
		case 48:
			f.add(dot11RSN(c, v, base+p+2)...)
		case 221:
			if len(v) >= 4 && v[0] == 0x00 && v[1] == 0x50 && v[2] == 0xf2 && v[3] == 0x01 {
				f.Label = "WPA (Vendor Specific)"
				f.add(dot11RSNSuite(c, v[4:], base+p+6, false)...)
			} else {
				f.Value = hexPreview(v, 32)
			}
		default:
			if l <= 16 {
				f.Value = hexPreview(v, l)
			} else {
				f.Value = hexPreview(v, 32)
			}
		}
		parent.add(f)
		p += 2 + l
	}
}

func dot11CipherName(v uint32) string {
	switch v {
	case 0x000fac01:
		return "WEP-40"
	case 0x000fac02:
		return "TKIP"
	case 0x000fac04:
		return "CCMP-128"
	case 0x000fac05:
		return "WEP-104"
	case 0x000fac08:
		return "GCMP-256"
	case 0x000fac09:
		return "GCMP-128"
	case 0x000fac06:
		return "BIP-CMAC-128"
	case 0x000fac07:
		return "BIP-GMAC-128"
	case 0x000fac0b:
		return "BIP-GMAC-256"
	}
	return fmt.Sprintf("0x%06x", v)
}

func dot11AKMName(v uint32) string {
	switch v {
	case 1:
		return "802.1X"
	case 2:
		return "PSK"
	case 3:
		return "FT-802.1X"
	case 4:
		return "FT-PSK"
	case 6:
		return "PSK-SHA256"
	case 8:
		return "SAE"
	case 9:
		return "FT-SAE"
	case 18:
		return "OWE"
	case 24:
		return "SAE-EXT-KEY"
	}
	return fmt.Sprintf("0x%06x", v)
}

func dot11RSN(c *ctx, v []byte, base int) []*Field {
	return dot11RSNSuite(c, v, base, true)
}

func dot11RSNSuite(c *ctx, v []byte, base int, rsn bool) []*Field {
	var out []*Field
	if len(v) < 2 {
		return out
	}
	p := 2
	if p+4 <= len(v) {
		grp := uint32(v[p])<<24 | uint32(v[p+1])<<16 | uint32(v[p+2])<<8 | uint32(v[p+3])
		out = append(out, c.newField("Group Cipher: "+dot11CipherName(grp), "", base+p, 4))
		p += 4
	}
	if p+2 <= len(v) {
		n := int(be16(v[p : p+2]))
		p += 2
		for i := 0; i < n && p+4 <= len(v); i++ {
			cc := uint32(v[p])<<24 | uint32(v[p+1])<<16 | uint32(v[p+2])<<8 | uint32(v[p+3])
			out = append(out, c.newField("Pairwise Cipher: "+dot11CipherName(cc), "", base+p, 4))
			p += 4
		}
	}
	if p+2 <= len(v) {
		n := int(be16(v[p : p+2]))
		p += 2
		for i := 0; i < n && p+4 <= len(v); i++ {
			akm := uint32(v[p+3])
			out = append(out, c.newField("AKM: "+dot11AKMName(akm), "", base+p, 4))
			p += 4
		}
	}
	if p+2 <= len(v) {
		caps := be16(v[p : p+2])
		out = append(out, c.newField(fmt.Sprintf("RSN Capabilities: 0x%04x", caps), "", base+p, 2))
		p += 2
	}
	if rsn && p+2 <= len(v) {
		n := int(be16(v[p : p+2]))
		p += 2
		for i := 0; i < n && p+16 <= len(v); i++ {
			out = append(out, c.newField("PMKID: "+hexPreview(v[p:p+16], 16), "", base+p, 16))
			p += 16
		}
	}
	return out
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
	root.add(c.newField(fmt.Sprintf("Frame Control: 0x%04x", fc), "", base, 2), c.newField("Type/Subtype: "+name, "", base, 1), c.newField("Flags: "+dot11Flags(fc), "", base+1, 1), c.newField(fmt.Sprintf("Duration: %d", binary.LittleEndian.Uint16(b[2:4])), "", base+2, 2))
	info := "802.11 " + name
	addr1 := macString(b[4:10])
	var addr2, addr3, addr4 string
	if len(b) >= 24 {
		addr2, addr3 = macString(b[10:16]), macString(b[16:22])
		root.add(c.newField("Address 1: "+addr1, "", base+4, 6), c.newField("Address 2: "+addr2, "", base+10, 6), c.newField("Address 3: "+addr3, "", base+16, 6), c.newField(fmt.Sprintf("Sequence Control: 0x%04x", binary.LittleEndian.Uint16(b[22:24])), "", base+22, 2))
	}
	hdr := 24
	toDS, fromDS := fc&0x0100 != 0, fc&0x0200 != 0
	if typ == 2 && toDS && fromDS && len(b) >= 30 {
		addr4 = macString(b[24:30])
		root.add(c.newField("Address 4: "+addr4, "", base+24, 6))
		hdr = 30
	}
	c.m.EthSrc, c.m.EthDst = addr2, addr1
	switch typ {
	case 0:
		c.dot11Management(b, base, fc, hdr, root, &info)
	case 1:
		if (fc>>4)&0xf == 12 || (fc>>4)&0xf == 13 { // CTS/ACK
			root.add(c.newField("Receiver: "+addr1, "", base+4, 6))
		}
	case 2:
		if fc&0x4000 != 0 {
			pt, ap, ok := wifiDecryptFrame(b, hdr, fc, addr1, addr2, addr3)
			if ok {
				apMAC, staMAC := dot11APSTA(fc, addr1, addr2, addr3)
				_ = ap
				root.add(c.newField(fmt.Sprintf("Decrypted CCMP MSDU (%d bytes)", len(pt)), printablePreview(pt, 96), base+hdr+8, len(pt)))
				c.addRoot(root)
				c.dot11LLC(pt, fc, addr1, addr2, addr3, base+hdr+8)
				info += " [decrypted]"
				if c.appInfo != "" {
					info += " " + c.appInfo
				}
				c.appInfo = info
				_ = apMAC
				_ = staMAC
				return
			}
			root.add(c.newField("Protected Frame: encrypted payload not decoded", "", base+1, 1))
			info += " [protected]"
		} else {
			if (fc>>4)&0x8 != 0 { // QoS data
				if hdr+2 <= len(b) {
					qos := binary.LittleEndian.Uint16(b[hdr : hdr+2])
					root.add(c.newField(fmt.Sprintf("QoS Control: 0x%04x (TID %d, EOSP %d, A-MSDU %d)", qos, qos&0xf, (qos>>4)&1, (qos>>7)&1), "", base+hdr, 2))
					hdr += 2
					if qos&0x80 != 0 {
						c.dot11AMSDU(b[hdr:], base+hdr, root)
						info += " A-MSDU"
					}
				}
			}
			if len(b) > hdr+8 && b[hdr] == 0xaa && b[hdr+1] == 0xaa && b[hdr+2] == 0x03 {
				et := be16(b[hdr+6 : hdr+8])
				root.add(c.newField(fmt.Sprintf("LLC/SNAP EtherType: 0x%04x", et), "", base+hdr+6, 2))
				c.addRoot(root)
				if et == 0x888e {
					apMAC, staMAC := dot11APSTA(fc, addr1, addr2, addr3)
					c.dissectEAPOL(b[hdr+8:], base+hdr+8, apMAC, staMAC)
				} else {
					switch et {
					case etherTypeIPv4:
						c.dissectIPv4(b[hdr+8:], base+hdr+8)
					case etherTypeIPv6:
						c.dissectIPv6(b[hdr+8:], base+hdr+8)
					case etherTypeARP:
						c.dissectARP(b[hdr+8:], base+hdr+8)
					}
				}
				if c.appInfo != "" {
					info += " " + c.appInfo
				}
				c.appInfo = info
				return
			}
		}
	}
	c.addRoot(root)
	c.appInfo = info
}

func dot11APSTA(fc uint16, addr1, addr2, addr3 string) (string, string) {
	toDS, fromDS := fc&0x0100 != 0, fc&0x0200 != 0
	switch {
	case toDS && !fromDS:
		return addr1, addr2
	case fromDS && !toDS:
		return addr2, addr1
	case toDS && fromDS:
		return addr1, addr3
	default:
		return addr3, addr2
	}
}

func (c *ctx) dot11LLC(payload []byte, fc uint16, addr1, addr2, addr3 string, base int) {
	if len(payload) < 8 || payload[0] != 0xaa || payload[1] != 0xaa || payload[2] != 0x03 {
		if len(payload) > 0 {
			c.addRoot(c.newField(fmt.Sprintf("Data (%d bytes)", len(payload)), hexPreview(payload, 48), base, len(payload)))
		}
		return
	}
	et := be16(payload[6:8])
	if et == 0x888e {
		ap, sta := dot11APSTA(fc, addr1, addr2, addr3)
		c.dissectEAPOL(payload[8:], base+8, ap, sta)
		return
	}
	switch et {
	case etherTypeIPv4:
		c.dissectIPv4(payload[8:], base+8)
	case etherTypeIPv6:
		c.dissectIPv6(payload[8:], base+8)
	case etherTypeARP:
		c.dissectARP(payload[8:], base+8)
	}
}

func (c *ctx) dot11Management(b []byte, base int, fc uint16, hdr int, root *Field, info *string) {
	sub := (fc >> 4) & 0xf
	if len(b) <= hdr {
		return
	}
	switch sub {
	case 8, 5: // beacon / probe response
		if len(b) >= 36 {
			root.add(c.newField(fmt.Sprintf("Timestamp: %d", rtU64(b, 24)), "", base+24, 8), c.newField(fmt.Sprintf("Beacon Interval: %d", rtU16(b, 32)), "", base+32, 2), c.newField(fmt.Sprintf("Capabilities: 0x%04x", rtU16(b, 34)), "", base+34, 2))
			c.dot11IEs(b[36:], base+36, root)
		}
	case 0, 2: // assoc/reassoc request
		if len(b) >= 28 {
			root.add(c.newField(fmt.Sprintf("Capabilities: 0x%04x", rtU16(b, 24)), "", base+24, 2), c.newField(fmt.Sprintf("Listen Interval: %d", rtU16(b, 26)), "", base+26, 2))
			c.dot11IEs(b[28:], base+28, root)
		}
	case 1, 3: // assoc/reassoc response
		if len(b) >= 30 {
			root.add(c.newField(fmt.Sprintf("Capabilities: 0x%04x", rtU16(b, 24)), "", base+24, 2), c.newField(fmt.Sprintf("Status: %d", rtU16(b, 26)), "", base+26, 2), c.newField(fmt.Sprintf("AID: %d", rtU16(b, 28)&0x3fff), "", base+28, 2))
			c.dot11IEs(b[30:], base+30, root)
		}
	case 4: // probe request
		c.dot11IEs(b[24:], base+24, root)
	case 11: // authentication
		if len(b) >= 28 {
			algo, seq, status := rtU16(b, 24), rtU16(b, 26), uint16(0)
			if len(b) >= 30 {
				status = rtU16(b, 28)
			}
			root.add(c.newField(fmt.Sprintf("Auth Algorithm: %d", algo), "", base+24, 2), c.newField(fmt.Sprintf("Auth Sequence: %d", seq), "", base+26, 2), c.newField(fmt.Sprintf("Status: %d", status), "", base+28, 2))
			if algo == 3 && len(b) > 30 {
				root.add(c.newField(fmt.Sprintf("SAE Group: %d", rtU16(b, 30)), "", base+30, 2), c.newField("SAE Data", hexPreview(b[32:], 64), base+32, len(b)-32))
			}
			*info += fmt.Sprintf(" algo=%d seq=%d", algo, seq)
		}
	case 10, 12: // disassoc/deauth
		if len(b) >= 26 {
			root.add(c.newField(fmt.Sprintf("Reason Code: %d", rtU16(b, 24)), "", base+24, 2))
		}
	case 13: // action
		if len(b) >= 26 {
			root.add(c.newField(fmt.Sprintf("Category: %d", b[24]), "", base+24, 1), c.newField(fmt.Sprintf("Action: %d", b[25]), "", base+25, 1))
			if len(b) > 26 {
				root.add(c.newField("Action Data", hexPreview(b[26:], 48), base+26, len(b)-26))
			}
		}
	}
	if v, ok := dot11SSID(b[hdr:]); ok {
		*info += " SSID=" + v
	}
}

func (c *ctx) dot11AMSDU(b []byte, base int, root *Field) {
	p := 0
	for i := 0; i < 16 && p+14 <= len(b); i++ {
		l := int(be16(b[p+12 : p+14]))
		if p+14+l > len(b) {
			break
		}
		f := c.newField(fmt.Sprintf("A-MSDU Subframe %d (%d bytes)", i+1, l), "", base+p, 14+l)
		f.add(c.newField("DA: "+macString(b[p:p+6]), "", base+p, 6), c.newField("SA: "+macString(b[p+6:p+12]), "", base+p+6, 6))
		root.add(f)
		p += 14 + ((l + 3) &^ 3)
	}
}

func (c *ctx) dissectEAPOL(b []byte, base int, ap, sta string) {
	if len(b) < 4 {
		return
	}
	ver, typ, l := b[0], b[1], int(be16(b[2:4]))
	if l < 4 || l > len(b) {
		return
	}
	names := map[byte]string{0: "EAP-Packet", 1: "EAPOL-Start", 2: "EAPOL-Logoff", 3: "EAPOL-Key", 4: "EAPOL-Encapsulated-ASF-Alert"}
	name := names[typ]
	if name == "" {
		name = fmt.Sprintf("EAPOL Type %d", typ)
	}
	c.addLayer("eapol")
	c.proto = "eapol"
	root := c.newNode("EAPOL "+name, base, l)
	root.add(c.newField(fmt.Sprintf("Version: %d", ver), "", base, 1), c.newField("Type: "+name, "", base+1, 1), c.newField(fmt.Sprintf("Length: %d", l), "", base+2, 2))
	info := "EAPOL " + name
	if typ == 3 && l >= 99 {
		desc := b[4]
		ki := be16(b[5:7])
		root.add(c.newField(fmt.Sprintf("Descriptor Type: %d", desc), "", base+4, 1), c.newField(fmt.Sprintf("Key Info: 0x%04x", ki), "", base+5, 2), c.newField(fmt.Sprintf("Key Length: %d", be16(b[7:9])), "", base+7, 2), c.newField(fmt.Sprintf("Replay Counter: %d", be64(b[9:17])), "", base+9, 8), c.newField("Nonce: "+hexPreview(b[17:49], 32), "", base+17, 32), c.newField("IV: "+hexPreview(b[49:65], 16), "", base+49, 16), c.newField("RSC: "+hexPreview(b[65:73], 8), "", base+65, 8), c.newField("Key ID: "+hexPreview(b[73:81], 8), "", base+73, 8), c.newField("MIC: "+hexPreview(b[81:97], 16), "", base+81, 16))
		kdLen := int(be16(b[97:99]))
		if 99+kdLen <= l {
			root.add(c.newField(fmt.Sprintf("Key Data (%d bytes)", kdLen), hexPreview(b[99:99+kdLen], 48), base+99, kdLen))
		}
		info += fmt.Sprintf(" replay=%d", be64(b[9:17]))
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
