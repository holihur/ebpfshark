//go:build full

package decode

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

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

func bgpAttrs(c *ctx, data []byte, base int) []*Field {
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
		f := c.newField(fmt.Sprintf("%s (flags 0x%02x, %d bytes)", name, flags, l), "", base+p-l, l)
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
	root := c.newNode("Border Gateway Protocol", base, len(b))
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
		f := c.newField(fmt.Sprintf("%s (length %d)", name, length), "", base+off, length)
		f.add(
			c.newField("Marker: 16 bytes", "", base+off, 16),
			c.newField(fmt.Sprintf("Length: %d", length), "", base+off+16, 2),
			c.newField(fmt.Sprintf("Type: %s (%d)", name, typ), "", base+off+18, 1),
		)
		switch typ {
		case 1: // OPEN
			if len(msg) >= 29 {
				asn := be16(msg[20:22])
				hold := be16(msg[22:24])
				routerID := netip.AddrFrom4([4]byte{msg[24], msg[25], msg[26], msg[27]}).String()
				optLen := int(msg[28])
				f.add(
					c.newField(fmt.Sprintf("Version: %d", msg[19]), "", base+off+19, 1),
					c.newField(fmt.Sprintf("My AS: %d", asn), "", base+off+20, 2),
					c.newField(fmt.Sprintf("Hold Time: %d s", hold), "", base+off+22, 2),
					c.newField("BGP Identifier: "+routerID, "", base+off+24, 4),
					c.newField(fmt.Sprintf("Optional Parameters Length: %d", optLen), "", base+off+28, 1),
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
						f.add(c.newField(fmt.Sprintf("Capability %d: %s", code, desc), hexPreview(pv[q:q+cl], 24), base+off+p-pl+q-2, cl))
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
				f.add(c.newField(fmt.Sprintf("Withdrawn Routes Length: %d", wlen), "", base+off+19, 2))
				withdrawn := []string{}
				if wlen > 0 && 21+wlen <= len(msg) {
					withdrawn = bgpPrefixList(msg[21:21+wlen], 1, false)
					f.add(c.newField("Withdrawn Routes: "+strings.Join(withdrawn, " "), "", base+off+21, wlen))
				}
				if alenOff+2 <= len(msg) {
					alen := int(be16(msg[alenOff : alenOff+2]))
					f.add(c.newField(fmt.Sprintf("Path Attributes Length: %d", alen), "", base+off+alenOff, 2))
					attrStart := alenOff + 2
					if attrStart+alen <= len(msg) {
						attrs := bgpAttrs(c, msg[attrStart:attrStart+alen], base+off+attrStart)
						f.add(attrs...)
						nlri := msg[attrStart+alen:]
						prefixes := bgpPrefixList(nlri, 1, false)
						if len(prefixes) > 0 {
							f.add(c.newField("NLRI: "+strings.Join(prefixes, " "), "", base+off+attrStart+alen, len(nlri)))
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
					c.newField(fmt.Sprintf("Error Code: %s (%d)", cname, errCode), "", base+off+19, 1),
					c.newField(fmt.Sprintf("Error Subcode: %d", sub), "", base+off+20, 1),
					c.newField("Data: "+hexPreview(msg[21:], 48), "", base+off+21, len(msg)-21),
				)
				info = fmt.Sprintf("BGP NOTIFICATION %s sub=%d", cname, sub)
			}
		case 4:
			info = "BGP KEEPALIVE"
		case 5:
			if len(msg) >= 23 {
				afi := be16(msg[19:21])
				safi := msg[22]
				f.add(c.newField(fmt.Sprintf("AFI: %d", afi), "", base+off+19, 2), c.newField("Reserved: "+strconv.Itoa(int(msg[21])), "", base+off+21, 1), c.newField(fmt.Sprintf("SAFI: %d", safi), "", base+off+22, 1))
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

func init() {
	RegisterPlugin(pluginSpec{Name: "bgp", Priority: 80, Transport: TransportTCP,
		Match: portMatch(map[uint16]bool{179: true}), Dissect: func(c *ctx, b []byte, base int) bool { return c.dissectBGP(b, base) }})
}
