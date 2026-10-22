//go:build full

package decode

import "fmt"

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
	root := c.newNode("QUIC", base, len(b))
	root.add(
		c.newField(fmt.Sprintf("Header Form: %s", map[bool]string{true: "long", false: "short"}[long]), "", base, 1),
		c.newField(fmt.Sprintf("Fixed Bit: %d", (first>>6)&1), "", base, 1),
	)
	info := "QUIC"
	flow := tlsFlowFor(c)

	if long {
		root.Label = fmt.Sprintf("QUIC (%s)", quicVersionName(version))
		root.add(c.newField(fmt.Sprintf("Version: %s (0x%08x)", quicVersionName(version), version), "", base+1, 4))
		info += " " + quicVersionName(version)
		pktType := (first >> 4) & 0x3
		typeName := []string{"Initial", "0-RTT", "Handshake", "Retry"}[pktType]
		root.add(c.newField("Packet Type: "+typeName, "", base, 1))
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
			c.newField("Destination Connection ID: "+hexPreview(dcid, 20), "", base+6, dcidLen),
			c.newField("Source Connection ID: "+hexPreview(scid, 20), "", base+7+dcidLen, scidLen),
		)
		if pktType == 0 && off < len(b) {
			tokenLen, n, ok := quicVarint(b, off)
			if ok {
				root.add(c.newField(fmt.Sprintf("Token Length: %d", tokenLen), "", base+off, n))
				tokenOff := n
				off = n + int(tokenLen)
				if tokenLen > 0 && tokenOff+int(tokenLen) <= len(b) {
					root.add(c.newField("Token: "+hexPreview(b[tokenOff:tokenOff+int(tokenLen)], 32), "", base+tokenOff, int(tokenLen)))
				}
				if off < len(b) {
					if plen, n2, ok := quicVarint(b, off); ok {
						root.add(c.newField(fmt.Sprintf("Length: %d", plen), "", base+off, n2))
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
				root.add(c.newField(fmt.Sprintf("Length: %d", plen), "", base+off, n2))
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
					if !c.noFields && c.quicDecryptWithSecrets(b, base, root, flow, n2, n2+int(plen), first, true, secs) {
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
			root.add(c.newField("Destination Connection ID: "+hexPreview(dcid, 20), "", base+1, dcidLen))
			random := flow.randomCopy()
			if len(random) > 0 {
				var secs []quicSecret
				for _, label := range []string{"CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0"} {
					if v := keylogSecret(random, label); len(v) > 0 {
						secs = append(secs, quicSecret{label, v})
					}
				}
				if !c.noFields && c.quicDecryptWithSecrets(b, base, root, flow, 1+dcidLen, len(b), first, false, secs) {
					info += " decrypted"
				}
			}
		}
	}

	c.addRoot(root)
	c.appInfo = shorten(info, 120)
	return true
}

func init() {
	RegisterPlugin(pluginSpec{Name: "quic", Priority: 140, Transport: TransportUDP,
		Match: func(_ *ctx, sport, dport uint16, b []byte) bool {
			return (sport == 443 || dport == 443) && looksLikeQUIC(b)
		}, Dissect: func(c *ctx, b []byte, base int) bool { return c.dissectQUIC(b, base) }, Display: "QUIC"})
}
