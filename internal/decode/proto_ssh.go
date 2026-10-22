//go:build full

package decode

import (
	"bytes"
	"fmt"
	"strings"
)

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

func sshAddStrings(c *ctx, f *Field, b []byte, off int, labels []string) {
	for _, label := range labels {
		v, n, ok := sshNameList(b, off)
		if !ok {
			return
		}
		f.add(c.newField(label+": "+v, "", 0, 0))
		off = n
	}
}

func (c *ctx) dissectSSH(b []byte, base int) bool {
	sshFlow := sshFlowFor(c)
	if plain, ok := sshFlow.decryptPacket(c, b); ok {
		b = plain
	}
	if bytes.HasPrefix(b, []byte("SSH-")) {
		line, _, ok := bytes.Cut(b, []byte("\n"))
		if !ok {
			line = b
		}
		ident := strings.TrimRight(string(line), "\r")
		parts := strings.SplitN(ident, "-", 3)
		c.addLayer("ssh")
		c.proto = "ssh"
		root := c.newNode("SSH Protocol", base, len(b))
		fields := []*Field{c.newField("Identification: "+ident, "", base, len(line))}
		if len(parts) >= 2 {
			fields = append(fields, c.newField("Protocol Version: SSH-"+parts[1], "", base, 0))
		}
		if len(parts) >= 3 {
			fields = append(fields, c.newField("Software Version: "+parts[2], "", base, 0))
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
	root := c.newNode("SSH Protocol ("+name+")", base, 4+pktLen)
	root.add(
		c.newField(fmt.Sprintf("Packet Length: %d", pktLen), "", base, 4),
		c.newField(fmt.Sprintf("Padding Length: %d", padding), "", base+4, 1),
		c.newField(fmt.Sprintf("Message: %s (%d)", name, code), "", base+5, 1),
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
			root.add(c.newField(fmt.Sprintf("Reason Code: %d", reason), "", 0, 0), c.newField("Description: "+desc, "", 0, 0), c.newField("Language: "+lang, "", 0, 0))
			info += " " + desc
		}
	case 2, 4: // IGNORE / DEBUG
		if code == 4 {
			always, n, ok := sshString(payload, p)
			if ok {
				root.add(c.newField("Always Display: "+always, "", 0, 0))
				p = n
			}
		}
		msg, _, _ := sshString(payload, p)
		root.add(c.newField("Message: "+shorten(msg, 160), "", 0, 0))
	case 3: // UNIMPLEMENTED
		if p+4 <= len(payload) {
			root.add(c.newField(fmt.Sprintf("Sequence Number: %d", be32(payload[p:p+4])), "", 0, 0))
		}
	case 5, 6: // SERVICE_REQUEST / SERVICE_ACCEPT
		svc, _, ok := sshString(payload, p)
		if ok {
			root.add(c.newField("Service: "+svc, "", 0, 0))
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
				root.add(c.newField(k+": "+v, "", 0, 0))
			}
		}
	case 20: // KEXINIT
		if len(payload) >= 17 {
			root.add(c.newField("Cookie: "+hexPreview(payload[1:17], 16), "", base+6, 16))
			p = 17
			sshAddStrings(c, root, payload, p, []string{
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
				root.add(c.newField(fmt.Sprintf("First KEX Packet Follows: %d", payload[q]), "", 0, 0))
				q++
				if q+4 <= len(payload) {
					root.add(c.newField(fmt.Sprintf("Reserved: %d", be32(payload[q:q+4])), "", 0, 0))
				}
			}
			info += " KEX"
		}
	case 30: // KEXDH_INIT / KEX_ECDH_INIT
		if v, _, ok := sshString(payload, p); ok {
			root.add(c.newField("Client Ephemeral Public Key: "+hexPreview([]byte(v), 64), "", 0, 0))
		}
	case 31, 33: // KEXDH_REPLY / GEX_REPLY / ECDH_REPLY
		if code == 31 && p+12 <= len(payload) {
			min := be32(payload[p : p+4])
			pref := be32(payload[p+4 : p+8])
			max := be32(payload[p+8 : p+12])
			if min >= 1024 && min <= pref && pref <= max {
				root.add(c.newField(fmt.Sprintf("Min Group Size: %d", min), "", 0, 0), c.newField(fmt.Sprintf("Preferred Group Size: %d", pref), "", 0, 0), c.newField(fmt.Sprintf("Max Group Size: %d", max), "", 0, 0))
				p += 12
				if v, _, ok := sshString(payload, p); ok {
					root.add(c.newField("Prime: "+hexPreview([]byte(v), 64), "", 0, 0))
				}
				break
			}
		}
		hostKey, n, ok := sshString(payload, p)
		if ok {
			root.add(c.newField("Server Host Key: "+hexPreview([]byte(hostKey), 64), "", 0, 0))
			p = n
			if f, n2, ok := sshString(payload, p); ok {
				root.add(c.newField("Server Ephemeral Public Key: "+hexPreview([]byte(f), 64), "", 0, 0))
				p = n2
			}
			if sig, _, ok := sshString(payload, p); ok {
				root.add(c.newField("Signature: "+hexPreview([]byte(sig), 64), "", 0, 0))
			}
		}
	case 32: // GEX_REQUEST_OLD
		if p+4 <= len(payload) {
			root.add(c.newField(fmt.Sprintf("Preferred Group Size: %d", be32(payload[p:p+4])), "", 0, 0))
		}
	case 34: // GEX_INIT / GEX_REPLY handled above
		if v, _, ok := sshString(payload, p); ok {
			root.add(c.newField("Client Ephemeral Public Key: "+hexPreview([]byte(v), 64), "", 0, 0))
		}
	case 36: // GEX_REQUEST
		if p+12 <= len(payload) {
			root.add(c.newField(fmt.Sprintf("Min Group Size: %d", be32(payload[p:p+4])), "", 0, 0), c.newField(fmt.Sprintf("Preferred Group Size: %d", be32(payload[p+4:p+8])), "", 0, 0), c.newField(fmt.Sprintf("Max Group Size: %d", be32(payload[p+8:p+12])), "", 0, 0))
		}
	case 50: // USERAUTH_REQUEST
		user, n, ok := sshString(payload, p)
		if ok {
			root.add(c.newField("User Name: "+user, "", 0, 0))
			p = n
			svc, n2, ok := sshString(payload, p)
			if ok {
				root.add(c.newField("Service: "+svc, "", 0, 0))
				p = n2
				method, n3, ok := sshString(payload, p)
				if ok {
					root.add(c.newField("Method: "+method, "", 0, 0))
					p = n3
					info = fmt.Sprintf("SSH USERAUTH_REQUEST user=%s method=%s", user, method)
					switch method {
					case "password":
						if p < len(payload) {
							root.add(c.newField(fmt.Sprintf("Change Password: %d", payload[p]), "", 0, 0))
							p++
							if pw, _, ok := sshString(payload, p); ok {
								root.add(c.newField("Password: "+shorten(pw, 32), "", 0, 0))
							}
						}
					case "publickey":
						if p < len(payload) {
							root.add(c.newField(fmt.Sprintf("Has Signature: %d", payload[p]), "", 0, 0))
							p++
						}
						if alg, _, ok := sshString(payload, p); ok {
							root.add(c.newField("Public Key Algorithm: "+alg, "", 0, 0))
						}
					}
				}
			}
		}
	case 51: // USERAUTH_FAILURE
		if list, n, ok := sshNameList(payload, p); ok {
			root.add(c.newField("Authentications That Can Continue: "+list, "", 0, 0))
			p = n
			if p < len(payload) {
				root.add(c.newField(fmt.Sprintf("Partial Success: %d", payload[p]), "", 0, 0))
			}
		}
	case 52:
		info = "SSH USERAUTH_SUCCESS"
	case 53: // BANNER
		if msg, n, ok := sshString(payload, p); ok {
			root.add(c.newField("Message: "+shorten(msg, 160), "", 0, 0))
			p = n
			if lang, _, ok := sshString(payload, p); ok {
				root.add(c.newField("Language: "+lang, "", 0, 0))
			}
		}
	case 60: // PK_OK
		if alg, n, ok := sshString(payload, p); ok {
			root.add(c.newField("Public Key Algorithm: "+alg, "", 0, 0))
			p = n
			if blob, _, ok := sshString(payload, p); ok {
				root.add(c.newField("Public Key: "+hexPreview([]byte(blob), 48), "", 0, 0))
			}
		}
	case 80: // GLOBAL_REQUEST
		if req, n, ok := sshString(payload, p); ok {
			root.add(c.newField("Request Name: "+req, "", 0, 0))
			p = n
			if p < len(payload) {
				root.add(c.newField(fmt.Sprintf("Want Reply: %d", payload[p]), "", 0, 0))
				p++
			}
			if p < len(payload) {
				root.add(c.newField("Request Data: "+hexPreview(payload[p:], 64), "", 0, 0))
			}
			info += " " + req
		}
	case 81, 82:
		if len(payload) > 1 {
			root.add(c.newField("Response Data: "+hexPreview(payload[1:], 64), "", 0, 0))
		}
	case 90: // CHANNEL_OPEN
		if typ, n, ok := sshString(payload, p); ok {
			root.add(c.newField("Channel Type: "+typ, "", 0, 0))
			p = n
			if p+12 <= len(payload) {
				root.add(c.newField(fmt.Sprintf("Sender Channel: %d", be32(payload[p:p+4])), "", 0, 0), c.newField(fmt.Sprintf("Initial Window Size: %d", be32(payload[p+4:p+8])), "", 0, 0), c.newField(fmt.Sprintf("Maximum Packet Size: %d", be32(payload[p+8:p+12])), "", 0, 0))
			}
			info += " " + typ
		}
	case 91: // OPEN_CONFIRMATION
		if p+16 <= len(payload) {
			root.add(c.newField(fmt.Sprintf("Recipient Channel: %d", be32(payload[p:p+4])), "", 0, 0), c.newField(fmt.Sprintf("Sender Channel: %d", be32(payload[p+4:p+8])), "", 0, 0), c.newField(fmt.Sprintf("Initial Window Size: %d", be32(payload[p+8:p+12])), "", 0, 0), c.newField(fmt.Sprintf("Maximum Packet Size: %d", be32(payload[p+12:p+16])), "", 0, 0))
		}
	case 92: // OPEN_FAILURE
		if p+4 <= len(payload) {
			root.add(c.newField(fmt.Sprintf("Recipient Channel: %d", be32(payload[p:p+4])), "", 0, 0))
			p += 4
			if p+4 <= len(payload) {
				root.add(c.newField(fmt.Sprintf("Reason Code: %d", be32(payload[p:p+4])), "", 0, 0))
				p += 4
				if desc, n, ok := sshString(payload, p); ok {
					root.add(c.newField("Description: "+desc, "", 0, 0))
					p = n
					if lang, _, ok := sshString(payload, p); ok {
						root.add(c.newField("Language: "+lang, "", 0, 0))
					}
				}
			}
		}
	case 93: // WINDOW_ADJUST
		if p+8 <= len(payload) {
			root.add(c.newField(fmt.Sprintf("Recipient Channel: %d", be32(payload[p:p+4])), "", 0, 0), c.newField(fmt.Sprintf("Bytes to Add: %d", be32(payload[p+4:p+8])), "", 0, 0))
		}
	case 94: // DATA
		if p+4 <= len(payload) {
			root.add(c.newField(fmt.Sprintf("Recipient Channel: %d", be32(payload[p:p+4])), "", 0, 0))
			p += 4
			if data, _, ok := sshString(payload, p); ok {
				root.add(c.newField(fmt.Sprintf("Data (%d bytes): %s", len(data), hexPreview([]byte(data), 64)), "", 0, 0))
			}
		}
	case 95: // EXTENDED_DATA
		if p+8 <= len(payload) {
			root.add(c.newField(fmt.Sprintf("Recipient Channel: %d", be32(payload[p:p+4])), "", 0, 0), c.newField(fmt.Sprintf("Data Type Code: %d", be32(payload[p+4:p+8])), "", 0, 0))
			p += 8
			if data, _, ok := sshString(payload, p); ok {
				root.add(c.newField(fmt.Sprintf("Data (%d bytes): %s", len(data), hexPreview([]byte(data), 64)), "", 0, 0))
			}
		}
	case 96, 97, 98:
		if code == 98 {
			if p+4 <= len(payload) {
				root.add(c.newField(fmt.Sprintf("Recipient Channel: %d", be32(payload[p:p+4])), "", 0, 0))
				p += 4
				if req, n, ok := sshString(payload, p); ok {
					root.add(c.newField("Request Type: "+req, "", 0, 0))
					p = n
					if p < len(payload) {
						root.add(c.newField(fmt.Sprintf("Want Reply: %d", payload[p]), "", 0, 0))
						p++
					}
					if p < len(payload) {
						root.add(c.newField("Request Data: "+hexPreview(payload[p:], 64), "", 0, 0))
					}
				}
			}
		} else if p+4 <= len(payload) {
			root.add(c.newField(fmt.Sprintf("Recipient Channel: %d", be32(payload[p:p+4])), "", 0, 0))
		}
	}
	if name == fmt.Sprintf("Unknown/Encrypted Message %d", code) {
		root.add(c.newField("Payload: "+hexPreview(payload, 96), "", base+5, len(payload)))
		info = "SSH encrypted/unknown payload"
	}
	c.addRoot(root)
	if code == 21 {
		sshFlow.markNewKeys(c)
	}
	c.appInfo = shorten(info, 140)
	return true
}

func init() {
	RegisterPlugin(pluginSpec{Name: "ssh", Priority: 30, Transport: TransportTCP,
		Match:   func(_ *ctx, _, _ uint16, b []byte) bool { return looksLikeSSHBanner(b) },
		Dissect: func(c *ctx, b []byte, base int) bool { return c.dissectSSH(b, base) }})
	RegisterPlugin(pluginSpec{Name: "ssh-port", Priority: 90, Transport: TransportTCP,
		Match: portMatch(map[uint16]bool{22: true}), Dissect: func(c *ctx, b []byte, base int) bool { return c.dissectSSH(b, base) }, Display: "SSH"})
}
