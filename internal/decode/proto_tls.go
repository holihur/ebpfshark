package decode

import (
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"strings"
	"sync"
)

// ---------------------------------------------------------------------- TLS

func looksLikeTLS(b []byte) bool {
	if len(b) < 5 {
		return false
	}
	if b[0] < 20 || b[0] > 24 {
		return false
	}
	if b[1] != 3 || b[2] > 4 {
		return false
	}
	l := int(be16(b[3:5]))
	return l > 0 && l <= 16384+2048
}

func tlsVersionName(v uint16) string {
	switch v {
	case 0x0300:
		return "SSL 3.0"
	case 0x0301:
		return "TLS 1.0"
	case 0x0302:
		return "TLS 1.1"
	case 0x0303:
		return "TLS 1.2"
	case 0x0304:
		return "TLS 1.3"
	}
	return fmt.Sprintf("0x%04x", v)
}

func tlsContentTypeName(t uint8) string {
	switch t {
	case 20:
		return "Change Cipher Spec"
	case 21:
		return "Alert"
	case 22:
		return "Handshake"
	case 23:
		return "Application Data"
	case 24:
		return "Heartbeat"
	}
	return fmt.Sprintf("Content Type %d", t)
}

func tlsHandshakeName(t uint8) string {
	switch t {
	case 0:
		return "Hello Request"
	case 1:
		return "Client Hello"
	case 2:
		return "Server Hello"
	case 4:
		return "New Session Ticket"
	case 8:
		return "Encrypted Extensions"
	case 11:
		return "Certificate"
	case 12:
		return "Server Key Exchange"
	case 13:
		return "Certificate Request"
	case 14:
		return "Server Hello Done"
	case 15:
		return "Certificate Verify"
	case 16:
		return "Client Key Exchange"
	case 20:
		return "Finished"
	}
	return fmt.Sprintf("Handshake Type %d", t)
}

func (c *ctx) dissectTLS(b []byte, base int) bool {
	if len(b) < 5 {
		return false
	}
	ct := b[0]
	ver := be16(b[1:3])
	recLen := int(be16(b[3:5]))
	if recLen == 0 || 5+recLen > len(b) {
		recLen = len(b) - 5
	}
	flow := tlsFlowFor(c)
	c.addLayer("tls")
	c.proto = "tls"

	root := c.newNode(fmt.Sprintf("Transport Layer Security (%s)", tlsContentTypeName(ct)), base, 5+recLen)
	root.add(
		c.newField(fmt.Sprintf("Content Type: %s (%d)", tlsContentTypeName(ct), ct), "", base, 1),
		c.newField(fmt.Sprintf("Version: %s (0x%04x)", tlsVersionName(ver), ver), "", base+1, 2),
		c.newField(fmt.Sprintf("Length: %d", recLen), "", base+3, 2),
	)

	body := b[5 : 5+recLen]
	c.m.Payload = body
	c.appInfo = tlsContentTypeName(ct)

	if ct == 22 && len(body) >= 4 {
		off := 0
		sawHS := false
		firstHT := byte(0)
		for off+4 <= len(body) {
			ht := body[off]
			hl := int(body[off+1])<<16 | int(body[off+2])<<8 | int(body[off+3])
			end := off + 4 + hl
			if end > len(body) {
				end = len(body)
			}
			if !sawHS {
				sawHS, firstHT = true, ht
			}
			c.parseTLSHandshakeMessage(ht, body[off+4:end], base+5+off+4, root, flow)
			off = end
		}
		if sawHS {
			c.appInfo = tlsHandshakeName(firstHT)
			if c.m.TLSSNI != "" {
				c.appInfo += " (SNI=" + c.m.TLSSNI + ")"
			}
		}
	} else if ct == 23 {
		root.add(c.newField(fmt.Sprintf("Encrypted Application Data (%d bytes)", len(body)), hexPreview(body, 32), base+5, len(body)))
		if c.noFields {
			// Summary mode only needs the record metadata; decryption is
			// deferred until the packet detail is opened.
			c.appInfo = fmt.Sprintf("Application Data (%d bytes)", len(body))
			c.addRoot(root)
			return true
		}
		if pt, inner, label, ok := flow.decryptRecord(c, b[:5], body); ok {
			dn := c.newNode(fmt.Sprintf("Decrypted TLS Record (%s)", tlsContentTypeName(inner)), base+5, recLen)
			dn.add(c.newField("Key Log Label: "+label, "", 0, 0))
			dn.add(c.newField(fmt.Sprintf("Inner Content Type: %s (%d)", tlsContentTypeName(inner), inner), "", 0, 0))
			switch inner {
			case 22:
				off := 0
				for off+4 <= len(pt) {
					ht := pt[off]
					hl := int(pt[off+1])<<16 | int(pt[off+2])<<8 | int(pt[off+3])
					end := off + 4 + hl
					if end > len(pt) {
						end = len(pt)
					}
					c.parseTLSHandshakeMessage(ht, pt[off+4:end], base+5, dn, flow)
					off = end
				}
			case 23:
				dn.add(c.newField(fmt.Sprintf("Decrypted Application Data (%d bytes)", len(pt)), printablePreview(pt, 300), 0, len(pt)))
				c.m.Payload = pt
				c.dissectDecryptedApp(pt, base+5)
				c.appInfo = fmt.Sprintf("Decrypted Application Data (%d bytes)", len(pt))
			case 21:
				if len(pt) >= 2 {
					dn.add(c.newField(fmt.Sprintf("Alert Level: %d, Description: %d", pt[0], pt[1]), "", 0, 2))
				}
			}
			root.add(dn)
		}
	} else if ct == 21 && len(body) >= 2 {
		root.add(c.newField(fmt.Sprintf("Alert Level: %d, Description: %d", body[0], body[1]), "", base+5, 2))
		c.appInfo = fmt.Sprintf("Alert (level %d, description %d)", body[0], body[1])
	}

	c.addRoot(root)
	return true
}

func (c *ctx) parseTLSHandshakeMessage(ht byte, b []byte, base int, root *Field, flow *tlsFlow) {
	hl := len(b)
	hsNode := c.newNode(fmt.Sprintf("%s (length %d)", tlsHandshakeName(ht), hl), base-4, min(hl+4, len(b)+4))
	switch ht {
	case 1:
		c.parseClientHello(b, base, hsNode, flow)
	case 2:
		c.parseServerHello(b, base, hsNode, flow)
	case 11:
		c.parseTLSCertificates(b, base, hsNode, flow)
	case 8:
		c.parseTLSExtensionsMessage(b, base, hsNode, flow, false)
	case 4: // NewSessionTicket
		if len(b) >= 4 {
			hsNode.add(c.newField(fmt.Sprintf("Ticket Lifetime: %d s", be32(b[0:4])), "", base, 4))
			if len(b) >= 8 {
				hsNode.add(c.newField(fmt.Sprintf("Ticket Age Add: %d", be32(b[4:8])), "", base+4, 4))
			}
		}
	case 15: // CertificateVerify
		if len(b) >= 4 {
			hsNode.add(c.newField(fmt.Sprintf("Signature Algorithm: 0x%04x", be16(b[0:2])), "", base, 2))
			if len(b) > 4 {
				hsNode.add(c.newField("Signature: "+hexPreview(b[4:], 64), "", base+4, len(b)-4))
			}
		}
	}
	root.add(hsNode)
}

func (c *ctx) parseTLSExtensionsMessage(b []byte, base int, node *Field, flow *tlsFlow, server bool) {
	if len(b) < 2 {
		return
	}
	l := int(be16(b[0:2]))
	if 2+l > len(b) {
		l = len(b) - 2
	}
	node.add(c.newField(fmt.Sprintf("Extensions Length: %d", l), "", base, 2))
	c.parseTLSExtensions(b[2:2+l], base+2, node, flow, server)
}

func tlsCipherName(s uint16) string {
	names := map[uint16]string{
		0x1301: "TLS_AES_128_GCM_SHA256", 0x1302: "TLS_AES_256_GCM_SHA384",
		0x1303: "TLS_CHACHA20_POLY1305_SHA256", 0x1304: "TLS_AES_128_CCM_SHA256",
		0x1305: "TLS_AES_128_CCM_8_SHA256", 0xc02b: "TLS_ECDHE_ECDSA_AES128_GCM_SHA256",
		0xc02c: "TLS_ECDHE_ECDSA_AES256_GCM_SHA384", 0xc02f: "TLS_ECDHE_RSA_AES128_GCM_SHA256",
		0xc030: "TLS_ECDHE_RSA_AES256_GCM_SHA384", 0x009c: "TLS_RSA_AES128_GCM_SHA256",
		0x009d: "TLS_RSA_AES256_GCM_SHA384", 0xcca8: "TLS_ECDHE_RSA_CHACHA20_POLY1305",
		0xcca9: "TLS_ECDHE_ECDSA_CHACHA20_POLY1305",
	}
	if n := names[s]; n != "" {
		return n
	}
	return fmt.Sprintf("0x%04x", s)
}

func (c *ctx) parseClientHello(b []byte, base int, node *Field, flow *tlsFlow) {
	if len(b) < 34 {
		return
	}
	ver := be16(b[0:2])
	random := b[2:34]
	node.add(
		c.newField(fmt.Sprintf("Version: %s (0x%04x)", tlsVersionName(ver), ver), "", base, 2),
		c.newField("Random: "+hexPreview(random, 32), "", base+2, 32),
	)
	flow.observeClientHello(c, random)

	off := 34
	if off >= len(b) {
		return
	}
	sidLen := int(b[off])
	if off+1+sidLen > len(b) {
		return
	}
	node.add(c.newField(fmt.Sprintf("Session ID (%d bytes): %s", sidLen, hexPreview(b[off+1:off+1+sidLen], 24)), "", base+off, 1+sidLen))
	off += 1 + sidLen
	if off+2 > len(b) {
		return
	}
	csLen := int(be16(b[off : off+2]))
	csEnd := off + 2 + csLen
	if csEnd > len(b) {
		csEnd = len(b)
	}
	var suites []string
	for q := off + 2; q+2 <= csEnd; q += 2 {
		suites = append(suites, tlsCipherName(be16(b[q:q+2])))
	}
	node.add(c.newField(fmt.Sprintf("Cipher Suites (%d): %s", len(suites), strings.Join(suites, ", ")), "", base+off, 2+csLen))
	off = csEnd
	if off >= len(b) {
		return
	}
	compLen := int(b[off])
	node.add(c.newField(fmt.Sprintf("Compression Methods: %d", compLen), "", base+off, 1+compLen))
	off += 1 + compLen
	if off+2 > len(b) {
		return
	}
	extTotal := int(be16(b[off : off+2]))
	off += 2
	end := off + extTotal
	if end > len(b) {
		end = len(b)
	}
	if end > off {
		node.add(c.newField(fmt.Sprintf("Extensions (%d bytes)", extTotal), "", base+off-2, 2+end-off))
		c.parseTLSExtensions(b[off:end], base+off, node, flow, false)
	}
}

func (c *ctx) parseServerHello(b []byte, base int, node *Field, flow *tlsFlow) {
	if len(b) < 38 {
		return
	}
	legacy := be16(b[0:2])
	random := b[2:34]
	node.add(
		c.newField(fmt.Sprintf("Legacy Version: %s (0x%04x)", tlsVersionName(legacy), legacy), "", base, 2),
		c.newField("Random: "+hexPreview(random, 32), "", base+2, 32),
	)
	off := 34
	sidLen := int(b[off])
	if off+1+sidLen+3 > len(b) {
		return
	}
	node.add(c.newField(fmt.Sprintf("Session ID (%d bytes): %s", sidLen, hexPreview(b[off+1:off+1+sidLen], 24)), "", base+off, 1+sidLen))
	off += 1 + sidLen
	suite := be16(b[off : off+2])
	node.add(c.newField(fmt.Sprintf("Cipher Suite: %s (0x%04x)", tlsCipherName(suite), suite), "", base+off, 2))
	off += 2
	node.add(c.newField(fmt.Sprintf("Compression Method: %d", b[off]), "", base+off, 1))
	off++
	version := legacy
	if off+2 <= len(b) {
		extTotal := int(be16(b[off : off+2]))
		off += 2
		end := off + extTotal
		if end > len(b) {
			end = len(b)
		}
		if end > off {
			// supported_versions is parsed below and updates the actual version.
			c.parseTLSExtensions(b[off:end], base+off, node, flow, true)
			if v := flow.getVersion(); v != 0 {
				version = v
			}
		}
	}
	node.add(c.newField(fmt.Sprintf("Negotiated Version: %s", tlsVersionName(version)), "", base, 0))
	flow.observeServerHello(c, random, version, suite)
}

var tlsCertCache = struct {
	sync.Mutex
	m map[[32]byte]*x509.Certificate
}{m: make(map[[32]byte]*x509.Certificate)}

func tlsParseCert(der []byte) (*x509.Certificate, error) {
	key := sha256.Sum256(der)
	tlsCertCache.Lock()
	cert, ok := tlsCertCache.m[key]
	tlsCertCache.Unlock()
	if ok {
		return cert, nil
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	tlsCertCache.Lock()
	if len(tlsCertCache.m) >= 512 {
		for k := range tlsCertCache.m {
			delete(tlsCertCache.m, k)
			break
		}
	}
	tlsCertCache.m[key] = cert
	tlsCertCache.Unlock()
	return cert, nil
}

func (c *ctx) parseTLSCertificates(b []byte, base int, node *Field, flow *tlsFlow) {
	if c.noFields {
		return
	}
	off := 0
	tlsVer := flow.getVersion()
	if tlsVer == 0x0304 {
		if len(b) < 1 {
			return
		}
		ctxLen := int(b[0])
		off = 1 + ctxLen
		if off+3 > len(b) {
			return
		}
		node.add(c.newField(fmt.Sprintf("Certificate Request Context (%d bytes)", ctxLen), hexPreview(b[1:1+ctxLen], 24), base, 1+ctxLen))
	}
	if off+3 > len(b) {
		return
	}
	listLen := int(b[off])<<16 | int(b[off+1])<<8 | int(b[off+2])
	off += 3
	end := off + listLen
	if end > len(b) {
		end = len(b)
	}
	node.add(c.newField(fmt.Sprintf("Certificate List Length: %d", listLen), "", base+off-3, 3))
	idx := 0
	for off+3 <= end {
		clen := int(b[off])<<16 | int(b[off+1])<<8 | int(b[off+2])
		off += 3
		if off+clen > end {
			break
		}
		der := b[off : off+clen]
		cf := c.newNode(fmt.Sprintf("Certificate %d (%d bytes)", idx+1, clen), base+off, clen)
		if cert, err := tlsParseCert(der); err == nil {
			cf.add(
				c.newField("Subject: "+cert.Subject.String(), "", 0, 0),
				c.newField("Issuer: "+cert.Issuer.String(), "", 0, 0),
				c.newField("Serial Number: "+cert.SerialNumber.String(), "", 0, 0),
				c.newField("Not Before: "+cert.NotBefore.UTC().Format("2006-01-02 15:04:05 MST"), "", 0, 0),
				c.newField("Not After: "+cert.NotAfter.UTC().Format("2006-01-02 15:04:05 MST"), "", 0, 0),
				c.newField("Signature Algorithm: "+cert.SignatureAlgorithm.String(), "", 0, 0),
				c.newField("Public Key Algorithm: "+cert.PublicKeyAlgorithm.String(), "", 0, 0),
			)
			if len(cert.DNSNames) > 0 {
				cf.add(c.newField("DNS Names: "+strings.Join(cert.DNSNames, ", "), "", 0, 0))
				if c.m.TLSSNI == "" {
					c.m.TLSSNI = cert.DNSNames[0]
				}
			}
			if len(cert.IPAddresses) > 0 {
				var ips []string
				for _, ip := range cert.IPAddresses {
					ips = append(ips, ip.String())
				}
				cf.add(c.newField("IP Addresses: "+strings.Join(ips, ", "), "", 0, 0))
			}
		} else {
			cf.add(c.newField("DER: "+hexPreview(der, 64), "", 0, 0), c.newField("Parse Error: "+err.Error(), "", 0, 0))
		}
		node.add(cf)
		off += clen
		idx++
		// TLS 1.3 per-certificate extensions.
		if tlsVer == 0x0304 && off+2 <= end {
			el := int(be16(b[off : off+2]))
			off += 2 + el
		}
	}
}

func (c *ctx) parseTLSExtensions(data []byte, base int, node *Field, flow *tlsFlow, server bool) {
	for off := 0; off+4 <= len(data); {
		etype := be16(data[off : off+2])
		elen := int(be16(data[off+2 : off+4]))
		if off+4+elen > len(data) {
			break
		}
		edata := data[off+4 : off+4+elen]
		name := tlsExtensionName(etype)
		f := c.newField(fmt.Sprintf("%s (%d bytes)", name, elen), "", base+off, 4+elen)
		switch etype {
		case 0: // server_name
			if len(edata) >= 5 {
				listLen := int(be16(edata[0:2]))
				p := 2
				for p+3 <= len(edata) && p < 2+listLen {
					ntype := edata[p]
					nlen := int(be16(edata[p+1 : p+3]))
					if p+3+nlen > len(edata) {
						break
					}
					if ntype == 0 {
						sni := string(edata[p+3 : p+3+nlen])
						c.m.TLSSNI = sni
						f.add(c.newField("Server Name: "+sni, "", base+off+4+p+3, nlen))
					}
					p += 3 + nlen
				}
			}
		case 16: // ALPN
			if len(edata) >= 2 {
				listLen := int(be16(edata[0:2]))
				p := 2
				for p < len(edata) && p < 2+listLen {
					l := int(edata[p])
					p++
					if p+l > len(edata) {
						break
					}
					proto := string(edata[p : p+l])
					f.add(c.newField("ALPN Protocol: "+proto, "", base+off+4+p, l))
					p += l
				}
			}
		case 10: // supported_groups
			if len(edata) >= 2 {
				l := int(be16(edata[0:2]))
				var groups []string
				for q := 2; q+2 <= len(edata) && q < 2+l; q += 2 {
					groups = append(groups, tlsGroupName(be16(edata[q:q+2])))
				}
				f.add(c.newField("Supported Groups: "+strings.Join(groups, ", "), "", base+off+4, len(edata)))
			}
		case 13: // signature_algorithms
			if len(edata) >= 2 {
				l := int(be16(edata[0:2]))
				var algs []string
				for q := 2; q+2 <= len(edata) && q < 2+l; q += 2 {
					algs = append(algs, fmt.Sprintf("0x%04x", be16(edata[q:q+2])))
				}
				f.add(c.newField("Signature Algorithms: "+strings.Join(algs, ", "), "", base+off+4, len(edata)))
			}
		case 43: // supported_versions
			if server {
				if len(edata) >= 2 {
					v := be16(edata[0:2])
					flow.setVersion(v)
					f.add(c.newField("Selected Version: "+tlsVersionName(v), "", base+off+4, 2))
				}
			} else if len(edata) >= 1 {
				l := int(edata[0])
				var vs []string
				for q := 1; q+2 <= len(edata) && q < 1+l; q += 2 {
					vs = append(vs, tlsVersionName(be16(edata[q:q+2])))
				}
				f.add(c.newField("Supported Versions: "+strings.Join(vs, ", "), "", base+off+4, len(edata)))
			}
		case 51: // key_share
			if server {
				if len(edata) >= 4 {
					g := be16(edata[0:2])
					l := int(be16(edata[2:4]))
					if 4+l <= len(edata) {
						f.add(c.newField("Selected Group: "+tlsGroupName(g), "", base+off+4, 2), c.newField("Key Exchange: "+hexPreview(edata[4:4+l], 48), "", base+off+6, l))
					}
				}
			} else if len(edata) >= 2 {
				listLen := int(be16(edata[0:2]))
				p := 2
				for p+4 <= len(edata) && p < 2+listLen {
					g := be16(edata[p : p+2])
					l := int(be16(edata[p+2 : p+4]))
					if p+4+l > len(edata) {
						break
					}
					f.add(c.newField("Key Share "+tlsGroupName(g)+": "+hexPreview(edata[p+4:p+4+l], 48), "", base+off+4+p, 4+l))
					p += 4 + l
				}
			}
		default:
			if elen > 0 {
				f.Value = hexPreview(edata, 32)
			}
		}
		node.add(f)
		off += 4 + elen
	}
}

func tlsExtensionName(t uint16) string {
	switch t {
	case 0:
		return "server_name"
	case 5:
		return "status_request"
	case 10:
		return "supported_groups"
	case 11:
		return "ec_point_formats"
	case 13:
		return "signature_algorithms"
	case 16:
		return "application_layer_protocol_negotiation"
	case 18:
		return "signed_certificate_timestamp"
	case 21:
		return "padding"
	case 23:
		return "extended_master_secret"
	case 27:
		return "compress_certificate"
	case 35:
		return "session_ticket"
	case 41:
		return "pre_shared_key"
	case 43:
		return "supported_versions"
	case 45:
		return "psk_key_exchange_modes"
	case 51:
		return "key_share"
	}
	return fmt.Sprintf("extension %d", t)
}

func tlsGroupName(g uint16) string {
	switch g {
	case 23:
		return "secp256r1"
	case 24:
		return "secp384r1"
	case 25:
		return "secp521r1"
	case 29:
		return "x25519"
	case 256:
		return "ffdhe2048"
	case 257:
		return "ffdhe3072"
	}
	return fmt.Sprintf("0x%04x", g)
}

func init() {
	RegisterPlugin(pluginSpec{Name: "tls", Priority: 40, Transport: TransportTCP,
		Match: func(_ *ctx, sport, dport uint16, b []byte) bool {
			return tlsPorts[sport] || tlsPorts[dport] || looksLikeTLS(b)
		}, Dissect: func(c *ctx, b []byte, base int) bool { return c.dissectTLS(b, base) }})
}
