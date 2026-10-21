//go:build full

package decode

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
)

func hkdfExtract(salt, ikm []byte) []byte {
	h := hmac.New(sha256.New, salt)
	h.Write(ikm)
	return h.Sum(nil)
}

func quicExpandLabel(secret []byte, label string, n int) []byte {
	info := make([]byte, 0, 4+len(label))
	info = append(info, byte(n>>8), byte(n))
	info = append(info, []byte("quic "+label)...)
	info = append(info, 0)
	return hkdfExpand(secret, info, n)
}

func quicInitialSecrets(dcid []byte, version uint32) (client, server []byte, ok bool) {
	var salt []byte
	switch version {
	case 0x00000001:
		salt = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
	case 0x6b3343cf:
		salt = []byte{0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9}
	default:
		return nil, nil, false
	}
	initial := hkdfExtract(salt, dcid)
	return quicExpandLabel(initial, "client in", 32), quicExpandLabel(initial, "server in", 32), true
}

func quicPacketKeys(secret []byte) (key, iv, hp []byte, ok bool) {
	if len(secret) < 32 {
		return nil, nil, nil, false
	}
	return quicExpandLabel(secret, "key", 16), quicExpandLabel(secret, "iv", 12), quicExpandLabel(secret, "hp", 16), true
}

func quicNonce(iv []byte, pn uint64) []byte {
	n := append([]byte(nil), iv...)
	for i := 0; i < 8; i++ {
		n[len(n)-1-i] ^= byte(pn >> (8 * i))
	}
	return n
}

func quicOpen(secret []byte, header, ciphertext []byte, pn uint64) ([]byte, bool) {
	key, iv, _, ok := quicPacketKeys(secret)
	if !ok {
		return nil, false
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, false
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, false
	}
	pt, err := aead.Open(nil, quicNonce(iv, pn), ciphertext, header)
	return pt, err == nil
}

func quicUnprotect(hpKey []byte, first byte, pnBytes []byte, sample []byte, long bool) (byte, []byte, bool) {
	if len(hpKey) != 16 || len(sample) < 16 {
		return 0, nil, false
	}
	block, err := aes.NewCipher(hpKey)
	if err != nil {
		return 0, nil, false
	}
	mask := make([]byte, 16)
	block.Encrypt(mask, sample[:16])
	f := first
	if long {
		f ^= mask[0] & 0x0f
	} else {
		f ^= mask[0] & 0x1f
	}
	pn := append([]byte(nil), pnBytes...)
	for i := range pn {
		pn[i] ^= mask[1+i]
	}
	return f, pn, true
}

func quicPacketNumber(b []byte) uint64 {
	var v uint64
	for _, x := range b {
		v = v<<8 | uint64(x)
	}
	return v
}

func quicFrameName(t uint64) string {
	switch t {
	case 0:
		return "PADDING"
	case 1:
		return "PING"
	case 2, 3:
		return "ACK"
	case 4:
		return "RESET_STREAM"
	case 5:
		return "STOP_SENDING"
	case 6:
		return "CRYPTO"
	case 7:
		return "NEW_TOKEN"
	case 8, 9, 10, 11, 12, 13, 14, 15:
		return "STREAM"
	case 16:
		return "MAX_DATA"
	case 17:
		return "MAX_STREAM_DATA"
	case 18:
		return "MAX_STREAMS"
	case 19:
		return "MAX_STREAMS"
	case 20:
		return "DATA_BLOCKED"
	case 21:
		return "STREAM_DATA_BLOCKED"
	case 22, 23:
		return "STREAMS_BLOCKED"
	case 24:
		return "NEW_CONNECTION_ID"
	case 25:
		return "RETIRE_CONNECTION_ID"
	case 26:
		return "PATH_CHALLENGE"
	case 27:
		return "PATH_RESPONSE"
	case 28, 29:
		return "CONNECTION_CLOSE"
	case 30:
		return "HANDSHAKE_DONE"
	case 31:
		return "DATAGRAM"
	}
	return fmt.Sprintf("Frame 0x%x", t)
}

func quicParseFrames(data []byte, base int, root *Field, c *ctx, flow *tlsFlow) {
	off := 0
	for i := 0; i < 128 && off < len(data); i++ {
		t, n, ok := quicVarint(data, off)
		if !ok {
			break
		}
		start := off
		off = n
		name := quicFrameName(t)
		f := newField(name, "", base+start, 0)
		switch {
		case t == 0:
			for off < len(data) && data[off] == 0 {
				off++
			}
			f.Label = fmt.Sprintf("PADDING (%d bytes)", off-start)
		case t == 1:
		case t == 2 || t == 3:
			largest, n1, ok := quicVarint(data, off)
			if !ok {
				break
			}
			off = n1
			delay, n2, ok := quicVarint(data, off)
			if !ok {
				break
			}
			off = n2
			rc, n3, ok := quicVarint(data, off)
			if !ok {
				break
			}
			off = n3
			fr, n4, ok := quicVarint(data, off)
			if !ok {
				break
			}
			off = n4
			f.add(newField(fmt.Sprintf("Largest Acknowledged: %d", largest), "", base+start, 0), newField(fmt.Sprintf("ACK Delay: %d", delay), "", base+start, 0), newField(fmt.Sprintf("ACK Range Count: %d", rc), "", base+start, 0), newField(fmt.Sprintf("First ACK Range: %d", fr), "", base+start, 0))
			for j := uint64(0); j < rc && off < len(data); j++ {
				g, ng, ok := quicVarint(data, off)
				if !ok {
					break
				}
				off = ng
				lenv, nl, ok := quicVarint(data, off)
				if !ok {
					break
				}
				off = nl
				f.add(newField(fmt.Sprintf("Gap %d: %d, Range Length: %d", j+1, g, lenv), "", base+start, 0))
			}
			if t == 3 && off < len(data) {
				ect0, ne, ok := quicVarint(data, off)
				if ok {
					off = ne
					f.add(newField(fmt.Sprintf("ECT0 Count: %d", ect0), "", base+start, 0))
				}
				if off < len(data) {
					ect1, ne1, ok := quicVarint(data, off)
					if ok {
						off = ne1
						f.add(newField(fmt.Sprintf("ECT1 Count: %d", ect1), "", base+start, 0))
					}
				}
				if off < len(data) {
					ce, nc, ok := quicVarint(data, off)
					if ok {
						off = nc
						f.add(newField(fmt.Sprintf("CE Count: %d", ce), "", base+start, 0))
					}
				}
			}
		case t == 6:
			coff, n1, ok := quicVarint(data, off)
			if !ok {
				break
			}
			off = n1
			l, n2, ok := quicVarint(data, off)
			if !ok {
				break
			}
			off = n2
			if off+int(l) > len(data) {
				break
			}
			cdata := data[off : off+int(l)]
			f.add(newField(fmt.Sprintf("Offset: %d", coff), "", 0, 0), newField(fmt.Sprintf("Length: %d", l), "", 0, 0), newField("Data: "+hexPreview(cdata, 64), "", base+off, len(cdata)))
			if coff == 0 {
				// CRYPTO offset 0 starts with a TLS handshake message header.
				for hp := 0; hp+4 <= len(cdata); {
					ht := cdata[hp]
					hl := int(cdata[hp+1])<<16 | int(cdata[hp+2])<<8 | int(cdata[hp+3])
					end := hp + 4 + hl
					if end > len(cdata) {
						end = len(cdata)
					}
					c.parseTLSHandshakeMessage(ht, cdata[hp+4:end], base+off+hp+4, f, flow)
					hp = end
				}
			}
			off += int(l)
		case t >= 8 && t <= 15:
			sid, n1, ok := quicVarint(data, off)
			if !ok {
				break
			}
			off = n1
			var soff uint64
			if t&0x04 != 0 {
				soff, n1, ok = quicVarint(data, off)
				if !ok {
					break
				}
				off = n1
			}
			var l uint64 = uint64(len(data) - off)
			if t&0x02 != 0 {
				l, n1, ok = quicVarint(data, off)
				if !ok {
					break
				}
				off = n1
			}
			if off+int(l) > len(data) {
				l = uint64(len(data) - off)
			}
			f.add(newField(fmt.Sprintf("Stream ID: %d", sid), "", 0, 0), newField(fmt.Sprintf("Offset: %d", soff), "", 0, 0), newField(fmt.Sprintf("Length: %d", l), "", 0, 0), newField(fmt.Sprintf("FIN: %d", t&1), "", 0, 0), newField("Data: "+printablePreview(data[off:off+int(l)], 160), "", base+off, int(l)))
			off += int(l)
		case t == 28 || t == 29:
			ec, n1, ok := quicVarint(data, off)
			if !ok {
				break
			}
			off = n1
			var ft uint64
			if t == 28 {
				ft, n1, ok = quicVarint(data, off)
				if !ok {
					break
				}
				off = n1
			}
			rl, n2, ok := quicVarint(data, off)
			if !ok {
				break
			}
			off = n2
			if off+int(rl) > len(data) {
				rl = uint64(len(data) - off)
			}
			f.add(newField(fmt.Sprintf("Error Code: %d", ec), "", 0, 0))
			if t == 28 {
				f.add(newField(fmt.Sprintf("Frame Type: %d", ft), "", 0, 0))
			}
			f.add(newField("Reason: "+printablePreview(data[off:off+int(rl)], 160), "", base+off, int(rl)))
			off += int(rl)
		case t == 24:
			seq, n1, ok := quicVarint(data, off)
			if !ok {
				break
			}
			off = n1
			rl, n2, ok := quicVarint(data, off)
			if !ok {
				break
			}
			off = n2
			ret, n3, ok := quicVarint(data, off)
			if !ok {
				break
			}
			off = n3
			if off+int(rl) > len(data) {
				break
			}
			f.add(newField(fmt.Sprintf("Sequence Number: %d", seq), "", 0, 0), newField("Retire Prior To: "+fmt.Sprint(ret), "", 0, 0), newField("Connection ID: "+hexPreview(data[off:off+int(rl)], 20), "", base+off, int(rl)), newField("Stateless Reset Token: "+hexPreview(data[off+int(rl):], 16), "", 0, 0))
			off += int(rl) + 16
		case t == 26 || t == 27:
			if off+8 > len(data) {
				break
			}
			f.add(newField("Data: "+hexPreview(data[off:off+8], 8), "", base+off, 8))
			off += 8
		case t == 30:
		case t == 31:
			l, n1, ok := quicVarint(data, off)
			if !ok {
				break
			}
			off = n1
			if off+int(l) > len(data) {
				l = uint64(len(data) - off)
			}
			f.add(newField(fmt.Sprintf("Length: %d", l), "", 0, 0), newField("Data: "+printablePreview(data[off:off+int(l)], 160), "", base+off, int(l)))
			off += int(l)
		case t == 7:
			l, n1, ok := quicVarint(data, off)
			if !ok {
				break
			}
			off = n1
			if off+int(l) > len(data) {
				break
			}
			f.add(newField("Token: "+hexPreview(data[off:off+int(l)], 32), "", base+off, int(l)))
			off += int(l)
		case t == 16 || t == 20:
			v, n1, ok := quicVarint(data, off)
			if !ok {
				break
			}
			off = n1
			f.add(newField(fmt.Sprintf("Maximum Data: %d", v), "", 0, 0))
		case t == 17 || t == 21:
			sid, n1, ok := quicVarint(data, off)
			if !ok {
				break
			}
			off = n1
			v, n2, ok := quicVarint(data, off)
			if !ok {
				break
			}
			off = n2
			f.add(newField(fmt.Sprintf("Stream ID: %d", sid), "", 0, 0), newField(fmt.Sprintf("Value: %d", v), "", 0, 0))
		case t == 18 || t == 19 || t == 22 || t == 23:
			v, n1, ok := quicVarint(data, off)
			if !ok {
				break
			}
			off = n1
			f.add(newField(fmt.Sprintf("Maximum Streams: %d", v), "", 0, 0))
		case t == 4 || t == 5:
			sid, n1, ok := quicVarint(data, off)
			if !ok {
				break
			}
			off = n1
			ec, n2, ok := quicVarint(data, off)
			if !ok {
				break
			}
			off = n2
			f.add(newField(fmt.Sprintf("Stream ID: %d", sid), "", 0, 0), newField(fmt.Sprintf("Error Code: %d", ec), "", 0, 0))
			if t == 4 {
				fs, n3, ok := quicVarint(data, off)
				if ok {
					off = n3
					f.add(newField(fmt.Sprintf("Final Size: %d", fs), "", 0, 0))
				}
			}
		case t == 25:
			v, n1, ok := quicVarint(data, off)
			if !ok {
				break
			}
			off = n1
			f.add(newField(fmt.Sprintf("Sequence Number: %d", v), "", 0, 0))
		default:
			f.Value = "unparsed"
			off = len(data)
		}
		f.Length = base + off - (base + start)
		root.add(f)
	}
}

func (c *ctx) quicDecryptInitial(b []byte, base int, root *Field, flow *tlsFlow, start int, dcid, scid []byte, version uint32, length uint64, pnOffset int, first byte) bool {
	if pnOffset+4+16 > len(b) {
		return false
	}
	packetEnd := pnOffset + int(length)
	if packetEnd > len(b) || packetEnd < pnOffset+1+16 {
		return false
	}
	sample := b[pnOffset+4 : pnOffset+4+16]
	clientSecret, serverSecret, ok := quicInitialSecrets(dcid, version)
	if !ok {
		return false
	}
	secrets := [][]byte{clientSecret, serverSecret}
	if c.m.SrcPort == 443 {
		secrets = [][]byte{serverSecret, clientSecret}
	}
	for _, secret := range secrets {
		_, _, hp, ok := quicPacketKeys(secret)
		if !ok {
			continue
		}
		block, err := aes.NewCipher(hp)
		if err != nil {
			continue
		}
		mask := make([]byte, 16)
		block.Encrypt(mask, sample)
		uf := first ^ (mask[0] & 0x0f)
		pnLen := int(uf&0x03) + 1
		if pnOffset+pnLen > packetEnd {
			continue
		}
		upn := append([]byte(nil), b[pnOffset:pnOffset+pnLen]...)
		for i := range upn {
			upn[i] ^= mask[1+i]
		}
		pn := quicPacketNumber(upn)
		header := append([]byte(nil), b[:pnOffset+pnLen]...)
		header[0] = uf
		copy(header[pnOffset:], upn)
		ct := b[pnOffset+pnLen : packetEnd]
		pt, ok := quicOpen(secret, header, ct, pn)
		if !ok {
			continue
		}
		root.add(newField(fmt.Sprintf("Packet Number: %d", pn), "", base+pnOffset, pnLen))
		fn := newNode(fmt.Sprintf("Decrypted QUIC Payload (%d bytes)", len(pt)), base+pnOffset+pnLen, len(pt))
		quicParseFrames(pt, base+pnOffset+pnLen, fn, c, flow)
		root.add(fn)
		root.Value = fmt.Sprintf("%d frames", len(fn.Children))
		return true
	}
	return false
}

type quicSecret struct {
	label string
	value []byte
}

func (c *ctx) quicDecryptWithSecrets(b []byte, base int, root *Field, flow *tlsFlow, pnOffset int, packetEnd int, first byte, long bool, secrets []quicSecret) bool {
	if pnOffset+4+16 > len(b) || packetEnd > len(b) || packetEnd <= pnOffset {
		return false
	}
	sample := b[pnOffset+4 : pnOffset+4+16]
	for _, sec := range secrets {
		if len(sec.value) == 0 {
			continue
		}
		_, _, hp, ok := quicPacketKeys(sec.value)
		if !ok {
			continue
		}
		block, err := aes.NewCipher(hp)
		if err != nil {
			continue
		}
		mask := make([]byte, 16)
		block.Encrypt(mask, sample)
		uf := first
		if long {
			uf ^= mask[0] & 0x0f
		} else {
			uf ^= mask[0] & 0x1f
		}
		pnLen := int(uf&0x03) + 1
		if pnOffset+pnLen > packetEnd {
			continue
		}
		upn := append([]byte(nil), b[pnOffset:pnOffset+pnLen]...)
		for i := range upn {
			upn[i] ^= mask[1+i]
		}
		header := append([]byte(nil), b[:pnOffset+pnLen]...)
		header[0] = uf
		copy(header[pnOffset:], upn)
		ct := b[pnOffset+pnLen : packetEnd]
		startPN := quicPacketNumber(upn)
		for n := uint64(0); n < 64; n++ {
			pn := startPN + n
			pt, ok := quicOpen(sec.value, header, ct, pn)
			if !ok {
				continue
			}
			root.add(newField(fmt.Sprintf("Packet Number: %d", pn), "", base+pnOffset, pnLen), newField("Key Log Label: "+sec.label, "", 0, 0))
			fn := newNode(fmt.Sprintf("Decrypted QUIC Payload (%d bytes)", len(pt)), base+pnOffset+pnLen, len(pt))
			quicParseFrames(pt, base+pnOffset+pnLen, fn, c, flow)
			root.add(fn)
			root.Value = fmt.Sprintf("%d frames", len(fn.Children))
			return true
		}
	}
	return false
}
