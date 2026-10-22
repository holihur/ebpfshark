//go:build full

package decode

import (
	"fmt"
	"sync"

	"golang.org/x/net/http2/hpack"
)

var qpackStatic = [...]struct{ name, value string }{
	{":authority", ""},
	{":path", "/"},
	{"age", "0"},
	{"content-disposition", ""},
	{"content-length", "0"},
	{"cookie", ""},
	{"date", ""},
	{"etag", ""},
	{"if-modified-since", ""},
	{"if-none-match", ""},
	{"last-modified", ""},
	{"link", ""},
	{"location", ""},
	{"referer", ""},
	{"set-cookie", ""},
	{":method", "CONNECT"},
	{":method", "DELETE"},
	{":method", "GET"},
	{":method", "HEAD"},
	{":method", "OPTIONS"},
	{":method", "POST"},
	{":method", "PUT"},
	{":scheme", "http"},
	{":scheme", "https"},
	{":status", "103"},
	{":status", "200"},
	{":status", "304"},
	{":status", "404"},
	{":status", "503"},
	{"accept", "*/*"},
	{"accept", "application/dns-message"},
	{"accept-encoding", "gzip, deflate, br"},
	{"accept-ranges", "bytes"},
	{"access-control-allow-headers", "cache-control"},
	{"access-control-allow-headers", "content-type"},
	{"access-control-allow-origin", "*"},
	{"cache-control", "max-age=0"},
	{"cache-control", "max-age=2592000"},
	{"cache-control", "max-age=604800"},
	{"cache-control", "no-cache"},
	{"cache-control", "no-store"},
	{"cache-control", "public, max-age=31536000"},
	{"content-encoding", "br"},
	{"content-encoding", "gzip"},
	{"content-type", "application/dns-message"},
	{"content-type", "application/javascript"},
	{"content-type", "application/json"},
	{"content-type", "application/x-www-form-urlencoded"},
	{"content-type", "image/gif"},
	{"content-type", "image/jpeg"},
	{"content-type", "image/png"},
	{"content-type", "text/css"},
	{"content-type", "text/html;charset=utf-8"},
	{"content-type", "text/plain"},
	{"content-type", "text/plain;charset=utf-8"},
	{"range", "bytes=0-"},
	{"strict-transport-security", "max-age=31536000"},
	{"strict-transport-security", "max-age=31536000;includesubdomains"},
	{"strict-transport-security", "max-age=31536000;includesubdomains;preload"},
	{"vary", "accept-encoding"},
	{"vary", "origin"},
	{"x-content-type-options", "nosniff"},
	{"x-xss-protection", "1; mode=block"},
	{":status", "100"},
	{":status", "204"},
	{":status", "206"},
	{":status", "302"},
	{":status", "400"},
	{":status", "403"},
	{":status", "421"},
	{":status", "425"},
	{":status", "500"},
	{"accept-language", ""},
	{"access-control-allow-credentials", "FALSE"},
	{"access-control-allow-credentials", "TRUE"},
	{"access-control-allow-headers", "*"},
	{"access-control-allow-methods", "get"},
	{"access-control-allow-methods", "get, post, options"},
	{"access-control-allow-methods", "options"},
	{"access-control-expose-headers", "content-length"},
	{"access-control-request-headers", "content-type"},
	{"access-control-request-method", "get"},
	{"access-control-request-method", "post"},
	{"alt-svc", "clear"},
	{"authorization", ""},
	{"content-security-policy", "script-src 'none';object-src 'none';base-uri 'none'"},
	{"early-data", "1"},
	{"expect-ct", ""},
	{"forwarded", ""},
	{"if-range", ""},
	{"origin", ""},
	{"purpose", "prefetch"},
	{"server", ""},
	{"timing-allow-origin", "*"},
	{"upgrade-insecure-requests", "1"},
	{"user-agent", ""},
	{"x-forwarded-for", ""},
	{"x-frame-options", "deny"},
	{"x-frame-options", "sameorigin"},
}

func qpackInt(b []byte, off, prefix int) (uint64, int, bool) {
	if off >= len(b) {
		return 0, off, false
	}
	mask := uint64((1 << prefix) - 1)
	v := uint64(b[off]) & mask
	off++
	if v < mask {
		return v, off, true
	}
	shift := uint(0)
	for i := 0; i < 10 && off < len(b); i++ {
		x := b[off]
		off++
		v += uint64(x&0x7f) << shift
		shift += 7
		if x&0x80 == 0 {
			return v, off, true
		}
	}
	return 0, off, false
}

func qpackStringBits(b []byte, off, prefix int, hbit byte) (string, int, bool) {
	if off >= len(b) {
		return "", off, false
	}
	huff := b[off]&hbit != 0
	l, next, ok := qpackInt(b, off, prefix)
	if !ok || next+int(l) > len(b) {
		return "", off, false
	}
	raw := b[next : next+int(l)]
	if huff {
		s, err := hpack.HuffmanDecodeToString(raw)
		if err != nil {
			return "", off, false
		}
		return s, next + int(l), true
	}
	return string(raw), next + int(l), true
}

func qpackString(b []byte, off int) (string, int, bool) {
	return qpackStringBits(b, off, 7, 0x80)
}

func qpackFieldName(idx uint64) string {
	if idx < uint64(len(qpackStatic)) {
		return qpackStatic[idx].name
	}
	return fmt.Sprintf(":qpindex%d", idx)
}

func qpackFieldValue(idx uint64) string {
	if idx < uint64(len(qpackStatic)) {
		return qpackStatic[idx].value
	}
	return ""
}

func decodeQPACK(b []byte) ([]hpack.HeaderField, error) {
	if len(b) < 2 {
		return nil, fmt.Errorf("short QPACK block")
	}
	_, off, ok := qpackInt(b, 0, 8) // Required Insert Count
	if !ok {
		return nil, fmt.Errorf("bad required insert count")
	}
	if off >= len(b) {
		return nil, fmt.Errorf("missing delta base")
	}
	_, off, ok = qpackInt(b, off, 7) // Delta Base, sign ignored for static decoding
	if !ok {
		return nil, fmt.Errorf("bad delta base")
	}
	var out []hpack.HeaderField
	for off < len(b) {
		first := b[off]
		switch {
		case first&0x80 != 0: // indexed field line
			idx, next, ok := qpackInt(b, off, 6)
			if !ok {
				return out, fmt.Errorf("bad indexed field")
			}
			off = next
			if first&0x40 != 0 {
				out = append(out, hpack.HeaderField{Name: qpackFieldName(idx), Value: qpackFieldValue(idx)})
			} else {
				out = append(out, hpack.HeaderField{Name: fmt.Sprintf(":dynamic%d", idx)})
			}
		case first&0x40 != 0: // literal with name reference
			idx, next, ok := qpackInt(b, off, 4)
			if !ok {
				return out, fmt.Errorf("bad name reference")
			}
			off = next
			val, next, ok := qpackString(b, off)
			if !ok {
				return out, fmt.Errorf("bad literal value")
			}
			off = next
			name := qpackFieldName(idx)
			if first&0x10 == 0 {
				name = fmt.Sprintf(":dynamic%d", idx)
			}
			out = append(out, hpack.HeaderField{Name: name, Value: val})
		case first&0x20 != 0: // literal with literal name
			name, next, ok := qpackStringBits(b, off, 3, 0x08)
			if !ok {
				return out, fmt.Errorf("bad literal name")
			}
			off = next
			val, next, ok := qpackString(b, off)
			if !ok {
				return out, fmt.Errorf("bad literal value")
			}
			off = next
			out = append(out, hpack.HeaderField{Name: name, Value: val})
		case first&0x10 != 0: // post-base indexed
			idx, next, ok := qpackInt(b, off, 4)
			if !ok {
				return out, fmt.Errorf("bad post-base index")
			}
			off = next
			out = append(out, hpack.HeaderField{Name: fmt.Sprintf(":postbase%d", idx)})
		default: // post-base name reference
			idx, next, ok := qpackInt(b, off, 4)
			if !ok {
				return out, fmt.Errorf("bad post-base name")
			}
			off = next
			val, next, ok := qpackString(b, off)
			if !ok {
				return out, fmt.Errorf("bad post-base value")
			}
			off = next
			out = append(out, hpack.HeaderField{Name: fmt.Sprintf(":postbase%d", idx), Value: val})
		}
	}
	return out, nil
}

func http3FrameName(t uint64) string {
	switch t {
	case 0:
		return "DATA"
	case 1:
		return "HEADERS"
	case 3:
		return "CANCEL_PUSH"
	case 4:
		return "SETTINGS"
	case 5:
		return "PUSH_PROMISE"
	case 7:
		return "GOAWAY"
	case 0xd:
		return "MAX_PUSH_ID"
	case 0xe:
		return "DUPLICATE_PUSH"
	}
	return fmt.Sprintf("HTTP/3 Frame 0x%x", t)
}

func (c *ctx) parseHTTP3Stream(data []byte, base int, parent *Field, streamID uint64) bool {
	off := 0
	parsed := 0
	q := qpackFor(c)
	if streamID&0x3 >= 2 {
		st, n, ok := quicVarint(data, 0)
		if !ok {
			return false
		}
		off = n
		switch st {
		case 0x02: // QPACK encoder stream
			q.feedEncoder(data[off:])
			return true
		case 0x03: // QPACK decoder stream
			return true
		case 0x00: // control stream; continue with HTTP/3 frames
		default:
			return false
		}
	}
	for off < len(data) {
		typ, n, ok := quicVarint(data, off)
		if !ok {
			break
		}
		l, n2, ok := quicVarint(data, n)
		if !ok || n2+int(l) > len(data) {
			break
		}
		payload := data[n2 : n2+int(l)]
		start := off
		off = n2 + int(l)
		name := http3FrameName(typ)
		f := c.newField(fmt.Sprintf("%s (%d bytes)", name, l), "", base+start, off-start)
		switch typ {
		case 0:
			f.Value = printablePreview(payload, 160)
		case 1:
			fields, err := q.decodeFieldSection(payload)
			if err != nil {
				f.add(c.newField("QPACK error: "+err.Error(), hexPreview(payload, 48), base+n2, len(payload)))
			} else {
				for _, hf := range fields {
					f.add(c.newField(hf.Name+": "+hf.Value, "", 0, 0))
				}
			}
		case 4:
			for p := 0; p < len(payload); {
				id, np, ok := quicVarint(payload, p)
				if !ok {
					break
				}
				val, nv, ok := quicVarint(payload, np)
				if !ok {
					break
				}
				f.add(c.newField(fmt.Sprintf("Setting 0x%x: %d", id, val), "", base+n2+p, nv-p))
				if id == 1 {
					q.Lock()
					if int(val) > q.maxCapacity {
						q.maxCapacity = int(val)
					}
					q.Unlock()
				}
				p = nv
			}
		case 7:
			if len(payload) > 0 {
				if id, _, ok := quicVarint(payload, 0); ok {
					f.add(c.newField(fmt.Sprintf("Stream ID: %d", id), "", base+n2, len(payload)))
				}
			}
		default:
			if len(payload) > 0 {
				f.Value = hexPreview(payload, 48)
			}
		}
		parent.add(f)
		parsed++
	}
	return parsed > 0
}

type qpackEntry struct {
	name, value string
	size        int
}

type qpackState struct {
	sync.Mutex
	capacity    int
	maxCapacity int
	entries     []qpackEntry
	size        int
	inserts     uint64
	streams     map[uint64][]byte
	encoderBuf  []byte
}

var qpackFlows flowStore[*qpackState]

func init() { qpackFlows.max = 1024 }

func qpackFor(c *ctx) *qpackState {
	key := tlsFlowKey(c)
	return qpackFlows.GetOrCreate(key, func() *qpackState {
		return &qpackState{maxCapacity: 4096, streams: make(map[uint64][]byte)}
	})
}

func (q *qpackState) evictLocked(add int) {
	for q.capacity > 0 && q.size+add > q.capacity && len(q.entries) > 0 {
		q.size -= q.entries[0].size
		q.entries = q.entries[1:]
	}
}

func (q *qpackState) addLocked(name, value string) {
	size := len(name) + len(value) + 32
	if size > q.capacity {
		return
	}
	q.evictLocked(size)
	q.entries = append(q.entries, qpackEntry{name: name, value: value, size: size})
	q.size += size
	q.inserts++
}

func (q *qpackState) abs(abs uint64) (qpackEntry, bool) {
	if abs >= q.inserts {
		return qpackEntry{}, false
	}
	// Absolute index 0 is the oldest retained entry. Entries before the
	// current window have already been evicted.
	base := q.inserts - uint64(len(q.entries))
	if abs < base {
		return qpackEntry{}, false
	}
	return q.entries[abs-base], true
}

func (q *qpackState) relative(rel uint64) (qpackEntry, bool) {
	if rel >= q.inserts {
		return qpackEntry{}, false
	}
	return q.abs(q.inserts - 1 - rel)
}

func (q *qpackState) fieldSection(base, index uint64, post bool) (qpackEntry, bool) {
	if post {
		return q.abs(base + index)
	}
	if index >= base {
		return qpackEntry{}, false
	}
	return q.abs(base - 1 - index)
}

func qpackInsertName(q *qpackState, static, idx uint64) string {
	if static != 0 {
		return qpackFieldName(idx)
	}
	e, ok := q.relative(idx)
	if !ok {
		return fmt.Sprintf(":dynamic%d", idx)
	}
	return e.name
}

func (q *qpackState) feedEncoder(data []byte) {
	q.Lock()
	defer q.Unlock()
	q.encoderBuf = append(q.encoderBuf, data...)
	off := q.parseEncoderLocked(q.encoderBuf)
	if off > 0 {
		q.encoderBuf = append([]byte(nil), q.encoderBuf[off:]...)
	}
}

func (q *qpackState) parseEncoderLocked(data []byte) int {
	off := 0
	for off < len(data) {
		first := data[off]
		switch {
		case first&0x80 != 0: // insert with name reference
			idx, next, ok := qpackInt(data, off, 6)
			if !ok {
				return off
			}
			off = next
			val, next, ok := qpackString(data, off)
			if !ok {
				return off
			}
			off = next
			q.addLocked(qpackInsertName(q, uint64(first&0x40), idx), val)
		case first&0x40 != 0: // insert with literal name
			name, next, ok := qpackStringBits(data, off, 5, 0x20)
			if !ok {
				return off
			}
			off = next
			val, next, ok := qpackString(data, off)
			if !ok {
				return off
			}
			off = next
			q.addLocked(name, val)
		case first&0x20 != 0: // set capacity
			capv, next, ok := qpackInt(data, off, 5)
			if !ok {
				return off
			}
			if int(capv) <= q.maxCapacity {
				q.capacity = int(capv)
				q.evictLocked(0)
			}
			off = next
		default: // duplicate
			idx, next, ok := qpackInt(data, off, 5)
			if !ok {
				return off
			}
			off = next
			if e, ok := q.relative(idx); ok {
				q.addLocked(e.name, e.value)
			}
		}
	}
	return off
}

func (q *qpackState) decodeFieldSection(b []byte) ([]hpack.HeaderField, error) {
	q.Lock()
	defer q.Unlock()
	if len(b) < 2 {
		return nil, fmt.Errorf("short QPACK block")
	}
	encRIC, off, ok := qpackInt(b, 0, 8)
	if !ok {
		return nil, fmt.Errorf("bad required insert count")
	}
	if off >= len(b) {
		return nil, fmt.Errorf("missing delta base")
	}
	sign := b[off]&0x80 != 0
	delta, off2, ok := qpackInt(b, off, 7)
	if !ok {
		return nil, fmt.Errorf("bad delta base")
	}
	off = off2
	maxEntries := uint64(q.maxCapacity / 32)
	ric := uint64(0)
	if encRIC != 0 && maxEntries > 0 {
		fullRange := 2 * maxEntries
		maxValue := q.inserts + maxEntries
		maxWrapped := (maxValue / fullRange) * fullRange
		ric = maxWrapped + encRIC - 1
		if ric > maxValue {
			if ric <= fullRange {
				return nil, fmt.Errorf("invalid required insert count")
			}
			ric -= fullRange
		}
	}
	base := ric + delta
	if sign {
		if ric <= delta {
			return nil, fmt.Errorf("invalid negative base")
		}
		base = ric - delta - 1
	}
	var out []hpack.HeaderField
	for off < len(b) {
		first := b[off]
		switch {
		case first&0x80 != 0: // indexed
			idx, next, ok := qpackInt(b, off, 6)
			if !ok {
				return out, fmt.Errorf("bad indexed field")
			}
			off = next
			if first&0x40 != 0 {
				out = append(out, hpack.HeaderField{Name: qpackFieldName(idx), Value: qpackFieldValue(idx)})
			} else if e, ok := q.fieldSection(base, idx, false); ok {
				out = append(out, hpack.HeaderField{Name: e.name, Value: e.value})
			} else {
				out = append(out, hpack.HeaderField{Name: fmt.Sprintf(":dynamic%d", idx)})
			}
		case first&0x40 != 0: // literal name reference
			idx, next, ok := qpackInt(b, off, 4)
			if !ok {
				return out, fmt.Errorf("bad name reference")
			}
			off = next
			val, next, ok := qpackString(b, off)
			if !ok {
				return out, fmt.Errorf("bad literal value")
			}
			off = next
			name := fmt.Sprintf(":dynamic%d", idx)
			if first&0x10 != 0 {
				name = qpackFieldName(idx)
			} else if e, ok := q.fieldSection(base, idx, false); ok {
				name = e.name
			}
			out = append(out, hpack.HeaderField{Name: name, Value: val})
		case first&0x20 != 0: // literal with literal name
			name, next, ok := qpackStringBits(b, off, 3, 0x08)
			if !ok {
				return out, fmt.Errorf("bad literal name")
			}
			off = next
			val, next, ok := qpackString(b, off)
			if !ok {
				return out, fmt.Errorf("bad literal value")
			}
			off = next
			out = append(out, hpack.HeaderField{Name: name, Value: val})
		case first&0x10 != 0: // post-base indexed
			idx, next, ok := qpackInt(b, off, 4)
			if !ok {
				return out, fmt.Errorf("bad post-base index")
			}
			off = next
			if e, ok := q.fieldSection(base, idx, true); ok {
				out = append(out, hpack.HeaderField{Name: e.name, Value: e.value})
			} else {
				out = append(out, hpack.HeaderField{Name: fmt.Sprintf(":postbase%d", idx)})
			}
		default: // post-base name reference
			idx, next, ok := qpackInt(b, off, 3)
			if !ok {
				return out, fmt.Errorf("bad post-base name")
			}
			off = next
			val, next, ok := qpackString(b, off)
			if !ok {
				return out, fmt.Errorf("bad post-base value")
			}
			off = next
			name := fmt.Sprintf(":postbase%d", idx)
			if e, ok := q.fieldSection(base, idx, true); ok {
				name = e.name
			}
			out = append(out, hpack.HeaderField{Name: name, Value: val})
		}
	}
	return out, nil
}

func (c *ctx) parseHTTP3StreamCompat(data []byte, base int, parent *Field) bool {
	return c.parseHTTP3Stream(data, base, parent, 0)
}
