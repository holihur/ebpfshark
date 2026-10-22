//go:build full

package decode

import (
	"bytes"
	"fmt"
	"strings"
)

// ------------------------------------------------------------ PostgreSQL

func pgTypeName(t byte) string {
	switch t {
	case 'R':
		return "Authentication"
	case 'S':
		return "ParameterStatus / Sync"
	case 'K':
		return "BackendKeyData"
	case 'Z':
		return "ReadyForQuery"
	case 'T':
		return "RowDescription"
	case 'D':
		return "DataRow / Describe"
	case 'C':
		return "CommandComplete"
	case 'E':
		return "ErrorResponse / Execute"
	case 'N':
		return "NoticeResponse"
	case 'Q':
		return "Query"
	case 'P':
		return "Parse"
	case 'B':
		return "Bind"
	case 'A':
		return "NotificationResponse"
	case 'X':
		return "Terminate"
	case 'd':
		return "CopyData"
	case 'c':
		return "CopyDone"
	case 'f':
		return "CopyFail"
	case '1':
		return "ParseComplete"
	case '2':
		return "BindComplete"
	case '3':
		return "CloseComplete"
	case 'n':
		return "NoData"
	case 's':
		return "PortalSuspended"
	case 'I':
		return "EmptyQueryResponse"
	}
	return fmt.Sprintf("Message '%c'", t)
}

func pgCString(b []byte, off int) (string, int, bool) {
	if off >= len(b) {
		return "", off, false
	}
	end := bytes.IndexByte(b[off:], 0)
	if end < 0 {
		return string(b[off:]), len(b), true
	}
	return string(b[off : off+end]), off + end + 1, true
}

func pgErrorFields(c *ctx, b []byte) []*Field {
	var out []*Field
	names := map[byte]string{'S': "Severity", 'V': "Severity (non-localized)", 'C': "SQLSTATE Code", 'M': "Message", 'D': "Detail", 'H': "Hint", 'P': "Position", 'W': "Where", 's': "Schema", 't': "Table", 'c': "Column", 'd': "Data type", 'n': "Constraint", 'F': "File", 'L': "Line", 'R': "Routine"}
	for off := 0; off < len(b) && b[off] != 0; {
		code := b[off]
		off++
		val, next, ok := pgCString(b, off)
		if !ok {
			break
		}
		name := names[code]
		if name == "" {
			name = fmt.Sprintf("Field '%c'", code)
		}
		out = append(out, c.newField(name+": "+val, "", 0, 0))
		off = next
	}
	return out
}

func pgAuthName(code uint32) string {
	switch code {
	case 0:
		return "AuthenticationOk"
	case 2:
		return "KerberosV5"
	case 3:
		return "CleartextPassword"
	case 5:
		return "MD5Password"
	case 6:
		return "SCMCredential"
	case 7:
		return "GSS"
	case 8:
		return "GSSContinue"
	case 9:
		return "SSPI"
	case 10:
		return "SASL"
	case 11:
		return "SASLContinue"
	case 12:
		return "SASLFinal"
	}
	return fmt.Sprintf("Authentication %d", code)
}

func (c *ctx) dissectPostgreSQL(b []byte, base int) bool {
	if len(b) < 4 {
		return false
	}
	startupLen := 0
	if len(b) >= 8 {
		l := int(be32(b[0:4]))
		if l >= 8 && l <= 1<<20 {
			startupLen = l
		}
	}
	c.addLayer("postgresql")
	c.proto = "postgresql"
	info := "PostgreSQL"
	root := c.newNode("PostgreSQL", base, len(b))

	if startupLen > 0 && int(be32(b[4:8])) >= 196608 {
		length := startupLen
		code := be32(b[4:8])
		switch code {
		case 196608:
			root = c.newNode("PostgreSQL Startup Message", base, min(length, len(b)))
			root.add(c.newField(fmt.Sprintf("Length: %d", length), "", base, 4), c.newField("Protocol Version: 3.0", "", base+4, 4))
			off := 8
			kv := map[string]string{}
			for off < len(b) {
				key, n, ok := pgCString(b, off)
				if !ok || key == "" {
					break
				}
				val, n2, ok := pgCString(b, n)
				if !ok {
					break
				}
				kv[key] = val
				off = n2
			}
			info = "PostgreSQL startup"
			for _, k := range []string{"user", "database", "application_name", "client_encoding", "options"} {
				if v := kv[k]; v != "" {
					root.add(c.newField(k+": "+v, "", base, 0))
					if k == "user" {
						info += " user=" + v
					}
					if k == "database" {
						info += " db=" + v
					}
				}
			}
		case 80877103:
			root = c.newNode("PostgreSQL SSLRequest", base, min(length, len(b)))
			info = "PostgreSQL SSLRequest"
		case 80877102:
			root = c.newNode("PostgreSQL CancelRequest", base, min(length, len(b)))
			info = "PostgreSQL CancelRequest"
		}
	} else if len(b) >= 5 {
		typ := b[0]
		msgLen := int(be32(b[1:5]))
		if msgLen < 4 || 1+msgLen > len(b) {
			return false
		}
		name := pgTypeName(typ)
		root = c.newNode("PostgreSQL "+name, base, 1+msgLen)
		root.add(c.newField(fmt.Sprintf("Type: %c (%s)", typ, name), "", base, 1), c.newField(fmt.Sprintf("Length: %d", msgLen), "", base+1, 4))
		payload := b[5:min(1+msgLen, len(b))]
		info = "PostgreSQL " + name
		switch typ {
		case 'R':
			if len(payload) >= 4 {
				code := be32(payload[0:4])
				root.add(c.newField(fmt.Sprintf("Authentication: %s (%d)", pgAuthName(code), code), "", base+5, 4))
				info += ": " + pgAuthName(code)
			}
		case 'S':
			if key, n, ok := pgCString(payload, 0); ok {
				if val, _, ok := pgCString(payload, n); ok {
					root.add(c.newField("Parameter: "+key+" = "+val, "", base+5, len(payload)))
					info += ": " + key + "=" + val
				}
			}
		case 'K':
			if len(payload) >= 8 {
				root.add(c.newField(fmt.Sprintf("Backend PID: %d", be32(payload[0:4])), "", base+5, 4), c.newField(fmt.Sprintf("Secret Key: 0x%08x", be32(payload[4:8])), "", base+9, 4))
			}
		case 'Z':
			if len(payload) >= 1 {
				st := map[byte]string{'I': "idle", 'T': "in transaction", 'E': "failed transaction"}[payload[0]]
				root.add(c.newField("Transaction Status: "+st, "", base+5, 1))
			}
		case 'Q':
			q := trimNul(payload)
			root.add(c.newField("Query: "+shorten(q, 300), "", base+5, len(payload)))
			info += ": " + shorten(q, 80)
		case 'P':
			stmt, n, ok := pgCString(payload, 0)
			if ok {
				q, n2, ok := pgCString(payload, n)
				if ok {
					root.add(c.newField("Statement: "+stmt, "", base+5, n), c.newField("Query: "+shorten(q, 300), "", base+5+n, n2-n))
					info += ": " + shorten(q, 80)
					if n2+2 <= len(payload) {
						cnt := int(be16(payload[n2 : n2+2]))
						root.add(c.newField(fmt.Sprintf("Parameter Types: %d", cnt), "", base+5+n2, 2))
					}
				}
			}
		case 'B':
			portal, n, ok := pgCString(payload, 0)
			if ok {
				stmt, n2, ok := pgCString(payload, n)
				if ok {
					root.add(c.newField("Portal: "+portal, "", base+5, n), c.newField("Statement: "+stmt, "", base+5+n, n2-n))
					info += fmt.Sprintf(" portal=%s statement=%s", portal, stmt)
					if n2+2 <= len(payload) {
						fc := int(be16(payload[n2 : n2+2]))
						root.add(c.newField(fmt.Sprintf("Parameter Format Codes: %d", fc), "", base+5+n2, 2))
					}
				}
			}
		case 'T':
			if len(payload) >= 2 {
				nfields := int(be16(payload[0:2]))
				root.add(c.newField(fmt.Sprintf("Fields: %d", nfields), "", base+5, 2))
				p := 2
				for i := 0; i < nfields && p+18 <= len(payload); i++ {
					fname, n, ok := pgCString(payload, p)
					if !ok {
						break
					}
					p = n
					col := c.newField(fmt.Sprintf("Column %d: %s", i+1, fname), "", base+5+p, 18)
					if p+18 <= len(payload) {
						col.add(
							c.newField(fmt.Sprintf("Table OID: %d", be32(payload[p:p+4])), "", 0, 0),
							c.newField(fmt.Sprintf("Column ID: %d", be16(payload[p+4:p+6])), "", 0, 0),
							c.newField(fmt.Sprintf("Type OID: %d", be32(payload[p+6:p+10])), "", 0, 0),
							c.newField(fmt.Sprintf("Type Size: %d", int16(be16(payload[p+10:p+12]))), "", 0, 0),
							c.newField(fmt.Sprintf("Type Modifier: %d", int32(be32(payload[p+12:p+16]))), "", 0, 0),
							c.newField(fmt.Sprintf("Format: %d", be16(payload[p+16:p+18])), "", 0, 0),
						)
						p += 18
					}
					root.add(col)
				}
			}
		case 'D':
			// Ambiguous: backend DataRow or frontend Describe.
			if len(payload) >= 2 {
				cols := int(be16(payload[0:2]))
				if cols < 1024 && (cols == 0 || len(payload) > 2+4) {
					root.add(c.newField(fmt.Sprintf("Columns: %d", cols), "", base+5, 2))
					p := 2
					for i := 0; i < cols && p+4 <= len(payload); i++ {
						l := int(int32(be32(payload[p : p+4])))
						p += 4
						if l < 0 {
							root.add(c.newField(fmt.Sprintf("Column %d: NULL", i+1), "", 0, 0))
							continue
						}
						if p+l > len(payload) {
							break
						}
						v := payload[p : p+l]
						txt := string(v)
						if !isPrintable(v) {
							txt = hexPreview(v, 32)
						}
						root.add(c.newField(fmt.Sprintf("Column %d: %s", i+1, shorten(txt, 120)), "", base+5+p, l))
						p += l
					}
					info += fmt.Sprintf(" rows=%d", cols)
					break
				}
			}
			target := "S"
			if len(payload) > 0 {
				target = string(payload[0])
			}
			nm, _, _ := pgCString(payload, 1)
			root.add(c.newField("Describe Target: "+target, "", base+5, 1), c.newField("Name: "+nm, "", 0, 0))
			info += " target=" + target
		case 'E':
			// Ambiguous: backend ErrorResponse or frontend Execute.
			if len(payload) > 0 && strings.IndexByte("SVCMDHPWstcdnFLR", payload[0]) >= 0 {
				fields := pgErrorFields(c, payload)
				root.add(fields...)
				for _, f := range fields {
					if strings.HasPrefix(f.Label, "Message: ") {
						info += ": " + shorten(f.Label, 80)
						break
					}
				}
			} else {
				portal, _, _ := pgCString(payload, 0)
				root.add(c.newField("Portal: "+portal, "", 0, 0))
				info += " portal=" + portal
			}
		case 'N':
			root.add(pgErrorFields(c, payload)...)
		case 'C':
			s := trimNul(payload)
			root.add(c.newField("Tag: "+s, "", base+5, len(payload)))
			info += ": " + s
		case 'A':
			if len(payload) >= 4 {
				pid := be32(payload[0:4])
				ch, n, ok := pgCString(payload, 4)
				if ok {
					msg, _, _ := pgCString(payload, n)
					root.add(c.newField(fmt.Sprintf("PID: %d", pid), "", base+5, 4), c.newField("Channel: "+ch, "", base+9, n-4), c.newField("Payload: "+shorten(msg, 120), "", 0, 0))
					info = fmt.Sprintf("PostgreSQL NOTIFY %s: %s", ch, shorten(msg, 60))
				}
			}
		}
	} else {
		return false
	}

	c.addRoot(root)
	c.appInfo = shorten(info, 120)
	return true
}

func isPrintable(b []byte) bool {
	for _, c := range b {
		if c < 32 && c != 9 && c != 10 && c != 13 {
			return false
		}
		if c > 126 {
			return false
		}
	}
	return true
}

func init() {
	RegisterPlugin(pluginSpec{Name: "postgresql", Priority: 50, Transport: TransportTCP,
		Match: portMatch(map[uint16]bool{5432: true}), Dissect: func(c *ctx, b []byte, base int) bool { return c.dissectPostgreSQL(b, base) }, Display: "PostgreSQL"})
}
