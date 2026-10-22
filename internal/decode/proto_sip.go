//go:build full

package decode

import (
	"bytes"
	"strings"
)

// ------------------------------------------------------------------- SIP

var sipMethods = map[string]bool{
	"INVITE": true, "ACK": true, "BYE": true, "CANCEL": true, "OPTIONS": true,
	"REGISTER": true, "SUBSCRIBE": true, "NOTIFY": true, "PUBLISH": true,
	"MESSAGE": true, "REFER": true, "INFO": true, "UPDATE": true, "PRACK": true,
}

func sipHeaderName(k string) string {
	k = strings.ToLower(strings.TrimSpace(k))
	names := map[string]string{"v": "via", "f": "from", "t": "to", "i": "call-id", "m": "contact", "l": "content-length", "c": "content-type", "s": "subject", "k": "supported"}
	if n := names[k]; n != "" {
		return n
	}
	return k
}

func sipSDP(c *ctx, body []byte, root *Field, base int) {
	sdp := c.newField("Session Description Protocol (SDP)", "", base, len(body))
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimRight(line, "\r")
		if len(line) < 2 || line[1] != '=' {
			continue
		}
		key, val := line[0], line[2:]
		label := map[byte]string{'v': "Version", 'o': "Origin", 's': "Session Name", 'i': "Session Information", 'u': "URI", 'e': "Email", 'p': "Phone", 'c': "Connection", 'b': "Bandwidth", 't': "Timing", 'r': "Repeat", 'z': "Time Zone", 'k': "Encryption Key", 'a': "Attribute", 'm': "Media"}[key]
		if label == "" {
			label = string(key)
		}
		field := c.newField(label+": "+val, "", base, 0)
		if key == 'm' {
			parts := strings.Fields(val)
			if len(parts) >= 3 {
				field.Value = ""
				field.add(c.newField("Media: "+parts[0], "", base, 0), c.newField("Port: "+parts[1], "", base, 0), c.newField("Protocol: "+parts[2], "", base, 0))
				if len(parts) > 3 {
					field.add(c.newField("Formats: "+strings.Join(parts[3:], " "), "", base, 0))
				}
			}
		} else if key == 'c' {
			parts := strings.Fields(val)
			if len(parts) >= 3 {
				field.Value = ""
				field.add(c.newField("Network Type: "+parts[0], "", base, 0), c.newField("Address Type: "+parts[1], "", base, 0), c.newField("Connection Address: "+strings.Join(parts[2:], " "), "", base, 0))
			}
		} else if key == 'a' {
			if k, v, ok := strings.Cut(val, ":"); ok {
				field.Label = "Attribute: " + k
				field.Value = v
			}
		}
		sdp.add(field)
	}
	root.add(sdp)
}

func (c *ctx) dissectSIP(b []byte, base int) bool {
	line, rest, ok := bytes.Cut(b, []byte("\n"))
	if !ok {
		return false
	}
	first := strings.TrimRight(string(line), "\r")
	parts := strings.Fields(first)
	if len(parts) < 3 {
		return false
	}
	isRequest := sipMethods[parts[0]] && parts[2] == "SIP/2.0"
	isResponse := parts[0] == "SIP/2.0" && len(parts) >= 2
	if !isRequest && !isResponse {
		return false
	}
	c.addLayer("sip")
	c.proto = "sip"
	root := c.newNode("Session Initiation Protocol", base, len(b))
	root.add(c.newField(first, "", base, len(line)))
	headers := map[string]string{}
	var body []byte
	headerText := rest
	if i := bytes.Index(rest, []byte("\r\n\r\n")); i >= 0 {
		headerText, body = rest[:i], rest[i+4:]
	} else if i := bytes.Index(rest, []byte("\n\n")); i >= 0 {
		headerText, body = rest[:i], rest[i+2:]
	}
	for _, hl := range strings.Split(string(headerText), "\n") {
		hl = strings.TrimRight(hl, "\r")
		if hl == "" {
			continue
		}
		k, v, ok := strings.Cut(hl, ":")
		if ok {
			key := sipHeaderName(k)
			headers[key] = strings.TrimSpace(v)
			root.add(c.newField(strings.TrimSpace(k)+": "+strings.TrimSpace(v), "", base, 0))
		}
	}
	info := first
	who := ""
	if v := headers["from"]; v != "" {
		who = v
	}
	if v := headers["to"]; v != "" {
		if who != "" {
			who += " -> "
		}
		who += v
	}
	if who != "" {
		info += " " + who
	}
	if v := headers["call-id"]; v != "" {
		info += " Call-ID=" + v
	}
	if v := headers["cseq"]; v != "" {
		info += " CSeq=" + v
	}
	ct := strings.ToLower(headers["content-type"])
	if len(body) > 0 && (strings.Contains(ct, "application/sdp") || bytes.HasPrefix(body, []byte("v="))) {
		sipSDP(c, body, root, base)
		info += " SDP"
	}
	c.addRoot(root)
	c.appInfo = shorten(info, 160)
	return true
}

func init() {
	RegisterPlugin(pluginSpec{Name: "sip", Priority: 100, Transport: TransportUDP | TransportTCP,
		Match: portMatch(map[uint16]bool{5060: true}), Dissect: func(c *ctx, b []byte, base int) bool { return c.dissectSIP(b, base) }})
}
