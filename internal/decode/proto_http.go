package decode

import (
	"fmt"
	"strconv"
	"strings"
)

// --------------------------------------------------------------------- HTTP

func looksLikeHTTP(b []byte) bool {
	s := string(b)
	nl := strings.IndexAny(s, "\r\n")
	if nl < 0 {
		// A very short segment may contain only part of the start line.
		nl = len(s)
	}
	line := strings.TrimRight(s[:nl], "\r")
	if strings.HasPrefix(line, "HTTP/1.") || strings.HasPrefix(line, "HTTP/2") {
		return true
	}
	parts := strings.Split(line, " ")
	if len(parts) < 3 || !isHTTPMethod(parts[0]) {
		return false
	}
	ver := parts[len(parts)-1]
	return strings.HasPrefix(ver, "HTTP/1.") || strings.HasPrefix(ver, "HTTP/2")
}

func isHTTPMethod(m string) bool {
	switch m {
	case "GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH", "CONNECT", "TRACE":
		return true
	}
	return false
}

func (c *ctx) dissectHTTP(b []byte, base int) bool {
	nl := strings.Index(string(b), "\r\n")
	if nl < 0 {
		nl = strings.Index(string(b), "\n")
	}
	if nl <= 0 {
		return false
	}
	firstLine := string(b[:nl])
	parts := strings.Fields(firstLine)
	if len(parts) < 2 {
		return false
	}
	isRequest := false
	switch {
	case isHTTPMethod(parts[0]):
		if len(parts) < 3 || !strings.HasPrefix(parts[len(parts)-1], "HTTP/") {
			return false
		}
		isRequest = true
	case strings.HasPrefix(parts[0], "HTTP/1.") || strings.HasPrefix(parts[0], "HTTP/2"):
		if len(parts) < 2 {
			return false
		}
	default:
		return false
	}

	c.addLayer("http")
	c.proto = "http"
	headerEnd := len(b)
	for i := 0; i+1 < len(b); i++ {
		if b[i] == '\n' && b[i+1] == '\n' {
			headerEnd = i + 2
			break
		}
		if b[i] == '\n' && i+2 < len(b) && b[i+1] == '\r' && b[i+2] == '\n' {
			headerEnd = i + 3
			break
		}
	}

	root := c.newNode("Hypertext Transfer Protocol", base, headerEnd)
	headers := map[string]string{}
	var headerOrder []string
	off := nl + 1
	for off < headerEnd {
		next := strings.Index(string(b[off:headerEnd]), "\n")
		if next < 0 {
			next = headerEnd - off
		}
		line := strings.TrimRight(string(b[off:off+next]), "\r")
		if line == "" {
			off += next + 1
			continue
		}
		if idx := strings.Index(line, ":"); idx > 0 {
			k := strings.ToLower(strings.TrimSpace(line[:idx]))
			v := strings.TrimSpace(line[idx+1:])
			if _, ok := headers[k]; !ok {
				headerOrder = append(headerOrder, k)
			}
			headers[k] = v
			root.add(c.newField(fmt.Sprintf("%s: %s", canonicalHeader(k), v), "", base+off, next))
		}
		off += next + 1
	}

	body := b[headerEnd:]
	aiBody := body
	if strings.Contains(strings.ToLower(headers["transfer-encoding"]), "chunked") {
		if decoded, ok := dechunkHTTP(body); ok {
			aiBody = decoded
		}
	}
	if len(body) > 0 {
		root.add(c.newField(fmt.Sprintf("Body (%d bytes)", len(body)), hexPreview(body, 32), base+headerEnd, len(body)))
	}

	if isRequest {
		method, uri, version := parts[0], parts[1], ""
		if len(parts) >= 3 {
			version = parts[2]
		}
		c.m.HTTPMethod = method
		c.m.HTTPURI = uri
		c.m.HTTPHost = headers["host"]
		root.add(
			c.newField("Request Method: "+method, "", base, len(parts[0])),
			c.newField("Request URI: "+uri, "", base+len(parts[0])+1, len(parts[1])),
		)
		if version != "" {
			root.add(c.newField("Request Version: "+version, "", base, 0))
		}
		c.appInfo = fmt.Sprintf("%s %s", method, uri)
		if v := headers["host"]; v != "" {
			c.appInfo += " (Host: " + v + ")"
		}
		if v := headers["content-type"]; v != "" && len(body) > 0 {
			c.appInfo += fmt.Sprintf(" [%s; %d bytes]", v, len(body))
		}
	} else {
		code := 0
		if len(parts) >= 2 {
			if v, err := strconv.Atoi(parts[1]); err == nil {
				code = v
			}
		}
		c.m.HTTPCode = code
		root.add(
			c.newField("Response Version: "+parts[0], "", base, len(parts[0])),
			c.newField(fmt.Sprintf("Status Code: %d", code), "", base+len(parts[0])+1, len(parts[1])),
		)
		c.appInfo = fmt.Sprintf("%s %s", parts[1], strings.Join(parts[2:], " "))
		if v := headers["content-type"]; v != "" && len(body) > 0 {
			c.appInfo += fmt.Sprintf(" [%s; %d bytes]", v, len(body))
		}
	}

	if len(aiBody) > 0 && looksLikeHLS(aiBody) {
		c.dissectHLS(aiBody, base+headerEnd, root)
	} else if len(aiBody) > 0 && looksLikeDASH(aiBody) {
		c.dissectDASH(aiBody, base+headerEnd, root)
	} else if len(aiBody) > 0 {
		path := ""
		if isRequest && len(parts) > 1 {
			path = parts[1]
		}
		c.dissectAI(aiBody, base+headerEnd, root, path, headers["content-type"], isRequest)
	}

	// Prepend a line field for the start line (offset points at the line).
	root.Children = append([]*Field{c.newField(firstLine, "", base, nl)}, root.Children...)
	c.addRoot(root)
	return true
}

func dechunkHTTP(b []byte) ([]byte, bool) {
	var out []byte
	off := 0
	for off < len(b) {
		nl := strings.Index(string(b[off:]), "\r\n")
		if nl < 0 {
			return nil, false
		}
		line := strings.TrimSpace(string(b[off : off+nl]))
		if i := strings.IndexByte(line, ';'); i >= 0 {
			line = line[:i]
		}
		n, err := strconv.ParseInt(line, 16, 64)
		if err != nil || n < 0 {
			return nil, false
		}
		off += nl + 2
		if n == 0 {
			return out, true
		}
		if n > int64(len(b)-off) {
			return nil, false
		}
		out = append(out, b[off:off+int(n)]...)
		off += int(n)
		if off+2 > len(b) || b[off] != '\r' || b[off+1] != '\n' {
			return nil, false
		}
		off += 2
	}
	return out, true
}

func canonicalHeader(k string) string {
	parts := strings.Split(k, "-")
	for i, p := range parts {
		if p == "" {
			continue
		}
		parts[i] = strings.ToUpper(p[:1]) + p[1:]
	}
	return strings.Join(parts, "-")
}

func init() {
	RegisterPlugin(pluginSpec{Name: "http", Priority: 30, Transport: TransportTCP,
		Match: func(_ *ctx, sport, dport uint16, b []byte) bool {
			return httpPorts[sport] || httpPorts[dport] || looksLikeHTTP(b)
		}, Dissect: func(c *ctx, b []byte, base int) bool { return c.dissectHTTP(b, base) }})
	RegisterPlugin(pluginSpec{Name: "http", Priority: 30, Decrypted: true,
		Match: func(_ *ctx, _, _ uint16, b []byte) bool {
			return bytesHasPrefixFold(b, "GET ") || bytesHasPrefixFold(b, "POST ") || bytesHasPrefixFold(b, "HTTP/")
		}, Dissect: func(c *ctx, b []byte, base int) bool { return c.dissectHTTP(b, base) }})
}
