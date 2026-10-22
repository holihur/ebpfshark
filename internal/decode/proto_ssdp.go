//go:build full

package decode

import (
	"bytes"
	"strings"
)

// ------------------------------------------------------------------ SSDP

func (c *ctx) dissectSSDP(b []byte, base int) bool {
	line, rest, ok := bytes.Cut(b, []byte("\n"))
	if !ok {
		return false
	}
	first := strings.TrimRight(string(line), "\r")
	isRequest := strings.HasPrefix(first, "M-SEARCH ") || strings.HasPrefix(first, "NOTIFY ")
	isResponse := strings.HasPrefix(first, "HTTP/1.1 ")
	if !isRequest && !isResponse {
		return false
	}
	c.addLayer("ssdp")
	c.proto = "ssdp"
	root := c.newNode("Simple Service Discovery Protocol", base, len(b))
	root.add(c.newField(first, "", base, len(line)))
	headers := map[string]string{}
	for _, hl := range strings.Split(string(rest), "\n") {
		hl = strings.TrimRight(hl, "\r")
		if hl == "" {
			break
		}
		k, v, ok := strings.Cut(hl, ":")
		if ok {
			headers[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
			root.add(c.newField(hl, "", base, 0))
		}
	}
	info := "SSDP " + strings.Split(first, " ")[0]
	if isResponse {
		info = "SSDP " + first
	}
	if v := headers["st"]; v != "" {
		info += " ST=" + v
	}
	if v := headers["nt"]; v != "" {
		info += " NT=" + v
	}
	if v := headers["usn"]; v != "" {
		info += " USN=" + v
	}
	c.addRoot(root)
	c.appInfo = shorten(info, 120)
	return true
}

func init() {
	RegisterPlugin(pluginSpec{Name: "ssdp", Priority: 90, Transport: TransportUDP,
		Match: portMatch(map[uint16]bool{1900: true}), Dissect: func(c *ctx, b []byte, base int) bool { return c.dissectSSDP(b, base) }})
}
