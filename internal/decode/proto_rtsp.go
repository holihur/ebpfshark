//go:build full

package decode

import (
	"bytes"
	"fmt"
	"strings"
)

var rtspMethods = map[string]bool{
	"OPTIONS": true, "DESCRIBE": true, "ANNOUNCE": true, "SETUP": true,
	"PLAY": true, "PAUSE": true, "TEARDOWN": true, "GET_PARAMETER": true,
	"SET_PARAMETER": true, "REDIRECT": true, "RECORD": true,
}

func looksLikeRTSP(b []byte) bool {
	line := b
	if i := bytes.IndexByte(b, '\n'); i >= 0 {
		line = b[:i]
	}
	parts := strings.Fields(string(line))
	if len(parts) < 2 {
		return false
	}
	if rtspMethods[parts[0]] {
		return true
	}
	return parts[0] == "RTSP/1.0" || parts[0] == "RTSP/2.0"
}

func (c *ctx) dissectRTSP(b []byte, base int) bool {
	if !looksLikeRTSP(b) {
		return false
	}
	line, rest, _ := bytes.Cut(b, []byte("\n"))
	first := strings.TrimRight(string(line), "\r")
	headers := map[string]string{}
	var body []byte
	headerText := rest
	if i := bytes.Index(rest, []byte("\r\n\r\n")); i >= 0 {
		headerText, body = rest[:i], rest[i+4:]
	} else if i := bytes.Index(rest, []byte("\n\n")); i >= 0 {
		headerText, body = rest[:i], rest[i+2:]
	}
	c.addLayer("rtsp")
	c.proto = "rtsp"
	root := newNode("Real Time Streaming Protocol", base, len(b))
	root.add(c.newField(first, "", base, len(line)))
	for _, hl := range strings.Split(string(headerText), "\n") {
		hl = strings.TrimRight(hl, "\r")
		if hl == "" {
			continue
		}
		k, v, ok := strings.Cut(hl, ":")
		if !ok {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(k))
		headers[key] = strings.TrimSpace(v)
		root.add(c.newField(strings.TrimSpace(k)+": "+strings.TrimSpace(v), "", base, 0))
	}
	info := first
	if v := headers["cseq"]; v != "" {
		info += " CSeq=" + v
	}
	if v := headers["session"]; v != "" {
		info += " Session=" + v
	}
	if len(body) > 0 {
		bodyBase := base + len(b) - len(body)
		ct := strings.ToLower(headers["content-type"])
		if strings.Contains(ct, "sdp") || bytes.HasPrefix(bytes.TrimSpace(body), []byte("v=")) {
			sipSDP(c, body, root, bodyBase)
			info += " SDP"
		} else {
			root.add(c.newField(fmt.Sprintf("Body (%d bytes)", len(body)), printablePreview(body, 160), bodyBase, len(body)))
		}
	}
	c.addRoot(root)
	c.appInfo = shorten(info, 180)
	return true
}

func init() {
	RegisterPlugin(pluginSpec{Name: "rtsp", Priority: 35, Transport: TransportTCP,
		Match: func(_ *ctx, sport, dport uint16, b []byte) bool {
			return (sport == 554 || dport == 554 || sport == 8554 || dport == 8554) && looksLikeRTSP(b)
		}, Dissect: func(c *ctx, b []byte, base int) bool { return c.dissectRTSP(b, base) }, Display: "RTSP"})
}
