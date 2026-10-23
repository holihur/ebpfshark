package decode

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
)

type aiHTTPState struct {
	mu      sync.Mutex
	buf     []byte
	headers map[string]string
	path    string
	ct      string
	request bool
}

var aiHTTPFlows = flowStore[*aiHTTPState]{max: 1024}

func aiHTTPFlowKey(c *ctx) string {
	return fmt.Sprintf("%s:%d|%s:%d", c.m.SrcIP, c.m.SrcPort, c.m.DstIP, c.m.DstPort)
}

// dissectAIHTTP buffers HTTP/1.x bodies across TCP segments. JSON bodies are
// parsed once complete; chunked bodies use the terminal zero chunk; SSE is
// parsed incrementally from the accumulated buffer.
func (c *ctx) dissectAIHTTP(body []byte, base int, root *Field, headers map[string]string, path string, request bool) bool {
	ct := strings.ToLower(headers["content-type"])
	if !aiHTTPCandidate(path, ct, headers["content-encoding"], body) {
		return false
	}
	st := aiHTTPFlows.GetOrCreate(aiHTTPFlowKey(c), func() *aiHTTPState { return &aiHTTPState{} })
	st.mu.Lock()
	defer st.mu.Unlock()
	if path != "" {
		st.path = path
	}
	st.ct, st.request = ct, request
	st.headers = cloneHeaders(headers)
	return c.processAIHTTPLocked(st, body, base, root)
}

// dissectAIHTTPContinuation consumes body-only TCP segments for an existing
// HTTP AI flow. It is called from the TCP dispatcher before protocol plugins.
func (c *ctx) dissectAIHTTPContinuation(body []byte, base int) bool {
	st, ok := aiHTTPFlows.Get(aiHTTPFlowKey(c))
	if !ok {
		return false
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if len(st.buf) == 0 && len(st.headers) == 0 {
		return false
	}
	root := c.newNode("AI API (continued body)", base, len(body))
	if !c.processAIHTTPLocked(st, body, base, root) {
		return false
	}
	c.addRoot(root)
	return true
}

func (c *ctx) processAIHTTPLocked(st *aiHTTPState, body []byte, base int, root *Field) bool {
	st.buf = append(st.buf, body...)
	if len(st.buf) > 4<<20 {
		st.buf = nil
		return false
	}
	payload := st.buf
	if strings.Contains(strings.ToLower(st.headers["transfer-encoding"]), "chunked") {
		decoded, ok := dechunkHTTP(st.buf)
		if !ok {
			return false
		}
		payload = decoded
	} else if n, err := strconv.Atoi(st.headers["content-length"]); err == nil && n >= 0 {
		if len(st.buf) < n {
			return false
		}
		payload = st.buf[:n]
	} else if !strings.Contains(st.ct, "text/event-stream") {
		if !jsonValid(payload) {
			return false
		}
	}
	decoded, ok := decodeAIBody(payload, st.headers["content-encoding"])
	if !ok {
		return false
	}
	payload = decoded
	if _, ok := c.dissectAI(payload, base, root, st.path, st.ct, st.request); !ok {
		return false
	}
	st.buf = nil
	return true
}

func cloneHeaders(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func aiHTTPCandidate(path, ct, encoding string, body []byte) bool {
	p := strings.ToLower(path)
	if strings.Contains(p, "/v1/messages") || strings.Contains(p, "/v1/chat/completions") || strings.Contains(p, "/v1/responses") || strings.Contains(p, "anthropic") {
		return true
	}
	if strings.Contains(ct, "text/event-stream") {
		return true
	}
	if strings.Contains(ct, "json") && strings.TrimSpace(encoding) != "" && strings.TrimSpace(encoding) != "identity" {
		return true
	}
	s := strings.ToLower(string(body))
	return strings.Contains(s, `"object":"chat.completion"`) || strings.Contains(s, `"object": "chat.completion"`) ||
		strings.Contains(s, `"object":"response"`) || strings.Contains(s, `"type":"message"`) ||
		strings.Contains(s, `"type": "message"`) || strings.Contains(s, `"output_text"`)
}

func jsonValid(b []byte) bool {
	s := strings.TrimSpace(string(b))
	if len(s) < 2 {
		return false
	}
	return (s[0] == '{' && s[len(s)-1] == '}') || (s[0] == '[' && s[len(s)-1] == ']')
}
