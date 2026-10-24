package decode

import (
	"bytes"
	"compress/gzip"
	"strconv"
	"strings"
	"testing"
)

func aiHTTP(body, path, ctype string) []byte {
	return []byte("POST " + path + " HTTP/1.1\r\nContent-Type: " + ctype + "\r\n\r\n" + body)
}

func TestOpenAIChatRequest(t *testing.T) {
	b := aiHTTP(`{"model":"gpt-4o","messages":[{"role":"user","content":"hello"}],"stream":true}`, "/v1/chat/completions", "application/json")
	c := appCtx(b)
	if !c.dissectHTTP(b, 0) || !c.m.HasLayer("ai") || !c.m.HasLayer("openai") || !strings.Contains(c.appInfo, "OpenAI") {
		t.Fatalf("layers=%v info=%q", c.m.Layers, c.appInfo)
	}
}

func TestAnthropicMessages(t *testing.T) {
	b := aiHTTP(`{"model":"claude-3-5-sonnet","max_tokens":128,"messages":[{"role":"user","content":"hi"}]}`, "/v1/messages", "application/json")
	c := appCtx(b)
	if !c.dissectHTTP(b, 0) || !c.m.HasLayer("ai") || !c.m.HasLayer("anthropic") || !strings.Contains(c.appInfo, "Anthropic") {
		t.Fatalf("layers=%v info=%q", c.m.Layers, c.appInfo)
	}
}

func TestOpenAIResponses(t *testing.T) {
	b := aiHTTP(`{"id":"resp_1","object":"response","status":"completed","output":[{"type":"message","content":[{"type":"output_text","text":"ok"}]}]}`, "/v1/responses", "application/json")
	c := appCtx(b)
	if !c.dissectHTTP(b, 0) || !c.m.HasLayer("ai") || !c.m.HasLayer("openai-responses") || !strings.Contains(c.appInfo, "OpenAI Responses") {
		t.Fatalf("layers=%v info=%q", c.m.Layers, c.appInfo)
	}
}

func TestAnthropicSSE(t *testing.T) {
	b := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\nevent: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"hello\"}}\n\ndata: [DONE]\n")
	c := appCtx(b)
	if _, ok := c.dissectAI([]byte(strings.SplitN(string(b), "\r\n\r\n", 2)[1]), 0, newNode("http", 0, len(b)), "/v1/messages", "text/event-stream", false); !ok || !c.m.HasLayer("ai") {
		t.Fatalf("layers=%v info=%q", c.m.Layers, c.appInfo)
	}
}

func TestAISplitBody(t *testing.T) {
	payload := []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"hello"}]}`)
	head := []byte("POST /v1/chat/completions HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: " + strconv.Itoa(len(payload)) + "\r\n\r\n")
	first := append(append([]byte(nil), head...), payload[:20]...)
	c1 := appCtx(first)
	if !c1.dissectHTTP(first, 0) {
		t.Fatal("headers not parsed")
	}
	c2 := appCtx(payload[20:])
	if !c2.dissectAIHTTPContinuation(payload[20:], 0) || !c2.m.HasLayer("ai") {
		t.Fatalf("layers=%v info=%q", c2.m.Layers, c2.appInfo)
	}
}

func TestAIGzipBody(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write([]byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"hello"}]}`))
	_ = zw.Close()
	head := []byte("POST /v1/chat/completions HTTP/1.1\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\nContent-Length: " + strconv.Itoa(buf.Len()) + "\r\n\r\n")
	b := append(head, buf.Bytes()...)
	c := appCtx(b)
	if !c.dissectHTTP(b, 0) || !c.m.HasLayer("ai") {
		t.Fatalf("layers=%v info=%q", c.m.Layers, c.appInfo)
	}
}
