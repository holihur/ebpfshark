package decode

import (
	"encoding/json"
	"fmt"
	"strings"
)

// dissectAI recognises the JSON/SSE payloads of the Anthropic Messages,
// OpenAI Chat Completions and OpenAI Responses APIs. It is deliberately
// conservative: it only claims a body when the path or JSON object shape
// identifies one of those APIs.
func (c *ctx) dissectAI(body []byte, base int, root *Field, path, contentType string, request bool) (string, bool) {
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return "", false
	}
	lowerPath := strings.ToLower(path)
	if strings.Contains(contentType, "text/event-stream") || strings.HasPrefix(trimmed, "event:") || strings.HasPrefix(trimmed, "data:") {
		return c.dissectAISSE(body, base, root, path, request)
	}
	var obj map[string]any
	if err := json.Unmarshal(body, &obj); err != nil {
		return "", false
	}
	provider := aiProvider(lowerPath, obj)
	if provider == "" {
		return "", false
	}
	c.addLayer("ai")
	c.proto = "ai"
	name := aiProviderName(provider)
	n := c.newField("AI API: "+name, "", base, len(body))
	n.add(c.newField("Provider: "+name, "", base, 0))
	addAIValue(c, n, obj, "model", "Model", base)
	addAIValue(c, n, obj, "id", "ID", base)
	addAIValue(c, n, obj, "object", "Object", base)
	addAIValue(c, n, obj, "status", "Status", base)
	addAIValue(c, n, obj, "stream", "Stream", base)
	addAIValue(c, n, obj, "max_tokens", "Max Tokens", base)
	addAIValue(c, n, obj, "max_output_tokens", "Max Output Tokens", base)
	addAIValue(c, n, obj, "temperature", "Temperature", base)
	addAIValue(c, n, obj, "top_p", "Top P", base)
	addAIValue(c, n, obj, "stop_reason", "Stop Reason", base)
	addAIValue(c, n, obj, "stop_sequence", "Stop Sequence", base)
	addAIValue(c, n, obj, "finish_reason", "Finish Reason", base)
	if v, ok := obj["usage"].(map[string]any); ok {
		u := c.newField("Usage", "", base, 0)
		for _, k := range []string{"input_tokens", "output_tokens", "total_tokens", "prompt_tokens", "completion_tokens"} {
			if x, ok := v[k]; ok {
				u.add(c.newField(k+": "+fmt.Sprint(x), "", base, 0))
			}
		}
		n.add(u)
	}
	if errObj, ok := obj["error"].(map[string]any); ok {
		e := c.newField("Error", "", base, 0)
		if x, ok := errObj["type"]; ok {
			e.add(c.newField("Type: "+fmt.Sprint(x), "", base, 0))
		}
		if x, ok := errObj["message"]; ok {
			e.add(c.newField("Message: "+shorten(fmt.Sprint(x), 240), "", base, 0))
		}
		n.add(e)
	}
	if msgs, ok := obj["messages"].([]any); ok {
		addAIMessages(c, n, msgs, "Messages", base)
	} else if input, ok := obj["input"].([]any); ok {
		addAIMessages(c, n, input, "Input", base)
	}
	if choices, ok := obj["choices"].([]any); ok {
		addAIChoices(c, n, choices, base)
	}
	if content, ok := obj["content"].([]any); ok {
		addAIContent(c, n, content, "Content", base)
	}
	if output, ok := obj["output"].([]any); ok {
		addAIContent(c, n, output, "Output", base)
	}
	if text, ok := obj["output_text"].(string); ok && text != "" {
		n.add(c.newField("Output Text: "+shorten(text, 300), "", base, 0))
	}
	root.add(n)
	summary := fmt.Sprintf("%s %s", name, aiInfoSuffix(provider, request, obj))
	c.appInfo = shorten(strings.TrimSpace(summary), 180)
	return c.appInfo, true
}

func aiProvider(path string, obj map[string]any) string {
	object, _ := obj["object"].(string)
	typ, _ := obj["type"].(string)
	switch {
	case strings.Contains(path, "/v1/messages"), strings.Contains(path, "anthropic"), typ == "message" && (obj["stop_reason"] != nil || obj["content"] != nil):
		return "anthropic"
	case strings.Contains(path, "/v1/responses"), object == "response", typ == "response":
		return "openresponses"
	case strings.Contains(path, "/v1/chat/completions"), object == "chat.completion", obj["choices"] != nil:
		return "openai"
	}
	return ""
}

func aiProviderName(p string) string {
	switch p {
	case "anthropic":
		return "Anthropic Messages"
	case "openresponses":
		return "OpenAI Responses"
	default:
		return "OpenAI Chat Completions"
	}
}

func aiInfoSuffix(provider string, request bool, obj map[string]any) string {
	if request {
		return "request"
	}
	if s, ok := obj["status"].(string); ok {
		return s
	}
	if provider == "openai" {
		if choices, ok := obj["choices"].([]any); ok && len(choices) > 0 {
			if m, ok := choices[0].(map[string]any); ok {
				if r, ok := m["finish_reason"]; ok {
					return fmt.Sprint(r)
				}
			}
		}
	}
	return "response"
}

func addAIValue(c *ctx, root *Field, obj map[string]any, key, label string, base int) {
	if v, ok := obj[key]; ok && v != nil {
		root.add(c.newField(label+": "+shorten(fmt.Sprint(v), 160), "", base, 0))
	}
}

func addAIMessages(c *ctx, root *Field, list []any, label string, base int) {
	n := c.newField(fmt.Sprintf("%s (%d)", label, len(list)), "", base, 0)
	for i, item := range list {
		if i >= 8 {
			break
		}
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		role, _ := m["role"].(string)
		content := ""
		switch v := m["content"].(type) {
		case string:
			content = v
		case []any:
			for _, part := range v {
				if pm, ok := part.(map[string]any); ok {
					if text, ok := pm["text"].(string); ok {
						content += text
					}
				}
			}
		}
		n.add(c.newField(fmt.Sprintf("%d. %s: %s", i+1, role, shorten(content, 300)), "", base, 0))
	}
	root.add(n)
}

func addAIChoices(c *ctx, root *Field, list []any, base int) {
	n := c.newField(fmt.Sprintf("Choices (%d)", len(list)), "", base, 0)
	for i, item := range list {
		if i >= 8 {
			break
		}
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		text := ""
		if msg, ok := m["message"].(map[string]any); ok {
			if s, ok := msg["content"].(string); ok {
				text = s
			}
		}
		if s, ok := m["text"].(string); ok {
			text = s
		}
		finish := m["finish_reason"]
		n.add(c.newField(fmt.Sprintf("%d. finish=%v %s", i+1, finish, shorten(text, 300)), "", base, 0))
	}
	root.add(n)
}

func addAIContent(c *ctx, root *Field, list []any, label string, base int) {
	n := c.newField(fmt.Sprintf("%s (%d)", label, len(list)), "", base, 0)
	for i, item := range list {
		if i >= 8 {
			break
		}
		switch v := item.(type) {
		case string:
			n.add(c.newField(fmt.Sprintf("%d. %s", i+1, shorten(v, 300)), "", base, 0))
		case map[string]any:
			typ, _ := v["type"].(string)
			text, _ := v["text"].(string)
			if text == "" {
				if inner, ok := v["content"].([]any); ok {
					for _, x := range inner {
						if xm, ok := x.(map[string]any); ok {
							if s, ok := xm["text"].(string); ok {
								text += s
							}
						}
					}
				}
			}
			n.add(c.newField(fmt.Sprintf("%d. %s: %s", i+1, typ, shorten(text, 300)), "", base, 0))
		}
	}
	root.add(n)
}

func (c *ctx) dissectAISSE(body []byte, base int, root *Field, path string, request bool) (string, bool) {
	lines := strings.Split(string(body), "\n")
	var provider string
	n := c.newField("AI API stream (SSE)", "", base, len(body))
	count := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if data == "" || data == "[DONE]" {
			if data == "[DONE]" {
				n.add(c.newField("Stream end", "", base, 0))
			}
			continue
		}
		var obj map[string]any
		if json.Unmarshal([]byte(data), &obj) != nil {
			continue
		}
		if provider == "" {
			provider = aiProvider(strings.ToLower(path), obj)
		}
		if provider == "" {
			continue
		}
		count++
		if count <= 32 {
			typ, _ := obj["type"].(string)
			if typ == "" {
				typ, _ = obj["object"].(string)
			}
			text := aiEventText(obj)
			n.add(c.newField(fmt.Sprintf("Event %d: %s %s", count, typ, shorten(text, 180)), "", base, 0))
		}
		if count == 1 && provider != "" {
			c.addLayer("ai")
			c.proto = "ai"
		}
	}
	if provider == "" || count == 0 {
		return "", false
	}
	root.add(n)
	c.appInfo = aiProviderName(provider) + " stream"
	return c.appInfo, true
}

func aiEventText(obj map[string]any) string {
	if d, ok := obj["delta"].(map[string]any); ok {
		if s, ok := d["text"].(string); ok {
			return s
		}
		if s, ok := d["content"].(string); ok {
			return s
		}
	}
	if s, ok := obj["text"].(string); ok {
		return s
	}
	if s, ok := obj["content"].(string); ok {
		return s
	}
	return ""
}
