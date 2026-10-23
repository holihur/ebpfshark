package decode

import (
	"strings"

	"ebpfshark/pkg/pluginapi"
)

func registerExternalPlugin(p pluginapi.Plugin) {
	if p == nil {
		return
	}
	name := strings.ToLower(strings.TrimSpace(p.Name()))
	if name == "" {
		return
	}
	decrypted := false
	if d, ok := p.(pluginapi.DecryptedPlugin); ok {
		decrypted = d.Decrypted()
	}
	RegisterPlugin(pluginSpec{
		Name:      name,
		Priority:  p.Priority(),
		Transport: Transport(p.Transport()),
		Decrypted: decrypted,
		Display:   p.Name(),
		Match: func(c *ctx, sport, dport uint16, b []byte) bool {
			return p.Match(externalRequest(c, b, sport, dport, 0))
		},
		Dissect: func(c *ctx, b []byte, base int) bool {
			res, ok := p.Dissect(externalRequest(c, b, c.m.SrcPort, c.m.DstPort, base))
			if !ok {
				return false
			}
			_ = base
			applyExternalResult(c, res)
			return true
		},
	})
}

func externalRequest(c *ctx, b []byte, sport, dport uint16, base int) pluginapi.Request {
	req := pluginapi.Request{
		Data: b,
		Meta: pluginapi.Metadata{
			SrcIP:   ipString(c.m.SrcIP),
			DstIP:   ipString(c.m.DstIP),
			SrcPort: sport,
			DstPort: dport,
		},
	}
	req.Base = base
	req.Meta.Layers = append([]string(nil), c.layers...)
	return req
}

func applyExternalResult(c *ctx, res pluginapi.Result) {
	layers := res.Layers
	if len(layers) == 0 && res.Proto != "" {
		layers = []string{res.Proto}
	}
	for _, l := range layers {
		if l != "" {
			c.addLayer(l)
		}
	}
	if res.Proto != "" {
		c.proto = res.Proto
	}
	if res.Info != "" {
		c.appInfo = res.Info
	}
	for i := range res.Fields {
		c.addRoot(fieldFromPlugin(res.Fields[i]))
	}
}

func fieldFromPlugin(f pluginapi.Field) *Field {
	out := &Field{
		Label:    f.Label,
		Value:    f.Value,
		Severity: f.Severity,
		Offset:   f.Offset,
		Length:   f.Length,
	}
	for _, ch := range f.Children {
		out.Children = append(out.Children, fieldFromPlugin(ch))
	}
	return out
}
