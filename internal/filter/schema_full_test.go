//go:build full

package filter

import "testing"

func TestFullSchemaContainsAllProtocols(t *testing.T) {
	got := map[string]bool{}
	for _, f := range Schema() {
		if f.Type == layerType {
			got[f.Name] = true
		}
	}
	for _, want := range []string{"mqtt", "redis", "http2", "quic", "bgp", "ssh", "sip"} {
		if !got[want] {
			t.Fatalf("full schema missing %s", want)
		}
	}
}
