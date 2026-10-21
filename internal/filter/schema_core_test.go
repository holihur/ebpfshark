//go:build !full

package filter

import "testing"

func TestCoreSchemaOnlyCommonProtocols(t *testing.T) {
	got := map[string]bool{}
	for _, f := range Schema() {
		if f.Type == layerType {
			got[f.Name] = true
		}
	}
	for _, want := range []string{"dns", "http", "tls", "dhcp"} {
		if !got[want] {
			t.Fatalf("core schema missing %s", want)
		}
	}
	for _, extra := range []string{"mqtt", "redis", "http2", "quic", "bgp"} {
		if got[extra] {
			t.Fatalf("core schema unexpectedly contains %s", extra)
		}
	}
}
