package filter

import "testing"

func TestSchema(t *testing.T) {
	seen := map[string]bool{}
	for _, f := range Schema() {
		if f.Name == "" || f.Group == "" || f.Type == "" {
			t.Fatalf("incomplete schema entry: %+v", f)
		}
		if seen[f.Name] {
			t.Fatalf("duplicate field %q", f.Name)
		}
		seen[f.Name] = true
		if !IsValidField(f.Name) {
			t.Errorf("schema field %q is not accepted by IsValidField", f.Name)
		}
		switch f.Type {
		case "layer":
			if !isProtoName(f.Name) {
				t.Errorf("layer field %q is not a protocol", f.Name)
			}
		case "bytes":
			if len(f.Ops) == 0 || f.Ops[0] != "contains" {
				t.Errorf("byte field %q must support contains", f.Name)
			}
		default:
			if len(f.Ops) == 0 {
				t.Errorf("field %q has no operators", f.Name)
			}
		}
	}
	for _, name := range []string{"ip.addr", "tcp.dstport", "http.request.method", "tls.handshake.extensions_server_name", "frame"} {
		if !seen[name] {
			t.Errorf("schema is missing %q", name)
		}
	}
}
