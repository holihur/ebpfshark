package filter

import "testing"

func TestCompileCapture(t *testing.T) {
	s, err := CompileCapture("tcp port 443")
	if err != nil {
		t.Fatal(err)
	}
	if s.Proto != 6 || s.SrcPortLo != 443 || s.DstPortLo != 443 {
		t.Fatalf("spec=%+v", s)
	}
	s, _ = CompileCapture("udp and host 10.0.0.5")
	if s.Proto != 17 || !s.SrcIPv4.IsValid() || !s.DstIPv4.IsValid() {
		t.Fatalf("spec=%+v", s)
	}
	if s, _ = CompileCapture("http.host contains example"); !s.Empty() {
		t.Fatalf("app filter must not push kernel filter: %+v", s)
	}
	if s, _ = CompileCapture("tcp port 80 or udp port 53"); !s.Empty() {
		t.Fatalf("or must not push a partial filter: %+v", s)
	}
	if s, _ = CompileCapture("tcp and (port 80 or port 443)"); s.Proto != 6 || s.SrcPortLo != 0 {
		t.Fatalf("only safe AND term should survive: %+v", s)
	}
	if s, _ = CompileCapture("vlan"); !s.HasVLAN || s.VLAN != 0xffff {
		t.Fatalf("vlan any spec=%+v", s)
	}
}
