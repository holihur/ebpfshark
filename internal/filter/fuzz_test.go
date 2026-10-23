package filter

import "testing"

func FuzzCompileCapture(f *testing.F) {
	for _, s := range []string{
		"", "tcp", "tcp port 443", "udp and host 10.0.0.5",
		"net 10.0.0.0/8", "vlan.id == 100", "http.host contains example",
		"tcp and (port 80 or port 443)", "not tcp", "ip.addr == 2001:db8::1",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 4096 {
			t.Skip()
		}
		spec, err := CompileCapture(input)
		if err != nil {
			return
		}
		if spec.SrcPortLo != 0 && spec.SrcPortHi != 0 && spec.SrcPortLo > spec.SrcPortHi {
			t.Fatalf("invalid source port range: %+v", spec)
		}
		if spec.DstPortLo != 0 && spec.DstPortHi != 0 && spec.DstPortLo > spec.DstPortHi {
			t.Fatalf("invalid destination port range: %+v", spec)
		}
		if spec.SrcMask > 32 || spec.DstMask > 32 {
			t.Fatalf("invalid IPv4 mask: %+v", spec)
		}
		if spec.SrcIPv4.IsValid() && !spec.SrcIPv4.Is4() {
			t.Fatalf("non-IPv4 source in IPv4 slot: %+v", spec)
		}
		if spec.DstIPv4.IsValid() && !spec.DstIPv4.Is4() {
			t.Fatalf("non-IPv4 destination in IPv4 slot: %+v", spec)
		}
	})
}
