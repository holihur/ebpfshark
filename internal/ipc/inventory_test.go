package ipc

import "testing"

func TestUnixSocketDecoding(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{"0001", "stream"},
		{"0002", "dgram"},
		{"0005", "seqpacket"},
		{"0007", "type-0007"},
	}
	for _, tc := range cases {
		if got := udsType(tc.raw); got != tc.want {
			t.Errorf("udsType(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
	states := map[string]string{"01": "listening", "02": "connecting", "03": "connected", "04": ""}
	for raw, want := range states {
		if got := udsState(raw); got != want {
			t.Errorf("udsState(%q) = %q, want %q", raw, got, want)
		}
	}
	if got := cgroupPath("1:foo:/\n0::/user.slice/app.scope\n"); got != "/user.slice/app.scope" {
		t.Errorf("cgroupPath = %q", got)
	}
	if got := socketTypeName(2); got != "dgram" {
		t.Errorf("socketTypeName(2) = %q", got)
	}
}
