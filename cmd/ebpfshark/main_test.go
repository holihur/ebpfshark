package main

import "testing"

func TestListenPort(t *testing.T) {
	cases := []struct {
		addr string
		want uint16
	}{
		{":9999", 9999},
		{"127.0.0.1:9999", 9999},
		{"0.0.0.0:8080", 8080},
		{"[::1]:9999", 9999},
		{"localhost", 0},
		{":notaport", 0},
		{":70000", 0},
	}
	for _, tc := range cases {
		if got := listenPort(tc.addr); got != tc.want {
			t.Errorf("listenPort(%q) = %d, want %d", tc.addr, got, tc.want)
		}
	}
}
