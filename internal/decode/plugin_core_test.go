//go:build !full

package decode

import "testing"

func TestCorePluginChains(t *testing.T) {
	udp := chainNames(appChain(TransportUDP))
	for _, want := range []string{"dns", "dhcp"} {
		if !udp[want] {
			t.Fatalf("core UDP chain missing %q: %v", want, udp)
		}
	}
	tcp := chainNames(appChain(TransportTCP))
	for _, want := range []string{"dns", "http", "tls"} {
		if !tcp[want] {
			t.Fatalf("core TCP chain missing %q: %v", want, tcp)
		}
	}
	if !chainNames(decryptedChain())["http"] {
		t.Fatal("core decrypted chain missing http")
	}
}
