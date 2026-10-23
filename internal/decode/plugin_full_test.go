//go:build full

package decode

import "testing"

func TestFullPluginChains(t *testing.T) {
	udp := chainNames(appChain(TransportUDP))
	for _, want := range []string{"dns", "dhcp", "ntp", "snmp", "stun", "vxlan", "wireguard", "ssdp", "sip", "radius", "netflow", "rtp", "quic", "coap", "mqttsn", "mpegts"} {
		if !udp[want] {
			t.Fatalf("full UDP chain missing %q: %v", want, udp)
		}
	}
	tcp := chainNames(appChain(TransportTCP))
	for _, want := range []string{"http2", "ssh", "redis", "postgresql", "mysql", "mqtt", "bgp", "sip", "radius", "netflow", "rtp", "syslog", "websocket", "http", "tls", "modbus", "rtsp"} {
		if !tcp[want] {
			t.Fatalf("full TCP chain missing %q: %v", want, tcp)
		}
	}
	dec := chainNames(decryptedChain())
	for _, want := range []string{"websocket", "http2", "http"} {
		if !dec[want] {
			t.Fatalf("full decrypted chain missing %q: %v", want, dec)
		}
	}
}
