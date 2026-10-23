//go:build cgo && (linux || darwin || freebsd)

package decode

import (
	"encoding/binary"
	"os"
	"strings"
	"testing"

	"ebpfshark/internal/packet"
)

func TestLoadDynamicPlugin(t *testing.T) {
	path := os.Getenv("EBPFSHARK_TEST_PLUGIN")
	if path == "" {
		t.Skip("set EBPFSHARK_TEST_PLUGIN to a buildmode=plugin .so")
	}
	if err := LoadDynamicPlugins([]string{path}); err != nil {
		t.Fatalf("load plugin: %v", err)
	}
	udp := chainNames(appChain(TransportUDP))
	if !udp["demo"] {
		t.Fatalf("demo plugin not registered: %v", udp)
	}
	b := make([]byte, 14+20+8+2)
	binary.BigEndian.PutUint16(b[12:14], 0x0800)
	b[14] = 0x45
	binary.BigEndian.PutUint16(b[16:18], 30)
	b[23] = 17
	copy(b[26:30], []byte{10, 0, 0, 1})
	copy(b[30:34], []byte{10, 0, 0, 2})
	binary.BigEndian.PutUint16(b[34:36], 12345)
	binary.BigEndian.PutUint16(b[36:38], 9999)
	binary.BigEndian.PutUint16(b[38:40], 10)
	copy(b[42:], "hi")
	res := Decode(b, packet.LinkEthernet, len(b))
	if !res.Meta.HasLayer("demo") || !strings.Contains(res.Summary.Info, "demo payload") {
		t.Fatalf("layers=%v info=%q", res.Meta.Layers, res.Summary.Info)
	}
}
