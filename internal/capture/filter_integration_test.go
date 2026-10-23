//go:build linux

package capture

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	"ebpfshark/internal/filter"
	"ebpfshark/internal/store"
)

// TestKernelCaptureFilter exercises the TCX prefilter with a veth pair. It is
// intentionally opt-in because it needs root/CAP_BPF/CAP_NET_ADMIN:
//
//	EBPFSHARK_PRIVILEGED=1 go test -run TestKernelCaptureFilter ./internal/capture
func TestKernelCaptureFilter(t *testing.T) {
	if os.Getenv("EBPFSHARK_PRIVILEGED") != "1" {
		t.Skip("set EBPFSHARK_PRIVILEGED=1 and run as root")
	}
	if os.Geteuid() != 0 {
		t.Skip("root is required for TCX attachment")
	}
	name := fmt.Sprintf("es%d", os.Getpid()%100000)
	peer := name + "p"
	ns := name + "ns"
	if len(name) > 12 || len(peer) > 14 || len(ns) > 14 {
		t.Skip("interface/netns name too long")
	}
	runIP := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %v: %s", args, err, out)
		}
	}
	runIP("netns", "add", ns)
	defer func() { _ = exec.Command("ip", "netns", "del", ns).Run() }()
	runIP("link", "add", name, "type", "veth", "peer", "name", peer)
	runIP("link", "set", peer, "netns", ns)
	runIP("addr", "add", "10.255.0.1/30", "dev", name)
	runIP("link", "set", name, "up")
	runIP("-n", ns, "addr", "add", "10.255.0.2/30", "dev", peer)
	runIP("-n", ns, "link", "set", peer, "up")
	runIP("-n", ns, "link", "set", "lo", "up")

	st := store.New(128)
	mgr := NewManager(st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := mgr.Start(Options{
		Interfaces:    []string{name},
		Snaplen:       128,
		SampleRate:    1,
		RingSize:      1 << 20,
		CaptureFilter: filter.CaptureSpec{Proto: 17, DstPortLo: 9999, DstPortHi: 9999},
	}); err != nil {
		t.Fatalf("start capture: %v", err)
	}
	defer mgr.Stop()

	send := func(port int) {
		c, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("10.255.0.2"), Port: port})
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		_, _ = c.Write([]byte("ebpfshark-filter-test"))
		_ = c.Close()
	}
	send(9999)
	send(9998)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		found := false
		for _, p := range st.All(nil) {
			if p.Meta.DstPort == 9999 {
				found = true
				break
			}
		}
		if found && mgr.Status().KernelFiltered > 0 {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("capture=%+v filtered=%d", st.Stats(), mgr.Status().KernelFiltered)
}
