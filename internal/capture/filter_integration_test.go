//go:build linux

package capture

import (
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	"golang.org/x/sys/unix"

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

	// Inject an Ethernet/IPv4/UDP frame directly on the veth. This avoids
	// flaky neighbour resolution while still exercising the TCX egress path.
	send := func(port int) {
		t.Helper()
		fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
		if err != nil {
			t.Fatalf("packet socket: %v", err)
		}
		defer unix.Close(fd)
		ifi, err := netInterface(name)
		if err != nil {
			t.Fatalf("interface %s: %v", name, err)
		}
		frame := udpFrame(uint16(port))
		addr := &unix.SockaddrLinklayer{
			Protocol: htons(unix.ETH_P_IP), Ifindex: ifi,
			Halen: 6, Addr: [8]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		}
		if err := unix.Sendto(fd, frame, 0, addr); err != nil {
			t.Fatalf("send raw frame: %v", err)
		}
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

func netInterface(name string) (int, error) {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return 0, err
	}
	return ifi.Index, nil
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

func udpFrame(dstPort uint16) []byte {
	const ethLen, ipLen, udpLen = 14, 20, 8
	payload := []byte("ebpfshark-filter-test")
	frame := make([]byte, ethLen+ipLen+udpLen+len(payload))
	copy(frame[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(frame[6:12], []byte{0x02, 0, 0, 0, 0, 1})
	binary.BigEndian.PutUint16(frame[12:14], unix.ETH_P_IP)
	ip := frame[ethLen:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(ipLen+udpLen+len(payload)))
	ip[8] = 64
	ip[9] = unix.IPPROTO_UDP
	copy(ip[12:16], []byte{10, 255, 0, 1})
	copy(ip[16:20], []byte{10, 255, 0, 2})
	binary.BigEndian.PutUint16(ip[10:12], checksum(ip[:ipLen]))
	udp := ip[ipLen:]
	binary.BigEndian.PutUint16(udp[0:2], 50000)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen+len(payload)))
	copy(udp[udpLen:], payload)
	return frame
}

func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
