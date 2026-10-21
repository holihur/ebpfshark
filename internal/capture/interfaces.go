package capture

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// Interface describes a capture-capable network interface.
type Interface struct {
	Name     string   `json:"name"`
	Index    int      `json:"index"`
	MAC      string   `json:"mac"`
	MTU      int      `json:"mtu"`
	Up       bool     `json:"up"`
	Loopback bool     `json:"loopback"`
	Default  bool     `json:"default"`
	Kind     string   `json:"kind"`
	Addrs    []string `json:"addrs"`
}

// ListInterfaces enumerates network interfaces with the metadata the UI needs.
func ListInterfaces() ([]Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	def := defaultRouteInterface()
	out := make([]Interface, 0, len(ifaces))
	for _, ifi := range ifaces {
		it := Interface{
			Name:     ifi.Name,
			Index:    ifi.Index,
			MAC:      ifi.HardwareAddr.String(),
			MTU:      ifi.MTU,
			Up:       ifi.Flags&net.FlagUp != 0,
			Loopback: ifi.Flags&net.FlagLoopback != 0,
			Default:  ifi.Name == def,
			Kind:     interfaceKind(ifi),
			Addrs:    []string{},
		}
		if addrs, err := ifi.Addrs(); err == nil {
			for _, a := range addrs {
				it.Addrs = append(it.Addrs, a.String())
			}
		}
		out = append(out, it)
	}
	return out, nil
}

func interfaceKind(ifi net.Interface) string {
	name := ifi.Name
	switch {
	case ifi.Flags&net.FlagLoopback != 0:
		return "loopback"
	case strings.HasPrefix(name, "wg"):
		return "wireguard"
	case strings.HasPrefix(name, "tun"), strings.HasPrefix(name, "tap"):
		return "tunnel"
	case strings.HasPrefix(name, "docker"), strings.HasPrefix(name, "veth"):
		return "veth"
	case strings.HasPrefix(name, "br-"), strings.HasPrefix(name, "virbr"):
		return "bridge"
	case strings.HasPrefix(name, "bond"):
		return "bond"
	case strings.HasPrefix(name, "wlan"), strings.HasPrefix(name, "wlp"):
		return "wireless"
	}
	if _, err := os.Stat("/sys/class/net/" + name + "/device"); err == nil {
		return "ethernet"
	}
	if t, err := os.ReadFile("/sys/class/net/" + name + "/type"); err == nil {
		switch strings.TrimSpace(string(t)) {
		case "772":
			return "loopback"
		case "65534":
			return "tunnel"
		}
	}
	return "virtual"
}

// defaultRouteInterface returns the interface carrying the lowest-metric IPv4
// default route (or the IPv6 default route when no IPv4 one exists).
func defaultRouteInterface() string {
	if name := parseProcRoute("/proc/net/route", "00000000", 0, 1, 3, 7); name != "" {
		return name
	}
	// /proc/net/ipv6_route: 36 hex chars dest, prefix len, ...
	if f, err := os.Open("/proc/net/ipv6_route"); err == nil {
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) < 10 {
				continue
			}
			if fields[0] != "00000000000000000000000000000000" {
				continue
			}
			if strings.TrimLeft(fields[1], "0") != "" { // prefix length != 0
				continue
			}
			return fields[len(fields)-1]
		}
	}
	return ""
}

func parseProcRoute(path string, wantDest string, ifaceIdx, destIdx, flagsIdx, metricIdx int) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	best := ""
	bestMetric := int64(1<<62 - 1)
	sc.Scan() // header
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) <= metricIdx {
			continue
		}
		if !strings.EqualFold(fields[destIdx], wantDest) {
			continue
		}
		flags, err := strconv.ParseInt(fields[flagsIdx], 16, 32)
		if err != nil || flags&0x1 == 0 {
			continue
		}
		metric, err := strconv.ParseInt(fields[metricIdx], 10, 64)
		if err != nil {
			continue
		}
		if metric < bestMetric {
			bestMetric = metric
			best = fields[ifaceIdx]
		}
	}
	return best
}

// ResolveIndexes maps interface names to indexes, validating that every name
// exists.
func ResolveIndexes(names []string) (map[string]int, error) {
	out := make(map[string]int, len(names))
	for _, n := range names {
		ifi, err := net.InterfaceByName(n)
		if err != nil {
			return nil, fmt.Errorf("interface %q: %w", n, err)
		}
		out[n] = ifi.Index
	}
	return out, nil
}
