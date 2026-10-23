package decode

import (
	"sort"
	"sync"
	"sync/atomic"
)

// Transport identifies the transport protocol a dissector handles.
type Transport uint8

const (
	TransportUDP Transport = 1 << iota
	TransportTCP
)

// pluginSpec is the registration unit for an application-layer dissector.
// Protocol modules register themselves during init; the registry builds the
// ordered matcher/dissector chain used by the core decoder.
type pluginSpec struct {
	Name      string
	Priority  int
	Transport Transport
	Decrypted bool
	Match     func(c *ctx, sport, dport uint16, b []byte) bool
	Dissect   func(c *ctx, b []byte, base int) bool
	Display   string
}

var pluginRegistry struct {
	mu    sync.RWMutex
	specs []pluginSpec
}

// RegisterPlugin adds an application dissector. Lower priorities run first.
// It is intended for init-time registration by protocol modules.
func RegisterPlugin(p pluginSpec) {
	if p.Name == "" || p.Dissect == nil {
		return
	}
	pluginRegistry.mu.Lock()
	pluginRegistry.specs = append(pluginRegistry.specs, p)
	pluginRegistry.mu.Unlock()
	pluginVersion.Add(1)
}

var pluginVersion atomic.Uint64

var pluginChains struct {
	mu      sync.RWMutex
	version uint64
	udp     []appDissector
	tcp     []appDissector
	dec     []appDissector
}

func buildPluginChains() ([]appDissector, []appDissector, []appDissector) {
	pluginRegistry.mu.RLock()
	specs := append([]pluginSpec(nil), pluginRegistry.specs...)
	pluginRegistry.mu.RUnlock()
	sort.SliceStable(specs, func(i, j int) bool {
		if specs[i].Priority != specs[j].Priority {
			return specs[i].Priority < specs[j].Priority
		}
		return specs[i].Name < specs[j].Name
	})
	var udp, tcp, dec []appDissector
	for _, p := range specs {
		d := appDissector{name: p.Name, match: p.Match, dissect: p.Dissect}
		switch {
		case p.Decrypted:
			dec = append(dec, d)
		default:
			if p.Transport&TransportUDP != 0 {
				udp = append(udp, d)
			}
			if p.Transport&TransportTCP != 0 {
				tcp = append(tcp, d)
			}
		}
	}
	return udp, tcp, dec
}

func chainFor(version uint64) ([]appDissector, []appDissector, []appDissector) {
	pluginChains.mu.RLock()
	if pluginChains.version == version {
		udp, tcp, dec := pluginChains.udp, pluginChains.tcp, pluginChains.dec
		pluginChains.mu.RUnlock()
		return udp, tcp, dec
	}
	pluginChains.mu.RUnlock()
	pluginChains.mu.Lock()
	defer pluginChains.mu.Unlock()
	if pluginChains.version != version {
		pluginChains.udp, pluginChains.tcp, pluginChains.dec = buildPluginChains()
		pluginChains.version = version
	}
	return pluginChains.udp, pluginChains.tcp, pluginChains.dec
}

func appChain(t Transport) []appDissector {
	udp, tcp, _ := chainFor(pluginVersion.Load())
	if t == TransportTCP {
		return tcp
	}
	return udp
}

func decryptedChain() []appDissector {
	_, _, dec := chainFor(pluginVersion.Load())
	return dec
}

func displayName(name string) string {
	pluginRegistry.mu.RLock()
	defer pluginRegistry.mu.RUnlock()
	for _, p := range pluginRegistry.specs {
		if p.Name == name && p.Display != "" {
			return p.Display
		}
	}
	return ""
}
