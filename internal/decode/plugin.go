package decode

import (
	"sort"
	"sync"
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
}

var pluginChains struct {
	once sync.Once
	udp  []appDissector
	tcp  []appDissector
	dec  []appDissector
}

func initPluginChains() {
	pluginRegistry.mu.RLock()
	specs := append([]pluginSpec(nil), pluginRegistry.specs...)
	pluginRegistry.mu.RUnlock()
	sort.SliceStable(specs, func(i, j int) bool {
		if specs[i].Priority != specs[j].Priority {
			return specs[i].Priority < specs[j].Priority
		}
		return specs[i].Name < specs[j].Name
	})
	for _, p := range specs {
		d := appDissector{name: p.Name, match: p.Match, dissect: p.Dissect}
		switch {
		case p.Decrypted:
			pluginChains.dec = append(pluginChains.dec, d)
		default:
			if p.Transport&TransportUDP != 0 {
				pluginChains.udp = append(pluginChains.udp, d)
			}
			if p.Transport&TransportTCP != 0 {
				pluginChains.tcp = append(pluginChains.tcp, d)
			}
		}
	}
}

func appChain(t Transport) []appDissector {
	pluginChains.once.Do(initPluginChains)
	if t == TransportTCP {
		return pluginChains.tcp
	}
	return pluginChains.udp
}

func decryptedChain() []appDissector {
	pluginChains.once.Do(initPluginChains)
	return pluginChains.dec
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
