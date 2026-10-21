package decode

// appDissector is a strategy entry in the application-layer dissector chain.
// Each protocol supplies a cheap matcher and a dissector; the first matcher
// that accepts the payload wins. This keeps port/protocol dispatch declarative
// and makes the core/full build split a matter of choosing a registry.
type appDissector struct {
	name    string
	match   func(c *ctx, sport, dport uint16, b []byte) bool
	dissect func(c *ctx, b []byte, base int) bool
}

func runDissectors(c *ctx, b []byte, base int, sport, dport uint16, chain []appDissector) bool {
	for _, d := range chain {
		if d.match == nil || d.match(c, sport, dport, b) {
			if d.dissect(c, b, base) {
				return true
			}
		}
	}
	return false
}

func portMatch(ports map[uint16]bool) func(*ctx, uint16, uint16, []byte) bool {
	return func(_ *ctx, sport, dport uint16, _ []byte) bool {
		return ports[sport] || ports[dport]
	}
}
