//go:build full

package decode

import (
	"fmt"
	"sync"

	"golang.org/x/net/http2/hpack"
)

type h2Flow struct {
	sync.Mutex
	clientEP, serverEP string
	decC, decS         *hpack.Decoder
	cache              map[string][]hpack.HeaderField
}

var h2Flows = flowStore[*h2Flow]{max: 2048}

func h2FlowKey(c *ctx) string {
	a := fmt.Sprintf("%s:%d", c.m.SrcIP, c.m.SrcPort)
	b := fmt.Sprintf("%s:%d", c.m.DstIP, c.m.DstPort)
	if a > b {
		a, b = b, a
	}
	return a + "|" + b
}

func h2FlowFor(c *ctx) *h2Flow {
	key := h2FlowKey(c)
	return h2Flows.GetOrCreate(key, func() *h2Flow {
		return &h2Flow{
			decC:  hpack.NewDecoder(4096, nil),
			decS:  hpack.NewDecoder(4096, nil),
			cache: make(map[string][]hpack.HeaderField),
		}
	})
}

func (f *h2Flow) observeClient(c *ctx) {
	f.Lock()
	defer f.Unlock()
	if f.clientEP == "" {
		f.clientEP = fmt.Sprintf("%s:%d", c.m.SrcIP, c.m.SrcPort)
		f.serverEP = fmt.Sprintf("%s:%d", c.m.DstIP, c.m.DstPort)
	}
}

func (f *h2Flow) isClient(c *ctx) bool {
	ep := fmt.Sprintf("%s:%d", c.m.SrcIP, c.m.SrcPort)
	if f.clientEP != "" {
		return ep == f.clientEP
	}
	// Without a preface, the destination is usually the server.
	return httpPorts[c.m.DstPort] || tlsPorts[c.m.DstPort]
}

func (f *h2Flow) decodeHeaders(c *ctx, block []byte, seq uint32, off int) ([]hpack.HeaderField, error) {
	f.Lock()
	defer f.Unlock()
	cacheKey := fmt.Sprintf("%t:%d:%d", f.isClient(c), seq, off)
	if v, ok := f.cache[cacheKey]; ok {
		return v, nil
	}
	dec := f.decC
	if !f.isClient(c) {
		dec = f.decS
	}
	fields, err := dec.DecodeFull(block)
	if err != nil {
		return nil, err
	}
	f.cache[cacheKey] = fields
	return fields, nil
}
