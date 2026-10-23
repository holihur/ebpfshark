//go:build full

package decode

import (
	"fmt"
	"sync"

	"golang.org/x/net/http2/hpack"
)

type h2Pending struct {
	block []byte
	seq   uint32
	off   int
}

type h2Flow struct {
	sync.Mutex
	clientEP, serverEP string
	decC, decS         *hpack.Decoder
	cache              map[string][]hpack.HeaderField
	pending            map[uint32]*h2Pending
	paths              map[uint32]string
	contentTypes       map[uint32]string
	contentEncodings   map[uint32]string
	bodies             map[uint32][]byte
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
			decC:             hpack.NewDecoder(4096, nil),
			decS:             hpack.NewDecoder(4096, nil),
			cache:            make(map[string][]hpack.HeaderField),
			paths:            make(map[uint32]string),
			contentTypes:     make(map[uint32]string),
			contentEncodings: make(map[uint32]string),
			bodies:           make(map[uint32][]byte),
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

func (f *h2Flow) appendBody(stream uint32, chunk []byte, end bool, limit int) []byte {
	f.Lock()
	defer f.Unlock()
	b := append(f.bodies[stream], chunk...)
	if len(b) > limit {
		b = nil
	}
	if end {
		delete(f.bodies, stream)
	}
	if b == nil {
		return nil
	}
	return append([]byte(nil), b...)
}

func (f *h2Flow) setMeta(stream uint32, path, contentType, contentEncoding string) {
	f.Lock()
	defer f.Unlock()
	if path != "" {
		f.paths[stream] = path
	}
	if contentType != "" {
		f.contentTypes[stream] = contentType
	}
	if contentEncoding != "" {
		f.contentEncodings[stream] = contentEncoding
	}
}

func (f *h2Flow) meta(stream uint32) (string, string, string) {
	f.Lock()
	defer f.Unlock()
	return f.paths[stream], f.contentTypes[stream], f.contentEncodings[stream]
}

func (f *h2Flow) startPending(stream uint32, block []byte, seq uint32, off int) {
	f.Lock()
	defer f.Unlock()
	if p, ok := f.pending[stream]; ok && p.seq == seq && p.off == off {
		return
	}
	f.pending[stream] = &h2Pending{block: append([]byte(nil), block...), seq: seq, off: off}
}

func (f *h2Flow) continuePending(stream uint32, fragment []byte, end bool) ([]byte, uint32, int, bool) {
	f.Lock()
	defer f.Unlock()
	p, ok := f.pending[stream]
	if !ok {
		return nil, 0, 0, false
	}
	p.block = append(p.block, fragment...)
	if !end {
		return nil, 0, 0, false
	}
	block, seq, off := p.block, p.seq, p.off
	delete(f.pending, stream)
	return block, seq, off, true
}
