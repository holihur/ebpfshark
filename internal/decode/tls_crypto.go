package decode

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"os"
	"strings"
	"sync"
)

// keylogData maps client_random (lower-case hex) to keylog label -> secret.
var keylogData = struct {
	sync.RWMutex
	m map[string]map[string][]byte
}{m: make(map[string]map[string][]byte)}

// LoadKeyLog loads an NSS SSLKEYLOGFILE. Existing entries are kept so the file
// can be loaded before or after a capture starts.
func LoadKeyLog(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	keylogData.Lock()
	defer keylogData.Unlock()
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) != 3 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		secret, err := hex.DecodeString(fields[2])
		if err != nil {
			continue
		}
		random := strings.ToLower(fields[1])
		if keylogData.m[random] == nil {
			keylogData.m[random] = make(map[string][]byte)
		}
		keylogData.m[random][fields[0]] = secret
	}
	return nil
}

func keylogSecret(clientRandom []byte, labels ...string) []byte {
	if len(clientRandom) == 0 {
		return nil
	}
	key := hex.EncodeToString(clientRandom)
	keylogData.RLock()
	defer keylogData.RUnlock()
	m := keylogData.m[key]
	for _, label := range labels {
		if s := m[label]; len(s) > 0 {
			return append([]byte(nil), s...)
		}
	}
	return nil
}

type tlsFlow struct {
	sync.Mutex
	clientEP, serverEP string
	clientRandom       []byte
	serverRandom       []byte
	version            uint16
	suite              uint16
	hsSeqC, hsSeqS     uint64
	appSeqC, appSeqS   uint64
	seq12C, seq12S     uint64
	cache              map[string]tlsCached
}

type tlsCached struct {
	pt    []byte
	inner byte
	label string
}

var tlsFlows sync.Map // canonical endpoint key -> *tlsFlow

func epKey(c *ctx, ipPort string) string { _ = c; return ipPort }

func tlsFlowKey(c *ctx) string {
	a := fmt.Sprintf("%s:%d", c.m.SrcIP, c.m.SrcPort)
	b := fmt.Sprintf("%s:%d", c.m.DstIP, c.m.DstPort)
	if a > b {
		a, b = b, a
	}
	return a + "|" + b
}

func tlsFlowFor(c *ctx) *tlsFlow {
	key := tlsFlowKey(c)
	if v, ok := tlsFlows.Load(key); ok {
		return v.(*tlsFlow)
	}
	f := &tlsFlow{cache: make(map[string]tlsCached)}
	actual, _ := tlsFlows.LoadOrStore(key, f)
	return actual.(*tlsFlow)
}

func (f *tlsFlow) observeClientHello(c *ctx, random []byte) {
	f.Lock()
	defer f.Unlock()
	f.clientEP = epKey(c, fmt.Sprintf("%s:%d", c.m.SrcIP, c.m.SrcPort))
	f.serverEP = epKey(c, fmt.Sprintf("%s:%d", c.m.DstIP, c.m.DstPort))
	f.clientRandom = append([]byte(nil), random...)
}

func (f *tlsFlow) observeServerHello(c *ctx, random []byte, version, suite uint16) {
	f.Lock()
	defer f.Unlock()
	if f.serverEP == "" {
		src := fmt.Sprintf("%s:%d", c.m.SrcIP, c.m.SrcPort)
		dst := fmt.Sprintf("%s:%d", c.m.DstIP, c.m.DstPort)
		// A ServerHello normally comes from the TLS server.
		f.serverEP, f.clientEP = src, dst
	}
	if len(f.clientEP) == 0 {
		f.clientEP = fmt.Sprintf("%s:%d", c.m.DstIP, c.m.DstPort)
	}
	f.serverRandom = append([]byte(nil), random...)
	f.version = version
	f.suite = suite
}

func (f *tlsFlow) setVersion(v uint16) {
	f.Lock()
	f.version = v
	f.Unlock()
}

func (f *tlsFlow) getVersion() uint16 {
	f.Lock()
	defer f.Unlock()
	return f.version
}

func (f *tlsFlow) randomCopy() []byte {
	f.Lock()
	defer f.Unlock()
	return append([]byte(nil), f.clientRandom...)
}

func (f *tlsFlow) isClient(c *ctx) bool {
	ep := fmt.Sprintf("%s:%d", c.m.SrcIP, c.m.SrcPort)
	if f.clientEP != "" {
		return ep == f.clientEP
	}
	return false
}

func tls13Suite(suite uint16) (keyLen int, hashLen int, ok bool) {
	switch suite {
	case 0x1301:
		return 16, 32, true
	case 0x1302:
		return 32, 48, true
	}
	return 0, 0, false
}

func hkdfExpand(secret, info []byte, n int) []byte {
	var out []byte
	var prev []byte
	for i := byte(1); len(out) < n; i++ {
		h := hmac.New(sha256.New, secret)
		h.Write(prev)
		h.Write(info)
		h.Write([]byte{i})
		prev = h.Sum(nil)
		out = append(out, prev...)
	}
	return out[:n]
}

func hkdfExpandLabel(secret []byte, label string, context []byte, n int) []byte {
	info := make([]byte, 0, 4+len(label)+len(context))
	info = append(info, byte(n>>8), byte(n))
	info = append(info, []byte("tls13 "+label)...)
	info = append(info, byte(len(context)))
	info = append(info, context...)
	return hkdfExpand(secret, info, n)
}

func tls13Keys(secret []byte, suite uint16) ([]byte, []byte, bool) {
	keyLen, _, ok := tls13Suite(suite)
	if !ok {
		return nil, nil, false
	}
	return hkdfExpandLabel(secret, "key", nil, keyLen), hkdfExpandLabel(secret, "iv", nil, 12), true
}

func xorSeq(iv []byte, seq uint64) []byte {
	n := append([]byte(nil), iv...)
	for i := 0; i < 8; i++ {
		n[len(n)-1-i] ^= byte(seq >> (8 * i))
	}
	return n
}

func tls13Open(secret []byte, suite uint16, seq uint64, header, body []byte) ([]byte, byte, bool) {
	key, iv, ok := tls13Keys(secret, suite)
	if !ok || len(body) < 17 {
		return nil, 0, false
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, 0, false
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, 0, false
	}
	pt, err := aead.Open(nil, xorSeq(iv, seq), body, header)
	if err != nil {
		return nil, 0, false
	}
	// TLSInnerPlaintext = content || type || zero padding
	end := len(pt)
	for end > 0 && pt[end-1] == 0 {
		end--
	}
	if end == 0 {
		return nil, 0, false
	}
	innerType := pt[end-1]
	return pt[:end-1], innerType, true
}

func tls12Hash(suite uint16) (func() hash.Hash, int) {
	switch suite {
	case 0xc030, 0xc02c, 0xc02b, 0xc02f:
		return sha512.New384, 48
	}
	return sha256.New, 32
}

func tls12PRF(secret []byte, label string, seed []byte, n int, hf func() hash.Hash) []byte {
	seed = append(append([]byte(nil), []byte(label)...), seed...)
	var out, a []byte
	a = hmacSum(hf, secret, seed)
	for len(out) < n {
		out = append(out, hmacSum(hf, secret, append(append([]byte(nil), a...), seed...))...)
		a = hmacSum(hf, secret, a)
	}
	return out[:n]
}

func hmacSum(hf func() hash.Hash, key, data []byte) []byte {
	m := hmac.New(hf, key)
	m.Write(data)
	return m.Sum(nil)
}

func tls12GCMKeys(master, clientRandom, serverRandom []byte, suite uint16) (ck, sk, civ, siv []byte, ok bool) {
	var keyLen int
	switch suite {
	case 0x009c, 0xc02f, 0xc02b:
		keyLen = 16
	case 0x009d, 0xc030, 0xc02c:
		keyLen = 32
	default:
		return nil, nil, nil, nil, false
	}
	hf, _ := tls12Hash(suite)
	seed := append(append([]byte(nil), serverRandom...), clientRandom...)
	kb := tls12PRF(master, "key expansion", seed, 2*keyLen+8, hf)
	return kb[:keyLen], kb[keyLen : 2*keyLen], kb[2*keyLen : 2*keyLen+4], kb[2*keyLen+4 : 2*keyLen+8], true
}

func tls12Open(key, fixedIV []byte, seq uint64, header, body []byte) ([]byte, bool) {
	if len(body) < 8+16 {
		return nil, false
	}
	explicit := body[:8]
	ct := body[8:]
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, false
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, false
	}
	nonce := append(append([]byte(nil), fixedIV...), explicit...)
	aad := make([]byte, 8+len(header))
	binary.BigEndian.PutUint64(aad, seq)
	copy(aad[8:], header)
	pt, err := aead.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, false
	}
	return pt, true
}

func (f *tlsFlow) decryptRecord(c *ctx, header, body []byte) ([]byte, byte, string, bool) {
	f.Lock()
	defer f.Unlock()
	dir := 0
	if !f.isClient(c) {
		dir = 1
	}
	cacheKey := fmt.Sprintf("%d:%d:%d:%d", dir, c.m.TCPSeq, len(header), len(body))
	if hit, ok := f.cache[cacheKey]; ok {
		return append([]byte(nil), hit.pt...), hit.inner, hit.label, true
	}
	random := f.clientRandom
	if len(random) == 0 {
		return nil, 0, "", false
	}

	// TLS 1.3 (or unknown version with TLS 1.3 traffic secrets).
	try13 := func() ([]byte, byte, string, bool) {
		labels := []string{"CLIENT_HANDSHAKE_TRAFFIC_SECRET", "SERVER_HANDSHAKE_TRAFFIC_SECRET"}
		seqs := []*uint64{&f.hsSeqC, &f.hsSeqS}
		if dir == 1 {
			labels[0], labels[1] = labels[1], labels[0]
			seqs[0], seqs[1] = seqs[1], seqs[0]
		}
		for i := 0; i < 2; i++ {
			secret := keylogSecret(random, labels[i])
			if secret == nil {
				continue
			}
			start := *seqs[i]
			for n := uint64(0); n < 64; n++ {
				seq := start + n
				if pt, inner, ok := tls13Open(secret, f.suite, seq, header, body); ok {
					*seqs[i] = seq + 1
					return pt, inner, labels[i], true
				}
			}
		}
		appLabels := []string{"CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0"}
		appSeqs := []*uint64{&f.appSeqC, &f.appSeqS}
		if dir == 1 {
			appLabels[0], appLabels[1] = appLabels[1], appLabels[0]
			appSeqs[0], appSeqs[1] = appSeqs[1], appSeqs[0]
		}
		for i := 0; i < 2; i++ {
			secret := keylogSecret(random, appLabels[i])
			if secret == nil {
				continue
			}
			start := *appSeqs[i]
			for n := uint64(0); n < 64; n++ {
				seq := start + n
				if pt, inner, ok := tls13Open(secret, f.suite, seq, header, body); ok {
					*appSeqs[i] = seq + 1
					return pt, inner, appLabels[i], true
				}
			}
		}
		return nil, 0, "", false
	}
	if f.version == 0x0304 || keylogSecret(random, "CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0") != nil {
		if pt, inner, label, ok := try13(); ok {
			f.cache[cacheKey] = tlsCached{append([]byte(nil), pt...), inner, label}
			return pt, inner, label, true
		}
	}

	// TLS 1.2 GCM with CLIENT_RANDOM master secret.
	master := keylogSecret(random, "CLIENT_RANDOM")
	if master != nil && len(f.clientRandom) == 32 && len(f.serverRandom) == 32 {
		ck, sk, civ, siv, ok := tls12GCMKeys(master, f.clientRandom, f.serverRandom, f.suite)
		if ok {
			key, iv, seqp := ck, civ, &f.seq12C
			if dir == 1 {
				key, iv, seqp = sk, siv, &f.seq12S
			}
			start := *seqp
			for n := uint64(0); n < 128; n++ {
				seq := start + n
				if pt, ok := tls12Open(key, iv, seq, header, body); ok {
					*seqp = seq + 1
					f.cache[cacheKey] = tlsCached{append([]byte(nil), pt...), 23, "CLIENT_RANDOM"}
					return pt, 23, "CLIENT_RANDOM", true
				}
			}
		}
	}
	return nil, 0, "", false
}
