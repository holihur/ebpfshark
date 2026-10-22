package decode

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"os"
	"sync"
)

type sshKeySpec struct {
	Cipher string `json:"cipher"`
	Key    string `json:"key"`
	IV     string `json:"iv"`
	MAC    string `json:"mac"`
	MACKey string `json:"mackey"`
}

type sshKeyConfig struct {
	ClientToServer sshKeySpec `json:"client_to_server"`
	ServerToClient sshKeySpec `json:"server_to_client"`
}

var sshKeyFile struct {
	sync.RWMutex
	cfg *sshKeyConfig
}

// LoadSSHKeys loads an opt-in session-key file. SSH private keys cannot
// decrypt modern sessions; this file must contain the negotiated traffic
// keys captured out-of-band.
func LoadSSHKeys(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var cfg sshKeyConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return err
	}
	sshKeyFile.Lock()
	sshKeyFile.cfg = &cfg
	sshKeyFile.Unlock()
	return nil
}

func sshSpec(spec sshKeySpec) (cipher.Block, []byte, []byte, func() hash.Hash, int, error) {
	key, err := hex.DecodeString(spec.Key)
	if err != nil {
		return nil, nil, nil, nil, 0, err
	}
	iv, err := hex.DecodeString(spec.IV)
	if err != nil {
		return nil, nil, nil, nil, 0, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, nil, nil, 0, err
	}
	var macKey []byte
	var hf func() hash.Hash
	macLen := 0
	switch spec.MAC {
	case "", "none":
	case "hmac-sha1":
		hf, macLen = sha1.New, 20
	case "hmac-sha2-256":
		hf, macLen = sha256.New, 32
	case "hmac-sha2-512":
		hf, macLen = sha256.New, 64
	default:
		return nil, nil, nil, nil, 0, fmt.Errorf("unsupported SSH MAC %q", spec.MAC)
	}
	if hf != nil {
		macKey, err = hex.DecodeString(spec.MACKey)
		if err != nil {
			return nil, nil, nil, nil, 0, err
		}
	}
	return block, iv, macKey, hf, macLen, nil
}

type sshDir struct {
	active bool
	stream cipher.Stream
	seq    uint32
	cache  map[uint32][]byte
}

type sshFlow struct {
	sync.Mutex
	c2s, s2c sshDir
}

var sshFlows = flowStore[*sshFlow]{max: 1024}

func sshFlowFor(c *ctx) *sshFlow {
	key := tlsFlowKey(c)
	return sshFlows.GetOrCreate(key, func() *sshFlow {
		return &sshFlow{c2s: sshDir{cache: make(map[uint32][]byte)}, s2c: sshDir{cache: make(map[uint32][]byte)}}
	})
}

func sshDirection(c *ctx) int {
	if c.m.DstPort == 22 {
		return 0
	}
	if c.m.SrcPort == 22 {
		return 1
	}
	return 0
}

func (f *sshFlow) dir(c *ctx) *sshDir {
	if sshDirection(c) == 0 {
		return &f.c2s
	}
	return &f.s2c
}

func (f *sshFlow) markNewKeys(c *ctx) {
	f.Lock()
	d := f.dir(c)
	d.active = true
	d.stream = nil
	d.seq = 0
	d.cache = make(map[uint32][]byte)
	f.Unlock()
}

func (f *sshFlow) decryptPacket(c *ctx, b []byte) ([]byte, bool) {
	f.Lock()
	defer f.Unlock()
	d := f.dir(c)
	if !d.active {
		return nil, false
	}
	if cached, ok := d.cache[c.m.TCPSeq]; ok {
		return cached, true
	}
	sshKeyFile.RLock()
	cfg := sshKeyFile.cfg
	sshKeyFile.RUnlock()
	if cfg == nil {
		return nil, false
	}
	spec := cfg.ClientToServer
	if sshDirection(c) == 1 {
		spec = cfg.ServerToClient
	}
	block, iv, macKey, hf, macLen, err := sshSpec(spec)
	if err != nil {
		return nil, false
	}
	if d.stream == nil {
		d.stream = cipher.NewCTR(block, iv)
	}
	if len(b) < 4 {
		return nil, false
	}
	lengthBytes := make([]byte, 4)
	d.stream.XORKeyStream(lengthBytes, b[:4])
	pktLen := int(binary.BigEndian.Uint32(lengthBytes))
	if pktLen < 2 || pktLen > 1<<20 || 4+pktLen > len(b) {
		return nil, false
	}
	body := make([]byte, pktLen)
	d.stream.XORKeyStream(body, b[4:4+pktLen])
	if hf != nil && macLen > 0 {
		if 4+pktLen+macLen > len(b) {
			return nil, false
		}
		m := hmac.New(hf, macKey)
		var seq [4]byte
		binary.BigEndian.PutUint32(seq[:], d.seq)
		m.Write(seq[:])
		m.Write(lengthBytes)
		m.Write(body)
		if !hmac.Equal(m.Sum(nil), b[4+pktLen:4+pktLen+macLen]) {
			return nil, false
		}
	}
	d.seq++
	plain := append(lengthBytes, body...)
	d.cache[c.m.TCPSeq] = plain
	return plain, true
}
