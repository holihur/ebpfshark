package decode

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"sync"

	"golang.org/x/crypto/pbkdf2"
)

var wifiKeys = struct {
	sync.Mutex
	psk      string
	ssids    map[string]string
	sessions map[string]*wifiSession
}{ssids: make(map[string]string), sessions: make(map[string]*wifiSession)}

type wifiSession struct {
	ssid           string
	anonce, snonce []byte
	pmk, ptk, tk   []byte
}

// LoadWiFiPSK enables WPA2-PSK/CCMP decryption. SSID and 4-way nonces must be
// present in the capture.
func LoadWiFiPSK(psk string) {
	wifiKeys.Lock()
	wifiKeys.psk = psk
	wifiKeys.Unlock()
}

func wifiKey(a, b string) string {
	if a > b {
		a, b = b, a
	}
	return a + "|" + b
}

func wifiSetSSID(bssid, ssid string) {
	if bssid == "" || ssid == "" {
		return
	}
	wifiKeys.Lock()
	wifiKeys.ssids[bssid] = ssid
	wifiKeys.Unlock()
}

func wifiPMK(psk, ssid string) []byte {
	return pbkdf2.Key([]byte(psk), []byte(ssid), 4096, 32, sha1.New)
}

func wifiPRF(key []byte, label string, data []byte, n int) []byte {
	out := make([]byte, 0, n)
	for i := byte(0); len(out) < n; i++ {
		m := hmac.New(sha1.New, key)
		m.Write([]byte(label))
		m.Write([]byte{0})
		m.Write(data)
		m.Write([]byte{i})
		out = append(out, m.Sum(nil)...)
	}
	return out[:n]
}

func wifiDerive(s *wifiSession, ap, sta string) {
	wifiKeys.Lock()
	psk := wifiKeys.psk
	ssid := s.ssid
	if ssid == "" {
		ssid = wifiKeys.ssids[ap]
	}
	wifiKeys.Unlock()
	if psk == "" || ssid == "" || len(s.anonce) != 32 || len(s.snonce) != 32 {
		return
	}
	pmk := s.pmk
	if len(pmk) == 0 {
		pmk = wifiPMK(psk, ssid)
	}
	a, b := ap, sta
	if a > b {
		a, b = b, a
	}
	// PTK = PRF-512(PMK, "Pairwise key expansion", min(AP,STA)||max(AP,STA)||
	//                min(ANonce,SNonce)||max(ANonce,SNonce))
	var data []byte
	data = append(data, a...)
	data = append(data, b...)
	n1, n2 := s.anonce, s.snonce
	if string(n1) > string(n2) {
		n1, n2 = n2, n1
	}
	data = append(data, n1...)
	data = append(data, n2...)
	s.ptk = wifiPRF(pmk, "Pairwise key expansion", data, 48)
	s.tk = s.ptk[:16]
	wifiKeys.Lock()
	wifiKeys.sessions[wifiKey(ap, sta)] = s
	wifiKeys.Unlock()
}

func wifiHandshake(ap, sta string, keyInfo uint16, nonce []byte) {
	key := wifiKey(ap, sta)
	wifiKeys.Lock()
	s := wifiKeys.sessions[key]
	if s == nil {
		s = &wifiSession{}
		wifiKeys.sessions[key] = s
	}
	wifiKeys.Unlock()
	if keyInfo&0x80 != 0 { // message 1/3: AP nonce
		s.anonce = append([]byte(nil), nonce...)
	} else if keyInfo&0x08 != 0 && !allZero(nonce) { // message 2: STA nonce
		s.snonce = append([]byte(nil), nonce...)
	}
	if len(s.anonce) == 32 && len(s.snonce) == 32 {
		wifiDerive(s, ap, sta)
	}
}

func aesGCMOpen(key, nonce, aad, ct, tag []byte) ([]byte, bool) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, false
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil || len(nonce) != gcm.NonceSize() {
		return nil, false
	}
	buf := append(append([]byte(nil), ct...), tag...)
	pt, err := gcm.Open(nil, nonce, buf, aad)
	return pt, err == nil
}

func wifiTK(ap, sta string) []byte {
	wifiKeys.Lock()
	defer wifiKeys.Unlock()
	s := wifiKeys.sessions[wifiKey(ap, sta)]
	if s == nil || len(s.tk) == 0 {
		return nil
	}
	return append([]byte(nil), s.tk...)
}

func aesCCMOpen(key, nonce, aad, ct, tag []byte) ([]byte, bool) {
	if len(key) != 16 || len(nonce) != 13 || len(tag) != 8 || len(ct) < 0 {
		return nil, false
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, false
	}
	// B0: flags | nonce | msg length (L=2)
	b0 := make([]byte, 16)
	b0[0] = 0x59 // Adata + (M=8 -> 6<<3) + (L-1=1)
	copy(b0[1:14], nonce)
	binary.BigEndian.PutUint16(b0[14:16], uint16(len(ct)))
	mac := make([]byte, 16)
	block.Encrypt(mac, b0)
	// AAD length and data.
	if len(aad) > 0 {
		var alen [2]byte
		binary.BigEndian.PutUint16(alen[:], uint16(len(aad)))
		mac = ccmMAC(block, mac, append(alen[:], aad...))
	}
	// Decrypt CTR.
	pt := make([]byte, len(ct))
	ctr := make([]byte, 16)
	ctr[0] = 1 // L'=1
	copy(ctr[1:14], nonce)
	for off := 0; off < len(ct); off += 16 {
		binary.BigEndian.PutUint16(ctr[14:16], uint16(off/16+1))
		ks := make([]byte, 16)
		block.Encrypt(ks, ctr)
		for i := 0; i < 16 && off+i < len(ct); i++ {
			pt[off+i] = ct[off+i] ^ ks[i]
		}
	}
	mac = ccmMAC(block, mac, pt)
	// Tag = T xor S0.
	s0 := make([]byte, 16)
	ctr[14], ctr[15] = 0, 0
	block.Encrypt(s0, ctr)
	want := make([]byte, 8)
	for i := 0; i < 8; i++ {
		want[i] = mac[i] ^ s0[i]
	}
	if subtle.ConstantTimeCompare(want, tag) != 1 {
		return nil, false
	}
	return pt, true
}

func ccmMAC(block interface{ Encrypt(dst, src []byte) }, mac, data []byte) []byte {
	out := make([]byte, 16)
	copy(out, mac)
	for len(data) > 0 {
		n := 16
		if len(data) < n {
			n = len(data)
		}
		for i := 0; i < n; i++ {
			out[i] ^= data[i]
		}
		block.Encrypt(out, out)
		data = data[n:]
	}
	return out
}

func wifiDecryptFrame(b []byte, hdr int, fc uint16, addr1, addr2, addr3 string) ([]byte, string, bool) {
	if hdr+8+8 > len(b) || fc&0x4000 == 0 {
		return nil, "", false
	}
	toDS, fromDS := fc&0x0100 != 0, fc&0x0200 != 0
	ap, sta := addr1, addr2
	if fromDS && !toDS {
		ap, sta = addr2, addr1
	} else if !toDS && !fromDS {
		ap, sta = addr3, addr2
	}
	tk := wifiTK(ap, sta)
	if len(tk) == 0 {
		return nil, "", false
	}
	ccmp := b[hdr : hdr+8]
	pn := []byte{ccmp[0], ccmp[1], ccmp[4], ccmp[5], ccmp[6], ccmp[7]}
	aad := append([]byte(nil), b[:hdr]...)
	aad[1] &^= 0x08 // Retry bit is cleared in the AAD.
	// CCMP: 8-byte tag, nonce = priority || A2 || PN.
	if len(b) >= hdr+8+8 {
		nonce := append([]byte{0}, macBytes(addr2)...)
		nonce = append(nonce, pn...)
		if pt, ok := aesCCMOpen(tk, nonce, aad, b[hdr+8:len(b)-8], b[len(b)-8:]); ok {
			return pt, ap, true
		}
	}
	// GCMP: 16-byte tag, nonce = A2 || PN.
	if len(b) >= hdr+8+16 {
		nonce := append(macBytes(addr2), pn...)
		keys := [][]byte{tk}
		if len(tk) >= 32 {
			keys = append(keys, tk[:32])
		}
		for _, key := range keys {
			if pt, ok := aesGCMOpen(key, nonce, aad, b[hdr+8:len(b)-16], b[len(b)-16:]); ok {
				return pt, ap, true
			}
		}
	}
	return nil, "", false
}

func macBytes(s string) []byte {
	if len(s) != 17 {
		return make([]byte, 6)
	}
	var out [6]byte
	for i := 0; i < 6; i++ {
		var v byte
		for j := 0; j < 2; j++ {
			c := s[i*3+j]
			v <<= 4
			switch {
			case c >= '0' && c <= '9':
				v |= c - '0'
			case c >= 'a' && c <= 'f':
				v |= c - 'a' + 10
			case c >= 'A' && c <= 'F':
				v |= c - 'A' + 10
			}
		}
		out[i] = v
	}
	return out[:]
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

type wifiKeyFile struct {
	Sessions []struct {
		AP     string `json:"ap"`
		STA    string `json:"sta"`
		SSID   string `json:"ssid"`
		PMK    string `json:"pmk"`
		PTK    string `json:"ptk"`
		ANonce string `json:"anonce"`
		SNonce string `json:"snonce"`
	} `json:"sessions"`
}

func LoadWiFiKeys(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var kf wifiKeyFile
	if err := json.Unmarshal(data, &kf); err != nil {
		return err
	}
	wifiKeys.Lock()
	defer wifiKeys.Unlock()
	for _, x := range kf.Sessions {
		s := &wifiSession{ssid: x.SSID}
		if b, err := hex.DecodeString(x.PMK); err == nil {
			s.pmk = b
		}
		if b, err := hex.DecodeString(x.PTK); err == nil {
			s.ptk = b
			n := 16
			if len(b) < n {
				n = len(b)
			}
			s.tk = b[:n]
		}
		if b, err := hex.DecodeString(x.ANonce); err == nil {
			s.anonce = b
		}
		if b, err := hex.DecodeString(x.SNonce); err == nil {
			s.snonce = b
		}
		wifiKeys.sessions[wifiKey(x.AP, x.STA)] = s
	}
	return nil
}
