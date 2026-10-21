package decode

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"testing"
	"time"
)

func TestTLSCertificateAndALPN(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "example.com"},
		DNSNames:     []string{"example.com", "www.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certList := make([]byte, 3+len(der)+2)
	certList[0] = byte(len(der) >> 16)
	certList[1] = byte(len(der) >> 8)
	certList[2] = byte(len(der))
	copy(certList[3:], der)
	body := []byte{0}
	body = append(body, byte(len(certList)>>16), byte(len(certList)>>8), byte(len(certList)))
	body = append(body, certList...)
	hs := []byte{11, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)
	rec := tlsRecord(22, hs)
	c := appCtx(rec)
	flow := tlsFlowFor(c)
	flow.version = 0x0304
	flow.suite = 0x1301
	if !c.dissectTLS(rec, 0) {
		t.Fatal("TLS not recognized")
	}
	labels := fieldLabels(c.roots)
	if !containsLabel(labels, "Subject: CN=example.com") {
		t.Fatal("certificate subject missing")
	}
	if !containsLabel(labels, "DNS Names: example.com, www.example.com") {
		t.Fatal("certificate SAN missing")
	}
}

func TestTLS13DecryptWithKeylog(t *testing.T) {
	hello := buildClientHello("example.com")
	random := hello[5+4+2 : 5+4+2+32]
	secret := bytes.Repeat([]byte{0x11}, 32)
	keylogData.Lock()
	keylogData.m[hexString(random)] = map[string][]byte{"CLIENT_TRAFFIC_SECRET_0": secret}
	keylogData.Unlock()

	c := appCtx(hello)
	c.m.SrcPort, c.m.DstPort = 50000, 443
	if !c.dissectTLS(hello, 0) {
		t.Fatal("ClientHello not recognized")
	}
	flow := tlsFlowFor(c)
	flow.Lock()
	flow.version, flow.suite = 0x0304, 0x1301
	flow.Unlock()

	inner := append([]byte("GET / HTTP/1.1\r\n\r\n"), 23)
	key, iv, _ := tls13Keys(secret, 0x1301)
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	header := []byte{23, 0x03, 0x03, 0, 0}
	binary.BigEndian.PutUint16(header[3:], uint16(len(inner)+16))
	ct := aead.Seal(nil, iv, inner, header)
	rec := append(header, ct...)
	c2 := appCtx(rec)
	c2.m.SrcPort, c2.m.DstPort = 50000, 443
	if !c2.dissectTLS(rec, 0) {
		t.Fatal("encrypted record not recognized")
	}
	labels := fieldLabels(c2.roots)
	if !containsLabel(labels, "Key Log Label: CLIENT_TRAFFIC_SECRET_0") {
		t.Fatalf("decryption missing: %v", labels)
	}
	if !containsLabel(labels, "GET / HTTP/1.1") {
		t.Fatal("plaintext missing")
	}
}

func TestTLSServerHelloALPN(t *testing.T) {
	ext := []byte{}
	// ALPN: list length 3, "h2"
	alpn := []byte{0, 3, 2, 'h', '2'}
	ext = append(ext, 0, 16, 0, byte(len(alpn)))
	ext = append(ext, alpn...)
	// supported_versions: TLS 1.3
	sv := []byte{3, 4}
	ext = append(ext, 0, 43, 0, 2)
	ext = append(ext, sv...)
	body := []byte{3, 3}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0)          // session id len
	body = append(body, 0x13, 0x01) // cipher suite
	body = append(body, 0)          // compression
	body = append(body, 0, byte(len(ext)))
	body = append(body, ext...)
	hs := []byte{2, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)
	rec := tlsRecord(22, hs)
	c := appCtx(rec)
	if !c.dissectTLS(rec, 0) {
		t.Fatal("ServerHello not recognized")
	}
	labels := fieldLabels(c.roots)
	for _, want := range []string{"ALPN Protocol: h2", "Negotiated Version: TLS 1.3", "Cipher Suite: TLS_AES_128_GCM_SHA256"} {
		if !containsLabel(labels, want) {
			t.Fatalf("missing %q in %v", want, labels)
		}
	}
}

func tlsRecord(typ byte, body []byte) []byte {
	out := make([]byte, 5+len(body))
	out[0] = typ
	out[1], out[2] = 0x03, 0x03
	binary.BigEndian.PutUint16(out[3:5], uint16(len(body)))
	copy(out[5:], body)
	return out
}

func hexString(b []byte) string {
	const h = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2], out[i*2+1] = h[v>>4], h[v&15]
	}
	return string(out)
}
