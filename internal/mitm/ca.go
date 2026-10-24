package mitm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// authority is a local CA used to terminate TLS for the proxy. The CA private
// key stays on disk under a 0700 directory.
type authority struct {
	dir  string
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	der  []byte
	pem  []byte

	mu    sync.Mutex
	leafs map[string]*tls.Certificate
}

// EnsureCA generates or reuses a CA and returns the public certificate path.
func EnsureCA(dir string) (string, error) {
	if _, err := loadOrCreateCA(dir); err != nil {
		return "", err
	}
	return filepath.Join(dir, "ca.crt"), nil
}

func loadOrCreateCA(dir string) (*authority, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	var cert *x509.Certificate
	var key *ecdsa.PrivateKey
	if certPEM, err := os.ReadFile(certPath); err == nil {
		if block, _ := pem.Decode(certPEM); block != nil {
			cert, _ = x509.ParseCertificate(block.Bytes)
		}
	}
	if keyPEM, err := os.ReadFile(keyPath); err == nil {
		if block, _ := pem.Decode(keyPEM); block != nil {
			key, _ = x509.ParseECPrivateKey(block.Bytes)
		}
	}
	if cert == nil || key == nil {
		var err error
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		tmpl := &x509.Certificate{
			SerialNumber: serial,
			Subject:      pkix.Name{CommonName: "ebpfshark MITM CA", Organization: []string{"ebpfshark"}},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().AddDate(10, 0, 0),
			IsCA:         true, BasicConstraintsValid: true,
			KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			return nil, err
		}
		cert, err = x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
			return nil, err
		}
		keyDER, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
			return nil, err
		}
	}
	return &authority{
		dir: dir, cert: cert, key: key, der: cert.Raw,
		pem:   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}),
		leafs: make(map[string]*tls.Certificate),
	}, nil
}

func (a *authority) certificateFor(host string) (*tls.Certificate, error) {
	host = stripPort(host)
	if host == "" {
		return nil, fmt.Errorf("empty TLS server name")
	}
	a.mu.Lock()
	if cert := a.leafs[host]; cert != nil {
		a.mu.Unlock()
		return cert, nil
	}
	a.mu.Unlock()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host, Organization: []string{"ebpfshark MITM"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.cert, &key.PublicKey, a.key)
	if err != nil {
		return nil, err
	}
	cert := &tls.Certificate{Certificate: [][]byte{der, a.der}, PrivateKey: key, Leaf: tmpl}
	a.mu.Lock()
	a.leafs[host] = cert
	a.mu.Unlock()
	return cert, nil
}

func stripPort(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}
