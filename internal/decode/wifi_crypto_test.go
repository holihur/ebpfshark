package decode

import (
	"encoding/hex"
	"testing"
)

func TestAESCCMVector(t *testing.T) {
	key, _ := hex.DecodeString("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf")
	nonce, _ := hex.DecodeString("00000003020100a0a1a2a3a4a5")
	aad, _ := hex.DecodeString("0001020304050607")
	ct, _ := hex.DecodeString("588c979a61c663d2f066d0c2c0f989806d5f6b61dac384")
	tag, _ := hex.DecodeString("17e8d12cfdf926e0")
	want, _ := hex.DecodeString("08090a0b0c0d0e0f101112131415161718191a1b1c1d1e")
	got, ok := aesCCMOpen(key, nonce, aad, ct, tag)
	if !ok {
		t.Fatal("CCM authentication failed")
	}
	if string(got) != string(want) {
		t.Fatalf("plaintext=%x", got)
	}
}

func TestWiFiPTKDerivation(t *testing.T) {
	LoadWiFiPSK("password123")
	wifiSetSSID("001122334455", "test-ssid")
	wifiHandshake("001122334455", "66778899aabb", 0x008a, []byte("0123456789abcdef0123456789abcdef"))
	wifiHandshake("001122334455", "66778899aabb", 0x010a, []byte("abcdef0123456789abcdef0123456789"))
	if tk := wifiTK("001122334455", "66778899aabb"); len(tk) != 16 {
		t.Fatalf("TK length=%d", len(tk))
	}
}
