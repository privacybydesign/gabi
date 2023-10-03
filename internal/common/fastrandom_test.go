package common

import (
	"encoding/hex"
	"testing"
)

func TestCPRNG(t *testing.T) {
	var seed [32]byte
	expected := "f29000b62a499fd0a9f39a6add2e7780c7b519846a11411cd6ac07cb03f801a84ef4b88bebd54953c37ffaf66efaca7b80c3017e8f89ab315ede32b11e48ab50d5786900334bbaad31a868ca3c29221b99ebccc0117949cd663c44c06a1c58b05daad7132f80983dae88ecf9ce714a1b600411a4cb4d0da02e107f8d0bcfdab864009471a3394f76374e38bfdc9fe26c62ac2e4b9ec5049108dccdb6488f325cf3297d5a71a5d1734dd46661023ea39f7402facdf1802b42d88a715615324bd502bddc6de19403882a27cdf934adffc9483c475aeb20edf61bfa6a18777a7ada695ebda390508948b1fc69971a26a169c0de48d769b197cd5cf9bb5f798f49d0"
	for i := 0; i < 32; i++ {
		seed[i] = byte(i)
	}
	var buf [256]byte
	_, err := NewCPRNG(&seed)
	if err != nil {
		t.Fatalf("NewCPRNG: %v", err)
	}
	for i := 0; i < 256; i++ {
		rng, _ := NewCPRNG(&seed)
		rng.Read(buf[0:i])
		if hex.EncodeToString(buf[:i]) != expected[:2*i] {
			t.Fatalf("TestCPRNG (1): %d", i)
		}
	}
	rng, _ := NewCPRNG(&seed)
	for i := 0; i < 16; i++ {
		rng.Read(buf[i*16 : (i+1)*16])
	}
	if hex.EncodeToString(buf[:]) != expected[:] {
		t.Fatalf("TestCPRNG (2)")
	}
	rng, _ = NewCPRNG(&seed)
	for i := 0; i < 8; i++ {
		rng.Read(buf[i*32 : (i+1)*32])
	}
	if hex.EncodeToString(buf[:]) != expected[:] {
		t.Fatalf("TestCPRNG (3)")
	}
	for j := 1; j < 16; j++ {
		rng, _ = NewCPRNG(&seed)
		for i := 0; i < 8; i++ {
			rng.Read(buf[:j])
			if hex.EncodeToString(buf[:j]) != expected[32*i:32*i+2*j] {
				t.Fatalf("TestCPRNG (4)")
			}
		}
	}
	for j := 17; j < 31; j++ {
		rng, _ = NewCPRNG(&seed)
		for i := 0; i < 8; i++ {
			rng.Read(buf[:j])
			if hex.EncodeToString(buf[:j]) != expected[64*i:64*i+2*j] {
				t.Fatalf("TestCPRNG (5)")
			}
		}
	}
}
