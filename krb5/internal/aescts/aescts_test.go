package aescts

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

// TestRFC3962Vectors tests against RFC 3962 Appendix B test vectors.
// https://www.rfc-editor.org/rfc/rfc3962.html
// Key is "chicken teriyaki", IV is all zeros.
// Expected ciphertexts generated with: github.com/jcmturner/aescts/v2
func TestRFC3962Vectors(t *testing.T) {
	key := []byte("chicken teriyaki")
	iv := make([]byte, 16)

	// RFC 3962 plaintexts - note "like" not "lick"
	vectors := []struct {
		name      string
		plain     string
		cipherHex string
	}{
		{"17 bytes", "I would like the ", "c6353568f2bf8cb4d8a580362da7ff7f97"},
		{"31 bytes", "I would like the General Gau's ", "fc00783e0efdb2c1d445d4c8eff7ed2297687268d6ecccc0c07b25e25ecfe5"},
		{"32 bytes", "I would like the General Gau's C", "39312523a78662d5be7fcbcc98ebf5a897687268d6ecccc0c07b25e25ecfe584"},
		{"33 bytes", "I would like the General Gau's Ch", "97687268d6ecccc0c07b25e25ecfe58455ad47fa866d88f74de0c5079e021c4a39"},
		{"47 bytes", "I would like the General Gau's Chicken, please", "97687268d6ecccc0c07b25e25ecfe58444de994342388523c6480adb77bc983a39312523a78662d5be7fcbcc98eb"},
		{"48 bytes", "I would like the General Gau's Chicken, please,", "97687268d6ecccc0c07b25e25ecfe584b3fffd940c16a18c1b5549d2f838029e39312523a78662d5be7fcbcc98ebf5"},
		{"64 bytes", "I would like the General Gau's Chicken, please, and wonton soup.", "97687268d6ecccc0c07b25e25ecfe58439312523a78662d5be7fcbcc98ebf5a84807efe836ee89a526730dbc2f7bc8409dad8bbb96c4cdc03bc103e1a194bbd8"},
	}

	for _, tt := range vectors {
		t.Run(tt.name, func(t *testing.T) {
			plain := []byte(tt.plain)
			expectedCipher := mustHex(tt.cipherHex)

			// Test encryption
			_, cipher, err := Encrypt(key, iv, plain)
			if err != nil {
				t.Fatalf("Encrypt failed: %v", err)
			}

			if !bytes.Equal(cipher, expectedCipher) {
				t.Errorf("Encryption mismatch\nExpected: %x\nGot:      %x", expectedCipher, cipher)
			}

			// Verify ciphertext length equals plaintext length
			if len(cipher) != len(plain) {
				t.Errorf("Cipher length %d != plain length %d", len(cipher), len(plain))
			}

			// Test decryption
			decrypted, err := Decrypt(key, iv, expectedCipher)
			if err != nil {
				t.Fatalf("Decrypt failed: %v", err)
			}
			if !bytes.Equal(decrypted, plain) {
				t.Errorf("Decryption mismatch\nExpected: %x\nGot:      %x", plain, decrypted)
			}
		})
	}
}

// TestEncryptDecryptRoundTrip tests encryption and decryption for various message lengths.
func TestEncryptDecryptRoundTrip(t *testing.T) {
	tests := []struct {
		name     string
		keyHex   string
		ivHex    string
		plainHex string
	}{
		{
			name:     "exactly one block (16 bytes)",
			keyHex:   "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
			ivHex:    "00000000000000000000000000000000",
			plainHex: "00112233445566778899aabbccddeeff",
		},
		{
			name:     "17 bytes",
			keyHex:   "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
			ivHex:    "00000000000000000000000000000000",
			plainHex: "00112233445566778899aabbccddeeff00",
		},
		{
			name:     "two complete blocks (32 bytes)",
			keyHex:   "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
			ivHex:    "00000000000000000000000000000000",
			plainHex: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
		},
		{
			name:     "36 bytes",
			keyHex:   "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
			ivHex:    "00000000000000000000000000000000",
			plainHex: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff0011223344",
		},
		{
			name:     "three complete blocks (48 bytes)",
			keyHex:   "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
			ivHex:    "00000000000000000000000000000000",
			plainHex: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
		},
		{
			name:     "17 bytes with non-zero IV",
			keyHex:   "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
			ivHex:    "ffeeddccbbaa99887766554433221100",
			plainHex: "00112233445566778899aabbccddeeff00",
		},
		{
			name:     "32 bytes with non-zero IV",
			keyHex:   "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
			ivHex:    "ffeeddccbbaa99887766554433221100",
			plainHex: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
		},
		{
			name:     "AES-128 key, 32 bytes",
			keyHex:   "000102030405060708090a0b0c0d0e0f",
			ivHex:    "00000000000000000000000000000000",
			plainHex: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := mustHex(tt.keyHex)
			iv := mustHex(tt.ivHex)
			plain := mustHex(tt.plainHex)

			// Encrypt
			_, ciphertext, err := Encrypt(key, iv, plain)
			if err != nil {
				t.Fatalf("Encrypt failed: %v", err)
			}

			// Verify ciphertext length matches plaintext length
			if len(ciphertext) != len(plain) {
				t.Errorf("Ciphertext length %d != plaintext length %d", len(ciphertext), len(plain))
			}

			// Decrypt
			decrypted, err := Decrypt(key, iv, ciphertext)
			if err != nil {
				t.Fatalf("Decrypt failed: %v", err)
			}

			if !bytes.Equal(plain, decrypted) {
				t.Errorf("Round-trip failed\nOriginal:  %x\nDecrypted: %x", plain, decrypted)
			}
		})
	}
}

// TestRandomLengths tests encryption/decryption for all lengths from 16 to 100 bytes.
func TestRandomLengths(t *testing.T) {
	key := make([]byte, 32)
	iv := make([]byte, 16)
	rand.Read(key)

	for length := 16; length <= 100; length++ {
		plain := make([]byte, length)
		rand.Read(plain)
		rand.Read(iv)

		_, cipher, err := Encrypt(key, iv, plain)
		if err != nil {
			t.Fatalf("Encrypt failed at length %d: %v", length, err)
		}

		decrypted, err := Decrypt(key, iv, cipher)
		if err != nil {
			t.Fatalf("Decrypt failed at length %d: %v", length, err)
		}

		if !bytes.Equal(plain, decrypted) {
			t.Errorf("Length %d: Round-trip failed\nOriginal:  %x\nDecrypted: %x", length, plain, decrypted)
		}
	}
}

// TestErrorCases tests error handling.
func TestErrorCases(t *testing.T) {
	key := make([]byte, 32)
	iv := make([]byte, 16)

	// Test plaintext too short
	_, _, err := Encrypt(key, iv, []byte("short"))
	if err == nil {
		t.Error("Expected error for short plaintext")
	}

	// Test ciphertext too short
	_, err = Decrypt(key, iv, []byte("short"))
	if err == nil {
		t.Error("Expected error for short ciphertext")
	}

	// Test invalid key length
	_, _, err = Encrypt([]byte("badkey"), iv, make([]byte, 16))
	if err == nil {
		t.Error("Expected error for invalid key length")
	}
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
