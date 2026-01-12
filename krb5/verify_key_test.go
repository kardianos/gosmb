package krb5

import (
	"encoding/hex"
	"testing"

	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/crypto/rfc3961"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/types"
)

func TestCompareWithGoKRB5(t *testing.T) {
	password := "alice-secret-password"
	principal := "alice"
	realm := "TEST.GOSMB.LOCAL"
	salt := realm + principal

	// Our key derivation
	ourKey, err := DeriveKey(ETypeAES256SHA1, password, principal, realm)
	if err != nil {
		t.Fatalf("Our DeriveKey failed: %v", err)
	}
	t.Logf("Our key: %x", ourKey)

	// gokrb5 key derivation
	princ := types.PrincipalName{
		NameType:   1, // KRB_NT_PRINCIPAL
		NameString: []string{principal},
	}

	// Use gokrb5 to derive the key
	et, err := crypto.GetEtype(etypeID.AES256_CTS_HMAC_SHA1_96)
	if err != nil {
		t.Fatalf("GetEtype failed: %v", err)
	}

	// s2kparams for gokrb5 should be hex-encoded
	// 4096 = 0x00001000
	s2kparams := hex.EncodeToString([]byte{0x00, 0x00, 0x10, 0x00})
	t.Logf("s2kparams: %s", s2kparams)
	gokrb5Key, err := et.StringToKey(password, salt, s2kparams)
	if err != nil {
		t.Fatalf("gokrb5 StringToKey failed: %v", err)
	}
	t.Logf("gokrb5 key: %x", gokrb5Key)

	// Also try with types.EncryptionKey
	encKey := types.EncryptionKey{
		KeyType:  etypeID.AES256_CTS_HMAC_SHA1_96,
		KeyValue: gokrb5Key,
	}
	t.Logf("gokrb5 EncryptionKey type: %d, value: %x", encKey.KeyType, encKey.KeyValue)

	// Compare
	if hex.EncodeToString(ourKey) != hex.EncodeToString(gokrb5Key) {
		t.Errorf("Keys don't match!\nOur key:    %x\ngokrb5 key: %x", ourKey, gokrb5Key)
	} else {
		t.Log("Keys match!")
	}

	_ = princ // silence unused variable warning
}

func TestDecryptWithGoKRB5(t *testing.T) {
	// Test that we can decrypt data encrypted by gokrb5 and vice versa
	password := "alice-secret-password"
	principal := "alice"
	realm := "TEST.GOSMB.LOCAL"
	salt := realm + principal

	// Get encryption type
	et, err := crypto.GetEtype(etypeID.AES256_CTS_HMAC_SHA1_96)
	if err != nil {
		t.Fatalf("GetEtype failed: %v", err)
	}

	// Derive key with gokrb5
	s2kparams := hex.EncodeToString([]byte{0x00, 0x00, 0x10, 0x00})
	gokrb5Key, err := et.StringToKey(password, salt, s2kparams)
	if err != nil {
		t.Fatalf("gokrb5 StringToKey failed: %v", err)
	}

	encKey := types.EncryptionKey{
		KeyType:  etypeID.AES256_CTS_HMAC_SHA1_96,
		KeyValue: gokrb5Key,
	}

	// Encrypt a test message with gokrb5
	plaintext := []byte("test message 123")
	keyUsage := 1 // AS-REQ timestamp

	ciphertext, err := crypto.GetEncryptedData(plaintext, encKey, uint32(keyUsage), 0)
	if err != nil {
		t.Fatalf("gokrb5 encryption failed: %v", err)
	}
	t.Logf("gokrb5 encrypted: etype=%d kvno=%d cipher=%x", ciphertext.EType, ciphertext.KVNO, ciphertext.Cipher)

	// Try to decrypt with our implementation
	ourKey, err := DeriveKey(ETypeAES256SHA1, password, principal, realm)
	if err != nil {
		t.Fatalf("Our DeriveKey failed: %v", err)
	}

	ourEncData := EncryptedData{
		EType:  ciphertext.EType,
		KVNO:   ciphertext.KVNO,
		Cipher: ciphertext.Cipher,
	}

	decrypted, err := DecryptDebug(EncryptionKey{KeyType: ETypeAES256SHA1, KeyValue: ourKey}, keyUsage, ourEncData, true)
	if err != nil {
		t.Fatalf("Our decryption failed: %v", err)
	}

	t.Logf("Decrypted: %s", string(decrypted))
	if string(decrypted) != string(plaintext) {
		t.Errorf("Decryption mismatch!\nExpected: %s\nGot: %s", string(plaintext), string(decrypted))
	}
}

func TestCompareKeyDerivation(t *testing.T) {
	// Compare our key derivation with gokrb5's deriveKeys function
	baseKey := mustHex("d092527e0f7ec8dd83e8ddf60a1064a79bd4dc2fbec4f97e75adb9f3587eb251")

	// Use gokrb5 to derive Ke and Ki
	et, _ := crypto.GetEtype(etypeID.AES256_CTS_HMAC_SHA1_96)

	// gokrb5 derives keys differently - let's check their method
	// From gokrb5 source: they use DeriveKey with usage-specific constants

	// For usage 1, the constants should be:
	// Ke: usage | 0xAA = 0x00000001 | 0xAA => constant = {0, 0, 0, 1, 0xAA}
	// Ki: usage | 0x55 = 0x00000001 | 0x55 => constant = {0, 0, 0, 1, 0x55}

	encKey := types.EncryptionKey{
		KeyType:  etypeID.AES256_CTS_HMAC_SHA1_96,
		KeyValue: baseKey,
	}

	// Encrypt something with gokrb5 to see what keys it uses
	plaintext := []byte("test")
	ciphertext, err := crypto.GetEncryptedData(plaintext, encKey, uint32(1), 0)
	if err != nil {
		t.Fatalf("gokrb5 encrypt failed: %v", err)
	}
	t.Logf("gokrb5 encrypted: %x", ciphertext.Cipher)

	// Now try to decrypt with gokrb5 itself to verify it works
	decrypted, err := crypto.DecryptEncPart(ciphertext, encKey, uint32(1))
	if err != nil {
		t.Fatalf("gokrb5 decrypt failed: %v", err)
	}
	t.Logf("gokrb5 decrypted: %s", string(decrypted))

	// Now let's trace through gokrb5's key derivation
	// We need to look at how DeriveKey works in rfc3961

	// Our derived keys
	keConstant := []byte{0, 0, 0, 1, 0xAA}
	kiConstant := []byte{0, 0, 0, 1, 0x55}

	ourKe, _ := deriveKeyExported(baseKey, keConstant, 32)
	ourKi, _ := deriveKeyExported(baseKey, kiConstant, 32)

	t.Logf("Our Ke: %x", ourKe)
	t.Logf("Our Ki: %x", ourKi)

	// Verify gokrb5's key derivation matches ours
	// gokrb5 uses rfc3961.DeriveKey internally

	// The problem might be in how we compute the n-fold of the constant
	keNfold := nfold(keConstant, 128)
	kiNfold := nfold(kiConstant, 128)
	t.Logf("n-fold(Ke constant): %x", keNfold)
	t.Logf("n-fold(Ki constant): %x", kiNfold)

	// Use gokrb5's rfc3961.DeriveKey directly
	// First compare nfold
	gokrb5KeNfold := rfc3961.Nfold(keConstant, 128)
	gokrb5KiNfold := rfc3961.Nfold(kiConstant, 128)
	t.Logf("gokrb5 n-fold(Ke constant): %x", gokrb5KeNfold)
	t.Logf("gokrb5 n-fold(Ki constant): %x", gokrb5KiNfold)

	if hex.EncodeToString(keNfold) != hex.EncodeToString(gokrb5KeNfold) {
		t.Errorf("Ke nfold mismatch!\nOur:    %x\ngokrb5: %x", keNfold, gokrb5KeNfold)
	}
	if hex.EncodeToString(kiNfold) != hex.EncodeToString(gokrb5KiNfold) {
		t.Errorf("Ki nfold mismatch!\nOur:    %x\ngokrb5: %x", kiNfold, gokrb5KiNfold)
	}

	// Now derive keys using gokrb5
	gokrb5Ke, err := rfc3961.DeriveKey(baseKey, keConstant, et)
	if err != nil {
		t.Fatalf("gokrb5 DeriveKey Ke failed: %v", err)
	}
	gokrb5Ki, err := rfc3961.DeriveKey(baseKey, kiConstant, et)
	if err != nil {
		t.Fatalf("gokrb5 DeriveKey Ki failed: %v", err)
	}
	t.Logf("gokrb5 Ke: %x", gokrb5Ke)
	t.Logf("gokrb5 Ki: %x", gokrb5Ki)

	// Compare
	if hex.EncodeToString(ourKe) != hex.EncodeToString(gokrb5Ke) {
		t.Errorf("Ke mismatch!\nOur Ke:    %x\ngokrb5 Ke: %x", ourKe, gokrb5Ke)
	}
	if hex.EncodeToString(ourKi) != hex.EncodeToString(gokrb5Ki) {
		t.Errorf("Ki mismatch!\nOur Ki:    %x\ngokrb5 Ki: %x", ourKi, gokrb5Ki)
	}
}
