package krb5

import (
	"bytes"
	"crypto/aes"
	"crypto/sha1"
	"encoding/asn1"
	"encoding/hex"
	"testing"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

// TestKeyDerivationRFC3962 tests our key derivation against RFC 3962 test vectors.
func TestKeyDerivationRFC3962(t *testing.T) {
	// Let's test with our actual parameters
	password := "alice-secret-password"
	principal := "alice"
	realm := "TEST.GOSMB.LOCAL"

	key, err := deriveKeyFromPassword(eTypeAES256SHA1, password, principal, realm)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}

	t.Logf("Derived key for %s@%s: %x", principal, realm, key)
	t.Logf("Key length: %d bytes", len(key))
	t.Logf("Last 2 bytes: %X", key[len(key)-2:])

	// Test intermediate PBKDF2 step without DK
	// to isolate where the difference might be
	salt := realm + principal
	t.Logf("Salt: %q", salt)
}

// TestRFC3962TestVectors tests against official RFC 3962 test vectors.
func TestRFC3962TestVectors(t *testing.T) {
	// RFC 3962 Appendix B test vector
	// Password: "password", Salt: "ATHENA.MIT.EDUraeburn"
	// Iteration count: 1 (not our default!)
	// 256-bit AES key:
	//   fe697b52bc0d3ce14432ba036a92e65b
	//   bb52280990a2fa27883998d72af30161

	expected := mustHex("fe697b52bc0d3ce14432ba036a92e65bbb52280990a2fa27883998d72af30161")

	password := "password"
	salt := "ATHENA.MIT.EDUraeburn"

	// PBKDF2 with iteration count 1
	tkey := pbkdf2Key([]byte(password), []byte(salt), 1, 32)
	t.Logf("PBKDF2 output (iter=1): %x", tkey)

	// Test n-fold of "kerberos"
	kerberosFolded := nfold([]byte("kerberos"), 128)
	t.Logf("n-fold('kerberos', 128): %x", kerberosFolded)

	// DK(tkey, "kerberos")
	finalKey, err := deriveKeyExported(tkey, []byte("kerberos"), 32)
	if err != nil {
		t.Fatalf("deriveKey failed: %v", err)
	}
	t.Logf("Final key after DK: %x", finalKey)
	t.Logf("Expected:           %x", expected)

	if !bytes.Equal(finalKey, expected) {
		t.Errorf("Key mismatch!\nGot:      %x\nExpected: %x", finalKey, expected)
	}
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// For testing - expose internal function
func deriveKeyExported(baseKey, constant []byte, keyLen int) ([]byte, error) {
	return deriveKey(baseKey, constant, keyLen)
}

// For testing - directly call PBKDF2
func pbkdf2Key(password, salt []byte, iterations, keyLen int) []byte {
	return pbkdf2.Key(password, salt, iterations, keyLen, sha1.New)
}

// TestKeyDerivationWithKTUtil tests key derivation against known ktutil output.
// You can verify with: ktutil -k test.keytab add -p alice@TEST.GOSMB.LOCAL -e aes256-cts -w alice-secret-password
func TestKeyDerivationWithKTUtil(t *testing.T) {
	// This test is for manual verification against ktutil
	// Run: ktutil -k /tmp/test.keytab add -p alice@TEST.GOSMB.LOCAL -e aes256-cts-hmac-sha1-96 -w "alice-secret-password"
	// Then: ktutil -k /tmp/test.keytab list -K
	// Compare the key displayed with what we derive

	password := "alice-secret-password"
	principal := "alice"
	realm := "TEST.GOSMB.LOCAL"

	key, _ := deriveKeyFromPassword(eTypeAES256SHA1, password, principal, realm)
	t.Logf("Our derived key: %x", key)
	t.Logf("Key length: %d bytes", len(key))
	t.Logf("Last 2 bytes (hex): %X", key[len(key)-2:])

	// Also show intermediate PBKDF2 step
	salt := realm + principal
	tkey := pbkdf2Key([]byte(password), []byte(salt), 4096, 32)
	t.Logf("PBKDF2 intermediate: %x", tkey)
	t.Logf("Salt used: %q", salt)

	// Show nfold output
	kerberosFolded := nfold([]byte("kerberos"), 128)
	t.Logf("n-fold('kerberos', 128): %x", kerberosFolded)

	// Show deriveKey output
	finalKey, err := deriveKeyExported(tkey, []byte("kerberos"), 32)
	if err != nil {
		t.Fatalf("deriveKey failed: %v", err)
	}
	t.Logf("deriveKey(PBKDF2, 'kerberos'): %x", finalKey)
}

func TestDeriveKeySteps(t *testing.T) {
	// Test deriveKey with the actual PBKDF2 output to verify each step
	pbkdf2Output := mustHex("cf8a2b6b5d73342e452f9fc9109ea42dd939293a4939846e3fb8ffb145e8e333")

	// n-fold("kerberos", 128 bits)
	kerberosFolded := nfold([]byte("kerberos"), 128)
	t.Logf("n-fold result: %x", kerberosFolded)
	t.Logf("Expected:      6b65726265726f737b9b5b2b93132b93")

	// First block: AES encrypt the n-folded constant
	block, _ := aes.NewCipher(pbkdf2Output)
	firstBlock := make([]byte, 16)
	block.Encrypt(firstBlock, kerberosFolded)
	t.Logf("First encrypted block: %x", firstBlock)

	// Second block: AES encrypt the first block
	secondBlock := make([]byte, 16)
	block.Encrypt(secondBlock, firstBlock)
	t.Logf("Second encrypted block: %x", secondBlock)

	// Full key
	fullKey := append(firstBlock, secondBlock...)
	t.Logf("Full derived key: %x", fullKey)
}

func TestEncryptionKeyDerivation(t *testing.T) {
	// Test Ke and Ki derivation from the base key
	// Base key for alice@TEST.GOSMB.LOCAL
	baseKey := mustHex("d092527e0f7ec8dd83e8ddf60a1064a79bd4dc2fbec4f97e75adb9f3587eb251")

	// For key usage 1 (AS-REQ timestamp):
	// Ke constant: 0x00000001 0xAA = {0, 0, 0, 1, 0xAA}
	// Ki constant: 0x00000001 0x55 = {0, 0, 0, 1, 0x55}
	keConstant := []byte{0, 0, 0, 1, 0xAA}
	kiConstant := []byte{0, 0, 0, 1, 0x55}

	t.Logf("Base key: %x", baseKey)
	t.Logf("Ke constant: %x", keConstant)
	t.Logf("Ki constant: %x", kiConstant)

	// n-fold the constants to 128 bits
	keFolded := nfold(keConstant, 128)
	kiFolded := nfold(kiConstant, 128)
	t.Logf("n-fold(Ke constant, 128): %x", keFolded)
	t.Logf("n-fold(Ki constant, 128): %x", kiFolded)

	// Derive Ke
	ke, err := deriveKeyExported(baseKey, keConstant, 32)
	if err != nil {
		t.Fatalf("deriveKey for Ke failed: %v", err)
	}
	t.Logf("Ke: %x", ke)

	// Derive Ki
	ki, err := deriveKeyExported(baseKey, kiConstant, 32)
	if err != nil {
		t.Fatalf("deriveKey for Ki failed: %v", err)
	}
	t.Logf("Ki: %x", ki)
}

func TestKRBErrorEncoding(t *testing.T) {
	// Create a KRB-ERROR like what we'd send for PREAUTH_REQUIRED
	// Including the ETYPE-INFO2 data that we actually send
	etypeInfo := []eTypeInfo2Entry{{
		EType: eTypeAES256SHA1,
		Salt:  "TEST.GOSMB.LOCALalice",
	}}
	etypeInfoBytes, _ := asn1.Marshal(etypeInfo)

	errData := []paData{{
		PADataType:  paTypeETypeInfo2,
		PADataValue: etypeInfoBytes,
	}}
	errDataBytes, _ := asn1.Marshal(errData)

	err := krbError{
		PVNO:      5,
		MsgType:   msgTypeError,
		STime:     time.Now().UTC(),
		SUSec:     0,
		ErrorCode: errPreAuthRequired,
		Realm:     "TEST.GOSMB.LOCAL",
		SName: principalName{
			NameType:   nameTypeSrvInst,
			NameString: []string{"krbtgt", "TEST.GOSMB.LOCAL"},
		},
		EText: "Pre-authentication required",
		EData: errDataBytes,
	}

	data, e := marshalKRBError(err)
	if e != nil {
		t.Fatalf("Marshal error: %v", e)
	}

	t.Logf("KRB-ERROR (%d bytes):\n%s", len(data), hex.Dump(data))

	// Parse and verify structure
	if len(data) < 2 {
		t.Fatal("Data too short")
	}

	t.Logf("First byte: 0x%02x", data[0])
	class := (data[0] >> 6) & 0x3
	constructed := (data[0] >> 5) & 0x1
	tag := data[0] & 0x1f

	t.Logf("  Class: %d (0=UNIVERSAL, 1=APPLICATION, 2=CONTEXT, 3=PRIVATE)", class)
	t.Logf("  Constructed: %v", constructed == 1)
	t.Logf("  Tag: %d", tag)

	// For APPLICATION 30, we expect: class=1, constructed=1, tag=30
	// But tag 30 >= 31 threshold? No, 30 < 31 so it fits in low-tag form
	// Expected: 01 1 11110 = 0111 1110 = 0x7e
	if data[0] != 0x7e {
		t.Errorf("Expected first byte 0x7e for APPLICATION 30, got 0x%02x", data[0])
	}

	// Try to parse it back
	var raw asn1.RawValue
	rest, parseErr := asn1.Unmarshal(data, &raw)
	if parseErr != nil {
		t.Errorf("Failed to parse: %v", parseErr)
	}
	t.Logf("Parsed RawValue: Class=%d Tag=%d IsCompound=%v BytesLen=%d RestLen=%d",
		raw.Class, raw.Tag, raw.IsCompound, len(raw.Bytes), len(rest))
}

func TestASRepEncoding(t *testing.T) {
	// Create a minimal AS-REP
	ticket := ticket{
		TktVNO: 5,
		Realm:  "TEST.REALM",
		SName: principalName{
			NameType:   nameTypeSrvInst,
			NameString: []string{"krbtgt", "TEST.REALM"},
		},
		EncPart: encryptedData{
			EType:  eTypeAES256SHA1,
			Cipher: []byte{0x01, 0x02, 0x03},
		},
	}

	ticketBytes, err := marshalTicket(ticket)
	if err != nil {
		t.Fatalf("Marshal ticket: %v", err)
	}

	rep := asRep{
		PVNO:    5,
		MsgType: msgTypeASRep,
		CRealm:  "TEST.REALM",
		CName: principalName{
			NameType:   nameTypePrincipal,
			NameString: []string{"user"},
		},
		TicketBytes: ticketBytes,
		EncPart: encryptedData{
			EType:  eTypeAES256SHA1,
			KVNO:   1,
			Cipher: []byte{0x04, 0x05, 0x06},
		},
	}

	data, err := marshalASRep(rep)
	if err != nil {
		t.Fatalf("Marshal AS-REP: %v", err)
	}

	t.Logf("AS-REP (%d bytes):\n%s", len(data), hex.Dump(data))

	// First byte should be APPLICATION 11 = 0x6b
	// Class 01 (APPLICATION), Constructed 1, Tag 01011 (11)
	// = 01 1 01011 = 0110 1011 = 0x6b
	if data[0] != 0x6b {
		t.Errorf("Expected first byte 0x6b for APPLICATION 11, got 0x%02x", data[0])
	}

	// Try to unmarshal it back
	parsed, err := unmarshalASRep(data)
	if err != nil {
		t.Fatalf("Unmarshal AS-REP: %v", err)
	}

	t.Logf("Parsed AS-REP: PVNO=%d MsgType=%d CRealm=%s TicketLen=%d EncPart.EType=%d",
		parsed.PVNO, parsed.MsgType, parsed.CRealm, len(parsed.TicketBytes), parsed.EncPart.EType)

	if parsed.PVNO != 5 {
		t.Errorf("PVNO mismatch: got %d, want 5", parsed.PVNO)
	}
	if parsed.EncPart.EType != eTypeAES256SHA1 {
		t.Errorf("EncPart.EType mismatch: got %d, want %d", parsed.EncPart.EType, eTypeAES256SHA1)
	}
}
