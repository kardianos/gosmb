package krb5

import (
	"crypto/aes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"fmt"

	"github.com/jcmturner/aescts/v2"
	"golang.org/x/crypto/pbkdf2"
)

// Encryption type constants
const (
	ETypeAES256SHA1 = 18 // aes256-cts-hmac-sha1-96
	ETypeAES128SHA1 = 17 // aes128-cts-hmac-sha1-96
)

// Key sizes for each encryption type
const (
	aes256KeySize = 32
	aes128KeySize = 16
	aesBlockSize  = 16
)

// DeriveKey derives a Kerberos key from a password using string2key.
// For AES encryption types, this uses PBKDF2 followed by DK per RFC 3962.
func DeriveKey(etype int32, password, principal, realm string) ([]byte, error) {
	return DeriveKeyDebug(etype, password, principal, realm, false)
}

// DeriveKeyDebug is like DeriveKey but with optional debug output.
func DeriveKeyDebug(etype int32, password, principal, realm string, debug bool) ([]byte, error) {
	salt := realm + principal

	var keySize int
	switch etype {
	case ETypeAES256SHA1:
		keySize = aes256KeySize
	case ETypeAES128SHA1:
		keySize = aes128KeySize
	default:
		return nil, fmt.Errorf("unsupported encryption type: %d", etype)
	}

	if debug {
		fmt.Printf("DEBUG DeriveKey: password=%q principal=%q realm=%q\n", password, principal, realm)
		fmt.Printf("DEBUG DeriveKey: salt=%q (%x)\n", salt, salt)
		fmt.Printf("DEBUG DeriveKey: keySize=%d\n", keySize)
	}

	// Step 1: PBKDF2 with 4096 iterations, SHA1
	tkey := pbkdf2.Key([]byte(password), []byte(salt), 4096, keySize, sha1.New)

	if debug {
		fmt.Printf("DEBUG DeriveKey: PBKDF2 output=%x\n", tkey)
	}

	// Step 2: DK(tkey, "kerberos") per RFC 3962
	// The constant is "kerberos" (without null terminator)
	key, err := deriveKey(tkey, []byte("kerberos"), keySize)
	if debug && err == nil {
		fmt.Printf("DEBUG DeriveKey: final key=%x\n", key)
	}
	return key, err
}

// GenerateSessionKey generates a random session key for the given encryption type.
func GenerateSessionKey(etype int32) (EncryptionKey, error) {
	var keySize int
	switch etype {
	case ETypeAES256SHA1:
		keySize = aes256KeySize
	case ETypeAES128SHA1:
		keySize = aes128KeySize
	default:
		return EncryptionKey{}, fmt.Errorf("unsupported encryption type: %d", etype)
	}

	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		return EncryptionKey{}, err
	}

	return EncryptionKey{
		KeyType:  etype,
		KeyValue: key,
	}, nil
}

// Encrypt encrypts plaintext using the specified key and key usage.
// Returns EncryptedData suitable for Kerberos messages.
func Encrypt(key EncryptionKey, usage int, plaintext []byte) (EncryptedData, error) {
	// Derive encryption and HMAC keys from the base key
	ke, ki, err := deriveKeys(key.KeyValue, key.KeyType, usage)
	if err != nil {
		return EncryptedData{}, err
	}

	// Generate random confounder (one block)
	confounder := make([]byte, aesBlockSize)
	if _, err := rand.Read(confounder); err != nil {
		return EncryptedData{}, err
	}

	// Plaintext = confounder || data (no padding for CTS)
	plainBytes := append(confounder, plaintext...)

	// Encrypt with AES-CTS
	ciphertext, err := aesCTSEncrypt(ke, plainBytes)
	if err != nil {
		return EncryptedData{}, err
	}

	// Calculate HMAC over plaintext (confounder + message), not ciphertext
	// This is per RFC 3962 as implemented by MIT Kerberos
	h := hmac.New(sha1.New, ki)
	h.Write(plainBytes)
	mac := h.Sum(nil)[:12] // Truncate to 96 bits

	// Final ciphertext = encrypted data || truncated HMAC
	result := append(ciphertext, mac...)

	return EncryptedData{
		EType:  key.KeyType,
		Cipher: result,
	}, nil
}

// Decrypt decrypts ciphertext using the specified key and key usage.
func Decrypt(key EncryptionKey, usage int, enc EncryptedData) ([]byte, error) {
	return DecryptDebug(key, usage, enc, false)
}

// DecryptDebug is like Decrypt but with optional debug output.
func DecryptDebug(key EncryptionKey, usage int, enc EncryptedData, debug bool) ([]byte, error) {
	if key.KeyType != enc.EType {
		return nil, fmt.Errorf("key type mismatch: key=%d, encrypted=%d", key.KeyType, enc.EType)
	}

	// Derive encryption and HMAC keys
	ke, ki, err := deriveKeys(key.KeyValue, key.KeyType, usage)
	if err != nil {
		return nil, err
	}

	if debug {
		fmt.Printf("DEBUG Decrypt: baseKey=%x\n", key.KeyValue)
		fmt.Printf("DEBUG Decrypt: usage=%d\n", usage)
		fmt.Printf("DEBUG Decrypt: ke=%x\n", ke)
		fmt.Printf("DEBUG Decrypt: ki=%x\n", ki)
		fmt.Printf("DEBUG Decrypt: cipher=%x (%d bytes)\n", enc.Cipher, len(enc.Cipher))
	}

	if len(enc.Cipher) < aesBlockSize+12 {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Split ciphertext and HMAC
	ciphertext := enc.Cipher[:len(enc.Cipher)-12]
	expectedMAC := enc.Cipher[len(enc.Cipher)-12:]

	if debug {
		fmt.Printf("DEBUG Decrypt: ciphertext=%x\n", ciphertext)
		fmt.Printf("DEBUG Decrypt: expectedMAC=%x\n", expectedMAC)
	}

	// AES-CTS decryption
	plaintext, err := aesCTSDecrypt(ke, ciphertext)
	if err != nil {
		return nil, err
	}

	if debug {
		fmt.Printf("DEBUG Decrypt: plaintext (for HMAC)=%x\n", plaintext)
	}

	// Verify HMAC over plaintext (confounder + message)
	// This is computed AFTER decryption, per RFC 3962
	h := hmac.New(sha1.New, ki)
	h.Write(plaintext)
	actualMAC := h.Sum(nil)[:12]
	if debug {
		fmt.Printf("DEBUG Decrypt: actualMAC=%x\n", actualMAC)
	}
	if !hmac.Equal(expectedMAC, actualMAC) {
		return nil, fmt.Errorf("HMAC verification failed")
	}

	// Remove confounder (first block)
	if len(plaintext) < aesBlockSize {
		return nil, fmt.Errorf("plaintext too short")
	}

	return plaintext[aesBlockSize:], nil
}

// aesCTSEncrypt encrypts plaintext using AES-CTS (Cipher Text Stealing)
// Uses the aescts library for correctness
func aesCTSEncrypt(key []byte, plaintext []byte) ([]byte, error) {
	iv := make([]byte, aesBlockSize)
	_, ciphertext, err := aescts.Encrypt(key, iv, plaintext)
	return ciphertext, err
}

// aesCTSDecrypt decrypts ciphertext using AES-CTS (Cipher Text Stealing)
// Uses the aescts library for correctness
func aesCTSDecrypt(key []byte, ciphertext []byte) ([]byte, error) {
	iv := make([]byte, aesBlockSize)
	return aescts.Decrypt(key, iv, ciphertext)
}

// deriveKeys derives encryption (Ke) and integrity (Ki) keys from a base key.
// Uses the Kerberos key derivation function (RFC 3962).
func deriveKeys(baseKey []byte, etype int32, usage int) (ke, ki []byte, err error) {
	// Key derivation constants
	// Ke uses usage || 0xAA
	// Ki uses usage || 0x55
	keConstant := make([]byte, 5)
	binary.BigEndian.PutUint32(keConstant, uint32(usage))
	keConstant[4] = 0xAA

	kiConstant := make([]byte, 5)
	binary.BigEndian.PutUint32(kiConstant, uint32(usage))
	kiConstant[4] = 0x55

	ke, err = deriveKey(baseKey, keConstant, len(baseKey))
	if err != nil {
		return nil, nil, err
	}

	ki, err = deriveKey(baseKey, kiConstant, len(baseKey))
	if err != nil {
		return nil, nil, err
	}

	return ke, ki, nil
}

// deriveKey derives a key using the Kerberos DK function (RFC 3961).
// DR(Key, Constant) = k-truncate(E(Key, Constant, initial-cipher-state))
func deriveKey(baseKey, constant []byte, keyLen int) ([]byte, error) {
	block, err := aes.NewCipher(baseKey)
	if err != nil {
		return nil, err
	}

	// n-fold the constant to block size
	inblock := nfold(constant, aesBlockSize*8)

	// Generate key bytes by repeatedly encrypting
	// First block: encrypt the n-folded constant
	// Subsequent blocks: encrypt the previous output
	var result []byte
	for len(result) < keyLen {
		outblock := make([]byte, aesBlockSize)
		block.Encrypt(outblock, inblock)
		result = append(result, outblock...)
		// Next iteration encrypts this output
		inblock = outblock
	}

	return result[:keyLen], nil
}

// nfold implements the RFC 3961 n-fold operation.
// It folds an input to a specified number of bits using ones-complement addition.
// Based on the gokrb5 implementation.
func nfold(input []byte, nbits int) []byte {
	k := len(input) * 8 // input bits
	n := nbits          // output bits

	// Get the lowest common multiple of the two bit sizes
	lcmval := lcm(n, k)
	replicate := lcmval / k

	// Create a buffer by concatenating rotated copies of the input
	var sumBytes []byte
	for i := 0; i < replicate; i++ {
		rotation := 13 * i
		sumBytes = append(sumBytes, rotateRight(input, rotation)...)
	}

	// Fold the buffer down to n bits using ones-complement addition
	nfoldResult := make([]byte, n/8)
	sum := make([]byte, n/8)
	for i := 0; i < lcmval/n; i++ {
		for j := 0; j < n/8; j++ {
			sum[j] = sumBytes[j+(i*len(sum))]
		}
		nfoldResult = onesComplementAdd(nfoldResult, sum)
	}
	return nfoldResult
}

// rotateRight rotates byte slice right by step bits
func rotateRight(b []byte, step int) []byte {
	out := make([]byte, len(b))
	bitLen := len(b) * 8
	for i := 0; i < bitLen; i++ {
		// Get bit at position i
		srcByteIdx := i / 8
		srcBitIdx := 7 - (i % 8)
		bit := (b[srcByteIdx] >> srcBitIdx) & 1

		// Set bit at position (i+step) % bitLen
		dstPos := (i + step) % bitLen
		dstByteIdx := dstPos / 8
		dstBitIdx := 7 - (dstPos % 8)
		if bit == 1 {
			out[dstByteIdx] |= 1 << dstBitIdx
		}
	}
	return out
}

// onesComplementAdd adds two byte slices using ones-complement addition
func onesComplementAdd(n1, n2 []byte) []byte {
	numBits := len(n1) * 8
	out := make([]byte, numBits/8)
	carry := 0

	// Add from LSB to MSB
	for i := numBits - 1; i >= 0; i-- {
		// Get bits at position i
		n1ByteIdx := i / 8
		n1BitIdx := 7 - (i % 8)
		n1b := int((n1[n1ByteIdx] >> n1BitIdx) & 1)

		n2ByteIdx := i / 8
		n2BitIdx := 7 - (i % 8)
		n2b := int((n2[n2ByteIdx] >> n2BitIdx) & 1)

		s := n1b + n2b + carry

		outByteIdx := i / 8
		outBitIdx := 7 - (i % 8)

		switch s {
		case 0, 1:
			if s == 1 {
				out[outByteIdx] |= 1 << outBitIdx
			}
			carry = 0
		case 2:
			carry = 1
		case 3:
			out[outByteIdx] |= 1 << outBitIdx
			carry = 1
		}
	}

	// Handle end-around carry (ones-complement)
	if carry == 1 {
		carryArray := make([]byte, len(n1))
		carryArray[len(carryArray)-1] = 1
		out = onesComplementAdd(out, carryArray)
	}
	return out
}

// gcd computes the greatest common divisor.
func gcd(a, b int) int {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}

// lcm computes the least common multiple.
func lcm(a, b int) int {
	return a * b / gcd(a, b)
}
