// Package aescts provides AES-CBC with Ciphertext Stealing (CTS) encryption
// and decryption as specified in RFC 3962 for use with Kerberos.
//
// CTS is a variant of CBC mode that handles plaintexts that are not a multiple
// of the block size without requiring padding that increases message length.
package aescts

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

const blockSize = aes.BlockSize // 16 bytes

// Encrypt encrypts plaintext using AES-CBC with Ciphertext Stealing.
// The plaintext must be at least 16 bytes (one AES block).
// Returns the IV for the next encryption (next-to-last ciphertext block) and the ciphertext.
func Encrypt(key, iv, plaintext []byte) ([]byte, []byte, error) {
	l := len(plaintext)
	if l < blockSize {
		return nil, nil, errors.New("aescts: plaintext must be at least 16 bytes")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	// Make a working copy of the plaintext
	m := make([]byte, len(plaintext))
	copy(m, plaintext)

	// Make a copy of IV
	ivCopy := make([]byte, blockSize)
	copy(ivCopy, iv)

	mode := cipher.NewCBCEncrypter(block, ivCopy)

	// Case 1: Exactly one block - just encrypt it
	if l <= blockSize {
		m = zeroPad(m, blockSize)
		mode.CryptBlocks(m, m)
		return m, m, nil
	}

	// Case 2: Multiple of block size - encrypt with CBC, swap last two blocks
	if l%blockSize == 0 {
		mode.CryptBlocks(m, m)
		nextIV := make([]byte, blockSize)
		copy(nextIV, m[len(m)-blockSize:])
		swapLastTwoBlocks(m, blockSize)
		return nextIV, m, nil
	}

	// Case 3: Not a multiple of block size - use CTS
	// Pad plaintext to block size
	padded := zeroPad(m, blockSize)

	// Split into: rest blocks, penultimate block, last block
	restLen := (len(padded)/blockSize - 2) * blockSize
	var rest, pb, lb []byte
	if restLen > 0 {
		rest = padded[:restLen]
		pb = padded[restLen : restLen+blockSize]
		lb = padded[restLen+blockSize:]
	} else {
		pb = padded[:blockSize]
		lb = padded[blockSize:]
	}

	var ct []byte

	// Encrypt rest blocks with CBC
	if len(rest) > 0 {
		mode.CryptBlocks(rest, rest)
		// Update IV for next encryption
		copy(ivCopy, rest[len(rest)-blockSize:])
		mode = cipher.NewCBCEncrypter(block, ivCopy)
		ct = append(ct, rest...)
	}

	// Encrypt penultimate block
	mode.CryptBlocks(pb, pb)

	// Encrypt last block using pb as IV
	mode = cipher.NewCBCEncrypter(block, pb)
	mode.CryptBlocks(lb, lb)

	// CTS: append lb first, then pb truncated to original length
	ct = append(ct, lb...)
	ct = append(ct, pb...)

	// Truncate to original plaintext length
	ct = ct[:l]

	// Next IV is lb (the encrypted last block, which is now second-to-last in output)
	nextIV := make([]byte, blockSize)
	copy(nextIV, lb)

	return nextIV, ct, nil
}

// Decrypt decrypts ciphertext using AES-CBC with Ciphertext Stealing.
// The ciphertext must be at least 16 bytes (one AES block).
func Decrypt(key, iv, ciphertext []byte) ([]byte, error) {
	l := len(ciphertext)
	if l < blockSize {
		return nil, errors.New("aescts: ciphertext must be at least 16 bytes")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Make copies
	ct := make([]byte, l)
	copy(ct, ciphertext)
	ivCopy := make([]byte, blockSize)
	copy(ivCopy, iv)

	// Case 1 & 2: Multiple of block size (including single block)
	if l%blockSize == 0 {
		if l > blockSize {
			swapLastTwoBlocks(ct, blockSize)
		}
		mode := cipher.NewCBCDecrypter(block, ivCopy)
		mode.CryptBlocks(ct, ct)
		return ct, nil
	}

	// Case 3: Not a multiple of block size - use CTS decryption
	// Split into: rest blocks (crb), penultimate block (cpb), last block (clb - partial)
	restLen := (l/blockSize - 1) * blockSize
	var crb, cpb, clb []byte
	if restLen > 0 {
		crb = ct[:restLen]
		cpb = ct[restLen : restLen+blockSize]
		clb = ct[restLen+blockSize:]
	} else {
		cpb = ct[:blockSize]
		clb = ct[blockSize:]
	}

	// v is the IV that gets updated
	v := make([]byte, blockSize)
	copy(v, iv)

	var plaintext []byte

	// Decrypt rest blocks if any
	if len(crb) > 0 {
		rb := make([]byte, len(crb))
		mode := cipher.NewCBCDecrypter(block, v)
		copy(v, crb[len(crb)-blockSize:]) // Update v to last block of crb
		mode.CryptBlocks(rb, crb)
		plaintext = append(plaintext, rb...)
	}

	// Raw block decrypt of cpb (which is enc_lb in our naming) to get intermediate value
	// We use raw block decryption (not CBC) because we need the XOR mask, not the plaintext
	// intermediate = Dec_block(enc_lb) = enc_pb XOR padded_lb
	// Since padded_lb has zeros in the tail, intermediate[tail] = enc_pb[tail]
	intermediate := make([]byte, blockSize)
	block.Decrypt(intermediate, cpb)

	// Pad the last cipher block using tail bytes from intermediate
	// These bytes are the tail of enc_pb that we need to reconstruct the full enc_pb
	npb := blockSize - (l % blockSize) // number of padding bytes needed
	paddedClb := make([]byte, blockSize)
	copy(paddedClb, clb)
	copy(paddedClb[len(clb):], intermediate[blockSize-npb:])

	// Decrypt the padded last block (this becomes the penultimate plaintext)
	lb := make([]byte, blockSize)
	mode := cipher.NewCBCDecrypter(block, v)
	mode.CryptBlocks(lb, paddedClb)
	plaintext = append(plaintext, lb...)

	// Decrypt the penultimate cipher block with padded last block as IV
	// (this becomes the last plaintext, truncated)
	mode = cipher.NewCBCDecrypter(block, paddedClb)
	mode.CryptBlocks(cpb, cpb)
	plaintext = append(plaintext, cpb...)

	// Truncate to original ciphertext length
	return plaintext[:l], nil
}

// zeroPad pads data to a multiple of blockSize with zeros.
func zeroPad(data []byte, blockSize int) []byte {
	if len(data)%blockSize == 0 {
		return data
	}
	padLen := blockSize - (len(data) % blockSize)
	padded := make([]byte, len(data)+padLen)
	copy(padded, data)
	return padded
}

// swapLastTwoBlocks swaps the last two blocks of data in place.
func swapLastTwoBlocks(data []byte, blockSize int) {
	l := len(data)
	if l < 2*blockSize {
		return
	}
	// Swap last two blocks
	temp := make([]byte, blockSize)
	copy(temp, data[l-2*blockSize:l-blockSize])
	copy(data[l-2*blockSize:l-blockSize], data[l-blockSize:])
	copy(data[l-blockSize:], temp)
}
