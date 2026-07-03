package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
)

const (
	aesKeySize = 32 // AES-256
	nonceSize  = 12 // standard GCM nonce size
)

// generateAESKey returns a fresh random 32-byte (AES-256) key.
func generateAESKey() ([]byte, error) {
	key := make([]byte, aesKeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

// generateNonce returns a fresh random 12-byte GCM nonce.
func generateNonce() ([]byte, error) {
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return nonce, nil
}

// encryptAESGCM encrypts plaintext under key using AES-256-GCM with the
// supplied nonce and additional authenticated data (aad). The returned
// ciphertext includes the GCM authentication tag (as appended by
// cipher.AEAD.Seal).
//
// The caller is responsible for generating the nonce (see generateNonce)
// before building the AAD, so that the nonce itself can be part of the AAD
// and is therefore integrity-protected along with the rest of the header.
func encryptAESGCM(key, nonce, plaintext, aad []byte) (ciphertext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ciphertext = gcm.Seal(nil, nonce, plaintext, aad)
	return ciphertext, nil
}

// decryptAESGCM decrypts ciphertext (which must include the GCM
// authentication tag) using AES-256-GCM with the given key, nonce, and
// additional authenticated data (aad). It returns an error if the
// key/nonce/aad are wrong or the ciphertext has been tampered with.
//
// aad must be the identical byte slice that was passed to encryptAESGCM;
// any modification to the header (public key, threshold, nonce, etc.) will
// cause this function to return an error rather than silently producing
// garbage plaintext.
func decryptAESGCM(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, errors.New("invalid nonce size")
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, errors.New("decryption failed: wrong key, or the file/shares have been tampered with")
	}
	return plaintext, nil
}

// keyToElements converts a 32-byte AES-256 key into 16 GF(65536) elements
// (each uint16 represents 2 bytes of the key, big-endian).
func keyToElements(key []byte) []uint16 {
	elems := make([]uint16, len(key)/2)
	for i := range elems {
		elems[i] = binary.BigEndian.Uint16(key[i*2 : i*2+2])
	}
	return elems
}

// elementsToKey converts GF(65536) elements back into the corresponding
// byte slice (the inverse of keyToElements).
func elementsToKey(elems []uint16) []byte {
	key := make([]byte, len(elems)*2)
	for i, e := range elems {
		binary.BigEndian.PutUint16(key[i*2:i*2+2], e)
	}
	return key
}
