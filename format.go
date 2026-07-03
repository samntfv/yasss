package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ---------------------------------------------------------------------------
// Encrypted file format
//
//   offset  size  field
//   0       4     magic "SSE1"
//   4       1     version
//   5       32    Ed25519 public key (trust anchor for verifying shares)
//   37      2     threshold (uint16, big-endian)
//   39      2     total shares originally generated (uint16, big-endian, informational)
//   41      12    AES-GCM nonce
//   53      ...   AES-256-GCM ciphertext (includes 16-byte auth tag)
//
// The 53-byte header (offsets 0–52) is passed as Additional Authenticated
// Data (AAD) to AES-GCM, so that any modification to the header (public key,
// threshold, nonce, etc.) causes decryption to fail rather than silently
// producing garbage or a misleading "not enough shares" error.
// ---------------------------------------------------------------------------

var encMagic = [4]byte{'S', 'S', 'E', '1'}

const encVersion = 1

const encHeaderSize = 4 + 1 + ed25519.PublicKeySize + 2 + 2 + nonceSize // = 53

// EncryptedFileHeader holds the metadata stored at the start of an
// encrypted file.
type EncryptedFileHeader struct {
	Version     byte
	PublicKey   ed25519.PublicKey
	Threshold   uint16
	TotalShares uint16
	Nonce       []byte
}

// marshalHeader serialises the header fields into exactly encHeaderSize bytes.
// These bytes are also used as GCM Additional Authenticated Data (AAD) so
// that the public key, threshold, and nonce are all integrity-protected by
// the ciphertext's authentication tag.
func marshalHeader(header EncryptedFileHeader) ([]byte, error) {
	if len(header.PublicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key size: %d", len(header.PublicKey))
	}
	if len(header.Nonce) != nonceSize {
		return nil, fmt.Errorf("invalid nonce size: %d", len(header.Nonce))
	}

	buf := new(bytes.Buffer)
	buf.Write(encMagic[:])
	buf.WriteByte(header.Version)
	buf.Write(header.PublicKey)
	if err := binary.Write(buf, binary.BigEndian, header.Threshold); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, header.TotalShares); err != nil {
		return nil, err
	}
	buf.Write(header.Nonce)
	return buf.Bytes(), nil
}

// writeEncryptedFile writes the header followed by the ciphertext to path
// using an atomic write (write to a temp file, then rename) so that a
// partial write never leaves a truncated file at the destination.
func writeEncryptedFile(path string, header EncryptedFileHeader, ciphertext []byte) error {
	headerBytes, err := marshalHeader(header)
	if err != nil {
		return err
	}

	buf := new(bytes.Buffer)
	buf.Write(headerBytes)
	buf.Write(ciphertext)

	return atomicWriteFile(path, buf.Bytes(), 0o600)
}

// readEncryptedFile reads and parses the header and ciphertext from path.
// It also returns the raw header bytes so the caller can reconstruct the
// AAD for AES-GCM decryption.
func readEncryptedFile(path string) (EncryptedFileHeader, []byte, []byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return EncryptedFileHeader{}, nil, nil, err
	}
	if len(data) < encHeaderSize {
		return EncryptedFileHeader{}, nil, nil, errors.New("encrypted file is too small or corrupt")
	}
	if !bytes.Equal(data[0:4], encMagic[:]) {
		return EncryptedFileHeader{}, nil, nil, errors.New("not a valid encrypted file (bad magic)")
	}

	offset := 4
	version := data[offset]
	offset++
	if version != encVersion {
		return EncryptedFileHeader{}, nil, nil, fmt.Errorf("unsupported file version: %d", version)
	}

	pubKey := make([]byte, ed25519.PublicKeySize)
	copy(pubKey, data[offset:offset+ed25519.PublicKeySize])
	offset += ed25519.PublicKeySize

	threshold := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	totalShares := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	nonce := make([]byte, nonceSize)
	copy(nonce, data[offset:offset+nonceSize])
	offset += nonceSize

	// Capture the raw header bytes before advancing past them; these are
	// the AAD that was passed to AES-GCM during encryption.
	aad := make([]byte, encHeaderSize)
	copy(aad, data[0:encHeaderSize])

	ciphertext := data[offset:]

	header := EncryptedFileHeader{
		Version:     version,
		PublicKey:   ed25519.PublicKey(pubKey),
		Threshold:   threshold,
		TotalShares: totalShares,
		Nonce:       nonce,
	}
	return header, ciphertext, aad, nil
}

// ---------------------------------------------------------------------------
// Share file format
//
//   offset  size  field
//   0       4     magic "SSH1"
//   4       2     share index / x-coordinate (uint16, big-endian, 1..65535)
//   6       32    16 GF(65536) elements (uint16, big-endian) -- the share
//                  of the AES-256 key
//   38      64    Ed25519 signature over bytes [0:38]
// ---------------------------------------------------------------------------

var shareMagic = [4]byte{'S', 'S', 'H', '1'}

const shareYCount = 16 // 16 * uint16 = 32 bytes = AES-256 key

const shareSignedSize = 4 + 2 + shareYCount*2 // = 38
const shareFileSize = shareSignedSize + ed25519.SignatureSize

// Share represents a single key share.
type Share struct {
	Index     uint16
	Y         []uint16 // shareYCount elements
	Signature []byte   // ed25519.SignatureSize bytes
}

// encodeSignedShare returns the byte representation of the share that is
// signed / verified (everything except the signature itself).
func encodeSignedShare(s Share) ([]byte, error) {
	if len(s.Y) != shareYCount {
		return nil, fmt.Errorf("share must have exactly %d elements, got %d", shareYCount, len(s.Y))
	}
	buf := new(bytes.Buffer)
	buf.Write(shareMagic[:])
	if err := binary.Write(buf, binary.BigEndian, s.Index); err != nil {
		return nil, err
	}
	for _, y := range s.Y {
		if err := binary.Write(buf, binary.BigEndian, y); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

// writeShareFile writes a signed share to path using an atomic write
// (write to a temp file, then rename) so that a partial write never leaves
// a truncated or corrupt share file at the destination.
// s.Signature must already be populated.
func writeShareFile(path string, s Share) error {
	signedData, err := encodeSignedShare(s)
	if err != nil {
		return err
	}
	if len(s.Signature) != ed25519.SignatureSize {
		return fmt.Errorf("invalid signature size: %d", len(s.Signature))
	}

	buf := new(bytes.Buffer)
	buf.Write(signedData)
	buf.Write(s.Signature)

	return atomicWriteFile(path, buf.Bytes(), 0o600)
}

// readShareFile reads and parses a share file. It returns the parsed share
// and the exact byte slice that was signed (for use with ed25519.Verify),
// but does NOT verify the signature itself.
func readShareFile(path string) (Share, []byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Share{}, nil, err
	}
	if len(data) != shareFileSize {
		return Share{}, nil, fmt.Errorf("invalid share file size: got %d, expected %d", len(data), shareFileSize)
	}
	if !bytes.Equal(data[0:4], shareMagic[:]) {
		return Share{}, nil, errors.New("not a valid share file (bad magic)")
	}

	signedData := make([]byte, shareSignedSize)
	copy(signedData, data[0:shareSignedSize])

	index := binary.BigEndian.Uint16(data[4:6])

	y := make([]uint16, shareYCount)
	for i := 0; i < shareYCount; i++ {
		off := 6 + i*2
		y[i] = binary.BigEndian.Uint16(data[off : off+2])
	}

	sig := make([]byte, ed25519.SignatureSize)
	copy(sig, data[shareSignedSize:])

	return Share{Index: index, Y: y, Signature: sig}, signedData, nil
}

// atomicWriteFile writes data to path atomically by writing to a temporary
// file in the same directory and then renaming it into place. This ensures
// that a crash or power failure mid-write never leaves a truncated or
// corrupt file at path.
func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".sss-tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()

	// Clean up the temp file on any failure path. After a successful
	// Rename the temp path no longer exists, so Remove is a no-op.
	ok := false
	defer func() {
		if !ok {
			tmp.Close()
			os.Remove(tmpName)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	ok = true
	return nil
}
