package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
)

func TestEndToEndEncryptReconstruct(t *testing.T) {
	dir := t.TempDir()

	inPath := filepath.Join(dir, "secret.txt")
	encPath := filepath.Join(dir, "secret.txt.enc")
	sharesDir := filepath.Join(dir, "shares")
	outPath := filepath.Join(dir, "secret.txt.out")

	original := []byte("The quick brown fox jumps over the lazy dog. This is the secret payload.\n")
	if err := os.WriteFile(inPath, original, 0o600); err != nil {
		t.Fatalf("writing input file: %v", err)
	}

	numShares, threshold := 5, 3
	if err := runEncrypt(inPath, encPath, sharesDir, numShares, threshold); err != nil {
		t.Fatalf("runEncrypt: %v", err)
	}

	// All numShares share files should exist.
	entries, err := os.ReadDir(sharesDir)
	if err != nil {
		t.Fatalf("reading shares dir: %v", err)
	}
	if len(entries) != numShares {
		t.Fatalf("expected %d share files, got %d", numShares, len(entries))
	}

	if err := runReconstruct(encPath, sharesDir, outPath, true); err != nil {
		t.Fatalf("runReconstruct: %v", err)
	}

	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("reading output file: %v", err)
	}
	if !bytes.Equal(got, original) {
		t.Fatalf("reconstructed file does not match original\noriginal: %q\ngot:      %q", original, got)
	}
}

// verify that reconstruction succeeds when exactly `threshold`
// shares are available (removing the rest),
// and fails when fewer than `threshold` shares are available.
func TestReconstructWithExactThresholdShares(t *testing.T) {
	dir := t.TempDir()

	inPath := filepath.Join(dir, "data.bin")
	encPath := filepath.Join(dir, "data.bin.enc")
	sharesDir := filepath.Join(dir, "shares")
	//outPath := filepath.Join(dir, "data.bin.out")

	original := make([]byte, 4096)
	if _, err := rand.Read(original); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inPath, original, 0o600); err != nil {
		t.Fatalf("writing input file: %v", err)
	}

	numShares, threshold := 6, 4
	if err := runEncrypt(inPath, encPath, sharesDir, numShares, threshold); err != nil {
		t.Fatalf("runEncrypt: %v", err)
	}

	entries, err := os.ReadDir(sharesDir)
	if err != nil {
		t.Fatalf("reading shares dir: %v", err)
	}
	if len(entries) != numShares {
		t.Fatalf("expected %d share files, got %d", numShares, len(entries))
	}

	// --- Case 1: remove shares down to exactly `threshold`, reconstruction should succeed ---
	exactDir := filepath.Join(dir, "exact-shares")
	if err := os.MkdirAll(exactDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < threshold; i++ {
		src := filepath.Join(sharesDir, entries[i].Name())
		dst := filepath.Join(exactDir, entries[i].Name())
		copyFile(t, src, dst)
	}

	outExact := filepath.Join(dir, "out-exact.bin")
	if err := runReconstruct(encPath, exactDir, outExact, true); err != nil {
		t.Fatalf("runReconstruct with exactly threshold shares: %v", err)
	}
	got, err := os.ReadFile(outExact)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) {
		t.Fatal("reconstructed file with exactly threshold shares does not match original")
	}

	// Case 2: one fewer than `threshold`, reconstruction should fail
	tooFewDir := filepath.Join(dir, "too-few-shares")
	if err := os.MkdirAll(tooFewDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < threshold-1; i++ {
		src := filepath.Join(sharesDir, entries[i].Name())
		dst := filepath.Join(tooFewDir, entries[i].Name())
		copyFile(t, src, dst)
	}

	outTooFew := filepath.Join(dir, "out-too-few.bin")
	if err := runReconstruct(encPath, tooFewDir, outTooFew, true); err == nil {
		t.Fatal("expected error when reconstructing with fewer than threshold shares, got nil")
	}
}

// verify that a share signed with a different
// (forged) Ed25519 key is detected and excluded during reconstruction, and
// that reconstruction still succeeds using the genuine shares alone.
func TestForgedShareIsRejected(t *testing.T) {
	dir := t.TempDir()

	inPath := filepath.Join(dir, "data.txt")
	encPath := filepath.Join(dir, "data.txt.enc")
	sharesDir := filepath.Join(dir, "shares")
	outPath := filepath.Join(dir, "data.txt.out")

	original := []byte("forged share detection test payload")
	if err := os.WriteFile(inPath, original, 0o600); err != nil {
		t.Fatal(err)
	}

	numShares, threshold := 5, 3
	if err := runEncrypt(inPath, encPath, sharesDir, numShares, threshold); err != nil {
		t.Fatalf("runEncrypt: %v", err)
	}

	// Forge a share signed with a brand-new (attacker) keypair, using a
	// share index that does not collide with any genuine share.
	_, forgedPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	forged := Share{
		Index: uint16(numShares + 1),
		Y:     make([]uint16, shareYCount),
	}
	for i := range forged.Y {
		forged.Y[i] = uint16(i * 1234)
	}
	signedData, err := encodeSignedShare(forged)
	if err != nil {
		t.Fatal(err)
	}
	forged.Signature = ed25519.Sign(forgedPriv, signedData)

	forgedPath := filepath.Join(sharesDir, "share-99999.shr")
	if err := writeShareFile(forgedPath, forged); err != nil {
		t.Fatal(err)
	}

	// In strict mode (the default), detecting the forged share should
	// abort reconstruction entirely, even though enough genuine shares
	// remain to satisfy the threshold.
	if err := runReconstruct(encPath, sharesDir, outPath, true); err == nil {
		t.Fatal("expected runReconstruct to abort in strict mode when a forged share is present")
	}

	// With -strict=false, the old behaviour is preserved: the forged share
	// is discarded and reconstruction succeeds using the genuine shares.
	if err := runReconstruct(encPath, sharesDir, outPath, false); err != nil {
		t.Fatalf("runReconstruct (strict=false) with a forged share present: %v", err)
	}

	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) {
		t.Fatal("reconstructed file does not match original when a forged share is present")
	}
}

// verify that modifying the data of a
// genuinely-issued share (without re-signing it) invalidates its signature
// and causes it to be excluded during reconstruction.
func TestTamperedShareIsRejected(t *testing.T) {
	dir := t.TempDir()

	inPath := filepath.Join(dir, "data.txt")
	encPath := filepath.Join(dir, "data.txt.enc")
	sharesDir := filepath.Join(dir, "shares")
	outPath := filepath.Join(dir, "data.txt.out")

	original := []byte("tampered share detection test payload")
	if err := os.WriteFile(inPath, original, 0o600); err != nil {
		t.Fatal(err)
	}

	// threshold == numShares so that tampering with even one share would
	// otherwise make reconstruction impossible if it were silently trusted;
	// the test verifies it is instead correctly rejected and so
	// reconstruction (correctly) fails since too few valid shares remain.
	numShares, threshold := 3, 3
	if err := runEncrypt(inPath, encPath, sharesDir, numShares, threshold); err != nil {
		t.Fatalf("runEncrypt: %v", err)
	}

	entries, err := os.ReadDir(sharesDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != numShares {
		t.Fatalf("expected %d shares, got %d", numShares, len(entries))
	}

	// Tamper with the first share file's data byte (within the signed
	// portion), without updating its signature.
	tamperedPath := filepath.Join(sharesDir, entries[0].Name())
	data, err := os.ReadFile(tamperedPath)
	if err != nil {
		t.Fatal(err)
	}
	data[10] ^= 0xFF // flip a byte inside the signed share-data region
	if err := os.WriteFile(tamperedPath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	// With one share tampered (and thus rejected) and threshold == numShares,
	// only numShares-1 valid shares remain, which is below the threshold, so
	// reconstruction should fail regardless of -strict.
	if err := runReconstruct(encPath, sharesDir, outPath, true); err == nil {
		t.Fatal("expected reconstruction to fail when a required share is tampered with (strict)")
	}

	// It should also fail in non-strict mode, since even discarding the
	// tampered share leaves too few valid shares to hit the threshold.
	if err := runReconstruct(encPath, sharesDir, outPath, false); err == nil {
		t.Fatal("expected reconstruction to fail when a required share is tampered with (non-strict)")
	}
}

// TestStrictModeAbortsEvenWithEnoughGenuineShares verifies that -strict
// (the default) refuses to reconstruct the moment any share fails
// signature verification, even when enough genuine, untampered shares are
// present to satisfy the threshold on their own.
func TestStrictModeAbortsEvenWithEnoughGenuineShares(t *testing.T) {
	dir := t.TempDir()

	inPath := filepath.Join(dir, "data.txt")
	encPath := filepath.Join(dir, "data.txt.enc")
	sharesDir := filepath.Join(dir, "shares")
	outPath := filepath.Join(dir, "data.txt.out")

	original := []byte("strict mode test payload")
	if err := os.WriteFile(inPath, original, 0o600); err != nil {
		t.Fatal(err)
	}

	// threshold < numShares, so one tampered share still leaves enough
	// genuine shares to reconstruct if they were silently discarded.
	numShares, threshold := 5, 3
	if err := runEncrypt(inPath, encPath, sharesDir, numShares, threshold); err != nil {
		t.Fatalf("runEncrypt: %v", err)
	}

	entries, err := os.ReadDir(sharesDir)
	if err != nil {
		t.Fatal(err)
	}

	tamperedPath := filepath.Join(sharesDir, entries[0].Name())
	data, err := os.ReadFile(tamperedPath)
	if err != nil {
		t.Fatal(err)
	}
	data[10] ^= 0xFF
	if err := os.WriteFile(tamperedPath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	// 4 genuine shares remain (>= threshold of 3), but strict mode should
	// still refuse to reconstruct because a tampered share was detected.
	if err := runReconstruct(encPath, sharesDir, outPath, true); err == nil {
		t.Fatal("expected strict-mode reconstruction to abort despite enough genuine shares remaining")
	}

	// Non-strict mode should succeed, discarding the tampered share.
	if err := runReconstruct(encPath, sharesDir, outPath, false); err != nil {
		t.Fatalf("runReconstruct (strict=false): %v", err)
	}
	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) {
		t.Fatal("reconstructed file does not match original in non-strict mode")
	}
}

// TestValidateReportsSignatureStatus checks that runValidate correctly
// reports genuine, forged, and tampered shares without attempting any
// reconstruction.
func TestValidateReportsSignatureStatus(t *testing.T) {
	dir := t.TempDir()

	inPath := filepath.Join(dir, "data.txt")
	encPath := filepath.Join(dir, "data.txt.enc")
	sharesDir := filepath.Join(dir, "shares")

	original := []byte("validate command test payload")
	if err := os.WriteFile(inPath, original, 0o600); err != nil {
		t.Fatal(err)
	}

	numShares, threshold := 4, 2
	if err := runEncrypt(inPath, encPath, sharesDir, numShares, threshold); err != nil {
		t.Fatalf("runEncrypt: %v", err)
	}

	// All genuine shares present: validate should report success (nil error).
	if err := runValidate(encPath, sharesDir); err != nil {
		t.Fatalf("runValidate on genuine shares: %v", err)
	}

	// Tamper with one share; validate should now return an error, since it
	// found a share that failed signature verification.
	entries, err := os.ReadDir(sharesDir)
	if err != nil {
		t.Fatal(err)
	}
	tamperedPath := filepath.Join(sharesDir, entries[0].Name())
	data, err := os.ReadFile(tamperedPath)
	if err != nil {
		t.Fatal(err)
	}
	data[10] ^= 0xFF
	if err := os.WriteFile(tamperedPath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := runValidate(encPath, sharesDir); err == nil {
		t.Fatal("expected runValidate to report an error after tampering with a share")
	}
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
