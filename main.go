package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "encrypt":
		cmdEncrypt(os.Args[2:])
	case "reconstruct":
		cmdReconstruct(os.Args[2:])
	case "validate":
		cmdValidate(os.Args[2:])
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %q\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`sss-tool -- Shamir's Secret Sharing file encryption

USAGE:
  sss-tool encrypt -in <file> -out <encrypted-file> -sharesdir <dir> [-shares N] [-threshold T]
  sss-tool reconstruct -in <encrypted-file> -sharesdir <dir> -out <file> [-strict=true|false]
  sss-tool validate -in <encrypted-file> -sharesdir <dir>

COMMANDS:
  encrypt
        Encrypts <file> with a randomly generated AES-256 key (AES-256-GCM),
        writes the encrypted file to <encrypted-file>, and splits the AES
        key into N shares (T of which are required to reconstruct it) using
        Shamir's Secret Sharing over GF(65536). Each share is signed with a
        one-time Ed25519 key; the corresponding public key is embedded in
        the encrypted file so reconstruction can detect forged/tampered
        shares.

  reconstruct
        Reads the shares from <dir>, verifies each share's signature against
        the public key embedded in <encrypted-file>, discards any that fail
        verification, reconstructs the AES key from the remaining shares
        (at least T are required), and decrypts <encrypted-file> into
        <file>.

        By default (-strict=true) reconstruction is aborted the moment any
        share fails signature verification -- a forged or tampered share is
        treated as a sign that something is wrong (an attacker, a bit-rot
        share, a mixed-up shares directory, etc.) and reconstruction refuses
        to proceed even if enough genuine shares remain. Pass -strict=false
        to restore the old behaviour of discarding invalid shares and
        proceeding as long as enough valid ones are left.

  validate
        Reads the shares from <dir> and verifies each one's signature
        against the public key embedded in <encrypted-file>, without
        reconstructing the key or touching the ciphertext. Useful for
        auditing a set of shares (e.g. checking a custodian's share is
        genuine and untampered) without needing a quorum of shares at all.

Run "sss-tool encrypt -h", "sss-tool reconstruct -h", or "sss-tool validate -h"
for flag details.`)
}

func cmdEncrypt(args []string) {
	fs := flag.NewFlagSet("encrypt", flag.ExitOnError)
	inPath := fs.String("in", "", "path to the file to encrypt (required)")
	outPath := fs.String("out", "", "path to write the encrypted file (required)")
	sharesDir := fs.String("sharesdir", "", "directory to write the key shares into (required, will be created)")
	numShares := fs.Int("shares", 5, "total number of shares to generate (1-65535)")
	threshold := fs.Int("threshold", 3, "number of shares required to reconstruct the key (>=2, <= shares)")
	fs.Parse(args)

	if *inPath == "" || *outPath == "" || *sharesDir == "" {
		fmt.Fprintln(os.Stderr, "error: -in, -out and -sharesdir are all required")
		fs.Usage()
		os.Exit(1)
	}
	if *numShares < 1 || *numShares > 65535 {
		fmt.Fprintln(os.Stderr, "error: -shares must be between 1 and 65535")
		os.Exit(1)
	}
	if *threshold < 2 || *threshold > *numShares {
		fmt.Fprintln(os.Stderr, "error: -threshold must be >= 2 and <= -shares")
		os.Exit(1)
	}

	if err := runEncrypt(*inPath, *outPath, *sharesDir, *numShares, *threshold); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func runEncrypt(inPath, outPath, sharesDir string, numShares, threshold int) error {
	plaintext, err := os.ReadFile(inPath)
	if err != nil {
		return fmt.Errorf("reading input file: %w", err)
	}

	// 1. Generate a random AES-256 key.
	key, err := generateAESKey()
	if err != nil {
		return fmt.Errorf("generating AES key: %w", err)
	}

	// 2. Generate a fresh nonce separately so it can be included in the
	//    header before encryption. This allows the header (including the
	//    nonce itself) to be used as GCM Additional Authenticated Data
	//    (AAD), binding the ciphertext to this specific header.
	nonce, err := generateNonce()
	if err != nil {
		return fmt.Errorf("generating nonce: %w", err)
	}

	// 3. Generate a one-time Ed25519 keypair used to sign the shares.
	//    The public key becomes part of the encrypted file (it is not
	//    secret) and acts as the trust anchor for verifying shares during
	//    reconstruction. The private key is used only in memory below and
	//    is never written to disk.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generating signing key: %w", err)
	}

	// 4. Build the header now (before encryption) so all header fields,
	//    including the nonce and public key, are covered by the GCM tag.
	header := EncryptedFileHeader{
		Version:     encVersion,
		PublicKey:   pub,
		Threshold:   uint16(threshold),
		TotalShares: uint16(numShares),
		Nonce:       nonce,
	}
	aad, err := marshalHeader(header)
	if err != nil {
		return fmt.Errorf("encoding header for AAD: %w", err)
	}

	// 5. Encrypt the file. The header bytes are the AAD, so any tampering
	//    with the public key, threshold, nonce, etc. will cause decryption
	//    to fail with an explicit authentication error.
	ciphertext, err := encryptAESGCM(key, nonce, plaintext, aad)
	if err != nil {
		return fmt.Errorf("encrypting file: %w", err)
	}

	// 6. Write the encrypted file (header + ciphertext).
	if err := writeEncryptedFile(outPath, header, ciphertext); err != nil {
		return fmt.Errorf("writing encrypted file: %w", err)
	}

	// 7. Split the AES-256 key (16 GF(65536) elements) into shares.
	elems := keyToElements(key)
	shares, err := shamirSplit(elems, numShares, threshold)
	if err != nil {
		return fmt.Errorf("splitting key: %w", err)
	}

	// 8. Sign each share and write it to sharesDir.
	//
	// Signing and writing are independent per share, so we run them in a
	// worker pool sized to GOMAXPROCS. This gives close to linear speedup
	// for the Ed25519 signing (the dominant CPU cost) and lets the OS
	// pipeline concurrent file writes. Errors from any goroutine are
	// collected and the first one is returned after all workers finish.
	if err := os.MkdirAll(sharesDir, 0o700); err != nil {
		return fmt.Errorf("creating shares directory: %w", err)
	}

	type workItem struct {
		idx uint16
		y   []uint16
	}
	workers := runtime.GOMAXPROCS(0)
	work := make(chan workItem, workers*2)
	errs := make(chan error, len(shares))

	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range work {
				s := Share{Index: item.idx, Y: item.y}
				signedData, err := encodeSignedShare(s)
				if err != nil {
					errs <- fmt.Errorf("encoding share %d: %w", item.idx, err)
					continue
				}
				s.Signature = ed25519.Sign(priv, signedData)
				fname := filepath.Join(sharesDir, fmt.Sprintf("share-%05d.shr", item.idx))
				if err := writeShareFile(fname, s); err != nil {
					errs <- fmt.Errorf("writing share file %s: %w", fname, err)
				}
			}
		}()
	}

	for idx, y := range shares {
		work <- workItem{idx, y}
	}
	close(work)
	wg.Wait()
	close(errs)

	if err := <-errs; err != nil {
		return err
	}

	fmt.Printf("Encrypted %q -> %q (AES-256-GCM)\n", inPath, outPath)
	fmt.Printf("Generated %d shares (threshold %d) in %q\n", numShares, threshold, sharesDir)
	return nil
}

func cmdReconstruct(args []string) {
	fs := flag.NewFlagSet("reconstruct", flag.ExitOnError)
	inPath := fs.String("in", "", "path to the encrypted file (required)")
	sharesDir := fs.String("sharesdir", "", "directory containing key share files (required)")
	outPath := fs.String("out", "", "path to write the decrypted (original) file (required)")
	strict := fs.Bool("strict", true, "abort reconstruction if any share fails signature verification "+
		"(forged or tampered share detected), even if enough genuine shares remain. Set -strict=false to "+
		"instead discard invalid shares and proceed as long as enough valid ones are left")
	fs.Parse(args)

	if *inPath == "" || *sharesDir == "" || *outPath == "" {
		fmt.Fprintln(os.Stderr, "error: -in, -sharesdir and -out are all required")
		fs.Usage()
		os.Exit(1)
	}

	if err := runReconstruct(*inPath, *sharesDir, *outPath, *strict); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// shareStats summarises the outcome of verifying every file found in a
// shares directory against a trust-anchor public key.
type shareStats struct {
	Accepted   int
	Rejected   int // failed signature verification, or invalid index 0
	Skipped    int // unreadable / malformed share files
	Duplicates int
}

// collectValidShares reads every file in sharesDir, verifies its Ed25519
// signature against pubKey, and returns the accepted shares (index -> Y)
// together with verification statistics. It performs no reconstruction and
// does not require any particular number of shares to be present -- it is
// shared by both `reconstruct` and `validate`.
func collectValidShares(pubKey ed25519.PublicKey, sharesDir string) (map[uint16][]uint16, shareStats, error) {
	entries, err := os.ReadDir(sharesDir)
	if err != nil {
		return nil, shareStats{}, fmt.Errorf("reading shares directory: %w", err)
	}

	validShares := make(map[uint16][]uint16)
	var stats shareStats

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		path := filepath.Join(sharesDir, entry.Name())

		share, signedData, err := readShareFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skipping %q: %v\n", entry.Name(), err)
			stats.Skipped++
			continue
		}

		if !ed25519.Verify(pubKey, signedData, share.Signature) {
			fmt.Fprintf(os.Stderr, "WARNING: %q failed signature verification -- ignoring (forged or tampered share)\n", entry.Name())
			stats.Rejected++
			continue
		}

		if share.Index == 0 {
			fmt.Fprintf(os.Stderr, "WARNING: %q has invalid share index 0 -- ignoring\n", entry.Name())
			stats.Rejected++
			continue
		}

		if _, exists := validShares[share.Index]; exists {
			fmt.Fprintf(os.Stderr, "WARNING: %q is a duplicate of share index %d -- ignoring\n", entry.Name(), share.Index)
			stats.Duplicates++
			continue
		}

		validShares[share.Index] = share.Y
		stats.Accepted++
	}

	return validShares, stats, nil
}

func runReconstruct(inPath, sharesDir, outPath string, strict bool) error {
	header, ciphertext, aad, err := readEncryptedFile(inPath)
	if err != nil {
		return fmt.Errorf("reading encrypted file: %w", err)
	}

	validShares, stats, err := collectValidShares(header.PublicKey, sharesDir)
	if err != nil {
		return err
	}

	fmt.Printf("Shares: %d valid, %d failed verification, %d unreadable, %d duplicate (threshold %d)\n",
		stats.Accepted, stats.Rejected, stats.Skipped, stats.Duplicates, header.Threshold)

	// In strict mode (the default), any share that fails verification is
	// treated as a reason to stop rather than something to quietly work
	// around: a forged/tampered share indicates an attacker, corruption, or
	// a mixed-up shares directory, and reconstruction should not proceed
	// silently even if a valid quorum happens to remain.
	if strict && stats.Rejected > 0 {
		return fmt.Errorf("aborting: %d share(s) failed signature verification (forged or tampered) -- "+
			"refusing to reconstruct in strict mode; re-run with -strict=false to proceed using only the "+
			"valid shares", stats.Rejected)
	}

	if stats.Accepted < int(header.Threshold) {
		return fmt.Errorf("not enough valid shares: have %d, need at least %d", stats.Accepted, header.Threshold)
	}

	// Use exactly `threshold` valid shares for reconstruction. Any subset of
	// that size will produce the same result if the shares are genuine.
	limited := make(map[uint16][]uint16, header.Threshold)
	count := 0
	for idx, y := range validShares {
		if count >= int(header.Threshold) {
			break
		}
		limited[idx] = y
		count++
	}

	elems, err := shamirCombine(limited)
	if err != nil {
		return fmt.Errorf("reconstructing key: %w", err)
	}
	key := elementsToKey(elems)

	// Pass the same header bytes as AAD that were used during encryption.
	// If the header has been tampered with, decryption will fail here with
	// an authentication error rather than silently accepting a corrupt key.
	plaintext, err := decryptAESGCM(key, header.Nonce, ciphertext, aad)
	if err != nil {
		return fmt.Errorf("%w (the reconstructed key is invalid -- check that the shares belong to this file)", err)
	}

	if err := os.WriteFile(outPath, plaintext, 0o600); err != nil {
		return fmt.Errorf("writing output file: %w", err)
	}

	fmt.Printf("Reconstructed key from %d shares and decrypted %q -> %q\n", len(limited), inPath, outPath)
	return nil
}

func cmdValidate(args []string) {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	inPath := fs.String("in", "", "path to the encrypted file, used as the trust anchor for the shares' public key (required)")
	sharesDir := fs.String("sharesdir", "", "directory containing key share files to validate (required)")
	fs.Parse(args)

	if *inPath == "" || *sharesDir == "" {
		fmt.Fprintln(os.Stderr, "error: -in and -sharesdir are both required")
		fs.Usage()
		os.Exit(1)
	}

	if err := runValidate(*inPath, *sharesDir); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// runValidate checks every share file's Ed25519 signature against the
// public key embedded in the encrypted file at inPath. Unlike
// runReconstruct, it never touches the ciphertext and never attempts
// Lagrange interpolation -- it is purely a signature-verification report,
// and works with any number of shares (including fewer than the
// threshold).
func runValidate(inPath, sharesDir string) error {
	header, _, _, err := readEncryptedFile(inPath)
	if err != nil {
		return fmt.Errorf("reading encrypted file: %w", err)
	}

	_, stats, err := collectValidShares(header.PublicKey, sharesDir)
	if err != nil {
		return err
	}

	fmt.Printf("Shares: %d valid, %d failed verification, %d unreadable, %d duplicate (threshold %d)\n",
		stats.Accepted, stats.Rejected, stats.Skipped, stats.Duplicates, header.Threshold)

	if stats.Accepted >= int(header.Threshold) {
		fmt.Printf("Result: OK -- %d valid share(s) available, meeting the threshold of %d.\n", stats.Accepted, header.Threshold)
	} else {
		fmt.Printf("Result: INSUFFICIENT -- only %d valid share(s) available, threshold is %d.\n", stats.Accepted, header.Threshold)
	}

	if stats.Rejected > 0 {
		return fmt.Errorf("%d share(s) failed signature verification (forged or tampered)", stats.Rejected)
	}
	return nil
}
