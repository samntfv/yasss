package main

import (
	cryptorand "crypto/rand"
	rnd "math/rand"
	"testing"
)

func randomElements(n int, r *rnd.Rand) []uint16 {
	elems := make([]uint16, n)
	for i := range elems {
		elems[i] = uint16(r.Intn(0x10000))
	}
	return elems
}

func TestShamirSplitCombineRoundTrip(t *testing.T) {
	r := rnd.New(rnd.NewSource(42))
	secret := randomElements(16, r)

	n, threshold := 7, 4
	shares, err := shamirSplit(secret, n, threshold)
	if err != nil {
		t.Fatalf("shamirSplit: %v", err)
	}

	// Try every combination of `threshold` shares.
	xs := make([]uint16, 0, n)
	for x := range shares {
		xs = append(xs, x)
	}

	combos := combinations(xs, threshold)
	if len(combos) == 0 {
		t.Fatal("no combinations generated")
	}
	for _, combo := range combos {
		subset := make(map[uint16][]uint16, threshold)
		for _, x := range combo {
			subset[x] = shares[x]
		}
		recovered, err := shamirCombine(subset)
		if err != nil {
			t.Fatalf("shamirCombine: %v", err)
		}
		if !equalUint16(recovered, secret) {
			t.Fatalf("combo %v: recovered %v, want %v", combo, recovered, secret)
		}
	}
}

func TestShamirInsufficientSharesDoNotRevealSecret(t *testing.T) {
	r := rnd.New(rnd.NewSource(99))
	secret := randomElements(16, r)

	n, threshold := 5, 3
	shares, err := shamirSplit(secret, n, threshold)
	if err != nil {
		t.Fatalf("shamirSplit: %v", err)
	}

	xs := make([]uint16, 0, n)
	for x := range shares {
		xs = append(xs, x)
	}

	// threshold-1 shares should NOT reconstruct the secret.
	subset := make(map[uint16][]uint16, threshold-1)
	for i := 0; i < threshold-1; i++ {
		subset[xs[i]] = shares[xs[i]]
	}
	recovered, err := shamirCombine(subset)
	if err != nil {
		t.Fatalf("shamirCombine: %v", err)
	}
	if equalUint16(recovered, secret) {
		t.Fatal("threshold-1 shares should not reconstruct the secret")
	}
}

func TestShamirMoreThanThresholdShares(t *testing.T) {
	r := rnd.New(rnd.NewSource(7))
	secret := randomElements(16, r)

	n, threshold := 6, 3
	shares, err := shamirSplit(secret, n, threshold)
	if err != nil {
		t.Fatalf("shamirSplit: %v", err)
	}

	// Use all 6 shares -> should still reconstruct correctly.
	recovered, err := shamirCombine(shares)
	if err != nil {
		t.Fatalf("shamirCombine: %v", err)
	}
	if !equalUint16(recovered, secret) {
		t.Fatalf("recovered %v, want %v", recovered, secret)
	}
}

func TestShamirInvalidParams(t *testing.T) {
	secret := []uint16{1, 2, 3}

	if _, err := shamirSplit(secret, 5, 1); err == nil {
		t.Error("expected error for threshold < 2")
	}
	if _, err := shamirSplit(secret, 2, 3); err == nil {
		t.Error("expected error for threshold > n")
	}
	if _, err := shamirSplit(secret, 0, 0); err == nil {
		t.Error("expected error for n < 1")
	}
}

func TestShamirEndToEndWithAESKey(t *testing.T) {
	key := make([]byte, aesKeySize)
	if _, err := cryptorand.Read(key); err != nil {
		t.Fatal(err)
	}
	elems := keyToElements(key)
	if len(elems) != shareYCount {
		t.Fatalf("expected %d elements, got %d", shareYCount, len(elems))
	}

	n, threshold := 5, 3
	shares, err := shamirSplit(elems, n, threshold)
	if err != nil {
		t.Fatalf("shamirSplit: %v", err)
	}

	subset := make(map[uint16][]uint16, threshold)
	count := 0
	for x, y := range shares {
		if count >= threshold {
			break
		}
		subset[x] = y
		count++
	}

	recoveredElems, err := shamirCombine(subset)
	if err != nil {
		t.Fatalf("shamirCombine: %v", err)
	}
	recoveredKey := elementsToKey(recoveredElems)

	if string(recoveredKey) != string(key) {
		t.Fatalf("recovered key does not match original\noriginal:  %x\nrecovered: %x", key, recoveredKey)
	}
}

// --- helpers ---

func equalUint16(a, b []uint16) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// combinations returns all k-length combinations of xs.
func combinations(xs []uint16, k int) [][]uint16 {
	var result [][]uint16
	n := len(xs)
	if k > n {
		return result
	}
	indices := make([]int, k)
	for i := range indices {
		indices[i] = i
	}
	for {
		combo := make([]uint16, k)
		for i, idx := range indices {
			combo[i] = xs[idx]
		}
		result = append(result, combo)

		// advance indices
		i := k - 1
		for i >= 0 && indices[i] == n-k+i {
			i--
		}
		if i < 0 {
			break
		}
		indices[i]++
		for j := i + 1; j < k; j++ {
			indices[j] = indices[j-1] + 1
		}
	}
	return result
}
