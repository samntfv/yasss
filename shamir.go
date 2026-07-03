package main

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
)

// This file implements Shamir's Secret Sharing (SSS) over GF(2^16).
//
// A secret is represented as a slice of uint16 "elements" (e.g. a 32-byte
// AES-256 key is represented as 16 elements of 2 bytes each). Each element
// is shared independently using its own random polynomial of degree
// (threshold - 1), evaluated at points x = 1, 2, ..., n (the share
// indices). Because GF(2^16) has 65535 non-zero elements, share indices
// 1..65535 are all valid, supporting up to 65535 shares.
//
// Reconstruction uses Lagrange interpolation at x = 0 to recover the
// constant term of each polynomial, which is the corresponding secret
// element.

// shamirSplit splits each element of secret into n shares, any t of which
// are required (and sufficient) to reconstruct the secret.
//
// It returns a map from share index (1..n) to the share's slice of
// elements (same length as secret).
func shamirSplit(secret []uint16, n, t int) (map[uint16][]uint16, error) {
	if t < 2 {
		return nil, errors.New("threshold must be at least 2")
	}
	if n < t {
		return nil, errors.New("number of shares must be >= threshold")
	}
	if n < 1 || n > 65535 {
		return nil, errors.New("number of shares must be between 1 and 65535")
	}

	shares := make(map[uint16][]uint16, n)
	for x := 1; x <= n; x++ {
		shares[uint16(x)] = make([]uint16, len(secret))
	}

	coeffBuf := make([]byte, 2)
	coeffs := make([]uint16, t)
	for i, s := range secret {
		// coeffs[0] is the secret element itself (the constant term of the
		// polynomial). coeffs[1..t-1] are random.
		coeffs[0] = s
		for j := 1; j < t; j++ {
			if _, err := rand.Read(coeffBuf); err != nil {
				return nil, err
			}
			coeffs[j] = binary.BigEndian.Uint16(coeffBuf)
		}

		// The leading coefficient coeffs[t-1] must be non-zero. A zero
		// leading coefficient reduces the polynomial's effective degree
		// below (t-1), which means fewer than t shares could reconstruct
		// this element of the secret, breaking the threshold guarantee.
		// The probability is 1/65536 per element, so resample if needed.
		for coeffs[t-1] == 0 {
			if _, err := rand.Read(coeffBuf); err != nil {
				return nil, err
			}
			coeffs[t-1] = binary.BigEndian.Uint16(coeffBuf)
		}

		for x := 1; x <= n; x++ {
			shares[uint16(x)][i] = evalPoly(coeffs, uint16(x))
		}
	}

	return shares, nil
}

// evalPoly evaluates the polynomial with the given coefficients (coeffs[0]
// is the constant term) at the point x, using Horner's method in GF(2^16).
func evalPoly(coeffs []uint16, x uint16) uint16 {
	var result uint16
	for i := len(coeffs) - 1; i >= 0; i-- {
		result = gfAdd(gfMul(result, x), coeffs[i])
	}
	return result
}

// shamirCombine reconstructs the original secret from a set of shares using
// Lagrange interpolation at x = 0. The map keys are the share indices (the
// x-coordinates) and the values are the per-element share data.
//
// At least `threshold` shares (as originally chosen by shamirSplit) must be
// supplied, or the result will be garbage (this function cannot detect
// that on its own -- callers should verify shares cryptographically before
// calling this, and/or verify the result by attempting decryption).
//
// Performance: the Lagrange basis coefficient l_i(0) for each share index
// x_i depends only on the set of x-coordinates {x_1, ..., x_T}, not on
// which secret element is being interpolated. The naive approach
// recomputes l_i(0) from scratch for every one of the `secretLen` elements,
// costing O(secretLen * T^2) field operations. Instead, we compute each
// l_i(0) exactly once (O(T^2) total, dominated by the T denominators, each
// O(T)) and reuse it across all `secretLen` elements, reducing the overall
// cost to O(T^2 + secretLen*T).
//
// The numerator of l_i(0), product_{j != i} x_j, is further sped up using
// the identity product_{j != i} x_j = (product_j x_j) / x_i: the full
// product over all x_j is computed once in O(T), and each per-i numerator
// is then a single O(1) division, rather than an O(T) product.
func shamirCombine(shares map[uint16][]uint16) ([]uint16, error) {
	if len(shares) == 0 {
		return nil, errors.New("no shares provided")
	}

	var secretLen int
	for _, y := range shares {
		secretLen = len(y)
		break
	}
	for x, y := range shares {
		if len(y) != secretLen {
			return nil, errors.New("shares have inconsistent lengths")
		}
		if x == 0 {
			return nil, errors.New("share index 0 is invalid")
		}
	}

	xs := make([]uint16, 0, len(shares))
	for x := range shares {
		xs = append(xs, x)
	}

	// totalProd = product of all x_i. Since every x_i is a non-zero
	// element of GF(2^16) (share index 0 is rejected above), totalProd is
	// non-zero too, so dividing by it (or by any individual x_i below) is
	// always valid.
	totalProd := uint16(1)
	for _, x := range xs {
		totalProd = gfMul(totalProd, x)
	}

	// Precompute the Lagrange basis coefficient l_i(0) for each x_i once.
	//   l_i(0) = product_{j != i} (0 - x_j) / (x_i - x_j)
	// In GF(2^n), subtraction is XOR and "0 - x_j" is just x_j, so the
	// numerator is product_{j != i} x_j = totalProd / x_i.
	coeffs := make(map[uint16]uint16, len(xs))
	for _, xi := range xs {
		num := gfDiv(totalProd, xi)

		den := uint16(1)
		for _, xj := range xs {
			if xj == xi {
				continue
			}
			den = gfMul(den, gfAdd(xi, xj))
		}

		coeffs[xi] = gfDiv(num, den)
	}

	secret := make([]uint16, secretLen)
	for i := 0; i < secretLen; i++ {
		var acc uint16
		for _, xi := range xs {
			acc = gfAdd(acc, gfMul(shares[xi][i], coeffs[xi]))
		}
		secret[i] = acc
	}

	return secret, nil
}
