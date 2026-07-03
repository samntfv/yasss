package main

// This file implements arithmetic in GF(2^16), the finite field with 65536
// elements. Elements are represented as uint16 values, where each value is
// interpreted as the coefficient vector of a polynomial of degree < 16 over
// GF(2) (i.e. bit i represents the coefficient of x^i).
//
// Addition/subtraction in this field is XOR.
// Multiplication is polynomial multiplication modulo an irreducible
// polynomial of degree 16 (gfModulus).
//
// gfModulus = 0x1100B represents x^16 + x^12 + x^3 + x + 1, which is
// irreducible over GF(2). This has been verified exhaustively: every
// element 1..65535 has a unique multiplicative inverse (see gf65536_test.go).
const gfModulus uint32 = 0x1100B

// gfAdd returns a + b (and a - b, which is the same operation in GF(2^n)).
func gfAdd(a, b uint16) uint16 {
	return a ^ b
}

// gfMul returns a * b in GF(2^16).
//
// It first computes the "carry-less" (XOR) product of a and b, which may
// have a degree up to 30, and then reduces the result modulo gfModulus
// (degree 16) by repeatedly XOR-ing in shifted copies of the modulus until
// the degree drops below 16.
//
// Both loops use branchless conditional XOR (bitmask derived from -(bit & 1)
// in uint32 arithmetic) rather than data-dependent if-statements, so the
// execution path does not vary with the values of a or b. This eliminates
// a timing side-channel when key material flows through gfMul during
// Lagrange interpolation.
func gfMul(a, b uint16) uint16 {
	var product uint32
	aa, bb := uint32(a), uint32(b)

	for i := 0; i < 16; i++ {
		// mask is 0xFFFFFFFF when the low bit of bb is 1, and 0 otherwise.
		// In uint32 two's complement: -(1) == 0xFFFFFFFF, -(0) == 0.
		mask := -(bb & 1)
		product ^= aa & mask
		bb >>= 1
		aa <<= 1
	}

	// Reduce modulo gfModulus. product has degree at most 30, gfModulus has
	// degree 16, so we eliminate bits 30 down to 16.
	for i := 30; i >= 16; i-- {
		bit := (product >> uint(i)) & 1
		mask := -bit // 0xFFFFFFFF if bit is set, 0 otherwise
		product ^= (gfModulus << uint(i-16)) & mask
	}

	return uint16(product)
}

// gfPow returns a^e in GF(2^16) using square-and-multiply.
func gfPow(a uint16, e uint32) uint16 {
	result := uint16(1)
	base := a
	for e > 0 {
		if e&1 == 1 {
			result = gfMul(result, base)
		}
		base = gfMul(base, base)
		e >>= 1
	}
	return result
}

// gfInv returns the multiplicative inverse of a in GF(2^16).
//
// The multiplicative group of GF(2^16) has order 2^16 - 1 = 65535, so for
// any non-zero a, a^65535 = 1, which means a^65534 = a^-1 (Fermat's little
// theorem analogue for finite fields). This avoids needing the extended
// Euclidean algorithm or a primitive-element/log table.
func gfInv(a uint16) uint16 {
	if a == 0 {
		panic("gf65536: attempted to invert zero")
	}
	return gfPow(a, 0xFFFE) // 65534 = 2^16 - 2
}

// gfDiv returns a / b in GF(2^16). b must be non-zero.
func gfDiv(a, b uint16) uint16 {
	return gfMul(a, gfInv(b))
}
