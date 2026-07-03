package main

import (
	"math/rand"
	"testing"
)

// checks that every non-zero element of
// GF(2^16) has a correct multiplicative inverse under the chosen modulus,
// (ie it is a field)
func TestGFFieldAxioms(t *testing.T) {
	for a := 1; a <= 0xFFFF; a++ {
		inv := gfInv(uint16(a))
		if got := gfMul(uint16(a), inv); got != 1 {
			t.Fatalf("gfMul(%#04x, gfInv(%#04x)=%#04x) = %#04x, want 1", a, a, inv, got)
		}
	}
}

func TestGFAddIsXOR(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	for i := 0; i < 1000; i++ {
		a := uint16(r.Intn(0x10000))
		b := uint16(r.Intn(0x10000))
		if gfAdd(a, b) != a^b {
			t.Fatalf("gfAdd(%#04x, %#04x) != a^b", a, b)
		}
		// a + a == 0 (characteristic 2)
		if gfAdd(a, a) != 0 {
			t.Fatalf("gfAdd(%#04x, %#04x) != 0", a, a)
		}
	}
}

func TestGFMulIdentityAndZero(t *testing.T) {
	r := rand.New(rand.NewSource(2))
	for i := 0; i < 1000; i++ {
		a := uint16(r.Intn(0x10000))
		if gfMul(a, 1) != a {
			t.Fatalf("gfMul(%#04x, 1) = %#04x, want %#04x", a, gfMul(a, 1), a)
		}
		if gfMul(a, 0) != 0 {
			t.Fatalf("gfMul(%#04x, 0) != 0", a)
		}
	}
}

func TestGFMulCommutativeAndAssociative(t *testing.T) {
	r := rand.New(rand.NewSource(3))
	for i := 0; i < 1000; i++ {
		a := uint16(r.Intn(0x10000))
		b := uint16(r.Intn(0x10000))
		c := uint16(r.Intn(0x10000))

		if gfMul(a, b) != gfMul(b, a) {
			t.Fatalf("multiplication not commutative for %#04x, %#04x", a, b)
		}
		if gfMul(gfMul(a, b), c) != gfMul(a, gfMul(b, c)) {
			t.Fatalf("multiplication not associative for %#04x, %#04x, %#04x", a, b, c)
		}
	}
}

func TestGFDistributive(t *testing.T) {
	r := rand.New(rand.NewSource(4))
	for i := 0; i < 1000; i++ {
		a := uint16(r.Intn(0x10000))
		b := uint16(r.Intn(0x10000))
		c := uint16(r.Intn(0x10000))

		lhs := gfMul(a, gfAdd(b, c))
		rhs := gfAdd(gfMul(a, b), gfMul(a, c))
		if lhs != rhs {
			t.Fatalf("distributivity failed for %#04x, %#04x, %#04x: %#04x != %#04x", a, b, c, lhs, rhs)
		}
	}
}

func TestGFInvPanicsOnZero(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic when inverting zero")
		}
	}()
	gfInv(0)
}
