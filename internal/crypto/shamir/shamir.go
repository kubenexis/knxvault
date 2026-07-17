// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

// Package shamir implements Shamir's Secret Sharing over GF(2^8) for unseal shares.
package shamir

import (
	"crypto/rand"
	"fmt"
)

// Split splits secret into n shares with threshold t (need t shares to recover).
// Each share is [x || y0 || y1 || ... || y_{len-1}] with x in 1..255.
func Split(secret []byte, n, t int) ([][]byte, error) {
	if t < 1 || n < t || n > 255 {
		return nil, fmt.Errorf("shamir: need 1 <= t <= n <= 255")
	}
	if len(secret) == 0 {
		return nil, fmt.Errorf("shamir: empty secret")
	}
	shares := make([][]byte, n)
	for i := range shares {
		shares[i] = make([]byte, len(secret)+1)
		shares[i][0] = byte(i + 1) // x-coordinate
	}
	for i, b := range secret {
		coeffs := make([]byte, t)
		coeffs[0] = b
		if _, err := rand.Read(coeffs[1:]); err != nil {
			return nil, err
		}
		for x := 1; x <= n; x++ {
			shares[x-1][i+1] = evalPoly(coeffs, byte(x))
		}
	}
	return shares, nil
}

// Combine recovers the secret from at least t distinct shares.
func Combine(shares [][]byte) ([]byte, error) {
	if len(shares) < 1 {
		return nil, fmt.Errorf("shamir: need at least one share")
	}
	secretLen := len(shares[0]) - 1
	if secretLen < 1 {
		return nil, fmt.Errorf("shamir: invalid share length")
	}
	for _, s := range shares {
		if len(s) != secretLen+1 {
			return nil, fmt.Errorf("shamir: inconsistent share length")
		}
	}
	// Deduplicate by x
	byX := make(map[byte][]byte, len(shares))
	for _, s := range shares {
		x := s[0]
		if x == 0 {
			return nil, fmt.Errorf("shamir: invalid share x=0")
		}
		byX[x] = s
	}
	if len(byX) < 1 {
		return nil, fmt.Errorf("shamir: no valid shares")
	}
	xs := make([]byte, 0, len(byX))
	for x := range byX {
		xs = append(xs, x)
	}
	out := make([]byte, secretLen)
	for i := 0; i < secretLen; i++ {
		points := make([][2]byte, len(xs))
		for j, x := range xs {
			points[j] = [2]byte{x, byX[x][i+1]}
		}
		out[i] = interpolate(points, 0)
	}
	return out, nil
}

func evalPoly(coeffs []byte, x byte) byte {
	// Horner
	var y byte
	for i := len(coeffs) - 1; i >= 0; i-- {
		y = gfMul(y, x) ^ coeffs[i]
	}
	return y
}

// Lagrange interpolate y at x=0.
func interpolate(points [][2]byte, x byte) byte {
	var result byte
	for i := range points {
		xi, yi := points[i][0], points[i][1]
		num, den := byte(1), byte(1)
		for j := range points {
			if i == j {
				continue
			}
			xj := points[j][0]
			num = gfMul(num, gfSub(x, xj))
			den = gfMul(den, gfSub(xi, xj))
		}
		result ^= gfMul(yi, gfDiv(num, den))
	}
	return result
}

// GF(2^8) with AES polynomial 0x11b (add and sub are XOR).
func gfSub(a, b byte) byte { return a ^ b }

func gfMul(a, b byte) byte {
	var p byte
	for i := 0; i < 8; i++ {
		if b&1 != 0 {
			p ^= a
		}
		hi := a & 0x80
		a <<= 1
		if hi != 0 {
			a ^= 0x1b
		}
		b >>= 1
	}
	return p
}

func gfInv(a byte) byte {
	if a == 0 {
		return 0
	}
	return gfExp(a, 254)
}

func gfExp(a byte, e int) byte {
	r := byte(1)
	for e > 0 {
		if e&1 != 0 {
			r = gfMul(r, a)
		}
		a = gfMul(a, a)
		e >>= 1
	}
	return r
}

func gfDiv(a, b byte) byte {
	if b == 0 {
		return 0
	}
	return gfMul(a, gfInv(b))
}
