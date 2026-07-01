// Package shamir implements Shamir secret sharing over GF(256).
package shamir

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"
)

// Split divides secret into parts shares requiring threshold shares to reconstruct.
// Each share is len(secret)+1 bytes: byte 0 is the x coordinate (1..parts).
func Split(secret []byte, parts, threshold int) ([][]byte, error) {
	if len(secret) == 0 {
		return nil, fmt.Errorf("cannot split empty secret")
	}
	if parts < threshold {
		return nil, fmt.Errorf("parts cannot be less than threshold")
	}
	if threshold < 2 {
		return nil, fmt.Errorf("threshold must be at least 2")
	}
	if parts > 255 {
		return nil, fmt.Errorf("parts cannot exceed 255")
	}

	matrix := make([][]byte, len(secret))
	for i := range matrix {
		row := make([]byte, threshold)
		row[0] = secret[i]
		if _, err := rand.Read(row[1:]); err != nil {
			return nil, fmt.Errorf("generate polynomial: %w", err)
		}
		matrix[i] = row
	}

	out := make([][]byte, parts)
	for i := 0; i < parts; i++ {
		x := byte(i + 1)
		share := make([]byte, len(secret)+1)
		share[0] = x
		for j := 0; j < len(secret); j++ {
			share[j+1] = eval(matrix[j], x)
		}
		out[i] = share
	}
	return out, nil
}

// Combine reconstructs the secret from at least threshold unique shares.
func Combine(parts [][]byte) ([]byte, error) {
	if len(parts) < 2 {
		return nil, fmt.Errorf("at least two shares required")
	}
	secretLen := len(parts[0]) - 1
	if secretLen <= 0 {
		return nil, fmt.Errorf("invalid share length")
	}
	for _, part := range parts {
		if len(part) != secretLen+1 {
			return nil, fmt.Errorf("inconsistent share lengths")
		}
	}

	secret := make([]byte, secretLen)
	for i := 0; i < secretLen; i++ {
		val, err := interpolate(parts, byte(i+1))
		if err != nil {
			return nil, err
		}
		secret[i] = val
	}
	return secret, nil
}

func eval(poly []byte, x byte) byte {
	if len(poly) == 0 {
		return 0
	}
	result := poly[0]
	for i := 1; i < len(poly); i++ {
		result = add(result, mul(poly[i], pow(x, byte(i))))
	}
	return result
}

func interpolate(parts [][]byte, yIdx byte) (byte, error) {
	seen := make(map[byte]struct{}, len(parts))
	for _, part := range parts {
		if _, ok := seen[part[0]]; ok {
			continue
		}
		seen[part[0]] = struct{}{}
	}
	if len(seen) < 2 {
		return 0, fmt.Errorf("insufficient unique shares")
	}

	var result byte
	for _, part := range parts {
		x := part[0]
		if x == 0 {
			continue
		}
		y := part[yIdx]
		num := byte(1)
		den := byte(1)
		for _, other := range parts {
			ox := other[0]
			if ox == 0 || ox == x {
				continue
			}
			num = mul(num, ox)
			den = mul(den, sub(ox, x))
		}
		if den == 0 {
			return 0, fmt.Errorf("duplicate share coordinate")
		}
		inv, err := invGF(den)
		if err != nil {
			return 0, err
		}
		lagrange := mul(num, inv)
		result = add(result, mul(y, lagrange))
	}
	return result, nil
}

func add(a, b byte) byte { return a ^ b }
func sub(a, b byte) byte { return a ^ b }
func pow(a, b byte) byte { return gfPow[a][b] }
func mul(a, b byte) byte { return gfMul[a][b] }

func invGF(a byte) (byte, error) {
	if a == 0 {
		return 0, fmt.Errorf("cannot invert zero")
	}
	return gfInv[a], nil
}

// VerifySplitRoundTrip is a test helper ensuring split/combine works.
func VerifySplitRoundTrip(secret []byte, parts, threshold int) error {
	shares, err := Split(secret, parts, threshold)
	if err != nil {
		return err
	}
	reconstructed, err := Combine(shares[:threshold])
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(secret, reconstructed) != 1 {
		return fmt.Errorf("reconstructed secret mismatch")
	}
	return nil
}
