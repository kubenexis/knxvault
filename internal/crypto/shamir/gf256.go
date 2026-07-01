package shamir

// GF(256) lookup tables for Shamir polynomial arithmetic.
var (
	gfMul [256][256]byte
	gfPow [256][256]byte
	gfInv [256]byte
)

func init() {
	for i := 0; i < 256; i++ {
		for j := 0; j < 256; j++ {
			gfMul[i][j] = gfMultiply(byte(i), byte(j))
		}
	}
	for i := 0; i < 256; i++ {
		gfPow[i][0] = 1
		for j := 1; j < 256; j++ {
			gfPow[i][j] = gfMul[gfPow[i][j-1]][byte(i)]
		}
	}
	for i := 1; i < 256; i++ {
		gfInv[i] = gfPow[i][254]
	}
}

func gfMultiply(a, b byte) byte {
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
