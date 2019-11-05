package bitcurve

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"
)

type BitCurve struct {
	P       *big.Int // the order of the underlying field
	P4      *big.Int // (p+1)/4
	N       *big.Int // the order of the base point
	B       *big.Int // the constant of the BitCurve equation
	Gx, Gy  *big.Int // (x,y) of the base point
	BitSize int      // the size of the underlying field
}

func (BitCurve *BitCurve) Params() *elliptic.CurveParams {
	return &elliptic.CurveParams{
		P:       BitCurve.P,
		N:       BitCurve.N,
		B:       BitCurve.B,
		Gx:      BitCurve.Gx,
		Gy:      BitCurve.Gy,
		BitSize: BitCurve.BitSize,
	}
}

// IsOnCurve returns true if the given (x,y) lies on the BitCurve.
func (curve *BitCurve) IsOnCurve(x, y *big.Int) bool {
	return curve.Params().IsOnCurve(x, y)
}

// Add returns the sum of (x1,y1) and (x2,y2)
func (curve *BitCurve) Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	return curve.Params().Add(x1, y1, x2, y2)
}

// Double returns 2*(x,y)
func (curve *BitCurve) Double(x1, y1 *big.Int) (*big.Int, *big.Int) {
	return curve.Params().Double(x1, y1)
}

func (curve *BitCurve) ScalarMult(Bx, By *big.Int, scalar []byte) (*big.Int, *big.Int) {
	return curve.Params().ScalarMult(Bx, By, scalar)
}

// ScalarBaseMult returns k*G, where G is the base point of the group and k is
// an integer in big-endian form.
func (curve *BitCurve) ScalarBaseMult(k []byte) (*big.Int, *big.Int) {
	return curve.Params().ScalarBaseMult(k)
}

var theCurve = new(BitCurve)

func init() {
	// See SEC 2 section 2.7.1
	// curve parameters taken from:
	// http://www.secg.org/sec2-v2.pdf
	theCurve.P, _ = new(big.Int).SetString("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 0)
	theCurve.P4, _ = new(big.Int).SetString("0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBFFFFF0C", 0)
	theCurve.N, _ = new(big.Int).SetString("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 0)
	theCurve.B, _ = new(big.Int).SetString("0x0000000000000000000000000000000000000000000000000000000000000007", 0)
	theCurve.Gx, _ = new(big.Int).SetString("0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 0)
	theCurve.Gy, _ = new(big.Int).SetString("0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 0)
	theCurve.BitSize = 256
}

// S256 returns a BitCurve which implements secp256k1.
func S256() *BitCurve {
	return theCurve
}

func (curve *BitCurve) sqrt(i *big.Int) (odd, even *big.Int) {
	// i ^ (p+1)/4
	first := new(big.Int).Exp(i, curve.P4, curve.P)
	second := new(big.Int).Sub(curve.P, first)

	if first.Bit(0) == 0 {
		even = first
		odd = second
	} else {
		odd = first
		even = second
	}
	return
}

func (curve *BitCurve) UncompressPoint(bytes33 []byte) *ecdsa.PublicKey {
	x := new(big.Int).SetBytes(bytes33[1:])
	even, odd := curve.sqrt(x)
	if bytes33[0] == 2 {
		// even y
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: even}
	} else if bytes33[0] == 3 {
		// odd y
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: odd}
	} else {
		return nil
	}
}

func CompressPoint(public *ecdsa.PublicKey) []byte {
	result := make([]byte, 0)
	if public.Y.Bit(0) == 0 {
		// even
		result = append(result, 2)
	} else {
		result = append(result, 3)
	}
	return append(result, public.X.Bytes()...)
}
