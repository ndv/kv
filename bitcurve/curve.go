package bitcurve

var (
	group = NewGroup()
	ctx = NewCtx()
	P = Hex2Bn("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F")
	P4 = Hex2Bn("3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBFFFFF0C")
	N = Hex2Bn("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
	B = Hex2Bn("0000000000000000000000000000000000000000000000000000000000000007")
	Gx = Hex2Bn("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
	Gy = Hex2Bn("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8")
)

// the resulting point should be release with FreePoint
// return nil on error
func UnmarshallCompressedPoint(bytes []byte) *Point {
	return Bin2point(group, bytes, ctx)
}

func MarshallCompressedPoint(p Point) []byte {
	return Point2binCompressed(group, p, ctx)
}

func PointGetCoordinates(p Point) (x,y Bignum) {
	x,y = pointGetCoordinates(group, p, ctx)
	return
}

func VerifySig(hash []byte, sig Sig, pubkey Point) bool {
	key := NewKey()
	KeySetGroup(key, group)
	KeySetPublic(key, pubkey)
	defer FreeKey(key)
	return Verify(hash, sig, key)
}
