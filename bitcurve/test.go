package bitcurve

import (
	"encoding/hex"
	"fmt"
)

func RunTests() {
	group := NewGroup()
	ctx := NewCtx()

	bn := NewBn()
	BnSetWord(bn, 1)

	point := PointMul(group, bn, PointNil, BnNil, ctx)
	x, y := PointGetCoordinates(point)

	fmt.Printf("1*G = (%s, %s)\n", Bn2hex(x), Bn2hex(y))

	FreePoint(point)
	FreeBn(x)
	FreeBn(y)

	BnSetWord(bn, 2)
	point = PointMul(group, bn, PointNil, BnNil, ctx)
	x, y = PointGetCoordinates(point)

	fmt.Printf("2*G = (%s, %s)\n", Bn2hex(x), Bn2hex(y))

	FreePoint(point)
	FreeBn(x)
	FreeBn(y)

	r := Hex2Bn("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
	s := Hex2Bn("0C8333020C4688A754BF3AD462F1E9F0B576E33053AC4E890BED5BD6A246120E")
	pubkeyBytes, _ := hex.DecodeString("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")

	pubkey := UnmarshallCompressedPoint(pubkeyBytes)

	x,y = PointGetCoordinates(*pubkey)
	fmt.Printf("pubkey = (%s, %s)\n", Bn2hex(x), Bn2hex(y))

	key := NewKey()
	KeySetGroup(key, group)
	KeySetPublic(key, *pubkey)
	sig := NewSig()
	SigSet(sig, r, s)

	r, s = SigGet(sig)
	fmt.Printf("r=%s s=%s\n", Bn2hex(r), Bn2hex(s))

	msg := []byte{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,3}
	/*
	N := GroupGetOrder(group, ctx)
	sinv := BnInvMod(s, N, ctx)
	rsinv := BnMulMod(r, sinv, N, ctx)
	msgsinv := BnMulMod(Bin2Bn(msg), sinv, N, ctx)
	kP := PointMul(group, msgsinv, *pubkey, rsinv, ctx)

	x,y = PointGetCoordinates(kP)
	fmt.Printf("kP = (%s, %s)\n", Bn2hex(x), Bn2hex(y))
	 */

	if !Verify(msg, sig, key) {
		fmt.Println("Wrong signature")
	} else {
		fmt.Println("OK")
	}
	/*
	P, _  := new(big.Int).SetString("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 0)
	N, _  := new(big.Int).SetString("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 0)
	B, _  := new(big.Int).SetString("0x0000000000000000000000000000000000000000000000000000000000000007", 0)
	Gx, _ := new(big.Int).SetString("0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 0)
	Gy, _ := new(big.Int).SetString("0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 0)
	BitSize := 256

	params := &elliptic.CurveParams{P: P,  N: N, B: B, Gx: Gx, Gy: Gy, BitSize: BitSize}

	x, y := params.ScalarBaseMult([]byte{1})
	fmt.Printf("1 * G = (%s, %s)\n", x.Text(16), y.Text(16))

	x, y = params.ScalarBaseMult([]byte{2})
	fmt.Printf("2 * G = (%s, %s)\n", x.Text(16), y.Text(16))
	*/
}
