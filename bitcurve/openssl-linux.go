// +build !windows

package bitcurve

// #cgo LDFLAGS: -lcrypto
//#include <openssl/ec.h>
//#include <openssl/bn.h>
//#include <openssl/evp.h>
import "C"

import (
	"unsafe"
)

type Bignum = *C.BIGNUM
type Group = *C.EC_GROUP
type Ctx = *C.BN_CTX

func Bn2hex(bn Bignum) string {
	ptr := C.BN_bn2hex(bn)
	defer C.CRYPTO_free(unsafe.Pointer(ptr), C.CString("openssl-lonux.go"), 17)
	return C.GoString(ptr)
}

func NewGroup() Group {
	NID_secp256k1 := 714
	return C.EC_GROUP_new_by_curve_name(C.int(NID_secp256k1))
}

func FreeGroup(group Group) {
	C.EC_GROUP_free(group)
}

func NewCtx() Ctx {
	return C.BN_CTX_new()
}

func NewBn() Bignum {
	return C.BN_new()
}

func BnSetWord(bn Bignum, w uint64) {
	C.BN_set_word(bn, C.ulong(w))
}

func Hex2Bn(s string) Bignum {
	b := Bignum(0)
	c := C.CString(s)
	C.BN_hex2bn(&b, c)
	C.free(unsafe.Pointer(c))
	return b
}

func Bin2Bn(bytes []byte) Bignum {
	return C.BN_bin2bn((*C.uchar)(unsafe.Pointer(&bytes[0])), len(bytes), 0)
}

func FreeBn(bn Bignum) {
	C.BN_free(bn)
}

// the point should later be released with FreePoint
func NewPoint(group Group) Point {
	return C.EC_POINT_new(group)
}

func FreePoint(point Point) {
	C.EC_POINT_free(point)
}

// compute G * n + P * m, where G is the curve generator point,
// P is another point, n and m are bignums created with NewBn().
// if n is 0, return P * m part. If P and m are 0, return the G * n part
// You have to free the returning point with FreePoint()
func PointMul(group Group, n Bignum, P Point, m Bignum, ctx Ctx) Point {
	result := NewPoint(group)
	C.EC_POINT_mul(group, result, n, P, m, ctx)
	return result
}

// Return the point's coordinates x and y. Both values should later be released with FreeBn
func pointGetCoordinates(group Group, point Point, ctx Ctx) (x Bignum, y Bignum) {
	x = NewBn()
	y = NewBn()
	C.EC_POINT_get_affine_coordinates_GFp(group, point, x, y, ctx)
	return
}

func Point2binCompressed(group Group, point Point, ctx Ctx) []byte {
	bytes := make([]byte, 33)
	C.EC_POINT_point2oct(group, point, 2, (*C.uchar)(unsafe.Pointer(&bytes[0])), 33, ctx)
	return bytes
}

// the result should later be released with FreePoint
func Bin2point(group Group, bytes []byte, ctx Ctx) *Point {
	point := NewPoint(group)
	ret := C.EC_POINT_oct2point(group, point, (*C.uchar)(unsafe.Pointer(&bytes[0])), len(bytes), ctx)
	if ret == 0 {
		return nil
	}
	return &point
}

func NewSig() Sig {
	return C.ECDSA_SIG_new()
}

// Calling this function transfers the memory management of the values 'r' and 's' to the Sig object,
// and therefore the values that have been passed in should not be freed directly after this function has been called.
func SigSet(sig Sig, r Bignum, s Bignum) {
	C.ECDSA_SIG_set0(sig, r, s)
}

func SigGet(sig Sig) (r,s Bignum) {
	r = Bignum(0)
	s = Bignum(0)
	C.ECDSA_SIG_get0(sig, &r, &s)
	return r, s
}

func FreeSig(sig Sig) {
	C.ECDSA_SIG_free(sig)
}

func Verify(digest []byte, sig Sig, key Key) bool {
	return C.ECDSA_do_verify((*C.uchar)(unsafe.Pointer(&digest[0])), len(digest), sig, key) == 1
}

func NewKey() Key {
	return C.EC_KEY_new()
}

func FreeKey(key Key) {
	return C.EC_KEY_free(key)
}

func KeySetPublic(key Key, pubkey Point) {
	C.EC_KEY_set_public_key(key, pubkey)
}

func KeySetGroup(key Key, group Group) {
	C.EC_KEY_set_group(key, group)
}
