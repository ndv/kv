// +build windows

package bitcurve

import "C"
import (
	"syscall"
	"unsafe"
)

var (
	libcrypto = syscall.NewLazyDLL("libcrypto-1_1-x64.dll")

	EC_GROUP_new_by_curve_name = libcrypto.NewProc("EC_GROUP_new_by_curve_name")
	EC_GROUP_get_order = libcrypto.NewProc("EC_GROUP_get_order")
	EC_GROUP_free = libcrypto.NewProc("EC_GROUP_free")
	BN_CTX_new = libcrypto.NewProc("BN_CTX_new")
	BN_CTX_free = libcrypto.NewProc("BN_CTX_free")
	BN_new = libcrypto.NewProc("BN_new")
	BN_bn2hex = libcrypto.NewProc("BN_bn2hex")
	BN_hex2bn = libcrypto.NewProc("BN_hex2bn")
	BN_bn2binpad = libcrypto.NewProc("BN_bn2binpad")
	BN_bin2bn = libcrypto.NewProc("BN_bin2bn")
	BN_set_word = libcrypto.NewProc("BN_set_word")
	BN_mod_exp = libcrypto.NewProc("BN_mod_exp")
	BN_sub = libcrypto.NewProc("BN_sub")
	BN_mod_mul = libcrypto.NewProc("BN_mod_mul")
	BN_mod_add = libcrypto.NewProc("BN_mod_add")
	BN_is_odd = libcrypto.NewProc("BN_is_odd")
	BN_mod_inverse = libcrypto.NewProc("BN_mod_inverse")
	BN_free = libcrypto.NewProc("BN_free")
	EC_POINT_new = libcrypto.NewProc("EC_POINT_new")
	EC_POINT_free = libcrypto.NewProc("EC_POINT_free")
	EC_POINT_mul = libcrypto.NewProc("EC_POINT_mul")
	EC_POINT_get_affine_coordinates_GFp = libcrypto.NewProc("EC_POINT_get_affine_coordinates_GFp")
	EC_POINT_point2oct = libcrypto.NewProc("EC_POINT_point2oct")
	EC_POINT_oct2point = libcrypto.NewProc("EC_POINT_oct2point")
	EC_KEY_new = libcrypto.NewProc("EC_KEY_new")
	EC_KEY_free = libcrypto.NewProc("EC_KEY_free")
	EC_KEY_set_public_key = libcrypto.NewProc("EC_KEY_set_public_key")
	EC_KEY_set_group = libcrypto.NewProc("EC_KEY_set_group")
	EC_KEY_can_sign = libcrypto.NewProc("EC_KEY_can_sign")
	ECDSA_SIG_new = libcrypto.NewProc("ECDSA_SIG_new")
	ECDSA_do_verify = libcrypto.NewProc("ECDSA_do_verify")
	ECDSA_SIG_set0 = libcrypto.NewProc("ECDSA_SIG_set0")
	ECDSA_SIG_get0 = libcrypto.NewProc("ECDSA_SIG_get0")
	ECDSA_SIG_free = libcrypto.NewProc("ECDSA_SIG_free")
	CRYPTO_free = libcrypto.NewProc("CRYPTO_free")
	ERR_get_error = libcrypto.NewProc("ERR_get_error")
)

type Bignum = uintptr
type Ctx = uintptr
type Group = uintptr
type Point = uintptr
type Key = uintptr
type Sig = uintptr

var (
	PointNil = Point(0)
	BnNil = Bignum(0)
)

func pointer2String(p uintptr) string {
	data := make([]byte, 0)
	for *(*byte)(unsafe.Pointer(p)) != 0 {
		data = append(data, *(*byte)(unsafe.Pointer(p)))
		p ++
	}
	return string(data)
}

// return null-terminating byte slice containing ASCII characters
func string2bytes(s string) []byte {
	data := []byte(s)
	data = append(data, 0)
	return data
}

// Creates new secp256k1 group. The result should later be released with FreeGroup
func NewGroup() Group {
	NID_secp256k1 := 714
	ret, _, _ := EC_GROUP_new_by_curve_name.Call(uintptr(NID_secp256k1))
	return ret
}

func GroupGetOrder(group Group, ctx Ctx) Bignum {
	order := NewBn()
	EC_GROUP_get_order.Call(group, order, ctx)
	return order
}

func FreeGroup(group Group) {
	EC_GROUP_free.Call(group)
}

// Creates new BN_CTX. The result should later be released with FreeCtx
func NewCtx() Ctx {
	ret, _, _ := BN_CTX_new.Call()
	return ret
}

func FreeCtx(ctx Ctx) {
	BN_CTX_free.Call(ctx)
}

// Creates new zero-initialized Bignum. The result should later be released with FreeBn
func NewBn() Bignum {
	ret, _, _ := BN_new.Call()
	return ret
}

func Bn2hex(bn Bignum) string {
	ret, _, _ := BN_bn2hex.Call(bn)
	defer CRYPTO_free.Call(ret, uintptr(0), uintptr(0))
	return pointer2String(ret)
}

// Parse hexadecimal to Bignum. The result should later be released with FreeBn
func Hex2Bn(s string) Bignum {
	b := uintptr(0)
	bytes := string2bytes(s)
	BN_hex2bn.Call(uintptr(unsafe.Pointer(&b)), uintptr(unsafe.Pointer(&bytes[0])))
	return b
}

func BnSetWord(bn Bignum, w uint64) {
	BN_set_word.Call(bn, uintptr(w))
}

// Computes bn^exp mod m. The result should later be released with FreeBn
func BnModExp(bn Bignum, exp Bignum, m Bignum, ctx uintptr) Bignum {
	result := NewBn()
	BN_mod_exp.Call(result, bn, exp, m, ctx)
	return result
}

// Computes a-b. The result should later be released with FreeBn
func BnSub(a Bignum, b Bignum) Bignum {
	result := NewBn()
	BN_sub.Call(result, a, b)
	return result
}

func BnIsOdd(a Bignum) bool {
	ret, _, _ := BN_is_odd.Call(a)
	return ret == 1
}

func Bin2Bn(bytes []byte) Bignum {
	ret, _, _ := BN_bin2bn.Call(uintptr(unsafe.Pointer(&bytes[0])), uintptr(len(bytes)), 0)
	return ret
}

func BnInvMod(bn Bignum, m Bignum, ctx Ctx) Bignum {
	r := NewBn()
	BN_mod_inverse.Call(r, bn, m, ctx)
	return r
}

func BnMulMod(a Bignum, b Bignum, m Bignum, ctx Ctx) Bignum {
	r := NewBn()
	BN_mod_mul.Call(r, a, b, m, ctx)
	return r
}

func BnAddMod(a Bignum, b Bignum, m Bignum, ctx Ctx) Bignum {
	r := NewBn()
	BN_mod_add.Call(r, a, b, m, ctx)
	return r
}

func FreeBn(bn Bignum) {
	BN_free.Call(bn)
}

// the point should later be released with FreePoint
func NewPoint(group Group) Point {
	ret, _, _ := EC_POINT_new.Call(group)
	return ret
}

func FreePoint(point Point) {
	EC_POINT_free.Call(point)
}

// compute G * n + P * m, where G is the curve generator point,
// P is another point, n and m are bignums created with NewBn().
// if n is 0, return P * m part. If P and m are 0, return the G * n part
// You have to free the returning point with FreePoint()
func PointMul(group Group, n Bignum, P Point, m Bignum, ctx Ctx) Point {
	result := NewPoint(group)
	EC_POINT_mul.Call(group, result, n, P, m, ctx)
	return result
}

// Return the point's coordinates x and y. Both values should later be released with FreeBn
func pointGetCoordinates(group Group, point Point, ctx Ctx) (x Bignum, y Bignum) {
	x = NewBn()
	y = NewBn()
	EC_POINT_get_affine_coordinates_GFp.Call(group, point, x, y, ctx)
	return
}

func Point2binCompressed(group Group, point Point, ctx Ctx) []byte {
	bytes := make([]byte, 33)
	EC_POINT_point2oct.Call(group, point, 2, uintptr(unsafe.Pointer(&bytes[0])), 33, ctx)
	return bytes
}

func Point2binUncompressed(group Group, point Point, ctx Ctx) []byte {
	bytes := make([]byte, 65)
	EC_POINT_point2oct.Call(group, point, 4, uintptr(unsafe.Pointer(&bytes[0])), 65, ctx)
	return bytes
}

// the result should later be released with FreePoint
func Bin2point(group Group, bytes []byte, ctx Ctx) *Point {
	point := NewPoint(group)
	ret, _, _ := EC_POINT_oct2point.Call(group, point, uintptr(unsafe.Pointer(&bytes[0])), uintptr(len(bytes)), ctx)
	if ret == 0 {
		return nil
	}
	return &point
}

func NewSig() Sig {
	ret, _, _ := ECDSA_SIG_new.Call()
	return ret
}

// Calling this function transfers the memory management of the values 'r' and 's' to the Sig object,
// and therefore the values that have been passed in should not be freed directly after this function has been called.
func SigSet(sig Sig, r Bignum, s Bignum) {
	ECDSA_SIG_set0.Call(sig, r, s)
}

func SigGet(sig Sig) (r,s Bignum) {
	r = Bignum(0)
	s = Bignum(0)
	ECDSA_SIG_get0.Call(sig, uintptr(unsafe.Pointer(&r)), uintptr(unsafe.Pointer(&s)))
	return r, s
}

func FreeSig(sig Sig) {
	ECDSA_SIG_free.Call(sig)
}

func Verify(digest []byte, sig Sig, key Key) bool {
	ret, _, _ := ECDSA_do_verify.Call(uintptr(unsafe.Pointer(&digest[0])), uintptr(len(digest)), sig, key)
	return ret == 1
}

func NewKey() Key {
	ret, _, _ := EC_KEY_new.Call()
	return ret
}

func FreeKey(key Key) {
	EC_KEY_free.Call(key)
}

func KeySetPublic(key Key, pubkey Point) {
	EC_KEY_set_public_key.Call(key, pubkey)
}

func KeySetGroup(key Key, group Group) {
	EC_KEY_set_group.Call(key, group)
}

func KeyCanSign(key Key) bool {
	ret, _, _ := EC_KEY_can_sign.Call(key)
	return ret != 0
}

func OsslError() int64 {
	ret, _, _ := ERR_get_error.Call()
	return int64(ret)
}
