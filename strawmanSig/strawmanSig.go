package strawmansig

import (
	"crypto/elliptic"
	"math/big"
)

type Schnorr struct {
	R *big.Int
	S *big.Int
}

type PublicKey struct {
	x *big.Int
	y *big.Int
}

func ComputePubKey(pubKeys []*PublicKey, curve *elliptic.Curve) *big.Int {
	finalKey := big.NewInt(1)

	for i := 1; i < len(pubKeys); i++ {
		finalKey = finalKey.Mul(finalKey, pubKeys[i].x)
	}

	return finalKey
}

// for i := 1; i < 5; i++ {
// 	sum += i
// }

//func (curve *CurveParams) ScalarMult(Bx, By *big.Int, k []byte) (*big.Int, *big.Int)
