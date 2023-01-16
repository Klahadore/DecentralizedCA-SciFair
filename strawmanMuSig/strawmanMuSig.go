package strawmanMuSig

import (
	// "fmt"
	"github.com/Klahadore/DecentralizedCA-SciFair/schnorr"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"math/big"
)

// This does not protect against rouge key attacks.
var curve = secp256k1.S256()

func AggPubKeys(key1, key2 *schnorr.Point) *schnorr.Point {
	point := schnorr.Point{}
	point.X, point.Y = curve.Add(key1.X, key1.Y, key2.X, key2.Y)
	return &point
}

func AggSignatures(sig1 *schnorr.Schnorr, sig2 *schnorr.Schnorr) schnorr.Schnorr {
	signature := schnorr.Schnorr{}

	R := schnorr.Point{}
	R.X, R.Y = curve.Add(sig1.R.X, sig1.R.Y, sig2.R.X, sig2.R.Y)

	signature.R = R
	signature.S = new(big.Int).Add(sig1.S, sig2.S)
	signature.S.Mod(signature.S, curve.P)
	return signature

}
