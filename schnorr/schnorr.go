// Preston S, Science Fair 2022-23

package schnorr

// Schnorr signature schemes vary and are not necessarily compatible with each other
// The notation is the same as shown in the Wikipedia article.
// Notation is not necessarily the same either.

// This

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"

	//"github.com/btcsuite/btcd/btcec/v2"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

type Schnorr struct {
	R *big.Int
	S *big.Int
}

func NonceGen() (*[]byte, error) {
	byteSlice := make([]byte, 8)

	_, err := rand.Read(byteSlice)
	if err != nil {
		return nil, err
	}

	//nonce := new(big.Int)
	//nonce.SetBytes(byteSlice)
	return &byteSlice, nil

}

var curve (
	secp256k1.S256()
)

func Sign(privateKey *big.Int, message *[]byte) (*Schnorr, error) {

	// instantiate curve
	

	k, err := NonceGen()
	if err != nil {
		return nil, err
	}
	kInt := byteToInt(*k)
	kInt.Mod(kInt, curve.N)

	r, _ := curve.ScalarBaseMult(*k)
	fmt.Println(r.String())

	e := hash(append(r.Bytes(), *message...))
	eInt := byteToInt(e)

	s := new(big.Int).Sub(kInt, new(big.Int).Mul(privateKey, eInt))
	s.Mod(kInt, curve.N)
	return &Schnorr{eInt, s}, nil
}

// Verify verifies a Schnorr signature for the given message and public key
func Verify(pkx, pky *big.Int, message []byte, signature *Schnorr) bool {


	// e := hash(append(signature.R.Bytes(), message...))
	// eInt := new(big.Int).Mod(byteToInt(e), curve.P)

	// Calculate r_v, r_v = g^s * y^e
	x1, y1 := curve.ScalarBaseMult(signature.S.Bytes())
	x2, y2 := curve.ScalarMult(pkx, pky, signature.R.Bytes())
	rx, _ := curve.Add(x1, y1, x2, y2)
	fmt.Println(rx.String())

	e := hash(append(rx.Bytes(), message...))

	return signature.R.Cmp(byteToInt(e)) == 0
}

func byteToInt(bytes []byte) *big.Int {
	bigInt := new(big.Int).SetBytes(bytes)
	return bigInt
}

func hash(s []byte) []byte {
	h := sha256.Sum256(s)

	return h[:]
}
