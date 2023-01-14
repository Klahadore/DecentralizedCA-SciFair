// Preston S, Science Fair 2022-23

package schnorr

// Schnorr signature schemes vary and are not necessarily compatible with each other
// This shows the original methods in CP Schnorrs paper, https://en.wikipedia.org/wiki/Schnorr_signature
// The notation is the same as shown in the Wikipedia article.
// Notation is not necessarily the same either.

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

type Schnorr struct {
	S *big.Int
	E *big.Int
}

// Generates random int less than q, in type []byte
func NonceGen() (*[]byte, error) {
	byteSlice := make([]byte, 16)

	_, err := rand.Read(byteSlice)
	if err != nil {
		return nil, err
	}

	//nonce := new(big.Int)
	//nonce.SetBytes(byteSlice)
	return &byteSlice, nil

}

func Sign(privateKey *big.Int, message *[]byte) (*Schnorr, error) {

	// instantiate curve
	curve := secp256k1.S256()

	k, err := NonceGen()
	if err != nil {
		return nil, err
	}
	kInt := byteToInt(*k)
	kInt.Mod(kInt, curve.N)

	r, _ := curve.ScalarBaseMult(*k)
	fmt.Println(r.String())
	e := hash(append(r.Bytes(), *message...))
	eInt := new(big.Int).Mod(byteToInt(e), curve.N)

	// s = k-xe

	s := new(big.Int).Sub(kInt, privateKey.Mul(privateKey, eInt))
	s.Mod(kInt, curve.N)
	return &Schnorr{s, byteToInt(e)}, nil
}

// Verify verifies a Schnorr signature for the given message and public key
func Verify(pkx, pky *big.Int, message []byte, signature *Schnorr) bool {
	curve := secp256k1.S256()

	// Calculate r_v, r_v = g^s * y^e
	x1, y1 := curve.ScalarBaseMult(signature.S.Bytes())
	x2, y2 := curve.ScalarMult(pkx, pky, signature.E.Bytes())
	rx, _ := curve.Add(x1, y1, x2, y2)
	fmt.Println(rx.String())

	e := hash(append(rx.Bytes(), message...))
	eInt := new(big.Int).Mod(byteToInt(e), curve.N)

	// Check that R = sG + hash * pub
	return eInt.Cmp(signature.E) == 0
}

func byteToInt(bytes []byte) *big.Int {
	bigInt := new(big.Int).SetBytes(bytes)
	return bigInt
}

func hash(s []byte) []byte {
	h := sha256.Sum256(s)

	return h[:]
}
