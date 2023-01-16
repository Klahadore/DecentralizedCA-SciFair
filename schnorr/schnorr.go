// Preston S, Science Fair 2022-23

package schnorr

// Schnorr signature schemes vary and are not necessarily compatible with each other
// Notation follows industry standards of using R,s form signatures.

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

type Point struct {
	X *big.Int
	Y *big.Int
}

type Schnorr struct {
	R Point
	S *big.Int
}

func NonceGen() (*[]byte, error) {
	byteSlice := make([]byte, 16)

	_, err := rand.Read(byteSlice)
	if err != nil {
		return nil, err
	}

	return &byteSlice, nil

}

var curve = secp256k1.S256()

func Sign(privateKey *big.Int, message *[]byte) (*Schnorr, error) {

	k, err := NonceGen()
	if err != nil {
		return nil, err
	}
	// K must be in the set of mod N
	kInt := byteToInt(*k)
	kInt.Mod(kInt, curve.N)

	R := Point{}
	R.X, R.Y = curve.ScalarBaseMult(kInt.Bytes()) // r=k*g, g is the base point
	fmt.Println(R.X.String())

	e := hash(append(R.X.Bytes(), *message...))
	eInt := byteToInt(e)

	s := new(big.Int).Sub(kInt, new(big.Int).Mul(privateKey, eInt))
	s.Mod(s, curve.N)
	return &Schnorr{R, s}, nil
}

// Verify verifies a Schnorr signature for the given message and public key
func Verify(pkx, pky *big.Int, message *[]byte, signature *Schnorr) bool {

	e := hash(append(signature.R.X.Bytes(), *message...))

	//Calculate r_v, r_v = g^s * y^e
	yE := Point{}
	yE.X, yE.Y = curve.ScalarMult(pkx, pky, e)
	gS := Point{}
	gS.X, gS.Y = curve.ScalarBaseMult(signature.S.Bytes())
	rv, _ := curve.Add(gS.X, gS.Y, yE.X, yE.Y)
	// fmt.Println(rv.String())

	// hash must be calculated again, r cannot be compared.
	ev := hash(append(rv.Bytes(), *message...))

	return byteToInt(ev).Cmp(byteToInt(e)) == 0
}

func byteToInt(bytes []byte) *big.Int {
	bigInt := new(big.Int).SetBytes(bytes)
	return bigInt
}

func hash(s []byte) []byte {
	h := sha256.Sum256(s)

	return h[:]
}
