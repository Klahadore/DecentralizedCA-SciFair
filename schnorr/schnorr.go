// Preston S, Science Fair 2022-23

package schnorr

// Schnorr signature schemes vary and are not necessarily compatible with each other
// This shows the original methods in CP Schnorrs paper, https://en.wikipedia.org/wiki/Schnorr_signature
// The notation is the same as shown in the Wikipedia article.
// Notation is not necessarily the same either.

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
)

type Schnorr struct {
	S *big.Int
	E *big.Int
}

// Generates random Hexadecimal nonce of type big.Int
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

func Sign(privateKey *big.Int, message []byte) (*Schnorr, error) {
	// instantiate secp
	curve := elliptic.P256()

	k, err := NonceGen()
	if err != nil {
		return nil, err
	}

	// compute the commitment R = gk ∈ G
	// Only the x value is used, the y value is discarded
	R, _ := curve.ScalarBaseMult(*k)
	//R := big.NewInt(0).SetBytes(Rx.Bytes)

	// Calculate the hash of R || message
	h := sha256.New()
	h.Write(R.Bytes())
	h.Write(message)
	hash := h.Sum(nil)
	// converts hash to big.Int
	e := new(big.Int)
	e.SetBytes(hash[:])

	// Calculate s, s = k - privateKey * e
	kToInt := new(big.Int).SetBytes(*k)
	hXprivateKey := new(big.Int).Mul(e, privateKey)
	s := new(big.Int).Sub(kToInt, hXprivateKey)

	return &Schnorr{s, e}, nil
}

// Verify verifies a Schnorr signature for the given message and public key
func Verify(pubKey *big.Int, message []byte, signature *Schnorr) bool {

	// Calculate r_v, r_v = g^s * y^e
	r := new(big.Int)
	r.Mul(r.Exp(g, signature.S, nil), r.Exp(pubKey, signature.E, nil))

	// Calculate the hash of r_v || message
	h := sha256.New()
	h.Write(r.Bytes())
	h.Write(message)
	hToInt := new(big.Int).SetBytes(h.Sum(nil))

	// Check that R = sG + hash * pub
	return hToInt.Cmp(signature.E) == 0
}
