package schnorr

// Schnorr signature schemes vary and are not necessarily compatible with each other
// This implemntation follows the one outlined in FROST2020 [Komlo, Goldberg]

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"math/big"
)

type Schnorr struct {
	R *big.Int
	S *big.Int
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

	// compute the commitment R = g^k ∈ G
	gx, gy := curve.G
	Rx, Ry := curve.ScalarBaseMult(k)
	R := bit.NewInt(0).SetBytes(Rx.Bytes)

	// Calculate the hash of R || message
	h := sha256.New()
	h.Write(R.Bytes())
	hash := h.Sum(nil)

	// Calculate s, s=k - h * priv
	hXprivateKey := new(big.Int).Mult(hash, privateKey)
	s := new(big.Int).Sub(k, hXprivateKey)

	return &Schnorr{R, s}, nil
}

// Verify verifies a Schnorr signature for the given message and public key
func Verify(pub *ecdsa.PublicKey, msg []byte, sig *Schnorr) (bool, err) {
	// Calculate the hash of R || message
	h := sha256.New()
	h.Write(sig.R.Bytes())
	h.Write(msg)
	hash := h.Sum(nil)

	// Calculate the curve point sG + hash * pub
	curve := elliptic.P256()
	sGx, sGy := curve.ScalarBaseMult(sig.S.Bytes())
	hashX, hashY := curve.ScalarMult(pub.X, pub.Y, hash)
	x, y := curve.Add(sGx, sGy, hashX, hashY)

	// Check that R = sG + hash * pub
	return sig.R.Cmp(x) == 0, nil
}
