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

func Sign(privateKey *big.Int, message [32]byte) (*[64]byte, error) {
	// instantiate secp
	curve := elliptic.P256()

	k, err := NonceGen()
	if err != nil {
		return nil, err
	}

	// compute the commitment R = g^k ∈ G
	gx, gy := curve.G
	R, err := curve.ScalarBaseMult(gx * k)
	if err != nil {
		return nil, err
	}

}
