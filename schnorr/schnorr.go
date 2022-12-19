package schnorr

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"math/big"
	
)

// Generates random Hexadecimal nonce of type big.Int 
func NonceGen() (*big.Int, error) {
	byteSlice := make([]byte, 32)

	_, err := rand.Read(byteSlice)
	if err != nil {
		return nil, err
	}

	nonce := new(big.Int)
	nonce.SetBytes(byteSlice)

	return nonce, nil

}

// Schnorr signature schemes vary and are not necessarily compatible with each other
// this implemntation follows the one outlined in 
func Sign(privateKey *big.Int, message [32]byte) ([64]byte, error) {
	curve := elliptic.Curve.P256() 
	// generate 256 bit random nonce 

	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		fmt.Println(err)
		return
	}





}

func Verify



