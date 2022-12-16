package schnorr

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"math/big"

)



var (
	Curve := elliptic.Curve.P256() 

)

// Schnorr signature schemes vary and are not necessarily compatible with each other
// this implemntation follows the one outlined in 
func Sign(privateKey *big.Int, message [32]byte) ([64]byte, error) {

	// generate 256 bit random nonce 

	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		fmt.Println(err)
		return
	}





}

func Verify



