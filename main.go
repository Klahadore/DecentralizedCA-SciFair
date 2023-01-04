package main

import (
	//"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"github.com/Klahadore/DecentralizedCA-SciFair/schnorr"
	"math/big"
)

func main() {
	curve := elliptic.P256()
	// func GenerateKey(curve Curve, rand io.Reader) (priv []byte, x, y *big.Int, err error))

	privateKey, x, _, err := elliptic.GenerateKey(curve, rand.Reader)

	if err != nil {
		fmt.Println("error has occured")
		fmt.Println(err)
	}

	m := big.NewInt(69)

	pKey := new(big.Int).SetBytes(privateKey)
	signature := schnorr.Sign(pKey, m)

	fmt.Println(schnorr.Verify(x, m, *signature) == true)
}

// func Sign(privateKey *big.Int, message []byte) (*Schnorr, error)
// func Verify(pubKey *big.Int, message []byte, signature *Schnorr) bool
