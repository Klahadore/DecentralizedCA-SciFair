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

	privateKey, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		fmt.Println("error has occured")
		fmt.Println(err)
	}
	message := []byte("Hello Schnorr")

	pkeyToInt := new(big.Int).SetBytes(privateKey)
	signature, err := schnorr.Sign(pkeyToInt, message)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println(schnorr.Verify(x, y, message, signature))

}

// func Sign(privateKey *big.Int, message []byte) (*Schnorr, error)
// func Verify(pubKey *big.Int, message []byte, signature *Schnorr) bool

// Note - exponentiation problem in schnorr package, must fix in order for this to work.
