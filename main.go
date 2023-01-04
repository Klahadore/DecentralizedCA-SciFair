package main

import (
	//"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"github.com/Klahadore/schnorr"
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

	m := new(big.Int).setInt(69)

	schnorr.Sign()
}
