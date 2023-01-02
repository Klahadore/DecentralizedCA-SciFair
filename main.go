package main

import (
	//"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	//"math/big"
)

func main() {
	curve := elliptic.P256()
	// func GenerateKey(curve Curve, rand io.Reader) (priv []byte, x, y *big.Int, err error))

	priv, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		fmt.Println("error has occured")
		fmt.Println(err)
	}
	fmt.Println(string(priv))
	fmt.Println(x.String() + " " + y.String())
}
