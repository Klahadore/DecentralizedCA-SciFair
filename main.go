package main

import (
	"fmt"

	"github.com/Klahadore/DecentralizedCA-SciFair/schnorr"
	"github.com/ethereum/go-ethereum/crypto"
)

func main() {
	key, err := crypto.GenerateKey()
	if err != nil {
		fmt.Println(err)
	}

	message := []byte("hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhn")

	signature, err := schnorr.Sign(key.D, &message)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println(schnorr.Verify(key.PublicKey.X, key.PublicKey.Y, message, signature))
}

// func Sign(privateKey *big.Int, message []byte) (*Schnorr, error)
// func Verify(pubKey *big.Int, message []byte, signature *Schnorr) bool

// Note - exponentiation problem in schnorr package, must fix in order for this to work.
