package main

import (
	"fmt"

	"github.com/Klahadore/DecentralizedCA-SciFair/schnorr"
	"github.com/ethereum/go-ethereum/crypto"
	// "github.com/Klahadore/DecentralizedCA-SciFair/strawmanMuSig"
)

func main() {
	message := []byte("Hello World")

	key1, err := crypto.GenerateKey()
	if err != nil {
		fmt.Println(err)
	}

	signature1, err := schnorr.Sign(key1.D, &message)
	if err != nil {
		fmt.Println(err)
	}

	key2, err := crypto.GenerateKey()
	if err != nil {
		fmt.Println(err)
	}

	signature2, err := schnorr.Sign(key2.D, &message)
	if err != nil {
		fmt.Println(err)
	}

	addedPubKeys, err := schnorr.AggregatePublicKeys(schnorr.Point{X: key1.PublicKey.X, Y: key1.PublicKey.Y}, schnorr.Point{X: key2.PublicKey.X, Y: key2.PublicKey.Y})
	if err != nil {
		fmt.Println(err)
	}
	addedSignatures, err := schnorr.AggregateSignatures(*signature1, *signature2)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(schnorr.Verify(key1.PublicKey.X, key1.PublicKey.Y, &message, signature1))
	fmt.Println(schnorr.Verify(key2.PublicKey.X, key2.PublicKey.Y, &message, signature2))
	fmt.Println(schnorr.Verify(addedPubKeys.X, addedPubKeys.Y, &message, &addedSignatures))

}
