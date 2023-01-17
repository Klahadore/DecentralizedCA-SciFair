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
	pubKey1Point := schnorr.Point{X: key1.PublicKey.X, Y: key1.PublicKey.Y}
	pubKey2Point := schnorr.Point{X: key2.PublicKey.X, Y: key2.PublicKey.Y}

	addedPubKeys, err := schnorr.AggregatePublicKeys(pubKey1Point, pubKey2Point)
	if err != nil {
		fmt.Println(err)
	}
	addedSignatures, err := schnorr.AggregateSignatures(*signature1, *signature2)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("the message is", string(message))

	fmt.Println("Signature 1")
	fmt.Println("Public Key", pubKey1Point.X, ",", pubKey1Point.Y)
	fmt.Println("verify", schnorr.Verify(key1.PublicKey.X, key1.PublicKey.Y, &message, signature1))

	fmt.Println("Signature 2")
	fmt.Println("Public Key", pubKey2Point.X, ", ", pubKey2Point.Y)
	fmt.Println("verify", schnorr.Verify(key2.PublicKey.X, key2.PublicKey.Y, &message, signature2))

	fmt.Println(schnorr.Verify(addedPubKeys.X, addedPubKeys.Y, &message, &addedSignatures))

}
