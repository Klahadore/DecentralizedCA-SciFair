package main

import (
	"encoding/hex"
	"fmt"
	"github.com/hbakhtiyor/schnorr"
	"math/big"
)

func main() {
	var message [32]byte

	privateKey, _ := new(big.Int).SetString("B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF", 16)
	msg, _ := hex.DecodeString("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89")
	copy(message[:], msg)

	signature, err := schnorr.Sign(privateKey, message)
	if err != nil {
		fmt.Printf("The signing is failed: %v\n", err)
	}
	fmt.Printf("The signature is: %x\n", signature)
}
