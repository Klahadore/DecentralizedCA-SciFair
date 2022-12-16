package schnorr

import (
	"crypto/elliptic"
	"fmt"
	"testing"
)

// func GenerateKey(curve Curve, rand io.Reader) (priv []byte, x, y *big.Int, err error)
func TestSign(t *testing.T) {
	// generate random reader
	rand := make([]byte, 32)
	_, err := rand.Read(rand)
	if err != nil {
		fmt.Println(err)
		return
	}

	curve := elliptic.Curve.P256()
	priv, x, y, err := elliptic.GenerateKey(curve, rand)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(string(priv) + string(x) + string(y))
}
