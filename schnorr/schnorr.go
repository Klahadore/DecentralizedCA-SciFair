// Preston S, Science Fair 2022-23

package schnorr

// Schnorr signature schemes vary and are not necessarily compatible with each other
// This shows the original methods in CP Schnorrs paper, https://en.wikipedia.org/wiki/Schnorr_signature
// The notation is the same as shown in the Wikipedia article.
// Notation is not necessarily the same either.

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
)

type Schnorr struct {
	S *big.Int
	E *big.Int
}

// Generates random int less than q, in type []byte
func NonceGen() (*[]byte, error) {
	byteSlice := make([]byte, 16)

	_, err := rand.Read(byteSlice)
	if err != nil {
		return nil, err
	}

	//nonce := new(big.Int)
	//nonce.SetBytes(byteSlice)
	curve := elliptic.P256()
	num := new(big.Int).SetBytes(byteSlice)
	num.Mod(num, curve.Params().N)

	b := num.Bytes()
	return &b, nil

}

// func deterministicK(privateKey []byte, message [32]byte) (*big.Int, error) {
// 	data := append(privateKey, message[:]...)
// 	digest := sha256.Sum256(data)
// 	k := new(big.Int).SetBytes(digest[:])
// 	k.Mod(k, N)
// 	return k, nil
// }

func Sign(privateKey *big.Int, message []byte) (*Schnorr, error) {

	// instantiate curve
	curve := elliptic.P256()

	k, err := NonceGen()

	if err != nil {
		return nil, err
	}

	// compute the commitment r = g^k ∈ G
	// Only the x value is used, the y value is discarded
	r, _ := curve.ScalarBaseMult(*k)
	r.Mod(r, curve.Params().P)
	fmt.Println(r.String())
	// Calculate the hash of r || message
	h := sha256.New()
	h.Write(r.Bytes())
	h.Write(message)
	hash := h.Sum(nil)
	// converts hash to big.Int
	e := new(big.Int)
	e.SetBytes(hash[:])

	// Calculate s, s = k + privateKey * e
	kToInt := new(big.Int).SetBytes(*k)
	hXprivateKey := new(big.Int).Mul(privateKey, e)
	s := new(big.Int).Add(kToInt, hXprivateKey)
	s.Mod(s, curve.Params().N)
	return &Schnorr{s, e}, nil
}

// Verify verifies a Schnorr signature for the given message and public key
func Verify(pkx, pky *big.Int, message []byte, signature *Schnorr) bool {

	curve := elliptic.P256()

	// Calculate r_v, r_v = g^s * y^e
	gx, gy := curve.ScalarBaseMult(signature.E.Bytes())
	yx, yy := curve.ScalarMult(pkx, pky, signature.S.Bytes())
	r, _ := curve.Add(gx, gy, yx, yy)
	r = r.Mod(r, curve.Params().P)

	fmt.Println("verify r is" + r.String())
	// Calculate the hash of r_v || message
	h := sha256.New()
	h.Write(r.Bytes())
	h.Write(message)

	hToInt := new(big.Int).SetBytes(h.Sum(nil))

	// Check that R = sG + hash * pub
	return hToInt.Cmp(signature.E) == 0
}

func intToBytes(bigInt *big.Int) []byte {
	var bytes [32]byte
	b := bigInt.Bytes()
	copy(bytes[32-len(b):], b)
	return bytes[:]
}

func hash(s []byte) []byte {
	h := sha256.New()
	h.Write(s)
	hash := h.Sum(nil)
	return hash
}

func bytesToInt(s []byte) *big.Int {
	bigInt := new(big.Int).SetBytes(s)
	return bigInt
}
