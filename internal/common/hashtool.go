package common

import (
	"crypto/sha256"
	"encoding/asn1"

	"github.com/privacybydesign/gabi/big"

	gobig "math/big"
)

// hashCommit computes the sha256 hash over the asn1 representation of a slice
// of big integers and returns a positive big integer that can be represented
// with that hash.
func HashCommit(values []*big.Int, issig bool) *big.Int {
	// The first element is the number of elements
	var tmp []interface{}
	offset := 0
	if issig {
		tmp = make([]interface{}, len(values)+2)
		tmp[0] = true
		offset++
	} else {
		tmp = make([]interface{}, len(values)+1)
	}
	tmp[offset] = gobig.NewInt(int64(len(values)))
	offset++
	for i, v := range values {
		tmp[i+offset] = v.Go()
	}
	r, err := asn1.Marshal(tmp)
	if err != nil {
		panic(err) // Marshal should never error, so panic if it does
	}

	sha := sha256.Sum256(r)
	return new(big.Int).SetBytes(sha[:])
}

// GetHashNumber uses a hash to generate random numbers of a given bitlength in the fiat-shamir heuristic
func GetHashNumber(a *big.Int, b *big.Int, index int, bitlen uint) *big.Int {
	tmp := []*big.Int{}
	if a != nil {
		tmp = append(tmp, a)
	}
	if b != nil {
		tmp = append(tmp, b)
	}
	tmp = append(tmp, big.NewInt(int64(index)))
	countIdx := len(tmp)
	tmp = append(tmp, big.NewInt(0))

	k := uint(0)
	res := big.NewInt(0)
	for k < bitlen {
		cur := HashCommit(tmp, false)
		cur.Lsh(cur, uint(k))
		res.Add(res, cur)
		k += 256
		tmp[countIdx].Add(tmp[countIdx], big.NewInt(1))
	}

	return res
}

// intHashSha256 is a utility function compute the sha256 hash over a byte array
// and return this hash as a big.Int.
func IntHashSha256(input []byte) *big.Int {
	h := sha256.New()
	h.Write(input)
	return new(big.Int).SetBytes(h.Sum(nil))
}
