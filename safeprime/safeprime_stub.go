// +build android ios windows !cgo

package safeprime

import (
	"math/big"
)

func Generate(bitsize int) (*big.Int, error) {
	panic("Not implemented on mobile platforms")
}
