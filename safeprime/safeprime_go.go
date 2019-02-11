// +build !cgo,!android,!ios

package safeprime

import "github.com/privacybydesign/gabi/big"

func Generate(bitsize int) (*big.Int, error) {
	return GenerateGo(bitsize)
}
