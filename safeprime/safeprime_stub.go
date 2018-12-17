// +build android ios windows !cgo

package safeprime

import (
	"github.com/privacybydesign/gabi/big"
)

func Generate(bitsize int) (*big.Int, error) {
	panic("Safe prime generation is disabled")
}
