// +build android ios

package safeprime

import (
	"github.com/privacybydesign/gabi/big"
)

func Generate(int) (*big.Int, error) {
	panic("Safe prime generation is disabled")
}
