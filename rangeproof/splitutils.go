package rangeproof

import (
	"errors"

	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/internal/common"
)

type Splitter interface {
	Ld() uint
	Nsplit() int
	Split(*big.Int) ([]*big.Int, error)
}

type SquaresTable [][]int64

// Generate lookup table for splitting numbers into 3 squares containing entries up-to and including limit
// takes O(n^3/2)
func GenerateSquaresTable(limit int64) SquaresTable {
	result := make(SquaresTable, limit+1)

	// 3 squares can't produce everything, but this is compensated for
	// so we only need to focus on n for which n == 2 (mod 4), with the
	// tradeoff that limit is 4x as large
	for i := int64(0); i*i <= 4*limit; i++ {
		for j := int64(0); i*i+j*j <= 4*limit; j++ {
			for k := int64(0); i*i+j*j+k*k <= 4*limit; k++ {
				v := i*i + j*j + k*k
				if v%4 != 2 {
					continue
				}
				result[(v-2)/4] = []int64{i, j, k}
			}
		}
	}

	return result
}

func (t_ *SquaresTable) Split(delta *big.Int) ([]*big.Int, error) {
	t := [][]int64(*t_)
	v := delta.Int64()
	if !delta.IsInt64() || v < 0 || v >= int64(len(t)) || v%4 != 2 {
		return nil, errors.New("Value outside of table range")
	}

	v = (v - 2) / 4

	return []*big.Int{big.NewInt(t[v][0]), big.NewInt(t[v][1]), big.NewInt(t[v][2])}, nil
}

func (t *SquaresTable) Nsplit() int {
	return 3
}

func (t *SquaresTable) Ld() uint {
	l := len([][]int64(*t))
	ld := uint(0)
	for l > 0 {
		l /= 4
		ld++
	}
	return ld + 1 // compensate for extra bit due to 3-square correction
}

type FourSquareSplitter struct{}

func (_ *FourSquareSplitter) Split(delta *big.Int) ([]*big.Int, error) {
	a, b, c, d := common.SumFourSquare(delta)
	return []*big.Int{a, b, c, d}, nil
}

func (_ *FourSquareSplitter) Nsplit() int {
	return 4
}

func (_ *FourSquareSplitter) Ld() uint {
	return 128
}
