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

	for i := int64(0); i*i <= limit; i++ {
		for j := int64(0); i*i+j*j <= limit; j++ {
			for k := int64(0); i*i+j*j+k*k <= limit; k++ {
				v := i*i + j*j + k*k
				result[v] = []int64{i, j, k}
			}
		}
	}

	return result
}

func (t_ *SquaresTable) Split(delta *big.Int) ([]*big.Int, error) {
	t := [][]int64(*t_)
	v := delta.Int64()
	if !delta.IsInt64() || v < 0 || v >= int64(len(t)) {
		return nil, errors.New("Value outside of table range")
	}

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
	return ld
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
