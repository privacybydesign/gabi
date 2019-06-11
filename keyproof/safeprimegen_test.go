package keyproof

import "testing"

var testcases = []int{
	250,
	256,
	512,
	600,
	1000,
	1024,
	1546,
	2570,
	4618,
}

func TestFindSafePrime(t *testing.T) {
	for _, tc := range testcases {
		result := findSafePrime(tc)
		if result == nil {
			t.Errorf("Missing result for %d", tc)
			continue
		}
		if result.BitLen() < tc {
			t.Errorf("Generated prime too short for %d", tc)
		}
	}
}
