package keyproof

import "github.com/privacybydesign/gabi/internal/common"
import "github.com/privacybydesign/gabi/big"

type DisjointPrimeProductProof struct {
	Responses []*big.Int
}

func disjointPrimeProductBuildProof(P *big.Int, Q *big.Int, challenge *big.Int, index *big.Int) DisjointPrimeProductProof {
	// Precalculate values for response
	N := new(big.Int).Mul(P, Q)
	phiN := new(big.Int).Mul(new(big.Int).Sub(P, big.NewInt(1)), new(big.Int).Sub(Q, big.NewInt(1)))
	oddN := new(big.Int).Sub(N, big.NewInt(1))
	for oddN.Bit(0) == 0 {
		oddN.Rsh(oddN, 1)
	}
	oddNInv := new(big.Int).ModInverse(oddN, phiN)
	if oddNInv == nil {
		panic("P*Q is not a disjoint prime product!")
	}

	// Generate the challenges and responses
	var proof DisjointPrimeProductProof
	for i := 0; i < squareFreeIters; i++ {
		// Generate the challenge
		curc := common.GetHashNumber(challenge, index, i, uint(N.BitLen()))
		curc.Mod(curc, N)

		if new(big.Int).GCD(nil, nil, curc, N).Cmp(big.NewInt(1)) != 0 {
			panic("Generated number not in Z_N")
		}

		// Generate response
		proof.Responses = append(proof.Responses, new(big.Int).Exp(curc, oddNInv, N))
	}

	return proof
}

func disjointPrimeProductVerifyStructure(proof DisjointPrimeProductProof) bool {
	if proof.Responses == nil || len(proof.Responses) != disjointPrimeProductIters {
		return false
	}

	for _, val := range proof.Responses {
		if val == nil {
			return false
		}
	}

	return true
}

func disjointPrimeProductVerifyProof(N *big.Int, challenge *big.Int, index *big.Int, proof DisjointPrimeProductProof) bool {
	// Check that N is not a fermat prime
	if N.ProbablyPrime(80) {
		return false
	}

	// Calculate oddN
	oddN := new(big.Int).Sub(N, big.NewInt(1))
	for oddN.Bit(0) == 0 {
		oddN.Rsh(oddN, 1)
	}

	// Generate the challenges and verify responses
	for i := 0; i < squareFreeIters; i++ {
		// Generate the challenge
		curc := common.GetHashNumber(challenge, index, i, uint(N.BitLen()))
		curc.Mod(curc, N)

		responseResult := new(big.Int).Exp(proof.Responses[i], oddN, N)
		if responseResult.Cmp(curc) != 0 {
			return false
		}
	}

	return true
}
