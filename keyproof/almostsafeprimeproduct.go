package keyproof

import "github.com/privacybydesign/gabi/internal/common"
import "github.com/privacybydesign/gabi/big"

type AlmostSafePrimeProductProof struct {
	Nonce       *big.Int
	Commitments []*big.Int
	Responses   []*big.Int
}

type almostSafePrimeProductCommit struct {
	nonce       *big.Int
	commitments []*big.Int
	logs        []*big.Int
}

func almostSafePrimeProductBuildCommitments(list []*big.Int, Pprime *big.Int, Qprime *big.Int) ([]*big.Int, almostSafePrimeProductCommit) {
	// Setup proof structure
	var commit almostSafePrimeProductCommit
	commit.commitments = []*big.Int{}
	commit.logs = []*big.Int{}

	// Calculate N and phiN
	N := new(big.Int).Mul(new(big.Int).Add(new(big.Int).Lsh(Pprime, 1), big.NewInt(1)), new(big.Int).Add(new(big.Int).Lsh(Qprime, 1), big.NewInt(1)))
	phiN := new(big.Int).Lsh(new(big.Int).Mul(Pprime, Qprime), 2)

	// Generate nonce
	nonceMax := new(big.Int).Lsh(big.NewInt(1), almostSafePrimeProductNonceSize)
	commit.nonce = common.FastRandomBigInt(nonceMax)

	for i := 0; i < almostSafePrimeProductIters; i++ {
		// Calculate base from nonce
		curc := common.GetHashNumber(commit.nonce, nil, i, uint(N.BitLen()))
		curc.Mod(curc, N)

		if new(big.Int).GCD(nil, nil, curc, N).Cmp(big.NewInt(1)) != 0 {
			panic("Generated number not in Z_N")
		}

		log := common.FastRandomBigInt(phiN)
		com := new(big.Int).Exp(curc, log, N)
		list = append(list, com)
		commit.commitments = append(commit.commitments, com)
		commit.logs = append(commit.logs, log)
	}

	return list, commit
}

func almostSafePrimeProductBuildProof(Pprime *big.Int, Qprime *big.Int, challenge *big.Int, index *big.Int, commit almostSafePrimeProductCommit) AlmostSafePrimeProductProof {
	// Setup proof structure
	var proof AlmostSafePrimeProductProof
	proof.Nonce = commit.nonce
	proof.Commitments = commit.commitments
	proof.Responses = []*big.Int{}

	// Calculate useful constants
	N := new(big.Int).Mul(new(big.Int).Add(new(big.Int).Lsh(Pprime, 1), big.NewInt(1)), new(big.Int).Add(new(big.Int).Lsh(Qprime, 1), big.NewInt(1)))
	phiN := new(big.Int).Lsh(new(big.Int).Mul(Pprime, Qprime), 2)
	oddPhiN := new(big.Int).Mul(Pprime, Qprime)
	factors := []*big.Int{
		Pprime,
		Qprime,
	}

	// Calculate responses
	for i := 0; i < almostSafePrimeProductIters; i++ {
		// Derive challenge
		curc := common.GetHashNumber(challenge, index, i, uint(2*N.BitLen()))

		log := new(big.Int).Mod(new(big.Int).Add(commit.logs[i], curc), phiN)

		// Calculate response
		x1 := new(big.Int).Mod(log, oddPhiN)
		x2 := new(big.Int).Sub(oddPhiN, x1)
		x3 := new(big.Int).Mod(new(big.Int).Mul(new(big.Int).ModInverse(big.NewInt(2), oddPhiN), x1), oddPhiN)
		x4 := new(big.Int).Sub(oddPhiN, x3)

		r1, ok1 := common.ModSqrt(x1, factors)
		r2, ok2 := common.ModSqrt(x2, factors)
		r3, ok3 := common.ModSqrt(x3, factors)
		r4, ok4 := common.ModSqrt(x4, factors)

		// And add the useful one
		if ok1 {
			proof.Responses = append(proof.Responses, r1)
		} else if ok2 {
			proof.Responses = append(proof.Responses, r2)
		} else if ok3 {
			proof.Responses = append(proof.Responses, r3)
		} else if ok4 {
			proof.Responses = append(proof.Responses, r4)
		} else {
			panic("none of +-x, +-x/2 are square")
		}
	}

	return proof
}

func almostSafePrimeProductVerifyStructure(proof AlmostSafePrimeProductProof) bool {
	if proof.Nonce == nil {
		return false
	}
	if proof.Commitments == nil || proof.Responses == nil {
		return false
	}
	if len(proof.Commitments) != almostSafePrimeProductIters || len(proof.Responses) != almostSafePrimeProductIters {
		return false
	}

	for _, val := range proof.Commitments {
		if val == nil {
			return false
		}
	}

	for _, val := range proof.Responses {
		if val == nil {
			return false
		}
	}

	return true
}

func almostSafePrimeProductExtractCommitments(list []*big.Int, proof AlmostSafePrimeProductProof) []*big.Int {
	return append(list, proof.Commitments...)
}

func almostSafePrimeProductVerifyProof(N *big.Int, challenge *big.Int, index *big.Int, proof AlmostSafePrimeProductProof) bool {
	// Verify N=1(mod 3), as this decreases the error prob from 9/10 to 4/5
	if new(big.Int).Mod(N, big.NewInt(3)).Cmp(big.NewInt(1)) != 0 {
		return false
	}

	// Prepare gamma
	gamma := new(big.Int).Lsh(big.NewInt(1), uint(N.BitLen()))

	// Check responses
	for i := 0; i < almostSafePrimeProductIters; i++ {
		// Generate base
		base := common.GetHashNumber(proof.Nonce, nil, i, uint(N.BitLen()))
		base.Mod(base, N)

		// Generate challenge
		x := common.GetHashNumber(challenge, index, i, uint(2*N.BitLen()))
		y := new(big.Int).Mod(
			new(big.Int).Mul(
				proof.Commitments[i],
				new(big.Int).Exp(base, x, N)),
			N)

		// Verify
		yg := new(big.Int).Exp(y, gamma, N)

		t1 := new(big.Int).Exp(base, gamma, N)
		t1.Exp(t1, proof.Responses[i], N)
		t1.Exp(t1, proof.Responses[i], N)

		t2 := new(big.Int).ModInverse(t1, N)
		t3 := new(big.Int).Exp(t1, big.NewInt(2), N)
		t4 := new(big.Int).ModInverse(t3, N)

		ok1 := (t1.Cmp(yg) == 0)
		ok2 := (t2.Cmp(yg) == 0)
		ok3 := (t3.Cmp(yg) == 0)
		ok4 := (t4.Cmp(yg) == 0)

		if !ok1 && !ok2 && !ok3 && !ok4 {
			return false
		}
	}
	return true
}
