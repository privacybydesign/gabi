package keyproof

import "github.com/privacybydesign/gabi/big"

type quasiSafePrimeProductCommit struct {
	asppCommit almostSafePrimeProductCommit
}

type QuasiSafePrimeProductProof struct {
	SFproof   SquareFreeProof
	PPPproof  PrimePowerProductProof
	DPPproof  DisjointPrimeProductProof
	ASPPproof AlmostSafePrimeProductProof
}

func quasiSafePrimeProductBuildCommitments(list []*big.Int, Pprime *big.Int, Qprime *big.Int) ([]*big.Int, quasiSafePrimeProductCommit) {
	var commit quasiSafePrimeProductCommit
	list, commit.asppCommit = almostSafePrimeProductBuildCommitments(list, Pprime, Qprime)
	return list, commit
}

func quasiSafePrimeProductBuildProof(Pprime *big.Int, Qprime *big.Int, challenge *big.Int, commit quasiSafePrimeProductCommit) QuasiSafePrimeProductProof {
	// Calculate useful intermediaries
	P := new(big.Int).Add(new(big.Int).Lsh(Pprime, 1), big.NewInt(1))
	Q := new(big.Int).Add(new(big.Int).Lsh(Qprime, 1), big.NewInt(1))
	N := new(big.Int).Mul(P, Q)
	phiN := new(big.Int).Lsh(new(big.Int).Mul(Pprime, Qprime), 2)

	// Build the actual proofs
	var proof QuasiSafePrimeProductProof
	proof.SFproof = squareFreeBuildProof(N, phiN, challenge, big.NewInt(0))
	proof.PPPproof = primePowerProductBuildProof(P, Q, challenge, big.NewInt(1))
	proof.DPPproof = disjointPrimeProductBuildProof(P, Q, challenge, big.NewInt(2))
	proof.ASPPproof = almostSafePrimeProductBuildProof(Pprime, Qprime, challenge, big.NewInt(3), commit.asppCommit)

	return proof
}

func quasiSafePrimeProductVerifyStructure(proof QuasiSafePrimeProductProof) bool {
	return squareFreeVerifyStructure(proof.SFproof) &&
		primePowerProductVerifyStructure(proof.PPPproof) &&
		disjointPrimeProductVerifyStructure(proof.DPPproof) &&
		almostSafePrimeProductVerifyStructure(proof.ASPPproof)
}

func quasiSafePrimeProductExtractCommitments(list []*big.Int, proof QuasiSafePrimeProductProof) []*big.Int {
	return almostSafePrimeProductExtractCommitments(list, proof.ASPPproof)
}

func quasiSafePrimeProductVerifyProof(N *big.Int, challenge *big.Int, proof QuasiSafePrimeProductProof) bool {
	// Check N = 5 (mod 8), as this is what differentiates quasi and almost safe prime products
	if new(big.Int).Mod(N, big.NewInt(8)).Cmp(big.NewInt(5)) != 0 {
		return false
	}

	// Verify Minimum factor rule
	for i := 2; i < minimumFactor; i++ {
		check := new(big.Int).GCD(nil, nil, N, big.NewInt(int64(i)))
		if check.Cmp(big.NewInt(1)) != 0 {
			return false
		}
	}

	// Validate the individual parts
	return squareFreeVerifyProof(N, challenge, big.NewInt(0), proof.SFproof) &&
		primePowerProductVerifyProof(N, challenge, big.NewInt(1), proof.PPPproof) &&
		disjointPrimeProductVerifyProof(N, challenge, big.NewInt(2), proof.DPPproof) &&
		almostSafePrimeProductVerifyProof(N, challenge, big.NewInt(3), proof.ASPPproof)
}
