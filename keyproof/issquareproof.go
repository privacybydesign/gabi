package keyproof

import "github.com/privacybydesign/gabi/internal/common"
import "github.com/privacybydesign/gabi/big"
import "strings"
import "fmt"

type isSquareProofStructure struct {
	n       *big.Int
	squares []*big.Int

	nRep representationProofStructure

	squaresRep []representationProofStructure
	rootsRep   []representationProofStructure
	rootsRange []rangeProofStructure
	rootsValid []multiplicationProofStructure
}

type IsSquareProof struct {
	NProof          PedersonProof
	SquaresProof    []PedersonProof
	RootsProof      []PedersonProof
	RootsRangeProof []RangeProof
	RootsValidProof []MultiplicationProof
}

type isSquareProofCommit struct {
	squares []pedersonSecret
	roots   []pedersonSecret
	n       pedersonSecret

	rootRangeCommit []rangeCommit
	rootValidCommit []multiplicationProofCommit
}

func newIsSquareProofStructure(N *big.Int, Squares []*big.Int) isSquareProofStructure {
	var result isSquareProofStructure

	// Copy over primary values
	result.n = new(big.Int).Set(N)
	result.squares = make([]*big.Int, len(Squares))
	for i, val := range Squares {
		result.squares[i] = new(big.Int).Set(val)
	}

	// Setup representation proof of N
	result.nRep = representationProofStructure{
		[]lhsContribution{
			{"N", big.NewInt(-1)},
			{"g", new(big.Int).Set(N)},
		},
		[]rhsContribution{
			{"h", "N_hider", -1},
		},
	}

	// Setup representation proofs of squares
	result.squaresRep = make([]representationProofStructure, len(Squares))
	for i, val := range result.squares {
		result.squaresRep[i] = representationProofStructure{
			[]lhsContribution{
				{strings.Join([]string{"s", fmt.Sprintf("%v", i)}, "_"), big.NewInt(-1)},
				{"g", new(big.Int).Set(val)},
			},
			[]rhsContribution{
				{"h", strings.Join([]string{"s", fmt.Sprintf("%v", i), "hider"}, "_"), -1},
			},
		}
	}

	// Setup representation proofs of roots
	result.rootsRep = make([]representationProofStructure, len(Squares))
	for i := range Squares {
		result.rootsRep[i] = newPedersonRepresentationProofStructure(
			strings.Join([]string{"r", fmt.Sprintf("%v", i)}, "_"))
	}

	// Setup range proof of roots
	result.rootsRange = make([]rangeProofStructure, len(Squares))
	for i := range Squares {
		result.rootsRange[i] = newPedersonRangeProofStructure(
			strings.Join([]string{"r", fmt.Sprintf("%v", i)}, "_"),
			0,
			uint(N.BitLen()))
	}

	// Setup proofs that the roots are roots
	result.rootsValid = make([]multiplicationProofStructure, len(Squares))
	for i := range Squares {
		result.rootsValid[i] = newMultiplicationProofStructure(
			strings.Join([]string{"r", fmt.Sprintf("%v", i)}, "_"),
			strings.Join([]string{"r", fmt.Sprintf("%v", i)}, "_"),
			"N",
			strings.Join([]string{"s", fmt.Sprintf("%v", i)}, "_"),
			uint(N.BitLen()))
	}

	return result
}

func (s *isSquareProofStructure) numRangeProofs() int {
	result := 0
	for _, ms := range s.rootsValid {
		result += ms.numRangeProofs()
	}

	return result + len(s.rootsRange)
}

func (s *isSquareProofStructure) numCommitments() int {
	// Constants
	res := 1 + len(s.squares)
	// Pedersons
	res += 1
	res += len(s.squares)
	res += len(s.squares)
	// Representationproofs
	res += 1
	res += len(s.squaresRep)
	res += len(s.rootsRep)
	// ValidityProofs
	for i := range s.rootsRange {
		res += s.rootsRange[i].numCommitments()
	}
	for i := range s.rootsValid {
		res += s.rootsValid[i].numCommitments()
	}
	return res
}

func (s *isSquareProofStructure) generateCommitmentsFromSecrets(g group, list []*big.Int, P *big.Int, Q *big.Int) ([]*big.Int, isSquareProofCommit) {
	var commit isSquareProofCommit

	// Build up the secrets
	commit.squares = make([]pedersonSecret, len(s.squares))
	for i, val := range s.squares {
		commit.squares[i] = newPedersonSecret(g, strings.Join([]string{"s", fmt.Sprintf("%v", i)}, "_"), val)
	}
	commit.roots = make([]pedersonSecret, len(s.squares))
	for i, val := range s.squares {
		root, ok := common.ModSqrt(val, []*big.Int{P, Q})
		if !ok {
			panic("Incorrect key")
		}
		commit.roots[i] = newPedersonSecret(g, strings.Join([]string{"r", fmt.Sprintf("%v", i)}, "_"), root)
	}
	commit.n = newPedersonSecret(g, "N", s.n)

	// Build up bases and secrets (this is ugly code, hopefully go2 will make this better someday)
	baseList := []baseLookup{}
	secretList := []secretLookup{}
	for i := range commit.squares {
		baseList = append(baseList, &commit.squares[i])
		secretList = append(secretList, &commit.squares[i])
	}
	for i := range commit.roots {
		baseList = append(baseList, &commit.roots[i])
		secretList = append(secretList, &commit.roots[i])
	}
	baseList = append(baseList, &commit.n)
	secretList = append(secretList, &commit.n)
	baseList = append(baseList, &g)
	bases := newBaseMerge(baseList...)
	secrets := newSecretMerge(secretList...)

	// Generate commitments
	commit.rootRangeCommit = make([]rangeCommit, len(s.squares))
	commit.rootValidCommit = make([]multiplicationProofCommit, len(s.squares))
	list = append(list, s.n)
	for _, val := range s.squares {
		list = append(list, val)
	}
	list = commit.n.generateCommitments(list)
	for i := range commit.squares {
		list = commit.squares[i].generateCommitments(list)
	}
	for i := range commit.roots {
		list = commit.roots[i].generateCommitments(list)
	}
	list = s.nRep.generateCommitmentsFromSecrets(g, list, &bases, &secrets)
	for i := range s.squaresRep {
		list = s.squaresRep[i].generateCommitmentsFromSecrets(g, list, &bases, &secrets)
	}
	for i := range s.rootsRep {
		list = s.rootsRep[i].generateCommitmentsFromSecrets(g, list, &bases, &secrets)
	}
	for i := range s.rootsRange {
		list, commit.rootRangeCommit[i] = s.rootsRange[i].generateCommitmentsFromSecrets(g, list, &bases, &secrets)
	}
	for i := range s.rootsValid {
		list, commit.rootValidCommit[i] = s.rootsValid[i].generateCommitmentsFromSecrets(g, list, &bases, &secrets)
	}

	return list, commit
}

func (s *isSquareProofStructure) buildProof(g group, challenge *big.Int, commit isSquareProofCommit) IsSquareProof {
	// Build up secrets (this is ugly code, hopefully go2 will make this better someday)
	secretList := []secretLookup{}
	for i := range commit.squares {
		secretList = append(secretList, &commit.squares[i])
	}
	for i := range commit.roots {
		secretList = append(secretList, &commit.roots[i])
	}
	secretList = append(secretList, &commit.n)
	secrets := newSecretMerge(secretList...)

	// Calculate proofs
	var proof IsSquareProof
	proof.NProof = commit.n.buildProof(g, challenge)
	proof.SquaresProof = make([]PedersonProof, len(s.squares))
	for i := range commit.squares {
		proof.SquaresProof[i] = commit.squares[i].buildProof(g, challenge)
	}
	proof.RootsProof = make([]PedersonProof, len(s.squares))
	for i := range commit.roots {
		proof.RootsProof[i] = commit.roots[i].buildProof(g, challenge)
	}
	proof.RootsRangeProof = make([]RangeProof, len(s.squares))
	for i := range s.rootsRange {
		proof.RootsRangeProof[i] = s.rootsRange[i].buildProof(g, challenge, commit.rootRangeCommit[i], &secrets)
	}
	proof.RootsValidProof = make([]MultiplicationProof, len(s.squares))
	for i := range s.rootsValid {
		proof.RootsValidProof[i] = s.rootsValid[i].buildProof(g, challenge, commit.rootValidCommit[i], &secrets)
	}

	return proof
}

func (s *isSquareProofStructure) verifyProofStructure(proof IsSquareProof) bool {
	if !proof.NProof.verifyStructure() {
		return false
	}
	if len(proof.SquaresProof) != len(s.squares) || len(proof.RootsProof) != len(s.squares) {
		return false
	}
	if len(proof.RootsRangeProof) != len(s.squares) || len(proof.RootsValidProof) != len(s.squares) {
		return false
	}
	for i := range s.squares {
		if !proof.SquaresProof[i].verifyStructure() || !proof.RootsProof[i].verifyStructure() {
			return false
		}
		if !s.rootsRange[i].verifyProofStructure(proof.RootsRangeProof[i]) {
			return false
		}
		if !s.rootsValid[i].verifyProofStructure(proof.RootsValidProof[i]) {
			return false
		}
	}

	return true
}

func (s *isSquareProofStructure) generateCommitmentsFromProof(g group, list []*big.Int, challenge *big.Int, proof IsSquareProof) []*big.Int {
	// Setup names in pederson proofs
	proof.NProof.setName("N")
	for i := range s.squares {
		proof.SquaresProof[i].setName(strings.Join([]string{"s", fmt.Sprintf("%v", i)}, "_"))
		proof.RootsProof[i].setName(strings.Join([]string{"r", fmt.Sprintf("%v", i)}, "_"))
	}

	// Build up bases and proofs mergers
	baseList := []baseLookup{}
	proofList := []proofLookup{}
	for i := range s.squares {
		baseList = append(baseList, &proof.SquaresProof[i])
		proofList = append(proofList, &proof.SquaresProof[i])
	}
	for i := range s.squares {
		baseList = append(baseList, &proof.RootsProof[i])
		proofList = append(proofList, &proof.RootsProof[i])
	}
	baseList = append(baseList, &proof.NProof)
	proofList = append(proofList, &proof.NProof)
	baseList = append(baseList, &g)
	var bases = newBaseMerge(baseList...)
	var proofs = newProofMerge(proofList...)

	// Build up commitment list
	list = append(list, s.n)
	for _, val := range s.squares {
		list = append(list, val)
	}
	list = proof.NProof.generateCommitments(list)
	for i := range s.squares {
		list = proof.SquaresProof[i].generateCommitments(list)
	}
	for i := range s.squares {
		list = proof.RootsProof[i].generateCommitments(list)
	}
	list = s.nRep.generateCommitmentsFromProof(g, list, challenge, &bases, &proofs)
	for i := range s.squares {
		list = s.squaresRep[i].generateCommitmentsFromProof(g, list, challenge, &bases, &proofs)
	}
	for i := range s.squares {
		list = s.rootsRep[i].generateCommitmentsFromProof(g, list, challenge, &bases, &proofs)
	}
	for i := range s.squares {
		list = s.rootsRange[i].generateCommitmentsFromProof(g, list, challenge, &bases, proof.RootsRangeProof[i])
	}
	for i := range s.squares {
		list = s.rootsValid[i].generateCommitmentsFromProof(g, list, challenge, &bases, &proofs, proof.RootsValidProof[i])
	}

	return list
}
