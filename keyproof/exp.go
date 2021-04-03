package keyproof

import (
	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/zkproof"

	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
)

type (
	expProofStructure struct {
		base     string
		exponent string
		mod      string
		result   string
		myname   string
		bitlen   uint

		expBits  []pedersenStructure
		expBitEq zkproof.RepresentationProofStructure

		basePows     []pedersenStructure
		basePowRange []rangeProofStructure
		basePowRels  []multiplicationProofStructure

		start    pedersenStructure
		startRep zkproof.RepresentationProofStructure

		interRess     []pedersenStructure
		interResRange []rangeProofStructure

		interSteps []expStepStructure
	}

	expProofCommit struct {
		expBits       []pedersenCommit
		expBitEqHider secret

		basePows           []pedersenCommit
		basePowRangeCommit []rangeCommit
		basePowRelCommit   []multiplicationProofCommit

		start pedersenCommit

		interRess           []pedersenCommit
		interResRangeCommit []rangeCommit

		interStepsCommit []expStepCommit
	}

	ExpProof struct {
		ExpBitProofs  []PedersenProof
		ExpBitEqHider Proof

		BasePowProofs      []PedersenProof
		BasePowRangeProofs []RangeProof
		BasePowRelProofs   []MultiplicationProof

		StartProof PedersenProof

		InterResProofs      []PedersenProof
		InterResRangeProofs []RangeProof

		InterStepsProofs []ExpStepProof
	}
)

func newExpProofStructure(base, exponent, mod, result string, bitlen uint) expProofStructure {
	structure := expProofStructure{
		base:     base,
		exponent: exponent,
		mod:      mod,
		result:   result,
		myname:   strings.Join([]string{base, exponent, mod, result, "exp"}, "_"),
		bitlen:   bitlen,
	}

	// Bit representation proofs
	for i := uint(0); i < bitlen; i++ {
		structure.expBits = append(
			structure.expBits,
			newPedersenStructure(strings.Join([]string{structure.myname, "bit", fmt.Sprintf("%v", i)}, "_")))
	}

	// Bit equality proof
	structure.expBitEq = zkproof.RepresentationProofStructure{
		[]zkproof.LhsContribution{
			zkproof.LhsContribution{exponent, big.NewInt(-1)},
		},
		[]zkproof.RhsContribution{
			zkproof.RhsContribution{"h", strings.Join([]string{structure.myname, "biteqhider"}, "_"), 1},
		},
	}
	for i := uint(0); i < bitlen; i++ {
		structure.expBitEq.Lhs = append(
			structure.expBitEq.Lhs,
			zkproof.LhsContribution{
				strings.Join([]string{structure.myname, "bit", fmt.Sprintf("%v", i)}, "_"),
				new(big.Int).Lsh(big.NewInt(1), i),
			})
	}

	// Base representation proofs
	for i := uint(0); i < bitlen; i++ {
		structure.basePows = append(
			structure.basePows,
			newPedersenStructure(strings.Join([]string{structure.myname, "base", fmt.Sprintf("%v", i)}, "_")))
	}

	// Base range proofs
	structure.basePowRange = []rangeProofStructure{}
	for i := uint(0); i < bitlen; i++ {
		structure.basePowRange = append(
			structure.basePowRange,
			newPedersenRangeProofStructure(strings.Join([]string{structure.myname, "base", fmt.Sprintf("%v", i)}, "_"), 0, bitlen))
	}

	// Base relations proofs
	structure.basePowRels = []multiplicationProofStructure{}
	for i := uint(0); i < bitlen; i++ {
		if i == 0 {
			// special case for start
			structure.basePowRels = append(
				structure.basePowRels,
				newMultiplicationProofStructure(
					strings.Join([]string{structure.myname, "start"}, "_"),
					base,
					mod,
					strings.Join([]string{structure.myname, "base", fmt.Sprintf("%v", i)}, "_"),
					bitlen))
		} else {
			structure.basePowRels = append(
				structure.basePowRels,
				newMultiplicationProofStructure(
					strings.Join([]string{structure.myname, "base", fmt.Sprintf("%v", i-1)}, "_"),
					strings.Join([]string{structure.myname, "base", fmt.Sprintf("%v", i-1)}, "_"),
					mod,
					strings.Join([]string{structure.myname, "base", fmt.Sprintf("%v", i)}, "_"),
					bitlen))
		}
	}

	// start representation proof
	structure.start = newPedersenStructure(strings.Join([]string{structure.myname, "start"}, "_"))
	structure.startRep = zkproof.RepresentationProofStructure{
		[]zkproof.LhsContribution{
			zkproof.LhsContribution{strings.Join([]string{structure.myname, "start"}, "_"), big.NewInt(1)},
			zkproof.LhsContribution{"g", big.NewInt(-1)},
		},
		[]zkproof.RhsContribution{
			zkproof.RhsContribution{"h", strings.Join([]string{structure.myname, "start", "hider"}, "_"), 1},
		},
	}

	// inter representation proofs
	for i := uint(0); i < bitlen-1; i++ {
		structure.interRess = append(
			structure.interRess,
			newPedersenStructure(strings.Join([]string{structure.myname, "inter", fmt.Sprintf("%v", i)}, "_")))
	}

	// inter range proofs
	structure.interResRange = []rangeProofStructure{}
	for i := uint(0); i < bitlen-1; i++ {
		structure.interResRange = append(
			structure.interResRange,
			newPedersenRangeProofStructure(strings.Join([]string{structure.myname, "inter", fmt.Sprintf("%v", i)}, "_"), 0, bitlen))
	}

	// step proofs
	structure.interSteps = []expStepStructure{}
	for i := uint(0); i < bitlen; i++ {
		if i == 0 {
			// special case for start
			structure.interSteps = append(
				structure.interSteps,
				newExpStepStructure(
					strings.Join([]string{structure.myname, "bit", fmt.Sprintf("%v", i)}, "_"),
					strings.Join([]string{structure.myname, "start"}, "_"),
					strings.Join([]string{structure.myname, "inter", fmt.Sprintf("%v", i)}, "_"),
					strings.Join([]string{structure.myname, "base", fmt.Sprintf("%v", i)}, "_"),
					mod,
					bitlen))
		} else if i == bitlen-1 {
			// special case for end
			structure.interSteps = append(
				structure.interSteps,
				newExpStepStructure(
					strings.Join([]string{structure.myname, "bit", fmt.Sprintf("%v", i)}, "_"),
					strings.Join([]string{structure.myname, "inter", fmt.Sprintf("%v", i-1)}, "_"),
					result,
					strings.Join([]string{structure.myname, "base", fmt.Sprintf("%v", i)}, "_"),
					mod,
					bitlen))
		} else {
			structure.interSteps = append(
				structure.interSteps,
				newExpStepStructure(
					strings.Join([]string{structure.myname, "bit", fmt.Sprintf("%v", i)}, "_"),
					strings.Join([]string{structure.myname, "inter", fmt.Sprintf("%v", i-1)}, "_"),
					strings.Join([]string{structure.myname, "inter", fmt.Sprintf("%v", i)}, "_"),
					strings.Join([]string{structure.myname, "base", fmt.Sprintf("%v", i)}, "_"),
					mod,
					bitlen))
		}
	}

	return structure
}

func (s *expProofStructure) commitmentsFromSecrets(g zkproof.Group, list []*big.Int, bases zkproof.BaseLookup, secretdata zkproof.SecretLookup) ([]*big.Int, expProofCommit) {
	var commit expProofCommit
	var todo []func([]*big.Int)
	todoOffset := new(uint32)

	// Build up commit structure

	// exponent bits
	BitEqHider := new(big.Int).Neg(secretdata.Secret(strings.Join([]string{s.exponent, "hider"}, "_")))
	commit.expBits = make([]pedersenCommit, s.bitlen)
	for i := uint(0); i < s.bitlen; i++ {
		list, commit.expBits[i] = s.expBits[i].commitmentsFromSecrets(g, list, big.NewInt(int64(secretdata.Secret(s.exponent).Bit(int(i)))))
		BitEqHider.Add(BitEqHider, new(big.Int).Lsh(commit.expBits[i].hider.secretv, i))
	}
	BitEqHider.Mod(BitEqHider, g.Order)
	commit.expBitEqHider = newSecret(g, strings.Join([]string{s.myname, "biteqhider"}, "_"), BitEqHider)

	// base powers
	commit.basePows = make([]pedersenCommit, s.bitlen)
	for i := uint(0); i < s.bitlen; i++ {
		list, commit.basePows[i] = s.basePows[i].commitmentsFromSecrets(g, list,
			new(big.Int).Exp(
				secretdata.Secret(s.base),
				new(big.Int).Lsh(big.NewInt(1), i),
				secretdata.Secret(s.mod)))
	}

	// Start pedersen
	list, commit.start = s.start.commitmentsFromSecrets(g, list, big.NewInt(1))

	// intermediate results
	curInterRes := big.NewInt(1)
	commit.interRess = make([]pedersenCommit, s.bitlen-1)
	for i := uint(0); i < s.bitlen-1; i++ {
		if secretdata.Secret(s.exponent).Bit(int(i)) == 1 {
			curInterRes.Mod(
				new(big.Int).Mul(
					curInterRes,
					new(big.Int).Exp(
						secretdata.Secret(s.base),
						new(big.Int).Lsh(big.NewInt(1), i),
						secretdata.Secret(s.mod))),
				secretdata.Secret(s.mod))
			if curInterRes.Cmp(new(big.Int).Sub(secretdata.Secret(s.mod), big.NewInt(1))) == 0 {
				curInterRes.SetInt64(-1) // ugly(ish) hack to make comparisons to -1 work
			}
		}
		list, commit.interRess[i] = s.interRess[i].commitmentsFromSecrets(g, list, curInterRes)
	}

	// inner bases and secrets (this is ugly code, hopefully go2 will make this better someday)
	baseList := []zkproof.BaseLookup{}
	secretList := []zkproof.SecretLookup{}
	for i := range commit.expBits {
		baseList = append(baseList, &commit.expBits[i])
		secretList = append(secretList, &commit.expBits[i])
	}
	for i := range commit.basePows {
		baseList = append(baseList, &commit.basePows[i])
		secretList = append(secretList, &commit.basePows[i])
	}
	baseList = append(baseList, &commit.start)
	secretList = append(secretList, &commit.start)
	for i := range commit.interRess {
		baseList = append(baseList, &commit.interRess[i])
		secretList = append(secretList, &commit.interRess[i])
	}
	baseList = append(baseList, bases)
	secretList = append(secretList, secretdata)
	secretList = append(secretList, &commit.expBitEqHider)
	innerBases := zkproof.NewBaseMerge(baseList...)
	innerSecrets := zkproof.NewSecretMerge(secretList...)

	// bits
	list = s.expBitEq.CommitmentsFromSecrets(g, list, &innerBases, &innerSecrets)

	//base
	commit.basePowRangeCommit = make([]rangeCommit, 0, len(s.basePowRange))
	for i := range s.basePowRange {
		curOff := len(list)
		list = append(list, make([]*big.Int, s.basePowRange[i].numCommitments())...)
		ic := i
		commitOff := len(commit.basePowRangeCommit)
		commit.basePowRangeCommit = append(commit.basePowRangeCommit, rangeCommit{})
		todo = append(todo, func(list []*big.Int) {
			var loc []*big.Int
			loc, commit.basePowRangeCommit[commitOff] = s.basePowRange[ic].commitmentsFromSecrets(g, []*big.Int{}, &innerBases, &innerSecrets)
			for _, v := range loc {
				list[curOff] = v
				curOff++
			}
		})
	}
	commit.basePowRelCommit = make([]multiplicationProofCommit, 0, len(s.basePowRels))
	for i := range s.basePowRels {
		curOff := len(list)
		list = append(list, make([]*big.Int, s.basePowRels[i].numCommitments())...)
		ic := i
		commitOff := len(commit.basePowRelCommit)
		commit.basePowRelCommit = append(commit.basePowRelCommit, multiplicationProofCommit{})
		todo = append(todo, func(list []*big.Int) {
			var loc []*big.Int
			loc, commit.basePowRelCommit[commitOff] = s.basePowRels[ic].commitmentsFromSecrets(g, []*big.Int{}, &innerBases, &innerSecrets)
			for _, v := range loc {
				list[curOff] = v
				curOff++
			}
		})
	}

	//start
	list = s.startRep.CommitmentsFromSecrets(g, list, &innerBases, &innerSecrets)

	// interres
	commit.interResRangeCommit = make([]rangeCommit, 0, len(s.interResRange))
	for i := range s.interResRange {
		curOff := len(list)
		list = append(list, make([]*big.Int, s.interResRange[i].numCommitments())...)
		ic := i
		commitOff := len(commit.interResRangeCommit)
		commit.interResRangeCommit = append(commit.interResRangeCommit, rangeCommit{})
		todo = append(todo, func(list []*big.Int) {
			var loc []*big.Int
			loc, commit.interResRangeCommit[commitOff] = s.interResRange[ic].commitmentsFromSecrets(g, []*big.Int{}, &innerBases, &innerSecrets)
			for _, v := range loc {
				list[curOff] = v
				curOff++
			}
		})
	}

	// steps
	commit.interStepsCommit = make([]expStepCommit, 0, len(s.interSteps))
	for i := range s.interSteps {
		curOff := len(list)
		list = append(list, make([]*big.Int, s.interSteps[i].numCommitments())...)
		ic := i
		commitOff := len(commit.interStepsCommit)
		commit.interStepsCommit = append(commit.interStepsCommit, expStepCommit{})
		todo = append(todo, func(list []*big.Int) {
			var loc []*big.Int
			loc, commit.interStepsCommit[commitOff] = s.interSteps[ic].commitmentsFromSecrets(g, []*big.Int{}, &innerBases, &innerSecrets)
			for _, v := range loc {
				list[curOff] = v
				curOff++
			}
		})
	}

	workerCount := runtime.NumCPU()
	wg := sync.WaitGroup{}
	wg.Add(workerCount)
	for worker := 0; worker < workerCount; worker++ {
		go func() {
			for {
				offset := int(atomic.AddUint32(todoOffset, 1))
				if offset > len(todo) {
					break
				}
				todo[offset-1](list)
			}
			wg.Done()
		}()
	}

	wg.Wait()

	return list, commit
}

func (s *expProofStructure) buildProof(g zkproof.Group, challenge *big.Int, commit expProofCommit, secretdata zkproof.SecretLookup) ExpProof {
	var proof ExpProof

	// inner secret data
	var secretList []zkproof.SecretLookup
	for i := range commit.expBits {
		secretList = append(secretList, &commit.expBits[i])
	}
	for i := range commit.basePows {
		secretList = append(secretList, &commit.basePows[i])
	}
	secretList = append(secretList, &commit.start)
	for i := range commit.interRess {
		secretList = append(secretList, &commit.interRess[i])
	}
	secretList = append(secretList, secretdata)
	secretList = append(secretList, &commit.expBitEqHider)
	innerSecrets := zkproof.NewSecretMerge(secretList...)

	//bit proofs
	proof.ExpBitProofs = make([]PedersenProof, len(commit.expBits))
	for i := range commit.expBits {
		proof.ExpBitProofs[i] = s.expBits[i].buildProof(g, challenge, commit.expBits[i])
	}

	//base proofs
	proof.BasePowProofs = make([]PedersenProof, len(commit.basePows))
	for i := range commit.basePows {
		proof.BasePowProofs[i] = s.basePows[i].buildProof(g, challenge, commit.basePows[i])
	}
	for i := range commit.basePowRangeCommit {
		proof.BasePowRangeProofs = append(
			proof.BasePowRangeProofs,
			s.basePowRange[i].buildProof(g, challenge, commit.basePowRangeCommit[i], &innerSecrets))
	}
	for i := range commit.basePowRelCommit {
		proof.BasePowRelProofs = append(
			proof.BasePowRelProofs,
			s.basePowRels[i].buildProof(g, challenge, commit.basePowRelCommit[i], &innerSecrets))
	}

	// start proof
	proof.StartProof = s.start.buildProof(g, challenge, commit.start)

	// interres proofs
	proof.InterResProofs = make([]PedersenProof, len(commit.interRess))
	for i := range commit.interRess {
		proof.InterResProofs[i] = s.interRess[i].buildProof(g, challenge, commit.interRess[i])
	}
	for i := range commit.interResRangeCommit {
		proof.InterResRangeProofs = append(
			proof.InterResRangeProofs,
			s.interResRange[i].buildProof(g, challenge, commit.interResRangeCommit[i], &innerSecrets))
	}

	// step proofs
	for i := range commit.interStepsCommit {
		proof.InterStepsProofs = append(
			proof.InterStepsProofs,
			s.interSteps[i].buildProof(g, challenge, commit.interStepsCommit[i], &innerSecrets))
	}

	// Calculate our segments of the proof
	proof.ExpBitEqHider = commit.expBitEqHider.buildProof(g, challenge)

	return proof
}

func (s *expProofStructure) fakeProof(g zkproof.Group, challenge *big.Int) ExpProof {
	var proof ExpProof

	proof.ExpBitEqHider = fakeProof(g)
	proof.ExpBitProofs = make([]PedersenProof, s.bitlen)
	for i := uint(0); i < s.bitlen; i++ {
		proof.ExpBitProofs[i] = s.expBits[i].fakeProof(g)
	}

	proof.BasePowProofs = make([]PedersenProof, len(s.basePows))
	proof.BasePowRangeProofs = make([]RangeProof, len(s.basePows))
	proof.BasePowRelProofs = make([]MultiplicationProof, len(s.basePows))
	for i := range s.basePows {
		proof.BasePowProofs[i] = s.basePows[i].fakeProof(g)
		proof.BasePowRangeProofs[i] = s.basePowRange[i].fakeProof(g)
		proof.BasePowRelProofs[i] = s.basePowRels[i].fakeProof(g)
	}

	proof.StartProof = s.start.fakeProof(g)

	proof.InterResProofs = make([]PedersenProof, len(s.interRess))
	proof.InterResRangeProofs = make([]RangeProof, len(s.interRess))
	for i := range s.interRess {
		proof.InterResProofs[i] = s.interRess[i].fakeProof(g)
		proof.InterResRangeProofs[i] = s.interResRange[i].fakeProof(g)
	}

	for i := range s.interSteps {
		proof.InterStepsProofs = append(proof.InterStepsProofs, s.interSteps[i].fakeProof(g, challenge))
	}

	return proof
}

func (s *expProofStructure) verifyProofStructure(challenge *big.Int, proof ExpProof) bool {
	// check bit proofs
	if !proof.ExpBitEqHider.verifyStructure() {
		return false
	}
	if len(proof.ExpBitProofs) != int(s.bitlen) {
		return false
	}
	for i := range proof.ExpBitProofs {
		if !s.expBits[i].verifyProofStructure(proof.ExpBitProofs[i]) {
			return false
		}
	}

	// check base proofs
	if len(proof.BasePowProofs) != int(s.bitlen) || len(proof.BasePowRangeProofs) != int(s.bitlen) || len(proof.BasePowRelProofs) != int(s.bitlen) {
		return false
	}
	for i := range proof.BasePowProofs {
		if !s.basePows[i].verifyProofStructure(proof.BasePowProofs[i]) ||
			!s.basePowRange[i].verifyProofStructure(proof.BasePowRangeProofs[i]) ||
			!s.basePowRels[i].verifyProofStructure(proof.BasePowRelProofs[i]) {
			return false
		}
	}

	// check start proof
	if !s.start.verifyProofStructure(proof.StartProof) {
		return false
	}

	// check inter res
	if len(proof.InterResProofs) != int(s.bitlen-1) || len(proof.InterResRangeProofs) != int(s.bitlen-1) {
		return false
	}
	for i := range proof.InterResProofs {
		if !s.interRess[i].verifyProofStructure(proof.InterResProofs[i]) ||
			!s.interResRange[i].verifyProofStructure(proof.InterResRangeProofs[i]) {
			return false
		}
	}

	// check step proof
	if len(proof.InterStepsProofs) != int(s.bitlen) {
		return false
	}
	for i := range proof.InterStepsProofs {
		if !s.interSteps[i].verifyProofStructure(challenge, proof.InterStepsProofs[i]) {
			return false
		}
	}

	return true
}

func (s *expProofStructure) commitmentsFromProof(g zkproof.Group, list []*big.Int, challenge *big.Int, bases zkproof.BaseLookup, proofdata zkproof.ProofLookup, proof ExpProof) []*big.Int {
	// inner bases and proofs (again hopefully go2 will make this better)
	baseList := []zkproof.BaseLookup{}
	proofList := []zkproof.ProofLookup{}
	for i := range proof.ExpBitProofs {
		proof.ExpBitProofs[i].setName(strings.Join([]string{s.myname, "bit", fmt.Sprintf("%v", i)}, "_"))
		baseList = append(baseList, &proof.ExpBitProofs[i])
		proofList = append(proofList, &proof.ExpBitProofs[i])
	}
	for i := range proof.BasePowProofs {
		proof.BasePowProofs[i].setName(strings.Join([]string{s.myname, "base", fmt.Sprintf("%v", i)}, "_"))
		baseList = append(baseList, &proof.BasePowProofs[i])
		proofList = append(proofList, &proof.BasePowProofs[i])
	}
	proof.StartProof.setName(strings.Join([]string{s.myname, "start"}, "_"))
	baseList = append(baseList, &proof.StartProof)
	proofList = append(proofList, &proof.StartProof)
	for i := range proof.InterResProofs {
		proof.InterResProofs[i].setName(strings.Join([]string{s.myname, "inter", fmt.Sprintf("%v", i)}, "_"))
		baseList = append(baseList, &proof.InterResProofs[i])
		proofList = append(proofList, &proof.InterResProofs[i])
	}
	baseList = append(baseList, bases)
	proofList = append(proofList, proofdata)
	proof.ExpBitEqHider.setName(strings.Join([]string{s.myname, "biteqhider"}, "_"))
	proofList = append(proofList, &proof.ExpBitEqHider)
	innerBases := zkproof.NewBaseMerge(baseList...)
	innerProof := zkproof.NewProofMerge(proofList...)

	// Generate commitment list
	var todo []func([]*big.Int)
	todoOffset := new(uint32)

	// bit
	for i := range proof.ExpBitProofs {
		curOff := len(list)
		list = append(list, make([]*big.Int, s.expBits[i].numCommitments())...)
		ic := i
		todo = append(todo, func(list []*big.Int) {
			loc := s.expBits[ic].commitmentsFromProof(g, nil, challenge, proof.ExpBitProofs[ic])
			for _, v := range loc {
				list[curOff] = v
				curOff++
			}
		})
	}

	//base
	for i := range proof.BasePowProofs {
		curOff := len(list)
		list = append(list, make([]*big.Int, s.basePows[i].numCommitments())...)
		ic := i
		todo = append(todo, func(list []*big.Int) {
			loc := s.basePows[ic].commitmentsFromProof(g, nil, challenge, proof.BasePowProofs[ic])
			for _, v := range loc {
				list[curOff] = v
				curOff++
			}
		})
	}

	// start
	list = s.start.commitmentsFromProof(g, list, challenge, proof.StartProof)

	// interres
	for i := range s.interRess {
		curOff := len(list)
		list = append(list, make([]*big.Int, s.interRess[i].numCommitments())...)
		ic := i
		todo = append(todo, func(list []*big.Int) {
			loc := s.interRess[ic].commitmentsFromProof(g, nil, challenge, proof.InterResProofs[ic])
			for _, v := range loc {
				list[curOff] = v
				curOff++
			}
		})
	}

	// bit
	list = s.expBitEq.CommitmentsFromProof(g, list, challenge, &innerBases, &innerProof)

	//base
	for i := range s.basePowRange {
		curOff := len(list)
		list = append(list, make([]*big.Int, s.basePowRange[i].numCommitments())...)
		ic := i
		todo = append(todo, func(list []*big.Int) {
			loc := s.basePowRange[ic].commitmentsFromProof(g, []*big.Int{}, challenge, &innerBases, proof.BasePowRangeProofs[ic])
			for _, v := range loc {
				list[curOff] = v
				curOff++
			}
		})
	}
	for i := range s.basePowRels {
		curOff := len(list)
		list = append(list, make([]*big.Int, s.basePowRels[i].numCommitments())...)
		ic := i
		todo = append(todo, func(list []*big.Int) {
			loc := s.basePowRels[ic].commitmentsFromProof(g, []*big.Int{}, challenge, &innerBases, &innerProof, proof.BasePowRelProofs[ic])
			for _, v := range loc {
				list[curOff] = v
				curOff++
			}
		})
	}

	// start
	list = s.startRep.CommitmentsFromProof(g, list, challenge, &innerBases, &innerProof)

	// interres
	for i := range s.interResRange {
		curOff := len(list)
		list = append(list, make([]*big.Int, s.interResRange[i].numCommitments())...)
		ic := i
		todo = append(todo, func(list []*big.Int) {
			loc := s.interResRange[ic].commitmentsFromProof(g, []*big.Int{}, challenge, &innerBases, proof.InterResRangeProofs[ic])
			for _, v := range loc {
				list[curOff] = v
				curOff++
			}
		})
	}

	// steps
	for i := range s.interSteps {
		curOff := len(list)
		list = append(list, make([]*big.Int, s.interSteps[i].numCommitments())...)
		ic := i
		todo = append(todo, func(list []*big.Int) {
			loc := s.interSteps[ic].commitmentsFromProof(g, []*big.Int{}, challenge, &innerBases, proof.InterStepsProofs[ic])
			for _, v := range loc {
				list[curOff] = v
				curOff++
			}
		})
	}

	workerCount := runtime.NumCPU()
	wg := sync.WaitGroup{}
	wg.Add(workerCount)
	for worker := 0; worker < workerCount; worker++ {
		go func() {
			for {
				offset := int(atomic.AddUint32(todoOffset, 1))
				if offset > len(todo) {
					break
				}
				todo[offset-1](list)
			}
			wg.Done()
		}()
	}

	wg.Wait()

	return list
}

func (s *expProofStructure) isTrue(secretdata zkproof.SecretLookup) bool {
	div := new(big.Int)
	mod := new(big.Int)

	div.DivMod(
		new(big.Int).Sub(
			new(big.Int).Exp(
				secretdata.Secret(s.base),
				secretdata.Secret(s.exponent),
				secretdata.Secret(s.mod)),
			secretdata.Secret(s.result)),
		secretdata.Secret(s.mod),
		mod)

	return mod.Cmp(big.NewInt(0)) == 0 && uint(div.BitLen()) <= s.bitlen
}

func (s *expProofStructure) numRangeProofs() int {
	res := len(s.basePowRange)
	for i := range s.basePowRels {
		res += s.basePowRels[i].numRangeProofs()
	}
	res += len(s.interResRange)
	for i := range s.interSteps {
		res += s.interSteps[i].numRangeProofs()
	}
	return res
}

func (s *expProofStructure) numCommitments() int {
	res := 0
	for i := range s.expBits {
		res += s.expBits[i].numCommitments()
	}
	res += s.expBitEq.NumCommitments()
	for i := range s.basePows {
		res += s.basePows[i].numCommitments()
	}
	for i := range s.basePowRange {
		res += s.basePowRange[i].numCommitments()
	}
	for i := range s.basePowRels {
		res += s.basePowRels[i].numCommitments()
	}
	res += s.start.numCommitments()
	res += s.startRep.NumCommitments()
	for i := range s.interRess {
		res += s.interRess[i].numCommitments()
	}
	for i := range s.interResRange {
		res += s.interResRange[i].numCommitments()
	}
	for i := range s.interSteps {
		res += s.interSteps[i].numCommitments()
	}
	return res
}
