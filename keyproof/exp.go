package keyproof

import (
	"github.com/privacybydesign/gabi/big"

	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
)

type expProofStructure struct {
	base     string
	exponent string
	mod      string
	result   string
	myname   string
	bitlen   uint

	expBits  []pedersenStructure
	expBitEq representationProofStructure

	basePows     []pedersenStructure
	basePowRange []rangeProofStructure
	basePowRels  []multiplicationProofStructure

	start    pedersenStructure
	startRep representationProofStructure

	interRess     []pedersenStructure
	interResRange []rangeProofStructure

	interSteps []expStepStructure
}

type expProofCommit struct {
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

type ExpProof struct {
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

func newExpProofStructure(base, exponent, mod, result string, bitlen uint) expProofStructure {
	var structure expProofStructure

	structure.base = base
	structure.exponent = exponent
	structure.mod = mod
	structure.result = result
	structure.myname = strings.Join([]string{base, exponent, mod, result, "exp"}, "_")
	structure.bitlen = bitlen

	// Bit representation proofs
	for i := uint(0); i < bitlen; i++ {
		structure.expBits = append(
			structure.expBits,
			newPedersenStructure(strings.Join([]string{structure.myname, "bit", fmt.Sprintf("%v", i)}, "_")))
	}

	// Bit equality proof
	structure.expBitEq = representationProofStructure{
		[]lhsContribution{
			lhsContribution{exponent, big.NewInt(-1)},
		},
		[]rhsContribution{
			rhsContribution{"h", strings.Join([]string{structure.myname, "biteqhider"}, "_"), 1},
		},
	}
	for i := uint(0); i < bitlen; i++ {
		structure.expBitEq.lhs = append(
			structure.expBitEq.lhs,
			lhsContribution{
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
	structure.startRep = representationProofStructure{
		[]lhsContribution{
			lhsContribution{strings.Join([]string{structure.myname, "start"}, "_"), big.NewInt(1)},
			lhsContribution{"g", big.NewInt(-1)},
		},
		[]rhsContribution{
			rhsContribution{"h", strings.Join([]string{structure.myname, "start", "hider"}, "_"), 1},
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

func (s *expProofStructure) numRangeProofs() int {
	res := len(s.basePowRange)
	for i, _ := range s.basePowRels {
		res += s.basePowRels[i].numRangeProofs()
	}
	res += len(s.interResRange)
	for i, _ := range s.interSteps {
		res += s.interSteps[i].numRangeProofs()
	}
	return res
}

func (s *expProofStructure) numCommitments() int {
	res := 0
	for i, _ := range s.expBits {
		res += s.expBits[i].numCommitments()
	}
	res += s.expBitEq.numCommitments()
	for i, _ := range s.basePows {
		res += s.basePows[i].numCommitments()
	}
	for i, _ := range s.basePowRange {
		res += s.basePowRange[i].numCommitments()
	}
	for i, _ := range s.basePowRels {
		res += s.basePowRels[i].numCommitments()
	}
	res += s.start.numCommitments()
	res += s.startRep.numCommitments()
	for i, _ := range s.interRess {
		res += s.interRess[i].numCommitments()
	}
	for i, _ := range s.interResRange {
		res += s.interResRange[i].numCommitments()
	}
	for i, _ := range s.interSteps {
		res += s.interSteps[i].numCommitments()
	}
	return res
}

func (s *expProofStructure) generateCommitmentsFromSecrets(g group, list []*big.Int, bases baseLookup, secretdata secretLookup) ([]*big.Int, expProofCommit) {
	var commit expProofCommit
	var todo []func([]*big.Int)
	todoOffset := new(uint32)

	// Build up commit structure

	// exponent bits
	BitEqHider := new(big.Int).Neg(secretdata.getSecret(strings.Join([]string{s.exponent, "hider"}, "_")))
	commit.expBits = make([]pedersenCommit, s.bitlen)
	for i := uint(0); i < s.bitlen; i++ {
		list, commit.expBits[i] = s.expBits[i].generateCommitmentsFromSecrets(g, list, big.NewInt(int64(secretdata.getSecret(s.exponent).Bit(int(i)))))
		BitEqHider.Add(BitEqHider, new(big.Int).Lsh(commit.expBits[i].hider.secret, i))
	}
	BitEqHider.Mod(BitEqHider, g.order)
	commit.expBitEqHider = newSecret(g, strings.Join([]string{s.myname, "biteqhider"}, "_"), BitEqHider)

	// base powers
	commit.basePows = make([]pedersenCommit, s.bitlen)
	for i := uint(0); i < s.bitlen; i++ {
		list, commit.basePows[i] = s.basePows[i].generateCommitmentsFromSecrets(g, list,
			new(big.Int).Exp(
				secretdata.getSecret(s.base),
				new(big.Int).Lsh(big.NewInt(1), i),
				secretdata.getSecret(s.mod)))
	}

	// Start pedersen
	list, commit.start = s.start.generateCommitmentsFromSecrets(g, list, big.NewInt(1))

	// intermediate results
	curInterRes := big.NewInt(1)
	commit.interRess = make([]pedersenCommit, s.bitlen-1)
	for i := uint(0); i < s.bitlen-1; i++ {
		if secretdata.getSecret(s.exponent).Bit(int(i)) == 1 {
			curInterRes.Mod(
				new(big.Int).Mul(
					curInterRes,
					new(big.Int).Exp(
						secretdata.getSecret(s.base),
						new(big.Int).Lsh(big.NewInt(1), i),
						secretdata.getSecret(s.mod))),
				secretdata.getSecret(s.mod))
			if curInterRes.Cmp(new(big.Int).Sub(secretdata.getSecret(s.mod), big.NewInt(1))) == 0 {
				curInterRes.SetInt64(-1) // ugly(ish) hack to make comparisons to -1 work
			}
		}
		list, commit.interRess[i] = s.interRess[i].generateCommitmentsFromSecrets(g, list, curInterRes)
	}

	// inner bases and secrets (this is ugly code, hopefully go2 will make this better someday)
	baseList := []baseLookup{}
	secretList := []secretLookup{}
	for i, _ := range commit.expBits {
		baseList = append(baseList, &commit.expBits[i])
		secretList = append(secretList, &commit.expBits[i])
	}
	for i, _ := range commit.basePows {
		baseList = append(baseList, &commit.basePows[i])
		secretList = append(secretList, &commit.basePows[i])
	}
	baseList = append(baseList, &commit.start)
	secretList = append(secretList, &commit.start)
	for i, _ := range commit.interRess {
		baseList = append(baseList, &commit.interRess[i])
		secretList = append(secretList, &commit.interRess[i])
	}
	baseList = append(baseList, bases)
	secretList = append(secretList, secretdata)
	secretList = append(secretList, &commit.expBitEqHider)
	innerBases := newBaseMerge(baseList...)
	innerSecrets := newSecretMerge(secretList...)

	// bits
	list = s.expBitEq.generateCommitmentsFromSecrets(g, list, &innerBases, &innerSecrets)

	//base
	commit.basePowRangeCommit = make([]rangeCommit, 0, len(s.basePowRange))
	for i, _ := range s.basePowRange {
		curOff := len(list)
		list = append(list, make([]*big.Int, s.basePowRange[i].numCommitments())...)
		ic := i
		commitOff := len(commit.basePowRangeCommit)
		commit.basePowRangeCommit = append(commit.basePowRangeCommit, rangeCommit{})
		todo = append(todo, func(list []*big.Int) {
			var loc []*big.Int
			loc, commit.basePowRangeCommit[commitOff] = s.basePowRange[ic].generateCommitmentsFromSecrets(g, []*big.Int{}, &innerBases, &innerSecrets)
			for _, v := range loc {
				list[curOff] = v
				curOff++
			}
		})
	}
	commit.basePowRelCommit = make([]multiplicationProofCommit, 0, len(s.basePowRels))
	for i, _ := range s.basePowRels {
		curOff := len(list)
		list = append(list, make([]*big.Int, s.basePowRels[i].numCommitments())...)
		ic := i
		commitOff := len(commit.basePowRelCommit)
		commit.basePowRelCommit = append(commit.basePowRelCommit, multiplicationProofCommit{})
		todo = append(todo, func(list []*big.Int) {
			var loc []*big.Int
			loc, commit.basePowRelCommit[commitOff] = s.basePowRels[ic].generateCommitmentsFromSecrets(g, []*big.Int{}, &innerBases, &innerSecrets)
			for _, v := range loc {
				list[curOff] = v
				curOff++
			}
		})
	}

	//start
	list = s.startRep.generateCommitmentsFromSecrets(g, list, &innerBases, &innerSecrets)

	// interres
	commit.interResRangeCommit = make([]rangeCommit, 0, len(s.interResRange))
	for i, _ := range s.interResRange {
		curOff := len(list)
		list = append(list, make([]*big.Int, s.interResRange[i].numCommitments())...)
		ic := i
		commitOff := len(commit.interResRangeCommit)
		commit.interResRangeCommit = append(commit.interResRangeCommit, rangeCommit{})
		todo = append(todo, func(list []*big.Int) {
			var loc []*big.Int
			loc, commit.interResRangeCommit[commitOff] = s.interResRange[ic].generateCommitmentsFromSecrets(g, []*big.Int{}, &innerBases, &innerSecrets)
			for _, v := range loc {
				list[curOff] = v
				curOff++
			}
		})
	}

	// steps
	commit.interStepsCommit = make([]expStepCommit, 0, len(s.interSteps))
	for i, _ := range s.interSteps {
		curOff := len(list)
		list = append(list, make([]*big.Int, s.interSteps[i].numCommitments())...)
		ic := i
		commitOff := len(commit.interStepsCommit)
		commit.interStepsCommit = append(commit.interStepsCommit, expStepCommit{})
		todo = append(todo, func(list []*big.Int) {
			var loc []*big.Int
			loc, commit.interStepsCommit[commitOff] = s.interSteps[ic].generateCommitmentsFromSecrets(g, []*big.Int{}, &innerBases, &innerSecrets)
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

func (s *expProofStructure) buildProof(g group, challenge *big.Int, commit expProofCommit, secretdata secretLookup) ExpProof {
	var proof ExpProof

	// inner secret data
	secretList := []secretLookup{}
	for i, _ := range commit.expBits {
		secretList = append(secretList, &commit.expBits[i])
	}
	for i, _ := range commit.basePows {
		secretList = append(secretList, &commit.basePows[i])
	}
	secretList = append(secretList, &commit.start)
	for i, _ := range commit.interRess {
		secretList = append(secretList, &commit.interRess[i])
	}
	secretList = append(secretList, secretdata)
	secretList = append(secretList, &commit.expBitEqHider)
	innerSecrets := newSecretMerge(secretList...)

	//bit proofs
	proof.ExpBitProofs = make([]PedersenProof, len(commit.expBits))
	for i, _ := range commit.expBits {
		proof.ExpBitProofs[i] = s.expBits[i].buildProof(g, challenge, commit.expBits[i])
	}

	//base proofs
	proof.BasePowProofs = make([]PedersenProof, len(commit.basePows))
	for i, _ := range commit.basePows {
		proof.BasePowProofs[i] = s.basePows[i].buildProof(g, challenge, commit.basePows[i])
	}
	proof.BasePowRangeProofs = []RangeProof{}
	for i, _ := range commit.basePowRangeCommit {
		proof.BasePowRangeProofs = append(
			proof.BasePowRangeProofs,
			s.basePowRange[i].buildProof(g, challenge, commit.basePowRangeCommit[i], &innerSecrets))
	}
	proof.BasePowRelProofs = []MultiplicationProof{}
	for i, _ := range commit.basePowRelCommit {
		proof.BasePowRelProofs = append(
			proof.BasePowRelProofs,
			s.basePowRels[i].buildProof(g, challenge, commit.basePowRelCommit[i], &innerSecrets))
	}

	// start proof
	proof.StartProof = s.start.buildProof(g, challenge, commit.start)

	// interres proofs
	proof.InterResProofs = make([]PedersenProof, len(commit.interRess))
	for i, _ := range commit.interRess {
		proof.InterResProofs[i] = s.interRess[i].buildProof(g, challenge, commit.interRess[i])
	}
	proof.InterResRangeProofs = []RangeProof{}
	for i, _ := range commit.interResRangeCommit {
		proof.InterResRangeProofs = append(
			proof.InterResRangeProofs,
			s.interResRange[i].buildProof(g, challenge, commit.interResRangeCommit[i], &innerSecrets))
	}

	// step proofs
	proof.InterStepsProofs = []ExpStepProof{}
	for i, _ := range commit.interStepsCommit {
		proof.InterStepsProofs = append(
			proof.InterStepsProofs,
			s.interSteps[i].buildProof(g, challenge, commit.interStepsCommit[i], &innerSecrets))
	}

	// Calculate our segments of the proof
	proof.ExpBitEqHider = commit.expBitEqHider.buildProof(g, challenge)

	return proof
}

func (s *expProofStructure) fakeProof(g group, challenge *big.Int) ExpProof {
	var proof ExpProof

	proof.ExpBitEqHider = fakeProof(g)
	proof.ExpBitProofs = make([]PedersenProof, s.bitlen)
	for i := uint(0); i < s.bitlen; i++ {
		proof.ExpBitProofs[i] = s.expBits[i].fakeProof(g)
	}

	proof.BasePowProofs = make([]PedersenProof, len(s.basePows))
	proof.BasePowRangeProofs = make([]RangeProof, len(s.basePows))
	proof.BasePowRelProofs = make([]MultiplicationProof, len(s.basePows))
	for i, _ := range s.basePows {
		proof.BasePowProofs[i] = s.basePows[i].fakeProof(g)
		proof.BasePowRangeProofs[i] = s.basePowRange[i].fakeProof(g)
		proof.BasePowRelProofs[i] = s.basePowRels[i].fakeProof(g)
	}

	proof.StartProof = s.start.fakeProof(g)

	proof.InterResProofs = make([]PedersenProof, len(s.interRess))
	proof.InterResRangeProofs = make([]RangeProof, len(s.interRess))
	for i, _ := range s.interRess {
		proof.InterResProofs[i] = s.interRess[i].fakeProof(g)
		proof.InterResRangeProofs[i] = s.interResRange[i].fakeProof(g)
	}

	proof.InterStepsProofs = []ExpStepProof{}
	for i, _ := range s.interSteps {
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
	for i, _ := range proof.ExpBitProofs {
		if !s.expBits[i].verifyProofStructure(proof.ExpBitProofs[i]) {
			return false
		}
	}

	// check base proofs
	if len(proof.BasePowProofs) != int(s.bitlen) || len(proof.BasePowRangeProofs) != int(s.bitlen) || len(proof.BasePowRelProofs) != int(s.bitlen) {
		return false
	}
	for i, _ := range proof.BasePowProofs {
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
	for i, _ := range proof.InterResProofs {
		if !s.interRess[i].verifyProofStructure(proof.InterResProofs[i]) ||
			!s.interResRange[i].verifyProofStructure(proof.InterResRangeProofs[i]) {
			return false
		}
	}

	// check step proof
	if len(proof.InterStepsProofs) != int(s.bitlen) {
		return false
	}
	for i, _ := range proof.InterStepsProofs {
		if !s.interSteps[i].verifyProofStructure(challenge, proof.InterStepsProofs[i]) {
			return false
		}
	}

	return true
}

func (s *expProofStructure) generateCommitmentsFromProof(g group, list []*big.Int, challenge *big.Int, bases baseLookup, proofdata proofLookup, proof ExpProof) []*big.Int {
	// inner bases and proofs (again hopefully go2 will make this better)
	baseList := []baseLookup{}
	proofList := []proofLookup{}
	for i, _ := range proof.ExpBitProofs {
		proof.ExpBitProofs[i].setName(strings.Join([]string{s.myname, "bit", fmt.Sprintf("%v", i)}, "_"))
		baseList = append(baseList, &proof.ExpBitProofs[i])
		proofList = append(proofList, &proof.ExpBitProofs[i])
	}
	for i, _ := range proof.BasePowProofs {
		proof.BasePowProofs[i].setName(strings.Join([]string{s.myname, "base", fmt.Sprintf("%v", i)}, "_"))
		baseList = append(baseList, &proof.BasePowProofs[i])
		proofList = append(proofList, &proof.BasePowProofs[i])
	}
	proof.StartProof.setName(strings.Join([]string{s.myname, "start"}, "_"))
	baseList = append(baseList, &proof.StartProof)
	proofList = append(proofList, &proof.StartProof)
	for i, _ := range proof.InterResProofs {
		proof.InterResProofs[i].setName(strings.Join([]string{s.myname, "inter", fmt.Sprintf("%v", i)}, "_"))
		baseList = append(baseList, &proof.InterResProofs[i])
		proofList = append(proofList, &proof.InterResProofs[i])
	}
	baseList = append(baseList, bases)
	proofList = append(proofList, proofdata)
	proof.ExpBitEqHider.setName(strings.Join([]string{s.myname, "biteqhider"}, "_"))
	proofList = append(proofList, &proof.ExpBitEqHider)
	innerBases := newBaseMerge(baseList...)
	innerProof := newProofMerge(proofList...)

	// Generate commitment list
	var todo []func([]*big.Int)
	todoOffset := new(uint32)

	// bit
	for i, _ := range proof.ExpBitProofs {
		curOff := len(list)
		list = append(list, make([]*big.Int, s.expBits[i].numCommitments())...)
		ic := i
		todo = append(todo, func(list []*big.Int) {
			loc := s.expBits[ic].generateCommitmentsFromProof(g, nil, challenge, proof.ExpBitProofs[ic])
			for _, v := range loc {
				list[curOff] = v
				curOff++
			}
		})
	}

	//base
	for i, _ := range proof.BasePowProofs {
		curOff := len(list)
		list = append(list, make([]*big.Int, s.basePows[i].numCommitments())...)
		ic := i
		todo = append(todo, func(list []*big.Int) {
			loc := s.basePows[ic].generateCommitmentsFromProof(g, nil, challenge, proof.BasePowProofs[ic])
			for _, v := range loc {
				list[curOff] = v
				curOff++
			}
		})
	}

	// start
	list = s.start.generateCommitmentsFromProof(g, list, challenge, proof.StartProof)

	// interres
	for i, _ := range s.interRess {
		curOff := len(list)
		list = append(list, make([]*big.Int, s.interRess[i].numCommitments())...)
		ic := i
		todo = append(todo, func(list []*big.Int) {
			loc := s.interRess[ic].generateCommitmentsFromProof(g, nil, challenge, proof.InterResProofs[ic])
			for _, v := range loc {
				list[curOff] = v
				curOff++
			}
		})
	}

	// bit
	list = s.expBitEq.generateCommitmentsFromProof(g, list, challenge, &innerBases, &innerProof)

	//base
	for i, _ := range s.basePowRange {
		curOff := len(list)
		list = append(list, make([]*big.Int, s.basePowRange[i].numCommitments())...)
		ic := i
		todo = append(todo, func(list []*big.Int) {
			loc := s.basePowRange[ic].generateCommitmentsFromProof(g, []*big.Int{}, challenge, &innerBases, proof.BasePowRangeProofs[ic])
			for _, v := range loc {
				list[curOff] = v
				curOff++
			}
		})
	}
	for i, _ := range s.basePowRels {
		curOff := len(list)
		list = append(list, make([]*big.Int, s.basePowRels[i].numCommitments())...)
		ic := i
		todo = append(todo, func(list []*big.Int) {
			loc := s.basePowRels[ic].generateCommitmentsFromProof(g, []*big.Int{}, challenge, &innerBases, &innerProof, proof.BasePowRelProofs[ic])
			for _, v := range loc {
				list[curOff] = v
				curOff++
			}
		})
	}

	// start
	list = s.startRep.generateCommitmentsFromProof(g, list, challenge, &innerBases, &innerProof)

	// interres
	for i, _ := range s.interResRange {
		curOff := len(list)
		list = append(list, make([]*big.Int, s.interResRange[i].numCommitments())...)
		ic := i
		todo = append(todo, func(list []*big.Int) {
			loc := s.interResRange[ic].generateCommitmentsFromProof(g, []*big.Int{}, challenge, &innerBases, proof.InterResRangeProofs[ic])
			for _, v := range loc {
				list[curOff] = v
				curOff++
			}
		})
	}

	// steps
	for i, _ := range s.interSteps {
		curOff := len(list)
		list = append(list, make([]*big.Int, s.interSteps[i].numCommitments())...)
		ic := i
		todo = append(todo, func(list []*big.Int) {
			loc := s.interSteps[ic].generateCommitmentsFromProof(g, []*big.Int{}, challenge, &innerBases, proof.InterStepsProofs[ic])
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

func (s *expProofStructure) isTrue(secretdata secretLookup) bool {
	div := new(big.Int)
	mod := new(big.Int)

	div.DivMod(
		new(big.Int).Sub(
			new(big.Int).Exp(
				secretdata.getSecret(s.base),
				secretdata.getSecret(s.exponent),
				secretdata.getSecret(s.mod)),
			secretdata.getSecret(s.result)),
		secretdata.getSecret(s.mod),
		mod)

	return mod.Cmp(big.NewInt(0)) == 0 && uint(div.BitLen()) <= s.bitlen
}
