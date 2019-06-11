package keyproof

import (
	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/internal/common"

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

	expBitRep []representationProofStructure
	expBitEq  representationProofStructure

	basePowRep   []representationProofStructure
	basePowRange []rangeProofStructure
	basePowRels  []multiplicationProofStructure

	startRep representationProofStructure

	interResRep   []representationProofStructure
	interResRange []rangeProofStructure

	interSteps []expStepStructure
}

type expProofCommit struct {
	nameBitEqHider          string
	expBitPederson          []pedersonSecret
	expBitEqHider           *big.Int
	expBitEqHiderRandomizer *big.Int

	basePowPederson    []pedersonSecret
	basePowRangeCommit []rangeCommit
	basePowRelCommit   []multiplicationProofCommit

	startPederson pedersonSecret

	interResPederson    []pedersonSecret
	interResRangeCommit []rangeCommit

	interStepsCommit []expStepCommit
}

type ExpProof struct {
	nameBitEqHider string
	ExpBitProofs   []PedersonProof
	ExpBitEqResult *big.Int

	BasePowProofs      []PedersonProof
	BasePowRangeProofs []RangeProof
	BasePowRelProofs   []MultiplicationProof

	StartProof PedersonProof

	InterResProofs      []PedersonProof
	InterResRangeProofs []RangeProof

	InterStepsProofs []ExpStepProof
}

func (c *expProofCommit) getSecret(name string) *big.Int {
	if name == c.nameBitEqHider {
		return c.expBitEqHider
	}
	return nil
}

func (c *expProofCommit) getRandomizer(name string) *big.Int {
	if name == c.nameBitEqHider {
		return c.expBitEqHiderRandomizer
	}
	return nil
}

func (p *ExpProof) getResult(name string) *big.Int {
	if name == p.nameBitEqHider {
		return p.ExpBitEqResult
	}
	return nil
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
	structure.expBitRep = []representationProofStructure{}
	for i := uint(0); i < bitlen; i++ {
		structure.expBitRep = append(
			structure.expBitRep,
			newPedersonRepresentationProofStructure(strings.Join([]string{structure.myname, "bit", fmt.Sprintf("%v", i)}, "_")))
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
	structure.basePowRep = []representationProofStructure{}
	for i := uint(0); i < bitlen; i++ {
		structure.basePowRep = append(
			structure.basePowRep,
			newPedersonRepresentationProofStructure(strings.Join([]string{structure.myname, "base", fmt.Sprintf("%v", i)}, "_")))
	}

	// Base range proofs
	structure.basePowRange = []rangeProofStructure{}
	for i := uint(0); i < bitlen; i++ {
		structure.basePowRange = append(
			structure.basePowRange,
			newPedersonRangeProofStructure(strings.Join([]string{structure.myname, "base", fmt.Sprintf("%v", i)}, "_"), 0, bitlen))
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
	structure.interResRep = []representationProofStructure{}
	for i := uint(0); i < bitlen-1; i++ {
		structure.interResRep = append(
			structure.interResRep,
			newPedersonRepresentationProofStructure(strings.Join([]string{structure.myname, "inter", fmt.Sprintf("%v", i)}, "_")))
	}

	// inter range proofs
	structure.interResRange = []rangeProofStructure{}
	for i := uint(0); i < bitlen-1; i++ {
		structure.interResRange = append(
			structure.interResRange,
			newPedersonRangeProofStructure(strings.Join([]string{structure.myname, "inter", fmt.Sprintf("%v", i)}, "_"), 0, bitlen))
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
	res := int(s.bitlen)
	for i, _ := range s.expBitRep {
		res += s.expBitRep[i].numCommitments()
	}
	res += s.expBitEq.numCommitments()
	res += int(s.bitlen)
	for i, _ := range s.basePowRep {
		res += s.basePowRep[i].numCommitments()
	}
	for i, _ := range s.basePowRange {
		res += s.basePowRange[i].numCommitments()
	}
	for i, _ := range s.basePowRels {
		res += s.basePowRels[i].numCommitments()
	}
	res += 1
	res += s.startRep.numCommitments()
	res += int(s.bitlen - 1)
	for i, _ := range s.interResRep {
		res += s.interResRep[i].numCommitments()
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
	commit.nameBitEqHider = strings.Join([]string{s.myname, "biteqhider"}, "_")
	commit.expBitEqHider = new(big.Int).Neg(secretdata.getSecret(strings.Join([]string{s.exponent, "hider"}, "_")))
	commit.expBitEqHiderRandomizer = common.FastRandomBigInt(g.order)
	commit.expBitPederson = []pedersonSecret{}
	for i := uint(0); i < s.bitlen; i++ {
		commit.expBitPederson = append(
			commit.expBitPederson,
			newPedersonSecret(
				g,
				strings.Join([]string{s.myname, "bit", fmt.Sprintf("%v", i)}, "_"),
				big.NewInt(int64(secretdata.getSecret(s.exponent).Bit(int(i))))))
		commit.expBitEqHider.Add(
			commit.expBitEqHider,
			new(big.Int).Lsh(commit.expBitPederson[i].hider, i))
	}
	commit.expBitEqHider.Mod(commit.expBitEqHider, g.order)

	// base powers
	commit.basePowPederson = []pedersonSecret{}
	for i := uint(0); i < s.bitlen; i++ {
		commit.basePowPederson = append(
			commit.basePowPederson,
			newPedersonSecret(
				g,
				strings.Join([]string{s.myname, "base", fmt.Sprintf("%v", i)}, "_"),
				new(big.Int).Exp(
					secretdata.getSecret(s.base),
					new(big.Int).Lsh(big.NewInt(1), i),
					secretdata.getSecret(s.mod))))
	}

	// Start pederson
	commit.startPederson = newPedersonSecret(
		g,
		strings.Join([]string{s.myname, "start"}, "_"),
		big.NewInt(1))

	// intermediate results
	curInterRes := big.NewInt(1)
	commit.interResPederson = []pedersonSecret{}
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
		commit.interResPederson = append(
			commit.interResPederson,
			newPedersonSecret(
				g,
				strings.Join([]string{s.myname, "inter", fmt.Sprintf("%v", i)}, "_"),
				curInterRes))
	}

	// inner bases and secrets (this is ugly code, hopefully go2 will make this better someday)
	baseList := []baseLookup{}
	secretList := []secretLookup{}
	for i, _ := range commit.expBitPederson {
		baseList = append(baseList, &commit.expBitPederson[i])
		secretList = append(secretList, &commit.expBitPederson[i])
	}
	for i, _ := range commit.basePowPederson {
		baseList = append(baseList, &commit.basePowPederson[i])
		secretList = append(secretList, &commit.basePowPederson[i])
	}
	baseList = append(baseList, &commit.startPederson)
	secretList = append(secretList, &commit.startPederson)
	for i, _ := range commit.interResPederson {
		baseList = append(baseList, &commit.interResPederson[i])
		secretList = append(secretList, &commit.interResPederson[i])
	}
	baseList = append(baseList, bases)
	secretList = append(secretList, secretdata)
	secretList = append(secretList, &commit)
	innerBases := newBaseMerge(baseList...)
	innerSecrets := newSecretMerge(secretList...)

	// bits
	for i, _ := range commit.expBitPederson {
		list = commit.expBitPederson[i].generateCommitments(list)
	}
	for i, _ := range s.expBitRep {
		curOff := len(list)
		list = append(list, make([]*big.Int, s.expBitRep[i].numCommitments())...)
		ic := i
		todo = append(todo, func(list []*big.Int) {
			loc := s.expBitRep[ic].generateCommitmentsFromSecrets(g, []*big.Int{}, &innerBases, &innerSecrets)
			for _, v := range loc {
				list[curOff] = v
				curOff++
			}
		})
	}
	list = s.expBitEq.generateCommitmentsFromSecrets(g, list, &innerBases, &innerSecrets)

	//base
	for i, _ := range commit.basePowPederson {
		list = commit.basePowPederson[i].generateCommitments(list)
	}
	for i, _ := range s.basePowRep {
		curOff := len(list)
		list = append(list, make([]*big.Int, s.expBitRep[i].numCommitments())...)
		ic := i
		todo = append(todo, func(list []*big.Int) {
			loc := s.basePowRep[ic].generateCommitmentsFromSecrets(g, []*big.Int{}, &innerBases, &innerSecrets)
			for _, v := range loc {
				list[curOff] = v
				curOff++
			}
		})
	}
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
	list = commit.startPederson.generateCommitments(list)
	list = s.startRep.generateCommitmentsFromSecrets(g, list, &innerBases, &innerSecrets)

	// interres
	for i, _ := range commit.interResPederson {
		list = commit.interResPederson[i].generateCommitments(list)
	}
	for i, _ := range s.interResRep {
		curOff := len(list)
		list = append(list, make([]*big.Int, s.interResRep[i].numCommitments())...)
		ic := i
		todo = append(todo, func(list []*big.Int) {
			loc := s.interResRep[ic].generateCommitmentsFromSecrets(g, []*big.Int{}, &innerBases, &innerSecrets)
			for _, v := range loc {
				list[curOff] = v
				curOff++
			}
		})
	}
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
	for i, _ := range commit.expBitPederson {
		secretList = append(secretList, &commit.expBitPederson[i])
	}
	for i, _ := range commit.basePowPederson {
		secretList = append(secretList, &commit.basePowPederson[i])
	}
	secretList = append(secretList, &commit.startPederson)
	for i, _ := range commit.interResPederson {
		secretList = append(secretList, &commit.interResPederson[i])
	}
	secretList = append(secretList, secretdata)
	secretList = append(secretList, &commit)
	innerSecrets := newSecretMerge(secretList...)

	//bit proofs
	proof.ExpBitProofs = []PedersonProof{}
	for _, expbit := range commit.expBitPederson {
		proof.ExpBitProofs = append(proof.ExpBitProofs, expbit.buildProof(g, challenge))
	}

	//base proofs
	proof.BasePowProofs = []PedersonProof{}
	for _, basePow := range commit.basePowPederson {
		proof.BasePowProofs = append(proof.BasePowProofs, basePow.buildProof(g, challenge))
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
	proof.StartProof = commit.startPederson.buildProof(g, challenge)

	// interres proofs
	proof.InterResProofs = []PedersonProof{}
	for i, _ := range commit.interResPederson {
		proof.InterResProofs = append(proof.InterResProofs, commit.interResPederson[i].buildProof(g, challenge))
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
	proof.ExpBitEqResult = new(big.Int).Mod(
		new(big.Int).Sub(
			commit.expBitEqHiderRandomizer,
			new(big.Int).Mul(
				challenge,
				commit.expBitEqHider)),
		g.order)

	return proof
}

func (s *expProofStructure) fakeProof(g group, challenge *big.Int) ExpProof {
	var proof ExpProof

	proof.ExpBitEqResult = common.FastRandomBigInt(g.order)
	proof.ExpBitProofs = []PedersonProof{}
	for i := uint(0); i < s.bitlen; i++ {
		proof.ExpBitProofs = append(proof.ExpBitProofs, newPedersonFakeProof(g))
	}

	proof.BasePowProofs = []PedersonProof{}
	proof.BasePowRangeProofs = []RangeProof{}
	proof.BasePowRelProofs = []MultiplicationProof{}
	for i, _ := range s.basePowRep {
		proof.BasePowProofs = append(proof.BasePowProofs, newPedersonFakeProof(g))
		proof.BasePowRangeProofs = append(proof.BasePowRangeProofs, s.basePowRange[i].fakeProof(g))
		proof.BasePowRelProofs = append(proof.BasePowRelProofs, s.basePowRels[i].fakeProof(g))
	}

	proof.StartProof = newPedersonFakeProof(g)

	proof.InterResProofs = []PedersonProof{}
	proof.InterResRangeProofs = []RangeProof{}

	for i, _ := range s.interResRep {
		proof.InterResProofs = append(proof.InterResProofs, newPedersonFakeProof(g))
		proof.InterResRangeProofs = append(proof.InterResRangeProofs, s.interResRange[i].fakeProof(g))
	}

	proof.InterStepsProofs = []ExpStepProof{}
	for i, _ := range s.interSteps {
		proof.InterStepsProofs = append(proof.InterStepsProofs, s.interSteps[i].fakeProof(g, challenge))
	}

	return proof
}

func (s *expProofStructure) verifyProofStructure(challenge *big.Int, proof ExpProof) bool {
	// check bit proofs
	if proof.ExpBitEqResult == nil || len(proof.ExpBitProofs) != int(s.bitlen) {
		return false
	}
	for i, _ := range proof.ExpBitProofs {
		if !proof.ExpBitProofs[i].verifyStructure() {
			return false
		}
	}

	// check base proofs
	if len(proof.BasePowProofs) != int(s.bitlen) || len(proof.BasePowRangeProofs) != int(s.bitlen) || len(proof.BasePowRelProofs) != int(s.bitlen) {
		return false
	}
	for i, _ := range proof.BasePowProofs {
		if !proof.BasePowProofs[i].verifyStructure() ||
			!s.basePowRange[i].verifyProofStructure(proof.BasePowRangeProofs[i]) ||
			!s.basePowRels[i].verifyProofStructure(proof.BasePowRelProofs[i]) {
			return false
		}
	}

	// check start proof
	if !proof.StartProof.verifyStructure() {
		return false
	}

	// check inter res
	if len(proof.InterResProofs) != int(s.bitlen-1) || len(proof.InterResRangeProofs) != int(s.bitlen-1) {
		return false
	}
	for i, _ := range proof.InterResProofs {
		if !proof.InterResProofs[i].verifyStructure() ||
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
	proof.nameBitEqHider = strings.Join([]string{s.myname, "biteqhider"}, "_")
	proofList = append(proofList, &proof)
	innerBases := newBaseMerge(baseList...)
	innerProof := newProofMerge(proofList...)

	// Generate commitment list
	var todo []func([]*big.Int)
	todoOffset := new(uint32)

	// bit
	for i, _ := range proof.ExpBitProofs {
		list = proof.ExpBitProofs[i].generateCommitments(list)
	}
	for i, _ := range s.expBitRep {
		curOff := len(list)
		list = append(list, make([]*big.Int, s.expBitRep[i].numCommitments())...)
		ic := i
		todo = append(todo, func(list []*big.Int) {
			loc := s.expBitRep[ic].generateCommitmentsFromProof(g, []*big.Int{}, challenge, &innerBases, &innerProof)
			for _, v := range loc {
				list[curOff] = v
				curOff++
			}
		})
	}
	list = s.expBitEq.generateCommitmentsFromProof(g, list, challenge, &innerBases, &innerProof)

	//base
	for i, _ := range proof.BasePowProofs {
		list = proof.BasePowProofs[i].generateCommitments(list)
	}
	for i, _ := range s.basePowRep {
		curOff := len(list)
		list = append(list, make([]*big.Int, s.basePowRep[i].numCommitments())...)
		ic := i
		todo = append(todo, func(list []*big.Int) {
			loc := s.basePowRep[ic].generateCommitmentsFromProof(g, []*big.Int{}, challenge, &innerBases, &innerProof)
			for _, v := range loc {
				list[curOff] = v
				curOff++
			}
		})
	}
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
	list = proof.StartProof.generateCommitments(list)
	list = s.startRep.generateCommitmentsFromProof(g, list, challenge, &innerBases, &innerProof)

	// interres
	for i, _ := range proof.InterResProofs {
		list = proof.InterResProofs[i].generateCommitments(list)
	}
	for i, _ := range s.interResRep {
		curOff := len(list)
		list = append(list, make([]*big.Int, s.interResRep[i].numCommitments())...)
		ic := i
		todo = append(todo, func(list []*big.Int) {
			loc := s.interResRep[ic].generateCommitmentsFromProof(g, []*big.Int{}, challenge, &innerBases, &innerProof)
			for _, v := range loc {
				list[curOff] = v
				curOff++
			}
		})
	}
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
