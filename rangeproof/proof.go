package rangeproof

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/internal/common"
	"github.com/privacybydesign/gabi/keyproof"
)

type (
	SplitFunction func(delta *big.Int) ([]*big.Int, error)

	ProofStructure struct {
		cRep     []qrRepresentationProofStructure
		mCorrect qrRepresentationProofStructure

		split SplitFunction
		a     int
		k     *big.Int

		ld      uint
		lm      uint
		lh      uint
		lstatzk uint
	}

	Proof struct {
		// Actual proof responses
		C                 []*big.Int `json:"C"`
		DResponse         []*big.Int `json:"d"`
		VResponse         []*big.Int `json:"v"`
		VCombinedResponse *big.Int   `json:"v5"`
		MResponse         *big.Int   `json:"m"`
	}

	ProofCommit struct {
		// Bases
		c []*big.Int

		// Secrets
		d            []*big.Int
		dRandomizer  []*big.Int
		v            []*big.Int
		vRandomizer  []*big.Int
		v5           *big.Int
		v5Randomizer *big.Int
		m            *big.Int
		mRandomizer  *big.Int
	}

	proof       Proof
	proofCommit ProofCommit
	qrGroup     QrGroup
)

// Create a new proof structure for proving a statement of form a*m - k > 0
//  split can be left nil if this structure will only be used for verification
//  2*ld is the maximum number of bits allowed for the difference
//  lh is the size of the challenge
//  lm the size of m, and also used as the number of bits for computational hiding
//  lstatzk the number of bits of statistical hiding to use
func New(split SplitFunction, nSplit, a int, k *big.Int, ld, lh, lstatzk, lm uint) *ProofStructure {
	if nSplit > 4 {
		panic("No support for range proofs with delta split in more than 4 squares")
	}

	result := &ProofStructure{
		mCorrect: qrRepresentationProofStructure{
			Lhs: []keyproof.LhsContribution{
				{Base: "R", Power: new(big.Int).Neg(k)},
			},
			Rhs: []keyproof.RhsContribution{
				{Base: "S", Secret: "v5", Power: -1},
				{Base: "R", Secret: "m", Power: int64(-a)},
			},
		},

		split: split,
		a:     a,
		k:     new(big.Int).Set(k),

		ld:      ld,
		lm:      lm,
		lh:      lh,
		lstatzk: lstatzk,
	}

	for i := 0; i < nSplit; i++ {
		result.cRep = append(result.cRep, qrRepresentationProofStructure{
			Lhs: []keyproof.LhsContribution{
				{Base: fmt.Sprintf("C%d", i), Power: big.NewInt(1)},
			},
			Rhs: []keyproof.RhsContribution{
				{Base: "R", Secret: fmt.Sprintf("d%d", i), Power: 1},
				{Base: "S", Secret: fmt.Sprintf("v%d", i), Power: 1},
			},
		})

		result.mCorrect.Rhs = append(result.mCorrect.Rhs, keyproof.RhsContribution{
			Base:   fmt.Sprintf("C%d", i),
			Secret: fmt.Sprintf("d%d", i),
			Power:  1,
		})
	}

	return result
}

func (s *ProofStructure) CommitmentsFromSecrets(g *QrGroup, m, mRandomizer *big.Int) ([]*big.Int, *ProofCommit, error) {
	var err error

	d := new(big.Int).Mul(m, big.NewInt(int64(s.a)))
	d.Sub(d, s.k)

	if d.Sign() < 0 {
		return nil, nil, errors.New("Requested inequality does not hold")
	}

	commit := &proofCommit{
		m:           m,
		mRandomizer: mRandomizer,
	}

	commit.d, err = s.split(d)
	if err != nil {
		return nil, nil, err
	}
	if len(commit.d) != len(s.cRep) {
		return nil, nil, errors.New("Split function returned wrong number of results")
	}

	// Check d values and generate randomizers for them
	dRandomizerLimit := new(big.Int).Lsh(big.NewInt(1), s.ld+s.lh+s.lstatzk)
	commit.dRandomizer = make([]*big.Int, len(commit.d))
	for i, v := range commit.d {
		if v.BitLen() > int(s.ld) {
			return nil, nil, errors.New("Split function returned oversized d")
		}
		commit.dRandomizer[i] = common.FastRandomBigInt(dRandomizerLimit)
	}

	// Generate v and vRandomizers
	commit.v = make([]*big.Int, len(commit.d))
	commit.vRandomizer = make([]*big.Int, len(commit.d))
	vLimit := new(big.Int).Lsh(big.NewInt(1), s.lm)
	vRandomizerLimit := new(big.Int).Lsh(big.NewInt(1), s.lm+s.lh+s.lstatzk)
	for i := range commit.d {
		commit.v[i] = common.FastRandomBigInt(vLimit)
		commit.vRandomizer[i] = common.FastRandomBigInt(vRandomizerLimit)
	}

	// Generate v5 and its randomizer
	commit.v5 = big.NewInt(0)
	for i := range commit.d {
		contrib := new(big.Int).Mul(commit.d[i], commit.v[i])
		commit.v5.Add(commit.v5, contrib)
	}
	commit.v5Randomizer = common.FastRandomBigInt(new(big.Int).Lsh(big.NewInt(1), s.lm+s.ld+2+s.lh+s.lstatzk))

	// Calculate the bases
	commit.c = make([]*big.Int, len(commit.d))
	for i := range commit.d {
		commit.c[i] = new(big.Int).Exp(g.R, commit.d[i], g.N)
		commit.c[i].Mul(commit.c[i], new(big.Int).Exp(g.S, commit.v[i], g.N))
		commit.c[i].Mod(commit.c[i], g.N)
	}

	bases := keyproof.NewBaseMerge((*qrGroup)(g), commit)

	contributions := []*big.Int{}
	contributions = s.mCorrect.commitmentsFromSecrets((*qrGroup)(g), contributions, &bases, commit)
	for i := range commit.d {
		contributions = s.cRep[i].commitmentsFromSecrets((*qrGroup)(g), contributions, &bases, commit)
	}

	return contributions, (*ProofCommit)(commit), nil
}

func (s *ProofStructure) BuildProof(commit *ProofCommit, challenge *big.Int) *Proof {
	result := &Proof{
		C:                 make([]*big.Int, len(commit.c)),
		DResponse:         make([]*big.Int, len(commit.d)),
		VResponse:         make([]*big.Int, len(commit.v)),
		VCombinedResponse: new(big.Int).Add(new(big.Int).Mul(challenge, commit.v5), commit.v5Randomizer),
		MResponse:         new(big.Int).Add(new(big.Int).Mul(challenge, commit.m), commit.mRandomizer),
	}

	for i := range commit.c {
		result.C[i] = new(big.Int).Set(commit.c[i])
	}
	for i := range commit.d {
		result.DResponse[i] = new(big.Int).Add(new(big.Int).Mul(challenge, commit.d[i]), commit.dRandomizer[i])
	}
	for i := range commit.v {
		result.VResponse[i] = new(big.Int).Add(new(big.Int).Mul(challenge, commit.v[i]), commit.vRandomizer[i])
	}

	return result
}

func (s *ProofStructure) VerifyProofStructure(g *QrGroup, p *Proof) bool {
	if len(s.cRep) != len(p.C) || len(s.cRep) != len(p.DResponse) || len(s.cRep) != len(p.VResponse) {
		return false
	}

	if p.VCombinedResponse == nil || p.MResponse == nil {
		return false
	}

	if uint(p.VCombinedResponse.BitLen()) > s.lm+s.ld+2+s.lh+s.lstatzk+1 ||
		uint(p.MResponse.BitLen()) > s.lm+s.lh+s.lstatzk+1 {
		return false
	}

	for i := range s.cRep {
		if p.C[i] == nil || p.DResponse[i] == nil || p.VResponse[i] == nil {
			return false
		}

		if p.C[i].BitLen() > g.N.BitLen() ||
			uint(p.DResponse[i].BitLen()) > s.ld+s.lh+s.lstatzk+1 ||
			uint(p.VResponse[i].BitLen()) > s.lm+s.lh+s.lstatzk+1 {
			return false
		}
	}

	return true
}

func (s *ProofStructure) CommitmentsFromProof(g *QrGroup, p *Proof, challenge *big.Int) []*big.Int {
	bases := keyproof.NewBaseMerge((*qrGroup)(g), (*proof)(p))

	contributions := []*big.Int{}
	contributions = s.mCorrect.commitmentsFromProof((*qrGroup)(g), contributions, challenge, &bases, (*proof)(p))
	for i := range s.cRep {
		contributions = s.cRep[i].commitmentsFromProof((*qrGroup)(g), contributions, challenge, &bases, (*proof)(p))
	}

	return contributions
}

// ---
// Commit structure keyproof interfaces
// ---
func (c *proofCommit) Secret(name string) *big.Int {
	if name == "m" {
		return c.m
	}
	if name == "v5" {
		return c.v5
	}
	if name[0] == 'v' {
		i, err := strconv.Atoi(name[1:])
		if err != nil || i < 0 || i >= len(c.v) {
			return nil
		}
		return c.v[i]
	}
	if name[0] == 'd' {
		i, err := strconv.Atoi(name[1:])
		if err != nil || i < 0 || i >= len(c.d) {
			return nil
		}
		return c.d[i]
	}
	return nil
}

func (c *proofCommit) Randomizer(name string) *big.Int {
	if name == "m" {
		return c.mRandomizer
	}
	if name == "v5" {
		return c.v5Randomizer
	}
	if name[0] == 'v' {
		i, err := strconv.Atoi(name[1:])
		if err != nil || i < 0 || i >= len(c.vRandomizer) {
			return nil
		}
		return c.vRandomizer[i]
	}
	if name[0] == 'd' {
		i, err := strconv.Atoi(name[1:])
		if err != nil || i < 0 || i >= len(c.dRandomizer) {
			return nil
		}
		return c.dRandomizer[i]
	}
	return nil
}

func (c *proofCommit) Base(name string) *big.Int {
	if name[0] == 'C' {
		i, err := strconv.Atoi(name[1:])
		if err != nil || i < 0 || i >= len(c.c) {
			return nil
		}
		return c.c[i]
	}
	return nil
}

func (c *proofCommit) Exp(ret *big.Int, name string, exp, n *big.Int) bool {
	base := c.Base(name)
	if base == nil {
		return false
	}
	ret.Exp(base, exp, n)
	return true
}

func (c *proofCommit) Names() []string {
	result := make([]string, 0, len(c.c))
	for i := range c.c {
		result = append(result, fmt.Sprintf("C%d", i))
	}

	return result
}

// ---
// Proof structure keyproof interfaces
// ---
func (p *proof) ProofResult(name string) *big.Int {
	if name == "m" {
		return p.MResponse
	}
	if name == "v5" {
		return p.VCombinedResponse
	}
	if name[0] == 'v' {
		i, err := strconv.Atoi(name[1:])
		if err != nil || i < 0 || i >= len(p.VResponse) {
			return nil
		}
		return p.VResponse[i]
	}
	if name[0] == 'd' {
		i, err := strconv.Atoi(name[1:])
		if err != nil || i < 0 || i >= len(p.DResponse) {
			return nil
		}
		return p.DResponse[i]
	}
	return nil
}

func (p *proof) Base(name string) *big.Int {
	if name[0] == 'C' {
		i, err := strconv.Atoi(name[1:])
		if err != nil || i < 0 || i >= len(p.C) {
			return nil
		}
		return p.C[i]
	}
	return nil
}

func (p *proof) Exp(ret *big.Int, name string, exp, n *big.Int) bool {
	base := p.Base(name)
	if base == nil {
		return false
	}
	ret.Exp(base, exp, n)
	return true
}

func (p *proof) Names() []string {
	result := make([]string, 0, len(p.C))
	for i := range p.C {
		result = append(result, fmt.Sprintf("C%d", i))
	}

	return result
}
