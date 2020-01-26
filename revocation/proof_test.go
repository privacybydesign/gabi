package revocation

import (
	"testing"

	"github.com/privacybydesign/gabi/keyproof"
	"github.com/privacybydesign/gabi/signed"
	"github.com/stretchr/testify/require"

	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/internal/common"
	"github.com/privacybydesign/gabi/safeprime"
)

func generateGroup() (qrGroup, *big.Int, *big.Int, error) {
	p, err := safeprime.Generate(32, nil)
	if err != nil {
		return qrGroup{}, nil, nil, err
	}
	q, err := safeprime.Generate(32, nil)
	if err != nil {
		return qrGroup{}, nil, nil, err
	}
	n := new(big.Int).Mul(p, q)

	p.Rsh(p, 1)
	q.Rsh(q, 1)

	g := NewQrGroup(n)
	g.G = common.RandomQR(g.N)
	g.H = common.RandomQR(g.N)

	return qrGroup(g), p, q, nil
}

func TestToyNonRevocationProof(t *testing.T) {
	g, p, q, err := generateGroup()
	require.NoError(t, err, "failed to generate group")

	require.True(t, test(t, g, p, q, true))
}

func TestNonRevocationProof(t *testing.T) {
	p, ok := new(big.Int).SetString("137638811993558195206420328357073658091105450134788808980204514105755078006531089565424872264423706112211603473814961517434905870865504591672559685691792489986134468104546337570949069664216234978690144943134866212103184925841701142837749906961652202656280177667215409099503103170243548357516953064641207916007", 10)
	require.True(t, ok, "failed to parse p")
	q, ok := new(big.Int).SetString("161568850263671082708797642691138038443080533253276097248590507678645648170870472664501153166861026407778587004276645109302937591955229881186233151561419055453812743980662387119394543989953096207398047305729607795030698835363986813674377580220752360344952636913024495263497458333887018979316817606614095137583", 10)
	require.True(t, ok, "failed to parse q")

	g := NewQrGroup(new(big.Int).Mul(p, q))
	g.G = common.RandomQR(g.N)
	g.H = common.RandomQR(g.N)

	p.Rsh(p, 1)
	q.Rsh(q, 1)

	require.True(t, test(t, qrGroup(g), p, q, true))
	require.False(t, test(t, qrGroup(g), p, q, false))
}

func test(t *testing.T, grp qrGroup, p, q *big.Int, valid bool) bool {
	privECDSAKey, err := signed.GenerateKey()
	privKey := PrivateKey{P: p, Q: q, N: grp.N, ECDSA: privECDSAKey}
	require.NoError(t, err)

	acc := &Accumulator{Nu: common.RandomQR(grp.N)}

	witn, err := RandomWitness(&privKey, acc)
	require.NoError(t, err)
	require.NoError(t, err, "failed to generate non-revocation witness")
	if !valid {
		witn.U = common.RandomQR(grp.N)
	}

	witn.randomizer = NewProofRandomizer()
	bases := keyproof.NewBaseMerge(&grp, (*accumulator)(acc))
	require.Equal(t, valid, proofstructure.isTrue((*witness)(witn), acc.Nu, grp.N), "statement to prove ")

	list, commit := proofstructure.generateCommitmentsFromSecrets(&grp, []*big.Int{}, &bases, (*witness)(witn))
	challenge := common.HashCommit(list, false)
	sacc, err := acc.Sign(&privKey)
	require.NoError(t, err)
	prf := (*ProofCommit)(&commit).BuildProof(challenge)
	prf.SignedAccumulator = sacc

	return (*proof)(prf).verify(&PublicKey{Group: (*QrGroup)(&grp), Counter: privKey.Counter, ECDSA: &privECDSAKey.PublicKey})
}
