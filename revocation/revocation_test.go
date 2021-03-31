package revocation

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/internal/common"
	"github.com/privacybydesign/gabi/keyproof"
	"github.com/privacybydesign/gabi/keys"
	"github.com/privacybydesign/gabi/prooftools"
	"github.com/privacybydesign/gabi/safeprime"
	"github.com/privacybydesign/gabi/signed"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func init() {
	Logger = logrus.StandardLogger()
	Logger.SetLevel(logrus.FatalLevel)
}

func generateKeys(t *testing.T) (*PrivateKey, *PublicKey) {
	N, p, q, err := generateGroup()
	require.NoError(t, err)
	ecdsa, err := signed.GenerateKey()
	require.NoError(t, err)

	sk := &PrivateKey{
		Counter: 0,
		ECDSA:   ecdsa,
		P:       p,
		Q:       q,
		N:       N,
	}
	pk := &PublicKey{
		Counter: 0,
		ECDSA:   &ecdsa.PublicKey,
		Group: &keys.PublicKey{
			N: N,
			G: common.RandomQR(N),
			H: common.RandomQR(N),
		},
	}

	return sk, pk
}

func generateGroup() (*big.Int, *big.Int, *big.Int, error) {
	p, err := safeprime.Generate(32, nil)
	if err != nil {
		return nil, nil, nil, err
	}
	q, err := safeprime.Generate(32, nil)
	if err != nil {
		return nil, nil, nil, err
	}
	n := new(big.Int).Mul(p, q)

	p.Rsh(p, 1)
	q.Rsh(q, 1)

	return n, p, q, nil
}

func TestToyNonRevocationProof(t *testing.T) {
	sk, pk := generateKeys(t)

	require.True(t, testProof(t, pk, sk, true))
}

func TestNonRevocationProof(t *testing.T) {
	p, ok := new(big.Int).SetString("137638811993558195206420328357073658091105450134788808980204514105755078006531089565424872264423706112211603473814961517434905870865504591672559685691792489986134468104546337570949069664216234978690144943134866212103184925841701142837749906961652202656280177667215409099503103170243548357516953064641207916007", 10)
	require.True(t, ok, "failed to parse p")
	q, ok := new(big.Int).SetString("161568850263671082708797642691138038443080533253276097248590507678645648170870472664501153166861026407778587004276645109302937591955229881186233151561419055453812743980662387119394543989953096207398047305729607795030698835363986813674377580220752360344952636913024495263497458333887018979316817606614095137583", 10)
	require.True(t, ok, "failed to parse q")
	N := new(big.Int).Mul(p, q)

	p.Rsh(p, 1)
	q.Rsh(q, 1)
	ecdsa, err := signed.GenerateKey()
	require.NoError(t, err)

	sk := &PrivateKey{
		Counter: 0,
		ECDSA:   ecdsa,
		P:       p,
		Q:       q,
		N:       N,
	}
	pk := &PublicKey{
		Counter: 0,
		ECDSA:   &ecdsa.PublicKey,
		Group: &keys.PublicKey{
			N: N,
			G: common.RandomQR(N),
			H: common.RandomQR(N),
		},
	}

	require.True(t, testProof(t, pk, sk, true))
	require.False(t, testProof(t, pk, sk, false))
}

func testProof(t *testing.T, pk *PublicKey, sk *PrivateKey, valid bool) bool {

	acc := &Accumulator{Nu: common.RandomQR(sk.N)}

	witn, err := RandomWitness(sk, acc)
	require.NoError(t, err)
	require.NoError(t, err, "failed to generate non-revocation witness")
	if !valid {
		witn.U = common.RandomQR(sk.N)
	}

	witn.randomizer = NewProofRandomizer()
	bases := keyproof.NewBaseMerge((*prooftools.PublicKeyGroup)(pk.Group), (*accumulator)(acc))
	require.Equal(t, valid, proofstructure.isTrue((*witness)(witn), acc.Nu, sk.N), "statement to prove ")

	list, commit := proofstructure.commitmentsFromSecrets((*prooftools.PublicKeyGroup)(pk.Group), []*big.Int{}, &bases, (*witness)(witn))
	challenge := common.HashCommit(list, false)
	sacc, err := acc.Sign(sk)
	require.NoError(t, err)
	prf := (*ProofCommit)(&commit).BuildProof(challenge)
	prf.SignedAccumulator = sacc

	return (*proof)(prf).verify(pk)
}

func TestNewAccumulator(t *testing.T) {
	sk, pk := generateKeys(t)

	update, err := NewAccumulator(sk)
	require.NoError(t, err)
	_, err = update.Verify(pk)
	require.NoError(t, err)
	require.Equal(t, 0, update.Events[0].E.Cmp(big.NewInt(1)))

	require.Len(t, update.Events, 1)
	initialhash := make([]byte, 32, 32) // construct initial SHA256 multihash
	initialhash = append([]byte{18, 32}, initialhash...)
	require.Equal(t, initialhash, []byte(update.Events[0].ParentHash))
}

func TestAccumulatorRemove(t *testing.T) {
	sk, pk := generateKeys(t)

	update, err := NewAccumulator(sk)
	require.NoError(t, err)
	_, err = update.Verify(pk)
	require.NoError(t, err)
	acc := update.SignedAccumulator.Accumulator
	require.NotNil(t, acc)

	e, err := common.RandomPrimeInRange(rand.Reader, 3, Parameters.AttributeSize)
	require.NoError(t, err)
	parentevent := update.Events[len(update.Events)-1]
	newAcc, event, err := acc.Remove(sk, e, parentevent)
	require.NoError(t, err)

	require.Equal(t, parentevent.hash(), event.ParentHash)
	require.Equal(t, parentevent.Index+1, event.Index)
	require.Equal(t, 0, event.E.Cmp(e))
	require.Equal(t, 0, new(big.Int).Exp(newAcc.Nu, e, pk.Group.N).Cmp(acc.Nu))
}

func revoke(t *testing.T, acc *Accumulator, parent *Event, sk *PrivateKey) (*Accumulator, *Event) {
	e, err := common.RandomPrimeInRange(rand.Reader, 3, Parameters.AttributeSize)
	require.NoError(t, err)
	acc, event, err := acc.Remove(sk, e, parent)
	require.NoError(t, err)
	return acc, event
}

func generateUpdate(t *testing.T) (*Update, *PublicKey, *PrivateKey, *Accumulator) {
	sk, pk := generateKeys(t)

	update, err := NewAccumulator(sk)
	require.NoError(t, err)
	_, err = update.Verify(pk)
	require.NoError(t, err)
	acc := update.SignedAccumulator.Accumulator
	require.NotNil(t, acc)

	event := update.Events[0]
	events := update.Events
	for i := 0; i < 3; i++ {
		acc, event = revoke(t, acc, event, sk)
		events = append(events, event)
	}

	update, err = NewUpdate(sk, acc, events)
	require.NoError(t, err)
	_, err = update.Verify(pk)
	require.NoError(t, err)

	return update, pk, sk, acc
}

func TestWitnessUpdate(t *testing.T) {
	update, pk, sk, acc := generateUpdate(t)
	witness, err := RandomWitness(sk, acc)
	require.NoError(t, err)
	witness.SignedAccumulator = update.SignedAccumulator // normally done by irmaclient after issuance

	// save a copy for below
	firstupdate := *update

	// updating against an update message of the same index does nothing
	i := witness.SignedAccumulator.Accumulator.Index
	require.NoError(t, witness.Update(pk, update))
	require.NoError(t, witness.Verify(pk))
	require.Equal(t, i, witness.SignedAccumulator.Accumulator.Index)

	// updating against an update with one new Event works
	events := update.Events
	acc, event := revoke(t, acc, update.Events[len(update.Events)-1], sk)
	events = append(events, event)
	update, err = NewUpdate(sk, acc, events)
	require.NoError(t, err)
	require.NoError(t, witness.Update(pk, update))
	require.NoError(t, witness.Verify(pk))

	// updating against a too new update is an error
	for i := 0; i < 3; i++ {
		acc, event = revoke(t, acc, event, sk)
		events = append(events, event)
	}
	update, err = NewUpdate(sk, acc, events)
	require.NoError(t, err)
	update.Events = update.Events[len(update.Events)-2:] // throw away first few events
	require.Error(t, witness.Update(pk, update))

	// updating against old updates does nothing
	firstupdate.SignedAccumulator.Accumulator = nil
	acc, err = firstupdate.SignedAccumulator.UnmarshalVerify(pk)
	i = witness.SignedAccumulator.Accumulator.Index
	require.NoError(t, witness.Update(pk, &firstupdate))
	require.NoError(t, witness.Verify(pk))
	require.Equal(t, i, witness.SignedAccumulator.Accumulator.Index)

	// updating against an update with no events of the same index increases witness's accumulator time
	newacc := *witness.SignedAccumulator.Accumulator
	newacc.Time = time.Now().Unix()
	update, err = NewUpdate(sk, &newacc, nil)
	require.NoError(t, err)
	i = witness.SignedAccumulator.Accumulator.Index
	require.NoError(t, witness.Update(pk, update))
	require.Equal(t, i, witness.SignedAccumulator.Accumulator.Index)
	require.Equal(t, newacc.Time, witness.SignedAccumulator.Accumulator.Time)
}

func TestUpdateVerification(t *testing.T) {
	t.Run("PartialEventChain", func(t *testing.T) {
		update, pk, _, _ := generateUpdate(t)
		count := len(update.Events)
		for i := 0; i < count; i++ {
			update.Events = update.Events[1:]
			_, err := update.Verify(pk)
			require.NoError(t, err)
		}
	})

	t.Run("InvalidSignature", func(t *testing.T) {
		update, pk, _, _ := generateUpdate(t)
		_, pk = generateKeys(t) // generate new random key to verify against
		update.SignedAccumulator.Accumulator = nil
		_, err := update.Verify(pk)
		require.Error(t, err)
	})

	t.Run("InvalidEvent", func(t *testing.T) {
		update, pk, _, _ := generateUpdate(t)
		update.Events[len(update.Events)-1].E = big.NewInt(42)
		_, err := update.Verify(pk)
		require.Error(t, err)
	})

	t.Run("InvalidHash", func(t *testing.T) {
		update, pk, _, _ := generateUpdate(t)
		for i := 0; i < len(update.Events); i++ {
			update.Events[i].ParentHash[3] = update.Events[i].ParentHash[3] + 1
			_, err := update.Verify(pk)
			require.Error(t, err)
		}
	})

	t.Run("MissingEvent", func(t *testing.T) {
		update, pk, _, _ := generateUpdate(t)
		update.Events = append(update.Events[:1], update.Events[2:]...) // remove event 1
		_, err := update.Verify(pk)
		require.Error(t, err)
	})

	t.Run("SwappedEvent", func(t *testing.T) {
		update, pk, _, _ := generateUpdate(t)
		event := update.Events[1]
		update.Events[1] = update.Events[2]
		update.Events[2] = event
		_, err := update.Verify(pk)
		require.Error(t, err)
	})
}
