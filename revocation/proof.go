package revocation

import (
	"crypto/rand"
	"time"

	"github.com/go-errors/errors"
	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/gabikeys"
	"github.com/privacybydesign/gabi/internal/common"
	"github.com/privacybydesign/gabi/keyproof"
	"github.com/privacybydesign/gabi/prooftools"
)

/*
This implements the zero knowledge proof of the RSA-B accumulator for revocation, introduced in
"Dynamic Accumulators and Application to Efficient Revocation of Anonymous Credentials",
Jan Camenisch and Anna Lysyanskaya, CRYPTO 2002, DOI https://doi.org/10.1007/3-540-45708-9_5,
http://static.cs.brown.edu/people/alysyans/papers/camlys02.pdf. This accumulator is only updated
when revoking and does not change when adding new revocation handles to the accumulator.

The user proves knowledge of two numbers u and e, called the witness, which are such that the relation
    u^e = 𝛎 mod n
holds, where 𝛎 (greek letter "nu") is the accumulator (the issuer's current "non-revocation publickey").
Both u and e are kept secret to the user. Elsewhere the number e is included as an attribute in an
IRMA credential, and this zero-knowledge proof convinces the verifier that the containing credential
is not revoked.

This is an implementation of the zero-knowledge proof at page 8 and 15 of the pdf linked to above,
with the following differences.
1. In the zero knowledge proof conjunction on page 8 of the pdf, we skip the first, second and
   third items in the conjunction: these only serve to prove that the secret e is committed to
   in an element of a known prime order group. We don't need to do this as we have no such group:
   in our case everything happens within QR_n.
2. The fifth relation C_e = g^e * h^r1 is replaced by the Idemix relation
   Z = A^epsilon * S^v * Ri^mi * Re^e which is already proved elsewhere by the calling code.
3. The interval [A, B] from which the witness e is chosen does not satisfy the relation
   B*2^(k'+k''+1) < A^2 - 1, which is unnecessary: as long as A > 2, witnesses are unforgeable,
   by a simple extension of the unforgeability proof of Theorem 3. See below.
In the following we follow the lead of the other zero knowledge proofs implemented elsehwere in gabi.
4. Secrets and randomizers within the zero-knowledge proofs are taken positive, instead of from
   symmetric intervals [-A,A].
5. We use addition in the zero-knowledge proof responses: response = randomizer + challenge*secret.
6. We use the Fiat-Shamir heuristic.
7. We include the challenge c in the proof, and then verify by hashing the Schnorr commitments
   reconstructed from the proof, obtaining c' which must then equal c.

We claim, prove, and implement the following:
Let [A, B] be the interval from which the number e from the witness (u,e) is chosen, as in the paper.
Then witnesses are unforgeable as in theorem 3, if A > 2 and B < 2^(l_n-1) where l_n
is the bitsize of the modulus n. In particular, it is not necesary to require A^2 > B
like theorem 3 does.

Proof: let (u')^(x') = u^x where x = x_1*...*x_n, and set d = gcd(x, x'), as in the proof.
Suppose that d is not relatively prime to phi(n) = 4*p'*q'.
Since d is the product of a subset of the primes x_1, ..., x_n and since x_i > 2 for all of these
primes, by the unique factorization theorem there must be a j such that x_j = p' or x_j = q'.
Thus since p = 2p'+1 and q = 2q'+1, the algorithm that for each i checks if 2x_i+1 divides n = pq
will succeed in factoring n.
The remainder of the proof which handles the other case, where d is relatively prime
to phi(n), works as is.
The claim "d = gcd(x,x') => (d = 1 or d = x_j)" in the middle of the proof, which requires
A^2 > B for its proof, is thus not necessary to use in the proof of theorem 3.

Thus for unforgeability the size of e is not relevant. However, e should be chosen from a set so large
that it is overhelmingly unlikely that any one prime e is chosen twice. Combining the prime counting
function with the birthday paradox and simplifying, one finds the following: if N witnesses are chosen
from the set of primes smaller than B, then the collision chance P approximately equals
   P = 1 - e^(-N^2 ln(B)/B).
At n = 10^9 we have P = 1/2^128 if B = 2^195.
*/

type (
	// Proof is a proof that a Witness is valid against the Accumulator from the specified
	// SignedAccumulator.
	Proof struct {
		Cr                *big.Int            `json:"C_r"` // Cr = g^r2 * h^r3      = g^epsilon * h^zeta
		Cu                *big.Int            `json:"C_u"` // Cu = u    * h^r2
		Nu                *big.Int            `json:"-"`   // nu = Cu^e * h^(-e*r2) = Cu^alpha * h^-beta
		Challenge         *big.Int            `json:"-"`
		Responses         map[string]*big.Int `json:"responses"`
		SignedAccumulator *SignedAccumulator  `json:"sacc"`
		acc               *Accumulator        // Extracted from SignedAccumulator during verification
	}

	// ProofCommit contains the commitment state of a nonrevocation Proof.
	ProofCommit struct {
		cu, cr, nu  *big.Int
		secrets     map[string]*big.Int
		randomizers map[string]*big.Int
		g           *gabikeys.PublicKey
		sacc        *SignedAccumulator
	}

	proofStructure struct {
		cr  prooftools.QrRepresentationProofStructure
		nu  prooftools.QrRepresentationProofStructure
		one prooftools.QrRepresentationProofStructure
	}

	// We implement the keyproof interfaces, containing exported methods, without exposing those
	// methods outside the package by implementing them on unexported structs - at the cost of
	// having to cast back and forth between these equivalent types when crossing the API boundary
	proof       Proof
	proofCommit ProofCommit
	accumulator Accumulator
	witness     Witness
)

var (
	ErrorRevoked = errors.New("revoked")

	Parameters = struct {
		AttributeSize    uint     // maximum size in bits for prime e
		ChallengeLength  uint     // k'  = len(SHA256) = 256
		ZkStat           uint     // k'' = 128
		twoZk, bTwoZk, b *big.Int // 2^(k'+k''), B*2^(k'+k''+1), 2^AttributeSize
	}{
		AttributeSize:   195,
		ChallengeLength: 256,
		ZkStat:          128,
	}

	bigOne         = big.NewInt(1)
	secretNames    = []string{"alpha", "beta", "delta", "epsilon", "zeta"}
	proofstructure = proofStructure{
		cr: prooftools.QrRepresentationProofStructure{
			Lhs: []keyproof.LhsContribution{{Base: "cr", Power: bigOne}},
			Rhs: []keyproof.RhsContribution{
				{Base: "G", Secret: "epsilon", Power: 1}, // r2
				{Base: "H", Secret: "zeta", Power: 1},    // r3
			},
		},
		nu: prooftools.QrRepresentationProofStructure{
			Lhs: []keyproof.LhsContribution{{Base: "nu", Power: bigOne}},
			Rhs: []keyproof.RhsContribution{
				{Base: "cu", Secret: "alpha", Power: 1}, // e
				{Base: "H", Secret: "beta", Power: -1},  // e r2
			},
		},
		one: prooftools.QrRepresentationProofStructure{
			Lhs: []keyproof.LhsContribution{{Base: "one", Power: bigOne}},
			Rhs: []keyproof.RhsContribution{
				{Base: "cr", Secret: "alpha", Power: 1}, // e
				{Base: "G", Secret: "beta", Power: -1},  // e r2
				{Base: "H", Secret: "delta", Power: -1}, // e r3
			},
		},
	}
)

func init() {
	// Compute derivative parameters
	Parameters.b = new(big.Int).Lsh(bigOne, Parameters.AttributeSize)
	Parameters.twoZk = new(big.Int).Lsh(bigOne, Parameters.ChallengeLength+Parameters.ZkStat)
	Parameters.bTwoZk = new(big.Int).Mul(Parameters.b, new(big.Int).Mul(Parameters.twoZk, big.NewInt(2)))
}

// API

// NewProofRandomizer returns a bigint suitable for use as the randomizer in a nonrevocation
// zero knowledge proof.
func NewProofRandomizer() *big.Int {
	return common.FastRandomBigInt(new(big.Int).Mul(Parameters.b, Parameters.twoZk))
}

// RandomWitness returns a new random Witness valid against the specified Accumulator.
func RandomWitness(sk *gabikeys.PrivateKey, acc *Accumulator) (*Witness, error) {
	e, err := common.RandomPrimeInRange(rand.Reader, 3, Parameters.AttributeSize)
	if err != nil {
		return nil, err
	}
	return newWitness(sk, acc, e)
}

// NewProofCommit performs the first move in the Schnorr zero-knowledge protocol: committing to randomizers.
func NewProofCommit(key *gabikeys.PublicKey, witn *Witness, randomizer *big.Int) ([]*big.Int, *ProofCommit, error) {
	Logger.Tracef("revocation.NewProofCommit()")
	defer Logger.Tracef("revocation.NewProofCommit() done")
	witn.randomizer = randomizer
	if randomizer == nil {
		witn.randomizer = NewProofRandomizer()
	}
	if !proofstructure.isTrue((*witness)(witn), witn.SignedAccumulator.Accumulator.Nu, key.N) {
		return nil, nil, errors.New("non-revocation relation does not hold")
	}

	bases := keyproof.NewBaseMerge(key, &accumulator{Nu: witn.SignedAccumulator.Accumulator.Nu})
	list, commit := proofstructure.commitmentsFromSecrets(key, []*big.Int{}, &bases, (*witness)(witn))
	commit.sacc = witn.SignedAccumulator
	return list, (*ProofCommit)(&commit), nil
}

// SetExpected sets certain values of the proof to expected values, inferred from the containing proofs,
// before verification.
func (p *Proof) SetExpected(pk *gabikeys.PublicKey, challenge, response *big.Int) error {
	acc, err := p.SignedAccumulator.UnmarshalVerify(pk)
	if err != nil {
		return err
	}
	p.Nu = acc.Nu
	p.Challenge = challenge
	p.Responses["alpha"] = response
	return nil
}

func (p *Proof) ChallengeContributions(key *gabikeys.PublicKey) []*big.Int {
	return proofstructure.commitmentsFromProof(key, []*big.Int{},
		p.Challenge, key, (*proof)(p), (*proof)(p))
}

func (p *Proof) VerifyWithChallenge(pk *gabikeys.PublicKey, reconstructedChallenge *big.Int) bool {
	if !proofstructure.verifyProofStructure((*proof)(p)) {
		return false
	}
	if (*proof)(p).ProofResult("alpha").Cmp(Parameters.bTwoZk) > 0 {
		return false
	}
	acc, err := p.SignedAccumulator.UnmarshalVerify(pk)
	if err != nil {
		return false
	}
	p.acc = acc
	if p.Nu.Cmp(p.acc.Nu) != 0 {
		return false
	}
	return p.Challenge.Cmp(reconstructedChallenge) == 0
}

func (c *ProofCommit) BuildProof(challenge *big.Int) *Proof {
	Logger.Tracef("revocation.ProofCommit.BuildProof()")
	defer Logger.Tracef("revocation.ProofCommit.BuildProof() done")
	responses := make(map[string]*big.Int, 5)
	for _, name := range secretNames {
		responses[name] = new(big.Int).Add(
			(*proofCommit)(c).Randomizer(name),
			new(big.Int).Mul(
				challenge,
				(*proofCommit)(c).Secret(name)),
		)
	}

	return &Proof{
		Cr: c.cr, Cu: c.cu, Nu: c.nu,
		Challenge:         challenge,
		Responses:         responses,
		SignedAccumulator: c.sacc,
	}
}

func (c *ProofCommit) Update(commitments []*big.Int, witness *Witness) {
	Logger.Tracef("revocation.ProofCommit.Update()")
	defer Logger.Tracef("revocation.ProofCommit.Update() done")
	c.cu = new(big.Int).Exp(c.g.H, c.secrets["epsilon"], c.g.N)
	c.cu.Mul(c.cu, witness.U)
	c.nu = witness.SignedAccumulator.Accumulator.Nu
	c.sacc = witness.SignedAccumulator

	commit := (*proofCommit)(c)
	b := keyproof.NewBaseMerge(c.g, commit)
	l := proofstructure.nu.CommitmentsFromSecrets(c.g, []*big.Int{}, &b, commit)

	commitments[1] = c.cu
	commitments[2] = witness.SignedAccumulator.Accumulator.Nu
	commitments[4] = l[0]
}

// Update updates the witness using the specified update data from the issuer,
// after which the witness can be used to prove nonrevocation against the latest Accumulator
// (contained in the update message).
func (w *Witness) Update(pk *gabikeys.PublicKey, update *Update) error {
	Logger.Tracef("revocation.Witness.Update()")
	defer Logger.Tracef("revocation.Witness.Update() done")

	newAcc, err := update.Verify(pk)
	ourAcc := w.SignedAccumulator.Accumulator
	if err != nil {
		return err
	}
	if newAcc.Index == ourAcc.Index {
		if newAcc.Time <= ourAcc.Time {
			return nil
		}
		*w.SignedAccumulator = *update.SignedAccumulator
		w.Updated = time.Unix(newAcc.Time, 0)
		return nil
	}

	if len(update.Events) == 0 {
		return nil
	}
	startIndex, endIndex := update.Events[0].Index, newAcc.Index
	if endIndex <= ourAcc.Index {
		return nil
	}
	if startIndex > ourAcc.Index+1 {
		return errors.New("update too new")
	}

	var a, b big.Int
	if new(big.Int).GCD(&a, &b, w.E, update.Product(ourAcc.Index+1)).Cmp(bigOne) != 0 {
		return ErrorRevoked
	}

	// u' = u^b * newNu^a mod n
	newU := new(big.Int)
	newU.Mul(
		new(big.Int).Exp(w.U, &b, pk.N),
		new(big.Int).Exp(newAcc.Nu, &a, pk.N),
	).Mod(newU, pk.N)

	if !verify(newU, w.E, newAcc, pk) {
		return errors.New("nonrevocation witness invalidated by update")
	}

	// Update witness state only now after all possible errors have not occured
	w.U = newU
	w.SignedAccumulator = update.SignedAccumulator
	w.Updated = time.Unix(newAcc.Time, 0)

	return nil
}

// Verify the witness against its SignedAccumulator.
func (w *Witness) Verify(pk *gabikeys.PublicKey) error {
	_, err := w.SignedAccumulator.UnmarshalVerify(pk)
	if err != nil {
		return err
	}
	if !verify(w.U, w.E, w.SignedAccumulator.Accumulator, pk) {
		return errors.New("invalid witness")
	}
	return nil
}

// Zero-knowledge proof methods

func (c *proofCommit) Exp(ret *big.Int, name string, exp, n *big.Int) bool {
	ret.Exp(c.Base(name), exp, n)
	return true
}

func (c *proofCommit) Base(name string) *big.Int {
	switch name {
	case "cu":
		return c.cu
	case "cr":
		return c.cr
	case "nu":
		return c.nu
	case "one":
		return big.NewInt(1)
	default:
		return nil
	}
}

func (c *proofCommit) Names() []string {
	return []string{"cu", "cr", "nu", "one"}
}

func (c *proofCommit) Secret(name string) *big.Int {
	return c.secrets[name]
}

func (c *proofCommit) Randomizer(name string) *big.Int {
	return c.randomizers[name]
}

func (p *proof) ProofResult(name string) *big.Int {
	return p.Responses[name]
}

func (p *proof) verify(pk *gabikeys.PublicKey) bool {
	commitments := proofstructure.commitmentsFromProof(pk, []*big.Int{}, p.Challenge, pk, p, p)
	return (*Proof)(p).VerifyWithChallenge(pk, common.HashCommit(commitments, false))
}

func (s *proofStructure) commitmentsFromSecrets(g *gabikeys.PublicKey, list []*big.Int, bases keyproof.BaseLookup, secretdata keyproof.SecretLookup) ([]*big.Int, proofCommit) {
	commit := proofCommit{
		g:           g,
		secrets:     make(map[string]*big.Int, 5),
		randomizers: make(map[string]*big.Int, 5),
		cu:          new(big.Int),
		cr:          new(big.Int),
		nu:          bases.Base("nu"),
	}

	nDiv4 := new(big.Int).Div(g.N, big.NewInt(4))
	nDiv4twoZk := new(big.Int).Mul(nDiv4, Parameters.twoZk)
	nbDiv4twoZk := new(big.Int).Mul(nDiv4twoZk, Parameters.b)

	r2 := common.FastRandomBigInt(nDiv4)
	r3 := common.FastRandomBigInt(nDiv4)

	alpha := secretdata.Secret("alpha")
	commit.secrets["alpha"] = alpha
	commit.secrets["beta"] = new(big.Int).Mul(alpha, r2)
	commit.secrets["delta"] = new(big.Int).Mul(alpha, r3)
	commit.secrets["epsilon"] = r2
	commit.secrets["zeta"] = r3

	commit.randomizers["alpha"] = secretdata.Randomizer("alpha")
	commit.randomizers["beta"] = common.FastRandomBigInt(nbDiv4twoZk)
	commit.randomizers["delta"] = common.FastRandomBigInt(nbDiv4twoZk)
	commit.randomizers["epsilon"] = common.FastRandomBigInt(nDiv4twoZk)
	commit.randomizers["zeta"] = common.FastRandomBigInt(nDiv4twoZk)

	var tmp big.Int

	// Set C_r = g^r2 * h^r3
	bases.Exp(commit.cr, "G", r2, g.N)
	bases.Exp(&tmp, "H", r3, g.N)
	commit.cr.Mul(commit.cr, &tmp).Mod(commit.cr, g.N)
	// Set C_u = u * h^r2
	bases.Exp(&tmp, "H", r2, g.N)
	commit.cu.Mul(secretdata.Secret("u"), &tmp).Mod(commit.cu, g.N)

	list = append(list, commit.cr, commit.cu, commit.nu)

	b := keyproof.NewBaseMerge(bases, &commit)
	list = s.cr.CommitmentsFromSecrets(g, list, &b, &commit)
	list = s.nu.CommitmentsFromSecrets(g, list, &b, &commit)
	list = s.one.CommitmentsFromSecrets(g, list, &b, &commit)

	return list, commit
}

func (s *proofStructure) commitmentsFromProof(g *gabikeys.PublicKey, list []*big.Int, challenge *big.Int, bases keyproof.BaseLookup, proofdata keyproof.ProofLookup, proof *proof) []*big.Int {
	proofs := keyproof.NewProofMerge(proof, proofdata)

	b := keyproof.NewBaseMerge(g, &proofCommit{cr: proof.Cr, cu: proof.Cu, nu: proof.Nu})

	list = append(list, proof.Cr, proof.Cu, proof.Nu)
	list = s.cr.CommitmentsFromProof(g, list, challenge, &b, &proofs)
	list = s.nu.CommitmentsFromProof(g, list, challenge, &b, &proofs)
	list = s.one.CommitmentsFromProof(g, list, challenge, &b, &proofs)

	return list
}

func (s *proofStructure) verifyProofStructure(p *proof) bool {
	for _, name := range secretNames {
		if p.Responses[name] == nil {
			return false
		}
	}
	return p.Cr != nil && p.Cu != nil && p.Nu != nil && p.Challenge != nil
}

func (s *proofStructure) isTrue(secretdata keyproof.SecretLookup, nu, n *big.Int) bool {
	return new(big.Int).
		Exp(secretdata.Secret("u"), secretdata.Secret("alpha"), n).
		Cmp(nu) == 0
}

func (b accumulator) Base(name string) *big.Int {
	if name == "nu" {
		return b.Nu
	}
	return nil
}

func (b accumulator) Exp(ret *big.Int, name string, exp, n *big.Int) bool {
	if name == "nu" {
		ret.Exp(b.Nu, exp, n)
		return true
	}
	return false
}

func (b accumulator) Names() []string {
	return []string{"nu"}
}

func (w *witness) Secret(name string) *big.Int {
	switch name {
	case "alpha":
		return w.E
	case "u":
		return w.U
	}

	return nil
}

func (w *witness) Randomizer(name string) *big.Int {
	if name == "alpha" {
		return w.randomizer
	}
	return nil
}

// Helpers

func verify(u, e *big.Int, acc *Accumulator, grp *gabikeys.PublicKey) bool {
	return new(big.Int).Exp(u, e, grp.N).Cmp(acc.Nu) == 0
}

func newWitness(sk *gabikeys.PrivateKey, acc *Accumulator, e *big.Int) (*Witness, error) {
	eInverse, ok := common.ModInverse(e, sk.Order)
	if !ok {
		return nil, errors.New("failed to compute modular inverse")
	}
	u := new(big.Int).Exp(acc.Nu, eInverse, sk.N)
	return &Witness{U: u, E: e}, nil
}
