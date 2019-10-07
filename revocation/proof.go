package revocation

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"

	"github.com/go-errors/errors"
	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/internal/common"
	"github.com/privacybydesign/gabi/keyproof"
	"github.com/privacybydesign/gabi/signed"
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
3. The bounds A and B between which the witness e is chosen does not satisfy the relation
   B*2^(k'+k''+1) < A^2 - 1, which again would only be relevant in the presence of a known prime
   order group. Instead we take for B the maximum size such that e still fits in an IRMA attribute
   in 1024 parameter settings and A one bit below. This ensures that with overwhelming probability
   no e will be chosen twice.
4. Secrets and randomizers within the zero-knowledge proofs are taken positive, instead of from
   symmetric intervals [-A,A].
5. like the rest of IRMA but unlike the paper, we use addition in the zero-knowledge proof responses:
   response = randomizer + challenge*secret.
6. We use the Fiat-Shamir heuristic.
7. Like in the rest of IRMA but unlike page 15 we include the challenge c in the proof, and then
   verify by hashing the Schnorr commitments reconstructed from the proof, obtaining c' which must
   equal c.
*/

type (
	Proof struct {
		Cr        *big.Int // Cr = g^r2 * h^r3      = g^epsilon * h^zeta
		Cu        *big.Int // Cu = u    * h^r2
		Nu        *big.Int // nu = Cu^e * h^(-e*r2) = Cu^alpha * h^-beta
		Challenge *big.Int
		Results   map[string]*big.Int
		Index     uint64
	}

	ProofCommit struct {
		cu, cr, nu  *big.Int
		secrets     map[string]*big.Int
		randomizers map[string]*big.Int
		g           *qrGroup
		index       uint64
	}

	proofStructure struct {
		cr  qrRepresentationProofStructure
		nu  qrRepresentationProofStructure
		one qrRepresentationProofStructure
	}

	// We implement the keyproof interfaces, containing exported methods, without exposing those
	// methods outside the package by implementing them on unexported structs - at the cost of
	// having to cast back and forth between these equivalent types when crossing the API boundary
	proof       Proof
	proofCommit ProofCommit
	accumulator Accumulator
	witness     Witness
	qrGroup     QrGroup
)

var (
	parameters = struct {
		attributeMinSize    uint     // minimum size in bits for prime e
		attributeMaxSize    uint     // maximum size in bits for prime e
		challengeLength     uint     // k'  = len(SHA256) = 256
		zkStat              uint     // k'' = 128
		twoZk, bTwoZk, a, b *big.Int // 2^(k'+k''), B*2^(k'+k''+1), 2^attributeMinSize, 2^attributeMaxSize
	}{
		attributeMinSize: 207,
		attributeMaxSize: 208,
		challengeLength:  256,
		zkStat:           128,
	}

	bigOne         = big.NewInt(1)
	secretNames    = []string{"alpha", "beta", "delta", "epsilon", "zeta"}
	proofstructure = proofStructure{
		cr: qrRepresentationProofStructure{
			Lhs: []keyproof.LhsContribution{{Base: "cr", Power: bigOne}},
			Rhs: []keyproof.RhsContribution{
				{Base: "g", Secret: "epsilon", Power: 1}, // r2
				{Base: "h", Secret: "zeta", Power: 1},    // r3
			},
		},
		nu: qrRepresentationProofStructure{
			Lhs: []keyproof.LhsContribution{{Base: "nu", Power: bigOne}},
			Rhs: []keyproof.RhsContribution{
				{Base: "cu", Secret: "alpha", Power: 1}, // e
				{Base: "h", Secret: "beta", Power: -1},  // e r2
			},
		},
		one: qrRepresentationProofStructure{
			Lhs: []keyproof.LhsContribution{{Base: "one", Power: bigOne}},
			Rhs: []keyproof.RhsContribution{
				{Base: "cr", Secret: "alpha", Power: 1}, // e
				{Base: "g", Secret: "beta", Power: -1},  // e r2
				{Base: "h", Secret: "delta", Power: -1}, // e r3
			},
		},
	}
)

func init() {
	// Compute derivative parameters
	parameters.twoZk = new(big.Int).Lsh(bigOne, parameters.challengeLength+parameters.zkStat)
	parameters.a = new(big.Int).Lsh(bigOne, parameters.attributeMinSize)
	parameters.b = new(big.Int).Lsh(bigOne, parameters.attributeMaxSize)
	parameters.bTwoZk = new(big.Int).Mul(parameters.b, new(big.Int).Mul(parameters.twoZk, big.NewInt(2)))
}

// API

// NewProofRandomizer returns a bigint suitable for use as the randomizer in a nonrevocation
// zero knowledge proof.
func NewProofRandomizer() *big.Int {
	return common.FastRandomBigInt(new(big.Int).Mul(parameters.b, parameters.twoZk))
}

// RandomWitness returns a new random Witness valid against the specified Accumulator.
func RandomWitness(sk *PrivateKey, acc *Accumulator) (*Witness, error) {
	e, err := common.RandomPrimeInRange(rand.Reader, parameters.attributeMinSize, parameters.attributeMinSize)
	if err != nil {
		return nil, err
	}
	return newWitness(sk, acc, e)
}

// NewProofCommit performs the first move in the Schnorr zero-knowledge protocol: committing to randomizers.
func NewProofCommit(grp *QrGroup, witn *Witness, randomizer *big.Int) ([]*big.Int, *ProofCommit, error) {
	witn.randomizer = randomizer
	if randomizer == nil {
		witn.randomizer = NewProofRandomizer()
	}
	if !proofstructure.isTrue((*witness)(witn), witn.Nu, grp.N) {
		return nil, nil, errors.New("non-revocation relation does not hold")
	}

	bases := keyproof.NewBaseMerge((*qrGroup)(grp), &accumulator{Nu: witn.Nu})
	list, commit := proofstructure.generateCommitmentsFromSecrets((*qrGroup)(grp), []*big.Int{}, &bases, (*witness)(witn))
	commit.index = witn.Index
	return list, (*ProofCommit)(&commit), nil
}

func (p *Proof) ChallengeContributions(grp *QrGroup) []*big.Int {
	return proofstructure.generateCommitmentsFromProof(
		(*qrGroup)(grp), []*big.Int{}, p.Challenge, (*qrGroup)(grp), (*proof)(p), (*proof)(p))
}

func (p *Proof) VerifyWithChallenge(reconstructedChallenge *big.Int) bool {
	if !proofstructure.verifyProofStructure((*proof)(p)) {
		return false
	}
	if (*proof)(p).GetResult("alpha").Cmp(parameters.bTwoZk) > 0 {
		return false
	}
	return p.Challenge.Cmp(reconstructedChallenge) == 0
}

func (c *ProofCommit) BuildProof(challenge *big.Int) *Proof {
	results := make(map[string]*big.Int, 5)
	for _, name := range secretNames {
		results[name] = new(big.Int).Add(
			(*proofCommit)(c).GetRandomizer(name),
			new(big.Int).Mul(
				challenge,
				(*proofCommit)(c).GetSecret(name)),
		)
	}

	return &Proof{
		Cr: c.cr, Cu: c.cu, Nu: c.nu,
		Challenge: challenge,
		Results:   results,
		Index:     c.index,
	}
}

func (c *ProofCommit) Update(commitments []*big.Int, witness *Witness) {
	c.cu = new(big.Int).Exp(c.g.H, c.secrets["epsilon"], c.g.N)
	c.cu.Mul(c.cu, witness.U)
	c.nu = witness.Nu
	c.index = witness.Index

	commit := (*proofCommit)(c)
	b := keyproof.NewBaseMerge(c.g, commit)
	l := proofstructure.nu.generateCommitmentsFromSecrets(c.g, []*big.Int{}, &b, commit)

	commitments[1] = c.cu
	commitments[2] = witness.Nu
	commitments[4] = l[0]
}

// update updates the witness using the specified update message from the issuer,
// after which the witness can be used to prove nonrevocation against the latest Accumulator
// (contained in the update message).
func (w *Witness) Update(pk *PublicKey, message signed.Message) error {
	var err error
	var update AccumulatorUpdate
	if err = signed.UnmarshalVerify(pk.ECDSA, message, &update); err != nil {
		return err
	}

	if update.Accumulator.Index <= w.Index || update.StartIndex > w.Index+1 {
		return nil // update was already applied or is too new
	}

	// compute product of all revoked attributes
	var a, b, prod big.Int
	prod.SetInt64(1)
	for i, e := range update.Revoked {
		if uint64(i)+update.StartIndex <= w.Index {
			continue
		}
		if e == w.E {
			return errors.New("revoked")
		}
		prod.Mul(&prod, e)
	}

	if new(big.Int).GCD(&a, &b, w.E, &prod).Cmp(bigOne) != 0 {
		return errors.New("revoked")
	}

	// u' = u^b * newNu^a mod n
	newU := new(big.Int)
	newU.Mul(
		new(big.Int).Exp(w.U, &b, pk.Group.N),
		new(big.Int).Exp(update.Accumulator.Nu, &a, pk.Group.N),
	).Mod(newU, pk.Group.N)

	if !verify(newU, w.E, &update.Accumulator, pk.Group) {
		return errors.New("nonrevocation witness invalidated by update")
	}

	// Update witness state only now after all possible errors have not occured
	w.U = newU
	w.Nu = update.Accumulator.Nu
	w.Index = update.Accumulator.Index

	return nil
}

// Zero-knowledge proof methods

func (c *proofCommit) Exp(ret *big.Int, name string, exp, n *big.Int) bool {
	ret.Exp(c.GetBase(name), exp, n)
	return true
}

func (c *proofCommit) GetBase(name string) *big.Int {
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

func (c *proofCommit) GetNames() []string {
	return []string{"cu", "cr", "nu", "one"}
}

func (c *proofCommit) GetSecret(name string) *big.Int {
	return c.secrets[name]
}

func (c *proofCommit) GetRandomizer(name string) *big.Int {
	return c.randomizers[name]
}

func (p *proof) GetResult(name string) *big.Int {
	return p.Results[name]
}

func (p *proof) verify(g *qrGroup) bool {
	commitments := proofstructure.generateCommitmentsFromProof(g, []*big.Int{}, p.Challenge, g, p, p)
	return (*Proof)(p).VerifyWithChallenge(common.HashCommit(commitments, false))
}

func (s *proofStructure) generateCommitmentsFromSecrets(g *qrGroup, list []*big.Int, bases keyproof.BaseLookup, secretdata keyproof.SecretLookup) ([]*big.Int, proofCommit) {
	commit := proofCommit{
		g:           g,
		secrets:     make(map[string]*big.Int, 5),
		randomizers: make(map[string]*big.Int, 5),
		cu:          new(big.Int),
		cr:          new(big.Int),
		nu:          bases.GetBase("nu"),
	}

	r2 := common.FastRandomBigInt(g.nDiv4)
	r3 := common.FastRandomBigInt(g.nDiv4)

	alpha := secretdata.GetSecret("alpha")
	commit.secrets["alpha"] = alpha
	commit.secrets["beta"] = new(big.Int).Mul(alpha, r2)
	commit.secrets["delta"] = new(big.Int).Mul(alpha, r3)
	commit.secrets["epsilon"] = r2
	commit.secrets["zeta"] = r3

	commit.randomizers["alpha"] = secretdata.GetRandomizer("alpha")
	commit.randomizers["beta"] = common.FastRandomBigInt(g.nbDiv4twoZk)
	commit.randomizers["delta"] = common.FastRandomBigInt(g.nbDiv4twoZk)
	commit.randomizers["epsilon"] = common.FastRandomBigInt(g.nDiv4twoZk)
	commit.randomizers["zeta"] = common.FastRandomBigInt(g.nDiv4twoZk)

	var tmp big.Int

	// Set C_r = g^r2 * h^r3
	bases.Exp(commit.cr, "g", r2, g.N)
	bases.Exp(&tmp, "h", r3, g.N)
	commit.cr.Mul(commit.cr, &tmp).Mod(commit.cr, g.N)
	// Set C_u = u * h^r2
	bases.Exp(&tmp, "h", r2, g.N)
	commit.cu.Mul(secretdata.GetSecret("u"), &tmp).Mod(commit.cu, g.N)

	list = append(list, commit.cr, commit.cu, commit.nu)

	b := keyproof.NewBaseMerge(bases, &commit)
	list = s.cr.generateCommitmentsFromSecrets(g, list, &b, &commit)
	list = s.nu.generateCommitmentsFromSecrets(g, list, &b, &commit)
	list = s.one.generateCommitmentsFromSecrets(g, list, &b, &commit)

	return list, commit
}

func (s *proofStructure) generateCommitmentsFromProof(g *qrGroup, list []*big.Int, challenge *big.Int, bases keyproof.BaseLookup, proofdata keyproof.ProofLookup, proof *proof) []*big.Int {
	proofs := keyproof.NewProofMerge(proof, proofdata)

	b := keyproof.NewBaseMerge(g, &proofCommit{cr: proof.Cr, cu: proof.Cu, nu: proof.Nu})

	list = append(list, proof.Cr, proof.Cu, proof.Nu)
	list = s.cr.generateCommitmentsFromProof(g, list, challenge, &b, &proofs)
	list = s.nu.generateCommitmentsFromProof(g, list, challenge, &b, &proofs)
	list = s.one.generateCommitmentsFromProof(g, list, challenge, &b, &proofs)

	return list
}

func (s *proofStructure) verifyProofStructure(p *proof) bool {
	for _, name := range secretNames {
		if p.Results[name] == nil {
			return false
		}
	}
	return p.Cr != nil && p.Cu != nil && p.Nu != nil && p.Challenge != nil
}

func (s *proofStructure) isTrue(secretdata keyproof.SecretLookup, nu, n *big.Int) bool {
	return new(big.Int).
		Exp(secretdata.GetSecret("u"), secretdata.GetSecret("alpha"), n).
		Cmp(nu) == 0
}

func (b accumulator) GetBase(name string) *big.Int {
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

func (b accumulator) GetNames() []string {
	return []string{"nu"}
}

func (w *witness) GetSecret(name string) *big.Int {
	switch name {
	case "alpha":
		return w.E
	case "u":
		return w.U
	}

	return nil
}

func (w *witness) GetRandomizer(name string) *big.Int {
	if name == "alpha" {
		return w.randomizer
	}
	return nil
}

// Helpers

func verify(u, e *big.Int, acc *Accumulator, grp *QrGroup) bool {
	return new(big.Int).Exp(u, e, grp.N).Cmp(acc.Nu) == 0
}

func newWitness(sk *PrivateKey, acc *Accumulator, e *big.Int) (*Witness, error) {
	order := new(big.Int).Mul(sk.P, sk.Q)
	eInverse, ok := common.ModInverse(e, order)
	if !ok {
		return nil, errors.New("failed to compute modular inverse")
	}
	u := new(big.Int).Exp(acc.Nu, eInverse, sk.N)
	return &Witness{U: u, E: e, Nu: acc.Nu, Index: acc.Index}, nil
}

func embedPrime(key, bts []byte) (*big.Int, error) {
	bts, err := asn1.Marshal([][]byte{key, bts})
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(bts)
	csprng, err := common.NewCPRNG(&h)
	if err != nil {
		return nil, err
	}
	return common.RandomPrimeInRange(csprng, parameters.attributeMinSize, parameters.attributeMinSize)
}

func embedWitness(sk *PrivateKey, acc *Accumulator, key, bts []byte) (*Witness, error) {
	e, err := embedPrime(key, bts)
	if err != nil {
		return nil, err
	}
	return newWitness(sk, acc, e)
}
