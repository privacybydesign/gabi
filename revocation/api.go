/*
Package revocation implements the RSA-B accumulator and associated zero knowledge proofs, introduced
in "Dynamic Accumulators and Application to Efficient Revocation of Anonymous Credentials",
Jan Camenisch and Anna Lysyanskaya, CRYPTO 2002, DOI https://doi.org/10.1007/3-540-45708-9_5,
http://static.cs.brown.edu/people/alysyans/papers/camlys02.pdf, and "Accumulators with Applications
to Anonymity-Preserving Revocation", Foteini Baldimtsi et al, IEEE 2017,
DOI https://doi.org/10.1109/EuroSP.2017.13, https://eprint.iacr.org/2017/043.pdf.

In short, revocation works as follows.

- Revokable credentials receive a "nonrevocation witness" consisting of two numbers, u and e,
of which e is added to the credential as a new (hidden) "nonrevocation attribute".

- The issuer publishes an Accumulator, i.e a bigint Nu (the greek letter 𝛎). The witness is valid
only if u^e = Nu mod N where N is the modulus of the (Idemix) public key of the issuer, i.e. e is
"accumulated" in Nu.

- The client can during an IRMA disclosure session prove in zero knowledge that it knows numbers u
and e such that (1) u^e = Nu mod N (2) e equals the credential's nonrevocation attribute, from
which the verifier concludes that the credential is not currently revoked.

- The issuer can revoke a credential by removing its nonrevocation attribute e from the accumulator, by
  (1) Updating the accumulator value as follows:
         NewNu := Nu^(1/e mod P*Q)
      where P, Q is the issuer Idemix private key
  (2) Broadcasting (NewNu, e) to all IRMA apps and verifiers
  (3) All IRMA clients update their nonrevocation witness, using an algorithm taking the broadcast
      message and the client's current witness, resulting in a new u which is such that
      u^e = NewNu mod N. This algorithm is guaranteed to fail for the credential containing the
      revoked nonrevocation attribute e.

To keep track of previous and current accumulators, each Accumulator has an index which is
incremented each time a credential is revoked and the accumulator changes value.

This package includes databases in which the issuer stores (1) all its accumulator values, and (2)
each of the nonrevocation attributes e that it uses (which it needs when it later wants to revoke a
credential).

Notes

By revoking, the issuer changes the value of the accumulator, of which all IRMA clients and
verifiers need to be made aware before the client can prove to the verifier that its credential is
not revoked against the new accumulator. If the client and verifier do not agree on the current
value of the accumulator (for example, the client has not received all revocation broadcast messages
while the verifier has), then the client cannot prove nonrevocation, leading the verifier to reject
the client. The issuer thus has an important responsibility to ensure that all its revocation
broadcast messages are always available to all IRMA participants.

If one thinks of the accumulator as a "nonrevocation public key", then the witness can be thought of
as a "nonrevocation signature" which verifies against that public key (either directly or in zero
knowledge). (That this "nonrevocation public key" changes when a credential is revoked, i.e. the
accumulator is updated, has however no equivalent in signature schemes.)

Unlike ours, accumulators generally have both an Add and Remove algorithm, adding or removing stuff
from the accumulator. The RSA-B has the property that the Add algorithm does nothing, i.e. all
revocation witnesses e are added to it "automatically", and only removing one from the accumulator
actually constitutes work (and broadcasting update messages).

In the literature the agent that is able to revoke (using a PrivateKey) is usually called the
"revocation authority", which generally need not be the same agent as the issuer. In IRMA the design
choice was made instead that the issuer is always the revocation authority.
*/
package revocation

import (
	"crypto/ecdsa"
	"time"

	"github.com/go-errors/errors"

	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/internal/common"
	"github.com/privacybydesign/gabi/signed"
)

type (
	// Accumulator is an RSA-B accumulator against which clients with a corresponding Witness
	// having the same Index can prove that their witness is accumulated, i.e. not revoked.
	Accumulator struct {
		Nu    *big.Int
		Index uint64
	}

	// Witness is a witness for the RSA-B accumulator, used for proving nonrevocation against the
	// Accumulator with the same Index.
	Witness struct {
		U, E       *big.Int
		Nu         *big.Int `json:",omitempty"`
		Index      uint64   `json:",omitempty"`
		Record     *Record
		randomizer *big.Int
	}

	// AccumulatorUpdate contains the data clients and verifiers need to update to the included
	// Accumulator, after it has been updated by the issuer by revoking.
	AccumulatorUpdate struct {
		Accumulator Accumulator
		Revoked     []*big.Int
		StartIndex  uint64
		Time        int64
	}

	// PrivateKey is the private key needed for revoking.
	PrivateKey struct {
		Counter uint
		ECDSA   *ecdsa.PrivateKey
		P, Q, N *big.Int
	}

	// PublicKey is the public key corresponding to PrivateKey, against which witness (zero-knowledge
	// proofs) are verified (containing fixed data as opposed to the Accumulator).
	PublicKey struct {
		Counter uint
		ECDSA   *ecdsa.PublicKey
		Group   *QrGroup
	}

	// Record contains a signed AccumulatorUpdate and associated information and is ued
	// by clients, issuers and verifiers to update their revocation state, so that they can create
	// and verify nonrevocation proofs and witnesses.
	Record struct {
		StartIndex     uint64
		EndIndex       uint64
		PublicKeyIndex uint
		Message        signed.Message // signed AccumulatorUpdate
	}
)

func NewAccumulator(sk *PrivateKey) (signed.Message, *Accumulator, error) {
	update := AccumulatorUpdate{
		Accumulator: Accumulator{
			Nu:    common.RandomQR(sk.N),
			Index: 0,
		},
		StartIndex: 0,
		Time:       time.Now().UnixNano(),
		Revoked:    nil,
	}

	msg, err := signed.MarshalSign(sk.ECDSA, &update)
	if err != nil {
		return nil, nil, err
	}

	return msg, &update.Accumulator, nil
}

// Remove returns a new accumulator with the specified e removed from it, and an increased index.
func (b *Accumulator) Remove(sk *PrivateKey, e *big.Int) (*Accumulator, error) {
	eInverse, ok := common.ModInverse(e, new(big.Int).Mul(sk.P, sk.Q))
	if !ok {
		// since N = P*Q and P, Q prime, e has no inverse if and only if e equals either P or Q
		return nil, errors.New("revocation attribute has no inverse")
	}

	return &Accumulator{
		Index: b.Index + 1,
		Nu:    new(big.Int).Exp(b.Nu, eInverse, sk.N),
	}, nil
}

func (r *Record) UnmarshalVerify(pk *PublicKey) (*AccumulatorUpdate, error) {
	msg := &AccumulatorUpdate{}
	if err := signed.UnmarshalVerify(pk.ECDSA, r.Message, msg); err != nil {
		return nil, err
	}
	if (r.StartIndex != msg.StartIndex) ||
		(r.EndIndex != msg.Accumulator.Index) ||
		(r.EndIndex > AccumulatorStartIndex && r.EndIndex != msg.StartIndex+uint64(len(msg.Revoked))-1) {
		return nil, errors.New("record has invalid start or end index")
	}
	return msg, nil
}

func (w *Witness) Verify(pk *PublicKey) error {
	acc, err := w.Record.UnmarshalVerify(pk)
	if err != nil {
		return err
	}
	w.Index = acc.Accumulator.Index
	w.Nu = acc.Accumulator.Nu
	if !verify(w.U, w.E, &acc.Accumulator, pk.Group) {
		return errors.New("invalid witness")
	}
	return nil
}
