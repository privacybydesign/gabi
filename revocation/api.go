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
         NewNu := Nu^(1/e mod (P-1)*(Q-1))
      where P, Q is the issuer Idemix private key
  (2) Broadcasting (NewNu, e) to all IRMA apps and verifiers
  (3) All IRMA clients update their nonrevocation witness, using an algorithm taking the broadcast
      message and the client's current witness, resulting in a new u which is such that
      u^e = NewNu mod N. This algorithm is guaranteed to fail for the credential containing the
      revoked nonrevocation attribute e.

To keep track of previous and current accumulators, each Accumulator has an index which is
incremented each time a credential is revoked and the accumulator changes value.

Issuers supporting revocation use ECDSA private/public keys to sign the accumulator update messages.
All IRMA participants (client, verifier, issuer) require the latest revocation record to be able
to function. The client additionally needs to know the complete chain of all events to be able to
update its witness to the latest accumulator.

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
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/fxamacker/cbor"
	"github.com/go-errors/errors"
	"github.com/multiformats/go-multihash"
	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/internal/common"
	"github.com/privacybydesign/gabi/signed"
)

type (
	// Accumulator is an RSA-B accumulator against which clients with a corresponding Witness
	// having the same Index can prove that their witness is accumulated, i.e. not revoked.
	Accumulator struct {
		Nu        *big.Int
		Index     uint64
		EventHash Hash
	}

	// SignedAccumulator is an Accumulator signed with the issuer's ECDSA key, along with the key index.
	SignedAccumulator struct {
		Data    signed.Message `json:"data"`
		PKIndex uint           `json:"pkindex"`
	}

	// Event contains the data clients need to update to the Accumulator of the specified index,
	// after it has been updated by the issuer by revoking. Forms a chain through the
	// ParentHash which is the SHA256 hash of its parent.
	Event struct {
		Index      uint64   `json:"i" gorm:"primary_key;column:eventindex"`
		E          *big.Int `json:"e"`
		ParentHash Hash     `json"parenthash"`
	}

	// Update contains all information for clients to update their witness to the latest accumulator:
	// the accumulator itself and a set of revocation attributes.
	// Its hash structure makes this message into a chain with the SignedAccumulator on top:
	// The accumulator contains the hash of the first Event, and each Event has a hash of its parent.
	// Thus the signature over the accumulator effectively signs the entire Update message,
	// and the partial tree specified by Events is verifiable regardless of its length.
	Update struct {
		SignedAccumulator *SignedAccumulator
		Events            []*Event
	}

	// Hash represents a SHA256 hash and has marshaling methods to/from JSON.
	Hash multihash.Multihash

	// Witness is a witness for the RSA-B accumulator, used for proving nonrevocation against the
	// Accumulator with the same Index.
	Witness struct {
		// U^E = Accumulator.Nu mod N
		U *big.Int `json:"u"`
		E *big.Int `json:"e"`
		// Accumulator against which the witness verifies.
		SignedAccumulator *SignedAccumulator `json:"sacc"`
		// Accumulator value for local computations, extracted from verified SignedAccumulator
		Accumulator *Accumulator `json:"-"`

		randomizer *big.Int
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
)

const (
	AccumulatorStartIndex uint64 = 1

	HashAlgorithm = multihash.SHA2_256
)

func NewAccumulator(sk *PrivateKey) (*Update, error) {
	empty := [32]byte{}
	emptyhash, err := multihash.Encode(empty[:], HashAlgorithm)
	initialEvent := &Event{
		Index:      AccumulatorStartIndex,
		E:          big.NewInt(0),
		ParentHash: emptyhash,
	}
	if err != nil {
		return nil, err
	}
	acc := &Accumulator{
		Nu:        common.RandomQR(sk.N),
		Index:     AccumulatorStartIndex,
		EventHash: initialEvent.hash(),
	}
	sig, err := acc.Sign(sk)
	if err != nil {
		return nil, err
	}
	return &Update{
		SignedAccumulator: sig,
		Events:            []*Event{initialEvent},
	}, nil
}

// Sign the accumulator into a SignedAccumulator (c.f. SignedAccumulator.UnmarshalVerify()).
func (acc *Accumulator) Sign(sk *PrivateKey) (*SignedAccumulator, error) {
	sig, err := signed.MarshalSign(sk.ECDSA, acc)
	if err != nil {
		return nil, err
	}
	return &SignedAccumulator{Data: sig, PKIndex: sk.Counter}, nil
}

// Remove generates a new accumulator with the specified e removed from it; signs it;
// and returns an Update message for clients to update their witness.
func (acc *Accumulator) Remove(sk *PrivateKey, e *big.Int, parent *Event) (*Update, error) {
	eInverse, ok := common.ModInverse(e, new(big.Int).Mul(sk.P, sk.Q))
	if !ok {
		// since N = P*Q and P, Q prime, e has no inverse if and only if e equals either P or Q
		return nil, errors.New("revocation attribute has no inverse")
	}

	newAcc := Accumulator{
		Index: acc.Index + 1,
		Nu:    new(big.Int).Exp(acc.Nu, eInverse, sk.N),
	}
	event := &Event{
		Index:      newAcc.Index,
		E:          e,
		ParentHash: parent.hash(),
	}
	newAcc.EventHash = event.hash()
	sig, err := newAcc.Sign(sk)
	if err != nil {
		return nil, err
	}

	return &Update{
		SignedAccumulator: sig,
		Events:            []*Event{event},
	}, nil
}

// UnmarshalVerify verifies the signature and unmarshals the accumulator
// (c.f. Accumulator.Sign()).
func (s *SignedAccumulator) UnmarshalVerify(pk *PublicKey) (*Accumulator, error) {
	msg := &Accumulator{}
	if pk.Counter != s.PKIndex {
		return nil, errors.New("wrong public key")
	}
	if err := signed.UnmarshalVerify(pk.ECDSA, s.Data, msg); err != nil {
		return nil, err
	}
	return msg, nil
}

type compressedUpdate struct {
	SignedAccumulator *SignedAccumulator `json:"sacc"`
	Index             uint64             `json:"i"`
	ParentHash        Hash               `json:"hash"`
	E                 []*big.Int         `json:"e"`
}

func (update *Update) compress() *compressedUpdate {
	c := compressedUpdate{
		SignedAccumulator: update.SignedAccumulator,
		Index:             update.Events[0].Index,
		ParentHash:        update.Events[0].ParentHash,
		E:                 make([]*big.Int, len(update.Events)),
	}
	for i := range update.Events {
		c.E[i] = update.Events[i].E
	}
	return &c
}

func (update *Update) uncompress(c *compressedUpdate) {
	update.SignedAccumulator = c.SignedAccumulator
	update.Events = make([]*Event, len(c.E))
	for i := range update.Events {
		update.Events[i] = &Event{
			E:     c.E[i],
			Index: uint64(i) + c.Index,
		}
		if i == 0 {
			update.Events[i].ParentHash = c.ParentHash
		} else {
			update.Events[i].ParentHash = update.Events[i-1].hash()
		}
	}
}

func (update *Update) MarshalJSON() ([]byte, error) {
	return json.Marshal(update.compress())
}

func (update *Update) UnmarshalJSON(bts []byte) error {
	var c compressedUpdate
	if err := json.Unmarshal(bts, &c); err != nil {
		return err
	}
	update.uncompress(&c)
	return nil
}

func (update *Update) MarshalCBOR() ([]byte, error) {
	return cbor.Marshal(update.compress(), cbor.EncOptions{})
}

func (update *Update) UnmarshalCBOR(data []byte) error {
	var c compressedUpdate
	if err := cbor.Unmarshal(data, &c); err != nil {
		return err
	}
	update.uncompress(&c)
	return nil
}

// Verify that the specified update message is a validly signed partial chain:
// - the accumulator is validly signed
// - the accumulator includes the hash of the last item in the hash chain
// - the hash chain is valid (each chain item has the correct hash of its parent).
func (update *Update) Verify(pk *PublicKey, index uint64) (*Accumulator, *big.Int, error) {
	count := len(update.Events)
	if count == 0 {
		return nil, nil, errors.New("no accumulator update specified")
	}

	acc, err := update.SignedAccumulator.UnmarshalVerify(pk)
	if err != nil {
		return nil, nil, err
	}

	if err = update.Events[count-1].hashEquals(acc.EventHash); err != nil {
		return nil, nil, errors.WrapPrefix(err, "update chain has wrong hash", 0)
	}

	// Verify the hashes of the chain, computing the product of all revoked attributes along the way
	startIndex := update.Events[0].Index
	prod := new(big.Int).SetInt64(1)
	for i, event := range update.Events {
		if i != 0 {
			if err = update.Events[i-1].hashEquals(event.ParentHash); err != nil {
				return nil, nil, errors.WrapPrefix(
					err, fmt.Sprintf("event chain element %d has wrong parent hash", i), 0,
				)
			}
		}
		if uint64(i)+startIndex != event.Index {
			return nil, nil, errors.Errorf("event %d has wrong index, found %d, expected %d", event.Index, uint64(i)+startIndex)
		}
		if uint64(i)+startIndex <= index {
			continue
		}
		prod.Mul(prod, event.E)
	}

	return acc, prod, nil
}

// whitelist of hash algorithms that we currently accept consisting of just SHA256
func checkHashAlg(code uint64) error {
	switch code {
	case multihash.SHA2_256:
		return nil
	default:
		return errors.New("unsupported hash algorithm")
	}
}

// Hash returns the SHA256 hash of the Event.
func (event *Event) hash() Hash {
	hash, err := event.hashUsingAlg(HashAlgorithm)
	if err != nil {
		// multihash only emits errors if using an unsupported hashing algorithm
		panic("failed to compute event multihash: " + err.Error())
	}
	return hash
}

func (event *Event) hashBytes() []byte {
	bts := make([]byte, 8, 8+len(event.ParentHash)+int(parameters.attributeMaxSize)/8+1)
	binary.BigEndian.PutUint64(bts, event.Index)
	bts = append(bts, event.ParentHash[:]...)
	bts = append(bts, event.E.Bytes()...)
	return bts
}

func (event *Event) hashUsingAlg(code uint64) (Hash, error) {
	if err := checkHashAlg(code); err != nil {
		return nil, err
	}
	hash, err := multihash.Sum(event.hashBytes(), code, -1)
	if err != nil {
		return nil, err
	}
	return Hash(hash), nil
}

func (event *Event) hashEquals(h Hash) error {
	alg, err := h.Algorithm()
	if err != nil {
		return err
	}
	ours, err := event.hashUsingAlg(alg)
	if err != nil {
		return err
	}
	if !ours.Equal(h) {
		return errors.New("unequal hash")
	}
	return nil
}

func (hash Hash) MarshalJSON() ([]byte, error) {
	return json.Marshal(hash.String())
}

func (hash *Hash) UnmarshalJSON(b []byte) error {
	var s string
	err := json.Unmarshal(b, &s)
	if err != nil {
		return err
	}
	b, err = base64.URLEncoding.DecodeString(s)
	if err != nil {
		return err
	}
	_, mh, err := multihash.MHFromBytes(b)
	if err != nil {
		return err
	}
	*hash = Hash(mh)
	return nil
}

func (hash Hash) String() string {
	return base64.URLEncoding.EncodeToString(hash[:])
}

func (hash Hash) Equal(other Hash) bool {
	for i := range hash {
		if i == len(other) {
			break
		}
		if hash[i] != other[i] {
			return false
		}
	}
	return true
}

func (hash Hash) Algorithm() (uint64, error) {
	mh, err := multihash.Decode(hash)
	if err != nil {
		return 0, err
	}
	if !multihash.ValidCode(mh.Code) {
		return 0, errors.New("unknown multihash algorithm")
	}
	if err = checkHashAlg(mh.Code); err != nil {
		return 0, err
	}
	return mh.Code, nil
}
