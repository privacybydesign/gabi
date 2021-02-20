package gabi

import (
	"encoding/asn1"
	"time"

	"github.com/go-errors/errors"
	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/internal/common"
)

type (
	// ContextualLinkability specifies options instructing the client to include integers in its
	// disclosure proof which are stable per epoch and per verifier, but distinct (unlinkable)
	// otherwise - i.e., 1-anonymity.
	ContextualLinkability struct {
		// Attributes specifies the indices for which attributes to send H(t, V)^attr.
		Attributes []int
		// EpochLength in seconds determines the current epoch by unixtimestamp/EpochLength.
		EpochLength int
		// EpochCount specifies for how many epoch's to send bigints: H(t, V)^attr, ..., H(t+count, V)^attr
		EpochCount int
		// Verifier is the name of the verifier, V; different verifier names result in different bigints.
		Verifier string

		// epoch keeps track of the epoch during proof construction.
		epoch int64
		// pk is the issuer's public key with which the credential is signed.
		pk *PublicKey
	}

	ContextualLinkabilityProof struct {
		Ints     map[int][]*big.Int `json:"ints"`
		Epoch    int64              `json:"epoch"`
		Verifier string             `json:"verifier"`
	}

	contextualLinkabilityHashInput struct {
		Epoch    int64
		Verifier string
		Count    int64 // For later extension to k-anonymity; not currently used
	}
)

// During verification, allow the client to use the previous epoch if the current epoch is
// this many seconds old
const epochGrace = 3 * 60

// hash computes the base element R = H(epoch || verifier || count) for linkable integers.
func (l *ContextualLinkability) hash(epoch int64) *big.Int {
	bts, _ := asn1.Marshal(contextualLinkabilityHashInput{epoch, l.Verifier, 0}) // does not error
	return l.pk.Hash(bts)
}

func (l *ContextualLinkability) validate(d *DisclosureProofBuilder, ic *Credential, nonrev bool) error {
	var revIdx int
	var err error
	if nonrev {
		revIdx, err = ic.NonrevIndex()
		if err != nil {
			return err
		}
	}

	if l.epoch != 0 {
		return errors.New("epoch must not be specified")
	}
	undisclosed := map[int]struct{}{}
	for _, i := range d.undisclosedAttributes {
		undisclosed[i] = struct{}{}
	}
	for _, i := range l.Attributes {
		if i >= len(ic.Attributes) {
			return errors.Errorf("cannot do contextual linkability for attribute %d: index too big", i)
		}
		if nonrev && i == revIdx {
			return errors.Errorf("cannot do contextual linkability for attribute %d: revocation attribute", i)
		}
		if _, present := undisclosed[i]; !present {
			return errors.Errorf("cannot do contextual linkability for attribute %d: attribute disclosed", i)
		}
	}

	return nil
}

func (l *ContextualLinkability) commit(attrRandomizers map[int]*big.Int) []*big.Int {
	var list []*big.Int
	for i := 0; i < l.EpochCount; i++ {
		H := l.hash(l.epoch + int64(i))
		for _, attr := range l.Attributes {
			list = append(list, common.ModPow(H, attrRandomizers[attr], l.pk.N))
		}
	}
	return list
}

func (l *ContextualLinkability) createProof(attributes []*big.Int) map[int][]*big.Int {
	linkableInts := make(map[int][]*big.Int)
	for _, attr := range l.Attributes {
		linkableInts[attr] = make([]*big.Int, l.EpochCount)
	}
	for i := 0; i < l.EpochCount; i++ {
		H := l.hash(l.epoch + int64(i))
		for _, attr := range l.Attributes {
			linkableInts[attr][i] = common.ModPow(H, attributes[attr], l.pk.N)
		}
	}
	return linkableInts
}

func (l *ContextualLinkability) challengeContributions(
	linkableInts map[int][]*big.Int, responses map[int]*big.Int, challenge *big.Int,
) []*big.Int {
	var list []*big.Int
	for i := 0; i < l.EpochCount; i++ {
		H := l.hash(l.epoch + int64(i))
		for attr := range linkableInts {
			contrib := new(big.Int).Mul(
				common.ModPow(H, responses[attr], l.pk.N),
				common.ModPow(linkableInts[attr][i], new(big.Int).Neg(challenge), l.pk.N),
			)
			list = append(list, contrib.Mod(contrib, l.pk.N))
		}
	}
	return list
}

func (l *ContextualLinkability) copy() *ContextualLinkability {
	return &ContextualLinkability{
		Attributes:  l.Attributes,
		EpochLength: l.EpochLength,
		EpochCount:  l.EpochCount,
		Verifier:    l.Verifier,
		epoch:       l.epoch,
		pk:          l.pk,
	}
}

func (p *ContextualLinkabilityProof) optionsFromProof(pk *PublicKey) (*ContextualLinkability, error) {
	if len(p.Ints) == 0 {
		return nil, errors.New("no linkable ints found")
	}

	// check that for all attributes, the same amount of linkable ints are present
	var count int
	for _, attrs := range p.Ints {
		count = len(attrs)
		break
	}
	if count == 0 {
		return nil, errors.New("zero linkable ints")
	}
	for _, attrs := range p.Ints {
		if len(attrs) != count {
			return nil, errors.New("incorrect amount of linkable ints")
		}
	}

	return &ContextualLinkability{
		Verifier:   p.Verifier,
		EpochCount: count,
		epoch:      p.Epoch,
		pk:         pk,
	}, nil
}

func (p *ContextualLinkabilityProof) LinkableInts(l *ContextualLinkability) (map[int][]*big.Int, error) {
	now := time.Now().Unix()
	epoch := now / int64(l.EpochLength)
	epochAge := now % int64(l.EpochLength)

	if !(p.Epoch == epoch || (epochAge < epochGrace && p.Epoch == epoch-1)) {
		return nil, errors.New("epoch too old")
	}
	if p.Verifier != l.Verifier {
		return nil, errors.New("wrong verifier")
	}
	attrmap := map[int]struct{}{}
	for i, attrs := range p.Ints {
		attrmap[i] = struct{}{}
		if len(attrs) != l.EpochCount {
			return nil, errors.New("wrong amount of linkable integers")
		}
	}
	for _, i := range l.Attributes {
		if _, present := attrmap[i]; !present {
			return nil, errors.New("required linkable integer not found")
		}
	}

	return p.Ints, nil
}
