package gabi

import (
	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/gabikeys"
)

// KeyshareResponseLegacy generates the keyshare response for a given challenge and commit, given a secret,
// in the legacy keyshare protocol.
func KeyshareResponseLegacy(secret, commit, challenge *big.Int, key *gabikeys.PublicKey) *ProofP {
	return &ProofP{
		P:         new(big.Int).Exp(key.R[0], secret, key.N),
		C:         new(big.Int).Set(challenge),
		SResponse: new(big.Int).Add(commit, new(big.Int).Mul(challenge, secret)),
	}
}

func (p *ProofU) RemoveKeyshareP(b *CredentialBuilder) {
	if b.keyshareP == nil {
		return
	}
	p.U.Mul(p.U, new(big.Int).ModInverse(b.keyshareP, b.pk.N))
	p.U.Mod(p.U, b.pk.N)
}
