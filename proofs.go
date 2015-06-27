package credential

import (
	"math/big"
)

// ProofU represents a proof of correctness of the commitment in the first phase
// of the issuance protocol.
type ProofU struct {
	c              *big.Int
	vPrimeResponse *big.Int
	sResponse      *big.Int
}

// Verify verifies whether the proof is correct.
func (p *ProofU) Verify(pk *PublicKey, U, context, nonce *big.Int) bool {
	maximum := new(big.Int).Lsh(bigONE, pk.Params.LvPrimeCommit+1)
	maximum.Sub(maximum, bigONE)
	minimum := new(big.Int).Neg(maximum)
	if !(p.vPrimeResponse.Cmp(minimum) >= 0 && p.vPrimeResponse.Cmp(maximum) <= 0) {
		return false
	}

	// Reconstruct Ucommit
	// U_commit = U^{-c} * S^{vPrimeResponse} * R_0^{sResponse}
	Uc := modPow(U, new(big.Int).Neg(p.c), &pk.N)
	Sv := modPow(&pk.S, p.vPrimeResponse, &pk.N)
	R0s := modPow(pk.R[0], p.sResponse, &pk.N)
	Ucommit := new(big.Int).Mul(Uc, Sv)
	Ucommit.Mul(Ucommit, R0s).Mod(Ucommit, &pk.N)

	cPrime := hashCommit([]*big.Int{context, U, Ucommit, nonce})

	return p.c.Cmp(cPrime) == 0
}

// ProofS represents a proof.
type ProofS struct {
	c         *big.Int
	eResponse *big.Int
}

// Verify verifies the proof agains the given public key, signature, context,
// and nonce.
func (p *ProofS) Verify(pk *PublicKey, signature *CLSignature, context, nonce *big.Int) bool {
	// Reconstruct A_commit
	// ACommit = A^{c + eResponse * e}
	exponent := new(big.Int).Mul(p.eResponse, signature.E)
	exponent.Add(p.c, exponent)
	ACommit := new(big.Int).Exp(signature.A, exponent, &pk.N)

	// Reconstruct Q
	Q := new(big.Int).Exp(signature.A, signature.E, &pk.N)

	// Recalculate hash
	cPrime := hashCommit([]*big.Int{context, Q, signature.A, nonce, ACommit})

	return p.c.Cmp(cPrime) == 0
}

// ProofD represents a proof in the showing protocol.
type ProofD struct {
	c, A, eResponse, vResponse *big.Int
	aResponses, aDisclosed     map[int]*big.Int
}

func (p *ProofD) checkSizeResponses(pk *PublicKey) bool {
	// Check range on the aResponses
	maximum := new(big.Int).Lsh(bigONE, pk.Params.LmCommit+1)
	maximum.Sub(maximum, bigONE)
	minimum := new(big.Int).Neg(maximum)
	for _, aResponse := range p.aResponses {
		if aResponse.Cmp(minimum) < 0 || aResponse.Cmp(maximum) > 0 {
			return false
		}
	}

	// Check range eResponse
	maximum.Lsh(bigONE, pk.Params.LeCommit+1)
	maximum.Sub(maximum, bigONE)
	minimum.Neg(maximum)

	if p.eResponse.Cmp(minimum) < 0 || p.eResponse.Cmp(maximum) > 0 {
		return false
	}

	return true
}

// reconstructZ reconstructs Z from the information in the proof and the
// provided public key.
func (p *ProofD) reconstructZ(pk *PublicKey) *big.Int {
	// known = Z / ( prod_{disclosed} R_i^{a_i} * A^{2^{l_e - 1}} )
	numerator := new(big.Int).Lsh(bigONE, pk.Params.Le-1)
	numerator.Exp(p.A, numerator, &pk.N)
	for i, attribute := range p.aDisclosed {
		numerator.Mul(numerator, new(big.Int).Exp(pk.R[i], attribute, &pk.N))
	}

	known := new(big.Int).ModInverse(numerator, &pk.N)
	known.Mul(&pk.Z, known)

	knownC := modPow(known, new(big.Int).Neg(p.c), &pk.N)
	Ae := modPow(p.A, p.eResponse, &pk.N)
	Sv := modPow(&pk.S, p.vResponse, &pk.N)
	Rs := big.NewInt(1)
	for i, response := range p.aResponses {
		Rs.Mul(Rs, modPow(pk.R[i], response, &pk.N))
	}
	Z := new(big.Int).Mul(knownC, Ae)
	Z.Mul(Z, Rs).Mul(Z, Sv).Mod(Z, &pk.N)

	return Z
}

// Verify verifies the proof agains the given public key, context, and nonce.
func (p *ProofD) Verify(pk *PublicKey, context, nonce1 *big.Int) bool {
	if !p.checkSizeResponses(pk) {
		return false
	}

	Z := p.reconstructZ(pk)

	cPrime := hashCommit([]*big.Int{context, p.A, Z, nonce1})

	return p.c.Cmp(cPrime) == 0
}
