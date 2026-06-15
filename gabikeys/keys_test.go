// Copyright 2016 Maarten Everts. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gabikeys

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/privacybydesign/gabi/big"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A real 1024-bit issuer keypair (safe primes), reused from the gabi package
// tests so the parsing/round-trip paths run against keys that DefaultSystemParameters
// recognises.
const (
	// p and q are the safe primes of xmlPrivKey1, used to exercise NewPrivateKey directly.
	p1 = "12511561644521105216249960315425509848310543851123625148071038103672749250653050780946327920540373585150518830678888836864183842100121288018131086700947919"
	q1 = "13175754961224278923898419496296790582860213842149399404614891067426616055648139811854869087421318470521236911637912285993998784296429335994419545592486183"

	xmlPrivKey1 = `<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<IssuerPrivateKey xmlns="http://www.zurich.ibm.com/security/idemix">
   <Counter>0</Counter>
   <ExpiryDate>1700000000</ExpiryDate>
   <Elements>
      <p>12511561644521105216249960315425509848310543851123625148071038103672749250653050780946327920540373585150518830678888836864183842100121288018131086700947919</p>
      <q>13175754961224278923898419496296790582860213842149399404614891067426616055648139811854869087421318470521236911637912285993998784296429335994419545592486183</q>
      <pPrime>6255780822260552608124980157712754924155271925561812574035519051836374625326525390473163960270186792575259415339444418432091921050060644009065543350473959</pPrime>
      <qPrime>6587877480612139461949209748148395291430106921074699702307445533713308027824069905927434543710659235260618455818956142996999392148214667997209772796243091</qPrime>
   </Elements>
</IssuerPrivateKey>`

	xmlPubKey1 = `<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<IssuerPublicKey xmlns="http://www.zurich.ibm.com/security/idemix">
   <Counter>0</Counter>
   <ExpiryDate>1700000000</ExpiryDate>
   <Elements>
      <n>164849270410462350104130325681247905590883554049096338805080434441472785625514686982133223499269392762578795730418568510961568211704176723141852210985181059718962898851826265731600544499072072429389241617421101776748772563983535569756524904424870652659455911012103327708213798899264261222168033763550010103177</n>
      <Z>85612209073231549357971504917706448448632620481242156140921956689865243071517333286408980597347754869291449755693386875207418733579434926868804114639149514414312088911027338251870409643059636340634892197874721564672349336579075665489514404442681614964231517891268285775435774878821304200809336437001672124945</Z>
      <S>95431387101397795194125116418957121488151703839429468857058760824105489778492929250965841783742048628875926892511288385484169300700205687919208898288594042075246841706909674758503593474606503299796011177189518412713004451163324915669592252022175131604797186534801966982736645522331999047305414834481507220892</S>
      <Bases num="6">
         <Base_0>15948796959221892486955992453179199515496923441128830967123361439118018661581037984810048354811434050038778558011395590650011565629310700360843433067202313291361609843998531962373969946197182940391414711398289105131565252299185121868561402842968555939684308560329951491463967030905495360286851791764439565922</Base_0>
         <Base_1>119523438901119086528333705353116973341573129722743063979885442255495816390473126070276442804547475203517104656193873407665058481273192071865721910619056848142740067272069428460724210705091048104466624895000063564223095487133194907203681789863578060886235105842841954519189942453426975057803871974937309502784</Base_1>
         <Base_2>21036812778930907905009726679774009067486097699134635274413938052367886222555608567065065339702690960558290977766511663461460906408225144877806673612081001465755091058944847078216758263034300782760502281865270151054157854728772298542643419836244547728225955304279190350362963560596454003412543292789187837679</Base_2>
         <Base_3>2507221674373339204944916721547102290807064604358409729371715856726643784893285066715992395214052930640947278288383410209092118436778149456628267900567208684458410552361708506911626161349456189054709967676518205745736652492505957876189855916223094854626710186459345996698113370306994139940441752005221653088</Base_3>
         <Base_4>43215325590379490852400435325847836613513274803460964568083232110934910151335113918829588414147781676586145312074043749201037447486205927144941119404243266454032858201713735324770837218773739346063812751896736791478531103409536739098007890723770126159814845238386299865793353073058783010002988453373168625327</Base_4>
         <Base_5>61146634020942775692657595021461289090915429142715194304483397998858712705680675945417056124974172620475325240482216550923967273908399017396442709297466408094303826941548068001214817725191465207971123378222070812822903173820970991987799984521470178624084174451047081964996323127069438975310975798326710264763</Base_5>
      </Bases>
   </Elements>
   <Features>
      <Epoch length="432000"></Epoch>
   </Features>
</IssuerPublicKey>`
)

func s2big(s string) *big.Int {
	v, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("invalid bigint literal: " + s)
	}
	return v
}

// smallSystemParameters returns system parameters for a tiny modulus so key
// generation terminates near-instantly in tests. GenerateKeyPair only depends
// on the base parameters, so we don't need an entry in DefaultSystemParameters.
func smallSystemParameters(ln uint) *SystemParameters {
	base := BaseParameters{
		LePrime: 120,
		Lh:      256,
		Lm:      256,
		Ln:      ln,
		Lstatzk: 80,
	}
	return &SystemParameters{BaseParameters: base, DerivedParameters: MakeDerivedParameters(base)}
}

func TestNewPrivateKey(t *testing.T) {
	p, q := s2big(p1), s2big(q1)
	sk, err := NewPrivateKey(p, q, "", 0, time.Now().AddDate(1, 0, 0))
	require.NoError(t, err)
	require.NotNil(t, sk)

	// N = p*q
	assert.Equal(t, 0, sk.N.Cmp(new(big.Int).Mul(p, q)))
	// P' = (p-1)/2, Q' = (q-1)/2
	assert.Equal(t, 0, sk.PPrime.Cmp(new(big.Int).Rsh(p, 1)))
	assert.Equal(t, 0, sk.QPrime.Cmp(new(big.Int).Rsh(q, 1)))
	assert.NoError(t, sk.Validate())
	assert.False(t, sk.RevocationSupported())
}

func TestNewPrivateKeyFromXML(t *testing.T) {
	sk, err := NewPrivateKeyFromXML(xmlPrivKey1, false)
	require.NoError(t, err)
	require.NotNil(t, sk)
	assert.Equal(t, 0, sk.P.Cmp(s2big(p1)))
	assert.Equal(t, 0, sk.Q.Cmp(s2big(q1)))
	assert.NoError(t, sk.Validate())

	// demo mode skips validation; should still parse.
	sk2, err := NewPrivateKeyFromXML(xmlPrivKey1, true)
	require.NoError(t, err)
	require.NotNil(t, sk2)
}

func TestNewPrivateKeyFromXMLMalformed(t *testing.T) {
	_, err := NewPrivateKeyFromXML("this is not xml", false)
	assert.Error(t, err)

	// well-formed XML but the primes do not satisfy p = 2p'+1, so Validate fails
	// (only when not in demo mode).
	bad := `<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<IssuerPrivateKey xmlns="http://www.zurich.ibm.com/security/idemix">
   <Counter>0</Counter>
   <ExpiryDate>1700000000</ExpiryDate>
   <Elements>
      <p>23</p><q>23</q><pPrime>3</pPrime><qPrime>3</qPrime>
   </Elements>
</IssuerPrivateKey>`
	_, err = NewPrivateKeyFromXML(bad, false)
	assert.Error(t, err)
	// In demo mode the same malformed key parses without validation.
	_, err = NewPrivateKeyFromXML(bad, true)
	assert.NoError(t, err)
}

func TestNewPrivateKeyFromFile(t *testing.T) {
	dir := t.TempDir()
	fname := filepath.Join(dir, "sk.xml")
	require.NoError(t, os.WriteFile(fname, []byte(xmlPrivKey1), 0600))

	sk, err := NewPrivateKeyFromFile(fname, false)
	require.NoError(t, err)
	assert.Equal(t, 0, sk.P.Cmp(s2big(p1)))

	_, err = NewPrivateKeyFromFile(filepath.Join(dir, "does-not-exist.xml"), false)
	assert.Error(t, err)
}

func TestPrivateKeyValidate(t *testing.T) {
	// P and P' are inconsistent.
	sk := &PrivateKey{
		P:      big.NewInt(11),
		Q:      big.NewInt(11),
		PPrime: big.NewInt(99),
		QPrime: big.NewInt(5),
	}
	assert.Error(t, sk.Validate())
}

func TestNewPublicKey(t *testing.T) {
	parsed, err := NewPublicKeyFromXML(xmlPubKey1)
	require.NoError(t, err)

	pk, err := NewPublicKey(parsed.N, parsed.Z, parsed.S, nil, nil, parsed.R, "", 0, time.Now().AddDate(1, 0, 0))
	require.NoError(t, err)
	require.NotNil(t, pk)
	require.NotNil(t, pk.Params, "Params should be derived from the modulus bit length")
	assert.Equal(t, 0, pk.N.Cmp(parsed.N))
	assert.Equal(t, DefaultEpochLength, int(pk.EpochLength))
	assert.False(t, pk.RevocationSupported())
}

func TestNewPublicKeyFromBytes(t *testing.T) {
	pk, err := NewPublicKeyFromBytes([]byte(xmlPubKey1))
	require.NoError(t, err)
	require.NotNil(t, pk.Params)
	assert.Len(t, pk.R, 6)

	_, err = NewPublicKeyFromBytes([]byte("not xml at all"))
	assert.Error(t, err)
}

func TestNewPublicKeyFromXML(t *testing.T) {
	pk, err := NewPublicKeyFromXML(xmlPubKey1)
	require.NoError(t, err)
	require.NotNil(t, pk)

	_, err = NewPublicKeyFromXML("<broken")
	assert.Error(t, err)
}

func TestNewPublicKeyFromFile(t *testing.T) {
	dir := t.TempDir()
	fname := filepath.Join(dir, "pk.xml")
	require.NoError(t, os.WriteFile(fname, []byte(xmlPubKey1), 0644))

	pk, err := NewPublicKeyFromFile(fname)
	require.NoError(t, err)
	require.NotNil(t, pk.Params)

	_, err = NewPublicKeyFromFile(filepath.Join(dir, "missing.xml"))
	assert.Error(t, err)
}

func TestPrivateKeyWriteToRoundTrip(t *testing.T) {
	sk, err := NewPrivateKeyFromXML(xmlPrivKey1, false)
	require.NoError(t, err)

	var buf bytes.Buffer
	n, err := sk.WriteTo(&buf)
	require.NoError(t, err)
	assert.Equal(t, int64(buf.Len()), n)

	sk2, err := NewPrivateKeyFromXML(buf.String(), false)
	require.NoError(t, err)
	assert.Equal(t, 0, sk.P.Cmp(sk2.P))
	assert.Equal(t, 0, sk.Q.Cmp(sk2.Q))
}

func TestPublicKeyWriteToRoundTrip(t *testing.T) {
	pk, err := NewPublicKeyFromXML(xmlPubKey1)
	require.NoError(t, err)

	var buf bytes.Buffer
	n, err := pk.WriteTo(&buf)
	require.NoError(t, err)
	assert.Equal(t, int64(buf.Len()), n)

	pk2, err := NewPublicKeyFromBytes(buf.Bytes())
	require.NoError(t, err)
	assert.Equal(t, 0, pk.N.Cmp(pk2.N))
	assert.Equal(t, 0, pk.Z.Cmp(pk2.Z))
	assert.Equal(t, 0, pk.S.Cmp(pk2.S))
	require.Len(t, pk2.R, len(pk.R))
	for i := range pk.R {
		assert.Equal(t, 0, pk.R[i].Cmp(pk2.R[i]))
	}
}

func TestWriteToFile(t *testing.T) {
	dir := t.TempDir()
	skFile := filepath.Join(dir, "sk.xml")
	pkFile := filepath.Join(dir, "pk.xml")

	sk, err := NewPrivateKeyFromXML(xmlPrivKey1, false)
	require.NoError(t, err)
	pk, err := NewPublicKeyFromXML(xmlPubKey1)
	require.NoError(t, err)

	_, err = sk.WriteToFile(skFile, false)
	require.NoError(t, err)
	// Without forceOverwrite, writing again must fail (O_EXCL).
	_, err = sk.WriteToFile(skFile, false)
	assert.Error(t, err)
	// With forceOverwrite it succeeds.
	_, err = sk.WriteToFile(skFile, true)
	require.NoError(t, err)

	_, err = pk.WriteToFile(pkFile, false)
	require.NoError(t, err)
	_, err = pk.WriteToFile(pkFile, true)
	require.NoError(t, err)

	// Files round-trip back into equal keys.
	sk2, err := NewPrivateKeyFromFile(skFile, false)
	require.NoError(t, err)
	assert.Equal(t, 0, sk.P.Cmp(sk2.P))
	pk2, err := NewPublicKeyFromFile(pkFile)
	require.NoError(t, err)
	assert.Equal(t, 0, pk.N.Cmp(pk2.N))
}

func TestRevocationSupported(t *testing.T) {
	sk := &PrivateKey{}
	assert.False(t, sk.RevocationSupported())
	sk.ECDSAString = "non-empty"
	assert.True(t, sk.RevocationSupported())

	pk := &PublicKey{}
	assert.False(t, pk.RevocationSupported())
	pk.ECDSAString = "non-empty"
	// G and H still nil: not supported.
	assert.False(t, pk.RevocationSupported())
	pk.G = big.NewInt(1)
	pk.H = big.NewInt(1)
	assert.True(t, pk.RevocationSupported())
}

func TestPublicKeyBaseAndNames(t *testing.T) {
	pk, err := NewPublicKeyFromXML(xmlPubKey1)
	require.NoError(t, err)

	assert.Same(t, pk.Z, pk.Base("Z"))
	assert.Same(t, pk.S, pk.Base("S"))
	assert.Same(t, pk.R[2], pk.Base("R2"))
	assert.Nil(t, pk.Base("R999"), "out-of-range base index")
	assert.Nil(t, pk.Base("nonsense"))

	names := pk.Names()
	assert.Contains(t, names, "Z")
	assert.Contains(t, names, "S")
	assert.Contains(t, names, "R0")
	assert.Contains(t, names, "R5")
}

func TestPublicKeyExp(t *testing.T) {
	pk, err := NewPublicKeyFromXML(xmlPubKey1)
	require.NoError(t, err)

	exp := big.NewInt(3)
	ret := new(big.Int)
	ok := pk.Exp(ret, "S", exp, pk.N)
	require.True(t, ok)
	// ret should equal S^3 mod N.
	expected := new(big.Int).Exp(pk.S, exp, pk.N)
	assert.Equal(t, 0, ret.Cmp(expected))

	// Unknown base names return false.
	assert.False(t, pk.Exp(new(big.Int), "nonsense", exp, pk.N))
}

func TestGenerateKeyPair(t *testing.T) {
	params := smallSystemParameters(256)
	priv, pub, err := GenerateKeyPair(params, 2, 0, time.Now().AddDate(1, 0, 0))
	require.NoError(t, err)
	require.NotNil(t, priv)
	require.NotNil(t, pub)

	// The generated private key must be internally consistent.
	require.NoError(t, priv.Validate())

	// Public and private moduli agree.
	assert.Equal(t, 0, priv.N.Cmp(pub.N))
	assert.Equal(t, uint(256), uint(pub.N.BitLen()))
	assert.Len(t, pub.R, 2)

	// GenerateKeyPair also generates a revocation keypair.
	assert.True(t, priv.RevocationSupported())
	assert.True(t, pub.RevocationSupported())
}

// TestGenerateKeyPairConcurrent stresses generateSafePrimePair (and therefore
// safeprime.GenerateConcurrent) by generating several keypairs in parallel. Run
// under `go test -race` to detect data races on the shared generation machinery.
func TestGenerateKeyPairConcurrent(t *testing.T) {
	params := smallSystemParameters(256)
	const n = 4

	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			priv, pub, err := GenerateKeyPair(params, 2, 0, time.Now().AddDate(1, 0, 0))
			if err != nil {
				errs <- err
				return
			}
			if err := priv.Validate(); err != nil {
				errs <- err
				return
			}
			if priv.N.Cmp(pub.N) != 0 {
				errs <- errors.New("private/public modulus mismatch")
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}
