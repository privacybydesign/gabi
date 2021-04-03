package rangeproof_test

import (
	"errors"
	"testing"

	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/internal/common"
	"github.com/privacybydesign/gabi/keys"
	"github.com/privacybydesign/gabi/rangeproof"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
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

func setupPubkey(t *testing.T) *keys.PublicKey {
	PubKey, err := gabi.NewPublicKeyFromXML(xmlPubKey1)
	require.NoError(t, err)
	return (*keys.PublicKey)(PubKey)
}

type bruteForce3 struct{}

func (_ *bruteForce3) Split(delta *big.Int) ([]*big.Int, error) {
	if !delta.IsInt64() {
		panic("too big")
	}

	d := delta.Int64()

	if d > 1e9 || d < 0 {
		panic("too big")
	}

	for i := int64(0); i*i <= d; i++ {
		for j := int64(0); i*i+j*j <= d; j++ {
			for k := int64(0); i*i+j*j+k*k <= d; k++ {
				if i*i+j*j+k*k == d {
					return []*big.Int{big.NewInt(i), big.NewInt(j), big.NewInt(k)}, nil
				}
			}
		}
	}

	panic("Not found")
}

func (_ *bruteForce3) SquareCount() int {
	return 3
}

func (_ *bruteForce3) Ld() uint {
	return 8
}

type bruteForce4 struct{}

func (_ *bruteForce4) Split(delta *big.Int) ([]*big.Int, error) {
	if !delta.IsInt64() {
		panic("too big")
	}

	d := delta.Int64()

	if d > 1e9 || d < 0 {
		panic("too big")
	}

	for i := int64(0); i*i <= d; i++ {
		for j := int64(0); i*i+j*j <= d; j++ {
			for k := int64(0); i*i+j*j+k*k <= d; k++ {
				for l := int64(0); i*i+j*j+k*k+l*l <= d; l++ {
					if i*i+j*j+k*k+l*l == d {
						return []*big.Int{big.NewInt(i), big.NewInt(j), big.NewInt(k), big.NewInt(l)}, nil
					}
				}
			}
		}
	}

	panic("Not found")
}

func (_ *bruteForce4) SquareCount() int {
	return 4
}

func (_ *bruteForce4) Ld() uint {
	return 8
}

func testRangeProofWithSplitter(t *testing.T, split rangeproof.SquareSplitter) {
	g := setupPubkey(t)

	s := rangeproof.New(1, 1, big.NewInt(45), split)

	m := big.NewInt(112)
	mRandomizer, err := common.RandomBigInt(g.Params.Lm + g.Params.Lh + g.Params.Lstatzk)
	require.NoError(t, err)

	secretList, commit, err := s.CommitmentsFromSecrets(g, m, mRandomizer)
	require.NoError(t, err)
	proof := s.BuildProof(commit, big.NewInt(1234567))
	assert.True(t, s.VerifyProofStructure(g, proof))
	assert.True(t, proof.ProvesStatement(1, big.NewInt(45)))
	proofList := s.CommitmentsFromProof(g, proof, big.NewInt(1234567))
	assert.Equal(t, secretList, proofList)
}

func TestRangeProofBasic(t *testing.T) {
	testRangeProofWithSplitter(t, &bruteForce3{})
}

func TestRangeProofBasic4(t *testing.T) {
	testRangeProofWithSplitter(t, &bruteForce4{})
}

func TestRangeProofUsingTable(t *testing.T) {
	table := rangeproof.GenerateSquaresTable(65536)

	testRangeProofWithSplitter(t, table)
}

func TestRangeProofUsingSumFourSquareAlg(t *testing.T) {
	testRangeProofWithSplitter(t, &rangeproof.FourSquaresSplitter{})
}

func TestRangeProofExtractStructure(t *testing.T) {
	g := setupPubkey(t)

	s := rangeproof.New(1, 1, big.NewInt(45), &bruteForce3{})

	m := big.NewInt(112)
	mRandomizer, err := common.RandomBigInt(g.Params.Lm + g.Params.Lh + g.Params.Lstatzk)
	require.NoError(t, err)

	secretList, commit, err := s.CommitmentsFromSecrets(g, m, mRandomizer)
	require.NoError(t, err)
	proof := s.BuildProof(commit, big.NewInt(1234567))

	s, err = proof.ExtractStructure(1, g)
	require.NoError(t, err)
	assert.True(t, s.VerifyProofStructure(g, proof))
	assert.True(t, proof.ProvesStatement(1, big.NewInt(45)))
	proofList := s.CommitmentsFromProof(g, proof, big.NewInt(1234567))
	assert.Equal(t, secretList, proofList)

	proof.Cs = append(proof.Cs, big.NewInt(1), big.NewInt(1))
	_, err = proof.ExtractStructure(1, g)
	assert.Error(t, err)
	proof.Cs = proof.Cs[:2]
	_, err = proof.ExtractStructure(1, g)
	assert.Error(t, err)
	proof.Cs = append(proof.Cs, big.NewInt(1))
	proof.Ld = 300
	_, err = proof.ExtractStructure(1, g)
	assert.Error(t, err)
	proof.Ld = 8
	proof.K = nil
	_, err = proof.ExtractStructure(1, g)
	assert.Error(t, err)
}

func TestRangeProofInvalidStatement(t *testing.T) {
	g := setupPubkey(t)

	s := rangeproof.New(1, 1, big.NewInt(113), &bruteForce3{})

	m := big.NewInt(112)
	mRandomizer, err := common.RandomBigInt(g.Params.Lm + g.Params.Lh + g.Params.Lstatzk)
	require.NoError(t, err)

	_, _, err = s.CommitmentsFromSecrets(g, m, mRandomizer)
	assert.Error(t, err)
}

type testSplit struct {
	val []*big.Int
	e   error
	n   int
	ld  uint
}

func (t *testSplit) Split(_ *big.Int) ([]*big.Int, error) {
	return t.val, t.e
}

func (t *testSplit) SquareCount() int {
	return t.n
}

func (t *testSplit) Ld() uint {
	return t.ld
}

func TestRangeProofMisbehavingSplit(t *testing.T) {
	g := setupPubkey(t)

	s := rangeproof.New(1, 1, big.NewInt(45), &testSplit{val: nil, e: errors.New("test"), n: 4, ld: 8})

	m := big.NewInt(112)
	mRandomizer, err := common.RandomBigInt(g.Params.Lm + g.Params.Lh + g.Params.Lstatzk)

	_, _, err = s.CommitmentsFromSecrets(g, m, mRandomizer)
	assert.Error(t, err)

	s = rangeproof.New(1, 1, big.NewInt(45), &testSplit{val: []*big.Int{big.NewInt(512), big.NewInt(512), big.NewInt(512)}, e: nil, n: 3, ld: 8})
	_, _, err = s.CommitmentsFromSecrets(g, m, mRandomizer)
	assert.Error(t, err)

	s = rangeproof.New(1, 1, big.NewInt(45), &testSplit{val: []*big.Int{big.NewInt(1), big.NewInt(1), big.NewInt(1)}, e: nil, n: 4, ld: 8})
	_, _, err = s.CommitmentsFromSecrets(g, m, mRandomizer)
	assert.Error(t, err)

	s = rangeproof.New(1, 1, big.NewInt(45), &testSplit{val: []*big.Int{big.NewInt(1), big.NewInt(1), big.NewInt(1)}, e: nil, n: 3, ld: 8})
	secretList, commit, err := s.CommitmentsFromSecrets(g, m, mRandomizer)
	require.NoError(t, err)
	proof := s.BuildProof(commit, big.NewInt(1234567))
	assert.True(t, s.VerifyProofStructure(g, proof))
	proofList := s.CommitmentsFromProof(g, proof, big.NewInt(1234567))
	assert.NotEqual(t, secretList, proofList)
}

func TestVerifyProofStructure(t *testing.T) {
	g := setupPubkey(t)

	s := rangeproof.New(1, 1, big.NewInt(45), &bruteForce3{})

	m := big.NewInt(112)
	mRandomizer, err := common.RandomBigInt(g.Params.Lm + g.Params.Lh + g.Params.Lstatzk)
	require.NoError(t, err)

	_, commit, err := s.CommitmentsFromSecrets(g, m, mRandomizer)
	require.NoError(t, err)
	proof := s.BuildProof(commit, big.NewInt(1234567))

	backup := new(big.Int).Set(proof.MResponse)
	proof.MResponse.Lsh(proof.MResponse, 2049)
	assert.False(t, s.VerifyProofStructure(g, proof))
	proof.MResponse = nil
	assert.False(t, s.VerifyProofStructure(g, proof))
	proof.MResponse = backup
	assert.True(t, s.VerifyProofStructure(g, proof))

	backup = new(big.Int).Set(proof.V5Response)
	proof.V5Response.Lsh(proof.V5Response, 2049)
	assert.False(t, s.VerifyProofStructure(g, proof))
	proof.V5Response = nil
	assert.False(t, s.VerifyProofStructure(g, proof))
	proof.V5Response = backup
	assert.True(t, s.VerifyProofStructure(g, proof))

	for i := range proof.Cs {
		backup = new(big.Int).Set(proof.Cs[i])
		proof.Cs[i].Lsh(proof.Cs[i], 2049)
		assert.False(t, s.VerifyProofStructure(g, proof))
		proof.Cs[i] = nil
		assert.False(t, s.VerifyProofStructure(g, proof))
		proof.Cs[i] = backup
		assert.True(t, s.VerifyProofStructure(g, proof))
	}

	for i := range proof.DResponses {
		backup = new(big.Int).Set(proof.DResponses[i])
		proof.DResponses[i].Lsh(proof.DResponses[i], 2049)
		assert.False(t, s.VerifyProofStructure(g, proof))
		proof.DResponses[i] = nil
		assert.False(t, s.VerifyProofStructure(g, proof))
		proof.DResponses[i] = backup
		assert.True(t, s.VerifyProofStructure(g, proof))
	}

	for i := range proof.VResponses {
		backup = new(big.Int).Set(proof.VResponses[i])
		proof.VResponses[i].Lsh(proof.VResponses[i], 2049)
		assert.False(t, s.VerifyProofStructure(g, proof))
		proof.VResponses[i] = nil
		assert.False(t, s.VerifyProofStructure(g, proof))
		proof.VResponses[i] = backup
		assert.True(t, s.VerifyProofStructure(g, proof))
	}

	backup = new(big.Int).Set(proof.Cs[len(proof.Cs)-1])
	proof.Cs = append(proof.Cs, big.NewInt(15))
	assert.False(t, s.VerifyProofStructure(g, proof))
	proof.Cs = proof.Cs[:len(proof.Cs)-2]
	assert.False(t, s.VerifyProofStructure(g, proof))
	proof.Cs = append(proof.Cs, backup)
	assert.True(t, s.VerifyProofStructure(g, proof))

	backup = new(big.Int).Set(proof.DResponses[len(proof.DResponses)-1])
	proof.DResponses = append(proof.DResponses, big.NewInt(15))
	assert.False(t, s.VerifyProofStructure(g, proof))
	proof.DResponses = proof.DResponses[:len(proof.DResponses)-2]
	assert.False(t, s.VerifyProofStructure(g, proof))
	proof.DResponses = append(proof.DResponses, backup)
	assert.True(t, s.VerifyProofStructure(g, proof))

	backup = new(big.Int).Set(proof.VResponses[len(proof.VResponses)-1])
	proof.VResponses = append(proof.VResponses, big.NewInt(15))
	assert.False(t, s.VerifyProofStructure(g, proof))
	proof.VResponses = proof.VResponses[:len(proof.VResponses)-2]
	assert.False(t, s.VerifyProofStructure(g, proof))
	proof.VResponses = append(proof.VResponses, backup)
	assert.True(t, s.VerifyProofStructure(g, proof))
}
