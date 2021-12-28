package zkproof_test

import (
	"sync/atomic"
	"testing"

	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/gabikeys"
	"github.com/privacybydesign/gabi/keyproof"
	"github.com/privacybydesign/gabi/zkproof"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	testPubK1, testPubK2 *gabikeys.PublicKey
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
	xmlPubKey2 = `<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<IssuerPublicKey xmlns="http://www.zurich.ibm.com/security/idemix">
   <Counter>0</Counter>
   <ExpiryDate>1700000000</ExpiryDate>
   <Elements>
      <n>139074042953200450756577573716087081093125755047959835310375736112120174400606581560965321655328552305330880412762069205250416578144697608952814011140599345836848582980530546248138864212612840364874312923816166397038873282769982501212640794354680085233677961149767121970163329979736254573701512654860500893293</n>
      <Z>42734451137499583379659313067721582376262445005019898840924212896341861721344880887076647548954065511016613532399873561753770596699950716884806217151189571670373798409647535613026097425988280287210414508240665780830389936353108210951728065700426436951835936702999674654289936428229982569295227091726810208504</Z>
      <S>126829853005972541969086001260986453668465797381061677444000682968013144068393822597398725937194773101762625079278987532636583109409344117202136151661601603097793537754186056937000748076167489862365768508194908399597522777250699581364596246205795577663373872577816687658275462617741670486719685398698263686551</S>
	  <G>43215325590379490852400435325847836613513274803460964568083232110934910151335113918829588414147781676586145312074043749201037447486205927144941119404243266454032858201713735324770837218773739346063812751896736791478531103409536739098007890723770126159814845238386299865793353073058783010002988453373168625327</G>
	  <H>61146634020942775692657595021461289090915429142715194304483397998858712705680675945417056124974172620475325240482216550923967273908399017396442709297466408094303826941548068001214817725191465207971123378222070812822903173820970991987799984521470178624084174451047081964996323127069438975310975798326710264763</H>
      <Bases num="3">
         <Base_0>40338259065130185314739658157310048192093670364817714952600609624607192408306024366086231626356707587756324374416236635377699775899652135471760526981946419799164489776538365542337621218846077191008645978143565824845696569002709540904092145615635620069766477253299607733404658708555482236387943774145644107155</Base_0>
         <Base_1>87294590926764077882765166008319250454824581316986036240948880310176122397314769805046534571305547053810590771663913726538715272940723444205499052940110064720613691982665763438729000435763267929115086526907175748438671858290067669579138779857489538782552512452684382063115068635634905118784884820252032788713</Base_1>
         <Base_2>45112630188085238903069069511798663932075329935779132383847263380203067284915894010441781813845184965705336439320602592823045182968796600558189004025038858823202813711551231906042036283775342496224178435309129468488081668058550719904823188068692199073681725733882486184478432125414991289211704253384344158081</Base_2>
      </Bases>
   </Elements>
   <Features>
      <Epoch length="432000"></Epoch>
   </Features>
</IssuerPublicKey>`
)

type RepTestSecret struct {
	secrets     map[string]*big.Int
	randomizers map[string]*big.Int
}

func (rs *RepTestSecret) Secret(name string) *big.Int {
	return rs.secrets[name]
}

func (rs *RepTestSecret) Randomizer(name string) *big.Int {
	return rs.randomizers[name]
}

type RepTestProof struct {
	results map[string]*big.Int
}

func (rp *RepTestProof) ProofResult(name string) *big.Int {
	return rp.results[name]
}

type RepTestCommit struct {
	commits map[string]*big.Int
}

func (rc *RepTestCommit) Base(name string) *big.Int {
	return rc.commits[name]
}
func (rc *RepTestCommit) Exp(ret *big.Int, name string, exp, P *big.Int) bool {
	base := rc.Base(name)
	if base == nil {
		return false
	}
	ret.Exp(base, exp, P)
	return true
}
func (rc *RepTestCommit) Names() (ret []string) {
	for name := range rc.commits {
		ret = append(ret, name)
	}
	return
}

func TestQrRepresentationProofBasics(t *testing.T) {
	setupParameters(t)

	var s zkproof.QrRepresentationProofStructure
	s.Lhs = []zkproof.LhsContribution{
		{Base: "x", Power: big.NewInt(1)},
	}
	s.Rhs = []zkproof.RhsContribution{
		{Base: "S", Secret: "x", Power: 1},
	}

	var secret RepTestSecret
	secret.secrets = map[string]*big.Int{"x": big.NewInt(10)}
	secret.randomizers = map[string]*big.Int{"x": big.NewInt(15)}

	var commit RepTestCommit
	commit.commits = map[string]*big.Int{"x": new(big.Int).Exp(testPubK1.S, secret.secrets["x"], testPubK1.N)}

	var proof RepTestProof
	proof.results = map[string]*big.Int{"x": big.NewInt(25)}

	bases := zkproof.NewBaseMerge(testPubK1, &commit)

	listSecrets := s.CommitmentsFromSecrets(testPubK1, []*big.Int{}, &bases, &secret)
	listProofs := s.CommitmentsFromProof(testPubK1, []*big.Int{}, big.NewInt(1), &bases, &proof)

	assert.Equal(t, listSecrets, listProofs, "commitment lists different")
}

func TestQrRepresentationProofComplex(t *testing.T) {
	setupParameters(t)

	var s zkproof.QrRepresentationProofStructure
	s.Lhs = []zkproof.LhsContribution{
		{Base: "c", Power: big.NewInt(4)},
	}
	s.Rhs = []zkproof.RhsContribution{
		{Base: "S", Secret: "x", Power: 2},
		{Base: "Z", Secret: "y", Power: 3},
	}

	var secret RepTestSecret
	secret.secrets = map[string]*big.Int{
		"x": big.NewInt(4),
		"y": big.NewInt(16),
	}
	secret.randomizers = map[string]*big.Int{
		"x": big.NewInt(12),
		"y": big.NewInt(21),
	}

	var commit RepTestCommit
	commit.commits = map[string]*big.Int{
		"c": new(big.Int).Mod(
			new(big.Int).Mul(
				new(big.Int).Exp(testPubK1.S, big.NewInt(2), testPubK1.N),
				new(big.Int).Exp(testPubK1.Z, big.NewInt(12), testPubK1.N)),
			testPubK1.N),
	}

	var proof RepTestProof
	proof.results = map[string]*big.Int{
		"x": big.NewInt(20),
		"y": big.NewInt(53),
	}

	bases := zkproof.NewBaseMerge(testPubK1, &commit)

	listSecrets := s.CommitmentsFromSecrets(testPubK1, []*big.Int{}, &bases, &secret)
	listProofs := s.CommitmentsFromProof(testPubK1, []*big.Int{}, big.NewInt(2), &bases, &proof)

	assert.Equal(t, listSecrets, listProofs, "Commitment lists different")
}

func setupParameters(t *testing.T) {
	var err error
	testPubK1, err = gabikeys.NewPublicKeyFromXML(xmlPubKey1)
	require.NoError(t, err)
	testPubK2, err = gabikeys.NewPublicKeyFromXML(xmlPubKey2)
	require.NoError(t, err)
}

func TestPkGroupBase(t *testing.T) {
	setupParameters(t)

	pk1 := testPubK1

	assert.Equal(t, pk1.Base("G"), pk1.G)
	assert.Equal(t, pk1.Base("H"), pk1.H)
	assert.Equal(t, pk1.Base("S"), pk1.S)
	assert.Equal(t, pk1.Base("Z"), pk1.Z)
	assert.Equal(t, pk1.Base("G0"), (*big.Int)(nil))
	assert.Equal(t, pk1.Base("H0"), (*big.Int)(nil))
	assert.Equal(t, pk1.Base("S0"), (*big.Int)(nil))
	assert.Equal(t, pk1.Base("Z0"), (*big.Int)(nil))
	assert.Equal(t, pk1.Base("R0"), pk1.R[0])
	assert.Equal(t, pk1.Base("R1"), pk1.R[1])
	assert.Equal(t, pk1.Base("R2"), pk1.R[2])
	assert.Equal(t, pk1.Base("R3"), pk1.R[3])
	assert.Equal(t, pk1.Base("R4"), pk1.R[4])
	assert.Equal(t, pk1.Base("R5"), pk1.R[5])
	assert.Equal(t, pk1.Base("R-1"), (*big.Int)(nil))
	assert.Equal(t, pk1.Base("R6"), (*big.Int)(nil))
	assert.Equal(t, pk1.Base("Rabc"), (*big.Int)(nil))
	assert.Equal(t, pk1.Base("sjdfy"), (*big.Int)(nil))

	pk2 := testPubK2

	assert.Equal(t, pk2.Base("G"), pk2.G)
	assert.Equal(t, pk2.Base("H"), pk2.H)
	assert.Equal(t, pk2.Base("S"), pk2.S)
	assert.Equal(t, pk2.Base("Z"), pk2.Z)
	assert.Equal(t, pk2.Base("G0"), (*big.Int)(nil))
	assert.Equal(t, pk2.Base("H0"), (*big.Int)(nil))
	assert.Equal(t, pk2.Base("S0"), (*big.Int)(nil))
	assert.Equal(t, pk2.Base("Z0"), (*big.Int)(nil))
	assert.Equal(t, pk2.Base("R0"), pk2.R[0])
	assert.Equal(t, pk2.Base("R1"), pk2.R[1])
	assert.Equal(t, pk2.Base("R2"), pk2.R[2])
	assert.Equal(t, pk2.Base("R-1"), (*big.Int)(nil))
	assert.Equal(t, pk2.Base("R3"), (*big.Int)(nil))
	assert.Equal(t, pk2.Base("Rfjg"), (*big.Int)(nil))
	assert.Equal(t, pk2.Base("dofp"), (*big.Int)(nil))
}

func TestPkGroupExp(t *testing.T) {
	setupParameters(t)

	ret := new(big.Int)

	pk1 := testPubK1

	assert.False(t, pk1.Exp(ret, "G", big.NewInt(12), pk1.N))
	assert.False(t, pk1.Exp(ret, "H", big.NewInt(13), pk1.N))
	assert.True(t, pk1.Exp(ret, "S", big.NewInt(14), pk1.N))
	assert.Equal(t, new(big.Int).Exp(pk1.S, big.NewInt(14), pk1.N), ret)
	assert.True(t, pk1.Exp(ret, "Z", big.NewInt(15), pk1.N))
	assert.Equal(t, new(big.Int).Exp(pk1.Z, big.NewInt(15), pk1.N), ret)
	assert.False(t, pk1.Exp(ret, "G0", big.NewInt(16), pk1.N))
	assert.False(t, pk1.Exp(ret, "H0", big.NewInt(17), pk1.N))
	assert.False(t, pk1.Exp(ret, "S0", big.NewInt(18), pk1.N))
	assert.False(t, pk1.Exp(ret, "Z0", big.NewInt(19), pk1.N))
	assert.True(t, pk1.Exp(ret, "R0", big.NewInt(20), pk1.N))
	assert.Equal(t, new(big.Int).Exp(pk1.R[0], big.NewInt(20), pk1.N), ret)
	assert.True(t, pk1.Exp(ret, "R1", big.NewInt(21), pk1.N))
	assert.Equal(t, new(big.Int).Exp(pk1.R[1], big.NewInt(21), pk1.N), ret)
	assert.True(t, pk1.Exp(ret, "R2", big.NewInt(22), pk1.N))
	assert.Equal(t, new(big.Int).Exp(pk1.R[2], big.NewInt(22), pk1.N), ret)
	assert.True(t, pk1.Exp(ret, "R3", big.NewInt(23), pk1.N))
	assert.Equal(t, new(big.Int).Exp(pk1.R[3], big.NewInt(23), pk1.N), ret)
	assert.True(t, pk1.Exp(ret, "R4", big.NewInt(24), pk1.N))
	assert.Equal(t, new(big.Int).Exp(pk1.R[4], big.NewInt(24), pk1.N), ret)
	assert.True(t, pk1.Exp(ret, "R5", big.NewInt(25), pk1.N))
	assert.Equal(t, new(big.Int).Exp(pk1.R[5], big.NewInt(25), pk1.N), ret)
	assert.False(t, pk1.Exp(ret, "R-1", big.NewInt(26), pk1.N))
	assert.False(t, pk1.Exp(ret, "R6", big.NewInt(27), pk1.N))
	assert.False(t, pk1.Exp(ret, "Rabc", big.NewInt(28), pk1.N))
	assert.False(t, pk1.Exp(ret, "sjdfy", big.NewInt(29), pk1.N))

	pk2 := testPubK2

	assert.True(t, pk2.Exp(ret, "G", big.NewInt(12), pk2.N))
	assert.Equal(t, new(big.Int).Exp(pk2.G, big.NewInt(12), pk2.N), ret)
	assert.True(t, pk2.Exp(ret, "H", big.NewInt(13), pk2.N))
	assert.Equal(t, new(big.Int).Exp(pk2.H, big.NewInt(13), pk2.N), ret)
	assert.True(t, pk2.Exp(ret, "S", big.NewInt(14), pk2.N))
	assert.Equal(t, new(big.Int).Exp(pk2.S, big.NewInt(14), pk2.N), ret)
	assert.True(t, pk2.Exp(ret, "Z", big.NewInt(15), pk2.N))
	assert.Equal(t, new(big.Int).Exp(pk2.Z, big.NewInt(15), pk2.N), ret)
	assert.False(t, pk2.Exp(ret, "G0", big.NewInt(16), pk2.N))
	assert.False(t, pk2.Exp(ret, "H0", big.NewInt(17), pk2.N))
	assert.False(t, pk2.Exp(ret, "S0", big.NewInt(18), pk2.N))
	assert.False(t, pk2.Exp(ret, "Z0", big.NewInt(19), pk2.N))
	assert.True(t, pk2.Exp(ret, "R0", big.NewInt(20), pk2.N))
	assert.Equal(t, new(big.Int).Exp(pk2.R[0], big.NewInt(20), pk2.N), ret)
	assert.True(t, pk2.Exp(ret, "R1", big.NewInt(21), pk2.N))
	assert.Equal(t, new(big.Int).Exp(pk2.R[1], big.NewInt(21), pk2.N), ret)
	assert.True(t, pk2.Exp(ret, "R2", big.NewInt(22), pk2.N))
	assert.Equal(t, new(big.Int).Exp(pk2.R[2], big.NewInt(22), pk2.N), ret)
	assert.False(t, pk2.Exp(ret, "R-1", big.NewInt(26), pk2.N))
	assert.False(t, pk2.Exp(ret, "R6", big.NewInt(27), pk2.N))
	assert.False(t, pk2.Exp(ret, "Rabc", big.NewInt(28), pk2.N))
	assert.False(t, pk2.Exp(ret, "sjdfy", big.NewInt(29), pk2.N))
}

func TestPkGroupNames(t *testing.T) {
	setupParameters(t)

	pk1 := testPubK1
	assert.ElementsMatch(t, []string{"S", "Z", "R0", "R1", "R2", "R3", "R4", "R5"}, pk1.Names())

	pk2 := testPubK2
	assert.ElementsMatch(t, []string{"S", "Z", "G", "H", "R0", "R1", "R2"}, pk2.Names())
}

func TestRepresentationProofBasics(t *testing.T) {
	g, gok := zkproof.BuildGroup(big.NewInt(47))
	require.True(t, gok, "Failed to setup group for Representation proof testing")

	keyproof.Follower.(*TestFollower).count = 0

	var s zkproof.RepresentationProofStructure
	s.Lhs = []zkproof.LhsContribution{
		zkproof.LhsContribution{"x", big.NewInt(1)},
	}
	s.Rhs = []zkproof.RhsContribution{
		zkproof.RhsContribution{"g", "x", 1},
	}

	var secret RepTestSecret
	secret.secrets = map[string]*big.Int{"x": big.NewInt(10)}
	secret.randomizers = map[string]*big.Int{"x": big.NewInt(15)}

	var commit RepTestCommit
	commit.commits = map[string]*big.Int{"x": new(big.Int).Exp(g.G, secret.secrets["x"], g.P)}

	var proof RepTestProof
	proof.results = map[string]*big.Int{"x": big.NewInt(5)}

	bases := zkproof.NewBaseMerge(&g, &commit)

	listSecrets := s.CommitmentsFromSecrets(g, []*big.Int{}, &bases, &secret)

	assert.Equal(t, len(listSecrets), s.NumCommitments(), "NumCommitments is off")
	assert.Equal(t, int(keyproof.Follower.(*TestFollower).count), s.NumRangeProofs(), "Logging is off GenerateCommitmentsFromSecrets")
	keyproof.Follower.(*TestFollower).count = 0

	listProofs := s.CommitmentsFromProof(g, []*big.Int{}, big.NewInt(1), &bases, &proof)

	assert.Equal(t, int(keyproof.Follower.(*TestFollower).count), s.NumRangeProofs(), "Logging is off on GenerateCommitmentsFromProof")
	assert.True(t, s.IsTrue(g, &bases, &secret), "Incorrect rejection of truth")
	assert.Equal(t, listSecrets, listProofs, "commitment lists different")
}

func TestRepresentationProofComplex(t *testing.T) {
	g, gok := zkproof.BuildGroup(big.NewInt(47))
	require.True(t, gok, "Failed to setup group for Representation proof testing")

	var s zkproof.RepresentationProofStructure
	s.Lhs = []zkproof.LhsContribution{
		zkproof.LhsContribution{"c", big.NewInt(4)},
	}
	s.Rhs = []zkproof.RhsContribution{
		zkproof.RhsContribution{"g", "x", 2},
		zkproof.RhsContribution{"h", "y", 1},
	}

	keyproof.Follower.(*TestFollower).count = 0

	var secret RepTestSecret
	secret.secrets = map[string]*big.Int{
		"x": big.NewInt(4),
		"y": big.NewInt(2),
	}
	secret.randomizers = map[string]*big.Int{
		"x": big.NewInt(12),
		"y": big.NewInt(21),
	}

	var commit RepTestCommit
	commit.commits = map[string]*big.Int{
		"c": new(big.Int).Mod(
			new(big.Int).Mul(
				new(big.Int).Exp(g.G, big.NewInt(2), g.P),
				new(big.Int).Exp(g.H, big.NewInt(12), g.P)),
			g.P),
	}

	var proof RepTestProof
	proof.results = map[string]*big.Int{
		"x": big.NewInt(4),
		"y": big.NewInt(17),
	}

	bases := zkproof.NewBaseMerge(&g, &commit)

	listSecrets := s.CommitmentsFromSecrets(g, []*big.Int{}, &bases, &secret)

	assert.Equal(t, len(listSecrets), s.NumCommitments(), "NumCommitments is off")
	assert.Equal(t, int(keyproof.Follower.(*TestFollower).count), s.NumRangeProofs(), "Logging is off GenerateCommitmentsFromSecrets")
	keyproof.Follower.(*TestFollower).count = 0

	listProofs := s.CommitmentsFromProof(g, []*big.Int{}, big.NewInt(2), &bases, &proof)

	assert.Equal(t, int(keyproof.Follower.(*TestFollower).count), s.NumRangeProofs(), "Logging is off on GenerateCommitmentsFromProof")
	assert.True(t, s.IsTrue(g, &bases, &secret), "Incorrect rejection of truth")
	assert.Equal(t, listSecrets, listProofs, "Commitment lists different")
}

type TestFollower struct {
	count int64
}

func (_ *TestFollower) StepStart(desc string, intermediates int) {}

func (t *TestFollower) Tick() {
	atomic.AddInt64(&t.count, 1)
}

func (t *TestFollower) StepDone() {}

func init() {
	keyproof.Follower = &TestFollower{}
}
