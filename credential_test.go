package credential

import (
	"math/big"
	"os"
	"testing"
)

var (
	sk *SecretKey
	pk *PublicKey
)

var (
	rValues []string = []string{"75350858539899247205099195870657569095662997908054835686827949842616918065279527697469302927032348256512990413925385972530386004430200361722733856287145745926519366823425418198189091190950415327471076288381822950611094023093577973125683837586451857056904547886289627214081538422503416179373023552964235386251",
		"16493273636283143082718769278943934592373185321248797185217530224336539646051357956879850630049668377952487166494198481474513387080523771033539152347804895674103957881435528189990601782516572803731501616717599698546778915053348741763191226960285553875185038507959763576845070849066881303186850782357485430766",
		"13291821743359694134120958420057403279203178581231329375341327975072292378295782785938004910295078955941500173834360776477803543971319031484244018438746973179992753654070994560440903251579649890648424366061116003693414594252721504213975050604848134539324290387019471337306533127861703270017452296444985692840",
		"86332479314886130384736453625287798589955409703988059270766965934046079318379171635950761546707334446554224830120982622431968575935564538920183267389540869023066259053290969633312602549379541830869908306681500988364676409365226731817777230916908909465129739617379202974851959354453994729819170838277127986187",
		"68324072803453545276056785581824677993048307928855083683600441649711633245772441948750253858697288489650767258385115035336890900077233825843691912005645623751469455288422721175655533702255940160761555155932357171848703103682096382578327888079229101354304202688749783292577993444026613580092677609916964914513",
		"65082646756773276491139955747051924146096222587013375084161255582716233287172212541454173762000144048198663356249316446342046266181487801411025319914616581971563024493732489885161913779988624732795125008562587549337253757085766106881836850538709151996387829026336509064994632876911986826959512297657067426387"}
	testAttributes = []*big.Int{
		new(big.Int).SetBytes([]byte("one")),
		new(big.Int).SetBytes([]byte("two")),
		new(big.Int).SetBytes([]byte("three")),
		new(big.Int).SetBytes([]byte("four"))}
)

func setupParameters() {
	p := s2big("10436034022637868273483137633548989700482895839559909621411910579140541345632481969613724849214412062500244238926015929148144084368427474551770487566048119")
	q := s2big("9204968012315139729618449685392284928468933831570080795536662422367142181432679739143882888540883909887054345986640656981843559062844656131133512640733759")

	n := s2big("96063359353814070257464989369098573470645843347358957127875426328487326540633303185702306359400766259130239226832166456957259123554826741975265634464478609571816663003684533868318795865194004795637221226902067194633407757767792795252414073029114153019362701793292862118990912516058858923030408920700061749321")
	S := s2big("68460510129747727135744503403370273952956360997532594630007762045745171031173231339034881007977792852962667675924510408558639859602742661846943843432940752427075903037429735029814040501385798095836297700111333573975220392538916785564158079116348699773855815825029476864341585033111676283214405517983188761136")
	Z := s2big("44579327840225837958738167571392618381868336415293109834301264408385784355849790902532728798897199236650711385876328647206143271336410651651791998475869027595051047904885044274040212624547595999947339956165755500019260290516022753290814461070607850420459840370288988976468437318992206695361417725670417150636")

	// Too bad there is no better way to have big int constants
	R := make([]*big.Int, len(rValues))
	for i, rv := range rValues {
		R[i], _ = new(big.Int).SetString(rv, 10)
	}

	sk = NewSecretKey(p, q)
	pk = NewPublicKey(n, Z, S, R)
}

func TestPrivateKey(t *testing.T) {
	if !sk.P.ProbablyPrime(20) {
		t.Error("p in secret key is not prime!")
	}
	if !sk.Q.ProbablyPrime(20) {
		t.Error("q in secret key is not prime!")
	}
	tmpP := new(big.Int).Mul(&sk.PPrime, bigTWO)
	tmpP.Add(tmpP, bigONE)
	if tmpP.Cmp(&sk.P) != 0 {
		t.Error("p = 2p' + 1 does not hold!")
	}
	tmpQ := new(big.Int).Mul(&sk.QPrime, bigTWO)
	tmpQ.Add(tmpQ, bigONE)
	if tmpQ.Cmp(&sk.Q) != 0 {
		t.Error("q = 2q' + 1 does not hold!")
	}
}

func TestPublicKey(t *testing.T) {
	r := new(big.Int).Mul(&sk.P, &sk.Q)
	if r.Cmp(&pk.N) != 0 {
		t.Error("p*q != n")
	}
}

func TestCLSignature(t *testing.T) {
	m := []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3)}
	sig, err := SignMessageBlock(sk, pk, m)
	if err != nil {
		t.Error(err)
	}
	if !sig.Verify(pk, m) {
		t.Error("CLSignature did not verify, whereas it should.")
	}

	m[0] = big.NewInt(1337)
	if sig.Verify(pk, m) {
		t.Error("CLSignature verifies, whereas it should not.")
	}
}

func TestClSignatureRandomize(t *testing.T) {
	m := []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3)}
	sig, err := SignMessageBlock(sk, pk, m)
	if err != nil {
		t.Error(err)
	}
	if !sig.Verify(pk, m) {
		t.Error("CLSignature did not verify, whereas it should.")
	}
	for i := 0; i < 10; i++ {
		sigRandomized := sig.Randomize(pk)
		if !sigRandomized.Verify(pk, m) {
			t.Error("Randomized CLSignature did not verify, whereas it should.")
		}
	}
}

func TestProofU(t *testing.T) {
	// context, _ := randomBigInt(pk.Params.Lh)
	// nonce1, _ := randomBigInt(pk.Params.Lstatzk)
	// secret, _ := randomBigInt(pk.Params.Lm)

	// b := NewBuilder2(pk, context, secret)
	// proofU := b.CreateProof(createChallenge(context, nonce1, b.Commit(secret)))

	// TODO: fix this! (Can we return a ProofU? Or add a Verify function to the interface?)
	// if !proofU.Verify(pk, context, nonce1) {
	// 	t.Error("ProofU does not verify, whereas it should.")
	// }
}

func TestProofULogged(t *testing.T) {

	context := s2big("34911926065354700717429826907189165808787187263593066036316982805908526740809")
	nonce1 := s2big("724811585564063105609243")
	c := s2big("4184045431748299802782143929438273256345760339041229271411466459902660986200")
	U := s2big("53941714038323323772993715692602421894514053229231925255570480167011458936488064431963770862062871590815370913733046166911453850329862473697478794938988248741580237664467927006089054091941563143176094050444799012171081539721321786755307076274602717003792794453593019124224828904640592766190733869209960398955")
	vPrimeResponse := s2big("930401833442556048954810956066821001094106683380918922610147216724718347679854246682690061274042716015957693675615113399347898060611144526167949042936228868420203309360695585386210327439216083389841383395698722832808268885873389302262079691644125050748391319832394519920382663304621540520277648619992590872190274152359156399474623649137315708728792245711389032617438368799004840694779408839779419604877135070624376537994035936")
	sResponse := s2big("59776396667523329313292302350278517468587673934875085337674938789292900859071752886820910103285722288747559744087880906618151651690169988337871960870439882357345503256963847251")

	proofU := &ProofU{u: U, c: c, vPrimeResponse: vPrimeResponse, sResponse: sResponse}

	if !proofU.Verify(pk, context, nonce1) {
		t.Error("ProofU (from constants) does not verify, whereas it should.")
	}
}

func TestCommitmentMessage(t *testing.T) {

	context, _ := randomBigInt(pk.Params.Lh)
	nonce1, _ := randomBigInt(pk.Params.Lstatzk)
	secret, _ := randomBigInt(pk.Params.Lm)

	b := NewBuilder(pk, context, secret)
	msg := b.CommitToSecretAndProve(nonce1)
	if !msg.Proofs.Verify([]*PublicKey{pk}, context, nonce1, false) {
		t.Error("Commitment message proof does not verify, whereas it should.")
	}
}

func TestProofS(t *testing.T) {
	// Silly commitment, content doesn't matter for this test
	exponent, _ := randomBigInt(pk.Params.Lm)
	U := new(big.Int).Exp(&pk.S, exponent, &pk.N)

	// Silly context
	context, _ := randomBigInt(pk.Params.Lh)

	// Nonce (normally from the credential recipient)
	nonce, _ := randomBigInt(pk.Params.Lstatzk)

	issuer := NewIssuer(sk, pk, context)
	sig, err := issuer.signCommitmentAndAttributes(U, testAttributes)
	if err != nil {
		t.Error(err)
	}

	proof := issuer.proveSignature(sig, nonce)

	if !proof.Verify(pk, sig, context, nonce) {
		t.Error("ProofS does not verify, whereas is should.")
	}

	// Silly nonce test
	if proof.Verify(pk, sig, context, big.NewInt(10)) {
		t.Error("ProofS verifies, whereas it should not (wrong nonce).")
	}

	// Silly context test
	if proof.Verify(pk, sig, big.NewInt(10), nonce) {
		t.Error("ProofS verifies, whereas it should not (wrong context).")
	}
}

func TestProofSLogged(t *testing.T) {
	context := s2big("34911926065354700717429826907189165808787187263593066036316982805908526740809")
	n2 := s2big("1424916368173409716606")

	// Signature
	A := s2big("66389313221915836241271893803869162372470096003861448260498566798077037255866372791540928160267561756794143545532118654736979223658343806335872047371607436291528588343320128898584874264796312130159695427439025355009934986408160536404163490935544221152821545871675088845781351195696518382628790514628112517886")
	e := s2big("259344723055062059907025491480697571938277889515152306249728583105665800713306759149981690559193987143012367913206299323899696942213235956742930207251663943512715842083759814664217")
	v := s2big("32427566863312925183262683355749521096160753564085736927716798279834745436154181827687524960554513739692930154573915901486008843583586162755818099731448281905764117842382407835789897633042765641230655956290191876265377547222981221260311549695231999461733778383779100992221748503727598149536948999564401095816377323412637286891625085960745712119714441272446053177642615033258689648568679017384011895908901362352242970432640019866501367925956123252426587516554347912178721773507440862343752105273189184247444400383")

	// Proof
	c := s2big("60359393410007276721785600209946099643760005142374188599509762410975853354415")
	eResponse := s2big("1139627737042307991725447845798004742853435356249558932466535799661640630812910641126155269500348608443317861800376689024557774460643901450316279085276256524076388421890909312661873221470626068394945683125859434135652717426417681918932528613003921792075852313319584079881881807505760375270399908999784672094")

	sig := &CLSignature{A: A, E: e, V: v}
	proof := &ProofS{c: c, eResponse: eResponse}

	if !proof.Verify(pk, sig, context, n2) {
		t.Error("ProofS (logged) does not verify, whereas it should.")
	}
}

func TestSignatureMessage(t *testing.T) {
	context, _ := randomBigInt(pk.Params.Lh)
	nonce1, _ := randomBigInt(pk.Params.Lstatzk)
	secret, _ := randomBigInt(pk.Params.Lm)

	b := NewBuilder(pk, context, secret)
	commitMsg := b.CommitToSecretAndProve(nonce1)

	issuer := NewIssuer(sk, pk, context)
	_, err := issuer.IssueSignature(commitMsg, testAttributes, nonce1)
	if err != nil {
		t.Error("Error in IssueSignature:", err)
	}
}

func TestFullIssuance(t *testing.T) {
	context, _ := randomBigInt(pk.Params.Lh)
	nonce1, _ := randomBigInt(pk.Params.Lstatzk)
	secret, _ := randomBigInt(pk.Params.Lm)

	b := NewBuilder(pk, context, secret)
	commitMsg := b.CommitToSecretAndProve(nonce1)

	issuer := NewIssuer(sk, pk, context)
	msg, err := issuer.IssueSignature(commitMsg, testAttributes, nonce1)
	if err != nil {
		t.Error("Error in IssueSignature:", err)
	}
	b.ConstructCredential(msg, testAttributes)
}

func TestShowingProof(t *testing.T) {
	signature, err := SignMessageBlock(sk, pk, testAttributes)
	if err != nil {
		t.Error("Error producing CL signature.")
	}
	cred := &IdemixCredential{Pk: pk, Attributes: testAttributes, Signature: signature}
	disclosed := []int{1, 2}

	context, _ := randomBigInt(pk.Params.Lh)
	nonce1, _ := randomBigInt(pk.Params.Lstatzk)

	proof := cred.CreateDisclosureProof(disclosed, context, nonce1)
	if !proof.Verify(pk, context, nonce1) {
		t.Error("Proof of disclosure did not verify, whereas it should.")
	}
}

func TestCombinedShowingProof(t *testing.T) {
	// signature1, err := SignMessageBlock(sk, pk, testAttributes)
	// if err != nil {
	// 	t.Error("Error producing CL signature.")
	// }
	// cred1 := &IdemixCredential{Pk: pk, Attributes: testAttributes, Signature: signature1}

	// signature2, err := SignMessageBlock(sk, pk, testAttributes)
	// if err != nil {
	// 	t.Error("Error producing CL signature.")
	// }
	// cred2 := &IdemixCredential{Pk: pk, Attributes: testAttributes, Signature: signature2}

	// context, _ := randomBigInt(pk.Params.Lh)
	// nonce1, _ := randomBigInt(pk.Params.Lstatzk)

	// TODO: here should the ProofList stuff go.

}

// A convenience function for initializing big integers from known correct (10
// base) strings. Use with care, errors are ignored.
func s2big(s string) (r *big.Int) {
	r, _ = new(big.Int).SetString(s, 10)
	return
}

func TestShowingProofLogged(t *testing.T) {
	nonce1 := s2big("356168310758183945030882")
	context := s2big("59317469690166962413036802769129097120995929488116634148207386064523180296869")

	c := s2big("92405256824458923934294175762399873039847432841647909261385804859937404075570")
	A := s2big("66467922530801909191099602528137141713616048447732479189179865050384832390931230033112445547628606292639430708552418462959456337530534055700746138057512598497120682196611341962749384189596253759402224308748002860890211498962735924481685975488607793795169788837476493253297353146422154392391732925567178805607")
	eResponse := s2big("44022597110989879399510333540268555303613344906583879371531630680320900347240418258690335759375210734514869637566864349585531295946323809")
	vResponse := s2big("26326301830460880582628741955953428491879823201714737915103888193625032953131902593859116395461541557845953939714765660366793552012359281854190756504190064959818584175057775414324351414234450208391534497565506441579960808534266557458251190151268682500197950418141493586125049371381626638554299245282498637246703583102656876690825544275995631773170789236920674341621008537679924624747222821679128060382072191284077393034573357698475000667180794116538132628586533009732462826119381931507809052573496513689222244701991737191273263148163121236326525677935993049602389899306007664212328515456044738278420")

	aResponses := map[int]*big.Int{
		0: s2big("55247823867049193571627241180110605447453053126985891402640532123848293918217459966028364637387399903283634100097425890971508590427350301193682412170041146212137866279677802531"),
	}

	aDisclosed := map[int]*big.Int{
		1: s2big("1100598411265"),
		2: s2big("43098508374675488371040117572049064979183030441504364"),
		3: s2big("4919409929397552454"),
	}

	proof1 := &ProofD{c: c, A: A, eResponse: eResponse, vResponse: vResponse, aResponses: aResponses, aDisclosed: aDisclosed}

	if !proof1.Verify(pk, context, nonce1) {
		t.Error("Proof of disclosure did not verify, whereas it should.")
	}

	aDisclosed[1] = s2big("123")
	proof2 := &ProofD{c: c, A: A, eResponse: eResponse, vResponse: vResponse, aResponses: aResponses, aDisclosed: aDisclosed}
	if proof2.Verify(pk, context, nonce1) {
		t.Error("Proof of disclosure verifies, whereas it should not.")
	}
}

func TestFullIssuanceAndShowing(t *testing.T) {
	context, _ := randomBigInt(pk.Params.Lh)
	nonce1, _ := randomBigInt(pk.Params.Lstatzk)
	secret, _ := randomBigInt(pk.Params.Lm)

	// Issuance
	builder := NewBuilder(pk, context, secret)
	commitMsg := builder.CommitToSecretAndProve(nonce1)
	issuer := NewIssuer(sk, pk, context)
	sigMsg, err := issuer.IssueSignature(commitMsg, testAttributes, nonce1)
	if err != nil {
		t.Error("Error in IssueSignature:", err)
	}

	cred, err := builder.ConstructCredential(sigMsg, testAttributes)
	if err != nil {
		t.Error("Error in credential construction:", err)
	}

	// Showing
	n1, _ := randomBigInt(pk.Params.Lstatzk)
	disclosed := []int{1, 2}

	proof := cred.CreateDisclosureProof(disclosed, context, n1)
	if !proof.Verify(pk, context, n1) {
		t.Error("Proof of disclosure does not verify, whereas it should.")
	}
}

func TestFullBoundIssuanceAndShowing(t *testing.T) {
	context, _ := randomBigInt(pk.Params.Lh)
	nonce1, _ := randomBigInt(pk.Params.Lstatzk)
	secret, _ := randomBigInt(pk.Params.Lm)

	// First create a credential
	cb1 := NewBuilder(pk, context, secret)
	commitMsg := cb1.CommitToSecretAndProve(nonce1)

	issuer1 := NewIssuer(sk, pk, context)
	ism, err := issuer1.IssueSignature(commitMsg, testAttributes, nonce1)
	if err != nil {
		t.Error("Error creating Issue Signature: ", err)
	}

	cred1, err := cb1.ConstructCredential(ism, testAttributes)
	if err != nil {
		t.Error("Error creating credential: ", err)
	}

	// Then create another credential based on the same credential with a partial
	// disclosure of the first credential.
	cb2 := NewBuilder(pk, context, secret)
	issuer2 := NewIssuer(sk, pk, context)

	prooflist := BuildProofList(pk.Params, context, nonce1, []ProofBuilder{cred1.CreateDisclosureProofBuilder([]int{1, 2}), cb2})

	commitMsg2 := cb2.CreateIssueCommitmentMessage(prooflist)

	if !commitMsg2.Proofs.Verify([]*PublicKey{pk, pk}, context, nonce1, true) {
		t.Error("Proofs in commit message do not verify!")
	}

	msg, err := issuer2.IssueSignature(commitMsg2, testAttributes, nonce1)
	if err != nil {
		t.Error("Error creating Issue Signature: ", err)
	}
	cred2, err := cb2.ConstructCredential(msg, testAttributes)
	if err != nil {
		t.Error("Error creating credential:", err)
	}

	// Showing
	nonce1s, _ := randomBigInt(pk.Params.Lstatzk)
	disclosedAttributes := []int{1, 3}
	proof := cred2.CreateDisclosureProof(disclosedAttributes, context, nonce1s)
	if !proof.Verify(pk, context, nonce1s) {
		t.Error("Proof of disclosure did not verify, whereas it should.")
	}

}

func TestMain(m *testing.M) {
	setupParameters()
	os.Exit(m.Run())
}
