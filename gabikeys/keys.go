package gabikeys

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strconv"
	"time"

	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/internal/common"
	"github.com/privacybydesign/gabi/safeprime"
	"github.com/privacybydesign/gabi/signed"

	"github.com/go-errors/errors"
)

type (
	// PublicKey represents an issuer's public key.
	PublicKey struct {
		XMLName     xml.Name    `xml:"http://www.zurich.ibm.com/security/idemix IssuerPublicKey"`
		Counter     uint        `xml:"Counter"`
		ExpiryDate  int64       `xml:"ExpiryDate"`
		N           *big.Int    `xml:"Elements>n"` // Modulus n
		Z           *big.Int    `xml:"Elements>Z"` // Generator Z
		S           *big.Int    `xml:"Elements>S"` // Generator S
		G           *big.Int    `xml:"Elements>G"` // Generator G for revocation
		H           *big.Int    `xml:"Elements>H"` // Generator H for revocation
		R           Bases       `xml:"Elements>Bases"`
		EpochLength EpochLength `xml:"Features"`
		ECDSAString string      `xml:"ECDSA,omitempty"`

		ECDSA  *ecdsa.PublicKey  `xml:"-"`
		Params *SystemParameters `xml:"-"`
		Issuer string            `xml:"-"`
	}

	// PrivateKey represents an issuer's private key.
	PrivateKey struct {
		XMLName     xml.Name `xml:"http://www.zurich.ibm.com/security/idemix IssuerPrivateKey"`
		Counter     uint     `xml:"Counter"`
		ExpiryDate  int64    `xml:"ExpiryDate"`
		P           *big.Int `xml:"Elements>p"`
		Q           *big.Int `xml:"Elements>q"`
		PPrime      *big.Int `xml:"Elements>pPrime"`
		QPrime      *big.Int `xml:"Elements>qPrime"`
		ECDSAString string   `xml:"ECDSA,omitempty"`

		N     *big.Int          `xml:"-"`
		ECDSA *ecdsa.PrivateKey `xml:"-"`
		Order *big.Int          `xml:"-"`
	}

	Bases []*big.Int

	EpochLength int
)

const (
	//XMLHeader can be a used as the XML header when writing keys in XML format.
	XMLHeader = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n"
	// DefaultEpochLength is the default epoch length for public keys.
	DefaultEpochLength = 432000
)

// NewPrivateKey creates a new issuer private key using the provided parameters.
func NewPrivateKey(p, q *big.Int, ecdsa string, counter uint, expiryDate time.Time) (*PrivateKey, error) {
	sk := PrivateKey{
		P:           p,
		Q:           q,
		N:           new(big.Int).Mul(p, q),
		PPrime:      new(big.Int).Rsh(p, 1),
		QPrime:      new(big.Int).Rsh(q, 1),
		Counter:     counter,
		ExpiryDate:  expiryDate.Unix(),
		ECDSAString: ecdsa,
	}

	sk.Order = new(big.Int).Mul(sk.PPrime, sk.QPrime)
	if err := sk.parseRevocationKey(); err != nil {
		return nil, err
	}

	return &sk, nil
}

// NewPrivateKeyFromXML creates a new issuer private key using the XML data
// provided.
func NewPrivateKeyFromXML(xmlInput string, demo bool) (*PrivateKey, error) {
	privk := &PrivateKey{}
	err := xml.Unmarshal([]byte(xmlInput), privk)
	if err != nil {
		return nil, err
	}

	if !demo {
		// Do some sanity checks on the key data
		if err := privk.Validate(); err != nil {
			return nil, err
		}
	}

	privk.N = new(big.Int).Mul(privk.P, privk.Q)
	privk.Order = new(big.Int).Mul(privk.PPrime, privk.QPrime)
	if err := privk.parseRevocationKey(); err != nil {
		return nil, err
	}

	return privk, nil
}

// NewPrivateKeyFromFile creates a new issuer private key from an XML file.
func NewPrivateKeyFromFile(filename string, demo bool) (*PrivateKey, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	b, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}

	return NewPrivateKeyFromXML(string(b), demo)
}

func (privk *PrivateKey) Validate() error {
	if new(big.Int).Rsh(new(big.Int).Sub(privk.P, big.NewInt(1)), 1).Cmp(privk.PPrime) != 0 {
		return errors.New("Incompatible values for P and P'")
	}
	if new(big.Int).Rsh(new(big.Int).Sub(privk.Q, big.NewInt(1)), 1).Cmp(privk.QPrime) != 0 {
		return errors.New("Incompatible values for Q and Q'")
	}
	if !safeprime.ProbablySafePrime(privk.P, 40) {
		return errors.New("P is not a safe prime")
	}
	if !safeprime.ProbablySafePrime(privk.Q, 40) {
		return errors.New("Q is not a safe prime")
	}
	return nil
}

// Print prints the key to stdout.
func (privk *PrivateKey) Print() error {
	_, err := privk.WriteTo(os.Stdout)
	return err
}

// WriteTo writes the XML-serialized public key to the given writer.
func (privk *PrivateKey) WriteTo(writer io.Writer) (int64, error) {
	// Write the standard XML header
	numHeaderBytes, err := writer.Write([]byte(XMLHeader))
	if err != nil {
		return 0, err
	}

	// And the actual XML body (with indentation)
	b, err := xml.MarshalIndent(privk, "", "   ")
	if err != nil {
		return int64(numHeaderBytes), err
	}
	numBodyBytes, err := writer.Write(b)
	return int64(numHeaderBytes + numBodyBytes), err
}

// WriteToFile writes the private key to an XML file. If any existing file with
// the same filename should be overwritten, set forceOverwrite to true.
func (privk *PrivateKey) WriteToFile(filename string, forceOverwrite bool) (int64, error) {
	var f *os.File
	var err error
	if forceOverwrite {
		f, err = os.Create(filename)
	} else {
		// This should return an error if the file already exists
		f, err = os.OpenFile(filename, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	}
	if err != nil {
		return 0, err
	}
	defer f.Close()

	return privk.WriteTo(f)
}

func (privk *PrivateKey) parseRevocationKey() error {
	if privk.ECDSA != nil || !privk.RevocationSupported() {
		return nil
	}
	bts, err := base64.StdEncoding.DecodeString(privk.ECDSAString)
	if err != nil {
		return err
	}
	key, err := signed.UnmarshalPrivateKey(bts)
	if err != nil {
		return err
	}
	privk.ECDSA = key
	return nil
}

func (privk *PrivateKey) RevocationSupported() bool {
	return len(privk.ECDSAString) > 0
}

func GenerateRevocationKeypair(privk *PrivateKey, pubk *PublicKey) error {
	if pubk.RevocationSupported() || privk.RevocationSupported() {
		return errors.New("revocation parameters already present")
	}

	key, err := signed.GenerateKey()
	if err != nil {
		return err
	}
	dsabts, err := signed.MarshalPrivateKey(key)
	if err != nil {
		return err
	}
	pubdsabts, err := signed.MarshalPublicKey(&key.PublicKey)
	if err != nil {
		return err
	}

	privk.ECDSAString = base64.StdEncoding.EncodeToString(dsabts)
	privk.ECDSA = key
	pubk.ECDSAString = base64.StdEncoding.EncodeToString(pubdsabts)
	pubk.ECDSA = &key.PublicKey
	pubk.G = common.RandomQR(pubk.N)
	pubk.H = common.RandomQR(pubk.N)

	return nil
}

// NewPublicKey creates and returns a new public key based on the provided parameters.
func NewPublicKey(N, Z, S, G, H *big.Int, R []*big.Int, ecdsa string, counter uint, expiryDate time.Time) (*PublicKey, error) {
	pk := &PublicKey{
		Counter:     counter,
		ExpiryDate:  expiryDate.Unix(),
		N:           N,
		Z:           Z,
		S:           S,
		R:           R,
		G:           G,
		H:           H,
		EpochLength: DefaultEpochLength,
		Params:      DefaultSystemParameters[N.BitLen()],
		ECDSAString: ecdsa,
	}

	if err := pk.parseRevocationKey(); err != nil {
		return nil, err
	}
	return pk, nil
}

// NewPublicKeyFromBytes creates a new issuer public key using the XML data
// provided.
func NewPublicKeyFromBytes(bts []byte) (*PublicKey, error) {
	// TODO: this might fail in the future. The DefaultSystemParameters and the
	// public key might not match!
	pubk := &PublicKey{}
	err := xml.Unmarshal(bts, pubk)
	if err != nil {
		return nil, err
	}
	keylength := pubk.N.BitLen()
	if sysparam, ok := DefaultSystemParameters[keylength]; ok {
		pubk.Params = sysparam
	} else {
		return nil, fmt.Errorf("Unknown keylength %d", keylength)
	}
	if err = pubk.parseRevocationKey(); err != nil {
		return nil, err
	}
	return pubk, nil
}

func NewPublicKeyFromXML(xmlInput string) (*PublicKey, error) {
	return NewPublicKeyFromBytes([]byte(xmlInput))
}

// NewPublicKeyFromFile creates a new issuer public key from an XML file.
func NewPublicKeyFromFile(filename string) (*PublicKey, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	pubk := &PublicKey{}

	b, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}

	err = xml.Unmarshal(b, pubk)
	if err != nil {
		return nil, err
	}
	pubk.Params = DefaultSystemParameters[pubk.N.BitLen()]
	if err = pubk.parseRevocationKey(); err != nil {
		return nil, err
	}
	return pubk, nil
}

func (pubk *PublicKey) parseRevocationKey() error {
	if pubk.ECDSA != nil || !pubk.RevocationSupported() {
		return nil
	}
	bts, err := base64.StdEncoding.DecodeString(pubk.ECDSAString)
	if err != nil {
		return err
	}
	dsakey, err := signed.UnmarshalPublicKey(bts)
	if err != nil {
		return err
	}
	pubk.ECDSA = dsakey
	return nil
}

func (pubk *PublicKey) RevocationSupported() bool {
	return pubk.G != nil && pubk.H != nil && len(pubk.ECDSAString) > 0
}

// Print prints the key to stdout.
func (pubk *PublicKey) Print() error {
	_, err := pubk.WriteTo(os.Stdout)
	return err
}

// WriteTo writes the XML-serialized public key to the given writer.
func (pubk *PublicKey) WriteTo(writer io.Writer) (int64, error) {
	// Write the standard XML header
	numHeaderBytes, err := writer.Write([]byte(XMLHeader))
	if err != nil {
		return 0, err
	}

	// And the actual XML body (with indentation)
	b, err := xml.MarshalIndent(pubk, "", "   ")
	if err != nil {
		return int64(numHeaderBytes), err
	}
	numBodyBytes, err := writer.Write(b)
	return int64(numHeaderBytes + numBodyBytes), err
}

// WriteToFile writes the public key to an XML file. If any existing file with
// the same filename should be overwritten, set forceOverwrite to true.
func (pubk *PublicKey) WriteToFile(filename string, forceOverwrite bool) (int64, error) {
	var f *os.File
	var err error
	if forceOverwrite {
		f, err = os.Create(filename)
	} else {
		// This should return an error if the file already exists
		f, err = os.OpenFile(filename, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0644)
	}
	if err != nil {
		return 0, err
	}
	defer f.Close()

	return pubk.WriteTo(f)
}

// findMatch returns the first element of safeprimes that makes a suitable pair with p:
// p*q has the required bith length and p != q mod 8.
func findMatch(safeprimes []*big.Int, param *SystemParameters, p *big.Int,
	n, pMod8, qMod8 *big.Int, // temp vars allocated by caller
) *big.Int {
	for _, q := range safeprimes {
		if uint(n.Mul(p, q).BitLen()) == param.Ln && pMod8.Mod(p, big.NewInt(8)).Cmp(qMod8.Mod(q, big.NewInt(8))) != 0 {
			return q
		}
	}
	return nil
}

func generateSafePrimePair(param *SystemParameters) (*big.Int, *big.Int, error) {
	primeSize := param.Ln / 2

	// Declare and allocate all vars outside the loop and outside the helper function above
	stop := make(chan struct{})
	safeprimes := make([]*big.Int, 0, 10) // store all generated safe primes until we find a suitable pair
	pPrime, pPrimeMod8, pMod8, qMod8, n := new(big.Int), new(big.Int), new(big.Int), new(big.Int), new(big.Int)
	var p, q *big.Int
	var err error

	// Start generating safe primes
	ints, errs := safeprime.GenerateConcurrent(int(primeSize), stop)

	// Receive safe prime results in a loop, until we have a suitable pair of safe primes.
loop: // we need this label to continue the for loop from within the select below
	for {
		select { // wait for and then handle an incoming bigint or error, whichever comes first

		case p = <-ints:
			pPrimeMod8.Mod(pPrime.Rsh(p, 1), big.NewInt(8))
			// p is our candidate safe prime, set p' = (p-1)/2. Check that p' mod 8 != 1
			if pPrimeMod8.Cmp(big.NewInt(1)) == 0 {
				continue loop
			}
			// If we have earlier found other candidates, see if any pair of them fits all requirements
			if q = findMatch(safeprimes, param, p, n, pMod8, qMod8); len(safeprimes) == 0 || q == nil {
				safeprimes = append(safeprimes, p) // include p as it might match with future safe primes
				continue loop
			}
			close(stop) // We have enough, stop safeprime.GenerateConcurrent()
			return p, q, nil

		case err = <-errs:
			close(stop) // Something went wrong during safe prime generation, abort
			return nil, nil, err

		}
	}
}

// GenerateKeyPair generates a private/public keypair for an Issuer
func GenerateKeyPair(param *SystemParameters, numAttributes int, counter uint, expiryDate time.Time) (*PrivateKey, *PublicKey, error) {
	p, q, err := generateSafePrimePair(param)
	if err != nil {
		return nil, nil, err
	}

	priv := &PrivateKey{
		P:          p,
		Q:          q,
		N:          new(big.Int).Mul(p, q),
		PPrime:     new(big.Int).Rsh(p, 1),
		QPrime:     new(big.Int).Rsh(q, 1),
		Counter:    counter,
		ExpiryDate: expiryDate.Unix(),
	}
	priv.Order = new(big.Int).Mul(priv.PPrime, priv.QPrime)
	if err = priv.parseRevocationKey(); err != nil {
		return nil, nil, err
	}

	// compute n
	pubk := &PublicKey{
		Params: param, EpochLength: DefaultEpochLength, Counter: counter, ExpiryDate: expiryDate.Unix(),
	}
	pubk.N = priv.N
	if err = pubk.parseRevocationKey(); err != nil {
		return nil, nil, err
	}

	// Find an acceptable value for S; we follow lead of the Silvia code here:
	// Pick a random l_n value and check whether it is a quadratic residue modulo n

	var s *big.Int
	for {
		s, err = common.RandomBigInt(param.Ln)
		if err != nil {
			return nil, nil, err
		}
		// check if S \elem Z_n
		if s.Cmp(pubk.N) > 0 {
			continue
		}
		if common.LegendreSymbol(s, priv.P) == 1 && common.LegendreSymbol(s, priv.Q) == 1 {
			break
		}
	}

	pubk.S = s

	// Derive Z from S
	primeSize := param.Ln / 2
	var x *big.Int
	for {
		x, err = common.RandomBigInt(primeSize)
		if err != nil {
			return nil, nil, err
		}
		if x.Cmp(big.NewInt(2)) > 0 && x.Cmp(pubk.N) < 0 {
			break
		}
	}

	// Compute Z = S^x mod n
	pubk.Z = new(big.Int).Exp(pubk.S, x, pubk.N)

	// Derive R_i for i = 0...numAttributes from S
	pubk.R = make([]*big.Int, numAttributes)
	for i := 0; i < numAttributes; i++ {
		pubk.R[i] = new(big.Int)

		var x *big.Int
		for {
			x, err = common.RandomBigInt(primeSize)
			if err != nil {
				return nil, nil, err
			}
			if x.Cmp(big.NewInt(2)) > 0 && x.Cmp(pubk.N) < 0 {
				break
			}
		}
		// Compute R_i = S^x mod n
		pubk.R[i].Exp(pubk.S, x, pubk.N)
	}

	if err = GenerateRevocationKeypair(priv, pubk); err != nil {
		return nil, nil, err
	}

	return priv, pubk, nil
}

func (pubk *PublicKey) Base(name string) *big.Int {
	switch {
	case name == "Z":
		return pubk.Z
	case name == "S":
		return pubk.S
	case name == "G":
		return pubk.G
	case name == "H":
		return pubk.H
	case name[0] == 'R':
		i, err := strconv.Atoi(name[1:])
		if err != nil || i < 0 || i >= len(pubk.R) {
			return nil
		}
		return pubk.R[i]
	default:
		return nil
	}
}

func (pubk *PublicKey) Exp(ret *big.Int, name string, exp, n *big.Int) bool {
	base := pubk.Base(name)
	if base == nil {
		return false
	}
	ret.Exp(base, exp, n)
	return true
}

func (pubk *PublicKey) Names() []string {
	names := []string{"Z", "S"}
	if pubk.G != nil && pubk.H != nil {
		names = append(names, "G", "H")
	}
	for i := range pubk.R {
		names = append(names, fmt.Sprintf("R%d", i))
	}
	return names
}
