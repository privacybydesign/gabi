// Copyright 2016 Maarten Everts. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gabi

import (
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strconv"
	"time"

	"github.com/go-errors/errors"
	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/internal/common"
	"github.com/privacybydesign/gabi/revocation"
	"github.com/privacybydesign/gabi/safeprime"
	"github.com/privacybydesign/gabi/signed"
)

const (
	//XMLHeader can be a used as the XML header when writing keys in XML format.
	XMLHeader = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n"
	// DefaultEpochLength is the default epoch length for public keys.
	DefaultEpochLength = 432000
)

// PrivateKey represents an issuer's private key.
type PrivateKey struct {
	XMLName    xml.Name `xml:"http://www.zurich.ibm.com/security/idemix IssuerPrivateKey"`
	Counter    uint     `xml:"Counter"`
	ExpiryDate int64    `xml:"ExpiryDate"`
	P          *big.Int `xml:"Elements>p"`
	Q          *big.Int `xml:"Elements>q"`
	PPrime     *big.Int `xml:"Elements>pPrime"`
	QPrime     *big.Int `xml:"Elements>qPrime"`
	ECDSA      string

	nonrevSk *revocation.PrivateKey
}

// NewPrivateKey creates a new issuer private key using the provided parameters.
func NewPrivateKey(p, q *big.Int, ecdsa string, counter uint, expiryDate time.Time) *PrivateKey {
	sk := PrivateKey{
		P:          p,
		Q:          q,
		PPrime:     new(big.Int).Rsh(p, 1),
		QPrime:     new(big.Int).Rsh(q, 1),
		Counter:    counter,
		ExpiryDate: expiryDate.Unix(),
		ECDSA:      ecdsa,
	}

	return &sk
}

// NewPrivateKeyFromXML creates a new issuer private key using the xml data
// provided.
func NewPrivateKeyFromXML(xmlInput string) (*PrivateKey, error) {
	privk := &PrivateKey{}
	err := xml.Unmarshal([]byte(xmlInput), privk)
	if err != nil {
		return nil, err
	}
	return privk, nil
}

// NewPrivateKeyFromFile create a new issuer private key from an xml file.
func NewPrivateKeyFromFile(filename string) (*PrivateKey, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	privk := &PrivateKey{}

	b, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}

	err = xml.Unmarshal(b, privk)
	if err != nil {
		return nil, err
	}
	return privk, nil
}

func (privk *PrivateKey) RevocationGenerateWitness(accumulator *revocation.Accumulator) (*revocation.Witness, error) {
	revkey, err := privk.RevocationKey()
	if err != nil {
		return nil, err
	}
	return revocation.RandomWitness(revkey, accumulator)
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

	// And the actual xml body (with indentation)
	b, err := xml.MarshalIndent(privk, "", "   ")
	if err != nil {
		return int64(numHeaderBytes), err
	}
	numBodyBytes, err := writer.Write(b)
	return int64(numHeaderBytes + numBodyBytes), err
}

// WriteToFile writes the private key to an xml file. If any existing file with
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

func (privk *PrivateKey) RevocationKey() (*revocation.PrivateKey, error) {
	if privk.nonrevSk == nil {
		if !privk.RevocationSupported() {
			return nil, errors.New("private key does not support revocation")
		}
		bts, err := base64.StdEncoding.DecodeString(privk.ECDSA)
		if err != nil {
			return nil, err
		}
		key, err := signed.UnmarshalPrivateKey(bts)
		if err != nil {
			return nil, err
		}
		privk.nonrevSk = &revocation.PrivateKey{
			Counter: privk.Counter,
			ECDSA:   key,
			P:       privk.PPrime,
			Q:       privk.QPrime,
			N:       new(big.Int).Mul(privk.P, privk.Q),
		}
	}
	return privk.nonrevSk, nil
}

func (privk *PrivateKey) RevocationSupported() bool {
	return len(privk.ECDSA) > 0
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

	privk.ECDSA = base64.StdEncoding.EncodeToString(dsabts)
	pubk.ECDSA = base64.StdEncoding.EncodeToString(pubdsabts)
	pubk.T = common.RandomQR(pubk.N)
	pubk.G = common.RandomQR(pubk.N)
	pubk.H = common.RandomQR(pubk.N)

	return nil
}

// xmlBases is an auxiliary struct to encode/decode the odd way bases are
// represented in the xml representation of public keys
type xmlBases struct {
	Num   int        `xml:"num,attr"`
	Bases []*xmlBase `xml:",any"`
}

type xmlBase struct {
	XMLName xml.Name
	Bigint  string `xml:",innerxml"` // Has to be a string for ",innerxml" to work
}

// xmlFeatures is an auxiliary struct to make the XML encoding/decoding a bit
// easier while keeping the struct for PublicKey somewhat simple.
type xmlFeatures struct {
	Epoch struct {
		Length int `xml:"length,attr"`
	}
}

// Bases is a type that is introduced to simplify the encoding/decoding of
// a PublicKey whilst using the xml support of Go's standard library.
type Bases []*big.Int

// UnmarshalXML is an internal function to simplify decoding a PublicKey from
// XML.
func (bl *Bases) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var t xmlBases

	if err := d.DecodeElement(&t, &start); err != nil {
		return err
	}

	arr := make([]*big.Int, t.Num)
	for i := range arr {
		arr[i], _ = new(big.Int).SetString(t.Bases[i].Bigint, 10)
	}

	*bl = Bases(arr)
	return nil
}

// MarshalXML is an internal function to simplify encoding a PublicKey to XML.
func (bl *Bases) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	l := len(*bl)
	bases := make([]*xmlBase, l)

	for i := range bases {
		bases[i] = &xmlBase{
			XMLName: xml.Name{Local: "Base_" + strconv.Itoa(i)},
			Bigint:  (*bl)[i].String(),
		}
	}

	t := xmlBases{
		Num:   l,
		Bases: bases,
	}
	return e.EncodeElement(t, start)
}

// EpochLength is a type that is introduced to simplify the encoding/decoding of
// a PublicKey whilst using the xml support of Go's standard library.
type EpochLength int

// UnmarshalXML is an internal function to simplify decoding a PublicKey from
// XML.
func (el *EpochLength) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var t xmlFeatures

	if err := d.DecodeElement(&t, &start); err != nil {
		return err
	}
	*el = EpochLength(t.Epoch.Length)
	return nil
}

// MarshalXML is an internal function to simplify encoding a PublicKey to XML.
func (el *EpochLength) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	var t xmlFeatures
	t.Epoch.Length = int(*el)
	return e.EncodeElement(t, start)
}

// PublicKey represents an issuer's public key.
type PublicKey struct {
	XMLName     xml.Name          `xml:"http://www.zurich.ibm.com/security/idemix IssuerPublicKey"`
	Counter     uint              `xml:"Counter"`
	ExpiryDate  int64             `xml:"ExpiryDate"`
	N           *big.Int          `xml:"Elements>n"` // Modulus n
	Z           *big.Int          `xml:"Elements>Z"` // Generator Z
	S           *big.Int          `xml:"Elements>S"` // Generator S
	G           *big.Int          `xml:"Elements>G"` // Generator G for revocation
	H           *big.Int          `xml:"Elements>H"` // Generator H for revocation
	T           *big.Int          `xml:"Elements>T"` // Generator T for revocation
	R           Bases             `xml:"Elements>Bases"`
	EpochLength EpochLength       `xml:"Features"`
	Params      *SystemParameters `xml:"-"`
	Issuer      string            `xml:"-"`
	ECDSA       string

	nonrevPk *revocation.PublicKey
}

// NewPublicKey creates and returns a new public key based on the provided parameters.
func NewPublicKey(N, Z, S, G, H, T *big.Int, R []*big.Int, ecdsa string, counter uint, expiryDate time.Time) *PublicKey {
	return &PublicKey{
		Counter:     counter,
		ExpiryDate:  expiryDate.Unix(),
		N:           N,
		Z:           Z,
		S:           S,
		R:           R,
		G:           G,
		H:           H,
		T:           T,
		EpochLength: DefaultEpochLength,
		Params:      DefaultSystemParameters[N.BitLen()],
		ECDSA:       ecdsa,
	}
}

// NewPublicKeyFromXML creates a new issuer public key using the xml data
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
	return pubk, nil
}

func NewPublicKeyFromXML(xmlInput string) (*PublicKey, error) {
	return NewPublicKeyFromBytes([]byte(xmlInput))
}

// NewPublicKeyFromFile create a new issuer public key from an xml file.
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
	return pubk, nil
}

func (pubk *PublicKey) RevocationKey() (*revocation.PublicKey, error) {
	if pubk.nonrevPk == nil {
		if !pubk.RevocationSupported() {
			return nil, errors.New("public key does not support revocation")
		}
		bts, err := base64.StdEncoding.DecodeString(pubk.ECDSA)
		if err != nil {
			return nil, err
		}
		dsakey, err := signed.UnmarshalPublicKey(bts)
		if err != nil {
			return nil, err
		}
		g := revocation.NewQrGroup(pubk.N)
		g.G = pubk.G
		g.H = pubk.H
		pubk.nonrevPk = &revocation.PublicKey{
			Counter: pubk.Counter,
			Group:   &g,
			ECDSA:   dsakey,
		}
	}
	return pubk.nonrevPk, nil
}

func (pubk *PublicKey) RevocationSupported() bool {
	return pubk.G != nil && pubk.H != nil && pubk.T != nil && len(pubk.ECDSA) > 0
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

	// And the actual xml body (with indentation)
	b, err := xml.MarshalIndent(pubk, "", "   ")
	if err != nil {
		return int64(numHeaderBytes), err
	}
	numBodyBytes, err := writer.Write(b)
	return int64(numHeaderBytes + numBodyBytes), err
}

// WriteToFile writes the public key to an xml file. If any existing file with
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
	safeprimes := make([]*big.Int, 0, 10) // store all generated safeprimes until we find a suitable pair
	pPrime, pPrimeMod8, pMod8, qMod8, n := new(big.Int), new(big.Int), new(big.Int), new(big.Int), new(big.Int)
	var p, q *big.Int
	var err error

	// Start generating safeprimes
	ints, errs := safeprime.GenerateConcurrent(int(primeSize), stop)

	// Receive safeprime results in a loop, until we have a suitable pair of safeprimes.
loop: // we need this label to continue the for loop from within the select below
	for {
		select { // wait for and then handle an incoming bigint or error, whichever comes first

		case p = <-ints:
			pPrimeMod8.Mod(pPrime.Rsh(p, 1), big.NewInt(8))
			// p is our candidate safeprime, set p' = (p-1)/2. Check that p' mod 8 != 1
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
			close(stop) // Something went wrong during safeprime generation, abort
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
		PPrime:     new(big.Int).Rsh(p, 1),
		QPrime:     new(big.Int).Rsh(q, 1),
		Counter:    counter,
		ExpiryDate: expiryDate.Unix(),
	}

	// compute n
	pubk := &PublicKey{Params: param, EpochLength: DefaultEpochLength, Counter: counter, ExpiryDate: expiryDate.Unix()}
	pubk.N = new(big.Int).Mul(priv.P, priv.Q)

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
		x, _ = common.RandomBigInt(primeSize)
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
			x, _ = common.RandomBigInt(primeSize)
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
