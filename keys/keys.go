package keys

import (
	"crypto/ecdsa"
	"encoding/xml"
	"strconv"

	"github.com/privacybydesign/gabi/big"
)

type (
	// SystemParameters holds the system parameters of the IRMA system.
	SystemParameters struct {
		BaseParameters
		DerivedParameters
	}

	// BaseParameters holds the base system parameters
	BaseParameters struct {
		LePrime uint
		Lh      uint
		Lm      uint
		Ln      uint
		Lstatzk uint
	}

	// DerivedParameters holds system parameters that can be drived from base
	// systemparameters (BaseParameters)
	DerivedParameters struct {
		Le            uint
		LeCommit      uint
		LmCommit      uint
		LRA           uint
		LsCommit      uint
		Lv            uint
		LvCommit      uint
		LvPrime       uint
		LvPrimeCommit uint
	}

	Bases []*big.Int

	EpochLength int

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
)

// Helper structs for (un)marshaling
type (
	// xmlBases is an auxiliary struct to encode/decode the odd way bases are
	// represented in the xml representation of public keys
	xmlBases struct {
		Num   int        `xml:"num,attr"`
		Bases []*xmlBase `xml:",any"`
	}

	xmlBase struct {
		XMLName xml.Name
		Bigint  string `xml:",innerxml"` // Has to be a string for ",innerxml" to work
	}

	// xmlFeatures is an auxiliary struct to make the XML encoding/decoding a bit
	// easier while keeping the struct for PublicKey somewhat simple.
	xmlFeatures struct {
		Epoch struct {
			Length int `xml:"length,attr"`
		}
	}
)

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
