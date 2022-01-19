package gabikeys

import (
	"encoding/xml"
	"strconv"

	"github.com/privacybydesign/gabi/big"
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

	*bl = arr
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
