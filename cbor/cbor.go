// Package cbor provides helper functions for encoding and decoding CBOR
// by wrapping functions provided by github.com/fxamacker/cbor.
//
// 1. CBOR is encoded using Core Deterministic Encoding defined in
//    RFC 8949, which obsoletes Canonical CBOR defined in RFC 7049.
// 2. CBOR decoder detects and rejects duplicate map keys, which is
//    an important requirement in security sensitive applications.
//
// For more info, see:
//   * https://github.com/fxamacker/cbor
//   * https://github.com/x448/safer-cbor
//   * https://tools.ietf.org/html/rfc8949
package cbor

import (
	"io"

	"github.com/fxamacker/cbor/v2" // imports as cbor
)

const MaxArrayElements = 1024 * 256
const MaxMapPairs = 1024 * 256

var (
	// encOptions specifies how CBOR should be encoded.
	encOptions = cbor.EncOptions{
		// Enable encoding options required by Core Deterministic Encoding
		// See https://datatracker.ietf.org/doc/html/rfc8949#section-4.2.1
		InfConvert:    cbor.InfConvertFloat16,
		IndefLength:   cbor.IndefLengthForbidden,
		NaNConvert:    cbor.NaNConvert7e00,
		ShortestFloat: cbor.ShortestFloat16,
		Sort:          cbor.SortCoreDeterministic,

		// We don't use tags
		TagsMd: cbor.TagsForbidden,
	}

	// decOptions specifies how CBOR should be decoded.
	decOptions = cbor.DecOptions{
		// Core Deterministic decoding options
		IndefLength: cbor.IndefLengthForbidden,

		// Sanity checks on maps and arrays
		DupMapKey:        cbor.DupMapKeyEnforcedAPF,
		MaxArrayElements: MaxArrayElements,
		MaxMapPairs:      MaxMapPairs,

		// We don't use tags
		TagsMd:  cbor.TagsForbidden,
		TimeTag: cbor.DecTagIgnored,

		// Don't set ExtraDecErrorUnknownField: we allow extra fields for forward compatibility
		ExtraReturnErrors: cbor.ExtraDecErrorNone,
	}

	encMode cbor.EncMode
	decMode cbor.DecMode
)

func init() {
	var err error
	if encMode, err = encOptions.EncMode(); err != nil {
		panic(err)
	}
	if decMode, err = decOptions.DecMode(); err != nil {
		panic(err)
	}
}

// Marshal encodes src into a CBOR-encoded byte slice.
func Marshal(src interface{}) ([]byte, error) {
	return encMode.Marshal(src)
}

// Unmarshal decodes CBOR in data into dst.
func Unmarshal(data []byte, dst interface{}) error {
	return decMode.Unmarshal(data, dst)
}

// NewEncoder creates a new CBOR encoder that writes to w.
func NewEncoder(w io.Writer) *cbor.Encoder {
	return encMode.NewEncoder(w)
}

// NewDecoder creates a new CBOR decoder that reads from r.
func NewDecoder(r io.Reader) *cbor.Decoder {
	return decMode.NewDecoder(r)
}
