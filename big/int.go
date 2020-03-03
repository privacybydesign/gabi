// Package big contains an API-compatible "math/big".Int that JSON-marshals to and from Base64.
package big

import (
	cryptorand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"math/big"
	"math/rand"

	"github.com/go-errors/errors"
)

// Int is an API-compatible "math/big".Int that JSON-marshals to and from Base64.
// Only supports positive integers.
type Int big.Int

func (i *Int) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	return e.EncodeElement(i.String(), start)
}

// UnmarshalXML implements xml.Unmarshaler, attempting to parse the text of the specified element
// as a base 10 integer.
func (i *Int) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	tmp := struct {
		Str string `xml:",chardata"`
	}{}
	if err := d.DecodeElement(&tmp, &start); err != nil {
		return err
	}
	if _, ok := i.SetString(tmp.Str, 10); !ok {
		return errors.New("XML element was not a base 10 integer")
	}
	if i.Sign() < 0 {
		return errors.New("Unexpected negative integer")
	}
	return nil
}

// MarshalText implements encoding.TextMarshaler, returning the base64-encoding
// of i.Bytes().
func (i *Int) MarshalText() ([]byte, error) {
	if i.Sign() == -1 {
		return nil, errors.New("Marshaling negative integers is not supported")
	}
	bts := i.Bytes()
	enc := make([]byte, base64.StdEncoding.EncodedLen(len(bts)))
	base64.StdEncoding.Encode(enc, bts)
	return enc, nil
}

// UnmarshalJSON implements json.Unmarshaler. If the input is quoted it attempts a
// base64 -> []byte -> Int conversion using i.SetBytes(). Otherwise it attempts to
// unmarshal the input as a JSON base 10 big integer.
func (i *Int) UnmarshalJSON(b []byte) error {
	if b[0] != '"' { // Not a JSON string, try to decode an ordinarily base-10 encoded "math.big".Int
		tmp := i.Value()
		err := json.Unmarshal(b, tmp)
		if err != nil {
			return err
		}
		if i.Sign() < 0 {
			return errors.New("Unexpected negative integer")
		}
		return nil
	}

	bts := make([]byte, base64.StdEncoding.DecodedLen(len(b)-2))
	n, err := base64.StdEncoding.Decode(bts, b[1:len(b)-1]) // Skip quote characters
	i.SetBytes(bts[0:n])
	// No need for sign check since setbytes interprets bytes as unsigned number.
	return err
}

// RandInt wraps "crypto/rand".Int:
// returns a uniform random value in [0, max). It panics if max <= 0.
func RandInt(rnd io.Reader, max *Int) (*Int, error) {
	i, err := cryptorand.Int(rnd, max.Value())
	return Convert(i), err
}

// Convert from a "math/big".Int
func Convert(x *big.Int) *Int {
	return (*Int)(x)
}

// Convert to a "math/big".Int
func (i *Int) Value() *big.Int {
	return (*big.Int)(i)
}

// "math/big".Int API
// We are liberal with using the conversion functions above; these are inlined by the compiler.

func NewInt(x int64) *Int  { return Convert(big.NewInt(x)) }
func Jacobi(x, y *Int) int { return big.Jacobi(x.Value(), y.Value()) }

func (i *Int) Format(s fmt.State, ch rune)         { i.Value().Format(s, ch) }
func (i *Int) GobDecode(buf []byte) error          { return i.Value().GobDecode(buf) }
func (i *Int) GobEncode() ([]byte, error)          { return i.Value().GobEncode() }
func (i *Int) Bit(j int) uint                      { return i.Value().Bit(j) }
func (i *Int) Bytes() []byte                       { return i.Value().Bytes() }
func (i *Int) BitLen() int                         { return i.Value().BitLen() }
func (i *Int) Int64() int64                        { return i.Value().Int64() }
func (i *Int) Uint64() uint64                      { return i.Value().Uint64() }
func (i *Int) IsInt64() bool                       { return i.Value().IsInt64() }
func (i *Int) IsUint64() bool                      { return i.Value().IsUint64() }
func (i *Int) Sign() int                           { return i.Value().Sign() }
func (i *Int) Cmp(y *Int) int                      { return i.Value().Cmp(y.Value()) }
func (i *Int) CmpAbs(y *Int) int                   { return i.Value().CmpAbs(y.Value()) }
func (i *Int) ProbablyPrime(n int) bool            { return i.Value().ProbablyPrime(n) }
func (i *Int) String() string                      { return i.Value().String() }
func (i *Int) Append(buf []byte, base int) []byte  { return i.Value().Append(buf, base) }
func (i *Int) Bits() []big.Word                    { return i.Value().Bits() }
func (i *Int) Scan(s fmt.ScanState, ch rune) error { return i.Value().Scan(s, ch) }
func (i *Int) Text(base int) string                { return i.Value().Text(base) }
func (i *Int) SetInt64(x int64) *Int               { return Convert(i.Value().SetInt64(x)) }
func (i *Int) SetUint64(x uint64) *Int             { return Convert(i.Value().SetUint64(x)) }
func (i *Int) Set(x *Int) *Int                     { return Convert(i.Value().Set(x.Value())) }
func (i *Int) SetBits(abs []big.Word) *Int         { return Convert(i.Value().SetBits(abs)) }
func (i *Int) Abs(x *Int) *Int                     { return Convert(i.Value().Abs(x.Value())) }
func (i *Int) Neg(x *Int) *Int                     { return Convert(i.Value().Neg(x.Value())) }
func (i *Int) Add(x, y *Int) *Int                  { return Convert(i.Value().Add(x.Value(), y.Value())) }
func (i *Int) Sub(x, y *Int) *Int                  { return Convert(i.Value().Sub(x.Value(), y.Value())) }
func (i *Int) Mul(x, y *Int) *Int                  { return Convert(i.Value().Mul(x.Value(), y.Value())) }
func (i *Int) MulRange(a, b int64) *Int            { return Convert(i.Value().MulRange(a, b)) }
func (i *Int) Binomial(n, k int64) *Int            { return Convert(i.Value().Binomial(n, k)) }
func (i *Int) Quo(x, y *Int) *Int                  { return Convert(i.Value().Quo(x.Value(), y.Value())) }
func (i *Int) Rem(x, y *Int) *Int                  { return Convert(i.Value().Rem(x.Value(), y.Value())) }
func (i *Int) Div(x, y *Int) *Int                  { return Convert(i.Value().Div(x.Value(), y.Value())) }
func (i *Int) Mod(x, y *Int) *Int                  { return Convert(i.Value().Mod(x.Value(), y.Value())) }
func (i *Int) SetBytes(buf []byte) *Int            { return Convert(i.Value().SetBytes(buf)) }
func (i *Int) Lsh(x *Int, n uint) *Int             { return Convert(i.Value().Lsh(x.Value(), n)) }
func (i *Int) Rsh(x *Int, n uint) *Int             { return Convert(i.Value().Rsh(x.Value(), n)) }
func (i *Int) Or(x, y *Int) *Int                   { return Convert(i.Value().Or(x.Value(), y.Value())) }
func (i *Int) Xor(x, y *Int) *Int                  { return Convert(i.Value().Xor(x.Value(), y.Value())) }
func (i *Int) Not(x *Int) *Int                     { return Convert(i.Value().Not(x.Value())) }
func (i *Int) Sqrt(x *Int) *Int                    { return Convert(i.Value().Sqrt(x.Value())) }
func (i *Int) And(x, y *Int) *Int                  { return Convert(i.Value().And(x.Value(), y.Value())) }
func (i *Int) Exp(x, y, m *Int) *Int {
	return Convert(i.Value().Exp(x.Value(), y.Value(), m.Value()))
}
func (i *Int) GCD(x, y, a, b *Int) *Int {
	return Convert(i.Value().GCD(x.Value(), y.Value(), a.Value(), b.Value()))
}
func (i *Int) Rand(rnd *rand.Rand, n *Int) *Int {
	return Convert(i.Value().Rand(rnd, n.Value()))
}
func (i *Int) ModInverse(g, n *Int) *Int {
	return Convert(i.Value().ModInverse(g.Value(), n.Value()))
}
func (i *Int) ModSqrt(x, p *Int) *Int {
	return Convert(i.Value().ModSqrt(x.Value(), p.Value()))
}
func (i *Int) SetBit(x *Int, j int, b uint) *Int {
	return Convert(i.Value().SetBit(x.Value(), j, b))
}
func (i *Int) AndNot(x, y *Int) *Int {
	return Convert(i.Value().AndNot(x.Value(), y.Value()))
}
func (i *Int) SetString(s string, base int) (*Int, bool) {
	z, b := i.Value().SetString(s, base)
	return Convert(z), b
}
func (i *Int) DivMod(x, y, m *Int) (*Int, *Int) {
	z, w := i.Value().DivMod(x.Value(), y.Value(), m.Value())
	return Convert(z), Convert(w)
}
func (i *Int) QuoRem(x, y, r *Int) (*Int, *Int) {
	z, w := i.Value().QuoRem(x.Value(), y.Value(), r.Value())
	return Convert(z), Convert(w)
}
