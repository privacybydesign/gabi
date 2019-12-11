// Package big contains a mostly API-compatible "math/big".Int that JSON-marshals to and from Base64.
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
		tmp := i.Go()
		return json.Unmarshal(b, tmp)
	}

	bts := make([]byte, base64.StdEncoding.DecodedLen(len(b)-2))
	n, err := base64.StdEncoding.Decode(bts, b[1:len(b)-1]) // Skip quote characters
	i.SetBytes(bts[0:n])
	return err
}

// RandInt wraps "crypto/rand".Int:
// returns a uniform random value in [0, max). It panics if max <= 0.
func RandInt(rnd io.Reader, max *Int) (*Int, error) {
	i, err := cryptorand.Int(rnd, max.Go())
	return Convert(i), err
}

// Convert from a "math/big".Int
func Convert(x *big.Int) *Int {
	return (*Int)(x)
}

// Convert to a "math/big".Int
func (i *Int) Go() *big.Int {
	return (*big.Int)(i)
}

// "math/big".Int API
// We are liberal with using the conversion functions above; these are inlined by the compiler.

func NewInt(x int64) *Int  { return Convert(big.NewInt(x)) }
func Jacobi(x, y *Int) int { return big.Jacobi(x.Go(), y.Go()) }

func (i *Int) Format(s fmt.State, ch rune)        { i.Go().Format(s, ch) }
func (i *Int) GobDecode(buf []byte) error         { return i.Go().GobDecode(buf) }
func (i *Int) GobEncode() ([]byte, error)         { return i.Go().GobEncode() }
func (i *Int) Bit(j int) uint                     { return i.Go().Bit(j) }
func (i *Int) Bytes() []byte                      { return i.Go().Bytes() }
func (i *Int) BitLen() int                        { return i.Go().BitLen() }
func (i *Int) Int64() int64                       { return i.Go().Int64() }
func (i *Int) Uint64() uint64                     { return i.Go().Uint64() }
func (i *Int) IsInt64() bool                      { return i.Go().IsInt64() }
func (i *Int) IsUint64() bool                     { return i.Go().IsUint64() }
func (i *Int) Sign() int                          { return i.Go().Sign() }
func (i *Int) Cmp(y *Int) int                     { return i.Go().Cmp(y.Go()) }
func (i *Int) CmpAbs(y *Int) int                  { return i.Go().CmpAbs(y.Go()) }
func (i *Int) ProbablyPrime(n int) bool           { return i.Go().ProbablyPrime(n) }
func (i *Int) String() string                     { return i.Go().String() }
func (i *Int) Append(buf []byte, base int) []byte { return i.Go().Append(buf, base) }
func (i *Int) Bits() []big.Word                   { return i.Go().Bits() }
func (i *Int) Text(base int) string               { return i.Go().Text(base) }
func (i *Int) SetInt64(x int64) *Int              { return Convert(i.Go().SetInt64(x)) }
func (i *Int) SetUint64(x uint64) *Int            { return Convert(i.Go().SetUint64(x)) }
func (i *Int) Set(x *Int) *Int                    { return Convert(i.Go().Set(x.Go())) }
func (i *Int) SetBits(abs []big.Word) *Int        { return Convert(i.Go().SetBits(abs)) }
func (i *Int) Abs(x *Int) *Int                    { return Convert(i.Go().Abs(x.Go())) }
func (i *Int) Neg(x *Int) *Int                    { return Convert(i.Go().Neg(x.Go())) }
func (i *Int) Add(x, y *Int) *Int                 { return Convert(i.Go().Add(x.Go(), y.Go())) }
func (i *Int) Sub(x, y *Int) *Int                 { return Convert(i.Go().Sub(x.Go(), y.Go())) }
func (i *Int) Mul(x, y *Int) *Int                 { return Convert(i.Go().Mul(x.Go(), y.Go())) }
func (i *Int) MulRange(a, b int64) *Int           { return Convert(i.Go().MulRange(a, b)) }
func (i *Int) Binomial(n, k int64) *Int           { return Convert(i.Go().Binomial(n, k)) }
func (i *Int) Quo(x, y *Int) *Int                 { return Convert(i.Go().Quo(x.Go(), y.Go())) }
func (i *Int) Rem(x, y *Int) *Int                 { return Convert(i.Go().Rem(x.Go(), y.Go())) }
func (i *Int) Div(x, y *Int) *Int                 { return Convert(i.Go().Div(x.Go(), y.Go())) }
func (i *Int) Mod(x, y *Int) *Int                 { return Convert(i.Go().Mod(x.Go(), y.Go())) }
func (i *Int) SetBytes(buf []byte) *Int           { return Convert(i.Go().SetBytes(buf)) }
func (i *Int) Lsh(x *Int, n uint) *Int            { return Convert(i.Go().Lsh(x.Go(), n)) }
func (i *Int) Rsh(x *Int, n uint) *Int            { return Convert(i.Go().Rsh(x.Go(), n)) }
func (i *Int) Or(x, y *Int) *Int                  { return Convert(i.Go().Or(x.Go(), y.Go())) }
func (i *Int) Xor(x, y *Int) *Int                 { return Convert(i.Go().Xor(x.Go(), y.Go())) }
func (i *Int) Not(x *Int) *Int                    { return Convert(i.Go().Not(x.Go())) }
func (i *Int) Sqrt(x *Int) *Int                   { return Convert(i.Go().Sqrt(x.Go())) }
func (i *Int) And(x, y *Int) *Int                 { return Convert(i.Go().And(x.Go(), y.Go())) }
func (i *Int) Exp(x, y, m *Int) *Int {
	return Convert(i.Go().Exp(x.Go(), y.Go(), m.Go()))
}
func (i *Int) GCD(x, y, a, b *Int) *Int {
	return Convert(i.Go().GCD(x.Go(), y.Go(), a.Go(), b.Go()))
}
func (i *Int) Rand(rnd *rand.Rand, n *Int) *Int {
	return Convert(i.Go().Rand(rnd, n.Go()))
}
func (i *Int) ModInverse(g, n *Int) *Int {
	return Convert(i.Go().ModInverse(g.Go(), n.Go()))
}
func (i *Int) ModSqrt(x, p *Int) *Int {
	return Convert(i.Go().ModSqrt(x.Go(), p.Go()))
}
func (i *Int) SetBit(x *Int, j int, b uint) *Int {
	return Convert(i.Go().SetBit(x.Go(), j, b))
}
func (i *Int) AndNot(x, y *Int) *Int {
	return Convert(i.Go().AndNot(x.Go(), y.Go()))
}
func (i *Int) SetString(s string, base int) (*Int, bool) {
	z, b := i.Go().SetString(s, base)
	return Convert(z), b
}
func (i *Int) DivMod(x, y, m *Int) (*Int, *Int) {
	z, w := i.Go().DivMod(x.Go(), y.Go(), m.Go())
	return Convert(z), Convert(w)
}
func (i *Int) QuoRem(x, y, r *Int) (*Int, *Int) {
	z, w := i.Go().QuoRem(x.Go(), y.Go(), r.Go())
	return Convert(z), Convert(w)
}
