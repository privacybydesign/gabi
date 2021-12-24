// Package signed contains
// (1) convenience functions for ECDSA private and public key handling, and for signing and
// verifying byte slices with ECDSA;
// (2) functions for marshaling structs to signed bytes, and verifying and unmarshaling signed bytes
// back to structs.
package signed

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"math/big"

	"github.com/privacybydesign/gabi/cbor"

	"github.com/go-errors/errors"
)

type (
	// Message is a signed message, created and signed by MarshalSign, and verified and parsed
	// by UnmarshalVerify.
	Message []byte

	// message-signature tuple
	tuple struct {
		Msg, Sig []byte
	}
)

func GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// Key (un)marshaling

// 2 for private/public + 2 functions for (un)marshaling + 2 for PEM or not = a total of 8 functions
// for key management, i.e. many; but we require all possibilities, and it seems better to have
// long simple code than compact complex code here. At least the PEM variants can reuse the other ones

func UnmarshalPublicKey(bts []byte) (*ecdsa.PublicKey, error) {
	genericPk, err := x509.ParsePKIXPublicKey(bts)
	if err != nil {
		return nil, err
	}
	pk, ok := genericPk.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("invalid ecdsa public key")
	}
	return pk, nil
}

func UnmarshalPemPublicKey(bts []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(bts)
	return UnmarshalPublicKey(block.Bytes)
}

func MarshalPublicKey(pk *ecdsa.PublicKey) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(pk)
}

func MarshalPemPublicKey(pk *ecdsa.PublicKey) ([]byte, error) {
	bts, err := MarshalPublicKey(pk)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Failed to serialize public key", 0)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: bts}), nil
}

func UnmarshalPrivateKey(bts []byte) (*ecdsa.PrivateKey, error) {
	return x509.ParseECPrivateKey(bts)
}

func UnmarshalPemPrivateKey(bts []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(bts)
	return UnmarshalPrivateKey(block.Bytes)
}

func MarshalPrivateKey(sk *ecdsa.PrivateKey) ([]byte, error) {
	return x509.MarshalECPrivateKey(sk)
}

func MarshalPemPrivateKey(sk *ecdsa.PrivateKey) ([]byte, error) {
	bts, err := MarshalPrivateKey(sk)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: bts}), nil
}

// Sign and verify bytes

func Sign(sk *ecdsa.PrivateKey, bts []byte) ([]byte, error) {
	hash := sha256.Sum256(bts)
	r, s, err := ecdsa.Sign(rand.Reader, sk, hash[:])
	if err != nil {
		return nil, err
	}
	return asn1.Marshal([]*big.Int{r, s})
}

func Verify(pk *ecdsa.PublicKey, bts []byte, signature []byte) error {
	ints := make([]*big.Int, 2, 2)
	_, err := asn1.Unmarshal(signature, &ints)
	if err != nil {
		return err
	}
	hash := sha256.Sum256(bts)
	if !ecdsa.Verify(pk, hash[:], ints[0], ints[1]) {
		return errors.New("ecdsa signature was invalid")
	}
	return nil
}

// create, verify and (un)marshal signed messages

// MarshalSign marshals the message to bytes using either its MarshalBinary() method (c.f.
// the encoding.BinaryMarshaler interface) or using gob, signs the resulting bytes, and returns
// signed message bytes suitable for verifying with UnmarshalVerify.
func MarshalSign(sk *ecdsa.PrivateKey, message interface{}) (Message, error) {
	var err error

	// marshal message to []byte
	bts, err := cbor.Marshal(message)

	// sign message []byte
	signature, err := Sign(sk, bts)
	if err != nil {
		return nil, err
	}

	// encode and return message-signature pair
	return cbor.Marshal(&tuple{bts, signature})
}

// UnmarshalVerify verifies the signature a Message created by MarshalSign, and unmarshals the
// message bytes into dst using either its UnmarshalBinary method (c.f. the
// encoding.BinaryUnmarshaler interface) or using gob.
func UnmarshalVerify(pk *ecdsa.PublicKey, signed Message, dst interface{}) error {
	var err error

	// decode message-signature pair
	var tmp tuple
	if err = cbor.Unmarshal(signed, &tmp); err != nil {
		return err
	}

	// verify signature
	if err = Verify(pk, tmp.Msg, tmp.Sig); err != nil {
		return err
	}

	// unmarshal message []byte into receiver
	return cbor.Unmarshal(tmp.Msg, dst)
}
