package common

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sync/atomic"

	"github.com/privacybydesign/gabi/big"
)

var globalCprng *CPRNG

// CPRNG is a simple thread-safe cryptographically secure pseudo-random number generator.
// Implemented with AES in counter mode with the seed as key and an
// atomic uint64 as counter.
type CPRNG struct {
	block   cipher.Block
	counter uint64
}

func NewCPRNG(seed *[32]byte) (*CPRNG, error) {
	c, err := aes.NewCipher(seed[:])
	if err != nil {
		return nil, err
	}
	return &CPRNG{
		block:   c,
		counter: 0,
	}, nil
}

func init() {
	var seed [32]byte
	_, err := rand.Reader.Read(seed[:])
	if err != nil {
		panic(fmt.Sprintf("Failed to generate seed for CPRNG: %v", err))
	}
	cprng, err := NewCPRNG(&seed)
	if err != nil {
		panic(fmt.Sprintf("Failed to initialize CPRNG: %v", err))
	}
	globalCprng = cprng
}

func (c *CPRNG) Read(buf []byte) (n int, err error) {
	var pt, ct [16]byte
	n = len(buf)
	if n == 0 {
		return
	}

	// Number of blocks required
	nBlocks := uint64(((len(buf) - 1) / 16) + 1)

	// Atomically increment counter by the number of blocks and set iv to
	// the first available block.
	iv := atomic.AddUint64(&c.counter, nBlocks) - nBlocks
	for {
		binary.LittleEndian.PutUint64(pt[:], iv)
		iv++

		// Still 16 bytes to go?  Then encrypt directly into buf.
		if len(buf) >= 16 {
			c.block.Encrypt(buf, pt[:])
			buf = buf[16:]
			continue
		}
		if len(buf) == 0 {
			break
		}

		// Otherwise, encrypt into ct and copy into buf.
		c.block.Encrypt(ct[:], pt[:])
		copy(buf, ct[:len(buf)])
		break
	}
	return
}

// FastRandomBigInt derives a random number uniformly chosen below the given limit
// from a random 256 bit seed generated when the application starts.
func FastRandomBigInt(limit *big.Int) *big.Int {
	res, err := big.RandInt(globalCprng, limit)
	if err != nil {
		panic(fmt.Sprintf("big.RandInt failed: %v", err))
	}
	return res
}

func RandomQR(n *big.Int) *big.Int {
	var r *big.Int
	var tmp big.Int
	for {
		r = FastRandomBigInt(n)
		// if GCD(r, n) == 1 then r is in (Z/nZ)*; return its square
		if tmp.GCD(nil, nil, r, n).Cmp(big.NewInt(1)) == 0 {
			return r.Mul(r, r).Mod(r, n)
		}
	}
}
