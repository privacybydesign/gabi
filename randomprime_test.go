// Copyright 2016 Maarten Everts. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gabi

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRandomPrimeInRange(t *testing.T) {
	p, err := randomPrimeInRange(rand.Reader, 597, 120)
	assert.NoError(t, err)

	assert.True(t, p.ProbablyPrime(22), "p not prime!")
}
