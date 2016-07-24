// Copyright 2016 Maarten Everts. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gabi

import (
	"crypto/rand"
	"testing"
)

func TestRandomPrimeInRange(t *testing.T) {
	p, err := randomPrimeInRange(rand.Reader, 597, 120)
	if err != nil {
		t.Error(err)
	}
	if !p.ProbablyPrime(22) {
		t.Error("p not prime!")
	}
}
