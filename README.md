[![Go Reference](https://pkg.go.dev/badge/github.com/privacybydesign/gabi.svg)](https://pkg.go.dev/github.com/privacybydesign/gabi)
Gabi
====

`gabi` is a Go implementation of the [IRMA](https://irma.app) approach to the Idemix attribute based credential system. Check out the [Privacy by Design Foundation](https://privacybydesign.foundation/irma-en) website to learn more on this great alternative to traditional identity management. 

`gabi` is the authoritative IRMA Idemix implementation, but it is still largely compatible with the now deprecated [Java](https://github.com/privacybydesign/irma_api_common) implementation.

gabi serves as the cryptographic core of [`irmago`](https://github.com/privacybydesign/irmago), which implements the IRMA server, IRMA app core, shared functionality between the two, and more. Most projects wanting to use IRMA or Idemix will want to use `irmago` instead of depending on `gabi` directly.

Install
-------

To install:

    go get github.com/privacybydesign/gabi

Test
----

To run tests:

    go test -v ./... 

