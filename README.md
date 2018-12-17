[![GoDoc](https://godoc.org/github.com/privacybydesign/gabi?status.svg)](https://godoc.org/github.com/privacybydesign/gabi) [![Build Status](https://travis-ci.org/mhe/gabi.svg?branch=master)](https://travis-ci.org/mhe/gabi)
Gabi
====

Gabi is a Go implementation of the [IRMA](https://www.irmacard.org) approach to the [Idemix](http://www.research.ibm.com/labs/zurich/idemix/) attribute based credential system. Check out the [IRMA](https://privacybydesign.foundation/irma) website to learn more on this great alternative to traditional identity management. 

gabi itself is designed to be compatible with the existing [Java](https://github.com/credentials/credentials_idemix) and [C++](https://github.com/credentials/silvia) implementations of the IRMA system.

Status
------

Do note that this library is still fairly young. As such there might be some API-changes in the near future. And although most (if not all) cryptographic primitives are present, it does need additional "field testing". In addition, since this library implements (non-trivial) cryptography it needs to be checked by many more eyeballs.

Install
-------

To install:

    go get -v github.com/privacybydesign/gabi

Test
----

To run tests:

    go test -v ./... 

