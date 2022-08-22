Gabi
&nbsp;
[![Go Reference](https://pkg.go.dev/badge/github.com/privacybydesign/gabi.svg)](https://pkg.go.dev/github.com/privacybydesign/gabi)
[![Go Report Card](https://goreportcard.com/badge/github.com/privacybydesign/gabi)](https://goreportcard.com/report/github.com/privacybydesign/gabi)
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

History
-------

`gabi` was originally created and developed by [Maarten Everts](https://github.com/mhe) in 2015 and 2016. Since 2017, the [Privacy by Design Foundation](https://privacybydesign.foundation/en) and [SIDN](https://sidn.nl/en) maintain and develop `gabi`.

Contact
-------
Request access to our IRMA slack channel by mailing to [our support](mailto:support.irma@sidn.nl) if you want to become part of the community. In our slack channels, the latest news on IRMA are shared and technical details get discussed.

For responsible disclosure mail to [our responsible disclosure mailbox](mailto:irma-responsibledisclosure@sidn.nl)
