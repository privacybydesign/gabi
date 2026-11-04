# Security Policy

## Supported versions

Only the latest tagged release of `gabi` receives security fixes.
Downstream users should track [`irmago`](https://github.com/privacybydesign/irmago),
which pins a vetted version of `gabi`.

## Reporting a vulnerability

Please report suspected vulnerabilities privately to
**security@privacybydesign.foundation**. Do **not** open a public GitHub
issue for cryptographic soundness bugs, key-recovery attacks, or anything
you believe gives an advantage to a malicious issuer, prover, or verifier.

We aim to acknowledge reports within 5 working days and to publish a fix
or mitigation advisory within 90 days, coordinated with downstream
consumers (notably `irmago`).

## Scope

`gabi` is the cryptographic core of the IRMA Idemix attribute-based
credential system. The following are in scope:

- Soundness of the Idemix protocol as implemented here: credential
  unforgeability, zero-knowledge of undisclosed attributes, unlinkability
  of disclosures.
- Correctness of the `keyproof`, `rangeproof`, and `revocation` packages.
- Correct serialization/deserialization of keys and proofs.
- Validation of protocol messages against the public parameters.

## Out of scope

`gabi` is a cryptographic library, not a hardened runtime. The following
are **not** in scope and will generally be closed as "won't fix" unless
accompanied by a concrete, minimally-invasive patch.

### Memory residency of secrets

Issuer private keys, user secrets, and private attribute values are
stored as Go `math/big.Int` and other heap-allocated objects. They are
**not** locked into RAM, not stored in guarded memory enclaves, and not
deterministically zeroed after use.

This is a deliberate consequence of building modular arithmetic on
`math/big`: every arithmetic operation allocates fresh backing storage,
so wrapping a top-level struct in a locked buffer (e.g. via `memguard`)
does not protect the intermediate values that actually carry the secret
during computation. A meaningful fix would require replacing the
arithmetic layer, which is a much larger change than gabi's threat
model justifies.

Operators are expected to mitigate this at the platform layer:

- Disable swap (`swapoff -a`) or use encrypted swap.
- Disable coredumps for the issuer process.
- Disable hibernation, or store the hibernation image on encrypted media.
- Encrypt the `PrivateKey` XML file at rest; decrypt only into memory.
- Restrict ptrace and `/proc/<pid>/mem` (`kernel.yama.ptrace_scope=2`).
- Apply kernel patches for info-leak CVEs promptly.

For wallets, the user secret and attributes should be protected at rest
by the embedding application (e.g. `irmago` and its storage backends).

### Side channels

`gabi` does not provide constant-time guarantees beyond those offered by
`math/big` and `crypto/ecdsa`. Timing, cache, and microarchitectural
attacks by a co-resident attacker are out of scope.

### Random number generation

`gabi` uses `crypto/rand`. A compromised system CSPRNG breaks the
scheme; defending against that is the operator's responsibility.

### Key generation environment

Issuer key generation should be performed on a trusted, ideally offline,
host. `gabi` does not enforce this.

### Denial of service

Resource exhaustion via malformed inputs is not treated as a security
issue unless it enables one of the in-scope concerns above.

## Threat model

A longer write-up of the threat model — assets, actors, and the
operational assumptions above — lives in
[`docs/threat-model.md`](docs/threat-model.md).
