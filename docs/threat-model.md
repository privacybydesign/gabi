# Threat model

This document describes the threat model that `gabi` is designed to meet,
the assumptions it makes about its operating environment, and the
classes of attack that are explicitly out of scope. It complements
[`SECURITY.md`](../SECURITY.md), which describes how to report
vulnerabilities and what is in scope for the disclosure process.

`gabi` is the cryptographic core of the IRMA Idemix attribute-based
credential system. Most deployments will consume `gabi` indirectly
through [`irmago`](https://github.com/privacybydesign/irmago); the
threat model below applies to `gabi` itself, and downstream consumers
add their own assumptions on top.

## Assets

| #   | Asset                                                                                                  | Where it lives                                              | Impact if disclosed                                                                          |
| --- | ------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| A1  | Issuer private key (`PrivateKey.P`, `Q`, `PPrime`, `QPrime`, `Order`, `ECDSA`)                         | Issuer server process memory; on disk as XML                | Attacker can mint arbitrary credentials — total scheme break for that issuer.                |
| A2  | User secret (`CredentialBuilder.secret`, `Credential.Attributes[0]`)                                   | Prover process memory; persisted by the wallet (`irmago`)   | Attacker can impersonate the user across credentials sharing this secret.                    |
| A3  | Private attribute values (`Credential.Attributes[1:]`)                                                 | Prover process memory; persisted by the wallet (`irmago`)   | Attacker learns attribute values that the user only ever discloses selectively.              |
| A4  | Randomness used during issuance and proving (`v`, `vPrime`, nonces, `mUser` shares of blind attributes) | Process memory, transient                                   | If recovered, can break unlinkability or the blinding of a specific issuance/disclosure run. |

## Actors

- **Honest issuer.** Runs the issuance protocol and holds A1.
- **Honest prover (user).** Holds A2 and A3 and runs proofs of
  possession/disclosure.
- **Verifier.** Sees disclosure proofs only; assumed potentially curious
  and may collude with other verifiers to attempt to link disclosures.
- **Network attacker.** Standard Dolev–Yao model on the wire; mitigated
  by TLS at the transport layer, which is outside the scope of `gabi`.
- **Local attacker on the issuer host.** Has some form of access to the
  process or filesystem hosting the issuer.
- **Local attacker on the prover device.** Has some form of access to
  the wallet device.

## In scope

`gabi` is responsible for:

1. **Cryptographic soundness of the Idemix protocol** as implemented
   here — credential unforgeability under the strong-RSA assumption,
   zero-knowledge of undisclosed attributes, unlinkability of
   disclosures, and the soundness arguments behind the `keyproof`,
   `rangeproof`, and `revocation` packages shipped in this repository.
2. **Correct serialization/deserialization** of keys and proofs.
3. **Validation of received protocol messages** against the public
   parameters.

Bugs in (1)–(3) are security bugs and follow the disclosure process in
[`SECURITY.md`](../SECURITY.md).

## Out of scope

`gabi` does **not** defend against an attacker who has already achieved
code execution, kernel memory read, or persistent disk access on the
host running the issuer or prover. In particular:

### Memory residency of secrets

Secret material (A1–A4) is stored as `math/big.Int` and as Go heap
objects. It is not `mlock`'d, not stored in guarded memory enclaves, and
not deterministically zeroed after use. A kernel info-leak (e.g.
Spectre-class side channels, `/proc/<pid>/mem`, swap file analysis,
hibernation image, coredump) can recover these values.

This is an inherent consequence of building modular arithmetic on
`math/big`. Every arithmetic operation may allocate fresh backing
arrays, so wrapping the top-level `PrivateKey` or `CredentialBuilder`
struct in a locked buffer (e.g. via `memguard`) does not protect the
intermediate values that actually carry the secret during computation.
A meaningful in-library fix would require replacing the arithmetic
layer — a substantially larger change than this threat model justifies.

Mitigation is therefore the operator's responsibility; see
[Operational guidance](#operational-guidance) below.

### Side channels

`gabi` does not provide constant-time guarantees beyond what `math/big`
and `crypto/ecdsa` offer. Timing attacks, cache attacks, and other
microarchitectural side channels against a co-resident attacker are out
of scope.

### Random number generation

`gabi` reads from `crypto/rand`. An attacker who can compromise or
predict the system CSPRNG can break the scheme. Defending against that
is the operator's responsibility.

### Key generation environment

Issuer key generation should happen on a trusted, ideally offline, host.
`gabi` does not enforce this.

### Key storage at rest

`gabi` serializes `PrivateKey` as plaintext XML. Encrypting that file
(KMS, sealed secrets, HSM-wrapped key wrapping, …) is the operator's
responsibility.

### Persisted prover state

The wallet/storage layer (e.g. `irmago`) owns at-rest protection of A2
and A3.

### Denial of service

Resource exhaustion via malformed proofs is not in scope unless it
enables one of the in-scope concerns above.

## Operational guidance

### For issuer deployments

- Run on a host with **swap disabled** (`swapoff -a`) or with an
  **encrypted swap partition**. This is the single highest-leverage
  mitigation against A1 disclosure via swap.
- Disable coredumps for the issuer process (`ulimit -c 0`, an
  appropriate `/proc/sys/kernel/core_pattern`, or systemd
  `LimitCORE=0`).
- Disable hibernation on issuer hosts, or ensure the hibernation image
  is on encrypted storage.
- Store the `PrivateKey` XML file encrypted at rest; decrypt only into
  the issuer process.
- Restrict ptrace and `/proc/<pid>/mem` access
  (`kernel.yama.ptrace_scope=2` or `3` on Linux).
- Treat the issuer host as a high-value target: minimal services,
  kernel hardening, and regular patching for kernel info-leak CVEs.

### For prover (wallet) deployments

- The wallet implementation (e.g. `irmago`) is responsible for at-rest
  encryption of the user secret and private attributes.
- On mobile platforms, prefer storage backed by the secure element /
  Keystore / Keychain rather than plain files.
- Avoid running the wallet on shared or rooted devices where a local
  attacker can read process memory.
