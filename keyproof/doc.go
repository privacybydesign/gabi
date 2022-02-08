/*
Package keyproof
------------
INTRODUCTION
------------
This sublibrary implements functionality for creating and verifying zero
knowledge attestations of proper generation of idemix keys. It implements the
proof layed out in "Proving in Zero-Knowledge that a Number is the Product of
Two Safe Primes, Camenisch et. al. BRICS RS-98-29" section 5.2, using the
quasi-safe prime product proofs described in "An efficient non-interactive
statistical zero-knowledge proof system for quasi-safe prime products, Gennaro
et. al. CCS '98". The text here will provide a global overview of what is
implemented where. For details on how and why the individual implementations
work, the reader should consult before mentioned papers.

----------------
GLOBAL STRUCTURE
----------------
The implementation of this library consists of two parts: The group
representation based zero knowledge proofs described in Camenisch et. al., and
the more ad-hoc zero knowledge proofs for quasi safe prime products given in
Gennaro. These proofs share little common infrastructure, and can be understood
separately.

Although their structure internally is rather different, and the generation
logic is not shared, there are structural commonalities between how these
proofs are implemented, which we will describe here.

All the zero knowledge proofs contained in this package are essentially
interactive zero knowledge proofs, which are turned non-interactive using the
Fiat-Shamir heuristic. The process of proving consists of two stages: first
a set of commitments is generated for the proof, which is used to calculate a
hash which forms the challenge. This challenge is then used to compute all
responses, and is stored together with the responses to form the actual proof.

--------------
GENNARO PROOFS
--------------
Let us now describe in some more detail the workings of the ad-hoc proofs from
Gennaro et. al. There are four of the proofs, each of them aimed at
demonstrating membership of some language of natural numbers:
- Squarefree allows for proofs that a given number N, for which the prover
   knows its prime factorization, that N is square free.
- Primepowerproduct shows that a given odd number N is a product of at most
   two prime powers, e.g. there are primes p and q, and positive integers n
   and m, such that N=p^n*q^m. Again, this uses that the prover knows
   the prime decomposition
- Disjointprimeproduct allows for proofs that a given number N, which has
   already been shown that it is the product of at most two distinct primes, is
   in fact the product of precisely two primes
- Finally, Almostsafeprimeproduct shows that a product N of exactly two distinct
   primes is the product of two almost safe primes, e.g. that there exists
   primes p, q, and integers n, m such that N = (2*p^n+1)*(2*q^m+1)

The final result is what this part needs to prove, and straightforward
reasoning now shows that if Squarefree and Primepowerproduct proofs hold, the
precondition for Disjointprimeproduct holds. Then Disjoinprimeproduct provides
the precondition needed for Almostsafeprimeproduct.

Because of how the math behind these proofs work, in this process they provide
several extra conditions on the form of N. In particular, if N = (2*p^n+1)*
(2*q^m+1), the following extra conditions are imposed:
 - (2*p^n+1) != (2*q^m+1) (mod 8)
 - (2*p^n+1) != 1 (mod 8) and (2*q^m+1) != 1 (mod 8)
 - p != q (mod 8)
 - p != 1 (mod 8) and q != 1 (mod 8)

In structure, the four proofs here act similarly. Each provides three core
functions:
 - (*BuildProof), which given a challenge, a number N and its prime
    decomposition constructs a proof
 - (*VerifyStructure), which given a proof, validates that it is structurally
    sound.
 - (*VerifyProof), which given a structurally sound proof, validates whether it
    holds cryptographically.
Additionally, almostSafePrimeProduct has two extra functions:
 - almostSafePrimeProductBuildCommitments, which generates commitments that are
    used together with N to build the challenge for these proofs
 - almostSafePrimeProductExtractCommitments, which reconstructs the commitments
    from the proof data such that the verifier can check whether the challenge
    was properly computed

All four proofs are combined in quasisafeprimeproduct, which provides a single
point of entry to generate and verify a proof of all 4 facts at the same time.

----------------
CAMENISCH PROOFS
----------------

The remainder of the package consists of more straightforward zero knowledge
proofs used to implement an explicit primality test as specified in Camenisch
et. al. section 5.2.

The general setup is as follows: The proof consists of a number of secret
values, of which the prover proves that he both knows these secret values, as
well as that they satisfy certain relations. These secret values are stored
in this code in secret structs, which provide the basic tooling to make proofs
on them. These are then used in combination with various representation and
range proofs to show the needed relations.

Each Camenisch-based proof provides a similar interface in terms of types and
functions. Each proof provides up to three types:
 - A structure type, describing abstractly the structure of the proof that
    is going to be given, as well as providing storage for any parameters in
    the proof. This is only used when needed.
 - A proof type, describing any proof data specifically generated by this
    proof. This type is not always present, as some proofs do not require extra
    information beyond that provided by their environment (see for example
    representationproof)
 - A commit type, describing any temporary data that needs to be stored
    that is generated during the commitment stage, and that is needed to
    generate the proof once the challenge is known. Again, this type is not
    always present, as not all proofs require it.
For interacting with these, each proof also provides the following functions:
 - A method for generating a proof structure given information on what to
    prove. (new*ProofStructure)
 - A method for generating commitments based on the secret data. optionally
    also returns a commit object. (generateCommitmentsFromSecrets)
 - A method to generate the resulting proof, based on secret data and any
    previously generated commit data. (buildProof)
 - A method for validating proof structure. This is used to verify that any
    proof given as input is structurally sound before trying to validate its
    cryptographic validity. (verifyProofStructure)
 - A method for generating commitments based on proof data.
    (generateCommitmentsFromProof)
 - A method for generating a fake proof when given a challenge. (fakeProof)
    this is needed in proofs that participate in a larger OR proof.
Finally, each proof has a number of utility functions:
 - IsTrue can be used in debugging to validate whether the proof holds on
    secret data
 - NumCommitments returns the number of commitments added to the list by the
    commitment generating functions. This is used to allocate space when
    generating parts of the proofs in parallel
 - numRangeproofs returns the number of range proofs contained within the
    current proof. This is used to power progress indication, as range proofs
    take the majority of the time used during proving.

To make it possible to chain these proofs together, and to hand off needed
values between complicated subproofs, this library contains structures to aid
in lookup of such values. These are BaseLookup, SecretLookup and ProofLookup.
Any proof that needs to provide bases, secrets or proofdata to other
subproofs construct these. They provide lookup functions that can provide
bases, secrets, hiders and proof results given the name of the relevant
variable. This allows us to construct subproofs referring to variables by name
without having to know in the subproof what the exact name is any caller is
going to use. This flexibility is needed because some subproofs are repeated
many times in the overall proof that the key is properly generated.

Finally, pedersen contains the container for storing variables. It also exposes
lookup interfaces for base, secret and proofdata related to its variable. It is
pedersens that are typically combined by proofs to construct base, secret and
prooflookups for their subproofs.

Having outlined these tools, we can now take a closer look at the proofs
provided in this package. First, let us start with the basic building blocks
- representationproof provides proofs for statements of the form
   b_l1^k1 * ... * b_ln^kn = b_r1^(v1*h1)*...b_rn^(vn*hn)
   where the bs are bases, v1 through vn are variables, and the ks and hs are
   numeric constants. These proofs rely on the proofdata of the variables to
   show validity, and thus only produce commitments
- rangeproof provides proof of a representationproof statement, but additionally
   arranges for its own proof data such that it can show for a single variable
   v occurring in the representationproof expression that it's value is bounded.
From these basic building blocks, the library then constructs proofs for basic
operations:
- pedersen provides a way to create a pedersen commitment on a value v, which
   is needed as a building block in several of the other proofs.
- additionproof proves in zero knowledge of the values of a, b, d and m that
   a + b = d (mod m) holds.
- multiplicationproof provides a similar proof, showing that for variables a, b
  d and m, the expression a*b = d(mod m) holds.

These mathematics and representation building blocks now allow the construction
of a proof that a^b = d (mod m), where a, b, d and m are all variables that are
hidden. This is implemented by taking the multiply-and-square method for
calculating exponents modulo m, and proving that each step in that method was
properly executed. In this:
- expstep provides a proof for each individual step of multiply-and-square. It
   shows that the bit for that step is either 0 or 1, and simultaneously proves
   that the corresponding action to its value was indeed properly executed.
   It works by proving an or between the statements of expstepa and b
- expstepa proves that the current bit is 0 and that we have just forwarded the
   value
- expstepb proves that the current bit is 1 and that we have properly done the
   multiplication with the correct 2-power of a.
- exp contains one expstep for each bit, showing that all the steps are
   correctly done, and is also responsible for proving that all the
   intermediate values and fixed powers of a are in range and correctly
   generated.

This proof of exponentiation then provides the main tool used in the main
proofs:
- primeproof uses exponentiation to show that a number N=p^a, where p is
   known to be prime, has exponent a=1 (e.g. is prime itself)
- issquareproof shows in zero knowledge that a known value a can be written
   as b*b (mod m), where b is not revealed.
- validkeyproof shows, using primeproof, issquareproof and
   quasisafeprimeproof that an Idemix public key was properly generated.
*/
package keyproof
