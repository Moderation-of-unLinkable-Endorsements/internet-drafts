---
title: "Ratatouille"
abbrev: "Ratatouille"
category: info

docname: draft-authors-mole-vole-act-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
keyword:
  - moderation
  - unlinkability
  - privacy
venue:
  github: "Moderation-of-unLinkable-Endorsements/internet-drafts"
  latest: "https://moderation-of-unlinkable-endorsements.github.io/internet-drafts/draft-authors-mole-vole-act.html"

author:
  -
    fullname: Tianyu Zhang
    organization: University of Illinois at Urbana-Champaign
    email: tianyuz@illinois.edu

  -
    fullname: Christopher Patton
    organization: Cloudflare
    email: chrispatton+ietf@gmail.com

  -
    fullname: Samuel Schlesinger
    organization: Google
    email: samschlesinger@google.com

normative:
  FIPS202:  # TurboShortSHAKE128(M,d) = Sponge[Keccak-p[800, 12], pad10*1, 800–256](M||1111,d)
    title: "SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions"
    target: https://doi.org/10.6028/NIST.FIPS.202
    date: 2015-08
    seriesinfo:
      "FIPS PUB": "202"
    author:
      -
        org: National Institute of Standards and Technology (NIST)
  FAEST:
    title: "The FAEST Signature Scheme"
    target: https://faest.info/faest-spec-v2.0.pdf
    date: 2025
    seriesinfo:
      "Version": "2.0"
    author:
      -
        ins: C. Baum
        name: Carsten Baum
      -
        ins: L. Braun
        name: Lennart Braun
      -
        ins: W. Beullens
        name: Ward Beullens
      -
        ins: C. Delpech de Saint Guilhem
        name: Cyprien Delpech de Saint Guilhem
      -
        ins: M. Klooß
        name: Michael Klooß
      -
        ins: C. Majenz
        name: Christian Majenz
      -
        ins: S. Mukherjee
        name: Shibam Mukherjee
      -
        ins: E. Orsini
        name: Emmanuela Orsini
      -
        ins: S. Ramacher
        name: Sebastian Ramacher
      -
        ins: C. Rechberger
        name: Christian Rechberger
      -
        ins: L. Roy
        name: Lawrence Roy
      -
        ins: P. Scholl
        name: Peter Scholl
  UOV:
    title: "UOV: Unbalanced Oil and Vinegar"
    target: https://csrc.nist.gov/csrc/media/Projects/pqc-dig-sig/documents/round-2/spec-files/uov-spec-round2-web.pdf
    date: 2025-02
    seriesinfo:
      "NIST PQC Additional Digital Signatures": "Round 2 Submission"
    author:
      -
        ins: W. Beullens
        name: Ward Beullens
      -
        ins: M.-S. Chen
        name: Ming-Shing Chen
      -
        ins: J. Ding
        name: Jintai Ding
      -
        ins: B. Gong
        name: Boru Gong
      -
        ins: M. J. Kannwischer
        name: Matthias J. Kannwischer
      -
        ins: J. Patarin
        name: Jacques Patarin
      -
        ins: B.-Y. Peng
        name: Bo-Yuan Peng
      -
        ins: D. Schmidt
        name: Dieter Schmidt
      -
        ins: C.-J. Shih
        name: Cheng-Jhih Shih
      -
        ins: C. Tao
        name: Chengdong Tao
      -
        ins: B.-Y. Yang
        name: Bo-Yin Yang

informative:
  ACT: I-D.draft-schlesinger-cfrg-act-01

  PoMFRIT:
    title: "Concretely Efficient Blind Signatures Based on VOLE-in-the-Head Proofs and the MAYO Trapdoor"
    target: https://eprint.iacr.org/2026/109
    date: 2026
    seriesinfo:
      "Cryptology ePrint Archive": "Paper 2026/109"
    author:
      -
        ins: C. Baum
        name: Carsten Baum
      -
        ins: M. Beckmann
        name: Marvin Beckmann
      -
        ins: W. Beullens
        name: Ward Beullens
      -
        ins: S. Mukherjee
        name: Shibam Mukherjee
      -
        ins: C. Rechberger
        name: Christian Rechberger

  Fischlin:
    title: "Round-Optimal Composable Blind Signatures in the Common Reference String Model"
    target: https://doi.org/10.1007/11818175_4
    date: 2006
    seriesinfo:
      "CRYPTO": "2006, LNCS 4117, pp. 60-77"
    author:
      -
        ins: M. Fischlin
        name: Marc Fischlin

  BFMRSV25a:
    title: "Multivariate Commitments and Signatures with Efficient Protocols"
    target: https://eprint.iacr.org/2025/2035
    date: 2025
    seriesinfo:
      "Cryptology ePrint Archive": "Paper 2025/2035"
    author:
      -
        ins: C. Bouillaguet
        name: Charles Bouillaguet
      -
        ins: T. Feneuil
        name: Thibauld Feneuil
      -
        ins: J. Maire
        name: Jules Maire
      -
        ins: M. Rivain
        name: Matthieu Rivain
      -
        ins: J. Sauvage
        name: Julia Sauvage
      -
        ins: D. Vergnaud
        name: Damien Vergnaud

  CryptEst:
    title: "CryptographicEstimators: A Software Library for Cryptographic Hardness Estimation"
    target: https://eprint.iacr.org/2023/589
    date: 2023
    seriesinfo:
      "Cryptology ePrint Archive": "Paper 2023/589"
    author:
      -
        ins: A. Esser
        name: Andre Esser
      -
        ins: J. Verbel
        name: Javier Verbel
      -
        ins: F. Zweydinger
        name: Floyd Zweydinger
      -
        ins: E. Bellini
        name: Emanuele Bellini

  BNPS03:
    title: "The One-More-RSA-Inversion Problems and the Security of Chaum's Blind Signature Scheme"
    target: https://eprint.iacr.org/2001/002
    date: 2003
    seriesinfo:
      "Journal of Cryptology": "16(3), pp. 185-215"
    author:
      -
        ins: M. Bellare
        name: Mihir Bellare
      -
        ins: C. Namprempre
        name: Chanathip Namprempre
      -
        ins: D. Pointcheval
        name: David Pointcheval
      -
        ins: M. Semanko
        name: Michael Semanko

  CCNY12:
    title: "Solving Quadratic Equations with XL on Parallel Architectures"
    target: https://eprint.iacr.org/2016/412
    date: 2012
    seriesinfo:
      "CHES": "2012, LNCS 7428, pp. 356-373"
    author:
      -
        ins: C.-M. Cheng
        name: Chen-Mou Cheng
      -
        ins: T. Chou
        name: Tung Chou
      -
        ins: R. Niederhagen
        name: Ruben Niederhagen
      -
        ins: B.-Y. Yang
        name: Bo-Yin Yang

...

--- abstract

This document specifies Ratatouille, a candidate post-quantum variant of the
Anonymous Credit Token (ACT) protocol. Ratatouille is based on the UOV digital
signature scheme and the VOLE-in-the-Head proof system (a component of the
FAEST signature scheme). The moderator issues a token by signing a commitment
to the client's state; to present a token, the client proves knowledge of this
signature and the opening of the commitment. Two variants of the protocol are
specified, one in which the commitment is instantiated with `Keccak-p[800,12]`
and another in which a UOV-friendly commitment scheme is used instead.

--- middle

# Introduction

> WARNING This document specifies a cryptographic protocol that has not yet
> undergone significant security analysis. It's not yet suitable for real world
> applications. Implement at your own risk.

Modern web services face a fundamental tension between operational needs and
user privacy. Services need to implement rate limiting to prevent abuse, charge
for API usage to sustain operations, and allocate computational resources
fairly. However, traditional approaches require tracking client identities and
creating detailed logs of client behavior, raising significant privacy concerns
in an era of increasing data protection awareness and regulation.

The Anonymous Credit Token (ACT) protocol {{ACT}} resolves this tension by
enabling credit-based systems without client tracking: an issuer can grant a
client a token worth some number of credits, and the client can later spend
those credits anonymously, in whole or in part, without the issuer being able
to link the spend to the issuance or to any other spend by the same client.

ACT {{ACT}} builds on BBS MACs over prime-order groups. Its
*unlinkability* (the issuer cannot correlate transactions) is
information-theoretic, following from the perfectly hiding commitments, so it
already holds against unbounded and hence quantum adversaries. Its
*unforgeability* (clients cannot mint or over-spend credits), however, rests on
the strong Diffie-Hellman assumption that Shor's algorithm breaks. What
remains, then, is to make unforgeability post-quantum as well.

This document specifies Ratatouille, a **post-quantum** variant of ACT, whose
security rests on assumptions believed to resist quantum attack: the hardness
of structured multivariate quadratic (MQ) problems, via the Unbalanced Oil and
Vinegar (UOV) signature scheme {{UOV}}, and the security of symmetric
primitives (hash functions and pseudorandom generators), via the
VOLE-in-the-Head (VOLEitH) zero-knowledge proof system {{FAEST}}. We build on
the Fischlin blind-signature paradigm {{Fischlin}}, in which a client sends the
issuer a hiding commitment to a message, the issuer signs the
commitment, and the client later proves knowledge of a signature on the
committed message. Ratatouille generalizes this from a one-time signature to a
spendable balance: the commitment binds a nullifier together with the remaining
credits, and each presentation additionally proves that the spend was
subtracted correctly and the balance stays in range, with the issuer re-signing
the updated commitment so that every spend chains into the next token.

Ratatouille is inspired by PoMFRIT {{PoMFRIT}}, which builds a post-quantum
blind signature from the MAYO signature (another MQ signature) and optimizes
the VOLEitH proof for SHAKE hashing, and by Bouillaguet et al. {{BFMRSV25a}},
which builds a post-quantum blind signature from an MQ commitment. In both, the
multivariate building block is chosen to be efficiently provable in VOLEitH --
the same principle Ratatouille follows.

## Key Properties and Use Cases

Ratatouille inherits the properties and use cases of ACT {{ACT}}; we refer the
reader there for their definitions. In particular, it provides
**unlinkability**, **flexible spending and refunding**, **balance privacy**, and
**double-spend prevention** (if a single database is shared across issuers), and it supports the same use cases, such as
**rate limiting** and **API credits**.

Beyond ACT, Ratatouille additionally achieves **Full Post-Quantum Security**: All security properties -- unforgeability,
unlinkability, and double-spend prevention -- are conjectured to hold against
adversaries equipped with a large-scale quantum computer. Security reduces to
the UOV and MQ problems and to the security of standard symmetric primitives.

This post-quantum security comes at a cost in **performance**: presentation proofs
are larger than in the classical construction, on the order of kilobytes to tens
of kilobytes. At the 128-bit security level, Ratatouille has significantly higher
communication cost than the classical ACT:

1. the issuer's public key is a UOV map -- approximately 42.6 KB for the hash
   instantiation ({{hash-commitment}}, the uov-Ip parameter set {{UOV}}), and
   larger for the MQ instantiation ({{mq-commitment}}), which widens the UOV map;

2. ~7.8 KB (hash) or ~4.3 KB (MQ) are transmitted during issuance; and

3. ~14.2 KB (hash) or ~9.0 KB (MQ) are transmitted during a spend; and

4. the issuer's reply is a single UOV signature -- about 112 B (hash) or 275 B
   (MQ), plus a few bytes of granted refund on a spend.

Nonetheless, the protocol remains practical for modern web services,
with efficient signing, verification, and proof generation.

Unlike ACT, Ratatouille tokens are publicly verifiable in the sense that it can be presented to any Moderator, not just the Moderator that issued it. Of course, this has implications for privacy, since the token necessarily reveals the identity of the Moderator that issued it.

## Building Blocks

Ratatouille builds on the following cryptographic primitives:

* **UOV Signatures {{UOV}}**: Unbalanced Oil and Vinegar is a multivariate
  hash-and-sign signature scheme and a Round 2 candidate in the NIST additional
  post-quantum signatures process. Its public key is a system of multivariate
  quadratic equations, and signature verification is a degree-2 check over a
  small field -- a structure that is especially friendly to VOLEitH proofs.
* **VOLE-in-the-Head {{FAEST}}**: A zero-knowledge proof and signature
  framework, used here as the proof system for spending. Its proofs are
  publicly verifiable, are built entirely from symmetric primitives, and are
  concretely small and fast for circuits over small binary fields.

# Conventions and Definitions {#conventions}

{::boilerplate bcp14-tagged}

## Notation

This document uses the following notation:

* `||`: Concatenation of bit strings.
* `x <- S`: Sampling `x` uniformly at random from the finite set `S`. Also
  written `x <- A(...)` for assigning to `x` the output of a randomized
  algorithm `A`.
* `x := y`: Assignment of the value `y` to the variable `x`.
* `[n]`: The set of integers `{0, 1, ..., n-1}`; `[a, b]` denotes the closed
  integer interval `{a, a+1, ..., b}`.
* `F_2`: The binary field `{0, 1}`. Bits are elements of `F_2`.
* `F_q`: The finite field with `q` elements. This document fixes `q = 256`, so
  `F_256 = F_{2^8}` is the field of bytes, in which the UOV signature operates.
* `F_{2^lambda}`: The degree-`lambda` extension field of `F_2`, in which the
  VOLE-in-the-Head proof operates. Because `lambda` is a multiple of 8, the
  fields are nested by subfield inclusion: `F_2 subset F_q subset
  F_{2^lambda}`. The same wire value over the circuit can be viewed as bits,
  bytes, or a single `F_{2^lambda}` element as needed.
* Vectors are written in lower case (e.g., `s`) and matrices in upper case
  (e.g., `P`). `F_q^n` denotes the set of length-`n` column vectors over `F_q`.
* `P(s)`: Application of a quadratic map `P: F_q^{n_uov} -> F_q^{m_uov}` to a
  vector `s`, yielding `(s^T P_0 s, ..., s^T P_{m_uov-1} s) in F_q^{m_uov}`,
  where each `P_i` is an upper-triangular matrix over `F_q`.
* `<t>_L`: The `L`-byte big-endian encoding of a nonnegative integer `t < 2^(8*L)`
  as an element of `F_256^L` (equivalently `F_2^(8*L)`).
* `H`: A cryptographic extendable-output hash function, modeled as a random
  oracle (see {{protocol}}). Domain separation is applied by prefixing a
  distinct label and the deployment tag `dst` to each use.

## Data Types

The protocol uses the following primitive data types:

* **Bit**: An element of `F_2`.
* **Field element**: An element of `F_q` or `F_{2^lambda}`.
* **Field vector**: A tuple of field elements, e.g., an element of `F_q^n`.
* **Credit value**: A nonnegative integer in the range `[0, 2^(8*L) - 1]`
  representing an amount of credits, encoded as `<t>_L`.
* **Nullifier**: A uniformly random byte string of length `nu`, denoted `nf`,
  that identifies a token for double-spend detection. Its length is governed by
  collision resistance across all tokens issued under one key (see
  {{parameters}}).
* **Randomness**: A uniformly random byte string of length `rho`, denoted `r`,
  used to hide a commitment. Its length is governed by the hiding of the
  commitment scheme.
* **ByteString**: A sequence of bytes.

From these, the protocol builds the following objects, each defined in
{{protocol}}:

* **Signature**: A UOV signature `s in F_q^{n_uov}` satisfying `P(s) = y` for a
  target `y in F_q^{m_uov}`. The target is the domain-separated hash `y =
  Tag(Com(nf, t, r), x)` of the token commitment and refund.
* **Commitment**: `c = Com(nf, t, r)`, binding a nullifier `nf` and credit
  value `t` under randomness `r`. We instantiate the commitment scheme in one
  of two ways: see {{instantiations}}.
* **Tag**: `Tag(c, x) in F_q^{m_uov}`, the UOV signing target derived from a
  commitment `c` and a refund amount `x`.
* **Token**: `tok = (nf, t, r, x, s)`, the state a client holds for one credit
  token.
* **Proof**: `pf`, a VOLE-in-the-Head zero-knowledge proof for the presentation
  relation of {{spending}}.

## VOLE-in-the-Head Proofs of Knowledge

We write `pf := VOLEitH.Prove(R, X, W)` to denote proving knowledge of a witness
`W` for which the pair `(X, W)` is in the relation `R`, where `X` is the
instance, using the VOLE-in-the-Head proof system of {{FAEST}}. We write `v :=
VOLEitH.Verify(R, X, pf)` to denote verification of `pf` under the same relation
and instance, where the output `v` is a bit.

Relations are specified as a sequence of constraints. Each constraint is an
equation of the instance and witness variables; unlike a linear system, each
side of the equation may be a polynomial over `F_q` of arbitrary degree. Because
the degree of a constraint influences the size of the proof, a relation is
designed to balance the size of the witness against the degree of its
constraints.

> TODO Give a high level overview of VOLEitH. Define any terms we use here, such
> as "small VOLE", "big VOLE", and "grinding".

## Cryptographic Parameters {#parameters}

The protocol is parameterized by the following values, whose concrete
instantiations (ciphersuites) are given in {{instantiations}}:

~~~
Parameters:
  - lambda: Security parameter in bits (e.g., 128). Sets the big VOLE field
            F_{2^lambda} and the default for nu and rho.
  - nu: Nullifier length in bytes. Chosen so that random nullifiers do not
        collide across all tokens issued under one key (see below).
  - rho: Commitment randomness length in bytes. Chosen for commitment hiding.
  - (n_uov, m_uov): UOV dimensions -- n_uov variables, m_uov equations -- over `F_q`.
  - (tau, N, w_grind): VOLE-in-the-Head parameters -- tau VOLE instances,
            N leaves per GGM tree (with tau * log2(N) = lambda), and a
            proof-of-work grinding parameter w_grind.
  - L: Byte width of credit values (1 <= L <= 16). The maximum credit a
       token can hold is 2^(8*L) - 1.
  - H: Extendable-output hash function, written H(M, d) to take input M and squeeze d bytes
       of output (e.g., the KP800 sponge over Keccak-p[800, 12] for
       lambda = 128; see hash commitment). (TODO: does this belong to Parameters?)
~~~

The issuer's public key is a UOV quadratic map `P: F_q^{n_uov} -> F_q^{m_uov}`; the
secret key is a trapdoor for sampling a solution `s` for a given target `P(s) =
t` (see {{UOV}}, Section 3.2). The UOV and VOLE-in-the-Head security levels must
match, so neither weakens the token's overall security ({{system-parameters}}).

The lengths `nu` and `rho` are independent. The nullifier is revealed and must
not collide across tokens issued under one key, so a birthday bound motivates
`nu >= lambda/4` bytes (`= 2*lambda` bits), and a ciphersuite defaults to `nu =
lambda/4`; a compact ciphersuite MAY use a smaller `nu` (e.g., `24` bytes in
{{hash-commitment}} and `28` bytes in the MQ instantiation of
{{mq-commitment}}), trading collision margin for size. The randomness only hides
the commitment; its length is instantiation-dependent -- `rho = lambda/8` bytes
for the hash commitment ({{hash-commitment}}) and `rho = n_com` (the `F_256`
input length, i.e. `n_com` elements of `F_256`) for the MQ commitment
({{mq-commitment}}). Credit values are exactly `L` bytes: the issuer MAY choose
any initial amount in `[1, 2^(8*L) - 1]`, with no cap beyond `L`.

# Protocol Overview {#overview}

The protocol involves two parties: an **issuer** (typically a service provider)
and **clients** (typically users of the service). The issuer holds a long-lived
UOV key pair and maintains a set of accepted nullifiers. The interaction
follows three main phases:

1. **Setup**: The issuer generates a UOV key pair and publishes the public key.
   The UOV signature has relative large public key size, but its signature size
   is small leading to small communication size.
2. **Issuance**: A client requests credits from the issuer. The client commits
   to a fresh random nullifier and to an initial credit count, and the issuer
   blindly signs the message (i.e., signs the hiding commitment of the
   message). The result is a credit token that the issuer cannot link to future
   spends.
3. **Spending (Present-and-Reissue)**: To spend credits, the client reveals the
   nullifier of its current token and proves, in zero knowledge, that (a) it
   holds a valid signature over that token, (b) the token's balance suffices,
   and (c) it has correctly formed a fresh commitment for the remaining
   balance. The issuer checks the proof, checks that the nullifier has not been
   accepted before, records it, and blindly signs the new commitment -- issuing
   change as a new, unlinkable token.

Because each spend simultaneously presents an old token and obtains a new one
for the change, spending and re-issuance are a single combined step. Only the
spend amount is revealed to the issuer; the balance and the client's identity
remain hidden.

# Protocol Specification {#protocol}

This section specifies the protocol algorithms once, over an abstract
commitment `Com` and tag `Tag` ({{commitment-tag}}). This document defines two
constructions of these primitives -- a hash commitment (a TurboSHAKE-style
sponge over `Keccak-p[800, 12]`) and the algebraic multivariate-quadratic (MQ)
commitment of {{BFMRSV25a}} over `F_256`: they share the token structure `(nf,
t, r, x, s)` with effective balance `B = t + x`, and the Issuance and Spend
flows. They differ only in how `Com` and `Tag` are realized. Both
instantiations are given in {{instantiations}}; a deployment MUST fix exactly
one for the lifetime of a key, as part of the ciphersuite ({{instantiations}})
and bound into `dst`.

This section begins with the deployment-wide system parameters
({{system-parameters}}) and the issuer's key generation ({{key-generation}}),
defines the abstract commitment and tag that binds a token's contents
({{commitment-tag}}), gives the interactive Issuance and Spend-and-Reissue
protocols ({{issuance}} and {{spending}}), and then specifies the two concrete
instantiations of `Com` and `Tag` ({{instantiations}}). The zero-knowledge
relation proved during spending is specified as conditions V1--V4 in
{{prove-spend}}; the proof system that establishes it is the VOLE-in-the-Head
proof of {{FAEST}} with parameters fixed by the ciphersuite
({{system-parameters}}).

## System Parameters {#system-parameters}

A deployment fixes two things:

1. A **ciphersuite** ({{instantiations}}), which determines `(lambda, nu, rho,
   n_uov, m_uov, tau, N, w_grind, L, H)`.
2. A **domain separation tag** `dst`, a byte string that identifies the
   deployment and isolates it cryptographically from every other deployment.

The `dst` encodes the version of this specification and an application context
string agreed upon by the client and issuer:

~~~
dst := "RATA-v1:" || application_context
~~~

This string MUST be unique per deployment. It might encode information like the
organization, the service, the deployment environment, and so on. For example:

~~~
"example-corp:rate-limiter:production:2026-01-15"
~~~

## Key Generation {#key-generation}

Key generation is run once by the issuer to produce a long-lived UOV key pair.
The routines `UOV.CompactKeyGen`, `UOV.ExpandPK`, and `UOV.ExpandSK` are those of
{{UOV}} (Section 3.2, Figure 2): `CompactKeyGen` samples a compact key pair
`(cpk, csk)`, `ExpandPK` expands `cpk` into the public UOV map `P`, and
`ExpandSK` expands `csk` into the trapdoor for `P`.

> TODO Ensure all algorithms are deterministic (the caller provides the initial randomness). This way we can easily generate consistent test vectors. We'll also need to plumb this through VOLEitH proving and UOV signing.

~~~~pseudocode
KeyGen():
  Output:
    - sk: Issuer secret key, a UOV trapdoor for P
    - pk: Issuer public key, a UOV map P from F_q^{n_uov} to F_q^{m_uov}

  Steps:
    1.  (cpk, csk) := UOV.CompactKeyGen()
    2.  pk := UOV.ExpandPK(cpk)
    3.  sk := UOV.ExpandSK(csk)
    4.  return (sk, pk)
~~~~

The issuer publishes `pk`. The issuer additionally maintains a set of accepted
nullifiers for rejecting any nullifier it has already accepted.

## Commitment and Tag {#commitment-tag}

The protocol is stated over two abstract primitives, `Com` and `Tag`, whose
concrete realizations are given in {{instantiations}}. Both are
domain-separated by `dst`. Any instantiation MUST provide the following
interface.

**Commitment.** `Com` binds a nullifier `nf` and a credit value `t` under
randomness `r`:

~~~~pseudocode
Com(nf, t, r):
  Input:
    - nf: Nullifier (nu bytes)
    - t: Credit value in [0, 2^(8*L) - 1]
    - r: Randomness (rho bytes)
  Output:
    - c: Commitment
~~~~

`Com` MUST be computationally **hiding** -- given `c`, the pair `(nf, t)` is
concealed by `r` -- and computationally **binding** -- no efficient party can
open one `c` to two distinct `(nf, t)`.

**Tag.** `Tag` derives the UOV signing target from a commitment `c` and a public
refund `x`:

~~~~pseudocode
Tag(c, x):
  Input:
    - c: Commitment
    - x: Refund in [0, 2^(8*L) - 1]
  Output:
    - y: UOV target in F_q^{m_uov}
~~~~

`Tag` hashes the commitment and issuer-granted refund to a full UOV target.
The issuer signs `Tag(c, x)` with the UOV trapdoor, so a single signature jointly
binds the committed contents `(nf, t)` through `c` and the refund `x`. The refund
is an input to `Tag` rather than `Com`, which lets the issuer add credits at
signing time without the client re-committing; at initial issuance `x = 0`.

**Token.** A token is the client-side state carried between presentations:

~~~
Token = (nf, t, r, x, s)     such that     P(s) = Tag( Com(nf, t, r), x )
~~~

where `nf` is the nullifier, `t` the committed credit, `r in {0,1}^(8*rho)` the
commitment randomness, `x` the refund amount, and `s` the UOV signature. The
token's **effective balance** -- the amount the client may spend -- is `B = t +
x`.

## Token Issuance {#issuance}

Issuance mints a fresh token carrying an initial credit balance `T_init in [1,
2^(8*L) - 1]` agreed between the client and issuer. It is a two-message interactive
protocol, structured as the Fischlin blind signature {{Fischlin}} -- commit,
sign, prove-knowledge -- instantiated with UOV and VOLE-in-the-Head.

The client commits to both its nullifier `nf` and the credit balance `t =
T_init`, and sends the commitment `c` to the issuer, who signs it directly via
its UOV target `Tag(c, 0)`. Because `Com` is opaque to the issuer, the client
attaches a zero-knowledge proof that `c` opens to the agreed balance `T_init`;
without it, a malicious client could commit to an arbitrary balance. The
signature `s` is a genuine UOV preimage of `Tag(c, 0)`, which the client stores
in its token.

Blindness does **not** come from masking the signing target. The issuer sees
`c` at issuance (which hides `nf` via `r`) and sees `nf` only at presentation
(where the zero-knowledge proof of {{spending}} hides `c`); because `Com` is
hiding, the issuer cannot link a presented `nf` to the `c` it signed. Every
later presentation proves knowledge of `(nf, t, r, x, s)` satisfying `P(s) =
Tag(Com(nf, t, r), x)` -- the UOV relation of {{commitment-tag}} -- without
revealing `c`.

The issuance relation proves that the commitment `c` opens to the agreed initial
balance `T_init`:

~~~
Relation IssueRelation(c, T_init):
  Instance:
    - c: commitment
    - T_init: agreed initial credit balance, in [1, 2^(8*L) - 1]

  Witness:
    - nf: nullifier
    - r: commitment randomness

  Constraints:
    - c = Com(nf, T_init, r)
~~~

### Client: Issuance Request {#issue-request}

~~~~pseudocode
IssueRequest(T_init):
  Input:
    - T_init in [1, 2^(8*L) - 1]: agreed initial credit balance
  Output:
    - request = (c, pf_init): commitment and well-formedness proof
    - state   = (nf, r): client state for Token Verification

  Steps:
    1.  nf     <- {0,1}^(8*nu)                 // nullifier
    2.  r      <- {0,1}^(8*rho)                // commitment randomness
    3.  c      := Com(nf, T_init, r)           // see Commitment and Tag
    4.  pf_init := VOLEitH.Prove(
          IssueRelation,   // relation
          (c, T_init),     // instance
          (nf, r),         // witness
        )
    5.  request := (c, pf_init)
    6.  state   := (nf, r)
    7.  return (request, state)
~~~~

### Issuer: Issuance Response {#issue-response}

~~~~pseudocode
IssueResponse(sk, request, T_init):
  Input:
    - sk: Issuer secret key (secret seed seed_sk)
    - request = (c, pf_init)
    - T_init in [1, 2^(8*L) - 1]: agreed initial credit balance
  Output:
    - response = s: UOV signature, or INVALID

  Steps:
    1.  if not (0 < T_init < 2^(8*L)): return INVALID
    2.  if VOLEitH.Verify(IssueRelation, (c, T_init), pf_init) = 0: return INVALID
    3.  s <- UOV.Sign(sk, Tag(c, 0))   // preimage of Tag(c, 0): P(s) = Tag(c, 0),
                                       // rejection sampling on singular system
    4.  return s
~~~~

### Client: Token Verification {#verify-issuance}

~~~~pseudocode
VerifyIssuance(pk, state, response, T_init):
  Input:
    - pk = P: Issuer public key
    - state  = (nf, r)
    - response = s
    - T_init: agreed initial credit balance
  Output:
    - tok = (nf, T_init, r, x = 0, s): a fresh token, or INVALID

  Steps:
    1.  c := Com(nf, T_init, r)
    2.  if P(s) != Tag(c, 0): return INVALID
    3.  return tok := (nf, T_init, r, 0, s)
~~~~

The issuer's view of a single issuance is the commitment `c`, the
well-formedness proof `pf_init`, and the signature `s` it produced.
Unlinkability of issuance to any later spend follows from the hiding of `Com`
and the zero-knowledge of the presentation proof ({{spending}}).

## Token Spending {#spending}

Spending lets a client spend `d` credits from a token of effective balance `B =
t + x` (with `0 <= d <= B`), atomically obtaining a fresh token for the change
`B - d`. It is the presentation half of the Fischlin blind signature: the
client reveals the token's nullifier `nf`, proves in zero knowledge that it
holds a valid signature over that token and that a freshly committed change
token is consistent, and the issuer signs the change commitment in its
response.

Spending is a single round trip. The client builds the change commitment `c' =
Com(nf', t + x - d, r')` itself and bundles it into the spend request; the
issuer verifies, ensures the revealed nullifier is fresh, optionally grants an
additional refund `x'` bound in the tag, and returns `s' = UOV.Sign(sk, Tag(c',
x'))`. In the common case `x' = 0` and the change is entirely committed; a
positive `x'` lets the issuer top the token up without a second message
({{commitment-tag}}). Setting `d = 0` re-randomizes a token under a fresh
nullifier -- a re-anonymization operation useful for transferring a token.

Let `L` be the credit byte length ({{system-parameters}}), so all balances lie
in `[0, 2^(8*L) - 1]` and `x, x' in [0, 2^(8*L) - 1]`.

The spend relation binds the spent token to a well-formed change token. It is
specified by the conditions V1--V4 below.

~~~
Relation SpendRelation(pk, nf, d, c'):
  Instance:
    - pk = P: Issuer public key
    - nf: nullifier of the spent token
    - d: amount to spend, in [0, 2^(8*L) - 1]
    - c': change commitment

  Witness:
    - t: committed credit of the spent token
    - r: commitment randomness of the spent token
    - x: refund carried by the spent token
    - s: UOV signature over the spent token
    - nf': nullifier of the change token
    - r': commitment randomness of the change token
    - t': committed change balance

  Constraints:
    - P(s) = Tag(Com(nf, t, r), x)                       // V1: valid signature
    - c' = Com(nf', t', r')                              // V2: change well-formed
    - t' = t + x - d                                     // V3: balance conservation
    - 0 <= t' < 2^(8*L) AND 0 <= x < 2^(8*L) AND 0 <= d < 2^(8*L)  // V4: ranges
~~~

### Client: Spend Proof Generation {#prove-spend}

~~~~pseudocode
ProveSpend(tok, d):
  Input:
    - tok  = (nf, t, r, x, s): a token of effective balance B = t + x
    - d in [0, B]: amount to spend
  Output:
    - proof = (nf, d, c', pf_spend): spend proof
    - state = (nf', t', r'): client state for Refund Token Construction

  Steps:
    1.  if not (0 <= d <= t + x): raise InvalidAmount
    2.  nf' <- {0,1}^(8*nu)                 // fresh nullifier for the change
    3.  r'  <- {0,1}^(8*rho)                // fresh commitment randomness
    4.  t'  := t + x - d                    // committed change balance
    5.  c'  := Com(nf', t', r')
    6.  pf_spend := VOLEitH.Prove(
          SpendRelation,                // relation
          (pk, nf, d, c'),              // instance
          (t, r, x, s, nf', r', t'),    // witness
        )
    7.  proof := (nf, d, c', pf_spend)    // nf, d, c' public; witness hidden
    8.  state := (nf', t', r')
    9.  return (proof, state)
~~~~

### Issuer: Spend Verification and Refund {#verify-spend}

~~~~pseudocode
VerifyAndRefund(sk, proof, x'):
  Input:
    - sk: Issuer secret key (secret seed seed_sk)
    - proof = (nf, d, c', pf_spend)
    - x' in [0, 2^(8*L) - 1]: issuer-granted refund; 0 for no refund
  Output:
    - response = (x', s'): granted refund and signature, or INVALID
  Exceptions:
    - DoubleSpend, raised when nf has already been accepted

  Steps:
    1.  if nf has already been accepted: raise DoubleSpend
    2.  if not (0 <= x' < 2^(8*L)): return INVALID
    3.  if VerifySpend(pk, proof) = INVALID: return INVALID      // see below
    4.  mark nf as accepted
    5.  s' <- UOV.Sign(sk, Tag(c', x'))       // sign the change commitment
                                              // (reuses issuance signing)
    6.  return (x', s')

VerifySpend(pk, proof):
  Input:
    - pk = P: Issuer public key
    - proof = (nf, d, c', pf_spend)
  Output:
    - VALID or INVALID

  Steps:
    1.  if not (0 <= d < 2^(8*L)): return INVALID
    2.  if VOLEitH.Verify(SpendRelation, (pk, nf, d, c'), pf_spend) = 0:
          return INVALID
    3.  return VALID
~~~~

The issuer MUST mark `nf` as accepted (step 4) before the signature is
released, so that a client cannot obtain two change tokens from one spend by
replaying the request.

Verification checks only the zero-knowledge proof against the public inputs
`(pk, nf, d, c')`; conditions V1--V4 of {{prove-spend}} are enforced inside
`pf_spend`. In particular V1 establishes that the client holds an issuer
signature over some token whose effective balance is `t + x`, V3 and V4
establish `d <= t + x` and that the change `t'` is a valid balance, and V2 binds
the change to the commitment `c'` the issuer is about to sign. The issuer learns
the spent amount `d` and the nullifier `nf`, but neither the effective balance
`B` nor the change `t'`.

### Client: Refund Token Construction {#refund-token}

~~~~pseudocode
VerifyRefund(pk, state, response):
  Input:
    - pk = P: Issuer public key
    - state    = (nf', t', r')
    - response = (x', s')
  Output:
    - tok' = (nf', t', r', x', s'): the change token, or INVALID

  Steps:
    1.  if not (0 <= x' < 2^(8*L)): return INVALID
    2.  c' := Com(nf', t', r')
    3.  if P(s') != Tag(c', x'): return INVALID
    4.  return tok' := (nf', t', r', x', s')
~~~~

The change token has effective balance `B' = t' + x' = (t + x - d) + x'`, and is
unlinkable to the spent token: the issuer saw only the hiding commitment `c'`
and the public `(nf, d, x')`, none of which reveal `nf'` or the change balance.

# Instantiations {#instantiations}

The protocol of {{key-generation}} through {{spending}} is parameterized by the
commitment `Com` and tag `Tag` of {{commitment-tag}}. This section gives the two
concrete instantiations. A deployment MUST fix exactly one for the lifetime of a
key (bound into `dst`); the choice is part of the ciphersuite.

Both realize the same abstract interface, so all of Issuance ({{issuance}}),
Spend ({{spending}}), the conditions V1--V4, double-spend handling, and
blindness are inherited unchanged. They differ only in `Com`, `Tag`, the
deployment-wide parameters derived from `dst`, and the resulting UOV dimensions
`(n_uov, m_uov)`.

## Hash commitment (`Keccak-p[800, 12]`) {#hash-commitment}

Here both `Com` and `Tag` are realized by `KP800`, a TurboSHAKE
{{!RFC9861}} sponge over the reduced-round permutation `Keccak-p[800, 12]`
{{FIPS202}}, modeled as a random oracle and domain-separated by `dst`.
`KP800(M, d)` squeezes `d` bytes of output, and `KP800(M)` defaults to
`d = 2*lambda/8` bytes (i.e. `2*lambda` bits). Distinct one-byte
labels separate commitment hashing from UOV-target hashing. In the Spend
relation ({{prove-spend}}), V1 evaluates `Com` and `Tag` for the old token, while
V2 evaluates `Com` for the change token. A spend therefore evaluates
`Keccak-p[800, 12]` three times in-circuit. The MQ instantiation
({{mq-commitment}}) removes these evaluations entirely.

The `800`-bit permutation, rather than TurboSHAKE128's `1600`-bit
`Keccak-p[1600, 12]`, halves the in-circuit state. Its 256-bit capacity leaves a
544-bit (`68`-byte) rate, which is sufficient for each fixed-length input below
to fit in one absorb block and for each output to fit in one squeeze block.

**Commitment.** `Com` binds a nullifier `nf` and a credit value `t` under
randomness `r`:

~~~~pseudocode
Com(nf, t, r):
  Input:
    - nf: Nullifier (nu bytes)
    - t: Credit value in [0, 2^(8*L) - 1]
    - r: Randomness (rho bytes)
  Output:
    - c: Commitment (lambda/4 bytes)

  Steps:
    1.  return KP800(0xAC || dst || nf || <t>_L || r)
~~~~

**Tag.** `Tag` hashes a commitment and public refund to a full UOV target of
`m_uov` bytes, where `m_uov` is the number of UOV equations ({{system-parameters}}):

~~~~pseudocode
Tag(c, x):
  Input:
    - c: Commitment (lambda/4 bytes)
    - x: Refund in [0, 2^(8*L) - 1]
  Output:
    - y: UOV target (m_uov bytes, = m_uov elements of F_256)

  Steps:
    1.  return KP800(0xAD || dst || c || <x>_L, m_uov)
~~~~

Both preimages have fixed-length fields and parse unambiguously. The `Com`
preimage is `1 + 18 + 24 + 8 + 16 = 67` bytes, leaving the final byte of the
68-byte rate for the sponge separator and padding. The `Tag` preimage is `1 +
18 + 32 + 8 = 59` bytes. Each call therefore requires one
`Keccak-p[800, 12]` permutation. At initial issuance `x = 0`, but `Tag(c, 0)` is
still a separate, domain-separated hash of `c` and zero.

**Security.** Commitment hiding follows from the `rho = 16` bytes of fresh
randomness, and binding follows from collision resistance of the domain-separated
`Com` random oracle. `Tag(c, x)` is a full random-oracle image that jointly binds
the commitment and refund before UOV inversion. This retains hash-and-sign
target semantics and avoids a chosen-tail or translated-target UOV assumption.
A complete protocol proof additionally requires knowledge soundness of the
VOLEitH proof, faithful integer arithmetic, and atomic nullifier handling
({{security}}).

**Parameter selection.** The knobs chosen for the ciphersuite
`RATA-KP800-uovIp`:

| Parameter | Value |
|-----------|-------|
| Security `lambda` | `128` |
| Nullifier `nu` | `24` bytes |
| Randomness `rho` | `16` bytes |
| Credit width `L` | `8` (`t, x, d in [0, 2^64 - 1]`) |
| Domain-separation tag `dst` | `18` bytes |
| Commitment `c` | `lambda/4 = 32` bytes |
| UOV `(n_uov, m_uov, q)` | `(112, 44, 256)` (`uov-Ip`) |
| VOLEitH `(tau, w_grind)` | `(11, 7)` (FAEST-128s) |

**API sizes.** Everything below is derived from the parameters above and is
given in bytes.

| Function | Input | Output |
|----------|-------|--------|
| `Com(nf, t, r)` | label `0xAC` = `1`, `dst: 18`, `nf: 24`, `<t>_L: 8`, `r: 16` | `c: 32` |
| `Tag(c, x)` | label `0xAD` = `1`, `dst: 18`, `c: 32`, `<x>_L: 8` | `y: m_uov = 44` |
| `P(s)` (UOV) | `s: n_uov = 112` | `y: m_uov = 44` |

## MQ commitment (BFMRSV25a) {#mq-commitment}

Here `Com` and `Tag` are realized by the algebraic multivariate-quadratic (MQ)
commitment of {{BFMRSV25a}} over `F_256`.  This removes the in-circuit hash:
because both `Com` and `Tag` are degree-2 relations over `F_256`, conditions V1
and V2 of {{prove-spend}} are pure `F_256` arithmetic with no Keccak in-circuit.
The realization differs from {{hash-commitment}} in two ways:

1. **`Com` is algebraic.** `Com(nf, t, r) = (EmbedNullifierBalance(nf, t) +
   F(r), G(r))` for public general quadratic maps `F`, `G` from the `GenerateParameters` function defined
   below.
2. **`Tag` is affine and homomorphic.** The MQ commitment is
   constant-additively homomorphic, so the refund is applied by a homomorphic
   addition rather than a hash: `Tag(c, x) = c + EmbedRefund(x)`, a degree-1 map
   that adds the issuer-granted refund `x` into a reserved commitment
   coordinate. The signing target `P(s) = Tag(Com(nf, t, r), x)` is unchanged
   form.

**GenerateParameters.** The MQ instantiation needs public commitment maps `F`,
`G`, produced by a routine `GenerateParameters`. Ours derives `F`, `G`
deterministically from `dst` by a nothing-up-my-sleeve expansion, so it needs no
trusted setup. Unlike the hash instantiation of {{hash-commitment}} (which evaluates
`Keccak-p[800, 12]` for both `Com` and `Tag` inside the spend proof), this
parameter expansion is never proven in zero knowledge. It therefore uses
standard SHAKE128 (FIPS 202) {{FIPS202}} -- the more conservatively reviewed
XOF:

* Two general (inhomogeneous) quadratic maps `F: F_256^{n_com} -> F_256^k` and
  `G: F_256^{n_com} -> F_256^{m_uov-k}`, obtained as `(F, G) =
  GenerateParameters(dst)`.

~~~~pseudocode
GenerateParameters(dst):
  Input:
    - dst: deployment domain-separation tag
  Output:
    - F: F_256^{n_com} -> F_256^k, G: F_256^{n_com} -> F_256^{m_uov-k}   // public quadratic maps
  Steps:
    1.  stream := SHAKE128("RATA-MQ-maps:" || dst)
    2.  for each output equation i in [m_uov]:
    3.      M_i := bytesIntoUpper(stream.next(n_com(n_com+1)/2))   // quadratic part, in F_256^{n_com * n_com}
    4.      l_i := stream.next(n_com)                              // linear part, in F_256^{n_com}
    5.      Q_i := (M_i, l_i)   such that   Q_i(x) = x^T M_i x + l_i . x
    6.  F := (Q_0, ..., Q_{k-1})                       // first k equations
    7.  G := (Q_k, ..., Q_{m_uov-1})                   // remaining m_uov-k equations
    8.  return (F, G)
~~~~

`bytesIntoUpper(b)` fills the upper triangle of an `n_com x n_com` matrix over
`F_256` row-major from the bytes `b`, one element per byte, with all other
entries zero. Each output equation is a general (inhomogeneous) quadratic map
`Q_i(x) = x^T M_i x + l_i . x` in the `n_com` variables, with `M_i` the quadratic
part and `l_i` the linear part. The linear terms are essential: a purely
homogeneous map (`l_i = 0`) has `F(0) = G(0) = 0` and is scaling-covariant
(`Q_i(a x) = a^2 Q_i(x)`), which admits a forgery.

**Commitment.** `Com` binds a nullifier `nf` and a credit value `t` under
randomness `r`, following the MQ commitment construction in {{BFMRSV25a}}:

~~~~pseudocode
Com(nf, t, r):
  Input:
    - nf: Nullifier (nu bytes)
    - t: Credit value in [0, 2^(8*L) - 1]
    - r: Randomness (rho = n_com bytes, parsed as n_com elements of F_256)
  Output:
    - c: Commitment (m_uov elements in F_256)
  Steps:
    1.  msg := EmbedNullifierBalance(nf, t)   in F_256^k   // refund coordinate = 0
    2.  return ( msg + F(r), G(r) )  in F_256^{m_uov}
~~~~

`EmbedNullifierBalance(nf, t)` returns a message vector `msg in F_256^k`, one
`F_256` element per byte. The first `nu` elements hold the nullifier, one byte
per element (`msg[i] = byte(nf[i])` for each `i in [nu)`); the next `L`
elements hold the balance encoding `<t>_L`; the following `L` elements are the
refund slot, left zero here and written later by `Tag`; and the remaining `k -
off_refund - L` elements are reserved and set to zero (there are none unless
`k > off_refund + L`).

**Tag.** The MQ commitment is *constant-additively homomorphic*: adding a public
vector to `c` shifts the committed message without touching the binding block
`G(r)` and without knowledge of `r` {{BFMRSV25a}}. `Tag` uses this to write the
issuer-granted refund `x` into the (zero) refund coordinate:

~~~~pseudocode
Tag(c, x):
  Input:
    - c: Commitment (m_uov elements in F_256)
    - x: Refund in [0, 2^(8*L) - 1]
  Output:
    - y: UOV target (m_uov elements in F_256)
  Steps:
    1.  return c + EmbedRefund(x)     in F_256^{m_uov}   // degree-1, no hash
~~~~

`EmbedRefund(x)` returns a vector `e in F_256^{m_uov}` that is zero everywhere except
the refund slot: its `L` elements starting at `off_refund = nu + L` hold
the refund encoding `<x>_L`.

Because the commitment length exceeds the standard NIST UOV output size, the UOV
parameters are enlarged to accommodate it, as reflected in the parameters below.

**Security.** Hiding is *heuristic* computational with respect to the
best-known attack (hybrid exhaustive-search + XL-Wiedemann {{CCNY12}}). Binding
is *computational*, reduced to collision-resistance of `G` (finding `r != r'`
with `G(r) = G(r')`, a bilinear MQ problem that is NP-complete in the worst
case). Separately, one-more unforgeability of the signed commitment rests on the
interactive one-more *quadratic-claw* assumption, flagged as unexplored in
{{BFMRSV25a}}.

**Parameter selection.**  The ciphersuite `RATA-MQ128-k32` takes the aggressive
*heuristic-hiding / computational-binding* row of {{BFMRSV25a}}, Table 3 (`q =
256`, so one commitment element is one byte), which minimizes commitment size.
Here `m_uov` is pinned by the commitment length rather than chosen for signature
compactness; with `m_uov` fixed, the only free UOV knob is the input size `n_uov`,
set to the smallest value keeping every known attack at `>= 2^lambda` under the
UOV estimator.

| Parameter | Value |
|-----------|-------|
| Security `lambda` | `128` |
| Commitment `(k, n_com, m_uov)` | `(32, 83, 131)` ({{BFMRSV25a}}, Table 3) |
| Nullifier `nu` | `28` bytes |
| Credit width `L` | `2` (`t, x, d in [0, 2^16 - 1]`) |
| UOV `n_uov` | `275` (`m_uov = 131`, `q = 256` shared with the commitment) |
| VOLEitH `(tau, w_grind)` | `(11, 7)` (FAEST-128s) |

Security margins: the binding block satisfies `m_uov - k = n_com + lambda/log2(q) =
n_com + 16`. Because `m_uov = 131` is far larger than a standard UOV set, `n_uov =
275` was fixed as the minimum passing a 128-bit check under the
CryptographicEstimators `UOVEstimator` ({{CryptEst}}, which implements the
{{UOV}} Section 4 attacks).

**API sizes.** Everything below is derived from the parameters above and is
given in bytes (one `F_256` element each). `F, G` are the public maps from
`GenerateParameters(dst)`; there is no in-circuit hash.

| Function | Input | Output |
|----------|-------|--------|
| `Com(nf, t, r)` | `nf: nu = 28`, `<t>_L: L = 2`, `r: n_com = 83` (`= rho`) | `c: m_uov = 131` |
| `Tag(c, x)` | `c: 131`, `<x>_L: L = 2` | `y: m_uov = 131` |
| `P(s)` (UOV) | `s: n_uov = 275` | `y: m_uov = 131` |

The message `msg = EmbedNullifierBalance(nf, t)` lays out `k = 32` bytes as `nf
(28) || <t>_L (2) || <x>_L (2)`, with the refund slot at `off_refund = nu +
L = 30` left zero until `Tag` writes it (no reserved bytes, since `off_refund
+ L = k`). Derived map and signature dimensions: `F: F_256^83 -> F_256^32`,
`G: F_256^83 -> F_256^99`, and `v = n_uov - m_uov = 144`.

# Security Considerations {#security}

> TODO Security reduction for both variants to (one-more-)UOV problem. As part of this,
> figure out if the constant-addition hommorphism trick for the MQ variant incurs a
> security loss.

> TODO Finalize parameters MQ variant (including the UOV parameters used), pending further cryptanalysis of the commitment.
> TODO Remind the reader here how the current parameters were chosen.

# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

The use of `Keccak-p[800,12]` in this application was proposed by Bas Westerbaan.
