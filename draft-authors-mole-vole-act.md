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
specified, one in which the commitment is instantiated with Keccak-p[800,12]
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

ACT {{ACT}} builds on BBS signatures over prime-order groups. Its
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
**double-spend prevention**, and it supports the same use cases, such as
**rate limiting** and **API credits**.

Beyond ACT, Ratatouille additionally provides:

1. **Full Post-Quantum Security**: All security properties -- unforgeability,
   unlinkability, and double-spend prevention -- are conjectured to hold against
   adversaries equipped with a large-scale quantum computer. Security reduces to
   the UOV and MQ problems and to the security of standard symmetric primitives.

This post-quantum security comes at a cost in **performance**: presentation
proofs are larger than in the classical construction -- on the order of
kilobytes to tens of kilobytes. Nonetheless, the protocol remains practical for
modern web services, with efficient signing, verification, and proof
generation.

> TODO: Is public verifiability of the token useful? Using public verifiability we can enable a
> token issued by one moderator can be redeemed at another: Moderator 1 can
> redeem a token issued by Moderator 2, at the cost of revealing the identity of
> Moderator 1 to Moderator 2. Is this trade-off worth supporting?

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
* `<t>_L`: The `L`-bit big-endian encoding of a nonnegative integer `t < 2^L`
  as an element of `F_2^L`.
* `H`: A cryptographic extendable-output hash function, modeled as a random
  oracle (see {{protocol}}). Domain separation is applied by prefixing a
  distinct label and the deployment tag `dst` to each use.

## Data Types

The protocol uses the following primitive data types:

* **Bit**: An element of `F_2`.
* **Field element**: An element of `F_q` or `F_{2^lambda}`.
* **Field vector**: A tuple of field elements, e.g., an element of `F_q^n`.
* **Credit value**: A nonnegative integer in the range `[0, 2^L - 1]`
  representing an amount of credits, encoded as `<t>_L`.
* **Nullifier**: A uniformly random bit string of length `nu`, denoted `nf`,
  that identifies a token for double-spend detection. Its length is governed by
  collision resistance across all tokens issued under one key (see
  {{parameters}}).
* **Randomness**: A uniformly random bit string of length `rho`, denoted `r`,
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

> TODO Define Prove{} and Verify{} APIs, with references to FAEST. Give a high
> level overview of VOLEitH. Define any terms we use here, such as "small
> VOLE", "big VOLE", and "grinding".

## Cryptographic Parameters {#parameters}

The protocol is parameterized by the following values, whose concrete
instantiations (ciphersuites) are given in {{instantiations}}:

~~~
Parameters:
  - lambda: Security parameter in bits (e.g., 128). Sets the big VOLE field
            F_{2^lambda} and the default for nu and rho.
  - nu: Nullifier length in bits. Chosen so that random nullifiers do not
        collide across all tokens issued under one key (see below).
  - rho: Commitment randomness length in bits. Chosen for commitment hiding.
  - (n_uov, m_uov): UOV dimensions -- n_uov variables, m_uov equations -- over `F_q`.
  - (tau, N, w_grind): VOLE-in-the-Head parameters -- tau VOLE instances,
            N leaves per GGM tree (with tau * log2(N) = lambda), and a
            proof-of-work grinding parameter w_grind.
  - L: Bit width of credit values (1 <= L <= 128). The maximum credit a
       token can hold is 2^L - 1.
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
`nu >= 2*lambda`, and a ciphersuite defaults to `nu = 2*lambda`; a compact
ciphersuite MAY use a smaller `nu` (e.g., `192` bits in {{hash-commitment}} and `224` bits in the MQ instantiation of
{{mq-commitment}}), trading collision margin for size. The randomness only hides
the commitment; its length is instantiation-dependent -- `rho = lambda` for the
hash commitment ({{hash-commitment}}) and `rho = 8*n_com` (the `F_256` input
length, i.e. `n_com` elements of `F_256`) for the MQ commitment
({{mq-commitment}}). Credit values are exactly `L` bits: the issuer MAY choose
any initial amount in `[1, 2^L - 1]`, with no cap beyond `L`.

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

Key generation is run once by the issuer. It produces a long-lived UOV key
pair. The routines `ExpandSK`, `ExpandPK`, and `Upper` are those of {{UOV}}
(Section 3.2, Figure 2): `ExpandSK` expands the secret seed into the trapdoor
(plus a public seed), `ExpandPK` expands that public seed `seed_pk` into the
first and second quadratic-map blocks `P^(1)` and `P^(2)`, and `Upper`
({{UOV}}, Section 3.1) derives the third block `P^(3)` from the first two and
the trapdoor.

We use the compressed form: the public key `pk` is just the public seed
`seed_pk` and the third quadratic-map blocks `P^(3)` while the secret key `sk`
is the secret seed `seed_sk`.

~~~
KeyGen():
  Input: None
  Output:
    - sk: Issuer secret key (secret seed seed_sk)
    - pk: Issuer public key (public seed seed_pk and blocks P^(3))

  Steps:
    1.  seed_sk <- {0,1}^(seed_sk_len)
    2.  (seed_pk, O) := ExpandSK(seed_sk)   // trapdoor O in F_q^(v * m_uov),
                                           // with v = n_uov - m_uov
    3.  {(P_i^(1), P_i^(2))}_{i in [m_uov]} := ExpandPK(seed_pk)
    4.  for i in [m_uov]:
    5.      P_i^(3) := Upper( - O^T P_i^(1) O - O^T P_i^(2) O )
    6.  sk := seed_sk
    7.  pk := (seed_pk, { P_i^(3) }_{i in [m_uov]})
    8.  return (sk, pk)
~~~

The issuer publishes `pk`. The issuer additionally maintains a set of accepted
nullifiers for rejecting any nullifier it has already accepted.

## Commitment and Tag {#commitment-tag}

The protocol is stated over two abstract primitives, `Com` and `Tag`, whose
concrete realizations are given in {{instantiations}}. Both are
domain-separated by `dst`. Any instantiation MUST provide the following
interface.

**Commitment.** `Com` binds a nullifier `nf` and a credit value `t` under
randomness `r`:

~~~
Com(nf, t, r):
  Input:
    - nf: Nullifier (nu bits)
    - t: Credit value in [0, 2^L - 1]
    - r: Randomness (rho bits)
  Output:
    - c: Commitment
~~~

`Com` MUST be computationally **hiding** -- given `c`, the pair `(nf, t)` is
concealed by `r` -- and computationally **binding** -- no efficient party can
open one `c` to two distinct `(nf, t)`.

**Tag.** `Tag` derives the UOV signing target from a commitment `c` and a public
refund `x`:

~~~
Tag(c, x):
  Input:
    - c: Commitment
    - x: Refund in [0, 2^L - 1]
  Output:
    - y: UOV target in F_q^{m_uov}
~~~

`Tag` hashes the commitment and issuer-granted refund to a full UOV target.
The issuer signs `Tag(c, x)` with the UOV trapdoor, so a single signature jointly
binds the committed contents `(nf, t)` through `c` and the refund `x`. The refund
is an input to `Tag` rather than `Com`, which lets the issuer add credits at
signing time without the client re-committing; at initial issuance `x = 0`.

**Token.** A token is the client-side state carried between presentations:

~~~
Token = (nf, t, r, x, s)     such that     P(s) = Tag( Com(nf, t, r), x )
~~~

where `nf` is the nullifier, `t` the committed credit, `r in {0,1}^rho` the
commitment randomness, `x` the refund amount, and `s` the UOV signature. The
token's **effective balance** -- the amount the client may spend -- is `B = t +
x`.

## Token Issuance {#issuance}

Issuance mints a fresh token carrying an initial credit balance `T_init in [1,
2^L - 1]` agreed between the client and issuer. It is a two-message interactive
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

### Client: Issuance Request {#issue-request}

~~~
IssueRequest(T_init):
  Input:
    - T_init in [1, 2^L - 1]: agreed initial credit balance
  Output:
    - request = (c, pf_init): commitment and well-formedness proof
    - state   = (nf, r): client state for Token Verification

  Steps:
    1.  nf     <- {0,1}^nu                     // nullifier
    2.  r      <- {0,1}^rho                    // commitment randomness
    3.  c      := Com(nf, T_init, r)           // see Commitment and Tag
    4.  pf_init := Prove{
          public:   (c, T_init)
          private:  (nf, r)
          relation: c = Com(nf, T_init, r)    // opens c to the agreed T_init
        }
    5.  request := (c, pf_init)
    6.  state   := (nf, r)
    7.  return (request, state)
~~~

### Issuer: Issuance Response {#issue-response}

~~~
IssueResponse(sk, request, T_init):
  Input:
    - sk: Issuer secret key (secret seed seed_sk)
    - request = (c, pf_init)
    - T_init in [1, 2^L - 1]: agreed initial credit balance
  Output:
    - response = s: UOV signature, or INVALID

  Steps:
    1.  if not (0 < T_init < 2^L): return INVALID
    2.  verify pf_init against (c, T_init); if invalid, return INVALID
    3.  s <- UOV.Sign(sk, Tag(c, 0))   // preimage of Tag(c, 0): P(s) = Tag(c, 0),
                                       // rejection sampling on singular system
    4.  return s
~~~

### Client: Token Verification {#verify-issuance}

~~~
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
~~~

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

Let `L` be the credit bit length ({{system-parameters}}), so all balances lie
in `[0, 2^L - 1]` and `x, x' in [0, 2^L - 1]`.

### Client: Spend Proof Generation {#prove-spend}

~~~
ProveSpend(tok, d):
  Input:
    - tok  = (nf, t, r, x, s): a token of effective balance B = t + x
    - d in [0, B]: amount to spend
  Output:
    - proof = (nf, d, c', pf_spend): spend proof
    - state = (nf', t', r'): client state for Refund Token Construction

  Steps:
    1.  if not (0 <= d <= t + x): raise InvalidAmount
    2.  nf' <- {0,1}^nu                     // fresh nullifier for the change
    3.  r'  <- {0,1}^rho                    // fresh commitment randomness
    4.  t'  := t + x - d                    // committed change balance
    5.  c'  := Com(nf', t', r')
    6.  pf_spend := Prove{
          public:   (pk, nf, d, c')
          private:  (t, r, x, s, nf', r', t')
          relation:
            //  V1  old token carries a valid signature
            P(s) = Tag(Com(nf, t, r), x)
            //  V2  change commitment is well-formed
            AND c' = Com(nf', t', r')
            //  V3  balance conservation
            AND t' = t + x - d
            //  V4  ranges: valid balances, non-negative debit
            AND 0 <= t' < 2^L  AND  0 <= x < 2^L  AND  0 <= d < 2^L
        }
    7.  proof := (nf, d, c', pf_spend)    // nf, d, c' public; witness hidden
    8.  state := (nf', t', r')
    9.  return (proof, state)
~~~

### Issuer: Spend Verification and Refund {#verify-spend}

~~~
VerifyAndRefund(sk, proof, x'):
  Input:
    - sk: Issuer secret key (secret seed seed_sk)
    - proof = (nf, d, c', pf_spend)
    - x' in [0, 2^L - 1]: issuer-granted refund; 0 for no refund
  Output:
    - response = (x', s'): granted refund and signature, or INVALID
  Exceptions:
    - DoubleSpend, raised when nf has already been accepted

  Steps:
    1.  if nf has already been accepted: raise DoubleSpend
    2.  if not (0 <= x' < 2^L): return INVALID
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
    1.  if not (0 <= d < 2^L): return INVALID
    2.  verify pf_spend against public inputs (pk, nf, d, c');
        if verification fails: return INVALID
    3.  return VALID
~~~

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

~~~
VerifyRefund(pk, state, response):
  Input:
    - pk = P: Issuer public key
    - state    = (nf', t', r')
    - response = (x', s')
  Output:
    - tok' = (nf', t', r', x', s'): the change token, or INVALID

  Steps:
    1.  if not (0 <= x' < 2^L): return INVALID
    2.  c' := Com(nf', t', r')
    3.  if P(s') != Tag(c', x'): return INVALID
    4.  return tok' := (nf', t', r', x', s')
~~~

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

## Hash commitment (Keccak-p[800, 12]) {#hash-commitment}

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

~~~
Com(nf, t, r):
  Input:
    - nf: Nullifier (nu bits)
    - t: Credit value in [0, 2^L - 1]
    - r: Randomness (rho bits)
  Output:
    - c: Commitment (2*lambda bits)

  Steps:
    1.  return KP800(0xAC || dst || nf || <t>_L || r)
~~~

**Tag.** `Tag` hashes a commitment and public refund to a full UOV target of
`m_uov` bytes, where `m_uov` is the number of UOV equations ({{system-parameters}}):

~~~
Tag(c, x):
  Input:
    - c: Commitment (2*lambda bits)
    - x: Refund in [0, 2^L - 1]
  Output:
    - y: UOV target (m_uov*8 bits, = m_uov elements of F_256)

  Steps:
    1.  return KP800(0xAD || dst || c || <x>_L, m_uov)
~~~

Both preimages have fixed-length fields and parse unambiguously. The `Com`
preimage is `1 + 18 + 24 + 8 + 16 = 67` bytes, leaving the final byte of the
68-byte rate for the sponge separator and padding. The `Tag` preimage is `1 +
18 + 32 + 8 = 59` bytes. Each call therefore requires one
`Keccak-p[800, 12]` permutation. At initial issuance `x = 0`, but `Tag(c, 0)` is
still a separate, domain-separated hash of `c` and zero.

**Security.** Commitment hiding follows from the `rho = 128` bits of fresh
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
| Nullifier `nu` | `192` bits |
| Randomness `rho` | `128` bits |
| Credit width `L` | `64` (`t, x, d in [0, 2^64 - 1]`) |
| Domain-separation tag `dst` | `18` bytes |
| Commitment `c` | `2*lambda = 256` bits (`32` bytes) |
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
   F(r), G(r))` for public quadratic maps `F`, `G` from the
   `GenerateParameters` function defined below.
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

* Two quadratic maps `F: F_256^{n_com} -> F_256^k` and `G: F_256^{n_com} ->
  F_256^{m_uov-k}`, obtained as `(F, G) = GenerateParameters(dst)`.

~~~
GenerateParameters(dst):
  Input:
    - dst: deployment domain-separation tag
  Output:
    - F: F_256^{n_com} -> F_256^k, G: F_256^{n_com} -> F_256^{m_uov-k}   // public quadratic maps
  Steps:
    1.  stream := SHAKE128("RATA-MQ-maps:" || dst)
    2.  for each output equation i in [m_uov]:
    3.      M_i := bytesIntoUpper(stream.next(n_com(n_com+1)/2))   // in F_256^{n_com * n_com}
    4.  F := (M_0, ..., M_{k-1})                       // first k equations
    5.  G := (M_k, ..., M_{m_uov-1})                   // remaining m_uov-k equations
    6.  return (F, G)
~~~

`bytesIntoUpper(b)` fills the upper triangle of an `n_com x n_com` matrix over
`F_256` row-major from the bytes `b`, one element per byte, with all other
entries zero; each `M_i` is the coefficient matrix of a quadratic form in the
`n_com` variables.

**Commitment.** `Com` binds a nullifier `nf` and a credit value `t` under
randomness `r`, following the MQ commitment construction in {{BFMRSV25a}}:

~~~
Com(nf, t, r):
  Input:
    - nf: Nullifier (nu bits)
    - t: Credit value in [0, 2^L - 1]
    - r: Randomness (rho = 8*n_com bits, parsed as n_com elements of F_256)
  Output:
    - c: Commitment (m_uov elements in F_256)
  Steps:
    1.  msg := EmbedNullifierBalance(nf, t)   in F_256^k   // refund coordinate = 0
    2.  return ( msg + F(r), G(r) )  in F_256^{m_uov}
~~~

`EmbedNullifierBalance(nf, t)` returns a message vector `msg in F_256^k`, one
`F_256` element per byte. The first `nu/8` elements hold the nullifier, one byte
per element (`msg[i] = byte(nf[i])` for each `i in [nu/8)`); the next `L/8`
elements hold the balance encoding `<t>_L`; the following `L/8` elements are the
refund slot, left zero here and written later by `Tag`; and the remaining `k -
off_refund - L/8` elements are reserved and set to zero (there are none unless
`k > off_refund + L/8`).

**Tag.** The MQ commitment is *constant-additively homomorphic*: adding a public
vector to `c` shifts the committed message without touching the binding block
`G(r)` and without knowledge of `r` {{BFMRSV25a}}. `Tag` uses this to write the
issuer-granted refund `x` into the (zero) refund coordinate:

~~~
Tag(c, x):
  Input:
    - c: Commitment (m_uov elements in F_256)
    - x: Refund in [0, 2^L - 1]
  Output:
    - y: UOV target (m_uov elements in F_256)
  Steps:
    1.  return c + EmbedRefund(x)     in F_256^{m_uov}   // degree-1, no hash
~~~

`EmbedRefund(x)` returns a vector `e in F_256^{m_uov}` that is zero everywhere except
the refund slot: its `L/8` elements starting at `off_refund = nu/8 + L/8` hold
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
| Nullifier `nu` | `224` bits |
| Credit width `L` | `16` (`t, x, d in [0, 2^16 - 1]`) |
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
| `Com(nf, t, r)` | `nf: nu/8 = 28`, `<t>_L: L/8 = 2`, `r: n_com = 83` (`= rho/8`) | `c: m_uov = 131` |
| `Tag(c, x)` | `c: 131`, `<x>_L: L/8 = 2` | `y: m_uov = 131` |
| `P(s)` (UOV) | `s: n_uov = 275` | `y: m_uov = 131` |

The message `msg = EmbedNullifierBalance(nf, t)` lays out `k = 32` bytes as `nf
(28) || <t>_L (2) || <x>_L (2)`, with the refund slot at `off_refund = nu/8 +
L/8 = 30` left zero until `Tag` writes it (no reserved bytes, since `off_refund
+ L/8 = k`). Derived map and signature dimensions: `F: F_256^83 -> F_256^32`,
`G: F_256^83 -> F_256^99`, and `v = n_uov - m_uov = 144`.

# Security Considerations {#security}

> TODO Security reduction for both variants to (one-more-)UOV problem. As part of this,
> figure out if the constant-addition hommorphism trick for the MQ variant incurs a
> security loss.

> TODO Finalize parameters MQ variant (including the UOV parameters used), pending further cryptanalysis of the commitment.
> [Remind the reader here how the current parameters were chosen.]

# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

# Performance {#performance}

The hash instantiation of {{hash-commitment}} evaluates one in-circuit
`Keccak-p[800, 12]` permutation per issuance and three per spend (recomputing
the old commitment, the `Tag`, and the change commitment). The figures below were
measured at `lambda = 128`, single-threaded on a laptop-class aarch64 core. The
numbers are indicative and are not normative bounds.

| Operation | Hash (KP800, {{hash-commitment}}) |
|-----------|-----------------------------------|
| `IssueRequest` (prove) | 60 ms |
| `IssueResponse` (verify) | 26 ms |
| `ProveSpend` | 696 ms |
| `VerifyAndRefund` (verify) | 66 ms |

| Proof | Hash (KP800) |
|-------|--------------|
| Issuance `pf_init` | 7.8 KiB |
| Spend `pf_spend` | 14.2 KiB |

The MQ instantiation was measured at `lambda = 128`, single-threaded on a
laptop-class aarch64 core. The numbers are indicative and are not normative
bounds.

| Operation | MQ (BFMRSV25a, {{mq-commitment}}) |
|-----------|------------------------------------|
| `IssueRequest` (prove) | 24 ms |
| `IssueResponse` (verify) | 65 ms |
| `ProveSpend` | 85 ms |
| `VerifyAndRefund` (verify) | 57 ms |

| Proof | MQ |
|-------|----|
| Issuance `pf_init` | 4.3 KiB |
| Spend `pf_spend` | 9.0 KiB |

The MQ instantiation removes all in-circuit Keccak evaluations, but its widened
UOV trapdoor makes key generation a one-time cost of several seconds. Its
performance also relies on folding the public quadratic forms with precomputed
lift tables; without that optimization, the UOV fold dominates proving time.

**Our One-More-UOV blind signature.** As a building block we also implement a
One-More-UOV blind signature -- the hash-free construction of PoMFRIT
{{PoMFRIT}} instantiated with UOV instead of MAYO. It is a plain blind signature
(no balance, nullifier, or change), so it is not an ACT, but it isolates the
cost of proving a UOV preimage in VOLEitH with no in-circuit hash. Measured on
the same aarch64 core with the compact `uov-Ip` map (`n_uov = 112`, `m_uov = 44`);
`Blind`/`BlindSign`/`Finalize` correspond to `Sig1`/`Sig2`/`Sig3` below.

| Operation | One-More-UOV |
|-----------|--------------|
| `Blind` (request) | 15 ms |
| `BlindSign` (issuer preimage) | 1.8 ms |
| `Finalize` (show / prove) | 80 ms |
| `Verify` | 47 ms |
| issuance `\|t\|` | 44 B |
| signature | 4.4 KiB |

**Comparison to PoMFRIT {{PoMFRIT}}.** For reference, PoMFRIT {{PoMFRIT}}
(ePrint 2026/109, Table 3) reports the following at `lambda = 128` with the
small (`s`) VOLEitH tuning, on an Intel Ultra 9 185H (AVX C/C++). PoMFRIT is a
blind signature, not an ACT: it has no balance arithmetic, nullifier, or change
commitment, so its showing (`Sig3`/`Ver`) is the closest analogue of our spend
and its blind-signature size the analogue of our token. It runs on a different
ISA and language, so treat this as a rough cross-scheme reference, not a
like-for-like measurement. `Sig1` is the user's request, `Sig2` the issuer's
blind-sign (MAYO preimage sampling), `Sig3` the user's showing proof, and `Ver`
the showing verification.

| Scheme (128s) | `Sig1` | `Sig2` | `Sig3` (show) | `Ver` | Issue comm | Signature |
|---------------|--------|--------|---------------|-------|------------|-----------|
| SHAKE256-deg16 + MAYO | 0.02 ms | 6.1 ms | 178 ms | 143 ms | 0.47 KB | 24.3 KB |
| One-More-MAYO (no in-circuit hash) | 47.2 ms | 6.1 ms | 42 ms | 91 ms | 0.45 KB | 6.7 KB |

One-More-MAYO drops the symmetric primitive from the proven statement entirely,
so it is both the smallest (6.7 KB) and fastest-to-show; the cost moves to
`Sig1`. Its direct analogue is our One-More-UOV blind signature above (show 80
ms / verify 47 ms / 4.4 KiB): both prove only a compact MQ preimage with no
in-circuit hash, and land in the same regime -- the residual gap is ISA and
language (AVX C/C++ vs aarch64 Rust). Our RATA-MQ spend (prove 85 ms / verify 57
ms) sits in the same regime once its widened-UOV map is folded with lift tables:
the map is ~26x larger in coefficients, but the fold cost scales with the number
of forms, not the map size, so the extra width costs little.
