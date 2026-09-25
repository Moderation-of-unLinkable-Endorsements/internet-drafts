---
title: "Anonymous Credit Tokens (ACT)"
abbrev: "ACT"
category: info

docname: draft-authors-mole-act-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
keyword:
 - moderation
 - credential
 - credits
 - unlinkability
 - privacy
venue:
#  group: "Anti-Fraud Community Group"
#  type: "Community Group"
#  mail: "public-antifraud@w3.org"
#  arch: "https://lists.w3.org/Archives/Public/public-antifraud/"
  github: "Moderation-of-unLinkable-Endorsements/internet-drafts"
  latest: "https://moderation-of-unlinkable-endorsements.github.io/internet-drafts/draft-authors-mole-act.html"

author:
 -
    fullname: Samuel Schlesinger
    organization: Google LLC
    email: sgschlesinger@gmail.com
 -
    fullname: Jonathan Katz
    organization: Google LLC
    email: jkcrypto@google.com
 -
    fullname: Armando Faz-Hernandez
    organization: Cloudflare, Inc.
    email: armfazh@cloudflare.com
 -
    fullname: Deep Inder Mohan
    organization: Georgia Institute of Technology
    email: dmohan@gatech.edu


normative:
  IHAT:
    title: Issuer-Hiding Anonymous Tokens (IHAT)
    target: https://moderation-of-unlinkable-endorsements.github.io/internet-drafts/draft-authors-mole-ihat.html
  ARCH: I-D.draft-jms-mole-architecture
  PROTOCOLS: I-D.draft-jms-mole-protocols
  HASH2CURVE: RFC9380
  SIGMA: I-D.irtf-cfrg-sigma-protocols-02
  FIAT-SHAMIR: I-D.irtf-cfrg-fiat-shamir-02

informative:
  BBS:
    title: "Short Group Signatures"
    target: https://crypto.stanford.edu/~dabo/pubs/papers/groupsigs.pdf
    date: 2004
    seriesinfo:
      "CRYPTO": "2004"
    author:
      -
        ins: D. Boneh
        name: Dan Boneh
      -
        ins: X. Boyen
        name: Xavier Boyen
      -
        ins: H. Shacham
        name: Hovav Shacham
  KVAC:
    title: "Algebraic MACs and Keyed-Verification Anonymous Credentials"
    target: https://eprint.iacr.org/2013/516
    date: 2014
    seriesinfo:
      "CCS": "2014"
    author:
      -
        ins: M. Chase
        name: Melissa Chase
      -
        ins: S. Meiklejohn
        name: Sarah Meiklejohn
      -
        ins: G. Zaverucha
        name: Greg Zaverucha
  TZ23:
    title: "Revisiting BBS Signatures"
    target: https://eprint.iacr.org/2023/275
    date: 2023
    seriesinfo:
      "EUROCRYPT": "2023"
    author:
      -
        ins: S. Tessaro
        name: Stefano Tessaro
      -
        ins: C. Zhu
        name: Chenzhi Zhu
  BBDT16:
    title: "Improved Algebraic MACs and Practical Keyed-Verification Anonymous Credentials"
    target: https://crypto.orange-labs.fr/acg/publication/infoPublication.php?id=225
    date: 2016
    seriesinfo:
      "SAC": "2016"
    author:
      -
        ins: A. Barki
        name: Amira Barki
      -
        ins: S. Brunet
        name: Solenn Brunet
      -
        ins: N. Desmoulins
        name: Nicolas Desmoulins
      -
        ins: J. Traore
        name: Jacques Traore

...

--- abstract

This document specifies Anonymous Credit Tokens (ACT), a keyed-verification
anonymous credential scheme with a hidden credit balance. A Client spends a
public amount and receives a fresh Credential for the remaining balance and
a return amount chosen by the issuer. The issuer verifies each spend without
learning the balance or linking it to issuance or to other spends.

ACT uses a pairing-free BBS-style signature and proofs over linear relations.
This document defines its cryptographic operations, encodings, and security
requirements. The MoLE protocols use ACT as a Credential scheme.

--- middle

# Introduction

MoLE Credentials carry per-Client state that a Moderator tests and updates at
each presentation without learning it, and without being able to link
presentations to each other or to issuance. Anonymous Credit Tokens (ACTs)
provide a numeric balance as this state ({{credential-scheme}}).

The Moderator is both the issuer and the verifier. A Client obtains an initial
Credential, spends credits, and finalizes the refund that replaces the spent
Credential. {{PROTOCOLS}} maps these operations to the MoLE credential APIs,
specifies when issuance is authorized, and supplies the credential and spend
contexts. This document treats those contexts as opaque byte strings.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

The capitalized terms Client, Moderator, and Credential are used as
defined in {{ARCH}}; a lowercase credential is the generic cryptographic
notion. The message-encoding conventions, Python notation, and helpers
`I2OSP`, `U16Prefixed`, `random`, and `Seed` are those of
Section 2 of {{IHAT}}. The algorithms use `bytes` for byte strings, `int`
for integers, and `Sequence` and `NamedTuple` from Python's `typing` module.
Record fields appear in the same order as their tuple representation.

The group `G`, protocol context `ctx_proto`, seed length `Nseed`,
generators, and balance width `L` are globals fixed by the ACT
configuration ({{act-config}}). Shared group methods from {{IHAT}} use
the ACT group instance `G`, which stores `ctx_proto` and applies ACT
domain separation. The shared `Seed` helper uses the same `Nseed = 48`
for both schemes. Public byte-string inputs retain the length bounds
specified by the operation that uses them.

# Preliminaries {#preliminaries}

The construction has two dependencies:

Group:
: A prime-order group implementing the interface in {{group}}. {{ciphersuites}}
  gives concrete instances.

Hash:
: A cryptographic hash function whose output length is `Nh` bytes.

## Prime-Order Group {#group}

ACT uses the prime-order group interface and the `Element` and `Scalar`
types of Section 3.1 of {{IHAT}}, instantiated as in {{ciphersuites}}.
The Python interface provides `G.scalar(x)` for an integer `x` in
`[0, G.Order())`, `s.isZero()` for a scalar, and `A.isIdentity()` for an
element. Arithmetic combines values of the same type: integer constants
are converted with `G.scalar` before scalar arithmetic. The negative of
an element `A` is `G.Identity() - A`.

## Errors {#errors}

`DeserializeError`, `VerifyError`, `DeriveError`, and `ValueError` have the
meanings given in Section 3.2 of {{IHAT}}. ACT additionally uses
`AmountError` when a balance or amount is outside the range admitted by
{{act-amounts}}:

~~~ python
class AmountError(ValueError):
    """A credit amount is outside its permitted range."""
~~~

An implementation that raises an error MUST abort the affected protocol run.

## Deriving Scalars {#derive-scalar}

Use `G.DeriveScalar(seed: bytes, info: bytes) -> Scalar` from Section
4.2 of {{IHAT}}, using the ACT group instance initialized with
`ctx_proto`. It rejects seeds of the wrong length with `ValueError`,
rejects zero outputs, and raises `DeriveError` if all 256 counter values
yield zero. ACT applies the following seed requirements to this shared
algorithm.

A seed MUST be `Nseed` bytes of `random` output, and MUST NOT be used for more
than one derivation. An algorithm that needs several scalars therefore draws
`Nseed` bytes for each of them, and additionally separates them by `info`.
`Nseed` is larger than `Ns` ({{ciphersuites}}) so that the derived scalar is
statistically close to uniform rather than merely unpredictable; deriving
several scalars from one seed instead would cap their joint entropy at the
length of that seed, which the unlinkability argument of
{{act-security}} does not permit. See {{randomness}}.

## Key Generation {#keygen}

Use `G.DeriveKeyPair(seed, info)` and `G.GenerateKeyPair()` from Section
4.3 of {{IHAT}}, with the ACT group instance of {{act-config}}. Both
return `tuple[Scalar, Element]`; ACT names the returned keys `(skM,
pkM)` because the Moderator is the issuer. The Moderator publishes
`G.SerializeElement(pkM)` in its configuration ({{PROTOCOLS}}).

# The Credential Scheme {#credential-scheme}

A MoLE Credential is an Anonymous Credit Token (ACT). It is a
keyed-verification anonymous credential {{KVAC}} over a privately
verifiable, pairing-free BBS-style signature {{BBS}} {{TZ23}}, whose
hidden state is a *balance*: a nonnegative integer number of credits. A
Moderator issues a Credential with an initial balance, and the Client
later *spends* from it. A spend reveals a public amount `s` and proves,
in zero knowledge, that the Credential holds at least `s` credits and
has not been spent before. In the same exchange the Moderator issues a
*refund*: a fresh Credential whose balance is the remainder plus a
Moderator-chosen return amount `t`. A spend may also declare a public
*top-up allowance* `a`, in which case the refund may return up to `s +
a`, raising the balance; without one, `t` is at most `s`. The Moderator
never learns the balance, and cannot link a spend to the issuance or
refund that produced the Credential it consumed, nor two spends to each
other.

The allowance `a` bounds the additional credit the Moderator may grant;
`t` is the amount it actually returns. The new balance is `c - s + t`,
so its increase over `c` is at most `a`.

This is the credential type `0x0001` of {{PROTOCOLS}}. In the vocabulary of
{{ARCH}}, a spend is a *Presentation* whose *Predicate* is "the balance is at
least `s`", and the refund is the *Update*.

The scheme is a two-party protocol between a Client and a Moderator. The
Moderator holds a key pair `(skM, pkM)` and is both the issuer and the
verifier: Credentials are not publicly verifiable, and only their issuer can
check a spend. Each of the two flows, issuance and spending, is a single
request/response exchange followed by a Client-local finalization.

~~~
   Client(pkM, ctx_cred)                     Moderator(skM, ctx_cred)
 ------------------------------------------------------------------
   state, request = IssueRequest()

                              request
                              -------->

                 response = IssueResponse(skM, ctx_cred, c, request)

                              response
                              <--------

   credential = FinalizeIssuance(pkM, ctx_cred, state, response)

                   ...

   state, proof = ProveSpend(credential, ctx_cred, s, a, ctx_spend)

                                proof
                              -------->

                   VerifySpend(skM, ctx_cred, ctx_spend, proof)
                   refund = IssueRefund(skM, ctx_cred, proof, t)

                               refund
                              <--------

   credential = FinalizeRefund(pkM, ctx_cred, state, proof, refund)
~~~
{: #fig-act title="Credential issuance and spending overview"}

The Moderator chooses the initial balance `c` and the return amount `t`
according to its policy; both are outside the scope of this document, as is
the nullifier store the Moderator keeps to reject a second spend of the same
Credential. {{PROTOCOLS}} specifies both, together with the carriage of the
four messages.

## Configuration {#act-config}

A ciphersuite ({{ciphersuites}}) is identified by an ASCII byte string
`identifier`, and both parties MUST agree on it before
running the protocol. The Credential scheme is specified for the P-256
ciphersuite of {{ciphersuites}}, whose Sigma-protocol instantiation {{SIGMA}}
defines; its protocol context is

~~~ python
def CreateCredentialProtocolContext(identifier: bytes) -> bytes:
    return b"ACTv1-" + identifier
~~~

Throughout this section and wherever the algorithms of this section are
invoked, `ctx_proto` denotes this value, and `HashToGroup`, `HashToScalar`,
`G.DeriveScalar`, and the key generation of {{keygen}} are parameterized by it.

The scheme has one further parameter, the *balance width* `L`. Balances and
amounts are integers in `[0, 2^L)`. `L` MUST satisfy `1 <= L <=
MAX_BIT_LENGTH`, where `MAX_BIT_LENGTH` is fixed by the ciphersuite. The size
of a spend proof and the cost of producing and verifying it grow linearly in
`L`, so a deployment SHOULD choose the smallest `L` that accommodates its
largest balance. The Moderator publishes `L` together with its public key
({{PROTOCOLS}}); a Client MUST use the published value.

`L` is fixed for the lifetime of a key and credential context. The invariant
that every balance the Moderator has signed lies below `2^L`, on which
{{act-security}} relies, is argued by induction over issuances and refunds
under one value of `L`, and does not survive a change of `L` under a key and
context that still have outstanding Credentials. A Moderator that changes `L`
MUST do so together with the credential context or the key. Deployments are
RECOMMENDED to fold `L` into the credential context, for instance by
appending `I2OSP(L, 1)` to it, so that a change of `L` is a change of context
by construction.

### Generators {#act-generators}

The scheme uses the group generator `B = G.Generator()` and four further
elements `H1`, `H2`, `H3`, `H4`, fixed by the ciphersuite:

~~~ python
def CreateGenerators() -> tuple[Element, Element, Element, Element]:
    return (
        G.HashToGroup(b"GenH1"),
        G.HashToGroup(b"GenH2"),
        G.HashToGroup(b"GenH3"),
        G.HashToGroup(b"GenH4"),
    )
~~~

`H1` commits to the balance, `H2` to the nullifier, `H3` is the blinding
base, and `H4` binds the credential context ({{act-context}}). The discrete
logarithm of any of these elements with respect to any other, or to `B`, MUST
NOT be known to any party; deriving them by hashing fixed labels ensures this.
The five elements are pairwise distinct except with negligible probability;
an implementation MAY verify this once when instantiating a ciphersuite.

### Key Generation {#act-keygen}

A Moderator holds a key pair `(skM, pkM)`, generated with `G.GenerateKeyPair`
of {{keygen}} under the protocol context of this section, or derived from a
seed with `G.DeriveKeyPair`. The Moderator publishes `SerializeElement(pkM)` in
its configuration ({{PROTOCOLS}}). The signing key `skM` is also the
verification key: `VerifySpend` requires it.

## Credential Context {#act-context}

Every Credential is bound at issuance to a *credential context* `ctx_cred`,
an opaque byte string of at most `2^16 - 1` bytes chosen by the Moderator and
agreed with the Client out of band; {{PROTOCOLS}} says how. It
restricts *when*, or under which policy, a Credential may be spent, so that a
Moderator can for instance expire all Credentials of an epoch at once without
rotating its key.

The context is bound as a signed attribute. It is mapped to a scalar and
carried under `H4`:

~~~ python
def CreateContextScalar(ctx_cred: bytes) -> Scalar:
    return G.HashToScalar(
        U16Prefixed(ctx_cred) + b"CredentialContext"
    )
~~~

The context is never carried on the wire. It is an input to every algorithm
of this section that computes or checks a signature, supplied by the party
running it, so that a spend verifies only under the context the Credential
was issued under: a Moderator states the context it accepts and learns whether
the Credential was issued under it, rather than being told by the Client. A
Client keeps its own copy of the context for as long as it holds the
Credential.

The credential context partitions Clients into the set that shares its
value, and MUST be coarse; see {{act-security}}.

## Amounts {#act-amounts}

Balances and amounts are nonnegative integers below `2^L`. On the wire they
are `uint64` values; in the algebra they enter as scalars.
`G.scalar(x)` denotes the `Scalar` whose integer value is `x`, and `Bits(x)` its
binary decomposition, least significant bit first, into `L` scalars each equal
to `0` or `1`:

~~~ python
def Bits(x: int) -> list[Scalar]:
    return [G.scalar((x >> j) & 1) for j in range(L)]
~~~

An implementation MUST compute `Bits` in constant time with respect to `x`,
which is the Client's hidden balance.

A party that receives an amount MUST check that it is below `2^L` before
using it, and MUST raise an `AmountError` otherwise. The spend range proof
bounds a difference of amounts. The bounds on each amount are needed to
interpret this difference over the integers ({{act-security}}).

# Ciphersuites {#ciphersuites}

The Credential scheme is specified for the P-256 ciphersuite below. A
ciphersuite fixes the group, hash functions, encodings, and domain separation
tags. Both parties agree on the ciphersuite as specified in {{act-config}}.

`ctx_proto` is as computed in {{act-config}}. The seed length is
`Nseed = Ns + 16 = 48` bytes. The 16 bytes in excess of `Ns` make a derived
scalar statistically close to uniform ({{derive-scalar}}), on the same grounds
that {{HASH2CURVE}} oversamples by 128 bits when mapping bytes to a field
element.

For the Credential scheme, the P-256 ciphersuite sets `MAX_BIT_LENGTH = 64`.

## ACT(P-256, SHA-256)

This ciphersuite uses P-256 (secp256r1) for the group and
SHA-256 for the hash function, with `Nh = 32`. The value of the ciphersuite
identifier is `b"P256-SHA256"`.

Use the P-256 group, SHA-256 hash, hash-to-curve and hash-to-scalar
algorithms, and canonical encodings of Section 7.1 of {{IHAT}}. ACT uses
`Ne = 33`, `Ns = 32`, and `Nseed = 48`. Instantiate every hash with the
ACT `ctx_proto` of {{act-config}}, including the explicit DST passed by
`G.DeriveScalar`; the group-element permutation used by IHAT is not needed.

## Randomness {#randomness}

Every random value in this document is a seed of `Nseed` bytes, drawn with
`random` and consumed by `G.DeriveScalar` ({{derive-scalar}}); no scalar is
sampled directly. Implementations MUST draw seeds with a cryptographically
secure random number generator and MUST NOT reuse a seed across derivations.
They SHOULD treat a seed as being as sensitive as the values derived from it,
and SHOULD handle both in constant time.

# Security Considerations {#act-security}

The Credential scheme is a keyed-verification anonymous credential {{KVAC}}
over the pairing-free BBS-style signature of {{BBS}} as analysed by {{TZ23}},
with the balance, the nullifier, the blinding factor, and the context scalar
as the signed attributes. Because the Moderator is both issuer and verifier
and there is no pairing, the scheme is an algebraic MAC in the sense of
{{KVAC}}, of the shape introduced as `MAC_BB` by {{BBDT16}}.

Credit conservation assumptions:
: The credit-conservation argument uses the following assumptions.

  * The q-SDH assumption in `G`, for the unforgeability of the signature
    {{TZ23}}.
  * The discrete-logarithm-relation assumption among `B`, `H1`, `H2`, `H3`,
    and `H4`: no party can produce a nontrivial linear relation among them.
    The generators are derived by hash-to-curve in the random oracle model
    ({{act-generators}}). Commitment binding and the range and spend proofs
    rely on this assumption.
  * The random oracle model for `HashToGroup`, `HashToScalar`, and the
    Fiat-Shamir transform of {{FIAT-SHAMIR}}, together with special
    soundness of the credential Sigma protocols.
  * Extraction for issuance and spend proofs across adaptive sessions,
    including the keyed-verification oracle. An ACT reduction covering
    verification queries and secret-derived signing exponents and proof
    nonces remains open; the results of {{TZ23}} and {{BBDT16}} do not
    cover this composition.

Verification key secrecy:
: `VerifySpend` requires `skM`, so a Credential can be verified only by the
  Moderator that issued it. A Moderator that shares `skM` with another party
  lets that party issue Credentials in its name.

Context granularity:
: The credential context is visible at every spend through the fact that the
  proof verifies under it, and so partitions Clients into the set sharing its
  value. It MUST be
  coarse: every Client issued under a given context MUST derive the
  byte-identical `ctx_cred`. The spend context does not partition Clients,
  since it binds a single presentation to a single challenge.

Balance width:
: `L` is public and identical for all Clients of a Moderator, and fixed for
  the lifetime of a key and context ({{act-config}}). A Moderator that used
  different values of `L` for different Clients would partition them by the
  length of their spend proofs, and one that changed `L` under a key and
  context with outstanding Credentials would invalidate the balance
  invariant of the conservation argument.

System requirements:
: Deployments must provide an atomic and durable nullifier store
  ({{PROTOCOLS}}), consistent configuration across Clients ({{ARCH}}),
  and coarse credential contexts. Privacy relies on the randomness
  requirements of {{randomness}}. Clients must use each Credential and
  each issuance or spend state only once, including across backups and
  restores.

# IANA Considerations {#iana}

This document has no IANA actions. The ACT credential type is registered by
{{PROTOCOLS}}.

--- back

# Test Vectors {#act-test-vectors}

TODO: ACT test vectors.

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
