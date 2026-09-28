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
    date: 2026
    seriesinfo:
      Internet-Draft: draft-authors-mole-ihat
    author:
      -
        ins: S. Schlesinger
      -
        ins: D. I. Mohan
  ARCH: I-D.draft-jms-mole-architecture
  PROTOCOLS: I-D.draft-jms-mole-protocols
  HASH2CURVE: RFC9380
  SIGMA: I-D.irtf-cfrg-sigma-protocols-03
  FIAT-SHAMIR: I-D.irtf-cfrg-fiat-shamir-03

informative:
  Pedersen91:
    title: "Non-Interactive and Information-Theoretic Secure Verifiable Secret Sharing"
    target: https://doi.org/10.1007/3-540-46766-1_9
    date: 1991
    seriesinfo:
      "CRYPTO": "1991"
    author:
      -
        ins: T. P. Pedersen
        name: Torben Pryds Pedersen
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

> **TODO.** The ACT profile of {{PROTOCOLS}} is not yet written. This
> document expects it to define how `ctx_cred` is agreed
> ({{act-context}}), how `L` is published with the key ({{act-config}}),
> the lifetime of the nullifier store and the policy bounding `t`
> ({{act-security}}), and how a Client obtains a refund again after a
> lost response ({{act-finalize-refund}}). Until then, those references
> name requirements on that profile rather than text it contains.

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

The construction has three dependencies:

Group:
: A prime-order group implementing the interface in {{group}}. {{ciphersuites}}
  gives concrete instances.

Hash:
: A cryptographic hash function, used by the `HashToGroup`, `HashToScalar`,
  and derivation algorithms that the group of {{IHAT}} provides.

Sigma protocol:
: The compact non-interactive Sigma protocol of {{SIGMA}}, instantiated in
  {{act-proofs}}.

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
`ctx_proto`. It rejects seeds of the wrong length with `ValueError`, and
raises `DeriveError` in the negligible event that its output is zero. ACT
applies the following seed requirements to this shared algorithm.

A seed MUST be `Nseed` bytes of `random` output, and MUST NOT be used for more
than one derivation. An algorithm that needs several scalars therefore draws
`Nseed` bytes for each of them, and additionally separates them by `info`;
deriving several scalars from one seed would cap their joint entropy at the
length of that seed. A derived scalar is within about `2^-128` of uniform
(Section 4.2 of {{IHAT}}), which the unlinkability argument of
{{act-security}} relies on. See {{randomness}}.

## Key Generation {#keygen}

Use `G.DeriveKeyPair(seed, info)` and `G.GenerateKeyPair()` from Section
4.4 of {{IHAT}}, with the ACT group instance of {{act-config}}. Both
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

   credential = FinalizeIssue(pkM, ctx_cred, state, response)

                   ...

   state, proof = ProveSpend(credential, ctx_cred, s, a, ctx_spend)

                                proof
                              -------->

                   VerifySpend(skM, ctx_cred, ctx_spend, proof)
                   refund = IssueRefund(skM, ctx_cred, proof, t)

                               refund
                              <--------

   credential = FinalizeRefund(pkM, ctx_cred, state, refund)
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
ciphersuite of {{ciphersuites}}; its protocol context is

~~~ python
def CreateCredentialProtocolContext(identifier: bytes) -> bytes:
    return b"ACTv1-" + identifier
~~~

Throughout this section and wherever the algorithms of this section are
invoked, `ctx_proto` denotes this value, and `HashToGroup`, `HashToScalar`,
`G.DeriveScalar`, `G.DeriveNonce`, and the key generation of {{keygen}} are
parameterized by it.

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
Credential. A Credential presented under a context other than the one it
was issued under fails verification; the mismatch is not otherwise
signalled.

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

The comparisons `s <= c` and `c + a < 2^L` in `ProveSpend`, `t <= s + a`
in `IssueRefund`, and `t <= s + a` and `v1 + t < 2^L` in `FinalizeRefund`
are between integers. Each sum can reach `2^(L+1) - 2`, which does not fit
in a `uint64` when `L = 64`, and an implementation MUST compute them
without overflow.

## Zero-Knowledge Proofs {#act-proofs}

Each proof of this document is a compact NARG string
({{Section 5.5 of SIGMA}}) for a linear relation declared where it is
used, in the notation of {{Section 3.4 of SIGMA}}, with `G` the generator
`B` of {{ciphersuites}}. The batchable form would add one element per
equation, which for the spend relation is most of the message, and the
Moderator verifies each spend atomically with recording its nullifier,
which precludes batch verification.

The ciphersuite is `sigma-proofs_Shake128_P256` of
{{Section 8 of SIGMA}}. Its group is the group of {{ciphersuites}}
with the same element and scalar encodings, so statement elements are
encoded identically in both documents.

### Tags {#act-tags}

Every proof is bound to a *tag* ({{Section 5.1 of SIGMA}}) built by `Tag`
from a label naming the operation and a possibly empty list of *bindings*:
public byte strings that the proof must be bound to but that do not appear
in the relation.

~~~ python
def Tag(label: bytes, bindings: Sequence[bytes]) -> bytes:
    tag = ctx_proto + b"-" + label + b"-CMPT-with-" + SIGMA_SUITE
    for binding in bindings:
        tag += U16Prefixed(binding)
    return tag
~~~

`SIGMA_SUITE` is the ciphersuite identifier `"sigma-proofs_Shake128_P256"`.
The labels are a fixed set, and each binding is length-prefixed, so
distinct inputs yield distinct tags ({{Section 5.1 of FIAT-SHAMIR}}).
Bindings are arbitrary byte strings, not the US-ASCII text that section
recommends; the length prefixes keep the tag unambiguous.

### Prover Nonces {#act-prover-nonces}

`ProveCompact` draws one nonce per witness scalar from its `rng`, in
scalar-index order. The `rng` MUST return, on its `i`-th call, the value
that `ProverNonces.random_scalar` computes below. Each nonce is derived
with `G.DeriveNonce` (Section 4.3 of {{IHAT}}) from the witness, the
session, the relation, and fresh randomness; a repeated or failed random
source therefore neither repeats a nonce across proofs of distinct
relations nor produces a zero nonce.

~~~ python
class ProverNonces:
    def __init__(
        self,
        witness: Sequence[Scalar],
        session_id: bytes,
        instance: bytes,
    ) -> None:
        self.secret = b"".join(G.SerializeScalar(w) for w in witness)
        self.instance = (
            session_id + I2OSP(len(instance), 4) + instance
        )
        self.rand = random(len(witness) * Nseed)
        self.count = 0

    def random_scalar(self) -> int:
        i = self.count
        self.count = i + 1
        nonce = G.DeriveNonce(
            self.secret,
            b"nonce",
            self.instance + I2OSP(i, 4),
            Seed(self.rand, i),
        )
        return int(nonce)
~~~

`witness` is the prover's whole witness in scalar-index order;
`session_id` is the 32-byte `DeriveSessionID(tag)` of
{{Section 5.1 of FIAT-SHAMIR}}; and `instance` is the
`SerializeLinearRelation` of the relation ({{Section 3.6 of SIGMA}}).

This rule binds only the prover; a verifier following {{SIGMA}} accepts
these proofs unchanged. The derivation is deterministic in the witness,
the tag, the relation, and `rand`: replaying the bytes of `random`
reproduces a proof byte for byte, which the test vectors of
{{act-test-vectors}} rely on, and a random source that repeats all of `rand`
reproduces a proof rather than reusing a nonce under a different challenge.
A retried operation draws fresh `rand` and produces a different proof.

### Proving and Verifying {#act-prove}

A relation is proven and verified as follows, where `relation` is the
declared relation compiled as in {{Section 3.4 of SIGMA}}, and
`DeriveSessionID`, `SerializeLinearRelation`, `ProveCompact`, and
`VerifyCompact` are those of {{FIAT-SHAMIR}} and {{SIGMA}}.

~~~ python
def Prove(
    tag: bytes, relation: LinearRelation, witness: Sequence[Scalar]
) -> bytes:
    nonces = ProverNonces(
        witness,
        DeriveSessionID(tag),
        SerializeLinearRelation(relation),
    )
    return ProveCompact(tag, relation, witness, nonces)


def Verify(
    tag: bytes, relation: LinearRelation, proof: bytes
) -> bool:
    return VerifyCompact(tag, relation, proof)
~~~

## Issuance {#act-issuance}

Issuance produces a signature on the message
`B + c * H1 + k * H2 + r * H3 + ctx * H4`, where `c` is the balance chosen
by the Moderator, `ctx` is the context scalar, and `k` and `r` are chosen
by the Client and hidden from the Moderator:

~~~
  IssueRequest -> IssueResponse -> FinalizeIssue
~~~

`IssueRequest` and `FinalizeIssue` are run by the Client, and
`IssueResponse` by the Moderator. The Python records are:

~~~ python
class ClientIssuanceState(NamedTuple):
    k: Scalar
    r: Scalar
    K: Element


class IssueRequestMessage(NamedTuple):
    K: Element
    pok: bytes


class IssueResponseMessage(NamedTuple):
    A: Element
    e: Scalar
    c: int
    pok: bytes


class Credential(NamedTuple):
    k: Scalar
    c: int
    r: Scalar
    A: Element
    e: Scalar
~~~

### Signing Exponent {#act-signing-exponent}

`IssueResponse` here and `IssueRefund` ({{act-refund}}) choose the
exponent `e` of the signature `(A, e)`. It is derived with `G.DeriveNonce`
(Section 4.3 of {{IHAT}}) from the signing key, the signed message, and
fresh randomness. A random source that repeats therefore reproduces an
earlier signature and never issues a second one with the same exponent
({{act-security}}).

~~~ python
def SigningExponent(
    skM: Scalar, label: bytes, X_A: Element
) -> Scalar:
    instance = U16Prefixed(label) + U16Prefixed(
        G.SerializeElement(X_A)
    )
    e = G.DeriveNonce(
        G.SerializeScalar(skM), b"e", instance, random(Nseed)
    )
    if (e + skM).isZero():
        raise DeriveError
    return e
~~~

`label` is `IssueResponse` or `Refund`, the tag label of the
accompanying proof, and `X_A` is the message being signed. The abort
when `e + skM` is zero has probability about `1/p`; a caller that
retries draws fresh randomness.

### Issuance Request {#act-issue-request}

The Client commits to a fresh nullifier `k` and blinding factor `r`, and
proves that it knows the opening:

~~~
Relation Commitment(H2, H3, K):
  Witness: k, r
  Equations:
    K = k * H2 + r * H3
~~~

~~~ python
def IssueRequest() -> (
    tuple[ClientIssuanceState, IssueRequestMessage]
):
    rand = random(2 * Nseed)
    k = G.DeriveScalar(Seed(rand, 0), b"k")
    r = G.DeriveScalar(Seed(rand, 1), b"r")

    K = k * H2 + r * H3

    tag = Tag(b"IssueRequest", [])
    pok = Prove(tag, CommitmentRelation(K), [k, r])

    return ClientIssuanceState(k, r, K), IssueRequestMessage(K, pok)
~~~

The nullifier `k` is revealed when the Credential is spent, and the
Moderator uses it to reject a second spend. A Client MUST NOT reuse it
across Credentials, and MUST NOT finalize one `state` against two
responses: the two Credentials would share `k`, and at most one of them
can be spent ({{act-security}}).

### Issuance Response {#act-issue-response}

The Moderator checks the request, chooses the balance, and signs the
message `X_A = B + c * H1 + ctx * H4 + K` as `A = X_A / (e + skM)`. It
proves that `A` is such a signature under `pkM` without revealing `skM`,
with the witness `x = e + skM` and `X_G = x * G`, which the Client
computes as `e * G + pkM`:

~~~
Relation Signature(A, X_A, X_G):
  Witness: x
  Equations:
    X_A = x * A
    X_G = x * G
~~~

~~~ python
def IssueResponse(
    skM: Scalar,
    ctx_cred: bytes,
    c: int,
    request: IssueRequestMessage,
) -> IssueResponseMessage:
    K, pok = request

    if not 0 <= c < 2**L:
        raise AmountError

    tag = Tag(b"IssueRequest", [])
    if not Verify(tag, CommitmentRelation(K), pok):
        raise VerifyError

    ctx = CreateContextScalar(ctx_cred)
    X_A = B + G.scalar(c) * H1 + ctx * H4 + K

    e = SigningExponent(skM, b"IssueResponse", X_A)
    x = e + skM
    A = G.ScalarInverse(x) * X_A
    X_G = G.ScalarMultGen(x)

    tag = Tag(b"IssueResponse", [])
    pok = Prove(tag, SignatureRelation(A, X_A, X_G), [x])

    return IssueResponseMessage(A, e, c, pok)
~~~

The check `c < 2^L` bounds every issued balance; the soundness of
spending relies on it ({{act-security}}).

### Issuance Finalization {#act-finalize-issuance}

The Client checks the response and assembles the Credential.

~~~ python
def FinalizeIssue(
    pkM: Element,
    ctx_cred: bytes,
    state: ClientIssuanceState,
    response: IssueResponseMessage,
) -> Credential:
    k, r, K = state
    A, e, c, pok = response

    if not 0 <= c < 2**L:
        raise AmountError

    ctx = CreateContextScalar(ctx_cred)
    X_A = B + G.scalar(c) * H1 + ctx * H4 + K
    X_G = G.ScalarMultGen(e) + pkM

    tag = Tag(b"IssueResponse", [])
    if not Verify(tag, SignatureRelation(A, X_A, X_G), pok):
        raise VerifyError

    return Credential(k, c, r, A, e)
~~~

A Credential is the tuple `(k, c, r, A, e)`; its encoding, for storage, is
given in {{act-wire}}. It is never sent. The Client also retains
`ctx_cred`, which is not part of the Credential but is needed to spend it.

## Spending {#act-spending}

Spending consumes a Credential with balance `c` and produces one with
balance `c - s + t`. The amount `s` and the top-up allowance `a` are
chosen by the Client to match the Moderator's challenge ({{PROTOCOLS}});
the return amount `t`, with `0 <= t <= s + a`, is chosen by the
Moderator. With `s = a = 0` a spend changes nothing but the nullifier and
refreshes the Credential. Spending consists of four algorithms:

~~~
  ProveSpend -> VerifySpend -> IssueRefund -> FinalizeRefund
~~~

`ProveSpend` and `FinalizeRefund` are run by the Client; `VerifySpend`
and `IssueRefund` by the Moderator, in that order and only if `VerifySpend`
succeeds.

A spend is bound to a *spend context* `ctx_spend`, an opaque byte string
of at most `2^16 - 1` bytes supplied by the verifier and known to the
Client, and the only binding of the spend proof's tag. {{PROTOCOLS}}
sets it to the `challenge_digest` of the challenge that triggered the
presentation. The top-up allowance is bound by the relation: a proof
produced for one value of `a` does not verify under another, so a
Moderator authorizes a top-up by verifying the proof with the value it
accepts, and a Moderator that offers none MUST reject a spend with
`a != 0`.

The Python records for spending are:

~~~ python
class ClientSpendState(NamedTuple):
    kstar: Scalar
    r_star: Scalar
    v1: int
    s: int
    a: int
    K_prime: Element


class SpendMessage(NamedTuple):
    k: Scalar
    s: int
    a: int
    A_prime: Element
    B_bar: Element
    K_n: Element
    Com1: Sequence[Element]
    Com_c: Element | None
    Com2: Sequence[Element]
    pok: bytes


class RefundMessage(NamedTuple):
    A: Element
    e: Scalar
    t: int
    pok: bytes
~~~

An absent commitment list is empty, and an absent `Com_c` is `None`.

### The Spend Relation {#act-spend-relation}

A spend shows two things about the hidden balance `c`: the *remainder*
`v1 = c - s` is nonnegative, so the Credential covers the spend, and the
*topped-up balance* `v2 = c + a` is below `2^L`, so the refund may return
up to `s + a` without a balance leaving `[0, 2^L)`. Each is a range
proof over the bits of the value, needed only when its amount is nonzero:
for `s = 0` the remainder is the balance itself, which is below `2^L` by
issuance, and for `a = 0` so is the topped-up balance. The relation
therefore has four shapes, selected by whether `s` and `a` are zero; a
group marked with a condition below is present exactly when it holds.

~~~
Relation Spend(H1, H2, H3, A_prime, B_bar, A_bar, H1_prime, K_n,
               s, a,
               Com1[0], ..., Com1[L-1],           (s > 0)
               Com_c,                             (s = 0)
               Com2[0], ..., Com2[L-1]):          (a > 0)
  Witness: e, r2, r3, c, r, kstar, rn,
           b1[0], ..., b1[L-1],
           s1[0], ..., s1[L-1],
           u1[0], ..., u1[L-1],                   (s > 0)
           rc,                                    (s = 0)
           b2[0], ..., b2[L-1],
           s2[0], ..., s2[L-1],
           u2[0], ..., u2[L-1]                    (a > 0)
  Equations:
    A_bar = -e * A_prime + r2 * B_bar
    H1_prime = r3 * B_bar - c * H1 - r * H3
    K_n = kstar * H2 + rn * H3
    for j in 0, ..., L-1:                         (s > 0)
      Com1[j] = b1[j] * H1 + s1[j] * H3
      Com1[j] = b1[j] * Com1[j] + u1[j] * H3
    s * H1 + sum_j 2^j * Com1[j]
      = c * H1 + sum_j 2^j * s1[j] * H3           (s > 0)
    Com_c = c * H1 + rc * H3                      (s = 0)
    for j in 0, ..., L-1:                         (a > 0)
      Com2[j] = b2[j] * H1 + s2[j] * H3
      Com2[j] = b2[j] * Com2[j] + u2[j] * H3
    -a * H1 + sum_j 2^j * Com2[j]
      = c * H1 + sum_j 2^j * s2[j] * H3           (a > 0)
~~~

The first equation states that `A_prime` is a rerandomization of a
signature under `skM`, since the verifier computes `A_bar = skM * A_prime`.
The second opens the signed message to the hidden balance `c` and blinding
factor `r`, relative to the public `H1_prime`, which fixes the nullifier
`k` and the context. The third opens `K_n` to the next nullifier and so
shows that `K_n` has no `H1` component; one would raise the balance the
refund signs.

Each pair of bit equations is the `Bit` relation of
{{Section 3.4 of SIGMA}}, with `u[j] = (1 - b[j]) * s[j]` for an honest
prover. The two sum equations tie the
committed bits to the balance: the left-hand side of the first opens under
`H1` to `s + v1`, so `c = s + v1` with `0 <= v1 < 2^L`; the second gives
`c + a = v2 < 2^L`. When `s = 0`, `Com_c` opens to `c` directly. The
equations share the witness `c`. The witness is supplied in the order
listed.

### Spend Proof Generation {#act-prove-spend}

The Client rerandomizes its signature, commits to the next nullifier and
to the remainder and, when there is a top-up, to the topped-up balance,
and proves the spend relation.

~~~ python
def ProveSpend(
    credential: Credential,
    ctx_cred: bytes,
    s: int,
    a: int,
    ctx_spend: bytes,
) -> tuple[ClientSpendState, SpendMessage]:
    k, c, r, A, e = credential

    if not (0 <= s < 2**L and 0 <= a < 2**L):
        raise AmountError
    if s > c or c + a >= 2**L:
        raise AmountError
    v1 = c - s
    v2 = c + a

    ctx = CreateContextScalar(ctx_cred)

    # One seed per scalar: four fixed ones, then L for the bits of
    # the remainder or one for its commitment, then L for the bits
    # of the topped-up balance.
    n = 4 + (L if s > 0 else 1) + (L if a > 0 else 0)
    rand = random(n * Nseed)
    seed = [Seed(rand, i) for i in range(n)]
    r1 = G.DeriveScalar(seed[0], b"r1")
    r2 = G.DeriveScalar(seed[1], b"r2")
    kstar = G.DeriveScalar(seed[2], b"kstar")
    rn = G.DeriveScalar(seed[3], b"rn")
    next_seed = 4

    # Rerandomize the signature.
    B_msg = B + G.scalar(c) * H1 + k * H2 + r * H3 + ctx * H4
    A_prime = (r1 * r2) * A
    B_bar = r1 * B_msg
    r3 = G.ScalarInverse(r1)
    A_bar = r2 * B_bar - e * A_prime

    # Commit to the next Credential's nullifier.
    K_n = kstar * H2 + rn * H3

    Com1: list[Element] = []
    Com_c: Element | None = None
    Com2: list[Element] = []
    witness = [e, r2, r3, G.scalar(c), r, kstar, rn]

    # Commit to the remainder: bitwise when it must be shown to be
    # nonnegative, in one commitment when it is the balance itself.
    if s > 0:
        b1 = Bits(v1)
        s1 = []
        r_star = rn
        for j in range(L):
            info = b"s1" + I2OSP(j, 1)
            s1.append(G.DeriveScalar(seed[next_seed + j], info))
            Com1.append(b1[j] * H1 + s1[j] * H3)
            r_star = r_star + G.scalar(2**j) * s1[j]
        u1 = [(G.scalar(1) - b1[j]) * s1[j] for j in range(L)]
        witness += b1 + s1 + u1
        next_seed = next_seed + L
    else:
        rc = G.DeriveScalar(seed[next_seed], b"rc")
        Com_c = G.scalar(c) * H1 + rc * H3
        r_star = rn + rc
        witness += [rc]
        next_seed = next_seed + 1

    # Commit to the topped-up balance when there is a top-up.
    if a > 0:
        b2 = Bits(v2)
        s2 = []
        for j in range(L):
            info = b"s2" + I2OSP(j, 1)
            s2.append(G.DeriveScalar(seed[next_seed + j], info))
            Com2.append(b2[j] * H1 + s2[j] * H3)
        u2 = [(G.scalar(1) - b2[j]) * s2[j] for j in range(L)]
        witness += b2 + s2 + u2

    H1_prime = B + k * H2 + ctx * H4
    relation = SpendRelation(
        A_prime, B_bar, A_bar, H1_prime, K_n, s, a, Com1, Com_c, Com2
    )
    pok = Prove(Tag(b"Spend", [ctx_spend]), relation, witness)

    # The commitment the refund will sign, opened by the new
    # Credential's secrets; the Moderator recomputes it from `proof`.
    K_prime = G.scalar(v1) * H1 + kstar * H2 + r_star * H3

    state = ClientSpendState(kstar, r_star, v1, s, a, K_prime)
    proof = SpendMessage(
        k, s, a, A_prime, B_bar, K_n, Com1, Com_c, Com2, pok
    )

    return state, proof
~~~

`A_bar` is not sent: the Moderator computes it as `skM * A_prime`. The
values `kstar` and `r_star` are the nullifier and blinding factor of the
Credential the refund will produce. They open `K_prime`, which equals
`K_n + V1` with `V1` the balance commitment of `BalanceCommitment`
below; the Moderator recomputes it from `proof` and signs it in
`IssueRefund`, and the Client keeps it in `state` to check the refund.

`ProveSpend` consumes the Credential: an implementation MUST NOT allow a
second call on the same Credential value. The Client MUST treat the
Credential as spent, and MUST have stored `state` durably, no later than
the moment `proof` becomes observable outside the Client; the refund is
unusable without the state, and a second proof from the same Credential
reveals the same nullifier ({{act-security}}). `state` holds everything
`FinalizeRefund` needs, so the Client need not retain `proof`.

### Spend Verification {#act-verify-spend}

The Moderator checks the spend proof under its own key and contexts.

~~~ python
def VerifySpend(
    skM: Scalar,
    ctx_cred: bytes,
    ctx_spend: bytes,
    proof: SpendMessage,
) -> None:
    k, s, a, A_prime, B_bar, K_n, Com1, Com_c, Com2, pok = proof

    if not (0 <= s < 2**L and 0 <= a < 2**L):
        raise AmountError

    ctx = CreateContextScalar(ctx_cred)
    A_bar = skM * A_prime
    H1_prime = B + k * H2 + ctx * H4

    relation = SpendRelation(
        A_prime, B_bar, A_bar, H1_prime, K_n, s, a, Com1, Com_c, Com2
    )
    if not Verify(Tag(b"Spend", [ctx_spend]), relation, pok):
        raise VerifyError
~~~

The shape of `proof` is fixed by `s` and `a` ({{act-wire}}): `Com1` is
present exactly when `s > 0`, `Com_c` exactly when `s = 0`, and `Com2`
exactly when `a > 0`; a message of any other shape is rejected at
deserialization. The amount checks of {{act-amounts}} precede
verification ({{act-security}}).

`VerifySpend` does not check whether `k` has been seen before, nor whether
the Moderator is willing to grant the top-up `a`. The Moderator MUST do
both, and MUST record `k` atomically with verification and with the
issuance of the refund ({{PROTOCOLS}}).

### Refund Issuance {#act-refund}

After a successful `VerifySpend`, the Moderator signs the remainder plus
its chosen return amount, proving the `Signature` relation under the
`Refund` tag.

~~~ python
def BalanceCommitment(proof: SpendMessage) -> Element:
    k, s, a, A_prime, B_bar, K_n, Com1, Com_c, Com2, pok = proof

    if s > 0:
        V1 = G.Identity()
        for j in range(L):
            V1 = V1 + G.scalar(2**j) * Com1[j]
    else:
        if Com_c is None:
            raise VerifyError
        V1 = Com_c

    return K_n + V1


def IssueRefund(
    skM: Scalar, ctx_cred: bytes, proof: SpendMessage, t: int
) -> RefundMessage:
    k, s, a, A_prime, B_bar, K_n, Com1, Com_c, Com2, pok = proof

    if not 0 <= t < 2**L or t > s + a:
        raise AmountError

    ctx = CreateContextScalar(ctx_cred)
    K_prime = BalanceCommitment(proof)
    X_A = B + K_prime + G.scalar(t) * H1 + ctx * H4

    e = SigningExponent(skM, b"Refund", X_A)
    x = e + skM
    A = G.ScalarInverse(x) * X_A
    X_G = G.ScalarMultGen(x)

    tag = Tag(b"Refund", [])
    pok = Prove(tag, SignatureRelation(A, X_A, X_G), [x])

    return RefundMessage(A, e, t, pok)
~~~

The comparison `t <= s + a` is between integers ({{act-amounts}}). This
bound keeps the new balance below `2^L` without a range proof over the
refund ({{act-security}}). The Moderator places the new balance anywhere in
`[c - s, c + a]` without learning where in that interval it falls.

### Refund Finalization {#act-finalize-refund}

The Client checks the refund and assembles its new Credential.

~~~ python
def FinalizeRefund(
    pkM: Element,
    ctx_cred: bytes,
    state: ClientSpendState,
    refund: RefundMessage,
) -> Credential:
    kstar, r_star, v1, s, a, K_prime = state
    A, e, t, pok = refund

    if not 0 <= t < 2**L or t > s + a or v1 + t >= 2**L:
        raise AmountError

    ctx = CreateContextScalar(ctx_cred)
    X_A = B + K_prime + G.scalar(t) * H1 + ctx * H4
    X_G = G.ScalarMultGen(e) + pkM

    tag = Tag(b"Refund", [])
    if not Verify(tag, SignatureRelation(A, X_A, X_G), pok):
        raise VerifyError

    return Credential(kstar, v1 + t, r_star, A, e)
~~~

A refund issued for a different spend signs a different `K_prime` and
fails verification. `FinalizeRefund` consumes `state`: a Client MUST NOT
finalize one spend state against two refunds, since the two Credentials
would share the nullifier `kstar`. The Client MUST NOT spend the consumed
Credential again, whether or not the refund arrives. A Client that has
sent a spend proof and not received a valid refund keeps `state` and MAY
ask the Moderator for the refund again; {{PROTOCOLS}} describes how, and
the Moderator recognizes the request by the recorded nullifier `k`. The
Moderator can answer with the refund it issued, which requires storing
it with the nullifier, or run `IssueRefund` again. The latter produces a
second signature under a different exponent; this is harmless, because
every refund of one spend carries the nullifier `kstar`, so at most one
of them can ever be spent ({{act-security}}).

## Encodings {#act-wire}

This section gives the encoding of the four messages exchanged and of the
Credential the Client stores. `Element` and `Scalar` are the fixed-length
encodings of `SerializeElement` and `SerializeScalar`, of `Ne` and `Ns`
bytes. A recipient MUST deserialize every received `Element` and `Scalar`
and MUST raise a `DeserializeError` if deserialization fails, which in
particular rejects the identity element. Amounts are `uint64` values,
checked against `2^L` as {{act-amounts}} requires.

Every `pok` field is a compact NARG string ({{act-proofs}}) of
`(Nw + 1) * Ns` bytes, where `Nw` is the number of witness scalars of its
relation: `2` for the request, `1` for the response and the refund, and
for the spend

~~~
  Nw = 7 + (3 * L if s > 0 else 1) + (3 * L if a > 0 else 0)
~~~

A recipient MUST reject a message whose `pok` has any other length, and
MUST reject a `SpendMessage` whose shape does not match its `s` and `a`.
Rejecting the identity element at deserialization keeps every relation of
this document valid ({{Section 3.5 of SIGMA}}).

The Client opens issuance with its commitment:

~~~ tls-presentation
struct {
  Element K;
  opaque pok[3 * Ns];
} IssueRequestMessage;
~~~

The Moderator answers with the signature and the balance it chose:

~~~ tls-presentation
struct {
  Element A;
  Scalar e;
  uint64 c;
  opaque pok[2 * Ns];
} IssueResponseMessage;
~~~

The Client spends with a proof whose shape follows its two amounts. The
`select` clauses distinguish a zero amount from a nonzero one:

~~~ tls-presentation
struct {
  Scalar k;
  uint64 s;
  uint64 a;
  Element A_prime;
  Element B_bar;
  Element K_n;
  select (s) {
    case 0:  Element Com_c;
    default: Element Com1[L * Ne];
  };
  select (a) {
    case 0:  struct {};
    default: Element Com2[L * Ne];
  };
  opaque pok[(Nw + 1) * Ns];
} SpendMessage;
~~~

The Moderator answers a valid spend with the refund:

~~~ tls-presentation
struct {
  Element A;
  Scalar e;
  uint64 t;
  opaque pok[2 * Ns];
} RefundMessage;
~~~

Neither context appears on the wire; both are inputs held by each party
({{act-context}}, {{act-spending}}). The Credential is held by the Client
and never sent:

~~~ tls-presentation
struct {
  Scalar k;
  uint64 c;
  Scalar r;
  Element A;
  Scalar e;
} Credential;
~~~

With `Ne = 33` and `Ns = 32`, the request is `129` bytes and the response
and refund are `137` bytes each. The spend message is `129 * L + 403`
bytes for an ordinary spend (`s > 0`, `a = 0`), `129 * L + 468` for a pure
top-up (`s = 0`, `a > 0`), `258 * L + 403` when both amounts are nonzero,
and `468` bytes for a refresh (`s = a = 0`). The spend message dominates
and is linear in `L`; {{act-config}} asks deployments to keep `L` small
for this reason.

# Ciphersuites {#ciphersuites}

The Credential scheme is specified for the P-256 ciphersuite below. A
ciphersuite fixes the group, hash functions, encodings, and domain separation
tags. Both parties agree on the ciphersuite as specified in {{act-config}}.

`ctx_proto` is as computed in {{act-config}}. The seed length is
`Nseed = Ns + 16 = 48` bytes. The 16 bytes in excess of `Ns` make a derived
scalar statistically close to uniform ({{derive-scalar}}), on the same grounds
that {{HASH2CURVE}} oversamples by 128 bits when mapping bytes to a field
element.

For the Credential scheme, the P-256 ciphersuite sets `MAX_BIT_LENGTH = 64`,
which allows amounts to be carried as `uint64` values and keeps `2^(L+1)`
far below the group order ({{act-security}}).

ACTv1 is specified against the `-03` revisions of {{SIGMA}} and
{{FIAT-SHAMIR}}. A later revision that changes the NARG string or its
derivation MUST be adopted under a new ciphersuite identifier, and so a new
`ctx_proto`; `ACTv1-P256-SHA256` then never denotes two transcript
formats.

> **TODO.** Revisit once {{SIGMA}} and {{FIAT-SHAMIR}} are stable, and
> move the pin to `-04` when it is published.

## ACT(P-256, SHA-256)

This ciphersuite uses P-256 (secp256r1) for the group and
SHA-256 for the hash function. The value of the ciphersuite
identifier is `b"P256-SHA256"`.

Use the P-256 group, SHA-256 hash, hash-to-curve and hash-to-scalar
algorithms, and canonical encodings of Section 7.1 of {{IHAT}}. ACT uses
`Ne = 33`, `Ns = 32`, and `Nseed = 48`. Instantiate every hash with the
ACT `ctx_proto` of {{act-config}}, including the explicit DSTs of
`G.DeriveScalar`, `G.SeedToScalar`, `G.DeriveNonce`, and `G.DeriveKeyPair`;
the group-element permutation used by IHAT is not needed.

## Randomness {#randomness}

Every random value in this document is a seed of `Nseed` bytes consumed by
`G.DeriveScalar` ({{derive-scalar}}), by `G.DeriveKeyPair` ({{keygen}}) for a
key, or, for the values listed below, by `G.DeriveNonce` (Section 4.3 of
{{IHAT}}); no scalar is sampled directly.
Implementations MUST draw with a cryptographically secure random number
generator and MUST NOT reuse a seed across derivations. A seed is as
sensitive as the values derived from it, and the constant-time requirement
of {{act-security}} covers both.

The following values MUST be derived with `G.DeriveNonce`, with the inputs
stated where they are used; drawing them directly is not conformant:

* the Moderator's signing exponent `e` in `IssueResponse` and
  `IssueRefund`, through `SigningExponent` ({{act-signing-exponent}});
* every nonce of a `ProveCompact` prover of the Credential scheme,
  through `ProverNonces` ({{act-prover-nonces}}).

The values drawn directly are the key seed of `G.GenerateKeyPair`, the
`aux` inputs of the derivations above, and the Client's `k`, `r`, `r1`,
`r2`, `kstar`, `rn`, `rc`, `s1`, and `s2`. A repetition among the
Client's values harms only that Client; a repetition of a signing
exponent or of a prover nonce is a key-compromise event
({{act-security}}); those are therefore derived.

# Security Considerations {#act-security}

The Credential scheme is a keyed-verification anonymous credential {{KVAC}}
over the pairing-free BBS-style signature of {{BBS}} as analysed by {{TZ23}},
with the balance, the nullifier, the blinding factor, and the context scalar
as the signed attributes. Because the Moderator is both issuer and verifier
and there is no pairing, the scheme is an algebraic MAC in the sense of
{{KVAC}}, of the shape introduced as `MAC_BB` by {{BBDT16}}.

Assumptions:
: Credit conservation rests on the q-SDH assumption in `G`, for the
  unforgeability of the signature {{TZ23}}; on no party knowing a nontrivial
  linear relation among `B`, `H1`, `H2`, `H3`, and `H4`, which the
  hash-to-curve derivation of {{act-generators}} provides in the random
  oracle model; and on the random oracle model for `HashToGroup`,
  `HashToScalar`, and the Fiat-Shamir transform of {{FIAT-SHAMIR}}, with the
  special soundness of the relations of {{act-proofs}}. The reduction is
  expected to follow that of {{TZ23}} in the algebraic group model with a
  programmable random oracle: the keyed-verification oracle is answered
  from the adversary's algebraic representations, since `skM * B`,
  `skM * H_i`, and `skM * A_j` are all computable by the reduction, and the
  derived signing exponents are programmed. {{BBDT16}} covers the
  keyed-verification setting for the underlying MAC.

> **TODO.** Write out this reduction, and the statistical unlinkability
> argument, for the idealized scheme.

Credit conservation:
: Fix a Moderator key, a credential context, and a balance width `L`. For
  any sequence of presentations the Moderator accepts, with amounts `s_i`
  and return amounts `t_i`, and any set of issuances with balances `c_j`,

      sum_i s_i <= sum_j c_j + sum_i t_i

  except with negligible probability, for an adversary controlling every
  Client, provided the nullifier store of {{PROTOCOLS}} rejects a repeated
  nullifier. The right-hand side is what the Moderator controls. The
  property follows from four facts: an accepted spend proof yields, by
  special soundness, a signature under `skM` on `(c, k, r, ctx)`; every such
  signature was produced by `IssueResponse` or `IssueRefund`, whose signing
  oracles are constrained by the proofs they verify, or q-SDH is broken; the
  sum equations of {{act-spend-relation}} hold over the integers ("Amount
  validation" below), so the refund Credential has balance exactly
  `c - s + t`; and a recorded nullifier is never counted twice.

Unlinkability:
: A spend reveals nothing about which issuance or refund produced the
  Credential it consumes, nor about the balance beyond the public amounts,
  to a Moderator that sees every message and holds `skM`. The commitments
  `K`, `K_n`, and the bit commitments are hiding {{Pedersen91}}; the
  pair `(A_prime, B_bar)` is a uniform rerandomization of the signature
  {{TZ23}}; and the proofs are statistically zero-knowledge
  ({{Section 7.5 of SIGMA}}). These hold for uniform blinding factors and
  nonces, and those of this document are each within about `2^-128` of
  uniform ({{derive-scalar}}, "Derived prover nonces" below). None of this
  relies on the hardness of discrete logarithms, so an observer with a
  quantum computer that records transcripts today gains nothing; such an
  attacker does recover `skM` from `pkM` and can forge Credentials, so credit
  conservation does not hold against it. The public amounts `s`, `a`, and
  `t`, and the configuration, determine which Credentials could have
  produced a presentation; `t` is the Moderator's choice, so {{PROTOCOLS}}
  constrains it as it constrains `s`, and {{ARCH}} states the anonymity-set
  requirements.

Amount validation:
: The spend relation constrains `c`, `s`, `a`, `v1`, and `v2` only modulo
  `p`: the bit equations show that `v1` and `v2` lie in `[0, 2^L)` as
  integers, while `c = s + v1` and `c + a = v2` hold in the scalar field.
  For these to hold over the integers, `c`, `s`, and `a` must be small.
  `c` is small by induction: `IssueResponse` rejects `c >= 2^L`, and a
  refund produces `v1 + t <= c + a`, which is `c` without a top-up and was
  proved below `2^L` with one. `s` and `a` are small only if the Moderator
  checks them, so `VerifySpend` MUST raise `AmountError` on either being
  `>= 2^L` before verifying the proof. With those checks and
  `2^(L+1) <= p`, which `MAX_BIT_LENGTH = 64` guarantees, neither relation
  can wrap. The same reasoning requires `t <= s + a` in `IssueRefund`, which
  keeps every balance below `2^L` without a range proof over the refund.

Randomness reuse:
: A repeated nonce in the `IssueResponse` or `Refund` proof reveals `skM`,
  and a repeated signing exponent `e` under one context lets a Client
  holding two Credentials with that exponent forge Credentials at any
  balance below `2^L`, each with a fresh nullifier, which the nullifier
  store cannot detect. Both values are therefore derived with
  `G.DeriveNonce` (Section 4.3 of {{IHAT}}) from the key and the operation
  ({{act-signing-exponent}}, {{act-prover-nonces}}), so that a rolled back
  or snapshotted random source reproduces an earlier response instead of
  yielding a second one. An implementation that draws either value
  directly MUST treat every repetition as a compromise of `skM`.

Identity elements:
: Deserialization rejects the identity element ({{act-wire}}), and the
  verifier of {{SIGMA}} rejects an instance that contains one. The check
  is soundness-critical for `A_prime`: were it the identity, `A_bar` would
  be too, the first spend equation would hold with `r2 = 0`, and the second
  would let a prover present `B_bar` as a blinding of any message of its
  choosing, at any balance, without holding a signature. An implementation
  whose group library accepts an encoding of the identity must perform the
  rejection itself.

Nullifier store:
: The scheme itself does not prevent a second spend of a Credential; the
  Moderator's record of seen nullifiers does. The Moderator MUST check the
  nullifier of a spend against that record and add it to the record
  atomically with verifying the proof and issuing the refund, so that a
  spend is either fully processed or not at all. Losing the record
  re-admits every Credential spent while it was in effect; the record
  covers at least the lifetime of the credential context it was recorded
  under ({{PROTOCOLS}}).

Single use of Credentials and states:
: A Client MUST treat a Credential as spent, and MUST have stored the
  returned state durably, no later than the moment the spend proof
  becomes observable outside the Client, and MUST NOT run `ProveSpend` on
  it again, whether or not the refund arrives. An implementation MUST
  have `ProveSpend` consume the Credential value, `FinalizeIssue`
  consume the issuance state, and `FinalizeRefund` consume the spend
  state, so that a second use of any of them within a process is
  impossible by construction; a Credential or state restored from a
  backup after use is the wallet's responsibility. A second spend of the
  same Credential presents the same nullifier, which the Moderator
  rejects, and links the two presentations to each other; one issuance
  state finalized against two responses, or one spend state against two
  refunds, yields Credentials that share a nullifier, of which at most
  one can ever be spent. A Client that loses the spend state after the
  Moderator has recorded the nullifier loses the balance.

Constant time:
: `Bits`, every operation on the witness of the spend relation, and every
  seed and the scalars derived from it operate on the Client's balance and
  blinding factors, and MUST be implemented in constant time with respect
  to them ({{Section 7.6 of SIGMA}}). The bit equations are linear in the
  bits, so nothing is selected by a bit's value; a disjunctive range proof
  would instead need its clause selection to be constant time as well. On
  the Moderator, `skM * A_prime` in `VerifySpend` and the inversion of
  `e + skM` and the multiplications by `x` in `IssueResponse` and
  `IssueRefund` operate on the signing key with inputs the Client chooses,
  and MUST be constant time with respect to `skM`; `A_bar` then enters the
  verification through a group element rather than a scalar, which
  {{Section 7.6 of SIGMA}} addresses for keyed-verification credentials.

Derived prover nonces:
: `ProverNonces` derives each nonce with `G.DeriveNonce` (Section 4.3 of
  {{IHAT}}) from its own `Nseed` bytes of fresh randomness, so that each
  nonce is within about `2^-128` of uniform whatever the witness, and the
  proofs are statistically zero-knowledge. If the random source fails by
  repeating all of a proof's `rand` or by returning a constant, each nonce is
  still a pseudorandom function of the witness at a distinct point, and
  `ProveCompact` remains zero-knowledge against a party without the witness
  ({{Section 8.4.2 of FIAT-SHAMIR}}), provided the blinding scalars in the
  witness carry entropy that party lacks. A random source that repeats only
  part of `rand` can repeat one nonce while changing another, and so the
  challenge; the repeated nonce under two challenges reveals the
  corresponding witness scalar.

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

The vectors below cover the Credential scheme under the `P256-SHA256`
ciphersuite at `L = 4`: the generators of {{act-generators}},
`CreateContextScalar`, one key pair, one issuance, and a chain of four
spends with their refunds, one per shape of {{act-spend-relation}}. Byte
strings are in hexadecimal, wrapped at 64 digits with the continuation
lines indented; amounts and `L` are decimal.

Every algorithm is a deterministic function of the bytes it draws from
`random`. Each `rand` entry is the concatenation of every `random` call
the algorithm makes, in the order made, including the `aux` of
`SigningExponent` and the `rand` of `ProverNonces`; an implementation
replays a vector by serving those bytes in place of `random`. The order
is: for `G.GenerateKeyPair`, the key seed; for `IssueRequest`, the
`2 * Nseed` bytes of `k` and `r`, then the prover's `2 * Nseed` bytes;
for `IssueResponse` and `IssueRefund`, the `Nseed` bytes of `aux`, then
the prover's `Nseed` bytes; for `ProveSpend`, the `n * Nseed` bytes of
its scalars, then the prover's `Nw * Nseed` bytes. The `state` entries
are the `ClientIssuanceState` `(k, r, K)` as
`SerializeScalar(k) || SerializeScalar(r) || SerializeElement(K)`, and
the `ClientSpendState` `(kstar, r_star, v1, s, a, K_prime)` as
`SerializeScalar(kstar) || SerializeScalar(r_star) || I2OSP(v1, 8) ||
I2OSP(s, 8) || I2OSP(a, 8) || SerializeElement(K_prime)`. Every message
and `credential` entry is the
encoding of {{act-wire}}, and the spend context of every spend is
`ctx_spend`.

## Ciphersuite {#act-tv-suite}

~~~
suite.identifier = 503235362d534841323536
suite.ctx_proto = 41435476312d503235362d534841323536
suite.L = 4
suite.H1 =
    03c16cd46e4807f2e52d460f03b5e8e11bffee91d9c8bd7e1225c384eaf39cd1
    ac
suite.H2 =
    0282697cb8474f49d091da0ac43c72353809a1999fea49a00a37037163279932
    7b
suite.H3 =
    02597d0ba6b076b6c829b7253943ee3c4a796df35cc38bb6bce03e5398b14f02
    dd
suite.H4 =
    02328e1b98965b32bb63af661190c98042ff24bf23c0fb1d5c6c7b38a3006bcd
    80
suite.ctx_cred =
    4143542d746573742d766563746f72732d636f6e74657874
suite.ctx =
    d1dda6b4b7a3ea5a1159fdde5652ead672730fed9941ca17f3a41220ca379b9a
~~~

## Key Pair {#act-tv-key}

~~~
key.rand =
    6b04e6141f669f915de1d7f0ed8b50405bf6fff65b3ef4a63b6610586ddc5e62
    b22c98437bb5746647de22933c80f522
key.skM =
    6a998a9bd63b4efcd641c1e0e13e4dd6035f1ce748a6aa1461885e0454c928e1
key.pkM =
    03513bbb46b2af7f4ed5304505528b96345064e50917e098630286c89383da72
    22
~~~

## Issuance {#act-tv-issue}

~~~
issue.request.rand =
    fba90a5829478c7590e20f1a6911d2b4f5a9a50bd4485c309c94fedad95f1f79
    0e0bc9994cd3c165d19b78a7e328de6e2c4f77e3aa99f8050f4a0c7d4b52a219
    4d33a5ea903a54a02a807cd6cdb7c269c2712669bbe6f5dfb13495eea30b7da9
    549a65b32ec23bbd0434f3787a143ef286df7fcc1a4afa990c0497780450f987
    a98919981c0f9481c4eb6ee73b79569a2ea0fc45c81480ed4451367947c1cc19
    ee957b16356a0ae63d6c83fbd9d757e69fa8138ada38975479fd20c98160eb78
issue.request.state =
    9771955ca11f5823d2dd81bee85ff622460531e10f623041d071885105987a63
    375a0690961e2d40724c10b8b964df4737d919b5f1a4052d75e006102a700275
    02d5e37c27c5551cf4e93a46b8c2391a9c3233463632344296a6163a96beaf86
    8f
issue.request.message =
    02d5e37c27c5551cf4e93a46b8c2391a9c3233463632344296a6163a96beaf86
    8f2957cfc15870d4f987b6bc2c44092a6f5bdfe414f40c674a0667e003985b0d
    f855c7603550daf61e215546203ebe927803cd0a74d016cb908e02187cd582ed
    27f9bdaf521b6c611aead9d4619a85d63c1dc8ff80fca79daba71a151fef8be5
    90
issue.response.c = 10
issue.response.rand =
    b429f745895b193f227dbad7fd1798339020f1ebb88b5e0429485e01bc34f6db
    93c846f8766d5ec446946ef0d9c6a44873a0ef46a50e37eacf061d40d7440e34
    516d54ee586c67dbb8fd0b7e931fb60a1731d3867e50bbaa1a7422f352070618
issue.response.message =
    0282ea1cdb05da5149a95d911c8d94864a1e18039d3eb9add9212296914c5d79
    2b392ea7d3aa9850a8e83ad34a89ef2c80ffc9323568a9d804005aa1bcdab030
    99000000000000000a105571a811263fbe05022c51cce73fe264e32cbb1191f6
    9a090841dedfbc73ea33ce5ae2d150f1c9ce773ff83e5c1f2e504a866ef79108
    0d61883ab0c56015ad
issue.credential =
    9771955ca11f5823d2dd81bee85ff622460531e10f623041d071885105987a63
    000000000000000a375a0690961e2d40724c10b8b964df4737d919b5f1a4052d
    75e006102a7002750282ea1cdb05da5149a95d911c8d94864a1e18039d3eb9ad
    d9212296914c5d792b392ea7d3aa9850a8e83ad34a89ef2c80ffc9323568a9d8
    04005aa1bcdab03099
~~~

## Spend 1: ordinary spend (`s = 3`, `a = 0`) {#act-tv-spend1}

~~~
spend1.s = 3
spend1.a = 0
spend1.ctx_spend =
    4143542d746573742d766563746f72732d6368616c6c656e67652d6469676573
    74
spend1.rand =
    6e51457124402a73bb25609f1647ee9589b57e96c8bb852d18ed16dc8b9c00f9
    79aa90e88908d06ea7ee259a2067e8981aa128ca2c16d17c0b0b145464a18fbb
    c8c98bdcc8a5541494a93478aece76eb306943b6dcca8781fbc382b4e7801c6d
    5df6aa3f75855db9c6eb9130e5fe4c7ea4173f47f405a3457518d227d0b83b1d
    342ecfe0498cdb99911dbee6f1c2dd66adf61aba8249bc8b66dbeab6351dbe28
    20ec0bec6a0fca3e98ae91f7d3ac00833552cda8198d8a585552c63b1b04a7f9
    8ab63a8b3af08128540a7dd8c6b84b892a3f0b2d6c3120b8ea53b7f40044860b
    33cb6e9930b235d1ac9a7c06261a2b26bba151899bb31a45a2988c425a2637fa
    4e1a0d285364f8fa0cf0e0610feda3d4b9980d16bd3da29447ab44b49e3f4713
    cf496508c825bc711aac384f4620152a8d3fc3a2d1943dfcb9cf2eb9fdc410c6
    f6dfbef97a289fc6550c72f79daef1e54f5cd0132ead59cf513fedf1fc5a05aa
    a0255b3f53c1ed12fbb96bf52197b059d609431451b117381a5a06bd4be53ee4
    951a4f39b3225c1929b35820269ac76d585baf0dbb927cd59f35addd001762b8
    ca25145e7c4159cb30f4cadac6b2f274a710f8916b01e7aa657125ac036e074c
    8dda6de23ecbfa7dba2bb3f490655c25fef2bfc2f3786596045b68563feeb24d
    a0197dc7f5d2128dceb0e4ac42a172d763b6d625df1d4bfcf61fd5fbfe7e222e
    35144cbb058151ff0eba61a90575de984665140d18c49d11df66f7b77bc618b9
    60599627a6606376365da00272f43dfe020306d04c39a7dd3c60a26a23830521
    752dc7ce9c6fb3e70d8c88a6bb1e1fa40b7956619b9571519feac0eae54c5cfa
    e117914953d8c1f88b0035512fa223b8a67174046422dffb4a899546001bc936
    82a8720ccd9fecd89f8e7b97f5ff29b951e586a5319626dd779b3fe45013dec5
    746fe0855edc6def239f89c67a1162e92da595c546f36ead93913f269664d959
    649a06cea9b0f1bd032e4af78eab61f02da2d3d7748d5670e2a6837a63b998a3
    b622944724c22449ae74bbb0271b97a4d2c466ce18481872b420da7f043f2fcf
    abc6e2119289f2d1bc93aadbf09b866d8f44558634afea20cbbf9eef1c34eca5
    591647990b5eb8a15eae624b4c032f18e299c3864d187dc2511ac020bcd3ac1c
    c32139a1cfad2218dff90826cf96f983d3a72d8ad09a7bd06e0286535d7ee13b
    a38d6b3d0042b3a08b2f5b7660d828758d145de84f58d169949632e3309284ab
    7f45b334bb186759c8b0a15ec324422bd9b42bad851fe39aadc603c3a4e7061b
    a59eb6489f0d22941ff4061949b7645143bacb73c28a66182b096b9b1d5e30d5
    e9c277878aad6f5caea62a412d5aaceb1a4d99f2a976e0f7fa081beb61f98a02
    fd85771af1b21d03226de3078ede303754fe2a76c6a0b8bcc70c48b8c4a4fa34
    5bacda0f34c2a2c2be1ab00f663febd847ba119bec3af40d43818406ac1c4f99
    e105a65cc312d673dc2af35c0299b8266af3ca1f398af6ea7b7161960a5571f8
    e3c4ddb248afc0a8c34ea3ef6d705bcecf5fb8aedea611cef7bcf05c89c977f6
    00148e6b43e3e5924c14a6e839452bd779ae72657aa1f2af4d8cfec061921f3f
    2e1015dfae3c34babf5fbaab402826b12129021d537ad519e33d834445f73281
    4215b7686bcdbd739cbd20c4ce7a776b2f43612a2999a36707c410a9f54673ff
    5fd0a13732c2b98c7d6b95de1c0075523afe47821331481606973a7e7cd55386
    6feafbde527e545759589059254213af26c663410aed38f2d2f6d887e776e1b4
    0a200a21f71f9ef8936fc6f4cbb45045
spend1.state =
    7f94975a165f12b8e54a140279d68b2620cf381eb515d7842f3324c34fc5a0ce
    486603ff558a41b73acbb24a59cc31b38534b4ee8a5b68666f0c592ac36a86a4
    00000000000000070000000000000003000000000000000002ba8efee7957123
    cc344752452a01e7389f23d5833dd75bb700f22366a658b7cf
spend1.message =
    9771955ca11f5823d2dd81bee85ff622460531e10f623041d071885105987a63
    0000000000000003000000000000000002de3992cc52293b7838b5e55a8b309e
    15155c2c2117a757c331f625ead65e9e4802fdcf30993888d685c4603bf25527
    79a2430e0404f6f1974a60653fd765f6a35a02173b706022fdd6155d0312a24d
    6848faee5e02bc026383391821f88a6d59282202530e8133e2b6df99a496203e
    7227928877941774e18924c5b9ebeb9ff3e6b3ec03796997f925d18c50be48fa
    929e7996dc5a11bb746d048e3b0a257c83b0136919028e5b242c2f0d640dfe46
    de651d1999f77d351e0e9e32a4056a9a769f89c886ca02361f90e4ec50911b98
    2c5d523f66f22093b5ca4595e226be764831f4a92f6aac8d70bd9d63bae2839a
    f75c05fddf1c442ac532fb7ef7a5e908fefa0ce2018c8d7ae7b46b1e4b3ef1bb
    055ab35da7ec0edda1ad156c3f7c76f0028308cd6f8f837021dcdf98e4930d36
    c79e2b209428d002bc4abff8fcc34cbf6226ef4e7759fd0ed8b1e4f96f3f4ac9
    5e2e7bc4606ace402700861bdf51708cdf2d2b548e64a5bec00ead2420e4d647
    7c102368f8463cc6865579cb53720b003377ecda62bae4a6b13d06ddaceefcc4
    165b2eed432081da7275a3de7e252f0db05266d596d5a0f4c452323c4ba101fa
    8219b7e7c2047bde9c0db8bff129be3d9706964af967234cc78e11b078c03c32
    2bebbd70a85927960f4be7835b7791ec8c893802e29b1f70845884e3f59b47d6
    05409fbe2bd9d47b00ad5470e1750b130b4e89c4d523651a29c1590ccf4060b1
    acd71e42c6f89629e78af6d5aa9eebae64cf86f26bbb38faec0cd830afce926a
    0863150892130d0175ced3f6fe4eb591fea08f9ab4078ae97367683565c61e2a
    2206f94f49cdb6df70082d41b7f0ed58ddbe9ea5f441fcd250296ce5b770d92a
    45efa7b29fd5a143f73d8b5e525d9dd051d399ba88e5114f7be2be897f64c1a2
    e93aa23a24a998e979b5326824c824e0c845e71d95ce8190cde1673c8f66fa45
    4ea12fe3b43d0d49f4284f32283dfa1c3ff07ee211e633782e4d28f23a00bca4
    0b3f4736ae026d8ffb530475eb5e42e7f545c88d33c4359d9dfc808994bf414c
    272536d5104a3705a3505a71e086627115ae3f84702d06c3754643e8ac771fb4
    dec5ff9968c0e31b2ce6660c5a6644043d32058ab240522ee15c3d42775b7ad6
    f1493677b165da862381e3ea559d36d8f708cc58fa1937eccbb8c5077d488d8c
    89576eabe6c423d05424357c7acecc8e0c4b651532fd7c
spend1.refund.t = 1
spend1.refund.rand =
    d0d4df4841caccbc18ff93ded09078976a3cb986f376d910ec2d033fea1cd0b5
    fd5edf4b0cee435e2af14b8f987e66c55ca601fa35bdf956572c2cf5d59f457a
    0da9024b59468d25626b72e92fdce7e9e9eec22fcbad3491280989a561a42da6
spend1.refund.message =
    020bd8856af2da92d3b0e8be1ac4d249927a54a3b997d015cbfe32f192c34024
    f8fe6abfc499b45f0db75d8d8a56f33c371c7f3b4fe433070c087884dcfb4238
    5c00000000000000018891929968c69c51426c7d0b88e12b5e4cc76c84d07d53
    e53cd0831c6d41a100b95158b867c292515fb3cde433954e6ffdff3b179541f9
    3a724c3c9c6a64a26f
spend1.credential =
    7f94975a165f12b8e54a140279d68b2620cf381eb515d7842f3324c34fc5a0ce
    0000000000000008486603ff558a41b73acbb24a59cc31b38534b4ee8a5b6866
    6f0c592ac36a86a4020bd8856af2da92d3b0e8be1ac4d249927a54a3b997d015
    cbfe32f192c34024f8fe6abfc499b45f0db75d8d8a56f33c371c7f3b4fe43307
    0c087884dcfb42385c
~~~

## Spend 2: refresh (`s = 0`, `a = 0`) {#act-tv-spend2}

~~~
spend2.s = 0
spend2.a = 0
spend2.ctx_spend =
    4143542d746573742d766563746f72732d6368616c6c656e67652d6469676573
    74
spend2.rand =
    862a5884515e374af418aa15d050758cb759e3d2aaf9e3aa3cd223239ccfe666
    c22ee29f5d7646d9e64c057d8a80d0942fa388f1090df4284e81d15284f25880
    24416909cfe3dcd528f00c4f34fb5ea2fe7e1c250b59fa5874e0ccd9e3ab6cf1
    d9f51d6239d946ed4f86c7c53d4b98e5025355b544a96c6b40ec9cf06c2030dc
    174462996c5f4398633ef8bb4a352384bad6216e16570ace2e4219fdad60b1aa
    8c9966552343acab6df9c4f5a94193cc9f8097c2bf3cb75b2d2d9e4d992740f7
    96a12b2dbf7d31cdc46f873936ddfbb06463803f220f8b4481c97b56051b0b67
    63be469316c2a24cda44ea9cae97e706eee44564180234fd63b167712f46b8c9
    86a8131ed2806cef6297c20560042355ef6e0955172bf264fa56cbbd1cb92612
    3ef34abf93de52b4b53673afff0a6b7d4f7f7488242f7f758f1b437d5efd41b9
    ec249013dd197f7cd6ec0a3aff65fac5ed2c59fb5f973b4458c25387a69ccab2
    5ff1fc8b71db15757c928dbbcea7db10d9a83841bd10aa0c96571b60fe64f113
    8aab7a7239d097119bddfbda82ed30189512f8995239941c1753b41a441e4890
    c5c8a420f0827ead8b4d7320da0f94872a392d0c3df3f1e688e43ac0cd776669
    55be9c1188634ca3da1393fe912e8321220a3a780d6f1d877bba3acd3b7a1a6b
    db563170e3621e1a39d47e9e3ff922eb7ea46c49d7463ef24153821ee8105f2b
    4208790d80ef9a3e592068fd8e82c7dcb6aad9fe1dc6922e1b9b4ffd01f01b9a
    4d429c7778bb32c15aa2e406c16cd9e2ad23ebfe74c28bfa073a38e9f18be169
    e6f88c119d7f98025372912d5fbb4ef1328690385ba6c69230eb7222af491f46
    df25f5d5967d6181ac93f6ab5f0581fe
spend2.state =
    0cb03fac0c1c386f59959db21ad2081db89a0febce6d3d333d2c98ea509ac7e2
    dfde10012917e76df43ce79b8abd579fbcc2ce95e3581bbc755a946d680d44f2
    0000000000000008000000000000000000000000000000000391c5ac7946222e
    da2eca67ea175370158f783f1849c71e012857affc00165834
spend2.message =
    7f94975a165f12b8e54a140279d68b2620cf381eb515d7842f3324c34fc5a0ce
    00000000000000000000000000000000034e76f8d6c431cb566f50a584f2683e
    482ab88b6db0fce33310689a773697945203ec19b6dd6e542e55c4a9393cb892
    3044f6702647a14ae16a74e93f6c54da7dc203c01abaf6e061eb8007c74c99f7
    0cbcb7bedb30a31c6a1a5953e0f118376a5cb2036baa02753bb185d8b08f12ff
    6595a5c9c31541ddbb916df9e386c2fa657b32ad8af8013a269f7f7ca3920e3b
    1303e791492fcb3abe6473f936fa8f8085f79e385c9366b5e89158b7f9ff4838
    4c836b7615051a82559ff2fd1658897e77bad71977c86fee7588c3a4c35dac72
    eaa89121de09825c86d74907e1f5c6bf6e619bb3078e2d449b600881491c2a9b
    4d8f89a35315a187308907fdc03797f4bca426a554c47aee82307174d7ded2fa
    4b336f97e75d8c441f8a8a88601eb5b5857ed5f5796e0b2b213680201eb14c3e
    b6c0d8a0a0f5a84e48e1199faf53e2cbfee61179ed2cdaf168e1d90e4fdf5ebc
    41aa886289aba0b74ca5158fbae669561a32c8fe0feb4c9416397460f8d8e16f
    ebf446b96251699c0c7db3716ca3e7c9237200ccdccbd6b29d702ecad4b6cf6d
    be65aef950742f937c068a8565982e2fb8c1b7e6
spend2.refund.t = 0
spend2.refund.rand =
    95b4caea533d53f0792b7032eaa799459ce759de2e53720cc977c96647659efe
    a09b16bcd8d252ddb54e6d634b504804f60f932babe6e1da4505806962a93d2f
    0a451bc180e762813ca3e255ed2c8bd816f9d2954e6189a1777eb675fcf35ebc
spend2.refund.message =
    0269823b92c0f3b6569fde5c9d175b69ccd0e850ad55689766d2be12dfc1a3e2
    a06fb0e6384b4acb3582e817b6d0cdf536d8dfc1e6fd49d6470f3a710e75682d
    d20000000000000000fc30b8263b8bc9437c6448679357bb1599898ed08bdcaf
    f1bad47954c88f5bb816ce848166f22f1108dee7879809ce5cfddb4c5425206b
    2403a7514af01cb2b8
spend2.credential =
    0cb03fac0c1c386f59959db21ad2081db89a0febce6d3d333d2c98ea509ac7e2
    0000000000000008dfde10012917e76df43ce79b8abd579fbcc2ce95e3581bbc
    755a946d680d44f20269823b92c0f3b6569fde5c9d175b69ccd0e850ad556897
    66d2be12dfc1a3e2a06fb0e6384b4acb3582e817b6d0cdf536d8dfc1e6fd49d6
    470f3a710e75682dd2
~~~

## Spend 3: pure top-up (`s = 0`, `a = 2`) {#act-tv-spend3}

~~~
spend3.s = 0
spend3.a = 2
spend3.ctx_spend =
    4143542d746573742d766563746f72732d6368616c6c656e67652d6469676573
    74
spend3.rand =
    4dad8dab420ac33ff0c76282d8812e0355708066d257233647efd0db0c04ce63
    01e93145b19783f428a5a7db291966174eec172883bddcd777c1ddebce8f07c5
    dcccb44cb4546e7ba79ab2fa244d63095ee241e7d6b7ec0a1e03a7ba7f683a0f
    542be108b6d1f96b39225d381dc2eb47557f7b376a2c4bbddb6e5b188a67592c
    b2341f551efb3ea7c9abfcc1826ec7963ee6ed4f075c233279a2d6d5693e4a53
    9d1dc063ee9a1a7993d6dfb0bd17ea800cbead18efa42ae92a64a3ab40bea8e5
    e8b264f1426ed6493df5e7af4e288216386f476cb1be9467bd7d5c1967d11e70
    e0b52bb7e1e1576945b20dcf1035c3842a44a48498cbcefa88a66e1ae294b715
    6b50a6a87c494adf8dd4ed8849c5327510a5011bf982e93d5b31404dadb213ce
    2d83b7c9c386cfb9cc193c6ec41a8f7de5fac829399bc90a213974067da2e5a0
    34ef5c24f3b593706b91032d0b293832738a0b0474d0fc14f69d76fe33e82414
    169b56b1cd7628a7907feb3adbad5687898829145cd13de01ab914258c957627
    45e7ca2130d8984a19fa95bed51450060f2f670f20632a932f8adf0068e39c95
    86b4a5e051b4646170c2abd036aa4033d757d10d09a457d519a9c1617915061e
    77c2904a355eff3bf5602a360abae9646fe1bbc699fc455714dd7dcd21830b0b
    847ae69950384f970419e6faea0c58ddc60c68aeaebcef693cd40dbfa75529a1
    4cd75fecd13fd751a2e9bda82f8ad4233461a69df5bd99aad7156f9aa8c62b8b
    bd1b7dff885c062b010ef9753c6fd7c149c25c5d1b5ae77ef509913dbcfbc653
    bc4feb5b644523efe4938af6e67611e6682eb751aa11a43a295b1525f9af5729
    6bf8d4f55ed2fb1c38debf13f358dfa46af42cf494f258240a18992ea508abbb
    92c3ea9976f2347147dc44700423d1d3d43f1e67fe997a3af036ae01651c5d92
    d4e9b45c40c1694f3ac89a2b2f5db70230623c39be05676130686f072ec1c4f1
    4311884b5f42f0797998d5d08235fafd80d5cb693820888b40e0082e6d52327e
    52a2f062e10f58b9308b041023596ccee794322aec769b4761107539bdba8172
    4b16ff40aece31b27629901333569e824b1a5286b6fc6b468dca0b071c9b1aa6
    9861d3511c70ca8d32f13b90451000d79160b366bd3fc9eb977f1deacb62aee8
    09cb13e96b46a44a47c809d5a941bf3bbb02f2523698fd0ac24b2a93da86ca6c
    133f46b1c237c30e480a0394d09c179d21830f3e73572c9ca85466f9ded7ac2b
    b84769db76584505068edf838e602c3b71da1296b351dc77ab1a2ef9cba59f48
    3583e5129a239270e8c131db79d26986a7e422d023529ecae19c3f531a90c7bb
    ab20350abd5c54ae824b56fac3f31f8439bc7c362dcfe81c6d12a59a91ec2e85
    906aee6ec0b1483b393eca374db4f3af1aa455637a369984661da29bd50c8e92
    713e794b77b7582d362225c1d1e051eebc61c19a47984b72631ed6dec7507826
    53c52688c9d28d7bd93cb61b16558c325a0616ce57e9ba9fdccc3b0d9c71a25d
    3031ae4b137340877fb04ea074f38fcbe2a5a467c39346b814e4fd4d54e4084e
    bb843908260ecac22be4b0295b83f69368a4e7017fd4901d51a62e80a7827a19
    7e98fb1bc326f554a37d9a2d985f35a924a7d4674bc7851b2eb6052f11abd939
    f7a6e4ec5143ede75e76b8667987ccbfd54f6c7db44abfe0d49b342c2e0b0851
    370892de406f390b7cf2197409969292103d787be384dd2a1ad959b6efb3cb75
    4cbf852c3f5f546be11f4a43c92db548370a2a4dae605ea0b3338c62d8101245
    0dd25d2a653837ff990de334f82cdcee354d5ccd250f7367a19a1a7376d5e994
    37822d0cccac981b25ff286eaa8a3caf255991a57100caa3797aad091bbfbac6
    d648214355259f6489a5e4d4e2348775e1aa9b2b5d0b17fc29845b3a06a2f978
    6ac03e67f7fbcd77d48eb569476340eb
spend3.state =
    abd3bf72d32e61734cb8953c98762b5f7c0d804988007508eaa7fb8f174fb497
    44b6cad7d649a806b85dda2fbb173369dc1b3323b67c89277df5ab672f3db501
    00000000000000080000000000000000000000000000000203071ee64d81ffac
    bbd2455c8369afc59228fe2950c3ff635f60ccf2597458f8c6
spend3.message =
    0cb03fac0c1c386f59959db21ad2081db89a0febce6d3d333d2c98ea509ac7e2
    00000000000000000000000000000002027d2636ead329c209b47b85adedcae5
    9e3e05dcfefaa2fb0eb3c08b1e49caad1802cdd03b9ccecd3f5bc4d8de96e400
    49765b8f56f1aa9eae1c642e5def070154b003d2d393e2f22fadd8370e63ac3a
    ebf1448be768efb9262af0797f7b2ff7c1014a03987d1e4031707638c83b9699
    ba18fa0d4c85206724307048823c8b22a8a246c20241d986cbb02fb5be756c2a
    948e27e54149f0c955765768763b35e887f140ec9503a5c850e8d95661596008
    e099b8ac5291f4fbdd7ef47a610a19ffedfba3f32a36024d79e3ee48fd3559dc
    113d5db8b0d5cbef4fcf49a092b552e83f54739324a3a702da6b877f9f8301fd
    6d5da86e075fe9e0dd0b97f325ebafb5ba041e6e38e69b2797911e614e2368d3
    6b103b12fcb9e09ffe639b6dc5577370b89f08c5f56ffcc15dd1bc6d8e5dbd93
    ffb40d8aefa13ca2ac3366f984adb2367b802b3dcd8b6600cdd1ae0d0ef0a3c6
    0c6d1b77c73d958029723fa66bd1f317b11720920fa6352cae1eb298554c2333
    70133b32c65fe484098db49ff86965ae05c4874f413f2168e55d3f988074a2b7
    59e4d70c92e43ebe121db4c736125c59917ebf69ca50404c4ca7e45735b4d49c
    5dce487019d73b69fa8bfc8bc01a4a63b7be128d8df63f50a2664742c64e9379
    62d3ea84f26b2f64713cbf202961fdf594785131485b81af3552f8cd0289f963
    342072d477aab66398ac755435f1474d5ce3de21b82363e546c10af8334fab20
    c51c4449691fa8317eb5577080eacd1b85a6000adea1362c1589c46990a024a5
    3ca4fec73012951e72105f54ea1feaff0615f74fd74bb9442b2de0cdf10b1251
    2b48f75c608b95bc2d683741445d4e551f01652070f9318a4956b91d01563f89
    884b250625789d2e645821115ab6c447bf718d76740be27291204b5b3e87d7d3
    2c7ca18d6b72fd3ec513e6d41e1ec5983255f5b381bae4d2642323123600068e
    dc5b07198ca933b0068f3ed14e4a7532147db75fc6b84e4b265a7e04dab3cb50
    a9f16e2771b4c71d655b3be3362015848cdc8ae64896f1f45d166136e6ee4b11
    12aa0a22f6e08d9d76fb92a8716bcbdd7ac26903ed2096c64f64879c6281461e
    8275c63d17ca568d9ca07c7aa1458194d8e1e876d8fb738439d621b0858e6445
    4aba618bb63d350266740bc3a1221fcf1075e6051197dcc2135f91da35a9a1ac
    a0493c0f0bec88d82ec7fb0eef0c7152a536ae23eb3ebd918bbfde4ea1b3eeff
    e3d5171b53293bd71a4b75c4060c8b9c2677e8532f4f7fec454cd5d578429a14
    f1e0181a750213ff11f0b74372e711fa7746bbd4f3565903
spend3.refund.t = 2
spend3.refund.rand =
    912d9992f195bfceea672989d47a02927822088f1470d8b0e9a8de1df4c028d8
    3c56fcdbee9108de7049551bc192dfaeeb02eee83b4f3e326c1ea261a0ac24ad
    f3dba144d9ee0d2d8df7c977aeaddfa73d01412a0eefb0a7926774193aa80f12
spend3.refund.message =
    02795a3b98075ef5d8a668f9ba92c02f63b2c1c98f94b6b18f73fa552f09ff66
    e4d04da1342d34bdab32257f501dbc30cef2ab8a499ffa51c7d43cd9c7ef8815
    590000000000000002ea418fea45543097fbf27b677bf57220d47f09b039b202
    e5a0ed2e59c9de266c66a07fec99cd7ad38165f861324a3af0df6651c8a4b11a
    28566ad35438726810
spend3.credential =
    abd3bf72d32e61734cb8953c98762b5f7c0d804988007508eaa7fb8f174fb497
    000000000000000a44b6cad7d649a806b85dda2fbb173369dc1b3323b67c8927
    7df5ab672f3db50102795a3b98075ef5d8a668f9ba92c02f63b2c1c98f94b6b1
    8f73fa552f09ff66e4d04da1342d34bdab32257f501dbc30cef2ab8a499ffa51
    c7d43cd9c7ef881559
~~~

## Spend 4: spend with top-up (`s = 3`, `a = 2`) {#act-tv-spend4}

~~~
spend4.s = 3
spend4.a = 2
spend4.ctx_spend =
    4143542d746573742d766563746f72732d6368616c6c656e67652d6469676573
    74
spend4.rand =
    778836d5538a27b3d35ea505d95784e8afd6e8a5c13eac89dc46f1751401aa77
    7f2c8899e0233877883c6659ff628a6178b54bfd8541c9bd5ab8247bcddb7568
    db9f02f4de5495efb4d40da8245bafb0ff356f4b5a53b7e9ea0cdef3c08f5871
    bf4049e9498bc8fa87e6c73a0dfd25178bd017ea592fd7f215337748197d3116
    90210b25cb83d9ad872d129dfb3d58959fd5ff5801ed8b9ab3bc79b42e5cf208
    89d338aa1829c0705ed329b71fd393fccfe87e1b3f82e0e600f0ab134ba28aaf
    8d8d5a25d18e1a21f803eb71dc9b189334ff35c46ba2cde89312bdd7326578c7
    1d9b10e4dd118e65ddf92f0eb90a0fdcb461503f3e159fa6908c65dd155feefc
    afb0e27de7687af7d26e7a36125aa223e0bd25c13985c804fcef2fee65f5099e
    95bca02001e353485868991cac8411ddd5f50639750b31057e7f21b650dc9c9e
    0918635219899b585caa36840ed388913fed240aa721aa8efef8a74277cce20e
    2d6cbb572706f7008c11329b6c1a15b8314555662fdcaf24305076dfa2fab1a7
    ed8a933c3da1e456e3b2b8a8647ac3e750852d32b830157c9a23ef47690b0cf1
    32d89f02217c8c71e5bf95bb4eceaec6c1c192c63f5d7dc0530a61fa70604fb0
    2fe2149f2cdf50ea9715e646ffc6ed65bff628caf3ed04f6a316c2722bb9798e
    3a340eda69f19e2c9773e7b1277c4569bcb56b1296d9ce3419c37b380cdd3135
    a364e2ed0268815855cf3f68980b14aa82faca814c9b637177506135355250cf
    601dc4df206b86b3f9119e019bd86842b64864b23470de35a8e866dea2e58e52
    95ac65993a4a4d2f677d9978e872faef02e05e5135eeb11c9b8f9551c8738008
    205a6230f5ef15463469e0cf19907a0c0f37b8b928f63334c3187c59527f19ea
    5a6373216a00ea28483ec8fed7c07ddeaf1894443b5ea5950d426d0dcb1bb956
    115c0b41913f24a727bfe461b87827a29e57bc2e69a6f2ae0687d509a467572c
    856ca6f11147e543511089f313068ab009c5e3fe6a31d685d07120f3be434f84
    a5e7549f5a1e4fdb3ea1a4eb7044604c057e35e71b624ab2578e3706ba07f99c
    11329ad44d1d575e059f19feccffcf87a294058171a0be41f1f99dee7e6830eb
    334661ed59f2e4823381c09e95023b1dfa0add2989a562577dbba3d54e804b0f
    b5d078555225a889b05ba5302bc2699b2c05d42090d1933239ea631a9b5c35c2
    5f1d9d4b865462b4fc5046816ca34e5eed2724672cced8bf7c8758f3b380d567
    7d409ebb6bbd5b1d9a78c3879059caa4506bfe23dc739c1cbeb5aab6a7c6b4a2
    b3c643fabd91197ca0b3af79b4e3367ab9f1b842b45c1ac2a1c735b7a1a644ed
    b652a2c6bb45fe56a24cd0e65c5d333523d138b15300280b6e2752699f9848b4
    2fb9304efb8e31cb8630878491326899e6d310d9784fbb7eeb281993db119b1b
    7e61a162a6615a775c3d666474f6eb9e033843362c0bff081c1a631fd5bfb347
    a6bf8a8f5df512d133e7f4f5de61f3204fb76b77218d00c0261f9e186c8d8c26
    9046b07101f958dab43a5938bb98842a1908ca5eb70cc142a853eaa42e57ef9e
    04d5fadf38960c97d191db2ebf949d0349d34187fd3bd4707de1eb422c3aa571
    451fc5282d6b01f99999b830726ada857a0884fdb4a47d3f8f4ae94dcb7ec9ad
    62b2ada6c19fa8c3b6ef26e796216884c2838cbe6b024f50c66a3b98b2cd45d4
    441355b0512ba70a6a773a529278c9a03647e3cae2830fe1b72d1d786eb2c86d
    0e2cc217364d6690b11057ba092e48115a99a33c7d5893e101e448a8bf30f2ed
    a759f45c45a65d2c4848bf3bc99e7db4a7ee69e974f29ca4ec18e60d36bf2a32
    fb8698963c874baa740fea303a5e9661bf325d53685054ed82347d121127d17d
    e4eb15379c845e13400b29e0610b8ef1bde950f286409e43ad34e29ef9b427a6
    3625390f32d480ba2e1e6d8efda86971d615dc1453d9a275b6bffdd1df6c6bf9
    3a5ae484b1a3de609f1b7750469d2954303e862b32be7e144041d869a8c2c038
    0608d2265a4510ce862b4edb79cd63296ae4a06f26fac09ff508e6f61db3070b
    63d95f8a122e898b39d521a35558b000c6249ba4ff9e4c1152addf2fb250c30d
    f6d2acbc656584986e36415ee76e8d2ce728335b8a44161d8ffd1abac5906957
    3c539bf82ca3dc338d01d66f09ba728859e47ab87d74ba8b0d9e4e752870d35c
    bab6f27f354072363fe7a65fb03dda490df3697b309e19dd7dc7654848911f0c
    4fad948308974fee98eac97f238e3567dd472e645cca2b755dda0cecf715ad67
    32508004c4e6f64f34e622fdf35277abd29740bbe73ee451b9b5485cfd1a1543
    3141ca653e4cf9b7f4234657a8bb7aea0d067433eacedc18a49892c5381d5021
    2be3add4c9d23f662b24c57acb32f509a714b9185433be1a4401985647a827c5
    85e6aaaa35211ac03fcc8c545b2da744cbbbfda72c2453ebf5eebdaf7480d663
    fbd822f8f040481b90fc5cbc2c716a880f78a4d4e3ab79113e5d6106fa345955
    6dabec445d3a1924c831878e03c8068e81bd9ec63b17433104e1cb1d0d379f79
    1b5c11a6d3615941bc6ab089348d8f267cec6d559a2be7983eeeeb8db6ab2c64
    3122ff437aa135b0f5d28f0cd18807f302a475858d533fcf0ae57f50142c54c4
    6dcb61e22b6aa702b55287e4e0e543a7e4df8468a5b36805e6e56eb99a1b866e
    baff7f081564ab3a31d2017ff4c277b71dfaefe915f678a06a9c007e7fb2ee4a
    a25cc500f2a0f3f9041c0caa60d937da17b32d0ff0598ccf40fee34f8c89fc73
    ceb570b9062fb457a935b1fdf7c182d30d7ecc5f2ba654b1c5048ef79191f4ed
    0d5e4fa662ca3050fb757bbd15d6040d569c4106c014cd45a815f609f8174583
    90b8461cb97570cb46d717ab190ad4ca
spend4.state =
    7005897e4e9731d908a469c185bcdabd506c86345329a9f25aea9924fa017599
    379c178f99568e6f95e77d5a85e6e26cb8efc4377c797440087279a2cef08b4a
    0000000000000007000000000000000300000000000000020253254677833518
    aa402d0a3e6f1ab97dd704673600caab785a95b78c431c991b
spend4.message =
    abd3bf72d32e61734cb8953c98762b5f7c0d804988007508eaa7fb8f174fb497
    0000000000000003000000000000000202f782e2fbe20bdd3913cb87a60f18a9
    825b1b3502bbde7f61d3e57c1cda1a0df503f5eceaa7b14c98f342d67ab51cda
    1a94dca84f83e5d0c9908f91d873964c9adb03994873a185a8b171f370f06a14
    fa8081e248f7327856b09f775ac1aa7c8b386503db19e3129885f382b46826ba
    acc88c282d4efdb0f790bf13c9773bd5594b3eb703289d0047abb1206db4f62f
    ead4da9f0c8ef0a483d4a8b17ba0511e43f8e7e9f8033ecea5d0eda0a50f7c83
    50095ed94c79ff2fa0e6d3929b3557ee4b1b4443a83103aa23cacd9c0717bc8b
    87b0f244bda7698ce33b1a9031f0a8d955697698a323d203d5279d91f3cc866b
    73ade7be42604508d9d530c47a41fac71b9830082fe07f9d022311cd632293c6
    a1929a548cf67d3ff61ef159c3a56a9b34e15c0ec270dffbf0020f4421ac97c3
    34814d4893d57af97eac09a3ff4650df470cb224ce90e468ef03025d6e99d0f6
    8a404e29e26cd98af05fb0c093e8f98f984737ae40153bed4a1e978daf044b5a
    df4664455ef502e52ec2d4c66e5df04fdb533838f9880e244ab7f2abddefccc4
    7dc93208f41f060101c54384b1aea6f8eb8a2e3b9290aca82b038477d576af21
    30b62a983f00f777d0afb83be1d1f53fd85c96a450c10ba609b38ac70ee2034d
    a5a256141b1f12a6212f0a9b8a4a7bf7bcc04c7698109acff10afb61931bec97
    f2d7265d3c8356613d00df808e6bfacbcb29ed47e839836498ed31253140a6dd
    bd96cef62cd5c400ebf7d9424aa8e72452ce97ca274f4dad1728887c0a7f09a1
    56702fbebe6e26b05b3f92106ebd5f1c082635fe4626e6eaab9c028ee71bdec7
    8dc7557180adb833eda377392538845a0632c0708f1b53f4fa19e5bbee7a8236
    750b7f1a06fb97b497231653210bf79be66c91ed9eda1a9a117184250e650a52
    0df3272e391295ddc641eedb207fb6d75318277cd8b3275e386025c284af1a49
    6f1e5c8e0836a940f4edf62494152dab914438be2ce61be0261d48bb1e1fd8df
    e712bba85bef5a42a725c974c201f303a3acab07d5a5affa82955e3597c33773
    7e2f45607365c4a7203f733839cd3722ecf8f852ff81f28f5835484d446398e5
    f7196d1b97f4d6ecd149985abb4de4f98e1ff0e1f9efb380429e486c4f828fd9
    032e3c991b2fbb4abcb5c7195f813b8bcc86dddfdbe522e3a5176507f21ac7c0
    d32dd88b02a0aa281a785c6a45193c87c2addcc28a8566801fa5d55f79f7ebcc
    da316637e5e22f4b36313f5a83dbd515fe4471f1c186f404844e99390fb68300
    483eb93c053ab71333b14b4710715455f9123eba8bb5d29366b7b364cb6f451e
    c7044b0dc88bf0fefcd2cfccf5e2313c2ba3d6f5c1ff1a91d7b780bb3aea4a4c
    2ebd497aa101cb53af5533d6e1f8589a1e781f60eb0828cf7dabf4847a3ab6bf
    3366db34c278bf8fa28aa544b3c6ff6d5c04422364cd4b9a3db9107044659033
    6d1a4ffc075c5fb5b8b66fe92fd457d423ec842215fa8ede0fcb426130a82797
    bc737b441a860686e6fbe1fef63f82a00d36cdc5f05c06b7fba6897e7e073056
    fdc63141719c55497262dc676438c63f70e9fdb4edb7880fce6723ae71ae3c64
    e5e76606153db3054c967b130e9ad62b55b129d6fe4a38b4c736144d8eb0cd86
    9edb6eb2a5cee3933d6857232455ebd27c77862afa9baf7ec9d3e0b2a755eb43
    7ae318e5f639f42e7e221d5a364526f9e1041b0a5a835ad5bbbbe652da85fa0b
    0401d40f7960a950b2af332b2195926a55ed95ed22d9f198ea30bb869082d173
    db7373b6c4a06ff45bcc6d30c58ee8e66f04ce478c0f5ef3441650665dba85e3
    ee0164672db492ce92d902738badc8b86bd17ed1512810f6951bc12b27af08f1
    8cc8faf12f9a7013b0fc8578591503e73cd777c0c0e31fa75697f9256c4559b9
    68ac98b5f640d30b7f51961562d117774f999efe8fe88be6c32007
spend4.refund.t = 5
spend4.refund.rand =
    15792e979eb42697338162856cb1eb2ead6eb2fdfca1ac6c998271398ea79aed
    f8c644173a51e3a3f5368e85b5b8543b19fc6d42d2ab5130dbd46e0dc8d8f43b
    34ed1514cb7272e7ae2e4981bcfd1072c13dc21d3905e5055216fad0c6feefc4
spend4.refund.message =
    02c3d7d3686b84d7666dbc9b310dc60d962c6e4aff1668629f3de83d646b8182
    80923b72830171d5df1d4ab65ccaf55062f694119273a8a3f42790d3a417f947
    68000000000000000558027e51cf5a139d636c90a7b09b1c3c8a19708d282133
    93752cd2e24d7f7fe6287f1cb437a771356b997cd60c15282dbd5cf4f2f5449d
    ce045f63282a81fc64
spend4.credential =
    7005897e4e9731d908a469c185bcdabd506c86345329a9f25aea9924fa017599
    000000000000000c379c178f99568e6f95e77d5a85e6e26cb8efc4377c797440
    087279a2cef08b4a02c3d7d3686b84d7666dbc9b310dc60d962c6e4aff166862
    9f3de83d646b818280923b72830171d5df1d4ab65ccaf55062f694119273a8a3
    f42790d3a417f94768
~~~

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
