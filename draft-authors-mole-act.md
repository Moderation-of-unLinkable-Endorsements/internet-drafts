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
  ROLLATINI:
    title: "Rollatini: An Issuer-Hiding Anonymous Token"
    target: https://moderation-of-unlinkable-endorsements.github.io/internet-drafts/draft-authors-mole-rollatini.html
    date: 2026
    seriesinfo:
      Internet-Draft: draft-authors-mole-rollatini
    author:
      -
        ins: S. Schlesinger
      -
        ins: D. I. Mohan
  ARCH: I-D.draft-jms-mole-architecture
  PROTOCOLS: I-D.draft-jms-mole-protocols
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
> lost response ({{act-finalize-refund}}). Until then, these references
> state requirements the profile must meet.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

The capitalized terms Client, Moderator, and Credential are used as
defined in {{ARCH}}; a lowercase credential is the generic cryptographic
notion. The message-encoding conventions, Python notation, and helpers
`I2OSP`, `U16Prefixed`, `random`, and `Seed` are those of
Section 2 of {{ROLLATINI}}. The algorithms use `bytes` for byte strings, `int`
for integers, and `Sequence` and `NamedTuple` from Python's `typing` module.
Record fields appear in the same order as their tuple representation.

The group `G`, protocol context `ctx_proto`, seed length `Nseed`,
generators, and balance width `L` are globals fixed by the ACT
configuration ({{act-config}}). Shared group methods from {{ROLLATINI}} use
the ACT group instance `G`, which stores `ctx_proto` and applies ACT
domain separation. Both schemes use `Nseed = 48`. Public byte-string
inputs retain the length bounds
specified by the operation that uses them.

# Preliminaries {#preliminaries}

The construction has three dependencies:

Group:
: A prime-order group implementing the interface in {{group}}. {{ciphersuites}}
  gives concrete instances.

Hash:
: A cryptographic hash function, used by the `HashToGroup`, `HashToScalar`,
  and derivation algorithms that the group of {{ROLLATINI}} provides.

Sigma protocol:
: The compact non-interactive Sigma protocol of {{SIGMA}}, instantiated in
  {{act-proofs}}.

## Prime-Order Group {#group}

ACT uses the prime-order group interface and the `Element` and `Scalar`
types of Section 3.1 of {{ROLLATINI}}, instantiated as in {{ciphersuites}}.
The Python interface provides `G.scalar(x)` for an integer `x` in
`[0, G.Order())`, `s.isZero()` for a scalar, and `A.isIdentity()` for an
element. Arithmetic combines values of the same type: integer constants
are converted with `G.scalar` before scalar arithmetic. The negative of
an element `A` is `G.Identity() - A`.

## Errors {#errors}

`DeserializeError`, `VerifyError`, `DeriveError`, and `ValueError` have the
meanings given in Section 3.2 of {{ROLLATINI}}. ACT additionally uses
`AmountError` when a balance or amount is outside the range admitted by
{{act-amounts}}:

~~~ python
class AmountError(ValueError):
    """A credit amount is outside its permitted range."""
~~~

An implementation that raises an error MUST abort the affected protocol run.

## Deriving Scalars {#derive-scalar}

Use `G.DeriveScalars(rand: bytes, info: bytes, count: int) ->
list[Scalar]` from Section 4.2 of {{ROLLATINI}}, using the ACT group instance
initialized with `ctx_proto`. It rejects `rand` whose length is not `Nseed`
with `ValueError`, and raises `DeriveError` in the negligible event that a
derived scalar is zero. ACT applies the following requirements to this
shared algorithm.

`rand` MUST be `Nseed` bytes of output of `random` and MUST NOT be used for
more than one derivation. An algorithm derives all of its scalars with one
call, under an `info` string that names it. In the random oracle model, each
derived scalar is within about `2^-128` of uniform (Section 4.2 of
{{ROLLATINI}}); the unlinkability argument of {{act-security}} relies on this.
See {{randomness}}.

## Key Generation {#keygen}

Use `G.DeriveKeyPair(seed, info)` and `G.GenerateKeyPair()` from Section
4.4 of {{ROLLATINI}}, with the ACT group instance of {{act-config}}. Both
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
`G.DeriveScalars`, `G.DeriveNonces`, and the key generation of {{keygen}} are
parameterized by it.

The scheme has one further parameter, the *balance width* `L`. Balances and
amounts are integers in `[0, 2^L)`. `L` MUST satisfy `1 <= L <=
MAX_BIT_LENGTH`, where `MAX_BIT_LENGTH` is fixed by the ciphersuite. The size
of a spend proof and the cost of producing and verifying it grow linearly in
`L`, so a deployment SHOULD choose the smallest `L` that accommodates its
largest balance. The Moderator publishes `L` together with its public key
({{PROTOCOLS}}); a Client MUST use the published value.

`L` is fixed for the lifetime of a key and credential context.
{{act-security}} shows by induction over issuances and refunds that every
balance the Moderator has signed lies below `2^L`, assuming one value of `L`
per key and context. A Moderator that changes `L` MUST also change the
credential context or the key. Deployments are RECOMMENDED to include `L` in
the credential context, for instance by appending `I2OSP(L, 1)` to it, so
that changing `L` changes the context.

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

The context is never carried on the wire. Each party supplies it to every
algorithm of this section that computes or checks a signature, so a spend
verifies only under the context the Credential was issued under. A
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
`B` of {{ciphersuites}}. Compact proofs are used because a batchable proof
adds one element per equation, most of the message for the spend relation,
and a Moderator verifies each spend on its own, atomically with recording
its nullifier.

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
that `ProverNonces.random_scalar` computes below. The nonces are derived
together with `G.DeriveNonces` (Section 4.3 of {{ROLLATINI}}) from the witness,
the session, the relation, and fresh randomness; see "Derived prover nonces"
in {{act-security}}.

~~~ python
class ProverNonces:
    def __init__(
        self,
        witness: Sequence[Scalar],
        session_id: bytes,
        instance: bytes,
    ) -> None:
        self.nonces = G.DeriveNonces(
            b"".join(G.SerializeScalar(w) for w in witness),
            b"nonce",
            session_id + I2OSP(len(instance), 4) + instance,
            random(Nseed),
            len(witness),
        )
        self.count = 0

    def random_scalar(self) -> int:
        i = self.count
        self.count = i + 1
        return int(self.nonces[i])
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
reproduces the same proof.
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
exponent `e` of the signature `(A, e)`. It is derived with `G.DeriveNonces`
(Section 4.3 of {{ROLLATINI}}) from the signing key, the signed message, and
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
    (e,) = G.DeriveNonces(
        G.SerializeScalar(skM), b"e", instance, random(Nseed), 1
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
    rand = random(Nseed)
    (k, r) = G.DeriveScalars(rand, b"IssueRequest", 2)

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
shows that `K_n` has no `H1` component, which would otherwise raise the
balance the refund signs.

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

    # Four fixed scalars, then L for the bits of the remainder or
    # one for its commitment, then L for the bits of the topped-up
    # balance.
    n = 4 + (L if s > 0 else 1) + (L if a > 0 else 0)
    derived = G.DeriveScalars(random(Nseed), b"ProveSpend", n)
    (r1, r2, kstar, rn) = derived[:4]
    next_scalar = 4

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
            s1.append(derived[next_scalar + j])
            Com1.append(b1[j] * H1 + s1[j] * H3)
            r_star = r_star + G.scalar(2**j) * s1[j]
        u1 = [(G.scalar(1) - b1[j]) * s1[j] for j in range(L)]
        witness += b1 + s1 + u1
        next_scalar = next_scalar + L
    else:
        rc = derived[next_scalar]
        Com_c = G.scalar(c) * H1 + rc * H3
        r_star = rn + rc
        witness += [rc]
        next_scalar = next_scalar + 1

    # Commit to the topped-up balance when there is a top-up.
    if a > 0:
        b2 = Bits(v2)
        s2 = []
        for j in range(L):
            s2.append(derived[next_scalar + j])
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

`ctx_proto` is as computed in {{act-config}}. The seed length, that of the
random input to every derivation, is `Nseed = 48` bytes.

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
algorithms, and canonical encodings of Section 7.1 of {{ROLLATINI}}. ACT uses
`Ne = 33`, `Ns = 32`, and `Nseed = 48`. Instantiate every hash with the
ACT `ctx_proto` of {{act-config}}, including the explicit DSTs of
`G.DeriveScalars`, `G.ExpandScalars`, `G.DeriveNonces`, and
`G.DeriveKeyPair`. The group-element permutation of Rollatini is not used.

## Randomness {#randomness}

Every random value in this document is drawn with `random` and consumed in
inputs of `Nseed` bytes, by `G.DeriveScalars` ({{derive-scalar}}), by
`G.DeriveKeyPair` ({{keygen}}) for a key, or, for the values listed below, by
`G.DeriveNonces` (Section 4.3 of {{ROLLATINI}}); no scalar is sampled directly.
Implementations MUST draw with a cryptographically secure random number
generator and MUST NOT reuse randomness across derivations. Randomness is as
sensitive as the values derived from it, and the constant-time requirement
of {{act-security}} covers both.

The following values MUST be derived with `G.DeriveNonces`, with the inputs
stated where they are used; drawing them directly is not conformant:

* the Moderator's signing exponent `e` in `IssueResponse` and
  `IssueRefund`, through `SigningExponent` ({{act-signing-exponent}});
* every nonce of a `ProveCompact` prover of the Credential scheme,
  through `ProverNonces` ({{act-prover-nonces}}).

The Client's `k`, `r`, `r1`, `r2`, `kstar`, `rn`, `rc`, `s1`, and `s2` are
derived with `G.DeriveScalars` from randomness alone; a repetition among them
harms only that Client. The signing exponent and the prover nonces are also
derived from a secret, because a repeated signing exponent, or a prover nonce
repeated under a different challenge, can compromise `skM` or reveal a
witness scalar ({{act-security}}).

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
  nullifier. The right-hand side is under the Moderator's control. The
  property rests on the following:

  * an accepted spend proof yields, by special soundness, a signature under
    `skM` on `(c, k, r, ctx)`;
  * every such signature was produced by `IssueResponse` or `IssueRefund`,
    whose signing oracles are constrained by the proofs they verify, or
    q-SDH is broken;
  * the sum equations of {{act-spend-relation}} hold over the integers
    ("Amount validation" below), so the refund Credential has balance exactly
    `c - s + t`; and
  * a recorded nullifier is never counted twice.

Unlinkability:
: A spend reveals nothing about which issuance or refund produced the
  Credential it consumes, nor about the balance beyond the public amounts,
  to a Moderator that sees every message and holds `skM`. The commitments
  `K`, `K_n`, and the bit commitments are hiding {{Pedersen91}}; the
  pair `(A_prime, B_bar)` is a uniform rerandomization of the signature
  {{TZ23}}; and the proofs are statistically zero-knowledge
  ({{Section 7.5 of SIGMA}}). These hold for uniform blinding factors and
  nonces, and in the random oracle model those of this document are each
  within about `2^-128` of uniform ({{derive-scalar}}, "Derived prover
  nonces" below). None of this relies on the hardness of discrete
  logarithms, so transcripts recorded today reveal nothing to a future
  quantum computer, which would need about `2^128` evaluations of the hash
  function to find a secret input of a derivation by search. Such an
  attacker can, however, recover `skM` from `pkM` and forge Credentials, so
  credit conservation does not hold against it. The public amounts `s`, `a`, and
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
  `G.DeriveNonces` (Section 4.3 of {{ROLLATINI}}) from the key and the operation
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
  state, so that no process can use any of them twice; a Credential or
  state restored from a
  backup after use is the wallet's responsibility. A second spend of the
  same Credential presents the same nullifier, which the Moderator
  rejects, and links the two presentations to each other; one issuance
  state finalized against two responses, or one spend state against two
  refunds, yields Credentials that share a nullifier, of which at most
  one can ever be spent. A Client that loses the spend state after the
  Moderator has recorded the nullifier loses the balance.

Constant time:
: `Bits`, every operation on the witness of the spend relation, and every
  operation on the Client's randomness and the scalars derived from it MUST be
  implemented in constant time with respect to those secrets
  ({{Section 7.6 of SIGMA}}). The bit equations are linear in the bits, so
  nothing is selected by a bit's value. On
  the Moderator, `skM * A_prime` in `VerifySpend` and the inversion of
  `e + skM` and the multiplications by `x` in `IssueResponse` and
  `IssueRefund` operate on the signing key with inputs the Client chooses,
  and MUST be constant time with respect to `skM`; `A_bar` then enters the
  verification through a group element rather than a scalar, which
  {{Section 7.6 of SIGMA}} addresses for keyed-verification credentials.

Derived prover nonces:
: `ProverNonces` derives the nonces of a proof together with
  `G.DeriveNonces` (Section 4.3 of {{ROLLATINI}}) from the witness, the
  relation, and `Nseed` bytes of fresh randomness. With a working random
  source each nonce is within about `2^-128` of uniform in the random oracle
  model, and the proofs are statistically zero-knowledge. With a failed one
  the nonces remain hash outputs on an input that contains the witness and
  change with any part of `rand` or the relation, as Section 4.3 of
  {{ROLLATINI}} states, so no nonce is reused under a different challenge.
  `ProveCompact` then remains zero-knowledge against a party without the
  witness
  ({{Section 8.4.2 of FIAT-SHAMIR}}), provided the blinding scalars in the
  witness carry entropy that party lacks.

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
: The requirements on deployments are those of "Nullifier store", "Context
  granularity", and "Single use of Credentials and states" above, consistent
  configuration across Clients ({{ARCH}}), and the randomness requirements
  of {{randomness}}.

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
the algorithm makes, in the order made, including those of
`SigningExponent` and `ProverNonces`; an implementation
replays a vector by serving those bytes in place of `random`. The order
is: for `G.GenerateKeyPair`, the key seed; for `IssueRequest`, the
`Nseed` bytes of `k` and `r`, then the prover's `Nseed` bytes; for
`IssueResponse` and `IssueRefund`, the `Nseed` bytes of `e`, then the
prover's `Nseed` bytes; for `ProveSpend`, the `Nseed` bytes of its
scalars, then the prover's `Nseed` bytes. The `state` entries
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
issue.request.state =
    45f6c6354b3a477530da6a339a6647bf1a18738f3e36197861ed0a435279c3ce
    6db698dc0ab0a626f2047331981742f4504932ef191ced0db687982bd5813eef
    02bc28c7238986ef41811943cfe8ccbfcb3cbe933f8a583f2190dc4187133197
    63
issue.request.message =
    02bc28c7238986ef41811943cfe8ccbfcb3cbe933f8a583f2190dc4187133197
    63a204de1dd76434170a6b1c0a07c3836307c53a17011b1f899f1bd6c58712ac
    86a4699524580fe3d4d305a96c18162b692adcecfd2c0ed4dbb04ce4aef93212
    1b5c845702018bf287c839f24ee7cd6a3f43494249fd82f78bed467e1d6ab94b
    3a
issue.response.c = 10
issue.response.rand =
    549a65b32ec23bbd0434f3787a143ef286df7fcc1a4afa990c0497780450f987
    a98919981c0f9481c4eb6ee73b79569a2ea0fc45c81480ed4451367947c1cc19
    ee957b16356a0ae63d6c83fbd9d757e69fa8138ada38975479fd20c98160eb78
issue.response.message =
    0219c7ca1c950892496809a235512c49773a31a35520647b92ee8a25c76f9aae
    68bed08bbfced4c5b6eee438a45ca29d878db075b304fb58593a93883e7c9030
    89000000000000000a229f0198688717aad558b8fb63fb983570067b333cec52
    cdebfa26c0ee95cfe98d094fc061ecb10259a0fb576e39907f9ed97438cb414e
    c162a58a26f51332a5
issue.credential =
    45f6c6354b3a477530da6a339a6647bf1a18738f3e36197861ed0a435279c3ce
    000000000000000a6db698dc0ab0a626f2047331981742f4504932ef191ced0d
    b687982bd5813eef0219c7ca1c950892496809a235512c49773a31a35520647b
    92ee8a25c76f9aae68bed08bbfced4c5b6eee438a45ca29d878db075b304fb58
    593a93883e7c903089
~~~

## Spend 1: ordinary spend (`s = 3`, `a = 0`) {#act-tv-spend1}

~~~
spend1.s = 3
spend1.a = 0
spend1.ctx_spend =
    4143542d746573742d766563746f72732d6368616c6c656e67652d6469676573
    74
spend1.rand =
    b429f745895b193f227dbad7fd1798339020f1ebb88b5e0429485e01bc34f6db
    93c846f8766d5ec446946ef0d9c6a44873a0ef46a50e37eacf061d40d7440e34
    516d54ee586c67dbb8fd0b7e931fb60a1731d3867e50bbaa1a7422f352070618
spend1.state =
    ee61f8215ebb0ca69e29a0bc91cf184347223292ebc2d3c7b69fb3da1efa92d0
    7d3f72f13d19b53838e0bf3d1bb80965d00a926d09f4e5250e9a03a2ff2d68fe
    000000000000000700000000000000030000000000000000021b48762b09e181
    9e8f8070a9e07926ec5d319b005462376c027a71c231fe08ad
spend1.message =
    45f6c6354b3a477530da6a339a6647bf1a18738f3e36197861ed0a435279c3ce
    00000000000000030000000000000000037462d06d0e1857691e39027fb94ba9
    87ee4d626b73957ef2577f4f7f80afdd8f031fd0f1ae300ef6086d3d1badbe53
    fdc73af5a3a7c3c7e94d31dfc3e200f1b14c034b324fe0ceaf20d9c14192a366
    9dde3854b90cbde819714214408c2173927e0d02e0976db98ca955ed1b86f1e6
    f5be405c855fd65b3c6648f26851324d0cd17d5502d9013827da0c05338a3319
    760b4d1d6804380d6f45614e70053a7808f4fa66ae02e2f88017a6fa3c10ff1c
    9616a4b5db3837b0c9642f43b8ede8af8942e9a8a6bb02143dcd3e4c15cdd475
    a94dc06eed156efed163051862ad7016ea1b90d4a646f70f0ed26f89cc5d5ddd
    b31df72cb8f49bd18a124a3ab793195c1bf893ed8cef724bb9ddb8525fb38e29
    edde5788ccd60c17eeefd03e6554fd67f11df8f3ea45b9879f7d64a0523f83f2
    b0c4536000606d9af46c4d093ac729c2b393347bd99681d97a849e426b88e1d4
    5671e86a12c4e512e1fa0c765e9258de12701fe28ea3517a4d244ff490b1b288
    c991b614cbaf26afd0ef945d92bceeb7dc00ee45d861c60b4c5f7e41739e0a35
    99d4ba252a3927ad9fedcf24f9ee28b7fd5bad9b571d2a125bf2fdce68e34338
    40a2821eb9170d1a2b706d2fb32f66d11812be3e16a2b2b14ec9ebcde6deace5
    cff6277742a95be0afeb2101e1a1c35291ea831df7d89f9b021459a7be6aecb6
    b86e7c863632fa02e38377c538df55e7a70a25f30c1081f4ec083c4fb1ac012c
    02eca834aa4f744750c1be793e3decc51e5d896e6a3bfa8eeaed28618f7415bb
    bf370a059c04b3440f2a627d4b33c6216b97d17826ca4caf2cdd532b868eb482
    3145e86454e0664ba54656ffbe9d52dcab4b7f5651c8b9ef06a00b13b7ef7bf0
    71c3308101f1835d3cbd965f5a884386d59f2d0b0940ad174ab04f55668a34ea
    818e2d624bade6b2c0c4eb8df108559045ffd53820556ed90c3a8cf18c3ef9b3
    b6ea2bda67f2898170c5ea2d0a4ea878c1b48c36f7144fcbceab9e32026234d1
    2a9c286586affae56499fca51f115fc956d79d2acb1e1889616bbdca3c37e907
    77d0b7d822d9b235c5b75d1a14b7c3132960963d12cbcc24ffc0c534a426960e
    ade06b1eb7f19de8c807e90f3b9ca7db2e9a928dac497f9488754ae394c727a6
    87ae8f52db082f22254a52dd078da391a81e069a2de6d42012f9d58734aded52
    57b52339941e3fb3a6af833ef96444b4f643a18a774c81
spend1.refund.t = 1
spend1.refund.rand =
    6e51457124402a73bb25609f1647ee9589b57e96c8bb852d18ed16dc8b9c00f9
    79aa90e88908d06ea7ee259a2067e8981aa128ca2c16d17c0b0b145464a18fbb
    c8c98bdcc8a5541494a93478aece76eb306943b6dcca8781fbc382b4e7801c6d
spend1.refund.message =
    02cdeb0b833d8d51bf0cb8b00d145e4dc7e771355ce9489a316d53630482dea1
    9a15a70756d3d9459b8f1708ee05b828fa7fa7e3cd5fd0b5d975599fd7585b3e
    050000000000000001063d7d32e384dd8ddf4df240017d730bdd899018d0b031
    13decf535d5b852b6811a648eaa0d20fc871f9b1d8699e1c34b9e7e0c3a5f03a
    f27d5765a0f029ef2e
spend1.credential =
    ee61f8215ebb0ca69e29a0bc91cf184347223292ebc2d3c7b69fb3da1efa92d0
    00000000000000087d3f72f13d19b53838e0bf3d1bb80965d00a926d09f4e525
    0e9a03a2ff2d68fe02cdeb0b833d8d51bf0cb8b00d145e4dc7e771355ce9489a
    316d53630482dea19a15a70756d3d9459b8f1708ee05b828fa7fa7e3cd5fd0b5
    d975599fd7585b3e05
~~~

## Spend 2: refresh (`s = 0`, `a = 0`) {#act-tv-spend2}

~~~
spend2.s = 0
spend2.a = 0
spend2.ctx_spend =
    4143542d746573742d766563746f72732d6368616c6c656e67652d6469676573
    74
spend2.rand =
    5df6aa3f75855db9c6eb9130e5fe4c7ea4173f47f405a3457518d227d0b83b1d
    342ecfe0498cdb99911dbee6f1c2dd66adf61aba8249bc8b66dbeab6351dbe28
    20ec0bec6a0fca3e98ae91f7d3ac00833552cda8198d8a585552c63b1b04a7f9
spend2.state =
    fd4592710665751a2ea3160ea16fe18ea7986f5af765533d3985625d938456fb
    5d634dda9fc8375ac6d2daa51cc50aca954fa420078c204349e1889a77d8b746
    00000000000000080000000000000000000000000000000002396aab2696270d
    5a81eefd48c992ed28d97873ab3685270a96f5ffee33bee181
spend2.message =
    ee61f8215ebb0ca69e29a0bc91cf184347223292ebc2d3c7b69fb3da1efa92d0
    00000000000000000000000000000000020f3a120dfacfc6382df58f9481f2bd
    24bd055d52604ea6c6580361939568e67202cb4def6ef93e55331eecb156a000
    c6c2756bebcf9814130d424882a4f8446e9302ea09ac5c4013a19262e8479449
    232c4b8da8769a34a13e01bf14175454ce2e4f0271058492ebfcf5032a715308
    0bf06e4523f1566d331eb662e9009c304e8dd5676062c3cbf8ca74f17e8305f0
    7d44df3d5592de1691bb0c4d21c0e22ee78b88b0bbb95e2dd3a377690936d37d
    b9d6e5580d97f98ef31b02897cd1c105313f254bd28f0c7204ad6e7ed19195e3
    ccd2024818ad3aa6c53efe2139e104baf007fcd5fd74ea7286a59533fd92afc6
    4ea401d7ab71fad46f74c922911051e5e7ae974b1eafc973e9368ad25970c9d5
    0b659343ca90b2f42ce4b3b4e667db05fce51db8f54ed5fce348c6989d0cdbd8
    31a2342c9fcb3c25b7ceb2cc392931ea25c112648fd6e410d9cbef089c6361bc
    1c61218d3a271f868f209be43ca5550d49c154b28962602ef3577fd8d99e6a95
    ea84dfcc09f92097df972fe8e73edf2a50b60a5a77537045f1ea74c31281117c
    6f893cb1c9a7650f5fe87fb3b36537954d53a72f
spend2.refund.t = 0
spend2.refund.rand =
    8ab63a8b3af08128540a7dd8c6b84b892a3f0b2d6c3120b8ea53b7f40044860b
    33cb6e9930b235d1ac9a7c06261a2b26bba151899bb31a45a2988c425a2637fa
    4e1a0d285364f8fa0cf0e0610feda3d4b9980d16bd3da29447ab44b49e3f4713
spend2.refund.message =
    02e4ca240712b4248e90bec8ed76f5b5a7008c65ada19c553478dcdc94576686
    8e2cbe8e60e995e1443af12dd9b0487fdd1c6ef29d12c12459afeeb16baffc85
    3c0000000000000000eab936b5c1e13c20f73a1ecacbc286f2ac7afd4f748844
    66435e2c12ed1da13a9a90d61edd767a5be2c6d00796b231311dc58e9e53208c
    ddbdae9f0db8440f96
spend2.credential =
    fd4592710665751a2ea3160ea16fe18ea7986f5af765533d3985625d938456fb
    00000000000000085d634dda9fc8375ac6d2daa51cc50aca954fa420078c2043
    49e1889a77d8b74602e4ca240712b4248e90bec8ed76f5b5a7008c65ada19c55
    3478dcdc945766868e2cbe8e60e995e1443af12dd9b0487fdd1c6ef29d12c124
    59afeeb16baffc853c
~~~

## Spend 3: pure top-up (`s = 0`, `a = 2`) {#act-tv-spend3}

~~~
spend3.s = 0
spend3.a = 2
spend3.ctx_spend =
    4143542d746573742d766563746f72732d6368616c6c656e67652d6469676573
    74
spend3.rand =
    cf496508c825bc711aac384f4620152a8d3fc3a2d1943dfcb9cf2eb9fdc410c6
    f6dfbef97a289fc6550c72f79daef1e54f5cd0132ead59cf513fedf1fc5a05aa
    a0255b3f53c1ed12fbb96bf52197b059d609431451b117381a5a06bd4be53ee4
spend3.state =
    be60dec14d630dcb30a104bf6bc798bc60cf5ca35911d94bab03a27694bc5607
    f613b07592172ebf8c4e04a6d3b6651b9d17eb9bc333fb7caa5da9087d7fad90
    00000000000000080000000000000000000000000000000202aa041fce3f3996
    aae6eb6a309ebf8965085ad5d5a156c48c4520a9397822706d
spend3.message =
    fd4592710665751a2ea3160ea16fe18ea7986f5af765533d3985625d938456fb
    0000000000000000000000000000000202f4e02b51f9f89f1fab195e19148e57
    94e508de92a21d3fdb5b171877a44024bf02a085171bcf8e6bf704798b88161c
    a627e9d027a5ac2865cc4a0404ac1c0fc45e02b9ab938fea505dc8d1b61bfacc
    d5332c589877769039c6f5b10602195b9f90dc03024debc8dac8db5b33197d3d
    3828b963f1bd1d58d2987cd61f685b3fd9e3ef820384ddb7f290db8504819611
    b720725aa557e90a2aab55e587387c9d13b2f50eee034c0ebe46aa9d656f9a5e
    93d9442055a50fd37ab2740d57225258019603d94c0a02c58a6127b75421a586
    cc55c715a86500b9193a2fb790c4c18a19140091ecae67022d3313dbaeb918eb
    0ae6748a81b15a03729aebe5b073fca48b428e538679563548b001de14ba58e1
    9509bf0aefa58ccb9b39020b1b8a271bd10d454d81988c043cf6722e5de70014
    087a10f9b38add90ba019b03548dce10a72cff85ab21e59382a64587b03f6941
    83a01e2170f94ed111832ae488a11caf632df7cfbcb17a6440d5275716fd5e35
    aa83a9b600e15e9bec055e225a6a8c17e91d1b40a4f406c92aa3093403f727e8
    c3f802f59c71365a67b228e381c4e57a1030da09c815a35b33f859085aa0e792
    f48498a2eee20e49ff5edf5b9b943041c9c6d098f446f39aa0bda166f8a46a42
    3ceff7f8e31a7a5cddb007b8a3cb24413b16a3d9c2e6875a71855cb8bf8fcd5a
    48c0fadf22e85a84ffff0d5a6c9ebb7874c09e4996d79dd77a643f08d8fbd8eb
    d427b47be8baf4b6cb422a56838aec0d81e671d9b001e715e88ceace47411c5f
    0e52de97f8e9df4a19c23a127622d572e7e4bcf5758ad063fb7998ff60d6c1e1
    9bfcc3aafb51ec8874eb8b37fdf14ee5fa564a2d6b7e0c5f3a208888bb731cda
    01dcdecfa612cd997eec9362c45e371e9680467a67c988276c3e9c18aa6ff1a6
    f6412ede66ab687eb54836fbc9174d2384522cbcb5e1df86343fd53762eeadf8
    ceb8cba8f2c8d61b45dae74abe67f47e43c0bf60068b7919c51182dbb5d3abfd
    0465576597ed5c26dae97edc00e6497cf82fd8a5c19b1e168285a3345d1ff8b9
    ff6173171049b51cef0fd7dbc5df1c706f3b8bd237ba6a2526e7d66f03240c57
    669e5628871ba4db195cde6a7a0709956b916f35be611137c17a38f1359b7901
    0ec91cc167fec971410504897fca0654ec47796fbb8bdb0829086aa6dcbea84c
    8ea162140fb1bde384133db4a6d9f6f296cd26f9639728e37eb1cdaece28a166
    0db110dbc2cfa50f9a6d658e20ae358bde696d403bd1b2405b9edb89fec57042
    c5b8337403b4ca941ba2bc8a0dc1f4202a7c476afc8c11ee
spend3.refund.t = 2
spend3.refund.rand =
    951a4f39b3225c1929b35820269ac76d585baf0dbb927cd59f35addd001762b8
    ca25145e7c4159cb30f4cadac6b2f274a710f8916b01e7aa657125ac036e074c
    8dda6de23ecbfa7dba2bb3f490655c25fef2bfc2f3786596045b68563feeb24d
spend3.refund.message =
    02e6956a32ae6001a3494c29c233e0f7bae689202070064d0ac112820177b2e3
    f8aae51d4331b1568f1c254e635e9409a6a5c41b8e667f83b63531ea51e0652d
    e00000000000000002dfdc81080741a6a136bea1e6b2dd08f2f14538205d8d3a
    524af77e4f43b317cc599fd8d86ac41d3a04d3c8fc3bfbed53c196f3a9ef46db
    4ba968e925730a2a65
spend3.credential =
    be60dec14d630dcb30a104bf6bc798bc60cf5ca35911d94bab03a27694bc5607
    000000000000000af613b07592172ebf8c4e04a6d3b6651b9d17eb9bc333fb7c
    aa5da9087d7fad9002e6956a32ae6001a3494c29c233e0f7bae689202070064d
    0ac112820177b2e3f8aae51d4331b1568f1c254e635e9409a6a5c41b8e667f83
    b63531ea51e0652de0
~~~

## Spend 4: spend with top-up (`s = 3`, `a = 2`) {#act-tv-spend4}

~~~
spend4.s = 3
spend4.a = 2
spend4.ctx_spend =
    4143542d746573742d766563746f72732d6368616c6c656e67652d6469676573
    74
spend4.rand =
    a0197dc7f5d2128dceb0e4ac42a172d763b6d625df1d4bfcf61fd5fbfe7e222e
    35144cbb058151ff0eba61a90575de984665140d18c49d11df66f7b77bc618b9
    60599627a6606376365da00272f43dfe020306d04c39a7dd3c60a26a23830521
spend4.state =
    a869aa59e7dbd1168f9c4edda1fa4529d5043b9a19101223228b773a941f4c17
    2aed566e0458743e56bc78cfcbb597fb6548edb58bfd1df4d23bcc91e37e9059
    00000000000000070000000000000003000000000000000202b7e2b124c51e90
    d9859cbc2c0141f985b4b78dce5270de619bd72c064e89d671
spend4.message =
    be60dec14d630dcb30a104bf6bc798bc60cf5ca35911d94bab03a27694bc5607
    0000000000000003000000000000000203219e95d338ab57ed4c64f9b77a984f
    f22d3bcecb4527dae610ad8d51275d2f2302db780d64911e69336569f5148ce4
    60c09e8256dd3041ee634e1598b27df4de2802f1be336d8979887881554c386c
    7cc0951b7f38572d1febd542a1b0145fb374c003359a94092b8d9c5b05e0818a
    574f76c84bd9bf7d999d5d2a8e10a4fec59282460317b52c87074a03790419d6
    ee5f92f6187c7d20c00341f76f7f43bc7705c0d92502f93967ce41252702b13e
    2f53b8e13c5b90a4cb340ad22e0c43e5d4bf45cf82530316f790b968ec4a5444
    e2153fb03ddda25a1383ba4160543fd6454352137f1174035f6b382e4f8c1c6d
    36470ae5c51e5809a99889fa5e56f80317dbe18abb189a80023381e2c53663e8
    377643875a49b4e8850b007de25c9a398f67e1765d0aa1123e02f5099dca8b8c
    0470a2ed14997c6e717b87c74b42126231b74d8a43cda3253611039847a9942f
    983ed8986a7fd1c22c733db052ccb944f6243a2339f761a220aea2a1eecd4bba
    2c7a96a6a8c2c9de796a079057ab7c1a5b2694a604efbe48f7236bbb11eb2e4f
    4a83f66203dfc0c0227a697988e32be213823f9f9e720e48c5cfd457553ceacb
    71611f7a1d6e11579c36ec5fda7bd5e923ee0e59b3aa6597823ab77097619620
    daf1bfe2781040c6a5b8a2c2f27ab361588dc9c3bfc86247a8e071e682ea424a
    e2f9492b7774a7bb579b4d17f990e12f8823233ae7b21654c0156293849fa06a
    7b7b72bb1b6692ff1de900447123d71259884f6f3712beae11972c4ef6ba155f
    ba2e9efa2298fb6648b992c42b5e42cc2d47ac9f911399819f97133ea88a1ded
    a907a5f97c369519a616e9f336a3e71a3fa1dce6b9e43b5bf565e162e0183415
    68519e8c2d7bf6ceb8061c2a75fed702702bb58821b2ae7c9cf4ae60da2751cf
    f40ebbbc94380f9cd00f33086508fe8ba7f840f3591fb81b16dfefaad1daf093
    0b63f12db65d1b356935a54b4476336e904178ea5041a49d0deab0b9c24e671a
    3c84d7f43e0e3880208735e1b895eaf97d341253c1564ea212bc8be2476872ce
    1df5228bdd0c2dc066807620812c7d63200a20b936141296c8e9253663717ab4
    a3e51df2fd6147b487ae2c3796ec7305b7e4b9b0ac30d122eb429bde31610400
    e8228bad372f46a15465141d04a83f6bf111cac924b6bdd5e1dd0b5845ba5896
    b57020db13405fc6bf27de97ea65be1182b507c9ce94f4f26b849d261bef2b7e
    b0284dd5ffb9a2a737179b5a78c633111d3e1e55ba1d4f410a6dcce7b4576ac9
    faf7425bb9b46399978d8fa940b92cf6fcedb34bab2bb5c829aa4be203805da6
    ce7d4e8aca04591982ef71276ee0dcb82003e0296c3ece58ed3f135e204770ba
    226f01a05426f6d3339b7eb3f41c80178aa9dbf365ac27c6c2154fb26a003e54
    f8e64fa7508308593a325ba797f9103152d0562d9ae24c61d570fc9fed280f94
    b0762dc00e9013829023b58d48e7dbff636935a07cbae61b794f152dd2b96d80
    e258b97d49a9036b5eac8fc23514af5298c2c212a1c1db124f56685a70d6cd14
    f082f40a78e61971ecce5d68b4e3db1e527bae3c0465f507dc07727b7521ffef
    60d9eec3c7b39e09c0244f4ec495719aa2640e16ec4f33d0003fb51c46109fbd
    ba55c42d75184b5723e7bf9ea7c3f9772200b7710b7f7fb6bbfc2f98b481d97d
    c9a3b0986c9fa899a160c882e39008e57485bfa7c94463c7c10642391a25b5d0
    808d4001a03f4366b113d12547b8e701b04f5d4643f27af39b41a0f81d114b08
    a75f3f0b9ca677ad69ae73aed92cb8fdeb7ca53c55a3a638b77672e8952237e9
    19618a91313537462ebd8a813d32bcdb340c537b31f7b687f40910d2506b6202
    2adec98b6f20bc2868eaf1d8d2fe3255e56a8cc105a3b3cbd33cdde81bc00b07
    2012a0a9ec66507d91e4aa38ebbe132e1149602cdebfe257cc1f7c
spend4.refund.t = 5
spend4.refund.rand =
    752dc7ce9c6fb3e70d8c88a6bb1e1fa40b7956619b9571519feac0eae54c5cfa
    e117914953d8c1f88b0035512fa223b8a67174046422dffb4a899546001bc936
    82a8720ccd9fecd89f8e7b97f5ff29b951e586a5319626dd779b3fe45013dec5
spend4.refund.message =
    02e40b0e6dd647996a9bad5602291ad325fc3b8bfedec9cfdbeef8235c688847
    9d844369d43ef409a7a049c4fc4d76f5463a41c79550d31b4872efa2318a1530
    400000000000000005f166402a7854a65baeb2cda7c12003caec31088897a3eb
    efbb0f81dc8deecbb7d401f696b0d66f224bbb8855ff213463c7ae93c663c00d
    62076bd3adce0e8d2e
spend4.credential =
    a869aa59e7dbd1168f9c4edda1fa4529d5043b9a19101223228b773a941f4c17
    000000000000000c2aed566e0458743e56bc78cfcbb597fb6548edb58bfd1df4
    d23bcc91e37e905902e40b0e6dd647996a9bad5602291ad325fc3b8bfedec9cf
    dbeef8235c6888479d844369d43ef409a7a049c4fc4d76f5463a41c79550d31b
    4872efa2318a153040
~~~

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
