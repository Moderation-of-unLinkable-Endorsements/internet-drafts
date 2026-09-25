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
: A cryptographic hash function whose output length is `Nh` bytes.

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

   credential = FinalizeIssue(pkM, ctx_cred, state, response)

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
ciphersuite of {{ciphersuites}}; its protocol context is

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
source therefore neither repeats a nonce across distinct proofs nor
produces a zero nonce.

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
these proofs unchanged. A proof repeated with the same inputs and the same
`rand` is byte-identical, so a retried operation reproduces its proof.

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
    K_n: Element


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

    state = ClientSpendState(kstar, r_star, v1, K_n)
    proof = SpendMessage(
        k, s, a, A_prime, B_bar, K_n, Com1, Com_c, Com2, pok
    )

    return state, proof
~~~

`A_bar` is not sent: the Moderator computes it as `skM * A_prime`. The
values `kstar` and `r_star` are the nullifier and blinding factor of the
Credential the refund will produce; they open the commitment
`K_prime = K_n + V1`, with `V1` the balance commitment of
`BalanceCommitment` below, to `v1 * H1 + kstar * H2 + r_star * H3`; the
Moderator signs this in `IssueRefund`.

`ProveSpend` consumes the Credential: an implementation MUST NOT allow a
second call on the same Credential value. The Client MUST treat the
Credential as spent, and MUST have stored `state` durably, no later than
the moment `proof` becomes observable outside the Client; the refund is
unusable without the state, and a second proof from the same Credential
reveals the same nullifier ({{act-security}}).

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

The comparison `t <= s + a` is between integers; `s + a` may exceed `2^L`
and an implementation MUST compute it without overflow. This bound keeps
the new balance below `2^L` without a range proof over the refund
({{act-security}}). The Moderator places the new balance anywhere in
`[c - s, c + a]` without learning where in that interval it falls.

### Refund Finalization {#act-finalize-refund}

The Client checks the refund and assembles its new Credential.

~~~ python
def FinalizeRefund(
    pkM: Element,
    ctx_cred: bytes,
    state: ClientSpendState,
    proof: SpendMessage,
    refund: RefundMessage,
) -> Credential:
    kstar, r_star, v1, K_n_state = state
    k, s, a, A_prime, B_bar, K_n, Com1, Com_c, Com2, _ = proof
    A, e, t, pok = refund

    if K_n != K_n_state:
        raise VerifyError
    if not 0 <= t < 2**L or t > s + a or v1 + t >= 2**L:
        raise AmountError

    ctx = CreateContextScalar(ctx_cred)
    K_prime = BalanceCommitment(proof)

    X_A = B + K_prime + G.scalar(t) * H1 + ctx * H4
    X_G = G.ScalarMultGen(e) + pkM

    tag = Tag(b"Refund", [])
    if not Verify(tag, SignatureRelation(A, X_A, X_G), pok):
        raise VerifyError

    return Credential(kstar, v1 + t, r_star, A, e)
~~~

The state records `K_n` so that a refund is finalized only against the
spend it was issued for. `FinalizeRefund` consumes `state`: a Client MUST
NOT finalize one spend state against two refunds, since the two
Credentials would share the nullifier `kstar`. The Client MUST NOT spend
the consumed Credential again, whether or not the refund arrives. A
Client that has sent a spend proof and not received a valid refund keeps
`state` and MAY ask the Moderator for the refund again; {{PROTOCOLS}}
describes this.

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
SHA-256 for the hash function, with `Nh = 32`. The value of the ciphersuite
identifier is `b"P256-SHA256"`.

Use the P-256 group, SHA-256 hash, hash-to-curve and hash-to-scalar
algorithms, and canonical encodings of Section 7.1 of {{IHAT}}. ACT uses
`Ne = 33`, `Ns = 32`, and `Nseed = 48`. Instantiate every hash with the
ACT `ctx_proto` of {{act-config}}, including the explicit DST passed by
`G.DeriveScalar`; the group-element permutation used by IHAT is not needed.

## Randomness {#randomness}

Every random value in this document is a seed of `Nseed` bytes consumed by
`G.DeriveScalar` ({{derive-scalar}}) or, for the values listed below, by
`G.DeriveNonce` (Section 4.3 of {{IHAT}}); no scalar is sampled directly.
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

A repetition among the Client's drawn values harms only that Client; a
repetition of a signing exponent or of a prover nonce is a key-compromise
event ({{act-security}}), which is why those are derived.

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
  ({{Section 7.5 of SIGMA}}), up to the derived nonces ("Derived prover
  nonces" below). None of this relies on the hardness of discrete
  logarithms, so an observer with a quantum computer that records
  transcripts today gains nothing; such an attacker does recover `skM` from
  `pkM` and can forge Credentials, so credit conservation does not hold
  against it. The public amounts `s`, `a`, and `t`, and the configuration,
  determine which Credentials could have produced a presentation; `t` is
  the Moderator's choice, so {{PROTOCOLS}} constrains it as it constrains
  `s`, and {{ARCH}} states the anonymity-set requirements.

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
  combine two Credentials into arbitrarily many at the same balance. Both
  values are therefore derived with `G.DeriveNonce` (Section 4.4 of
  {{IHAT}}) from the key and the operation ({{act-signing-exponent}},
  {{act-prover-nonces}}), so that a rolled back or snapshotted random source
  reproduces an earlier response instead of yielding a second one. An
  implementation that draws either value directly MUST treat every
  repetition as a compromise of `skM`.

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
  to them ({{Section 7.6 of SIGMA}}). The
  bit equations involve no branching on bit values, unlike a disjunctive
  range proof.

Derived prover nonces:
: `ProveCompact` is zero-knowledge when its nonces are indistinguishable
  from uniform to a party without the witness
  ({{Section 8.4.2 of FIAT-SHAMIR}}). `ProverNonces` meets this with
  `G.DeriveNonce` (Section 4.3 of {{IHAT}}), each nonce from its own
  `Nseed` bytes of fresh randomness; if the random source fails, each nonce
  is still a pseudorandom function of the witness at a distinct point, which
  relies on the blinding scalars in the witness carrying entropy the
  verifier lacks.

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
