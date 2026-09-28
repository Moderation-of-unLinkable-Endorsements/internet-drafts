---
title: "Issuer-Hiding Anonymous Tokens (IHAT)"
abbrev: "IHAT"
category: info

docname: draft-authors-mole-ihat-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
keyword:
 - moderation
 - endorsement
 - unlinkability
 - privacy
venue:
#  group: "Anti-Fraud Community Group"
#  type: "Community Group"
#  mail: "public-antifraud@w3.org"
#  arch: "https://lists.w3.org/Archives/Public/public-antifraud/"
  github: "Moderation-of-unLinkable-Endorsements/internet-drafts"
  latest: "https://moderation-of-unlinkable-endorsements.github.io/internet-drafts/draft-authors-mole-ihat.html"

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
  ARCH: I-D.draft-jms-mole-architecture
  PROTOCOLS: I-D.draft-jms-mole-protocols
  HTTP-TRANSPORT: I-D.draft-jms-mole-http-transport
  HASH2CURVE: RFC9380
  I2OSP: RFC8017
  OPRF: RFC9497
  TLS13: RFC8446
  SIGMA: I-D.irtf-cfrg-sigma-protocols-02
  NISTCurves:
    title: "Digital Signature Standard (DSS)"
    target: https://doi.org/10.6028/NIST.FIPS.186-5
    date: 2023-02
    seriesinfo:
      "FIPS PUB": "186-5"
    author:
      -
        org: National Institute of Standards and Technology (NIST)
  SEC1:
    title: "SEC 1: Elliptic Curve Cryptography"
    target: https://www.secg.org/sec1-v2.pdf
    date: 2009
    author:
      -
        org: Standards for Efficient Cryptography Group (SECG)

informative:
  CDS94:
    title: "Proofs of Partial Knowledge and Simplified Design of Witness Hiding Protocols"
    target: https://doi.org/10.1007/3-540-48658-5_19
    date: 1994
    seriesinfo:
      "CRYPTO": "1994"
    author:
      -
        ins: R. Cramer
        name: Ronald Cramer
      -
        ins: I. Damgard
        name: Ivan Damgard
      -
        ins: B. Schoenmakers
        name: Berry Schoenmakers
  DS15:
    title: "Indifferentiability of 8-Round Feistel Networks"
    target: https://eprint.iacr.org/2015/1069
    date: 2015
    author:
      -
        ins: Y. Dai
        name: Yuanxi Dai
      -
        ins: J. Steinberger
        name: John Steinberger
  FFKLLS26:
    title: "Issuer-Hiding BBS-Based Anonymous Credentials without Policy Keys"
    target: https://eprint.iacr.org/2026/870
    date: 2026
    author:
      -
        ins: A. Flamini
        name: Andrea Flamini
      -
        ins: K. Friedrichs
        name: Karla Friedrichs
      -
        ins: J. Katz
        name: Jonathan Katz
      -
        ins: W. Ladd
        name: Watson Ladd
      -
        ins: A. Lehmann
        name: Anja Lehmann
      -
        ins: M. Sefranek
        name: Marek Sefranek
  STACKSIG:
    title: "Stacking Sigmas: A Framework to Compose Sigma-Protocols for Disjunctions"
    target: https://eprint.iacr.org/2021/422
    date: 2022
    seriesinfo:
      "EUROCRYPT": "2022"
    author:
      -
        ins: A. Goel
        name: Aarushi Goel
      -
        ins: M. Green
        name: Matthew Green
      -
        ins: M. Hall-Andersen
        name: Mathias Hall-Andersen
      -
        ins: G. Kaptchuk
        name: Gabriel Kaptchuk
  TESSZHU:
    title: "Short Pairing-Free Blind Signatures with Exponential Security"
    target: https://eprint.iacr.org/2022/047
    date: 2022
    seriesinfo:
      "EUROCRYPT": "2022"
    author:
      -
        ins: S. Tessaro
        name: Stefano Tessaro
      -
        ins: C. Zhu
        name: Chenzhi Zhu

...

--- abstract

This document specifies the cryptographic construction used to produce and
consume MoLE Endorsements. An Endorsement is an anonymous token that an Anchor
issues to a Client, and that the Client later redeems at a Moderator without
the Anchor being able to link the redemption to the issuance.

This document defines the endorsement issuance protocol, built from a
pairing-free partially blind signature scheme, together with the group,
encoding, and context-binding rules that both the Anchor and the Client follow.


--- middle

# Introduction

MoLE Endorsements have a number of constraints imposed by the architecture
{{ARCH}}. They must be unlinkable by the Anchor that issued them, they must be
publicly verifiable, and a redemption must hide which Anchor issued the
Endorsement among the set of Anchors a Moderator accepts. Existing systems do
not meet all of these needs. This document defines such a system, the
Issuer-Hiding Anonymous Token (IHAT), which is endorsement type `0x0002` in
{{PROTOCOLS}}.

The construction is a pairing-free partially blind signature {{TESSZHU}}. An
Anchor holds a signing key and issues, in three moves, a signature on a
Client-chosen message that the Anchor never sees. Each Endorsement is also bound
at issuance time to two contexts. These may be used to limit the validity scope
of each Endorsement, i.e., when and for whom it may later be used.

* The issuance context `ctx_iss` is agreed out of band among the Client, the
  Anchor, and the Moderator. `ctx_iss` can encode, for instance, the time
  period in which the Endorsement is issued, ensuring Endorsements expire.

* The redemption context `ctx_red` is agreed out of band between the Client
  and the Moderator. For example, it may be a long-term identity of the target
  Moderator. This may be used to prevent Endorsement reuse across Moderators
  without requiring a synchronized state between them.

> TODO Decide whether the validity window or the Moderator identity should be
> an explicit part of the syntax here. Currently we leave the issuance and
> redemption contexts as arbitrary strings chosen by the higher level protocol.
> Arguably we should deal with this security sensitive stuff here.

## Scope

This document is a work in progress. This revision specifies:

* the prime-order group interface and encodings ({{preliminaries}});
* the protocol context, scalar derivation, Anchor key generation, and context
  binding ({{scheme}});
* the endorsement issuance protocol, that is, the four algorithms `Commit`,
  `Challenge`, `Respond`, and `Finalize`, along with the wire messages they
  exchange, and the endorsement verification equation ({{issuance}});
* endorsement redemption, that is, key rerandomization, the issuer-hiding
  proof over a Moderator's Anchor Set, whose size is logarithmic in that of the
  Anchor Set, and the algorithms `Redeem` and `VerifyRedemption`
  ({{redemption}});
* one ciphersuite, over P-256, with test vectors ({{test-vectors}}).

The formal security statements and reductions are not yet written, and are
marked as such in {{security-considerations}}.

{{PROTOCOLS}} maps the cryptographic algorithms to the MoLE grant and
redemption APIs. It supplies the issuance and redemption contexts; this
document treats those contexts as opaque byte strings. Configuration
encodings and discovery remain open work in {{PROTOCOLS}}.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

The terms Client, Anchor, Moderator, Endorsement, Credential, and Anchor Set
are used as defined in {{ARCH}}.

Unless otherwise specified, this document encodes protocol messages in TLS
notation ({{Section 3 of TLS13}}). Moreover, all constants are in network byte
order. This document also uses the variable-size vector convention `<V>`
defined in {{HTTP-TRANSPORT}}: the length prefix of such a vector is a
variable-length integer in its minimum-size encoding, so its width depends on
the length of the contents it carries.

The following functions, types, and notation are used throughout this
document. The Python snippets are excerpts from the reference implementation.
They use `bytes` for byte strings, `int` for integers, and `Sequence` for a
read-only sequence.

For any byte string `x`, `len(x)` denotes its length in bytes.

For two byte strings `x` and `y`, `x + y` denotes their concatenation, and,
if they are of equal length, `_xor(x, y)` denotes their bytewise exclusive or.

For a byte string `x`, `x[i:j]` denotes the substring of `x` that begins at
its byte with index `i` and ends just before its byte with index `j`, where
indices start at zero. Its length is `j - i` bytes.

For a list `x`, `x[i]` denotes its element at index `i`, counting from zero,
`x[i:j]` denotes the sublist from index `i` up to but not including index `j`,
and `len(x)` denotes the number of elements it holds.

`I2OSP(value, length)` converts a nonnegative integer into a byte string of the
requested length in big-endian byte order, as described in {{I2OSP}}. We write
`U16Prefixed(value)` for the concatenation of `I2OSP(len(value), 2)` and
byte string `value`.

`random(n)` returns `n` uniformly random bytes. Implementations MUST generate
them with a cryptographically secure random number generator. It is the only
source of randomness in this document: every other value that has to be
unpredictable is derived from its output ({{derive-scalar}}).

`Seed(x, k)` denotes the `k`-th seed in a byte string of concatenated seeds,
that is `x[k * Nseed:(k + 1) * Nseed]`, with `k` counted from zero.
{{ciphersuites}} fixes the seed length `Nseed`.

~~~python
def Seed(value: bytes, index: int) -> bytes:
    return value[index * Nseed : (index + 1) * Nseed]
~~~

Byte strings such as `b"Challenge"` contain the corresponding ASCII bytes and
do not include a terminating NUL byte.

The definitions of the record types named in function signatures are implicit.
Parameters become constant values once the ciphersuite is fixed. An algorithm
that can fail raises an error; the errors used in this document are listed in
{{errors}}.

# Preliminaries {#preliminaries}

The construction has two dependencies:

Group:
: A prime-order group implementing the interface in {{group}}. {{ciphersuites}}
  gives concrete instances.

Hash:
: A cryptographic hash function whose output length is `Nh` bytes.

## Prime-Order Group {#group}

This document uses an additive, prime-order group, denoted `G`, of order `p`,
as described in {{Section 2.1 of OPRF}}. The types `Element` and `Scalar`
denote elements of the group and of its scalar field respectively. Group
elements are added with `+` and subtracted with `-`; scalar multiplication of
an `Element` `A` by a `Scalar` `r` is written `r * A`. Scalars are added,
subtracted, and multiplied modulo `p`. In the Python snippets, `G.scalar(x)`
converts an integer `x` in `[0, p)` to a `Scalar`.

The group also provides `G.DeriveScalars`, `G.SeedsToScalars`,
`G.DeriveNonces`, `G.DeriveKeyPair`, and `G.GenerateKeyPair`, defined in
{{derive-scalar}}, {{derive-nonce}}, and {{keygen}}.

The following member functions are used. Except where noted, they are as
defined in {{Section 2.1 of OPRF}}.

Order():
: Outputs the order `p` of the group.

Identity():
: Outputs the identity element of the group.

Generator():
: Outputs the generator element `B` of the group.

ScalarMultGen(r):
: Outputs `r * B`, where `B` is the group generator.

HashToGroup(x):
: Deterministically maps a byte string `x` to an `Element`. Parameterized by a
  domain separation tag (DST); see {{ciphersuites}}.

HashToScalar(x):
: Deterministically maps a byte string `x` to a `Scalar`. Parameterized by a
  DST; see {{ciphersuites}}.

ScalarInverse(s):
: Outputs the multiplicative inverse of the nonzero `Scalar` `s` modulo `p`.

SerializeElement(A):
: Maps an `Element` `A` other than the identity element to a canonical byte
  string of fixed length `Ne`. Raises a `ValueError` if `A` is the identity
  element, which has no such encoding.

DeserializeElement(buf):
: Attempts to map a byte string `buf` to an `Element`. Raises a
  `DeserializeError` if `buf` is not the canonical encoding of a group element,
  or if it encodes the identity element.

SerializeScalar(s):
: Maps a `Scalar` `s` to a canonical byte string of fixed length `Ns`.

DeserializeScalar(buf):
: Attempts to map a byte string `buf` to a `Scalar`. Raises a
  `DeserializeError` if `buf` does not encode a `Scalar` in the range
  `[0, p-1]`.

This document does not use the `RandomScalar()` member of
{{Section 2.1 of OPRF}}. Every scalar that has to be unpredictable is instead
obtained from `G.DeriveScalars` ({{derive-scalar}}), `G.DeriveNonces`
({{derive-nonce}}), or `G.DeriveKeyPair` ({{keygen}}), each deterministic in
its random input. This makes each algorithm reproducible from the randomness
it is given, which is what allows the test vectors of {{test-vectors}} to pin
the randomness of an otherwise randomized protocol.

## Errors {#errors}

The following errors are used.

DeserializeError:
: A byte string is not a canonical encoding of the expected type.

VerifyError:
: A received value failed a verification check.

SessionError:
: A message was received for a session that is not in the expected state.

DeriveError:
: A deterministic derivation failed to produce a usable scalar. See
  {{derive-scalar}}.

ValueError:
: An input has an invalid length or is outside its permitted range.

An implementation that raises an error MUST abort the protocol run. Errors are
fatal to the affected session; see {{sessions}}.

# The Endorsement Scheme {#scheme}

Issuance is a three-move protocol between a Client and an Anchor, followed by a
local finalization step at the Client. The Anchor moves first and holds
per-session state between its two moves.

~~~
   Client(pkA, ctx_iss, ctx_red)                Anchor(skA, ctx_iss)
 ---------------------------------------------------------------------
                               state, commitment = Commit(ctx_iss)

                             commitment
                              <--------

   state, challenge = Challenge(pkA, ctx_iss, ctx_red, commitment)

                              challenge
                              -------->

                          response = Respond(skA, state, challenge)

                              response
                              <--------

   endorsement = Finalize(pkA, state, response)
~~~
{: #fig-issuance title="Endorsement issuance overview"}

The Anchor speaks first. This document does not prescribe how the three
messages are carried, nor how a Client that wants an Endorsement reaches an
Anchor in the first place; both are the business of the transport, and a Client
will in general have to signal its intent by some means that carries no
protocol data. For example, over HTTP a Client might ask for issuance in a
request with an empty body, receive the commitment in the response, send the
challenge in a second request, and receive the response in the reply to that.
{{wire}} specifies the encoding of the three messages and their mapping onto
the exchanges of {{PROTOCOLS}}.

Neither context is carried in these messages. Both parties already hold the
issuance context, having agreed on it out of band; the redemption context is
known only to the Client.

The Client's output is an Endorsement that is publicly verifiable under the
Anchor's public key `pkA` ({{verify}}). The Anchor learns neither the nullifier
nor the redemption context bound into it, and cannot link the Endorsement to
the session that produced it.

## Configuration and Protocol Context {#config}

A ciphersuite ({{ciphersuites}}) is identified by an ASCII string
`identifier`. Both parties MUST agree on the ciphersuite before running the
protocol; {{PROTOCOLS}} describes how this agreement is reached.

The protocol context, written `ctx_proto`, is the domain separation tag that
this document derives from that identifier:

~~~python
def CreateProtocolContext(identifier: bytes) -> bytes:
    return b"IHATv1-" + identifier
~~~

Throughout the remainder of this document, `ctx_proto` denotes the output of
`CreateProtocolContext` for the ciphersuite in use. It is distinct from the
issuance and redemption contexts of {{context-binding}}: those are inputs to
the protocol, chosen by its participants, whereas `ctx_proto` is fixed by the
ciphersuite.

Every hash this document computes is domain-separated by `ctx_proto`,
which it carries in its DST rather than in its input: `HashToGroup` and
`HashToScalar` are so parameterized ({{ciphersuites}}), and so are
`G.DeriveScalars` ({{derive-scalar}}) and `G.DeriveNonces`
({{derive-nonce}}). Every algorithm below therefore
depends on `ctx_proto`, including those in which it does not appear
explicitly, and a value produced under one ciphersuite does not verify
under another. The Python group instance `G` stores this context as
`G.ctx_proto`. The group methods below use `self` for that instance, so
the context is fixed when `G` is constructed.

## Deriving Scalars {#derive-scalar}

The group method `G.DeriveScalars` derives values in the scalar field of `G`.
An algorithm that needs random scalars draws `Nseed` bytes of randomness for
each of them and derives them all with one call, under an `info` string that
names the algorithm:

~~~python
def DeriveScalars(self, rand: bytes, info: bytes) -> list[Scalar]:
    key = expand_message_xmd(
        U16Prefixed(info), b"DeriveScalars-" + self.ctx_proto, Nh
    )
    return self.SeedsToScalars(key, rand)
~~~

The group method `G.SeedsToScalars` permutes its input with a four-round
Feistel network whose round functions are keyed by `key`, splits the result
into seeds of `Nseed` bytes, and reduces each modulo `p`:

~~~python
def SeedsToScalars(self, key: bytes, rand: bytes) -> list[Scalar]:
    if len(rand) == 0 or len(rand) % Nseed != 0:
        raise ValueError(
            f"rand must be a positive multiple of {Nseed} bytes"
        )
    half = len(rand) // 2
    left, right = rand[:half], rand[half:]
    for i in range(4):
        mask = b""
        for j in range((half + Nseed - 1) // Nseed):
            mask += expand_message_xmd(
                key + I2OSP(i, 1) + I2OSP(j, 4) + right,
                b"SeedsToScalars-" + self.ctx_proto,
                Nseed,
            )
        left, right = right, _xor(left, mask[:half])
    permuted = left + right
    scalars = []
    for k in range(len(rand) // Nseed):
        s = self.scalar(
            int.from_bytes(Seed(permuted, k), "big") % self.Order()
        )
        if s.isZero():
            raise DeriveError
        scalars.append(s)
    return scalars
~~~

`expand_message_xmd` is that of {{Section 5.3.1 of HASH2CURVE}}, over the
hash function of the ciphersuite. The Feistel network is a permutation of its
input for every key, so it maps uniformly random input to uniformly random
output. The reduction is the one `hash_to_field` applies to uniform bytes
({{Section 5.2 of HASH2CURVE}}), and since `Nseed` exceeds `Ns` by 16 bytes
({{ciphersuites}}), the scalars derived from uniformly random input are each
within about `2^-128` of uniform over the nonzero scalars, and jointly within
the sum of those distances. With the round functions modeled as random
oracles, a change to any part of the input changes every derived scalar,
except with negligible probability. A derived scalar is zero, and
`DeriveError` raised, with probability about `1/p`. This probability is
negligible, and implementations might choose to panic rather than handle the
exception.

`rand` MUST be output of `random`, `Nseed` bytes for each scalar derived from
it, and MUST NOT be used for more than one derivation. Deriving several
scalars from fewer bytes would cap their joint entropy at the length of the
input, which the unlinkability argument of {{security-considerations}} does
not permit. See {{randomness}}.

## Deriving Nonces {#derive-nonce}

The nonces of a proof of knowledge, and the other secret values of its first
move, must not be reused under a different challenge. The group method
`G.DeriveNonces` derives them together, keying the permutation of
`G.SeedsToScalars` by a secret the party holds and a public description of
the operation:

~~~python
def DeriveNonces(
    self, secret: bytes, label: bytes, instance: bytes, rand: bytes
) -> list[Scalar]:
    derive_nonce_input = (
        U16Prefixed(label)
        + I2OSP(len(secret), 4)
        + secret
        + I2OSP(len(instance), 4)
        + instance
    )
    key = expand_message_xmd(
        derive_nonce_input, b"DeriveNonces-" + self.ctx_proto, Nh
    )
    return self.SeedsToScalars(key, rand)
~~~

When `rand` is uniformly random, the nonces are distributed as derived
scalars ({{derive-scalar}}), whatever the key. The key is a pseudorandom
function of `secret` at a point that identifies the operation, and with it the
Feistel network is a pseudorandom permutation of `rand`. Every nonce therefore
changes, unpredictably to a party that does not know `secret`, whenever any
part of `rand`, `secret`, or `instance` changes. A random source that repeats
part of `rand`, returns a constant, or returns values related to earlier ones
never causes a nonce to be reused under a different challenge; one that
repeats all of `rand` for the same operation reproduces the same nonces, and
so the same proof. Every `instance` in this document is an unambiguous
encoding, with its variable-length parts length-prefixed. Implementations
MUST wipe `secret`, `derive_nonce_input`, `key`, the intermediate values of
`G.SeedsToScalars`, and the returned values once they have been used.

## Key Generation {#keygen}

An Anchor holds a key pair `(skA, pkA)`. It is derived from a seed, which is
what allows the test vectors in {{test-vectors}} to fix a key. The procedure is
the key generation of {{Section 3.2 of OPRF}}. Note that, by design, knowledge
of both `seed` and `info` is required, so the secrecy of `skA` rests on the
secrecy of `seed`. On the other hand, the `info` string is usually public.

~~~python
def DeriveKeyPair(
    self, seed: bytes, info: bytes
) -> tuple[Scalar, Element]:
    if len(seed) != Nseed:
        raise ValueError(f"seed must be exactly {Nseed} bytes")
    derive_input = seed + U16Prefixed(info)
    for counter in range(256):
        skA = self.HashToScalar(
            derive_input + I2OSP(counter, 1),
            DST=b"DeriveKeyPair-" + self.ctx_proto,
        )
        if not skA.isZero():
            return (skA, self.ScalarMultGen(skA))
    raise DeriveError
~~~

The derivation differs from that of {{Section 3.2 of OPRF}} only in its domain
separation tag, which comes from the protocol context of this document rather
than from an OPRF context string, and in the length of the seed. The loop
terminates after one iteration except with probability about `1/p`.

A fresh key pair is generated by deriving one from a random seed.

~~~python
def GenerateKeyPair(self) -> tuple[Scalar, Element]:
    seed = random(Nseed)
    return self.DeriveKeyPair(seed, b"GenerateKeyPair")
~~~

The Anchor publishes `SerializeElement(pkA)` in its configuration; see
{{PROTOCOLS}}.

## Context Binding {#context-binding}

Each Endorsement is bound at issuance to two contexts, the issuance context and
the redemption context, and a redemption succeeds only if the Client and the
Moderator agree on both values. Both are opaque byte strings. `ctx_iss` is at
most `2^16 - 1` bytes. Because the encoded message is itself passed to
`U16Prefixed`, `ctx_red` is at most `2^16 - 1 - Nn - 4` bytes. These bounds are
enforced by `U16Prefixed`. The two contexts are bound by deliberately different
means, reflecting who is trusted to choose each.

{{PROTOCOLS}} specifies how MoLE obtains these contexts from configuration.
The examples below illustrate their cryptographic roles and do not define
alternative context encodings.

The issuance context, written `ctx_iss`, restricts when, and potentially where,
an Endorsement may be redeemed; it might for example name the epoch the
Endorsement was issued in. Both parties hold it. It is bound by deriving the
second commitment base from it:

~~~python
def CreateContextBase(ctx_iss: bytes) -> Element:
    context_base_input = U16Prefixed(ctx_iss) + b"ContextBase"
    return G.HashToGroup(context_base_input)
~~~

The Anchor forms its commitment under this base, and the base is recomputed at
verification time. The Client and the Anchor MUST agree on the issuance context.
Disagreement causes issuance to fail: a Client that uses any other value fails
the commitment-opening check in `Finalize`. The binding is therefore enforced by
the construction rather than by an explicit check, and a Client cannot bind an
Endorsement to an issuance context of its own choosing.

The redemption context, written `ctx_red`, restricts where an Endorsement
may be redeemed: a redemption succeeds only under the value the Endorsement was
issued under. It might for example identify the Moderator the Client intends to
redeem at, in which case the Endorsement is redeemable at that Moderator and at
no other. It is chosen by the Client and is hidden from the Anchor. It is bound
by placing it, together with a fresh Client-chosen nullifier `nf` of `Nn = 32`
bytes, in the signed message:

~~~python
def Message(nf: bytes, ctx_red: bytes) -> bytes:
    if len(nf) != Nn:
        raise ValueError(f"nullifier must be exactly {Nn} bytes")
    return U16Prefixed(nf) + U16Prefixed(ctx_red)
~~~

A redemption under a different redemption context recomputes a different
message, for which the Client holds no valid signature. Two consequences
follow. A Client has to fix `ctx_red` before it runs `Challenge`, that is,
before the Endorsement exists; and an Endorsement cannot afterwards be re-bound
to another value, so a Client that needs to redeem under several redemption
contexts needs a separate Endorsement, and so a separate issuance, for each.
Anchors bound how many Endorsements they grant a given Client in order to keep
Endorsements scarce ({{ARCH}}), so that budget is consumed per redemption
context rather than per Client.

The nullifier `nf` MUST be a fresh string of `Nn` uniformly random bytes,
generated by the Client, and MUST NOT be reused across Endorsements. It is
revealed during redemption, so the Moderator ensures each Endorsement is
redeemed at most once.

The values the two contexts take determine the anonymity set a Client redeems
in, and a deployment can destroy the unlinkability the construction provides
without breaking any of its cryptographic properties; see
{{security-considerations}}.

# Endorsement Issuance {#issuance}

Issuance produces a signature on the message `Message(nf, ctx_red)` relative to
the public input `ctx_iss`. It consists of four algorithms, run in the order

~~~
  Commit -> Challenge -> Respond -> Finalize
~~~

`Commit` and `Respond` are run by the Anchor; `Challenge` and `Finalize` are
run by the Client. Both parties input the issuance context `ctx_iss`; only the
Client inputs the redemption context `ctx_red`.

Each of the first three algorithms outputs one protocol message, and the next
algorithm takes that message as a single input. The messages are the
commitment, the pair `(A, C)`; the challenge, a single scalar; and the
response, the triple `(s, y, t)`. The types `Commitment` and `Response` denote
the first and the last of these. The wire format of each message is defined in
{{wire}}. All four algorithms treat `G`, `ctx_proto`, `Nn`, and `Nseed` as
global variables.

## Anchor Commitment {#commit}

The Anchor opens a session by committing to the values it will later reveal.

~~~python
def Commit(ctx_iss: bytes) -> tuple[AnchorState, Commitment]:
    Z = CreateContextBase(ctx_iss)

    rand = random(3 * Nseed)
    (a, t, y) = G.DeriveScalars(rand, b"Commit")

    A = G.ScalarMultGen(a)
    C = G.ScalarMultGen(t) + y * Z

    return (AnchorState(a, y, t), Commitment(A, C))
~~~

The Anchor stores `state` for the duration of the session and sends `commitment`
to the Client in a `CommitMessage` ({{wire}}). The signing key is not needed
until `Respond`.

`Commit` draws all of its randomness in one call and derives its three
scalars from it together ({{derive-scalar}}). A test vector fixes the single
value `rand`; `y` is nonzero by construction.

## Client Challenge {#challenge}

The Client blinds the Anchor's commitment, derives the challenge over the
blinded values, and returns the challenge in blinded form.

~~~python
def Challenge(
    pkA: Element,
    ctx_iss: bytes,
    ctx_red: bytes,
    commitment: Commitment,
) -> tuple[ClientState, Scalar]:
    if pkA.isIdentity():
        raise VerifyError

    (A, C) = commitment

    rand = random(Nn + 4 * Nseed)
    nf = rand[:Nn]
    (r1, r2, gamma1, gamma2) = G.DeriveScalars(rand[Nn:], b"Challenge")

    m = Message(nf, ctx_red)
    gamma = gamma1 * G.ScalarInverse(gamma2)

    blinded_A = G.ScalarMultGen(r1) + gamma * A
    blinded_C = gamma1 * C + G.ScalarMultGen(r2)
    blinded_commitment = Commitment(blinded_A, blinded_C)

    c = ComputeChallenge(ctx_iss, blinded_commitment, m)
    if c.isZero():
        raise VerifyError

    challenge = c * gamma2
    state = ClientState(
        nf,
        ctx_iss,
        commitment,
        r1,
        r2,
        gamma1,
        gamma2,
        challenge,
        c,
    )
    return (state, challenge)
~~~

As in `Commit`, all randomness is drawn in one call: the first `Nn` bytes are
the nullifier, and the remaining `4 * Nseed` bytes derive the four blinding
scalars. `ComputeChallenge` is as follows:

~~~python
def ComputeChallenge(ctx_iss: bytes, commitment: Commitment, m: bytes) -> Scalar:
    (A, C) = commitment

    Am = G.SerializeElement(A)
    Cm = G.SerializeElement(C)

    challenge_transcript = (
        U16Prefixed(ctx_iss)
        + U16Prefixed(Am)
        + U16Prefixed(Cm)
        + U16Prefixed(m)
        + b"Challenge"
    )

    c = G.HashToScalar(challenge_transcript)

    return c
~~~

Two challenge values appear here: `c` is computed over the blinded commitment
and is the value that ends up in the Endorsement ({{finalize}}); it never
leaves the Client. The `challenge` message the Anchor receives is its blinded
form `c * gamma2`, and the Anchor cannot recover `c` from it because `gamma2`
is uniform and secret.

`HashToScalar` can return zero, whereas the construction requires a nonzero
challenge. `Challenge` therefore aborts in that case rather than resampling, so
that the challenge remains a deterministic function of the transcript. The
abort occurs with probability approximately `1/p`, which again is negligible
and can safely be ignored. That is, implementations might choose to panic
rather than handle this exception explicitly. See {{security-considerations}}
for details.

The Client sends `challenge` to the Anchor encoded as a `ChallengeMessage`
({{wire}}) and retains `state` for the next step.

## Anchor Response {#respond}

The Anchor answers the challenge and closes the session.

~~~python
def Respond(skA: Scalar, state: AnchorState, challenge: Scalar) -> Response:
    (a, y, t) = state

    if challenge.isZero():
        raise VerifyError

    s = a + challenge * y * skA
    response = Response(s, y, t)

    return response
~~~

The resulting `Response` is encoded as a `ResponseMessage` ({{wire}}) and sent
to the Client.

An Anchor MUST call `Respond` at most once per session state produced by
`Commit`, and MUST destroy that state immediately afterwards. Answering two
distinct challenges on the same state discloses the signing key: from
`s1 = a + c1 * y * skA` and `s2 = a + c2 * y * skA` with `c1 != c2`, and `y`
revealed in the response, an attacker recovers
`skA = (s1 - s2) * ScalarInverse((c1 - c2) * y)`. An Anchor that receives a
second `ChallengeMessage` for a session it has already answered MUST raise a
`SessionError` and MUST NOT compute a response.

## Client Finalization {#finalize}

The Client checks the Anchor's response and unblinds it into an Endorsement.

~~~python
def Finalize(pkA: Element, state: ClientState, response: Response) -> Endorsement:
    if pkA.isIdentity():
        raise VerifyError

    (nf, ctx_iss, (A, C), r1, r2, gamma1, gamma2, challenge, c) = state
    (s, y, t) = response

    Z = CreateContextBase(ctx_iss)

    if y.isZero():
        raise VerifyError
    if C != G.ScalarMultGen(t) + y * Z:
        raise VerifyError
    if G.ScalarMultGen(s) != A + (challenge * y) * pkA:
        raise VerifyError

    gamma = gamma1 * G.ScalarInverse(gamma2)

    s_final = gamma * s + r1
    y_final = gamma1 * y
    t_final = gamma1 * t + r2

    return Endorsement(c, s_final, y_final, t_final, nf)
~~~

The three checks verify that the Anchor opened its commitment honestly and
answered the challenge under its published key. A Client whose `Finalize`
raises an error MUST discard the session state and MUST NOT retry the exchange
with the same state.

An Endorsement consists of the signature `(c, s, y, t)` together with the
nullifier; its encoding is given in {{endorsement-encoding}}.

## Endorsement Verification {#verify}

An Endorsement is publicly verifiable under the issuing Anchor's public key.

The two contexts are inputs to `Verify` in addition to the Endorsement. A
verifier therefore states the pair it is willing to accept and learns whether
the Endorsement was issued under it.

~~~python
def Verify(
    pkA: Element,
    endorsement: Endorsement,
    ctx_iss: bytes,
    ctx_red: bytes,
) -> bool:
    if pkA.isIdentity():
        return False

    (c, s, y, t, nf) = endorsement

    if len(nf) != Nn or c.isZero() or y.isZero():
        return False

    Z = CreateContextBase(ctx_iss)
    m = Message(nf, ctx_red)

    C = G.ScalarMultGen(t) + y * Z
    A = G.ScalarMultGen(s) - (c * y) * pkA
    if A.isIdentity() or C.isIdentity():
        return False
    commitment = Commitment(A, C)

    return c == ComputeChallenge(ctx_iss, commitment, m)
~~~

A Moderator never runs `Verify` under an Anchor's public key: a redemption does
not reveal which Anchor issued the Endorsement, so the Moderator runs it under a
rerandomized key and checks an issuer-hiding proof alongside ({{redemption}}).
The Client MUST NOT reveal the Anchor's public key to the Moderator.

`Verify` rejects a reconstructed `A` or `C` equal to the identity element, which
`SerializeElement` cannot encode. Under an Anchor's key this happens with
negligible probability, but the rerandomized key is the Client's choice, and a
Client that knows its discrete logarithm `x` reaches the identity by setting
`s = c * y * x`.

An honestly produced Endorsement always verifies. Writing `gamma` for
`gamma1 * ScalarInverse(gamma2)`, and `A_anchor` and `C_anchor` for the two
elements of the Anchor's commitment, the commitment reconstructed by `Verify` is
exactly the blinded commitment the Client hashed in `Challenge`:

~~~
  C = t_final * B + y_final * Z
    = gamma1 * (t * B + y * Z) + r2 * B
    = gamma1 * C_anchor + r2 * B
    = blinded_C

  A = s_final * B - (c * y_final) * pkA
    = (gamma * s + r1) * B - (c * gamma1 * y) * pkA
    = r1 * B + gamma * A_anchor
    = blinded_A
~~~

where the last step uses `s = a + challenge * y * skA` and
`challenge = c * gamma2`, so that the two terms in `skA` cancel.

## Encodings {#wire}

This section gives the encoding of the three messages exchanged during
issuance, of the session identifier that correlates them, and of the
Endorsement they produce.

`Element` and `Scalar` are the fixed-length encodings produced by
`SerializeElement` and `SerializeScalar`, of `Ne` and `Ns` bytes respectively.
A recipient MUST deserialize every received `Element` and `Scalar`, and MUST
abort the session with a `DeserializeError` if deserialization fails. In
particular, deserializing an `Element` rejects the group identity element.
Deserialization of a structure also fails if its input is truncated, if bytes
remain after it, or if a vector's length is not a multiple of the size of its
elements.

### Issuance Messages {#issuance-messages}

The three messages exchanged during issuance are carried in the
`EndorsementRequest` and `EndorsementResponse` bodies defined in {{PROTOCOLS}},
whose transport is HTTP. The first request is empty, and the corresponding
response contains the `CommitMessage`; the second request contains the
`ChallengeMessage`, and the corresponding response contains the
`ResponseMessage`.

The messages include a session identifier that allows the Anchor to correlate
the Client's challenge with the state corresponding to the Anchor's commitment.
The Anchor opens the session with its commitment:

~~~ tls-presentation
struct {
  opaque session_id<V>;
  Element A;
  Element C;
} CommitMessage;
~~~

The Client replies with the blinded challenge, echoing the session identifier:

~~~ tls-presentation
struct {
  opaque session_id<V>;
  Scalar challenge;
} ChallengeMessage;
~~~

The Anchor replies with its response, which closes the session:

~~~ tls-presentation
struct {
  Scalar s;
  Scalar y;
  Scalar t;
} ResponseMessage;
~~~

An Anchor MUST NOT have two open sessions with the same `session_id`, and SHOULD
generate it with a cryptographically secure random number generator so that a
Client cannot guess, and so collide with, another Client's session. An Anchor
that receives a `ChallengeMessage` whose `session_id` does not correspond to one
of its open sessions MUST raise a `SessionError`.

### Endorsement {#endorsement-encoding}

The output of `Finalize` is encoded as follows.

~~~ tls-presentation
struct {
  Scalar c;
  Scalar s;
  Scalar y;
  Scalar t;
  opaque nf[Nn];
} Endorsement;
~~~

This structure is never sent to an Anchor. The Client holds it until it is
redeemed, and {{redemption}} defines what is sent to a Moderator then. The
issuance and redemption contexts are not carried in it: they are inputs to
`Verify` ({{verify}}) and to redemption, held by the verifier.

## Session Handling {#sessions}

An Anchor is stateful: it holds the secret state produced by `Commit` from the
moment it sends `CommitMessage` until it answers or discards the session. That
state is single-use; see {{respond}} and {{security-considerations}}.

An Anchor SHOULD bound both the number of concurrent open sessions per Client
and the lifetime of an open session, and SHOULD discard state for sessions that
are not completed within that lifetime. Discarding state early is always safe:
it causes the Client's `Finalize` to be unreachable, but cannot produce an
invalid Endorsement.

# Endorsement Redemption {#redemption}

A Client redeems an Endorsement at a Moderator.

An Endorsement is single-use ({{context-binding}}), so redemption does not have
to hide the signature: the Client reveals it, and the Moderator deduplicates on
the nullifier. What redemption must hide is which Anchor issued it. The
signature of {{issuance}} verifies under one Anchor's public key, so presenting
it against that key would name the Anchor. Instead the Client rerandomizes the
key ({{rerandomization}}) and proves in zero knowledge that the rerandomized key
belongs to some Anchor in the Moderator's Anchor Set ({{issuer-proof}}).

Redemption is one message from the Client, answering a challenge from the
Moderator. The Moderator holds the ordered Anchor Set and carries it in that
challenge; the Client learns it there and locates its own Anchor in it. Both
parties input the two contexts.

~~~
   Client(endorsement,                   Moderator(anchor_set,
          ctx_iss, ctx_red)                        ctx_iss, ctx_red)
 ---------------------------------------------------------------------
                    challenge (carries anchor_set)
                              <--------

   redemption = Redeem(anchor_set, index, endorsement,
                       ctx_iss, ctx_red, challenge_digest)

                             redemption
                              -------->

                    nf = VerifyRedemption(anchor_set, redemption,
                                          ctx_iss, ctx_red,
                                          challenge_digest)
~~~
{: #fig-redemption title="Endorsement redemption overview"}

`anchor_set` is the list of Anchor public keys the Moderator accepts. Both
parties MUST use the same list in the same order. A proof computed over a
different list or order will not verify.

`challenge_digest` binds the redemption to the challenge that triggered it. It
is computed from the Moderator's challenge as specified in {{PROTOCOLS}}, and
this document treats it as an opaque byte string. Note that this challenge is
the Moderator's, and has nothing to do with the issuance challenge of
{{challenge}}.

`index` is the position in `anchor_set` of the public key of the Anchor that
issued the Endorsement. A Client whose Anchor does not appear in `anchor_set`
cannot redeem at this Moderator and MUST NOT try: the Endorsement will not
verify under any key it can prove membership for.

## Key Rerandomization {#rerandomization}

The Client shifts the Anchor's public key by a secret scalar `delta` of its own
choosing and adapts the signature to the shifted key. Writing `pkA` for
`anchor_set[index]` and `(c, s, y, t, nf)` for the Endorsement:

~~~
  X_hat = pkA + delta * B
  s_hat = s + (c * y) * delta
~~~

Here `B` denotes the group's base point, i.e., `B = G.Generator()`.

The result is an Endorsement `(c, s_hat, y, t, nf)` that verifies under `X_hat`
exactly as the original verifies under `pkA`, because the shift cancels in the
reconstruction of `A`:

~~~
  s_hat * B - (c * y) * X_hat
    = (s + c * y * delta) * B - (c * y) * (pkA + delta * B)
    = s * B - (c * y) * pkA
~~~

Every other value `Verify` recomputes is untouched, so a Moderator can check
the signature by running `Verify` ({{verify}}) with `X_hat` in place of `pkA`.

Because this shift is additive, issuance is left unmodified and the
unforgeability of {{issuance}} carries over to the modified Endorsement
({{security-considerations}}). But `X_hat` by itself provides no evidence that
it was derived from an Anchor key. The Client therefore also proves knowledge
of `delta` relating `X_hat` to a key in `anchor_set`, without revealing which
key.

## The Issuer-Hiding Proof {#issuer-proof}

The Client proves knowledge of `delta` such that
`X_hat - anchor_set[i] = delta * B` for at least one `i`, without revealing
`i`. This is a one-out-of-`n` disjunction of knowledge of a discrete logarithm.
All of them over the same base `B = G.Generator()`.

Such a disjunction is classically composed with the technique of Cramer,
Damgard and Schoenmakers {{CDS94}}, in which the Client answers the branch it
can and simulates the others, sending one challenge and one response per
branch. That proof is linear in `n`, and the Anchor Set is also the anonymity
set ({{security-considerations}}). This document instead composes the branches
with the *stacking* technique of Goel, Green, Hall-Andersen and Kaptchuk
{{STACKSIG}}, whose proof is logarithmic in `n`: the Client sends a single
response, which every branch reuses, together with a commitment whose opening
forces one branch to have been answered honestly. {{FFKLLS26}} applies the same
two compositions, for the same purpose, to a pairing-based credential.

Both compositions are used with the same rerandomization ({{rerandomization}}),
and switching between them changes neither issuance nor {{verify}}.

The construction below first defines the branch proof, then builds a partially
binding tree commitment over its branches. It finally specifies the
Fiat-Shamir challenge and the proving and verification algorithms.

Each branch is the discrete logarithm proof of {{SIGMA}}, and the composition
below could be expressed in that framework. It is written out here instead, so
that this document fixes the transcript and the encodings without depending on
work in progress.

> **TODO:** Revisit once {{SIGMA}} is stable.

Throughout this section and its subsections, `x / y` denotes integer division
of nonnegative integers, that is the quotient rounded down, and `x mod y` the
remainder.

### The Branch Proof {#branch}

The disjunction is proved over the statements

~~~
  Y[i] = X_hat - anchor_set[i]   for i in range(n)
~~~

of which the Client can answer branch `index`, where `Y[index] = delta * B`.

A single branch is proved by the usual three moves: the Client draws a nonce
`r` and commits `T = r * B`; the verifier sends a challenge `c`; the Client
answers `z = r - c * delta`; and the verifier checks that
`T = c * Y[index] + z * B`.

Read the other way round, that check determines the commitment from the
challenge and the response:

~~~python
def BranchCommitment(
    proof_challenge: Scalar,
    response: Scalar,
    Y: Element,
) -> Element:
    return proof_challenge * Y + G.ScalarMultGen(response)


def Statements(
    anchor_set: Sequence[Element],
    X_hat: Element,
) -> list[Element]:
    return [X_hat - pkA for pkA in anchor_set]
~~~

Two properties of this branch proof are what allow the composition below, and
{{STACKSIG}} calls a Sigma protocol with both of them *stackable*. First, a
verifying commitment can be computed for *any* statement from a challenge and a
response, by the function above, without knowing a witness; this is the
extended honest-verifier zero-knowledge property. Second, the response is
a fixed shift of the derived nonce `r`, and so is statistically close to
uniform independently of the statement and witness; see
{{security-considerations}}. One response can therefore be reused across
branches without revealing which branch produced it.

It follows that a verifier given `proof_challenge` and one `response` can
compute a commitment for every branch, and that every branch then verifies by
construction. Nothing is proved by the responses themselves. What has to be
enforced is that the Client fixed the commitment of one branch before the
challenge existed, and could not afterwards change it.

### Partially Binding Commitments {#pbvc}

A *partially binding vector commitment* {{STACKSIG}} commits to a vector of
values such that one position, chosen when the commitment key is generated and
hidden from the verifier, is binding, while every other position can afterwards
be opened to any value. The Client commits the branch commitment of `index` at
the binding position, and after the challenge is known it opens every other
position to the branch commitment that the shared response determines. The
branch at the binding position uses the actual witness and a commitment fixed
before the challenge; the index of the branch remains hidden by the commitment
key.

This document uses the commitment of the appendix of {{STACKSIG}} over pairs,
and then assembles them into a tree. The inputs to the commitments are arbitrary
strings of bytes, and the outputs are compressed group elements.

The commitment to a pair uses a permutation `P` on group elements, with
inverse `Pinv` ({{permutation}}). Its key is a point `Q`, and an opening is a
single scalar, the randomness used in the commitment. The two values are
hashed to scalars and committed under the bases `Q` and `P(Q)`:

~~~python
def CommitStep(
    Q: Element,
    left: bytes,
    right: bytes,
    randomness: Scalar,
) -> bytes:
    C = (
        randomness * B
        + G.HashToScalar(left) * Q
        + G.HashToScalar(right) * G.P(Q)
    )
    return G.SerializeElement(C)
~~~

The committer knows the discrete logarithm of one base, and that is the
position it can later open to another value. A key that binds the `left`
position is one whose `P(Q)` has the known logarithm, and vice versa:

~~~python
def GenerateStep(bind_left: bool, secret: Scalar) -> Element:
    T = secret * B
    (Q, _) = G.PermutationPair(T, bind_left)
    return Q
~~~

`bind_left` is a secret boolean: true binds the left position and false
binds the right. `G.PermutationPair` ({{permutation-pair}}) returns `(Q, P(Q))`,
with `T = P(Q)` when binding left and `T = Q` when binding right. It walks
the same permutation edge in either case, hiding which endpoint has the
known logarithm. Its second output can be cached for use in `CommitStep`.

The `secret` is the trapdoor: replacing the equivocal value shifts the
randomness by the difference of the hashes times the trapdoor, and the
commitment is unchanged:

~~~python
def EquivocateStep(
    oldb: bytes, newb: bytes, randomness: Scalar, secret: Scalar
) -> Scalar:
    old = G.HashToScalar(oldb)
    new = G.HashToScalar(newb)
    return randomness + (old - new) * secret
~~~

A vector `V[0], ..., V[n-1]` of byte strings is committed by pairing
neighbours level by level. Each level has its own key and its own
randomness; a vector of odd length carries its last element up unchanged.

~~~python
def VecCommit(
    V: Sequence[bytes],
    Qi: Sequence[Element],
    rands: Sequence[Scalar],
) -> bytes:
    if len(V) == 1:
        return V[0]

    V_prime = []
    for i in range(len(V) // 2):
        V_prime.append(CommitStep(Qi[0], V[2 * i], V[2 * i + 1], rands[0]))

    if len(V) % 2 == 1:
        V_prime.append(V[-1])

    return VecCommit(V_prime, Qi[1:], rands[1:])
~~~

A vector of `n` values has `Depth(n)` levels, each with one key and one
opening:

~~~python
def Depth(n: int) -> int:
    q = 0
    while 2**q < n:
        q += 1
    return q
~~~

Bit `j` of `index` is the side of its pair that the binding value is on
at level `j`, which fixes the direction of that level's key; each key has
its own trapdoor:

~~~python
def GenerateVecBind(
    index: int, trapdoors: Sequence[Scalar]
) -> list[Element]:
    commitment_keys = []
    for j in range(len(trapdoors)):
        bind_left = ((index >> j) & 1) == 0
        commitment_keys.append(GenerateStep(bind_left, trapdoors[j]))
    return commitment_keys
~~~

The first move commits the value at `index` with every other leaf empty,
under one opening per level:

~~~python
def CommitValAtPlace(
    commitment_keys: Sequence[Element],
    n: int,
    index: int,
    value: bytes,
    openings: Sequence[Scalar],
) -> bytes:
    V = [b"" for _ in range(n)]
    V[index] = value
    return VecCommit(V, commitment_keys, openings)
~~~

Once the other leaves are known, each level's randomness is shifted so that
the sibling of the binding path takes its new value and the node above is
unchanged. An odd last element on the binding path has no sibling and keeps
its randomness.

~~~python
def VecEquivocate(
    commitment_keys: Sequence[Element],
    trapdoors: Sequence[Scalar],
    openings: Sequence[Scalar],
    old: Sequence[bytes],
    new: Sequence[bytes],
    index: int,
) -> list[Scalar]:
    if len(old) != len(new):
        raise ValueError("vectors must have the same length")
    if old[index] != new[index]:
        raise ValueError("the binding position cannot change")
    if len(old) == 1:
        return []

    if index == len(old) - 1 and len(old) % 2 == 1:
        opening = openings[0]
    else:
        partner = index - 1 if index % 2 == 1 else index + 1
        opening = EquivocateStep(
            old[partner], new[partner], openings[0], trapdoors[0]
        )

    old_prime = []
    new_prime = []
    for i in range(len(old) // 2):
        Q = commitment_keys[0]
        old_prime.append(
            CommitStep(Q, old[2 * i], old[2 * i + 1], openings[0])
        )
        new_prime.append(
            CommitStep(Q, new[2 * i], new[2 * i + 1], opening)
        )
    if len(old) % 2 == 1:
        old_prime.append(old[-1])
        new_prime.append(new[-1])

    rest = VecEquivocate(
        commitment_keys[1:],
        trapdoors[1:],
        openings[1:],
        old_prime,
        new_prime,
        index // 2,
    )
    return [opening] + rest


def VecEquivocateFromZero(
    commitment_keys: Sequence[Element],
    trapdoors: Sequence[Scalar],
    openings: Sequence[Scalar],
    new: Sequence[bytes],
    index: int,
) -> list[Scalar]:
    V = [b"" for _ in new]
    V[index] = new[index]
    return VecEquivocate(
        commitment_keys, trapdoors, openings, V, new, index
    )
~~~

### The Permutation {#permutation}

`P` is a permutation on the elements of `G`, computed on their compressed
encodings by cycle walking: a permutation of the encoding space is applied
until the result decodes to an element, and `Pinv` walks the same cycle
backwards. Since a permutation partitions its domain into cycles, the two
are inverse to each other.

The following direct implementations define the permutation and its inverse.
They MAY be used on public points, including the commitment keys in
`CommitStep`. Key generation instead uses `G.PermutationPair`
({{permutation-pair}}), whose execution does not distinguish the two binding
directions when its outputs are fixed.

~~~python
def P(self, element: Element) -> Element:
    buf = bytearray(self.SerializeElement(element))
    buf[0] = buf[0] - 0x02
    while True:
        buf = PermuteBytes(buf)
        try:
            return self.DeserializeElement(
                bytes([buf[0] + 0x02]) + bytes(buf[1:])
            )
        except DeserializeError:
            continue

def Pinv(self, element: Element) -> Element:
    buf = bytearray(self.SerializeElement(element))
    buf[0] = buf[0] - 0x02
    while True:
        buf = UnpermuteBytes(buf)
        try:
            return self.DeserializeElement(
                bytes([buf[0] + 0x02]) + bytes(buf[1:])
            )
        except DeserializeError:
            continue
~~~

The permutation of the encoding space is an eight-round Feistel network over
33-byte strings whose first byte is `0x02` or `0x03`, carried as its low
bit. Each iteration of the loop below computes two rounds, one per half:

~~~python
def PermuteBytes(buf: bytearray) -> bytearray:
    left, right = bytearray(buf[0:17]), bytearray(buf[17:33])
    for i in range(4):
        label = f"left round {i}".encode()
        left = bytearray(_xor(left, _sha256(right + label)[0:17]))
        left[0] = left[0] & 0x01
        label = f"right round {i}".encode()
        right = bytearray(_xor(right, _sha256(left + label)[0:16]))
    return left + right

def UnpermuteBytes(buf: bytearray) -> bytearray:
    left, right = bytearray(buf[0:17]), bytearray(buf[17:33])
    for i in reversed(range(4)):
        label = f"right round {i}".encode()
        right = bytearray(_xor(right, _sha256(left + label)[0:16]))
        label = f"left round {i}".encode()
        left = bytearray(_xor(left, _sha256(right + label)[0:17]))
        left[0] = left[0] & 0x01
    return left + right
~~~

The binding argument of {{security-considerations}} models `P` as a random
permutation. Eight is the number of rounds for which a balanced Feistel network
with independent random round functions is known to be indifferentiable from a
random permutation {{DS15}}. The round functions here are SHA-256 separated by
their labels, and the halves are of 129 and 128 bits, a one-bit imbalance
that {{DS15}} does not treat.

#### Walking a Permutation Edge {#permutation-pair}

`G.PermutationPair(T, bind_left)` returns `(Q, P(Q))`. If `bind_left` is true,
it walks backwards from `T = P(Q)` to `Q`. Otherwise it walks forwards from
`T = Q` to `P(Q)`. At each iteration it computes both one-step byte
permutations, selects the next encoding using the secret bit, and tests
whether that encoding is valid. It selects the order of the endpoints before
decoding them, so both final decodings operate on the same public values
`Q` and `P(Q)`, in that order.

~~~python
def PermutationPair(
    self, element: Element, bind_left: bool
) -> tuple[Element, Element]:
    if not isinstance(bind_left, bool):
        raise ValueError("bind_left must be a boolean")
    start = bytearray(self.SerializeElement(element))
    start[0] -= 0x02
    buf = start
    while True:
        forward = PermuteBytes(buf)
        backward = UnpermuteBytes(buf)
        buf = SelectBytes(forward, backward, bind_left)
        if IsValidPermutationEncoding(buf):
            break

    left = SelectBytes(start, buf, bind_left)
    right = SelectBytes(buf, start, bind_left)
    Q = self.DeserializeElement(
        bytes([left[0] + 0x02]) + bytes(left[1:])
    )
    PQ = self.DeserializeElement(
        bytes([right[0] + 0x02]) + bytes(right[1:])
    )
    return (Q, PQ)


def SelectBytes(
    left: bytearray, right: bytearray, choose_right: bool
) -> bytearray:
    mask = -int(choose_right)
    return bytearray(
        (a & ~mask) | (b & mask)
        for a, b in zip(left, right, strict=True)
    )
~~~

`SelectBytes` takes equal-length inputs and selects `right` if its boolean
argument is true, or `left` otherwise. Implementations MUST perform this
selection without secret-dependent branches or memory accesses.

For P-256, encoding validity can be tested without attempting a point
decoding or raising exceptions. Here `FIELD_MODULUS`, `CURVE_A`, and
`CURVE_B` are the P-256 field modulus and Weierstrass coefficients from
{{NISTCurves}}. Since the field modulus is 3 modulo 4, the fixed exponent
below computes a square-root candidate; squaring it tests whether a root
exists. P-256 has prime, odd order, so an affine point with `y = 0` cannot
occur. Each valid `x` therefore supports both sign bits. The identity has
no affine encoding.

~~~python
def IsValidPermutationEncoding(buf: bytearray) -> bool:
    if len(buf) != 33:
        return False
    x = int.from_bytes(buf[1:], "big")
    rhs = (
        pow(x, 3, FIELD_MODULUS) + CURVE_A * x + CURVE_B
    ) % FIELD_MODULUS
    y = pow(rhs, (FIELD_MODULUS + 1) // 4, FIELD_MODULUS)
    return (
        ((buf[0] == 0) | (buf[0] == 1))
        & (x < FIELD_MODULUS)
        & (y * y % FIELD_MODULUS == rhs)
    )
~~~

The validity test MUST execute in constant time for all 33-byte candidates,
including those with an out-of-range coordinate or no square root. All
conditions are evaluated; an exception-based decoder or short-circuit
validation is not a substitute. The byte permutations, selections, initial
serialization of `T`, and computation of `T = secret * B` MUST likewise
have no secret-dependent timing or memory access patterns. The Python
snippets specify the computation and operation schedule; Python integer
arithmetic and the reference implementation's group operations do not
provide these constant-time guarantees.

To see why the loop may stop at the first valid encoding, fix the public
output `Q`. Let `k` be the number of applications of `PermuteBytes` needed
to reach `P(Q)` from `Q`. None of the `k - 1` intermediate encodings is
valid. Walking backwards from `P(Q)` therefore reaches `Q` after exactly
`k` applications of `UnpermuteBytes`, with the same sequence of validity
results: `k - 1` failures followed by one success. Each orientation executes
one forward permutation, one inverse permutation, one selection, and one
validity test per iteration. Thus the observable operation schedule depends
only on `Q`, which is included in the proof, and can be reproduced from it.
This argument also covers fixed points and does not assume that `P` is
random; the separate binding assumption on `P` is unchanged.

Implementations MUST NOT optimize away the unused permutation direction.
Calling `Pinv(T)` only for left binding leaks the direction directly.
Computing `Pinv(T)` for both directions and selecting an endpoint afterwards
also leaks: for a fixed public `Q`, its walk length describes the edge
leaving `Q` in one case and the edge entering `Q` in the other. Both one-step
permutations MUST be computed on each iteration of the selected walk.

### Challenge Computation {#proof-challenge}

`ProofStatement` encodes the statement being proven: the Anchor Set, the
rerandomized key, the signature being presented, the two contexts, and the
Moderator's challenge digest. The Fiat-Shamir challenge covers it together
with the first move of the proof, which is the commitment keys and the root
of the tree.

~~~python
def ProofStatement(
    anchor_set: Sequence[Element],
    X_hat: Element,
    endorsement: Endorsement,
    ctx_iss: bytes,
    ctx_red: bytes,
    challenge_digest: bytes,
) -> bytes:
    (c, s_hat, y, t, nf) = endorsement
    n = len(anchor_set)

    anchor_set_enc = b""
    for i in range(n):
        anchor_set_enc += G.SerializeElement(anchor_set[i])

    return (
        I2OSP(n, 2)
        + anchor_set_enc
        + G.SerializeElement(X_hat)
        + G.SerializeScalar(c)
        + G.SerializeScalar(s_hat)
        + G.SerializeScalar(y)
        + G.SerializeScalar(t)
        + U16Prefixed(nf)
        + U16Prefixed(ctx_iss)
        + U16Prefixed(ctx_red)
        + U16Prefixed(challenge_digest)
    )


def ComputeProofChallenge(
    anchor_set: Sequence[Element],
    X_hat: Element,
    endorsement: Endorsement,
    ctx_iss: bytes,
    ctx_red: bytes,
    challenge_digest: bytes,
    commitment_keys: Sequence[Element],
    root: bytes,
) -> Scalar:
    ck_enc = b""
    for j in range(len(commitment_keys)):
        ck_enc += G.SerializeElement(commitment_keys[j])

    proof_transcript = (
        ProofStatement(
            anchor_set,
            X_hat,
            endorsement,
            ctx_iss,
            ctx_red,
            challenge_digest,
        )
        + ck_enc
        + root
        + b"IssuerProof"
    )

    return G.HashToScalar(proof_transcript)
~~~

The length of the Anchor Set `n` is prefixed and `Element` encodings are
fixed-length, so `anchor_set_enc` and `ck_enc` are unambiguous without length
prefixes of their own; `q`, and with it the number of commitment keys, is
determined by `n`. The label `"IssuerProof"` separates this transcript from the
issuance transcript of {{challenge}}, which is hashed with the same function.

Unlike `ComputeChallenge`, this function accepts zero rather than aborting and
retrying: a challenge of zero yields a proof that verifies, and no branch is
privileged by it.

### Proving {#prove-issuer}

~~~python
def ProveIssuer(
    anchor_set: Sequence[Element],
    index: int,
    delta: Scalar,
    X_hat: Element,
    endorsement: Endorsement,
    ctx_iss: bytes,
    ctx_red: bytes,
    challenge_digest: bytes,
    rand: bytes,
) -> tuple[Scalar, Scalar, Sequence[Element], Sequence[Scalar]]:
    Y = Statements(anchor_set, X_hat)
    q = Depth(len(anchor_set))
    if not 0 <= index < len(anchor_set):
        raise ValueError("index is outside the Anchor Set")
    if len(rand) != (2 * q + 1) * Nseed:
        raise ValueError("invalid issuer proof randomness length")

    instance = ProofStatement(
        anchor_set,
        X_hat,
        endorsement,
        ctx_iss,
        ctx_red,
        challenge_digest,
    )
    derived = G.DeriveNonces(
        G.SerializeScalar(delta), b"ProveIssuer", instance, rand
    )
    r = derived[0]
    trapdoors = derived[1 : q + 1]
    first_openings = derived[q + 1 :]
    A = B * r

    commitment_keys = GenerateVecBind(index, trapdoors)
    # First move: commit along the binding path; other leaves empty.
    root = CommitValAtPlace(
        commitment_keys,
        len(Y),
        index,
        G.SerializeElement(A),
        first_openings,
    )

    proof_challenge = ComputeProofChallenge(
        anchor_set,
        X_hat,
        endorsement,
        ctx_iss,
        ctx_red,
        challenge_digest,
        commitment_keys,
        root,
    )

    response = r - proof_challenge * delta

    V = []
    for i in range(len(Y)):
        commitment = BranchCommitment(proof_challenge, response, Y[i])
        V.append(G.SerializeElement(commitment))
    openings = VecEquivocateFromZero(
        commitment_keys, trapdoors, first_openings, V, index
    )

    return (proof_challenge, response, commitment_keys, openings)
~~~

`ProveIssuer` derives the nonce `r`, the trapdoors of the `q` commitment
keys, and the `q` openings of its first move with one call to
`G.DeriveNonces` ({{derive-nonce}}), keyed by `delta` and the proof
statement; `rand` holds `Nseed` bytes for each of these `2 * q + 1` scalars.
Every value of the first move therefore changes whenever `delta`, the
statement, or any part of `rand` does.

The first move commits only the path from leaf `index` to the root: at each
level the Client commits the value it holds on one side and an empty value
on the other, having generated that level's key so that the *other* side is
the equivocal one. The third move then computes the branch commitment of
every statement from the single response, equivocates each level to the
value its sibling subtree now has, and rebuilds the tree with the
equivocated randomness. The root is unchanged by this, which is why the
verifier can recompute it.

### Verifying {#verify-issuer}

~~~python
def VerifyIssuer(
    anchor_set: Sequence[Element],
    X_hat: Element,
    endorsement: Endorsement,
    ctx_iss: bytes,
    ctx_red: bytes,
    challenge_digest: bytes,
    proof_challenge: Scalar,
    response: Scalar,
    commitment_keys: Sequence[Element],
    openings: Sequence[Scalar],
) -> bool:
    n = len(anchor_set)
    if n < 2:
        return False

    Y = Statements(anchor_set, X_hat)
    q = Depth(n)
    if len(commitment_keys) != q:
        return False
    if len(openings) != q:
        return False

    T = []
    for i in range(n):
        commitment = BranchCommitment(proof_challenge, response, Y[i])
        if commitment.isIdentity():
            return False
        T.append(G.SerializeElement(commitment))

    root = VecCommit(T, commitment_keys, openings)

    return proof_challenge == ComputeProofChallenge(
        anchor_set,
        X_hat,
        endorsement,
        ctx_iss,
        ctx_red,
        challenge_digest,
        commitment_keys,
        root,
    )
~~~

The verifier computes a commitment for every branch from the single response,
rebuilds the whole tree from those commitments and the openings it was given,
and checks that the root it arrives at is the one the challenge was computed
over. Neither the branch commitments nor the interior nodes are transmitted.

`VerifyIssuer` returns `false` rather than raising an error, so that it is a
total predicate on its inputs, as `Verify` ({{verify}}) is. Two of its
rejections are defensive restatements of its input types: the lengths of
`commitment_keys` and `openings` are fixed by the Anchor Set, and a redemption
whose vectors have any other length is rejected before this algorithm is
reached, when it is deserialized ({{redemption-wire}}). Another, `n < 2`, is
not a property of the redemption at all but of the Moderator's own Anchor Set;
reaching it means the Moderator is misconfigured ({{verify-redemption}}).

The last rejects a branch commitment equal to the identity element, which
`SerializeElement` cannot encode. A Client reaches it on its own branch by
answering `response = -proof_challenge * delta`. An interior node is the
identity only for a Client that knows a discrete logarithm relation among `B`,
`Q`, and `P(Q)` for the key `Q` of its level, which the binding property of
{{pbvc}} rules out, so `VecCommit` does not check for it.

A proof produced by `ProveIssuer` is accepted by `VerifyIssuer`. On branch
`index`,

~~~
  proof_challenge * Y[index] + response * B
    = proof_challenge * delta * B
      + (r - proof_challenge * delta) * B
    = r * B
~~~

This is the commitment the Client committed at the binding leaf, and every
other leaf holds by definition the commitment the verifier recomputes. Each
level then reproduces the node the Client committed: the binding side is
unchanged, and the equivocal side was shifted to match.

Conversely, the binding leaf is fixed before `proof_challenge` exists and
cannot be moved afterwards, so a Client that could produce an accepting proof
for two different challenges would yield `delta` for that leaf's statement. The
soundness of the proof rests on that, and on nothing about the other branches;
see {{security-considerations}}.

## Redemption {#redeem}

The Client produces a redemption from an Endorsement it holds.

~~~python
def Redeem(
    anchor_set: Sequence[Element],
    index: int,
    endorsement: Endorsement,
    ctx_iss: bytes,
    ctx_red: bytes,
    challenge_digest: bytes,
) -> Redemption:
    (c, s, y, t, nf) = endorsement
    n = len(anchor_set)

    if n < 2:
        raise VerifyError
    if not 0 <= index < n:
        raise ValueError("index is outside the Anchor Set")

    q = Depth(n)
    rand = random((2 * q + 2) * Nseed)
    (delta,) = G.DeriveScalars(Seed(rand, 0), b"delta")

    X_hat = anchor_set[index] + delta * B
    s_hat = s + (c * y) * delta
    shown = Endorsement(c, s_hat, y, t, nf)

    (proof_challenge, response, commitment_keys, openings) = ProveIssuer(
        anchor_set,
        index,
        delta,
        X_hat,
        shown,
        ctx_iss,
        ctx_red,
        challenge_digest,
        rand[Nseed:],
    )

    return Redemption(
        X_hat,
        shown,
        proof_challenge,
        response,
        commitment_keys,
        openings,
    )
~~~

In order to keep the Anchor anonymous, the Client MUST NOT redeem against an
Anchor Set of fewer than two keys. Refusing also keeps the depth `q` of the
tree at least one, so a redemption always carries at least one commitment key.

`delta` MUST be freshly derived for every redemption, and MUST NOT be derived
from the Endorsement or from any other value a Client reuses. It is what makes
the redemption unlinkable to the Anchor, and reusing it across two redemptions
would link them to each other.

## Redemption Verification {#verify-redemption}

The Moderator checks the signature under the rerandomized key and the proof
against its Anchor Set.

~~~python
def VerifyRedemption(
    anchor_set: Sequence[Element],
    redemption: Redemption,
    ctx_iss: bytes,
    ctx_red: bytes,
    challenge_digest: bytes,
) -> bytes:
    (
        X_hat,
        shown,
        proof_challenge,
        response,
        commitment_keys,
        openings,
    ) = redemption

    if not Verify(X_hat, shown, ctx_iss, ctx_red):
        raise VerifyError

    if not VerifyIssuer(
        anchor_set,
        X_hat,
        shown,
        ctx_iss,
        ctx_red,
        challenge_digest,
        proof_challenge,
        response,
        commitment_keys,
        openings,
    ):
        raise VerifyError

    return shown.nf
~~~

The first check is the endorsement verification of {{verify}}, run against the
rerandomized key. Together the two checks establish that the Client holds an
Endorsement issued under `ctx_iss` and `ctx_red` by one of the Anchors in
`anchor_set`, and reveal nothing further about which one. On success,
`VerifyRedemption` returns the nullifier; either failed check raises a
`VerifyError`.

`VerifyRedemption` does not enforce single use. The nullifier `nf` is in the
clear in the redemption, and a Moderator that accepts a redemption MUST reject
it if it has already recorded that `nf`, and MUST record `nf` before granting
anything on the strength of it. A Moderator SHOULD scope its nullifier store to
the issuance context, since an Endorsement issued under a different `ctx_iss`
does not verify anyway. {{PROTOCOLS}} places these checks, and the check that
`ctx_iss` is current, at the Moderator.

A Moderator MUST NOT offer an Anchor Set of one key: with `n = 1` the tree has
depth zero, the proof carries no commitment key, and what remains is a plain
proof of knowledge of `delta` for the single key, which identifies the Anchor.
`VerifyIssuer` rejects that case, but that rejection is a guard on the
Moderator's own configuration rather than a verdict on the redemption: a
Moderator that configures it has already lost the property before any proof is
checked. See {{security-considerations}}.

## Encodings {#redemption-wire}

A redemption is carried in the `bytes` field of the `Presentation` structure of
{{PROTOCOLS}}, which a Client sends in the `endorsement_presentation` field of a
`CredentialRequest`.

~~~ tls-presentation
struct {
  Element rerandomized_key;
  Endorsement shown_endorsement;
  Scalar proof_challenge;
  Scalar response;
  Element commitment_keys<V>;
  Scalar openings<V>;
} Redemption;
~~~

`shown_endorsement` uses the `Endorsement` structure of
{{endorsement-encoding}}, with `s` carrying `s_hat`. It is a valid Endorsement
under `rerandomized_key`, which is the point of {{rerandomization}}; it is not
the Endorsement the Client stored, and the Client MUST NOT send that one.

A Moderator deserializes a `Redemption` against its Anchor Set of `n` keys, as
in {{wire}}. It MUST raise a `DeserializeError` unless `commitment_keys` is
`Depth(n) * Ne` bytes long and `openings` is `Depth(n) * Ns` bytes long
({{pbvc}}).

# Ciphersuites {#ciphersuites}

A ciphersuite fixes the group, the hash functions, and the associated encodings
and domain separation tags. Both parties are assumed to agree on the
ciphersuite in use ({{config}}).

For each ciphersuite, `ctx_proto` is as computed in {{config}}. The nullifier
length is `Nn = 32` bytes and the seed length is `Nseed = Ns + 16` bytes, that
is 48 bytes, for the ciphersuite below. The 16 bytes in excess of `Ns` make
a derived scalar statistically close to uniform ({{derive-scalar}}), on the
same grounds that {{HASH2CURVE}} oversamples by 16 bytes when it maps a byte
string to a field element.

## IHAT(P-256, SHA-256)

This ciphersuite uses P-256 (secp256r1) {{NISTCurves}} for the group and
SHA-256 for the hash function, with `Nh = 32`. The value of the ciphersuite
identifier is `"P256-SHA256"`.

The interface of {{group}} is instantiated as follows.

Order():
: Return 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551.

Identity(), Generator(), ScalarMultGen(r):
: As defined in {{NISTCurves}}.

HashToGroup(x):
: Use `hash_to_curve` with suite `P256_XMD:SHA-256_SSWU_RO_` {{HASH2CURVE}} and
  `DST = "HashToGroup-" + ctx_proto`.

HashToScalar(x):
: Use `hash_to_field` from {{HASH2CURVE}} with `L = 48`, `expand_message_xmd`
  with SHA-256, `DST = "HashToScalar-" + ctx_proto`, and a prime modulus
  equal to `Order()`.

ScalarInverse(s):
: The multiplicative inverse of `s` modulo `Order()`.

SerializeElement(A):
: The compressed Elliptic-Curve-Point-to-Octet-String method of {{SEC1}};
  `Ne = 33`.

DeserializeElement(buf):
: Deserialize a 33-byte input using the compressed
  Octet-String-to-Elliptic-Curve-Point method of {{SEC1}}, then perform partial
  public key validation as in {{Section 4.3 of OPRF}}. This includes checking
  that the coordinates are in range, that the point is on the curve, and that
  the point is not the identity element. Raise a `DeserializeError` if any
  check fails.

SerializeScalar(s):
: The Field-Element-to-Octet-String conversion of {{SEC1}}; `Ns = 32`.

DeserializeScalar(buf):
: Deserialize a 32-byte input using Octet-String-to-Field-Element from
  {{SEC1}}. Raise a `DeserializeError` if the result is not in
  `[0, Order()-1]`.

P:
: The SHA-256 Feistel permutation and cycle walk in {{permutation}}.
  Compressed SEC1 prefixes are `0x02` and `0x03`; subtracting `0x02` gives
  the one-bit prefix used by the byte permutation. `Pinv` reverses the
  walk. `PermutationPair` ({{permutation-pair}}) is used during commitment
  key generation. For a random encoding permutation, the walk takes about
  two iterations on average.

## Randomness {#randomness}

Every random value in this document is drawn with `random`. Apart from the
nullifier, it is consumed, `Nseed` bytes per scalar, by `G.DeriveScalars`
({{derive-scalar}}), by `G.DeriveNonces` ({{derive-nonce}}) for the values of
the issuer-hiding proof, or by `G.DeriveKeyPair` ({{keygen}}) for a key; no
scalar is sampled directly. Implementations MUST draw this randomness with a
cryptographically secure random number generator and MUST NOT reuse it across
derivations. They SHOULD treat it as being as sensitive as the values derived
from it, and SHOULD handle both in constant time: the randomness drawn in
`Commit` determines the Anchor's session state, that drawn in `Challenge` the
Client's blinding factors, and that drawn in `Redeem` every value of the
issuer-hiding proof, so recovering any of it undoes the property that
algorithm provides.

# Security Considerations {#security-considerations}

> **TODO.** This section is a summary of the properties the construction is
> intended to provide and of the requirements implementations must meet. Formal
> statements and the corresponding reductions are not yet written.

The issuance protocol is the partially blind signature scheme of Tessaro and
Zhu {{TESSZHU}}, instantiated with the public input set to the issuance context.
Its security is analysed in the random oracle model, and one-more
unforgeability additionally in the algebraic group model under the discrete
logarithm assumption. Notably, its concurrent security does not rely on the
hardness of the ROS problem, which is broken in polynomial time, nor on the
mROS problem, which admits sub-exponential attacks.

Blindness:
: All the Anchor receives in a session is the blinded challenge `c * gamma2`.
  With uniform blinding factors, the blinded challenge is uniformly
  distributed and independent of the message and of the resulting signature,
  and the scheme is perfectly blind {{TESSZHU}}. The derived blinding factors
  of this document are each within about `2^-128` of uniform ("Derived
  blinding factors" below), so the scheme is statistically blind: an Anchor
  cannot link an Endorsement to the session that produced it, even with
  unbounded computation. This is what makes endorsement grants and
  redemptions unlinkable as required by {{ARCH}}, including against an
  attacker with a quantum computer that records transcripts today.

Derived blinding factors:
: `Challenge` derives its four blinding factors with `G.DeriveScalars`, and
  `Redeem` derives `delta` the same way and the `2 * q + 1` scalars of its
  proof with `G.DeriveNonces`, whose output is distributed as that of
  `G.DeriveScalars` when its input is uniformly random ({{derive-nonce}}).
  Each derived scalar is within about `2^-128` of uniform
  ({{derive-scalar}}), so the four blinding factors of a session are jointly
  within about `2^-126` of uniform, and blindness holds against unbounded
  computation up to that distance. Each scalar has `Nseed` bytes of
  randomness of its own: deriving several scalars from fewer bytes would bound
  their joint entropy by that input's, and an exhaustive search over inputs
  would identify the one session consistent with a given Endorsement.
  Implementations MUST NOT derive several scalars from fewer than `Nseed`
  bytes each.

Derived first move:
: A value of the first move of `ProveIssuer` reused under a different
  challenge reveals `delta`, which names the Anchor, or the trapdoor of a
  commitment key and with it a bit of `index`. `ProveIssuer` therefore derives
  all of them together with `G.DeriveNonces` from `delta`, the proof
  statement, and all of its randomness ({{prove-issuer}}). With a working
  random source they are distributed as derived scalars ("Derived blinding
  factors" above). With a failed one they are pseudorandom functions of
  `delta`, unpredictable to a verifier that does not know `delta`, and each
  of them changes whenever `delta`, the statement, or any part of the
  randomness does ({{derive-nonce}}); a random source that repeats all of
  its output reproduces the proof. The Anchor's signing nonce `a` in `Commit`
  cannot be protected the same way: it is fixed before the Client's
  challenge is known, so no public input distinguishes two sessions at that
  point. `Commit` derives `a` together with `t` and `y`, so a random source
  that repeats part of its output still changes `a`, but only fresh
  randomness, or persistent per-session state, prevents a full repetition.
  An Anchor that reuses `a` across two challenges reveals `y * skA`, and
  hence `skA`, since `y` is public in the Endorsement.

One-more unforgeability:
: A Client that completes `k` issuance sessions under a given issuance context
  cannot produce `k+1` distinct valid Endorsements under that context,
  regardless of how many sessions it has completed under *other* issuance
  contexts {{TESSZHU}}. This is what allows a Moderator to conclude that an
  accepted Endorsement corresponds to exactly one grant by a trusted Anchor.

Unforgeability under rerandomization:
: Rerandomization is additive and applies only after issuance, so issuance is
  the unmodified scheme of {{TESSZHU}} and its unforgeability is intended to
  carry over directly: a reduction relays the signing oracle verbatim, extracts
  `delta` and the branch it belongs to from the issuer-hiding proof, and undoes
  the public shift to obtain a forgery under the Anchor's own key. The
  extraction is the special soundness of the stacking composition
  (Section 7 of {{STACKSIG}}): two accepting proofs that share a first move but
  answer different challenges agree on the branch commitment at the binding
  position, and the branch proof of {{branch}} then yields `delta` for that
  branch's statement. Nothing in `Redeem` gives a Client a signature it did not
  already hold: `X_hat` and `s_hat` are computed from values it has, and a
  Client that could produce an accepted redemption without an Endorsement from
  some Anchor in `anchor_set` would yield a forgery. **TODO:** this reduction is
  stated, not written out, and must account for multiple redemptions in the
  one-more unforgeability game.

Issuer hiding:
: Up to the statistical distance given below, a redemption reveals no
  information about which Anchor in `anchor_set` issued the Endorsement, so a
  Moderator, an Anchor, and the two colluding learn only that some key in
  `anchor_set` was used. Three facts establish this. `X_hat` and the
  `response` of the single branch proof are statistically close to uniform
  independently of the branch ({{branch}}). And the commitment
  scheme of {{pbvc}} hides which position it binds: a commitment key is
  distributed over the group essentially independently of that position, and
  an opening essentially independently of whether the value it opens to was
  committed or equivocated. The proof therefore reveals the branch only through
  values that are almost independent of it, which is witness
  indistinguishability of the composition (Section 7 of {{STACKSIG}}).

: The commitment of {{pbvc}} hides which position it binds, and the stacked
  composition is witness indistinguishable (appendix and Section 7 of
  {{STACKSIG}}); those results assume uniform randomness, and each of the
  `2 * q + 2` scalars a redemption derives is within about `2^-128` of
  uniform ("Derived blinding factors" above), a statistical distance of at
  most `(2 * q + 2) * 2^-128`. Like blindness, issuer hiding therefore holds
  against unbounded computation, including a quantum computer that records
  transcripts today. It is the *binding* property of the commitment, and not
  its hiding, that rests on the discrete logarithm, which is the direction
  {{ARCH}} requires.

Partially binding commitments:
: The soundness of the issuer-hiding proof rests on two things: the
  commitment of {{pbvc}} binding one position of each node, and the
  collision resistance of `HashToScalar` on the leaf and node encodings,
  without which a position could be opened to a colliding value and no
  discrete logarithm would be extractable. Binding is computational. A
  Client that opens the value under base `Q` two ways knows the discrete
  logarithm of `Q`, and one that opens the value under `P(Q)` two ways knows
  that of `P(Q)`; the key generation gives it one of the two. Opening both
  positions would require both logarithms. That a `Q` with both known is as
  hard to find as a discrete logarithm when `P` is modelled as a random
  permutation ({{permutation}}) is the assumption under which the pair
  commitment of the appendix of {{STACKSIG}} binds. `P` MUST therefore be the
  permutation specified in {{permutation}} and MUST NOT be chosen or
  negotiated by any party: a Client that could choose `P` could take
  `P(Q) = 2 * Q`, equivocate every position of every node, open the binding
  leaf to whatever the challenge required, and produce accepting redemptions
  holding no Endorsement at all.

Anchor Set size:
: Issuer hiding hides the Anchor *within the Anchor Set*, so the set is the
  anonymity set, and a redemption against a single-key set would name the
  Anchor outright ({{verify-redemption}}); a Client MUST refuse such a set
  rather than rely on the Moderator to avoid offering one ({{redeem}}).
  The anonymity set is exactly `n`, the size of the Anchor Set ({{pbvc}}).
  More generally a Moderator that offers different Anchor
  Sets to different Clients partitions them, and one that reorders the set
  between Clients does the same; the set and its order MUST be the same for
  every Client offered a given `ctx_iss`. See {{ARCH}} for how set size
  interacts with Anchor diversity.

Proof size and cost:
: The proof is logarithmic in the size of the Anchor Set: two scalars, plus one
  element and one scalar for each of the `q` levels of the tree
  ({{redemption-wire}}). Computation is not. Both the prover and the verifier
  evaluate all `n` branch commitments. The verifier builds one tree, of `n - 1`
  node commitments; the prover builds the tree of its first move and then,
  in `VecEquivocate`, an old and a new tree, `3 * (n - 1)` node commitments in
  all, of which the old tree repeats the first and can be kept from it. Each
  party performs a number of scalar multiplications linear in `n`, so a large
  Anchor Set is cheap in bandwidth and not in CPU, which reverses the tradeoff
  of the linear disjunction {{CDS94}} for bandwidth but not for work;
  {{FFKLLS26}} notes the same for its own instantiations. Two consequences
  for deployments: the linear disjunction is smaller for Anchor Sets of three
  keys or fewer, and since the depth `q = Depth(n)` is `ceil(log2 n)`, an
  Anchor Set of `2^q + 1` keys costs a whole extra level while adding one
  Anchor to the anonymity set.

Constant-time proving:
: `ProveIssuer` treats one leaf, and one side of each node on the path to it,
  differently from the others, and which leaf that is is exactly the secret the
  proof exists to hide. Implementations MUST NOT allow the binding path to be
  distinguished by timing, memory access patterns, or the amount of randomness
  consumed. The specification is written so that the last of these is not a
  signal: the randomness a redemption consumes is a function of `q` alone
  ({{redeem}}). The first move places the real branch commitment at `index`
  and empty values at every other leaf; both commitment passes visit every
  node of the tree. That placement and the later equivocation MUST avoid
  observable secret-dependent branches and memory accesses.

: Commitment key generation uses the balanced walk of {{permutation-pair}}.
  Its iteration count is determined by the published commitment key, and
  both binding directions execute the same operation schedule for that key.
  This addresses the permutation walk only: secret-index selection,
  scalar arithmetic, and the rest of the proving algorithm still require
  constant-time implementations. In particular, source-level masking in
  the Python reference implementation is not a constant-time guarantee.

Single-use sessions:
: **Implementations MUST ensure that the session state produced by `Commit` is
  never used more than once.** This requirement is load-bearing, not defensive.
  If an Anchor answers two distinct challenges `c1 != c2` on one `Commit` state,
  then from the two responses `s1 = a + c1*y*skA` and `s2 = a + c2*y*skA`, with
  `y` revealed in both, anyone recovers the signing key as
  `skA = (s1 - s2) * ScalarInverse((c1 - c2) * y)`. The requirement extends to
  process restarts, to replicas sharing a signing key, and to any retry or
  replay of a `ChallengeMessage`: an Anchor MUST treat a session as closed the
  moment it emits a response, and MUST answer a repeated `session_id` with a
  `SessionError` rather than recomputing. Anchors are stateful for this reason,
  and this state cannot be made stateless by sealing it into a cookie handed to
  the Client: sealing preserves the secrecy of `(a, y, t)` but not their
  single use, and single use is the property that matters here.

Challenge binding:
: `challenge_digest` enters the proof transcript ({{proof-challenge}}), so a
  proof produced for one challenge does not verify under any other. Whether that
  amounts to replay protection depends on the challenge being fresh, which this
  document does not control: {{PROTOCOLS}} fixes what the Moderator's challenge
  contains, and a challenge that carries only the Moderator's configuration
  takes the same value for every Client and every session. Under such a
  challenge, `challenge_digest` binds a proof to the Moderator rather than to a
  session, and it is the nullifier check of {{verify-redemption}} that prevents
  a redemption from being replayed. A deployment that wants challenge binding to
  carry session freshness needs the challenge to include a value that varies per
  session. It binds the proof, not the signature: the
  signature is the same bytes whatever challenge is answered, which is why the
  nullifier check and not challenge binding is what makes an Endorsement
  single-use.

Context binding:
: The issuance context enters both the commitment base and the challenge
  transcript, and the redemption context enters the signed message, so an
  Endorsement does not verify under any other pair of contexts. Neither context
  is carried in the Endorsement; both are supplied by the verifier
  ({{verify}}), so a Client cannot assert the pair its Endorsement is checked
  against. A Client also cannot select the issuance context unilaterally: it is
  never sent from the Client to the Anchor, and using a value other than the one
  the Anchor committed under fails the opening check in `Finalize`.

Nullifier reuse:
: A Client that reuses a nullifier across Endorsements links those Endorsements
  to each other at redemption and, depending on the Moderator's nullifier
  store, causes all but the first redemption to be rejected. Nullifiers MUST be
  freshly generated.

Aborts on zero:
: `Challenge` aborts when the challenge hashes to zero and `Respond` aborts on
  a zero challenge. Both events occur with probability approximately `1/p` for
  honest parties, where `p` is the order of the group. A Client that observes
  such an abort learns nothing and SHOULD start a fresh session.

Context granularity:
: The unlinkability arguments above are cryptographic; the anonymity set they
  operate over is set by the contexts. Both contexts are visible at redemption,
  the issuance context directly and the redemption context through the fact
  that the Endorsement verifies under it, so each partitions Clients into the
  set that shares its value. Whatever {{ARCH}} eventually specifies them to be
  ({{context-binding}}), both values must therefore be **coarse**. Every Client
  holding an Endorsement issued under a given issuance context MUST derive the
  byte-identical `ctx_iss`, and every Client redeeming under a given
  redemption context MUST derive the byte-identical `ctx_red`. A deployment
  that refines either value, for instance by using a per-request timestamp
  rather than a shared epoch, or a per-Client identifier rather than a value
  shared by every Client redeeming in the same place, reduces the anonymity set
  accordingly, in the limit to a single Client, and does so without violating
  any cryptographic property of the construction. Implementations MUST NOT do
  so.

Session identifiers:
: The `session_id` of {{wire}} is chosen by the Anchor and so is a value
  the Anchor recognises. It is confined to the transport: it is not an input to
  any algorithm of {{issuance}}, nor is it included in the challenge transcript. Were
  it bound into the Endorsement, the Anchor could recognise its own identifier at
  redemption and link the redemption to the issuance session.

Anonymity sets:
: The effective privacy a Client obtains also depends on deployment properties
  beyond this document, in particular the number of Clients an Anchor serves per
  epoch and the size of a Moderator's Anchor Set; see {{ARCH}}.

# IANA Considerations {#iana}

This document has no IANA actions. The endorsement type for the scheme
specified here is registered by {{PROTOCOLS}}.


--- back

# Test Vectors {#test-vectors}

The vectors below cover the ciphersuite of {{ciphersuites}}: `G.DeriveScalars`,
the permutation `P`, a key pair, one issuance, and redemptions of the
resulting Endorsement against an Anchor Set of two keys and against one of
five. Byte strings are in hexadecimal, wrapped at 64 digits with the
continuation lines indented; integers are decimal.

Every algorithm is a deterministic function of the bytes it draws from
`random`. Each `rand` entry is the concatenation of every `random` call the
algorithm makes, in the order made; an implementation replays a vector by
serving those bytes in place of `random`. For `G.GenerateKeyPair` it is the
key seed; for `Commit`, the `3 * Nseed` bytes of `(a, t, y)`; for
`Challenge`, the `Nn` bytes of the nullifier and then the `4 * Nseed` bytes
of the blinding factors; and for `Redeem`, the `Nseed` bytes of `delta` and
then the `(2 * q + 1) * Nseed` bytes of the issuer-hiding proof. The
`commit.state` entry is the `AnchorState` `(a, y, t)` as
`SerializeScalar(a) || SerializeScalar(y) || SerializeScalar(t)`, and the
`challenge.state` entry is `nf || SerializeScalar(r1) || SerializeScalar(r2)
|| SerializeScalar(gamma1) || SerializeScalar(gamma2) || SerializeScalar(c)`.
`issue.Z` is `CreateContextBase(ctx_iss)`, and `key.P_pkA` is `P(pkA)`.
Every message and `endorsement` entry is an encoding of {{wire}} or
{{redemption-wire}}, and both issuance messages carry `issue.session_id`.
The keys of each Anchor Set other than `key.pkA` were generated for the
vectors. Both redemptions present the same Endorsement, which a Moderator
would accept only once; each `nf` entry is the output of `VerifyRedemption`.

## Ciphersuite {#ihat-tv-suite}

~~~
suite.identifier = 503235362d534841323536
suite.ctx_proto = 4948415476312d503235362d534841323536
~~~

## Scalar Derivation {#ihat-tv-derive}

~~~
derive.info = 49484154207465737420766563746f7273
derive.rand =
    b491ebc7b27ab6686b79b3baaf7b25927fbe526f960022f8a57d19117e851a24
    c92c63561f2eeaa41bf2ccd38f542fc9529989449460c9ba637562b809c0aa66
    16e8abeb471ae9ca90d5a167ee82e11c1883c884b90089705e685340c4a71e24
    2db356c9b2d831181cd46fbbf6700b24fdfbd763307775e8ea735664aa6752cf
    143b4285c4babf4bf236040ce535d9bd
derive.scalars =
    8e206776b3b13202c0f91c77cdf07545a53224a8a70a9392e67cd8b5c514aae0
    65fbf5ed7bff2e0ae92988c17faaa8b0d087574322006e06e05e103c5cf8de20
    6d4e18742f79608cc98eadebfe23df733edf4cd3ac80229ecdb1370ec48f4660
~~~

## Key Pair {#ihat-tv-key}

~~~
key.rand =
    43e61c3cab7fe45a244be4ee39d021ca8f321e60e3551edc333b35ef5a02fa60
    348b68d1f71146eaa46d223bf89eda15
key.skA =
    bb38180155e1f20d1dbf004c91509fa7e29df40d3198188343e9ea0c15691a25
key.pkA =
    02780ffa25f6b3c2cdef39d64a847a3bcc03a137696e1a57d984fb486ebaae74
    d9
key.P_pkA =
    02bb8cf74bf5298da4247cb2f15a56d3b69ce9ccac80868af957ac732aedf3f3
    3f
~~~

## Issuance {#ihat-tv-issue}

~~~
issue.ctx_iss =
    49484154207465737420766563746f72732069737375616e636520636f6e7465
    7874
issue.ctx_red =
    49484154207465737420766563746f727320726564656d7074696f6e20636f6e
    74657874
issue.Z =
    03e4d8bd93a95d62cd6206c01a2bb88b801e00c347fb2c76a42471d0d86c581e
    2f
issue.session_id =
    49484154207465737420766563746f72732073657373696f6e
issue.commit.rand =
    eb65750be50f08b753084e5aaa5c7ff1f5cf704df5ff6f50580f86252b68036a
    585fbf3cb880193720458e840ee62cad256fba5c97cd71c863a51eb09f00bf3d
    62fa2f414b1ed06d89c26b44730cccb252c54acf76286e21578da59d7b1c550a
    aff8cf57c97aac37fcfc8173983bb9ccb6c290cc04ab3c2be5bd926e8136099b
    15521c0ab3cef48a36e8198a0c408479
issue.commit.state =
    6cd55389982a5c4869bd6d032eacbaad5999f837b3ec5cb26e0768daef846cc5
    409d9ffa301f945abbde0a5976c015597156ee6de3741cd92b7cf0da93cc2cb1
    7207b5513db23b55be86e6aca9c43c7fea0d630a978a18ef547a5ccd72c5f6a5
issue.commit.message =
    1949484154207465737420766563746f72732073657373696f6e02ff0bf3fe5d
    4b74e6fc1a85f6c64e9c3b66dfb56fe51cf1435c6e3418cc4c37b803b71161f4
    7bb7f161bdf97a0859c0e64c7dba8e9cf36b47f2f8be78b9dcef70b7
issue.challenge.rand =
    a0ab32bb3faea7dfe5e30dc762cde359fac2ad47aec08727b3aba7fac90e55d7
    2a241e1d7dbc231c763814e297999defaae82d271329fe3f288521b3d0af9771
    e6c1812536b9f0e6d1e07cdda9a0850577268339096617cbe15784664fc20913
    9ebaf59d04a9552f879c222da6da5a7dd0128f373861dc677b01bd9f29c0b609
    355f703f6de72c62525470ab4fb53b7f674840a349e1668ad7b07c47f260de04
    6e818e1df225daf8aee6c7a2229e2e0f812ee948219b18dc924f922dbc4f2fe2
    cf0a100d3e5d2c41cdacdd8830a71924e5e0f3b482715d168da08cbb4eae6722
issue.challenge.state =
    a0ab32bb3faea7dfe5e30dc762cde359fac2ad47aec08727b3aba7fac90e55d7
    43fe130a855f39c1bdb878eb9ba77da55581a0c1a19020610ade2189c3c715c2
    6b8b66575f3da50fca56c6a912423c6a4c323234360b70a1418619f5a50f58a6
    c8b87746de082662bafc05d4c1720c20c8a085330b8b897b18c5a7fcc2b49495
    85aaf1c778de16955727c890f99f97ce7c9f9bbd60a2fa0e5d228ca31e426b8f
    51b91bf8ace61d102b64eac49b8c1b2fd4e56be08b5e359293834b032fe97e2a
issue.challenge.message =
    1949484154207465737420766563746f72732073657373696f6e450a2afe6c32
    b223ecc974fc9d9fd99873f97b635facd5a45da73a5c7a0071c1
issue.response.message =
    a436e9af9871967ba9f4d11cb09e81a7cd19d079f822e0a0144658fc65140333
    409d9ffa301f945abbde0a5976c015597156ee6de3741cd92b7cf0da93cc2cb1
    7207b5513db23b55be86e6aca9c43c7fea0d630a978a18ef547a5ccd72c5f6a5
issue.endorsement =
    51b91bf8ace61d102b64eac49b8c1b2fd4e56be08b5e359293834b032fe97e2a
    c003fbcf365ef3343bbf170455d0729ae578be8e847d936b551d8acf3768f3d5
    77721b72226a41306dea580615b3a9b87e6aca355a59c1676cde64630e8e43e3
    20e054407aa628fd699c51f6dc063e230c6b531dfb4dbf485280102bf9e918f9
    a0ab32bb3faea7dfe5e30dc762cde359fac2ad47aec08727b3aba7fac90e55d7
~~~

## Redemption Against 2 Anchors {#ihat-tv-redeem2}

~~~
redeem2.index = 1
redeem2.anchor_set =
    0294d7e1b3ffc50baff230b23fa2a82a1d270901ba0559abffa0446d12af7f80
    9b02780ffa25f6b3c2cdef39d64a847a3bcc03a137696e1a57d984fb486ebaae
    74d9
redeem2.challenge_digest =
    49484154207465737420766563746f7273206368616c6c656e67652064696765
    7374
redeem2.rand =
    b5b84e47277be49f3a309f5c72b88342e544f4965ef73713170cf727be01aa59
    dfcd9b73ae23f6d23063274409ef20fae8d6b0429e2cc02d434975d44f6d83b7
    105c44d41ef0caf7290a0eb6c718ac2107d391f16b4d744f2e413c099dc33efc
    e8cf2e642f9a8b1e1f830b307bb478a7f04836a3ebe89a7096e32a14f6023ba1
    3a779487b86c6453d0c3a22d7a8d25edb8daf4d6e45f80cd035a94f9baa71586
    99045ffeeaeaadac7dd42aa1dfb9f6767b8425c147eb7fde296d1a4e579b398b
redeem2.delta =
    8d50da85b3ce520151fa848e777febfe277dfa83e2c2508605b8faedfad248cc
redeem2.message =
    02fc2eb316f16330ff67c150960f49e687e90941523eedfd332fc24224739ed2
    9951b91bf8ace61d102b64eac49b8c1b2fd4e56be08b5e359293834b032fe97e
    2a8c76e8408e0d15504e1e9a6426365a3abc40f258cdc11ee8532647a348c82e
    5777721b72226a41306dea580615b3a9b87e6aca355a59c1676cde64630e8e43
    e320e054407aa628fd699c51f6dc063e230c6b531dfb4dbf485280102bf9e918
    f9a0ab32bb3faea7dfe5e30dc762cde359fac2ad47aec08727b3aba7fac90e55
    d75422ea9bdb85d798207f4933173ea51c503a9dfeb0840596692c676f84f8bc
    d6086eead4dbcf264800df1177d01cfb5d2c5c774d614b5f6d263cb64cd174bf
    562103c522892dd6077689cb1a56db39cba38759ad4011dd6d9d701f55a0beee
    57af0620f42fa853d32f190f397129fb17686cdeca68f4ad94cf9dbc74a6c938
    b4d56838
redeem2.nf =
    a0ab32bb3faea7dfe5e30dc762cde359fac2ad47aec08727b3aba7fac90e55d7
~~~

## Redemption Against 5 Anchors {#ihat-tv-redeem5}

~~~
redeem5.index = 3
redeem5.anchor_set =
    03b2a4499ad643cee1225a21b1777586bb309933fd5e7ce6a041d0c685ea43ed
    8102bdc1404aa8e4528c2c0a39224adbfba230b91f379d5fc53a3d658bd673f6
    9afb0282203c62d4dff1f268b01b70d0b47c6ae30ec5482a79a667c7d937ad83
    0334a002780ffa25f6b3c2cdef39d64a847a3bcc03a137696e1a57d984fb486e
    baae74d903f955d5f33ceafc64459ec629d2bf82aa4f72c5b8bf2ae86970147f
    b99d7a2786
redeem5.challenge_digest =
    49484154207465737420766563746f7273206368616c6c656e67652064696765
    7374
redeem5.rand =
    3f35c08f755d907004a5a357b62ecd32f24e3076545f1a625ffbe81e63307899
    60b02229f19d93f6b17f731488995c72f2ea660953aabd8df0dbd67cb175c601
    17b027882f1251240e3681ac2edd0b6264a6298c1120f78010c1c22d4a8e70c0
    d9639c54171618349157efcf43292bf7d915f417f05490371abf23fe03a79c8d
    1b65fea1626e807cc856f008c0a13fbe5e79b4c1ac553607b84b8800a5b40a41
    05d12b072e7433005d0f8f0b1111c921556a1c233d8d7aedc8f3fbda37684bf9
    0d623275838ee926f823907225d68a9a7ef9554dbb7ff3b52ef630aa78ad2a64
    fc6c463d83217c48e88a4dd2d40361aa6e0b1b04145c2b8fb7c450368889c5dd
    a1150544b4cabfc08885cedc13df9c9025b18f33e00ce2bd32e354f710448b76
    74119e9a7330397207807762cba41d01492856053193de68a1250e69faaa5296
    059c82fbd1cc18c3b02783df9758655904829b0f695510bf049bd0d8cc0c161e
    c9fd749aba93c804e0d16deb24d1a2fe9f8816a2903f052badff99e3fc5865a0
redeem5.delta =
    df197ae93fb0d02b9872577b08720d915e5f48d4f70da620d77aaecf3d875fbc
redeem5.message =
    02ccf7d53054c50ba38c35fce6a6b1dbd489e2aa07ca6594a93135318545fb61
    0651b91bf8ace61d102b64eac49b8c1b2fd4e56be08b5e359293834b032fe97e
    2a6f03c282d40e18e54d3ec627ba3fdb8f3d4f79c493bee806422c807c23e266
    8677721b72226a41306dea580615b3a9b87e6aca355a59c1676cde64630e8e43
    e320e054407aa628fd699c51f6dc063e230c6b531dfb4dbf485280102bf9e918
    f9a0ab32bb3faea7dfe5e30dc762cde359fac2ad47aec08727b3aba7fac90e55
    d7e0d18a33b799c1fef2123c4bc5838e4642f1ae6c2031e616851aa173e7738b
    23600c2521c543acb1d1a379a6573f115a44dad79eed5c6e4e1d69b9b6086c35
    e34063028071ef2eb426297682105021e0d2a1eb5211c88bbbacbe271bf35c56
    f527c2e8022842d140f227cbb69e5c88e91f2e97b4c93e971565037b0553b238
    4a59a50f9a03132481ef776b9c424849d57e3d02d27a5c304dcbf97b58aa18ec
    4926d708926740603f510c59a33a9322b213933a235061592e9a7426958a27b7
    871e48535190cceff6b98ca7674cc2c7bc1fb0d3a128d076deabdff9a0c36053
    65fd12adf372250dd1237325de17f4dc2c0394c4a14b627b1c2bc3a393e5a7f6
    832f4d3da25cba9d
redeem5.nf =
    a0ab32bb3faea7dfe5e30dc762cde359fac2ad47aec08727b3aba7fac90e55d7
~~~

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
