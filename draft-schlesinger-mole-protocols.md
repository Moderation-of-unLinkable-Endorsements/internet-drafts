---
title: "MoLE Protocols"
abbrev: "MoLE Protocols"
category: info

docname: draft-schlesinger-mole-protocols-latest
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
  latest: "https://moderation-of-unlinkable-endorsements.github.io/internet-drafts/draft-schlesinger-mole-protocols.html"

author:
 -
    fullname: Thibault Meunier
    organization: Cloudflare
    email: ot-ietf@thibault.uk

normative:
  ACT: I-D.draft-schlesinger-cfrg-act
  ARCHITECTURE: #I-D.draft-schlesinger-mole-architecture
    title: MoLE Architecture
    target: https://moderation-of-unlinkable-endorsements.github.io/internet-drafts/draft-schlesinger-mole-architecture.html
  CRYPTO: #I-D.draft-authors-mole-crypto
    title: MoLE Cryptography
    target: https://moderation-of-unlinkable-endorsements.github.io/internet-drafts/draft-authors-mole-crypto.html
  HTTP-TRANSPORT: #I-D.draft-schlesinger-mole-http-transport
    title: MoLE HTTP Transport
    target: https://moderation-of-unlinkable-endorsements.github.io/internet-drafts/draft-schlesinger-mole-http-transport.html
  LONGFELLOW: I-D.draft-google-cfrg-libzk
  PRIVACYPASS-AUTH: RFC9577
  PRIVACYPASS-BATCHED: I-D.draft-ietf-privacypass-batched-tokens
  PRIVACYPASS-PROTOCOLS: RFC9578
  REVERSE-FLOW: I-D.draft-meunier-privacypass-reverse-flow
  SHA2: RFC6234
  TLS13: RFC8446

informative:
  HIDDEN-ISSUER-CIRCUIT:
    title: "Hidden issuer circuit for longfellow-zk"
    target: https://github.com/thibmeu/longfellow-zk/blob/hidden-issuer-poc/lib/circuits/mdoc/HIDDEN_ISSUER.md

...

--- abstract

This document defines protocols that instantiate the MoLE architecture: two
endorsement protocols, by which a Client proves to a Moderator that it holds
an Endorsement from a trusted Anchor without revealing which one, and three
credential protocols, by which a Moderator issues, verifies, and updates
per-Client state without being able to link presentations. It also
establishes the registries that identify these protocols.


--- middle

# Introduction

The MoLE architecture {{ARCHITECTURE}} defines three roles. Clients obtain
Endorsements from Anchors, redeem them at Moderators in exchange for
Credentials, and present those Credentials to Moderators to access
resources. The architecture states the required properties of Endorsements
and Credentials but does not say how to build them. This document does.

TODO: the protocols below reflect our current understanding of how MoLE
may work, and showcase agility. They are not final. Some may be removed,
others added.

It defines two endorsement protocols and three credential protocols. Each is
identified by a type value from a registry established in this document
({{iana}}). The HTTP carriage of challenges, redemptions, and
presentations is defined in {{HTTP-TRANSPORT}}. This document defines the
messages themselves and, for the grant flow, the HTTP exchanges that carry
them.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

Protocol messages are described in TLS presentation language ({{Section 3 of
TLS13}}). This document also uses the optional-value and variable-size
vector conventions (`optional<T>`, `<V>`) defined in {{HTTP-TRANSPORT}}.
All constants are in network byte order.

This document uses the following terms for protocol actions:

Grant:
: An Anchor gives a Client an Endorsement.

Redeem:
: A Client spends an Endorsement at a Moderator. Each Endorsement can be
  redeemed once.

Issue:
: A Moderator gives a Client a Credential in return for a redemption.

Present:
: A Client shows a Credential to a Moderator. Each Credential can be
  presented once. The update replaces it.

Update:
: The Moderator's adjustment to a presented Credential, returned in the
  same exchange.

Finalize:
: The Client-local step that turns a protocol response into a stored
  Endorsement or Credential.

# Common Requirements {#common}

## Message Types

Every MoLE protocol message MUST begin with a `uint16` type field:
`endorsement_type` for messages in the endorsement flow, `credential_type`
for messages in the credential flow. Values are assigned in the registries
defined in {{iana}}. A recipient that does not recognize the type MUST
ignore the message. A Client that receives a challenge with an unknown type
simply does not respond to it.

The value 0x0000 is reserved in both registries and MUST NOT appear on the
wire. Endorsement type 0x0001 means the Moderator establishes trust in the
Client on its own, and no Endorsement is redeemed.

## Greasing {#greasing}

In order to prevent Moderators from becoming incompatible with future
credential types, Clients SHOULD send presentations whose
`credential_type` is a random value from the reserved greased values
({{iana-grease}}), with some non-trivial probability. The body of a
greased presentation is random bytes.

The greased values follow the pattern 0x?A?A, spread uniformly across the
registry space. Moderators MUST handle them exactly as any other unknown
type and MUST NOT special-case the reserved list: a Moderator that
enumerates greased values defeats their purpose and will still receive
unknown types it did not enumerate.

Additionally, when a credential is not required, Clients SHOULD randomly
choose not to answer a challenge with some non-trivial probability. This
helps ensure that Moderators maintain their behavior for handling Clients
without credentials, rather than relying on a presentation always being
present.

## Challenge Binding {#challenge-binding}

Every redemption and presentation is bound to the challenge that triggered
it. The binding value is:

~~~
challenge_digest = SHA-256(challenge)
~~~

where `challenge` is the challenge structure in its binary form: the
octets of its TLS-presentation encoding. When a challenge arrives
base64url encoded in an HTTP header ({{HTTP-TRANSPORT}}), the Client first
decodes it, then hashes the resulting octets. The digest is never computed
over the ASCII form. SHA-256 is defined in {{SHA2}}.

Each protocol in this document states where `challenge_digest` enters its
messages. A verifier MUST reject a redemption or presentation bound to a
different challenge. This prevents a message captured in one context from
being replayed in another.

In the endorsement protocols, the presentation is a proof generated at
redemption time, and `challenge_digest` is an input to that proof: it
enters the proof transcript in IHAT and the public inputs in Longfellow.
A proof produced for one challenge does not verify under another.
Challenge binding is separate from the nullifier. The nullifier is a PRF
output over a credential-bound secret and the epoch; it limits a Client
to one presentation per epoch.

# Endorsement Protocols {#endorsement-protocols}

An endorsement protocol has two parts. First, the Client runs one or more
request/response exchanges with an Anchor and finalizes the result into an
Endorsement. This is the grant. Second, the Client redeems the Endorsement
at a Moderator, proving it came from an Anchor in the Moderator's accepted
set without revealing which one. Redemption happens inside the Redeem &
Issue flow ({{credential-protocols}}).

~~~ aasvg
+--------+                    +--------+
| Client |                    | Anchor |
+---+----+                    +---+----+
    |                             |
    +--- EndorsementRequest ----->|  \
    |<-- EndorsementResponse -----+  |  one or more
    |            ...              |  /  exchanges
Finalize                          |
    |
    |                        +-----------+
    |                        | Moderator |
    |                        +-----+-----+
    |                              |
    |<-------- Challenge ----------+
    +------- Presentation -------->|
    |                              |
~~~
{: #fig-endorsement-flow title="Endorsement grant and redemption"}

Exchanges with the Anchor are HTTP POST requests. The request body has media
type `application/mole-endorsement-request` and contains an
`EndorsementRequest`. The response body has media type
`application/mole-endorsement-response` and contains an
`EndorsementResponse`. The endorsement type determines how many exchanges
are needed and what the `body` field contains at each step.

~~~ tls-presentation
struct {
  uint16 endorsement_type;
  opaque body<V>;
} EndorsementRequest;

struct {
  uint16 endorsement_type;
  opaque body<V>;
} EndorsementResponse;
~~~

Every endorsement protocol defines two structures. `Challenge` is the
type-specific content of the Moderator's challenge, carried in its
`challenge` field ({{HTTP-TRANSPORT}}). Its content, including any Anchor
set, is opaque at the transport level. Each endorsement type refines it,
for example into a list of accepted Anchor keys. `Presentation` is the protocol's
final output: the message a Client sends to redeem the Endorsement,
carried in the `endorsement_presentation` field of a `CredentialRequest`
({{credential-protocols}}).

## Issuer-Hiding Anonymous Token (IHAT) {#ihat}

Endorsement type: 0x0002.

TODO: IHAT is a placeholder name. Once we have a first version for {{CRYPTO}},
we would align.

IHAT is a pairing-free, issuer-hiding endorsement scheme over P-256. The
Anchor blindly signs a Client-chosen nullifier. The Client later proves,
with a 1-of-n OR proof, that its Endorsement verifies under one of the
Anchor keys the Moderator accepts. The cryptographic operations, and the
contents of every message body, are defined in {{CRYPTO}}. Until that
document is complete, bodies in this section are opaque byte strings
produced and consumed by the functions named below.

The following primitive types are used in this section:

~~~ tls-presentation
opaque Scalar[32];  /* big-endian integer mod the group order */
opaque Point[33];   /* P-256 point, SEC1 compressed */
~~~

### Configuration

The Client needs, from Anchor configuration ({{key-rotation}}):

Anchor Public Key
: `pkA`, a `Point`, as generated in {{CRYPTO}}.

Endorsement Context
: an opaque byte string identifying the current epoch. Endorsements are
  valid for one epoch, see {{key-rotation}}.

### Grant

The grant takes two exchanges with the Anchor.

In the first exchange, the Client runs `Prepare(pkA,
endorsement_context)` ({{CRYPTO}}), keeps the returned client state, and
sends the resulting request as the `body` of an `EndorsementRequest`. The
Anchor runs `Sign(skA, body)`, keeps its own state for the second
exchange, and returns the result in an `EndorsementResponse`.

In the second exchange, the Client runs `RequestProof(state, body)` and
sends the result. The Anchor runs `Prove(state, body)` and returns the
result.

The Client finalizes with `Finalize(state, body)`, which verifies the
Anchor's commitment opening and produces an Endorsement. The Endorsement
contains a nullifier `nf` and the `endorsement_context` it was granted
under. If finalization fails, the Client MUST discard the session. It MUST
NOT retry with the same state.

The Anchor learns neither `nf` nor the final Endorsement, so it cannot
recognize the Endorsement when it is later redeemed.

TODO: the two exchanges must be correlated, since the Anchor holds state
between them. Either {{CRYPTO}} adds a session identifier to its messages
or this document mandates connection reuse.

### Redemption

The Moderator's challenge ({{HTTP-TRANSPORT}}) carries the set of Anchor
keys it accepts:

~~~ tls-presentation
struct {
  Point keys<V>;      /* accepted Anchor public keys */
} Challenge;
~~~

The order of `keys` is significant: OR-proof branches are matched to keys
by position. Moderators MUST present the set in the order published in
their configuration ({{key-rotation}}).

The Client runs `Present(endorsement, keys, challenge_digest)`
({{CRYPTO}}), with `challenge_digest` computed as in {{challenge-binding}},
and sends the result:

~~~ tls-presentation
struct {
  opaque bytes<V>;    /* output of Present */
} Presentation;
~~~

`Present` MUST bind `challenge_digest` into the proof transcript, and
`Verify` MUST fail when given any other `challenge_digest`. This is a
requirement on {{CRYPTO}}.

The Moderator runs `Verify(presentation, keys, challenge_digest)`
({{CRYPTO}}), which exposes `nf` and `endorsement_context`, and
additionally checks that:

1. `endorsement_context` names the current epoch, and
2. `nf` has not been seen before in this epoch.

If all checks pass, the Moderator records `nf` and proceeds with credential
issuance. The Endorsement is spent: redeeming it again MUST fail check 2.

## Longfellow {#longfellow}

Endorsement type: 0x0003.

Where IHAT requires Anchors to run new cryptography, this protocol preserves
backward compatibility with credentials Clients may hold, such as mdocs.
The Client proves in zero knowledge, using the scheme of {{LONGFELLOW}}, that it
holds a valid credential from one of an accepted set of issuers, without
revealing which issuer or any credential attribute. An experimental circuit is
described in {{HIDDEN-ISSUER-CIRCUIT}}.

There is no grant exchange in this protocol. The Client obtains its
credential from the Anchor out of band, through whatever legacy issuance
that credential uses. The circuit is likewise distributed out of band and
identified by its hash.

### Configuration

The Client needs, from Moderator configuration ({{key-rotation}}):

Circuit Identifier
: `circuit_id`, the SHA-256 hash of the circuit both parties use.

Accepted Issuer Set
: the credential-issuer certificates the Moderator accepts, in a fixed
  published order.

Epoch
: the validity window redemptions must fall in.

### Redemption

This protocol needs no type-specific challenge content: `Challenge` is
empty. The accepted issuer set, circuit, and epoch come from configuration.

The Client evaluates the circuit over its credential to produce a proof and
a nullifier. The nullifier is derived, inside the circuit, from a
credential-bound secret and the current epoch, so one credential yields
exactly one valid nullifier per epoch.

~~~ tls-presentation
struct {
  opaque circuit_id[32];
  opaque nullifier<V>;
  opaque proof<V>;
} Presentation;
~~~

The public inputs to the proof are the accepted issuer set, the epoch, the
nullifier, and `challenge_digest` ({{challenge-binding}}). A proof is
valid only for its exact public inputs, so a presentation bound to a
different challenge fails verification. The Moderator
verifies the proof using the verifier of {{LONGFELLOW}}, then applies the
same epoch and nullifier-freshness checks as IHAT redemption.

### Differences from IHAT

While Longfellow does not require the Anchor to actively participate in MoLE,
it is preferred to guarantee and control scarcity. Otherwise, the number of
Endorsements that can be obtained by a given Client is unbounded.
Scarcity comes both from the participation of the Anchor, and from the
one-nullifier-per-epoch rule. Deployments without an aware Anchor remain
possible, but lose Anchor-controlled scarcity.

The required circuit properties, in particular sound nullifier derivation
from a credential-bound secret, are stated here as requirements on the
circuit. {{HIDDEN-ISSUER-CIRCUIT}} is one candidate that could be refined.

# Credential Protocols {#credential-protocols}

A credential protocol has two parts: Redeem & Issue, in which the Client
redeems an Endorsement and receives a Credential from the Moderator, and
presentation, in which the Client shows the Credential and receives an
update. Presentation and update happen in one exchange, following
{{REVERSE-FLOW}}.

~~~ aasvg
+--------+                             +-----------+
| Client |                             | Moderator |
+---+----+                             +-----+-----+
    |                                        |
    |<------------ Challenge ----------------+
    +-- Redemption + CredentialRequest ----->|
    |<-------- CredentialResponse -----------+
Finalize                                     |
    |                                        |
   ...                                       |
    |                                        |
    |<------------ Challenge ----------------+
    +--- Presentation + UpdateRequest ------>|
    |<------------ UpdateResponse -----------+
Finalize                                     |
    |                                        |
~~~
{: #fig-credential-flow title="Redeem & Issue, then presentation and update"}

Both parts ride on HTTP requests to the Moderator, since each is an
authorization. Redeem & Issue carries a `CredentialRequest` in the
`Authorization` header and receives the `CredentialResponse` in the
`Mole-Credential` response header. Presentation uses the same
authentication scheme, with the update returned in the same
`Mole-Credential` header under its `update` parameter. Carriage is
defined in {{HTTP-TRANSPORT}}.

~~~ tls-presentation
struct {
  uint16 endorsement_type;
  opaque endorsement_presentation<V>;
  uint16 credential_type;
  opaque issuance_request<V>;
} CredentialRequest;

struct {
  uint16 credential_type;
  opaque issuance_response<V>;
} CredentialResponse;
~~~

The `endorsement_presentation` field carries the `Presentation` structure
of the named endorsement type. With `endorsement_type` 0x0001 it is empty,
and the Moderator relies on its own trust establishment ({{common}}).

Every credential protocol defines five structures. `Challenge` is the
type-specific content of the Moderator's challenge, carried in its
`challenge` field ({{HTTP-TRANSPORT}}). `IssuanceRequest` and
`IssuanceResponse` fill the `issuance_request` and `issuance_response`
fields above. `PresentationAndUpdate` is carried in the
`presentation_and_update` field of a `CredentialPresentation`
({{HTTP-TRANSPORT}}). `Update` is returned in the `update` parameter of
the `Mole-Credential` header.

## Anonymous Credit Tokens (ACT) {#credential-act}

Credential type: 0x0001.

An ACT credential {{ACT}} is an anonymous state machine: the Moderator can
test a predicate against the Credential's hidden state and update that
state, without learning the state or linking presentations. This is the
credential protocol that provides every property required by
{{ARCHITECTURE}}, including that updates provably apply to the credential
that was presented.

### Configuration

The Moderator publishes its ACT public key and the predicate description
({{key-rotation}}).

### Redeem & Issue

~~~ tls-presentation
struct {
  uint8 truncated_key_id;
  opaque request<V>;
} IssuanceRequest;

struct {
  opaque response<V>;
} IssuanceResponse;
~~~

The `request` and `response` fields are defined in {{ACT}}. The Client
finalizes the response into a Credential with an initial state chosen by
the Moderator's policy.

### Presentation and Update

The Client presents the Credential against the challenged predicate,
spending it, and in the same message requests the replacement that carries
the updated state.

~~~ tls-presentation
struct {
  opaque challenge_digest[32];
  opaque key_id[32];
  opaque spend_proof<V>;
} PresentationAndUpdate;

struct {
  opaque refund<V>;
} Update;
~~~

The `spend_proof` and `refund` fields are defined in {{ACT}}. The
Moderator verifies the spend proof and learns whether the Credential's
hidden state satisfies the challenged predicate. For range-style
predicates, this necessarily reveals the public bound being tested, but
not the hidden state value. The Client finalizes the refund into its new
Credential. ACT guarantees the refund applies to the state that was
presented.

TODO: the exact mapping between the spend and refund operations of {{ACT}}
and MoLE's predicate and update is not settled. In particular, `Challenge`
for this type must express the predicate and the charged amount, and its
contents are not yet defined.

The `Challenge` for this type therefore needs to identify the predicate,
including any public bound, and the update to apply.

## Privacy Pass with a Reverse Flow {#credential-reverse}

Credential type: 0x0002.

The Credential is a single privately verifiable Privacy Pass token. Any
token type registered in the Privacy Pass Token Types registry
({{PRIVACYPASS-PROTOCOLS}}) can be used. The Moderator's configuration
names one. The Credential encodes one bit: the Client either holds a valid
token or it does not. Presentation consumes the token. The update, if
granted, is a fresh token issued through the reverse flow of
{{REVERSE-FLOW}}, with the Moderator acting as both initial and reverse
issuer.

The presented and reissued token MUST use the same token type and the same
Moderator public key. Anything else partitions Clients and leaks state.

### Redeem & Issue

`IssuanceRequest` is a `TokenRequest` and `IssuanceResponse` is a
`TokenResponse`, both as defined for the configured token type in
{{PRIVACYPASS-PROTOCOLS}}. The finalized token is the Credential.

### Presentation and Update

`Challenge` is empty for this type. Binding comes from the `Token`
structure below.

~~~ tls-presentation
struct {
  opaque token<V>;
  opaque token_request<V>;  /* TokenRequest */
} PresentationAndUpdate;

struct {
  opaque token_response<V>; /* TokenResponse */
} Update;
~~~

The `token` field carries a `Token` as defined in {{PRIVACYPASS-AUTH}}.
Challenge binding comes from the `Token` structure itself: its
`challenge_digest` field MUST equal the digest of the Moderator's
challenge ({{challenge-binding}}).

If the Moderator's policy allows continued access, it returns an `Update`.
If not, it returns an empty update and the Client is out of credentials.

### Limitations

TODO: define a device binding mechanism, issuing tokens bound to a Client
key so that presentation requires proof of possession. This would restore
the binding between update and presented credential. Open problem.

## Budget Privacy Pass {#credential-budget}

Credential type: 0x0003.

The Credential is a balance, represented as Privacy Pass tokens drawn from
N issuers operated by the same Moderator, where issuer i denominates 2^i
units. Tokens are issued in batches using {{PRIVACYPASS-BATCHED}}, and any
token type registered in the Privacy Pass Token Types registry that
supports batched issuance can be used. The Client presents whatever tokens
it wants, and the sum of their denominations is the amount spent. The
Moderator returns change and any policy adjustment as freshly issued
tokens through the reverse flow, summing to the intended new balance.

A presentation reveals that the Client can spend the challenged amount. If
the protocol presents exactly one token for that amount, and balance
management remains Client-local, this is the same disclosure as an ACT
predicate over that amount: the Moderator learns the predicate result, not
the Client's remaining balance. Deployments that allow multiple tokens,
variable denominations, or observable change shapes need padding or another
mitigation.

### Redeem & Issue

`IssuanceRequest` is a `BatchTokenRequest` and `IssuanceResponse` is a
`BatchTokenResponse` ({{PRIVACYPASS-BATCHED}}), for tokens summing to the
initial balance set by the Moderator's policy.

### Presentation and Update

The challenge indicates the amount to spend:

~~~ tls-presentation
struct {
  uint64 amount;
} Challenge;
~~~

The `amount` is an indicator, not a per-Client value. A Moderator MUST
use the same amount for every Client under a policy: varying it
partitions Clients. Deployments MAY publish the amount out of band
instead ({{key-rotation}}), in which case the field repeats the published
value.

~~~ tls-presentation
struct {
  opaque tokens<V>;         /* one or more Tokens */
  opaque token_request<V>;  /* BatchTokenRequest */
} PresentationAndUpdate;

struct {
  opaque token_response<V>; /* BatchTokenResponse */
} Update;
~~~

Challenge binding comes from each `Token` structure, as in
{{credential-reverse}}. The Client MAY at any time exchange several small
tokens for larger ones at the Moderator's refund endpoint.

### When to use it

Balances with many possible values need many tokens and padding traffic to
avoid leaking through request counts. If the state fits an ACT credential,
{{credential-act}} is simpler and leaks less. This protocol fits
deployments that already run Privacy Pass issuers and need only coarse
balances.

# Key Rotation and Discovery {#key-rotation}

TODO.

Anchors and Moderators each publish a configuration that Clients fetch
before running any flow. It contains their endpoints, supported endorsement
and credential types, public keys, and, for Moderators, the accepted Anchor
set for each policy. The order of the accepted set is normative: IHAT
OR proofs and Longfellow issuer sets match elements by position, so all
parties must see the same order.

Endorsements live in epochs. The `endorsement_context` of IHAT and the
epoch of Longfellow name the epoch an Endorsement is granted in, which is
also the window the Moderator's nullifier store covers. Epoch length is a
privacy parameter: short epochs shrink the double-spend store but
partition Clients into smaller anonymity sets. See {{ARCHITECTURE}} for
the consistency requirements on configuration. A Moderator that shows
different configurations to different Clients can partition them.

Open questions:

1. Format: a Privacy Pass style directory, or JWKS. Reusing JWKS matters if
   deployments want existing key-management tooling, despite feelings.
2. How and when Anchor and Moderator keys rotate.
3. Whether messages carry a key identifier, such as a truncated key
   identifier as in Privacy Pass token requests, or a JWK Thumbprint.
4. How Clients validate Moderator configuration without revealing
   themselves, and how consistency is audited.

# Privacy Considerations {#privacy-considerations}

TODO. The list to cover:

1. Anchor set verification: the Client must be able to verify the number
   of Anchors in an accepted set, and that these Anchors are real rather
   than fabricated by the Moderator. A set padded with fake Anchors
   shrinks the effective anonymity set to the Clients of the real ones.
2. Configuration partitioning: accepted-set contents and order as a
   fingerprinting vector (with {{ARCHITECTURE}}).
3. Epoch width versus anonymity set size.

# Security Considerations {#security-considerations}

All exchanges defined in this document and {{HTTP-TRANSPORT}} MUST be
carried over HTTPS.

TODO. The list to cover:

1. Nullifier store sizing and eviction: the store is per epoch, and a
   Moderator that evicts early re-admits spent Endorsements.
2. Anchor key compromise: an attacker with an Anchor key in an accepted set
   can mint Endorsements freely. Blast radius and rotation response.
3. Reverse-flow update transfer: the two-credential attack of
   {{credential-reverse}}, and why single-credential enforcement cannot be
   verified.
4. Timing and error side channels during verification, especially
   distinguishing "bad proof" from "spent nullifier".

# IANA Considerations {#iana}

This document sketches two candidate registries under a future "MoLE"
group. The values below are candidate values for discussion in this -00
draft and are not stable assignments.

A registration MUST define the per-type structures its flow requires:
`Challenge` and `Presentation` for endorsement types
({{endorsement-protocols}}), and `Challenge`, `IssuanceRequest`,
`IssuanceResponse`, `PresentationAndUpdate`, and `Update` for credential
types ({{credential-protocols}}). Every message begins with the registered
`uint16` type ({{common}}). A registration MUST also state how redemption
or presentation binds `challenge_digest` ({{challenge-binding}}).

## MoLE Endorsement Types

| Value           | Name                          | Reference      |
|:----------------|:------------------------------|:---------------|
| 0x0000          | Reserved                      | this document  |
| 0x0001          | Moderator trust establishment | {{common}}     |
| 0x0002          | IHAT                          | {{ihat}}       |
| 0x0003          | Longfellow                    | {{longfellow}} |
| 0xFF00 - 0xFFFF | Reserved for testing          | this document  |
{: #endorsement-types title="Candidate MoLE Endorsement Type Values"}

The registration template contains:

* Value: The two-byte endorsement type.
* Name: A short name for the protocol.
* Exchanges: The number of request/response exchanges with the Anchor, or
  "none" if the grant is out of band.
* Publicly Verifiable: Whether the Endorsement can be verified without
  Anchor secret key material.
* Reference: Where the protocol is defined.

The following initial registrations are candidates only.

### IHAT {#iana-ihat}

* Value: 0x0002
* Name: IHAT
* Exchanges: 2
* Publicly Verifiable: Yes
* Reference: {{ihat}}

### Longfellow {#iana-longfellow}

* Value: 0x0003
* Name: Longfellow
* Exchanges: none (out of band)
* Publicly Verifiable: Yes
* Reference: {{longfellow}}

## MoLE Credential Types

| Value           | Name                       | Reference             |
|:----------------|:---------------------------|:----------------------|
| 0x0000          | Reserved                   | this document         |
| 0x0001          | ACT                        | {{credential-act}}    |
| 0x0002          | Privacy Pass Reverse Flow  | {{credential-reverse}} |
| 0x0003          | Budget Privacy Pass        | {{credential-budget}} |
| 0x0A0A, 0x1A1A, ..., 0xFAFA | Reserved for greasing | {{greasing}} |
| 0xFF00 - 0xFFFF | Reserved for testing       | this document         |
{: #credential-types title="Candidate MoLE Credential Type Values"}

The registration template contains:

* Value: The two-byte credential type.
* Name: A short name for the protocol.
* Bound Update: Whether updates provably apply to the presented
  credential.
* Reference: Where the protocol is defined.

### ACT {#iana-act}

* Value: 0x0001
* Name: ACT
* Bound Update: Yes
* Reference: {{credential-act}}

### Privacy Pass Reverse Flow {#iana-reverse}

* Value: 0x0002
* Name: Privacy Pass Reverse Flow
* Bound Update: No
* Reference: {{credential-reverse}}

### Budget Privacy Pass {#iana-budget}

* Value: 0x0003
* Name: Budget Privacy Pass
* Bound Update: No
* Reference: {{credential-budget}}

### Greased Values {#iana-grease}

* Value: 0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
  0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA
* Name: RESERVED
* Bound Update: N/A
* Reference: {{greasing}}

These values MUST NOT be assigned. Message bodies carrying them contain
random bytes ({{greasing}}).

## Media Types

| Media Type                            | Reference                 |
|:--------------------------------------|:--------------------------|
| application/mole-endorsement-request  | {{endorsement-protocols}} |
| application/mole-endorsement-response | {{endorsement-protocols}} |
{: #media-types-table title="MoLE Media Types"}

TODO: full registration templates, following the Privacy Pass template.


--- back

# Example {#example}

A Client requests a resource protected by a Moderator that uses credential
type 0x0002 (Privacy Pass Reverse Flow) and accepts endorsement type
0x0002 (IHAT).

~~~ aasvg
+--------+         +--------+      +-----------+
| Client |         | Anchor |      | Moderator |
+---+----+         +---+----+      +-----+-----+
    |                  |                 |
    +------------------|---- request --->|
    |<-----------------|--- challenge ---+
    +--- exchange 1 -->|                 |
    |<-- response 1 ---+                 |
    +--- exchange 2 -->|                 |
    |<-- response 2 ---+                 |
Finalize               |                 |
    +------------------|---- redeem ---->|
    |<-----------------|---- credential -+
Finalize               |                 |
    +------------------|---- present --->|
    |<-----------------|-- ok + update --+
    |                  |                 |
~~~
{: #fig-example title="Complete exchange"}

The Moderator challenges the Client:

~~~
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Mole challenge="<credential-challenge>",
                       realm="moderator"
~~~

The Client holds no Credential for this Moderator, so it first obtains an
Endorsement. It runs the two IHAT exchanges against the Anchor:

~~~
POST /mole/endorse HTTP/1.1
Host: anchor.example
Content-Type: application/mole-endorsement-request

EndorsementRequest { 0x0002, Prepare(...) }
~~~

The Anchor answers each POST with an
`application/mole-endorsement-response` body, and the Client finalizes the
Endorsement.

The Client then runs Redeem & Issue. It repeats its request, this time
carrying a `CredentialRequest` that redeems the Endorsement bound to the
Moderator's challenge together with a Privacy Pass TokenRequest:

~~~
GET /resource HTTP/1.1
Host: moderator.example
Authorization: Mole credential-request="<credential-request>"
~~~

The Moderator verifies the redemption, records its nullifier, and returns
a `CredentialResponse` carrying a TokenResponse in the `Mole-Credential`
header, alongside its unchanged challenge. The Client finalizes it into a
token and answers the challenge:

~~~
GET /resource HTTP/1.1
Host: moderator.example
Authorization: Mole presentation="<credential-presentation>"
~~~

The Moderator verifies the presentation and serves the resource. Its
response carries a `Mole-Credential` header whose `update` parameter
holds a fresh token, or an absent update if it chose to consume the
Credential.

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
