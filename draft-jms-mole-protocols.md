---
title: "MoLE Protocols"
abbrev: "MoLE Protocols"
category: info

docname: draft-jms-mole-protocols-latest
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
  latest: "https://moderation-of-unlinkable-endorsements.github.io/internet-drafts/draft-jms-mole-protocols.html"

author:
 -
    fullname: Samuel Schlesinger
    organization: Google LLC
    email: sgschlesinger@gmail.com
 -
    fullname: Dennis Jackson
    organization: Mozilla
    email: ietf@dennis-jackson.uk
 -
    fullname: Thibault Meunier
    organization: Cloudflare
    email: ot-ietf@thibault.uk

normative:
  ACT:
    title: "Anonymous Credit Tokens (ACT)"
    target: https://moderation-of-unlinkable-endorsements.github.io/internet-drafts/draft-authors-mole-act.html
  ARCHITECTURE: I-D.draft-jms-mole-architecture
  CDDL: RFC8610
  IHAT-ROLLATINI:
    title: "Rollatini: An Issuer-Hiding Anonymous Token"
    target: https://moderation-of-unlinkable-endorsements.github.io/internet-drafts/draft-authors-mole-ihat-rollatini.html
  HTTP-TRANSPORT: I-D.draft-jms-mole-http-transport
  IANA: RFC8126
  LONGFELLOW: I-D.draft-google-cfrg-libzk
  QUIC: RFC9000
  PRIVACYPASS-AUTH: RFC9577
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
an Endorsement from a trusted Anchor without revealing which one, and two
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

It defines two endorsement protocols and two credential protocols. Each is
identified by a type value from a registry established in this document
({{iana}}). The HTTP carriage of challenges, requests, redemptions, and
presentations is defined by {{HTTP-TRANSPORT}}. This document defines the
messages themselves and, for the grant flow, the HTTP exchanges that carry
them.

TODO: the protocols below reflect our current understanding of how MoLE
may work, and showcase agility. They are not final. Some may be removed,
others added.

An Endorsement establishes eligibility for Credential issuance under the
Moderator's policy. It does not directly authorize resource access. A fresh
Credential acceptance authorizes one attempt of the protected operation
within the deployment's replay protection scope, not successful execution.
ACT binds the presentation to its Challenge, whose contents determine the
operation binding. Reverse flow provides bearer authorization under a
configured token Challenge, without binding the replacement request to the
holder of the presented token.

An accepted presentation either replaces the Credential or ends its chain.
A missing response leaves that decision unknown. Presentation recovery
returns the recorded decision, not another authorization. These properties depend on
the construction and replay scope below. {{ARCHITECTURE}} describes the
trust relationships, anonymity sets, configuration consistency, and side
channels. Cryptographic issuer hiding and unlinkability do not remove those
deployment dependencies.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

Binary payloads and hash inputs use TLS presentation language ({{Section 3 of
TLS13}}). `opaque x<V>` is a vector whose length prefix
is the variable-length integer of {{Section 16 of QUIC}}, in its shortest
encoding. A recipient MUST reject a non-shortest length or trailing bytes.
All constants are in network byte order.

This document uses the following terms for protocol actions:

Grant:
: An Anchor gives a Client an Endorsement.

Redeem:
: A Client proves possession of an Endorsement to a Moderator. The endorsement
  protocol defines the redemption scope and consequences of reuse. A Client
  SHOULD NOT redeem the same Endorsement at a second Moderator because reuse
  can make its activity linkable.

Issue:
: A Moderator gives a Client a Credential in return for a redemption.

Present:
: A Client shows a Credential to a Moderator. Each Credential can be accepted
  once within the Moderator's configured replay protection scope, with or
  without replacement.

Update:
: The Moderator's adjustment to a presented Credential, returned in the
  same exchange.

Finalize:
: The Client-local step that turns a protocol response into a stored
  Endorsement or Credential.

# Common Requirements {#common}

## Message Types

Endorsement and credential types are `uint16` values assigned in {{iana}}.
HTTP carries them in parameter suffixes or grant media-type parameters, not
inside payload wrappers. A Client ignores an unknown Challenge. An unknown request
or response is rejected. A Moderator treats an unknown optional presentation
as absent and rejects an unknown required presentation. Moderator Challenge
material is never sent to an Anchor by the Client.

The value 0x0000 is reserved in both registries and MUST NOT appear on the
wire. Endorsement type 0x0001 means that no Endorsement is required.

These canonical Challenge encodings are hash inputs, not HTTP payload
wrappers. Both parties reconstruct them from the selected type and decoded
type-specific payload, preserving the cryptographic transcripts:

~~~ tls-presentation
struct {
  uint16 endorsement_type;
  opaque challenge<V>;      /* RedemptionChallenge */
} ModeratorChallenge;

struct {
  uint16 credential_type;
  opaque challenge<V>;      /* type-specific Challenge */
} CredentialChallenge;
~~~

Each encoding is the two-byte type in network order, the shortest QUIC
variable-length integer encoding of the body length, then the body. For
`ModeratorChallenge` the type is the endorsement type. For `CredentialChallenge`
it is the credential type. Hashes cover these bytes, never HTTP parameter
names, quoting, or base64url text. This document defines no alternative
non-HTTP transport. The canonical encodings do not negotiate one.

## Greasing {#greasing}

In order to prevent Moderators from becoming incompatible with future
credential types, Clients SHOULD send presentations whose selected type is a
random value from the reserved greased values ({{iana-grease}}), with some
non-trivial probability. The body of a greased presentation is random bytes. A
Moderator handles it as if no Credential were presented.

The greased values follow the pattern 0x?A?A, spread uniformly across the
registry space. Moderators MUST handle them exactly as any other unknown type
and MUST NOT special-case the reserved list. A Moderator that enumerates
greased values defeats their purpose and will still receive unknown types it
did not enumerate.

Additionally, when a credential is not required, Clients SHOULD randomly
choose not to send a presentation with some non-trivial probability. This
helps ensure that Moderators maintain their behavior for handling Clients
without credentials, rather than relying on a presentation always being
present.

## Challenges and Contexts {#challenges-and-contexts}

A Moderator Challenge is a message sent by a Moderator to a Client. It selects
the operation and carries any type-specific input chosen by the Moderator.
A Moderator Challenge, or a value derived from it, MUST NOT be sent to an
Anchor. Clients enforce this separation in their grant requests. It does
not prevent a colluding Moderator from disclosing its own Challenge.

A Context is a protocol-specific cryptographic input. A protocol defines how
the Client and Moderator derive the same Context from authenticated
configuration, the operation, and, when required, the Moderator Challenge. A
Context can include the complete Moderator Challenge, a digest of it, or
selected fields. Moderator Challenge and Context are therefore not
interchangeable terms.

Each credential protocol defines the contents of its type-specific
`CredentialChallenge` body. Endorsement protocols use the common Challenge in
{{challenge-binding}}. For a new operation, a Moderator MUST be able to
verify, from retained state or by recomputing the Challenge, that a response
uses a Challenge it issued and that remains valid. A credential protocol can return an already accepted result after its
Challenge expires, without authorizing a new operation
({{act-missing-refund}}).

# Endorsement Protocols {#endorsement-protocols}

An endorsement protocol has two parts. First, before contacting a Moderator,
the Client runs one or more
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
    +----- grant request ------->|  \
    |<---- grant response -------+  |  one or more
    |            ...              |  /  exchanges
Finalize                          |
    |
    |                        +-----------+
    |                        | Moderator |
    |                        +-----+-----+
    |                              |
    |<-------- Challenge ----------+
    +-------- Redemption --------->|
    |                              |
~~~
{: #fig-endorsement-flow title="Endorsement grant and redemption"}

Exchanges with the Anchor are HTTP POST requests carrying the type-specific
grant messages directly, as specified in {{HTTP-TRANSPORT}}. The endorsement
type determines how many exchanges are needed and the message at each step.

The Anchor returns 200 (OK) with the response media type only when it produced
a complete grant response. A Client MUST reject a non-success status, an
unexpected media type, a response whose type differs from its request, trailing
bytes, or malformed type-specific content. Clients MUST NOT automatically
redirect a grant POST carrying protocol state.

Every endorsement protocol defines a `Redemption` structure. It is the message
a Client sends to redeem the Endorsement, carried in the
`endorsement_presentation` field of a `CredentialRequest`
({{credential-protocols}}).

## Redemption Challenge Binding {#challenge-binding}

The type-specific body of `ModeratorChallenge` is:

~~~ tls-presentation
struct {
  opaque redemption_context[32];
} RedemptionChallenge;
~~~

The structure fields are:

* `redemption_context` scopes the redemption. The Moderator constructs it
  and the Client uses it as received. It MUST distinguish the Moderator and
  the policy it issues under, and SHOULD distinguish a time window.

The Client does not send the challenge back. The Moderator either keeps the
challenges it sends or recomputes `redemption_context` when a request
arrives, for instance as an authenticated encoding of its origin, policy,
and time window, trying adjacent windows.

Endorsement protocols compute the following value when creating or verifying
a redemption:

~~~
challenge_digest = SHA-256(moderator_challenge)
~~~

The values are defined as follows:

* `moderator_challenge` is the canonical `ModeratorChallenge` reconstructed
  from the selected endorsement type and decoded challenge payload ({{common}}).
  It is not required to contain an origin.
* `challenge_digest` is the 32-octet SHA-256 digest of
  `moderator_challenge`. It is not computed over a base64url or other textual
  encoding. SHA-256 is defined in {{SHA2}}.

`challenge_digest` enters the Fiat-Shamir transcript in both Rollatini and
Longfellow, but is not a Longfellow circuit public input. A redemption created
for one `ModeratorChallenge` does not verify under another, so a Moderator
that accepts only the `redemption_context` it constructs rejects a
redemption made under another Moderator's challenge. This does not stop a
Moderator that relays another Moderator's challenge to the Client.

The `Challenge` algorithm and `ChallengeMessage` in Rollatini issuance are
defined by {{IHAT-ROLLATINI}} and are unrelated to a `ModeratorChallenge`.

## Abstract Endorsement API

Each endorsement protocol defines these abstract operations:

~~~
RedeemRequest(endorsement, moderator_challenge, configuration)
  -> redemption | INVALID
FinalizeRedeem(redemption, moderator_challenge, configuration)
  -> replay_protection_ids | INVALID
~~~

`RedeemRequest` runs at the Client. `FinalizeRedeem` runs at the Moderator,
verifies the redemption and Challenge binding, and returns a possibly empty
set of `replay_protection_ids` or `INVALID`. Both operations derive
`challenge_digest` from `moderator_challenge` as specified above. The
Moderator MUST atomically insert every returned identifier in the protocol's
configured replay protection scope, each only if absent. If any is already
present, the Moderator MUST treat the result as `INVALID` and MUST NOT issue
a Credential for the accompanying `IssuanceRequest`. There is no global
replay protection service. The Moderator MUST retain an identifier while the
Endorsement it came from can still verify, independently of credential key or
context rotation.

## No Endorsement Required {#no-endorsement-required}

Endorsement type 0x0001 indicates that the Moderator does not require an
Endorsement under its policy. It has no grant. The `endorsement` input and
`Redemption` are both the distinguished empty value. `RedeemRequest` returns
that empty value. `FinalizeRedeem` returns the empty set when the
Moderator's policy permits issuance without an Endorsement, and `INVALID`
otherwise. How often a Client can obtain a Credential this way is up to
Moderator policy, for instance rate limiting.

## Rollatini {#rollatini}

Endorsement type: 0x0002.

This protocol uses Rollatini {{IHAT-ROLLATINI}}, a pairing-free Issuer-Hiding
Anonymous Token (IHAT). The Anchor blindly signs a
Client-chosen nullifier. The Client later proves,
with an issuer-hiding proof, that its Endorsement verifies under one of the
Anchor keys the Moderator accepts. The cryptographic operations, and the
contents and encodings of every message body, are defined in {{IHAT-ROLLATINI}}.

The following primitive types are ciphersuite-dependent:

~~~ tls-presentation
opaque Scalar[Ns];
opaque Element[Ne];
~~~

### Configuration

The Client needs, from Anchor configuration ({{key-rotation}}):

Rollatini Ciphersuite
: A ciphersuite identifier defined by {{IHAT-ROLLATINI}}. It determines
  `Element`, `Scalar`, and all cryptographic encodings.

Anchor Public Key
: `pkA`, an `Element`, as generated in {{IHAT-ROLLATINI}}. An Anchor has one
  key per grant endpoint.

Issuance Context
: `ctx_iss`, the issuance epoch the Anchor currently issues under. It is an
  opaque byte string. Endorsements are valid for that epoch, see
  {{key-rotation}}.

Redemption Context
: `ctx_red`, the ASCII string `"MoLE-Rollatini-ctx_red-v1"`, without a
  terminating NUL byte. This fixed, domain-separated value is the same for all
  Moderators. This is the cryptographic redemption Context defined by
  {{IHAT-ROLLATINI}}, not a Moderator Challenge. A specific redemption operation
  is bound separately by `challenge_digest`.

### Grant

The grant takes two HTTP exchanges and three protocol messages. The Anchor
speaks first, as specified by {{IHAT-ROLLATINI}}:

1. The Client sends a grant POST with empty content. The Anchor
   runs `Commit(ctx_iss)`, stores the returned state under a fresh
   `session_id`, and returns a `CommitMessage` in the response body.
2. The Client runs `Challenge(pkA, ctx_iss, ctx_red, commitment)`, stores the
   returned state, and sends a `ChallengeMessage` containing the returned
   issuance challenge and opaque `session_id`. The Anchor atomically claims and
   consumes that identifier before reading the single-use state. Only the
   instance that wins the claim runs `Respond(skA, state, challenge)` and
   returns a `ResponseMessage`.
   Tombstones are retained through session expiry. All later requests for the
   identifier fail without invoking `Respond`.
3. The Client runs `Finalize(pkA, state, response)` as specified by
   {{IHAT-ROLLATINI}}. On failure it MUST discard the session state and MUST NOT
   retry with that state. If the second response is lost, the Client starts
   a fresh grant.

`CommitMessage`, `ChallengeMessage`, `ResponseMessage`, `session_id`, and the
Endorsement encoding are defined by {{IHAT-ROLLATINI}}. The session identifier
is only transport correlation and is not bound into the Endorsement.

The Anchor learns neither `nf` nor the final Endorsement. Under the statistical
blindness claim in {{IHAT-ROLLATINI}}, its protocol transcript does not let it
recognize the Endorsement when it is later redeemed. Timing, network, and
configuration metadata are outside that claim.

### Redemption

The type-specific `Redemption` payload is the encoding of `Redemption` in
{{IHAT-ROLLATINI}}. `RedeemRequest` derives `challenge_digest` as in
{{challenge-binding}} and calls
`Redeem(anchor_set, index, endorsement, ctx_iss, ctx_red, challenge_digest)`.
The Client uses the Moderator's accepted Anchor set for the `ctx_iss` its
Endorsement was issued under ({{key-rotation}}). `index` is the position of
the entry whose key equals the issuing `pkA`. The Client fails if no set has
that `ctx_iss` or the set omits its Anchor.

The `Redemption` does not carry `ctx_iss`. `FinalizeRedeem` checks that the
Moderator Challenge is accepted. Then, for each accepted Anchor set until one
succeeds, it decodes the payload against that set, since the decoding depends
on its size, and calls
`VerifyRedemption(anchor_set, redemption, ctx_iss, ctx_red, challenge_digest)`.
It returns `{nf}`, scoped to the matching `ctx_iss` in the Moderator's store,
or `INVALID` if decoding or verification fails under every set.
The common replay protection rules apply before Credential issuance. The
same `nf` is exposed on repeated redemptions, including across Moderators;
the scheme does not enforce global single use.

## Longfellow {#longfellow}

Endorsement type: 0x0003.

Where Rollatini requires Anchors to run new cryptography, this protocol
preserves backward compatibility with credentials Clients may hold, such as
mdocs. The Client proves in zero knowledge, using the scheme of {{LONGFELLOW}},
that it holds a valid credential from one of an accepted set of issuers, without
revealing which issuer or any credential attribute. An experimental circuit is
described in {{HIDDEN-ISSUER-CIRCUIT}}.

There is no grant exchange in this protocol. The Client obtains its
credential from the Anchor out of band, through whatever legacy issuance
that credential uses, before contacting a Moderator. A compressed circuit
artifact containing the two Longfellow circuits is likewise distributed out
of band and identified by its hash.

### Configuration

The Client needs, from Moderator configuration ({{key-rotation}}):

Circuit Artifact Identifier
: `circuit_artifact_id`, the SHA-256 hash of the compressed circuit artifact
  both parties use.

Circuit Manifest
: An out-of-band manifest that names the artifact version, the two circuit
  identifiers, and all proof parameters needed to interpret and verify it.

Accepted Issuer Set
: the credential-issuer certificates the Moderator accepts, in a fixed
  published order.

Epoch
: the validity window redemptions must fall in.

Moderator Origin
: the canonical origin of the Moderator. Its source is trusted configuration.
  It MUST NOT be derived from a client-controlled HTTP `Host` value.

Verification Time
: `verification_time`, a Moderator-selected time within the current epoch.

### Redemption

The accepted issuer set, circuit artifact, epoch, Moderator origin, and
verification time come from authenticated configuration. The selected
redemption operation supplies the digest of the reconstructed canonical
`ModeratorChallenge` as `challenge_digest`, as defined in
{{challenge-binding}}.

The Client evaluates the two circuits over its credential to produce a proof
and a nullifier. The nullifier is derived, inside the circuit, from a
credential-bound secret, the canonical Moderator origin, and the current
epoch. One credential therefore yields exactly one valid nullifier per
Moderator origin and epoch.

~~~ tls-presentation
struct {
  opaque circuit_artifact_id[32];
  opaque nullifier<V>;
  opaque proof<V>;
} Redemption;
~~~

The structure fields are:

* `circuit_artifact_id` is the SHA-256 digest of the configured circuit
  artifact.
* `nullifier` is the circuit-produced replay protection identifier.
* `proof` is the encoded Longfellow proof.

The circuit public inputs are the accepted issuer set, epoch, canonical
Moderator origin, `verification_time`, and nullifier. The proof establishes
`validFrom <= verification_time <= validUntil`. `challenge_digest`
({{challenge-binding}}) is bound into the Longfellow Fiat-Shamir transcript.
It is not a circuit public input.

Longfellow implements the common API in {{endorsement-protocols}}.
`RedeemRequest` checks that the artifact and manifest match configuration,
evaluates the circuits, and returns the encoded `Redemption` above.
`FinalizeRedeem` checks the artifact identifier, verifies the proof and its
transcript binding, and checks that the configured epoch and
`verification_time` remain current. It returns `{nullifier}`, or `INVALID`
on any failure. Both operations derive `challenge_digest` from
`moderator_challenge`. The common caller performs the
atomic replay protection check.

### Differences from Rollatini

Longfellow does not inherently require an Anchor to change its issuance
protocol. Scarcity then depends on the legacy credential's own issuance limits
and on whether it contains a credential-bound Client secret suitable for
nullifier derivation. An Anchor that participates in MoLE can control scarcity
and arrange for such a secret to be committed during issuance. Some existing
credential formats may already provide a suitable Client-contributed or
device-bound secret. The one-nullifier-per-origin-and-epoch rule lets the
Moderator prevent repeat redemption within its replay protection scope. The
legacy credential remains usable at other Moderator origins and in later
epochs. This does not limit how many credentials a Client can obtain.

> **Editor note.** This protocol is blocked on normative circuit definitions,
> public-input encodings and ordering, transcript binding, artifact lifecycle
> and size limits, and test vectors.

# Credential Protocols {#credential-protocols}

A credential protocol has two parts. In Redeem & Issue, the Client redeems an
Endorsement and receives a Credential from the Moderator. In Presentation and
Update, the Client shows the Credential and receives an update in the same
exchange.

~~~ aasvg
+--------+                             +-----------+
| Client |                             | Moderator |
+---+----+                             +-----+-----+
    |                                        |
    |<--------- ModeratorChallenge ----------+
    +--- Redemption + IssuanceRequest ------>|  HTTP request
    |<---------- IssuanceResponse -----------+
Finalize                                    |
    |                                        |
   ...                                       |
    |                                        |
    |<-------- CredentialChallenge ----------+
    +-------- PresentationAndUpdate -------->|
    |<-------------- Update? ----------------+
Finalize                                    |
    |                                        |
~~~
{: #fig-credential-flow title="Redeem & Issue, then presentation and update"}

Redeem & Issue carries a redemption and an issuance request. The Moderator
runs the endorsement protocol's `FinalizeRedeem` before accepting issuance.
Presentation carries `PresentationAndUpdate` and returns `Update` or a recorded
`NoUpdate` decision. {{HTTP-TRANSPORT}} carries these payloads directly.

`CredentialRequest` names the pair of Redeem & Issue payloads. HTTP carries
them as two typed parameters, not as this encoding:

~~~ tls-presentation
struct {
  uint16 endorsement_type;
  opaque endorsement_presentation<V>; /* encoded Redemption */
  uint16 credential_type;
  opaque issuance_request<V>;
} CredentialRequest;
~~~

The structure fields are:

* `endorsement_type` identifies the endorsement protocol.
* `endorsement_presentation` is its encoded `Redemption`. It is empty for
  endorsement type 0x0001 ({{no-endorsement-required}}).
* `credential_type` identifies the credential protocol.
* `issuance_request` is its encoded `IssuanceRequest`.

`CredentialResponse` below means the selected credential type and its encoded
`IssuanceResponse`. HTTP carries the type in its response
parameter suffix. The Client MUST reject a type that differs from its request.

All credential protocols define the same four payloads:

IssuanceRequest
: A Client-generated request for a new Credential.

IssuanceResponse
: The Moderator's response to `IssuanceRequest`.

PresentationAndUpdate
: A presentation of a Credential and any request needed to replace or update
  it.

Update
: The Moderator's response to `PresentationAndUpdate`, when the Client remains
  eligible for a Credential.

HTTP carries these type-specific encodings without additional wrappers.

## Abstract Credential API

Each credential protocol defines these abstract operations:

~~~
CreateIssuanceRequest(moderator_challenge, configuration)
  -> (issuance_state, issuance_request) | INVALID
IssueCredential(issuance_request, moderator_challenge, policy, configuration)
  -> issuance_response | INVALID
FinalizeIssuance(issuance_state, issuance_response, configuration)
  -> credential | INVALID

CreatePresentationAndUpdate(credential, credential_challenge, configuration)
  -> (presentation_state, presentation_and_update) | INVALID
ProcessPresentation(
    presentation_and_update, credential_challenge, policy, configuration)
  -> INVALID
   | ACCEPTED_NO_UPDATE(fresh)
   | ACCEPTED_WITH_UPDATE(update, fresh)
FinalizeUpdate(presentation_state, update, configuration)
  -> credential | INVALID
~~~

`CreateIssuanceRequest`, `FinalizeIssuance`, `CreatePresentationAndUpdate`, and
`FinalizeUpdate` run at the Client. `IssueCredential` and `ProcessPresentation`
run at the Moderator. State values are local and are not sent on the wire.
`ACCEPTED_NO_UPDATE` means that the presentation succeeded but the Credential
was consumed without replacement. `ACCEPTED_WITH_UPDATE` carries the encoded
`Update` that the Client finalizes into its replacement Credential by calling
`FinalizeUpdate`. The Client does not call `FinalizeUpdate` for
`ACCEPTED_NO_UPDATE`. A complete protocol specification defines its Context
derivation, replay protection, and retry behavior. The Moderator completes that
replay protection before returning an accepted result. `fresh` is true when
this call recorded the result, and false when it returns a result already
recorded for a retry. Only a fresh result authorizes one attempt of the
protected operation within the replay protection scope. It does not establish
that the operation completed. `ACCEPTED_NO_UPDATE` ends this Credential's
chain, not other Credentials the Client may hold. A missing response or an
unavailable recovery result does not establish `ACCEPTED_NO_UPDATE`.

| Presentation outcome | Credential result | Protected operation |
|---|---|---|
| Rejected before acceptance | No committed replacement decision | Not attempted |
| Acceptance uncertain | Client cannot infer consumption or replacement | Not attempted unless this request's acceptance is confirmed |
| Fresh acceptance, response lost or server crashes | Recorded update or `NoUpdate` is fixed | May not have started or completed |
| Byte-identical duplicate with retained result | Return the recorded result | No additional attempt |
| Same Credential, conflicting presentation | Reject without changing the record | No additional attempt |
| Recovery result unavailable | No conclusion about the recorded decision | No additional attempt |
{: title="Presentation and recovery outcomes within a replay scope"}

## Anonymous Credit Tokens (ACT) {#credential-act}

Credential type: 0x0001.

An ACT Credential, specified in {{ACT}}, carries a hidden *balance* `c`, a
number of credits. The Moderator issues a Credential with an initial
balance of its choosing. A presentation *spends* a public amount `s`,
proving that the balance covers it, and may accept a *top-up* of at most
`a` that the challenge offers. In the same exchange the Moderator issues a *refund*
message with a return amount `t` of its choosing, with `0 <= t <= s + a`.
The Client finalizes this message into a fresh Credential with balance
`c - s + t`. The presentation reveals `s`, `a`, and a single-use nullifier;
the balance is hidden beyond the public amounts and predicates
({{privacy-act}}).

A Credential is invalid once spent, and its replacement exists only once the
Moderator has answered, so one Credential supports one presentation in flight
at a time. This gives the Moderator:

Concurrency control:
: Copies of a Credential yield at most one fresh acceptance across all servers
  accepting the same key and credential context. Every copy presents the same
  nullifier.

Dynamic revocation:
: The Moderator ends a Credential chain, and its remaining balance, by
  declining to refund, without waiting for the Credential to expire.

Per-session adjustment:
: A balance changes only through `s`, `a`, and `t`, each of which can follow
  the Moderator's assessment of the request, subject to {{privacy-act}}.

The abstract credential API maps onto {{ACT}} as follows:

| Abstract operation | ACT |
|---|---|
| `CreateIssuanceRequest` | `IssueRequest`, with key selection ({{act-issue}}) |
| `IssueCredential` | `IssueResponse` ({{act-issue}}) |
| `FinalizeIssuance` | `FinalizeIssue` |
| `CreatePresentationAndUpdate` | `ProveSpend` ({{act-spend}}) |
| `ProcessPresentation` | `VerifySpend` and `IssueRefund` ({{act-spend}}) |
| `FinalizeUpdate` | `FinalizeRefund` |

The Client's `presentation_state` is the `ClientSpendState` of {{ACT}}, the
`pkM`, `credential_context`, `L`, and Moderator identity and endpoint stored
with the spent Credential, and the `PresentationAndUpdate` octets with the
HTTP request information needed to resend them to their original
destination ({{act-missing-refund}}). `ProcessPresentation` returns
`ACCEPTED_WITH_UPDATE` with a refund, and `ACCEPTED_NO_UPDATE` when the
Moderator declines to refund. For a retry answered from a record
({{act-missing-refund}}), it returns the recorded result with `fresh` false.
The ACT response rules in {{HTTP-TRANSPORT}} define the HTTP status and
`Mole-Credential` header for each outcome.

### Configuration {#act-configuration}

The Moderator publishes, in its configuration ({{key-rotation}}):

Public Key
: `pkM`, encoded with `SerializeElement`. Its identifier is
  `key_id = SHA-256(SerializeElement(pkM))`, and `truncated_key_id` is the
  last byte of `key_id`.

Ciphersuite
: The ACT ciphersuite identifier; {{ACT}} defines `P256-SHA256`.

Balance Width
: `L`, fixed for the lifetime of the key and credential context ({{ACT}}).

Credential Context
: `credential_context`, an opaque byte string of at most `2^16 - 2` bytes
  that names the epoch or policy that Credentials under the key are valid
  for.

Result Retention Period
: The recovery interval after acceptance of a presentation. Recovery ends
  earlier if its key or credential context is retired
  ({{act-missing-refund}}).

The credential context of {{ACT}} is

~~~
ctx_cred = credential_context || I2OSP(L, 1)
~~~

which includes `L` as {{ACT}} recommends. A Moderator expires every
outstanding Credential under a key by publishing a new `credential_context`,
without changing the key. A refund is issued under the context of the spent
Credential, so balances do not carry over to a new context. A Moderator
SHOULD announce the successor context and a grace period before expiry.
Clients obtain Credentials under the new context through Redeem & Issue;
this document does not specify balance migration.

A Moderator MAY have several active keys, for instance during a rotation. It
MUST ensure that no two active keys share a `truncated_key_id`, SHOULD NOT
give a new key the `truncated_key_id` of a recently retired one, and SHOULD
keep the number of active keys small ({{privacy-act}}).

### Redeem & Issue {#act-issue}

~~~ tls-presentation
struct {
  uint8 truncated_key_id;
  opaque credential_context<V>;
  IssueRequestMessage request;
} IssuanceRequest;

struct {
  IssueResponseMessage response;
} IssuanceResponse;
~~~

`IssueRequestMessage` and `IssueResponseMessage` are defined in {{ACT}}.

The Client runs `IssueRequest()`, keeps the returned state, and sends the
request with the truncated identifier of the key and the
`credential_context` it holds in its configuration.

The Moderator processes a `CredentialRequest` in this order:

1. It selects the active key whose `truncated_key_id` matches, and checks
   that `credential_context` is the context it issues under for that key.
   It rejects the request if either check fails.
2. It checks that `request` deserializes and that its proof verifies, as
   `IssueResponse` does, and rejects the request otherwise.
3. It validates the accompanying redemption with `FinalizeRedeem`
   ({{endorsement-protocols}}).
4. It chooses the initial balance `c` under its policy and runs
   `IssueResponse(skM, ctx_cred, c, request)`. It then records the
   `replay_protection_ids` returned by `FinalizeRedeem`. Recording is atomic
   and fails if any identifier is already recorded. If any step fails, or
   it is unknown whether the identifiers were recorded, no response is
   released.
5. It returns the result in a `CredentialResponse`.

A request rejected before recording does not cost the Client its
Endorsement. A response lost after recording cannot be recovered, and the
Client needs a new Endorsement.

The Client runs `FinalizeIssue(pkM, ctx_cred, state, response)` and stores
the resulting Credential with `pkM`, `credential_context`, `L`, the
identity of the Moderator, and its configured Redeem & Issue endpoint.
If finalization fails, the Client MUST discard the state, SHOULD refresh
its configuration, and MAY run Redeem & Issue again.

### Presentation and Update {#act-present}

The ACT `Challenge` names the amounts, the context the Moderator accepts,
and the scope of the authorization it asks for:

~~~ tls-presentation
struct {
  uint64 s;
  uint64 a;
  opaque credential_context<V>;
  opaque request_context<V>;
} Challenge;
~~~

`s` is the amount to spend and is the Predicate of {{ARCHITECTURE}}: a
presentation succeeds only if the balance is at least `s`. `a` is the
largest top-up the Moderator offers in this presentation, `0` if none. A
challenge with `s = a = 0` asks for a refresh, which replaces the nullifier
and leaves the balance unchanged, since `t <= s + a = 0`. A Moderator that
wants to lower balances challenges with `s > 0` and returns `t < s`; one that
wants to raise them offers `a > 0`. `credential_context` repeats the
configured value, so that a Client can tell that its Credential has expired
without refetching the configuration. It is the challenge field that
partitions cached Credentials ({{HTTP-TRANSPORT}}).

#### Challenge Binding {#act-challenge-binding}

The spend context of {{ACT}} is

~~~
ctx_spend = SHA-256(credential_challenge)
~~~

where `credential_challenge` is the canonical encoding of the
`CredentialChallenge` ({{common}}), reconstructed with its `credential_type`
and the length-prefixed ACT `Challenge`. The Client hashes those octets, not
their base64url encoding. This digest is separate from the redemption digest
of {{challenge-binding}}.

The presentation does not carry the challenge. The Moderator determines the
challenge a presentation answers from its policy and the request it is
authorizing, and selects one of two profiles by what it puts in
`request_context`:

Policy-scoped:
: `request_context` is empty. Every challenge with the same `s`, `a`, and
  `credential_context` then has the same octets and the same digest, and a
  presentation is a one-use bearer authorization for those values: the
  Moderator accepts it once, against whichever request carries it
  ({{security-act}}).

Request-bound:
: `request_context` is non-empty and identifies the request, session, or
  time window the presentation is for. The Moderator MUST accept a
  presentation only under a value it issued for the request being
  authorized. The value MAY be stateless, for instance an
  authenticated encoding of the origin, the method and target, a session
  identifier, or a time window, which the Moderator recomputes from the
  request. The binding is only as specific as what the value encodes; to
  bind one operation, it MUST distinguish every request field that affects
  authorization, including the request body where relevant.

When several challenges could apply to a request, for instance for adjacent
time windows or for two credential contexts during a rollover, the Moderator
runs steps 2 and 3 of {{act-spend}} for each until one succeeds. The two
profiles differ only in the challenge octets. The cryptographic operations,
the message formats, and the nullifier rules are the same.

#### Spending and Refunds {#act-spend}

A Client that holds no Usable Credential ({{act-client-state}}) for this
Moderator under the challenged `credential_context`, or whose Credential
`ProveSpend` would reject for the challenged `s` and `a`, does not present.
It runs Redeem & Issue, first obtaining an Endorsement if the Moderator
requires one ({{endorsement-protocols}}).

Otherwise the Client computes `ctx_spend`, runs
`ProveSpend(credential, ctx_cred, s, a, ctx_spend)`, stores the returned
state and the presentation as {{act-client-state}} requires, and sends:

~~~ tls-presentation
struct {
  opaque key_id[32];
  SpendMessage spend;
} PresentationAndUpdate;

struct {
  RefundMessage refund;
} Update;
~~~

`SpendMessage` and `RefundMessage` are defined in {{ACT}}. The full `key_id`
is sent: the Moderator issued the Credential and knows its key, so the
identifier tells it nothing more.

The Moderator processes a presentation as follows. Steps 1 and 2 read public
state and the nullifier store, step 3 ends by atomically recording the
result, and step 4 follows.

1. It checks that `key_id` names an active key, then looks up
   `(key_id, spend.k)` in the nullifier store. If a record exists, the
   Moderator answers from it only if it holds the SHA-256 digest of the
   received `PresentationAndUpdate` octets, its result is still retained,
   and its credential context is still accepted for that key
   ({{act-missing-refund}}). The challenge may have expired. A record that
   fails any of these checks causes the presentation to be rejected. Only
   an unrecorded nullifier proceeds to step 2.
2. It determines the challenge ({{act-challenge-binding}}), and checks
   that its `credential_context` is accepted for that key and that
   `spend.s` and `spend.a` equal its `s` and `a`. It rejects the presentation
   if any check fails.
3. It runs `VerifySpend(skM, ctx_cred, ctx_spend, spend)`, decides under its
   policy whether to refund and, if so, the return amount `t`, and runs
   `IssueRefund(skM, ctx_cred, spend, t)` if it refunds. It then records the
   *result* under `(key_id, spend.k)`: the digest of the presentation
   octets, `ctx_cred`, and the decision, either `Refund(t)` with
   the octets of the `RefundMessage`, or `NoUpdate`. Recording is atomic and
   MUST fail if a result is already recorded under that nullifier or if the
   key or context is no longer accepted, so of two racing presentations at
   most one is recorded. If any step fails, or it is unknown whether the
   result was recorded, no refund is released. The Moderator MUST NOT
   attempt the protected operation unless this request's result was
   successfully recorded.
4. It attempts the protected operation. Its HTTP response carries the
   recorded credential result as an `Update`: the refund, or, for
   `NoUpdate`, an absent update, which leaves the Client without a
   replacement. The Moderator MUST include this result even when the
   protected operation fails ({{HTTP-TRANSPORT}}).

Spending credits authorizes one attempt of the protected operation. A
failure after step 3 can charge the Client without completing step 4; a
retry recovers the result but does not authorize another attempt. Reliable
execution needs application-specific recovery, for example a durable outbox
written with the step 3 record and a worker that retries the operation
idempotently under the presentation digest. This document does not specify
that recovery.

The Client runs `FinalizeRefund(pkM, ctx_cred, state, refund)` and stores
the resulting Credential in place of the spent one, with the same `pkM`,
`credential_context`, and `L`. If the refund does not verify, the Client
discards it and proceeds as in {{act-missing-refund}}.

### Client State {#act-client-state}

An ACT Credential goes through the following states:

~~~ aasvg
   +----------+
   |  Usable  |  balance c
   +----+-----+
        |
        | ProveSpend(credential, ctx_cred, s, a, ctx_spend)
        v
   +----------+
   |  Spent   |  awaiting refund; the Credential is invalid
   +----+-----+
        |
        | FinalizeRefund(pkM, ctx_cred, state, refund)
        v
   +----------+
   |  Usable  |  balance c - s + t, in [c - s, c + a]
   +----------+
~~~
{: #fig-act-states title="ACT Credential states"}

Usable:
: The Client holds a Credential with balance `c`, together with `pkM`,
  `credential_context`, and `L`, and may present it as {{act-spend}}
  describes.

Spent:
: The Client has run `ProveSpend`, and the Credential is invalid whether or
  not the presentation is sent or answered ({{ACT}}). Besides the spend state
  that {{ACT}} requires it to store, the Client MUST durably store the
  presentation octets and the HTTP request needed to resend them before
  the presentation leaves it.

A valid refund returns the Client to Usable. A Credential chain is therefore
serialized: one presentation at a time, each waiting for the Moderator's
answer to the previous one. When a Client learns that a key or credential
context has been retired, it MUST discard the Credentials and pending spend
states under that key or context. It obtains a Credential under the current
configuration through Redeem & Issue.

### Lost Refunds {#act-missing-refund}

A presentation may be sent and its response lost, or the Moderator may fail
between recording the result in step 3 of {{act-spend}} and returning it. The
Client cannot then finalize, and the spent Credential cannot be reused.

A Moderator MUST keep each result until the earlier of the end of its
published result retention period ({{act-configuration}}), counted from
the recording in step 3, and retirement of the key or credential context.
It MUST delete the result when this interval ends. A Client missing an
`Update` MAY resend the byte-identical `PresentationAndUpdate` during the
interval. Step 1 of {{act-spend}} checks the record and the continued
acceptance of its key and credential context before returning a result.
Recovery remains available after the presentation's challenge expires:

* For a recorded `Refund(t)`, the Moderator returns the refund it stored.
* For a recorded `NoUpdate`, the Moderator returns an absent update.

The recovery handle ({{HTTP-TRANSPORT}}) is
`key_id || SerializeScalar(spend.k) || SHA-256(PresentationAndUpdate)`.

The Moderator MUST NOT authorize another operation for a recorded nullifier,
and MUST NOT change a recorded decision. It returns the recovered result
with HTTP status `200` for explicit recovery. A byte-identical retry at the
protected resource returns `409` without another operation attempt, as specified
in {{HTTP-TRANSPORT}}.

Once recovery ends, a retry is rejected, and the Client MUST discard the
spend state. To continue, it runs Redeem & Issue. The Moderator MUST retain
the nullifier after deleting its result for as long as the key and
credential context are accepted ({{key-rotation}}).

### Limitations {#act-limitations}

A `SpendMessage` grows linearly in `L` ({{ACT}}). With P-256 and `L = 32`,
it is about 4.5 KB when one of `s` and `a` is nonzero and 8.7 KB when both
are, before base64url encoding in the `Authorization` header. Deployments
with tight header limits should choose `L` accordingly.

## Privacy Pass with a Reverse Flow {#credential-reverse}

Credential type: 0x0002.

The Credential is a single Privacy Pass token. The Moderator's configuration
names one issuance token type and key, used by Redeem & Issue and by updates,
and the token types and keys it accepts for presentation. The accepted set
includes the issuance one, and can include others, for instance a key being
rotated out. Presentation consumes the token. The update, if granted, is a
fresh token issued through {{REVERSE-FLOW}}, with redemption in place of
attestation.

### Redeem & Issue

`IssuanceRequest` is a `TokenRequest` and `IssuanceResponse` is a
`TokenResponse`, both as defined for the configured token type in
{{PRIVACYPASS-PROTOCOLS}}. That token type's finalization operation produces
the Credential. These messages implement `CreateIssuanceRequest`,
`IssueCredential`, and `FinalizeIssuance`.

### Presentation and Update

~~~ tls-presentation
struct {
  opaque token<V>;
  opaque token_request<V>;  /* TokenRequest */
} PresentationAndUpdate;

struct {
  opaque token_response<V>; /* TokenResponse */
} Update;
~~~

The structure fields are:

* `token` is the presented Privacy Pass `Token`.
* `token_request` is the encoded replacement `TokenRequest`.
* `token_response` is the encoded replacement `TokenResponse`.

These structures implement `CreatePresentationAndUpdate`, `ProcessPresentation`,
and `FinalizeUpdate`.

The `token` field carries a `Token` as defined in {{PRIVACYPASS-AUTH}}.
Each configured token key has its own `TokenChallenge` ({{key-rotation}}).
A token is verified against the `TokenChallenge` of the key it was issued
under. Initial issuance and replacements use the `TokenChallenge` of the
issuance key.

The type-specific body of `CredentialChallenge` is the issuance key's
`TokenChallenge`. A Client MUST reject a `CredentialChallenge` whose
`TokenChallenge` differs from it. The Client presents a token issued under
any accepted key, and builds `token_request` under the issuance key.

`TokenChallenge` is fixed when the token is issued, before the operation in
which it is presented. It MUST be the same for every Client using a given
configuration, and MUST NOT contain a per-Client or per-request value.
The Client checks agreement with its configuration, not consistency across
Clients ({{privacy-considerations}}).
`Token.challenge_digest` is SHA-256 over the encoded `TokenChallenge`. It is
distinct from the endorsement `challenge_digest` of {{challenge-binding}}.

The Moderator processes a presentation as follows:

1. It looks up `(token.token_key_id, token.nonce)` in its record store. If a
   record exists, it returns the recorded result with `fresh` false, only
   if the record holds the SHA-256 digest of the received
   `PresentationAndUpdate` octets and is still retained. Otherwise it rejects the presentation. Only an unrecorded
   nonce proceeds to step 2.
2. It verifies the token as specified by {{PRIVACYPASS-AUTH}} against the
   accepted key matching `token.token_type` and `token.token_key_id`, and
   that key's `TokenChallenge`, including `Token.challenge_digest`. It
   rejects the presentation if verification fails.
3. It decides under its policy whether to issue an update and, if so, runs
   the issuance of the configured issuance token type on `token_request`.
4. It atomically records under `(token.token_key_id, token.nonce)` the
   digest of the `PresentationAndUpdate` octets and the result: the
   `Update`, or no update. Recording MUST fail if a record exists. If any
   step fails, or it is unknown whether the result was recorded, no update is
   released and the protected operation MUST NOT be attempted.
5. It returns the recorded result with `fresh` true and attempts the
   protected operation.

With no update this token's chain ends. Other tokens the Client holds are
unaffected.

### Retry after a lost response

A Client that receives no response MAY retry the byte-identical
`PresentationAndUpdate` only to recover from that loss. The Moderator
retains each result for the `result-retention` period in its configuration,
then keeps the nonce without the result while the token key is
accepted. It MUST NOT issue a second Credential for a recorded nonce. The
Client MUST NOT combine the same presented Credential with a different update
request. These requirements are the retry semantics of {{REVERSE-FLOW}}.

If concurrent presentations race to record the nonce, only the winner returns
`fresh` true. A loser returns the retained result with `fresh` false only if
the recorded presentation digest matches. Otherwise it rejects the request.
Once the result expires, the retained nonce still prevents another acceptance.

The recovery handle ({{HTTP-TRANSPORT}}) is
`token.token_key_id || token.nonce || SHA-256(PresentationAndUpdate)`.

### Limitations

The presented token is a bearer credential. Its verification does not prove
that the replacement `token_request` belongs to the same holder. A holder
can therefore supply another party's replacement request. Replay protection
limits acceptance of the presented token within its scope. It does not
prevent this transfer or establish that a Client holds only one token.
The fixed `TokenChallenge` also does not bind presentation to a particular
HTTP request.

TODO: define a device binding mechanism, issuing tokens bound to a Client
key so that presentation requires proof of possession. This would restore
the binding between update and presented credential. Open problem.

# Key Rotation and Discovery {#key-rotation}

Each Anchor and Moderator publishes a configuration, which a Client fetches
over an authenticated channel. For example, a Moderator accepting Rollatini
Endorsements from two Anchors and issuing ACT Credentials publishes, in JSON
with byte strings truncated:

~~~ json
{
  "issuance-uri": "https://moderator.example/mole/issue",
  "endorsements": [
    {
      "endorsement-type": 2,
      "ciphersuite": "P256-SHA256",
      "issuance-epoch": "MjAyNi0xMA",
      "anchor-set": ["A8mT...", "Ao3L..."]
    }
  ],
  "credential-keys": [
    {
      "credential-type": 1,
      "credential-key": "AjRx...",
      "ciphersuite": "P256-SHA256",
      "balance-width": 8,
      "credential-context": "bW9kZXJhdG9yLXYx",
      "result-retention": 300
    }
  ]
}
~~~

Configurations are described in CDDL {{CDDL}}:

~~~ cddl
moderator-configuration = {
  "issuance-uri": tstr,
  "endorsements": [+ $endorsement],
  "credential-keys": [+ $credential-key],
  * tstr => any
}

$anchor-configuration /= {
  "grant-uri": tstr,
  "endorsement-type": 2,            ; Rollatini
  "ciphersuite": tstr,
  "anchor-key": bstr,               ; SerializeElement(pkA)
  "issuance-epoch": bstr,           ; ctx_iss
  * tstr => any
}

$endorsement /= {
  "endorsement-type": 1,            ; No Endorsement Required
  * tstr => any
}

$endorsement /= {
  "endorsement-type": 2,            ; Rollatini
  "ciphersuite": tstr,
  "issuance-epoch": bstr,           ; ctx_iss
  "anchor-set": [+ bstr],           ; SerializeElement(pkA), in order
  * tstr => any
}

$credential-key /= {
  "credential-type": 1,             ; ACT
  "credential-key": bstr,           ; SerializeElement(pkM)
  "ciphersuite": tstr,
  "balance-width": 1..64,           ; L
  "credential-context": bstr .size (0..65534),
  "result-retention": uint,         ; seconds
  * tstr => any
}

$credential-key /= {
  "credential-type": 2,             ; Privacy Pass Reverse Flow
  "token-type": uint .size 2,
  "token-key": bstr,
  "token-challenge": bstr,          ; encoded TokenChallenge
  "issuance": bool,                 ; the issuance key, exactly one
  "result-retention": uint,         ; seconds
  * tstr => any
}
~~~

`grant-uri` and `issuance-uri` are absolute HTTPS URIs without userinfo or
fragments. Other protocols,
such as {{longfellow}}, add entries to the sockets. A Client ignores unknown
members and skips entries of unknown types.

`endorsements` lists the endorsement types the Moderator accepts. A
Rollatini entry is one accepted Anchor set, with the `ctx_iss` shared by all
its Anchors. A Moderator accepting several epochs publishes one entry per
epoch. Order within `anchor-set` matters: Rollatini proof branches match
Anchors by position.

ACT nullifiers MUST remain recorded while their credential context is
accepted for their key. A Moderator that publishes different configurations
to different Clients partitions them ({{ARCHITECTURE}}).

The serialization, for instance JSON or CBOR, is to be defined with the
configuration's authentication and consistency checks. In JSON, `bstr`
values are unpadded base64url strings.

# Privacy Considerations {#privacy-considerations}

TODO. Follow {{ARCHITECTURE}} and cover:

1. Anonymity-set partitioning by protocol type, keys, contexts, epochs,
   accepted-set contents and order, and public amounts. Cryptographic issuer
   hiding and unlinkability do not remove these distinctions.
2. Configuration consistency: authenticated delivery does not prevent split
   views. Local Client checks do not establish consistency across Clients.
3. Anchor set verification: counting keys does not establish that they
   represent distinct, active Anchors. Fabricated entries do not add Clients
   to the anonymity set.
4. Epoch width versus anonymity-set size.
5. Amount tagging: conformance requirements do not prevent a malicious
   Moderator from choosing identifying amounts. State Client checks,
   external consistency assumptions, and residual attacks.

During redemption of an Endorsement, the Client uses the accepted Anchor Set
from the Moderator's authenticated configuration. If the Client does not have
an Endorsement issued by one of the Anchors in the Anchor Set, it must either
abort the redemption flow or pause it until it can obtain a suitable
Endorsement. The Client must take care to ensure its actions in this case do not
inadvertently reveal the issuing Anchor of an accepted Endorsement. For example,
if the Client initiates two concurrent redemption flows, the Moderator can
select Anchor Sets that differ by just one Anchor. If one flow aborts but the
other does not, then the Moderator immediately learns the Anchor of the accepted
Endorsement.

## Anonymous Credit Tokens {#privacy-act}

An ACT presentation reveals `s`, `a`, and a fresh nullifier, and, because
the proof verifies, the key and credential context of the Credential. Its
Update reveals `t`. The unlinkability of {{ACT}} holds among the Clients
that share the key, the context, and the amounts, so each of these
partitions Clients:

Keys and contexts:
: The truncated key identifier shortens the encoding, but it still selects
  one active key, and every active key splits the Clients holding
  Credentials under it. {{ACT}} requires the credential context to be coarse: a
  per-Client or per-session context makes presentations linkable without
  breaking any cryptographic property.

Amounts:
: The initial balance, `s`, `a`, and `t` MUST NOT vary per Client under a
  policy, since a Moderator could recognize a Client by the values it
  uses. A Moderator SHOULD draw them from a small set of values fixed by
  policy, so that a value reveals no more than the policy decision it
  encodes. A Client whose balance plus `a` reaches `2^L` cannot present,
  which sets it apart. A Moderator SHOULD choose `L` so that the largest
  balance its policy lets Clients reach, plus the largest `a` it offers, is
  below `2^L`.

Balance inference:
: A presentation succeeds only if the balance covers `s`. A Moderator that
  challenges a Client repeatedly with amounts of its choosing can bound the
  balance, and in the end recover it and use it to link presentations
  ({{ARCHITECTURE}}). The serialized chain of {{act-client-state}} limits
  such probing to one presentation per round trip. Clients SHOULD limit the
  number of presentations they make in one context, as {{ARCHITECTURE}}
  recommends.

Timing:
: The refund arrives in the same exchange as the presentation, so a Client
  that presents it in another context at once is likely the one that just
  received it. {{ARCHITECTURE}} keeps a Credential used in one context
  locked to that context for a period of time; this applies to the refund
  that replaces it.

# Security Considerations {#security-considerations}

All exchanges defined in this document and {{HTTP-TRANSPORT}} MUST be
carried over HTTPS.

TODO. The list to cover:

1. Anchor key compromise: an attacker with an Anchor key in an accepted set
   can mint Endorsements freely. Blast radius and rotation response.
2. Timing and error side channels during verification, especially
   distinguishing "bad proof" from "spent nullifier".

Replay protection scope is deployment-selected and can differ for Endorsement
redemption and Credential presentation. Atomic checks within that scope
prevent repeated acceptance. Except for ACT's shared-store requirement below,
this document does not require global uniqueness or a particular storage
architecture. Independent scopes can accept the same Endorsement or Credential
again. For ACT, all servers accepting the same key and credential context MUST
share one atomic nullifier store; independent stores need disjoint keys or
contexts. Otherwise a Client can fork a balance across stores, which breaks
the credit conservation of {{ACT}}.
A Rollatini redemption exposes the same nullifier in each scope, making
cross-scope reuse linkable if records are compared. Proof rerandomization does
not hide that reuse.

Replay markers and recoverable presentation results have different lifetimes.
A Moderator MUST retain a marker while the corresponding Endorsement or
Credential remains acceptable in its scope, even after its recovery result
expires. Deleting the result ends recovery. Deleting the marker permits replay. After deleting a
marker on retirement, the Moderator MUST NOT accept the retired configuration
again.

## Anonymous Credit Tokens {#security-act}

Nullifier store:
: Step 3 of {{act-spend}} is the atomic recording that {{ACT}} requires.
  The store MUST be durable: a Moderator that loses it re-admits every
  Credential spent under a context for as long as that context is
  accepted. Nullifiers MAY be partitioned by key and context and discarded
  once the context is no longer accepted; a Moderator MUST NOT accept that
  key and context again afterwards.

Amounts:
: Step 2 of {{act-spend}} requires `spend.s` and `spend.a` to equal the
  challenge's `s` and `a`. Accepting another `s` would let the Client choose
  its charge, and accepting a larger `a` would let it choose how far its
  balance may rise. {{ACT}} gives the range checks that credit conservation
  needs.

Credential sharing:
: Copies of one Credential yield at most one fresh acceptance across all
  servers accepting the same key and credential context. Byte-identical retries
  recover the retained result.
  Conflicting spends are rejected. Both expose the same nullifier and are
  linkable to the first presentation ({{ACT}}).

Recorded results:
: A recorded result is returned only for a byte-identical presentation and
  never authorizes another operation. A party that replays an observed
  presentation receives a refund it cannot finalize without the spend
  state. A recorded `NoUpdate` stays `NoUpdate`; answering a retry with a
  refund would undo the Moderator's revocation.

Dynamic revocation:
: A Moderator that records `NoUpdate` ends that Credential chain, and the
  Client loses its remaining balance with no cryptographic recourse.
  Clients therefore trust Moderators to refund honest presentations; a
  Moderator that withholds refunds indiscriminately costs its Clients their
  Endorsements. Client Vendors can limit their Clients' use of such a
  Moderator.

Presentation scope:
: Under the policy-scoped profile of {{act-challenge-binding}}, a party
  that sees a presentation before the Moderator does, such as an
  intermediary terminating TLS for the Moderator, can attach it to another
  request under the same policy. The nullifier check ensures that only one use
  is accepted within the replay scope, not which. Deployments that need a
  presentation tied to one request use the request-bound profile.

Verification cost:
: An unrecorded nullifier passes step 1 of {{act-spend}}, so a forged
  presentation costs the Moderator a full `VerifySpend`, whose cost is
  linear in `L`. Mitigations are rate limiting applied before verification,
  which identifies Clients no more than the transport already does, and a
  small `L`.

# IANA Considerations {#iana}

This document sketches two candidate registries under a future "MoLE"
group. The values below are candidate values for discussion in this -00
draft and are not stable assignments.

New registrations use Specification Required as defined by {{IANA}}. A
specification MUST define the structures and abstract operations required by
the relevant common API, including canonical encodings and maximum sizes. An
endorsement registration MUST provide issuer hiding where applicable, define
its replay protection behavior, and state how a Challenge affects its cryptographic
Context. A credential registration MUST define `IssuanceRequest`,
`IssuanceResponse`, `PresentationAndUpdate`, `Update`, finalization, retry
behavior, and Challenge-to-Context derivation. Type-specific Update encodings
MUST be nonempty so HTTP can represent `NoUpdate` as an empty payload.

## MoLE Endorsement Types

| Value           | Name                          | Reference      |
|:----------------|:------------------------------|:---------------|
| 0x0000          | Reserved                      | this document  |
| 0x0001          | No Endorsement Required       | {{no-endorsement-required}} |
| 0x0002          | Rollatini                     | {{rollatini}}  |
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

### Rollatini {#iana-rollatini}

* Value: 0x0002
* Name: Rollatini
* Exchanges: 2
* Publicly Verifiable: Yes
* Reference: {{rollatini}}

### Longfellow {#iana-longfellow}

* Value: 0x0003
* Name: Longfellow
* Exchanges: none (out of band)
* Publicly Verifiable: Yes
* Reference: {{longfellow}}

## MoLE Credential Types

One MoLE credential type identifies the issuance, presentation, and update
payloads defined by a credential protocol.

| Value           | Name                       | Reference             |
|:----------------|:---------------------------|:----------------------|
| 0x0000          | Reserved                   | this document         |
| 0x0001          | ACT                        | {{credential-act}}    |
| 0x0002          | Privacy Pass Reverse Flow  | {{credential-reverse}} |
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

Both media types require a `type` parameter containing the four-digit
hexadecimal endorsement type defined by {{HTTP-TRANSPORT}}. Bodies are the
type-specific binary grant messages. Duplicate or mismatched type parameters
are rejected. Neither type has optional parameters defined here.

> **Editor note.** The final registry names and expert-review instructions
> remain to be specified.


--- back

# Example {#example}

A Client requests a resource protected by a Moderator that uses credential
type 0x0002 (Privacy Pass Reverse Flow) and accepts endorsement type
0x0002 (Rollatini). The Client obtains the Endorsement before contacting that
Moderator.

~~~ aasvg
+--------+         +--------+      +-----------+
| Client |         | Anchor |      | Moderator |
+---+----+         +---+----+      +-----+-----+
    |                  |                 |
    +--- empty body --->|                |
    |<-- CommitMessage -+                |
    +-- ChallengeMessage -->|            |
    |<-- ResponseMessage ---+            |
Finalize               |                 |
    |<-------- ModeratorChallenge -------+
    |   Redemption + IssuanceRequest      |
    +------------------------------------>|
    |<------------------------------------+
    |   IssuanceResponse                  |
Finalize               |                 |
    |<-------- CredentialChallenge ------+
    |   PresentationAndUpdate             |
    +------------------------------------>|
    |<------------------------------------+
    |   Update                            |
    |                  |                 |
~~~
{: #fig-example title="Complete exchange"}

The first Rollatini request has an empty body. The Anchor returns a
`CommitMessage`. The Client then sends the corresponding `ChallengeMessage`,
and the Anchor returns a `ResponseMessage`:

~~~
POST <anchor-grant-link> HTTP/1.1
Host: anchor.example
Content-Type: application/mole-endorsement-request; type=0002
Content-Length: 0
~~~

The Client finalizes the `ResponseMessage` into an Endorsement. It then obtains
a `ModeratorChallenge` from the Moderator, computes its digest, and sends an
HTTP request with the Rollatini `Redemption` and a Privacy Pass `TokenRequest`
as separate typed parameters to its Redeem & Issue endpoint:

~~~
POST /issue HTTP/1.1
Host: moderator.example
Authorization: Mole redeem-0002="<redemption>",
                    credential-request-0002="<token-request>"
~~~

The Moderator verifies the redemption against the Challenge it sent and
atomically records its nullifier.
It then processes the issuance request and returns a `CredentialResponse`
carrying a `TokenResponse` in the `Mole-Credential` header. The Client finalizes
the issuance response. On a later request, it obtains a
`CredentialChallenge` carrying the configured Privacy Pass `TokenChallenge`
before presenting the resulting token:

~~~
GET /resource HTTP/1.1
Host: moderator.example
Authorization: Mole presentation-0002="<presentation-and-update>"
~~~

The Moderator verifies the presentation and serves the resource. Its response
carries an `Update` for a fresh token, or no update if it chose to consume the
Credential.

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
