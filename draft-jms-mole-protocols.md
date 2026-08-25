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
  ACT: I-D.draft-schlesinger-cfrg-act
  ARCHITECTURE: I-D.draft-jms-mole-architecture
  CRYPTO: #I-D.draft-authors-mole-crypto
    title: MoLE Cryptography
    target: https://moderation-of-unlinkable-endorsements.github.io/internet-drafts/draft-authors-mole-crypto.html
  HTTP-TRANSPORT: I-D.draft-jms-mole-http-transport
  IANA: RFC8126
  LONGFELLOW: I-D.draft-google-cfrg-libzk
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

TODO: the protocols below reflect our current understanding of how MoLE
may work, and showcase agility. They are not final. Some may be removed,
others added.

It defines two endorsement protocols and two credential protocols. Each is
identified by a type value from a registry established in this document
({{iana}}). The HTTP carriage of challenges, requests, redemptions, and
presentations is defined by {{HTTP-TRANSPORT}}. This document defines the
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
: A Client spends an Endorsement at one logical Moderator. A Client MUST NOT
  attempt to redeem the same Endorsement at a second Moderator. The Moderator
  enforces replay protection within its configured replay protection scope.

Issue:
: A Moderator gives a Client a Credential in return for a redemption.

Present:
: A Client shows a Credential to a Moderator. Each Credential can be
  presented once within the Moderator's configured replay protection scope. The
  update replaces it.

Update:
: The Moderator's adjustment to a presented Credential, returned in the
  same exchange.

Finalize:
: The Client-local step that turns a protocol response into a stored
  Endorsement or Credential.

# Common Requirements {#common}

## Message Types

Every outer MoLE message that selects a protocol carries a `uint16` type field.
These messages are `EndorsementRequest`, `EndorsementResponse`,
`CredentialRequest`, `CredentialResponse`, `CredentialPresentation`,
`CredentialUpdate`, `ModeratorChallenge`, and `CredentialChallenge`. Values are
assigned in {{iana}}. A Client ignores an unknown Challenge. An unknown request
or response is rejected. A Moderator treats an unknown optional presentation
as absent and rejects an unknown required presentation. Challenge wrappers are
exchanged only between a Moderator and Client. They are never sent to an Anchor.

The value 0x0000 is reserved in both registries and MUST NOT appear on the
wire. Endorsement type 0x0001 means that no Endorsement is required.

## Greasing {#greasing}

In order to prevent Moderators from becoming incompatible with future
credential types, Clients SHOULD send presentations whose `credential_type` is a
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
Anchor.

A Context is a protocol-specific cryptographic input. A protocol defines how
the Client and Moderator derive the same Context from authenticated
configuration, the operation, and, when required, the Moderator Challenge. A
Context can include the complete Moderator Challenge, a digest of it, or
selected fields. Moderator Challenge and Context are therefore not
interchangeable terms.

Each credential protocol defines the contents of its type-specific
`CredentialChallenge` body. Endorsement protocols use the common Challenge in
{{challenge-binding}}. A Moderator MUST retain enough state to verify that a
response uses a Challenge it issued and that remains valid.

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
    +-------- Redemption --------->|
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

The structure fields are:

* `endorsement_type` identifies a registered endorsement protocol.
* `body` is that protocol's grant message.

The Anchor returns 200 (OK) with the response media type only when it produced
a complete `EndorsementResponse`. A Client MUST reject a non-success status, an
unexpected media type, a response whose type differs from its request, trailing
bytes, or malformed type-specific content. Clients MUST NOT automatically
redirect a grant POST carrying protocol state. If the second IHAT response is
lost, the consumed session cannot be replayed. The Client starts a fresh grant
session.

Every endorsement protocol defines a `Redemption` structure. It is the message
a Client sends to redeem the Endorsement, carried in the
`endorsement_presentation` field of a `CredentialRequest`
({{credential-protocols}}).

## Redemption Challenge Binding {#challenge-binding}

The type-specific body of `ModeratorChallenge` is:

~~~ tls-presentation
struct {
  opaque nonce[32];
} RedemptionChallenge;
~~~

The structure fields are:

* `nonce` is an unpredictable value that the Moderator MUST NOT reuse within
  its configured replay protection scope.

Endorsement protocols compute the following value when creating or verifying
a redemption:

~~~
challenge_digest = SHA-256(moderator_challenge)
~~~

The values are defined as follows:

* `moderator_challenge` is the complete decoded TLS-presentation encoding of
  the `ModeratorChallenge` sent by the Moderator. It is not required to contain
  an origin.
* `challenge_digest` is the 32-octet SHA-256 digest of
  `moderator_challenge`. It is not computed over a base64url or other textual
  encoding. SHA-256 is defined in {{SHA2}}.

`challenge_digest` enters the Fiat-Shamir transcript in both IHAT and
Longfellow, but is not a Longfellow circuit public input. A redemption created
for one `ModeratorChallenge` does not verify under another.

The `Challenge` algorithm and `ChallengeMessage` in IHAT issuance are defined
by {{CRYPTO}} and are unrelated to a `ModeratorChallenge`.

## Abstract Endorsement API

Each endorsement protocol defines these abstract operations:

~~~
RedeemRequest(endorsement, moderator_challenge, configuration)
  -> redemption | INVALID
FinalizeRedeem(redemption, moderator_challenge, configuration)
  -> replay_protection_id | INVALID
~~~

`RedeemRequest` runs at the Client. `FinalizeRedeem` runs at the Moderator,
verifies the redemption and Challenge binding, and returns a
`replay_protection_id` or `INVALID`. Both operations derive
`challenge_digest` from `moderator_challenge` as specified above. After a
successful call, the Moderator MUST atomically insert `replay_protection_id`
in the protocol's configured replay protection scope only if it is absent. If
it is already present, the Moderator MUST treat the result as `INVALID` and
MUST NOT process the accompanying `IssuanceRequest`. There is no global replay
protection service.

## No Endorsement Required {#no-endorsement-required}

Endorsement type 0x0001 indicates that the Moderator does not require an
Endorsement under its policy. It has no grant. The `endorsement` input and
`Redemption` are both the distinguished empty value. `RedeemRequest` returns
that empty value. `FinalizeRedeem` returns `challenge_digest` as its
`replay_protection_id` when the Moderator's policy permits issuance without an
Endorsement, and `INVALID` otherwise. This prevents reuse of one Moderator
Challenge within the configured replay protection scope. This type therefore
implements the same abstract API as every other endorsement type.

## Issuer-Hiding Anonymous Token (IHAT) {#ihat}

Endorsement type: 0x0002.

This protocol uses the IHAT-TZ variant defined in {{CRYPTO}}. IHAT is a
pairing-free, issuer-hiding endorsement scheme. The Anchor blindly signs a
Client-chosen nullifier. The Client later proves,
with an issuer-hiding proof, that its Endorsement verifies under one of the
Anchor keys the Moderator accepts. The cryptographic operations, and the
contents and encodings of every message body, are defined in {{CRYPTO}}.

The following primitive types are ciphersuite-dependent:

~~~ tls-presentation
opaque Scalar[Ns];
opaque Element[Ne];
~~~

### Configuration

The Client needs, from Anchor configuration ({{key-rotation}}):

IHAT Ciphersuite
: A ciphersuite identifier defined by {{CRYPTO}}. It determines `Element`,
  `Scalar`, and all cryptographic encodings.

Anchor Public Key
: `pkA`, an `Element`, as generated in {{CRYPTO}}, with a stable key ID.

Issuance Context
: `ctx_iss`, the canonical encoding of the issuance epoch. Endorsements are
  valid for that epoch, see {{key-rotation}}.

Redemption Context
: `ctx_red`, the ASCII string `"MoLE-IHAT-ctx_red-v1"`, without a terminating
  NUL byte. This fixed, domain-separated value is the same for all Moderators.
  This is the cryptographic redemption Context defined by {{CRYPTO}}, not a
  Moderator Challenge. A specific redemption operation is bound separately by
  `challenge_digest`.

### Grant

The grant takes two HTTP exchanges and three protocol messages. The Anchor
speaks first, as specified by {{CRYPTO}}:

1. The Client sends an `EndorsementRequest` with an empty `body`. The Anchor
   runs `Commit(skA, ctx_iss)`, stores the returned state under a fresh
   `session_id`, and returns a `CommitMessage` in the response body.
2. The Client runs `Challenge(pkA, ctx_iss, ctx_red, commitment)`, stores the
   returned state, and sends a `ChallengeMessage` containing the returned
   issuance challenge and opaque `session_id`. The Anchor atomically claims and
   consumes that identifier before reading the single-use state. Only the
   instance that wins the claim runs `Respond(skA, state, challenge)` and
   returns a `ResponseMessage`.
   Tombstones are retained through session expiry. All later requests for the
   identifier fail without invoking `Respond`.
3. The Client runs `Finalize(pkA, state, response)` as specified by {{CRYPTO}}.
   On failure it MUST discard the session state and MUST NOT retry with that
   state.

`CommitMessage`, `ChallengeMessage`, `ResponseMessage`, `session_id`, and the
Endorsement encoding are defined by {{CRYPTO}}. The session identifier is only
transport correlation and is not bound into the Endorsement.

The Anchor learns neither `nf` nor the final Endorsement. Under the statistical
blindness claim in {{CRYPTO}}, its protocol transcript does not let it
recognize the Endorsement when it is later redeemed. Timing, network, and
configuration metadata are outside that claim.

### Redemption

> **Editor note.** {{CRYPTO}} does not yet define IHAT redemption. This section
> is blocked on its exact `Redemption` encoding, `RedeemRequest` and
> `FinalizeRedeem` algorithms, Context and Challenge binding, replay protection
> identifier, and security analysis.

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
redemption operation supplies the digest of the complete decoded
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
`verification_time` remain current. It returns the nullifier as
`replay_protection_id`, or `INVALID` on any failure. Both operations derive
`challenge_digest` from `moderator_challenge`. The common caller performs the
atomic replay protection check.

### Differences from IHAT

Longfellow does not inherently require an Anchor to change its issuance
protocol. Scarcity then depends on the legacy credential's own issuance limits
and on whether it contains a credential-bound Client secret suitable for
nullifier derivation. An Anchor that participates in MoLE can control scarcity
and arrange for such a secret to be committed during issuance. Some existing
credential formats may already provide a suitable Client-contributed or
device-bound secret. The one-nullifier-per-origin-and-epoch rule prevents
repeat redemption of one credential in that scope. It does not limit how many
credentials a Client can obtain.

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

Both parts ride on HTTP requests to the Moderator. Redeem & Issue carries a
`CredentialRequest` in the
`Authorization` header and receives the `CredentialResponse` in the
`Mole-Credential` response header. The Moderator runs the selected endorsement
protocol's `FinalizeRedeem` operation before processing the issuance request.
Presentation uses the same authentication scheme.

~~~ tls-presentation
struct {
  uint16 endorsement_type;
  opaque endorsement_presentation<V>; /* encoded Redemption */
  uint16 credential_type;
  opaque issuance_request<V>;
} CredentialRequest;

struct {
  uint16 credential_type;
  opaque issuance_response<V>;
} CredentialResponse;
~~~

The structure fields are:

* `endorsement_type` identifies the endorsement protocol.
* `endorsement_presentation` is its encoded `Redemption`. It is empty for
  endorsement type 0x0001 ({{no-endorsement-required}}).
* `credential_type` identifies the credential protocol.
* `issuance_request` is its encoded `IssuanceRequest`.
* `issuance_response` is its encoded `IssuanceResponse`.

A recipient of `CredentialResponse` MUST reject it unless `credential_type`
matches the type selected by `CredentialRequest`.

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

The type-specific encodings fill the opaque fields of the outer structures
above and of `CredentialPresentation` and `CredentialUpdate` from
{{HTTP-TRANSPORT}}.

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
   | ACCEPTED_NO_UPDATE
   | ACCEPTED_WITH_UPDATE(update)
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
replay protection before returning an accepted result.

## Anonymous Credit Tokens (ACT) {#credential-act}

Credential type: 0x0001.

An ACT credential {{ACT}} is an anonymous state machine: the Moderator can
test a predicate against the Credential's hidden state and update that
state, without learning the state or linking presentations. This protocol is
intended to provide every property required by
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

The structure fields are:

* `truncated_key_id` selects the configured ACT key.
* `request` is the encoded ACT issuance request.
* `response` is the encoded ACT issuance response.

These structures are intended to implement `CreateIssuanceRequest`,
`IssueCredential`, and `FinalizeIssuance`.

### Presentation and Update

The Client presents the Credential against the selected predicate,
spending it, and in the same message requests the replacement that carries
the updated state.

~~~ tls-presentation
struct {
  opaque key_id[32];
  opaque spend_proof<V>;
} PresentationAndUpdate;

struct {
  opaque refund<V>;
} Update;
~~~

The structure fields are:

* `key_id` identifies the ACT key.
* `spend_proof` is the encoded ACT spend proof.
* `refund` is the encoded ACT refund.

These structures are intended to implement `CreatePresentationAndUpdate`,
`ProcessPresentation`, and `FinalizeUpdate`.

> **Editor note.** The mapping from ACT issuance, spend, and refund operations
> to MoLE Contexts and payloads is undefined. This protocol is not interoperable
> until that mapping and its canonical encodings are specified.

## Privacy Pass with a Reverse Flow {#credential-reverse}

Credential type: 0x0002.

The Credential is a single Privacy Pass token. The Moderator's configuration
names both the registered token type used for presentation and the registered
token type used for update issuance. Presentation consumes the token. The
update, if granted, is a fresh token issued through {{REVERSE-FLOW}}, with
redemption in place of attestation.

For the protocol described here, the presented and reissued token use the same
token type and Moderator key. Changing either partitions Clients and leaks
state.

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
Privacy Pass names its cryptographic Context `TokenChallenge`. In MoLE, the
type-specific body of `CredentialChallenge` carries that configured
`TokenChallenge`. It is therefore both sent by the Moderator as part of a
Challenge and supplied to the Privacy Pass replacement-issuance and
verification operations as their Context. Initial issuance obtains the same
`TokenChallenge` from authenticated configuration.

`TokenChallenge` is fixed when the token is issued. It MUST be stable for every
Client using the same configured credential type, key, and epoch, and MUST NOT
contain a per-Client or per-request value. This is necessary because a
replacement token is issued before the operation in which it will be
presented.
The Privacy Pass `Token.challenge_digest` field MUST equal SHA-256 over the
encoded configured `TokenChallenge`. It is distinct from the MoLE endorsement
`challenge_digest` defined in {{challenge-binding}}. The Moderator MUST reject
a token carrying any other digest. Replay protection comes from token single use.
The Moderator MUST verify the token as specified by {{PRIVACYPASS-AUTH}}
against the configured token type, key, and `TokenChallenge`, then atomically
record its nonce before accepting it. An invalid or previously recorded nonce
is rejected, except for the retry behavior below. Holder binding remains an
open limitation below.

If the Moderator's policy allows continued access, it returns an `Update`. If
not, it returns no update and the Client is out of credentials.

### Retry after a lost response

A Client that receives no response MAY retry the byte-identical
`PresentationAndUpdate` only to recover from that loss. The Moderator MUST
return the same accepted result while it retains the idempotency record,
including the same `Update` or the same absence of an update. It MUST reject the
replay after that record expires and MUST NOT issue a second Credential. The
Client MUST NOT combine the same presented Credential with a different update
request. These requirements are the retry semantics of {{REVERSE-FLOW}}.

### Limitations

TODO: define a device binding mechanism, issuing tokens bound to a Client
key so that presentation requires proof of possession. This would restore
the binding between update and presented credential. Open problem.

# Key Rotation and Discovery {#key-rotation}

This draft assumes authenticated configuration supplies endpoints, supported
types, keys, epochs, accepted issuer sets, and type-specific inputs. The order
of accepted sets is significant because IHAT proof branches and Longfellow
issuer inputs match elements by position.

> **Editor note.** Configuration discovery, serialization, authentication,
> canonical encodings, consistency, and rotation remain undefined. The wire
> protocols are not interoperable until these are specified.

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

The replay protection store is shared only within its configured scope. A
deployment can use one atomic scope across all regions, including by routing
each replay protection identifier to an authoritative region. This does not
require the Client to know that region. A deployment can instead operate
independent regional stores, but then the same Endorsement can be accepted once
in each region. Credentials can likewise be presented once in each region,
potentially creating divergent updates. Separate Moderators also do not
coordinate stores.
An IHAT redemption exposes the same nullifier in each scope, making cross-scope
reuse linkable if records are compared. Proof rerandomization does not hide that
reuse.

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
behavior, and Challenge-to-Context derivation. Outer type-selecting messages
carry the registered `uint16` type as specified in {{common}}.

## MoLE Endorsement Types

| Value           | Name                          | Reference      |
|:----------------|:------------------------------|:---------------|
| 0x0000          | Reserved                      | this document  |
| 0x0001          | No Endorsement Required       | {{no-endorsement-required}} |
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

> **Editor note.** The final registry names and expert-review instructions
> remain to be specified.


--- back

# Example {#example}

A Client requests a resource protected by a Moderator that uses credential
type 0x0002 (Privacy Pass Reverse Flow) and accepts endorsement type
0x0002 (IHAT). The Client obtains the Endorsement before contacting that
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

The first IHAT request has an empty body. The Anchor returns a
`CommitMessage`. The Client then sends the corresponding `ChallengeMessage`,
and the Anchor returns a `ResponseMessage`:

~~~
POST <anchor-grant-link> HTTP/1.1
Host: anchor.example
Content-Type: application/mole-endorsement-request

EndorsementRequest { 0x0002, "" }
~~~

The Client finalizes the `ResponseMessage` into an Endorsement. It then obtains
a `ModeratorChallenge` from the Moderator, computes its digest, and sends an
HTTP request with a `CredentialRequest` containing the IHAT `Redemption` and a
Privacy Pass `TokenRequest`:

~~~
GET /resource HTTP/1.1
Host: moderator.example
Authorization: Mole credential-request="<credential-request>"
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
Authorization: Mole presentation="<credential-presentation>"
~~~

The Moderator verifies the presentation and serves the resource. Its response
carries an `Update` for a fresh token, or no update if it chose to consume the
Credential.

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
