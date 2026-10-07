---
title: "MoLE HTTP Transport"
abbrev: "MoLE HTTP Transport"
category: info

docname: draft-jms-mole-http-transport-latest
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
  latest: "https://moderation-of-unlinkable-endorsements.github.io/internet-drafts/draft-jms-mole-http-transport.html"

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
  HTTP: RFC9110
  PROTOCOLS: #I-D.draft-jms-mole-protocols
    title: MoLE Protocols
    target: https://datatracker.ietf.org/doc/draft-jms-mole-protocols/00/
  TLS13: RFC8446

informative:
  BASE64: RFC4648
  QUIC: RFC9000

...

--- abstract

MoLE targets browser deployments, so Clients, Anchors, and Moderators need
an HTTP transport for the protocol flows defined by the architecture.

This document defines the `Mole` HTTP authentication scheme, which carries
challenges and presentations for the endorsement and credential flows, and
the headers used to return credential material. The grant exchanges with
the Anchor are defined per protocol in {{PROTOCOLS}}.


--- middle

# Introduction

TODO

# Terminology

{::boilerplate bcp14-tagged}

# Presentation Language

This document uses the TLS presentation language {{TLS13}} to describe the
structure of protocol messages.  In addition to the base syntax, it uses two
additional features: the ability for fields to be optional and the ability for
vectors to have variable-size length headers.

## Optional Value {#optional-value}

An optional value is encoded with a presence-signaling octet, followed by the
value itself if present.  When decoding, a presence octet with a value other
than 0 or 1 MUST be rejected as malformed.

~~~ tls-presentation
struct {
    uint8 present;
    select (present) {
        case 0: struct{};
        case 1: T value;
    };
} optional<T>;
~~~

## Variable-Size Vector Length Headers

In the TLS presentation language, vectors are encoded as a sequence of encoded
elements prefixed with a length.  The length field has a fixed size set by
specifying the minimum and maximum lengths of the encoded sequence of elements.

In this document, there are several vectors whose sizes vary over significant
ranges.  So instead of using a fixed-size length field, it uses a variable-size
length using a variable-length integer encoding based on the one described in
{{Section 16 of QUIC}}. They differ only in that the one here requires a
minimum-size encoding. Instead of presenting min and max values, the vector
description simply includes a `V`. For example:

~~~ tls-presentation
struct {
    uint32 fixed<0..255>;
    opaque variable<V>;
} StructWithVectors;
~~~

# HTTP Authentication Scheme {#http-authentication-scheme}

We describe the HTTP authentication method used by a Client that has an
Endorsement from an Anchor and obtains a Credential from a Moderator.

The `Mole` authentication scheme follows the HTTP authentication framework
defined in {{HTTP}}. It carries challenges, redemptions, and
presentations: an Anchor or a Moderator challenges the Client, and the
Client answers in the `Authorization` header of a request. Only the grant
exchanges with the Anchor sit outside the scheme. Their carriage is
defined per endorsement protocol in {{PROTOCOLS}}, for example over HTTP
POST.

~~~ aasvg
+--------+                                +-----------+
| Client |                                | Moderator |
+---+----+                                +-----+-----+
    |                                           |
    |<--- WWW-Authenticate: Mole challenge= ----+
    |                                           |
(Redeem & Issue, if needed)                     |
    |                                           |
    +--- Authorization: Mole presentation= ---->|
    |                                           |
    |<----------------------- Mole-Credential --+
    |                                           |
~~~

A challenge names a single endorsement or credential type. To offer a
choice, a server sends multiple `Mole` challenges; the Client picks one it
supports and MUST ignore challenges whose type it does not recognize.

All base64url values in this document are encoded without padding
({{BASE64}}).

# Configuration

Anchors and Moderators publish configuration used by Clients before
running the HTTP authentication flows. Configuration includes endpoint URLs,
supported protocol types, public key material, and the Anchor set associated
with each Moderator policy. Its contents and format are defined in the Key
Rotation and Discovery section of {{PROTOCOLS}}.

Clients MUST retain the authenticated association between each Moderator,
its Redeem & Issue endpoint, and the policies and credential configurations
it serves. Cached Credentials MUST identify this configuration so that the
Client can select the endpoint when it needs to obtain a Credential. A
Client that retains a presentation for recovery MUST also retain the HTTP
request needed to resend it to its original destination.

# Error Handling {#http-errors}

Moderators can use MoLE as optional authentication. A `200` response MAY
include a `WWW-Authenticate: Mole` challenge. This tells the Client that a
later request can include a presentation, for example to get a higher limit
or avoid other friction. In such deployments, Clients SHOULD apply the
greasing rules of {{PROTOCOLS}}.

A `401` response with a `WWW-Authenticate: Mole` challenge means that the
Moderator requires MoLE, or another acceptable authentication scheme,
before serving the resource. A `403` response means that policy forbids
the request. {{act-responses}} specifies the status codes and credential
headers for ACT exchanges.

## Endorsement

The criteria to provide an endorsement is left to the Anchor. This document only defines the
HTTP carriage for the Endorsement protocol messages.

### Anchor -> Client

~~~tls-presentation
struct {
  uint16 endorsement_type;
  opaque anchor_context<V>;
} EndorsementChallenge;
~~~

* `challenge` contains a base64url `EndorsementChallenge` value, encoded per
  {{BASE64}}.

~~~
WWW-Authenticate: Mole challenge="<endorsement-challenge>",
                       realm="anchor"
~~~

### Client <-> Anchor

After receiving a challenge, the Client runs the grant exchanges with the
Anchor as defined by the endorsement protocol in {{PROTOCOLS}}, for
example HTTP POST requests such as the ones defined there. The
`anchor_context` from the challenge is carried into the first request as
specified by the endorsement type.

## Issuance

### Moderator -> Client

~~~tls-presentation
struct {
  uint16 endorsement_type; // always present, see PROTOCOLS
  opaque challenge<V>;
} ModeratorChallenge;
~~~

* `challenge` which contains a base64url ModeratorChallenge value, encoded per {{BASE64}}

The `challenge` field carries exactly the TLS encoding of the common
`RedemptionChallenge` defined in {{PROTOCOLS}}. Anchor material and
issuance contexts come from authenticated configuration; this challenge
is never sent to an Anchor.

~~~
WWW-Authenticate: Mole challenge="<moderator-challenge>",
                       realm="moderator"
~~~

### Client -> Moderator

The Client answers with a `CredentialRequest` ({{PROTOCOLS}}) in the
`Authorization` header of a request to the Moderator. It carries the
endorsement redemption, bound to this challenge, together with the
issuance request.

~~~
Authorization: Mole credential-request="<credential-request>"
~~~

### Moderator -> Client

The Moderator returns the `CredentialResponse` ({{PROTOCOLS}}) in the
`Mole-Credential` response header.

~~~
Mole-Credential: response="<credential-response>"
~~~

## Presentation

### Moderator -> Client - Challenge

~~~tls-presentation
struct {
  uint16 credential_type; // always present, see PROTOCOLS
  opaque challenge<V>;
} CredentialChallenge;
~~~

* `challenge` which contains a base64url `CredentialChallenge` value, encoded per {{BASE64}}

The `challenge` field carries exactly the type-specific challenge defined
for the named credential type in {{PROTOCOLS}}. The Moderator endpoint for
Redeem & Issue comes from configuration ({{configuration}}).

A field that binds a presentation to a request, such as the ACT
`request_context` of {{PROTOCOLS}}, is constructed by the Moderator and
opaque to the Client, which uses the received challenge octets as the
credential type specifies. This document defines no canonicalization of
HTTP requests.

~~~
WWW-Authenticate: Mole challenge="<credential-challenge>",
                       realm="moderator"
~~~

### Client -> Moderator - Presentation

~~~tls-presentation
struct {
  uint16 credential_type; // always present, see PROTOCOLS
  opaque presentation_and_update<V>;
} CredentialPresentation;
~~~

The `presentation_and_update` field carries the `PresentationAndUpdate`
structure of the named credential type, defined in {{PROTOCOLS}}.

~~~
Authorization: Mole presentation="<credential-presentation>"
~~~

A complete instantiation example is given in the appendix of
{{PROTOCOLS}}.

### Moderator -> Client - Update

TODO(thibault)
1. Headers do not have a fixed protocol limit, but large values are hard to deploy. Other instantiations may define another method, such as returning a URL that the client can fetch. TBD

~~~tls-presentation
struct {
  uint16 credential_type;
  opaque update_response<V>;
} CredentialUpdate;

struct {
  optional<CredentialUpdate> update;
} OptionalCredentialUpdate;
~~~

The `update_response` field carries the `Update` structure of the named
credential type, defined in {{PROTOCOLS}}.

Updates use the same `Mole-Credential` header as issuance: both return
credential material from the Moderator. The parameter distinguishes them,
`response` for issuance and `update` after a presentation.

The Moderator MUST send `Mole-Credential` with the `update` parameter
after accepting a presentation. For `ACCEPTED_WITH_UPDATE`, the optional
update is present and carries the credential type's `Update`. For
`ACCEPTED_NO_UPDATE`, the optional update is absent. The Client MUST process
this header even when the protected operation returns an error status.

An absent optional update records the Moderator's decision to consume the
Credential without a replacement. A missing header supplies no such
decision; Clients MUST apply the credential type's recovery rules and
single-use requirements.

* `update` which contains a base64url OptionalCredentialUpdate value, encoded per {{BASE64}}

~~~
Mole-Credential: update="<optional-credential-update>"
~~~

Each credential type MUST define the challenge fields that partition cached
Credentials, or state that Credentials of that type are not cacheable.

### ACT Responses {#act-responses}

For credential type `0x0001`, the Moderator MUST use the following response
rules. The issuance rows apply to Redeem & Issue, and the presentation rows
apply to Presentation and Update, as specified in {{PROTOCOLS}}.

| Outcome | HTTP status | Mole-Credential |
|---|---|---|
| Malformed request encoding | `400` | Omitted |
| Missing, expired, or invalid authentication | `401` | Omitted |
| Rejection by policy before acceptance | `403` | Omitted |
| Successful issuance | `200` | `response` with the `CredentialResponse` |
| Newly accepted presentation | Protected operation's status | `update` with the recorded result |
| Recovery of an accepted presentation's result | `409` | `update` with the recorded result |
{: #tab-act-responses title="ACT HTTP responses"}

A `401` response MUST include a `WWW-Authenticate: Mole` challenge for the
required exchange. Invalid authentication includes an unknown or retired
key, an unaccepted credential context, a failed proof, or a repeated
nullifier for which recovery is unavailable. A recoverable byte-identical
presentation is handled by the recovery row.

Acceptance of an ACT presentation is the recording of its result in the
nullifier store. A response sent after that recording MUST carry the recorded
update, including when the protected operation fails with a `4xx` or `5xx`
status. The update is present for a refund and absent for a recorded
`NoUpdate` decision. Rejecting a presentation MUST NOT create a nullifier
record or carry a credential update.

A recovery response uses `409` (Conflict, {{Section 15.5.10 of HTTP}})
because the presentation has
already been accepted. It carries only the recorded credential result and
MUST NOT authorize another attempt of the protected operation.
Application-specific recovery determines the outcome of the earlier
operation. The Client finalizes a recovered refund under the same rules as
a refund received with the original response.


# Security Considerations

All exchanges defined in this document MUST be carried over HTTPS.

TODO. The list to cover:

1. Challenge replay and caching: when a Client may reuse a cached
   credential against a repeated challenge.
2. Header size limits and what happens when updates exceed them.

# IANA Considerations

## Authentication Scheme

This document registers the `Mole` authentication scheme, as defined in
{{http-authentication-scheme}}, in the "HTTP Authentication Schemes"
registry.

## HTTP Field Names

This document registers the `Mole-Credential` field name in the
"Hypertext Transfer Protocol (HTTP) Field Name Registry".

Endorsement and credential type values are registered in {{PROTOCOLS}}, not
in this document.

--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
