---
title: "MoLE HTTP Transport"
abbrev: "MoLE HTTP Transport"
category: info

docname: draft-schlesinger-mole-http-transport-latest
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
  latest: "https://moderation-of-unlinkable-endorsements.github.io/internet-drafts/draft-schlesinger-mole-http-transport.html"

author:
 -
    fullname: Thibault Meunier
    organization: Cloudflare
    email: ot-ietf@thibault.uk

normative:
  HTTP: RFC9110
  URI: RFC3986
  TLS13: RFC8446

informative:
  BASE64: RFC4648
  PRIVACYPASS_ACT: I-D.draft-schlesinger-privacypass-act
  QUIC: RFC9000
  REVERSE-FLOW: I-D.draft-meunier-privacypass-reverse-flow

...

--- abstract

MoLE targets browser deployments, so Clients, Anchors, Moderators, and Sites
need an HTTP transport for the protocol flows defined by the architecture.

This document defines HTTP authentication scheme for endorsement, credential
issuance, and credential presentation. It also defines configuration material
exposed by Anchors and Moderators.


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
defined in {{HTTP}}. The same scheme is used for three protocol exchanges:
Client to Anchor endorsement, Client to Moderator credential issuance, and
Client to Site credential presentation.

~~~ aasvg
+--------+                                     +------+
| Client |                                     | Site |
+---+----+                                     +---+--+
    |                                              |
    |<--- WWW-Authenticate: CredentialChallenge ---+
    |                                              |
(Run issuance and presentation protocol)           |
    |                                              |
    +--- Authorization: token                  --->|
    |    Mole-Issuance: CredentialRequest          |
    |                                              |
    |<-------- Mole-Issuance: CredentialResponse --+
    |                                              |
~~~

Mole-Issuance is a placeholder header. We might want Mole-Presentation as well.

# Configuration

TODO(thibault)
1. if protocol section goes into its own draft, this should follow
2. I suspect we'll use JSON here. If we use key material, I think re-using JWKS is important (even if there are feelings).

Anchors and Moderators publish configuration used by Clients and Sites before
running the HTTP authentication flows. Configuration includes endpoint URLs,
supported protocol types, public key material, and the Anchor set associated
with each Moderator policy.

TODO(thibault)
1. Anchor-Set format. I'm not sure we can find a shared format, or if this should
   be specific to each endorsement protocol

# Error Handling

TODO: define error status codes, authentication error parameters, and recovery
behavior for malformed messages, unsupported protocol types, failed validation,
and unavailable Anchors or Moderators.

## Endorsement

The attestation method is left to the Anchor. This document only defines the
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
WWW-Authenticate: Mole challenge="<endorsement-challenge>", realm="anchor"
~~~

### Client -> Anchor

~~~tls-presentation
struct {
  uint16 endorsement_type;
  opaque request<V>;
} EndorsementRequest;
~~~

~~~
Authorization: Mole endorsement-request="<endorsement-request>"
~~~

### Anchor -> Client

~~~tls-presentation
struct {
  uint16 endorsement_type;
  opaque response<V>;
} EndorsementResponse;
~~~

~~~
Mole-Endorsement: response="<endorsement-response>"
~~~

## Issuance

### Moderator -> Client

~~~tls-presentation
struct {
  uint16 endorsement_type; // We always want endorsement type to be present
  opaque policy_context<V>; // Moderator-generated policy identifier
  opaque anchor_set<V>; // This may differ based on the endorsement type: one cryptographic blob that the client can use, multiple public keys that form a set, something else.
} ModeratorChallenge;
~~~

* `challenge` which contains a base64url ModeratorChallenge value, encoded per {{BASE64}}

~~~
WWW-Authenticate: Mole challenge="<moderator-challenge>", realm="moderator"
~~~

### Client -> Moderator

MUST be prefixed by `endorsement_type`.

~~~
Authorization: Mole endorsement="..."
~~~

## Presentation

### Site -> Client - Challenge

~~~tls-presentation
struct {
  uint16 credential_type; // We always want credential type to be present
  opaque moderator_url<1..2^16-1>; // Absolute HTTPS URL of the moderator
  opaque policy_context<V>; // Moderator-generated policy identifier
  opaque presentation_context<0..32>; // Site-chosen binding value, analogous to redemption_context in RFC9577
} CredentialChallenge;
~~~

* `challenge` which contains a base64url `CredentialChallenge` value, encoded per {{BASE64}}

The `moderator_url` field contains an absolute `https` URI. It MUST NOT contain
a fragment component. Clients MUST reject challenges with non-HTTPS Moderator
URLs or malformed URLs. URI syntax is defined by {{URI}}.

The `policy_context` field is generated by the Moderator. It identifies the
Moderator policy and accepted Anchor set used for this Site. The same Moderator
MAY use different policy contexts for different Sites. The value MUST be
non-empty.

The `presentation_context` field is chosen by the Site. It binds the
presentation to a request, session, or time window. A non-empty value affects
credential caching and replay handling.

TODO(thibault):
1. decide exact construction rules for presentation_context

~~~
WWW-Authenticate: Mole challenge="<credential-challenge>", realm="site"
~~~

### Client -> Site - Presentation

~~~tls-presentation
struct {
  uint16 credential_type; // We always want credential type to be present
  opaque presentation_proof[Npp];
  opaque update_request[Nur];
} CredentialPresentation;
~~~

TODO(thibault):
1. presentation needs to include both the proof and the update request. Maybe we split this into two headers as that would make scheme easier to compose. Might not be desirable

~~~
Authorization: Mole presentation="<credential-presentation>"
~~~

For Credential types that require private verification, the Site MUST validate
the presentation with the Moderator identified by `moderator_url` before
granting access to a protected resource.

The validation request is sent to `moderator_url` over HTTPS. The exact HTTP
method and response status handling are TBD.

### Site -> Moderator - Validation

~~~tls-presentation
struct {
  uint16 credential_type;
  opaque policy_context<V>;
  opaque presentation_context<0..32>;
  opaque presentation_proof[Npp];
  opaque update_request[Nur];
} ValidationRequest;
~~~

~~~tls-presentation
struct {
  uint16 credential_type;
  uint8 valid;
  opaque update_response<V>;
} ValidationResult;
~~~

### Site -> Client - Update

TODO(thibault)
1. This is the only place where we don't have an established pattern. We need to define a new header. {{REVERSE-FLOW}} uses PrivacyPass-Reverse. Here is a Mole-Update. I'd like something clearer.
2. Headers do not have a fixed protocol limit, but large values are hard to deploy. Other instantiations may define another method, such as returning a URL that the client can fetch. TBD

~~~tls-presentation
struct {
  uint16 credential_type;
  opaque update_response<V>;
} CredentialUpdate;
~~~

The Site SHOULD send `Mole-Update` when the Credential remains usable after
presentation. The Site MAY omit `Mole-Update` to intentionally consume the
Credential. Clients MUST follow the Credential type semantics for reuse after an
omitted update.

~~~
Mole-Update: update="<credential-update>"
~~~

Cached Credentials MUST only be used for matching `credential_type`,
`moderator_url`, and `policy_context`. If `presentation_context` is non-empty,
the cached Credential MUST also match that value.


# HTTP protocol (probably its own draft)

In {{http-authentication-scheme}}, we define two protocol registries: endorsement and site.

## Endorsement

0x0001 - Anchor-Hiding endorsement

This is the first protocol

## Credentials

0x0001 - ACT

See {{PRIVACYPASS_ACT}}. Will need to be adapted to be specific here.

0x0002 - ReverseFlow(VOPRF(P384))

Presenting a VOPRF token, with the update being a request for a new VOPRF token.

### Client -> Anchor

### Anchor -> Client

# IANA Considerations

## Authentication Scheme

We register `Mole` as defined in {{http-authentication-scheme}}

## Endorsement registries

## Credential registries

--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
