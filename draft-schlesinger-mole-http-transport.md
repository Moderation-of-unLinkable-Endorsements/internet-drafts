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
  TLS13: RFC8446

informative:
  BASE64: RFC4648
  PRIVACYPASS_ACT: I-D.draft-schlesinger-privacypass-act
  QUIC: RFC9000
  REVERSE-FLOW: I-D.draft-meunier-privacypass-reverse-flow

...

--- abstract

TODO Abstract


--- middle

# Introduction

We target browser first. We'll need some HTTP transport. We need to iterate to have

1. discovery. Given both the Anchor and the Moderator both attest and issue, exposing material can be done easily
2. transmission of the anchor set (format+serialisation)
3. errors?
4. credential issuance+presentation flow. Ideally we define a header here that supports CredentialRequest and CredentialResponse. Either we provice one header with a parameter (think step=client-request, step=anchor-response), or distinct headers all together. This is similar to waht is done in {{REVERSE-FLOW}}

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

We describe authentication method of a client that has an endorsement from an
anchor with a site and a moderator.

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

## Endorsement

Nothing to do here, as the attestation method is left to the discretion of the
anchor.

## Issuance

### Moderator -> Client

~~~tls-presentation
struct {
  uint_8 endorsement-type; // We always want endorsement type to be present
  opaque anchor-set; // left opaque for now. Probably opaque anchor-set<V>. This may differ based on the endorsement type: one cryptographic blob that the client can use, multiple public keys that form a set, something else.
} ModeratorChallenge;
~~~

* `challenge` which contains a base64url ModeratorChallenge value, encoded per {{BASE64}}

~~~
WWW-Authenticate: Mole challenge="0x<moderator-challenge>";realm="moderator"
~~~

### Client -> Moderator

MUST be prefixed by `endorsement-type`

~~~
Authorization: Mole endorsement="..."
~~~

## Presentation

### Site -> Client - Challenge

~~~tls-presentation
struct {
  uint_8 credential-type; // We always want credential type to be present
  opaque moderator<1..2^16-1>; // URL of the moderator
} CredentialChallenge;
~~~

* `challenge` which contains a base64url `CredentialChallenge` value, encoded per {{BASE64}}

TODO(thibault):
1. do we need a context?
2. do we need a nonce?

~~~
WWW-Authenticate: Mole challenge="0x<credential-challenge>";realm="site"
~~~

### Client -> Site - Presentation

~~~tls-presentation
struct {
  uint_8 credential-type; // We always want credential type to be present
  opaque presentation-proof[Npp];
  opaque update-request[Nur];
} CredentialPresentation;
~~~

TODO(thibault):
1. presentation needs to include both the proof and the update request. Maybe we split this into two headers as thsat would make scheme easier to compose. Might not be desireable

~~~
Authorization: Mole presentation="0x<credential-presentation>"
~~~

### Site -> Client - Presentation

TODO(thibault)
1. This is the only place where we don't have an established pattern. We need to define a new header. {{REVERSE-FLOW}} uses PrivacyPass-Reverse. Here is a Mole-Update. I'd like something clearer.
2. Header "theoritically" don't have an upper limit, but that might be challenging. Other instantiation may define other method, such as returning a URL that the client can fetch. TBD

~~~tls-presentation
struct {
  uint_8 credential-type;
  opaque update-response<V>;
} CredentialUpdate;
~~~

~~~
Mole-Update: Mole update="0x<credential-presentation>"
~~~


# HTTP protocol (probably its own draft)

In {{http-authentication-scheme}}, we define two protocol registries: endorsement and site.

## Endorsement

0x0001 - Anchor-Hiding endorsement

This is the first protocol

## Credentials

0x0001 - ACT

See {{PRIVACYPASS-ACT}}. Will need to be adapted to be specific here.

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
