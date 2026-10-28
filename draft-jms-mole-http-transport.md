---
title: "MOLE HTTP Transport"
abbrev: "MOLE HTTP Transport"
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
    title: MOLE Protocols
    target: https://datatracker.ietf.org/doc/draft-jms-mole-protocols/00/

informative:
  BASE64: RFC4648

...

--- abstract

MOLE targets browser deployments, so Clients, Anchors, and Moderators need
an HTTP transport for the protocol flows defined by the architecture.

This document defines the `Mole` HTTP authentication scheme, which carries
challenges and presentations for the endorsement and credential flows, and
the headers used to return credential material. The grant exchanges with
the Anchor are defined per protocol in {{PROTOCOLS}}.


--- middle

# Introduction

{{PROTOCOLS}} defines the MOLE messages. This document carries them over
HTTP. Challenges and presentations use the `Mole` authentication scheme
{{HTTP}}. Credential material returns in the `Mole-Credential` response
header. Grant exchanges with an Anchor are HTTP POST requests defined in
{{PROTOCOLS}}.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

Payload encodings and abstract operations are defined by {{PROTOCOLS}}.
Header payloads use canonical unpadded base64url ({{BASE64}}). HTTP carries
type-specific payloads directly, without outer type or length wrappers.

# The Mole Authentication Scheme {#http-authentication-scheme}

~~~ aasvg
+--------+                                +-----------+
| Client |                                | Moderator |
+---+----+                                +-----+-----+
    |                                           |
    |<--- WWW-Authenticate: Mole challenge-T= --+
    |                                           |
(Redeem & Issue, if needed)                     |
    |                                           |
    +--- Authorization: Mole presentation-T= -->|
    |                                           |
    |<------------ Mole-Credential: update-T= --+
    |                                           |
~~~

Payload parameter names end in `-T`, where `T` is a registered endorsement or
credential type from {{PROTOCOLS}}, written as exactly four lowercase
hexadecimal digits. For example, EC-IHAT (endorsement type 0x0002) is
challenged with `redeem-0002`, and EC-ACT (credential type 0x0001) is presented
with `presentation-0001`. Recipients also accept uppercase digits, since
parameter names are case-insensitive ({{Section 11.2 of HTTP}}). Type 0x0000
is invalid.

Each `Mole` challenge has exactly one payload parameter:

| Parameter | Registry | Decoded payload |
|---|---|---|
| `endorse-T` | Endorsement | Anchor context, empty for the types here |
| `redeem-T` | Endorsement | `RedemptionChallenge` |
| `challenge-T` | Credential | Type-specific `Challenge` |
{: title="Challenge parameters"}

A server offers a choice using separate `Mole` challenges. The Client ignores
unknown types and chooses a supported configuration. A `redeem-T` challenge
selects the endorsement type. The Client selects the credential type from the
same Moderator's configuration, independently of the endorsement type.

A `Mole` credential in `Authorization` selects one operation:

| Parameters | Decoded payloads |
|---|---|
| `redeem-E`, `credential-request-C` | `Redemption`, `IssuanceRequest` |
| `presentation-T` | `PresentationAndUpdate` |
| `recovery-T` | Recovery handle |
{: title="Authorization parameters"}

`E` uses the endorsement registry. `C`, presentation, and recovery use the
credential registry. Only Redeem & Issue has two payload
parameters. It requires exactly one of each, in either order. Type 0001's
empty redemption is carried as `redeem-0001=""`.

Parameters use auth-param syntax ({{Section 11.2 of HTTP}}). Values can be
tokens or quoted-strings. Senders quote empty values. Recipients unescape
quoted-strings before decoding. Multiple challenges in one field follow
{{Section 11.6.1 of HTTP}}. These rules apply to each challenge separately.
Unknown parameters, including `realm`, are ignored. A name beginning with one
of the operation prefixes above but lacking exactly four hexadecimal digits
is malformed, not an unknown extension. A recipient MUST reject duplicate
parameter names, mixed operations, and missing or extra payload parameters,
including payloads of unknown types. It MUST reject noncanonical base64url and,
for known types, trailing bytes or malformed content. Clients ignore malformed
challenges and may use another one.

An unknown presentation type is treated as absent when authentication is
optional and rejected when required, as specified by {{PROTOCOLS}}. Other
requests of unknown type are rejected. Unknown types never select a known
payload decoder. Greased types follow these same rules.

# The Mole-Credential Field {#mole-credential}

`Mole-Credential` returns credential material to the Client. Its value is
one parameter, with the syntax above:

| Parameter | Decoded payload |
|---|---|
| `response-T` | `IssuanceResponse` |
| `update-T` | `Update`, or empty for recorded `NoUpdate` |
{: title="Mole-Credential parameters"}

`T` uses the credential registry and MUST match the pending exchange. The
field contains exactly one parameter and MUST NOT be repeated. An empty
`update-T=""` means the Moderator consumed the Credential without replacement.
A nonempty value carries the type's `Update`. Registered credential protocols
MUST define nonempty Update encodings. A missing `Mole-Credential` field carries
no such decision. A Client MUST process `Mole-Credential` whatever the response
status. The credential result does not establish whether the protected
operation completed. Recovery returns this result without another operation
attempt.

A server sending `Mole-Credential` MUST also send `Cache-Control: no-store`.
A server answering cross-origin requests MUST list `WWW-Authenticate` and
`Mole-Credential` in `Access-Control-Expose-Headers`.

# Configuration {#configuration}

The Anchor and Moderator configurations are defined in {{PROTOCOLS}}. A Client
stores each Credential with the Moderator and Redeem & Issue endpoint it
came from. A Client that keeps a presentation for recovery also keeps the
HTTP request that carried it.

# Exchanges

## Grant {#grant}

~~~
WWW-Authenticate: Mole endorse-0002=""
~~~

The grant endpoint comes from Anchor configuration. The Client sends a POST
with the type-specific grant message as its body. The media type is
`application/mole-endorsement-request` with a required `type` parameter using
the same four-digit hexadecimal encoding. The response uses
`application/mole-endorsement-response` with the same type. The Client MUST
reject a mismatched type. There is no outer `EndorsementRequest` or
`EndorsementResponse` wrapper. The first EC-IHAT request carries a
`GrantRequest` naming the number of Endorsements the Client asks for
({{PROTOCOLS}}):

~~~
Content-Type: application/mole-endorsement-request; type=0002
~~~

The criteria for granting are the Anchor's.

## Redeem & Issue {#redeem-issue}

The Moderator challenges with the endorsement type:

~~~
WWW-Authenticate: Mole redeem-0002="<redemption-challenge>"
~~~

The Client answers with a `POST` to the Redeem & Issue endpoint from
configuration, whichever resource sent the challenge:

~~~
Authorization: Mole redeem-0002="<redemption>",
                    credential-request-0001="<issuance-request>"
~~~

On success the Moderator answers `200` with:

~~~
Mole-Credential: response-0001="<issuance-response>"
~~~

## Presentation {#presentation}

The Moderator challenges with the credential type:

~~~
WWW-Authenticate: Mole challenge-0001="<ec-act-challenge>"
~~~

A challenge in a `401` response means the resource requires a presentation.
A challenge in a `200` response means a presentation is optional, for
instance to raise a limit. Clients then apply the greasing rules of
{{PROTOCOLS}}.

The Client repeats the protected request with:

~~~
Authorization: Mole presentation-0001="<presentation-and-update>"
~~~

The Moderator runs `ProcessPresentation`. Every response to an accepted
presentation, fresh or not, MUST carry the recorded update, including when
the protected operation fails with a `4xx` or `5xx` status:

~~~
Mole-Credential: update-0001="<update>"
~~~

For a fresh result the Moderator attempts the protected operation and
returns its status. For a result that is not fresh, it MUST return `409`
({{Section 15.5.10 of HTTP}}) and MUST NOT attempt the protected operation.
A rejected presentation MUST NOT carry `Mole-Credential`.

A Client that receives no `Mole-Credential` after sending a presentation
keeps its pending state and MAY recover ({{recovery}}).

Each credential type MUST define the challenge fields that partition cached
Credentials, or state that its Credentials are not cacheable.

## Recovery {#recovery}

Instead of resending a presentation, a Client MAY send a `POST` with empty
content to the Redeem & Issue endpoint it stored with the Credential:

~~~
Authorization: Mole recovery-0001="<recovery-handle>"
~~~

The recovery handle is defined by the credential type in {{PROTOCOLS}}. The
Moderator treats it as the byte-identical presentation and uses no other
Client identifier. It MUST NOT verify a proof or attempt the protected
operation. If a result is still retained, it answers `200` with the recorded
`update-T`, including the empty value for a recorded `NoUpdate`. Otherwise it
answers `404` without `Mole-Credential`, whether or not a record exists.

## Status Codes {#status-codes}

| Outcome | Status | Mole-Credential |
|---|---|---|
| Malformed request | `400` | none |
| Missing, expired, or invalid authentication | `401` | none |
| Rejected by policy before acceptance | `403` | none |
| Credential issued | `200` | `response-T` |
| Fresh accepted presentation | protected operation's status | `update-T` |
| Duplicate presentation with retained result sent to the protected resource | `409` | `update-T` |
| Recovery, result retained | `200` | `update-T` |
| Recovery, result unavailable | `404` | none |
{: #tab-status title="Mole responses"}

The Moderator MUST use these rules for every credential type. A `401`
response MUST carry a `Mole` challenge for the required exchange. A `403`
returned by the protected operation after a fresh acceptance is that
operation's status, and carries the update.

A Client MUST NOT infer chain termination from any status without the
recorded empty update.

# Security Considerations

All exchanges defined in this document MUST be carried over HTTPS.

TODO. The list to cover:

1. Header size limits: request and response field limits a deployment must
   provision for the payloads it offers, and the status returned before
   acceptance when a payload does not fit. A Moderator must not consume an
   Endorsement, or record `NoUpdate`, because a response would be too large.
2. Challenge caching and reuse: when a Client may reuse a cached challenge
   (same Moderator, type, key and context, scope), and that reuse never
   permits reuse of a spent Credential or Endorsement.
3. Request binding: this document defines no canonical HTTP request
   serialization. EC-ACT `request_context` must cover what the Moderator
   authorizes, including the body. Reverse flow has no request binding.
4. Recovery: what recovery reveals and its lack of Client authentication
   beyond the handle.
5. Grant and issuance recovery: a lost grant or issuance response currently
   costs the Client its session or Endorsement. Whether to add recovery for
   these exchanges, and how to authenticate a lookup by session ID or
   nullifier, is open.

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
