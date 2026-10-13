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

informative:
  BASE64: RFC4648

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

{{PROTOCOLS}} defines the MoLE messages. This document carries them over
HTTP. Challenges and presentations use the `Mole` authentication scheme
{{HTTP}}. Credential material returns in the `Mole-Credential` response
header. Grant exchanges with an Anchor are HTTP POST requests defined in
{{PROTOCOLS}}.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

Message structures, their encoding, and the abstract operations
(`ProcessPresentation`) are those of {{PROTOCOLS}}.
Every binary value in a header is the unpadded base64url encoding
({{BASE64}}) of the TLS presentation encoding of the named structure.

# The Mole Authentication Scheme {#http-authentication-scheme}

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
    |<-------------- Mole-Credential: update= --+
    |                                           |
~~~

Each `Mole` challenge carries exactly one of these payload parameters:

| Parameter | Sent by | Value |
|---|---|---|
| `endorse` | Anchor | `EndorsementChallenge` ({{grant}}) |
| `redeem` | Moderator | `ModeratorChallenge` |
| `challenge` | Moderator | `CredentialChallenge` |
{: title="Challenge parameters"}

The parameter name tells the Client which structure it holds;
`ModeratorChallenge` and `CredentialChallenge` share a layout. A server
offering a choice sends several `Mole` challenges. The Client picks one it
supports and MUST ignore challenges of unknown type.

A `Mole` credential in `Authorization` carries exactly one of these payload
parameters:

| Parameter | Value |
|---|---|
| `credential-request` | `CredentialRequest` |
| `presentation` | `CredentialPresentation` |
| `recovery` | `CredentialRecovery` ({{recovery}}) |
{: title="Authorization parameters"}

Parameters follow the auth-param syntax of {{Section 11.2 of HTTP}}; a value
may be a token or a quoted-string. One `WWW-Authenticate` field can carry
several challenges ({{Section 11.6.1 of HTTP}}), and the rules below apply to
each `Mole` challenge or credential separately. A recipient ignores unknown
parameters, including `realm`. It MUST reject as malformed a challenge or
credential with a repeated parameter, or with none or more than one of the
payload parameters above. It MUST reject a payload value that is not
canonical unpadded base64url, or whose decoded value does not parse as the
named structure. A Client ignores a malformed challenge and can use another
one.

# The Mole-Credential Field {#mole-credential}

`Mole-Credential` returns credential material to the Client. Its value is
one parameter, with the syntax above:

| Parameter | Value |
|---|---|
| `response` | `CredentialResponse` |
| `update` | `optional<CredentialUpdate>` |
{: title="Mole-Credential parameters"}

An absent `CredentialUpdate` means the Moderator consumed the Credential
without replacement. A missing `Mole-Credential` field carries no such
decision. A Client MUST process `Mole-Credential` whatever the response
status.

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

An Anchor that requires an Endorsement sends:

~~~ tls-presentation
struct {
  uint16 endorsement_type;
  opaque anchor_context<V>;
} EndorsementChallenge;
~~~

~~~
WWW-Authenticate: Mole endorse="<endorsement-challenge>"
~~~

`anchor_context` is opaque to the Client. An endorsement type that uses it
defines how. For the types of {{PROTOCOLS}} it is empty. The criteria for
granting are the Anchor's. The grant requests are those of the endorsement
type in {{PROTOCOLS}}.

## Redeem & Issue {#redeem-issue}

The Moderator challenges with `redeem`:

~~~
WWW-Authenticate: Mole redeem="<moderator-challenge>"
~~~

The Client answers with a `POST` to the Redeem & Issue endpoint from
configuration, whichever resource sent the challenge:

~~~
Authorization: Mole credential-request="<credential-request>"
~~~

On success the Moderator answers `200` with:

~~~
Mole-Credential: response="<credential-response>"
~~~

## Presentation {#presentation}

The Moderator challenges with `challenge`:

~~~
WWW-Authenticate: Mole challenge="<credential-challenge>"
~~~

A challenge in a `401` response means the resource requires a presentation.
A challenge in a `200` response means a presentation is optional, for
instance to raise a limit. Clients then apply the greasing rules of
{{PROTOCOLS}}.

The Client repeats the protected request with:

~~~
Authorization: Mole presentation="<credential-presentation>"
~~~

The Moderator runs `ProcessPresentation`. Every response to an accepted
presentation, fresh or not, MUST carry the recorded update, including when
the protected operation fails with a `4xx` or `5xx` status:

~~~
Mole-Credential: update="<optional-credential-update>"
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
content to the Redeem & Issue endpoint:

~~~ tls-presentation
struct {
  uint16 credential_type;
  opaque recovery_handle<V>;
} CredentialRecovery;
~~~

~~~
Authorization: Mole recovery="<credential-recovery>"
~~~

The recovery handle is defined by the credential type in {{PROTOCOLS}}. The
Moderator treats it as the byte-identical presentation and uses no other
Client identifier. It answers `409` with the recorded update if a result is
still retained, and `401` otherwise, whether or not a record exists. It MUST
NOT perform the protected operation or verify a proof.

## Status Codes {#status-codes}

| Outcome | Status | Mole-Credential |
|---|---|---|
| Malformed request | `400` | none |
| Missing, expired, or invalid authentication | `401` | none |
| Rejected by policy before acceptance | `403` | none |
| Credential issued | `200` | `response` |
| Fresh accepted presentation | protected operation's status | `update` |
| Accepted presentation, not fresh, or recovery | `409` | `update` |
{: #tab-status title="Mole responses"}

The Moderator MUST use these rules for every credential type. A `401`
response MUST carry a `Mole` challenge for the required exchange. A `403`
returned by the protected operation after a fresh acceptance is that
operation's status, and carries the update.

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
