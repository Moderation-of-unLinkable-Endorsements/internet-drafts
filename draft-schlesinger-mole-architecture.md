---
title: "MoLE Architecture"
abbrev: "MoLE Architecture"
category: info

docname: draft-schlesinger-mole-architecture-latest
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
  github: "Moderation-of-unLinkable-Endorsements/architecture-draft"
  latest: "https://Moderation-of-unLinkable-Endorsements.github.io/architecture-draft/draft-schlesinger-mole-architecture.html"

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

informative:
  INTERNET-END-USER: RFC8890
  OBLIVIOUS-HTTP: RFC9458
  PERVASIVE-MONITORING: RFC7258
  RFC9110:
  RFC9576:

...

--- abstract

TODO Abstract


--- middle

# Introduction

Moderation of unLinkable Endorsements (MoLE) is an architecture in which
Sites make authorization decisions from unlinkable, issuer-hiding credential
presentations derived from scarce signals.

Users often encounter friction when a Site has little prior context about
them: for example, when they arrive with no cookies, use a VPN, enable
privacy-preserving browser settings, or delegate browsing to a software agent.
In those cases, the Site may present a CAPTCHA, use fingerprinting, reject the
request, or return a degraded experience. These mechanisms add friction,
collect more information about users, or both. They affect users with strong
privacy preferences and users with accessibility needs. {{INTERNET-END-USER}}
directs the IETF to consider the interests of end users;
{{PERVASIVE-MONITORING}} treats pervasive monitoring as an attack.

MoLE aims to reduce this friction, whilst maintaining the privacy of users, by
enabling new information flows between Sites subject to cryptographically
enforced limits.

Some Sites have access to relatively rich context about a user, e.g. because
the user maintains an account, made a payment or provided some other scare
signal to the Site. MoLE enables such Sites to act as Anchors which issue
Endorsements to users, suitable for bootstrapping trust in other contexts.

MoLE enables multiple Sites to share an access policy through a
Moderator. The Moderator holds a list of trusted Anchors, and can use the Anchor's
Endorsements to issue Credentials to Users which are suitable for use on any of
it's associated Sites. The Moderator can adjust their confidence in the
credentials presented by a user over time. This allows the Moderator to reduce
friction for honest users and increase friction for users which are judged to be
misbehaving (e.g. spamming, credential stuffing, etc).

MoLE
delivers this functionality whilst providing strong privacy protections for users. Sites and Moderators cannot
learn which Anchors a user has access to, only that it holds at least one
suitable Endorsement from the Moderator's trusted list (Anchor Blindness).
Further, even if Sites, Moderators and Anchors all collude in an attempt to
violate User privacy, the user's presentation of their credentials and
endorsements cannot be linked across different contexts (Unlinkability).

MoLE is inspired by the Privacy Pass architecture {{RFC9576}}, but differs in
a number of aspects.

Firstly, MoLE provides greater utility to Sites by enabling Moderators to
dynamically adjust access in response to how a credential is used. Privacy Pass
enforces a flat rate limit based on access to an underlying credential which
cannot be curtailed even if usage is obviously abusive. This leads to
fundamentally different information flows, privacy analysis and cryptographic
techniques.

Secondly, MoLE targets a deployment in an open ecosystem where multiple Anchors,
Moderators and Sites coexist with different policies. This openness, necessary
for deployment in contexts like the Web, requires stronger privacy properties
than are delivered by Privacy Pass. For example, MoLE cannot rely on
non-collusion assumptions between Issuer and Attester as is required in Privacy
Pass's rate-limiting deployments and must instead ensure it's privacy properties
are founded on suitable cryptographic assumptions.

This document specifies MoLE roles, privacy and security requirements, and
deployment considerations. Wire protocols and cryptographic instantiations are
specified in companion documents.

# Use Cases {#use-cases}

In each use case the Client acts on behalf of a user, as part of, or accessed
by, a user agent {{RFC9110}}. The architecture distinguishes the trust the
user places in the user agent from any further delegation the user agent may
itself perform, and does not prejudge the latter.

No use case below by itself motivates the full architecture: simpler designs
cover each in isolation. The case for the architecture rests on the openness
argument in the Introduction together with the union of these cases, and is
most strongly load-bearing for the second.

## Reduced-Friction Challenges {#uc-friction}

A user visits a Site for the first time, with no cookies, possibly through a
VPN or shared NAT that obscures the network-layer identifier. The Site has no
per-user history and limited reputational signal from the network path. The
user is the party who bears the cost of whatever the Site then chooses ---
repeated CAPTCHAs, silent rejection, or a degraded experience --- with
disproportionate cost to users on privacy-preserving network paths and to users
with accessibility needs.

In this use case, the Client presents a Moderator credential whose underlying
Anchor credential attests to a scarce property accepted under the Moderator's
policy. The Site combines this signal with its existing inputs to decide
whether to admit, challenge, or reject the request. A Moderator credential is
one input among several; it does not entitle the Client to admission.

Two consequences shape the design. First, the Client presents a Moderator
credential to the Site in a single request/response exchange; acquisition of
Anchor and Moderator credentials happens off this path. Second, the design must
admit user agents partially or wholly automated on behalf of the user; see
{{uc-agents}}.

## User Agents Acting Under Delegation {#uc-agents}

A user delegates some of their interaction with a Site to an automated agent
running in, or alongside, their browser. Such an agent is a user agent: it acts
under delegation from a user who could otherwise have driven the browser
themselves. Sites that lack a richer signal commonly treat the appearance of
automation as grounds for friction or denial of service. This blocks delegated
browsing as a side effect of resisting unwanted automation.

In this use case, the user agent presents a Moderator credential on the user's
behalf. The Site admits the request based on the user's standing without the
user agent surfacing a stable identity or correlatable state. From the
credential alone, the Moderator and the Site cannot distinguish presentations
driven by the agent from presentations driven by the user directly.
Distinguishability via request content, timing, or rate is the responsibility
of the user agent and is not addressed by the credential.

When delegated agent behaviour violates a Moderator's policy, the Moderator may
update state bound to the user's Moderator credential. This is a deliberate
design choice: the user bears the policy consequence of how they have chosen to
delegate, but does so via a credential unlinkable to the Site, not via
per-user reputation visible to it. The scope of that state, and the requirement
that Moderator state updates not leak information equivalent to per-user state
queries, are addressed in {{privacy-properties}}.

This use case is in tension with {{uc-friction}}: the same surface that admits
a low-friction first visit can also admit unwanted automation. The architecture
locates the trust decision at the Anchor (over scarce signals about the user or
device) and at the Moderator (over policy), not at the appearance of automation
in any single request.

User agents not acting under delegation from a user --- for example, autonomous
crawlers and non-browser automation --- are not explicitly dealt with by this
document, though the architecture can likely apply in many such cases as well.
Whether such an agent obtains an Anchor credential is determined by Anchor
policy, and whether a Moderator continues to admit them when detectable is
determined by Moderator policy. The line between user-driven and autonomous
agents is therefore drawn by Anchors and Moderators.

## Private Access Control {#uc-access}

A user visits a Site repeatedly, without persistent cookies, expecting that
successive visits are not linkable to one another. The Site gates some
functionality on a non-public criterion such as a paid subscription, group
membership, or a per-period quota of allowed operations.

In this use case, the Anchor's attestation conveys eligibility under such a
criterion, and the Moderator translates that eligibility into a credential
under a policy that may include rate or quota state. Against the Site alone,
successive presentations are unlinkable to each other and to issuance. The
Moderator necessarily observes issuance; cross-presentation linkage at the
Moderator is bounded to the granularity of the rate or quota state the
credential carries, with details in {{privacy-properties}}.

This use case is a secondary goal: it does not by itself motivate the
state-bearing Moderator credential, but the architecture admits it and the
authors recommend it's usage for deployments which require this feature. More
elaborate authorization policies, including rich attribute-based access control
and multi-factor eligibility combinations, are out of scope of this
architecture document but may be included in companion documents.


# Conventions and Definitions

{::boilerplate bcp14-tagged}

The following terms are used throughout this document:

**Client:**
: An entity that seeks access to resources held by a Site.

**Site:**
: An entity that consumes presentations from Clients and uses them to make
  authorization decisions.

**Anchor:**
: An entity that issues Endorsements to Clients based on scarce signals.

**Endorsement:**
: A cryptographic object issued by an Anchor to a Client.

**Moderator:**
: An entity that consumes presentations from Clients and issues credentials
  according to a policy.

**Credential:**
: A cryptographic object issued by a Moderator to a Client.

**Presentation:**
: The mechanism by which Clients prove possession of a credential satisfying
  specified attributes.

**Policy:**
: Rules used by a Moderator or Site to evaluate presentations.

# Architecture {#architecture}

## Overview

The Client obtains a credential from an Anchor, presents it to a Moderator, and
uses the resulting Moderator credential when sending requests to a Site.

~~~ aasvg
+--------+                 +--------+             +-----------+             +------+
| Client |                 | Anchor |             | Moderator |             | Site |
+---+----+                 +---+----+             +-----+-----+             +---+--+
    |                          |                        |                       |
    +--- EndorsementRequest -->|                        |                       |
    |<-- EndorsementResponse --+                        |                       |
EndorsementFinalization        |                        |                       |
    |                          |                        |                       |
EndorsementPresentation        |                        |                       |
    +------- EndorsementToken+CredentialRequest ------->|                       |
    |<--------------- CredentialResponse ---------------+                       |
CredentialFinalization         |                        |                       |
    |                          |                        |                       |
CredentialPresentation         |                        |                       |
    +------------------------ Request+CredentialToken ------------------------->|
    |                          |                        |<-- ValidateRequest ---+
    |                          |                        +-- ValidationResult -->|
    |<---------------------- Response+CredentialResponse -----------------------+
CredentialFinalization         |                        |                       |
    |                          |                        |                       |
~~~
{: #fig-mole-architecture title="MoLE Architecture"}

## Flows

Taking {{fig-mole-architecture}}, we can distinguish three flows.

### Endorsement

~~~ aasvg
+--------+                 +--------+
| Client |                 | Anchor |
+---+----+                 +---+----+
    |                          |
    |<===== Attestation ======>|
    +--- EndorsementRequest -->|
    |<-- EndorsementResponse --+
EndorsementFinalization        |
    |                          |
~~~
{: #fig-mole-architecture-endorsement title="MoLE Endorsement"}

Upon passing an attestation, a Client may request an Endorsement from an Anchor.
An Endorsement is a cryptographic object that the client can later present to
a Moderator that proves the Client has been attested by the Anchor.

### Credential Issuance

~~~ aasvg
+--------+                 +--------+             +-----------+
| Client |                 | Anchor |             | Moderator |
+---+----+                 +---+----+             +-----+-----+
    |<===== Endorsement ======>|                        |
    |                          |                        |
EndorsementPresentation        |                        |
    +------- EndorsementToken+CredentialRequest ------->|
    |<--------------- CredentialResponse ---------------+
CredentialFinalization         |                        |
    |                          |                        |
~~~
{: #fig-mole-architecture-issuance title="MoLE Issuance"}

When an Endorsement is presented to a Moderator, the Moderator learns
whether or not the Endorsement originates from the set of Anchors it trusts. The
presentation must not be reveal the Anchor the Client has been endorsed by,
and must not be linkable to other presentations of made using that same
Endorsement.

### Credential Presentation and updates

~~~ aasvg
+--------+               +-----------+             +------+
| Client |               | Moderator |             | Site |
+---+----+               +-----+-----+             +---+--+
    |<====== Endorsement =====>|                       |
    |                          |                       |
CredentialPresentation         |                       |
    +------------- Request+CredentialToken ----------->|
    |                          |<-- ValidateRequest ---+
    |                          +-- ValidationResult -->|
    |<----------- Response+CredentialResponse ---------+
CredentialFinalization         |                       |
    |                          |                       |
~~~
{: #fig-mole-architecture-presentation title="MoLE Presentation"}

When a Moderator credential is presented to a Site, the Site learns
whether or not it satisfies a Site specific policy. The presentation
must not be linkable to past updates, or to the credential issuance.

Credential updates must demonstrate that they are applied to the same
credential as was initially presented. This prevents attacks where an
attacker with two credentials shows one, and applies updates only
to the other.

Credential updates have to be applied before access to resources that
an origin may gate or rate limit, so that Clients do not simply ignore
the update request after getting them.

# Privacy Properties {#privacy-properties}

This section states the privacy goals for MoLE constructions. The wire protocol
and cryptographic instantiation are specified in companion documents.

## Goals

MoLE constructions provide three privacy properties.

1. *Moderator-credential unlinkability.* A Site cannot link two valid
   Moderator-credential presentations to the same Client from the presentation
   alone.

2. *Issuer-hiding.* A Moderator-credential presentation reveals that the
   underlying Anchor is in the Moderator's accepted Anchor set, but not which
   Anchor issued the Anchor credential.

3. *Anchor-endorsement post-issuance unlinkability.* A Moderator cannot link an
   Anchor-endorsement presentation to its issuance transcript. Constructions are
   expected to preserve this property against adversaries that record issuance
   traffic and later gain access to a cryptographically relevant quantum
   computation.

A successful presentation tells the Site that the Client holds a Moderator
credential satisfying the Site's policy. It does not reveal the Client's
identity, the underlying Anchor, or a score assigned by the Moderator.

## Threat Model

The properties above are cryptographic properties of the protocol transcript.
They do not hide information available outside the transcript, such as network
metadata, request contents, timing, or user-agent fingerprinting.

Collusion changes the privacy properties. For example, a Site and Moderator
that share request timing, network metadata, and validation logs may be able to
link presentations even when the credential presentation itself is unlinkable.
Deployment sections describe which entities need to be separated for a given
privacy claim.

## Anonymity Sets

The strength of these properties depends on anonymity-set size. For
Moderator-credential unlinkability, the relevant set is the population of
Clients holding credentials under the same Moderator policy. For issuer-hiding,
the relevant set is the Moderator's accepted Anchor set. A Moderator with one
accepted Anchor provides no issuer-hiding.

Deployments should avoid policy choices, key rotations, or Anchor-set changes
that partition Clients into small sets.

## State

Moderator credentials can carry policy state, such as quota or revocation state.
State updates must not give a Site or Moderator a stable handle that links
future presentations by the same Client.

The details are construction-specific. Companion documents need to specify what
state is carried, who can update it, and what information is revealed by each
update.

## Side Channels

MoLE does not address all channels that can identify Clients. Relevant channels
include network metadata between Client and Anchor, Client and Moderator, and
Client and Site; presentation timing; request contents; accepted-set churn;
policy changes; and key rotation.

These channels need deployment-specific mitigations. For example, {{OBLIVIOUS-HTTP}}
can hide network metadata between the Client and Anchor or
Moderator. The Client-Site channel is outside this architecture.

# Deployment Considerations

# Security Considerations

TODO Security

# Privacy Considerations

TODO Privacy
Consideration section is more widespread than properties


# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
