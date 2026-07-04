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
  github: "Moderation-of-unLinkable-Endorsements/internet-drafts"
  latest: "https://moderation-of-unlinkable-endorsements.github.io/internet-drafts/draft-schlesinger-mole-architecture.html"

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
  CONSISTENCY-MIRROR: I-D.ietf-privacypass-consistency-mirror
  KEYTRANS: I-D.ietf-keytrans-architecture
  SCITT: I-D.ietf-scitt-architecture
  RFC9110:
  RFC9576:

...

--- abstract

Moderation of unLinkable Endorsements (MoLE) is an architecture that lets a party performing access control (a Moderator) bootstrap trust in a client from a third party (an Anchor) that already has a trust relationship with that client, and then adjust that trust over time in response to the client's behaviour, for example by dynamically rate-limiting access.

MoLE minimizes the information a client discloses when trust is bootstrapped and limits the signals by which a client can be tracked as it interacts with the system. In particular, a client's interactions are unlinkable to one another, and the endorsing Anchor for a client is hidden among the set of Anchors a Moderator trusts. These properties are designed to hold even when Anchors and Moderators collude. MoLE targets open deployments, in which Moderators and Anchors set their policies independently and need not coordinate.

This document specifies the roles, the information flows between them, the privacy and security requirements, and deployment considerations.

--- middle

# Introduction

Moderation of unLinkable Endorsements (MoLE) is an architecture that allows a
party performing access control to efficiently bootstrap trust in a client from
a third party that already trusts it, and then to adjust that trust over time in
response to the client's behaviour. It does so while minimizing the information
the client discloses when trust is bootstrapped and reducing the signals by
which the client can be tracked as it interacts with the system. MoLE targets
open deployments, in which participants need not coordinate and may hold
independent views of a client's trustworthiness and of one another's
trustworthiness.

Traditional approaches to this problem rely on long-term identifiers such as
user IDs or cookies, which allow clients to be tracked as they interact with the
system. Newer approaches like Privacy Pass {{RFC9576}} enable access control
without identification, but do not support a privacy-preserving mechanism for
bootstrapping trust and cannot adjust trust in clients dynamically over time.

MoLE has three distinct roles. Clients seek to access resources protected by
Moderators, who set and enforce access control policy. A Moderator may have no
direct trust relationship with a Client, but instead trusts Anchors, who do have
a relationship with some Clients, to vouch for them. A given Moderator may trust
multiple Anchors in order to cover more of its user base. An Anchor may vouch for
Clients that a Moderator deems untrustworthy; the Moderator can mitigate this
either by withdrawing trust in those specific Clients or by withdrawing trust in
the Anchor entirely.

At a high level, MoLE relies on three distinct flows: Endorsement, Issuance, and
Presentation. In Endorsement, an Anchor issues a Client an Endorsement, which
conveys the Anchor's trust in the Client to other parties. In Issuance, a Client
presents an Endorsement to a Moderator and receives a Credential, allowing the
Moderator to bootstrap its trust in the Client. In Presentation, the Client
presents a Credential to a Moderator, allowing the Moderator to make an access
control decision and to adjust its level of trust in the Client over time,
including by dynamically rate-limiting access.

Critically, presenting an Endorsement does not reveal the issuing Anchor, only
that it was drawn from a pool of Anchors the Moderator trusts. This avoids
leaking information about the Client, such as which Anchor's policy it satisfies.
Further, a Client's interactions across Issuance and Presentation are unlinkable,
preventing Anchors and Moderators from tracking Clients. These privacy properties
are designed to hold even when Anchors and Moderators collude.

This document describes the requirements for these flows and how they interact,
as well as the anticipated deployment model.

# Use Cases {#use-cases}

MoLE is intended to be deployed on the web, but is applicable to any system where Moderators wish to rate-limit access to resources without having a direct relationship with those clients, instead trusting third parties to vouch for trustworthy users. MoLE tolerates third parties making incorrect decisions, e.g. trusting a malicious client, and enables Moderators to respond dynamically to limit abuse.

MoLE targets an open system where a population of Moderators and Anchors make independent decisions about their access control policy, which Anchors they trust, and which users are Endorsed. This contrasts with a closed system where the parties participating in the system are known a priori and can be expected to coordinate their deployment configuration.

## Reduced-Friction Challenges {#uc-friction}

A user visits a website for the first time, with no cookies and possibly through
a VPN, shared NAT, or privacy-preserving proxy that obscures network-layer
identifiers. The site has no per-user history and limited reputational signal
from the network path. The user then bears the friction if the site responds
with measures intended to mitigate volumetric abuse --- repeated CAPTCHAs,
silent rejection, or a degraded experience --- which also harm users trying to
access the site legitimately.

However, other sites may have access to relatively rich context about a user, e.g. because
the user maintains an account, made a payment, or provided some other scarce
signal to the site. MoLE enables such sites to act as Anchors which issue
Endorsements to users, suitable for bootstrapping trust when users visit new sites for the first time.

In this use case, the site acts as or works with a Moderator.
The Client presents a Credential whose underlying
Endorsement attests to a scarce property accepted under the Moderator's
policy. The site combines this signal with its existing inputs to decide
whether to admit, challenge, or reject the request. A Credential may be
one input among several; it does not entitle the Client to admission.
The Moderator can then go on to adjust the Client's Credential in response to the Client's behaviour, allowing access to be upgraded or removed over time.

## User Agents Acting Under Delegation {#uc-agents}

A user delegates some of their interaction with a site to an automated agent
running in, or alongside, their browser. Such an agent is a user agent: it acts
under delegation from a user who could otherwise have driven the browser
themselves. Sites that lack a richer signal commonly treat the appearance of
automation as grounds for friction or denial of service. This blocks delegated
browsing as a side effect of resisting unwanted automation.

In this use case, the user agent presents a Credential on the user's
behalf. The site admits the request based on the user's standing without the
user agent surfacing a stable identity or correlatable state. From the
Credential alone, the Moderator and the site cannot distinguish presentations
driven by the agent from presentations driven by the user directly.
Distinguishability via request content, timing, or rate is the responsibility
of the user agent and is not addressed by the Credential.

When delegated agent behaviour violates a Moderator's policy, the Moderator may
update state bound to the user's Credential. As a result, the user bears the policy consequences for the behaviour of the delegated agent. However, the delegated agent's actions remain unlinkable to other sessions and to the user's own sessions, and the user's identity is not revealed to the site.

Alternatively, delegated agents may use a distinct pool of Anchors and Credentials from
the user's traditional user agent. This configuration enables sites and Moderators to differentiate
between traditional user agents and delegated user agents and prevents the consequences of
misbehaviour in one context from propagating to the other. User agents not acting under delegation from a user --- for example, autonomous crawlers and non-browser automation --- could also be served with this architecture.

In all configurations, clients enjoy strong privacy protections from sites and Moderators, whilst sites and Moderators enjoy strong protections from abusive clients mounting volumetric attacks.

## Private Access Control {#uc-access}

A user visits a site repeatedly, without persistent cookies, expecting that
successive visits are not linkable to one another. The site gates some
functionality on a non-public criterion such as a paid subscription, group
membership, or a per-period quota of allowed operations.

In this use case, the Anchor's attestation conveys eligibility under such a
criterion, and the Moderator translates that eligibility into a Credential
under a policy that may include rate or quota state. Against the site alone,
successive presentations are unlinkable to each other and to Issuance. The
Moderator necessarily observes Issuance; cross-presentation linkage at the
Moderator is bounded to the granularity of the rate or quota state the
credential carries, with details in {{privacy-properties}}.

This use case is a secondary goal. More
elaborate authorization policies, including rich attribute-based access control
and multi-factor eligibility combinations, are out of scope of this
architecture document but may be included in companion documents.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

The following terms are used throughout this document:

**Client:**
: An entity that seeks access to resources controlled by a Moderator.

**Anchor:**
: An entity that issues Endorsements to Clients based on a trust relationship.

**Moderator:**
: An entity that consumes presentations from Clients and issues Credentials
  according to an access policy.

**Endorsement:**
: A cryptographic object issued by an Anchor to a Client.

**Credential:**
: A cryptographic object issued by a Moderator to a Client. This Credential
  has an associated integer state that is updated during presentation.

**Predicate:**
: A boolean test that a Moderator evaluates against a Credential's hidden state
  during a Presentation. The Moderator learns only whether the state satisfies
  the Predicate, not the state itself.

**Presentation:**
: The mechanism by which a Client proves possession of a Credential whose state
  satisfies a Predicate specified by the Moderator.

**Policy:**
: Rules used by a Moderator to evaluate presentations.

**Anonymity Set:**
: The set of Clients among which a given Client is indistinguishable during an
  interaction. The strength of MoLE's unlinkability and Anchor-hiding properties
  depends on the size of this set.

# Architecture {#architecture}

The MoLE architecture orchestrates trust relationships and
information flows between three entities: Client, Anchor, and Moderator.
These entities have a limited exchange of information that allows for dynamic
rate-limiting, bootstrapped from an Anchor's existing trust, in an open ecosystem. This
section details the information flows and trust relationships between these
entities along with requirements for the underlying protocols and APIs.

## Overview

MoLE is composed of three distinct flows:
Endorsement, in which a Client obtains an Endorsement signifying
its trust relationship with an Anchor; Issuance, in which a Client uses an
Endorsement from an Anchor to obtain a Credential from a Moderator without
revealing which Anchor issued it; and Presentation, in which a Client uses
a Credential from a Moderator to prove that it is
presently in good standing with the Moderator in order to access a resource.

~~~ aasvg
+--------+                    +-----------+               +--------+
| Client |                    | Moderator |               | Anchor |
+---+----+                    +-----+-----+               +----+---+
    |                               |                          |
    |<=========== Interaction ================================>|
    |<=========== Endorsement ================================>|
    |                               |                          |
    |<=========== Interaction =====>|
    |<====== If needed: Issuance ==>|                          |
    |<========= Presentation ======>|                          |
    |                               |                          |
~~~
{: #fig-mole-architecture title="MoLE Architecture"}

During Endorsement, a Client interacts with an Anchor with which it has a
trust relationship. The nature of the trust relationship is specific to the Anchor and may be based on some kind
of strong authentication, e.g. a login, or may be relatively weak, e.g. based on solving a
CAPTCHA. The Anchor issues the Client an Endorsement to signify this trust relationship.
Clients may accrue multiple Endorsements from the same or different Anchors.

Later, when trying to access a resource, a Client may be prompted by a Moderator to present
a Credential. If the Client doesn't have a Credential for this Moderator it will then engage in the
Issuance flow. In this flow, the Client presents the Moderator with an Endorsement from the Moderator's
list of trusted Anchors and receives a Credential in return. Presenting an Endorsement does not reveal which
Anchor was used, only that it came from the trusted pool.

Once a Moderator has accepted a specific Endorsement, the Moderator can prevent a second use of that Endorsement in their system. This property prevents abusive Clients from constantly resetting their state to receive an initial Credential from the Moderator in order to bypass rate limits.

Finally, the Client can present the Credential to the Moderator, along with a credential update request. This presentation enables the Moderator to
query the state of the Credential and receive a boolean value indicating whether the presented Credential meets the
Moderator's chosen predicate. The Moderator can also update the state of the Credential, e.g. to increase or decrease access, but this process does not reveal any further information about the state of the Credential. Depending on the result of the applied predicate, the Moderator can make a decision about access control to the protected resource.

## Privacy Goals and Threat Model {#privacy-properties}

### Goals

MoLE deployments aim to provide three privacy properties for Clients:

1. *Endorsement Issuances and Presentations are Unlinkable* - During an interaction in which a Moderator issues a new Credential on the basis of an Endorsement obtained from an Anchor, neither the Moderator nor the Anchor can link the session in which the Endorsement was issued to the session in which it was presented.

1. *Endorsement Presentations are Anchor-hiding* - During an interaction in which a Moderator issues a new Credential on the basis of an Endorsement from an Anchor, the Client hides the Anchor it obtained the Endorsement from among a set of Anchors the Moderator trusts. Such Anchor-hiding makes an Endorsement presentation indistinguishable regardless of which trusted Anchor the Client used, to both the Anchor and the Moderator.

1. *Credential Issuances and Presentations are Unlinkable* - If a Client engages in multiple presentations, then those presentations are unlinkable to each other and to the Issuance that produced the Credential.

A successful presentation tells the Moderator that the Client holds a
Credential satisfying the Moderator's policy. It does not reveal the Client's
identity, the underlying Anchor, or the state of the Credential. Collectively,
these properties minimize the information Clients reveal to Anchors and Moderators
beyond what is necessary to participate in the system.

The strength of these unlinkability properties depends on anonymity-set size. For
Moderator-credential unlinkability, the relevant set is the population of
Clients holding Credentials under the same Moderator policy.

For Anchor-hiding,
the relevant set is the Moderator's accepted Anchor set. A Moderator with one
accepted Anchor provides no Anchor-hiding.

Further considerations for maximizing the size of these sets are set out in the Privacy Considerations section.

### Threat Model

MoLE's privacy properties are intended to hold in the face of strong attackers who:

* May act in the role of Anchor, Moderator, or Client.
* May collude with other Anchors and Moderators in order to try to identify Clients.
* May have access to a cryptographically relevant quantum computer.
* May deliberately deviate from the protocol and attempt to alter or forge messages.

Some attackers may exploit information not directly revealed by the protocol, for example:
 - Timing information
 - Network metadata like IP addresses
 - Implementation fingerprinting

These side channels, which depend on details specific to each deployment, may compromise the privacy properties of MoLE and are discussed further in the Privacy Considerations.

## Security Goals and Threat Model

### Goals

MoLE's security properties are intended for Moderators. Moderators can be assured:

- When they accept an Endorsement, that it corresponds to exactly one Endorsement Issuance by a trusted Anchor.
- When they accept a Credential under a given predicate, that the Credential is one they previously issued with a matching predicate. Once a Credential has been presented, it will not be accepted again unless the Moderator chooses to re-issue it.

Collectively, these two properties allow Moderators to dynamically rate-limit access to the population of Anchor-endorsed Clients. If Endorsements or Credentials could be presented multiple times, it would allow malicious Clients to obtain additional Credentials which could be used to bypass rate limits.

### Threat Model

MoLE's security properties are intended to hold in the face of coordinated attackers who:
- Can control a number of Clients and deviate from the protocol.
- Cannot violate the issuance criteria for a Moderator's trusted Anchors but may control other Anchors.
- Do not have access to a cryptographically relevant quantum computer.

MoLE considers a cryptographically relevant quantum computer (CRQC) for its privacy properties like Anchor-hiding and unlinkability, because a CRQC deployed in the future could be used to analyse protocol transcripts recorded today and so identify Clients. By contrast, MoLE's security properties hold until an attacker gains access to a CRQC; once they do, only future protocol sessions are affected.

## Flows

### Endorsement

~~~ aasvg
+--------+                 +--------+
| Client |                 | Anchor |
+---+----+                 +---+----+
    |                          |
    |<==Trust Establishment===>|
    +--- EndorsementRequest -->|
    |<-- EndorsementResponse --+
EndorsementFinalization        |
    |                          |
~~~
{: #fig-mole-architecture-endorsement title="MoLE Endorsement"}

An Anchor will endorse a client according to its own criteria for trust in the client.
This may be because of some kind of strong authentication like a login, weak authentication
like a CAPTCHA or any other mechanism that the Anchor deems suitable. Moderators will choose
whether to trust a specific Anchor on the basis of its criteria for endorsing users.

In order to be useful, Anchors will need to constrain how many times they will Endorse a given user.
This is because Endorsements are valuable to Clients and Moderators insofar as they are scarce. If
an Anchor gave out a very large number of Endorsements, this would reduce the effectiveness of rate limiting
applied by Moderators.

Endorsement is likely to be triggered by the Anchor, with the Client storing the resulting
Endorsement. However, in some deployments it may be requested pro-actively by the Client.

Anchors furnish each Endorsement with the necessary metadata to identify the Anchor that used it and for the Client to evaluate whether a given Moderator can consume that Endorsement. This metadata may enumerate specific Moderators (in a small deployment) or identify authentication material like a public key which can be used later to evaluate whether a given Moderator is authorized.

The specific properties of the Endorsement vary based on the exact protocol used. Important properties are described below:

1. The Endorsement is publicly verifiable. That is, any party can verify that the Endorsement is valid without needing access to secret key material held by the Anchor.
1. The Endorsement supports blind presentation. A client presenting the Endorsement does not reveal any information other than that the Endorsement from one of a set of trusted Anchors.
1. Unlinkable Presentation. Even if the Anchor colludes with another party to whom the Endorsement is presented to, they can't link the presentation to the issuance session.
1. The Endorsement supports expiry. A client presenting the Endorsement can prove that the Endorsement was issued within a particular time period.
1. The Endorsement supports one-time use. A Moderator accepting a presented Endorsement will not accept it a second time.

The Endorsement flow must not allow malicious clients to forge tokens offline or otherwise obtain further valid Endorsements without interacting with the Anchor directly. It must be safe to run the Endorsement protocol concurrently with many Clients, some of whom may abort or otherwise misbehave.

### Credential Issuance

~~~ aasvg
+--------+                                +-----------+
| Client |                                | Moderator |
+---+----+                                +-----+-----+
    |                                           |
    |<========== Anchor Negotiation ===========>|
EndorsementPresentation                         |
    +--- EndorsementToken+CredentialRequest --->|
    |<---------- CredentialResponse ------------+
CredentialFinalization                          |
    |                                           |
~~~
{: #fig-mole-architecture-issuance title="MoLE Issuance"}

Issuance is likely to happen on-demand in response to a Moderator's challenge for a
Client to present a valid Credential. The challenge should contain enough information
to identify the Moderator and the Anchors whose Endorsements it will trust for Issuance.
If the Client wishes to complete the presentation and has suitable Endorsements, it will
begin the Issuance flow. In some circumstances, the Moderator may not require any Anchors for Issuance, i.e. it has some local means of establishing trust in this case.

In order to maximize unlinkability, the Issuance and Presentation flows can happen in isolated
contexts, e.g. over distinct communication channels with partitioned state.

In Issuance, the Client presents a proof that it has a suitable Endorsement from an
Anchor Trusted by the Moderator without revealing which specific Anchor was used. In order to translate this into a tangible privacy property for clients, the see the Privacy Considerations section for a discussion around anonymity sets and maximizing them. The proof of Endorsement must be unlinkable to the Issuance of the Endorsement so that even if the Anchor and Moderator collude they can't link the two sessions.

Further, the proof of Endorsement must ensure that even in the presence of a dishonest client, a Moderator will only issue a Credential once for a given Endorsement in order to mitigate attempts to bypass rate limits.

The properties of the Credential issued by the Moderator will vary depending on the exact protocol used. However, they must support:

1. Unlinkable Presentation. A Client presenting a Credential reveals nothing beyond the result of the Moderator's predicate. Two successful presentations cannot be linked to one another, to the Issuance session that produced the Credential, or to any prior update, even if the Moderator records every transcript.
1. One-Time Use. A Moderator accepting a presented Credential will not accept the same Credential a second time. Each successful presentation yields a freshly issued Credential carrying the updated state, so a Client cannot replay a Credential or present a version whose state has since been updated.
1. Predicate Testing. The Moderator can evaluate a predicate against the Credential's hidden state and learns only whether the state satisfies the predicate, not the state itself nor any other information about the Credential.
1. Private Verifiability. Unlike an Endorsement, a Credential is not publicly verifiable. Only the issuing Moderator, using its secret key material, can verify a presented Credential and apply updates to it.
1. One-More Unforgeability. Even a dishonest Client cannot forge a Credential or derive additional valid Credentials from those it holds. A Client issued some number of Credentials cannot produce more valid presentations than it was issued, ensuring each accepted presentation corresponds to exactly one Credential the Moderator issued.
1. Authorization Material. Used by the Client to determine whether a presentation challenge is genuine. This is necessary to prevent a party other than the Moderator 'burning' the Client's Credential.

### Credential Presentation and updates

~~~ aasvg
+--------+                                +-----------+
| Client |                                | Moderator |
+---+----+                                +-----+-----+
    |                                           |
    |<--------- PresentationChallenge ----------+
    |<======= If needed, Issuance =============>|
    |                                           |
CredentialPresentation                             |
    +----- Request+CredentialToken ------------>|
    |                                           |
    |<---- Response+CredentialResponse ---------+
CredentialFinalization                          |
    |                                           |
~~~
{: #fig-mole-architecture-presentation title="MoLE Presentation"}


A Presentation is triggered by the Moderator challenging the Client to present a valid Credential.
The Client will check that the Challenge is from the Moderator via the Authorization Material.
The client will consult its stored Credentials and identify if it has a Credential for this Moderator.
If it doesn't, it will consider triggering the Issuance flow described above.

The challenge will identify a specific Predicate.
If the Client holds a Credential which satisfies the predicate it will perform the presentation.
When a Moderator credential is presented, the Moderator learns
whether or not it satisfies the Moderator's predicate. The presentation
must not be linkable to past updates, or to the credential issuance.

The Presentation is one-time. The Client will not present it again.
The Moderator may re-issue the Credential.
The Moderator may adjust the Credential.

Credential updates must demonstrate that they are applied to the same
credential as was initially presented. This prevents attacks where an
attacker with two credentials shows one, and applies updates only
to the other.

Credential updates have to be applied before access to resources that
an origin may gate or rate limit, so that Clients do not simply ignore
the update request after getting them.

TODO: Updates are Predicates which are true.

## Anchor Feedback

TODO: Discuss use of Prio in Endorsements which feeds into Credentials to measure per-anchor abuse rates.

# Deployment Considerations

## Anchor Selection and Policy

Moderators seek a deployment where honest users are able to pass as many challenges as possible, whereas the number of presentations that malicious users can pass is minimized. The exact weighting between the risk of excluding honest users vs including malicious users is deployment specific.

This guides how Moderator's should select suitable Anchors, seeking to cover their user base whilst minimizing the number of Endorsements that users hold for a given time period. Each Endorsment can be converted into an independent credential, so if a malicious user can get away with X queries before their credential is revoked and they have E endorsements then their total access is X * E.

## Authorization Strategies

Endorsements are associated with a list of Moderators which the Anchor has approved for them to be used with. In a small deployment, this might be a hardcoded list. In a larger deployment, this might be a public key and each Moderator presented a suitable signature from their trusted Anchors. Alternatively an open credential which could be used with any Moderator could be issued.

Similarly, when a Moderator is challenging for a credential, the client needs to know it's a legitimate request. This might be because of a hardcoded credential like a domain name and then using TLS to authenticate the presentation request or might involve a public key and a signature over the challenge.

## Discriminatory Treatment

In general servers already have the ability to deploy access control mechanisms to protect resources under their control. MoLE does not change this but does provide a new privacy preserving access control mechanism.

In {{Section 5.1 of RFC9576}}, Privacy Pass Issuers were encouraged to support a diverse range of attesters in order to reduce the possibility of discriminatory treatment by token verifiers. However, arranging many attesters to agree to use a single issuer is challenging. It requires coordinating changes in the trusted attesters with each downstream verifier. If downstream verifiers have differing token value requirements, this creates friction which leads to partitioning by issuer which reduces client privacy. There is also little incentive for high value attesters to share fate with low value attesters.

The use of Anchors in MoLE and support for multiple Anchors mitigates this issue. Rather than requiring Issuers to coordinate with their Verifiers as to Attestor policy, instead Anchors can individually issue according to their own policies and Moderators can choose which anchors to trust. Moving the decision on aggregation from Issuers to Verifiers resolves the tension inherent in Privacy Pass.

Further, the use of Anchor-Blinding prevents this from being a privacy risk for Clients, since even if Anchors are very fine grained and specific to a particular attestation type, the Moderator does not learn which Anchor was used and so cannot discriminate on this basis. This relies on the Moderator's Anchor set being large and not being partitioned on something specific to the client, which is discussed further in the Privacy Considerations section.

## Centralization

{{Section 5.2 of RFC9576}} identifies Centralization as a major risk from Privacy Pass, in large part due to the motivation for sharing Issuers as described in the previous section. MoLE aims to avoid the same centralization risk through a number of mechanisms.

The Anchor / Endorsement mechanism means that parties that have user relationships and parties that provide access control can be distinct parties without compromising on user privacy. Without this mechanism, only parties which access to a scarce resource could also be effective Moderators, which would encourage centralization.

MoLE allows each Moderator to make an independent decision about which anchors to trust rather than requiring shared Issuers to be established and coordinated. The dynamic rate limiting supported by MoLE enables lower-accuracy Anchors to be used than could otherwise be supported. The Feedback Mechanism also encourages experimentation with new Anchors by providing Moderators with insights into Anchor quality.

However, there are residual risks. Moderators inherently benefit from scale which provides more insight into Client behavior and means that decisions to promote or restrict access are consequently more impactful. Sharing a rate limit across more sites means the amount of volumetric abuse that a attacker can inflict becomes smaller.

## Deployment in a Web Context

In a Web setting, the MoLE architecture may be deployed in several different configurations. For example, the Moderator could be deployed in front of a site, mediating access to protected resources directly, or it could be deployed as an independent service which the site interacts with on the back-end, or the Moderator could be a third party service which communicates with the site through an information flow mediated by the user-agent.

Many browsers limit the flow of information between distinct top-level origins, for example by partitioning cookies and other state. In a web context, MoLE endorsements and credentials may be used without partitioning to enable a limited form of cross-site information transfer. However, user-agents must employ suitable safeguards to ensure that the information flow is limited in line with the user-agent's privacy posture, specific recommendations are given in the Privacy Considerations.

# Security Considerations

## Key Compromise

Anchor key compromise will enable an attacker to produce as many endorsement as they wish. For Moderators which trust this Anchor, attackers will be able to run the Issuance flow as many times as they wish. If any Moderator allocates some rate limited access to each initial Credential, this will enable the Attacker to bypass the rate limit.

Moderator key compromise will enable an attack to produce as many credentials as they like with arbitrary state. However, this will impact only the Moderator and not any other parties.

## State Management

MoLE requires Anchors and Moderators to maintain state in order to uphold its security properties. Anchors which issue on the basis of some long term account will need to maintain state in order to record when a user has been issued an Endorsement. Moderators require state in order to prevent the double-spend of Endorsements and Credentials.

MoLE requires Clients to maintain state in order to benefit from the system. It also requires the timely deletion of state in order to maintain its privacy properties. Firstly, clients must maintain state for their Endorsements and Credentials in order to benefit from the system. Secondly, clients must ensure that once an Endorsement or Credential has been presented, it is deleted or otherwise rendered incapable of being presented again. If a Client undergoes state reset, it compromises the privacy properties of the system.

## DDOS Mitigations

The server-side cost of Presentation flows needs to be as cheap as possible as malicious users who receive a challenge for a presentation may submit responses which will certainly fail but cost server-side resources to verify.

The Issuance Flow is particularly susceptible to DDOS as it is the only flow which is triggered by the client. Moderators should give consideration to suitable protection mechanisms for this endpoint, for example, using a client-side puzzle to ensure that clients spend at least as much CPU as it costs servers to reject a faulty Endorsement presentation.

As the Endorsement flow is triggered by the Anchor in a context where it already trusts the user, it is less vulnerable to DDOS.

# Privacy Considerations

## Anonymity Sets and Minimum Thresholds

Client anonymity sets depend on the total number of clients that share the same configuration metadata. During an Issuance flow, this corresponds to the number of other Clients that possess valid Endorsements for the specified anchor pool. During a Presentation flow, this corresponds to the number of other clients that possess valid Credentials for the specified Anchor pool.

Client Vendors may act to limit the use of Anchors or Moderators where the total anonymity size is too low. For example, the Client Vendors may allow Endorsement flows to succeed but program Clients to flag the resulting Endorsement as unusable until a threshold is met across the fleet of clients. The Client can be programmed not to present an Endorsement during Issuance unless at least one trusted Anchor is of sufficient size.

The same process may be applied to a Moderator's credential during issuance, ensuring that a minimum size set is reached before the Client will present a Credential from a given Moderator.

TODO: Provide a stronger recommendation about which mitigation to apply.

## Configuration Consistency and Partitioning Attacks

During Issuance, if Moderators can rotate their configuration material freely, they can enable the tracking of users, e.g. by restricting a user to a unique configuration which it can later detect. For this reason, Client Vendors should ensure that their clients receive consistent information from Anchors and Moderators.

Deployments should make configuration material consistent across
Clients and resistant to split views. A deployment can use a
{{CONSISTENCY-MIRROR}}, {{KEYTRANS}}, {{SCITT}}, or another mechanism with
similar properties.

TODO: Client-local consistent information vs Globally consistent configuration.

## Side Channels

MoLE does not address all channels that can identify Clients. For example, side channels may reveal information about the user's Client, associated user-agent, hardware configuration, network address or similar information which can be used to cut the user's practical anonymity set. This type of side channel exists largely outside of the architecture's deployment and needs deployment-specific mitigations.

Timing side channels may also reduce the practical anonymity set. For example, Issuance may be performed in response to a challenge for a Presentation by a Moderator. Based on the latency which the Client takes to answer the Presentation Challenge and can likely infer that the Client's presentation can be linked to just-issued Credential. Further, the Moderator can even control how long issuance takes in order to actively cut the anonymity set. Clients can reduce their vulnerability to this type of attack by imposing a limit after which they will not attempt a presentation with a fresh credential after issuance.

Depending on the configuration of clients, other timing side channels may exist in the protocol. For example, if the Client is programmed to fetch Anchor endorsements on-demand (rather than pro-actively provided by an Anchor), a similar timing side channel exists between Endorsement and Issuance. This timing side channel is particularly severe as the Endorsement session may have context which identifies the user or their device. For this reason, deployments are discouraged from fetching Endorsements in direct response to an Issuance session.

Particular consideration should be given to designing flows in which Moderators provide all the information that Clients need during Issuance and Presentation pro-actively, rather than requiring clients to interact with third parties, the Moderator or their Anchors in ways in which might lead to timing side channels.

## Multiple Presentations in Concurrent Contexts

Credentials can only be used a single time. Consider a malicious Moderator which begins a presentation with a Client in one context. From the moment the Client begins to present their credential, they must mark it as burned and cannot use it in another session.

If the Moderator simultaneously issues a challenge for a presentation in a different session, the Moderator can conclude that the Client cannot also answer that presentation (assuming it has a single Credential). A similar pattern holds for Updates. A Credential being Updated cannot be Updated or Presented in any other session.

In order to avoid this behavior being exploited for a timing side channel. E.g. an attacker holds an Update on one client and challenges for Updates in other sessions in order to link two sessions. The client must only never offer the same Credential in concurrent contexts. That is, once a Credential has been used in one context, it must remain locked to that context for a period of a time.

Alt: Destroy credentials for a Moderator if you ever can't present because of concurrency issues?

## Multiple Presentations in the Same Context

Every successful presentation of a Credential reveals at least one bit of information about a client. Answering Multiple presentations for the same or different moderators within one context can lead to greater inferences about the Client.

For example, consider a Moderator that assigns each user a unique integer in their credential, a Presentation Predictate which checks the integer is > 0 and an Update predicate which reduces the integer by 1. If the Moderator can repeatedly issue Presentations and Updates, it can recover each user's unique integer in a given context, allowing their sessions to be linked.

Consequently, the Clients should limit the number of presentations they'll make in any given context. A context is determined by the boundary of information flow. For example, in a web context, a context is governed not only by the top level origin but also carries on through navigations to different sites as bounce tracking or use of tracking URLs can enable information to cross to new pages.

Multiple updates are fine as long as the Updates can never fail.

# IANA Considerations

This document has no IANA actions.

--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
