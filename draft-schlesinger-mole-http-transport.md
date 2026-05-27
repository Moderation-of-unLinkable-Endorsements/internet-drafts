---
title: "MoLE Architecture"
abbrev: "MoLE Architecture"
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
  github: "Moderation-of-unLinkable-Endorsements/architecture-draft"
  latest: "https://Moderation-of-unLinkable-Endorsements.github.io/architecture-draft/draft-schlesinger-mole-http-transport.html"

author:
 -
    fullname: Thibault Meunier
    organization: Cloudflare
    email: ot-ietf@thibault.uk

normative:

informative:
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

# Overview

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

# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
