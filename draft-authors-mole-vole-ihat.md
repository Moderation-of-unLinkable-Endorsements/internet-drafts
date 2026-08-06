---
title: "Moussaka"
abbrev: "Moussaka"
category: info

docname: draft-authors-mole-vole-ihat-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
keyword:
  - moderation
  - unlinkability
  - privacy
venue:
  github: "Moderation-of-unLinkable-Endorsements/internet-drafts"
  latest: "https://moderation-of-unlinkable-endorsements.github.io/internet-drafts/draft-authors-mole-vole-ihat.html"

author:

  -
    fullname: Christopher Patton
    organization: Cloudflare
    email: chrispatton+ietf@gmail.com

normative:
informative:

...

--- abstract

This document specifies Moussaka, a candidate post-quantum variant of the
Issuer-Hiding Anonymous Token (IHAT) protocol. Moussaka is based on the UOV
digital signature scheme and the VOLE-in-the-Head proof system (a component of
the FAEST signature scheme). The anchor issues a token by signing a commitment
to the client's state; to redeem a token, the client proves knowledge of the
opening of this commitment and a valid signature produced by some anchor
trusted by the moderator. The commitment is instantiated with Keccak-p[800,12].

--- middle

# Introduction

> TODO(cjpatton)

# Conventions and Definitions

{::boilerplate bcp14-tagged}

> TODO

# Protocol

> TODO(cjpatton)

# Security Considerations

> TODO

# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

The use of Keccak-p[800,12] in this application was proposed by Bas Westerbaan.
