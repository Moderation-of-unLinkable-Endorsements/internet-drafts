---
title: "MoLE Cryptography"
abbrev: "MoLE Cryptography"
category: info

docname: draft-authors-mole-crypto-latest
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
  latest: "https://moderation-of-unlinkable-endorsements.github.io/internet-drafts/draft-authors-mole-cryptography.html"

author:
 -
    fullname: John Doe
    organization: ACME
    email: john@example.com

normative:
  Hash2Curve: RFC9380
  TLS13: RFC8446

informative:

...

--- abstract

TODO Abstract


--- middle

# Introduction

TODO

# Conventions and Definitions

{::boilerplate bcp14-tagged}

Unless otherwise specified, this document encodes protocol messages in TLS notation ({{Section 3 of TLS13}}). Moreover, all constants are in network byte order.

# Crypto Bits

We define a two round protocol between an Anchor and Client to produce an endorsement, and then a half-round
Credential generation step presuming the Client knows the Anchors the Issuer accepts. We let hash2curve be the
Hash2Curve function from {{Hash2Curve}}, and H be hash function whose output length is sufficiently long.

The Endorsement is a structure with m, Y=Hash2Curve(m), Zhat, Xhat and
private data gamma. The Anchor has a public key X and a private key x,
and X = xG. The public form of a credential Zhat, Xhat, and a proof
that Xhat = vG, Zhat = vY. Xhat = gamma X, and the client will prove
it knows gamma such that Xhat is a power of one of the public keys of
an Anchor the moderator trusts.

## Issuance Step One: Statement and Commitment

Client randomly selects scalars v and gamma, and sends Yprime = v Y to the anchor.

The Anchor computes Zprime = x Yprime, selects three random scalars aprime, bprime, and tprime.
It computes a commitment. It then computes T1prime = tprime Yprime, T2Prime = tprime G. It then transmits Zprime, Cprime,
and T1prime and T2prime to the client.

## Issuance Step Two: Opening and Proof

The client now has to compute some proof elements and send a scalar to the server. The client
lets Zhat = gamma v^-1 Z. It then picks alpha, a random nonzero scalar, beta, a random scalar,
epsilon, a random nonzero scalar, and rho, a random scalar. The client computes C = alpha^-1 C' - beta H,
T1 = epsilon ^ -1 v ^ -1 (T1prime - rho Yprime), T2 = epsilon ^ -1 (T2prime - rho G).

The client now computes e = H(Y, Zhat, T1, T2, C), and sends eprime = epsilon alpha^{-1} gamma e
to the anchor

The anchor computes rprime = tprime + eprime aprime x and sends back rprime aprime and  bprime.

The client then checks Cprime = aprime G + bprime H, that aprime is invertable, and then computes
a = alpha ^-1 aprime, b=alpha^-1 bprime - beta, r = epsilon ^ -1 (rprime - rho). The client then
verifies Xhat, Zhat, m, e, a, b, r  are a valid endorsement as in the section below.


## Verifying such an endorsement

A verifier gets Xhat, Zhat, m and e, a, b, r. The verifier computes Y=Hash2Curve(m), and then
lets T1 = r Y - e a Zhat, T2 = rG - e a Xhat, C = a G + b H. It checks a is not zero and Y is
not the identity and then checks e = H(Y, Zhat, T1, T2, C).

## Connecting to the issuer

In addition to the above endorsement, the client must prove knowledge of a value gamma such that
Xhat = gamma Xi for some i, where the Xi is the list of issuers trusted. This is a standard
OR sigma proof, and we can use sigma stacking to compact the proof.

# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
