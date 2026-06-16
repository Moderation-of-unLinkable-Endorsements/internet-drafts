---
title: "MoLE Protocols"
abbrev: "MoLE Protocols"
category: info

docname: draft-schlesinger-mole-protocols-latest
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
  latest: "https://moderation-of-unlinkable-endorsements.github.io/internet-drafts/draft-schlesinger-mole-protocols.html"

author:
 -
    fullname: Samuel Schlesinger
    organization: Google LLC
    email: sgschlesinger@gmail.com

normative:
  TLS13: RFC8446
  Hash2Curve: RFC9380

informative:
  REVERSE-FLOW: I-D.draft-meunier-privacypass-reverse-flow
  RFC9576:

...

--- abstract

TODO Abstract


--- middle

# Introduction

In this document, we'll register all the token type that privacy pass is lacking and that we need.
I suspect this is likely to lead to another registry, but maybe not needed.

We will NOT use the vocabulary from {{RFC9576}} but rather use {{REVERSE-FLOW}} vocabulary
We indeed need to use credentialRequest/response and distinguish finalisation from presentation.

These are not specific to MoLE, but MoLE must constrain them.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

Unless otherwise specified, this document encodes protocol messages in TLS notation ({{Section 3 of TLS13}}). Moreover, all constants are in network byte order.

# Protocols

Beyond ACT (with some improvement), we'll need to specify the following protocol

## Issuance Protocol for Issuer-unlinkable Privately Verifiable Tokens

Token type `0x0531`

Configuration (these bits will probably differ for MoLE, and we should define the discovery we want)

1. Issuer Request URL <-- issuer name is going to be th erequest URL. Name is a footgun meant for private deployment
2. Issuer public key
3. Challenge value
4. Issuer set <-- magic crypto bits?

This token follws this flow with properties

1. how do we build context to get the endorsement
2. challenge?
3. presentation context: does it need to be flexible?
4. obtention of the issuer set from the origin: what information can the client validate to not reveal themselves

Note: this issuance protocol DOES NOT require a reverse flow, even if in MoLE it will use it to obtain a credential from an endorsement.

Realisation: there is work to do something like https://eprint.iacr.org/2026/870.pdf but without pairing

### Client to Issuer

~~~tls
struct CredentialRequest {
  uint16_t token_type = 0x0531; /* Type something(something) */
  uint8_t truncated_token_key_id; /* Allow for multiple keys per issuer */
  ...
}
~~~

### Issuer to Client

~~~tls
struct CredentialResponse {
  opaque response
}
~~~

The client finalises the response into a Credential

~~~tls
struct Credential {
  uint16_t token_type = 0x0531;
  opaque cred
}
~~~

### Client to Origin

The client knows the set of issuers it needs to present to. It presents the credential to obtain a token

~~~tls
struct Token {
  uint16_t token_type = 0x0531;
  opaque token
}
~~~

# Crypto Bits

We define a two round protocol between an Anchor and Client to produce a Credential, and then a half-round
Token generation step presuming the Client knows the Anchors the Issuer accepts. We let hash2curve be the
Hash2Curve function from {{Hash2Curve}}, and H be hash function whose output length is sufficiently long.

The Credential is a structure with m, Y=Hash2Curve(m), Zhat, Xhat and
private data gamma. The Anchor has a public key X and a private key x,
and X = xG. The public form of a credential Zhat, Xhat, and a proof
that Xhat = vG, Zhat = vY. Xhat = gamma X, and the client will prove
it knows gamma such that Xhat is a power of one of the public keys of
an Anchor the moderator trusts.

## Issuance Step One: Statement and Commitment

Client selects randomly v and gamma, and sends Yprime = v Y to the anchor.

The Anchor computes Zprime = x Yprime, selects three random scalars aprime, bprime, and tprime.
It computes a commitment. It then computes T1prime = tprime Yprime, T2Prime = tprime G. It then transmits Zprime, Cprime,
and T1prime and T2prime to the client.

## Issuance Step Two: Opening and Proof

The client now has to compute some proof elements and send a scalar to the server. The client
lets Zhat = gamma v^-1 Y. It then picks alpha a random nonzero scalar, beta a random scalar,
epsilon a random nonzero scalar, rho a random scalar. The client computes C = alpha^-1 C' - beta G,
T1 = epsilon ^ -1 v ^ -1 (T1prime - rho Yprime), T2 = epsilon ^ -1 (T2prime - rho G).

The client now computes e = H(Y, Zhat, T1, T2, C), and sends eprime = epsilon alpha^{-1} gamma e
to the anchor

The anchor computes rprime = tprime + eprime aprime x and sends back rprime aprime bprime.

The client then checks Cprime = aprime G + brime H, that aprime is invertable, and then computes
a = alpha ^ aprime, b=alpha^-1 bprime - beta, r = epsilon ^ -1 (rprime - rho). The client then
verifies Xhat, Zhat, m, e, a, b, r  are a valid credential as in the section below.


## Verifying such a credential

A verifier gets Xhat, Zhat, m and e, a, b, r. The verifier computes Y=Hash2Curve(m), and then
lets T1 = r Y - e a Zhat, T2 = rG - e a Xhat, C = a G + b H. It checks a is not zero and Y is
not the identity and then checks e = H(Y, Zhat, T1, T2, C).

## Connecting to the issuer

In addition to the above credential, the client must prove knowledge of a value gamma such that
Xhat = gamma Xi for some i, where the Xi is the list of issuers trusted. This is a standard
OR sigma proof, and we can use sigma stacking to compact the proof.

# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
