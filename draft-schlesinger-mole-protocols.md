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
  ACT: I-D.draft-schlesinger-cfrg-act
  ARCHITECTURE: I-D.draft-schlesinger-mole-architecture
  CRYPTO: I-D.draft-authors-mole-crypto
  HTTP-TRANSPORT: I-D.draft-schlesinger-mole-http
  LONGFELLOW: I-D.draft-google-cfrg-libzk
  PRIVACYPASS-BATCHED: I-D.draft-ietf-privacypass-batched-tokens
  PRIVACYPASS-PROTOCOLS: RFC9578
  REVERSE-FLOW: I-D.draft-meunier-privacypass-reverse-flow

informative:
  RFC9576:

...

--- abstract

This document defines realisation of {{ARCHITECTURE}}, with two endorsements and two credentials protocols.


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

# Endorsement Protocols

Endorsements is defined in {{Section X of ARCHITECTURE}}. It takes part in the
Endorsement flow and the Redemption+Issue flow. Such a protocol is defined in
three flows: Client to Anchor, Anchor to Client, Client to Moderator. This
section present two protocols that achieve this.

## Issuer-Hiding Anonyous Token {#ihat}

Vocabulary

Anchor Public Key
: pkI as defined in {{Section X of CRYPTO}}

Challenge
: an opaque byte string. Might be provided by {{HTTP-TRANSPORT}}

### Client to Anchor

The client creates a context as follow

~~~
client_context = SetupIHATClient("P256-SHA256", PKI)
~~~

"P256-SHA256" corresponds to IHAT(P-256, SHA-256) defined in {{Section X of CRYPTO}}.

... complete once the crypto is done.

### Anchor to Client

Response of the anchor + finalisation, if any

### Client to Moderator

OR proof, possibly interactive

## Longfellow

Builds on legacy credential. On the contrary to {{ihat}}, it favours compatibility with legacy credentials
over using performant cryptography constructions.

Fill with https://github.com/thibmeu/longfellow-zk/blob/hidden-issuer-poc/lib/circuits/mdoc/HIDDEN_ISSUER.md
In short, we need a circuit

### Client to Anchor

### Anchor to Client

### Client to Moderator

# Credentials Protocols

Credential is defined in {{Section X of ARCHITECTURE}}. It takes part in the
Endorsement flow and the Redemption+Issue flow. Such a protocol is defined in
four flows between the Client and the Moderator, two for the Issuance, and two for the "Presentation and update". 
This section present three protocols that achieve this.

## ACT {#credential-act}

Take the information from draft-schlesinger-privacypass-act
It is very much an anonymous state machine.

### Issuance

### Presentation and Update

## Privacy Pass with a Reverse Flow

Only one bit back and forth, leveraging the tokens defined in {{PRIVACYPASS-PROTOCOLS}}.

Open question: ensure that the update can only be applied to the issuing state, and not transfered?

### Issuance

Request a privacy pass token. The bits are essentially the same as privacy pass , except that
they are base64url encoded when passed as an HTTP header like defined in {{HTTP-TRANSPORT}}.

### Presentation and Update

Using {{REVERSE-FLOW}} architecture. The moderator acts as joint initial and reverse issuer.
We mandate that the presented and requested token use the same protocol and
are associated to the same public key. This prevents leakage.

### Moderator configuration

supported algorithm + public key

Open question: how to format this configuration? options are
1. privacy pass like configuration
2. a new type of configuration
3. something closer to JWKS/JWP, not sure what is required there.

## Budget Privacy Pass

Leverages {{PRIVACYPASS-BATCHED}} along with {{REVERSE-FLOW}}.
The moderator operates N issuer, each representing a power of 2.
This is known to the client.

Note: depending on your deployment constraints and the number of bits
required in the encoding, {{credential-act}} may be better suited.

### Issuance

The client requests a token from the issuer with the highest value.

### Presentation and Update

The client present the token with the higest value, while it requests token for each of the other issuer.
This include issuer with a higher value tan the one it has, in case of a positive update from the issuer.
The moderator issues tokens that sum up to the update it wants to provide back to the client.

### Moderator configuration

Public key for each issuer, value of the issuer (possiby infered from the order), refund endpoint to exchange multiple
small tokens against a bigger one.

# Security Considerations

# IANA Considerations

We create two registries

1. Endorsement protocols
2. Credentials Protocols

Initially populated with protocols presented in this draft.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
