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
    fullname: Watson Ladd
    organization: Akamai
    email: watsonbladd@gmail.com

normative:
  Hash2Curve: RFC9380
  TLS13: RFC8446
  DLEQ: I-D.draft-irtf-cfrg-sigma-protocols
  FIAT: I-D.draft-irtf-cfrg-fiat-shamir
  ARCH: I-D.draft-jms-mole-architecture

informative:

...

--- abstract

This document defines an issuer hiding anonymous token schemes and how to use it for generating endorsements in MOLE.


--- middle

# Introduction

MOLE Endorsements have a number of constraints imposed by the
architecture {{ARCH}}. They must hide which anchor was used by the
client, must be publicly verifiable, and unlinkable by the anchor. Existing systems do not
meet all of these needs. This document defines such a system and algorithms for issuing an
Endorsement, presenting it, and validating a presentation.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

Unless otherwise specified, this document encodes protocol messages in TLS notation ({{Section 3 of TLS13}}). Moreover, all constants are in network byte order.

# Crypto Bits

We define a two round protocol between an Anchor and Client to produce
an endorsement, and then a half-round Credential generation step
presuming the Client knows the Anchors the Issuer accepts. We let
hash2curve be the RO based Hash2Curve function from {{Hash2Curve}},
and H be hash function whose output length is sufficiently long.

The Endorsement is a structure with m, Y=Hash2Curve(m), Zhat, Xhat and
private data gamma. The Anchor has a public key X and a private key x,
and X = xG. The public form of a credential Zhat, Xhat, and a proof
that Xhat = vG, Zhat = vY. Xhat = gamma X, and the client will prove
it knows gamma such that Xhat is a power of one of the public keys of
an Anchor the moderator trusts.

We present the protocol in a way agnostic to what group is used.
{{ARCH}} currently instantiates this protocol with P-256, in which case
the following two definitions are appropriate.

~~~
    struct {
        uncompressed bytes[65]
    } Point

    struct {
        val bytes[32]
    } Scalar
~~~

We use two generators. G is the generator of the group. H is Hash2Curve("IHAT second generator").
# Issuance

## Issuance Step One: Statement and Commitment

Client randomly selects scalars v and gamma, and sends Yprime = v Y to the anchor.

~~~
    struct {
        Yprime Point
    } ClientFirstMessage
~~~

The Anchor computes Zprime = x Yprime, selects three random scalars
aprime, bprime, and tprime.  It computes a commitment. It then
computes T1prime = tprime Yprime, T2Prime = tprime G. It then
transmits Zprime, Cprime, and T1prime and T2prime to the client. The
anchor also sends a proof that Zprime is computed correctly, that is
DLEQ(G, Yprime, X, Zprime). This proof is a noninteractive sigma
protocol instantiated using the DLEQ proof of {{DLEQ}}, the appropriate group Codec
for the group used,
and SHAKE128 sponge in {{FIAT}}.

~~~
    struct {
        Zprime Point
        Cprime Point
        T1Prime Point
        T2prime Point
        proof bytes<0..2^16-1>
    } AnchorFirstMessage
~~~

## Issuance Step Two: Opening and Proof

The client now has to compute some proof elements and send a scalar to the server. The client
lets Zhat = gamma v^-1 Z. It then picks alpha, a random nonzero scalar, beta, a random scalar,
epsilon, a random nonzero scalar, and rho, a random scalar. The client computes C = alpha^-1 C' - beta H,
T1 = epsilon ^ -1 v ^ -1 (T1prime - rho Yprime), T2 = epsilon ^ -1 (T2prime - rho G).

The client now computes e = H(Y, Zhat, T1, T2, C), and sends eprime = epsilon alpha^{-1} gamma e
to the anchor

~~~
    struct {
        eprime Scalar
    } ClientSecondMessage
~~~

The anchor computes rprime = tprime + eprime aprime x and sends back rprime aprime and  bprime.

~~~
    struct {
        rprime Scalar
        aprime Scalar
        bprime Scalar
    } AnchorSecondMessage
~~~

The client then checks Cprime = aprime G + bprime H, that aprime is invertable, and then computes
a = alpha ^-1 aprime, b=alpha^-1 bprime - beta, r = epsilon ^ -1 (rprime - rho). The client then
verifies Xhat, Zhat, m, e, a, b, r  are a valid partial endorsement as in the section below.

# Presentation

## Verifying a partial endorsement

A verifier gets Xhat, Zhat, m and e, a, b, r. The verifier computes Y=Hash2Curve(m), and then
lets T1 = r Y - e a Zhat, T2 = rG - e a Xhat, C = a G + b H. It checks a is not zero and Y is
not the identity and then checks e = H(Y, Zhat, T1, T2, C).

## Linking to an issuer

In addition to the above endorsement, the client must prove knowledge of a nonzero gamma such that
Xhat = gamma Xi for some i, where the Xi is the list of issuers. This is a disjunctive statement that
can be proven through composition of Sigma Protocols (an OR proof). The next three subsections present
a compact and reasonably efficient OR proof.

### One of Two binding commitments

Let P = Hash2Curve("IHAT unknown discrete logarithm point"). We will define a one of two binding commitment scheme:
the parameters can be generated with a trapdoor such that either the left input or the right input can be equivocated,
but not both.

The parameters for this commitment are a point L. Let R = L + P. Then to bind
a vector (l, r), pick a random s and compute C = s G + l L + r R. This is
a Pedersen commitment.

If L was computed as t G for a random trapdoor t, then the commitment  does
not bind on the left: letting s' = t (l' - l) we get an opening to (l', r). It
does bind on the right as the discrete log of P, and hence R is not known.

Conversely if L was computed as t G - P, then the commitment does not
bind on the right: someone with the trapdoor can set s' = t (r' - r) and
get an opening to (l, r').

The commitment does bind to one of the two positions as the discrete log of
P with respect to G is not known.

To convert to a commitment to arbitrary binary data, not just scalars we use
hash_to_field from {{Hash2Curve}} to hash the inputs into the scalar field.

### One of N binding commitments

Let N be the length of a vector, at least 2. Let n=ceil(log2(N)). A
one of N binding commitment can be formed by a tree construction, where
each internal node is a One of Two binding commitment. The parameters are
n points, each point a parameter for one of two binding commitment.

To commit to a vector pad it on the end to a power of two. Then use
the one of two commitment scheme to collect each pair of adjacent
elements, and produce a single commitment, then recurse until a single
commitment is formed at the top. The same randomness is used at each level.

TODO: consider more efficient, but harder to describe (and maybe more susceptible to side channel) constructions

To create a trapdoor in the parameters the creator of the parameters must
find the path to the point they want to bind, and at each level determine if
that path goes to the right or the left, and set up the trapdoor accordingly
for that level.

To use the trapdoor, equivocate each One of Two commitment on the
binding path, and recompute the rest at each level. This produces a
new opening.

~~~
struct {
    p Point<0..2^16-1>
} OneOfNParams

struct {
    s Scalar<0..2^16-1>
} OneOfNOpening
~~~

### Compact OR proofs

For each i, Xhat = gamma Xi is a statement that fits the Schnorr proof example
in {{DLEQ}}. The client will instantiate a SigmaProtocol instance for each Xi,
but only one will have a witness.

Let j be the index of the key that was actually used. The client will
construct parameters that bind at j.

The client executes prover_commit for instance j, and serializes the
commitment. It then commits to a vector where the entry at j  is the commitment, and all others are zero, to get C

The client then computes challenge = H(params, Xi, C), and then executes
prover_response and serialize_response to obtain the third message. Since all
the instances are of the same sigma protocol, this third message can be used by each instance.

The client now computes a vector of simulated commitments for all instances,
and equivocates the commitment C to this vector. That opening is put in the proof.

~~~
struct {
    params OneofNParams
    s OneOfNOpening
    challenge byte<0..2^16-1>
    third byte<0..2^8-1>
} OneOfNProof
~~~

A verifier uses the third message and challenge to compute the simulated commitments, and then computes C from the opening, then checks challenge = H(params, Xi, C).

## Putting it together

The structure of an endorsement presentation is described below.

~~~
    struct {
        Xhat Point
        Zhat Point
        m Scalar
        e Sclar
        a Scalar
        b Scalar
        r Scalar
        proof OneofNProof
    } EndorsementPresentation

~~~

Given such a presentation, the moderator verifies Xhat, Zhat, m, e, a, b, r
as in Verifying a Partial Presentation, and verifies that Xhat is not the identity. It then verifies that proof demonstrates knowledge of gamma such that
Xhat = gamma Xi for one i, where Xi is the list of public keys to accept.

# IANA Considerations

This document has no IANA actions.

# Security Considerations

Endorsements can only be shown once while preserving
unlinkability. Unlinkability holds even if attackers have quantum
computers, but an attacker with a quantum computer can recover the
public key.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
