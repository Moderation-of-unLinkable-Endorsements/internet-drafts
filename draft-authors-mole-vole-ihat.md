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
    fullname: Tianyu Zhang
    organization: University of Illinois at Urbana-Champaign
    email: tianyuz@illinois.edu

  -
    fullname: Christopher Patton
    organization: Cloudflare
    email: chrispatton+ietf@gmail.com

normative:
  IHAT: I-D.draft-authors-mole-crypto
  FIPS202:  # TurboShortSHAKE128(M,d) = Sponge[Keccak-p[800, 12], pad10*1, 800–256](M||1111,d)
    title: "SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions"
    target: https://doi.org/10.6028/NIST.FIPS.202
    date: 2015-08
    seriesinfo:
      "FIPS PUB": "202"
    author:
      -
        org: National Institute of Standards and Technology (NIST)
  FAEST:
    title: "The FAEST Signature Scheme"
    target: https://faest.info/faest-spec-v2.0.pdf
    date: 2025
    seriesinfo:
      "Version": "2.0"
    author:
      -
        ins: C. Baum
        name: Carsten Baum
      -
        ins: L. Braun
        name: Lennart Braun
      -
        ins: W. Beullens
        name: Ward Beullens
      -
        ins: C. Delpech de Saint Guilhem
        name: Cyprien Delpech de Saint Guilhem
      -
        ins: M. Klooß
        name: Michael Klooß
      -
        ins: C. Majenz
        name: Christian Majenz
      -
        ins: S. Mukherjee
        name: Shibam Mukherjee
      -
        ins: E. Orsini
        name: Emmanuela Orsini
      -
        ins: S. Ramacher
        name: Sebastian Ramacher
      -
        ins: C. Rechberger
        name: Christian Rechberger
      -
        ins: L. Roy
        name: Lawrence Roy
      -
        ins: P. Scholl
        name: Peter Scholl
  MAYO:
    title: "MAYO: Practical Post-Quantum Signatures from Oil-and-Vinegar Maps"
    target: https://pqmayo.org/assets/specs/mayo-round2.pdf
    date: 2025-02-05
    seriesinfo:
      "NIST PQC Additional Digital Signatures": "Round 2 Submission"
    author:
      -
        ins: W. Beullens
        name: Ward Beullens
      -
        ins: F. Campos
        name: Fabio Campos
      -
        ins: S. Celi
        name: Sofía Celi
      -
        ins: B. Hess
        name: Basil Hess
      -
        ins: M. J. Kannwischer
        name: Matthias J. Kannwischer
  UOV:
    title: "UOV: Unbalanced Oil and Vinegar"
    target: https://csrc.nist.gov/csrc/media/Projects/pqc-dig-sig/documents/round-2/spec-files/uov-spec-round2-web.pdf
    date: 2025-02
    seriesinfo:
      "NIST PQC Additional Digital Signatures": "Round 2 Submission"
    author:
      -
        ins: W. Beullens
        name: Ward Beullens
      -
        ins: M.-S. Chen
        name: Ming-Shing Chen
      -
        ins: J. Ding
        name: Jintai Ding
      -
        ins: B. Gong
        name: Boru Gong
      -
        ins: M. J. Kannwischer
        name: Matthias J. Kannwischer
      -
        ins: J. Patarin
        name: Jacques Patarin
      -
        ins: B.-Y. Peng
        name: Bo-Yuan Peng
      -
        ins: D. Schmidt
        name: Dieter Schmidt
      -
        ins: C.-J. Shih
        name: Cheng-Jhih Shih
      -
        ins: C. Tao
        name: Chengdong Tao
      -
        ins: B.-Y. Yang
        name: Bo-Yin Yang

informative:
  ARCH: I-D.draft-jms-mole-architecture
  PoMFRIT:
    title: "Concretely Efficient Blind Signatures Based on VOLE-in-the-Head Proofs and the MAYO Trapdoor"
    target: https://eprint.iacr.org/2026/109
    date: 2026
    seriesinfo:
      "Cryptology ePrint Archive": "Paper 2026/109"
    author:
      -
        ins: C. Baum
        name: Carsten Baum
      -
        ins: M. Beckmann
        name: Marvin Beckmann
      -
        ins: W. Beullens
        name: Ward Beullens
      -
        ins: S. Mukherjee
        name: Shibam Mukherjee
      -
        ins: C. Rechberger
        name: Christian Rechberger


...

--- abstract

This document specifies Moussaka, a candidate post-quantum variant of the
Issuer-Hiding Anonymous Token (IHAT) protocol. Moussaka is based on the UOV
digital signature scheme and the VOLE-in-the-Head proof system (a component of
the FAEST signature scheme). The anchor issues a token by signing a commitment
to the client's state; to redeem a token, the client proves knowledge of the
opening of this commitment and a signature produced by some anchor trusted by
the moderator. The commitment is instantiated with Keccak-p[800,12].

--- middle

# Introduction

> WARNING This document specifies a cryptographic protocol that has not yet
> undergone significant security analysis. It's not yet suitable for real world
> applications. Implement at your own risk.

The Issuer-Hiding Anonymous Token {{IHAT}} protocol allows a Client to redeem a
token with a Moderator without revealing which Anchor issued the token.
Instead, the client proves the token was issued by some Anchor in the Anchor
Set trusted by the Moderator. IHAT is also designed to be post-issuance
unlinkable, meaning the redemption of a token cannot be linked to its issuance.

IHAT meets these privacy goals unconditionally, meaning regardless of its
computational resources, no attacker can learn which Anchor issued a token or
to which Client it was issued. On the other hand, it is well known that a
quantum attacker can forge tokens by recovering the Anchor's secret key from
its public key.

This document specifies Moussaka, a variant of IHAT that is plausibly fully
post-quantum secure. Its design is based on the PoMFRIT blind signature scheme
{{PoMFRIT}}, which combines a post-quantum signature scheme with a suitable
zero-knowledge proof system and commitment scheme. Specifically, the signer
signs a commitment to the message, and the verifier checks a zero-knowledge
proof-of-knowledge of the signature and the opening of the commitment. Moussaka
extends this paradigm in the natural way: rather than prove knowledge of a
signature under the public key of a particular Anchor, the Client proves
knowledge of a signature under some public key in the Anchor Set.

Moussaka has significantly higher bandwidth cost compared to IHAT:

1. each Anchor public key is `42.6` kilobytes (this corresponds to the uov-Ip
   parameter set {{UOV}});

1. `TODO` kilobytes are transmitted during issuance; and

1. `TODO*L` kilobytes are transmitted during redemption,

where `L` is the size of the Anchor Set. In particular, the size of the
redemption proof scales linearily with the number of Anchors.

> NOTE(tnyuzg) We should be able to make redemption sublinear using the
> OR proof of ia,cr/2025/113, Section 4.1.
>
> NOTE(tnyuzg) We might be able to reduce the size of both VOLEitH proofs (one
> for issuance and another for redemption) using the more invasive techniques
> from {{PoMFRIT}}, Algorithm 2.

On the other hand, Moussaka is round optimal: only two moves are required for
issuance, whereas IHAT requires three.

The remainder of this document is structured as follows. {{conventions}}
defines some conventions and notation. {{overview}} provides a high-level
overview of the protocol. {{preliminaries}} defines the relevant interfaces for
the signature scheme, commitment scheme, and proof system used by Moussaka and
provides normative references for their specifications. {{protocol}} specifies
the protocol in full detail. Finally, {{security}} enumerates some security
considerations for implementers and adopters.

# Conventions and Definitions {#conventions}

{::boilerplate bcp14-tagged}

> TODO

# Overview {#overview}

Moussaka makes use of three cryptographic primitives:

1. The Unbalanced Oil and Vinegar {{UOV}} digital signature scheme. Each Anchor
   uses a UOV secret key to issue tokens, and during redemption, the Client and
   Moderator agree on a sequence of UOV public keys to use as the Anchor Set.

1. The VOLE-in-the-Head (VOLEitH) zero-knowledge proof system, a component of
   the FAEST digital signature scheme {{FAEST}}.

1. A commitment scheme based on the Keccak permutation {{FIPS202}}.

A UOV public key is a map `P` from `F_q^n` to `F_q^m`. A UOV signature is a
solution `s` to an equation `P(s) = t`, where `t` is called the target and is
computed by hashing the message to be signed. The UOV secret key is a trapdoor
for `P` that can be used to efficiently sample signatures for a given target.
We adopt the uov-1p parameter set (NIST Level 1):  `n=112`, `m=44`, and
`q=2^8`.

Issuance binds a token to an issuance context `ctx_iss` agreed upon by the
Client, Anchor, and Moderator, and a redemption context `ctx_red` agreed upon
by the Client and Moderator {{IHAT}}. The protocol commits to both contexts
during issuance: the Anchor verifies the `ctx_iss` binding during issuance, and
the Moderator verifies both the `ctx_iss` and `ctx_red` binding during
redemption.

The issuance protocol is as follows:

> TODO(cjpatton) Add an illustration of the issuance flow.

1. The Client constructs a commitment `t = Com(nf, ctx_iss, ctx_red, r) ` to a
   nullifier `nf` and the intended issuance and redemption context, where `r`
   is the opening. It also constructs a VOLEitH proof `pf_iss` of knowledge of
   `nf, r, ctx_red` from which `t` was computed sends `t, pf_iss` to the
   Anchor.

1. The Anchor verifies `pf_iss`, samples a solution `s` to `P(s) = t`, then
   sends `s` to the Client.

1. The Client finalizes issuance by checking that `P(s) = t`.

The process resembles blind signature issuance {{?RFC9474}}, The key difference
is that the Anchor observes the signature `s` in plaintext. To ensure
unlinkability, the Client must hide the signature from the Moderator during
redemption.

Let `P[1], ..., P[L]` denote the Anchor Set. To redeem a token, the Client
presents the nullifier in plaintext along with a VOLEitH proof of knowledge of
`s, r` for which `P[i](s) = t` for some `i in [L]` without revealing `i`. In
order to prove this statement with VOLEitH, we need to express it as an
arithmetic circuit.

Our arithmetization exploits the simple structure of UOV signatures as defined
in {{UOV}}. Namely, for any public key  `P` it holds that `P(0^n) = 0^m`. The
idea is to extend the witness with a "selector" vector `b[1], ..., b[L]` for
which `b[j] = 1` if `j = i` and `0` otherwise. First the circuit computes `Q`
as follows:

~~~
Q = [0] * P_len  # number of field elements in each P[i]
for i in range(L):
  for j in range(len(P[i])):
     Q[j] += b[i] * P[i][j]
~~~

It then checks that `Q(s) == Com(nf, ctx_iss, ctx_red, r)` and that
`b[i]*(b[i] - 1) == 0` for all `i in [L]`.

The commitment `Com()` is instantiated with a single evaluation of the
Keccak-p[800,12] permutation {{FIPS202}}. Similar to TurboSHAKE {{!RFC9474}},
this parameterization of Keccak has half the number of rounds as used in SHA-3.
However, its state is also half the size of either SHA-3 or TurboSHAKE. This
helps reduce the size of the VOLEitH proof without impacting the binding or
hiding of the commitment. See {{security}} for details.

> NOTE Both issuance and redemption involve a `Com()` evaluation. An
> alternative is to have the Anchor bind the issuance context by applying an
> outer commit, like `Com(Com(nf, ctx_red, r_red), ctx_iss, r_iss)`. This way
> no issuance proof is required. It would also have the benefit of not
> requiring the stronger one-more-UOV assumption. See {{security}} for details.

# Preliminaries {#preliminaries}

> TODO(cjpatton)

# Protocol {#protocol}

> TODO(cjpatton)

# Security Considerations {#security}

> TODO Prove the following claims.

Issuer-hiding and post-issuance unlinkability of Moussaka reduces to the
zero-knowledge property of the VOLEitH proof system and the hiding property of
our commitment. One-more-unforgeability reduces to witness-extractability of
VOLEitH, binding of the commitment, and the one-more-UOV assumption
({{PoMFRIT}}, Definition 8). The one-more-UOV assumption is a stronger
assumption than standard UOV ({{UOV}}, Definition 2) that requires some
scrutiny before we rely on it too heavily.

> NOTE Here's a sketch of the reduction to one-more-UOV. We consider a
> simplified version of Moussaka, similar to PoMFRIT. During redemption, the
> Client proves knowledge of `s, r` for which `P(s) = c` and `c = Com(nf, r)`.
>
> Our goal is to transform a one-more-redemption forger `B` into a one-more-UOV
> forger `A`. We simulate `B`'s RO queries using the random targets we got as
> input to our one-more-UOV instance; when `B` requests issuance, we forward
> the target to our own `SPre` oracle.
>
> On input `P, t[1], ..., t[Q]` and with oracle `SPre`: Run `B` with `P` as the
> issuer public key and respond to its queries as follows:
>
> * When `B` asks `Com(nf, r)`: for the `i`-th such query, respond with `c =
>   t[i]`.
>
> * When `B` requests issuance for `c`: respond with `s = SPre(c)`.
>
> * When `B` requests redemption for `nf, pi`: extract the witness `s, r` for
>   `pi` and let `c = Com(nf, r)`. (If this fails, then witness extractability
>   of VOLEitH implies the Moderator will reject.) If we didn't issue `s` for
>   `c`, then `B` has successfully one-more-forged. Furthermore, `c = t[i]` for
>   some `i in [Q]`, hence `s` is a solution to our one-more-UOV
>   instance.
>
> NOTE We previously looked at an alternative to the outer commitment in which
> `c` was "tagged" with issuance context `x` via either `c || x` or `c ^ x`. A
> reduction to one-more-UOV is possible, but it incurs a significant loss in
> concrete security, since the reduction has to guess `x` so that it can
> program the random oracle accordingly. Matching attack: XORing the tag
> into the image under the hash makes means the attacker gets to pick any
> prefix it wants. It now only needs to find a collision in the remaining bits
> of the image.

> TODO Justify halving the Keccak state from 1600 to 800 (relative to
> TurboSHAKE).

# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

The use of Keccak-p[800,12] in this application was proposed by Bas Westerbaan.
