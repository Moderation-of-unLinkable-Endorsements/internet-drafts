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
  VOLE-ACT: I-D.draft-authors-mole-vole-act
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
  SIGMA: I-D.draft-irtf-cfrg-sigma-protocols
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
the moderator. The commitment is instantiated with `Keccak-p[800,12]`.

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
post-quantum secure. Similar to {{VOLE-ACT}}, its design is based on the
PoMFRIT blind signature scheme {{PoMFRIT}}, which combines a post-quantum
signature scheme with a suitable zero-knowledge proof system and commitment
scheme. Specifically, the signer signs a commitment to the message, and the
verifier checks a zero-knowledge proof-of-knowledge of the signature and the
opening of the commitment. Moussaka extends this paradigm in the natural way:
rather than prove knowledge of a signature under the public key of a particular
Anchor, the Client proves knowledge of a signature under some public key in the
Anchor Set.

Moussaka has significantly higher bandwidth cost compared to IHAT:

1. each Anchor public key is 42.6KB (this corresponds to the uov-Ip parameter
   set {{UOV}});

1. ~8KB are transmitted during issuance; and

1. ~9KB are transmitted during redemption, plus a couple bytes per Anchor in
   the Anchor Set.

> NOTE(cjpatton) These numbers aren't based on an actual implementation. They
> are the result of an analysis from Claude Opus 5 looking at the FAEST spec
> and an arithmetization of Keccak in a work in progress implementation.

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

> TODO(cjpatton) Harmonize this section with {{VOLE-ACT}}.

This document follows the same conventions and uses the same notation as
{{VOLE-ACT}}.

Vectors and sequences are indexed from zero: the elements of a length-`k` vector
`v` are `v[0], ..., v[k-1]`. For an integer `k > 0`, we write `[k]` to denote
the set of indices `{0, ..., k-1}`.

We adopt the following notation for byte strings from {{IHAT}}. For two byte
strings `x` and `y`, `x || y` denotes their concatenation. For a byte string
`x`, `x[i..j]` denotes the substring of `x` that begins at its byte with index
`i` and ends just before its byte with index `j`; its length is `j - i` bytes.

We adopt the uov-Ip parameter set (NIST Level 1). That is, in the remainder of
this document, let `n=112`, `m=44`, and `q=2^8`. Each element of `F_q` has a
natural representation as a byte. We sometimes write `F_q^k` to denote the set
of length-`k` byte strings, e.g., `r <- F_q^16` means to choose 16 random bytes
and assign them to `r`.

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

Issuance binds a token to an issuance context `ctx_iss` agreed upon by the
Client, Anchor, and Moderator, and a redemption context `ctx_red` agreed upon
by the Client and Moderator {{IHAT}}. The protocol commits to both contexts
during issuance: the Anchor verifies the `ctx_iss` binding during issuance, and
the Moderator verifies both the `ctx_iss` and `ctx_red` binding during
redemption. Note that Moussaka constrains how these values are chosen compared
to {{IHAT}}; see {{commitment}} for details.

The issuance protocol is as follows:

> TODO(cjpatton) Add an illustration of the issuance flow.

1. The Client constructs a commitment `t = Com(nf, ctx_iss, ctx_red, r)` to a
   nullifier `nf` and the intended issuance and redemption context, where `r`
   is the opening. It also constructs a VOLEitH proof `pf_iss` of knowledge of
   the `nf, r, ctx_red` from which `t` was computed, then sends `t, pf_iss` to
   the Anchor.

1. The Anchor verifies `pf_iss`, samples a solution `s` to `P(s) = t`, then
   sends `s` to the Client.

1. The Client finalizes issuance by checking that `P(s) = t`.

The process resembles RSA blind signature issuance {{?RFC9474}}. The key
difference is that the Anchor observes the signature `s` in plaintext. To
ensure unlinkability, the Client must hide the signature from the Moderator
during redemption.

Let `P[0], ..., P[L-1]` denote the Anchor Set. To redeem a token, the Client
presents the nullifier in plaintext along with a VOLEitH proof of knowledge of
`i, s, r` for which `P[i](s) = t` without revealing `i`. In order to prove this
statement with VOLEitH, we need to express it as a system of constraints over
`F_q`.

The idea is to extend the witness with a "selector" vector `b[0], ..., b[L-1]`
for which `b[u] = 1` if `u = i` and `0` otherwise. The constraints then check
that the public key selected by `b` maps `s` to `Com(nf, ctx_iss, ctx_red, r)`
and that `b` is the indicator vector of a single Anchor. See {{redemption}} for
details.

The commitment `Com()` is instantiated with a single evaluation of the
`Keccak-p[800,12]` permutation {{FIPS202}}. Similar to TurboSHAKE {{?RFC9861}},
this parameterization of Keccak uses half as many rounds as SHA-3. However, its
state is also half the size of the state used by either SHA-3 or TurboSHAKE.
This helps reduce the size of the VOLEitH proof. See {{security}} for
justification.

> NOTE Both issuance and redemption involve a `Com()` evaluation. An
> alternative is to have the Anchor bind the issuance context by applying an
> outer commit, like `Com(Com(nf, ctx_red, r_red), ctx_iss, r_iss)`. This way
> no issuance proof is required. It would also have the benefit of not
> requiring the stronger one-more-UOV assumption. See {{security}} for details.

> NOTE We can add multishow and late binding of redemption context by adding
> another hash evaluation to the redemption proof. See issue 45.

# Preliminaries {#preliminaries}

> TODO(cjpatton) Align preliminaries with {{VOLE-ACT}}.

> TODO(cjpatton) Make all of these algorithms deterministic, passing any
> randomness they would generate as input. This will make it easier to generate
> test vectors.

Define `KP800(state)` to be the output of applying `Keccak-p[800,12]`
{{FIPS202}} to `state in F_q^100`. Note that this is a non-standard size for
the Keccak permutation; see {{security}} for discussion.

We write `(cpk, csk) := UOV.CompactKeyGen()` to denote execution of the compact
key generation algorithm of {{UOV}}, Figure 2. Output `cpk` is the public key
and `csk` is the secret key. The input parameters are omitted and instead
hard-coded as uov-Ip (see {{UOV}}, Table 4).

We write `P := UOV.ExpandPK(cpk)` to denote expansion of the public key into the
UOV map `P : F_q^n -> F_q^m` using the procedure in {{UOV}}, Figure 2.
Likewise, we write `td := UOV.ExpandSK(csk)` to denote expansion of the secret
key into the trapdoor `td` for `P`.

We write `s := UOV.SPre(td, t)` to denote sampling a pre-image of target `t`
under `P`, i.e., an `s` for which `P(s) = t`. This is the same procedure as used
in the signing algorithm in {{UOV}}, Figure 2.

We write `pf := VOLEitH.Prove(R, X, W)` to denote proving knowledge of a
witness `W` for which the pair `(X, W)` is in the relation `R`, where `X` is
the instance, using the VOLE-in-the-Head proof system defined in {{FAEST}}. We
write `v := VOLEitH.Verify(R, X, pf)` to denote verification of `pf` under the
same relation and instance, where the output `v` is a bit.

Relations are specified in the style of {{Section 3.4 of SIGMA}} as a sequence
of constraints. Each constraint is an equation of the instance and witness
variables. Unlike {{SIGMA}}, these equations need not be linear: each side of
the equation is a polynomial of arbitrary degree. However, because the degree
of the polynomial influences the size of the proof, the relation needs to be
designed to balance the size of the witness with the degree of the constraints.

> TODO(cjpatton) Figure out how to cite {{FAEST}} more precisely. Ideally it
> specifies a compiler of constraints into a proof, as in {{SIGMA}}, but this
> is currently beyond the scope of what the FAEST spec does. The degree of
> constraints is coupled tightly to the proof generation procedure, which means
> I think we'll end up pulling some details of the proof construction into this
> document.

# Protocol {#protocol}

> TODO(cjpatton) Specify wire formats for each of the messages. For now we will
> ignore how things are encoded until we're more certain of the shape of the
> protocol.

The constant `VERSION`, an element of `F_q`, is used for versioning and is meant
to be kept in sync with revisions to this document. Its current value SHALL be
`0`.

## Anchor Key Generation

Each Anchor generates its public and secret key pair using the procedure below.

~~~~pseudocode
KeyGen():
  Output:
    - P: a public UOV map from F_q^n to F_q^m
    - td: a secret UOV trapdoor for P

  Steps:
    1. (cpk, csk) := UOV.CompactKeyGen()
    2. P := UOV.ExpandPK(cpk)
    3. td := UOV.ExpandSK(csk)
    4. return (P, td)
~~~~

## Commitment {#commitment}

A Moussaka token commits the Client to a nullifier, an issuance context, and a
redemption context. The commitment is generated by sampling a randomizer `r <-
F_q^16` and running the following procedure:

~~~~pseudocode
Com(nf, ctx_iss, ctx_red, r):
  Input:
    - nf: the nullifier, in F_q^24
    - ctx_iss: issuance context, in F_q^16
    - ctx_red: redemption context, in F_q^16
    - r: the commitment opening, in F_q^16

  Output:
    - t: the commitment, in F_q^m

  Steps:
    1. state := "mouss" || VERSION || 0^10 || r ||
                ctx_iss || ctx_red || 0^12 || nf
    2. t := KP800(state)[0..m]
    3. return t
~~~~

The layout of `state` is chosen so that the entire commitment is computed with a
single application of the permutation. This constrains the lengths of the
inputs: `nf` is 24 bytes, whereas {{IHAT}} uses a 32-byte nullifier, and the
contexts are 16 bytes, whereas {{IHAT}} allows them to be arbitrary byte
strings.

> TODO(cjpatton) Add guidelines for choosing the context strings. Honestly,
> truncating a hash to 16 bytes is not terrible.

## Issuance

During issuance the Client proves knowledge of an opening of the commitment `t`
that binds `t` to the issuance context observed by the Anchor:

~~~~
Relation IssueRelation(t, ctx_iss):
  Instance:
    - t: commitment, in F_q^m
    - ctx_iss: issuance context, in F_q^16

  Witness:
    - nf: nullifier, in F_q^24
    - r: commitment opening, in F_q^16
    - ctx_red: redemption context, in F_q^16

  Constraints:
    - t = Com(nf, ctx_iss, ctx_red, r)
~~~~

> TODO Expand `Com()` into a set of polynomial constraints. An optimization
> that will be important for practice is to commit intermediate states of the
> Keccak evaluation to the witness. We need to define precisely how this works.

### Issue Request

To request a Moussaka token from an Anchor, the Client runs the following
procedure.

~~~~pseudocode
IssueRequest(ctx_iss, ctx_red):
  Input:
    - ctx_iss: issuance context, in F_q^16
    - ctx_red: redemption context, in F_q^16

  Output:
    - pending_token: Client state
    - request: issuance request

  Steps:
    1. nf <- F_q^24
    2. r  <- F_q^16
    3. t  := Com(nf, ctx_iss, ctx_red, r)
    4. pf_iss := VOLEitH.Prove(
         IssueRelation,     // relation
         (t, ctx_iss),      // instance
         (nf, r, ctx_red),  // witness
       )
    5. request := (t, pf_iss)
    6. pending_token := (nf, r)
    7. return (pending_token, request)
~~~~

### Issue Response

To issue a token, the Anchor runs the following procedure on the request, the
trapdoor for its public key, and the issuance context.

~~~~pseudocode
IssueResponse(td, request, ctx_iss):
  Input:
    - td: Anchor secret key
    - request: issuance request
    - ctx_iss: issuance context, in F_q^16

  Output:
    - s: Anchor signature, in F_q^n, or INVALID

  Steps:
    1. (t, pf_iss) := request  // commitment, issuance proof
    2. v := VOLEitH.Verify(
         IssueRelation,  // relation
         (t, ctx_iss),   // instance
         pf_iss,
       )
    3. if v = 0: return INVALID
    4. s := UOV.SPre(td, t)
    5. return s
~~~~

### Finalization

To complete token issuance, the Client runs the following procedure using the
Anchor's public key.

~~~~pseudocode
FinalizeIssue(P, pending_token, s, ctx_iss, ctx_red):
  Input:
    - P: Anchor public key
    - pending_token: Client state
    - s: Anchor signature, in F_q^n
    - ctx_iss: issuance context, in F_q^16
    - ctx_red: redemption context, in F_q^16

  Output:
    - token: the issued token, or INVALID

  Steps:
    1. (nf, r) := pending_token
    2. if P(s) != Com(nf, ctx_iss, ctx_red, r): return INVALID
    3. token := (nf, r, s)
    4. return token
~~~~

## Redemption {#redemption}

Before redemption, the Client and Moderator agree on an Anchor Set consisting
of a sequence of UOV public keys `P[0], ..., P[L-1]`. The Anchor Set MUST NOT
be empty, that is, `L > 0`.

Let `i in [L]` be the index of the issuing Anchor. The witness for the
redemption proof is the opening `r`, the signature `s`, and the selector vector
`b`, where `b[u] = 1` if `u = i` and `0` otherwise. The relation first selects
the Anchor public key `Q` with the following procedure:

~~~~pseudocode
Select(b, P):
  Input:
    - b: selector vector, in F_q^L
    - P: Anchor Set, a sequence of L maps from F_q^n to F_q^m

  Output:
    - Q: the selected map from F_q^n to F_q^m

  Steps:
    1. N := m * n * (n + 1) / 2
    2. Q := 0^N
    3. for u in [L]:
    4.   for j in [N]:
    5.     Q[j] += b[u] * P[u][j]
    6. return Q
~~~~

The first constraint is that `Q(s) = Com(nf, ctx_iss, ctx_red, r)`. The
remaining constraints prove that the selector vector is well-formed, that is,
exactly one entry is set. Because `F_q` has characteristic `2`, the weight
constraint `sum(b) = 1` only tells us that the number of nonzero entries is
odd. We also need some parity constraints, namely `sum(b[0..u+1]) * b[u+1] = 0`
for all `u in [L-1]`. The redemption relation is defined as follows:

~~~~
Relation RedeemRelation(P, nf, ctx_iss, ctx_red):
  Instance:
    - P: Anchor Set of length L
    - nf: nullifier, in F_q^24
    - ctx_iss: issuance context, in F_q^16
    - ctx_red: redemption context, in F_q^16

  Witness:
    - r: F_q^16
    - s: F_q^n
    - b: F_q^L

  Where:
    - Q = Select(b, P)

  Constraints:
    - Q(s) = Com(nf, ctx_iss, ctx_red, r)
    - sum(b[0..u+1]) * b[u+1] = 0            for u in [L-1]
    - sum(b) = 1
~~~~


### Redeem Request

To redeem a token `token = (nf, r, s)` issued by Anchor `P[i]`, the Client runs
the following procedure.

~~~~pseudocode
RedeemRequest(P, i, token, ctx_iss, ctx_red):
  Input:
    - P: Anchor Set of length L
    - i: index of the issuing Anchor, in [L]
    - token: the issued token
    - ctx_iss: issuance context, in F_q^16
    - ctx_red: redemption context, in F_q^16

  Output:
    - request: redemption request

  Steps:
    1. (nf, r, s) := token
    2. b := 0^L  // selector vector
    3. b[i] := 1
    4. pf_red := VOLEitH.Prove(
         RedeemRelation,             // relation
         (P, nf, ctx_iss, ctx_red),  // instance
         (r, s, b),                  // witness
       )
    5. request := (nf, pf_red)
    6. return request
~~~~

### Finalization

To complete the redemption request, the Moderator runs the following procedure.

~~~~pseudocode
FinalizeRedeem(P, request, ctx_iss, ctx_red):
  Input:
    - P: Anchor Set of length L
    - request: redemption request
    - ctx_iss: issuance context, in F_q^16
    - ctx_red: redemption context, in F_q^16

  Output:
    - nf: the nullifier of the redeemed token, in F_q^24, or INVALID

  Steps:
    1. (nf, pf_red) := request
    2. v := VOLEitH.Verify(
         RedeemRelation,             // relation
         (P, nf, ctx_iss, ctx_red),  // instance
         pf_red,
       )
    3. if v = 0: return INVALID
    4. return nf
~~~~

# Security Considerations {#security}

> TODO Prove the following claims.

Issuer-hiding and post-issuance unlinkability of Moussaka reduce to the
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
> On input `P, t[0], ..., t[Q-1]` and with oracle `SPre`: Run `B` with `P` as
> the issuer public key and respond to its queries as follows:
>
> * When `B` asks `Com(nf, r)`: for the `i`-th such query, counting from zero,
>   respond with `c = t[i]`.
>
> * When `B` requests issuance for `c`: respond with `s = SPre(c)`.
>
> * When `B` requests redemption for `nf, pf`: extract the witness `s, r` for
>   `pf` and let `c = Com(nf, r)`. (If this fails, then witness extractability
>   of VOLEitH implies the Moderator will reject.) If we didn't issue `s` for
>   `c`, then `B` has successfully one-more-forged. Furthermore, `c = t[i]` for
>   some `i in [Q]`, hence `s` is a solution to our one-more-UOV
>   instance.

> NOTE We previously looked at an alternative to the outer commitment in which
> `c` was "tagged" with issuance context `x` via either `c || x` or `c XOR x`. A
> reduction to one-more-UOV is possible, but it incurs a significant loss in
> concrete security, since the reduction has to guess `x` so that it can
> program the random oracle accordingly. Matching attack: XORing the tag
> into the image under the hash means the attacker gets to pick any prefix it
> wants. It now only needs to find a collision in the remaining bits of the
> image.

> TODO Justify halving the Keccak state from 1600 to 800 (relative to
> TurboSHAKE).

# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

The use of `Keccak-p[800,12]` in this application was proposed by Bas
Westerbaan. Claude Opus 5 suggested the parity constraints for the redemption
proof.
