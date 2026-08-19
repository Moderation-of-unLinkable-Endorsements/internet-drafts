---
title: "Ratatouille"
abbrev: "Ratatouille"
category: info

docname: draft-authors-mole-vole-act-latest
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
  latest: "https://moderation-of-unlinkable-endorsements.github.io/internet-drafts/draft-authors-mole-vole-act.html"

author:
  -
    fullname: Tianyu Zhang
    organization: University of Illinois at Urbana-Champaign
    email: tianyuz@illinois.edu

  -
    fullname: Christopher Patton
    organization: Cloudflare
    email: chrispatton+ietf@gmail.com

  -
    fullname: Samuel Schlesinger
    organization: Google
    email: samschlesinger@google.com

normative:
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
  ARCHITECTURE: I-D.draft-jms-mole-architecture
  ACT: I-D.draft-schlesinger-cfrg-act-01
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

  Fischlin:
    title: "Round-Optimal Composable Blind Signatures in the Common Reference String Model"
    target: https://doi.org/10.1007/11818175_4
    date: 2006
    seriesinfo:
      "CRYPTO": "2006, LNCS 4117, pp. 60-77"
    author:
      -
        ins: M. Fischlin
        name: Marc Fischlin

  BFMRSV25:
    title: "Multivariate Commitments and Signatures with Efficient Protocols"
    target: https://eprint.iacr.org/2025/2035
    date: 2025
    seriesinfo:
      "Cryptology ePrint Archive": "Paper 2025/2035"
    author:
      -
        ins: C. Bouillaguet
        name: Charles Bouillaguet
      -
        ins: T. Feneuil
        name: Thibauld Feneuil
      -
        ins: J. Maire
        name: Jules Maire
      -
        ins: M. Rivain
        name: Matthieu Rivain
      -
        ins: J. Sauvage
        name: Julia Sauvage
      -
        ins: D. Vergnaud
        name: Damien Vergnaud

  CryptEst:
    title: "CryptographicEstimators: A Software Library for Cryptographic Hardness Estimation"
    target: https://eprint.iacr.org/2023/589
    date: 2023
    seriesinfo:
      "Cryptology ePrint Archive": "Paper 2023/589"
    author:
      -
        ins: A. Esser
        name: Andre Esser
      -
        ins: J. Verbel
        name: Javier Verbel
      -
        ins: F. Zweydinger
        name: Floyd Zweydinger
      -
        ins: E. Bellini
        name: Emanuele Bellini

  BNPS03:
    title: "The One-More-RSA-Inversion Problems and the Security of Chaum's Blind Signature Scheme"
    target: https://eprint.iacr.org/2001/002
    date: 2003
    seriesinfo:
      "Journal of Cryptology": "16(3), pp. 185-215"
    author:
      -
        ins: M. Bellare
        name: Mihir Bellare
      -
        ins: C. Namprempre
        name: Chanathip Namprempre
      -
        ins: D. Pointcheval
        name: David Pointcheval
      -
        ins: M. Semanko
        name: Michael Semanko

...

--- abstract

This document specifies Ratatouille, a candidate post-quantum variant of the
Anonymous Credit Token (ACT) protocol. Ratatouille is based on the UOV digital
signature scheme and the VOLE-in-the-Head proof system (a component of the
FAEST signature scheme). The moderator issues a token by signing a commitment
to the client's state; to present a token, the client proves knowledge of this
signature and the opening of the commitment. Two variants of the protocol are
specified, one in which the commitment is instantiated with `Keccak-p[800,12]`
and another in which a UOV-friendly commitment scheme is used instead.

--- middle

# Introduction

> WARNING This document specifies a cryptographic protocol that has not yet
> undergone significant security analysis. It's not yet suitable for real world
> applications. Implement at your own risk.

Modern web services face a fundamental tension between operational needs and
user privacy. Services need to implement rate limiting to prevent abuse, charge
for API usage to sustain operations, and allocate computational resources
fairly. However, traditional approaches require tracking user identities and
creating detailed logs of user behavior, raising significant privacy concerns
in an era of increasing data protection awareness and regulation.

The Anonymous Credit Token (ACT) protocol {{ACT}} resolves this tension by
enabling credit-based systems without user tracking: an Issuer can grant a
Client a token worth some number of credits, and the Client can later spend
those credits anonymously, in whole or in part, without the Issuer being able
to link the spend to the issuance or to any other spend by the same Client.

ACT achieves this privacy goal information-theoretically, meaning no attacker,
regardless of its computational resources, can link the presentation of a token
to its issuance. However, ACT is based on elliptic curve cryptography, which
means a quantum attacker can forge a token by recovering the Issuer's secret
key from its public key.

This document specifies Ratatouille, a variant of ACT that is plausibly fully
post-quantum secure. Its design is based on the PoMFRIT blind signature scheme
{{PoMFRIT}}, which combines a post-quantum signature scheme with a suitable
zero-knowledge proof system and commitment scheme. Specifically, the signer
signs a commitment to the message, and the verifier checks a zero-knowledge
proof-of-knowledge of the signature and the opening of the commitment.
Ratatouille generalizes this from a one-time use token to a token with
updatable state: the commitment binds a nullifier together with the remaining
credits, and each presentation additionally proves that the spend was
subtracted correctly and the balance stays in range, with the Issuer re-signing
the updated commitment so that every spend chains into the next token.

Ratatouille uses {{UOV}} as its signature scheme. Two instantiations of the
commitment are defined, one based on the Keccak permutation {{FIPS202}} and
another based on the Multivariate Quadratic (MQ) problem {{BFMRSV25}}. The
latter composes more naturally with UOV, is much simpler to evaluate in zero
knowledge, and, with its current parameterization, has significantly lower
communication cost than the hash-based variant.

> WARNING Adopters should not implement the MQ variant just yet. MQ commitments
> are understudied, and we don't know if the parameters we've chosen are
> sufficient for either unlinkability or unforgeability. Our goal for this
> variant is to give researchers a sense of the parameter regime for which MQ
> commitments are useful in our application. In particular, if communication
> cost is at or below hash-based commitments, then their relative simplicity
> makes them a good choice.

Both variants of Ratatouille have higher bandwidth cost than ACT:

1. the Issuer's public key is 42.6 KB, which corresponds to the uov-Ip
   parameter set for UOV (the MQ instantiation has a larger public key in
   order to accommodate the commitment parameters);

1. the Client uploads 7.8 KB during initial issuance (4.3 KB for the MQ
   variant); and

1. the Client uploads 14.2 KB during a spend (9.0 KB for the MQ variant).

In both the initial issuance and a spend, the Issuer's reply is a single UOV
signature, which is below a couple of hundred bytes for both instantiations.

Unlike ACT, Ratatouille tokens are publicly verifiable, meaning they can be
presented to any party with the Issuer's public key. Of course, this has
implications for privacy, since the token necessarily reveals the identity of
the Moderator that issued it.

The remainder of this document is structured as follows. {{conventions}}
defines some conventions and notation. {{overview}} provides a high-level
overview of the protocol. {{preliminaries}} defines the relevant interfaces for
the signature scheme, commitment scheme, and proof system used by Ratatouille,
and provides normative references for their specifications. {{protocol}}
specifies the protocol in terms of a generic commitment scheme;
{{instantiations}} gives our two instantiations of the commitment. Finally,
{{security}} enumerates some security considerations for implementers and
adopters.

# Conventions and Definitions {#conventions}

{::boilerplate bcp14-tagged}

## Notation

This document uses the following notation:

- `x <- S`: Sampling `x` uniformly at random from the finite set `S`.

- `x := y`: Assignment of the value `y` to the variable `x`.

- `x || y`: Concatenation of byte strings `x` and `y`.

- `x[i]`: The `i`-th element of byte string or vector `x`. Indexing begins at
  `0`, i.e., `x[0], ..., x[|x|-1]` are the elements of `x`.

- `x[i..j]`: The slice of byte string or vector `x` from index `i` to index
  `j-1`.

- `[a..b]`: The set of integers `{a, a+1, ..., b-1}`, i.e., the upper bound is
  exclusive, as for slices. `[n]` is shorthand for `[0..n]`, the set of integers
  `{0, 1, ..., n-1}`.

- `F_q`: The finite field with `q` elements. `F_2` is the binary field,
  i.e., `{0, 1}`. In this document, `q` is always a power of two so that `F_q`
  is an extension field of `F_2`.

- `<t>_L`: The `L`-byte big-endian encoding of a non-negative integer `t <
  2^(8*L)` as an element of `F_256^L` (equivalently `F_2^(8*L)`).

Each element of `F_256` has a natural representation as a byte. We sometimes
write `F_256^k` to denote the set of length-`k` byte strings, e.g., `r <-
F_256^k` means to choose `k` random bytes and assign them to `r`.

# Overview {#overview}

Ratatouille makes use of three cryptographic primitives:

1. The Unbalanced Oil and Vinegar {{UOV}} digital signature scheme. The Issuer,
   such as a MoLE Moderator {{ARCHITECTURE}}, uses a long-lived UOV secret key
   to issue tokens, and the Client uses the corresponding public key to
   generate proofs of knowledge.

1. The VOLE-in-the-Head (VOLEitH) zero-knowledge proof system, a component of
   the FAEST digital signature scheme {{FAEST}}.

1. A commitment scheme, instantiated either with the Keccak permutation
   {{FIPS202}} or with the Multivariate Quadratic (MQ) commitment of
   {{BFMRSV25}}.

A UOV public key is a map `P` from `F_q^n` to `F_q^m`. A UOV signature is a
solution `s` to an equation `P(s) = y`, where `y` is called the target and is
normally computed by hashing the message to be signed. The UOV secret key is a
trapdoor for `P` that can be used to efficiently sample signatures for a given
target.

A token is a tuple `(nf, t, r, x, s)` that binds a nullifier `nf` to the
Client's current state. The state is an effective balance `t + x`, where `t` is
the credit held by the Client and `x` is a refund chosen by the Issuer. `r` is
the opening of a commitment `c = Com(nf, ctx_iss, t, r)` and `s` is a signature
`P(s) = Tag(c, x)` that certifies the state committed to by `c` and binds the
refund to the state. Here `ctx_iss` is the issuance context agreed upon out of
band by the Client and Issuer.

Initially `t = T_init`, where `T_init` is a parameter agreed upon out of band
by the Client and Issuer, and `x = 0`. The initial issuance protocol is as
follows:

1. The Client samples a nullifier `nf` and an opening `r`, then constructs a
   commitment `c = Com(nf, ctx_iss, T_init, r)` and VOLEitH proof `pf_init` of
   knowledge of the `nf, r` for which `c = Com(nf, ctx_iss, T_init, r)`. It then
   sends `c, pf_init` to the Issuer.

1. The Issuer verifies `pf_init`, samples a solution `s` to `P(s) = Tag(c, 0)`,
   then sends `s` to the Client.

1. The Client finalizes issuance by checking that `P(s) = Tag(c, 0)`.

To spend credits, the Client reveals the nullifier `nf` for the current state,
commits to an updated state, and proves the updated state is consistent with
the previous state and the requested spend. It must do so without revealing the
current state, as this would allow the Issuer to link the spend to the initial
issuance or to a previous spend. To spend `d` credits from a token with
effective balance `t + x`:

1. The Client samples a fresh nullifier `nf'` and opening `r'`, then constructs
   a commitment `c' = Com(nf', ctx_iss, t', r')` to the change `t' = t + x - d`.
   It then constructs a VOLEitH proof `pf_spend` of knowledge of `t, r, x, s,
   nf', t', r'` for which:

   - the current state was certified by the Issuer, i.e.,
     `P(s) = Tag(Com(nf, ctx_iss, t, r), x)`;

   - the updated state is consistent, i.e., `c' = Com(nf', ctx_iss, t', r')` and
     `t' = t + x - d`; and

   - the updated state is valid, i.e., `t'` is at least `0` but no greater than
     a maximum value specified by the parameters of the protocol.

   Finally, the Client sends `nf, d, c', pf_spend` to the Issuer.

1. The Issuer checks that `nf` has not been spent and verifies `pf_spend`. It
   then chooses a refund `x'`, certifies the updated state by sampling a
   solution `s'` to `P(s') = Tag(c', x')`, then sends `x', s'` to the Client.

1. The Client finalizes the spend by checking that `P(s') = Tag(c', x')`. Its
   new token is `(nf', t', r', x', s')`.

The commitment `Com()` and tag `Tag()` are instantiated in one of two ways.

In the hash-based variant of Ratatouille ({{hash-commitment}}), both are
instantiated with a single evaluation of the `Keccak-p[800,12]` permutation
{{FIPS202}}. Similar to TurboSHAKE {{!RFC9861}}, this parameterization of
Keccak uses half as many rounds as SHA-3. However, its state is also half the
size of the state used by either SHA-3 or TurboSHAKE. This helps reduce the
size of the VOLEitH proof. See {{security}} for justification.

> NOTE The size of the spend proof is dominated by Keccak evaluations, of which
> there are three: one `Tag()` and two `Com()`s. If we can forego the refund
> feature, then we don't need the `Tag()` at all. Refunding can be emulated at
> the protocol level by having the Client and Issuer negotiate the requested
> spend so that it accounts for the refund.

The MQ-based variant of Ratatouille ({{mq-commitment}}) uses the MQ commitment
of {{BFMRSV25}} to instantiate `Com()`. The tag function `Tag()` updates the
commitment homomorphically with the refund.

> TODO Determine if this homomorphic trick is sound. See {{security}} for
> discussion.

# Preliminaries {#preliminaries}

We write `stream := SHAKE128(msg)` to denote the absorb phase of the SHAKE128
eXtendable Output Function (XOF) on input `msg` {{FIPS202}}. The `stream`
object denotes the XOF state. We write `out := stream.next(n)` to denote
squeezing out the next `n` bytes and assigning them to `out` in `F_256^n`.

Define `KP800(state)` as the output of applying `Keccak-p[800,12]`
{{FIPS202}} to `state` in `F_q^100`. Note that this is a non-standard size for
the Keccak permutation; see {{security}} for discussion.

We write `(cpk, csk) := UOV.CompactKeyGen()` to denote execution of the compact
key generation algorithm of {{UOV}}, Figure 2. Output `cpk` is the public key
and `csk` is the secret key. The input parameters are omitted and are instead
hard-coded to the uov-Ip parameter set (see {{UOV}}, Table 4).

We write `P := UOV.ExpandPK(cpk)` to denote expansion of the public key into the
UOV map `P : F_q^n -> F_q^m` using the procedure in {{UOV}}, Figure 2.
Likewise, we write `td := UOV.ExpandSK(csk)` to denote expansion of the secret
key into the trapdoor `td` for `P`.

We write `s := UOV.SPre(td, t)` to denote sampling a preimage of target `t`
under `P`, i.e., an `s` for which `P(s) = t`. This is the same procedure as used
in the signing algorithm in {{UOV}}, Figure 2.

We consider UOV parameters over `F_256`. That is, for the remainder of this
document, we let `q = 256`.

We write `pf := VOLEitH.Prove(R, X, W)` to denote proving knowledge of a
witness `W` for which the pair `(X, W)` is in the relation `R`, where `X` is
the instance, using the VOLE-in-the-Head proof system defined in {{FAEST}}. We
write `v := VOLEitH.Verify(R, X, pf)` to denote verification of `pf` under the
same relation and instance, where the output `v` is a bit.

Relations are specified in the style of {{Section 3.4 of SIGMA}} as a sequence
of constraints. Each constraint is an equation of the instance and witness
variables. Unlike {{SIGMA}}, these equations need not be linear: each side of
the equation is a polynomial of arbitrary degree. However, because the degree
of the polynomial influences the size of the proof, the relation must be
designed to balance the size of the witness with the degree of the constraints.

> TODO(cjpatton) Figure out how to cite {{FAEST}} more precisely. Ideally it
> specifies a compiler of constraints into a proof, as in {{SIGMA}}, but this
> is currently beyond the scope of what the FAEST spec does. The degree of
> constraints is coupled tightly to the proof generation procedure, which means
> I think we'll end up pulling some details of the proof construction into this
> document.

# Protocol Specification {#protocol}

> TODO Specify wire formats for each of the messages. For now we will ignore
> how things are encoded until we're more certain of the shape of the protocol.
>
> TODO Make all of these algorithms deterministic, passing any randomness they
> would generate as input. This will make it easier to generate test vectors.
> We'll also need to plumb this through VOLEitH proving and UOV signing.

This section specifies Ratatouille in terms of a generic configuration:
{{parameters}} defines the various parameters and functions that are determined
by a concrete configuration, and {{instantiations}} specifies two concrete
configurations, called Ratatouille-KP800 and Ratatouille-MQ. A deployment MUST
fix its configuration for the lifetime of an Issuer key.

A global constant `VERSION` in `F_q` is defined. Its value SHALL be `0`. This
constant is used for domain separation and is meant to be kept in sync with
revisions to this document. The overall template for domain separation is as
follows: the first four bytes of each permutation input identify the protocol;
the next byte is the document version (`VERSION`); the next byte indicates the
usage (commit, tag, or MQ map derivation); and the last byte indicates the
configuration (KP800 or MQ).

The rest of this section is organized as follows: {{key-generation}} specifies
Issuer key generation; {{issuance}} specifies initial token issuance; and
{{spending}} specifies token spending.

## Parameters {#parameters}

A Ratatouille configuration specifies the following constants:

- `L`: The credit length in bytes. It determines the largest credit value or
  refund the configuration can carry, i.e., `t, x` in `[2^(8*L)]`.

- `nf_len`: The nullifier length in bytes.

- `r_len`: The commitment randomness length in bytes.

- `ctx_len`: The issuance context length in bytes.

- `n_uov, m_uov`: The UOV signature and target lengths. The Issuer's public key
  is a map `P: F_q^{n_uov} -> F_q^{m_uov}`. Ratatouille-KP800 uses the uov-Ip
  parameter set (NIST Level 1) from {{UOV}}. Ratatouille-MQ uses larger
  parameters in order to accommodate MQ commitments.

### Commitment {#commitment}

A Ratatouille configuration specifies a function `Com()` that commits the Client
to a nullifier, the issuance context, and a credit value:

~~~~pseudocode
Com(nf, ctx_iss, t, r):
  Input:
    - nf: nullifier, in F_q^nf_len
    - ctx_iss: issuance context, in F_q^ctx_len
    - t: credit value, in [2^(8*L)]
    - r: commitment opening, in F_q^r_len
  Output:
    - c: commitment
~~~~

The commitment must be (computationally) hiding, meaning that for a random
opening `r`, no (efficient) attacker can distinguish commitments to different
values. It must also be (computationally) binding, meaning that no (efficient)
attacker can open a commitment to two distinct values.

### Tag {#tag}

A Ratatouille configuration specifies a tagging function `Tag()` that binds a
commitment to a refund and returns a UOV target:

~~~~pseudocode
Tag(c, x):
  Input:
    - c: commitment
    - x: refund, in [2^(8*L)]
  Output:
    - y: UOV target, in F_q^{m_uov}
~~~~

The Issuer signs `Tag(c, x)` with its UOV trapdoor, so a single signature binds
both the contents committed by `c` and the refund `x`. The refund is an input to
`Tag` rather than `Com`, which lets the Issuer add credits at signing time
without the Client re-committing.

## Issuer Key Generation {#key-generation}

Each Issuer generates its public and secret key pair using the procedure below.

~~~~pseudocode
KeyGen():
  Output:
    - P: a public UOV map from F_q^{n_uov} to F_q^{m_uov}
    - td: a secret UOV trapdoor for P

  Steps:
    1. (cpk, csk) := UOV.CompactKeyGen()
    2. P := UOV.ExpandPK(cpk)
    3. td := UOV.ExpandSK(csk)
    4. return (P, td)
~~~~

> TODO(cjpatton) `n_uov` and `m_uov` are meant to be determined by the
> Ratatouille configuration ({{parameters}}), but the UOV parameters are fixed
> in {{preliminaries}}. This is only relevant for Ratatouille-MQ.

## Initial Issuance {#issuance}

Issuance mints a fresh token carrying an initial credit balance `T_init in
[1..2^(8*L)]` and bound to the issuance context `ctx_iss`, both agreed between
the Client and Issuer. The Client commits to its nullifier `nf`, the context,
and the credit balance `t = T_init`, and sends the commitment `c` to the Issuer.
It also sends along a zero-knowledge proof of the following relation:

~~~
Relation IssueRelation(c, T_init, ctx_iss):
  Instance:
    - c: commitment
    - T_init: agreed initial credit balance, in [1..2^(8*L)]
    - ctx_iss: issuance context, in F_q^ctx_len

  Witness:
    - nf: nullifier, in F_q^nf_len
    - r: commitment opening, in F_q^r_len

  Constraints:
    - c = Com(nf, ctx_iss, T_init, r)
~~~

### Issue Request

To request a Ratatouille token from the Issuer, the Client runs the following
procedure.

~~~~pseudocode
IssueRequest(T_init, ctx_iss):
  Input:
    - T_init: initial credit balance, in [1..2^(8*L)]
    - ctx_iss: issuance context, in F_q^ctx_len

  Output:
    - pending_token: Client state
    - request: issuance request

  Steps:
    1. nf <- F_q^nf_len
    2. r  <- F_q^r_len
    3. c  := Com(nf, ctx_iss, T_init, r)
    4. pf_init := VOLEitH.Prove(
         IssueRelation,         // relation
         (c, T_init, ctx_iss),  // instance
         (nf, r),               // witness
       )
    5. request := (c, pf_init)
    6. pending_token := (nf, r)
    7. return (pending_token, request)
~~~~

### Issue Response

To issue a token, the Issuer runs the following procedure on the request, the
trapdoor for its public key, and the agreed initial credit balance.

~~~~pseudocode
IssueResponse(td, request, T_init, ctx_iss):
  Input:
    - td: Issuer secret key
    - request: issuance request
    - T_init: initial credit balance, in [1..2^(8*L)]
    - ctx_iss: issuance context, in F_q^ctx_len

  Output:
    - s: Issuer signature, in F_q^{n_uov}, or INVALID

  Steps:
    1. (c, pf_init) := request  // commitment, issuance proof
    2. v := VOLEitH.Verify(
         IssueRelation,         // relation
         (c, T_init, ctx_iss),  // instance
         pf_init,
       )
    3. if v = 0: return INVALID
    4. s := UOV.SPre(td, Tag(c, 0))
    5. return s
~~~~

### Token Verification

To complete token issuance, the Client runs the following procedure using the
Issuer's public key.

~~~~pseudocode
VerifyIssuance(P, pending_token, s, T_init, ctx_iss):
  Input:
    - P: Issuer public key
    - pending_token: Client state
    - s: Issuer signature, in F_q^{n_uov}
    - T_init: initial credit balance, in [1..2^(8*L)]
    - ctx_iss: issuance context, in F_q^ctx_len

  Output:
    - token: the issued token, or INVALID

  Steps:
    1. (nf, r) := pending_token
    2. if P(s) != Tag(Com(nf, ctx_iss, T_init, r), 0): return INVALID
    3. token := (nf, T_init, r, 0, s)
    4. return token
~~~~

## Spending {#spending}

Spending lets the Client spend `d` credits from a token of effective balance
`t + x`, obtaining a fresh token for the change `t + x - d` in the same round
trip. The Client reveals the nullifier `nf` of the current state and commits to
the updated state, then proves in zero knowledge that the current state was
certified by the Issuer and that the updated state is consistent with the
current state and the requested spend. The Issuer checks the proof, ensures
`nf` has not been spent, and certifies the updated state. The Issuer may also
grant a refund `x'`, which it binds to the updated state via the tag ({{tag}}).

The witness for the spend proof is the current state, the signature that
certifies it, and the updated state. The relation checks that the current state
was certified by the Issuer (V1), that the updated state is consistent with the
current state and the requested spend (V2 and V3), and that the updated state is
valid (V4):

~~~
Relation SpendRelation(P, nf, d, c', ctx_iss):
  Instance:
    - P: Issuer public key
    - nf: nullifier of the current state, in F_q^nf_len
    - d: credits to spend, in [2^(8*L)]
    - c': commitment to the updated state
    - ctx_iss: issuance context, in F_q^ctx_len

  Witness:
    - t: credit of the current state
    - r: commitment opening of the current state, in F_q^r_len
    - x: refund carried by the current state
    - s: Issuer signature over the current state, in F_q^{n_uov}
    - nf': nullifier of the updated state, in F_q^nf_len
    - t': credit of the updated state
    - r': commitment opening of the updated state, in F_q^r_len

  Constraints:
    - P(s) = Tag(Com(nf, ctx_iss, t, r), x)  // V1: current state was certified
    - c' = Com(nf', ctx_iss, t', r')         // V2: c' commits to updated state
    - t' = t + x - d                         // V3: credits are conserved
    - t', x, d in [2^(8*L)]                  // V4: credits are in range
~~~

Note that the same `ctx_iss` appears in V1 and V2, so the updated token is
necessarily bound to the context the token was issued under.

### Spend Proof Generation

To spend `d` credits from a token, the Client runs the following procedure using
the Issuer's public key.

~~~~pseudocode
ProveSpend(P, token, d, ctx_iss):
  Input:
    - P: Issuer public key
    - token: the token to spend
    - d: credits to spend, in [2^(8*L)]
    - ctx_iss: issuance context, in F_q^ctx_len

  Output:
    - pending_token: Client state
    - request: spend request, or INVALID

  Steps:
    1.  (nf, t, r, x, s) := token
    2.  if d > t + x: return INVALID  // insufficient balance
    3.  nf' <- F_q^nf_len             // nullifier of the updated state
    4.  r'  <- F_q^r_len              // opening of the updated state
    5.  t'  := t + x - d              // credit of the updated state
    6.  c'  := Com(nf', ctx_iss, t', r')
    7.  pf_spend := VOLEitH.Prove(
          SpendRelation,              // relation
          (P, nf, d, c', ctx_iss),    // instance
          (t, r, x, s, nf', t', r'),  // witness
        )
    8.  request := (nf, d, c', pf_spend)
    9.  pending_token := (nf', t', r')
    10. return (pending_token, request)
~~~~

### Spend Verification and Refund

To process a spend, the Issuer runs the following procedure on the request, the
trapdoor for its public key, the refund `x'` it grants, and the issuance context
it expects.

~~~~pseudocode
VerifyAndRefund(P, td, request, x', ctx_iss):
  Input:
    - P: Issuer public key
    - td: Issuer secret key
    - request: spend request
    - x': granted refund, in [2^(8*L)]
    - ctx_iss: issuance context, in F_q^ctx_len

  Output:
    - response: spend response, or INVALID

  Steps:
    1. (nf, d, c', pf_spend) := request
    2. if nf in used_nullifiers: return INVALID  // double spend
    3. if x' not in [2^(8*L)]: return INVALID
    4. if VerifySpend(P, request, ctx_iss) = INVALID: return INVALID
    5. used_nullifiers.add(nf)
    6. s' := UOV.SPre(td, Tag(c', x'))
    7. response := (x', s')
    8. return response

VerifySpend(P, request, ctx_iss):
  Input:
    - P: Issuer public key
    - request: spend request
    - ctx_iss: issuance context, in F_q^ctx_len

  Output:
    - VALID or INVALID

  Steps:
    1. (nf, d, c', pf_spend) := request
    2. if d not in [2^(8*L)]: return INVALID
    3. v := VOLEitH.Verify(
         SpendRelation,            // relation
         (P, nf, d, c', ctx_iss),  // instance
         pf_spend,
       )
    4. if v = 0: return INVALID
    5. return VALID
~~~~

Here `used_nullifiers` is the set of nullifiers the Issuer has accepted so far,
which it maintains for the lifetime of its key.

### Refund Token Construction

To complete the spend, the Client runs the following procedure using the
Issuer's public key.

~~~~pseudocode
VerifyRefund(P, pending_token, response, ctx_iss):
  Input:
    - P: Issuer public key
    - pending_token: Client state
    - response: spend response
    - ctx_iss: issuance context, in F_q^ctx_len

  Output:
    - token: the change token, or INVALID

  Steps:
    1. (nf', t', r') := pending_token
    2. (x', s') := response
    3. if x' not in [2^(8*L)]: return INVALID
    4. if P(s') != Tag(Com(nf', ctx_iss, t', r'), x'): return INVALID
    5. token := (nf', t', r', x', s')
    6. return token
~~~~

# Instantiations {#instantiations}

This section specifies two concrete configurations of Ratatouille
({{parameters}}): Ratatouille-KP800 ({{hash-commitment}}) and Ratatouille-MQ
({{mq-commitment}}).

## Ratatouille-KP800 {#hash-commitment}

| Parameter                    | Value                   |
|:-----------------------------|:------------------------|
| `L` credit length            | `8`                     |
| `nf_len` nullifier length    | `24`                    |
| `ctx_len` context length     | `16`                    |
| `r_len` opening length       | `16`                    |
| `n_uov` UOV signature length | `112` ({{UOV}}, uov-Ip) |
| `m_uov` UOV target length    | `44` ({{UOV}}, uov-Ip)  |
{: #ratatouille-kp800-parameters title="Ratatouille-KP800 Parameters" }

Ratatouille-KP800 uses the uov-Ip parameter set for UOV and a reduced-round and
state-size variant of Keccak, `Keccak-p[800, 12]` {{FIPS202}}. Its parameters
are listed in {{ratatouille-kp800-parameters}}.

> TODO Expand `Com()` and `Tag()` into sets of polynomial constraints for the
> issuance ({{issuance}}) and spend ({{spending}}) relations. An optimization
> that will be important for practice is to commit intermediate states of the
> Keccak evaluation to the witness. We need to define precisely how this works.

### Commitment {#kp800-commitment}

~~~~pseudocode
Com(nf, ctx_iss, t, r):
  Input:
    - nf: nullifier, in F_q^nf_len
    - ctx_iss: issuance context, in F_q^ctx_len
    - t: credit value, in [2^(8*L)]
    - r: commitment opening, in F_q^r_len
  Output:
    - c: commitment, in F_q^32

  Steps:
    1. state := "rata" || VERSION || "c0" || r || 0^(25 - r_len) ||
                ctx_iss || <t>_L || nf || 0^(68 - nf_len - ctx_len - L)
    2. c := KP800(state)[0..32]
    3. return c
~~~~

### Tag {#kp800-tag}

~~~~pseudocode
Tag(c, x):
  Input:
    - c: commitment, in F_q^32
    - x: refund, in [2^(8*L)]
  Output:
    - y: UOV target, in F_q^{m_uov}

  Steps:
    1. state := "rata" || VERSION || "t0" || 0^25 ||
                c || <x>_L || 0^(36 - L)
    2. y := KP800(state)[0..m_uov]
    3. return y
~~~~

## Ratatouille-MQ {#mq-commitment}

| Parameter                    | Value                               |
|:-----------------------------|:------------------------------------|
| `L` credit length            | `2`                                 |
| `nf_len` nullifier length    | `16`                                |
| `ctx_len` context length     | `12`                                |
| `r_len` opening length       | `83` (determined by MQ parameters)  |
| `n_uov` UOV signature length | `275` (determined by `m_uov`)       |
| `m_uov` UOV target length    | `131` (determined by MQ parameters) |
{: #ratatouille-mq-parameters title="Ratatouille-MQ Parameters" }

Ratatouille-MQ is based on the Multivariate Quadratic (MQ) commitment of
{{BFMRSV25}} over `F_q`. Its parameters are listed in
{{ratatouille-mq-parameters}}.

Just like the UOV signatures, MQ commitment evaluations can be expressed as
degree-2 constraints, which makes the issuance and spend proofs more efficient
than Ratatouille-KP800 ({{hash-commitment}}). The commitment involves two
inhomogeneous quadratic maps `F: F_q^{n_com} -> F_q^k` and `G:
F_q^{n_com} -> F_q^{m_uov-k}`. To commit to a token state, we encode the
state as `msg` in `F_q^k`, generate an opening `r <- F_q^{n_com}`, and
compute `c := (F(r) + msg) || G(r)`.

The tag is an affine, homomorphic operation on the commitment. To tag `c`, we
encode the refund as `refund` in `F_q^{m_com}` and compute `y := refund + c` as
the target to be signed by the Issuer. Thus, the UOV parameters are chosen so
that the UOV target is the same length as the MQ commitment, i.e., `m_uov =
m_com`.

We start with the most aggressive parameters of {{BFMRSV25}} (Table 3): `k =
32`, `n_com = 83`, and `m_com = 131`. This determines the UOV target length.
Because this is larger than the standard parameters {{UOV}}, we must adjust the
signature length accordingly. The UOV signature length is set to `n_uov = 275`,
which is the minimum passing a 128-bit check under the CryptographicEstimators
`UOVEstimator` ({{CryptEst}}, which implements the {{UOV}} Section 4 attacks).

The public commitment maps `F`, `G` are derived deterministically in a
nothing-up-my-sleeve manner so that no trusted setup is required.

Let `bytesIntoUpper(b)` denote the upper-triangular, `n_com`-by-`n_com` matrix
over `F_q` obtained by reading bytes from `b` in row-major order.

~~~~pseudocode
GenerateParameters():
  Output:
    - F: F_q^{n_com} -> F_q^k,
    - G: F_q^{n_com} -> F_q^{m_uov-k}

  Steps:
    1.  u_com := n_com * (n_com + 1) / 2
    2.  stream := SHAKE128("rata" || VERSION || "m1")
    3.  for i in [m_uov]:
    4.    // quadratic part
    5.    M_i := bytesIntoUpper(stream.next(u_com))
    6.    // linear part
    7.    l_i := stream.next(n_com)
    8.    // inhomogeneous quadratic map F_q^{n_com} -> F_q
    9.    Q_i(x) := x^T*M_i*x + l_i*x
    10. F := (Q_0, ..., Q_{k-1})
    11. G := (Q_k, ..., Q_{m_uov-1})
    12. return (F, G)
~~~~

Each quadratic map has a quadratic component and a linear component. The linear
terms are essential: a purely homogeneous map (`l_i = 0`) has `F(0) = G(0) = 0`
and is scaling-covariant (`Q_i(a x) = a^2 Q_i(x)`), which admits a forgery.

### Commitment {#mq-com}

~~~~pseudocode
Com(nf, ctx_iss, t, r):
  Input:
    - nf: nullifier, in F_q^nf_len
    - ctx_iss: issuance context, in F_q^ctx_len
    - t: credit value, in [2^(8*L)]
    - r: commitment opening, in F_q^r_len

  Output:
    - c: commitment, in F_q^{m_uov}

  Steps:
    1. (F, G) := GenerateParameters()
    2. msg := EmbedState(nf, ctx_iss, t)
    3. c := (F(r) + msg) || G(r)
    4. return c
~~~~

The parameters of Ratatouille-MQ are set so that `k = nf_len + ctx_len + 2*L`.
Function `EmbedState(nf, ctx_iss, t)` encodes the token state as
`msg = nf || ctx_iss || <t>_L || 0^L`. Note that the last `L` elements are set
to `0` as these are reserved for the refund.

> TODO(cjpatton) Figure out if we can safely bind the issuance context to `F,
> G` derivation. This would save some bytes in the commitment, which would
> allow us to bump nullifier length match Ratatouille-KP800. (Likewise for the
> credit length.)

### Tag {#mq-tag}

An MQ commitment is constant-additively homomorphic, which means adding a
public vector to `c` shifts the committed message without touching the binding
block `G(r)` and without knowledge of `r` {{BFMRSV25}}. The tagging function
uses this to write the issuer-granted refund `x` into the (zero) refund
coordinate:

~~~~pseudocode
Tag(c, x):
  Input:
    - c: commitment, in F_q^{m_uov}
    - x: refund, in [2^(8*L)]

  Output:
    - y: UOV target, in F_q^{m_uov}

  Steps:
    1. refund := EmbedRefund(x)
    2. y := c + refund
    3. return y
~~~~

Function `EmbedRefund(x)` returns a vector `e` in `F_q^{m_uov}` that is zero
everywhere except the refund slot: its `L` elements starting at `off_refund =
nf_len + ctx_len + L` hold the refund encoding `<x>_L`.

# Security Considerations {#security}

> TODO Prove the following claims.

Unlinkability of Ratatouille reduces to the zero-knowledge property of the
VOLEitH proof system and the hiding property of the commitment.
One-more-unforgeability reduces to witness-extractability of VOLEitH, binding
of the commitment, and the one-more-UOV assumption ({{PoMFRIT}}, Definition 8).
The one-more-UOV assumption is a stronger assumption than standard UOV
({{UOV}}, Definition 2) that requires some scrutiny before we rely on it too
heavily.

> NOTE A few observations we've made so far:
>
> 1. One-more-UOV reduction likely treats `Com()` and `Tag()` as random
>    oracles. This is reasonable for Ratatouille-KP800, but we would need to
>    figure out something else for Ratatouille-MQ. It seems to be me (cjpatton)
>    that we probably need a proper hash for `Tag()` at least.
>
> 2. If we add a randomizer to `Tag()` and instantiate it with Keccak, then we
>    might even be able to reduce to standard UOV rather than one-more-UOV.
>
> 3. For Ratatouille-MQ, figure out if the homomorphic tagging trick for the MQ
>    variant is sound. We likely need the commitment to be pseudorandom, in
>    which case allowing the attacker to select the tag probably incurs a
>    security loss multiplicative in the number of bits of the refund.

The parameters of the MQ commitment in {{mq-commitment}} were chosen from a
regime for which security is only heuristically justified based on the best
known attacks. Further cryptanalysis is required to determine if these
parameters are safe {{BFMRSV25}}.

> TODO Justify halving the Keccak state from 1600 to 800 (relative to
> TurboSHAKE).

# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

The use of `Keccak-p[800,12]` in this application was proposed by Bas Westerbaan.
