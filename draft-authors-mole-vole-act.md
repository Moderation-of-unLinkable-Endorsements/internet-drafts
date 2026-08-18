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

  CCNY12:
    title: "Solving Quadratic Equations with XL on Parallel Architectures"
    target: https://eprint.iacr.org/2016/412
    date: 2012
    seriesinfo:
      "CHES": "2012, LNCS 7428, pp. 356-373"
    author:
      -
        ins: C.-M. Cheng
        name: Chen-Mou Cheng
      -
        ins: T. Chou
        name: Tung Chou
      -
        ins: R. Niederhagen
        name: Ruben Niederhagen
      -
        ins: B.-Y. Yang
        name: Bo-Yin Yang

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

- `[n]`: The set of integers `{0, 1, ..., n-1}`; `[a, b]` denotes the closed
  integer interval `{a, a+1, ..., b}`.

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
the opening of a commitment `c = Com(nf, t, r)` and `s` is a signature `P(s) =
Tag(c, x)` that certifies the state committed to by `c` and binds the refund to
the state.

Initially `t = T_init`, where `T_init` is a parameter agreed upon out of band
by the Client and Issuer, and `x = 0`. The initial issuance protocol is as
follows:

1. The Client samples a nullifier `nf` and an opening `r`, then constructs a
   commitment `c = Com(nf, T_init, r)` and VOLEitH proof `pf_init` of knowledge
   of the `nf, r` for which `c = Com(nf, T_init, r)`. It then sends `c, pf_init`
   to the Issuer.

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
   a commitment `c' = Com(nf', t', r')` to the change `t' = t + x - d`. It then
   constructs a VOLEitH proof `pf_spend` of knowledge of `t, r, x, s, nf', r',
   t'` for which:

   - the current state was certified by the Issuer, i.e.,
     `P(s) = Tag(Com(nf, t, r), x)`;

   - the updated state is consistent, i.e., `c' = Com(nf', t', r')` and
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
>
> We need to make sure there is domain separation between commitments in these
> two variants of the protocol.

The MQ-based variant of Ratatouille ({{mq-commitment}}) uses the MQ commitment
of {{BFMRSV25}} to instantiate `Com()`. The tag function `Tag()` updates the
commitment homomorphically with the refund.

> TODO Determine if this homomorphic trick is sound. See {{security}} for
> discussion.

# Preliminaries {#preliminaries}

Define `KP800(state)` as the output of applying `Keccak-p[800,12]`
{{FIPS202}} to `state in F_q^100`. Note that this is a non-standard size for
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
configurations, called Ratatouille-Keccak and Ratatouille-MQ. A deployment MUST
fix its configuration for the lifetime of an Issuer key.

> TODO(cjpatton) Bind the variant to key derivation and the various key
> operations to mitigate confusion attacks properly.

The rest of this section is organized as follows: {{key-generation}} specifies
Issuer key generation; {{issuance}} specifies initial token issuance; and
{{spending}} specifies token spending.

## Parameters {#parameters}

A Ratatouille configuration specifies the following constants:

- `L`: The credit width in bytes. It determines the largest credit value or
  refund the configuration can carry, i.e., `t, x in [2^(8*L)]`.

- `nu`: The nullifier length in bytes.

- `rho`: The commitment randomness length in bytes.

- `q`: The size of the finite field `F_q` over which UOV signatures are
  defined. `q` MUST be a power of two; typically `q=256`.

  > TODO(cjpatton) Consider hardcoding this like we do in Moussaka.

- `n_uov, m_uov`: The dimensions of the UOV map. The Issuer's public key is
  a map `P: F_q^{n_uov} -> F_q^{m_uov}`. Ratatouille-Keccak uses the uov-Ip
  parameter set (NIST Level 1) from {{UOV}}. Ratatouille-MQ uses larger
  parameters in order to accommodate MQ commitments.

### Commitment {#commitment}

A Ratatouille configuration specifies a function `Com()` that commits the Client
to a nullifier and a credit value:

~~~~pseudocode
Com(nf, t, r):
  Input:
    - nf: nullifier, in F_256^nu
    - t: credit value, in [2^(8*L)]
    - r: commitment opening, in F_256^rho
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

## Domain Separation Tag

> TODO(cjpatton) Drop this and align with domain separation in Moussaka. We
> also need to include the configuration in the domain.

A deployment fixes a **domain separation tag** `dst`, a byte string that
identifies the deployment and isolates it cryptographically from every other
deployment.

The `dst` encodes the version of this specification and an application context
string agreed upon by the client and issuer:

~~~
dst := "RATA-v1:" || application_context
~~~

This string MUST be unique per deployment. It might encode information like the
organization, the service, the deployment environment, and so on. For example:

~~~
"example-corp:rate-limiter:production:2026-01-15"
~~~

## Key Generation {#key-generation}

Key generation is run once by the issuer to produce a long-lived UOV key pair.
The routines `UOV.CompactKeyGen`, `UOV.ExpandPK`, and `UOV.ExpandSK` are those of
{{UOV}} (Section 3.2, Figure 2): `CompactKeyGen` samples a compact key pair
`(cpk, csk)`, `ExpandPK` expands `cpk` into the public UOV map `P`, and
`ExpandSK` expands `csk` into the trapdoor for `P`.

~~~~pseudocode
KeyGen():
  Output:
    - sk: Issuer secret key, a UOV trapdoor for P
    - pk: Issuer public key, a UOV map P from F_q^{n_uov} to F_q^{m_uov}

  Steps:
    1.  (cpk, csk) := UOV.CompactKeyGen()
    2.  pk := UOV.ExpandPK(cpk)
    3.  sk := UOV.ExpandSK(csk)
    4.  return (sk, pk)
~~~~

The issuer publishes `pk`. The issuer additionally maintains a set of accepted
nullifiers for rejecting any nullifier it has already accepted.

## Token Issuance {#issuance}

Issuance mints a fresh token carrying an initial credit balance `T_init in [1,
2^(8*L) - 1]` agreed between the client and issuer. It is a two-message interactive
protocol, structured as the Fischlin blind signature {{Fischlin}} -- commit,
sign, prove-knowledge -- instantiated with UOV and VOLE-in-the-Head.

The client commits to both its nullifier `nf` and the credit balance `t =
T_init`, and sends the commitment `c` to the issuer, who signs it directly via
its UOV target `Tag(c, 0)`. Because `Com` is opaque to the issuer, the client
attaches a zero-knowledge proof that `c` opens to the agreed balance `T_init`;
without it, a malicious client could commit to an arbitrary balance. The
signature `s` is a genuine UOV preimage of `Tag(c, 0)`, which the client stores
in its token.

Blindness does **not** come from masking the signing target. The issuer sees
`c` at issuance (which hides `nf` via `r`) and sees `nf` only at presentation
(where the zero-knowledge proof of {{spending}} hides `c`); because `Com` is
hiding, the issuer cannot link a presented `nf` to the `c` it signed. Every
later presentation proves knowledge of `(nf, t, r, x, s)` satisfying `P(s) =
Tag(Com(nf, t, r), x)` -- the UOV relation of {{parameters}} -- without
revealing `c`.

The issuance relation proves that the commitment `c` opens to the agreed initial
balance `T_init`:

~~~
Relation IssueRelation(c, T_init):
  Instance:
    - c: commitment
    - T_init: agreed initial credit balance, in [1, 2^(8*L) - 1]

  Witness:
    - nf: nullifier
    - r: commitment randomness

  Constraints:
    - c = Com(nf, T_init, r)
~~~

### Client: Issuance Request {#issue-request}

~~~~pseudocode
IssueRequest(T_init):
  Input:
    - T_init in [1, 2^(8*L) - 1]: agreed initial credit balance
  Output:
    - request = (c, pf_init): commitment and well-formedness proof
    - state   = (nf, r): client state for Token Verification

  Steps:
    1.  nf     <- {0,1}^(8*nu)                 // nullifier
    2.  r      <- {0,1}^(8*rho)                // commitment randomness
    3.  c      := Com(nf, T_init, r)           // see Commitment and Tag
    4.  pf_init := VOLEitH.Prove(
          IssueRelation,   // relation
          (c, T_init),     // instance
          (nf, r),         // witness
        )
    5.  request := (c, pf_init)
    6.  state   := (nf, r)
    7.  return (request, state)
~~~~

### Issuer: Issuance Response {#issue-response}

~~~~pseudocode
IssueResponse(sk, request, T_init):
  Input:
    - sk: Issuer secret key (secret seed seed_sk)
    - request = (c, pf_init)
    - T_init in [1, 2^(8*L) - 1]: agreed initial credit balance
  Output:
    - response = s: UOV signature, or INVALID

  Steps:
    1.  if not (0 < T_init < 2^(8*L)): return INVALID
    2.  if VOLEitH.Verify(IssueRelation, (c, T_init), pf_init) = 0: return INVALID
    3.  s <- UOV.Sign(sk, Tag(c, 0))   // preimage of Tag(c, 0): P(s) = Tag(c, 0),
                                       // rejection sampling on singular system
    4.  return s
~~~~

### Client: Token Verification {#verify-issuance}

~~~~pseudocode
VerifyIssuance(pk, state, response, T_init):
  Input:
    - pk = P: Issuer public key
    - state  = (nf, r)
    - response = s
    - T_init: agreed initial credit balance
  Output:
    - tok = (nf, T_init, r, x = 0, s): a fresh token, or INVALID

  Steps:
    1.  c := Com(nf, T_init, r)
    2.  if P(s) != Tag(c, 0): return INVALID
    3.  return tok := (nf, T_init, r, 0, s)
~~~~

The issuer's view of a single issuance is the commitment `c`, the
well-formedness proof `pf_init`, and the signature `s` it produced.
Unlinkability of issuance to any later spend follows from the hiding of `Com`
and the zero-knowledge of the presentation proof ({{spending}}).

## Token Spending {#spending}

Spending lets a client spend `d` credits from a token of effective balance `B =
t + x` (with `0 <= d <= B`), atomically obtaining a fresh token for the change
`B - d`. It is the presentation half of the Fischlin blind signature: the
client reveals the token's nullifier `nf`, proves in zero knowledge that it
holds a valid signature over that token and that a freshly committed change
token is consistent, and the issuer signs the change commitment in its
response.

Spending is a single round trip. The client builds the change commitment `c' =
Com(nf', t + x - d, r')` itself and bundles it into the spend request; the
issuer verifies, ensures the revealed nullifier is fresh, optionally grants an
additional refund `x'` bound in the tag, and returns `s' = UOV.Sign(sk, Tag(c',
x'))`. In the common case `x' = 0` and the change is entirely committed; a
positive `x'` lets the issuer top the token up without a second message
({{tag}}). Setting `d = 0` re-randomizes a token under a fresh nullifier -- a
re-anonymization operation useful for transferring a token.

Recall from {{parameters}} that the credit width `L` bounds every balance,
refund, and spend: they all lie in `[2^(8*L)]`.

The spend relation binds the spent token to a well-formed change token. It is
specified by the conditions V1--V4 below.

~~~
Relation SpendRelation(pk, nf, d, c'):
  Instance:
    - pk = P: Issuer public key
    - nf: nullifier of the spent token
    - d: amount to spend, in [0, 2^(8*L) - 1]
    - c': change commitment

  Witness:
    - t: committed credit of the spent token
    - r: commitment randomness of the spent token
    - x: refund carried by the spent token
    - s: UOV signature over the spent token
    - nf': nullifier of the change token
    - r': commitment randomness of the change token
    - t': committed change balance

  Constraints:
    - P(s) = Tag(Com(nf, t, r), x)                       // V1: valid signature
    - c' = Com(nf', t', r')                              // V2: change well-formed
    - t' = t + x - d                                     // V3: balance conservation
    - 0 <= t' < 2^(8*L) AND 0 <= x < 2^(8*L) AND 0 <= d < 2^(8*L)  // V4: ranges
~~~

### Client: Spend Proof Generation {#prove-spend}

~~~~pseudocode
ProveSpend(tok, d):
  Input:
    - tok  = (nf, t, r, x, s): a token of effective balance B = t + x
    - d in [0, B]: amount to spend
  Output:
    - proof = (nf, d, c', pf_spend): spend proof
    - state = (nf', t', r'): client state for Refund Token Construction

  Steps:
    1.  if not (0 <= d <= t + x): raise InvalidAmount
    2.  nf' <- {0,1}^(8*nu)                 // fresh nullifier for the change
    3.  r'  <- {0,1}^(8*rho)                // fresh commitment randomness
    4.  t'  := t + x - d                    // committed change balance
    5.  c'  := Com(nf', t', r')
    6.  pf_spend := VOLEitH.Prove(
          SpendRelation,                // relation
          (pk, nf, d, c'),              // instance
          (t, r, x, s, nf', r', t'),    // witness
        )
    7.  proof := (nf, d, c', pf_spend)    // nf, d, c' public; witness hidden
    8.  state := (nf', t', r')
    9.  return (proof, state)
~~~~

### Issuer: Spend Verification and Refund {#verify-spend}

~~~~pseudocode
VerifyAndRefund(sk, proof, x'):
  Input:
    - sk: Issuer secret key (secret seed seed_sk)
    - proof = (nf, d, c', pf_spend)
    - x' in [0, 2^(8*L) - 1]: issuer-granted refund; 0 for no refund
  Output:
    - response = (x', s'): granted refund and signature, or INVALID
  Exceptions:
    - DoubleSpend, raised when nf has already been accepted

  Steps:
    1.  if nf has already been accepted: raise DoubleSpend
    2.  if not (0 <= x' < 2^(8*L)): return INVALID
    3.  if VerifySpend(pk, proof) = INVALID: return INVALID      // see below
    4.  mark nf as accepted
    5.  s' <- UOV.Sign(sk, Tag(c', x'))       // sign the change commitment
                                              // (reuses issuance signing)
    6.  return (x', s')

VerifySpend(pk, proof):
  Input:
    - pk = P: Issuer public key
    - proof = (nf, d, c', pf_spend)
  Output:
    - VALID or INVALID

  Steps:
    1.  if not (0 <= d < 2^(8*L)): return INVALID
    2.  if VOLEitH.Verify(SpendRelation, (pk, nf, d, c'), pf_spend) = 0:
          return INVALID
    3.  return VALID
~~~~

The issuer MUST mark `nf` as accepted (step 4) before the signature is
released, so that a client cannot obtain two change tokens from one spend by
replaying the request.

Verification checks only the zero-knowledge proof against the public inputs
`(pk, nf, d, c')`; conditions V1--V4 of {{prove-spend}} are enforced inside
`pf_spend`. In particular V1 establishes that the client holds an issuer
signature over some token whose effective balance is `t + x`, V3 and V4
establish `d <= t + x` and that the change `t'` is a valid balance, and V2 binds
the change to the commitment `c'` the issuer is about to sign. The issuer learns
the spent amount `d` and the nullifier `nf`, but neither the effective balance
`B` nor the change `t'`.

### Client: Refund Token Construction {#refund-token}

~~~~pseudocode
VerifyRefund(pk, state, response):
  Input:
    - pk = P: Issuer public key
    - state    = (nf', t', r')
    - response = (x', s')
  Output:
    - tok' = (nf', t', r', x', s'): the change token, or INVALID

  Steps:
    1.  if not (0 <= x' < 2^(8*L)): return INVALID
    2.  c' := Com(nf', t', r')
    3.  if P(s') != Tag(c', x'): return INVALID
    4.  return tok' := (nf', t', r', x', s')
~~~~

The change token has effective balance `B' = t' + x' = (t + x - d) + x'`, and is
unlinkable to the spent token: the issuer saw only the hiding commitment `c'`
and the public `(nf, d, x')`, none of which reveal `nf'` or the change balance.

# Instantiations {#instantiations}

The protocol of {{key-generation}} through {{spending}} is parameterized by the
commitment `Com` ({{commitment}}) and tag `Tag` ({{tag}}). This section gives
the two concrete instantiations. A deployment MUST fix exactly one for the
lifetime of a key (bound into `dst`); the choice is part of the configuration.

Both realize the same abstract interface, so all of Issuance ({{issuance}}),
Spend ({{spending}}), the conditions V1--V4, double-spend handling, and
blindness are inherited unchanged. They differ only in `Com`, `Tag`, the
deployment-wide parameters derived from `dst`, and the resulting UOV dimensions
`(n_uov, m_uov)`.

## Ratatouille-Keccak {#hash-commitment}

Here both `Com` and `Tag` are realized by `KP800`, a TurboSHAKE
{{!RFC9861}} sponge over the reduced-round permutation `Keccak-p[800, 12]`
{{FIPS202}}, modeled as a random oracle and domain-separated by `dst`.
`KP800(M, d)` squeezes `d` bytes of output, and `KP800(M)` defaults to `d = 32`
bytes. Distinct one-byte labels separate commitment hashing from UOV-target
hashing. In the Spend relation ({{prove-spend}}), V1 evaluates `Com` and `Tag`
for the old token, while V2 evaluates `Com` for the change token. A spend
therefore evaluates `Keccak-p[800, 12]` three times in-circuit. The MQ
instantiation ({{mq-commitment}}) removes these evaluations entirely.

The `800`-bit permutation, rather than TurboSHAKE128's `1600`-bit
`Keccak-p[1600, 12]`, halves the in-circuit state. Its 256-bit capacity leaves a
544-bit (`68`-byte) rate, which is sufficient for each fixed-length input below
to fit in one absorb block and for each output to fit in one squeeze block.

**Commitment.** `Com` binds a nullifier `nf` and a credit value `t` under
randomness `r`:

~~~~pseudocode
Com(nf, t, r):
  Input:
    - nf: nullifier, in F_256^nu
    - t: credit value, in [2^(8*L)]
    - r: commitment opening, in F_256^rho
  Output:
    - c: commitment, in F_256^32

  Steps:
    1.  return KP800(0xAC || dst || nf || <t>_L || r)
~~~~

**Tag.** `Tag` hashes a commitment and public refund to a full UOV target of
`m_uov` bytes, where `m_uov` is the number of UOV equations ({{parameters}}):

~~~~pseudocode
Tag(c, x):
  Input:
    - c: commitment, in F_256^32
    - x: refund, in [2^(8*L)]
  Output:
    - y: UOV target, in F_256^{m_uov}

  Steps:
    1.  return KP800(0xAD || dst || c || <x>_L, m_uov)
~~~~

Both preimages have fixed-length fields and parse unambiguously. The `Com`
preimage is `1 + 18 + 24 + 8 + 16 = 67` bytes, leaving the final byte of the
68-byte rate for the sponge separator and padding. The `Tag` preimage is `1 +
18 + 32 + 8 = 59` bytes. Each call therefore requires one
`Keccak-p[800, 12]` permutation. At initial issuance `x = 0`, but `Tag(c, 0)` is
still a separate, domain-separated hash of `c` and zero.

**Security.** Commitment hiding follows from the `rho = 16` bytes of fresh
randomness, and binding follows from collision resistance of the domain-separated
`Com` random oracle. `Tag(c, x)` is a full random-oracle image that jointly binds
the commitment and refund before UOV inversion. This retains hash-and-sign
target semantics and avoids a chosen-tail or translated-target UOV assumption.
A complete protocol proof additionally requires knowledge soundness of the
VOLEitH proof, faithful integer arithmetic, and atomic nullifier handling
({{security}}).

**Parameter selection.** The knobs chosen for Ratatouille-Keccak:

| Parameter | Value |
|-----------|-------|
| Nullifier `nu` | `24` bytes |
| Randomness `rho` | `16` bytes |
| Credit width `L` | `8` (`t, x, d in [0, 2^64 - 1]`) |
| Domain-separation tag `dst` | `18` bytes |
| Commitment `c` | `32` bytes |
| UOV `(n_uov, m_uov, q)` | `(112, 44, 256)` (`uov-Ip`) |

**API sizes.** Everything below is derived from the parameters above and is
given in bytes.

| Function | Input | Output |
|----------|-------|--------|
| `Com(nf, t, r)` | label `0xAC` = `1`, `dst: 18`, `nf: 24`, `<t>_L: 8`, `r: 16` | `c: 32` |
| `Tag(c, x)` | label `0xAD` = `1`, `dst: 18`, `c: 32`, `<x>_L: 8` | `y: m_uov = 44` |
| `P(s)` (UOV) | `s: n_uov = 112` | `y: m_uov = 44` |

## Ratatouille-MQ {#mq-commitment}

Here `Com` and `Tag` are realized by the algebraic multivariate-quadratic (MQ)
commitment of {{BFMRSV25}} over `F_256`. This removes the in-circuit hash:
because both `Com` and `Tag` are degree-2 relations over `F_256`, conditions V1
and V2 of {{prove-spend}} are pure `F_256` arithmetic with no Keccak in-circuit.
The realization differs from {{hash-commitment}} in two ways:

1. **`Com` is algebraic.** `Com(nf, t, r) = (EmbedNullifierBalance(nf, t) +
   F(r), G(r))` for public general quadratic maps `F`, `G` from the `GenerateParameters` function defined
   below.
2. **`Tag` is affine and homomorphic.** The MQ commitment is
   constant-additively homomorphic, so the refund is applied by a homomorphic
   addition rather than a hash: `Tag(c, x) = c + EmbedRefund(x)`, a degree-1 map
   that adds the issuer-granted refund `x` into a reserved commitment
   coordinate. The signing target `P(s) = Tag(Com(nf, t, r), x)` is unchanged
   form.

**GenerateParameters.** The MQ instantiation needs public commitment maps `F`,
`G`, produced by a routine `GenerateParameters`. Ours derives `F`, `G`
deterministically from `dst` by a nothing-up-my-sleeve expansion, so it needs no
trusted setup. Unlike the hash instantiation of {{hash-commitment}} (which evaluates
`Keccak-p[800, 12]` for both `Com` and `Tag` inside the spend proof), this
parameter expansion is never proven in zero knowledge. It therefore uses
standard SHAKE128 (FIPS 202) {{FIPS202}} -- the more conservatively reviewed
XOF:

* Two general (inhomogeneous) quadratic maps `F: F_256^{n_com} -> F_256^k` and
  `G: F_256^{n_com} -> F_256^{m_uov-k}`, obtained as `(F, G) =
  GenerateParameters(dst)`.

~~~~pseudocode
GenerateParameters(dst):
  Input:
    - dst: deployment domain-separation tag
  Output:
    - F: F_256^{n_com} -> F_256^k, G: F_256^{n_com} -> F_256^{m_uov-k}   // public quadratic maps
  Steps:
    1.  stream := SHAKE128("RATA-MQ-maps:" || dst)
    2.  for each output equation i in [m_uov]:
    3.      M_i := bytesIntoUpper(stream.next(n_com(n_com+1)/2))   // quadratic part, in F_256^{n_com * n_com}
    4.      l_i := stream.next(n_com)                              // linear part, in F_256^{n_com}
    5.      Q_i := (M_i, l_i)   such that   Q_i(x) = x^T M_i x + l_i . x
    6.  F := (Q_0, ..., Q_{k-1})                       // first k equations
    7.  G := (Q_k, ..., Q_{m_uov-1})                   // remaining m_uov-k equations
    8.  return (F, G)
~~~~

`bytesIntoUpper(b)` fills the upper triangle of an `n_com x n_com` matrix over
`F_256` row-major from the bytes `b`, one element per byte, with all other
entries zero. Each output equation is a general (inhomogeneous) quadratic map
`Q_i(x) = x^T M_i x + l_i . x` in the `n_com` variables, with `M_i` the quadratic
part and `l_i` the linear part. The linear terms are essential: a purely
homogeneous map (`l_i = 0`) has `F(0) = G(0) = 0` and is scaling-covariant
(`Q_i(a x) = a^2 Q_i(x)`), which admits a forgery.

**Commitment.** `Com` binds a nullifier `nf` and a credit value `t` under
randomness `r`, following the MQ commitment construction in {{BFMRSV25}}:

~~~~pseudocode
Com(nf, t, r):
  Input:
    - nf: nullifier, in F_256^nu
    - t: credit value, in [2^(8*L)]
    - r: commitment opening, in F_256^rho (rho = n_com)
  Output:
    - c: commitment, in F_256^{m_uov}
  Steps:
    1.  msg := EmbedNullifierBalance(nf, t)   in F_256^k   // refund coordinate = 0
    2.  return ( msg + F(r), G(r) )  in F_256^{m_uov}
~~~~

`EmbedNullifierBalance(nf, t)` returns a message vector `msg in F_256^k`, one
`F_256` element per byte. The first `nu` elements hold the nullifier, one byte
per element (`msg[i] = byte(nf[i])` for each `i in [nu]`); the next `L`
elements hold the balance encoding `<t>_L`; the following `L` elements are the
refund slot, left zero here and written later by `Tag`; and the remaining `k -
off_refund - L` elements are reserved and set to zero (there are none unless
`k > off_refund + L`).

**Tag.** The MQ commitment is *constant-additively homomorphic*: adding a public
vector to `c` shifts the committed message without touching the binding block
`G(r)` and without knowledge of `r` {{BFMRSV25}}. `Tag` uses this to write the
issuer-granted refund `x` into the (zero) refund coordinate:

~~~~pseudocode
Tag(c, x):
  Input:
    - c: commitment, in F_256^{m_uov}
    - x: refund, in [2^(8*L)]
  Output:
    - y: UOV target, in F_256^{m_uov}
  Steps:
    1.  return c + EmbedRefund(x)     in F_256^{m_uov}   // degree-1, no hash
~~~~

`EmbedRefund(x)` returns a vector `e in F_256^{m_uov}` that is zero everywhere except
the refund slot: its `L` elements starting at `off_refund = nu + L` hold
the refund encoding `<x>_L`.

Because the commitment length exceeds the standard NIST UOV output size, the UOV
parameters are enlarged to accommodate it, as reflected in the parameters below.

**Security.** Hiding is *heuristic* computational with respect to the
best-known attack (hybrid exhaustive-search + XL-Wiedemann {{CCNY12}}). Binding
is *computational*, reduced to collision-resistance of `G` (finding `r != r'`
with `G(r) = G(r')`, a bilinear MQ problem that is NP-complete in the worst
case). Separately, one-more unforgeability of the signed commitment rests on the
interactive one-more *quadratic-claw* assumption, flagged as unexplored in
{{BFMRSV25}}.

**Parameter selection.** Ratatouille-MQ takes the aggressive
*heuristic-hiding / computational-binding* row of {{BFMRSV25}}, Table 3 (`q =
256`, so one commitment element is one byte), which minimizes commitment size.
Here `m_uov` is pinned by the commitment length rather than chosen for signature
compactness; with `m_uov` fixed, the only free UOV knob is the input size `n_uov`,
set to the smallest value that keeps the cost of every known attack at `>= 2^128`
under the UOV estimator.

| Parameter | Value |
|-----------|-------|
| Commitment `(k, n_com, m_uov)` | `(32, 83, 131)` ({{BFMRSV25}}, Table 3) |
| Nullifier `nu` | `28` bytes |
| Credit width `L` | `2` (`t, x, d in [0, 2^16 - 1]`) |
| UOV `n_uov` | `275` (`m_uov = 131`, `q = 256` shared with the commitment) |

Security margins: the binding block satisfies `m_uov - k = n_com + 128/log2(q) =
n_com + 16`. Because `m_uov = 131` is far larger than a standard UOV set, `n_uov =
275` was fixed as the minimum passing a 128-bit check under the
CryptographicEstimators `UOVEstimator` ({{CryptEst}}, which implements the
{{UOV}} Section 4 attacks).

**API sizes.** Everything below is derived from the parameters above and is
given in bytes (one `F_256` element each). `F, G` are the public maps from
`GenerateParameters(dst)`; there is no in-circuit hash.

| Function | Input | Output |
|----------|-------|--------|
| `Com(nf, t, r)` | `nf: nu = 28`, `<t>_L: L = 2`, `r: n_com = 83` (`= rho`) | `c: m_uov = 131` |
| `Tag(c, x)` | `c: 131`, `<x>_L: L = 2` | `y: m_uov = 131` |
| `P(s)` (UOV) | `s: n_uov = 275` | `y: m_uov = 131` |

The message `msg = EmbedNullifierBalance(nf, t)` lays out `k = 32` bytes as `nf
(28) || <t>_L (2) || <x>_L (2)`, with the refund slot at `off_refund = nu +
L = 30` left zero until `Tag` writes it (no reserved bytes, since `off_refund
+ L = k`). Derived map and signature dimensions: `F: F_256^83 -> F_256^32`,
`G: F_256^83 -> F_256^99`, and `v = n_uov - m_uov = 144`.

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
>    oracles. This is reasonable for Keccak, but we would need to figure out
>    something else for the MQ variant.
>
> 2. If we add a randomizer to `Tag()` and instantiate it with Keccak, then we
>    might even be able to reduce to standard UOV rather than one-more-UOV.
>
> 3. For the MQ variant, Figure out if the homomorphic tagging trick for the MQ
>    variant is sound. We likely need the commitment to be pseudorandom, in
>    which case allowing the attacker to select the tag probably incurs a
>    security loss multiplicative in the number of bits of the refund.

> TODO Finalize parameters MQ variant (including the UOV parameters used), pending further cryptanalysis of the commitment.
> TODO Remind the reader here how the current parameters were chosen.

> TODO Justify halving the Keccak state from 1600 to 800 (relative to
> TurboSHAKE).

# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

The use of `Keccak-p[800,12]` in this application was proposed by Bas Westerbaan.
