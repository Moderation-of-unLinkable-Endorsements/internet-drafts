---
title: "MoLE Cryptography: Issuer-Hiding Anonymous Tokens (IHAT)"
abbrev: "IHAT"
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
  latest: "https://moderation-of-unlinkable-endorsements.github.io/internet-drafts/draft-authors-mole-crypto.html"

author:
 -
    fullname: Samuel Schlesinger
    organization: Google LLC
    email: sgschlesinger@gmail.com

normative:
  Hash2Curve: RFC9380
  TLS13: RFC8446
  SEC1:
    title: "SEC 1: Elliptic Curve Cryptography"
    target: https://www.secg.org/sec1-v2.pdf
    date: 2009

informative:
  ARCHITECTURE: I-D.draft-jms-mole-architecture
  PROTOCOLS: I-D.draft-jms-mole-protocols
  ACT: I-D.draft-schlesinger-cfrg-act
  ChaumPedersen: DOI.10.1007/3-540-48071-4_7
  CDS94: DOI.10.1007/3-540-48658-5_19
  FST: DOI.10.1007/3-540-47721-7_12

...

--- abstract

This document specifies IHAT (Issuer-Hiding Anonymous Tokens), a
pairing-free anonymous endorsement scheme over NIST P-256. An Anchor
obliviously issues a publicly verifiable endorsement on a Client-chosen
nullifier: the endorsement is a Chaum-Pedersen DLEQ proof over the
Diffie-Hellman keyed MAC `Z = x * Y`, transferred to a statement the
Anchor never sees. At redemption the Client presents the endorsement with
a 1-of-n OR proof that its rerandomised key matches one of an accepted set
of Anchor keys, hiding which Anchor issued it. Redemption is bound to a
caller-supplied byte string, scoping each presentation to the challenge
that requested it.

IHAT instantiates the endorsement protocol of the MoLE architecture: the
grant flow is the two-exchange issuance defined here, and redemption
proves membership in a Moderator's Anchor set without revealing the
Anchor, linking back to issuance, or requiring pairings or new
assumptions beyond DDH.

--- middle

# Introduction

The MoLE architecture {{ARCHITECTURE}} needs an endorsement with an
unusual combination of properties: an Anchor grants it to a Client it
trusts, yet the Anchor must not be able to recognize it later; a Moderator
must be able to verify it against a *set* of Anchor keys without learning
which member issued it; anyone must be able to verify it without Anchor
secrets; and each endorsement must be redeemable exactly once inside a
stated validity window.

IHAT provides these properties over NIST P-256 without pairings. The
construction has two phases:

* **Issuance** (the MoLE grant): a two-round exchange after which the
  Client holds a publicly verifiable endorsement on the *rerandomised*
  statement `(X_hat, Z_hat) = (gamma * X, gamma * x * Y)`, where `X` is
  the Anchor key, `Y` is the hash of a Client-chosen nullifier, and
  `gamma` is a Client-chosen rerandomiser the Anchor never sees. The
  endorsement itself is a Chaum-Pedersen {{ChaumPedersen}} DLEQ proof
  that `(G, X_hat, Y, Z_hat)` is a Diffie-Hellman tuple, obtained
  obliviously: the Anchor computes over blinded values and learns
  neither the nullifier, the final statement, nor the final proof.

* **Redemption** (the MoLE Redeem & Issue presentation): the Client
  presents the endorsement together with a Cramer-Damgard-Schoenmakers
  {{CDS94}} 1-of-n OR proof that `X_hat` is a `gamma`-scaling of *some*
  key in the Verifier's accepted set. The OR proof's Fiat-Shamir {{FST}}
  challenge additionally absorbs a caller-supplied *presentation
  binding*, so a presentation produced for one context fails
  verification in every other.

## Key Properties

1. **Public verifiability**: an endorsement verifies against Anchor
   public keys only; no Anchor secret is needed at redemption.

2. **Blind issuance**: the Anchor sees only the blinded point
   `Y' = v * Y` and the twisted challenge `e'`; it learns neither the
   nullifier `nf`, the rerandomised statement, nor the finished
   endorsement. The blinding is information-theoretic: every issuance
   transcript is consistent with every finished endorsement under unique
   blinding values.

3. **Unlinkable redemption**: because the finished endorsement is
   uniformly rerandomised, a colluding Anchor and Verifier cannot link a
   redemption to the grant session that produced it, beyond the validity
   window (`endorsement_context`) both commit to.

4. **Issuer hiding**: the redemption OR proof is witness
   indistinguishable; the Verifier learns only that the issuing Anchor is
   a member of the accepted set it supplied.

5. **One-time use**: the nullifier `nf` is revealed at redemption, so a
   Verifier that records nullifiers accepts each endorsement once.
   (Replay protection is the Verifier's store; see
   {{security-considerations}}.)

6. **Context binding**: the `endorsement_context` (in MoLE, the epoch) is
   bound into the issuance proof both structurally — the Pedersen
   generator used in the Anchor's commitment is derived from it — and
   through the Fiat-Shamir challenge, so an endorsement cannot be moved
   across contexts. The presentation binding does the same for the
   redemption challenge.

The privacy properties (2, 3, 4) are by design unconditional, in line
with the MoLE threat model {{ARCHITECTURE}}, which requires Client
privacy to survive a future cryptographically relevant quantum computer
analysing recorded transcripts. The security properties (unforgeability,
one-time use) are computational and rest on the hardness of Diffie-Hellman
problems over P-256; a CRQC breaks them only for sessions after it
exists.

## Protocol Overview

Three roles, matching {{ARCHITECTURE}}: the **Anchor** (issuer) holds the
key pair; the **Client** obtains and redeems endorsements; the
**Verifier** (in MoLE, the Moderator) decides acceptance against its
accepted set of Anchor keys.

~~~ aasvg
+--------+                                     +--------+
| Client |                                     | Anchor |
+---+----+                                     +---+----+
    |                                              |
    +--- SignatureRequest: Y' = v*Y, ctx --------->|
    |<-- Signature: Z', C', T1', T2' --------------+
    +--- ProofRequest: e' ------------------------>|
    |<-- Proof: r', a', b' ------------------------+
 Finalize                                          |
    |
    |                                     +----------+
    |                                     | Verifier |
    |                                     +----+-----+
    |                                          |
    +--- Presentation: endorsement, OR proof ->|
    |                                          |
~~~
{: #fig-ihat-overview title="IHAT issuance (GetEnd) and redemption (Show)"}

# Conventions and Definitions

{::boilerplate bcp14-tagged}

## Notation

- `||`: concatenation of byte arrays.
- `x <- S`: uniformly sampling `x` from the set `S`.
- `[n]`: the set of integers {0, 1, ..., n-1}.
- `len(x)`: the length of the byte array `x`, encoded as an 8-byte
  little-endian integer when used as a hash input prefix.
- Group operations are written additively: `A + B` adds group elements,
  `A * n` multiplies the element `A` by the scalar `n`, and `0` is the
  identity element.
- `Zp` is the scalar field of the group; `Zp*` excludes zero.

The protocol uses the following data types:

- **Group**: the NIST P-256 (secp256r1) group {{SEC1}}. Its order is
  prime, so every non-identity element generates it. `G` is the standard
  base point.
- **Group Element**: a P-256 point, encoded in 33-byte SEC1 compressed
  form.
- **Scalar**: an element of `Zp`, encoded as a 32-byte big-endian
  integer; encodings not in `[0, p)` are rejected.
- **PRNG**: a cryptographically secure random number generator.

## Hash Functions

All hashing uses the {{Hash2Curve}} constructions over P-256 with the
suite `P256_XMD:SHA-256_SSWU_RO_` for hashing to the group and
`hash_to_field` with `expand_message_xmd`/SHA-256 for hashing to scalars.
Four independent hashes are obtained by domain separation:

| Function | DST | Purpose |
|:---------|:----|:--------|
| `H1(nf)` | `MOLE-IHAT-P256:H1-nullifier-to-group:v1` | Hash a nullifier to a group element |
| `Hctx(ctx)` | `MOLE-IHAT-P256:pedersen-generator-H:v1` | The context-bound Pedersen generator `H` |
| `HFS(...)` | `MOLE-IHAT-P256:fiat-shamir-getend:v1` | The issuance Fiat-Shamir challenge (to scalar) |
| `HOR(...)` | `MOLE-IHAT-P256:fiat-shamir-or-proof:v1` | The redemption OR-proof challenge (to scalar) |
{: #hash-table title="IHAT hash functions"}

Deriving the Pedersen generator `H = Hctx(endorsement_context)` from the
context, rather than fixing one global `H`, binds the context into the
Anchor's commitment structurally, and hash-to-curve guarantees no party
knows `log_G H` for any context.

**Transcript framing.** Both Fiat-Shamir hashes take multiple inputs.
Fixed-width inputs (33-byte points) are concatenated in order. Every
variable input is framed by an 8-byte little-endian prefix: byte strings
by their byte length, point lists by their element count. The hash input
encoding is therefore injective by construction, for every input shape.

# Protocol Specification

## System Parameters

An IHAT instance is parameterized by the group (P-256 in this document;
see {{suites}}) and its standard generator `G`. The per-endorsement
parameter is:

- `endorsement_context`: an opaque byte string naming the validity
  window of the endorsement. In MoLE this is the epoch from the Anchor's
  configuration ({{PROTOCOLS}}). The Client, Anchor, and Verifier must
  agree on it exactly: the Anchor MUST refuse to sign under any context
  other than its current one, and the Verifier rejects endorsements whose
  context is not the one it accepts.

## Key Generation

~~~ pseudocode
KeyGen(rng):
  Input:
    - rng: PRNG.
  Output:
    - x: Scalar.         # Anchor private key, x != 0
    - X: Group Element.  # Anchor public key

  Steps:
    1. x <- Zp*
    2. X = G * x
    3. return (x, X)
~~~

## The Endorsement Statement

An endorsement attests, for the Anchor key `X = G * x` and the hashed
nullifier `Y = H1(nf)`, to the keyed MAC value `Z = Y * x` — that is,
that `(G, X, Y, Z)` is a Diffie-Hellman tuple. To make issuance blind,
the finished endorsement is stated on the *rerandomised* pair

~~~
X_hat = X * gamma        Z_hat = Z * gamma
~~~

for a Client-chosen `gamma <- Zp*`. The DLEQ relation is preserved
(`(G, X_hat, Y, Z_hat)` is again a DH tuple), and `gamma` becomes the
Client's redemption witness: knowledge of `gamma` with
`X_hat = X_j * gamma` for some accepted key `X_j` is exactly what the
redemption OR proof shows.

The endorsement itself is the tuple

~~~
endorsement = (X_hat, Z_hat, nf, e, a, b, r, endorsement_context)
~~~

where `(e, a, b, r)` is a Chaum-Pedersen DLEQ transcript with a Pedersen
commitment to the committed-challenge factor `a` (the commitment `C = G *
a + H * b` enters the Fiat-Shamir challenge, which is what makes the
oblivious two-round issuance below sound).

## Issuance (GetEnd)

Issuance is two request/response exchanges. The Client drives; the
Anchor keeps state (its randomness) between the exchanges, correlated at
the transport layer ({{PROTOCOLS}}).

### Client: Prepare

~~~ pseudocode
Prepare(nf, endorsement_context, rng):
  Input:
    - nf: Byte Array.                   # Client-chosen nullifier
    - endorsement_context: Byte Array.
    - rng: PRNG.
  Output:
    - request: SignatureRequest.
    - state: Client state.

  Steps:
    1. v <- Zp*        # input blinding
    2. gamma <- Zp*    # key rerandomiser (the redemption witness)
    3. alpha <- Zp*    # committed-challenge twist
    4. beta <- Zp      # Pedersen rerandomiser
    5. epsilon <- Zp*  # response twist
    6. rho <- Zp       # nonce rerandomiser
    7. Y = H1(nf)
    8. Y' = Y * v
    9. request = (Y', endorsement_context)
   10. state = (nf, endorsement_context, Y, Y',
                v, gamma, alpha, beta, epsilon, rho)
   11. return (request, state)
~~~

The randomness MUST be fresh per issuance; see
{{security-considerations}}.

### Anchor: Sign

~~~ pseudocode
Sign(x, request, rng):
  Input:
    - x: Scalar.                # Anchor private key
    - request: SignatureRequest = (Y', endorsement_context).
    - rng: PRNG.
  Output:
    - response: Signature.
    - state: Anchor state for the second exchange.

  Steps:
    1. H = Hctx(endorsement_context)
    2. a' <- Zp*   # committed-challenge factor
    3. b' <- Zp    # Pedersen blinding
    4. t' <- Zp    # proof nonce
    5. Z'  = Y' * x
    6. C'  = G * a' + H * b'
    7. T1' = Y' * t'
    8. T2' = G * t'
    9. response = (Z', C', T1', T2')
   10. state = (a', b', t')
   11. return (response, state)
~~~

The Anchor MUST check that `endorsement_context` is its current context
before signing, and MUST use fresh `(a', b', t')` per issuance: the
second-exchange response `r' = t' + e' * a' * x` is a Schnorr-type
response under the nonce `t'` against a Client-chosen challenge, so nonce
reuse reveals the private key.

### Client: RequestProof

~~~ pseudocode
RequestProof(state, X, response):
  Input:
    - state: Client state from Prepare.
    - X: Group Element.          # Anchor public key
    - response: Signature = (Z', C', T1', T2').
  Output:
    - request: ProofRequest.
    - state': Client state.

  Steps:
    1. H = Hctx(endorsement_context)
    2. X_hat = X * gamma
    3. Z_hat = Z' * (gamma * v^-1)          # = Y * x * gamma
    4. C  = C' * alpha^-1 - H * beta
    5. T1 = (T1' - Y' * rho) * (epsilon^-1 * v^-1)
    6. T2 = (T2' - G * rho) * epsilon^-1
    7. e  = HFS(X_hat, Y, Z_hat, T1, T2, C, endorsement_context)
    8. e' = epsilon * alpha^-1 * gamma * e  # the twisted challenge
    9. request = (e')
   10. state' = state + (X, Z', C', T1', T2', e, e', X_hat, Z_hat)
   11. return (request, state')
~~~

`HFS` binds the full statement — including `X_hat`, so a finished proof
cannot be transported to a different rerandomised key, and the
`endorsement_context`, so the endorsement commits to its validity
window. Its input is the six points in the listed order followed by the
length-prefixed context.

### Anchor: Prove

~~~ pseudocode
Prove(x, state, request):
  Input:
    - x: Scalar.                 # Anchor private key
    - state: Anchor state = (a', b', t').
    - request: ProofRequest = (e').
  Output:
    - response: Proof.

  Steps:
    1. r' = t' + e' * a' * x
    2. response = (r', a', b')
    3. return response
~~~

The Anchor MUST forget `state` after answering (or after a timeout): each
`(a', b', t')` answers exactly one `ProofRequest`.

### Client: Finalize

~~~ pseudocode
Finalize(state', response):
  Input:
    - state': Client state from RequestProof.
    - response: Proof = (r', a', b').
  Output:
    - endorsement, or FAIL.

  Steps:
    // Validate the Anchor's opening and DLEQ responses. Evaluate all
    // four checks before branching on the combined (public) result.
    1. H = Hctx(endorsement_context)
    2. check a' != 0
    3. check C' == G * a' + H * b'
    4. check Y' * r' == Z' * (e' * a') + T1'
    5. check G  * r' == X  * (e' * a') + T2'
    6. if any check failed: return FAIL

    // Unblind into the endorsement transcript.
    7. a = alpha^-1 * a'
    8. b = alpha^-1 * b' - beta
    9. r = epsilon^-1 * (r' - rho)
   10. return (X_hat, Z_hat, nf, e, a, b, r, endorsement_context)
~~~

If `Finalize` fails the Client MUST discard the whole session, including
its randomness; it MUST NOT retry with the same state.

The Client SHOULD verify its own finished endorsement with `DLEQValid`
below; for an honest exchange this always succeeds (the checks in
`Finalize` imply it), so a failure indicates an implementation fault.

## Endorsement Verification

`DLEQValid` checks that an endorsement is a well-formed proof that
`(G, X_hat, Y, Z_hat)` is a DH tuple. **It is not acceptance**: it never
references an Anchor key, so `X_hat` is unconstrained and anyone can mint
a passing endorsement for a statement of their choice. Acceptance is
`Verify` below, which additionally requires the OR proof binding `X_hat`
to the accepted set.

~~~ pseudocode
DLEQValid(endorsement):
  Input:
    - endorsement = (X_hat, Z_hat, nf, e, a, b, r, ctx).
  Output:
    - valid: boolean.

  Steps:
    1. if a == 0: return false
    2. if X_hat == 0 or Z_hat == 0: return false
    3. Y = H1(nf)
    4. if Y == 0: return false
    5. T1 = Y * r - Z_hat * (e * a)
    6. T2 = G * r - X_hat * (e * a)
    7. H  = Hctx(ctx)
    8. C  = G * a + H * b
    9. return e == HFS(X_hat, Y, Z_hat, T1, T2, C, ctx)
~~~

The identity guards in step 2 are load-bearing: with
`X_hat = Z_hat = 0` the `e * a` terms vanish from the transcript and a
forged endorsement would verify.

## Redemption (Show)

At redemption the Client proves that `X_hat` is a `gamma`-scaling of
some key in the Verifier's accepted set `AccSet = (X_1, ..., X_n)`,
without revealing which. The proof is a CDS94 1-of-n OR of Schnorr
proofs for the relations `X_hat = X_l * w`, `l` in `[n]`; the true branch
`j` uses the witness `w = gamma` and the others are simulated.

Both `Present` and `Verify` take a byte string `binding` that is hashed
into the OR proof's challenge. In MoLE, `binding` is the
`challenge_digest` of the Moderator challenge that requested the
presentation ({{PROTOCOLS}}); a presentation is then valid only for the
challenge it answers. Deployments without such a context pass the empty
string, which is itself a distinct binding.

### Client: Present

~~~ pseudocode
Present(endorsement, gamma, AccSet, j, binding, rng):
  Input:
    - endorsement: as produced by Finalize.
    - gamma: Scalar.            # the redemption witness
    - AccSet: (X_1, ..., X_n).  # accepted Anchor keys, n >= 1
    - j: the index with X_hat == X_j * gamma (secret)
    - binding: Byte Array.
    - rng: PRNG.
  Output:
    - presentation = (endorsement, or_proof).

  Steps:
    // Simulated challenge/response pairs for every branch, one
    // honest nonce. All steps below MUST be constant-time in j:
    // recover values at index j by constant-time selection, never
    // by indexing.
    1. for l in [n]: c_l <- Zp; s_l <- Zp
    2. k <- Zp
    3. t_honest = X_j * k              # constant-time selected base
    4. for l in [n]:
    5.   t_l = X_l * s_l - X_hat * c_l # simulated commitment
    6.   if l == j: t_l = t_honest     # constant-time selection
    7. c = HOR(AccSet, X_hat, (t_1, ..., t_n), binding)
    8. c_j = c - sum(c_l for l != j)   # real branch absorbs c
    9. s_j = k + c_j * gamma
   10. or_proof = ((t_1, c_1, s_1), ..., (t_n, c_n, s_n))
   11. return (endorsement, or_proof)
~~~

`HOR`'s input is: the length-prefixed accepted set (each key 33 bytes,
in the Verifier's published order), then `X_hat`, then the
length-prefixed commitment list, then the length-prefixed `binding`.
Binding `AccSet` and `X_hat` — not only the commitments — strengthens
soundness in the random-oracle model, and the framing keeps the input
injective for every shape.

### Verifier: Verify

~~~ pseudocode
Verify(presentation, AccSet, binding):
  Input:
    - presentation = (endorsement, or_proof).
    - AccSet: (X_1, ..., X_n).
    - binding: Byte Array.
  Output:
    - accept: boolean.

  Steps:
    1. if not DLEQValid(endorsement): return false
    2. if count(or_proof) != n or n == 0: return false
    3. if X_hat == 0 or any X_l == 0: return false
    4. c = HOR(AccSet, X_hat, (t_1, ..., t_n), binding)
    5. if sum(c_1, ..., c_n) != c: return false
    6. for l in [n]:
    7.   if X_l * s_l != t_l + X_hat * c_l: return false
    8. return true
~~~

On acceptance the Verifier reads `nf` and `endorsement_context` from the
endorsement and applies its own policy: in MoLE, the context must name
the current epoch and `nf` must not have been seen in it
({{PROTOCOLS}}). `Verify` itself is a pure predicate: the same
presentation verifies every time under its binding, and replay
protection is the caller's nullifier store.

The identity checks in step 3 mirror those of `DLEQValid`: the identity
statement `X_hat = 0` is satisfiable for every base without a witness,
and an identity key in the accepted set is a degenerate policy entry.

# Protocol Messages and Wire Format {#wire-format}

Messages use the TLS presentation language ({{Section 3 of TLS13}}).
All elliptic-curve values are over P-256; `n` is the group order.

~~~ tls-presentation
opaque Scalar[32];   /* big-endian, in [0, n); reject otherwise */
opaque Point[33];    /* SEC1 compressed; reject invalid points */

opaque VarBytes<0..2^16-1>;

struct {
    Point    yp;                  /* Y' = Y * v */
    VarBytes endorsement_context;
} SignatureRequest;               /* Client -> Anchor */

struct {
    Point zp;                     /* Z'  = Y' * x  */
    Point cp;                     /* C'  = G*a' + H*b' */
    Point t1p;                    /* T1' = Y' * t' */
    Point t2p;                    /* T2' = G * t'  */
} Signature;                      /* Anchor -> Client */

struct {
    Scalar e_prime;         /* e' = epsilon * alpha^-1 * gamma * e */
} ProofRequest;                   /* Client -> Anchor */

struct {
    Scalar rp;                    /* r' = t' + e' * a' * x */
    Scalar ap;                    /* a' */
    Scalar bp;                    /* b' */
} Proof;                          /* Anchor -> Client */

struct {
    Point    x_hat;
    Point    z_hat;
    VarBytes nf;
    Scalar   e;
    Scalar   a;
    Scalar   b;
    Scalar   r;
    VarBytes endorsement_context;
} Endorsement;

struct {
    Point  t;                     /* branch commitment    */
    Scalar c;                     /* branch sub-challenge */
    Scalar s;                     /* branch response      */
} Transcript;                     /* 97 bytes */

struct {
    Transcript transcripts<0..2^16-1>;  /* one per accepted key,
                                           in accepted-set order */
} OrProof;

struct {
    Endorsement endorsement;
    OrProof     or_proof;
} Presentation;                   /* Client -> Verifier */

struct {
    Point pk;                     /* X = G * x */
} AnchorPublicKey;
~~~

Decoders MUST reject non-canonical scalars, invalid or non-canonical
point encodings, and trailing bytes. The `binding` of `Present`/`Verify`
never crosses the wire: both parties derive it from context (in MoLE,
`challenge_digest = SHA-256` of the triggering challenge).

Message sizes: `SignatureRequest` is `35 + |ctx|` bytes, `Signature` 132
bytes, `ProofRequest` 32 bytes, `Proof` 96 bytes, `Endorsement`
`198 + |nf| + |ctx|` bytes, and a `Presentation` over an accepted set of
size `n` adds `2 + 97 * n` bytes.

# Implementation Considerations

## Nullifier Selection

The nullifier `nf` is Client-chosen and revealed at redemption. Clients
MUST sample it uniformly at random with at least 256 bits (32 bytes) of
entropy: a colliding nullifier makes the later of the two endorsements
unredeemable, and any structure in `nf` is visible to the Verifier at
redemption. The Anchor never sees `nf` — only `Y' = H1(nf) * v` — so it
cannot recognize the endorsement at redemption even in collusion with
the Verifier.

## Randomness Hygiene

Fresh randomness per issuance is security-critical on both sides:

- **Anchor**: reusing the nonce `t'` across issuances (or answering two
  `ProofRequest`s from one `Sign` state) reveals the private key, since
  `r' = t' + e' * a' * x` with a Client-chosen `e'`. The Anchor state
  from `Sign` MUST answer at most one `Prove`.
- **Client**: reusing `(v, gamma, alpha, beta, epsilon, rho)` across
  issuances links the resulting endorsements and can leak the blinders.

## Constant-Time Requirements

The value that redemption hides is the true-branch index `j`. `Present`
MUST be constant-time in `j`: the reference implementation recovers the
true base, the honest commitment position, and the real
challenge/response slots by constant-time selection over all branches
rather than by secret-dependent indexing or branching. `Finalize`
evaluates all four of its checks and branches once on the combined
result. Verification operates on public values and needs no such
protection.

## Point and Scalar Validation

All received points MUST be validated as P-256 points on decode (the
compressed encoding forces this) and all received scalars checked
canonical. The identity-element guards of `DLEQValid` and `Verify` are
part of the protocol, not optional hardening; see
{{security-considerations}}.

## Session Correlation

The Anchor holds `(a', b', t')` between the two exchanges. The transport
correlates them — in MoLE, via the opaque `session_id` of the grant
bodies ({{PROTOCOLS}}) — and the Anchor MUST expire unanswered sessions
and forget state after answering.

## Client Storage

Redemption needs `gamma` alongside the endorsement. Implementations that
persist endorsements (e.g. wallet-style Clients) MUST store `gamma` with
the same confidentiality as the endorsement itself and erase both after
redemption. A standard storage encoding is TODO; the wire format above
covers only what crosses the wire.

# Suites {#suites}

## IHAT(P-256, SHA-256)

- **Group**: NIST P-256 (secp256r1), SEC1 compressed encodings.
- **Hash to group**: `P256_XMD:SHA-256_SSWU_RO_` {{Hash2Curve}}.
- **Hash to scalar**: `hash_to_field` with `expand_message_xmd` /
  SHA-256, count 1 {{Hash2Curve}}.
- **DSTs**: as in {{hash-table}}.

Other suites (e.g. over ristretto255) would need new DSTs and are not
defined here.

# Security Considerations {#security-considerations}

## Threat Model

Matching {{ARCHITECTURE}}: the Verifier and Anchor may collude and keep
transcripts to attack Client privacy (issuer hiding, unlinkability),
including with future quantum assistance; Clients may deviate
arbitrarily to attack soundness (forging endorsements, redeeming twice,
escaping the accepted set). Privacy properties are designed to be
unconditional; soundness properties are computational, resting on
Diffie-Hellman assumptions over P-256 in the random-oracle model, and
fail only forward once a CRQC exists.

TODO: a formal statement and proof of the one-more-unforgeability and
blindness properties for the GetEnd issuance (the construction follows
the MoLE collaborators' design notes) belongs in a companion analysis.

## Unforgeability and the Identity Guards

An endorsement is a DLEQ proof on `(G, X_hat, Y, Z_hat)` with the
committed factor `a` entering multiplicatively as `e * a`. Two
degenerate cases would bypass it and are excluded by explicit checks:
`a = 0` (kills the response terms) and `X_hat = Z_hat = 0` (kills the
`e * a` terms; any `(e, r)` verifies). Similarly, `Y = 0` never occurs
for hash-to-curve outputs but is checked to keep `DLEQValid` sound on
adversarial inputs, and identity keys in the accepted set are rejected
because the OR relation `X_hat = X_l * w` is meaningless for `X_l = 0`.

One-more unforgeability — that a Client granted `q` endorsements cannot
present `q + 1` distinct nullifiers that verify — is required by
{{ARCHITECTURE}} and relies on the Pedersen-committed challenge
factor: the Anchor's challenge contribution `a'` stays hidden inside
`C'` until after the Client commits to `e'`, preventing the Client from
steering the Fiat-Shamir challenge of a second statement into one
issuance session.

## Blindness and Unlinkability

Given an issuance transcript `(Y', ctx, Z', C', T1', T2', e', r', a',
b')` and any finished endorsement `(X_hat, Z_hat, nf, e, a, b, r, ctx)`
over the same context and key, there is exactly one assignment of the
blinders `(v, gamma, alpha, beta, epsilon, rho)` consistent with both.
The blinding is therefore perfect: transcripts reveal nothing about
which endorsement they produced, and this holds against unbounded
(including quantum) adversaries. What issuance and redemption do share
is the `endorsement_context`; its width is the anonymity-set knob
discussed in {{PROTOCOLS}}.

## Issuer Hiding

The CDS94 OR proof is perfectly witness indistinguishable: simulated and
real branches are identically distributed, so the presentation reveals
only that `X_hat` scales *some* accepted key. Two caveats belong to the
deployment, not the proof. First, the anonymity set is the accepted set:
a Verifier with one Anchor hides nothing. Second, a malicious Verifier
can pad its set with keys no real Anchor uses; Clients cannot detect
this cryptographically, so accepted sets must be published, consistent
across Clients, and auditable ({{ARCHITECTURE}}, {{PROTOCOLS}}).

## Replay and Binding

`Verify` is stateless; one-time use comes from the Verifier's nullifier
store keyed by `(endorsement_context, nf)`, sized to the context window.
The presentation `binding` prevents a different kind of reuse: without
it, a presentation captured in one context verifies in any other with
the same accepted set. With the binding absorbed into `HOR`, moving a
presentation between challenges requires re-proving, which requires
`gamma`. Verifiers MUST pass the exact binding bytes they challenged
with; in MoLE this is the SHA-256 digest of the triggering challenge
structure ({{PROTOCOLS}}).

## Side Channels

Beyond the constant-time requirements above, Verifiers SHOULD return
indistinguishable errors for "invalid proof" and "spent nullifier" —
distinguishing them lets an attacker probe whether someone else has
redeemed a guessed nullifier — and SHOULD apply the timing guidance of
{{ARCHITECTURE}} for the flows this protocol sits inside.

# IANA Considerations

This document has no IANA actions. The MoLE endorsement type for IHAT
(0x0002) is registered in {{PROTOCOLS}}.

--- back

# Test Vectors
{:numbered="false"}

TODO: generate deterministic test vectors (fixed randomness for both
roles) covering issuance, an accepted set of size 4, and a bound
presentation, from the reference implementation
(`ihat-rs`).

# Acknowledgments
{:numbered="false"}

The GetEnd construction and its oblivious-issuance blinding follow the
design notes of the MoLE collaborators. This document specifies the
protocol as implemented in `ihat-rs`, and its shape follows {{ACT}}.
TODO: complete the author and acknowledgment lists.
