# Practicalities from the first end-to-end instantiation

Working notes from building the first end-to-end instantiation of MoLE
(IHAT endorsements, type 0x0002, via `ihat-rs`; ACT credentials, type
0x0001, via `anonymous-credit-tokens`; both flows over the `Mole` HTTP
authentication scheme). Each entry records something the drafts left open,
underspecified, or wrong-by-omission that implementation forced a decision
on, together with the decision made and where it now lives.

Where an entry says "resolved in this branch", the corresponding draft text
has been updated here; the rest are recommendations awaiting discussion.

## 1. IHAT presentations must take the challenge digest as a proof input

**Draft**: protocols, "Challenge Binding" and the IHAT redemption section
require `Present`/`Verify` to bind `challenge_digest` into the proof
transcript.

**Found**: the IHAT cryptography (and `ihat-rs`) had no such input: `show`
and `verify` took only the accepted set and the statement, so a captured
presentation verified under any challenge.

**Resolution**: the redemption OR-proof's Fiat–Shamir challenge now absorbs
a caller-supplied, length-prefixed *presentation binding*; MoLE passes
`challenge_digest`. Implemented on the `presentation-binding` branch of
`ihat-rs`; specified in the crypto draft on this branch. A presentation
produced for one challenge fails verification under every other.

## 2. The two grant exchanges need explicit session correlation

**Draft**: protocols, IHAT grant section, flagged as TODO: "the two
exchanges must be correlated, since the Anchor holds state between them.
Either CRYPTO adds a session identifier to its messages or this document
mandates connection reuse."

**Found**: the Anchor keeps per-issuance state (its committed-challenge
factors and proof nonce) between `Sign` and `Prove`; without correlation, a
server with more than one concurrent grant cannot pair them. Mandating
connection reuse is fragile: HTTP/2 multiplexing, proxies, and connection
racing all break the assumption.

**Resolution (resolved in this branch)**: correlation at the endorsement
protocol layer. The grant bodies are step-tagged; the Anchor returns an
opaque `session_id` in its first response and the Client echoes it in its
second request. The identifier is opaque, single-use, and unlinkable to
anything but the grant itself (which the Anchor can already correlate — it
is one session with an authenticated user). Anchors MUST forget the session
state after answering step 2 or after a timeout.

## 3. The ACT `Challenge` and the spend/refund ↔ predicate/update mapping

**Draft**: protocols, ACT section, flagged as TODO: "the exact mapping
between the spend and refund operations of ACT and MoLE's predicate and
update is not settled. `Challenge` for this type must express the predicate
and the charged amount."

**Resolution (resolved in this branch)**:

```
struct {
  opaque policy_context<V>;
  uint64 charge;   /* the spend amount s */
  uint64 topup;    /* the Moderator-authorized top-up a, normally 0 */
} Challenge;
```

The mapping:

* **Predicate** = the ACT spend with public amounts `s = charge`,
  `a = topup`. A verifying spend proof says exactly "the hidden balance
  satisfies `c - s + a >= 0`" — that is the one bit the Moderator learns.
* **Update** = the ACT refund `t`, chosen by the Moderator in
  `[0, max(0, s - a)]`. The Client's replacement Credential has balance
  `c - s + a + t`. `t = s` sustains access indefinitely; `t = 0` burns the
  initial grant down; anything between is dynamic rate limiting.
* The Moderator MUST check the revealed `s`, `a` equal the challenged
  `charge`, `topup`, and that the revealed request context is the policy's
  (see 4). Both amounts are policy-wide constants: varying them per Client
  partitions the anonymity set (same rule the Budget Privacy Pass section
  already states for its `amount`).

## 4. ACT's request context must be policy-wide, never per-client

**Found**: ACT binds a *request context* scalar `ctx` into every token at
issuance, and **the spend proof reveals it**. Nothing in the MoLE drafts
says how to choose it, and the natural-looking choices (per-request
binding, per-client value) are privacy bugs: a per-client `ctx` links every
presentation back to the Redeem & Issue that produced the token.

**Resolution (resolved in this branch)**: `ctx` is derived from public,
policy-wide values only — this instantiation uses
`SHA-512("MoLE-ACT:request-context:v1" || len(policy_context) ||
policy_context || len(epoch) || epoch) mod ell`, computed independently by
both sides. The Moderator checks the revealed `ctx` at presentation, which
scopes tokens to a policy and epoch without partitioning Clients.

## 5. ACT presentations are challenge-checked, not challenge-bound

**Found**: the ACT spend proof's transcript binds the nullifier, the public
amounts, and `ctx` — but not a per-presentation value. The
`challenge_digest` field of `PresentationAndUpdate` is therefore an
*equality check* by the Moderator, not a proof input: the proof itself
would verify under any challenge with the same amounts.

**Why this is acceptable**: a spend proof is single-use — replaying it under
a different challenge is stopped by the nullifier store, the same argument
the protocols draft already makes for Privacy Pass Reverse Flow ("anti-replay
does not come from challenge binding: it comes from the token being
single-use"). The party who could re-bind a fresh proof before its first
use is the Moderator itself, which gains nothing.

**Recommendation**: either document this in the ACT registration's
challenge-binding statement (done on this branch), or extend draft-act with
an associated-data input to the spend transcript so ACT can offer the same
binding strength as IHAT redemption. The latter is cleaner and cheap; filed
as a suggestion for draft-act.

## 6. A concrete discovery format

**Draft**: protocols, "Key Rotation and Discovery" is a TODO with an open
directory-format question (Privacy Pass style vs JWKS).

**Resolution (strawman in this branch)**: Privacy Pass-style JSON
directories at well-known paths:

* `/.well-known/mole-anchor`: per endorsement type, the Anchor public key,
  the current `endorsement-context` (epoch), and the grant endpoint.
* `/.well-known/mole-moderator`: per policy, the `policy-context`, the
  credential type and its key material (for ACT: public key and domain
  separator), the issuance amounts (`initial-credits`, `charge`), the
  accepted endorsement type, the accepted Anchor keys **in normative
  order**, and the accepted `endorsement-context`.

Notes from implementation: the Moderator must republish whenever an Anchor
rotates; anchors trusted by one Moderator must agree on the epoch (this
instantiation's Moderator refuses to start otherwise); and the directory is
exactly the material a consistency mechanism must cover, since everything
in it partitions Clients if served inconsistently.

## 7. `ModeratorChallenge` and `CredentialChallenge` are indistinguishable on the wire

**Found**: both structures are `uint16` + `opaque<V>`, their type
namespaces are disjoint registries, and both arrive as `Mole` challenges on
the same 401 with the same realm. A Client cannot tell which registry a
challenge's leading `uint16` indexes except by trying both decodings and
checking which type value it recognizes — which happens to work today
(0x0001 is ACT in one registry and "moderator trust" in the other) but is a
collision waiting for an assignment.

**Recommendation**: distinguish the two structurally — a leading role
octet, distinct auth-params (`challenge` vs `endorsement-challenge`), or
distinct realms. Until then, implementations must do what this one does:
attempt both interpretations and dispatch on recognized type values.

## 8. The status of a successful Redeem & Issue response

**Found**: the transport draft's example implies that after a successful
redemption the Moderator returns the `CredentialResponse` "alongside its
unchanged challenge", but no status code is stated.

**Resolution (resolved in this branch)**: 401 with the unchanged
`WWW-Authenticate` challenges and the `Mole-Credential: response=` header.
The Client holds a Credential but has not yet presented one; any success
status would make optional-authentication deployments ambiguous.

## 9. Challenge determinism is what makes digest checking implementable

**Found**: verifying a redemption or presentation requires the Moderator to
know *which* challenge it was bound to. With per-policy deterministic
challenges (this instantiation), the Moderator recomputes the challenge and
its digest statelessly. The moment a challenge carries per-request entropy
(`request_context`), the Moderator must persist every outstanding challenge
it has issued, with an eviction policy that becomes a replay-window knob.

**Recommendation**: when the `request_context` construction rules are
settled (open TODO in the transport draft), state this state-keeping
consequence explicitly, and recommend deterministic challenges for
deployments that do not need per-request binding.

## 10. ACT proofs overflow default thread stacks (mostly a D = 80 artifact)

**Found**: ACT spend proof generation and verification overflowed the
default 2 MiB stacks of tokio worker threads and Rust test threads,
forcing the instantiation to size its runtime threads to 16 MiB.

**Corrected diagnosis (see 15)**: the pressure is proportional to the
digit count D. At D = 8, release builds fit the default stacks with no
accommodation; only unoptimized debug builds still want headroom
(~4 MiB) from frame bloat under the async call depth.

**Recommendation**: implementation-considerations feedback for draft-act
(and the `anonymous-credit-tokens` crate): note that stack use scales
with D, or move the digit-decomposition working set to the heap.

## 11. Endorsements are not durable client state yet

**Found**: presenting an IHAT endorsement requires the issuance
rerandomiser gamma alongside the endorsement, and `ihat-rs` (correctly)
keeps gamma private inside `IssuedEndorsement` — but provides no
serialization, so an Endorsement cannot outlive the process that obtained
it. ACT, by contrast, defines storage encodings for every client-side
object. A wallet-style Client needs the same from IHAT.

**Recommendation**: define a client-storage encoding for
`(Endorsement, gamma)` in the crypto draft / `ihat-rs` (it never crosses
the wire, so it needs no registry action, but interoperable wallets want a
common format).

## 12. Uniform rejection, on purpose

**Found**: the protocols draft's security-considerations TODO already
names the "bad proof" vs "spent nullifier" timing/error side channel. In
practice the tempting implementation returns distinct errors for
diagnostics. This instantiation returns one uniform 403 (`"rejected"`) for
every policy rejection — bad proof, wrong epoch, spent endorsement
nullifier, spent spend nullifier, wrong amounts, wrong key — and reserves
401-with-challenges for material it does not recognize at all (including
greased types, which are answered identically to absent authentication, as
the greasing section requires).

## 13. Emitting and parsing multiple challenges

**Found**: offering both a credential challenge and an endorsement
challenge on one 401 is the normal case, and RFC 9110 allows them
comma-joined in one `WWW-Authenticate` field or split across several
fields. Comma-joined challenges are genuinely fiddly to parse (auth-params
are themselves comma-separated).

**Resolution**: this instantiation emits one challenge per header field and
parses both forms. Recommend the transport draft advise the same.

## 14. Grant requests ride inside the Anchor's existing session

**Found**: the grant flow needs the Anchor to know *who* it is endorsing
(to enforce its per-user grant budget) at the moment the first exchange
arrives — i.e. the `application/mole-endorsement-request` POST must carry
the Anchor's ordinary session authentication (cookies, tokens). The drafts
say Anchors "constrain how many times they will endorse a given user" but
not that this forces the grant endpoint to be an authenticated,
first-party endpoint. Also worth stating: the Client takes the
`endorsement_context` from the Anchor's configuration; an Anchor MUST
refuse to sign under any other context, or Clients could mint endorsements
into past or future epochs.

## 15. ACT's balance digit count D is a policy parameter, and the default was 10x too big

**Found**: draft-act defines the digit count D as a deployment parameter
(`D <= MAX_DIGITS = 80`), but the reference crate pinned `D = 80` — the
largest value whose balance range fits a `u128` — making every spend
proof carry an ~127-bit range proof. Measured on the wire: a spend proof
is `192 * D + 450` bytes, so a MoLE presentation was a **21,174-byte**
base64url `Authorization` header at D = 80, beyond common intermediary
header limits (nginx and Apache default to 8 KB). This was the real
cause of finding 1's deployment worry and most of finding 10's stack
pressure.

**Resolution**: the instantiation now runs D = 8 (balances in
`[0, 6561)`, ample for rate-limiting policies): the presentation header
is 2,742 bytes and release builds fit default thread stacks. Because D
fixes the proof size on the wire, it MUST be policy-wide: the Moderator
directory publishes `act-balance-digits`, Clients refuse mismatches, and
a per-client D would be a partitioning vector exactly like `charge`.
Resolved in this branch (protocols, ACT configuration); the remaining
upstream item is making D a const generic in `anonymous-credit-tokens`
(branch `d8` fixes it at 8) and stating the header-size consequence in
draft-act's implementation considerations.
