---
title: "MOLE Anchor-Bound Quality Reports"
abbrev: "MOLE Quality Reports"
category: info
docname: draft-chris-mole-anchor-quality-latest
submissiontype: IETF
v: 3
venue:
  github: Moderation-of-unLinkable-Endorsements/internet-drafts
author:
  - fullname: Christopher A. Wood
    organization: Cloudflare
  - fullname: Christopher Patton
    organization: Cloudflare
    email: chrispatton+ietf@gmail.com
normative:
  MOLE: I-D.draft-jms-mole-protocols
  EC-IHAT: I-D.draft-ladd-mole-ec-ihat
  EC-ACT: I-D.draft-schlesinger-mole-ec-act
  VDAF: I-D.draft-irtf-cfrg-vdaf
...

--- abstract

This document specifies an experimental MOLE quality-reporting profile in
which an issuer-hiding endorsement is bound to a private credential attribute
and a fresh, commitment-bound histogram report. It describes changes required
to EC-IHAT, EC-ACT, and the aggregation protocol. It does not change the
existing EC-IHAT or EC-ACT v1 ciphersuites.

--- middle

# Introduction {#intro}

An origin can assign a local quality label to an authorized operation. A
Moderator can learn aggregate counts by Anchor and by origin, but MUST NOT
learn the Anchor behind an individual endorsement or credential presentation.
There is no global notion of a good or bad Anchor. This profile does not
measure endorsement issuance volume or per-client endorsement rates.

# Task and Anchor Set {#task}

A reporting task fixes a Moderator key and credential context, an ordered,
nonempty Anchor public-key list, an epoch, origin, label-policy identifier,
time bucket, group ciphersuite, two aggregation-service keys, and a VDAF
algorithm identifier. This profile selects the two-aggregator Field128
Commitment-Bound Prio3Histogram with one proof; Field64 is not specified.
The Anchor at position `i` has a 1-based tag `j=i+1`.
The list and epoch are authenticated and frozen for a credential's lifetime;
rotation requires a fresh task and credential context. Clients MUST reject a
duplicate key or an ambiguous mapping. A task MUST have more than one possible
Anchor if the origin requires issuer hiding.

The group has independent fixed generators `H` and `R`, derived with distinct
domain-separation strings for this profile. Each report gets a fresh
commitment `C=j*H+rho*R`; reuse of `C` across issuance, reports, or
presentations is forbidden. An ACT profile may additionally sign the scalar
`HashToScalar(SerializeElement(pkA))` as its canonical, set-independent Anchor
identifier. The finite-field histogram uses `j`, not this full-size scalar.
If this optional identifier is used, the issuance proof MUST show that both
identifiers name the SAME Anchor.

# EC-IHAT Extension {#ihat}

EC-IHAT v1's `VerifyRedemption` proves membership of the rerandomized key
`X_hat` in the Anchor Set but says nothing about an ACT credential request.
A new redemption-proof variant takes an externally supplied issuance
commitment `C_issue=j*H+rho*R` and the digest of the versioned ACT issuance
request as part of its challenge transcript. Its joint statement is:

~~~
  exists i, delta, rho:
      X_hat - pkA[i] = delta * B
      C_issue - (i+1) * H = rho * R
~~~

The branch MUST be the same in BOTH equations. A simple first implementation
uses a Fiat-Shamir OR proof over the Anchor Set: each branch has two Schnorr
commitments, one branch is answered using `(delta, rho)`, and the other
branches are simulated. The Fiat-Shamir transcript contains the complete,
ordered Anchor Set, epoch, contexts, endorsement, `X_hat`, `C_issue`, ACT
request digest, and all branch commitments, with a new domain-separation
label. The verifier checks the sum of branch challenges and BOTH branch
equations. Responses and branch challenges use canonical scalars; reject
identity or invalid points. This initial encoding is linear in the number
of Anchors. Extending the existing partially binding commitment proof with
two-equation branches is a potential logarithmic optimization, but is not
interoperable with this OR-proof encoding. Redemption nullifier replay checks
remain mandatory. Merely appending `C_issue` to the existing proof transcript
does NOT establish the joint statement.

# EC-ACT Extension {#act}

Use a new credential type and independent transcript domain, never EC-ACTv1's
wire identifier or serialized proof lengths. The credential signs hidden
`j` (and optionally the set-independent Anchor scalar) in addition to its
nullifier and balance. Let `Hj` be a new ACT generator and `Ha, Hr` independent
issuance/report commitment generators. Its initial commitment is:

~~~
  K = k*H2 + r*H3 + j*Hj
  C_issue = j*Ha + rho*Hr
~~~

The new IssueRequest proof uses the SAME witness `j` in both equations.
The verifier MUST reject requests using different tags before issuing.
The signed issuance message remains `B+c*H1+ctx*H4+K`, so its signature
authenticates `j`. The client verifies that signature against its saved `K`.
The EC-IHAT joint proof binds `C_issue` to the signing Anchor. The ACT and
EC-IHAT commitment generators MUST be byte-for-byte identical in this step.

At presentation the client makes a fresh `C_report=j*Ha+rho_report*Hr`.
The EC-ACT spend proof's witness includes `j` and `rho_report` and proves:

~~~
  H1_prime = r3*B_bar - c*H1 - r*H3 - j*Hj
  K_n = kstar*H2 + rn*H3 + j*Hj
  C_report = j*Ha + rho_report*Hr
~~~

The remaining balance-range equations remain as in EC-ACT, but their
compiled witness indices, proof lengths, and transcript IDs change. The
refund signs `K_n + V1`, thereby authenticating the SAME hidden `j` in the
replacement credential. The client retains `j` in both pending spend and
completed credential state. Test the `s=0`, nonzero-spend, top-up, and
terminal-consumption branches, including a tampered `C_report` and an
attempt to change `j` in a refund. The spend challenge binds the versioned
task, report ID, report digest, origin, and label-policy ID; an unrelated
presentation MUST NOT authorize a report.

# Aggregation and Quality Labels {#aggregation}

Each report uses the Commitment-Bound Prio3Histogram variant: its private
one-hot bucket and private tag agree, and two aggregators verify that their
tag shares and commitment-blinding shares add to `C_report` (or to
`C_report + p*Ha` if the canonical Field128 tag shares carry, where `p` is
the field modulus). A proposed public DAP report extension carries the
canonical `C_report` in report metadata visible to BOTH aggregators. Each
HPKE-encrypted `PlaintextInputShare` carries the VDAF input share as its
payload and a proposed private extension carrying that aggregator's scalar
blinding share. The DAP `report_id` is the VDAF nonce; the task ID selects
the task in the DAP reports URL. No second report identifier is required.

The Client submits the ACT presentation, authenticated origin outcome receipt,
and exact encoded DAP `Report` in ONE proposed combined submission. The spend
proof's transcript binds the task, report ID, origin, label-policy version,
and a digest of that whole report, including `C_report` and BOTH HPKE
ciphertexts. The Moderator checks that the commitment in the ACT proof is
the one in the report's public extension, the origin's authenticated label,
the digest, and the credential and report replay rules. A digest identifies
the authorized report; it does NOT by itself prove that the encrypted bucket
matches the signed `j`. There is no separate client-visible report
authorization token or later client upload.

The Moderator is the DAP Leader and Collector. In an extended
`AggregationJobInitReq`, it forwards the Helper's encrypted `ReportShare`,
its Prio3 verifier share and its locally computed point `P_0`, plus an
authenticated assertion that the MOLE presentation for the exact task,
report ID, digest, and `C_report` was accepted. The Helper checks the
assertion, computes its point `P_1` from its OWN expanded VDAF tag share and
private blinding share, checks Prio3 and the commitment, and returns the
verifier message and `P_1` in the existing aggregation-job response. The
Leader completes the same checks. Neither side accumulates an output share
unless both checks succeed. This extends the EXISTING Prio3 one-request/
one-response exchange; it does not introduce a second round trip. The
combined transport, assertion, report extensions, point fields, and failure
and retry semantics require a DAP integration specification; ordinary DAP
does not implement them.

An origin, not the Client, supplies an authenticated quality label and
policy version. Counts are scoped by origin and label policy, never pooled
across origins with incompatible semantics. The first profile applies to
labels known at presentation. Delayed labels need a separate authenticated
outcome receipt and a subsequent credential-linked presentation; missing
reports MUST be accounted for explicitly rather than treated as positive.
Reports are unique per accepted outcome, and retries reuse the same bytes.

# Security Considerations {#security}

The Moderator sees randomized commitments and report IDs, not `j`. Reports
MUST use independent randomness to prevent linking. Small result cells and
report timing can reveal Anchor information; enforce minimum batch sizes and
release windows. The two aggregation services MUST execute validity and
commitment verification correctly for report integrity; one non-colluding
service is required for measurement privacy. A malicious service can forge
its commitment-check point or falsify an aggregate. This profile does not
offer verifiable collection against such a service. The Moderator and origin
can omit or selectively delay outcomes; neither report soundness nor a
valid histogram establishes unbiased reporting.
The two aggregators can distinguish the field-carry cases from the exchanged
points; constant-time comparisons alone do not hide that bit. Its privacy
effect requires analysis. The Helper relies on the Moderator's authenticated
acceptance assertion for the ACT proof, rather than independently verifying
that proof.

# IANA Considerations {#iana}

This experimental profile reserves no codepoints. Implementations MUST use
distinct local experimental protocol and VDAF identifiers until allocated.

--- back

# Acknowledgments
{:numbered="false"}

TODO.
