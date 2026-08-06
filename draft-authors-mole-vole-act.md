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
    date: 2026
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
  ACT: I-D.draft-schlesinger-cfrg-act-01

  POMFRIT:
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

This document specifies Ratatouille, a candidate post-quantum variant of the
Anonymous Credit Token (ACT) protocol. Ratatouille is based on the UOV digital
signature scheme and the VOLE-in-the-Head proof system (a component of the
FAEST signature scheme). The moderator issues a token by signing a commitment
to the client's state; to present a token, the client proves knowledge of this
signature and the opening of the commitment. Two variants of the protocol are
specified, one in which the commitment is instantiated with Keccak-p[800,12]
and another in which a UOV-friendly commitment scheme is used instead.

--- middle

# Introduction

> TODO(tnyuzg)

# Conventions and Definitions

{::boilerplate bcp14-tagged}

> TODO(tnyuzg)

# Protocol Specification

> TODO(tnyuzg)

# Security Considerations

> TODO

# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

The use of Keccak-p[800,12] in this application was proposed by Bas Westerbaan.
