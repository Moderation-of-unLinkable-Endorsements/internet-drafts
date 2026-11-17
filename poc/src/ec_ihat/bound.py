"""Experimental same-Anchor proof for EC-IHAT redemption and a hidden tag.

This is a separate, linear-size OR proof; existing EC-IHAT v1 transcripts
and encodings are unchanged. Do not substitute this for ACT's issuance proof.
"""

from __future__ import annotations

from typing import NamedTuple, Sequence

from . import protocol as ihat
from .ciphersuite import P256Element as Element
from .ciphersuite import P256Scalar as Scalar
from .common import I2OSP, U16Prefixed, random

G = ihat.G
H = G.HashToGroup(b"MOLE-bound-anchor-tag-H-v1")
R = G.HashToGroup(b"MOLE-bound-anchor-tag-R-v1")


class BoundRedemption(NamedTuple):
    redemption: ihat.Redemption
    commitment: Element
    challenges: tuple[Scalar, ...]
    key_responses: tuple[Scalar, ...]
    tag_responses: tuple[Scalar, ...]


def transcript(
    anchor_set: Sequence[Element],
    redemption: ihat.Redemption,
    commitment: Element,
    challenge_digest: bytes,
    request_digest: bytes,
    first: Sequence[Element],
    second: Sequence[Element],
) -> bytes:
    """Domain-separated, unambiguous transcript of both branch equations."""
    if len(anchor_set) != len(first) or len(first) != len(second):
        raise ValueError("invalid branch count")
    data = I2OSP(len(anchor_set), 2)
    for key in anchor_set:
        data += G.SerializeElement(key)
    data += G.SerializeElement(redemption.X_hat)
    data += G.SerializeElement(commitment)
    for part in (redemption.shown.nf, challenge_digest, request_digest):
        data += U16Prefixed(part)
    for points in (first, second):
        for point in points:
            data += G.SerializeElement(point)
    return data + b"MOLE-BoundIssuerProof-v1"


def prove(
    anchor_set: Sequence[Element],
    index: int,
    endorsement: ihat.Endorsement,
    ctx_iss: bytes,
    ctx_red: bytes,
    challenge_digest: bytes,
    request_digest: bytes,
) -> tuple[BoundRedemption, Scalar]:
    """Redeem and prove that the hidden commitment names the same Anchor."""
    if not 0 <= index < len(anchor_set) or not anchor_set:
        raise ValueError("index is outside the Anchor Set")
    (delta, rho) = G.DeriveScalars(random(ihat.Nseed), b"BoundRedeem", 2)
    x_hat = anchor_set[index] + delta * ihat.B
    shown = ihat.Endorsement(
        endorsement.c,
        endorsement.s + endorsement.c * endorsement.y * delta,
        endorsement.y,
        endorsement.t,
        endorsement.nf,
    )
    seed = random(ihat.Nseed)
    proof = ihat.ProveIssuer(
        anchor_set, index, delta, x_hat, shown,
        ctx_iss, ctx_red, challenge_digest, seed,
    )
    redemption = ihat.Redemption(x_hat, shown, *proof)
    commitment = G.scalar(index + 1) * H + rho * R

    count = len(anchor_set)
    nonces = G.DeriveScalars(random(ihat.Nseed), b"BoundBranch", 2 * count)
    simulated = G.DeriveScalars(random(ihat.Nseed), b"BoundSimulated", 3 * count)
    challenges = [G.scalar(0) for _ in anchor_set]
    key_responses = [G.scalar(0) for _ in anchor_set]
    tag_responses = [G.scalar(0) for _ in anchor_set]
    first: list[Element] = []
    second: list[Element] = []
    for i, key in enumerate(anchor_set):
        if i == index:
            first.append(nonces[2 * i] * ihat.B)
            second.append(nonces[2 * i + 1] * R)
        else:
            c, z_key, z_tag = simulated[3 * i:3 * i + 3]
            challenges[i], key_responses[i], tag_responses[i] = c, z_key, z_tag
            first.append(z_key * ihat.B - c * (x_hat - key))
            second.append(z_tag * R - c * (commitment - G.scalar(i + 1) * H))

    total = G.HashToScalar(transcript(
        anchor_set, redemption, commitment, challenge_digest,
        request_digest, first, second,
    ))
    challenges[index] = total - sum(challenges, G.scalar(0))
    key_responses[index] = nonces[2 * index] + challenges[index] * delta
    tag_responses[index] = nonces[2 * index + 1] + challenges[index] * rho
    return BoundRedemption(
        redemption, commitment, tuple(challenges),
        tuple(key_responses), tuple(tag_responses),
    ), rho


def verify(
    anchor_set: Sequence[Element],
    bound: BoundRedemption,
    ctx_iss: bytes,
    ctx_red: bytes,
    challenge_digest: bytes,
    request_digest: bytes,
) -> bytes:
    """Reject a tag for a different Anchor before accepting the redemption."""
    ihat.VerifyRedemption(
        anchor_set, bound.redemption, ctx_iss, ctx_red, challenge_digest,
    )
    if not anchor_set or any(
        len(part) != len(anchor_set)
        for part in (bound.challenges, bound.key_responses, bound.tag_responses)
    ):
        raise ihat.VerifyError
    first = []
    second = []
    for i, key in enumerate(anchor_set):
        c = bound.challenges[i]
        first.append(
            bound.key_responses[i] * ihat.B - c * (bound.redemption.X_hat - key)
        )
        second.append(
            bound.tag_responses[i] * R - c * (bound.commitment - G.scalar(i + 1) * H)
        )
    expected = G.HashToScalar(transcript(
        anchor_set, bound.redemption, bound.commitment,
        challenge_digest, request_digest, first, second,
    ))
    if sum(bound.challenges, G.scalar(0)) != expected:
        raise ihat.VerifyError
    return bound.redemption.shown.nf
