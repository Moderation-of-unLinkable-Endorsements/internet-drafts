"""Experimental application-level binding of VDAF tag shares to ACT.

In one-round Prio3, the Leader sends its locally computed point with its
verifier share; the Helper returns its point with the verifier message.
Each uses its own untruncated, private tag share, and both must enforce
Prio3 validity and this check before accumulating an output share. This
module models group arithmetic, not DAP wire messages or constant-time code.
"""

from __future__ import annotations

from ec_ihat.ciphersuite import P256Element as Element
from ec_ihat.ciphersuite import P256Scalar as Scalar

from .feedback import G, H, R

# The modulus of the Field128 used by the commitment-bound Prio3 circuit.
FIELD128_MODULUS = 2**66 * 4611686018427387897 + 1


def split_blinding(rho: Scalar, mask: Scalar) -> tuple[Scalar, Scalar]:
    """Privately deliver one scalar to each aggregator for this report."""
    return mask, rho - mask


def tag_point(tag_share: int, blinding_share: Scalar) -> Element:
    """Encode only this aggregator's canonical field share as a group point."""
    if G.Order() <= 2 * FIELD128_MODULUS:
        raise ValueError("commitment group is too small for the VDAF field")
    if not 0 <= tag_share < FIELD128_MODULUS:
        raise ValueError("noncanonical tag share")
    return G.scalar(tag_share) * H + blinding_share * R


def matches_commitment(commitment: Element, left: Element, right: Element) -> bool:
    """Account for the carry; the two aggregators can observe which case holds."""
    point = left + right
    return point in (commitment, commitment + G.scalar(FIELD128_MODULUS) * H)
