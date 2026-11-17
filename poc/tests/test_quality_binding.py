"""Reference tests for the P-256 commitment check and the Prio3 shares."""

import secrets

import pytest

from ec_act.feedback import G, H, R
from ec_act.quality import FIELD128_MODULUS, matches_commitment, split_blinding, tag_point


def test_tag_point_binds_private_shares_to_commitment():
    """Check no carry, field carry, and mismatched tag values."""
    rho = G.scalar(89)
    left_blind, right_blind = split_blinding(rho, G.scalar(19))
    commitment = G.scalar(2) * H + rho * R

    for left in (0, 1, FIELD128_MODULUS - 1):
        right = (2 - left) % FIELD128_MODULUS
        assert matches_commitment(
            commitment, tag_point(left, left_blind), tag_point(right, right_blind)
        )

    assert not matches_commitment(
        commitment, tag_point(FIELD128_MODULUS - 1, left_blind), tag_point(2, right_blind)
    )


def test_real_prio3_input_shares_match_only_the_authorized_commitment():
    """Run with the VDAF reference poc on PYTHONPATH to exercise both repos."""
    module = pytest.importorskip("vdaf_poc.vdaf_prio3_commitment_bound")
    vdaf = module.Prio3CommitmentBoundHistogram(3, 2)
    ctx = b"origin.example/quality/v1"
    nonce = secrets.token_bytes(vdaf.NONCE_SIZE)
    _, input_shares = vdaf.shard(ctx, 1, nonce, secrets.token_bytes(vdaf.RAND_SIZE))
    tag_shares = [vdaf.tag_share(ctx, i, share) for i, share in enumerate(input_shares)]
    rho = G.scalar(2025)
    blind_shares = split_blinding(rho, G.scalar(42))
    points = [tag_point(tag, blind) for tag, blind in zip(tag_shares, blind_shares)]
    assert matches_commitment(G.scalar(2) * H + rho * R, *points)
    assert not matches_commitment(G.scalar(3) * H + rho * R, *points)
