"""Exercise an endorsement, ACT presentation, and two-party VDAF report."""

import hashlib
import secrets

import pytest

from ec_act import feedback, protocol as act
from ec_act.quality import matches_commitment, split_blinding, tag_point
from ec_ihat import bound, protocol as ihat


def test_endorsed_anchor_is_the_reported_histogram_bucket():
    """Verify the complete reference path through a single quality report."""
    module = pytest.importorskip("vdaf_poc.vdaf_prio3_commitment_bound")
    vdaf = module.Prio3CommitmentBoundHistogram(3, 2)
    keys = [ihat.G.DeriveKeyPair(bytes([i + 1]) * 48, b"anchor")[1] for i in range(3)]
    anchor_sk, _ = ihat.G.DeriveKeyPair(bytes([2]) * 48, b"anchor")
    moderator_sk, moderator_pk = act.G.DeriveKeyPair(bytes([4]) * 48, b"moderator")
    anchor_state, opening = ihat.Commit(b"epoch")
    grant_state, challenge = ihat.Challenge(keys[1], b"epoch", b"moderator", opening)
    endorsement = ihat.Finalize(
        keys[1], grant_state, ihat.Respond(anchor_sk, anchor_state, challenge)
    )

    redemption, rho_issue = bound.prove(
        keys, 1, endorsement, b"epoch", b"moderator", b"challenge", b"request"
    )
    bound.verify(keys, redemption, b"epoch", b"moderator", b"challenge", b"request")
    issue_state, request = feedback.issue_request(2, rho_issue, redemption.commitment)
    credential = feedback.finalize_issue(
        moderator_pk, b"credential task", issue_state,
        feedback.issue_response(moderator_sk, b"credential task", 3, request),
    )

    context = b"quality/origin.example/label-policy-1"
    nonce = secrets.token_bytes(vdaf.NONCE_SIZE)
    public_share, input_shares = vdaf.shard(
        context, 1, nonce, secrets.token_bytes(vdaf.RAND_SIZE)
    )
    blind = act.G.DeriveScalars(secrets.token_bytes(48), b"report blind", 1)[0]
    commitment = credential.j * bound.H + blind * bound.R
    blind_shares = split_blinding(
        blind, act.G.DeriveScalars(secrets.token_bytes(48), b"share blind", 1)[0]
    )
    report_digest = hashlib.sha256(
        context + nonce + act.G.SerializeElement(commitment)
        + vdaf.encode_public_share(public_share)
        + b"".join(vdaf.encode_input_share(share) for share in input_shares)
    ).digest()
    _, spend, opening = feedback.prove_spend(
        credential, b"credential task", 1, 0, report_digest, blind
    )
    feedback.verify_spend(moderator_sk, b"credential task", report_digest, spend)
    assert spend.C == commitment and opening == blind

    verify_key = secrets.token_bytes(vdaf.VERIFY_KEY_SIZE)
    leader_input = vdaf.decode_input_share(0, vdaf.encode_input_share(input_shares[0]))
    helper_input = vdaf.decode_input_share(1, vdaf.encode_input_share(input_shares[1]))

    # Existing one-round Prio3 request: the Leader sends its verifier share
    # together with a point computed from the SAME input share.
    leader_point = tag_point(vdaf.tag_share(context, 0, leader_input), blind_shares[0])
    leader_state, leader_verifier_share = vdaf.verify_init(
        verify_key, context, 0, None, nonce, public_share, leader_input
    )

    # The Helper relies on the already verified MOLE presentation, expands its
    # actual input share, and checks both bindings before forming the response.
    helper_point = tag_point(vdaf.tag_share(context, 1, helper_input), blind_shares[1])
    helper_state, helper_verifier_share = vdaf.verify_init(
        verify_key, context, 1, None, nonce, public_share, helper_input
    )
    message = vdaf.verifier_shares_to_message(
        context, None, [leader_verifier_share, helper_verifier_share]
    )
    assert matches_commitment(commitment, leader_point, helper_point)
    assert not matches_commitment(commitment + bound.H, leader_point, helper_point)
    helper_output = vdaf.verify_next(context, helper_state, message)

    # Existing Prio3 response: the Helper returns the verifier message and
    # its point. The Leader checks both before accepting its output share.
    assert not matches_commitment(commitment, leader_point, helper_point + bound.H)
    assert matches_commitment(commitment, leader_point, helper_point)
    leader_output = vdaf.verify_next(context, leader_state, message)
    output_shares = [leader_output, helper_output]
    assert vdaf.unshard(None, output_shares, 1) == [0, 1, 0]
