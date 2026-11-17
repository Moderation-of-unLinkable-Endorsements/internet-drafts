"""Issuer binding and ACT credential update preserve the private tag."""

import pytest

from ec_ihat import bound, protocol as ihat
from ec_act import feedback, protocol as act


def test_issuer_bound_issuance_and_refunds():
    keys = [ihat.G.DeriveKeyPair(bytes([i + 1]) * 48, b"anchor")[1] for i in range(3)]
    anchor_sk, _ = ihat.G.DeriveKeyPair(bytes([2]) * 48, b"anchor")
    moderator_sk, moderator_pk = act.G.DeriveKeyPair(bytes([4]) * 48, b"moderator")
    anchor_state, opening = ihat.Commit(b"epoch")
    grant_state, challenge = ihat.Challenge(keys[1], b"epoch", b"moderator", opening)
    endorsement = ihat.Finalize(keys[1], grant_state, ihat.Respond(anchor_sk, anchor_state, challenge))

    redemption, rho_issue = bound.prove(keys, 1, endorsement, b"epoch", b"moderator", b"challenge", b"request")
    assert bound.verify(keys, redemption, b"epoch", b"moderator", b"challenge", b"request") == endorsement.nf
    state, request = feedback.issue_request(2, rho_issue, redemption.commitment)
    credential = feedback.finalize_issue(moderator_pk, b"context", state,
                                         feedback.issue_response(moderator_sk, b"context", 8, request))
    for cost, allowance, return_amount in [(2, 0, 1), (0, 0, 0), (1, 1, 2)]:
        report_blind = act.G.scalar(100 + cost)
        pending, spend, rho = feedback.prove_spend(
            credential, b"context", cost, allowance, b"report digest", report_blind
        )
        assert rho == report_blind
        feedback.verify_spend(moderator_sk, b"context", b"report digest", spend)
        assert spend.C == credential.j * bound.H + rho * bound.R
        with pytest.raises(ihat.VerifyError):
            feedback.verify_spend(moderator_sk, b"context", b"other report", spend)
        with pytest.raises(ihat.VerifyError):
            feedback.verify_spend(moderator_sk, b"context", b"report digest",
                                  spend._replace(C=spend.C + bound.H))
        refund = feedback.issue_refund(moderator_sk, b"context", spend, return_amount)
        credential = feedback.finalize_refund(moderator_pk, b"context", pending, refund)
        assert int(credential.j) == 2
