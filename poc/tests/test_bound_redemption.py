"""The new issuer proof must use the same hidden branch for key and tag."""

import pytest

from ec_ihat import bound, protocol as ihat


def test_joint_anchor_proof():
    ctx_iss, ctx_red, challenge = b"epoch", b"moderator", b"challenge"
    keys = [ihat.G.DeriveKeyPair(bytes([i + 1]) * 48, b"anchor")[1] for i in range(3)]
    sk, _ = ihat.G.DeriveKeyPair(bytes([2]) * 48, b"anchor")
    anchor_state, opening = ihat.Commit(ctx_iss)
    state, challenge_scalar = ihat.Challenge(keys[1], ctx_iss, ctx_red, opening)
    endorsement = ihat.Finalize(keys[1], state, ihat.Respond(sk, anchor_state, challenge_scalar))

    proof, rho = bound.prove(keys, 1, endorsement, ctx_iss, ctx_red, challenge, b"act-request")
    assert bound.verify(keys, proof, ctx_iss, ctx_red, challenge, b"act-request") == endorsement.nf
    assert proof.commitment == ihat.G.scalar(2) * bound.H + rho * bound.R

    with pytest.raises(ihat.VerifyError):
        bound.verify(keys, proof, ctx_iss, ctx_red, challenge, b"other-request")
    with pytest.raises(ihat.VerifyError):
        bound.verify(keys, proof._replace(commitment=ihat.G.scalar(3) * bound.H + rho * bound.R),
                     ctx_iss, ctx_red, challenge, b"act-request")
