import pytest

from act import protocol as act, wire
from ihat.protocol import VerifyError


@pytest.mark.parametrize(
    "s,a,t", [(3, 0, 0), (3, 0, 3), (0, 3, 3), (3, 3, 6), (0, 0, 0)]
)
def test_refund_can_be_spent(s, a, t):
    skM, pkM = act.G.GenerateKeyPair()
    issuance, request = act.IssueRequest()
    response = act.IssueResponse(skM, b"epoch", 10, request)
    credential = act.FinalizeIssue(pkM, b"epoch", issuance, response)
    state, proof = act.ProveSpend(credential, b"epoch", s, a, b"first")
    act.VerifySpend(skM, b"epoch", b"first", proof)
    refund = act.IssueRefund(skM, b"epoch", proof, t)
    encoded = wire.EncodeRefund(refund)
    assert len(encoded) == act.Ne + 3 * act.Ns + 8
    refund = wire.DecodeRefund(encoded)
    new = act.FinalizeRefund(pkM, b"epoch", state, proof, refund)
    assert new.c == 10 - s + t
    assert new.k != credential.k
    _, next_proof = act.ProveSpend(new, b"epoch", 1, 0, b"second")
    act.VerifySpend(skM, b"epoch", b"second", next_proof)
    with pytest.raises(act.AmountError):
        act.IssueRefund(skM, b"epoch", proof, s + a + 1)
    with pytest.raises(act.AmountError):
        act.IssueRefund(skM, b"epoch", proof, -1)
    with pytest.raises(VerifyError):
        act.FinalizeRefund(pkM, b"other epoch", state, proof, refund)
    with pytest.raises(VerifyError):
        act.FinalizeRefund(
            pkM,
            b"epoch",
            state._replace(K_n=state.K_n + act.H2),
            proof,
            refund,
        )
    if s + a > 0:
        other = t - 1 if t == s + a else t + 1
        with pytest.raises(VerifyError):
            act.FinalizeRefund(
                pkM, b"epoch", state, proof, refund._replace(t=other)
            )
