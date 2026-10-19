import pytest

from ec_act import protocol as ec_act, wire
from ec_ihat.protocol import VerifyError


@pytest.mark.parametrize(
    "s,a,t", [(3, 0, 0), (3, 0, 3), (0, 3, 3), (3, 3, 6), (0, 0, 0)]
)
def test_refund_can_be_spent(s, a, t):
    skM, pkM = ec_act.G.GenerateKeyPair()
    issuance, request = ec_act.IssueRequest()
    response = ec_act.IssueResponse(skM, b"epoch", 10, request)
    credential = ec_act.FinalizeIssue(pkM, b"epoch", issuance, response)
    state, proof = ec_act.ProveSpend(credential, b"epoch", s, a, b"first")
    assert state.K_prime == ec_act.BalanceCommitment(proof)
    ec_act.VerifySpend(skM, b"epoch", b"first", proof)
    refund = ec_act.IssueRefund(skM, b"epoch", proof, t)
    encoded = wire.EncodeRefund(refund)
    assert len(encoded) == ec_act.Ne + 3 * ec_act.Ns + 8
    refund = wire.DecodeRefund(encoded)
    new = ec_act.FinalizeRefund(pkM, b"epoch", state, refund)
    assert new.c == 10 - s + t
    assert new.k != credential.k
    _, next_proof = ec_act.ProveSpend(new, b"epoch", 1, 0, b"second")
    ec_act.VerifySpend(skM, b"epoch", b"second", next_proof)
    with pytest.raises(ec_act.AmountError):
        ec_act.IssueRefund(skM, b"epoch", proof, s + a + 1)
    with pytest.raises(ec_act.AmountError):
        ec_act.IssueRefund(skM, b"epoch", proof, -1)
    with pytest.raises(VerifyError):
        ec_act.FinalizeRefund(pkM, b"other epoch", state, refund)
    with pytest.raises(VerifyError):
        ec_act.FinalizeRefund(
            pkM,
            b"epoch",
            state._replace(K_prime=state.K_prime + ec_act.H2),
            refund,
        )
    if s + a > 0:
        other = t - 1 if t == s + a else t + 1
        with pytest.raises(VerifyError):
            ec_act.FinalizeRefund(
                pkM, b"epoch", state, refund._replace(t=other)
            )
