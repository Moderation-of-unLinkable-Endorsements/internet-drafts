import pytest

from act import protocol as act, wire
from ihat.ciphersuite import DeserializeError
from ihat.protocol import VerifyError


def issued(balance=10):
    skM, pkM = act.G.GenerateKeyPair()
    state, request = act.IssueRequest()
    response = act.IssueResponse(skM, b"epoch", balance, request)
    return skM, pkM, act.FinalizeIssue(pkM, b"epoch", state, response)


def spend_length(s, a):
    elements = 3 + (act.L if s > 0 else 1) + (act.L if a > 0 else 0)
    return (
        act.Ns
        + 16
        + elements * act.Ne
        + (wire.SpendWitnessCount(s, a) + 1) * act.Ns
    )


@pytest.mark.parametrize("s,a", [(3, 0), (0, 3), (3, 3), (0, 0)])
def test_all_spend_shapes(s, a):
    skM, _, credential = issued()
    _, proof = act.ProveSpend(credential, b"epoch", s, a, b"challenge")
    encoded = wire.EncodeSpend(proof)
    assert len(encoded) == spend_length(s, a)
    proof = wire.DecodeSpend(encoded)
    act.VerifySpend(skM, b"epoch", b"challenge", proof)
    for bad_key, ctx, ctx_spend, bad in (
        (skM, b"epoch", b"other challenge", proof),
        (skM, b"other epoch", b"challenge", proof),
        (skM + act.G.scalar(1), b"epoch", b"challenge", proof),
        (
            skM,
            b"epoch",
            b"challenge",
            proof._replace(K_n=proof.K_n + act.H1),
        ),
        (
            skM,
            b"epoch",
            b"challenge",
            proof._replace(k=proof.k + act.G.scalar(1)),
        ),
    ):
        with pytest.raises(VerifyError):
            act.VerifySpend(bad_key, ctx, ctx_spend, bad)
    with pytest.raises(act.AmountError):
        act.VerifySpend(
            skM, b"epoch", b"challenge", proof._replace(s=2**act.L)
        )
    with pytest.raises(DeserializeError):
        wire.DecodeSpend(encoded + b"\0")


def test_amount_bounds_are_enforced_by_the_prover():
    _, _, credential = issued(10)
    for s, a in ((11, 0), (0, 2**act.L - 10), (2**act.L, 0), (0, 2**act.L)):
        with pytest.raises(act.AmountError):
            act.ProveSpend(credential, b"epoch", s, a, b"challenge")


def test_nonbinary_bit_openings_are_rejected(monkeypatch):
    # A range proof over a single "bit" equal to 2 must not verify.
    monkeypatch.setattr(act, "L", 1)
    from act import sigma

    for value, valid in ((0, True), (1, True), (2, False)):
        b = act.G.scalar(value)
        blinding = act.G.scalar(13)
        commitment = b * act.H1 + blinding * act.H3
        statement = sigma.Statement(act.G)
        statement.elements(H1=act.H1, H3=act.H3, C=commitment)
        statement.witness("b", "s", "u")
        statement.equation("C = b * H1 + s * H3")
        statement.equation("C = b * C + u * H3")
        relation = statement.compile()
        witness = [b, blinding, (act.G.scalar(1) - b) * blinding]
        tag = act.Tag(b"test", [])
        proof = act.Prove(tag, relation, witness)
        assert act.Verify(tag, relation, proof) is valid
