import pytest

from act import protocol as act, wire
from rollatini.ciphersuite import DeserializeError
from rollatini.protocol import VerifyError


def issued(balance=10):
    skM, pkM = act.G.GenerateKeyPair()
    state, request = act.IssueRequest()
    response = act.IssueResponse(skM, b"epoch", balance, request)
    return skM, pkM, act.FinalizeIssue(pkM, b"epoch", state, response)


def spend_length(s, a):
    elements = 3 + (wire.SpendCommitmentCount(s, a) if s + a else 1)
    return (
        act.Ns
        + 16
        + elements * act.Ne
        + (wire.SpendWitnessCount(s, a) + 1) * act.Ns
    )


@pytest.mark.parametrize(
    "s,a",
    [(3, 0), (0, 3), (3, 3), (0, 0), (2**7, 0), (100, 30)],
)
def test_all_spend_shapes(s, a):
    skM, _, credential = issued(2**7 + 3)
    _, proof = act.ProveSpend(credential, b"epoch", s, a, b"challenge")
    encoded = wire.EncodeSpend(proof)
    assert len(encoded) == spend_length(s, a)
    if s + a:
        assert len(encoded) == 129 * len(proof.Com1) + 403
    else:
        assert len(encoded) == 468
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


def test_spend_shape_must_match_amounts():
    skM, _, credential = issued()
    _, proof = act.ProveSpend(credential, b"epoch", 3, 0, b"challenge")
    for bad in (
        proof._replace(Com1=list(proof.Com1)[:-1]),
        proof._replace(Com1=[*proof.Com1, act.H1]),
        proof._replace(s=4),
        proof._replace(a=1),
        proof._replace(s=0, Com1=[]),
        proof._replace(Com_c=act.H1),
        proof._replace(s=0, Com1=[], Com_c=act.H1 + act.H3),
    ):
        with pytest.raises(VerifyError):
            act.VerifySpend(skM, b"epoch", b"challenge", bad)


def test_spend_and_top_up_to_the_largest_balance():
    # s + a = 2^L - 1 leaves no room for the remainder: m = 0, no bits.
    skM, pkM, credential = issued(10)
    a = 2**act.L - 11
    state, proof = act.ProveSpend(credential, b"epoch", 10, a, b"challenge")
    assert proof.Com1 == []
    proof = wire.DecodeSpend(wire.EncodeSpend(proof))
    act.VerifySpend(skM, b"epoch", b"challenge", proof)
    refund = act.IssueRefund(skM, b"epoch", proof, 10 + a)
    credential = act.FinalizeRefund(pkM, b"epoch", state, refund)
    assert credential.c == 2**act.L - 1


def test_top_up_from_zero_to_the_largest_balance():
    # s = 0 and m = 0: the sum equation has no bits and no s * H1 term.
    skM, pkM, credential = issued(0)
    a = 2**act.L - 1
    state, proof = act.ProveSpend(credential, b"epoch", 0, a, b"challenge")
    act.VerifySpend(skM, b"epoch", b"challenge", proof)
    refund = act.IssueRefund(skM, b"epoch", proof, a)
    credential = act.FinalizeRefund(pkM, b"epoch", state, refund)
    assert credential.c == a


def test_amounts_summing_past_the_range_are_rejected():
    skM, _, credential = issued(10)
    _, proof = act.ProveSpend(credential, b"epoch", 3, 0, b"challenge")
    bad = proof._replace(a=2**act.L - 3)
    with pytest.raises(act.AmountError):
        act.VerifySpend(skM, b"epoch", b"challenge", bad)
    with pytest.raises(act.AmountError):
        wire.EncodeSpend(bad)
    encoded = bytearray(wire.EncodeSpend(proof))
    encoded[act.Ns + 8 : act.Ns + 16] = (2**act.L - 3).to_bytes(8, "big")
    with pytest.raises(act.AmountError):
        wire.DecodeSpend(bytes(encoded))
