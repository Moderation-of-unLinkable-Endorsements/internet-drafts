import pytest

from act import protocol as act, wire
from ihat.ciphersuite import DeserializeError
from ihat.protocol import VerifyError


def test_issuance_roundtrip_and_binding():
    skM, pkM = act.G.GenerateKeyPair()
    state, request = act.IssueRequest()
    encoded = wire.EncodeIssueRequest(request)
    assert len(encoded) == act.Ne + 3 * act.Ns
    request = wire.DecodeIssueRequest(encoded)
    response = act.IssueResponse(skM, b"epoch", 10, request)
    encoded = wire.EncodeIssueResponse(response)
    assert len(encoded) == act.Ne + 3 * act.Ns + 8
    response = wire.DecodeIssueResponse(encoded)
    credential = act.FinalizeIssue(pkM, b"epoch", state, response)
    assert credential.c == 10
    assert (
        wire.DecodeCredential(wire.EncodeCredential(credential))
        == credential
    )
    message = (
        act.B
        + act.G.scalar(10) * act.H1
        + credential.k * act.H2
        + credential.r * act.H3
        + act.CreateContextScalar(b"epoch") * act.H4
    )
    assert (credential.e + skM) * credential.A == message
    other_pk = act.G.ScalarMultGen(skM + act.G.scalar(1))
    for pk, ctx, bad in (
        (pkM, b"other epoch", response),
        (other_pk, b"epoch", response),
        (pkM, b"epoch", response._replace(c=9)),
        (pkM, b"epoch", response._replace(pok=bytes(len(response.pok)))),
    ):
        with pytest.raises(VerifyError):
            act.FinalizeIssue(pk, ctx, state, bad)
    with pytest.raises(VerifyError):
        act.IssueResponse(skM, b"epoch", 10, request._replace(K=act.H1))
    with pytest.raises(act.AmountError):
        act.IssueResponse(skM, b"epoch", 2**act.L, request)
    with pytest.raises(DeserializeError):
        wire.DecodeIssueRequest(encoded[:-1])
    with pytest.raises(act.AmountError):
        wire.DecodeIssueResponse(
            encoded[: act.Ne + act.Ns]
            + (2**act.L).to_bytes(8, "big")
            + encoded[act.Ne + act.Ns + 8 :]
        )


def test_signing_exponent_is_hedged(monkeypatch):
    skM, _ = act.G.GenerateKeyPair()
    monkeypatch.setattr(
        act.common.secrets, "token_bytes", lambda size: bytes(size)
    )
    e = act.SigningExponent(skM, b"IssueResponse", act.H1)
    assert e == act.SigningExponent(skM, b"IssueResponse", act.H1)
    assert e != act.SigningExponent(skM, b"Refund", act.H1)
    assert e != act.SigningExponent(skM, b"IssueResponse", act.H2)
    assert e != act.SigningExponent(
        skM + act.G.scalar(1), b"IssueResponse", act.H1
    )
