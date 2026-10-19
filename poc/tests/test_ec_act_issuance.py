import pytest

from ec_act import protocol as ec_act, wire
from ec_ihat.ciphersuite import DeserializeError
from ec_ihat.protocol import VerifyError


def test_issuance_roundtrip_and_binding():
    skM, pkM = ec_act.G.GenerateKeyPair()
    state, request = ec_act.IssueRequest()
    encoded = wire.EncodeIssueRequest(request)
    assert len(encoded) == ec_act.Ne + 3 * ec_act.Ns
    request = wire.DecodeIssueRequest(encoded)
    response = ec_act.IssueResponse(skM, b"epoch", 10, request)
    encoded = wire.EncodeIssueResponse(response)
    assert len(encoded) == ec_act.Ne + 3 * ec_act.Ns + 8
    response = wire.DecodeIssueResponse(encoded)
    credential = ec_act.FinalizeIssue(pkM, b"epoch", state, response)
    assert credential.c == 10
    assert (
        wire.DecodeCredential(wire.EncodeCredential(credential))
        == credential
    )
    message = (
        ec_act.B
        + ec_act.G.scalar(10) * ec_act.H1
        + credential.k * ec_act.H2
        + credential.r * ec_act.H3
        + ec_act.CreateContextScalar(b"epoch") * ec_act.H4
    )
    assert (credential.e + skM) * credential.A == message
    other_pk = ec_act.G.ScalarMultGen(skM + ec_act.G.scalar(1))
    for pk, ctx, bad in (
        (pkM, b"other epoch", response),
        (other_pk, b"epoch", response),
        (pkM, b"epoch", response._replace(c=9)),
        (pkM, b"epoch", response._replace(pok=bytes(len(response.pok)))),
    ):
        with pytest.raises(VerifyError):
            ec_act.FinalizeIssue(pk, ctx, state, bad)
    with pytest.raises(VerifyError):
        ec_act.IssueResponse(skM, b"epoch", 10, request._replace(K=ec_act.H1))
    with pytest.raises(ec_act.AmountError):
        ec_act.IssueResponse(skM, b"epoch", 2**ec_act.L, request)
    with pytest.raises(DeserializeError):
        wire.DecodeIssueRequest(encoded[:-1])
    with pytest.raises(ec_act.AmountError):
        wire.DecodeIssueResponse(
            encoded[: ec_act.Ne + ec_act.Ns]
            + (2**ec_act.L).to_bytes(8, "big")
            + encoded[ec_act.Ne + ec_act.Ns + 8 :]
        )


def test_signing_exponent_is_hedged(monkeypatch):
    skM, _ = ec_act.G.GenerateKeyPair()
    monkeypatch.setattr(
        ec_act.common.secrets, "token_bytes", lambda size: bytes(size)
    )
    e = ec_act.SigningExponent(skM, b"IssueResponse", ec_act.H1)
    assert e == ec_act.SigningExponent(skM, b"IssueResponse", ec_act.H1)
    assert e != ec_act.SigningExponent(skM, b"Refund", ec_act.H1)
    assert e != ec_act.SigningExponent(skM, b"IssueResponse", ec_act.H2)
    assert e != ec_act.SigningExponent(
        skM + ec_act.G.scalar(1), b"IssueResponse", ec_act.H1
    )
