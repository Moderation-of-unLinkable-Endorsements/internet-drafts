import pytest

from act import protocol as act
from ihat import protocol as ihat
from ihat.ciphersuite import DeriveError
from ihat import common


def test_act_context_and_generators():
    assert act.ctx_proto == b"ACTv1-P256-SHA256"
    assert act.G.SerializeElement(act.H1).hex() == (
        "03c16cd46e4807f2e52d460f03b5e8e11bffee91d9c8bd7e1225c384eaf39cd1ac"
    )
    assert (
        len(
            {
                act.G.SerializeElement(h)
                for h in (act.B, act.H1, act.H2, act.H3, act.H4)
            }
        )
        == 5
    )
    assert act.CreateContextScalar(b"epoch") != act.CreateContextScalar(
        b"epoch2"
    )
    assert [int(b) for b in act.Bits(129)] == [1, 0, 0, 0, 0, 0, 0, 1]


def test_shared_derivation_preserves_domain_separation(monkeypatch):
    seed = bytes(range(act.Nseed))
    skM, pkM = act.G.DeriveKeyPair(seed, b"GenerateKeyPair")
    assert pkM == act.G.ScalarMultGen(skM)
    assert skM != ihat.G.DeriveScalar(seed, b"GenerateKeyPair")
    monkeypatch.setattr(
        common.secrets, "token_bytes", lambda size: seed
    )
    assert act.G.GenerateKeyPair() == (skM, pkM)
    assert act.Seed(b"x" * act.Nseed + seed, 1) == seed
    for wrong in (b"", bytes(act.Nseed - 1), bytes(act.Nseed + 1)):
        with pytest.raises(
            ValueError, match="seed must be exactly 48 bytes"
        ):
            act.G.DeriveScalar(wrong, b"test")


def test_derivation_retries_zero_and_exhausts(monkeypatch):
    calls = []

    def hash_to_scalar(value, *, DST):
        calls.append((value, DST))
        return act.G.scalar(int(value[-1] == 2))

    monkeypatch.setattr(act.G, "HashToScalar", hash_to_scalar)
    assert act.G.DeriveScalar(
        bytes(act.Nseed), b"test"
    ) == act.G.scalar(1)
    assert [v[-1] for v, _ in calls] == [0, 1, 2]
    assert all(
        dst == b"DeriveScalar-ACTv1-P256-SHA256" for _, dst in calls
    )
    monkeypatch.setattr(
        act.G, "HashToScalar", lambda value, *, DST: act.G.scalar(0)
    )
    with pytest.raises(DeriveError):
        act.G.DeriveScalar(bytes(act.Nseed), b"test")
