import pytest

from ec_act import protocol as ec_act
from ec_ihat import protocol as ec_ihat
from ec_ihat.ciphersuite import DeriveError
from ec_ihat import common


def test_ec_act_context_and_generators():
    assert ec_act.ctx_proto == b"EC-ACTv1-P256-SHA256"
    assert ec_act.G.SerializeElement(ec_act.H1).hex() == (
        "021a3022391ada95c2e90ec5452609f54b6c72db02587405e64e23e1fb38e3a8dd"
    )
    assert (
        len(
            {
                ec_act.G.SerializeElement(h)
                for h in (ec_act.B, ec_act.H1, ec_act.H2, ec_act.H3, ec_act.H4)
            }
        )
        == 5
    )
    assert ec_act.CreateContextScalar(b"epoch") != ec_act.CreateContextScalar(
        b"epoch2"
    )
    weights = ec_act.RangeWeights(2**ec_act.L - 1)
    assert weights == [2**j for j in range(ec_act.L)]
    assert [int(b) for b in ec_act.Bits(129, weights)] == [1, 0, 0, 0, 0, 0, 0, 1]


@pytest.mark.parametrize("m", range(2**6))
def test_range_weights_cover_exactly_the_range(monkeypatch, m):
    monkeypatch.setattr(ec_act, "L", 6)
    weights = ec_act.RangeWeights(m)
    assert len(weights) == m.bit_length()
    assert all(w > 0 for w in weights)
    assert sum(weights) == m
    for x in range(m + 1):
        bits = [int(b) for b in ec_act.Bits(x, weights)]
        assert set(bits) <= {0, 1}
        assert sum(b * w for b, w in zip(bits, weights)) == x


def test_range_weights_reject_out_of_range_bounds():
    for m in (-1, 2**ec_act.L):
        with pytest.raises(ec_act.AmountError):
            ec_act.RangeWeights(m)


def test_shared_derivation_preserves_domain_separation(monkeypatch):
    seed = bytes(range(ec_act.Nseed))
    skM, pkM = ec_act.G.DeriveKeyPair(seed, b"GenerateKeyPair")
    assert pkM == ec_act.G.ScalarMultGen(skM)
    assert skM != ec_ihat.G.DeriveKeyPair(seed, b"GenerateKeyPair")[0]
    assert ec_act.G.DeriveScalars(seed, b"x", 1) != ec_ihat.G.DeriveScalars(
        seed, b"x", 1
    )
    monkeypatch.setattr(
        common.secrets, "token_bytes", lambda size: seed
    )
    assert ec_act.G.GenerateKeyPair() == (skM, pkM)
    assert ec_act.Seed(b"x" * ec_act.Nseed + seed, 1) == seed
    for wrong in (b"", bytes(ec_act.Nseed - 1), bytes(ec_act.Nseed + 1)):
        with pytest.raises(ValueError, match="exactly 48 bytes"):
            ec_act.G.DeriveScalars(wrong, b"test", 1)


def test_key_derivation_retries_zero_and_exhausts(monkeypatch):
    calls = []

    def hash_to_scalar(value, *, DST):
        calls.append((value, DST))
        return ec_act.G.scalar(int(value[-1] == 2))

    monkeypatch.setattr(ec_act.G, "HashToScalar", hash_to_scalar)
    skM, _ = ec_act.G.DeriveKeyPair(bytes(ec_act.Nseed), b"test")
    assert skM == ec_act.G.scalar(1)
    assert [v[-1] for v, _ in calls] == [0, 1, 2]
    assert all(
        dst == b"DeriveKeyPair-EC-ACTv1-P256-SHA256" for _, dst in calls
    )
    monkeypatch.setattr(
        ec_act.G, "HashToScalar", lambda value, *, DST: ec_act.G.scalar(0)
    )
    with pytest.raises(DeriveError):
        ec_act.G.DeriveKeyPair(bytes(ec_act.Nseed), b"test")
