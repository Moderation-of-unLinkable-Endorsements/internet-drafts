import json
from pathlib import Path

import pytest

from rollatini.ciphersuite import (
    DeserializeError,
    FIELD_MODULUS,
    ORDER,
    P256Group,
    P256Scalar as Scalar,
    expand_message_xmd,
)


VECTOR_DIR = Path(__file__).parent / "vectors"


@pytest.mark.parametrize(
    "vector_path",
    sorted(VECTOR_DIR.glob("expand_message_xmd_SHA256_*.json")),
    ids=lambda path: path.stem,
)
def test_expand_message_xmd_vectors(vector_path: Path):
    vectors = json.loads(vector_path.read_bytes())

    assert vectors["hash"] == "SHA256"
    assert vectors["name"] == "expand_message_xmd"
    dst = vectors["DST"].encode("ascii")
    for test in vectors["tests"]:
        assert expand_message_xmd(
            test["msg"].encode("ascii"), dst, int(test["len_in_bytes"], 16)
        ) == bytes.fromhex(test["uniform_bytes"])


def test_rfc9380_p256_hash_to_curve_vectors():
    vectors = json.loads(
        (VECTOR_DIR / "P256_XMD_SHA-256_SSWU_RO.json").read_bytes()
    )

    assert vectors["ciphersuite"] == "P256_XMD:SHA-256_SSWU_RO_"
    assert vectors["randomOracle"] is True
    group = P256Group(b"unused-by-explicit-DST")
    dst = vectors["dst"].encode("ascii")
    for test in vectors["vectors"]:
        point = group.HashToGroup(test["msg"].encode("ascii"), DST=dst)
        assert int(point._point.x) == int(test["P"]["x"], 16)
        assert int(point._point.y) == int(test["P"]["y"], 16)


def test_element_and_scalar_round_trips():
    group = P256Group(b"test")
    element = group.ScalarMultGen(Scalar(42))
    assert group.DeserializeElement(group.SerializeElement(element)) == element
    assert group.DeserializeScalar(group.SerializeScalar(Scalar(42))) == Scalar(42)


def test_noncanonical_values_are_rejected():
    group = P256Group(b"test")
    with pytest.raises(DeserializeError):
        group.DeserializeElement(bytes(33))
    with pytest.raises(DeserializeError, match="x-coordinate is out of range"):
        group.DeserializeElement(b"\x02" + FIELD_MODULUS.to_bytes(32, "big"))
    with pytest.raises(DeserializeError):
        group.DeserializeScalar(ORDER.to_bytes(32, "big"))


def test_scalar_rejects_values_outside_the_group_order():
    assert Scalar(0).value == 0
    assert Scalar(ORDER - 1).value == ORDER - 1
    with pytest.raises(ValueError):
        Scalar(-1)
    with pytest.raises(ValueError):
        Scalar(ORDER)

def test_scalar_equality():
    assert Scalar(42) == Scalar(42)
    assert Scalar(42) != Scalar(43)


def test_scalar_is_zero():
    assert Scalar(0).isZero()
    assert not Scalar(1).isZero()

def test_scalar_arithmetic_reduces_modulo_order():
    sum_result = Scalar(ORDER - 1) + Scalar(2)
    difference_result = Scalar(1) - Scalar(2)
    product_result = Scalar(ORDER - 1) * Scalar(2)

    assert sum_result == Scalar(1)
    assert difference_result == Scalar(ORDER - 1)
    assert product_result == Scalar(ORDER - 2)

def test_p_not_identity():
    group = P256Group(b"test")
    for i in range(1, 100):
        elt = group.HashToGroup(f"test iteration {i}".encode("ascii"),  DST=b"separation")
        elt2 = group.P(elt)
        res = elt - elt2
        assert not res.isIdentity()

def test_p_invertable():
    group = P256Group(b"test")
    for i in range(1, 100):
        elt1 = group.HashToGroup(f"test iteration {i}".encode("ascii"),  DST=b"separation")
        elt2 = group.P(elt1)
        elt3 = group.Pinv(elt2)
        res = elt1 - elt3
        assert res.isIdentity()

def test_p_not_involution():
    group = P256Group(b"test")
    for i in range(1, 100):
        elt1 = group.HashToGroup(f"test iteration {i}".encode("ascii"),  DST=b"separation")
        elt2 = group.P(elt1)
        elt3 = group.P(elt2)
        res = elt1 - elt3
        assert not res.isIdentity()


def test_permute_bytes_is_a_permutation():
    from rollatini.ciphersuite import PermuteBytes, UnpermuteBytes

    for i in range(32):
        buf = bytearray([i & 1]) + bytearray(range(i, i + 32))
        out = PermuteBytes(buf)
        assert len(out) == 33 and out[0] in (0, 1)
        assert UnpermuteBytes(out) == buf


def test_derive_nonces_binds_every_input():
    from rollatini import common

    G = P256Group(b"test")
    aux = bytes(common.Nseed)
    (nonce,) = G.DeriveNonces(b"secret", b"label", b"instance", aux, 1)
    assert not nonce.isZero()
    assert [nonce] == G.DeriveNonces(b"secret", b"label", b"instance", aux, 1)
    for other in (
        G.DeriveNonces(b"secret!", b"label", b"instance", aux, 1),
        G.DeriveNonces(b"secret", b"label!", b"instance", aux, 1),
        G.DeriveNonces(b"secret", b"label", b"instance!", aux, 1),
        G.DeriveNonces(b"secret", b"label", b"instance", b"\1" + aux[1:], 1),
        P256Group(b"other").DeriveNonces(
            b"secret", b"label", b"instance", aux, 1
        ),
    ):
        assert other != [nonce]
    for wrong in (b"", aux[1:], aux + b"\0"):
        with pytest.raises(ValueError, match="exactly 48"):
            G.DeriveNonces(b"secret", b"label", b"instance", wrong, 1)
        with pytest.raises(ValueError, match="exactly 48"):
            G.DeriveScalars(wrong, b"info", 1)


def test_derivation_hashes_then_expands():
    from rollatini import common
    from rollatini.common import I2OSP, U16Prefixed

    G = P256Group(b"test")
    rand = bytes(range(common.Nseed))

    def expand(seed, count):
        return [
            G.HashToScalar(
                seed + I2OSP(i, 4), DST=b"ExpandScalars-" + G.ctx_proto
            )
            for i in range(count)
        ]

    seed = expand_message_xmd(
        rand + U16Prefixed(b"info"), b"DeriveScalars-" + G.ctx_proto, 32
    )
    assert G.DeriveScalars(rand, b"info", 5) == expand(seed, 5)

    # The random bytes fill the first block after the hash's zero block,
    # and the secret starts a block of its own.
    secret = bytes(range(100, 134))
    derive_nonce_input = (
        rand + bytes(16)
        + I2OSP(len(secret), 4) + secret + bytes(26)
        + U16Prefixed(b"label") + I2OSP(8, 4) + b"instance"
    )
    seed = expand_message_xmd(
        derive_nonce_input, b"DeriveNonces-" + G.ctx_proto, 32
    )
    assert G.DeriveNonces(secret, b"label", b"instance", rand, 3) == expand(
        seed, 3
    )


def test_a_zero_scalar_raises(monkeypatch):
    from rollatini import common
    from rollatini.ciphersuite import DeriveError

    G = P256Group(b"test")
    monkeypatch.setattr(G, "HashToScalar", lambda *_, **__: Scalar(0))
    with pytest.raises(DeriveError):
        G.DeriveScalars(bytes(common.Nseed), b"info", 1)


def test_related_randomness_gives_unrelated_nonces():
    # Nonces for one operation whose randomness differs in a single bit
    # must not differ by a known amount, or two proofs reveal the witness.
    from rollatini import common

    G = P256Group(b"test")
    aux = bytes(range(common.Nseed))
    (nonce,) = G.DeriveNonces(b"secret", b"label", b"instance", aux, 1)
    for position in range(common.Nseed):
        for bit in (0, 7):
            related = bytearray(aux)
            related[position] ^= 1 << bit
            (other,) = G.DeriveNonces(
                b"secret", b"label", b"instance", bytes(related), 1
            )
            difference = int(nonce - other)
            assert min(difference, ORDER - difference) > 2**200


def test_partial_repetition_changes_every_nonce():
    # A random source that repeats all but one byte of an operation's
    # randomness must not repeat any of its nonces.
    from rollatini import common

    G = P256Group(b"test")
    rand = bytes((3 * i) % 256 for i in range(common.Nseed))
    nonces = G.DeriveNonces(b"secret", b"label", b"instance", rand, 5)
    for position in range(0, common.Nseed, 7):
        changed = bytearray(rand)
        changed[position] ^= 1
        others = G.DeriveNonces(
            b"secret", b"label", b"instance", bytes(changed), 5
        )
        for nonce, other in zip(nonces, others, strict=True):
            difference = int(nonce - other)
            assert min(difference, ORDER - difference) > 2**200
