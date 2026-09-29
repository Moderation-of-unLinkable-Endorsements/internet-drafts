"""Functional schedules and compatibility, not Python timing guarantees."""

import pytest

import rollatini.ciphersuite as suite
from rollatini.ciphersuite import (
    DeserializeError,
    FIELD_MODULUS,
    IsValidPermutationEncoding,
    P256Group,
    SelectBytes,
)


def test_select_bytes():
    left = bytearray(range(256))
    right = bytearray(reversed(range(256)))
    assert SelectBytes(left, right, False) == left
    assert SelectBytes(left, right, True) == right
    assert left == bytearray(range(256))
    assert right == bytearray(reversed(range(256)))
    with pytest.raises(ValueError):
        SelectBytes(left, right[:-1], False)


def test_permutation_encoding_validity_matches_sec1_decoder():
    group = P256Group(b"test")
    results = set()
    for prefix in (0, 1):
        for x in [*range(128), FIELD_MODULUS - 1, FIELD_MODULUS, 2**256 - 1]:
            coordinate = x.to_bytes(32, "big")
            try:
                group.DeserializeElement(bytes([prefix + 2]) + coordinate)
                expected = True
            except DeserializeError:
                expected = False
            buf = bytearray([prefix]) + coordinate
            assert IsValidPermutationEncoding(buf) == expected
            results.add(expected)
    assert results == {False, True}
    for invalid in (
        bytearray(), bytearray(32), bytearray(34), bytearray([2]) + bytearray(32)
    ):
        assert not IsValidPermutationEncoding(invalid)


def test_permutation_pair_has_same_schedule_for_both_orientations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    group = P256Group(b"test")
    events: list[str] = []
    forward = suite.PermuteBytes
    backward = suite.UnpermuteBytes
    select = suite.SelectBytes
    valid = suite.IsValidPermutationEncoding
    decode = group.DeserializeElement

    def record_forward(buf):
        events.append("forward")
        return forward(buf)

    def record_backward(buf):
        events.append("backward")
        return backward(buf)

    def record_select(left, right, choose_right):
        events.append("select")
        return select(left, right, choose_right)

    def record_valid(buf):
        result = valid(buf)
        events.append(f"valid:{int(result)}")
        return result

    def record_decode(buf):
        events.append("decode:" + buf.hex())
        return decode(buf)

    monkeypatch.setattr(suite, "PermuteBytes", record_forward)
    monkeypatch.setattr(suite, "UnpermuteBytes", record_backward)
    monkeypatch.setattr(suite, "SelectBytes", record_select)
    monkeypatch.setattr(suite, "IsValidPermutationEncoding", record_valid)
    monkeypatch.setattr(group, "DeserializeElement", record_decode)

    lengths = set()
    for sample in range(1, 33):
        Q = group.ScalarMultGen(group.scalar(sample))
        PQ = group.P(Q)
        events.clear()
        assert group.PermutationPair(Q, False) == (Q, PQ)
        right_events = events.copy()
        events.clear()
        assert group.PermutationPair(PQ, True) == (Q, PQ)
        assert events == right_events

        steps = events.count("forward")
        lengths.add(steps)
        assert events == (
            ["forward", "backward", "select", "valid:0"] * (steps - 1)
            + ["forward", "backward", "select", "valid:1", "select", "select"]
            + [
                "decode:" + group.SerializeElement(point).hex()
                for point in (Q, PQ)
            ]
        )
    assert 1 in lengths and max(lengths) > 1


@pytest.mark.parametrize("bind_left", [False, True])
def test_permutation_pair_handles_fixed_points(monkeypatch, bind_left):
    group = P256Group(b"test")
    calls = []

    def forward(buf):
        calls.append("forward")
        return buf.copy()

    def backward(buf):
        calls.append("backward")
        return buf.copy()

    monkeypatch.setattr(suite, "PermuteBytes", forward)
    monkeypatch.setattr(suite, "UnpermuteBytes", backward)
    point = group.Generator()
    assert group.PermutationPair(point, bind_left) == (point, point)
    assert calls == ["forward", "backward"]
