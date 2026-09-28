import pytest

import ihat.protocol as protocol
from ihat import wire
from ihat.ciphersuite import DeserializeError, ORDER

G = protocol.G
SESSION_ID = b"session-7"


def _issue_over_the_wire():
    skA, pkA = G.DeriveKeyPair(bytes(range(48)), b"anchor")
    anchor_state, commitment = protocol.Commit(b"epoch-1")
    commit_message = wire.EncodeCommitMessage(SESSION_ID, commitment)
    session_id, commitment = wire.DecodeCommitMessage(commit_message)
    assert session_id == SESSION_ID

    client_state, challenge = protocol.Challenge(
        pkA, b"epoch-1", b"moderator-1", commitment
    )
    challenge_message = wire.EncodeChallengeMessage(session_id, challenge)
    session_id, challenge = wire.DecodeChallengeMessage(challenge_message)
    assert session_id == SESSION_ID

    response = protocol.Respond(skA, anchor_state, challenge)
    response_message = wire.EncodeResponseMessage(response)
    response = wire.DecodeResponseMessage(response_message)

    endorsement = protocol.Finalize(pkA, client_state, response)
    encoded = wire.EncodeEndorsement(endorsement)
    assert wire.DecodeEndorsement(encoded) == endorsement
    messages = [commit_message, challenge_message, response_message, encoded]
    return pkA, endorsement, messages


def _redemption(size):
    pkA, endorsement, _ = _issue_over_the_wire()
    anchor_set = [G.ScalarMultGen(protocol.Scalar(100 + i)) for i in range(size)]
    anchor_set[-1] = pkA
    redemption = protocol.Redeem(
        anchor_set, size - 1, endorsement, b"epoch-1", b"moderator-1", b"d"
    )
    return anchor_set, redemption, wire.EncodeRedemption(redemption)


def test_message_sizes():
    _, _, messages = _issue_over_the_wire()
    header = 1 + len(SESSION_ID)
    assert [len(m) for m in messages] == [
        header + 2 * G.Ne,
        header + G.Ns,
        3 * G.Ns,
        4 * G.Ns + protocol.Nn,
    ]


@pytest.mark.parametrize("size", [2, 3, 5, 8, 9])
def test_redemption_round_trip(size):
    anchor_set, redemption, encoded = _redemption(size)
    q = protocol.Depth(size)
    headers = len(wire.EncodeLength(q * G.Ne)) + len(wire.EncodeLength(q * G.Ns))
    assert len(encoded) == (
        G.Ne + 4 * G.Ns + protocol.Nn + 2 * G.Ns + headers + q * (G.Ne + G.Ns)
    )
    decoded = wire.DecodeRedemption(encoded, size)
    assert decoded == redemption
    assert protocol.VerifyRedemption(
        anchor_set, decoded, b"epoch-1", b"moderator-1", b"d"
    ) == redemption.shown.nf


def test_redemption_rejects_another_anchor_set_size():
    _, _, encoded = _redemption(3)
    for n in (2, 5):
        with pytest.raises(DeserializeError, match="Anchor Set"):
            wire.DecodeRedemption(encoded, n)
    # Depth(3) == Depth(4), so a set of four keys decodes and the proof fails.
    wire.DecodeRedemption(encoded, 4)


def test_truncated_and_padded_messages_are_rejected():
    _, _, messages = _issue_over_the_wire()
    _, _, redemption = _redemption(3)
    decoders = [
        wire.DecodeCommitMessage,
        wire.DecodeChallengeMessage,
        wire.DecodeResponseMessage,
        wire.DecodeEndorsement,
        lambda data: wire.DecodeRedemption(data, 3),
    ]
    for decode, message in zip(decoders, messages + [redemption], strict=True):
        decode(message)
        for end in range(len(message)):
            with pytest.raises(DeserializeError):
                decode(message[:end])
        with pytest.raises(DeserializeError, match="trailing"):
            decode(message + b"\0")


def test_invalid_elements_and_scalars_are_rejected():
    _, _, messages = _issue_over_the_wire()
    commit_message, _, response_message, _ = messages
    offset = 1 + len(SESSION_ID)
    for element in (bytes(G.Ne), b"\x02" + b"\xff" * 32):
        bad = commit_message[:offset] + element + commit_message[offset + G.Ne :]
        with pytest.raises(DeserializeError):
            wire.DecodeCommitMessage(bad)
    bad = ORDER.to_bytes(G.Ns, "big") + response_message[G.Ns :]
    with pytest.raises(DeserializeError):
        wire.DecodeResponseMessage(bad)


@pytest.mark.parametrize(
    "value, encoded",
    [
        (0, "00"),
        (63, "3f"),
        (64, "4040"),
        (16383, "7fff"),
        (16384, "80004000"),
        (2**30 - 1, "bfffffff"),
        (2**30, "c000000040000000"),
        (2**62 - 1, "ffffffffffffffff"),
    ],
)
def test_variable_length_integers(value, encoded):
    assert wire.EncodeLength(value).hex() == encoded
    reader = wire.Reader(bytes.fromhex(encoded))
    assert reader.length() == value
    reader.finish()


def test_variable_length_integers_must_be_minimal():
    for encoded in ("4000", "403f", "80003fff", "c00000003fffffff"):
        with pytest.raises(DeserializeError, match="non-minimal"):
            wire.Reader(bytes.fromhex(encoded)).length()
    with pytest.raises(ValueError):
        wire.EncodeLength(2**62)
