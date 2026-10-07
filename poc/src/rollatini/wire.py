"""The message encodings of the draft.

Decode received messages before passing them to the protocol algorithms:
these routines check lengths and canonical encodings; the algorithms check
the signatures and proofs.
"""

from .ciphersuite import DeserializeError
from .ciphersuite import P256Element as Element
from .ciphersuite import P256Scalar as Scalar
from .common import I2OSP
from .protocol import (
    Commitment,
    Depth,
    Endorsement,
    G,
    Nn,
    Response,
    Token,
)


def EncodeLength(value: int) -> bytes:
    """The minimum-size variable-length integer of HTTP-TRANSPORT."""
    for size, prefix in ((1, 0x00), (2, 0x40), (4, 0x80), (8, 0xC0)):
        if 0 <= value < 1 << (8 * size - 2):
            encoded = I2OSP(value, size)
            return bytes([encoded[0] | prefix]) + encoded[1:]
    raise ValueError("length does not fit a variable-length integer")


def _vector(value: bytes) -> bytes:
    return EncodeLength(len(value)) + value


class Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0

    def take(self, length: int) -> bytes:
        if self.offset + length > len(self.data):
            raise DeserializeError("truncated Rollatini message")
        result = self.data[self.offset : self.offset + length]
        self.offset += length
        return result

    def length(self) -> int:
        first = self.take(1)[0]
        size = 1 << (first >> 6)
        value = int.from_bytes(
            bytes([first & 0x3F]) + self.take(size - 1), "big"
        )
        if size > 1 and value < 1 << (8 * (size // 2) - 2):
            raise DeserializeError("non-minimal variable-length integer")
        return value

    def vector(self) -> bytes:
        return self.take(self.length())

    def element(self) -> Element:
        return G.DeserializeElement(self.take(G.Ne))

    def scalar(self) -> Scalar:
        return G.DeserializeScalar(self.take(G.Ns))

    def token(self) -> Token:
        c = self.scalar()
        s = self.scalar()
        y = self.scalar()
        t = self.scalar()
        return Token(c, s, y, t, self.take(Nn))

    def finish(self) -> None:
        if self.offset != len(self.data):
            raise DeserializeError("trailing bytes in Rollatini message")


def EncodeCommitMessage(session_id: bytes, commitment: Commitment) -> bytes:
    return (
        _vector(session_id)
        + G.SerializeElement(commitment.A)
        + G.SerializeElement(commitment.C)
    )


def DecodeCommitMessage(data: bytes) -> tuple[bytes, Commitment]:
    reader = Reader(data)
    session_id = reader.vector()
    A = reader.element()
    C = reader.element()
    reader.finish()
    return (session_id, Commitment(A, C))


def EncodeChallengeMessage(session_id: bytes, challenge: Scalar) -> bytes:
    return _vector(session_id) + G.SerializeScalar(challenge)


def DecodeChallengeMessage(data: bytes) -> tuple[bytes, Scalar]:
    reader = Reader(data)
    session_id = reader.vector()
    challenge = reader.scalar()
    reader.finish()
    return (session_id, challenge)


def EncodeResponseMessage(response: Response) -> bytes:
    return (
        G.SerializeScalar(response.s)
        + G.SerializeScalar(response.y)
        + G.SerializeScalar(response.t)
    )


def DecodeResponseMessage(data: bytes) -> Response:
    reader = Reader(data)
    s = reader.scalar()
    y = reader.scalar()
    t = reader.scalar()
    reader.finish()
    return Response(s, y, t)


def EncodeToken(token: Token) -> bytes:
    if len(token.nf) != Nn:
        raise ValueError(f"nullifier must be exactly {Nn} bytes")
    return (
        G.SerializeScalar(token.c)
        + G.SerializeScalar(token.s)
        + G.SerializeScalar(token.y)
        + G.SerializeScalar(token.t)
        + token.nf
    )


def DecodeToken(data: bytes) -> Token:
    reader = Reader(data)
    token = reader.token()
    reader.finish()
    return token


def EncodeEndorsement(endorsement: Endorsement) -> bytes:
    return (
        G.SerializeElement(endorsement.X_hat)
        + EncodeToken(endorsement.shown)
        + G.SerializeScalar(endorsement.proof_challenge)
        + G.SerializeScalar(endorsement.response)
        + _vector(
            b"".join(G.SerializeElement(Q) for Q in endorsement.commitment_keys)
        )
        + _vector(b"".join(G.SerializeScalar(o) for o in endorsement.openings))
    )


def DecodeEndorsement(data: bytes, n: int) -> Endorsement:
    """Decode an Endorsement against an Anchor Set of `n` keys."""
    reader = Reader(data)
    X_hat = reader.element()
    shown = reader.token()
    proof_challenge = reader.scalar()
    response = reader.scalar()
    keys = reader.vector()
    openings = reader.vector()
    reader.finish()

    q = Depth(n)
    if len(keys) != q * G.Ne or len(openings) != q * G.Ns:
        raise DeserializeError("vector lengths do not match the Anchor Set")
    keys_reader = Reader(keys)
    openings_reader = Reader(openings)
    return Endorsement(
        X_hat,
        shown,
        proof_challenge,
        response,
        [keys_reader.element() for _ in range(q)],
        [openings_reader.scalar() for _ in range(q)],
    )
