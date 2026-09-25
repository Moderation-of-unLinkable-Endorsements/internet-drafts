"""The message encodings of the draft.

Decode received messages before passing them to the protocol algorithms:
these routines check lengths, canonical encodings, and amount bounds; the
algorithms check the proofs.
"""

from ihat.ciphersuite import DeserializeError
from ihat.ciphersuite import P256Element as Element
from ihat.ciphersuite import P256Scalar as Scalar

from . import protocol as act


class Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0

    def take(self, length: int) -> bytes:
        if self.offset + length > len(self.data):
            raise DeserializeError("truncated ACT message")
        result = self.data[self.offset : self.offset + length]
        self.offset += length
        return result

    def element(self) -> Element:
        return act.G.DeserializeElement(self.take(act.Ne))

    def scalar(self) -> Scalar:
        return act.G.DeserializeScalar(self.take(act.Ns))

    def amount(self) -> int:
        value = int.from_bytes(self.take(8), "big")
        if value >= 2**act.L:
            raise act.AmountError
        return value

    def proof(self, witnesses: int) -> bytes:
        proof = self.take((witnesses + 1) * act.Ns)
        for i in range(0, len(proof), act.Ns):
            act.G.DeserializeScalar(proof[i : i + act.Ns])
        return proof

    def finish(self) -> None:
        if self.offset != len(self.data):
            raise DeserializeError("trailing bytes in ACT message")


def _amount(value: int) -> bytes:
    if not 0 <= value < 2**act.L:
        raise act.AmountError
    return value.to_bytes(8, "big")


def _proof(value: bytes, witnesses: int) -> bytes:
    reader = Reader(value)
    result = reader.proof(witnesses)
    reader.finish()
    return result


def EncodeIssueRequest(message: act.IssueRequestMessage) -> bytes:
    return act.G.SerializeElement(message.K) + _proof(message.pok, 2)


def DecodeIssueRequest(data: bytes) -> act.IssueRequestMessage:
    reader = Reader(data)
    result = act.IssueRequestMessage(reader.element(), reader.proof(2))
    reader.finish()
    return result


def EncodeIssueResponse(message: act.IssueResponseMessage) -> bytes:
    return (
        act.G.SerializeElement(message.A)
        + act.G.SerializeScalar(message.e)
        + _amount(message.c)
        + _proof(message.pok, 1)
    )


def DecodeIssueResponse(data: bytes) -> act.IssueResponseMessage:
    reader = Reader(data)
    result = act.IssueResponseMessage(
        reader.element(),
        reader.scalar(),
        reader.amount(),
        reader.proof(1),
    )
    reader.finish()
    return result


def EncodeCredential(credential: act.Credential) -> bytes:
    return (
        act.G.SerializeScalar(credential.k)
        + _amount(credential.c)
        + act.G.SerializeScalar(credential.r)
        + act.G.SerializeElement(credential.A)
        + act.G.SerializeScalar(credential.e)
    )


def DecodeCredential(data: bytes) -> act.Credential:
    reader = Reader(data)
    result = act.Credential(
        reader.scalar(),
        reader.amount(),
        reader.scalar(),
        reader.element(),
        reader.scalar(),
    )
    reader.finish()
    return result
