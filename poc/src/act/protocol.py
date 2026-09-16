"""ACT algorithms transcribed from draft-authors-mole-act.md."""

from __future__ import annotations

from ihat.ciphersuite import P256Element as Element
from ihat.ciphersuite import P256Scalar as Scalar
from ihat.common import U16Prefixed
from ihat.ciphersuite import P256Group
from ihat import common

Nseed = common.Nseed
Seed = common.Seed
Ns = 32
Ne = 33
Nh = 32
L = 8


class AmountError(ValueError):
    """A credit amount is outside its permitted range."""


def CreateCredentialProtocolContext(identifier: bytes) -> bytes:
    return b"ACTv1-" + identifier


def CreateGenerators() -> tuple[Element, Element, Element, Element]:
    return (
        G.HashToGroup(b"GenH1"),
        G.HashToGroup(b"GenH2"),
        G.HashToGroup(b"GenH3"),
        G.HashToGroup(b"GenH4"),
    )


def CreateContextScalar(ctx_cred: bytes) -> Scalar:
    return G.HashToScalar(U16Prefixed(ctx_cred) + b"CredentialContext")


def Bits(x: int) -> list[Scalar]:
    return [G.scalar((x >> j) & 1) for j in range(L)]


ctx_proto = CreateCredentialProtocolContext(b"P256-SHA256")
G = P256Group(ctx_proto)
B = G.Generator()
H1, H2, H3, H4 = CreateGenerators()
