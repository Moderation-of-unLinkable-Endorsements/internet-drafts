"""ACT algorithms transcribed from draft-authors-mole-act.md."""

from __future__ import annotations

from collections.abc import Sequence

from ihat.ciphersuite import P256Element as Element
from ihat.ciphersuite import P256Scalar as Scalar
from ihat.common import I2OSP
from ihat.common import U16Prefixed
from ihat.ciphersuite import P256Group
from ihat import common
from .sigma import DeriveSessionID
from .sigma import ProveCompact
from .sigma import SerializeLinearRelation
from .sigma import LinearRelation
from .sigma import VerifyCompact

Nseed = common.Nseed
Seed = common.Seed
random = common.random
SIGMA_SUITE = b"sigma-proofs_Shake128_P256"
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


def Tag(label: bytes, bindings: Sequence[bytes]) -> bytes:
    tag = ctx_proto + b"-" + label + b"-CMPT-with-" + SIGMA_SUITE
    for binding in bindings:
        tag += U16Prefixed(binding)
    return tag


class ProverNonces:
    def __init__(
        self,
        witness: Sequence[Scalar],
        session_id: bytes,
        instance: bytes,
    ) -> None:
        self.secret = b"".join(G.SerializeScalar(w) for w in witness)
        self.instance = (
            session_id + I2OSP(len(instance), 4) + instance
        )
        self.rand = random(len(witness) * Nseed)
        self.count = 0

    def random_scalar(self) -> int:
        i = self.count
        self.count = i + 1
        nonce = G.DeriveNonce(
            self.secret,
            b"nonce",
            self.instance + I2OSP(i, 4),
            Seed(self.rand, i),
        )
        return int(nonce)


def Prove(
    tag: bytes, relation: LinearRelation, witness: Sequence[Scalar]
) -> bytes:
    nonces = ProverNonces(
        witness,
        DeriveSessionID(tag),
        SerializeLinearRelation(relation),
    )
    return ProveCompact(tag, relation, witness, nonces)


def Verify(
    tag: bytes, relation: LinearRelation, proof: bytes
) -> bool:
    return VerifyCompact(tag, relation, proof)


ctx_proto = CreateCredentialProtocolContext(b"P256-SHA256")
G = P256Group(ctx_proto)
B = G.Generator()
H1, H2, H3, H4 = CreateGenerators()
