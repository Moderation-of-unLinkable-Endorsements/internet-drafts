"""ACT algorithms transcribed from draft-authors-mole-act.md."""

from __future__ import annotations

from collections.abc import Sequence
from typing import NamedTuple

from ihat.ciphersuite import DeriveError
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
from .statements import CommitmentRelation
from .statements import SignatureRelation
from ihat.protocol import VerifyError

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


def SigningExponent(
    skM: Scalar, label: bytes, X_A: Element
) -> Scalar:
    instance = U16Prefixed(label) + U16Prefixed(
        G.SerializeElement(X_A)
    )
    e = G.DeriveNonce(
        G.SerializeScalar(skM), b"e", instance, random(Nseed)
    )
    if (e + skM).isZero():
        raise DeriveError
    return e


class ClientIssuanceState(NamedTuple):
    k: Scalar
    r: Scalar
    K: Element


class IssueRequestMessage(NamedTuple):
    K: Element
    pok: bytes


class IssueResponseMessage(NamedTuple):
    A: Element
    e: Scalar
    c: int
    pok: bytes


class Credential(NamedTuple):
    k: Scalar
    c: int
    r: Scalar
    A: Element
    e: Scalar


def IssueRequest() -> (
    tuple[ClientIssuanceState, IssueRequestMessage]
):
    rand = random(2 * Nseed)
    k = G.DeriveScalar(Seed(rand, 0), b"k")
    r = G.DeriveScalar(Seed(rand, 1), b"r")

    K = k * H2 + r * H3

    tag = Tag(b"IssueRequest", [])
    pok = Prove(tag, CommitmentRelation(K), [k, r])

    return ClientIssuanceState(k, r, K), IssueRequestMessage(K, pok)


def IssueResponse(
    skM: Scalar,
    ctx_cred: bytes,
    c: int,
    request: IssueRequestMessage,
) -> IssueResponseMessage:
    K, pok = request

    if not 0 <= c < 2**L:
        raise AmountError

    tag = Tag(b"IssueRequest", [])
    if not Verify(tag, CommitmentRelation(K), pok):
        raise VerifyError

    ctx = CreateContextScalar(ctx_cred)
    X_A = B + G.scalar(c) * H1 + ctx * H4 + K

    e = SigningExponent(skM, b"IssueResponse", X_A)
    x = e + skM
    A = G.ScalarInverse(x) * X_A
    X_G = G.ScalarMultGen(x)

    tag = Tag(b"IssueResponse", [])
    pok = Prove(tag, SignatureRelation(A, X_A, X_G), [x])

    return IssueResponseMessage(A, e, c, pok)


def FinalizeIssue(
    pkM: Element,
    ctx_cred: bytes,
    state: ClientIssuanceState,
    response: IssueResponseMessage,
) -> Credential:
    k, r, K = state
    A, e, c, pok = response

    if not 0 <= c < 2**L:
        raise AmountError

    ctx = CreateContextScalar(ctx_cred)
    X_A = B + G.scalar(c) * H1 + ctx * H4 + K
    X_G = G.ScalarMultGen(e) + pkM

    tag = Tag(b"IssueResponse", [])
    if not Verify(tag, SignatureRelation(A, X_A, X_G), pok):
        raise VerifyError

    return Credential(k, c, r, A, e)


ctx_proto = CreateCredentialProtocolContext(b"P256-SHA256")
G = P256Group(ctx_proto)
B = G.Generator()
H1, H2, H3, H4 = CreateGenerators()
