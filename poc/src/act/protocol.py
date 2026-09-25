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
from .statements import SpendRelation
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


class ClientSpendState(NamedTuple):
    kstar: Scalar
    r_star: Scalar
    v1: int
    K_n: Element


class SpendMessage(NamedTuple):
    k: Scalar
    s: int
    a: int
    A_prime: Element
    B_bar: Element
    K_n: Element
    Com1: Sequence[Element]
    Com_c: Element | None
    Com2: Sequence[Element]
    pok: bytes


class RefundMessage(NamedTuple):
    A: Element
    e: Scalar
    t: int
    pok: bytes


def ProveSpend(
    credential: Credential,
    ctx_cred: bytes,
    s: int,
    a: int,
    ctx_spend: bytes,
) -> tuple[ClientSpendState, SpendMessage]:
    k, c, r, A, e = credential

    if not (0 <= s < 2**L and 0 <= a < 2**L):
        raise AmountError
    if s > c or c + a >= 2**L:
        raise AmountError
    v1 = c - s
    v2 = c + a

    ctx = CreateContextScalar(ctx_cred)

    # One seed per scalar: four fixed ones, then L for the bits of
    # the remainder or one for its commitment, then L for the bits
    # of the topped-up balance.
    n = 4 + (L if s > 0 else 1) + (L if a > 0 else 0)
    rand = random(n * Nseed)
    seed = [Seed(rand, i) for i in range(n)]
    r1 = G.DeriveScalar(seed[0], b"r1")
    r2 = G.DeriveScalar(seed[1], b"r2")
    kstar = G.DeriveScalar(seed[2], b"kstar")
    rn = G.DeriveScalar(seed[3], b"rn")
    next_seed = 4

    # Rerandomize the signature.
    B_msg = B + G.scalar(c) * H1 + k * H2 + r * H3 + ctx * H4
    A_prime = (r1 * r2) * A
    B_bar = r1 * B_msg
    r3 = G.ScalarInverse(r1)
    A_bar = r2 * B_bar - e * A_prime

    # Commit to the next Credential's nullifier.
    K_n = kstar * H2 + rn * H3

    Com1: list[Element] = []
    Com_c: Element | None = None
    Com2: list[Element] = []
    witness = [e, r2, r3, G.scalar(c), r, kstar, rn]

    # Commit to the remainder: bitwise when it must be shown to be
    # nonnegative, in one commitment when it is the balance itself.
    if s > 0:
        b1 = Bits(v1)
        s1 = []
        r_star = rn
        for j in range(L):
            info = b"s1" + I2OSP(j, 1)
            s1.append(G.DeriveScalar(seed[next_seed + j], info))
            Com1.append(b1[j] * H1 + s1[j] * H3)
            r_star = r_star + G.scalar(2**j) * s1[j]
        u1 = [(G.scalar(1) - b1[j]) * s1[j] for j in range(L)]
        witness += b1 + s1 + u1
        next_seed = next_seed + L
    else:
        rc = G.DeriveScalar(seed[next_seed], b"rc")
        Com_c = G.scalar(c) * H1 + rc * H3
        r_star = rn + rc
        witness += [rc]
        next_seed = next_seed + 1

    # Commit to the topped-up balance when there is a top-up.
    if a > 0:
        b2 = Bits(v2)
        s2 = []
        for j in range(L):
            info = b"s2" + I2OSP(j, 1)
            s2.append(G.DeriveScalar(seed[next_seed + j], info))
            Com2.append(b2[j] * H1 + s2[j] * H3)
        u2 = [(G.scalar(1) - b2[j]) * s2[j] for j in range(L)]
        witness += b2 + s2 + u2

    H1_prime = B + k * H2 + ctx * H4
    relation = SpendRelation(
        A_prime, B_bar, A_bar, H1_prime, K_n, s, a, Com1, Com_c, Com2
    )
    pok = Prove(Tag(b"Spend", [ctx_spend]), relation, witness)

    state = ClientSpendState(kstar, r_star, v1, K_n)
    proof = SpendMessage(
        k, s, a, A_prime, B_bar, K_n, Com1, Com_c, Com2, pok
    )

    return state, proof


def VerifySpend(
    skM: Scalar,
    ctx_cred: bytes,
    ctx_spend: bytes,
    proof: SpendMessage,
) -> None:
    k, s, a, A_prime, B_bar, K_n, Com1, Com_c, Com2, pok = proof

    if not (0 <= s < 2**L and 0 <= a < 2**L):
        raise AmountError

    ctx = CreateContextScalar(ctx_cred)
    A_bar = skM * A_prime
    H1_prime = B + k * H2 + ctx * H4

    relation = SpendRelation(
        A_prime, B_bar, A_bar, H1_prime, K_n, s, a, Com1, Com_c, Com2
    )
    if not Verify(Tag(b"Spend", [ctx_spend]), relation, pok):
        raise VerifyError


def BalanceCommitment(proof: SpendMessage) -> Element:
    k, s, a, A_prime, B_bar, K_n, Com1, Com_c, Com2, pok = proof

    if s > 0:
        V1 = G.Identity()
        for j in range(L):
            V1 = V1 + G.scalar(2**j) * Com1[j]
    else:
        if Com_c is None:
            raise VerifyError
        V1 = Com_c

    return K_n + V1


def IssueRefund(
    skM: Scalar, ctx_cred: bytes, proof: SpendMessage, t: int
) -> RefundMessage:
    k, s, a, A_prime, B_bar, K_n, Com1, Com_c, Com2, pok = proof

    if not 0 <= t < 2**L or t > s + a:
        raise AmountError

    ctx = CreateContextScalar(ctx_cred)
    K_prime = BalanceCommitment(proof)
    X_A = B + K_prime + G.scalar(t) * H1 + ctx * H4

    e = SigningExponent(skM, b"Refund", X_A)
    x = e + skM
    A = G.ScalarInverse(x) * X_A
    X_G = G.ScalarMultGen(x)

    tag = Tag(b"Refund", [])
    pok = Prove(tag, SignatureRelation(A, X_A, X_G), [x])

    return RefundMessage(A, e, t, pok)


def FinalizeRefund(
    pkM: Element,
    ctx_cred: bytes,
    state: ClientSpendState,
    proof: SpendMessage,
    refund: RefundMessage,
) -> Credential:
    kstar, r_star, v1, K_n_state = state
    k, s, a, A_prime, B_bar, K_n, Com1, Com_c, Com2, _ = proof
    A, e, t, pok = refund

    if K_n != K_n_state:
        raise VerifyError
    if not 0 <= t < 2**L or t > s + a or v1 + t >= 2**L:
        raise AmountError

    ctx = CreateContextScalar(ctx_cred)
    K_prime = BalanceCommitment(proof)

    X_A = B + K_prime + G.scalar(t) * H1 + ctx * H4
    X_G = G.ScalarMultGen(e) + pkM

    tag = Tag(b"Refund", [])
    if not Verify(tag, SignatureRelation(A, X_A, X_G), pok):
        raise VerifyError

    return Credential(kstar, v1 + t, r_star, A, e)


ctx_proto = CreateCredentialProtocolContext(b"P256-SHA256")
G = P256Group(ctx_proto)
B = G.Generator()
H1, H2, H3, H4 = CreateGenerators()
