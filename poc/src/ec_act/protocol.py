"""EC-ACT algorithms transcribed from draft-authors-mole-ec-act.md."""

from __future__ import annotations

from collections.abc import Sequence
from typing import NamedTuple

from ec_ihat.ciphersuite import DeriveError
from ec_ihat.ciphersuite import P256Element as Element
from ec_ihat.ciphersuite import P256Scalar as Scalar
from ec_ihat.common import I2OSP
from ec_ihat.common import U16Prefixed
from ec_ihat.ciphersuite import P256Group
from ec_ihat import common
from .sigma import DeriveSessionID
from .sigma import ProveCompact
from .sigma import SerializeLinearRelation
from .sigma import LinearRelation
from .sigma import VerifyCompact
from .statements import CommitmentRelation
from .statements import SignatureRelation
from .statements import SpendRelation
from ec_ihat.protocol import VerifyError

Nseed = common.Nseed
Seed = common.Seed
random = common.random
SIGMA_SUITE = b"sigma-proofs_Shake128_P256"
Ns = 32
Ne = 33
L = 8


class AmountError(ValueError):
    """A credit amount is outside its permitted range."""


def CreateCredentialProtocolContext(identifier: bytes) -> bytes:
    return b"EC-ACTv1-" + identifier


def CreateGenerators() -> tuple[Element, Element, Element, Element]:
    return (
        G.HashToGroup(b"GenH1"),
        G.HashToGroup(b"GenH2"),
        G.HashToGroup(b"GenH3"),
        G.HashToGroup(b"GenH4"),
    )


def CreateContextScalar(ctx_cred: bytes) -> Scalar:
    return G.HashToScalar(U16Prefixed(ctx_cred) + b"CredentialContext")


def RangeWeights(m: int) -> list[int]:
    if not 0 <= m < 2**L:
        raise AmountError
    n = m.bit_length()
    if n == 0:
        return []
    return [2**j for j in range(n - 1)] + [m - 2 ** (n - 1) + 1]


def Bits(x: int, weights: Sequence[int]) -> list[Scalar]:
    n = len(weights)
    if n == 0:
        return []
    top = (x >> (n - 1)) & 1
    rest = x - top * weights[n - 1]
    return [G.scalar((rest >> j) & 1) for j in range(n - 1)] + [
        G.scalar(top)
    ]


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
        self.nonces = G.DeriveNonces(
            b"".join(G.SerializeScalar(w) for w in witness),
            b"nonce",
            session_id + I2OSP(len(instance), 4) + instance,
            random(Nseed),
            len(witness),
        )
        self.count = 0

    def random_scalar(self) -> int:
        i = self.count
        self.count = i + 1
        return int(self.nonces[i])


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
    (e,) = G.DeriveNonces(
        G.SerializeScalar(skM), b"e", instance, random(Nseed), 1
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
    rand = random(Nseed)
    (k, r) = G.DeriveScalars(rand, b"IssueRequest", 2)

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
    s: int
    a: int
    K_prime: Element


class SpendMessage(NamedTuple):
    k: Scalar
    s: int
    a: int
    A_prime: Element
    B_bar: Element
    K_n: Element
    Com1: Sequence[Element]
    Com_c: Element | None
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
    w = RangeWeights(2**L - 1 - (s + a)) if s + a > 0 else []
    n = len(w)

    ctx = CreateContextScalar(ctx_cred)

    # Four fixed scalars, then one for each bit of the remainder or
    # one for the commitment of a refresh.
    count = 4 + (n if s + a > 0 else 1)
    derived = G.DeriveScalars(random(Nseed), b"ProveSpend", count)
    (r1, r2, kstar, rn) = derived[:4]

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
    witness = [e, r2, r3, G.scalar(c), r, kstar, rn]

    # Commit to the remainder: bitwise when it must be shown to be in
    # range, in one commitment when it is the balance of a refresh.
    if s + a > 0:
        b1 = Bits(v1, w)
        s1 = derived[4:]
        Com1 = [b1[j] * H1 + s1[j] * H3 for j in range(n)]
        u1 = [(G.scalar(1) - b1[j]) * s1[j] for j in range(n)]
        r_star = rn
        for j in range(n):
            r_star = r_star + G.scalar(w[j]) * s1[j]
        witness += b1 + s1 + u1
    else:
        rc = derived[4]
        Com_c = G.scalar(c) * H1 + rc * H3
        r_star = rn + rc
        witness += [rc]

    H1_prime = B + k * H2 + ctx * H4
    relation = SpendRelation(
        A_prime, B_bar, A_bar, H1_prime, K_n, s, a, Com1, Com_c
    )
    pok = Prove(Tag(b"Spend", [ctx_spend]), relation, witness)

    # The commitment the refund will sign, opened by the new
    # Credential's secrets; the Moderator recomputes it from `proof`.
    K_prime = G.scalar(v1) * H1 + kstar * H2 + r_star * H3

    state = ClientSpendState(kstar, r_star, v1, s, a, K_prime)
    proof = SpendMessage(
        k, s, a, A_prime, B_bar, K_n, Com1, Com_c, pok
    )

    return state, proof


def VerifySpend(
    skM: Scalar,
    ctx_cred: bytes,
    ctx_spend: bytes,
    proof: SpendMessage,
) -> None:
    k, s, a, A_prime, B_bar, K_n, Com1, Com_c, pok = proof

    if not (0 <= s < 2**L and 0 <= a < 2**L):
        raise AmountError
    if s + a >= 2**L:
        raise AmountError

    ctx = CreateContextScalar(ctx_cred)
    A_bar = skM * A_prime
    H1_prime = B + k * H2 + ctx * H4

    relation = SpendRelation(
        A_prime, B_bar, A_bar, H1_prime, K_n, s, a, Com1, Com_c
    )
    if not Verify(Tag(b"Spend", [ctx_spend]), relation, pok):
        raise VerifyError


def BalanceCommitment(proof: SpendMessage) -> Element:
    k, s, a, A_prime, B_bar, K_n, Com1, Com_c, pok = proof

    if s + a > 0:
        w = RangeWeights(2**L - 1 - (s + a))
        if len(Com1) != len(w):
            raise VerifyError
        V1 = G.Identity()
        for j in range(len(w)):
            V1 = V1 + G.scalar(w[j]) * Com1[j]
    else:
        if Com_c is None:
            raise VerifyError
        V1 = Com_c

    return K_n + V1


def IssueRefund(
    skM: Scalar, ctx_cred: bytes, proof: SpendMessage, t: int
) -> RefundMessage:
    k, s, a, A_prime, B_bar, K_n, Com1, Com_c, pok = proof

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
    refund: RefundMessage,
) -> Credential:
    kstar, r_star, v1, s, a, K_prime = state
    A, e, t, pok = refund

    if not 0 <= t < 2**L or t > s + a or v1 + t >= 2**L:
        raise AmountError

    ctx = CreateContextScalar(ctx_cred)
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
