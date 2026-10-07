"""Rollatini algorithms transcribed from draft-authors-mole-rollatini.md."""

from __future__ import annotations

from typing import NamedTuple, Sequence

from .ciphersuite import P256Element as Element
from .ciphersuite import P256Group, P256Scalar as Scalar
from .common import CreateProtocolContext, I2OSP, U16Prefixed, random
from . import common

Nn = 32
Nseed = common.Nseed
Seed = common.Seed
ctx_proto = CreateProtocolContext(b"P256-SHA256")
G = P256Group(ctx_proto)
B = G.Generator()


class VerifyError(Exception):
    """A received value failed a verification check."""


class SessionError(Exception):
    """A session is not in the expected state."""

class AnchorState(NamedTuple):
    a: Scalar
    y: Scalar
    t: Scalar


class Commitment(NamedTuple):
    A: Element
    C: Element


class ClientState(NamedTuple):
    nf: bytes
    ctx_iss: bytes
    commitment: Commitment
    r1: Scalar
    r2: Scalar
    gamma1: Scalar
    gamma2: Scalar
    challenge: Scalar
    c: Scalar


class Response(NamedTuple):
    s: Scalar
    y: Scalar
    t: Scalar


class Token(NamedTuple):
    c: Scalar
    s: Scalar
    y: Scalar
    t: Scalar
    nf: bytes


class Endorsement(NamedTuple):
    X_hat: Element
    shown: Token
    proof_challenge: Scalar
    response: Scalar
    commitment_keys: Sequence[Element]
    openings: Sequence[Scalar]

def CreateContextBase(ctx_iss: bytes) -> Element:
    context_base_input = U16Prefixed(ctx_iss) + b"ContextBase"
    return G.HashToGroup(context_base_input)


def Message(nf: bytes, ctx_red: bytes) -> bytes:
    if len(nf) != Nn:
        raise ValueError(f"nullifier must be exactly {Nn} bytes")
    return U16Prefixed(nf) + U16Prefixed(ctx_red)


def Commit(ctx_iss: bytes) -> tuple[AnchorState, Commitment]:
    Z = CreateContextBase(ctx_iss)

    rand = random(Nseed)
    (a, t, y) = G.DeriveScalars(rand, b"Commit", 3)

    A = G.ScalarMultGen(a)
    C = G.ScalarMultGen(t) + y * Z

    return (AnchorState(a, y, t), Commitment(A, C))


def Challenge(
    pkA: Element,
    ctx_iss: bytes,
    ctx_red: bytes,
    commitment: Commitment,
) -> tuple[ClientState, Scalar]:
    if pkA.isIdentity():
        raise VerifyError

    (A, C) = commitment

    rand = random(Nn + Nseed)
    nf = rand[:Nn]
    (r1, r2, gamma1, gamma2) = G.DeriveScalars(
        rand[Nn:], b"Challenge", 4
    )

    m = Message(nf, ctx_red)
    gamma = gamma1 * G.ScalarInverse(gamma2)

    blinded_A = G.ScalarMultGen(r1) + gamma * A
    blinded_C = gamma1 * C + G.ScalarMultGen(r2)
    blinded_commitment = Commitment(blinded_A, blinded_C)

    c = ComputeChallenge(ctx_iss, blinded_commitment, m)
    if c.isZero():
        raise VerifyError

    challenge = c * gamma2
    state = ClientState(
        nf,
        ctx_iss,
        commitment,
        r1,
        r2,
        gamma1,
        gamma2,
        challenge,
        c,
    )
    return (state, challenge)


def ComputeChallenge(ctx_iss: bytes, commitment: Commitment, m: bytes) -> Scalar:
    (A, C) = commitment

    Am = G.SerializeElement(A)
    Cm = G.SerializeElement(C)

    challenge_transcript = (
        U16Prefixed(ctx_iss)
        + U16Prefixed(Am)
        + U16Prefixed(Cm)
        + U16Prefixed(m)
        + b"Challenge"
    )

    c = G.HashToScalar(challenge_transcript)

    return c


def Respond(skA: Scalar, state: AnchorState, challenge: Scalar) -> Response:
    (a, y, t) = state

    if challenge.isZero():
        raise VerifyError

    s = a + challenge * y * skA
    response = Response(s, y, t)

    return response


def Finalize(pkA: Element, state: ClientState, response: Response) -> Token:
    if pkA.isIdentity():
        raise VerifyError

    (nf, ctx_iss, (A, C), r1, r2, gamma1, gamma2, challenge, c) = state
    (s, y, t) = response

    Z = CreateContextBase(ctx_iss)

    if y.isZero():
        raise VerifyError
    if C != G.ScalarMultGen(t) + y * Z:
        raise VerifyError
    if G.ScalarMultGen(s) != A + (challenge * y) * pkA:
        raise VerifyError

    gamma = gamma1 * G.ScalarInverse(gamma2)

    s_final = gamma * s + r1
    y_final = gamma1 * y
    t_final = gamma1 * t + r2

    return Token(c, s_final, y_final, t_final, nf)


def Verify(
    pkA: Element,
    token: Token,
    ctx_iss: bytes,
    ctx_red: bytes,
) -> bool:
    if pkA.isIdentity():
        return False

    (c, s, y, t, nf) = token

    if len(nf) != Nn or c.isZero() or y.isZero():
        return False

    Z = CreateContextBase(ctx_iss)
    m = Message(nf, ctx_red)

    C = G.ScalarMultGen(t) + y * Z
    A = G.ScalarMultGen(s) - (c * y) * pkA
    if A.isIdentity() or C.isIdentity():
        return False
    commitment = Commitment(A, C)

    return c == ComputeChallenge(ctx_iss, commitment, m)


def BranchCommitment(
    proof_challenge: Scalar,
    response: Scalar,
    Y: Element,
) -> Element:
    return proof_challenge * Y + G.ScalarMultGen(response)


def Statements(
    anchor_set: Sequence[Element],
    X_hat: Element,
) -> list[Element]:
    return [X_hat - pkA for pkA in anchor_set]


def CommitStep(
    Q: Element,
    left: bytes,
    right: bytes,
    randomness: Scalar,
) -> bytes:
    C = (
        randomness * B
        + G.HashToScalar(left) * Q
        + G.HashToScalar(right) * G.P(Q)
    )
    return G.SerializeElement(C)


def GenerateStep(bind_left: bool, secret: Scalar) -> Element:
    T = secret * B
    (Q, _) = G.PermutationPair(T, bind_left)
    return Q


def EquivocateStep(
    oldb: bytes, newb: bytes, randomness: Scalar, secret: Scalar
) -> Scalar:
    old = G.HashToScalar(oldb)
    new = G.HashToScalar(newb)
    return randomness + (old - new) * secret


def VecCommit(
    V: Sequence[bytes],
    Qi: Sequence[Element],
    rands: Sequence[Scalar],
) -> bytes:
    if len(V) == 1:
        return V[0]

    V_prime = []
    for i in range(len(V) // 2):
        V_prime.append(CommitStep(Qi[0], V[2 * i], V[2 * i + 1], rands[0]))

    if len(V) % 2 == 1:
        V_prime.append(V[-1])

    return VecCommit(V_prime, Qi[1:], rands[1:])


def Depth(n: int) -> int:
    q = 0
    while 2**q < n:
        q += 1
    return q


def ProofStatement(
    anchor_set: Sequence[Element],
    X_hat: Element,
    token: Token,
    ctx_iss: bytes,
    ctx_red: bytes,
    challenge_digest: bytes,
) -> bytes:
    (c, s_hat, y, t, nf) = token
    n = len(anchor_set)

    anchor_set_enc = b""
    for i in range(n):
        anchor_set_enc += G.SerializeElement(anchor_set[i])

    return (
        I2OSP(n, 2)
        + anchor_set_enc
        + G.SerializeElement(X_hat)
        + G.SerializeScalar(c)
        + G.SerializeScalar(s_hat)
        + G.SerializeScalar(y)
        + G.SerializeScalar(t)
        + U16Prefixed(nf)
        + U16Prefixed(ctx_iss)
        + U16Prefixed(ctx_red)
        + U16Prefixed(challenge_digest)
    )


def ComputeProofChallenge(
    anchor_set: Sequence[Element],
    X_hat: Element,
    token: Token,
    ctx_iss: bytes,
    ctx_red: bytes,
    challenge_digest: bytes,
    commitment_keys: Sequence[Element],
    root: bytes,
) -> Scalar:
    ck_enc = b""
    for j in range(len(commitment_keys)):
        ck_enc += G.SerializeElement(commitment_keys[j])

    proof_transcript = (
        ProofStatement(
            anchor_set,
            X_hat,
            token,
            ctx_iss,
            ctx_red,
            challenge_digest,
        )
        + ck_enc
        + root
        + b"IssuerProof"
    )

    return G.HashToScalar(proof_transcript)


def GenerateVecBind(
    index: int, trapdoors: Sequence[Scalar]
) -> list[Element]:
    commitment_keys = []
    for j in range(len(trapdoors)):
        bind_left = ((index >> j) & 1) == 0
        commitment_keys.append(GenerateStep(bind_left, trapdoors[j]))
    return commitment_keys


def CommitValAtPlace(
    commitment_keys: Sequence[Element],
    n: int,
    index: int,
    value: bytes,
    openings: Sequence[Scalar],
) -> bytes:
    V = [b"" for _ in range(n)]
    V[index] = value
    return VecCommit(V, commitment_keys, openings)


def VecEquivocate(
    commitment_keys: Sequence[Element],
    trapdoors: Sequence[Scalar],
    openings: Sequence[Scalar],
    old: Sequence[bytes],
    new: Sequence[bytes],
    index: int,
) -> list[Scalar]:
    if len(old) != len(new):
        raise ValueError("vectors must have the same length")
    if old[index] != new[index]:
        raise ValueError("the binding position cannot change")
    if len(old) == 1:
        return []

    if index == len(old) - 1 and len(old) % 2 == 1:
        opening = openings[0]
    else:
        partner = index - 1 if index % 2 == 1 else index + 1
        opening = EquivocateStep(
            old[partner], new[partner], openings[0], trapdoors[0]
        )

    old_prime = []
    new_prime = []
    for i in range(len(old) // 2):
        Q = commitment_keys[0]
        old_prime.append(
            CommitStep(Q, old[2 * i], old[2 * i + 1], openings[0])
        )
        new_prime.append(
            CommitStep(Q, new[2 * i], new[2 * i + 1], opening)
        )
    if len(old) % 2 == 1:
        old_prime.append(old[-1])
        new_prime.append(new[-1])

    rest = VecEquivocate(
        commitment_keys[1:],
        trapdoors[1:],
        openings[1:],
        old_prime,
        new_prime,
        index // 2,
    )
    return [opening] + rest


def VecEquivocateFromZero(
    commitment_keys: Sequence[Element],
    trapdoors: Sequence[Scalar],
    openings: Sequence[Scalar],
    new: Sequence[bytes],
    index: int,
) -> list[Scalar]:
    V = [b"" for _ in new]
    V[index] = new[index]
    return VecEquivocate(
        commitment_keys, trapdoors, openings, V, new, index
    )


def ProveIssuer(
    anchor_set: Sequence[Element],
    index: int,
    delta: Scalar,
    X_hat: Element,
    token: Token,
    ctx_iss: bytes,
    ctx_red: bytes,
    challenge_digest: bytes,
    rand: bytes,
) -> tuple[Scalar, Scalar, Sequence[Element], Sequence[Scalar]]:
    Y = Statements(anchor_set, X_hat)
    q = Depth(len(anchor_set))
    if not 0 <= index < len(anchor_set):
        raise ValueError("index is outside the Anchor Set")
    if len(rand) != Nseed:
        raise ValueError("invalid issuer proof randomness length")

    instance = ProofStatement(
        anchor_set,
        X_hat,
        token,
        ctx_iss,
        ctx_red,
        challenge_digest,
    )
    derived = G.DeriveNonces(
        G.SerializeScalar(delta) + I2OSP(index, 2),
        b"ProveIssuer",
        instance,
        rand,
        2 * q + 1,
    )
    r = derived[0]
    trapdoors = derived[1 : q + 1]
    first_openings = derived[q + 1 :]
    A = B * r

    commitment_keys = GenerateVecBind(index, trapdoors)
    # First move: commit along the binding path; other leaves empty.
    root = CommitValAtPlace(
        commitment_keys,
        len(Y),
        index,
        G.SerializeElement(A),
        first_openings,
    )

    proof_challenge = ComputeProofChallenge(
        anchor_set,
        X_hat,
        token,
        ctx_iss,
        ctx_red,
        challenge_digest,
        commitment_keys,
        root,
    )

    response = r - proof_challenge * delta

    V = []
    for i in range(len(Y)):
        commitment = BranchCommitment(proof_challenge, response, Y[i])
        V.append(G.SerializeElement(commitment))
    openings = VecEquivocateFromZero(
        commitment_keys, trapdoors, first_openings, V, index
    )

    return (proof_challenge, response, commitment_keys, openings)


def VerifyIssuer(
    anchor_set: Sequence[Element],
    X_hat: Element,
    token: Token,
    ctx_iss: bytes,
    ctx_red: bytes,
    challenge_digest: bytes,
    proof_challenge: Scalar,
    response: Scalar,
    commitment_keys: Sequence[Element],
    openings: Sequence[Scalar],
) -> bool:
    n = len(anchor_set)
    if n == 0:
        return False

    Y = Statements(anchor_set, X_hat)
    q = Depth(n)
    if len(commitment_keys) != q:
        return False
    if len(openings) != q:
        return False

    T = []
    for i in range(n):
        commitment = BranchCommitment(proof_challenge, response, Y[i])
        if commitment.isIdentity():
            return False
        T.append(G.SerializeElement(commitment))

    root = VecCommit(T, commitment_keys, openings)

    return proof_challenge == ComputeProofChallenge(
        anchor_set,
        X_hat,
        token,
        ctx_iss,
        ctx_red,
        challenge_digest,
        commitment_keys,
        root,
    )


def Redeem(
    anchor_set: Sequence[Element],
    index: int,
    token: Token,
    ctx_iss: bytes,
    ctx_red: bytes,
    challenge_digest: bytes,
) -> Endorsement:
    (c, s, y, t, nf) = token
    n = len(anchor_set)

    if not 0 <= index < n:
        raise ValueError("index is outside the Anchor Set")

    rand = random(2 * Nseed)
    (delta,) = G.DeriveScalars(Seed(rand, 0), b"delta", 1)

    X_hat = anchor_set[index] + delta * B
    s_hat = s + (c * y) * delta
    shown = Token(c, s_hat, y, t, nf)

    (proof_challenge, response, commitment_keys, openings) = ProveIssuer(
        anchor_set,
        index,
        delta,
        X_hat,
        shown,
        ctx_iss,
        ctx_red,
        challenge_digest,
        Seed(rand, 1),
    )

    return Endorsement(
        X_hat,
        shown,
        proof_challenge,
        response,
        commitment_keys,
        openings,
    )


def VerifyEndorsement(
    anchor_set: Sequence[Element],
    endorsement: Endorsement,
    ctx_iss: bytes,
    ctx_red: bytes,
    challenge_digest: bytes,
) -> bytes:
    (
        X_hat,
        shown,
        proof_challenge,
        response,
        commitment_keys,
        openings,
    ) = endorsement

    if not Verify(X_hat, shown, ctx_iss, ctx_red):
        raise VerifyError

    if not VerifyIssuer(
        anchor_set,
        X_hat,
        shown,
        ctx_iss,
        ctx_red,
        challenge_digest,
        proof_challenge,
        response,
        commitment_keys,
        openings,
    ):
        raise VerifyError

    return shown.nf
