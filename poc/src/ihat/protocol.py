"""IHAT algorithms transcribed from draft-authors-mole-crypto.md."""

from __future__ import annotations

from typing import NamedTuple, Sequence

from .ciphersuite import P256Element as Element
from .ciphersuite import P256Group, P256Scalar as Scalar
from .common import CreateProtocolContext, I2OSP, U16Prefixed, random


Nn = 32
Nseed = 48
ctx_proto = CreateProtocolContext(b"P256-SHA256")
G = P256Group(ctx_proto)
B = G.Generator()


class VerifyError(Exception):
    """A received value failed a verification check."""


class SessionError(Exception):
    """A session is not in the expected state."""


class DeriveError(Exception):
    """A deterministic derivation failed to produce a usable scalar."""


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


class Endorsement(NamedTuple):
    c: Scalar
    s: Scalar
    y: Scalar
    t: Scalar
    nf: bytes


class Redemption(NamedTuple):
    X_hat: Element
    shown: Endorsement
    proof_challenge: Scalar
    response: Scalar
    commitment_keys: Sequence[Element]
    openings: Sequence[Scalar]


def Seed(value: bytes, index: int) -> bytes:
    return value[index * Nseed : (index + 1) * Nseed]


def DeriveScalar(seed: bytes, info: bytes) -> Scalar:
    if len(seed) != Nseed:
        raise ValueError(f"seed must be exactly {Nseed} bytes")
    derive_input = seed + U16Prefixed(info)
    for counter in range(256):
        scalar = G.HashToScalar(
            derive_input + I2OSP(counter, 1),
            DST=b"DeriveScalar-" + ctx_proto,
        )
        if not scalar.is_zero():
            return scalar
    raise DeriveError


def DeriveKeyPair(seed: bytes, info: bytes) -> tuple[Scalar, Element]:
    skA = DeriveScalar(seed, info)
    return skA, G.ScalarMultGen(skA)


def GenerateKeyPair() -> tuple[Scalar, Element]:
    return DeriveKeyPair(random(Nseed), b"GenerateKeyPair")


def CreateContextBase(ctx_iss: bytes) -> Element:
    context_base_input = U16Prefixed(ctx_iss) + b"ContextBase"
    return G.HashToGroup(context_base_input)


def Message(nf: bytes, ctx_red: bytes) -> bytes:
    return U16Prefixed(nf) + U16Prefixed(ctx_red)


def Commit(ctx_iss: bytes) -> tuple[AnchorState, Commitment]:
    Z = CreateContextBase(ctx_iss)

    rand = random(3 * Nseed)
    a = DeriveScalar(Seed(rand, 0), b"a")
    t = DeriveScalar(Seed(rand, 1), b"t")
    y = DeriveScalar(Seed(rand, 2), b"y")

    A = G.ScalarMultGen(a)
    C = G.ScalarMultGen(t) + y * Z

    return (AnchorState(a, y, t), Commitment(A, C))


def Challenge(
    pkA: Element,
    ctx_iss: bytes,
    ctx_red: bytes,
    commitment: Commitment,
) -> tuple[ClientState, Scalar]:
    if pkA.is_identity():
        raise VerifyError

    (A, C) = commitment

    rand = random(Nn + 4 * Nseed)
    nf = rand[:Nn]
    seeds = rand[Nn:]

    r1 = DeriveScalar(Seed(seeds, 0), b"r1")
    r2 = DeriveScalar(Seed(seeds, 1), b"r2")
    gamma1 = DeriveScalar(Seed(seeds, 2), b"gamma1")
    gamma2 = DeriveScalar(Seed(seeds, 3), b"gamma2")

    m = Message(nf, ctx_red)
    gamma = gamma1 * G.ScalarInverse(gamma2)

    blinded_A = G.ScalarMultGen(r1) + gamma * A
    blinded_C = gamma1 * C + G.ScalarMultGen(r2)

    c = ComputeChallenge(ctx_iss, Commitment(blinded_A, blinded_C), m)
    if c.is_zero():
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

    if challenge.is_zero():
        raise VerifyError

    s = a + challenge * y * skA
    response = Response(s, y, t)

    return response


def Finalize(pkA: Element, state: ClientState, response: Response) -> Endorsement:
    if pkA.is_identity():
        raise VerifyError

    (nf, ctx_iss, (A, C), r1, r2, gamma1, gamma2, challenge, c) = state
    (s, y, t) = response

    Z = CreateContextBase(ctx_iss)

    if y.is_zero():
        raise VerifyError
    if C != G.ScalarMultGen(t) + y * Z:
        raise VerifyError
    if G.ScalarMultGen(s) != A + (challenge * y) * pkA:
        raise VerifyError

    gamma = gamma1 * G.ScalarInverse(gamma2)

    s_final = gamma * s + r1
    y_final = gamma1 * y
    t_final = gamma1 * t + r2

    return Endorsement(c, s_final, y_final, t_final, nf)


def Verify(
    pkA: Element,
    endorsement: Endorsement,
    ctx_iss: bytes,
    ctx_red: bytes,
) -> bool:
    if pkA.is_identity():
        return False

    (c, s, y, t, nf) = endorsement

    if c.is_zero() or y.is_zero():
        return False

    Z = CreateContextBase(ctx_iss)
    m = Message(nf, ctx_red)

    C = G.ScalarMultGen(t) + y * Z
    A = G.ScalarMultGen(s) - (c * y) * pkA
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
) -> tuple[list[Element], int]:
    n = len(anchor_set)
    q = 0
    while 2**q < n:
        q += 1

    Y = [X_hat - pkA for pkA in anchor_set]

    # XXX Should q be a scalar?
    return (Y, q)


def CommitStep(
    Q: Element,
    left: bytes,
    right: bytes,
    randomness: Scalar,
) -> bytes:
    C = (
        randomness * B
        + DeriveScalar(left, b"left") * Q
        + DeriveScalar(right, b"right") * G.P(Q)
    )
    return G.SerializeElement(C)


def GenerateStep(bind_direction: str) -> tuple[Element, Scalar]:
    secret = DeriveScalar(random(Nseed), b"TODO")
    T = secret * B
    if bind_direction == "left":
        return (G.Pinv(T), secret)
    elif bind_direction == "right":
        return (T, secret)
    else:
        raise NotImplementedError("TODO define an error for this")


def EquivocateStep(
    old: Scalar, new: Scalar, randomness: Scalar, secret: Scalar
) -> Scalar:
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
        # NOTE(GPT 5.6 Sol) The draft uses index len(V) / 2 + 1, which leaves
        # an undefined entry in a zero-based vector. Carrying the final value
        # contiguously is the apparent intent. The binding path through such a
        # carry is unclear.
        V_prime.append(V[-1])

    return VecCommit(V_prime, Qi[1:], rands[1:])


def EncodeNode(root: bytes) -> bytes:
    # TODO: EncodeNode is undefined after root changed from a pair of elements
    # to an already-encoded compact commitment. Treating it as the identity is
    # the apparent intent.
    return root


def ComputeProofChallenge(
    anchor_set: Sequence[Element],
    X_hat: Element,
    endorsement: Endorsement,
    ctx_iss: bytes,
    ctx_red: bytes,
    challenge_digest: bytes,
    commitment_keys: Sequence[Element],
    root: bytes,
) -> Scalar:
    (c, s_hat, y, t, nf) = endorsement
    n = len(anchor_set)

    anchor_set_enc = b""
    for i in range(n):
        anchor_set_enc += G.SerializeElement(anchor_set[i])

    ck_enc = b""
    for j in range(len(commitment_keys)):
        ck_enc += G.SerializeElement(commitment_keys[j])

    proof_transcript = (
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
        + ck_enc
        + EncodeNode(root)
        + b"IssuerProof"
    )

    return G.HashToScalar(proof_transcript)


def GenerateVecBind(q, index, rand):
    # TODO(wbl) Define the types of the inputs and outputs and specify this
    # function. It is currently referenced by ProveIssuer.
    raise NotImplementedError("GenerateVecBind is not specified")


def CommitValAtPlace(q, index, value):
    # TODO(wbl) Define the types of the inputs and outputs and specify this
    # function. It is currently referenced by ProveIssuer.
    raise NotImplementedError("CommitValAtPlace is not specified")


def VecEquivocate(trapdoor, values, index, original):
    # TODO(wbl) Define the types of the inputs and outputs and specify this
    # function. It is currently referenced by ProveIssuer.
    raise NotImplementedError("VecEquivocate is not specified")


def ProveIssuer(
    anchor_set: Sequence[Element],
    index: int,
    delta: Scalar,
    X_hat: Element,
    endorsement: Endorsement,
    ctx_iss: bytes,
    ctx_red: bytes,
    challenge_digest: bytes,
    rand: bytes,
) -> tuple[Scalar, Scalar, Sequence[Element], Sequence[Scalar]]:
    (Y, q) = Statements(anchor_set, X_hat)

    # TODO Consume the randomness from `rand`.
    r = DeriveScalar(random(Nseed), b"TODO")
    A = B * r

    (commitment_keys, trapdoor) = GenerateVecBind(q, index, rand)
    # First move: commit along the binding path, sibling value zero.
    (root, first_open) = CommitValAtPlace(q, index, G.SerializeElement(A))

    proof_challenge = ComputeProofChallenge(
        anchor_set,
        X_hat,
        endorsement,
        ctx_iss,
        ctx_red,
        challenge_digest,
        commitment_keys,
        root,
    )

    response = r - proof_challenge * delta

    V = []
    for i in range(len(Y)):
        V.append(BranchCommitment(proof_challenge, response, Y[i]))
    openings = VecEquivocate(trapdoor, V, index, G.SerializeElement(A))

    return (proof_challenge, response, commitment_keys, openings)


def VerifyIssuer(
    anchor_set: Sequence[Element],
    X_hat: Element,
    endorsement: Endorsement,
    ctx_iss: bytes,
    ctx_red: bytes,
    challenge_digest: bytes,
    proof_challenge: Scalar,
    response: Scalar,
    commitment_keys: Sequence[Element],
    openings: Sequence[Scalar],
) -> bool:
    n = len(anchor_set)
    if n < 2:
        return False

    (Y, q) = Statements(anchor_set, X_hat)
    if len(commitment_keys) != q:
        return False
    if len(openings) != q:
        return False

    T = []
    for i in range(n):
        T.append(BranchCommitment(proof_challenge, response, Y[i]))

    # TODO(wbl) VecCommit is specified over byte strings, but the draft passes
    # the Element values returned by BranchCommitment without serializing them.
    root = VecCommit(T, commitment_keys, openings)  # type: ignore[arg-type]

    return proof_challenge == ComputeProofChallenge(
        anchor_set,
        X_hat,
        endorsement,
        ctx_iss,
        ctx_red,
        challenge_digest,
        commitment_keys,
        root,
    )


def Redeem(
    anchor_set: Sequence[Element],
    index: int,
    endorsement: Endorsement,
    ctx_iss: bytes,
    ctx_red: bytes,
    challenge_digest: bytes,
) -> Redemption:
    (c, s, y, t, nf) = endorsement
    n = len(anchor_set)

    if n < 2:
        raise VerifyError

    (Y, q) = Statements(anchor_set, G.Identity())
    nrand = (3 * q + 2) * Nseed

    rand = random(nrand)
    delta = DeriveScalar(Seed(rand, 0), b"delta")

    X_hat = anchor_set[index] + delta * B
    s_hat = s + (c * y) * delta
    shown = Endorsement(c, s_hat, y, t, nf)

    (proof_challenge, response, commitment_keys, openings) = ProveIssuer(
        anchor_set,
        index,
        delta,
        X_hat,
        shown,
        ctx_iss,
        ctx_red,
        challenge_digest,
        rand[Nseed:nrand],
    )

    return Redemption(
        X_hat,
        shown,
        proof_challenge,
        response,
        commitment_keys,
        openings,
    )


def VerifyRedemption(
    anchor_set: Sequence[Element],
    redemption: Redemption,
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
    ) = redemption

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
