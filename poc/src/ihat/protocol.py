"""IHAT algorithms transcribed from draft-authors-mole-ihat.md."""

from __future__ import annotations

from typing import NamedTuple, Sequence
from Cryptodome.Protocol.KDF import HKDF
from Cryptodome.Hash import SHA256

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

def to_bin(n: int, q: int) -> list[int]:
    return [int(b) for b in format(n, f'0{q}b')]

class VerifyError(Exception):
    """A received value failed a verification check."""


class SessionError(Exception):
    """A session is not in the expected state."""

class DeriveError(Exception):
    """We failed to derive a scalar"""


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

def DeriveSeed(oldseed: bytes, info: bytes)->bytes:
    ret = HKDF(oldseed, Nseed, info, SHA256)
    return bytes(ret) # type: ignore

def DeriveScalar(seed: bytes, info: bytes) -> Scalar:
    if len(seed) != Nseed:
        raise ValueError(f"seed must be exactly {Nseed} bytes")
    derive_input = seed + U16Prefixed(info)
    for counter in range(256):
        s = G.HashToScalar(
            derive_input + I2OSP(counter, 1),
            DST=b"DeriveScalar-" + ctx_proto,
        )
        if not s.isZero():
            return s
    raise DeriveError


def DeriveKeyPair(seed: bytes, info: bytes) -> tuple[Scalar, Element]:
    skA = DeriveScalar(seed, info)
    pkA = G.ScalarMultGen(skA)
    return (skA, pkA)


def GenerateKeyPair() -> tuple[Scalar, Element]:
    seed = random(Nseed)
    return DeriveKeyPair(seed, b"GenerateKeyPair")


def CreateContextBase(ctx_iss: bytes) -> Element:
    context_base_input = U16Prefixed(ctx_iss) + b"ContextBase"
    return G.HashToGroup(context_base_input)


def Message(nf: bytes, ctx_red: bytes) -> bytes:
    if len(nf) != Nn:
        raise ValueError(f"nullifier must be exactly {Nn} bytes")
    return U16Prefixed(nf) + U16Prefixed(ctx_red)


def Commit(ctx_iss: bytes) -> tuple[AnchorState, Commitment]:
    Z = CreateContextBase(ctx_iss)

    rand = random(3 * Nseed)
    a = G.DeriveScalar(Seed(rand, 0), b"a")
    t = G.DeriveScalar(Seed(rand, 1), b"t")
    y = G.DeriveScalar(Seed(rand, 2), b"y")

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

    rand = random(Nn + 4 * Nseed)
    nf = rand[:Nn]
    seeds = rand[Nn:]

    r1 = G.DeriveScalar(Seed(seeds, 0), b"r1")
    r2 = G.DeriveScalar(Seed(seeds, 1), b"r2")
    gamma1 = G.DeriveScalar(Seed(seeds, 2), b"gamma1")
    gamma2 = G.DeriveScalar(Seed(seeds, 3), b"gamma2")

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


def Finalize(pkA: Element, state: ClientState, response: Response) -> Endorsement:
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

    return Endorsement(c, s_final, y_final, t_final, nf)


def Verify(
    pkA: Element,
    endorsement: Endorsement,
    ctx_iss: bytes,
    ctx_red: bytes,
) -> bool:
    if pkA.isIdentity():
        return False

    (c, s, y, t, nf) = endorsement

    if len(nf) != Nn or c.isZero() or y.isZero():
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

    return (Y, q)


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


def GenerateStep(bind_direction: str, seed: bytes) -> tuple[Element, Scalar]:
    secret = DeriveScalar(seed, b"GenerateStep")
    T = secret * B
    if bind_direction == "left":
        return (G.Pinv(T), secret)
    elif bind_direction == "right":
        return (T, secret)
    else:
        raise ValueError("bind_direction must be 'left' or 'right'")


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
        + root
        + b"IssuerProof"
    )

    return G.HashToScalar(proof_transcript)


def GenerateVecBind(q, index, rand):
    bits = to_bin(index, q)
    params = []
    traps = []
    bits.reverse()
    for b in bits:
        rand = DeriveSeed(rand, b"GenerateVecBind")
        seed = DeriveSeed(rand, b"generate step")
        if b == 0:
            p, t = GenerateStep("left", seed)
            params.append(p)
            traps.append(t)
        else:
            p, t = GenerateStep("right", seed)
            params.append(p)
            traps.append(t)
    return params, traps


def CommitValAtPlace(commitment_keys, length, index, value, seed):
    V = [b"" for x in range(length)]
    V[index] = value
    rands = []
    for k in commitment_keys:
        seed = DeriveSeed(seed, b"CommitValAtPlace")
        rands.append(DeriveScalar(seed, b"derived rand"))
    return VecCommit(V, commitment_keys, rands), rands


def VecEquivocate(commitment_keys, trapdoor, openings,  oldvalues, newvalues, index):
    newopen = 0
    partner = index
    if len(oldvalues) != len(newvalues):
        raise ValueError("lengths should match")
    if oldvalues[index] != newvalues[index]:
        raise ValueError("we have to match at index")
    if len(oldvalues) == 1:
        return []
    if len(oldvalues) - 1 == index and len(oldvalues) %2 == 1:
        newopen = openings[0]
    else:
        if index % 2 == 1:
            partner = index - 1
        else:
            partner = index +1
        newopen = EquivocateStep(oldvalues[partner], newvalues[partner], openings[0], trapdoor[0])
    oldprime = []
    newprime = []
    for i in range(len(oldvalues) // 2):
        newprime.append(CommitStep(commitment_keys[0], newvalues[2 * i], newvalues[2 * i + 1], newopen))
        oldprime.append(CommitStep(commitment_keys[0], oldvalues[2 *i], oldvalues[2 * i +1], openings[0]))
    if len(oldvalues) % 2 == 1:
        newprime.append(newvalues[-1])
        oldprime.append(oldvalues[-1])
    rest = VecEquivocate(commitment_keys[1:], trapdoor[1:], openings[1:], oldprime, newprime, index//2)
    rest.insert(0, newopen)
    return rest

def VecEquivocateFromZero(keys, trapdoor, first_open, new, index):
    V = [b"" for x in new]
    V[index]=new[index]
    return VecEquivocate(keys, trapdoor, first_open, V, new, index)
        
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
    if not 0 <= index < len(anchor_set):
        raise ValueError("index is outside the Anchor Set")
    if len(rand) != (3 * q + 1) * Nseed:
        raise ValueError("invalid issuer proof randomness length")

    rand = DeriveSeed(rand, b"ProveIssuer")
    r = DeriveScalar(Seed(rand, 0), b"r")
    A = B * r

    (commitment_keys, trapdoor) = GenerateVecBind(q, index, rand)
    rand = DeriveSeed(rand, b"CommitAtPlace")
    # First move: commit along the binding path, sibling value zero.
    (root, first_open) = CommitValAtPlace(commitment_keys, len(Y), index, G.SerializeElement(A), rand)

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
        commitment = BranchCommitment(proof_challenge, response, Y[i])
        V.append(G.SerializeElement(commitment))
    openings = VecEquivocateFromZero(commitment_keys, trapdoor, first_open, V, index)

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
        commitment = BranchCommitment(proof_challenge, response, Y[i])
        T.append(G.SerializeElement(commitment))

    root = VecCommit(T, commitment_keys, openings)

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
    if not 0 <= index < n:
        raise ValueError("index is outside the Anchor Set")

    (Y, q) = Statements(anchor_set, G.Identity())
    nrand = (3 * q + 2) * Nseed

    rand = random(nrand)
    delta = G.DeriveScalar(Seed(rand, 0), b"delta")

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
