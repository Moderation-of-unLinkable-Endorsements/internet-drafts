import pytest

import ihat.protocol as protocol
from ihat.protocol import (
    Challenge,
    Commit,
    Endorsement,
    Finalize,
    ProveIssuer,
    Respond,
    Response,
    Verify,
    VerifyError,
    GenerateVecBind,
    CommitValAtPlace,
    VecEquivocateFromZero,
    VecCommit,
)

from ihat.common import random

def _issue(ctx_iss=b"epoch-1", ctx_red=b"moderator-1"):
    skA, pkA = protocol.G.DeriveKeyPair(bytes(range(48)), b"anchor")
    anchor_state, commitment = Commit(ctx_iss)
    client_state, challenge = Challenge(pkA, ctx_iss, ctx_red, commitment)
    response = Respond(skA, anchor_state, challenge)
    endorsement = Finalize(pkA, client_state, response)
    return skA, pkA, endorsement


def test_honest_issuance_verifies():
    _, pkA, endorsement = _issue()
    assert Verify(pkA, endorsement, b"epoch-1", b"moderator-1")


def test_both_contexts_are_bound():
    _, pkA, endorsement = _issue()
    assert not Verify(pkA, endorsement, b"epoch-2", b"moderator-1")
    assert not Verify(pkA, endorsement, b"epoch-1", b"moderator-2")


def test_endorsement_tampering_fails():
    _, pkA, endorsement = _issue()
    changed = Endorsement(
        endorsement.c,
        endorsement.s + protocol.G.scalar(1),
        endorsement.y,
        endorsement.t,
        endorsement.nf,
    )
    assert not Verify(pkA, changed, b"epoch-1", b"moderator-1")


def test_finalize_rejects_false_response():
    skA, pkA = protocol.G.DeriveKeyPair(bytes(range(48)), b"anchor")
    anchor_state, commitment = Commit(b"epoch-1")
    client_state, challenge = Challenge(pkA, b"epoch-1", b"moderator", commitment)
    response = Respond(skA, anchor_state, challenge)
    false_response = Response(
        response.s, response.y + protocol.G.scalar(1), response.t
    )
    with pytest.raises(VerifyError):
        Finalize(pkA, client_state, false_response)


def test_respond_rejects_zero_challenge():
    skA, _ = protocol.G.DeriveKeyPair(bytes(range(48)), b"anchor")
    state, _ = Commit(b"epoch-1")
    with pytest.raises(VerifyError):
        Respond(skA, state, protocol.G.scalar(0))


# TODO: Remove these smoke tests once end-to-end tests exercise these functions.
def test_commit_step_runs_without_raising(monkeypatch):
    monkeypatch.setattr(protocol.G, "P", lambda point: point)
    protocol.CommitStep(
        protocol.G.Generator(),
        bytes(protocol.Nseed),
        bytes([1]) * protocol.Nseed,
        protocol.Scalar(1),
    )


@pytest.mark.parametrize("bind_direction", ["left", "right"])
def test_generate_step_runs_without_raising(monkeypatch, bind_direction):
    seed = random(protocol.Nseed)
    protocol.GenerateStep(bind_direction, seed)


def test_generate_step_rejects_invalid_direction():
    with pytest.raises(ValueError, match="bind_direction must be 'left' or 'right'"):
        seed = random(protocol.Nseed)
        protocol.GenerateStep("invalid", seed)


def test_equivocate_step_runs_without_raising():
    protocol.EquivocateStep(
        b"1",
        b"2",
        protocol.Scalar(3),
        protocol.Scalar(4),
    )


def test_vec_commit_runs_without_raising(monkeypatch):
    protocol.VecCommit(
        [bytes(protocol.Nseed), bytes([1]) * protocol.Nseed],
        [protocol.G.Generator()],
        [protocol.Scalar(1)],
    )


def test_compute_proof_challenge_runs_without_raising():
    _, pkA, endorsement = _issue()
    protocol.ComputeProofChallenge(
        [pkA, protocol.G.ScalarMultGen(protocol.Scalar(2))],
        pkA,
        endorsement,
        b"epoch-1",
        b"moderator-1",
        b"challenge-digest",
        [protocol.G.Generator()],
        protocol.G.SerializeElement(protocol.G.Generator()),
    )


def test_prove_issuer_runs_without_raising(monkeypatch):
    _, pkA, endorsement = _issue()
    delta = protocol.Scalar(3)
    X_hat = pkA + delta * protocol.G.Generator()

    ProveIssuer(
        [pkA, protocol.G.ScalarMultGen(protocol.Scalar(2))],
        0,
        delta,
        X_hat,
        endorsement,
        b"epoch-1",
        b"moderator-1",
        b"challenge-digest",
        bytes(3 * protocol.Nseed),
    )


def test_verify_issuer_runs_without_raising(monkeypatch):
    _, pkA, endorsement = _issue()
    anchor_set = [pkA, protocol.G.ScalarMultGen(protocol.Scalar(2))]

    protocol.VerifyIssuer(
        anchor_set,
        pkA,
        endorsement,
        b"epoch-1",
        b"moderator-1",
        b"challenge-digest",
        protocol.Scalar(1),
        protocol.Scalar(2),
        [protocol.G.Generator()],
        [protocol.Scalar(3)],
    )


def test_redeem_runs_without_raising(monkeypatch):
    _, pkA, endorsement = _issue()
    anchor_set = [pkA, protocol.G.ScalarMultGen(protocol.Scalar(2))]

    monkeypatch.setattr(
        protocol,
        "ProveIssuer",
        lambda *args: (
            protocol.Scalar(1),
            protocol.Scalar(2),
            [protocol.G.Generator()],
            [protocol.Scalar(3)],
        ),
    )

    protocol.Redeem(
        anchor_set,
        0,
        endorsement,
        b"epoch-1",
        b"moderator-1",
        b"challenge-digest",
    )


def test_verify_redemption_runs_without_raising(monkeypatch):
    _, pkA, endorsement = _issue()
    anchor_set = [pkA, protocol.G.ScalarMultGen(protocol.Scalar(2))]
    delta = protocol.Scalar(3)
    X_hat = pkA + delta * protocol.G.Generator()
    shown = Endorsement(
        endorsement.c,
        endorsement.s + (endorsement.c * endorsement.y) * delta,
        endorsement.y,
        endorsement.t,
        endorsement.nf,
    )
    redemption = protocol.Redemption(
        X_hat,
        shown,
        protocol.Scalar(1),
        protocol.Scalar(2),
        [protocol.G.Generator()],
        [protocol.Scalar(3)],
    )

    monkeypatch.setattr(protocol, "VerifyIssuer", lambda *args: True)

    protocol.VerifyRedemption(
        anchor_set,
        redemption,
        b"epoch-1",
        b"moderator-1",
        b"challenge-digest",
    )


def test_verify_rejects_identity_public_key_and_bad_nullifier_length():
    _, pkA, endorsement = _issue()
    assert not Verify(protocol.G.Identity(), endorsement, b"epoch-1", b"moderator-1")
    malformed = Endorsement(*endorsement[:4], b"short")
    assert not Verify(pkA, malformed, b"epoch-1", b"moderator-1")


def test_message_rejects_bad_nullifier_length():
    with pytest.raises(ValueError):
        protocol.Message(b"short", b"moderator-1")


def test_prove_issuer_rejects_bad_index_and_randomness_length():
    _, pkA, endorsement = _issue()
    anchor_set = [pkA, protocol.G.ScalarMultGen(protocol.Scalar(2))]
    delta = protocol.Scalar(3)
    X_hat = pkA + delta * protocol.B
    args = (
        anchor_set,
        0,
        delta,
        X_hat,
        endorsement,
        b"epoch-1",
        b"moderator-1",
        b"challenge-digest",
    )

    with pytest.raises(ValueError, match="index"):
        ProveIssuer(*args[:1], 2, *args[2:], bytes(3 * protocol.Nseed))
    with pytest.raises(ValueError, match="randomness"):
        ProveIssuer(*args, bytes(3 * protocol.Nseed - 1))


def test_redeem_rejects_bad_index():
    _, pkA, endorsement = _issue()
    anchor_set = [pkA, protocol.G.ScalarMultGen(protocol.Scalar(2))]

    with pytest.raises(ValueError, match="index"):
        protocol.Redeem(
            anchor_set,
            len(anchor_set),
            endorsement,
            b"epoch-1",
            b"moderator-1",
            b"challenge-digest",
        )

def test_vector_commitment_comprehensive():
    for i in range(2, 16):
        q = 0
        while 2**q < i:
            q += 1
        for j in range(0, i):
            keys, trapdoor = GenerateVecBind(q, j, random(q * 48))
            comm, opening = CommitValAtPlace(
                keys, i, j, b"Bob", random(q * 48)
            )
            V = [random(32) for i in range(0, i)]
            V[j] = b"Bob"
            newopen = VecEquivocateFromZero(keys, trapdoor, opening, V, j)
            comm2 = VecCommit(V, keys, newopen)
            assert comm == comm2

def test_verify_end_to_end():
    _, pkA, endorsement = _issue()
    anchor_set = [pkA, protocol.G.ScalarMultGen(protocol.Scalar(2))]
    redemption = protocol.Redeem(
        anchor_set,
        0,
        endorsement,
        b"epoch-1",
        b"moderator-1",
        b"challenge-digest",
    )

    protocol.VerifyRedemption(
        anchor_set,
        redemption,
        b"epoch-1",
        b"moderator-1",
        b"challenge-digest",
    )


