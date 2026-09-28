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


@pytest.mark.parametrize("bind_left", [False, True])
def test_generate_step_preserves_key_and_trapdoor(bind_left):
    seed = bytes(range(protocol.Nseed))
    secret = protocol.G.DeriveScalar(seed, b"GenerateStep")
    T = secret * protocol.B
    expected = protocol.G.Pinv(T) if bind_left else T
    assert protocol.GenerateStep(bind_left, seed) == (expected, secret)


@pytest.mark.parametrize("bind_left", ["left", "right", None, 0, 1])
def test_generate_step_rejects_non_boolean_direction(bind_left):
    with pytest.raises(ValueError, match="bind_left must be a boolean"):
        seed = random(protocol.Nseed)
        protocol.GenerateStep(bind_left, seed)


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


@pytest.mark.parametrize("size", [2, 3, 8])
def test_redemption_matches_previous_key_generation(monkeypatch, size):
    _, pkA, endorsement = _issue()
    calls = []

    def fixed_random(length):
        calls.append(length)
        return bytes(i % 256 for i in range(length))

    def previous_generate_step(bind_left, seed):
        secret = protocol.G.DeriveScalar(seed, b"GenerateStep")
        T = secret * protocol.B
        return (protocol.G.Pinv(T) if bind_left else T, secret)

    monkeypatch.setattr(protocol, "random", fixed_random)
    for index in range(size):
        anchor_set = [
            protocol.G.ScalarMultGen(protocol.Scalar(1000 + i))
            for i in range(size)
        ]
        anchor_set[index] = pkA
        args = (anchor_set, index, endorsement, b"epoch-1", b"moderator-1", b"digest")
        calls.clear()
        redemption = protocol.Redeem(*args)
        with monkeypatch.context() as previous:
            previous.setattr(protocol, "GenerateStep", previous_generate_step)
            assert redemption == protocol.Redeem(*args)
        q = (size - 1).bit_length()
        assert calls == [(2 * q + 2) * protocol.Nseed] * 2
        assert protocol.VerifyRedemption(
            anchor_set, redemption, b"epoch-1", b"moderator-1", b"digest"
        ) == endorsement.nf



def test_depth():
    for n in range(1, 130):
        assert protocol.Depth(n) == (n - 1).bit_length()


def _tampered_redemptions(anchor_set, index, redemption):
    G = protocol.G
    one = protocol.Scalar(1)
    shown = redemption.shown
    keys = list(redemption.commitment_keys)
    openings = list(redemption.openings)
    others = [a for i, a in enumerate(anchor_set) if i != index]
    ok = (b"epoch-1", b"moderator-1", b"digest")
    yield "reordered anchor set", anchor_set[::-1], redemption, ok
    yield "anchor removed", others + [G.Generator()], redemption, ok
    yield "other ctx_iss", anchor_set, redemption, (b"epoch-2",) + ok[1:]
    yield "other ctx_red", anchor_set, redemption, (ok[0], b"moderator-2", ok[2])
    yield "other challenge_digest", anchor_set, redemption, ok[:2] + (b"x",)
    for name, changed in [
        ("X_hat", redemption._replace(X_hat=redemption.X_hat + G.Generator())),
        ("c", redemption._replace(shown=shown._replace(c=shown.c + one))),
        ("s_hat", redemption._replace(shown=shown._replace(s=shown.s + one))),
        ("y", redemption._replace(shown=shown._replace(y=shown.y + one))),
        ("t", redemption._replace(shown=shown._replace(t=shown.t + one))),
        ("nf", redemption._replace(shown=shown._replace(nf=bytes(32)))),
        ("proof_challenge", redemption._replace(
            proof_challenge=redemption.proof_challenge + one)),
        ("response", redemption._replace(response=redemption.response + one)),
    ]:
        yield name, anchor_set, changed, ok
    for j in range(len(keys)):
        swapped = keys[:j] + [keys[j] + G.Generator()] + keys[j + 1 :]
        yield f"key {j}", anchor_set, redemption._replace(
            commitment_keys=swapped), ok
        shifted = openings[:j] + [openings[j] + one] + openings[j + 1 :]
        yield f"opening {j}", anchor_set, redemption._replace(
            openings=shifted), ok
    if len(keys) > 1:
        yield "keys reversed", anchor_set, redemption._replace(
            commitment_keys=keys[::-1]), ok
    yield "key dropped", anchor_set, redemption._replace(
        commitment_keys=keys[1:]), ok


@pytest.mark.parametrize("size, index", [(2, 0), (3, 2), (5, 1), (5, 4), (8, 3)])
def test_redemption_rejects_tampering(size, index):
    _, pkA, endorsement = _issue()
    anchor_set = [
        protocol.G.ScalarMultGen(protocol.Scalar(1000 + i)) for i in range(size)
    ]
    anchor_set[index] = pkA
    redemption = protocol.Redeem(
        anchor_set, index, endorsement, b"epoch-1", b"moderator-1", b"digest"
    )
    for name, anchors, tampered, (ctx_iss, ctx_red, digest) in (
        _tampered_redemptions(anchor_set, index, redemption)
    ):
        try:
            protocol.VerifyRedemption(anchors, tampered, ctx_iss, ctx_red, digest)
        except VerifyError:
            continue
        pytest.fail(f"accepted a tampered redemption: {name}")


def test_verify_rejects_identity_commitment():
    # A Client that knows the discrete logarithm x of the key it presents
    # reaches A = identity with s = c * y * x.
    G = protocol.G
    x = G.DeriveScalar(bytes(48), b"x")
    c, y, t = protocol.Scalar(5), protocol.Scalar(7), protocol.Scalar(9)
    shown = Endorsement(c, c * y * x, y, t, bytes(32))
    assert not Verify(x * protocol.B, shown, b"epoch-1", b"moderator-1")

    anchor_set = [G.ScalarMultGen(protocol.Scalar(i)) for i in (2, 3)]
    redemption = protocol.Redemption(
        x * protocol.B, shown, protocol.Scalar(1), protocol.Scalar(1),
        [anchor_set[0]], [protocol.Scalar(1)],
    )
    with pytest.raises(VerifyError):
        protocol.VerifyRedemption(
            anchor_set, redemption, b"epoch-1", b"moderator-1", b"d"
        )


def test_verify_issuer_rejects_identity_branch_commitment():
    # With X_hat = pkA, Y[0] is the identity, and a zero response makes the
    # branch commitment of that branch the identity too.
    _, pkA, endorsement = _issue()
    anchor_set = [pkA, protocol.G.ScalarMultGen(protocol.Scalar(2))]
    args = (anchor_set, pkA, endorsement, b"epoch-1", b"moderator-1", b"d")
    assert Verify(pkA, endorsement, b"epoch-1", b"moderator-1")
    assert not protocol.VerifyIssuer(
        *args, protocol.Scalar(1), protocol.Scalar(0),
        [pkA], [protocol.Scalar(1)],
    )
    redemption = protocol.Redemption(
        pkA, endorsement, protocol.Scalar(1), protocol.Scalar(0),
        [pkA], [protocol.Scalar(1)],
    )
    with pytest.raises(VerifyError):
        protocol.VerifyRedemption(
            anchor_set, redemption, b"epoch-1", b"moderator-1", b"d"
        )
