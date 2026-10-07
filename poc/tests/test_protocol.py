import pytest

import rollatini.protocol as protocol
from rollatini.protocol import (
    Challenge,
    Commit,
    Token,
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

from rollatini.common import random

def _issue(ctx_iss=b"epoch-1", ctx_red=b"moderator-1"):
    skA, pkA = protocol.G.DeriveKeyPair(bytes(range(48)), b"anchor")
    anchor_state, commitment = Commit(ctx_iss)
    client_state, challenge = Challenge(pkA, ctx_iss, ctx_red, commitment)
    response = Respond(skA, anchor_state, challenge)
    token = Finalize(pkA, client_state, response)
    return skA, pkA, token


def test_honest_issuance_verifies():
    _, pkA, token = _issue()
    assert Verify(pkA, token, b"epoch-1", b"moderator-1")


def test_both_contexts_are_bound():
    _, pkA, token = _issue()
    assert not Verify(pkA, token, b"epoch-2", b"moderator-1")
    assert not Verify(pkA, token, b"epoch-1", b"moderator-2")


def test_token_tampering_fails():
    _, pkA, token = _issue()
    changed = Token(
        token.c,
        token.s + protocol.G.scalar(1),
        token.y,
        token.t,
        token.nf,
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
    secret = protocol.Scalar(12345)
    T = secret * protocol.B
    expected = protocol.G.Pinv(T) if bind_left else T
    assert protocol.GenerateStep(bind_left, secret) == expected


@pytest.mark.parametrize("bind_left", ["left", "right", None, 0, 1])
def test_generate_step_rejects_non_boolean_direction(bind_left):
    with pytest.raises(ValueError, match="bind_left must be a boolean"):
        protocol.GenerateStep(bind_left, protocol.Scalar(12345))


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
    _, pkA, token = _issue()
    protocol.ComputeProofChallenge(
        [pkA, protocol.G.ScalarMultGen(protocol.Scalar(2))],
        pkA,
        token,
        b"epoch-1",
        b"moderator-1",
        b"challenge-digest",
        [protocol.G.Generator()],
        protocol.G.SerializeElement(protocol.G.Generator()),
    )


def test_prove_issuer_runs_without_raising(monkeypatch):
    _, pkA, token = _issue()
    delta = protocol.Scalar(3)
    X_hat = pkA + delta * protocol.G.Generator()

    ProveIssuer(
        [pkA, protocol.G.ScalarMultGen(protocol.Scalar(2))],
        0,
        delta,
        X_hat,
        token,
        b"epoch-1",
        b"moderator-1",
        b"challenge-digest",
        bytes(protocol.Nseed),
    )


def test_verify_issuer_runs_without_raising(monkeypatch):
    _, pkA, token = _issue()
    anchor_set = [pkA, protocol.G.ScalarMultGen(protocol.Scalar(2))]

    protocol.VerifyIssuer(
        anchor_set,
        pkA,
        token,
        b"epoch-1",
        b"moderator-1",
        b"challenge-digest",
        protocol.Scalar(1),
        protocol.Scalar(2),
        [protocol.G.Generator()],
        [protocol.Scalar(3)],
    )


def test_redeem_runs_without_raising(monkeypatch):
    _, pkA, token = _issue()
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
        token,
        b"epoch-1",
        b"moderator-1",
        b"challenge-digest",
    )


def test_verify_endorsement_runs_without_raising(monkeypatch):
    _, pkA, token = _issue()
    anchor_set = [pkA, protocol.G.ScalarMultGen(protocol.Scalar(2))]
    delta = protocol.Scalar(3)
    X_hat = pkA + delta * protocol.G.Generator()
    shown = Token(
        token.c,
        token.s + (token.c * token.y) * delta,
        token.y,
        token.t,
        token.nf,
    )
    endorsement = protocol.Endorsement(
        X_hat,
        shown,
        protocol.Scalar(1),
        protocol.Scalar(2),
        [protocol.G.Generator()],
        [protocol.Scalar(3)],
    )

    monkeypatch.setattr(protocol, "VerifyIssuer", lambda *args: True)

    protocol.VerifyEndorsement(
        anchor_set,
        endorsement,
        b"epoch-1",
        b"moderator-1",
        b"challenge-digest",
    )


def test_verify_rejects_identity_public_key_and_bad_nullifier_length():
    _, pkA, token = _issue()
    assert not Verify(protocol.G.Identity(), token, b"epoch-1", b"moderator-1")
    malformed = Token(*token[:4], b"short")
    assert not Verify(pkA, malformed, b"epoch-1", b"moderator-1")


def test_message_rejects_bad_nullifier_length():
    with pytest.raises(ValueError):
        protocol.Message(b"short", b"moderator-1")


def test_prove_issuer_rejects_bad_index_and_randomness_length():
    _, pkA, token = _issue()
    anchor_set = [pkA, protocol.G.ScalarMultGen(protocol.Scalar(2))]
    delta = protocol.Scalar(3)
    X_hat = pkA + delta * protocol.B
    args = (
        anchor_set,
        0,
        delta,
        X_hat,
        token,
        b"epoch-1",
        b"moderator-1",
        b"challenge-digest",
    )

    with pytest.raises(ValueError, match="index"):
        ProveIssuer(*args[:1], 2, *args[2:], bytes(protocol.Nseed))
    with pytest.raises(ValueError, match="randomness"):
        ProveIssuer(*args, bytes(protocol.Nseed - 1))


def test_redeem_rejects_bad_index():
    _, pkA, token = _issue()
    anchor_set = [pkA, protocol.G.ScalarMultGen(protocol.Scalar(2))]

    with pytest.raises(ValueError, match="index"):
        protocol.Redeem(
            anchor_set,
            len(anchor_set),
            token,
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
            trapdoor = protocol.G.DeriveScalars(random(48), b"test", q)
            opening = protocol.G.DeriveScalars(random(48), b"test", q)
            keys = GenerateVecBind(j, trapdoor)
            comm = CommitValAtPlace(keys, i, j, b"Bob", opening)
            V = [random(32) for i in range(0, i)]
            V[j] = b"Bob"
            newopen = VecEquivocateFromZero(keys, trapdoor, opening, V, j)
            comm2 = VecCommit(V, keys, newopen)
            assert comm == comm2

def test_verify_end_to_end():
    _, pkA, token = _issue()
    anchor_set = [pkA, protocol.G.ScalarMultGen(protocol.Scalar(2))]
    endorsement = protocol.Redeem(
        anchor_set,
        0,
        token,
        b"epoch-1",
        b"moderator-1",
        b"challenge-digest",
    )

    protocol.VerifyEndorsement(
        anchor_set,
        endorsement,
        b"epoch-1",
        b"moderator-1",
        b"challenge-digest",
    )


@pytest.mark.parametrize("size", [2, 3, 8])
def test_redemption_matches_previous_key_generation(monkeypatch, size):
    _, pkA, token = _issue()
    calls = []

    def fixed_random(length):
        calls.append(length)
        return bytes(i % 256 for i in range(length))

    def previous_generate_step(bind_left, secret):
        T = secret * protocol.B
        return protocol.G.Pinv(T) if bind_left else T

    monkeypatch.setattr(protocol, "random", fixed_random)
    for index in range(size):
        anchor_set = [
            protocol.G.ScalarMultGen(protocol.Scalar(1000 + i))
            for i in range(size)
        ]
        anchor_set[index] = pkA
        args = (anchor_set, index, token, b"epoch-1", b"moderator-1", b"digest")
        calls.clear()
        endorsement = protocol.Redeem(*args)
        with monkeypatch.context() as previous:
            previous.setattr(protocol, "GenerateStep", previous_generate_step)
            assert endorsement == protocol.Redeem(*args)
        assert calls == [2 * protocol.Nseed] * 2
        assert protocol.VerifyEndorsement(
            anchor_set, endorsement, b"epoch-1", b"moderator-1", b"digest"
        ) == token.nf


def test_depth():
    for n in range(1, 130):
        assert protocol.Depth(n) == (n - 1).bit_length()


def _tampered_endorsements(anchor_set, index, endorsement):
    G = protocol.G
    one = protocol.Scalar(1)
    shown = endorsement.shown
    keys = list(endorsement.commitment_keys)
    openings = list(endorsement.openings)
    others = [a for i, a in enumerate(anchor_set) if i != index]
    ok = (b"epoch-1", b"moderator-1", b"digest")
    if len(anchor_set) > 1:
        yield "reordered anchor set", anchor_set[::-1], endorsement, ok
    yield "anchor removed", others + [G.Generator()], endorsement, ok
    yield "other ctx_iss", anchor_set, endorsement, (b"epoch-2",) + ok[1:]
    yield "other ctx_red", anchor_set, endorsement, (ok[0], b"moderator-2", ok[2])
    yield "other challenge_digest", anchor_set, endorsement, ok[:2] + (b"x",)
    for name, changed in [
        ("X_hat", endorsement._replace(X_hat=endorsement.X_hat + G.Generator())),
        ("c", endorsement._replace(shown=shown._replace(c=shown.c + one))),
        ("s_hat", endorsement._replace(shown=shown._replace(s=shown.s + one))),
        ("y", endorsement._replace(shown=shown._replace(y=shown.y + one))),
        ("t", endorsement._replace(shown=shown._replace(t=shown.t + one))),
        ("nf", endorsement._replace(shown=shown._replace(nf=bytes(32)))),
        ("proof_challenge", endorsement._replace(
            proof_challenge=endorsement.proof_challenge + one)),
        ("response", endorsement._replace(response=endorsement.response + one)),
    ]:
        yield name, anchor_set, changed, ok
    for j in range(len(keys)):
        swapped = keys[:j] + [keys[j] + G.Generator()] + keys[j + 1 :]
        yield f"key {j}", anchor_set, endorsement._replace(
            commitment_keys=swapped), ok
        shifted = openings[:j] + [openings[j] + one] + openings[j + 1 :]
        yield f"opening {j}", anchor_set, endorsement._replace(
            openings=shifted), ok
    if len(keys) > 1:
        yield "keys reversed", anchor_set, endorsement._replace(
            commitment_keys=keys[::-1]), ok
    if keys:
        yield "key dropped", anchor_set, endorsement._replace(
            commitment_keys=keys[1:]), ok
    yield "key added", anchor_set, endorsement._replace(
        commitment_keys=keys + [G.Generator()]), ok


@pytest.mark.parametrize(
    "size, index", [(1, 0), (2, 0), (3, 2), (5, 1), (5, 4), (8, 3)]
)
def test_redemption_rejects_tampering(size, index):
    _, pkA, token = _issue()
    anchor_set = [
        protocol.G.ScalarMultGen(protocol.Scalar(1000 + i)) for i in range(size)
    ]
    anchor_set[index] = pkA
    endorsement = protocol.Redeem(
        anchor_set, index, token, b"epoch-1", b"moderator-1", b"digest"
    )
    for name, anchors, tampered, (ctx_iss, ctx_red, digest) in (
        _tampered_endorsements(anchor_set, index, endorsement)
    ):
        try:
            protocol.VerifyEndorsement(anchors, tampered, ctx_iss, ctx_red, digest)
        except VerifyError:
            continue
        pytest.fail(f"accepted a tampered redemption: {name}")


def test_verify_rejects_identity_commitment():
    # A Client that knows the discrete logarithm x of the key it presents
    # reaches A = identity with s = c * y * x.
    G = protocol.G
    (x,) = G.DeriveScalars(bytes(48), b"x", 1)
    c, y, t = protocol.Scalar(5), protocol.Scalar(7), protocol.Scalar(9)
    shown = Token(c, c * y * x, y, t, bytes(32))
    assert not Verify(x * protocol.B, shown, b"epoch-1", b"moderator-1")

    anchor_set = [G.ScalarMultGen(protocol.Scalar(i)) for i in (2, 3)]
    endorsement = protocol.Endorsement(
        x * protocol.B, shown, protocol.Scalar(1), protocol.Scalar(1),
        [anchor_set[0]], [protocol.Scalar(1)],
    )
    with pytest.raises(VerifyError):
        protocol.VerifyEndorsement(
            anchor_set, endorsement, b"epoch-1", b"moderator-1", b"d"
        )


def test_verify_issuer_rejects_identity_branch_commitment():
    # With X_hat = pkA, Y[0] is the identity, and a zero response makes the
    # branch commitment of that branch the identity too.
    _, pkA, token = _issue()
    anchor_set = [pkA, protocol.G.ScalarMultGen(protocol.Scalar(2))]
    args = (anchor_set, pkA, token, b"epoch-1", b"moderator-1", b"d")
    assert Verify(pkA, token, b"epoch-1", b"moderator-1")
    assert not protocol.VerifyIssuer(
        *args, protocol.Scalar(1), protocol.Scalar(0),
        [pkA], [protocol.Scalar(1)],
    )
    endorsement = protocol.Endorsement(
        pkA, token, protocol.Scalar(1), protocol.Scalar(0),
        [pkA], [protocol.Scalar(1)],
    )
    with pytest.raises(VerifyError):
        protocol.VerifyEndorsement(
            anchor_set, endorsement, b"epoch-1", b"moderator-1", b"d"
        )


def test_partly_repeated_randomness_gives_a_fresh_first_move():
    # Two proofs of one statement whose randomness differs only in its last
    # byte share no value of the first move, so neither delta nor a trapdoor
    # can be solved for from the two responses.
    _, pkA, token = _issue()
    anchor_set = [protocol.G.ScalarMultGen(protocol.Scalar(i)) for i in (2, 3)]
    anchor_set.append(pkA)
    delta = protocol.Scalar(77)
    X_hat = pkA + delta * protocol.B
    rand = bytes(range(protocol.Nseed))
    changed = rand[:-1] + bytes([rand[-1] ^ 1])
    args = (anchor_set, 2, delta, X_hat, token, b"i", b"r", b"d")
    (c1, z1, keys1, openings1) = ProveIssuer(*args, rand)
    (c2, z2, keys2, openings2) = ProveIssuer(*args, changed)
    assert c1 != c2
    assert z1 - z2 != (c2 - c1) * delta
    assert all(k1 != k2 for k1, k2 in zip(keys1, keys2, strict=True))
    assert all(
        o1 != o2 for o1, o2 in zip(openings1, openings2, strict=True)
    )


def test_a_repeated_key_at_another_position_gives_a_fresh_first_move():
    # With one key at two positions, redeeming at either with the same
    # randomness must not reuse r under a different challenge.
    _, pkA, token = _issue()
    anchor_set = [pkA, protocol.G.ScalarMultGen(protocol.Scalar(2)), pkA]
    delta = protocol.Scalar(77)
    X_hat = pkA + delta * protocol.B
    rand = bytes(range(protocol.Nseed))
    (c0, z0, _, _), (c2, z2, _, _) = [
        ProveIssuer(
            anchor_set, index, delta, X_hat, token, b"i", b"r", b"d",
            rand,
        )
        for index in (0, 2)
    ]
    assert c0 != c2
    assert z0 - z2 != (c2 - c0) * delta
