import pytest

import ec_ihat.protocol as protocol
from ec_ihat.protocol import (
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

from ec_ihat.common import random

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
def test_commit_step_runs_without_raising():
    node = protocol.CommitStep(
        protocol.G.Generator(),
        bytes(protocol.Nseed),
        bytes([1]) * protocol.Nseed,
        [protocol.Scalar(1), protocol.Scalar(2)],
    )
    assert len(node) == 2 * protocol.G.Ne


def test_stack_base_is_fixed_and_distinct_from_a_context_base():
    assert protocol.G0 == protocol.CreateStackBase()
    assert protocol.G0 == protocol.G.HashToGroup(b"StackBase")
    assert protocol.G0 != protocol.CreateContextBase(b"")
    assert protocol.G0 != protocol.B


def test_step_bases_sum_to_twice_the_stack_base():
    # Knowing the discrete logarithm of both bases gives that of G0.
    for Q in (protocol.B, protocol.Scalar(7) * protocol.B, protocol.G0):
        (base_left, base_right) = protocol.StepBases(Q)
        assert base_left + base_right == protocol.G0 + protocol.G0


@pytest.mark.parametrize("bind_left", [False, True])
def test_generate_step_puts_the_trapdoor_under_the_equivocal_base(bind_left):
    secret = protocol.Scalar(12345)
    Q = protocol.GenerateStep(bind_left, secret)
    (base_left, base_right) = protocol.StepBases(Q)
    equivocal = base_right if bind_left else base_left
    assert equivocal == secret * protocol.B


def test_generate_step_keys_are_negations_of_each_other():
    secret = protocol.Scalar(12345)
    left = protocol.GenerateStep(True, secret)
    right = protocol.GenerateStep(False, secret)
    assert (left + right).isIdentity()


@pytest.mark.parametrize("bind_left", [False, True])
def test_only_the_equivocal_position_of_a_step_can_be_reopened(bind_left):
    secret = protocol.Scalar(12345)
    Q = protocol.GenerateStep(bind_left, secret)
    opening = [protocol.Scalar(3), protocol.Scalar(4)]
    node = protocol.CommitStep(Q, b"left", b"right", opening)
    equivocal = 1 if bind_left else 0
    old = (b"left", b"right")[equivocal]

    shifted = list(opening)
    shifted[equivocal] = protocol.EquivocateStep(
        old, b"new", opening[equivocal], secret
    )
    values = [b"left", b"right"]
    values[equivocal] = b"new"
    assert protocol.CommitStep(Q, *values, shifted) == node

    # The same shift at the binding position does not reopen it.
    binding = 1 - equivocal
    shifted = list(opening)
    shifted[binding] = protocol.EquivocateStep(
        (b"left", b"right")[binding], b"new", opening[binding], secret
    )
    values = [b"left", b"right"]
    values[binding] = b"new"
    assert protocol.CommitStep(Q, *values, shifted) != node


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


def test_vec_commit_runs_without_raising():
    protocol.VecCommit(
        [bytes(protocol.Nseed), bytes([1]) * protocol.Nseed],
        [protocol.G.Generator()],
        [protocol.Scalar(1), protocol.Scalar(2)],
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
        bytes(protocol.Nseed),
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
        [protocol.Scalar(3), protocol.Scalar(4)],
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
            [protocol.Scalar(3), protocol.Scalar(4)],
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
        [protocol.Scalar(3), protocol.Scalar(4)],
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
        ProveIssuer(*args[:1], 2, *args[2:], bytes(protocol.Nseed))
    with pytest.raises(ValueError, match="randomness"):
        ProveIssuer(*args, bytes(protocol.Nseed - 1))


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
            trapdoor = protocol.G.DeriveScalars(random(48), b"test", q)
            opening = protocol.G.DeriveScalars(random(48), b"test", 2 * q)
            keys = GenerateVecBind(j, trapdoor)
            comm = CommitValAtPlace(keys, i, j, b"Bob", opening)
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
def test_redemption_draws_two_seeds_at_every_index(monkeypatch, size):
    _, pkA, endorsement = _issue()
    calls = []

    def fixed_random(length):
        calls.append(length)
        return bytes(i % 256 for i in range(length))

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
        assert calls == [2 * protocol.Nseed]
        q = protocol.Depth(size)
        assert len(redemption.commitment_keys) == q
        assert len(redemption.openings) == 2 * q
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
    if len(anchor_set) > 1:
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
    for j in range(len(openings)):
        shifted = openings[:j] + [openings[j] + one] + openings[j + 1 :]
        yield f"opening {j}", anchor_set, redemption._replace(
            openings=shifted), ok
    if openings:
        yield "opening dropped", anchor_set, redemption._replace(
            openings=openings[1:]), ok
        yield "openings of a level swapped", anchor_set, redemption._replace(
            openings=[openings[1], openings[0]] + openings[2:]), ok
    yield "opening added", anchor_set, redemption._replace(
        openings=openings + [one]), ok
    if len(keys) > 1:
        yield "keys reversed", anchor_set, redemption._replace(
            commitment_keys=keys[::-1]), ok
    if keys:
        yield "key dropped", anchor_set, redemption._replace(
            commitment_keys=keys[1:]), ok
    yield "key added", anchor_set, redemption._replace(
        commitment_keys=keys + [G.Generator()]), ok


@pytest.mark.parametrize(
    "size, index", [(1, 0), (2, 0), (3, 2), (5, 1), (5, 4), (8, 3)]
)
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
    (x,) = G.DeriveScalars(bytes(48), b"x", 1)
    c, y, t = protocol.Scalar(5), protocol.Scalar(7), protocol.Scalar(9)
    shown = Endorsement(c, c * y * x, y, t, bytes(32))
    assert not Verify(x * protocol.B, shown, b"epoch-1", b"moderator-1")

    anchor_set = [G.ScalarMultGen(protocol.Scalar(i)) for i in (2, 3)]
    redemption = protocol.Redemption(
        x * protocol.B, shown, protocol.Scalar(1), protocol.Scalar(1),
        [anchor_set[0]], [protocol.Scalar(1), protocol.Scalar(1)],
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
        [pkA], [protocol.Scalar(1), protocol.Scalar(1)],
    )
    redemption = protocol.Redemption(
        pkA, endorsement, protocol.Scalar(1), protocol.Scalar(0),
        [pkA], [protocol.Scalar(1), protocol.Scalar(1)],
    )
    with pytest.raises(VerifyError):
        protocol.VerifyRedemption(
            anchor_set, redemption, b"epoch-1", b"moderator-1", b"d"
        )


@pytest.mark.parametrize("bind_left", [False, True])
def test_verify_issuer_rejects_identity_node_commitment(bind_left):
    # A Client that knows the trapdoor of the equivocal base can choose that
    # position's opening so that its commitment is the identity, which has
    # no encoding. VerifyIssuer rejects the proof instead of raising.
    G = protocol.G
    _, pkA, endorsement = _issue()
    anchor_set = [pkA, G.ScalarMultGen(protocol.Scalar(2))]
    X_hat = pkA + protocol.Scalar(3) * protocol.B
    proof_challenge, response = protocol.Scalar(5), protocol.Scalar(7)
    secret = protocol.Scalar(12345)
    Q = protocol.GenerateStep(bind_left, secret)
    equivocal = 1 if bind_left else 0

    Y = protocol.Statements(anchor_set, X_hat)
    leaf = G.SerializeElement(
        protocol.BranchCommitment(proof_challenge, response, Y[equivocal])
    )
    openings = [protocol.Scalar(1), protocol.Scalar(1)]
    openings[equivocal] = G.scalar(0) - G.HashToScalar(leaf) * secret

    args = (anchor_set, X_hat, endorsement, b"epoch-1", b"moderator-1", b"d")
    assert not protocol.VerifyIssuer(
        *args, proof_challenge, response, [Q], openings
    )


def test_partly_repeated_randomness_gives_a_fresh_first_move():
    # Two proofs of one statement whose randomness differs only in its last
    # byte share no value of the first move, so neither delta nor a trapdoor
    # can be solved for from the two responses.
    _, pkA, endorsement = _issue()
    anchor_set = [protocol.G.ScalarMultGen(protocol.Scalar(i)) for i in (2, 3)]
    anchor_set.append(pkA)
    delta = protocol.Scalar(77)
    X_hat = pkA + delta * protocol.B
    rand = bytes(range(protocol.Nseed))
    changed = rand[:-1] + bytes([rand[-1] ^ 1])
    args = (anchor_set, 2, delta, X_hat, endorsement, b"i", b"r", b"d")
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
    _, pkA, endorsement = _issue()
    anchor_set = [pkA, protocol.G.ScalarMultGen(protocol.Scalar(2)), pkA]
    delta = protocol.Scalar(77)
    X_hat = pkA + delta * protocol.B
    rand = bytes(range(protocol.Nseed))
    (c0, z0, _, _), (c2, z2, _, _) = [
        ProveIssuer(
            anchor_set, index, delta, X_hat, endorsement, b"i", b"r", b"d",
            rand,
        )
        for index in (0, 2)
    ]
    assert c0 != c2
    assert z0 - z2 != (c2 - c0) * delta
