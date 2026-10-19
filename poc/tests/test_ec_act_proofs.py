from ec_ihat import common

from ec_act import protocol as ec_act
from ec_act import sigma


def compiled(statement):
    relation = statement.compile()
    assert relation.elements[0] == ec_act.B
    return len(relation.elements), [
        (equation.image, equation.terms) for equation in relation.equations
    ]


def test_builder_matches_the_sigma_draft_examples():
    # Each case is a worked example of the notation section of the Sigma
    # Protocols draft, with the compiled form the draft gives for it.
    G, H1, H2, H3 = ec_act.B, ec_act.H1, ec_act.H2, ec_act.H3
    x = ec_act.G.scalar(3)
    minus = lambda k: -k % ec_act.G.Order()  # noqa: E731

    s = sigma.Statement(ec_act.G)
    s.elements(H=H1, X=x * G, Y=x * H1)
    s.witness("x")
    s.equation("X = x * G")
    s.equation("Y = x * H")
    assert compiled(s) == (
        4,
        [([(2, 1)], [(0, 0, 1)]), ([(3, 1)], [(0, 1, 1)])],
    )

    s = sigma.Statement(ec_act.G)
    s.elements(H=H1, C=H2)
    s.witness("m", "r")
    s.equation("C = m * G + r * H")
    assert compiled(s) == (3, [([(2, 1)], [(0, 0, 1), (1, 1, 1)])])

    s = sigma.Statement(ec_act.G)
    s.scalars(m=5)
    s.elements(H=H1, C=H2)
    s.witness("r")
    s.equation("C = m * G + r * H")
    assert compiled(s) == (3, [([(2, 1), (0, minus(5))], [(0, 1, 1)])])

    s = sigma.Statement(ec_act.G)
    s.elements(X=x * G, E0=H1, E1=H2, M=H3)
    s.witness("x")
    s.equation("X = x * G")
    s.equation("M = x * E0 - E1")
    assert compiled(s) == (
        5,
        [([(1, 1)], [(0, 0, 1)]), ([(4, 1), (3, 1)], [(0, 2, 1)])],
    )

    s = sigma.Statement(ec_act.G)
    s.elements(X1=H1, X2=H2, M=H3, E0=x * G, E1=x * H1)
    s.witness("r")
    s.equation("E0 = r * G")
    s.equation("M + E1 = r * (X1 + X2)")
    assert compiled(s) == (
        6,
        [
            ([(4, 1)], [(0, 0, 1)]),
            ([(3, 1), (5, 1)], [(0, 1, 1), (0, 2, 1)]),
        ],
    )

    s = sigma.Statement(ec_act.G)
    s.elements(H=H1, C=H2)
    s.witness("b", "r", "s")
    s.equation("C = b * G + r * H")
    s.equation("C = b * C + s * H")
    assert compiled(s) == (
        3,
        [
            ([(2, 1)], [(0, 0, 1), (1, 1, 1)]),
            ([(2, 1)], [(0, 2, 1), (2, 1, 1)]),
        ],
    )


def test_builder_coefficients_and_signs():
    s = sigma.Statement(ec_act.G)
    s.scalars(k=7)
    s.elements(H=ec_act.H1, C=ec_act.H2)
    s.witness("r")
    s.equation("C - 2 * H = 3 * k * r * H - G")
    [(image, terms)] = compiled(s)[1]
    assert image == [(2, 1), (1, -2 % ec_act.G.Order()), (0, 1)]
    assert terms == [(0, 1, 21)]


def test_builder_rejects_malformed_equations():
    import pytest

    s = sigma.Statement(ec_act.G)
    s.elements(H=ec_act.H1, C=ec_act.H2)
    s.witness("r")
    for text, message in (
        ("C = r * H3", "undeclared name 'H3'"),
        ("C = r * r * H", "nonlinear"),
        ("C = r * H * C", "two elements"),
        ("C = r", "names no element"),
        ("C = r * H = C", "unexpected '='"),
        ("C = r * H +", "expected a factor"),
        ("C = 2 ^ H", "cannot parse"),
    ):
        with pytest.raises(ValueError, match=message):
            s.equation(text)
    with pytest.raises(ValueError, match="not a valid name"):
        s.witness("2r")
    with pytest.raises(ValueError, match="already declared"):
        s.elements(H=ec_act.H1)
    with pytest.raises(ValueError, match="already declared"):
        s.witness("G")


def pedersen():
    m, r = ec_act.G.scalar(7), ec_act.G.scalar(11)
    statement = sigma.Statement(ec_act.G)
    statement.elements(H=ec_act.H2, C=m * ec_act.B + r * ec_act.H2)
    statement.witness("m", "r")
    statement.equation("C = m * G + r * H")
    return statement, [m, r]


def test_upstream_reference_vectors_pass():
    # The upstream harness also covers BLS12-381 and batch verification,
    # which take minutes in pure Python; EC-ACT uses neither.
    import test_vectors as upstream

    for stem in (
        "fiatShamirCodecVectors",
        "fiatShamirShake128Vectors",
        "fiatShamirTurboShake128Vectors",
    ):
        for record in upstream.load(stem):
            upstream.check_fiat_shamir_record(record)
    suite = "sigma-proofs_Shake128_P256"
    valid = upstream.load(suite)
    invalid = upstream.load("sigma-proofs-invalid_Shake128_P256")
    upstream.check_sigma_valid(suite, valid)
    upstream.check_sigma_invalid(
        suite, invalid, {record["Id"] for record in valid}
    )
    assert valid and invalid


def test_proof_roundtrip_and_rejection(monkeypatch):
    statement, witness = pedersen()
    monkeypatch.setattr(
        common.secrets, "token_bytes", lambda size: bytes(size)
    )
    tag = ec_act.Tag(b"test", [b"first"])
    relation = statement.compile()
    proof = ec_act.Prove(tag, relation, witness)
    assert len(proof) == 3 * ec_act.Ns
    assert ec_act.Verify(tag, relation, proof)
    assert proof == ec_act.Prove(tag, statement.compile(), witness)
    assert not ec_act.Verify(tag, relation, proof[:-1])
    assert not ec_act.Verify(tag, relation, proof + b"\0")
    assert not ec_act.Verify(tag, relation, bytes([proof[0] ^ 1]) + proof[1:])
    assert not ec_act.Verify(
        tag,
        relation,
        ec_act.G.Order().to_bytes(ec_act.Ns, "big") + proof[ec_act.Ns :],
    )
    other = ec_act.Tag(b"test", [b"second"])
    assert not ec_act.Verify(other, relation, proof)
    assert ec_act.Prove(other, statement.compile(), witness) != proof
    wrong = sigma.Statement(ec_act.G)
    wrong.elements(H=ec_act.H2, C=ec_act.H3)
    wrong.witness("m", "r")
    wrong.equation("C = m * G + r * H")
    assert not ec_act.Verify(tag, wrong.compile(), proof)


def test_tag_carries_flavor_suite_and_bindings():
    tag = ec_act.Tag(b"Spend", [b"ab", b""])
    assert tag.startswith(ec_act.ctx_proto + b"-Spend-CMPT-with-")
    assert b"sigma-proofs_Shake128_P256" in tag
    assert tag.endswith(b"\x00\x02ab\x00\x00")
    assert ec_act.Tag(b"Spend", [b"a", b"b"]) != ec_act.Tag(b"Spend", [b"ab"])


def test_prover_nonces_are_derived(monkeypatch):
    monkeypatch.setattr(
        common.secrets, "token_bytes", lambda size: bytes(size)
    )
    _, witness = pedersen()
    session_id, instance = bytes(32), b"relation"
    nonces = ec_act.ProverNonces(witness, session_id, instance)
    first, second = nonces.random_scalar(), nonces.random_scalar()
    assert 0 < first < ec_act.G.Order() and 0 < second < ec_act.G.Order()
    assert first != second
    again = ec_act.ProverNonces(witness, session_id, instance)
    assert again.random_scalar() == first
    other_witness = ec_act.ProverNonces(
        [ec_act.G.scalar(8), witness[1]], session_id, instance
    )
    assert other_witness.random_scalar() != first
    other_instance = ec_act.ProverNonces(witness, session_id, b"other")
    assert other_instance.random_scalar() != first
    other_session = ec_act.ProverNonces(witness, bytes(31) + b"\1", instance)
    assert other_session.random_scalar() != first
    assert len(nonces.nonces) == 2
