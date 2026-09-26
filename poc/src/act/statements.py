"""The relations of the draft, compiled from their `Relation` blocks."""

from __future__ import annotations

from collections.abc import Sequence

from ihat.ciphersuite import P256Element as Element

from .sigma import LinearRelation, Statement


def CommitmentRelation(K: Element) -> LinearRelation:
    from . import protocol as act

    statement = Statement(act.G)
    statement.elements(H2=act.H2, H3=act.H3, K=K)
    statement.witness("k", "r")
    statement.equation("K = k * H2 + r * H3")
    return statement.compile()


def SignatureRelation(
    A: Element, X_A: Element, X_G: Element
) -> LinearRelation:
    from . import protocol as act

    statement = Statement(act.G)
    statement.elements(A=A, X_A=X_A, X_G=X_G)
    statement.witness("x")
    statement.equation("X_A = x * A")
    statement.equation("X_G = x * G")
    return statement.compile()


def SpendRelation(
    A_prime: Element,
    B_bar: Element,
    A_bar: Element,
    H1_prime: Element,
    K_n: Element,
    s: int,
    a: int,
    Com1: Sequence[Element],
    Com_c: Element | None,
    Com2: Sequence[Element],
) -> LinearRelation:
    from . import protocol as act

    statement = Statement(act.G)
    statement.elements(
        H1=act.H1,
        H2=act.H2,
        H3=act.H3,
        A_prime=A_prime,
        B_bar=B_bar,
        A_bar=A_bar,
        H1_prime=H1_prime,
        K_n=K_n,
    )
    statement.scalars(s=s, a=a)
    statement.witness("e", "r2", "r3", "c", "r", "kstar", "rn")
    statement.equation("A_bar = -e * A_prime + r2 * B_bar")
    statement.equation("H1_prime = r3 * B_bar - c * H1 - r * H3")
    statement.equation("K_n = kstar * H2 + rn * H3")
    if s > 0:
        _range(statement, "Com1", Com1, "b1", "s1", "u1", "s * H1")
    else:
        if Com_c is None:
            raise ValueError("Com_c is required when s = 0")
        statement.elements(Com_c=Com_c)
        statement.witness("rc")
        statement.equation("Com_c = c * H1 + rc * H3")
    if a > 0:
        _range(statement, "Com2", Com2, "b2", "s2", "u2", "-a * H1")
    return statement.compile()


def _range(
    statement: Statement,
    Com: str,
    values: Sequence[Element],
    b: str,
    s: str,
    u: str,
    offset: str,
) -> None:
    """The bit commitments `values` open to a value in `[0, 2^L)` that,
    plus the public `offset`, equals `c`."""
    L = len(values)
    # The draft writes `Com1[j]`; a Python name cannot, so `Com1_j`.
    statement.elements(**{f"{Com}_{j}": values[j] for j in range(L)})
    for name in (b, s, u):
        statement.witness(*[f"{name}_{j}" for j in range(L)])
    for j in range(L):
        statement.equation(f"{Com}_{j} = {b}_{j} * H1 + {s}_{j} * H3")
        statement.equation(
            f"{Com}_{j} = {b}_{j} * {Com}_{j} + {u}_{j} * H3"
        )
    statement.equation(
        offset
        + "".join(f" + {2**j} * {Com}_{j}" for j in range(L))
        + " = c * H1"
        + "".join(f" + {2**j} * {s}_{j} * H3" for j in range(L))
    )
