"""The relations of the draft, compiled from their `Relation` blocks."""

from __future__ import annotations

from collections.abc import Sequence

from ec_ihat.ciphersuite import P256Element as Element
from ec_ihat.protocol import VerifyError

from .sigma import LinearRelation, Statement


def CommitmentRelation(K: Element) -> LinearRelation:
    from . import protocol as ec_act

    statement = Statement(ec_act.G)
    statement.elements(H2=ec_act.H2, H3=ec_act.H3, K=K)
    statement.witness("k", "r")
    statement.equation("K = k * H2 + r * H3")
    return statement.compile()


def SignatureRelation(
    A: Element, X_A: Element, X_G: Element
) -> LinearRelation:
    from . import protocol as ec_act

    statement = Statement(ec_act.G)
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
) -> LinearRelation:
    from . import protocol as ec_act

    refresh = s + a == 0
    w = [] if refresh else ec_act.RangeWeights(2**ec_act.L - 1 - (s + a))
    n = len(w)
    if len(Com1) != n:
        raise VerifyError(f"Com1 must hold {n} commitments")
    if (Com_c is None) == refresh:
        raise VerifyError("Com_c is required exactly when s + a = 0")

    statement = Statement(ec_act.G)
    statement.elements(
        H1=ec_act.H1,
        H2=ec_act.H2,
        H3=ec_act.H3,
        A_prime=A_prime,
        B_bar=B_bar,
        A_bar=A_bar,
        H1_prime=H1_prime,
        K_n=K_n,
    )
    statement.scalars(s=s, a=a)
    statement.scalars(**{f"w_{j}": w[j] for j in range(n)})
    # The draft writes `Com1[j]`; a Python name cannot, so `Com1_j`.
    statement.elements(**{f"Com1_{j}": Com1[j] for j in range(n)})
    statement.witness("e", "r2", "r3", "c", "r", "kstar", "rn")
    for name in ("b1", "s1", "u1"):
        statement.witness(*[f"{name}_{j}" for j in range(n)])
    statement.equation("A_bar = -e * A_prime + r2 * B_bar")
    statement.equation("H1_prime = r3 * B_bar - c * H1 - r * H3")
    statement.equation("K_n = kstar * H2 + rn * H3")
    if Com_c is not None:
        statement.elements(Com_c=Com_c)
        statement.witness("rc")
        statement.equation("Com_c = c * H1 + rc * H3")
        return statement.compile()
    for j in range(n):
        statement.equation(f"Com1_{j} = b1_{j} * H1 + s1_{j} * H3")
        statement.equation(f"Com1_{j} = b1_{j} * Com1_{j} + u1_{j} * H3")
    statement.equation(
        "K_n + s * H1"
        + "".join(f" + w_{j} * Com1_{j}" for j in range(n))
        + " = c * H1 + kstar * H2 + rn * H3"
        + "".join(f" + w_{j} * s1_{j} * H3" for j in range(n))
    )
    return statement.compile()
