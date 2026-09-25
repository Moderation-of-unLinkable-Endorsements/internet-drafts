"""The relations of the draft, compiled from their `Relation` blocks."""

from __future__ import annotations

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
