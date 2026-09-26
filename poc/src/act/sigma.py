"""Run ACT's proofs on the CFRG reference code, unchanged.

``poc/vendor/sigma-protocols`` is the draft-irtf-cfrg-sigma-protocols
repository at its ``-03`` tag. Its modules import each other by bare name,
so its ``poc`` directory goes on ``sys.path`` once, here. Nothing upstream
is copied or patched. This module bridges the IHAT group to upstream's,
exposes the upstream procedures under the draft's names, and compiles
relations written in the draft's notation.
"""

from __future__ import annotations

import re
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any, NamedTuple

from ihat.ciphersuite import DeserializeError
from ihat.ciphersuite import P256Element as Element
from ihat.ciphersuite import P256Group
from ihat.ciphersuite import P256Scalar as Scalar

UPSTREAM = Path(__file__).resolve().parents[2] / "vendor/sigma-protocols/poc"
if not (UPSTREAM / "sigma_protocols.py").is_file():
    raise ImportError(
        "ACT needs the pinned sigma-protocols submodule. From the repository "
        "root, run: git submodule update --init poc/vendor/sigma-protocols"
    )
if str(UPSTREAM) not in sys.path:
    sys.path.insert(0, str(UPSTREAM))

import fiat_shamir  # noqa: E402
import groups  # noqa: E402
import sigma_protocols  # noqa: E402

LinearRelation = sigma_protocols.LinearRelation
DeriveSessionID = fiat_shamir.derive_session_id
SerializeLinearRelation = sigma_protocols.serialize_linear_relation


def ProveCompact(
    tag: bytes, relation: Any, witness: Sequence[Scalar], rng: Any
) -> bytes:
    """Upstream ``prove_compact``; the witness is given as IHAT scalars."""
    return bytes(
        sigma_protocols.prove_compact(
            tag, relation, [int(w) for w in witness], rng
        )
    )


def VerifyCompact(tag: bytes, relation: Any, proof: bytes) -> bool:
    """Upstream ``verify_compact``; every rejection is ``False``."""
    try:
        return bool(sigma_protocols.verify_compact(tag, relation, proof))
    except (sigma_protocols.SigmaError, groups.DeserializeError, ValueError):
        return False


class Group(groups.PrimeOrderGroup):
    """Upstream's group interface over the IHAT group.

    Upstream defines its protocol over an abstract prime-order group and
    ships a pure-Python P-256. This class presents IHAT's P-256, whose
    arithmetic is native, through the same interface, so the proofs run
    on the same elements the rest of ACT uses. Upstream represents the
    identity as ``None``; the encodings coincide (compressed SEC1).
    """

    name = "P256"
    Ne = 33
    Ns = 32

    def __init__(self, G: P256Group) -> None:
        self.G = G
        self.order = G.Order()

    def generator(self) -> Element:
        return self.G.Generator()

    def identity(self) -> None:
        return None

    def add(self, P: Element | None, Q: Element | None) -> Element | None:
        if P is None:
            return Q
        if Q is None:
            return P
        R = P + Q
        return None if R.isIdentity() else R

    def neg(self, P: Element | None) -> Element | None:
        return None if P is None else self.G.Identity() - P

    def mul(self, k: int, P: Element | None) -> Element | None:
        if P is None or k % self.order == 0:
            return None
        R = self.G.scalar(k % self.order) * P
        return None if R.isIdentity() else R

    def serialize_element(self, P: Element | None) -> bytes:
        if P is None:
            raise ValueError("Group.serialize is undefined for the identity")
        return self.G.SerializeElement(P)

    def deserialize_element(self, buf: bytes) -> Element:
        try:
            return self.G.DeserializeElement(buf)
        except DeserializeError as error:
            raise groups.DeserializeError(str(error)) from error


class Term(NamedTuple):
    """One term of a linear combination: ``coeff * scalar * element``."""

    coeff: int
    scalar: int | None
    element: int


class Statement:
    """A relation in the notation of the Sigma Protocols draft.

    Declare the elements, public scalars, and witness, then write each
    equation as it appears in the draft's ``Relation`` block::

        statement = Statement(G)
        statement.elements(H=H, C=C)
        statement.witness("m", "r")
        statement.equation("C = m * G + r * H")

    ``compile()`` returns the upstream ``LinearRelation``, with names
    indexed in declaration order and ``G`` at element index 0.
    """

    def __init__(self, G: P256Group) -> None:
        self.group = Group(G)
        self.points: list[Any] = [self.group.generator()]
        self.element_index: dict[str, int] = {"G": 0}
        self.public: dict[str, int] = {}
        self.scalar_index: dict[str, int] = {}
        self.equations: list[Any] = []

    def elements(self, **named: Element) -> None:
        for name, value in named.items():
            self._declare(name)
            self.element_index[name] = len(self.points)
            self.points.append(value)

    def scalars(self, **named: int | Scalar) -> None:
        for name, value in named.items():
            self._declare(name)
            self.public[name] = int(value) % self.group.order

    def witness(self, *names: str) -> None:
        for name in names:
            self._declare(name)
            self.scalar_index[name] = len(self.scalar_index)

    def equation(self, text: str) -> None:
        """Append an equation written as ``lhs = rhs``.

        A term without a witness scalar goes to the image, negated when
        it is written on the right; a term with one goes to the terms,
        negated when it is written on the left ({{relation-notation}}).
        """
        lhs, rhs = _Parser(self, text).equation()
        image = [(t.element, (sign * t.coeff) % self.group.order)
                 for sign, side in ((1, lhs), (-1, rhs))
                 for t in side if t.scalar is None]
        terms = [(t.scalar, t.element, (-sign * t.coeff) % self.group.order)
                 for sign, side in ((1, lhs), (-1, rhs))
                 for t in side if t.scalar is not None]
        self.equations.append(sigma_protocols.Equation(image, terms))

    def compile(self) -> Any:
        return sigma_protocols.LinearRelation(
            self.group, self.points, self.equations
        )

    def _declare(self, name: str) -> None:
        if not name.isidentifier():
            raise ValueError(f"{name!r} is not a valid name")
        if name in self.element_index or name in self.public:
            raise ValueError(f"{name!r} is already declared")
        if name in self.scalar_index:
            raise ValueError(f"{name!r} is already declared")


_TOKEN = re.compile(r"\s*(?:(\d+)|([A-Za-z_]\w*)|([-+*=()]))\s*")


class _Parser:
    """Recursive descent over ``combination = term {(+|-) term}``,
    ``term = factor {* factor}``, ``factor = integer | name | (combination)``.
    """

    def __init__(self, statement: Statement, text: str) -> None:
        self.statement = statement
        self.text = text
        self.tokens: list[str] = []
        pos = 0
        while pos < len(text):
            match = _TOKEN.match(text, pos)
            if match is None:
                raise ValueError(f"cannot parse {text!r} at offset {pos}")
            self.tokens.append(next(t for t in match.groups() if t))
            pos = match.end()
        self.pos = 0

    def peek(self) -> str | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def take(self, expected: str | None = None) -> str:
        token = self.peek()
        if token is None or (expected is not None and token != expected):
            raise ValueError(
                f"expected {expected or 'a factor'} in {self.text!r}"
            )
        self.pos += 1
        return token

    def equation(self) -> tuple[list[Term], list[Term]]:
        lhs = self.combination()
        self.take("=")
        rhs = self.combination()
        if self.peek() is not None:
            raise ValueError(f"unexpected {self.peek()!r} in {self.text!r}")
        return lhs, rhs

    def combination(self) -> list[Term]:
        terms = []
        while True:
            sign = 1
            if self.peek() in ("+", "-"):
                sign = -1 if self.take() == "-" else 1
            terms.extend(self.term(sign))
            if self.peek() not in ("+", "-"):
                return terms

    def term(self, sign: int) -> list[Term]:
        coeff, scalar, element, inner = sign, None, None, None
        while True:
            token = self.take()
            if token == "(":
                inner = self.combination()
                self.take(")")
            elif token.isdigit():
                coeff *= int(token)
            elif token in self.statement.public:
                coeff *= self.statement.public[token]
            elif token in self.statement.scalar_index:
                if scalar is not None:
                    raise ValueError(f"nonlinear term in {self.text!r}")
                scalar = self.statement.scalar_index[token]
            elif token in self.statement.element_index:
                if element is not None:
                    raise ValueError(
                        f"two elements in a term of {self.text!r}"
                    )
                element = self.statement.element_index[token]
            else:
                raise ValueError(f"undeclared name {token!r} in {self.text!r}")
            if self.peek() != "*":
                break
            self.take("*")
        if inner is None:
            if element is None:
                raise ValueError(f"a term of {self.text!r} names no element")
            return [Term(coeff, scalar, element)]
        if element is not None:
            raise ValueError(f"element times a sum in {self.text!r}")
        distributed = []
        for t in inner:
            if scalar is not None and t.scalar is not None:
                raise ValueError(f"nonlinear term in {self.text!r}")
            distributed.append(
                Term(coeff * t.coeff, t.scalar if scalar is None else scalar,
                     t.element)
            )
        return distributed
