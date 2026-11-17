"""Experimental EC-ACT profile carrying a signed, hidden Anchor-set index.

This deliberately uses a different proof tag and separate message types from
EC-ACTv1. Wire versioning and production constant-time code are separate work.
"""

from __future__ import annotations

from typing import NamedTuple, Sequence

from ec_ihat import bound
from ec_ihat.ciphersuite import P256Element as Element
from ec_ihat.ciphersuite import P256Scalar as Scalar
from ec_ihat.protocol import VerifyError

from . import protocol as act
from .sigma import Statement

G = act.G
Hj = G.HashToGroup(b"MOLE-ACT-anchor-index-Hj-v1")
H, R = bound.H, bound.R


class IssuanceState(NamedTuple):
    k: Scalar
    r: Scalar
    j: Scalar
    K: Element


class IssueRequest(NamedTuple):
    K: Element
    C: Element
    pok: bytes


class Credential(NamedTuple):
    k: Scalar
    c: int
    r: Scalar
    j: Scalar
    A: Element
    e: Scalar


class SpendState(NamedTuple):
    kstar: Scalar
    r_star: Scalar
    v1: int
    s: int
    allowance: int
    j: Scalar
    K_prime: Element


class SpendMessage(NamedTuple):
    k: Scalar
    s: int
    allowance: int
    A_prime: Element
    B_bar: Element
    K_n: Element
    C: Element
    Com1: Sequence[Element]
    Com_c: Element | None
    pok: bytes


def issue_relation(K: Element, C: Element):
    statement = Statement(G)
    statement.elements(H2=act.H2, H3=act.H3, Hj=Hj, H=H, R=R, K=K, C=C)
    statement.witness("k", "r", "j", "rho")
    statement.equation("K = k * H2 + r * H3 + j * Hj")
    statement.equation("C = j * H + rho * R")
    return statement.compile()


def issue_request(j: int, rho: Scalar, C: Element) -> tuple[IssuanceState, IssueRequest]:
    if j < 1 or j >= 2**128 or C != G.scalar(j) * H + rho * R:
        raise ValueError("invalid Anchor commitment")
    k, r = G.DeriveScalars(act.random(act.Nseed), b"BoundIssueRequest", 2)
    tag = G.scalar(j)
    K = k * act.H2 + r * act.H3 + tag * Hj
    pok = act.Prove(act.Tag(b"BoundIssueRequest-v1", []), issue_relation(K, C), [k, r, tag, rho])
    return IssuanceState(k, r, tag, K), IssueRequest(K, C, pok)


def issue_response(skM: Scalar, ctx_cred: bytes, credits: int, request: IssueRequest) -> act.IssueResponseMessage:
    if not 0 <= credits < 2**act.L:
        raise act.AmountError
    if not act.Verify(act.Tag(b"BoundIssueRequest-v1", []), issue_relation(request.K, request.C), request.pok):
        raise VerifyError
    X_A = act.B + G.scalar(credits) * act.H1 + act.CreateContextScalar(ctx_cred) * act.H4 + request.K
    e = act.SigningExponent(skM, b"BoundIssueResponse-v1", X_A)
    x = e + skM
    A = G.ScalarInverse(x) * X_A
    pok = act.Prove(act.Tag(b"BoundIssueResponse-v1", []), act.SignatureRelation(A, X_A, G.ScalarMultGen(x)), [x])
    return act.IssueResponseMessage(A, e, credits, pok)


def finalize_issue(pkM: Element, ctx_cred: bytes, state: IssuanceState, response: act.IssueResponseMessage) -> Credential:
    if not 0 <= response.c < 2**act.L:
        raise act.AmountError
    X_A = act.B + G.scalar(response.c) * act.H1 + act.CreateContextScalar(ctx_cred) * act.H4 + state.K
    X_G = G.ScalarMultGen(response.e) + pkM
    if not act.Verify(act.Tag(b"BoundIssueResponse-v1", []), act.SignatureRelation(response.A, X_A, X_G), response.pok):
        raise VerifyError
    return Credential(state.k, response.c, state.r, state.j, response.A, response.e)


def spend_statement(proof: SpendMessage, A_bar: Element, H1_prime: Element):
    s, allowance = proof.s, proof.allowance
    refresh = s + allowance == 0
    weights = [] if refresh else act.RangeWeights(2**act.L - 1 - (s + allowance))
    n = len(weights)
    if len(proof.Com1) != n or (proof.Com_c is None) == refresh:
        raise VerifyError
    statement = Statement(G)
    statement.elements(H1=act.H1, H2=act.H2, H3=act.H3, Hj=Hj, H=H, R=R,
                       A_prime=proof.A_prime, B_bar=proof.B_bar,
                       A_bar=A_bar, H1_prime=H1_prime, K_n=proof.K_n, C=proof.C)
    statement.scalars(s=s, allowance=allowance)
    statement.scalars(**{f"w_{i}": weights[i] for i in range(n)})
    statement.elements(**{f"Com1_{i}": proof.Com1[i] for i in range(n)})
    statement.witness("e", "r2", "r3", "c", "r", "kstar", "rn", "j", "rho")
    for name in ("b1", "s1", "u1"):
        statement.witness(*[f"{name}_{i}" for i in range(n)])
    statement.equation("A_bar = -e * A_prime + r2 * B_bar")
    statement.equation("H1_prime = r3 * B_bar - c * H1 - r * H3 - j * Hj")
    statement.equation("K_n = kstar * H2 + rn * H3 + j * Hj")
    statement.equation("C = j * H + rho * R")
    if proof.Com_c is not None:
        statement.elements(Com_c=proof.Com_c)
        statement.witness("rc")
        statement.equation("Com_c = c * H1 + rc * H3")
    else:
        for i in range(n):
            statement.equation(f"Com1_{i} = b1_{i} * H1 + s1_{i} * H3")
            statement.equation(f"Com1_{i} = b1_{i} * Com1_{i} + u1_{i} * H3")
        statement.equation(
            "K_n + s * H1" + "".join(f" + w_{i} * Com1_{i}" for i in range(n))
            + " = c * H1 + kstar * H2 + rn * H3 + j * Hj"
            + "".join(f" + w_{i} * s1_{i} * H3" for i in range(n))
        )
    return statement.compile()


def prove_spend(credential: Credential, ctx_cred: bytes, s: int, allowance: int,
                ctx_spend: bytes, report_blind: Scalar | None = None) -> tuple[SpendState, SpendMessage, Scalar]:
    k, c, r, j, A, e = credential
    if not (0 <= s < 2**act.L and 0 <= allowance < 2**act.L) or s > c or c + allowance >= 2**act.L:
        raise act.AmountError
    v1 = c - s
    weights = [] if s + allowance == 0 else act.RangeWeights(2**act.L - 1 - (s + allowance))
    count = 5 + (len(weights) if weights else 1)
    derived = G.DeriveScalars(act.random(act.Nseed), b"BoundProveSpend", count)
    r1, r2, kstar, rn, generated_blind = derived[:5]
    rho = generated_blind if report_blind is None else report_blind
    ctx = act.CreateContextScalar(ctx_cred)
    B_msg = act.B + G.scalar(c) * act.H1 + k * act.H2 + r * act.H3 + ctx * act.H4 + j * Hj
    A_prime = (r1 * r2) * A
    B_bar = r1 * B_msg
    r3 = G.ScalarInverse(r1)
    A_bar = r2 * B_bar - e * A_prime
    K_n = kstar * act.H2 + rn * act.H3 + j * Hj
    C = j * H + rho * R
    Com1: list[Element] = []
    Com_c: Element | None = None
    witness = [e, r2, r3, G.scalar(c), r, kstar, rn, j, rho]
    if weights:
        bits = act.Bits(v1, weights)
        blinds = derived[5:]
        Com1 = [bits[i] * act.H1 + blinds[i] * act.H3 for i in range(len(weights))]
        products = [(G.scalar(1) - bits[i]) * blinds[i] for i in range(len(weights))]
        r_star = rn + sum((G.scalar(weights[i]) * blinds[i] for i in range(len(weights))), G.scalar(0))
        witness += bits + blinds + products
    else:
        rc = derived[5]
        Com_c = G.scalar(c) * act.H1 + rc * act.H3
        r_star = rn + rc
        witness.append(rc)
    proof = SpendMessage(k, s, allowance, A_prime, B_bar, K_n, C, Com1, Com_c, b"")
    H1_prime = act.B + k * act.H2 + ctx * act.H4
    pok = act.Prove(act.Tag(b"BoundSpend-v1", [ctx_spend]), spend_statement(proof, A_bar, H1_prime), witness)
    proof = proof._replace(pok=pok)
    K_prime = G.scalar(v1) * act.H1 + kstar * act.H2 + r_star * act.H3 + j * Hj
    return SpendState(kstar, r_star, v1, s, allowance, j, K_prime), proof, rho


def verify_spend(skM: Scalar, ctx_cred: bytes, ctx_spend: bytes, proof: SpendMessage) -> None:
    if not (0 <= proof.s < 2**act.L and 0 <= proof.allowance < 2**act.L) or proof.s + proof.allowance >= 2**act.L:
        raise act.AmountError
    A_bar = skM * proof.A_prime
    H1_prime = act.B + proof.k * act.H2 + act.CreateContextScalar(ctx_cred) * act.H4
    if not act.Verify(act.Tag(b"BoundSpend-v1", [ctx_spend]), spend_statement(proof, A_bar, H1_prime), proof.pok):
        raise VerifyError


def issue_refund(skM: Scalar, ctx_cred: bytes, proof: SpendMessage, amount: int) -> act.RefundMessage:
    if not 0 <= amount < 2**act.L or amount > proof.s + proof.allowance:
        raise act.AmountError
    if proof.Com_c is not None:
        V1 = proof.Com_c
    else:
        weights = act.RangeWeights(2**act.L - 1 - (proof.s + proof.allowance))
        if len(weights) != len(proof.Com1):
            raise VerifyError
        V1 = sum((G.scalar(weights[i]) * proof.Com1[i] for i in range(len(weights))), G.Identity())
    X_A = act.B + proof.K_n + V1 + G.scalar(amount) * act.H1 + act.CreateContextScalar(ctx_cred) * act.H4
    e = act.SigningExponent(skM, b"BoundRefund-v1", X_A)
    x = e + skM
    A = G.ScalarInverse(x) * X_A
    pok = act.Prove(act.Tag(b"BoundRefund-v1", []), act.SignatureRelation(A, X_A, G.ScalarMultGen(x)), [x])
    return act.RefundMessage(A, e, amount, pok)


def finalize_refund(pkM: Element, ctx_cred: bytes, state: SpendState, refund: act.RefundMessage) -> Credential:
    if not 0 <= refund.t <= state.s + state.allowance or state.v1 + refund.t >= 2**act.L:
        raise act.AmountError
    X_A = act.B + state.K_prime + G.scalar(refund.t) * act.H1 + act.CreateContextScalar(ctx_cred) * act.H4
    X_G = G.ScalarMultGen(refund.e) + pkM
    if not act.Verify(act.Tag(b"BoundRefund-v1", []), act.SignatureRelation(refund.A, X_A, X_G), refund.pok):
        raise VerifyError
    return Credential(state.kstar, state.v1 + refund.t, state.r_star, state.j, refund.A, refund.e)
