"""Generate the draft's test vectors: python -m act.vectors.

Every algorithm is a deterministic function of the bytes it draws from
`random`. The generator serves those bytes from SHAKE128 of a fixed label,
records what each algorithm consumed as its `rand` entry, and renders the
blocks of the draft's Test Vectors section. The test suite regenerates
them and compares against the draft, so the vectors are reproducible from
this module alone.
"""

from ihat import common
from ihat.vectors import Source, block, entry

from . import protocol as act, wire

L = 4
CTX_CRED = b"ACT-test-vectors-context"
CTX_SPEND = b"ACT-test-vectors-challenge-digest"
INITIAL_BALANCE = 10
FLOWS = [
    ("ordinary spend", 3, 0, 1),
    ("refresh", 0, 0, 0),
    ("pure top-up", 0, 2, 2),
    ("spend with top-up", 3, 2, 5),
]


def render() -> str:
    saved_L, saved_random = act.L, common.secrets.token_bytes
    act.L, source = L, Source(b"ACTv1-P256-SHA256 test vectors")
    setattr(common.secrets, "token_bytes", source)
    try:
        return _render(source)
    finally:
        act.L = saved_L
        setattr(common.secrets, "token_bytes", saved_random)


def _render(source: Source) -> str:
    G = act.G
    out = "## Ciphersuite {#act-tv-suite}\n\n" + block(
        entry("suite.identifier", b"P256-SHA256")
        + entry("suite.ctx_proto", act.ctx_proto)
        + entry("suite.L", act.L)
        + "".join(
            entry("suite." + name, G.SerializeElement(getattr(act, name)))
            for name in ("H1", "H2", "H3", "H4")
        )
        + entry("suite.ctx_cred", CTX_CRED)
        + entry(
            "suite.ctx",
            G.SerializeScalar(act.CreateContextScalar(CTX_CRED)),
        )
    )

    skM, pkM = G.GenerateKeyPair()
    out += "\n## Key Pair {#act-tv-key}\n\n" + block(
        entry("key.rand", source.rand())
        + entry("key.skM", G.SerializeScalar(skM))
        + entry("key.pkM", G.SerializeElement(pkM))
    )

    state, request = act.IssueRequest()
    entries = entry("issue.request.rand", source.rand())
    entries += entry(
        "issue.request.state",
        G.SerializeScalar(state.k)
        + G.SerializeScalar(state.r)
        + G.SerializeElement(state.K),
    )
    encoded = wire.EncodeIssueRequest(request)
    entries += entry("issue.request.message", encoded)
    request = wire.DecodeIssueRequest(encoded)
    response = act.IssueResponse(skM, CTX_CRED, INITIAL_BALANCE, request)
    entries += entry("issue.response.c", INITIAL_BALANCE)
    entries += entry("issue.response.rand", source.rand())
    encoded = wire.EncodeIssueResponse(response)
    entries += entry("issue.response.message", encoded)
    response = wire.DecodeIssueResponse(encoded)
    credential = act.FinalizeIssue(pkM, CTX_CRED, state, response)
    entries += entry("issue.credential", wire.EncodeCredential(credential))
    out += "\n## Issuance {#act-tv-issue}\n\n" + block(entries)

    for index, (name, s, a, t) in enumerate(FLOWS, start=1):
        key = f"spend{index}"
        title = f"Spend {index}: {name} (`s = {s}`, `a = {a}`)"
        entries = entry(key + ".s", s) + entry(key + ".a", a)
        entries += entry(key + ".ctx_spend", CTX_SPEND)
        spend, proof = act.ProveSpend(credential, CTX_CRED, s, a, CTX_SPEND)
        entries += entry(key + ".rand", source.rand())
        entries += entry(
            key + ".state",
            G.SerializeScalar(spend.kstar)
            + G.SerializeScalar(spend.r_star)
            + spend.v1.to_bytes(8, "big")
            + spend.s.to_bytes(8, "big")
            + spend.a.to_bytes(8, "big")
            + G.SerializeElement(spend.K_prime),
        )
        encoded = wire.EncodeSpend(proof)
        entries += entry(key + ".message", encoded)
        proof = wire.DecodeSpend(encoded)
        act.VerifySpend(skM, CTX_CRED, CTX_SPEND, proof)
        refund = act.IssueRefund(skM, CTX_CRED, proof, t)
        entries += entry(key + ".refund.t", t)
        entries += entry(key + ".refund.rand", source.rand())
        encoded = wire.EncodeRefund(refund)
        entries += entry(key + ".refund.message", encoded)
        refund = wire.DecodeRefund(encoded)
        credential = act.FinalizeRefund(pkM, CTX_CRED, spend, refund)
        entries += entry(
            key + ".credential", wire.EncodeCredential(credential)
        )
        out += f"\n## {title} {{#act-tv-{key}}}\n\n" + block(entries)
    return out


if __name__ == "__main__":
    print(render(), end="")
