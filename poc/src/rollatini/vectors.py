"""Generate the draft's test vectors: python -m rollatini.vectors.

Every algorithm is a deterministic function of the bytes it draws from
`random`. The generator serves those bytes from SHAKE128 of a fixed label,
records what each algorithm consumed as its `rand` entry, and renders the
blocks of the draft's Test Vectors section. The test suite regenerates
them and compares against the draft, so the vectors are reproducible from
this module alone.
"""

from hashlib import shake_128

from . import common, protocol as rollatini, wire

DERIVE_INFO = b"Rollatini test vectors"
CTX_ISS = b"Rollatini test vectors issuance context"
CTX_RED = b"Rollatini test vectors redemption context"
SESSION_ID = b"Rollatini test vectors session"
CHALLENGE_DIGEST = b"Rollatini test vectors challenge digest"
# Anchor Set sizes and the position of the issuing Anchor in each.
REDEMPTIONS = [(2, 1), (5, 3), (1, 0)]


class Source:
    """Serves `random` from a fixed stream and logs what was consumed."""

    def __init__(self, label: bytes) -> None:
        self.stream = shake_128(label).digest(1 << 16)
        self.position = 0
        self.consumed = b""

    def __call__(self, count: int | None = None) -> bytes:
        assert count is not None
        chunk = self.stream[self.position : self.position + count]
        self.position += count
        self.consumed += chunk
        return chunk

    def rand(self) -> bytes:
        consumed, self.consumed = self.consumed, b""
        return consumed


def entry(key: str, value: bytes | int) -> str:
    if isinstance(value, int):
        return f"{key} = {value}\n"
    digits = value.hex()
    if len(digits) <= 64 - len(key) - 3:
        return f"{key} = {digits}\n"
    lines = [digits[i : i + 64] for i in range(0, len(digits), 64)]
    return f"{key} =\n" + "".join(f"    {line}\n" for line in lines)


def block(entries: str) -> str:
    return "~~~\n" + entries + "~~~\n"


def render() -> str:
    saved_random = common.secrets.token_bytes
    source = Source(b"Rollatiniv1-P256-SHA256 test vectors")
    setattr(common.secrets, "token_bytes", source)
    try:
        return _render(source)
    finally:
        setattr(common.secrets, "token_bytes", saved_random)


def _render(source: Source) -> str:
    G = rollatini.G
    out = "## Ciphersuite {#rollatini-tv-suite}\n\n" + block(
        entry("suite.identifier", b"P256-SHA256")
        + entry("suite.ctx_proto", rollatini.ctx_proto)
    )

    scalars = G.DeriveScalars(source(3 * rollatini.Nseed), DERIVE_INFO)
    out += "\n## Scalar Derivation {#rollatini-tv-derive}\n\n" + block(
        entry("derive.info", DERIVE_INFO)
        + entry("derive.rand", source.rand())
        + entry(
            "derive.scalars",
            b"".join(G.SerializeScalar(s) for s in scalars),
        )
    )

    skA, pkA = G.GenerateKeyPair()
    out += "\n## Key Pair {#rollatini-tv-key}\n\n" + block(
        entry("key.rand", source.rand())
        + entry("key.skA", G.SerializeScalar(skA))
        + entry("key.pkA", G.SerializeElement(pkA))
        + entry("key.P_pkA", G.SerializeElement(G.P(pkA)))
    )

    entries = entry("issue.ctx_iss", CTX_ISS)
    entries += entry("issue.ctx_red", CTX_RED)
    entries += entry(
        "issue.Z", G.SerializeElement(rollatini.CreateContextBase(CTX_ISS))
    )
    entries += entry("issue.session_id", SESSION_ID)
    anchor_state, commitment = rollatini.Commit(CTX_ISS)
    entries += entry("issue.commit.rand", source.rand())
    entries += entry(
        "issue.commit.state",
        b"".join(G.SerializeScalar(s) for s in anchor_state),
    )
    encoded = wire.EncodeCommitMessage(SESSION_ID, commitment)
    entries += entry("issue.commit.message", encoded)
    _, commitment = wire.DecodeCommitMessage(encoded)
    client_state, challenge = rollatini.Challenge(
        pkA, CTX_ISS, CTX_RED, commitment
    )
    entries += entry("issue.challenge.rand", source.rand())
    entries += entry(
        "issue.challenge.state",
        client_state.nf
        + b"".join(
            G.SerializeScalar(s)
            for s in (
                client_state.r1,
                client_state.r2,
                client_state.gamma1,
                client_state.gamma2,
                client_state.c,
            )
        ),
    )
    encoded = wire.EncodeChallengeMessage(SESSION_ID, challenge)
    entries += entry("issue.challenge.message", encoded)
    _, challenge = wire.DecodeChallengeMessage(encoded)
    response = rollatini.Respond(skA, anchor_state, challenge)
    encoded = wire.EncodeResponseMessage(response)
    entries += entry("issue.response.message", encoded)
    response = wire.DecodeResponseMessage(encoded)
    endorsement = rollatini.Finalize(pkA, client_state, response)
    assert rollatini.Verify(pkA, endorsement, CTX_ISS, CTX_RED)
    entries += entry("issue.endorsement", wire.EncodeEndorsement(endorsement))
    out += "\n## Issuance {#rollatini-tv-issue}\n\n" + block(entries)

    for n, index in REDEMPTIONS:
        key = f"redeem{n}"
        anchor_set = []
        for i in range(n):
            if i == index:
                anchor_set.append(pkA)
            else:
                anchor_set.append(G.GenerateKeyPair()[1])
                source.rand()
        entries = entry(key + ".index", index)
        entries += entry(
            key + ".anchor_set",
            b"".join(G.SerializeElement(pk) for pk in anchor_set),
        )
        entries += entry(key + ".challenge_digest", CHALLENGE_DIGEST)
        redemption = rollatini.Redeem(
            anchor_set, index, endorsement, CTX_ISS, CTX_RED, CHALLENGE_DIGEST
        )
        rand = source.rand()
        (delta,) = G.DeriveScalars(common.Seed(rand, 0), b"delta")
        entries += entry(key + ".rand", rand)
        entries += entry(key + ".delta", G.SerializeScalar(delta))
        encoded = wire.EncodeRedemption(redemption)
        entries += entry(key + ".message", encoded)
        redemption = wire.DecodeRedemption(encoded, n)
        nf = rollatini.VerifyRedemption(
            anchor_set, redemption, CTX_ISS, CTX_RED, CHALLENGE_DIGEST
        )
        entries += entry(key + ".nf", nf)
        title = f"Redemption Against {n} Anchor{'s' if n > 1 else ''}"
        out += f"\n## {title} {{#rollatini-tv-{key}}}\n\n" + block(entries)
    return out


if __name__ == "__main__":
    print(render(), end="")
