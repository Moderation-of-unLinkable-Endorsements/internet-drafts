"""Run issuance and all four spend/refund shapes: python -m act.demo."""

from . import protocol as act, wire


def main() -> None:
    ctx_cred = b"demo epoch"
    skM, pkM = act.G.GenerateKeyPair()
    state, request = act.IssueRequest()
    request = wire.DecodeIssueRequest(wire.EncodeIssueRequest(request))
    response = act.IssueResponse(skM, ctx_cred, 10, request)
    response = wire.DecodeIssueResponse(
        wire.EncodeIssueResponse(response)
    )
    credential = act.FinalizeIssue(pkM, ctx_cred, state, response)
    del state
    print(f"{act.ctx_proto.decode()}: {act.L}-bit balances")
    print(f"Issued {credential.c} credits")

    # An in-memory nullifier store suffices for this single-process demo.
    seen: set[bytes] = set()
    flows = [
        ("spend", 3, 0, 1),
        ("top-up", 0, 3, 3),
        ("spend + top-up", 2, 2, 3),
        ("refresh", 0, 0, 0),
    ]
    for index, (name, s, a, t) in enumerate(flows):
        ctx_spend = b"demo challenge " + bytes([index])
        spend_state, proof = act.ProveSpend(
            credential, ctx_cred, s, a, ctx_spend
        )
        del credential
        encoded = wire.EncodeSpend(proof)
        proof = wire.DecodeSpend(encoded)
        nullifier = act.G.SerializeScalar(proof.k)
        if nullifier in seen:
            raise act.VerifyError("credential already spent")
        act.VerifySpend(skM, ctx_cred, ctx_spend, proof)
        refund = act.IssueRefund(skM, ctx_cred, proof, t)
        seen.add(nullifier)
        refund = wire.DecodeRefund(wire.EncodeRefund(refund))
        credential = act.FinalizeRefund(
            pkM, ctx_cred, spend_state, proof, refund
        )
        del spend_state
        print(f"{name}: {len(encoded)} bytes, balance {credential.c}")


if __name__ == "__main__":
    main()
