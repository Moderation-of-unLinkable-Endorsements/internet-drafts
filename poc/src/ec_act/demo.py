"""Run issuance and four spend/refund flows: python -m ec_act.demo."""

from . import protocol as ec_act, wire


def main() -> None:
    ctx_cred = b"demo epoch"
    skM, pkM = ec_act.G.GenerateKeyPair()
    state, request = ec_act.IssueRequest()
    request = wire.DecodeIssueRequest(wire.EncodeIssueRequest(request))
    response = ec_act.IssueResponse(skM, ctx_cred, 10, request)
    response = wire.DecodeIssueResponse(
        wire.EncodeIssueResponse(response)
    )
    credential = ec_act.FinalizeIssue(pkM, ctx_cred, state, response)
    del state
    print(f"{ec_act.ctx_proto.decode()}: {ec_act.L}-bit balances")
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
        spend_state, proof = ec_act.ProveSpend(
            credential, ctx_cred, s, a, ctx_spend
        )
        del credential
        encoded = wire.EncodeSpend(proof)
        proof = wire.DecodeSpend(encoded)
        nullifier = ec_act.G.SerializeScalar(proof.k)
        if nullifier in seen:
            raise ec_act.VerifyError("credential already spent")
        ec_act.VerifySpend(skM, ctx_cred, ctx_spend, proof)
        refund = ec_act.IssueRefund(skM, ctx_cred, proof, t)
        seen.add(nullifier)
        refund = wire.DecodeRefund(wire.EncodeRefund(refund))
        credential = ec_act.FinalizeRefund(pkM, ctx_cred, spend_state, refund)
        del spend_state
        print(f"{name}: {len(encoded)} bytes, balance {credential.c}")


if __name__ == "__main__":
    main()
