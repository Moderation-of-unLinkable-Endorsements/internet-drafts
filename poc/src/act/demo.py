"""Issue a Credential and print its balance: python -m act.demo."""

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


if __name__ == "__main__":
    main()
