"""Run the ACT model and key-generation example: python -m act.demo."""

from . import protocol as act


def main() -> None:
    _, pkM = act.G.GenerateKeyPair()
    print(f"{act.ctx_proto.decode()}: {act.L}-bit balances")
    print(f"Moderator public key: {act.G.SerializeElement(pkM).hex()}")


if __name__ == "__main__":
    main()
