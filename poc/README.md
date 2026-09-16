# Reference implementation

Python reference implementations of IHAT and ACT. From this directory:

```sh
python3 -m venv .venv
.venv/bin/pip install -e '.[test]'
.venv/bin/python -m act.demo
.venv/bin/pytest
.venv/bin/mypy
.venv/bin/pyflakes src tests
.venv/bin/pylint --disable=all --enable=redefined-outer-name src tests
```

The ACT implementation includes generators, contexts, and key derivation.
The demo generates a Moderator key pair.

The algorithms in `src/act/protocol.py` match the draft's Python snippets;
tests check that they stay in sync. ACT shares IHAT's group and derivation
code. Each group instance carries its own protocol context and provides
`G.DeriveScalar`, `G.DeriveKeyPair`, and `G.GenerateKeyPair`. Both schemes
use the common `Seed` helper and 48-byte seeds.
Group values carry an invariant ciphersuite type parameter, allowing static
checkers to reject scalars and elements from a different ciphersuite.

This is a specification demo, not production cryptography. The Python code
is not constant-time and does not securely erase secrets.
