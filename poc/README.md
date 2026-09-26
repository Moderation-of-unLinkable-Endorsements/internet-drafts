# Reference implementation

Python reference implementations of IHAT and ACT. ACT's proofs run on the
CFRG reference implementation of the Sigma Protocols and Fiat-Shamir drafts,
which is a Git submodule. Initialize it from the repository root:

```sh
git submodule update --init poc/vendor/sigma-protocols
```

Then, from this directory:

```sh
python3 -m venv .venv
.venv/bin/pip install -e '.[test]'
.venv/bin/python -m act.demo
.venv/bin/python -m act.vectors
.venv/bin/pytest
.venv/bin/mypy
.venv/bin/pyflakes src tests
.venv/bin/pylint --disable=all --enable=redefined-outer-name src tests
```

The demo issues a Credential and runs the four spend shapes with their
refunds, encoding every message on the way. `act.vectors` prints the
draft's Test Vectors section; a test regenerates it and compares.

The algorithms in `src/act/protocol.py` match the draft's Python snippets;
tests check that they stay in sync. `src/act/statements.py` compiles the
draft's `Relation` blocks, `src/act/sigma.py` runs them on the pinned CFRG
code, and `src/act/wire.py` holds the message encodings. ACT shares IHAT's
group and derivation code. Each group instance carries its own protocol context and provides
`G.DeriveScalar`, `G.DeriveKeyPair`, and `G.GenerateKeyPair`. Both schemes
use the common `Seed` helper and 48-byte seeds.
Group values carry an invariant ciphersuite type parameter, allowing static
checkers to reject scalars and elements from a different ciphersuite.

This is a specification demo, not production cryptography. The Python code
is not constant-time and does not securely erase secrets.

See [vendor/README.md](vendor/README.md) for the pinned upstream revision.
Upstream code is imported unchanged and is not part of our lint targets.
