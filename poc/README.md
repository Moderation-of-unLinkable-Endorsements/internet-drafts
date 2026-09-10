# Reference implementation

Reference implementations of MoLE's cryptographic primitives. Install and run
the tests with:

```sh
python3 -m venv .venv
.venv/bin/pip install -e '.[test]'
.venv/bin/pytest
.venv/bin/mypy
```

Group values carry an invariant ciphersuite type parameter, allowing static
checkers to reject scalars and elements from a different ciphersuite.
