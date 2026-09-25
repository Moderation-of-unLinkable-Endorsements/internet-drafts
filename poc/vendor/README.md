# Sigma Protocols and Fiat-Shamir reference code

`sigma-protocols` is a Git submodule of the CFRG draft repository
https://github.com/mmaker/draft-irtf-cfrg-sigma-protocols, pinned at the
tag `draft-irtf-cfrg-sigma-protocols-03`, whose bundled Fiat-Shamir draft
is `draft-irtf-cfrg-fiat-shamir-03`. The gitlink records the exact commit.

`act/sigma.py` puts the submodule's `poc` directory on `sys.path` and calls
its `prove_compact` and `verify_compact` directly, the way the ARC reference
implementation does. No upstream file is copied or patched. Its own vector
harness, `poc/test_vectors.py`, is run by our test suite.

Updating the pin is a separate change: ACTv1 is specified against these
revisions, and a revision that changes the NARG string or its derivation
requires a new ACT ciphersuite identifier.

Credit belongs to the contributors of the upstream draft repository. Its
`LICENSE.md` refers to `CONTRIBUTING.md`, which applies the IETF contribution
rules, including the Simplified BSD License for code components. Those files
and the upstream history are retained in the submodule.
