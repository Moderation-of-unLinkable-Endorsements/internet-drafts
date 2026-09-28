# Contributor Guidance

Keep the Python snippets in `draft-authors-mole-rollatini.md` consistent with
the reference implementation in `poc/src/rollatini/`. Apply the same rule to
`draft-authors-mole-act.md` and `poc/src/act/`; shared derivation
methods live in `poc/src/rollatini/ciphersuite.py`, and `Seed` lives in
`poc/src/rollatini/common.py`. When changing an algorithm, update
both locations in the same change and preserve matching signatures, variable
names, error types, error messages, and behavior.

After relevant changes, build the draft and run the reference implementation's
tests, type checker, and linters.
