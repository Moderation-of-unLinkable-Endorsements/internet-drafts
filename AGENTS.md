# Contributor Guidance

Keep the Python snippets in `draft-authors-mole-crypto.md` consistent with the
reference implementation in `poc/src/ihat/`. When changing an algorithm, update
both locations in the same change and preserve matching signatures, variable
names, error types, error messages, and behavior.

After relevant changes, build the draft and run the reference implementation's
tests, type checker, and linters.
