"""The draft's test vectors are regenerated and compared byte for byte."""

from pathlib import Path

from act import vectors


def test_draft_vectors_are_reproducible():
    draft = (
        Path(__file__).resolve().parents[2] / "draft-authors-mole-act.md"
    ).read_text()
    section = draft.split("## Ciphersuite {#act-tv-suite}", 1)[1]
    section = "## Ciphersuite {#act-tv-suite}" + section.split(
        "# Acknowledgments", 1
    )[0]
    assert section.rstrip("\n") == vectors.render().rstrip("\n")
