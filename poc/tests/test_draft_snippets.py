"""The executable draft snippets and the demo must describe the same code."""

import ast
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]


def definitions(
    source, *, concrete_group=False, kinds=(ast.FunctionDef, ast.ClassDef)
):
    tree = ast.parse(source)
    if concrete_group:
        # The draft's Scalar and Element are P256Scalar and P256Element
        # in this ciphersuite. Normalize the annotations only, leaving
        # the method bodies and their argument names unchanged.
        aliases = {"P256Scalar": "Scalar", "P256Element": "Element"}
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            annotations = [a.annotation for a in node.args.args]
            annotations.append(node.returns)
            for root in annotations:
                for annotation in ast.walk(root) if root else ():
                    if isinstance(annotation, ast.Name):
                        annotation.id = aliases.get(
                            annotation.id, annotation.id
                        )
    return {
        node.name: ast.dump(node, include_attributes=False)
        for node in ast.walk(tree)
        if isinstance(node, kinds)
    }


def test_act_snippets_match_implementation():
    draft = (ROOT / "draft-authors-mole-act.md").read_text()
    snippets = "\n\n".join(
        re.findall(r"(?ms)^~~~\s*python\n(.*?)^~~~", draft)
    )
    expected = definitions(snippets)
    actual = definitions((ROOT / "poc/src/act/protocol.py").read_text())
    assert expected
    for name, definition in expected.items():
        assert actual[name] == definition, name
    assert actual.keys() == expected.keys()


def test_rollatini_snippets_match_implementation():
    draft = (ROOT / "draft-authors-mole-ihat-rollatini.md").read_text()
    snippets = "\n\n".join(
        re.findall(r"(?ms)^~~~\s*python\n(.*?)^~~~", draft)
    )
    expected = definitions(snippets)
    actual = definitions(
        (ROOT / "poc/src/rollatini/ciphersuite.py").read_text(),
        concrete_group=True,
    )
    actual.update(
        definitions((ROOT / "poc/src/rollatini/common.py").read_text())
    )
    # The record types of protocol.py are implicit in the draft.
    protocol = definitions(
        (ROOT / "poc/src/rollatini/protocol.py").read_text(),
        kinds=(ast.FunctionDef,),
    )
    actual.update(protocol)
    assert expected
    for name, definition in expected.items():
        assert actual[name] == definition, name
    assert protocol.keys() <= expected.keys()
