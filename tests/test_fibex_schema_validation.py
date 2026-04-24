#!/usr/bin/python
"""Validate that all FIBEX XML example files pass schema validation.

These tests are skipped when the FIBEX 4.1.2 XSD schemas are absent from
tools/fibex_schema/4.1.2/.  The schemas are not checked into the repository;
members can download them from https://www.asam.net/standards/detail/mcd-2-net/
and place them in that folder to enable this test.
"""

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
EXAMPLES_DIR = REPO_ROOT / "examples"
SCHEMA_PATH = REPO_ROOT / "tools" / "fibex_schema" / "4.1.2" / "validate_wrapper.xsd"

# Skip the entire module at collection time if the schema is not present.
pytestmark = pytest.mark.skipif(
    not SCHEMA_PATH.is_file(),
    reason="FIBEX 4.1.2 XSD schemas not present in tools/fibex_schema/4.1.2/",
)

_xml_files = sorted(EXAMPLES_DIR.glob("*.xml"))


@pytest.fixture(scope="module")
def schema():
    etree = pytest.importorskip("lxml.etree")
    with open(SCHEMA_PATH, "rb") as f:
        schema_doc = etree.parse(f)
    return etree.XMLSchema(schema_doc)


@pytest.mark.parametrize("xml_file", _xml_files, ids=[f.name for f in _xml_files])
def test_xml_schema_valid(xml_file, schema):
    """Each example XML file must validate against the FIBEX 4.1.2 XSD schema."""
    from lxml import etree

    with open(xml_file, "rb") as f:
        doc = etree.parse(f)

    is_valid = schema.validate(doc)
    errors = [f"Line {e.line}: {e.message}" for e in schema.error_log]
    assert is_valid, f"{xml_file.name} failed schema validation:\n" + "\n".join(errors)
