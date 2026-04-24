#!/usr/bin/env python3
"""
FIBEX XML Schema Validator

Validates FIBEX XML files against the ASAM FIBEX XSD schemas.
The XSD schemas can be downloaded by members from:
  https://www.asam.net/standards/detail/mcd-2-net/
Move the 4.1.2 schema files into the 4.1.2 folder.
"""

import sys
from pathlib import Path

from lxml import etree


def create_schema_validator(xsd_path: Path) -> etree.XMLSchema:
    """Load XSD schema and create a validator."""
    with open(xsd_path, "rb") as f:
        schema_doc = etree.parse(f)
    schema = etree.XMLSchema(schema_doc)
    return schema


def validate_xml_file(xml_path: Path, schema: etree.XMLSchema) -> tuple[bool, list[str]]:
    """
    Validate an XML file against a schema.

    Returns:
        (is_valid, error_messages)
    """
    errors = []
    try:
        with open(xml_path, "rb") as f:
            doc = etree.parse(f)

        if schema.validate(doc):
            return True, []
        else:
            for error in schema.error_log:
                errors.append(f"Line {error.line}: {error.message} (Level: {error.level})")
            return False, errors

    except etree.XMLSyntaxError as e:
        errors.append(f"XML Syntax Error: {e}")
        return False, errors


def main():
    """Main validation entry point."""
    base_dir = Path(__file__).parent
    xml_dir = base_dir / ".." / "examples"
    schema_path = base_dir / "fibex_schema" / "4.1.2" / "validate_wrapper.xsd"

    verbose = len(sys.argv) < 2 or str(sys.argv[1]).upper() != "PIPELINE"

    # XML files to validate
    xml_files = list(xml_dir.glob("*.xml"))

    if not xml_files:
        print(f"No XML files found in {xml_dir}")
        sys.exit(1)

    if verbose:
        print(f"Found {len(xml_files)} XML file(s) to validate:\n")

    # Load the validate_wrapper.xsd which imports all necessary schemas
    if verbose:
        print(f"Loading schema: {schema_path.name}")
    try:
        schema = create_schema_validator(schema_path)
        if verbose:
            print("Schema loaded successfully.\n")
    except Exception as e:
        print(f"Error loading schema: {e}")
        sys.exit(1)

    # Validate each XML file
    all_valid = True
    for xml_file in sorted(xml_files):
        is_valid, errors = validate_xml_file(xml_file, schema)

        if is_valid:
            if verbose:
                print(f"Validating: {xml_file.name}")
                print("  ✓ PASSED")
                print()
        else:
            print(f"Validating: {xml_file.name}")
            print("  ✗ FAILED")
            all_valid = False
            for error in errors:
                print(f"    - {error}")
            print()

    # Summary
    if verbose:
        print("=" * 50)
        if all_valid:
            if verbose:
                print("All XML files validated successfully!")
            sys.exit(0)
        else:
            print("Some files failed validation.")
            sys.exit(1)


if __name__ == "__main__":
    main()
