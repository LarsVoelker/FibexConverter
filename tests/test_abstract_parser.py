#!/usr/bin/python

"""Unit tests for AbstractParser base class."""

import xml.etree.ElementTree as ET
from typing import Any, cast

import pytest
from lxml.etree import _Element

from abstract_parser import AbstractParser


def _root(xml: str) -> _Element:
    return cast(_Element, ET.fromstring(xml))


class TestAbstractParser:
    """Test cases for AbstractParser."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.parser = AbstractParser()

    def test_get_child_text_with_valid_element(self) -> None:
        """Test get_child_text with valid element."""
        root = _root("<root><child>test text</child></root>")
        result = self.parser.get_child_text(root, "child")
        assert result == "test text"

    def test_get_child_text_with_none_element(self) -> None:
        """Test get_child_text with None element."""
        result = self.parser.get_child_text(None, "child")
        assert result is None

    def test_get_child_text_with_missing_child(self) -> None:
        """Test get_child_text with missing child element."""
        root = _root("<root><other>text</other></root>")
        result = self.parser.get_child_text(root, "child")
        assert result is None

    def test_get_attribute_with_existing_attribute(self) -> None:
        """Test get_attribute with existing attribute."""
        root = _root("<root attr1='value1' attr2='value2'></root>")
        result = self.parser.get_attribute(root, "attr1")
        assert result == "value1"

    def test_get_attribute_with_missing_attribute(self) -> None:
        """Test get_attribute with missing attribute."""
        root = _root("<root></root>")
        result = self.parser.get_attribute(root, "attr1")
        assert result is None

    def test_get_attribute_with_non_existing_namespace(self) -> None:
        """Test get_attribute with existing attribute."""
        root = _root("<root attr1='value1' attr2='value2'></root>")
        result = self.parser.get_attribute(root, "wrong:attr1")
        assert result is None

    def test_get_child_attribute_with_existing_attribute(self) -> None:
        """Test get_child_attribute with existing attribute."""
        root = _root("<root><child attr='value'></child></root>")
        result = self.parser.get_child_attribute(root, "child", "attr")
        assert result == "value"

    def test_get_child_attribute_with_none_child(self) -> None:
        """Test get_child_attribute with None child tag."""
        root = _root("<root></root>")
        result = self.parser.get_child_attribute(root, None, "attr")
        assert result is None

    def test_get_child_attribute_with_none_attribute(self) -> None:
        """Test get_child_attribute with None attribute."""
        root = _root("<root><child></child></root>")
        result = self.parser.get_child_attribute(root, "child", None)
        assert result is None

    def test_get_child_attribute_with_missing_child(self) -> None:
        """Test get_child_attribute with missing child."""
        root = _root("<root><other></other></root>")
        result = self.parser.get_child_attribute(root, "child", "attr")
        assert result is None

    def test_get_child_attribute_with_missing_attribute(self) -> None:
        """Test get_child_attribute with missing child."""
        root = _root("<root><other></other></root>")
        result = self.parser.get_child_attribute(root, "other", "attr")
        assert result is None

    def test_element_text_to_int_with_valid_int(self) -> None:
        """Test element_text_to_int with valid integer."""
        root = _root("<root><value>42</value></root>")
        result = AbstractParser.element_text_to_int(cast(_Element, root.find("value")), 0)
        assert result == 42

    def test_element_text_to_int_with_none_element(self) -> None:
        """Test element_text_to_int with None element."""
        result = AbstractParser.element_text_to_int(cast(_Element, None), 42)
        assert result == 42

    def test_element_text_to_int_with_invalid_int(self) -> None:
        """Test element_text_to_int with invalid integer raises ValueError."""
        root = _root("<root><value>not_a_number</value></root>")
        with pytest.raises(ValueError):
            AbstractParser.element_text_to_int(cast(_Element, root.find("value")), 0)

    def test_element_text_with_valid_element(self) -> None:
        """Test element_text with valid element."""
        root = _root("<root><value>test text</value></root>")
        result = AbstractParser.element_text(root.find("value"))
        assert result == "test text"

    def test_element_text_with_none_element(self) -> None:
        """Test element_text with None element."""
        result = AbstractParser.element_text(None)
        assert result is None

    def test_get_from_dict_with_existing_key(self) -> None:
        """Test get_from_dict with existing key."""
        d = {"key1": "value1", "key2": "value2"}
        result = AbstractParser.get_from_dict(d, "key1", "default")
        assert result == "value1"

    def test_get_from_dict_with_missing_key(self) -> None:
        """Test get_from_dict with missing key."""
        d = {"key1": "value1"}
        result = AbstractParser.get_from_dict(d, "key2", "default")
        assert result == "default"

    def test_get_from_dict_with_none_dict(self) -> None:
        """Test get_from_dict with None dictionary."""
        result = AbstractParser.get_from_dict(None, "key", "default")
        assert result == "default"

    def test_get_from_dict_or_none_with_existing_key(self) -> None:
        """Test get_from_dict_or_none with existing key."""
        d = {"key1": "value1"}
        result = self.parser.get_from_dict_or_none(d, "key1")
        assert result == "value1"

    def test_get_from_dict_or_none_with_missing_key(self) -> None:
        """Test get_from_dict_or_none with missing key."""
        d = {"key1": "value1"}
        result = self.parser.get_from_dict_or_none(d, "key2")
        assert result is None

    def test_get_from_dict_or_none_with_none_dict(self) -> None:
        """Test get_from_dict_or_none with None dictionary."""
        result = self.parser.get_from_dict_or_none(None, "key")
        assert result is None

    def test_dict_to_sorted_set(self) -> None:
        """Test dict_to_sorted_set."""
        d = {"b": 2, "a": 1, "c": 3}
        result = AbstractParser.dict_to_sorted_set(d)
        assert result == (1, 2, 3)

    def test_dict_to_sorted_set_empty(self) -> None:
        """Test dict_to_sorted_set with empty dict."""
        d: dict[Any, Any] = {}
        result = AbstractParser.dict_to_sorted_set(d)
        assert result == ()

    def test_get_child_iso_duration_with_valid_duration(self) -> None:
        """Test get_child_iso_duration with valid duration."""
        root = _root("<root><duration>P1DT2H3M4S</duration></root>")
        result = self.parser.get_child_iso_duration(root, "duration")
        # 1 day + 2 hours + 3 minutes + 4 seconds = 93784 seconds
        assert result == 93784

    def test_get_child_iso_duration_with_missing_element(self) -> None:
        """Test get_child_iso_duration with missing element."""
        root = _root("<root><other>value</other></root>")
        result = self.parser.get_child_iso_duration(root, "duration")
        assert result == -1

    def test_value_to_bit_with_power_of_two(self) -> None:
        """Test value_to_bit with power of two."""
        result = AbstractParser.value_to_bit(1)
        assert result == 0

        result = AbstractParser.value_to_bit(2)
        assert result == 1

        result = AbstractParser.value_to_bit(4)
        assert result == 2

        result = AbstractParser.value_to_bit(8)
        assert result == 3

        result = AbstractParser.value_to_bit(16)
        assert result == 4

        result = AbstractParser.value_to_bit(32)
        assert result == 5

        result = AbstractParser.value_to_bit(64)
        assert result == 6

        result = AbstractParser.value_to_bit(128)
        assert result == 7

        result = AbstractParser.value_to_bit(256)
        assert result == 8

    def test_value_to_bit_with_non_power_of_two(self) -> None:
        """Test value_to_bit with non-power of two."""
        result = AbstractParser.value_to_bit(3)
        assert result is None

        result = AbstractParser.value_to_bit(5)
        assert result is None

        result = AbstractParser.value_to_bit(0)
        assert result is None
