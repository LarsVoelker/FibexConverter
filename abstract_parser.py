#!/usr/bin/python

# Automotive configuration file scripts
# Copyright (C) 2015-2026  Dr. Lars Voelker
# Copyright (C) 2018-2019  Dr. Lars Voelker, BMW AG
# Copyright (C) 2020-2025  Dr. Lars Voelker, Technica Engineering GmbH

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

import logging
from typing import Any, cast

import isodate  # type: ignore[import-untyped]
from lxml.etree import _Element

from configuration_base_classes import BaseConfigurationFactory

logger = logging.getLogger(__name__)


class AbstractParser(object):
    """Common helper functions for XML-based configuration parsers."""

    def __init__(self) -> None:
        self.__conf_factory__: BaseConfigurationFactory | None = None
        self.__ns__: dict[str, str] = {}

    def get_child_text(self, element: _Element | None, childtag: str) -> str | None:
        """Return the text of the first matching child or ``None`` if not found."""
        if element is None:
            return None

        c = element.find(childtag, self.__ns__)
        if c is None:
            return None

        return c.text

    def get_attribute(self, element: _Element, attribkey: str) -> str | None:
        """Return the attribute value from *element* or ``None``.

        Namespaced attributes can be requested with the ``prefix:name`` notation.
        """
        if self.__ns__ is not None and ":" in attribkey:
            prefix, elem = attribkey.split(":", 1)
            if prefix in self.__ns__:
                attribkey = "{" + self.__ns__[prefix] + "}" + elem
            else:
                logger.warning("Cannot lookup namespace for attribute %s", attribkey)

        return element.attrib.get(attribkey)

    def get_child_attribute(self, element: _Element, childtag: str | None, attribkey: str | None) -> str | None:
        """Return an attribute of a child element or ``None`` if child/attribute is missing."""
        if childtag is None or attribkey is None:
            return None

        c = element.find(childtag, self.__ns__)
        if c is None:
            # xml.etree.ElementTree.dump(element)
            return None
        return c.attrib.get(attribkey)

    @staticmethod
    def element_text_to_int(element: _Element | None, default: int) -> int:
        if element is None:
            return default
        return int(element.text or "")

    @staticmethod
    def element_text(element: _Element | None) -> str | None:
        """Return ``element.text`` or ``None`` when *element* is ``None``."""
        if element is None:
            return None
        return element.text

    @staticmethod
    def get_from_dict(d: dict[str, Any] | None, key: str | None, default: Any) -> Any:
        """Safe dictionary lookup that tolerates ``None`` for *d* or *key*."""
        if d is None or key is None or key not in d:
            return default
        return d[key]

    def get_from_dict_or_none(self, d: dict[str, Any] | None, key: str) -> Any | None:
        """Convenience wrapper to get a value from a dict or ``None``."""
        if d is None:
            return None
        return self.get_from_dict(d, key, None)

    @staticmethod
    def dict_to_sorted_set(d: dict[Any, Any]) -> tuple[Any, ...]:
        """Return tuple of dictionary values ordered by sorted keys."""
        ret: tuple[Any, ...] = ()

        for k in sorted(d.keys()):
            ret = ret + (d[k],)

        return ret

    def get_child_iso_duration(self, element: _Element, childtag: str) -> float:
        s = self.get_child_text(element, childtag)
        if s is None:
            return -1
        return float((isodate.parse_duration(s)).total_seconds())

    @staticmethod
    def value_to_bit(i: int) -> int | None:
        """Return the bit index of a power-of-two integer or ``None`` otherwise."""
        if i <= 0 or i.bit_count() != 1:
            return None

        bitnumber = 0
        tmp = i
        while tmp & 1 != 1:
            tmp = tmp >> 1
            bitnumber += 1

        return bitnumber
