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
from typing import Any, Dict, Hashable, Iterable, Optional, Tuple
from xml.etree.ElementTree import Element

import isodate

logger = logging.getLogger(__name__)

class AbstractParser:
    """Common helper functions for XML-based configuration parsers."""

    def __init__(self) -> None:
        self.__conf_factory__: Optional[Any] = None
        # Namespace map used when querying XML elements
        self.__ns__: Dict[str, str] = {}

    def get_child_text(self, element: Optional[Element], childtag: str) -> Optional[str]:
        """Return the text of the first matching child or ``None`` if not found."""
        if element is None:
            return None

        child = element.find(childtag, self.__ns__)
        if child is None:
            return None

        return child.text

    def get_attribute(self, element: Element, attribkey: str) -> Optional[str]:
        """
        Return the attribute value from *element* or ``None``.

        Namespaced attributes can be requested with the ``prefix:name`` notation.
        """
        if element is None or attribkey is None:
            return None

        if self.__ns__ is not None and ":" in attribkey:
            prefix, elem = attribkey.split(":", 1)
            if prefix in self.__ns__:
                attribkey = "{" + self.__ns__[prefix] + "}" + elem
            else:
                logger.warning("Cannot lookup namespace for attribute %s", attribkey)

        return element.attrib.get(attribkey)

    def get_child_attribute(
        self,
        element: Optional[Element],
        childtag: Optional[str],
        attribkey: Optional[str],
    ) -> Optional[str]:
        """Return an attribute of a child element or ``None`` if child/attribute is missing."""
        if element is None or childtag is None or attribkey is None:
            return None

        child = element.find(childtag, self.__ns__)
        if child is None:
            # xml.etree.ElementTree.dump(element)
            return None

        return child.attrib.get(attribkey)

    @staticmethod
    def element_text_to_int(element: Optional[Element], default: int) -> int:
        """Convert an element's text to ``int`` or return *default* on failure."""
        try:
            if element is None or element.text is None:
                return default
            return int(element.text)
        except (AttributeError, TypeError, ValueError):
            return default

    @staticmethod
    def element_text(element: Optional[Element]) -> Optional[str]:
        """Return ``element.text`` or ``None`` when *element* is ``None``."""
        if element is None:
            return None
        return element.text

    @staticmethod
    def get_from_dict(d: Optional[Dict[Hashable, Any]], key: Any, default: Any) -> Any:
        """Safe dictionary lookup that tolerates ``None`` for *d* or *key*."""
        if d is None or key is None:
            return default
        return d.get(key, default)

    def get_from_dict_or_none(
        self,
        d: Optional[Dict[Hashable, Any]],
        key: Any,
    ) -> Any:
        """Convenience wrapper to get a value from a dict or ``None``."""

        if d is None:
            return None
        return self.get_from_dict(d, key, None)

    @staticmethod
    def dict_to_sorted_set(d: Dict[Hashable, Any]) -> Tuple[Any, ...]:
        """
        Return tuple of dictionary values ordered by sorted keys.

        Keeping the return type as a tuple maintains the original API behaviour.
        """
        if not d:
            return tuple()

        return tuple(d[k] for k in sorted(d.keys()))

    def get_child_iso_duration(self, element: Optional[Element], childtag: str) -> float:
        """
        Parse an ISO-8601 duration from a child element and return its length in seconds.

        Returns ``-1`` when the child or its text is missing to preserve legacy semantics.
        """
        duration_str = self.get_child_text(element, childtag)
        if duration_str is None:
            return -1

        return isodate.parse_duration(duration_str).total_seconds()

    @staticmethod
    def value_to_bit(i: int) -> Optional[int]:
        """
        Return the bit index of a power-of-two integer or ``None`` otherwise.

        ``i`` must be a strictly positive power of two (e.g. 1, 2, 4, 8, ...).
        """
        if i <= 0 or i.bit_count() != 1:
            return None

        bitnumber = 0
        tmp = i
        while tmp & 1 != 1:
            tmp >>= 1
            bitnumber += 1

        return bitnumber