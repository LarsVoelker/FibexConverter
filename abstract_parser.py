#!/usr/bin/python

# Automotive configuration file scripts
# Copyright (C) 2015-2023  Dr. Lars Voelker
# Copyright (C) 2018-2019  Dr. Lars Voelker, BMW AG
# Copyright (C) 2020-2023  Dr. Lars Voelker, Technica Engineering GmbH

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

import isodate


class AbstractParser(object):
    def __init__(self):
        self.__conf_factory__ = None
        self.__ns__ = {}

    def get_child_text(self, element, childtag):
        if element is None:
            return None

        c = element.find(childtag, self.__ns__)
        if c is None:
            return None

        return c.text

    def get_attribute(self, element, attribkey):
        if self.__ns__ is not None and len(attribkey.split(':')) > 1:
            prefix, elem = attribkey.split(':')
            if prefix in self.__ns__:
                attribkey = '{' + self.__ns__[prefix] + '}' + elem
            else:
                print(f"Cannot lookup namespace: {attribkey}")

        if attribkey in element.attrib:
            return element.attrib[attribkey]
        return None

    def get_child_attribute(self, element, childtag, attribkey):
        if childtag is None or attribkey is None:
            return None

        c = element.find(childtag, self.__ns__)
        if c is None:
            # xml.etree.ElementTree.dump(element)
            return None
        if attribkey in c.attrib:
            return c.attrib[attribkey]
        return None

    @staticmethod
    def element_text_to_int(element, default):
        try:
            return int(element.text)
        except AttributeError:
            return default

    @staticmethod
    def element_text(element):
        if element is None:
            return None
        return element.text

    @staticmethod
    def get_from_dict(d, key, default):
        if d is None or key is None or key not in d:
            return default
        return d[key]

    def get_from_dict_or_none(self, d, key):
        if d is None:
            return None
        return self.get_from_dict(d, key, None)

    @staticmethod
    def dict_to_sorted_set(d):
        ret = ()

        for k in sorted(d.keys()):
            ret = ret + (d[k],)

        return ret

    def get_child_iso_duration(self, element, childtag):
        s = self.get_child_text(element, childtag)
        if s is None:
            return -1
        return (isodate.parse_duration(s)).total_seconds()
