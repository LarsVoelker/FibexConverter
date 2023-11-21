#!/usr/bin/python

# Automotive configuration file scripts
# Copyright (C) 2015-2023  Dr. Lars Voelker
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

class FibexParserPlugin:
    def __init__(self):
        print(f"Creating FibexParserPlugin!")

    def parse_file(self, parser, conf_factory, filename, verbose=False):
        print(f"I should be parsing manufacturer extensions, etc.")
