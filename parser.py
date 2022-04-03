#!/usr/bin/python

# Automotive configuration file scripts
# Copyright (C) 2015-2022  Dr. Lars Voelker
# Copyright (C) 2018-2019  Dr. Lars Voelker, BMW AG
# Copyright (C) 2020-2022  Dr. Lars Voelker, Technica Engineering GmbH

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

import os.path
import glob

from fibex_parser import FibexParser


def parse_input_files(filename, t, conf_factory, print_filename=True, file_filter="/**/FBX*.xml"):
    if os.path.isdir(filename):
        files = glob.glob(filename + file_filter, recursive=True)
        output_dir = filename

    elif os.path.isfile(filename):
        files = [filename]
        (path, f) = os.path.split(filename)
        filenoext = '.'.join(f.split('.')[:-1])
        output_dir = os.path.join(path, filenoext)
    else:
        print("Error: File not found!")
        return None

    if t.upper() == "FIBEX":
        parser = FibexParser()
        for f in files:
            if print_filename:
                print(f"\nFile: {f}")
            parser.parse_file(conf_factory, f)
    else:
        print("Error: type {t} not known/supported!")
        return None

    return output_dir
