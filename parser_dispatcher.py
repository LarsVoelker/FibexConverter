#!/usr/bin/python

# Automotive configuration file scripts
# Copyright (C) 2015-2026  Dr. Lars Voelker
# Copyright (C) 2018-2019  Dr. Lars Voelker, BMW AG
# Copyright (C) 2020-2024  Dr. Lars Voelker, Technica Engineering GmbH

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
import os.path
import glob
from typing import Any, List, Optional

from fibex_parser import FibexParser

logger = logging.getLogger(__name__)

parser_formats = ["FIBEX"]

def is_file_or_dir_valid(parser: Any, arg: str) -> str:
    """
    Validate that a file or directory path exists.

    Args:
        parser: ArgumentParser instance for error reporting
        arg: Path to validate

    Returns:
        The validated path

    Raises:
        argparse.ArgumentError: If the path does not exist
    """
    if not os.path.exists(arg):
        parser.error(f"File or directory does not exist: {arg}")
    return arg

def is_file_valid(parser: Any, arg: str) -> str:
    """
    Validate that a file path exists and is a file.

    Args:
        parser: ArgumentParser instance for error reporting
        arg: File path to validate

    Returns:
        The validated file path

    Raises:
        argparse.ArgumentError: If the path does not exist or is not a file
    """
    if not os.path.isfile(arg):
        parser.error(f"File does not exist: {arg}")
    return arg

def parse_input_files(
    filename: str,
    format_type: str,
    conf_factory: Any,
    plugin_file: Optional[str] = None,
    ecu_name_replacement: Optional[dict] = None,
    print_filename: bool = True,
    file_filter: str = "",
    verbose: bool = False,
) -> str:
    """
    Parse input files based on the specified format type.

    Args:
        filename: Path to a file or directory to parse
        format_type: Format type (e.g., "FIBEX")
        conf_factory: Configuration factory instance
        plugin_file: Optional path to a parser plugin file
        ecu_name_replacement: Optional dictionary for ECU name replacements
        print_filename: Whether to print filenames during parsing
        file_filter: Optional glob pattern for filtering files
        verbose: Enable verbose output

    Returns:
        Output directory path

    Raises:
        FileNotFoundError: If the input file/directory does not exist
        ValueError: If the format type is not supported
    """
    # Set default file filter for FIBEX format
    if not file_filter and format_type.upper() == "FIBEX":
        file_filter = "/**/FBX*.xml"

    # Determine files to parse and output directory
    if os.path.isdir(filename):
        files = glob.glob(filename + file_filter, recursive=True)
        output_dir = filename
    elif os.path.isfile(filename):
        files = [filename]
        path, f = os.path.split(filename)
        filenoext = '.'.join(f.split('.')[:-1])
        output_dir = os.path.join(path, filenoext)
    else:
        raise FileNotFoundError(f"File not found: {filename}")

    if format_type.upper() == "FIBEX":
        parser = FibexParser(plugin_file, ecu_name_replacement)
        for f in files:
            if print_filename:
                print(f"File: {f}")
            parser.parse_file(conf_factory, f, verbose=verbose)
    else:
        raise ValueError(f"Type {format_type} not known/supported!")

    conf_factory.parsing_done()

    return output_dir
