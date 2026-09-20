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

import argparse
import glob
import logging
import os.path
import sys

from configuration_base_classes import BaseConfigurationFactory
from fibex_parser import FibexParser
from flync_parser import FlyncParser

logger = logging.getLogger(__name__)

parser_formats: list[str] = ["FIBEX", "FLYNC"]


def is_file_or_dir_valid(parser: argparse.ArgumentParser, arg: str) -> str:
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


def is_file_valid(parser: argparse.ArgumentParser, arg: str) -> str:
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
    t: str,
    conf_factory: BaseConfigurationFactory,
    plugin_file: str | None = None,
    ecu_name_replacement: dict[str, str] | None = None,
    print_filename: bool = True,
    file_filter: str = "",
    verbose: bool = False,
) -> str | None:
    """
    Parse input files based on the specified format type.

    Args:
        filename: Path to a file or directory to parse
        t: Format type (e.g., "FIBEX" or "FLYNC")
        conf_factory: Configuration factory instance
        plugin_file: Optional path to a parser plugin file
        ecu_name_replacement: Optional dictionary for ECU name replacements
        print_filename: Whether to print filenames during parsing
        file_filter: Optional glob pattern for filtering files
        verbose: Enable verbose output

    Returns:
        Output directory path
    """
    if t.upper() == "FLYNC":
        if not os.path.isdir(filename):
            print(f"FLYNC type requires a workspace directory, not a file: {filename}")
            sys.exit(-2)
        output_dir = filename.rstrip(os.sep) + "_output"
        flync_parser: FlyncParser = FlyncParser()
        flync_parser.parse_dir(conf_factory, filename, verbose=verbose)
        conf_factory.parsing_done()
        return output_dir

    if file_filter == "":
        if t.upper() == "FIBEX":
            file_filter = "/**/FBX*.xml"

    if os.path.isdir(filename):
        files = glob.glob(filename + file_filter, recursive=True)
        output_dir = filename
    elif os.path.isfile(filename):
        files = [filename]
        path, f = os.path.split(filename)
        filenoext = ".".join(f.split(".")[:-1])
        output_dir = os.path.join(path, filenoext)
    else:
        print(f"File not found: {filename}")
        sys.exit(-1)
        return None

    if t.upper() == "FIBEX":
        fb_parser: FibexParser = FibexParser(plugin_file, ecu_name_replacement)
        for f in files:
            if print_filename:
                print(f"\nFile: {f}")
            fb_parser.parse_file(conf_factory, f, verbose=verbose)
    else:
        print(f"Type {t} not known/supported!")
        sys.exit(-2)

    conf_factory.parsing_done()

    return output_dir
