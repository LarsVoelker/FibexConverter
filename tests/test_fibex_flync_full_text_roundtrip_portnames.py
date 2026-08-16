#!/usr/bin/python
"""E2E full-text round-trip tests with --generate-switch-port-names enabled.

Mirrors test_fibex_flync_full_text_roundtrip.py, but enables generated switch
port names (the CLI flag --generate-switch-port-names on both
configuration_to_flync and configuration_to_text) for both legs of the
round-trip.  Both the FIBEX→TEXT and FIBEX→FLYNC→TEXT outputs must remain
identical when generated port names are used.
"""

from pathlib import Path

import pytest

import configuration_to_flync
import configuration_to_text
from configuration_to_flync import SimpleConfigurationFactory as FlyncFactory
from configuration_to_text import SimpleConfigurationFactory as TextFactory
from fibex_parser import FibexParser
from flync_parser import FlyncParser

EXAMPLES_DIR = Path(__file__).parent.parent / "examples"

SOMEIP_FILES = sorted(EXAMPLES_DIR.glob("*.xml"))


@pytest.fixture(autouse=True)
def _enable_generated_port_names():
    """Enable --generate-switch-port-names for both text and flync modules."""
    prev_text = configuration_to_text.g_gen_portid
    prev_flync = configuration_to_flync.g_gen_portid
    configuration_to_text.g_gen_portid = True
    configuration_to_flync.g_gen_portid = True
    try:
        yield
    finally:
        configuration_to_text.g_gen_portid = prev_text
        configuration_to_flync.g_gen_portid = prev_flync


def _parse_fibex_with_text_factory(fibex_path):
    factory = TextFactory()
    FibexParser(plugin_file=None, ecu_name_replacement=None).parse_file(factory, str(fibex_path), verbose=False)
    factory.parsing_done()
    return factory


def _fibex_to_flync_workspace(fibex_path, tmp_path):
    factory = FlyncFactory()
    FibexParser(plugin_file=None, ecu_name_replacement=None).parse_file(factory, str(fibex_path), verbose=False)
    factory.parsing_done()
    ws_dir = tmp_path / "flync"
    ws_dir.mkdir()
    factory.create_flync_model()
    factory.save_flync_model(str(ws_dir.resolve()))
    return ws_dir


def _parse_flync_with_text_factory(ws_dir):
    factory = TextFactory()
    FlyncParser().parse_dir(factory, str(ws_dir), verbose=False)
    factory.parsing_done()
    return factory


@pytest.mark.parametrize("fibex_file", SOMEIP_FILES, ids=lambda p: p.stem)
def test_round_trip_full_text_with_generated_port_names(fibex_file, tmp_path):
    """FIBEX→TEXT and FIBEX→FLYNC→TEXT must match with generated switch port names."""

    fibex_factory = _parse_fibex_with_text_factory(fibex_file)
    ws_dir = _fibex_to_flync_workspace(fibex_file, tmp_path)
    flync_factory = _parse_flync_with_text_factory(ws_dir)

    assert str(fibex_factory) == str(flync_factory)
