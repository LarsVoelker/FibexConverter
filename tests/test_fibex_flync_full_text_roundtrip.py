#!/usr/bin/python
"""E2E full-text round-trip tests: FIBEX → FLYNC workspace → text comparison.

For each SOME/IP FIBEX example file the test:
  1. Parses the FIBEX directly into a text factory and captures str(factory).
  2. Converts the FIBEX to a FLYNC workspace via configuration_to_flync's factory.
  3. Parses the generated FLYNC workspace into a second text factory and captures str(factory).
  4. Asserts that the full text output is identical across both paths.
"""

from pathlib import Path

import pytest

import configuration_to_text
from configuration_to_flync import SimpleConfigurationFactory as FlyncFactory
from configuration_to_text import SimpleConfigurationFactory as TextFactory
from fibex_parser import FibexParser
from flync_parser import FlyncParser

# Replicate the initialization that configuration_to_text.main() normally performs.
configuration_to_text.g_gen_portid = False

EXAMPLES_DIR = Path(__file__).parent.parent / "examples"

# All XML files directly in examples/ (no subdirectories).
SOMEIP_FILES = sorted(EXAMPLES_DIR.glob("*.xml"))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_fibex_with_text_factory(fibex_path):
    """Parse *fibex_path* using the configuration_to_text SimpleConfigurationFactory."""
    factory = TextFactory()
    FibexParser(plugin_file=None, ecu_name_replacement=None).parse_file(factory, str(fibex_path), verbose=False)
    factory.parsing_done()
    return factory


def _fibex_to_flync_workspace(fibex_path, tmp_path):
    """Convert *fibex_path* to a FLYNC workspace directory inside *tmp_path*."""
    factory = FlyncFactory()
    FibexParser(plugin_file=None, ecu_name_replacement=None).parse_file(factory, str(fibex_path), verbose=False)
    factory.parsing_done()
    ws_dir = tmp_path / "flync"
    ws_dir.mkdir()
    factory.create_flync_model()
    factory.save_flync_model(str(ws_dir.resolve()))
    return ws_dir


def _parse_flync_with_text_factory(ws_dir):
    """Parse the FLYNC workspace at *ws_dir* using the configuration_to_text SimpleConfigurationFactory."""
    factory = TextFactory()
    FlyncParser().parse_dir(factory, str(ws_dir), verbose=False)
    factory.parsing_done()
    return factory


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fibex_file", SOMEIP_FILES, ids=lambda p: p.stem)
def test_round_trip_full_text(fibex_file, tmp_path):
    """Full text output of configuration_to_text must be identical after FIBEX → FLYNC → text round-trip."""
    fibex_factory = _parse_fibex_with_text_factory(fibex_file)
    ws_dir = _fibex_to_flync_workspace(fibex_file, tmp_path)
    flync_factory = _parse_flync_with_text_factory(ws_dir)

    assert str(fibex_factory) == str(flync_factory)
