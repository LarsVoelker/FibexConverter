#!/usr/bin/python
"""E2E round-trip tests: FIBEX → FLYNC workspace → text factory comparison.

For each SOME/IP FIBEX example file the test:
  1. Parses the FIBEX directly into a text factory (FIBEX path).
  2. Converts the FIBEX to a FLYNC workspace via configuration_to_flync's factory.
  3. Parses the generated FLYNC workspace into a second text factory (FLYNC path).
  4. Asserts that service structure and ECU names are identical across both paths.

Full text comparison is intentionally avoided because known round-trip differences
exist (endianness representation, array wrappers, string type names, socket instance
bindings).  Instead, only the semantically stable parts are compared:
  - service IDs, names, major versions
  - method IDs → names
  - event IDs → names
  - field names (as a set, independent of internal key choice)
  - eventgroup IDs → names
  - ECU names
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


def _service_summary(factory):
    """Return a comparable dict of the service structure held in *factory*.

    Fields are reduced to a *set* of names rather than a dict keyed by internal
    IDs because the field key choice may differ between FIBEX and FLYNC parsers.
    """
    result = {}
    for sid, svc in factory.__services__.items():
        result[sid] = {
            "name": svc.name(),
            "major": svc.majorversion(),
            "methods": {mid: m.name() for mid, m in svc.methods().items()},
            "events": {eid: e.name() for eid, e in svc.events().items()},
            "field_names": {f.name() for f in svc.fields().values()},
            "eventgroups": {egid: eg.name() for egid, eg in svc.eventgroups().items()},
        }
    return result


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fibex_file", SOMEIP_FILES, ids=lambda p: p.stem)
def test_round_trip_services(fibex_file, tmp_path):
    """Service structure must be identical after a FIBEX → FLYNC → text round-trip."""
    fibex_factory = _parse_fibex_with_text_factory(fibex_file)
    ws_dir = _fibex_to_flync_workspace(fibex_file, tmp_path)
    flync_factory = _parse_flync_with_text_factory(ws_dir)

    fibex_summary = _service_summary(fibex_factory)
    flync_summary = _service_summary(flync_factory)

    assert fibex_summary == flync_summary


@pytest.mark.parametrize("fibex_file", SOMEIP_FILES, ids=lambda p: p.stem)
def test_round_trip_ecus(fibex_file, tmp_path):
    """ECU names must be identical after a FIBEX → FLYNC → text round-trip."""
    fibex_factory = _parse_fibex_with_text_factory(fibex_file)
    ws_dir = _fibex_to_flync_workspace(fibex_file, tmp_path)
    flync_factory = _parse_flync_with_text_factory(ws_dir)

    assert set(fibex_factory.__ecus__.keys()) == set(flync_factory.__ecus__.keys())
