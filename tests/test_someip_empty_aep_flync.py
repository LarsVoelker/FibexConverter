#!/usr/bin/python
"""Tests for SOMEIP_Multiple_AEPs.xml — verifying that empty/bad AEPs are
handled gracefully and that valid AEPs are still converted correctly.

Scenario:
    ECU_PROVIDER has one connector with three AEPs:
      AEP_BAD   — NETWORK-ENDPOINT-REF points to a non-existent NEP.
                  Before the fix this caused a TypeError crash that prevented
                  all subsequent AEPs in the loop from being processed.
      AEP_VALID — valid NEP, UDP:30000, PSI for SVC_ECHO instance 1.
      AEP_EMPTY — valid NEP, UDP:30001, no service instances (empty
                  deployments expected in FLYNC output).

Assertions:
    1. parse_file() completes without exception (Bug 1 fix).
    2. ECU_PROVIDER has exactly two sockets (ports 30000 and 30001);
       AEP_BAD is gracefully skipped and contributes no socket.
    3. The socket at port 30000 carries one PSI deployment (SVC_ECHO 0x1234).
    4. The socket at port 30001 has an empty deployments list (not None).
    5. create_flync_ecus() and create_flync_model() succeed without exception.
    6. The FLYNC ECU for ECU_PROVIDER exposes exactly two sockets.
"""

from pathlib import Path

import pytest

from configuration_to_flync import SimpleConfigurationFactory as FlyncFactory
from fibex_parser import FibexParser

EXAMPLES_DIR = Path(__file__).parent.parent / "examples"
MULTI_AEP_FIBEX = EXAMPLES_DIR / "SOMEIP_Multiple_AEPs.xml"


# ---------------------------------------------------------------------------
# Module-scoped fixture: parse once, shared across all tests in this module.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def flync_factory():
    """Parse and convert to FLYNC, returning the FlyncFactory."""
    factory = FlyncFactory()
    FibexParser(plugin_file=None, ecu_name_replacement=None).parse_file(factory, str(MULTI_AEP_FIBEX), verbose=False)
    factory.parsing_done()
    factory.create_flync_ecus()
    return factory


# ---------------------------------------------------------------------------
# 1. parse_file must not raise — verifies the Bug 1 fix
# ---------------------------------------------------------------------------


def test_parse_completes_without_exception():
    """parse_file() must not raise TypeError for the bad NEP-REF AEP."""
    factory = FlyncFactory()
    # This would crash before the fix (TypeError from "ipsv4" in None):
    FibexParser(plugin_file=None, ecu_name_replacement=None).parse_file(factory, str(MULTI_AEP_FIBEX), verbose=False)
    factory.parsing_done()


# ---------------------------------------------------------------------------
# 2 & 3. Base-level sockets — two present; AEP_BAD contributes nothing
# ---------------------------------------------------------------------------


def _provider_base_sockets(flync_factory):
    """Return all base-level sockets belonging to ECU_PROVIDER."""
    sockets = []
    base_ecus = flync_factory.__base_ecus__
    ecu = base_ecus.get("ECU_PROVIDER")
    if ecu is None:
        return sockets
    for ctrl in ecu.controllers():
        for iface in ctrl.interfaces():
            sockets.extend(iface.sockets())
    return sockets


def test_provider_has_two_sockets(flync_factory):
    """ECU_PROVIDER must have exactly 2 sockets (AEP_VALID + AEP_EMPTY)."""
    sockets = _provider_base_sockets(flync_factory)
    ports = sorted(s.portnumber() for s in sockets)
    assert ports == [30000, 30001], (
        f"Expected ports [30000, 30001], got {ports}. " "AEP_BAD must be skipped; AEP_VALID and AEP_EMPTY must be present."
    )


def test_valid_aep_has_service(flync_factory):
    """The socket at port 30000 (AEP_VALID) must carry one PSI for SVC_ECHO."""
    sockets = _provider_base_sockets(flync_factory)
    sock_30000 = next((s for s in sockets if s.portnumber() == 30000), None)
    assert sock_30000 is not None, "Socket at port 30000 not found"
    instances = sock_30000.instances() or []
    assert len(instances) == 1, f"Expected 1 PSI, got {len(instances)}"
    svc = instances[0].service()
    assert svc.serviceid() == 0x1234, f"Expected service 0x1234, got 0x{svc.serviceid():04x}"


def test_empty_aep_has_no_services(flync_factory):
    """The socket at port 30001 (AEP_EMPTY) must have zero service instances."""
    sockets = _provider_base_sockets(flync_factory)
    sock_30001 = next((s for s in sockets if s.portnumber() == 30001), None)
    assert sock_30001 is not None, "Socket at port 30001 not found"
    instances = sock_30001.instances() or []
    assert instances == [], f"Expected no PSIs on AEP_EMPTY, got {instances}"


# ---------------------------------------------------------------------------
# 4. FLYNC conversion — two sockets in ECU_PROVIDER's SocketContainer
# ---------------------------------------------------------------------------


def _provider_flync_sockets(flync_factory):
    """Collect all FLYNC sockets for ECU_PROVIDER."""
    sockets = []
    for ecu in flync_factory._SimpleConfigurationFactory__flync_ecus:
        if ecu.name != "ECU_PROVIDER":
            continue
        for sc in ecu.sockets:
            sockets.extend(sc.sockets)
    return sockets


def test_flync_provider_has_two_sockets(flync_factory):
    """FLYNC ECU_PROVIDER must expose exactly 2 sockets after conversion."""
    sockets = _provider_flync_sockets(flync_factory)
    ports = sorted(s.port_no for s in sockets)
    assert ports == [30000, 30001], f"Expected [30000, 30001], got {ports}"


def test_flync_valid_aep_has_deployment(flync_factory):
    """FLYNC socket at port 30000 must have exactly one deployment."""
    sockets = _provider_flync_sockets(flync_factory)
    sock = next((s for s in sockets if s.port_no == 30000), None)
    assert sock is not None, "FLYNC socket at port 30000 not found"
    assert len(sock.deployments) == 1, f"Expected 1 deployment on port 30000, got {len(sock.deployments)}"


def test_flync_empty_aep_has_no_deployments(flync_factory):
    """FLYNC socket at port 30001 must have an empty (not None) deployments list."""
    sockets = _provider_flync_sockets(flync_factory)
    sock = next((s for s in sockets if s.port_no == 30001), None)
    assert sock is not None, "FLYNC socket at port 30001 not found"
    assert sock.deployments == [], f"Expected empty deployments on port 30001, got {sock.deployments}"


# ---------------------------------------------------------------------------
# 5. Full model creation succeeds
# ---------------------------------------------------------------------------


def test_flync_model_creation_succeeds(tmp_path):
    """Full FIBEX → FLYNC model creation must not raise any exception."""
    factory = FlyncFactory()
    FibexParser(plugin_file=None, ecu_name_replacement=None).parse_file(factory, str(MULTI_AEP_FIBEX), verbose=False)
    factory.parsing_done()
    factory.create_flync_model()
    ws_dir = tmp_path / "flync"
    ws_dir.mkdir()
    factory.save_flync_model(str(ws_dir.resolve()))
    assert ws_dir.exists()
