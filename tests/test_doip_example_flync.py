#!/usr/bin/python
"""Tests for DoIP_example.xml — a single ECU on untagged Ethernet with TCP:13400.

Scenario:
    ECU_DOIP at 192.168.0.1/24, untagged Ethernet (no VLAN), one AEP on
    TCP port 13400 (standard DoIP port per ISO 13400), no SOME/IP services.

Assertions:
    1. parse_file() completes without exception.
    2. ECU_DOIP has exactly one socket at port 13400.
    3. That socket uses TCP protocol and port number 13400.
    4. The interface has no VLAN (vlanid == 0, the default for untagged).
    5. The socket carries no service instances.
"""

from pathlib import Path

import pytest

from configuration_to_flync import SimpleConfigurationFactory as FlyncFactory
from fibex_parser import FibexParser

EXAMPLES_DIR = Path(__file__).parent.parent / "examples"
DOIP_FIBEX = EXAMPLES_DIR / "DoIP_example.xml"


# ---------------------------------------------------------------------------
# Module-scoped fixture: parse once, shared across all tests in this module.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def flync_factory():
    """Parse DoIP_example.xml and convert to FLYNC, returning the FlyncFactory."""
    factory = FlyncFactory()
    FibexParser(plugin_file=None, ecu_name_replacement=None).parse_file(factory, str(DOIP_FIBEX), verbose=False)
    factory.parsing_done()
    factory.create_flync_ecus()
    return factory


def _doip_sockets(flync_factory):
    """Return all base-level sockets belonging to ECU_DOIP."""
    sockets = []
    ecu = flync_factory.__base_ecus__.get("ECU_DOIP")
    if ecu is None:
        return sockets
    for ctrl in ecu.controllers():
        for iface in ctrl.interfaces():
            sockets.extend(iface.sockets())
    return sockets


# ---------------------------------------------------------------------------
# 1. Parse must not raise
# ---------------------------------------------------------------------------


def test_parse_completes_without_exception():
    """parse_file() must not raise for DoIP_example.xml."""
    factory = FlyncFactory()
    FibexParser(plugin_file=None, ecu_name_replacement=None).parse_file(factory, str(DOIP_FIBEX), verbose=False)
    factory.parsing_done()


# ---------------------------------------------------------------------------
# 2. ECU_DOIP has exactly one socket
# ---------------------------------------------------------------------------


def test_doip_ecu_has_one_socket(flync_factory):
    """ECU_DOIP must have exactly one socket (AEP_DOIP on TCP:13400)."""
    sockets = _doip_sockets(flync_factory)
    assert len(sockets) == 1, f"Expected 1 socket, got {len(sockets)}: {[s.portnumber() for s in sockets]}"


# ---------------------------------------------------------------------------
# 3. Socket is TCP:13400
# ---------------------------------------------------------------------------


def test_doip_socket_is_tcp_port_13400(flync_factory):
    """The single socket must use TCP protocol on port 13400."""
    sockets = _doip_sockets(flync_factory)
    sock = next(iter(sockets), None)
    assert sock is not None, "No socket found for ECU_DOIP"
    assert sock.proto() == "tcp", f"Expected proto 'tcp', got '{sock.proto()}'"
    assert sock.portnumber() == 13400, f"Expected port 13400, got {sock.portnumber()}"


# ---------------------------------------------------------------------------
# 4. Interface has no VLAN (vlanid == 0)
# ---------------------------------------------------------------------------


def test_doip_interface_has_no_vlan(flync_factory):
    """The Ethernet interface must report vlanid == 0 (untagged channel)."""
    ecu = flync_factory.__base_ecus__.get("ECU_DOIP")
    assert ecu is not None, "ECU_DOIP not found"
    ifaces = [iface for ctrl in ecu.controllers() for iface in ctrl.interfaces()]
    assert len(ifaces) == 1, f"Expected 1 interface, got {len(ifaces)}"
    assert ifaces[0].vlanid() == 0, f"Expected vlanid 0, got {ifaces[0].vlanid()}"


# ---------------------------------------------------------------------------
# 5. Socket carries no service instances
# ---------------------------------------------------------------------------


def test_doip_socket_has_no_services(flync_factory):
    """The DoIP socket must carry no SOME/IP service instances."""
    sockets = _doip_sockets(flync_factory)
    sock = next(iter(sockets), None)
    assert sock is not None, "No socket found for ECU_DOIP"
    instances = sock.instances() or []
    assert instances == [], f"Expected no service instances, got {instances}"
