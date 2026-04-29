#!/usr/bin/python
"""Tests for SOMEIP_Nonstandard_Netmask.xml — verifying that non-standard
IPv4 netmasks (e.g. /25 = 255.255.255.128) are correctly preserved throughout
the FIBEX → text and FIBEX → FLYNC conversion pipelines.

Background:
    BaseInterface.__init__ was changed to store IPs as ipaddress.IPv4Address
    objects instead of raw strings.  Every place that calls get_ipv4_netmask()
    with an IPv4Address object would silently fall back to the default /24
    (255.255.255.0) because the internal dict key is a string.  This test
    ensures get_ipv4_netmask() accepts both str and IPv4Address inputs and
    returns the correct netmask.

Topology used:
    ECU_PROVIDER  10.10.10.10 / 255.255.255.128 (/25)  UDP 30000
    ECU_CONSUMER  10.10.10.11 / 255.255.255.128 (/25)  UDP 30001
"""

import ipaddress
from pathlib import Path

import pytest

import configuration_to_text
from configuration_to_flync import SimpleConfigurationFactory as FlyncFactory
from configuration_to_text import SimpleConfigurationFactory as TextFactory
from fibex_parser import FibexParser

configuration_to_text.g_gen_portid = False

EXAMPLES_DIR = Path(__file__).parent.parent / "examples"
NONSTANDARD_NETMASK_FIBEX = EXAMPLES_DIR / "SOMEIP_Nonstandard_Netmask.xml"

PROVIDER_IP = "10.10.10.10"
CONSUMER_IP = "10.10.10.11"
NETMASK = "255.255.255.128"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def text_factory():
    factory = TextFactory()
    FibexParser(plugin_file=None, ecu_name_replacement=None).parse_file(factory, str(NONSTANDARD_NETMASK_FIBEX), verbose=False)
    factory.parsing_done()
    return factory


@pytest.fixture(scope="module")
def flync_factory():
    factory = FlyncFactory()
    FibexParser(plugin_file=None, ecu_name_replacement=None).parse_file(factory, str(NONSTANDARD_NETMASK_FIBEX), verbose=False)
    factory.parsing_done()
    factory.create_flync_ecus()
    return factory


# ---------------------------------------------------------------------------
# 1. Factory netmask lookup (both str and IPv4Address input)
# ---------------------------------------------------------------------------


def test_text_factory_get_ipv4_netmask_str(text_factory):
    """get_ipv4_netmask() must work when called with a plain string key."""
    assert text_factory.get_ipv4_netmask(PROVIDER_IP) == NETMASK
    assert text_factory.get_ipv4_netmask(CONSUMER_IP) == NETMASK


def test_text_factory_get_ipv4_netmask_ipv4address(text_factory):
    """get_ipv4_netmask() must work when called with an IPv4Address object."""
    assert text_factory.get_ipv4_netmask(ipaddress.IPv4Address(PROVIDER_IP)) == NETMASK
    assert text_factory.get_ipv4_netmask(ipaddress.IPv4Address(CONSUMER_IP)) == NETMASK


def test_flync_factory_get_ipv4_netmask_str(flync_factory):
    """FlyncFactory.get_ipv4_netmask() must work with a plain string key."""
    assert flync_factory.get_ipv4_netmask(PROVIDER_IP) == NETMASK


def test_flync_factory_get_ipv4_netmask_ipv4address(flync_factory):
    """FlyncFactory.get_ipv4_netmask() must work with an IPv4Address object."""
    assert flync_factory.get_ipv4_netmask(ipaddress.IPv4Address(PROVIDER_IP)) == NETMASK


# ---------------------------------------------------------------------------
# 2. Text output contains CIDR notation with the correct prefix length
# ---------------------------------------------------------------------------


def test_text_output_provider_cidr(text_factory):
    """Text output must include 10.10.10.10/255.255.255.128 for the provider."""
    text = str(text_factory)
    assert f"{PROVIDER_IP}/{NETMASK}" in text, f"Expected '{PROVIDER_IP}/{NETMASK}' in text output.\n" f"Got (relevant lines):\n" + "\n".join(
        l for l in text.splitlines() if "10.10.10" in l
    )


def test_text_output_consumer_cidr(text_factory):
    """Text output must include 10.10.10.11/255.255.255.128 for the consumer."""
    text = str(text_factory)
    assert f"{CONSUMER_IP}/{NETMASK}" in text, f"Expected '{CONSUMER_IP}/{NETMASK}' in text output."


# ---------------------------------------------------------------------------
# 3. FLYNC model preserves the non-standard netmask
# ---------------------------------------------------------------------------


def _get_flync_addresses(flync_factory):
    """Collect (ecu_name, address_obj) tuples from built FLYNC ECUs."""
    results = []
    for ecu in flync_factory._SimpleConfigurationFactory__flync_ecus:
        for ctrl in ecu.controllers:
            for iface in ctrl.interfaces:
                if iface is None:
                    continue
                for vi in iface.virtual_interfaces:
                    for addr in vi.addresses:
                        results.append((ecu.name, addr))
    return results


def test_flync_provider_netmask(flync_factory):
    """FLYNC IPv4AddressEndpoint for provider must use 255.255.255.128."""
    addresses = _get_flync_addresses(flync_factory)
    provider_addrs = [addr for name, addr in addresses if name == "ECU_PROVIDER"]
    assert provider_addrs, "No addresses found for ECU_PROVIDER in FLYNC model"
    addr = provider_addrs[0]
    assert str(addr.address) == PROVIDER_IP
    assert str(addr.ipv4netmask) == NETMASK, f"Expected netmask {NETMASK}, got {addr.ipv4netmask}. " "Likely falling back to default 255.255.255.0."


def test_flync_consumer_netmask(flync_factory):
    """FLYNC IPv4AddressEndpoint for consumer must use 255.255.255.128."""
    addresses = _get_flync_addresses(flync_factory)
    consumer_addrs = [addr for name, addr in addresses if name == "ECU_CONSUMER"]
    assert consumer_addrs, "No addresses found for ECU_CONSUMER in FLYNC model"
    addr = consumer_addrs[0]
    assert str(addr.address) == CONSUMER_IP
    assert str(addr.ipv4netmask) == NETMASK, f"Expected netmask {NETMASK}, got {addr.ipv4netmask}. " "Likely falling back to default 255.255.255.0."


# ---------------------------------------------------------------------------
# 4. Full FLYNC model creation succeeds
# ---------------------------------------------------------------------------


def test_flync_model_creation_succeeds(tmp_path):
    """Full FIBEX → FLYNC model creation must not raise any exception."""
    factory = FlyncFactory()
    FibexParser(plugin_file=None, ecu_name_replacement=None).parse_file(factory, str(NONSTANDARD_NETMASK_FIBEX), verbose=False)
    factory.parsing_done()
    factory.create_flync_model()
    ws_dir = tmp_path / "flync"
    ws_dir.mkdir()
    factory.save_flync_model(str(ws_dir.resolve()))
    assert ws_dir.exists()
