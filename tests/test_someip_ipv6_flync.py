#!/usr/bin/python
"""IPv6-specific tests for SOMEIP_IPv6_service.xml.

Verifies that:
1. The FIBEX parser correctly extracts IPv6 addresses and prefix lengths.
2. configuration_to_flync correctly builds IPv6AddressEndpoint objects.
3. The text output contains the expected IPv6 CIDR notation.
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
IPV6_FIBEX = EXAMPLES_DIR / "SOMEIP_IPv6_service.xml"


@pytest.fixture(scope="module")
def flync_factory():
    factory = FlyncFactory()
    FibexParser(plugin_file=None, ecu_name_replacement=None).parse_file(factory, str(IPV6_FIBEX), verbose=False)
    factory.parsing_done()
    factory.create_flync_ecus()
    return factory


@pytest.fixture(scope="module")
def text_factory():
    factory = TextFactory()
    FibexParser(plugin_file=None, ecu_name_replacement=None).parse_file(factory, str(IPV6_FIBEX), verbose=False)
    factory.parsing_done()
    return factory


# ---------------------------------------------------------------------------
# Prefix-length lookup
# ---------------------------------------------------------------------------


def test_ipv6_prefix_length_provider(flync_factory):
    prefix = flync_factory.get_ipv6_prefix_length("2001:db8::1")
    assert prefix == "64", f"Expected prefix '64', got {prefix!r}"


def test_ipv6_prefix_length_consumer(flync_factory):
    prefix = flync_factory.get_ipv6_prefix_length("2001:db8::2")
    assert prefix == "64", f"Expected prefix '64', got {prefix!r}"


# ---------------------------------------------------------------------------
# FLYNC ECU interface addresses
# ---------------------------------------------------------------------------


def _get_all_addresses(flync_factory):
    """Collect all (ecu_name, ip_obj, prefix) tuples from built FLYNC ECUs."""
    results = []
    for ecu in flync_factory._SimpleConfigurationFactory__flync_ecus:
        for ctrl in ecu.controllers:
            for iface in ctrl.interfaces:
                if iface is None:
                    continue
                for vi in iface.virtual_interfaces:
                    for addr in vi.addresses:
                        results.append((ecu.name, addr.address, getattr(addr, "ipv6prefix", None)))
    return results


def test_provider_ipv6_address(flync_factory):
    addresses = _get_all_addresses(flync_factory)
    provider_addrs = [(ip, pfx) for name, ip, pfx in addresses if name == "ECU_PROVIDER6"]
    assert provider_addrs, "No addresses found for ECU_PROVIDER6"
    ip, pfx = provider_addrs[0]
    assert isinstance(ip, ipaddress.IPv6Address), f"Expected IPv6Address, got {type(ip)}"
    assert str(ip) == "2001:db8::1"
    assert pfx == 64


def test_consumer_ipv6_address(flync_factory):
    addresses = _get_all_addresses(flync_factory)
    consumer_addrs = [(ip, pfx) for name, ip, pfx in addresses if name == "ECU_CONSUMER6"]
    assert consumer_addrs, "No addresses found for ECU_CONSUMER6"
    ip, pfx = consumer_addrs[0]
    assert isinstance(ip, ipaddress.IPv6Address), f"Expected IPv6Address, got {type(ip)}"
    assert str(ip) == "2001:db8::2"
    assert pfx == 64


# ---------------------------------------------------------------------------
# Text output contains CIDR notation
# ---------------------------------------------------------------------------


def test_text_output_contains_provider_cidr(text_factory):
    text = str(text_factory)
    assert "2001:db8::1/64" in text, "Expected '2001:db8::1/64' in text output"


def test_text_output_contains_consumer_cidr(text_factory):
    text = str(text_factory)
    assert "2001:db8::2/64" in text, "Expected '2001:db8::2/64' in text output"


# ---------------------------------------------------------------------------
# FLYNC model roundtrip (build full model without error)
# ---------------------------------------------------------------------------


def test_flync_model_creation_succeeds(tmp_path):
    """Full FIBEX → FLYNC model creation must not raise any exception."""
    factory = FlyncFactory()
    FibexParser(plugin_file=None, ecu_name_replacement=None).parse_file(factory, str(IPV6_FIBEX), verbose=False)
    factory.parsing_done()
    factory.create_flync_model()
    ws_dir = tmp_path / "flync"
    ws_dir.mkdir()
    factory.save_flync_model(str(ws_dir.resolve()))
    assert ws_dir.exists()
