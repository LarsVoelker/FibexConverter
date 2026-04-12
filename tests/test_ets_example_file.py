#!/usr/bin/python
"""Integration tests for examples/SOMEIP_Enhanced_Testability_Service.xml.

Covers both configuration_to_text (SimpleConfigurationFactory) and
configuration_to_wireshark_config (WiresharkConfigurationFactory).
"""

from pathlib import Path

import configuration_to_text
from configuration_to_text import SimpleConfigurationFactory
from configuration_to_wireshark_config import WiresharkConfigurationFactory
from fibex_parser import FibexParser

# g_gen_portid is only initialised inside main(); set it here for test use.
configuration_to_text.g_gen_portid = False

EXAMPLE_FILE = str(Path(__file__).parent.parent / "examples" / "SOMEIP_Enhanced_Testability_Service.xml")


def _parse_text():
    factory = SimpleConfigurationFactory()
    parser = FibexParser(plugin_file=None, ecu_name_replacement=None)
    parser.parse_file(factory, EXAMPLE_FILE, verbose=False)
    return factory, str(factory)


def _parse_wireshark():
    factory = WiresharkConfigurationFactory()
    parser = FibexParser(plugin_file=None, ecu_name_replacement=None)
    parser.parse_file(factory, EXAMPLE_FILE, verbose=False)
    return factory, parser


# ---------------------------------------------------------------------------
# Scenario 1 — configuration_to_text text output
# ---------------------------------------------------------------------------


class TestETSTextOutput:
    """Verify str(factory) content after parsing SOMEIP_Enhanced_Testability_Service.xml
    with SimpleConfigurationFactory."""

    def setup_method(self):
        self.factory, self.text = _parse_text()

    def test_services_section_present(self):
        assert "Services:" in self.text

    def test_service_name_in_output(self):
        assert "EnhancedTestabilityService" in self.text

    def test_service_id_in_output(self):
        assert "0x0101" in self.text

    def test_reset_method_in_output(self):
        assert "resetInterface" in self.text

    def test_echo_uint8_method_in_output(self):
        assert "echoUINT8" in self.text

    def test_event_uint8_in_output(self):
        assert "TestEventUINT8" in self.text

    def test_ecus_section_present(self):
        assert "ECUs:" in self.text

    def test_provider_ecu_in_output(self):
        assert "ECU_ETS_PROVIDER" in self.text

    def test_provider_ip_in_output(self):
        assert "192.168.200.1" in self.text

    def test_vlan_channel_in_output(self):
        assert "ETS_VLAN" in self.text

    def test_service_instance_in_output(self):
        assert "ServiceInstance" in self.text


# ---------------------------------------------------------------------------
# Scenario 2 — configuration_to_wireshark_config factory state
# ---------------------------------------------------------------------------


class TestETSWiresharkService:
    """Verify WiresharkConfigurationFactory internal state after parsing."""

    def setup_method(self):
        self.factory, self.parser = _parse_wireshark()
        self.service = self.factory.__services__["0101-01"]

    def test_service_registered(self):
        assert "0101-01" in self.factory.__services__

    def test_service_id(self):
        assert self.service.serviceid() == 0x0101

    def test_service_name(self):
        assert self.service.name() == "EnhancedTestabilityService"

    def test_service_major_version(self):
        assert self.service.majorversion() == 1

    def test_method_count(self):
        """All 34 unique method IDs must be registered."""
        assert len(self.service.methods()) == 34

    def test_reset_method_present(self):
        assert 0x01 in self.service.methods()
        assert self.service.methods()[0x01].name() == "resetInterface"

    def test_echo_uint8_method_present(self):
        assert 0x08 in self.service.methods()
        assert self.service.methods()[0x08].name() == "echoUINT8"

    def test_echo_common_datatypes_at_0x23(self):
        assert 0x23 in self.service.methods()
        assert self.service.methods()[0x23].name() == "echoCommonDatatypes"

    def test_subscribe_eventgroup_at_0x32(self):
        assert 0x32 in self.service.methods()
        assert self.service.methods()[0x32].name() == "clientServiceSubscribeEventgroup"

    def test_echo_union_present(self):
        assert 0x19 in self.service.methods()

    def test_echo_bitfields_present(self):
        assert 0x41 in self.service.methods()

    def test_event_count(self):
        assert len(self.service.events()) == 5

    def test_event_uint8_present(self):
        assert 0x8001 in self.service.events()
        assert self.service.events()[0x8001].name() == "TestEventUINT8"

    def test_event_uint8_array_present(self):
        assert 0x8002 in self.service.events()

    def test_event_uint8_reliable_present(self):
        assert 0x8003 in self.service.events()

    def test_event_uint8_multicast_present(self):
        assert 0x800B in self.service.events()

    def test_field_count(self):
        assert len(self.service.fields()) == 4

    def test_interface_version_field_present(self):
        names = {f.name() for f in self.service.fields().values()}
        assert "InterfaceVersion" in names

    def test_testfield_uint8_present(self):
        names = {f.name() for f in self.service.fields().values()}
        assert "TestFieldUINT8" in names

    def test_eventgroup_count(self):
        assert len(self.service.eventgroups()) == 3

    def test_eg2_all_present(self):
        assert 2 in self.service.eventgroups()
        assert self.service.eventgroups()[2].name() == "eg2_all"

    def test_eg5_unreliable_present(self):
        assert 5 in self.service.eventgroups()

    def test_eg6_multicast_present(self):
        assert 6 in self.service.eventgroups()
        assert self.service.eventgroups()[6].name() == "eg6_events_multicast"

    def test_provider_ecu_in_factory(self):
        assert "ECU_ETS_PROVIDER" in self.factory.__ecus__


# ---------------------------------------------------------------------------
# Scenario 3 — configuration_to_wireshark_config file output
# ---------------------------------------------------------------------------


class TestETSWiresharkOutput:
    """Verify write_name_configs() produces correct file content."""

    def setup_method(self):
        self.factory, _ = _parse_wireshark()

    def _write(self, tmp_path):
        sf = str(tmp_path / "services")
        mf = str(tmp_path / "methods")
        ef = str(tmp_path / "eventgroups")
        self.factory.write_name_configs(sf, mf, ef)
        return (
            (tmp_path / "services").read_text(),
            (tmp_path / "methods").read_text(),
            (tmp_path / "eventgroups").read_text(),
        )

    def test_services_file_header(self, tmp_path):
        services, _, _ = self._write(tmp_path)
        assert "# This file is automatically generated" in services

    def test_service_entry_in_services_file(self, tmp_path):
        services, _, _ = self._write(tmp_path)
        assert '"0101","EnhancedTestabilityService"' in services

    def test_reset_method_in_methods_file(self, tmp_path):
        _, methods, _ = self._write(tmp_path)
        assert '"0101","0001","resetInterface"' in methods

    def test_echo_uint8_in_methods_file(self, tmp_path):
        _, methods, _ = self._write(tmp_path)
        assert '"0101","0008","echoUINT8"' in methods

    def test_echo_common_datatypes_0x23_in_methods_file(self, tmp_path):
        _, methods, _ = self._write(tmp_path)
        assert '"0101","0023","echoCommonDatatypes"' in methods

    def test_subscribe_eventgroup_0x32_in_methods_file(self, tmp_path):
        _, methods, _ = self._write(tmp_path)
        assert '"0101","0032","clientServiceSubscribeEventgroup"' in methods

    def test_event_uint8_in_methods_file(self, tmp_path):
        _, methods, _ = self._write(tmp_path)
        assert '"0101","8001","TestEventUINT8"' in methods

    def test_event_multicast_in_methods_file(self, tmp_path):
        _, methods, _ = self._write(tmp_path)
        assert '"0101","800b","TestEventUINT8Multicast"' in methods

    def test_field_getter_in_methods_file(self, tmp_path):
        _, methods, _ = self._write(tmp_path)
        assert '"0101","0025","InterfaceVersion_Getter"' in methods

    def test_field_setter_in_methods_file(self, tmp_path):
        _, methods, _ = self._write(tmp_path)
        assert '"0101","0026","TestFieldUINT8_Setter"' in methods

    def test_field_notifier_in_methods_file(self, tmp_path):
        _, methods, _ = self._write(tmp_path)
        assert '"0101","8005","InterfaceVersion_Notifier"' in methods

    def test_eg2_all_in_eventgroups_file(self, tmp_path):
        _, _, eventgroups = self._write(tmp_path)
        assert '"0101","0002","eg2_all"' in eventgroups

    def test_eg5_unreliable_in_eventgroups_file(self, tmp_path):
        _, _, eventgroups = self._write(tmp_path)
        assert '"0101","0005","eg5_events_and_fields_unreliable"' in eventgroups

    def test_eg6_multicast_in_eventgroups_file(self, tmp_path):
        _, _, eventgroups = self._write(tmp_path)
        assert '"0101","0006","eg6_events_multicast"' in eventgroups
