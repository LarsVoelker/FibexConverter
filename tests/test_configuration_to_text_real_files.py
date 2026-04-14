#!/usr/bin/python
"""Integration tests for configuration_to_text using real generated FIBEX files."""

from pathlib import Path

import configuration_to_text
from configuration_to_text import SimpleConfigurationFactory
from fibex_parser import FibexParser

# g_gen_portid is only initialized inside main(); set it here for test use.
configuration_to_text.g_gen_portid = False

FIXTURES_DIR = Path(__file__).parent / "fibex_files"
TOPOLOGY_FILE = str(FIXTURES_DIR / "ethernet_topology.xml")
SOMEIP_FILE = str(FIXTURES_DIR / "someip_service.xml")


def _parse(filepath):
    factory = SimpleConfigurationFactory()
    parser = FibexParser(plugin_file=None, ecu_name_replacement=None)
    parser.parse_file(factory, filepath, verbose=False)
    return factory, str(factory)


# ---------------------------------------------------------------------------
# Scenario 1 — Ethernet topology text output
# ---------------------------------------------------------------------------


class TestEthernetTopologyTextOutput:
    """Verify str(factory) content after parsing ethernet_topology.xml."""

    def setup_method(self):
        self.factory, self.text = _parse(TOPOLOGY_FILE)

    def test_ecu_a_in_output(self):
        assert "ECU_A" in self.text

    def test_ecu_b_in_output(self):
        assert "ECU_B" in self.text

    def test_ecu_c_in_output(self):
        assert "ECU_C" in self.text

    def test_ecu_switch_in_output(self):
        assert "ECU_SWITCH" in self.text

    def test_ecus_section_present(self):
        assert "ECUs:" in self.text

    def test_ethernet_topology_section_present(self):
        assert "Ethernet Topology:" in self.text

    def test_switch_in_topology_section(self):
        """MainSwitch must appear inside the Ethernet Topology section.

        MainSwitch also appears earlier under ECU_SWITCH in the ECUs section,
        so search for it starting from the Ethernet Topology header position.
        """
        topology_idx = self.text.index("Ethernet Topology:")
        assert "MainSwitch" in self.text[topology_idx:]

    def test_vlan10_in_output(self):
        """VLAN10 channel name must appear in the Channels section."""
        assert "VLAN10" in self.text

    def test_vlan20_in_output(self):
        """VLAN20 channel name must appear in the Channels section."""
        assert "VLAN20" in self.text

    def test_channels_section_present(self):
        assert "Channels/Busses/VLANs:" in self.text

    def test_switch_ports_listed(self):
        """SwitchPort entries must appear for each of the three ports."""
        assert self.text.count("SwitchPort") >= 3

    def test_switch_port_references_ecu_a_controller(self):
        """Text must mention ECU_A's controller name near the switch."""
        assert "ECU_A_Ctrl" in self.text

    def test_switch_port_references_ecu_b_controller(self):
        assert "ECU_B_Ctrl" in self.text

    def test_switch_port_references_ecu_c_controller(self):
        assert "ECU_C_Ctrl" in self.text


# ---------------------------------------------------------------------------
# Scenario 2 — SOME/IP service text output
# ---------------------------------------------------------------------------


class TestSomeIPServiceTextOutput:
    """Verify str(factory) content after parsing someip_service.xml."""

    def setup_method(self):
        self.factory, self.text = _parse(SOMEIP_FILE)

    def test_services_section_present(self):
        assert "Services:" in self.text

    def test_service_name_in_output(self):
        """SVC_ECHO service name must appear in the Services section."""
        assert "SVC_ECHO" in self.text

    def test_service_id_in_output(self):
        """Service ID 0x1234 must appear in the formatted output."""
        assert "0x1234" in self.text

    def test_method_name_in_output(self):
        """GetValue method name must be listed under the service."""
        assert "GetValue" in self.text

    def test_event_name_in_output(self):
        """StatusEvent name must be listed under the service."""
        assert "StatusEvent" in self.text

    def test_ecus_section_present(self):
        assert "ECUs:" in self.text

    def test_provider_ecu_in_output(self):
        assert "ECU_PROVIDER" in self.text

    def test_consumer_ecu_in_output(self):
        assert "ECU_CONSUMER" in self.text

    def test_provider_ip_in_output(self):
        """Provider IP address must appear in the ECU/socket section."""
        assert "192.168.1.1" in self.text

    def test_consumer_ip_in_output(self):
        """Consumer IP address must appear in the ECU/socket section."""
        assert "192.168.1.2" in self.text

    def test_service_instance_in_output(self):
        """ServiceInstance entry must appear in the socket section."""
        assert "ServiceInstance" in self.text

    def test_vlan100_in_output(self):
        """VLAN100 channel must appear in the Channels section."""
        assert "VLAN100" in self.text
