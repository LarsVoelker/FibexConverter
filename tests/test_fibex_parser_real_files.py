#!/usr/bin/python
"""Integration tests for FibexParser using real generated FIBEX files."""

from pathlib import Path

import pytest

from configuration_to_text import SimpleConfigurationFactory
from fibex_parser import FibexParser

FIXTURES_DIR = Path(__file__).parent / "fibex_files"
TOPOLOGY_FILE = str(FIXTURES_DIR / "ethernet_topology.xml")
SOMEIP_FILE = str(FIXTURES_DIR / "someip_service.xml")


# ---------------------------------------------------------------------------
# Scenario 1 — Ethernet topology (ECUs + switch)
# ---------------------------------------------------------------------------


class TestEthernetTopologyFibexParser:
    """Parse ethernet_topology.xml and verify ECU/channel/switch results."""

    def setup_method(self):
        self.factory = SimpleConfigurationFactory()
        self.parser = FibexParser(plugin_file=None, ecu_name_replacement=None)
        self.parser.parse_file(self.factory, TOPOLOGY_FILE, verbose=False)

    def test_four_ecus_parsed(self):
        """All four ECUs (three endpoints + switch host) must be found."""
        ecus = self.factory.__ecus__
        assert "ECU_A" in ecus
        assert "ECU_B" in ecus
        assert "ECU_C" in ecus
        assert "ECU_SWITCH" in ecus

    def test_two_channels_with_correct_vlan_ids(self):
        """Both VLANs must be parsed with their numeric identifiers.

        Note: parse_topology() converts vlanid from string to int when it
        processes VLAN-MEMBERSHIP elements, so after parse_file() the value
        is an integer.
        """
        channels = self.parser.__channels__
        assert "CHAN_VLAN10" in channels
        assert "CHAN_VLAN20" in channels
        assert int(channels["CHAN_VLAN10"]["vlanid"]) == 10
        assert int(channels["CHAN_VLAN20"]["vlanid"]) == 20

    def test_vlan_channel_names(self):
        """Channel short-names are stored correctly."""
        assert self.parser.__channels__["CHAN_VLAN10"]["name"] == "VLAN10"
        assert self.parser.__channels__["CHAN_VLAN20"]["name"] == "VLAN20"

    def test_switch_present_in_factory(self):
        """The MainSwitch coupling element must appear in the factory."""
        assert "MainSwitch" in self.factory.__switches__

    def test_switch_has_three_ports(self):
        """MainSwitch must expose exactly three coupling ports."""
        switch = self.factory.__switches__["MainSwitch"]
        assert len(switch.__ports__) == 3

    def test_switch_is_associated_with_ecu(self):
        """The switch must reference its host ECU (ECU_SWITCH)."""
        switch = self.factory.__switches__["MainSwitch"]
        assert switch.ecu() is not None
        assert switch.ecu().name() == "ECU_SWITCH"

    def test_switch_ports_reference_ecu_controllers(self):
        """Every port that connects to an ECU must have a non-None controller."""
        switch = self.factory.__switches__["MainSwitch"]
        connected_controllers = [p.__ctrl__ for p in switch.__ports__ if p.__ctrl__ is not None]
        # All three ports connect to ECU controllers
        assert len(connected_controllers) == 3

    def test_switch_port_controller_names(self):
        """Switch port controllers must match the ECU controller short-names."""
        switch = self.factory.__switches__["MainSwitch"]
        ctrl_names = {p.__ctrl__.name() for p in switch.__ports__ if p.__ctrl__ is not None}
        assert "ECU_A_Ctrl" in ctrl_names
        assert "ECU_B_Ctrl" in ctrl_names
        assert "ECU_C_Ctrl" in ctrl_names


# ---------------------------------------------------------------------------
# Scenario 2 — SOME/IP service (provider + consumer)
# ---------------------------------------------------------------------------


class TestSomeIPServiceFibexParser:
    """Parse someip_service.xml and verify service/instance results."""

    def setup_method(self):
        self.factory = SimpleConfigurationFactory()
        self.parser = FibexParser(plugin_file=None, ecu_name_replacement=None)
        self.parser.parse_file(self.factory, SOMEIP_FILE, verbose=False)

    # --- Service interface ---

    def test_service_is_parsed(self):
        """The SVC_ECHO service interface must be present in parser state."""
        assert len(self.parser.__services__) > 0
        assert "SVC_ECHO" in self.parser.__services__

    def test_service_id(self):
        """Service identifier must be 0x1234 (4660 decimal)."""
        service = self.parser.__services__["SVC_ECHO"]
        assert service.serviceid() == 0x1234

    def test_service_version(self):
        """Service version must be major=1, minor=0."""
        service = self.parser.__services__["SVC_ECHO"]
        assert service.__major__ == 1
        assert service.__minor__ == 0

    def test_service_has_method_getvalue(self):
        """GetValue method (id=1) must be present in the service."""
        service = self.parser.__services__["SVC_ECHO"]
        assert 1 in service.methods()

    def test_method_getvalue_name(self):
        """GetValue method must have the correct short-name."""
        service = self.parser.__services__["SVC_ECHO"]
        assert service.methods()[1].name() == "GetValue"

    def test_method_getvalue_call_type(self):
        """GetValue must be REQUEST_RESPONSE."""
        service = self.parser.__services__["SVC_ECHO"]
        assert service.methods()[1].calltype() == "REQUEST_RESPONSE"

    def test_service_has_event_status(self):
        """StatusEvent (id=0x8001 = 32769) must be present in the service."""
        service = self.parser.__services__["SVC_ECHO"]
        assert 0x8001 in service.events()

    def test_event_status_name(self):
        """StatusEvent must have the correct short-name."""
        service = self.parser.__services__["SVC_ECHO"]
        assert service.events()[0x8001].name() == "StatusEvent"

    # --- Service instances ---

    def test_provider_service_instance_created(self):
        """PSI_ECHO must produce a service instance in the parser."""
        assert "PSI_ECHO" in self.parser.__ServiceInstances__

    def test_provider_instance_id(self):
        """Provided service instance must have instance-id=1."""
        si = self.parser.__ServiceInstances__["PSI_ECHO"]
        assert si.instanceid() == 1

    def test_provider_instance_references_service(self):
        """Service instance must reference the correct service."""
        si = self.parser.__ServiceInstances__["PSI_ECHO"]
        assert si.service().serviceid() == 0x1234

    # --- ECUs ---

    def test_provider_ecu_parsed(self):
        """ECU_PROVIDER must appear in the factory ECU registry."""
        assert "ECU_PROVIDER" in self.factory.__ecus__

    def test_consumer_ecu_parsed(self):
        """ECU_CONSUMER must appear in the factory ECU registry."""
        assert "ECU_CONSUMER" in self.factory.__ecus__

    def test_provider_ecu_has_one_controller(self):
        """ECU_PROVIDER must have exactly one controller."""
        ecu = self.factory.__ecus__["ECU_PROVIDER"]
        assert len(ecu.controllers()) == 1

    def test_consumer_ecu_has_one_controller(self):
        """ECU_CONSUMER must have exactly one controller."""
        ecu = self.factory.__ecus__["ECU_CONSUMER"]
        assert len(ecu.controllers()) == 1

    def test_channel_has_correct_vlan(self):
        """CHAN_VLAN100 must have VLAN identifier 100."""
        assert "CHAN_VLAN100" in self.parser.__channels__
        assert self.parser.__channels__["CHAN_VLAN100"]["vlanid"] == "100"
