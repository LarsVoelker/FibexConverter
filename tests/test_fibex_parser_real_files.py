#!/usr/bin/python
"""Integration tests for FibexParser using real generated FIBEX files."""

from pathlib import Path

from configuration_to_text import SimpleConfigurationFactory
from fibex_parser import FibexParser

TOPOLOGY_FILE = str(Path(__file__).parent.parent / "examples" / "Ethernet_Topology_with_Switches.xml")
SOMEIP_FILE = str(Path(__file__).parent.parent / "examples" / "SOMEIP_simple_service.xml")


# ---------------------------------------------------------------------------
# Scenario 1 — Ethernet topology (ECUs + switch)
# ---------------------------------------------------------------------------


class TestEthernetTopologyFibexParser:
    """Parse ethernet_topology.xml and verify ECU/channel/switch results."""

    def setup_method(self):
        self.factory = SimpleConfigurationFactory()
        self.parser = FibexParser(plugin_file=None, ecu_name_replacement=None)
        self.parser.parse_file(self.factory, TOPOLOGY_FILE, verbose=False)

    def test_ecus_parsed(self):
        """All nine ECUs (six endpoints + three switch hosts) must be found."""
        ecus = self.factory.__ecus__
        expected = {"ECU_A", "ECU_B", "ECU_C", "ECU_D", "ECU_E", "ECU_F", "ECU_SW1", "ECU_SW2", "ECU_SW3"}
        assert expected.issubset(set(ecus.keys()))

    def test_channels_with_correct_vlan_ids(self):
        """All five VLANs must be parsed with their numeric identifiers."""
        channels = self.parser.__channels__
        expected = {
            "CHAN_VLAN10": 10,
            "CHAN_VLAN20": 20,
            "CHAN_VLAN30": 30,
            "CHAN_VLAN40": 40,
            "CHAN_VLAN18": 18,
        }
        for chan_id, vlan_id in expected.items():
            assert chan_id in channels, f"Missing channel {chan_id}"
            # vlanid may be stored as string or int; ensure it matches
            actual = channels[chan_id].get("vlanid")
            # In the parser, vlanid may be string from XML or int from processing; convert to int for comparison
            if actual is not None:
                actual_int = int(actual) if isinstance(actual, str) else actual
                assert actual_int == vlan_id, f"VLAN ID mismatch for {chan_id}: expected {vlan_id}, got {actual}"
            else:
                assert False, f"Channel {chan_id} has no vlanid"

    def test_vlan_channel_names(self):
        """Channel short-names are stored correctly."""
        assert self.parser.__channels__["CHAN_VLAN10"]["name"] == "VLAN10"
        assert self.parser.__channels__["CHAN_VLAN20"]["name"] == "VLAN20"

    def test_switch_present_in_factory(self):
        """All three switches must appear in the factory."""
        expected_switches = {"Switch1", "Switch2", "Switch3"}
        assert expected_switches.issubset(set(self.factory.__switches__.keys()))

    def test_switch_has_expected_ports(self):
        """Each switch must expose the expected number of coupling ports."""
        switch1 = self.factory.__switches__["Switch1"]
        assert len(switch1.__ports__) == 5
        switch2 = self.factory.__switches__["Switch2"]
        assert len(switch2.__ports__) == 5
        switch3 = self.factory.__switches__["Switch3"]
        assert len(switch3.__ports__) == 3

    def test_switch_is_associated_with_ecu(self):
        """Each switch must reference its host ECU."""
        assert self.factory.__switches__["Switch1"].ecu().name() == "ECU_SW1"
        assert self.factory.__switches__["Switch2"].ecu().name() == "ECU_SW2"
        assert self.factory.__switches__["Switch3"].ecu().name() == "ECU_SW3"

    def test_switch_ports_reference_ecu_controllers(self):
        """Ports that connect to ECUs must have a non-None controller."""
        # Switch1: ports 1,2,4,5 have controllers (ECU_A, ECU_B, ECU_C, Switch1_Mgmt) => 4
        switch1 = self.factory.__switches__["Switch1"]
        ctrls1 = [p.__ctrl__ for p in switch1.__ports__ if p.__ctrl__ is not None]
        assert len(ctrls1) == 4
        # Switch2: ports 2,3,5 have controllers (ECU_D, ECU_E, Switch2_Mgmt) => 3
        switch2 = self.factory.__switches__["Switch2"]
        ctrls2 = [p.__ctrl__ for p in switch2.__ports__ if p.__ctrl__ is not None]
        assert len(ctrls2) == 3
        # Switch3: ports 2,3 have controllers (ECU_F, Switch3_Mgmt) => 2
        switch3 = self.factory.__switches__["Switch3"]
        ctrls3 = [p.__ctrl__ for p in switch3.__ports__ if p.__ctrl__ is not None]
        assert len(ctrls3) == 2

    def test_switch_port_controller_names(self):
        """Switch port controllers must match the expected ECU controller short-names."""
        switch1 = self.factory.__switches__["Switch1"]
        names1 = {p.__ctrl__.name() for p in switch1.__ports__ if p.__ctrl__ is not None}
        assert names1 == {"ECU_A_Ctrl", "ECU_B_Ctrl", "ECU_C_Ctrl", "Switch1_Mgmt"}

        switch2 = self.factory.__switches__["Switch2"]
        names2 = {p.__ctrl__.name() for p in switch2.__ports__ if p.__ctrl__ is not None}
        assert names2 == {"ECU_D_Ctrl", "ECU_E_Ctrl", "Switch2_Mgmt"}

        switch3 = self.factory.__switches__["Switch3"]
        names3 = {p.__ctrl__.name() for p in switch3.__ports__ if p.__ctrl__ is not None}
        assert names3 == {"ECU_F_Ctrl", "Switch3_Mgmt"}


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
