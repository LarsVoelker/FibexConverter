#!/usr/bin/python
"""Unit tests for configuration_to_topology module."""

from configuration_base_classes import BaseConfigurationFactory


class TestTopologyOutput:
    """Test cases for topology output generation."""

    def setup_method(self):
        """Set up test fixtures."""
        self.factory = BaseConfigurationFactory()

    def test_create_vlan(self):
        """Test VLAN creation."""
        vlan = self.factory.create_vlan("VLAN100", 100, 0)
        assert vlan.name() == "VLAN100"
        assert vlan.vlanid() == 100
        assert vlan.priority() == 0

    def test_create_switch(self):
        """Test switch creation."""
        ecu = self.factory.create_ecu("ECU1", [])
        switch = self.factory.create_switch("Switch1", ecu, [])
        assert switch.name() == "Switch1"
        assert switch.ecu() == ecu

    def test_create_switch_port(self):
        """Test switch port creation."""
        controller = self.factory.create_controller("Controller1", [])
        port = self.factory.create_switch_port(portid="PORT1", ctrl=controller, port=None, default_vlan=None, vlans=[])
        assert port.portid() == "PORT1"
        assert port.connected_to_ecu_ctrl() == controller

    def test_create_multicast_path(self):
        """Test multicast path creation."""
        port1 = self.factory.create_switch_port("PORT1", None, None, None, [])
        port2 = self.factory.create_switch_port("PORT2", None, None, None, [])

        mcast = self.factory.create_multicast_path(
            switchport_tx=port1,
            vlan_tx=100,
            src_addr="192.168.1.1",
            switchport_rx=port2,
            vlan_rx=100,
            mcast_addr="224.0.0.1",
            comment="Test multicast",
        )
        assert mcast.vlanid() == 100
        assert mcast.source_addr() == "192.168.1.1"
        assert mcast.mc_addr() == "224.0.0.1"

    def test_create_socket(self):
        """Test socket creation."""
        socket = self.factory.create_socket(
            name="Socket1",
            ip="192.168.1.1",
            proto="udp",
            portnumber=30000,
            serviceinstances=[],
            serviceinstanceclients=[],
            eventhandlers=[],
            eventgroupreceivers=[],
        )
        assert socket.name() == "Socket1"
        assert socket.ip() == "192.168.1.1"
        assert socket.proto() == "udp"
        assert socket.portnumber() == 30000


class TestTopologyTableEntry:
    """Test cases for TopologyTableEntry."""

    def test_entry_creation_with_controllers(self):
        """Test creating an entry with controllers."""
        from configuration_to_topology import TopologyTableEntry

        entry = TopologyTableEntry(
            ecu_from="ECU1",
            ctrl_from="Controller1",
            switch_from=None,
            swport_from=None,
            ecu_to="ECU2",
            ctrl_to="Controller2",
            switch_to=None,
            swport_to=None,
            vlans={100, 200},
        )
        assert entry.ecu_from() == "ECU1"
        assert entry.ecu_to() == "ECU2"
        assert entry.to_output_set([100, 200]) is not None

    def test_entry_creation_with_switches(self):
        """Test creating an entry with switches."""
        from configuration_to_topology import TopologyTableEntry

        entry = TopologyTableEntry(
            ecu_from=None,
            ctrl_from=None,
            switch_from="Switch1",
            swport_from="Port1",
            ecu_to=None,
            ctrl_to=None,
            switch_to="Switch2",
            swport_to="Port2",
            vlans={100},
        )
        assert entry.to_output_set([100]) is not None
        assert entry.ecu_from() is None
        assert entry.ecu_to() is None


class TestTopologyHelper:
    """Test helper functions for topology."""

    def test_create_vlan(self):
        """Test creating VLANs."""
        factory = BaseConfigurationFactory()
        vlan1 = factory.create_vlan("VLAN100", 100, 0)
        vlan2 = factory.create_vlan("VLAN200", 200, 5)

        assert vlan1.vlanid() == 100
        assert vlan2.vlanid() == 200

    def test_create_ecu(self):
        """Test creating ECUs."""
        factory = BaseConfigurationFactory()
        ecu1 = factory.create_ecu("ECU1", [])
        ecu2 = factory.create_ecu("ECU2", [])

        assert ecu1.name() == "ECU1"
        assert ecu2.name() == "ECU2"
