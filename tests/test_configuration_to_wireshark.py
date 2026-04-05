#!/usr/bin/python
"""Unit tests for configuration_to_wireshark_config module."""

from configuration_base_classes import BaseConfigurationFactory


class TestWiresharkConfig:
    """Test cases for Wireshark configuration generation."""

    def setup_method(self):
        """Set up test fixtures."""
        self.factory = BaseConfigurationFactory()

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

    def test_create_vlan(self):
        """Test VLAN creation."""
        vlan = self.factory.create_vlan("VLAN100", 100, 0)
        assert vlan.name() == "VLAN100"
        assert vlan.vlanid() == 100

    def test_create_switch(self):
        """Test switch creation."""
        ecu = self.factory.create_ecu("ECU1", [])
        switch = self.factory.create_switch("Switch1", ecu, [])
        assert switch.name() == "Switch1"


class TestWiresharkConfigHelper:
    """Test helper functions for Wireshark config."""

    def test_format_ip_for_wireshark(self):
        """Test formatting IP addresses for Wireshark."""
        from configuration_base_classes import is_ip

        # Valid IPs
        assert is_ip("192.168.1.1")
        assert is_ip("10.0.0.1")
        assert is_ip("172.16.0.1")

    def test_format_port_for_wireshark(self):
        """Test port formatting."""
        # SOME/IP default ports
        default_ports = [30000, 30001, 30002, 30003]

        for port in default_ports:
            assert isinstance(port, int)
            assert port >= 30000
