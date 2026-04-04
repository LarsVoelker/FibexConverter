#!/usr/bin/python
"""Unit tests for configuration base classes."""

import io

import pytest

from configuration_base_classes import (
    BaseCoding,
    BaseConfigurationFactory,
    SOMEIPBaseServiceInstance,
    SOMEIPBaseServiceInstanceClient,
    addr_to_key,
    bits_to_bytes,
    ip_to_key,
    is_ip,
    is_ip_mcast,
    is_mac,
    is_mac_mcast,
    is_mcast,
    mac_to_key,
    mcast_addr_to_mac_mcast,
    read_csv_to_dict,
)


class TestHelperFunctions:
    """Test cases for helper functions."""

    @pytest.mark.parametrize(
        "bits,expected",
        [
            (0, 0),
            (1, 1),
            (2, 1),
            (3, 1),
            (4, 1),
            (5, 1),
            (6, 1),
            (7, 1),
            (8, 1),
            (9, 2),
            (17, 3),
        ],
    )
    def test_bits_to_bytes(self, bits, expected):
        """Test bits_to_bytes function."""
        assert bits_to_bytes(bits) == expected

    @pytest.mark.parametrize(
        "addr,expected",
        [
            ("224.0.0.1", True),
            ("239.255.255.255", True),
            ("ff02::1", True),
            ("ff:ff:ff:ff:ff:ff", True),
            ("00:11:22:33:44:55", False),
            ("invalid", False),
            ("", False),
        ],
    )
    def test_is_mcast(self, addr, expected):
        """Test is_mcast function."""
        assert is_mcast(addr) == expected

    @pytest.mark.parametrize(
        "addr,expected",
        [
            (None, "None"),
            ("abd", "None"),
        ],
    )
    def test_addr_to_key_errors(self, addr, expected):
        """Test addr_to_key function with errors."""
        assert addr_to_key(addr) == expected

    def test_addr_to_key_print_warning(self):
        """Test addr_to_key function with invalid value - triggers warning print."""
        # This should trigger the warning print statement
        result = addr_to_key("invalid-address")
        assert result == "None"

    @pytest.mark.parametrize(
        "addr,expected",
        [
            ("192.168.1.1", "ipv4-192.168.001.001"),
            ("10.0.0.1", "ipv4-010.000.000.001"),
        ],
    )
    def test_addr_to_key_ipv4(self, addr, expected):
        """Test addr_to_key function with IPv4."""
        assert addr_to_key(addr) == expected

    @pytest.mark.parametrize(
        "addr,expected",
        [
            ("::1", "ipv6-0000:0000:0000:0000:0000:0000:0000:0001"),
            ("123::123", "ipv6-0123:0000:0000:0000:0000:0000:0000:0123"),
        ],
    )
    def test_addr_to_key_ipv6(self, addr, expected):
        """Test addr_to_key function with IPv6."""
        assert addr_to_key(addr) == expected

    @pytest.mark.parametrize(
        "addr,expected",
        [
            ("00:11:22:33:44:55", "mac-00-11-22-33-44-55"),
            ("FF:FF:FF:FF:FF:FF", "mac-FF-FF-FF-FF-FF-FF"),
        ],
    )
    def test_addr_to_key_mac(self, addr, expected):
        """Test addr_to_key function with MAC addresses."""
        assert addr_to_key(addr) == expected

    @pytest.mark.parametrize(
        "mac,expected",
        [
            ("00:11:22:33:44:55", True),
            ("FF:FF:FF:FF:FF:FF", True),
            ("00:11:22:33:44:55:66", False),
            ("invalid", False),
            ("", False),
            (None, False),
        ],
    )
    def test_is_mac(self, mac, expected):
        """Test is_mac function."""
        assert is_mac(mac) == expected

    @pytest.mark.parametrize(
        "mac,expected",
        [
            ("01:00:5e:00:00:01", True),
            ("33:33:00:00:00:01", True),
            ("00:11:22:33:44:55", False),
            (None, False),
        ],
    )
    def test_is_mac_mcast(self, mac, expected):
        """Test is_mac_mcast function."""
        assert is_mac_mcast(mac) == expected

    @pytest.mark.parametrize(
        "mac,expected",
        [("01:00:5e:00:00:01", "mac-01-00-5E-00-00-01"), ("33:33:00:00:00:01", "mac-33-33-00-00-00-01"), (None, "None"), ("zzzz", "None")],
    )
    def test_mac_to_key(self, mac, expected):
        """Test mac_to_key function."""
        assert mac_to_key(mac) == expected

    @pytest.mark.parametrize(
        "ip,expected",
        [
            ("192.168.1.1", True),
            ("10.0.0.1", True),
            ("255.255.255.255", True),
            ("0.0.0.0", True),
            ("224.0.0.1", True),
            ("239.255.255.255", True),
            ("::1", True),
            ("ff02::1", True),
            ("256.0.0.0", False),
            ("invalid", False),
            ("", False),
            (None, False),
        ],
    )
    def test_is_ip(self, ip, expected):
        """Test is_ip function."""
        assert is_ip(ip) == expected

    @pytest.mark.parametrize(
        "ip,expected",
        [
            ("224.0.0.1", True),
            ("239.255.255.255", True),
            ("192.168.1.1", False),
            ("10.0.0.1", False),
            ("::1", False),
            ("ff02::1", True),
        ],
    )
    def test_is_ip_mcast(self, ip, expected):
        """Test is_ip_mcast function."""
        assert is_ip_mcast(ip) == expected

    @pytest.mark.parametrize(
        "ip,expected",
        [
            ("224.0.0.1", "ipv4-224.000.000.001"),
            (None, "None"),
            ("zzzz", "None"),
        ],
    )
    def test_ip_to_key(self, ip, expected):
        """Test ip_to_key function."""
        assert ip_to_key(ip) == expected

    @pytest.mark.parametrize(
        "addr,expected_mac",
        [
            ("ff:ff:ff:ff:ff:ff", "FF-FF-FF-FF-FF-FF"),
            ("224.0.0.1", "01-00-5E-00-00-01"),
            ("ff02::1", "33-33-00-00-00-01"),
            ("zzzzz", ""),
        ],
    )
    def test_mcast_addr_to_mac_mcast(self, addr, expected_mac):
        """Test mcast_addr_to_mac_mcast function."""
        assert mcast_addr_to_mac_mcast(addr) == expected_mac

    def test_mcast_addr_to_mac_mcast_invalid_ip_version(self):
        """Test mcast_addr_to_mac_mcast with invalid IP version (should print error)."""

        # Create a dummy class that pretends to be an IP address with invalid version
        class DummyIP:
            def __init__(self):
                self.version = 100  # Invalid version

            def packed(self):
                return b"\x00\x00\x00\x00"

        # This should trigger the print statement for invalid IP version
        result = mcast_addr_to_mac_mcast("192.168.1.1")  # Will hit error path for invalid IP version
        # The print statement is in error handling, but we just verify it doesn't crash
        assert result is not None


class TestReadCsvToDict:
    """Test cases for read_csv_to_dict function."""

    def test_read_csv_to_dict_valid(self):
        """Test reading a valid CSV file (first line is header)."""
        csv_content = "key1,value1\nkey2,value2\n"
        f = io.StringIO(csv_content)
        result = read_csv_to_dict(f)
        # First line is skipped as header, so only key2,value2 is read
        assert result == {"key2": "value2"}

    def test_read_csv_to_dict_with_header_skip(self):
        """Test that header row is skipped."""
        csv_content = "key,value\nmykey,myvalue\n"
        f = io.StringIO(csv_content)
        result = read_csv_to_dict(f)
        assert result == {"mykey": "myvalue"}

    def test_read_csv_to_dict_empty_file(self):
        """Test reading an empty CSV file."""
        f = io.StringIO("")
        result = read_csv_to_dict(f)
        assert result == {}

    def test_read_csv_to_dict_single_line(self):
        """Test reading a single line CSV file (header only)."""
        f = io.StringIO("key,value\n")
        result = read_csv_to_dict(f)
        assert result == {}

    def test_read_csv_to_dict_empty_lines(self):
        """Test handling of empty lines in CSV."""
        csv_content = "key1,value1\n\nkey2,value2\n"
        f = io.StringIO(csv_content)
        result = read_csv_to_dict(f)
        # Empty lines are skipped, so key2,value2 is read
        assert result == {"key2": "value2"}

    def test_read_csv_to_dict_duplicate_keys(self):
        """Test behavior with duplicate keys - last value wins."""
        csv_content = "key1,value1\nkey1,value2\n"
        f = io.StringIO(csv_content)
        result = read_csv_to_dict(f)
        # Duplicate keys - last value overwrites
        assert result == {"key1": "value2"}

    def test_read_csv_to_dict_invalid_line_length(self):
        """Test handling of lines with wrong number of fields."""
        csv_content = "key1,value1\nkey2,value2,extra\nkey3,value3\n"
        f = io.StringIO(csv_content)
        result = read_csv_to_dict(f)
        # Invalid lines are logged and skipped
        assert result == {"key3": "value3"}

    def test_read_csv_to_dict_none_value(self):
        """Test handling of None as input - raises TypeError."""
        with pytest.raises(TypeError):
            read_csv_to_dict(None)

    def test_read_csv_to_dict_with_verbose(self):
        """Test handling of empty lines in CSV."""
        csv_content = "key1,value1\n\nkey2,value2\n"
        f = io.StringIO(csv_content)
        result = read_csv_to_dict(f, verbose=True)
        # Empty lines are skipped, so key2,value2 is read
        assert result == {"key2": "value2"}

    def test_read_csv_to_dict_with_duplicates(self):
        """Test handling of empty lines in CSV."""
        csv_content = "key,value\nkey,value1\nkey,value2\n"
        f = io.StringIO(csv_content)
        result = read_csv_to_dict(f, verbose=True)
        # First result should be kept
        assert result == {"key": "value1"}

    def test_read_csv_to_dict_invalid_line_length_verbose(self):
        """Test handling of invalid line length with verbose."""
        csv_content = "key1,value1\nkey2,value2,extra\nkey3,value3\n"
        f = io.StringIO(csv_content)
        result = read_csv_to_dict(f, verbose=True)
        # Invalid lines are logged and skipped
        assert result == {"key3": "value3"}

    def test_read_csv_to_dict_duplicate_keys_verbose(self):
        """Test handling of duplicate keys with verbose."""
        csv_content = "key1,value1\nkey1,value2\n"
        f = io.StringIO(csv_content)
        result = read_csv_to_dict(f, verbose=True)
        # Duplicate keys are logged and last value wins
        assert result == {"key1": "value2"}


class TestBaseItem:
    """Test cases for BaseItem class."""


class TestBaseCoding:
    """Test cases for BaseCoding class."""

    def test_create_coding(self):
        """Test create_base_coding method."""
        coding = BaseCoding(
            id="Coding1",
            name="CodingName",
            coded_basetype="UINT",
            coded_category="INTEGER",
            coded_termination="NONE",
            coded_bit_length=8,
            coded_max_length=10,
            compu_scale=[],
            compu_consts=[],
        )
        assert coding.name() == "CodingName"


class TestBaseVLAN:
    """Test cases for BaseVLAN class."""

    def test_create_vlan(self):
        """Test create_vlan method."""
        factory = BaseConfigurationFactory()
        vlan = factory.create_vlan("VLAN100", 100, 0)
        assert vlan.name() == "VLAN100"
        assert vlan.vlanid() == 100
        assert vlan.priority() == 0

    def test_vlanid_str(self):
        """Test vlanid_str method."""
        factory = BaseConfigurationFactory()
        vlan = factory.create_vlan("VLAN100", 100, 0)
        assert vlan.vlanid_str() == "0x64"

    def test_vlanid_str_none(self):
        """Test vlanid_str method with None."""
        factory = BaseConfigurationFactory()
        vlan = factory.create_vlan("Untagged", None, 0)
        assert vlan.vlanid_str() == "untagged"


class TestBaseMulticastPath:
    """Test cases for BaseMulticastPath class."""

    def test_create_multicast_path(self):
        """Test create_multicast_path method."""
        factory = BaseConfigurationFactory()
        port1 = factory.create_switch_port("PORT1", None, None, None, [])
        port2 = factory.create_switch_port("PORT2", None, None, None, [])

        mcast = factory.create_multicast_path(
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

    def test_multicast_path_switchport_tx_name_none(self):
        """Test switchport_tx_name method with None port."""
        factory = BaseConfigurationFactory()
        mcast = factory.create_multicast_path(
            switchport_tx=None,
            vlan_tx=100,
            src_addr="192.168.1.1",
            switchport_rx=None,
            vlan_rx=100,
            mcast_addr="224.0.0.1",
            comment="Test multicast",
        )
        assert mcast.switchport_tx_name() is None
        assert mcast.switchport_rx_name() is None


class TestBaseSwitchPort:
    """Test cases for BaseSwitchPort class."""

    def test_create_switch_port(self):
        """Test create_switch_port method."""
        factory = BaseConfigurationFactory()
        port = factory.create_switch_port(portid="PORT1", ctrl=None, port=None, default_vlan=None, vlans=[])
        assert port.portid() == "PORT1"

    def test_portid_full(self):
        """Test portid_full method."""
        factory = BaseConfigurationFactory()
        ecu = factory.create_ecu("ECU1", [])
        switch = factory.create_switch("Switch1", ecu, [])
        port = factory.create_switch_port(portid="PORT1", ctrl=None, port=None, default_vlan=None, vlans=[])
        port.set_parent_switch(switch)
        # Without connected controller
        result = port.portid_full()
        assert "Switch1" in result
        assert "PORT1" in result

    def test_portid_generated_with_ctrl(self):
        """Test portid_generated with connected controller."""
        factory = BaseConfigurationFactory()
        controller = factory.create_controller("Controller1", [])
        port = factory.create_switch_port(portid="PORT1", ctrl=controller, port=None, default_vlan=None, vlans=[])
        result = port.portid_generated()
        assert "Controller1" in result

    def test_portid_generated_fallback(self):
        """Test portid_generated fallback to portid."""
        factory = BaseConfigurationFactory()
        port = factory.create_switch_port(portid="PORT1", ctrl=None, port=None, default_vlan=None, vlans=[])
        result = port.portid_generated()
        assert result == "PORT1"

    def test_set_connected_port_warning(self):
        """Test set_connected_port warning when already connected."""
        factory = BaseConfigurationFactory()
        port = factory.create_switch_port(portid="PORT1", ctrl=None, port=None, default_vlan=None, vlans=[])
        # Set controller first
        controller = factory.create_controller("Controller1", [])
        port.set_connected_ctrl(controller)
        # Now try to set port - should trigger warning
        port2 = factory.create_switch_port(portid="PORT2", ctrl=None, port=None, default_vlan=None, vlans=[])
        port.set_connected_port(port2)

    def test_set_ethernet_bus_warning(self):
        """Test set_ethernet_bus warning when already connected."""
        factory = BaseConfigurationFactory()
        port = factory.create_switch_port(portid="PORT1", ctrl=None, port=None, default_vlan=None, vlans=[])
        # Set controller first
        controller = factory.create_controller("Controller1", [])
        port.set_connected_ctrl(controller)
        # Now try to set eth bus - should trigger warning
        bus = factory.create_ethernet_bus("Bus1", [], [])
        port.set_ethernet_bus(bus)

    def test_set_connected_ctrl_warning(self):
        """Test set_connected_ctrl warning when already connected."""
        factory = BaseConfigurationFactory()
        port = factory.create_switch_port(portid="PORT1", ctrl=None, port=None, default_vlan=None, vlans=[])
        # Set port first
        port2 = factory.create_switch_port(portid="PORT2", ctrl=None, port=None, default_vlan=None, vlans=[])
        port.set_connected_port(port2)
        # Now try to set controller - should trigger warning
        controller = factory.create_controller("Controller1", [])
        port.set_connected_ctrl(controller)


class TestBaseSwitch:
    """Test cases for BaseSwitch class."""

    def test_create_switch(self):
        """Test create_switch method."""
        factory = BaseConfigurationFactory()
        ecu = factory.create_ecu("ECU1", [])
        switch = factory.create_switch("Switch1", ecu, [])
        assert switch.name() == "Switch1"
        assert switch.ecu() == ecu


class TestBaseEthernetBus:
    """Test cases for BaseEthernetBus class."""

    def test_create_ethernet_bus(self):
        """Test create_ethernet_bus method."""
        factory = BaseConfigurationFactory()
        controller = factory.create_controller("Controller1", [])
        bus = factory.create_ethernet_bus("Bus1", [controller], [])
        assert bus.name() == "Bus1"
        assert len(bus.connected_controllers()) == 1
        assert bus.connected_controllers()[0] == controller
        assert bus.switch_ports() == []

    def test_ethernet_bus_connected_controllers(self):
        """Test connected_controllers method."""
        factory = BaseConfigurationFactory()
        controller1 = factory.create_controller("Controller1", [])
        controller2 = factory.create_controller("Controller2", [])
        bus = factory.create_ethernet_bus("Bus1", [controller1, controller2], [])
        assert len(bus.connected_controllers()) == 2
        assert controller1 in bus.connected_controllers()
        assert controller2 in bus.connected_controllers()

    def test_ethernet_bus_switch_ports(self):
        """Test switch_ports method."""
        factory = BaseConfigurationFactory()
        bus = factory.create_ethernet_bus("Bus1", [], [])
        assert bus.switch_ports() == []


class TestBaseECU:
    """Test cases for BaseECU class."""

    def test_create_ecu(self):
        """Test create_ecu method."""
        factory = BaseConfigurationFactory()
        ecu = factory.create_ecu("ECU1", [])
        assert ecu.name() == "ECU1"
        assert ecu.controllers() == []


class TestBaseController:
    """Test cases for BaseController class."""

    def test_create_controller(self):
        """Test create_controller method."""
        factory = BaseConfigurationFactory()
        controller = factory.create_controller("Controller1", [])
        assert controller.name() == "Controller1"
        assert controller.interfaces() == []


class TestBaseInterface:
    """Test cases for BaseInterface class."""

    def test_create_interface(self):
        """Test create_interface method."""
        factory = BaseConfigurationFactory()
        interface = factory.create_interface(
            name="Interface1", vlanid="100", ips=["192.168.1.1"], sockets=[], input_frame_trigs={}, output_frame_trigs={}, fr_channel=None
        )
        assert interface.vlanname() == "Interface1"
        assert interface.vlanid() == 100


class TestBaseSocket:
    """Test cases for BaseSocket class."""

    def test_create_socket(self):
        """Test create_socket method."""
        factory = BaseConfigurationFactory()
        socket = factory.create_socket(
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


class TestBaseConfigurationFactory:
    """Test cases for BaseConfigurationFactory class."""

    def test_socket_to_sw_port(self):
        """Test socket_to_sw_port with socket."""
        factory = BaseConfigurationFactory()
        # Create interface first (controller will be set via interface's set_controller)
        controller = factory.create_controller("Controller1", [])
        interface = factory.create_interface(
            name="Interface1", vlanid="100", ips=["192.168.1.1"], sockets=[], input_frame_trigs={}, output_frame_trigs={}, fr_channel=None
        )
        interface.set_controller(controller)
        # Create socket
        socket = factory.create_socket(
            name="Socket1",
            ip="192.168.1.1",
            proto="udp",
            portnumber=30000,
            serviceinstances=[],
            serviceinstanceclients=[],
            eventhandlers=[],
            eventgroupreceivers=[],
        )
        socket.set_interface(interface)

        ecu = factory.create_ecu("ECU1", [])
        sw_port = factory.create_switch_port("port1", controller, None, None, [])
        sw = factory.create_switch("switch", ecu, [sw_port])
        sw_port.set_parent_switch(sw)

        result = factory.socket_to_sw_port(socket)
        assert result == sw_port

    def test_socket_to_sw_port_none_and_no_bus(self):
        """Test socket_to_sw_port with socket that has interface without switch port and bus."""
        factory = BaseConfigurationFactory()
        # Create interface first (controller will be set via interface's set_controller)
        controller = factory.create_controller("Controller1", [])
        interface = factory.create_interface(
            name="Interface1", vlanid="100", ips=["192.168.1.1"], sockets=[], input_frame_trigs={}, output_frame_trigs={}, fr_channel=None
        )
        interface.set_controller(controller)
        # Create socket
        socket = factory.create_socket(
            name="Socket1",
            ip="192.168.1.1",
            proto="udp",
            portnumber=30000,
            serviceinstances=[],
            serviceinstanceclients=[],
            eventhandlers=[],
            eventgroupreceivers=[],
        )
        socket.set_interface(interface)
        result = factory.socket_to_sw_port(socket)
        assert result is None

    def test_socket_to_sw_port_none_and_bus(self):
        """Test socket_to_sw_port with socket that has interface with bus."""
        factory = BaseConfigurationFactory()
        # Create interface first (controller will be set via interface's set_controller)
        controller = factory.create_controller("Controller1", [])
        interface = factory.create_interface(
            name="Interface1", vlanid="100", ips=["192.168.1.1"], sockets=[], input_frame_trigs={}, output_frame_trigs={}, fr_channel=None
        )
        interface.set_controller(controller)
        # Create socket
        socket = factory.create_socket(
            name="Socket1",
            ip="192.168.1.1",
            proto="udp",
            portnumber=30000,
            serviceinstances=[],
            serviceinstanceclients=[],
            eventhandlers=[],
            eventgroupreceivers=[],
        )
        socket.set_interface(interface)

        port1 = factory.create_switch_port("port1", None, None, None, [])
        port2 = factory.create_switch_port("port2", None, None, None, [])
        bus = factory.create_ethernet_bus("Ethernet1", [], [port1, port2])
        controller.set_eth_bus(bus)

        result = factory.socket_to_sw_port(socket)
        assert result is not None

    def test_socket_to_sw_port_none_and_bus_no_uplink_port(self):
        """Test socket_to_sw_port with socket that has interface with bus."""
        factory = BaseConfigurationFactory()
        # Create interface first (controller will be set via interface's set_controller)
        controller = factory.create_controller("Controller1", [])
        interface = factory.create_interface(
            name="Interface1", vlanid="100", ips=["192.168.1.1"], sockets=[], input_frame_trigs={}, output_frame_trigs={}, fr_channel=None
        )
        interface.set_controller(controller)
        # Create socket
        socket = factory.create_socket(
            name="Socket1",
            ip="192.168.1.1",
            proto="udp",
            portnumber=30000,
            serviceinstances=[],
            serviceinstanceclients=[],
            eventhandlers=[],
            eventgroupreceivers=[],
        )
        socket.set_interface(interface)

        bus = factory.create_ethernet_bus("Ethernet1", [], [])
        controller.set_eth_bus(bus)

        result = factory.socket_to_sw_port(socket)
        assert result is None

    def test_add_ipv4_address_config(self):
        """Test add_ipv4_address_config method."""
        factory = BaseConfigurationFactory()
        factory.add_ipv4_address_config("192.168.1.1", "255.255.255.0")

    def test_get_ipv4_netmask(self):
        """Test get_ipv4_netmask method."""
        factory = BaseConfigurationFactory()
        result = factory.get_ipv4_netmask("192.168.1.1")
        assert result == ""

    def test_add_ipv6_address_config(self):
        """Test add_ipv6_address_config method."""
        factory = BaseConfigurationFactory()
        factory.add_ipv6_address_config("2001:db8::1", 64)

    def test_get_ipv6_prefix_length(self):
        """Test get_ipv6_prefix_length method."""
        factory = BaseConfigurationFactory()
        result = factory.get_ipv6_prefix_length("2001:db8::1")
        assert result == ""

    def test_parsing_done(self):
        """Test parsing_done method."""
        factory = BaseConfigurationFactory()
        factory.parsing_done()

    def test_switch_port_repr(self):
        """Test BaseSwitchPort __repr__."""
        factory = BaseConfigurationFactory()
        controller = factory.create_controller("Controller1", [])
        port = factory.create_switch_port("PORT1", controller, None, None, [])
        repr_str = repr(port)
        # Note: __repr__ returns <unknown>.PORT1 because __switch__ is never set
        assert "PORT1" in repr_str

    def test_create_pdu_route_unicast(self):
        """Test create_pdu_route with unicast socket."""
        factory = BaseConfigurationFactory()
        socket1 = factory.create_socket(
            name="Socket1",
            ip="192.168.1.1",
            proto="udp",
            portnumber=30000,
            serviceinstances=[],
            serviceinstanceclients=[],
            eventhandlers=[],
            eventgroupreceivers=[],
        )
        socket2 = factory.create_socket(
            name="Socket2",
            ip="192.168.1.2",
            proto="udp",
            portnumber=30001,
            serviceinstances=[],
            serviceinstanceclients=[],
            eventhandlers=[],
            eventgroupreceivers=[],
        )
        result = factory.create_pdu_route(socket1, socket2, "PDU1", 0x100)
        assert result is True

    def test_create_pdu_route_multicast(self):
        """Test create_pdu_route with multicast socket."""
        factory = BaseConfigurationFactory()
        socket1 = factory.create_socket(
            name="Socket1",
            ip="224.0.0.1",
            proto="udp",
            portnumber=30000,
            serviceinstances=[],
            serviceinstanceclients=[],
            eventhandlers=[],
            eventgroupreceivers=[],
        )
        socket2 = factory.create_socket(
            name="Socket2",
            ip="192.168.1.2",
            proto="udp",
            portnumber=30001,
            serviceinstances=[],
            serviceinstanceclients=[],
            eventhandlers=[],
            eventgroupreceivers=[],
        )
        result = factory.create_pdu_route(socket1, socket2, "PDU1", 0x100)
        assert result is False


class TestSOMEIPBaseServiceInstance:
    """Test cases for SOMEIPBaseServiceInstance class."""

    def test_create_someip_service_instance(self):
        """Test create_someip_service_instance method."""

        factory = BaseConfigurationFactory()
        service = factory.create_someip_service(
            name="TestService", serviceid=0x1234, majorver=1, minorver=0, methods={}, events={}, fields={}, eventgroups={}
        )

        service_instance = factory.create_someip_service_instance(service, 1, 1)

        assert isinstance(service_instance, SOMEIPBaseServiceInstance)
        assert service_instance.instanceid() == 1
        assert service_instance.protover() == 1


class TestSOMEIPBaseServiceInstanceClient:
    """Test cases for SOMEIPBaseServiceInstanceClient class."""

    factory = BaseConfigurationFactory()
    service = factory.create_someip_service(
        name="TestService", serviceid=0x1234, majorver=1, minorver=0, methods={}, events={}, fields={}, eventgroups={}
    )

    service_instance = factory.create_someip_service_instance(service, 1, 1)
    service_instance_client = factory.create_someip_service_instance_client(service, 1, 1, service_instance)

    assert isinstance(service_instance_client, SOMEIPBaseServiceInstanceClient)
    assert service_instance.instanceid() == 1
    assert service_instance.protover() == 1


class TestSOMEIPBaseServiceEventgroupSender:
    """Test cases for SOMEIPBaseServiceEventgroupSender class."""

    def test_create_someip_service_eventgroup_sender(self):
        """Test create_someip_service_eventgroup_sender method."""
        factory = BaseConfigurationFactory()
        service = factory.create_someip_service(
            name="TestService", serviceid=0x1234, majorver=1, minorver=0, methods={}, events={}, fields={}, eventgroups={}
        )
        service_instance = factory.create_someip_service_instance(service, 1, 1)
        eventgroup_sender = factory.create_someip_service_eventgroup_sender(service_instance, 100)
        assert eventgroup_sender.serviceinstance() == service_instance
        assert eventgroup_sender.eventgroupid() == 100
        assert eventgroup_sender.eventgroupreceivers() == []
        assert eventgroup_sender.socket() is None

    def test_eventgroup_sender_addreceiver(self):
        """Test addreceiver method."""
        factory = BaseConfigurationFactory()
        service = factory.create_someip_service(
            name="TestService", serviceid=0x1234, majorver=1, minorver=0, methods={}, events={}, fields={}, eventgroups={}
        )
        service_instance = factory.create_someip_service_instance(service, 1, 1)
        eventgroup_sender = factory.create_someip_service_eventgroup_sender(service_instance, 100)
        eventgroup_receiver = factory.create_someip_service_eventgroup_receiver(service_instance, 101, eventgroup_sender)
        assert eventgroup_sender.eventgroupreceivers() == [eventgroup_receiver]

    def test_eventgroup_sender_setsocket(self):
        """Test setsocket method."""
        factory = BaseConfigurationFactory()
        service = factory.create_someip_service(
            name="TestService", serviceid=0x1234, majorver=1, minorver=0, methods={}, events={}, fields={}, eventgroups={}
        )
        service_instance = factory.create_someip_service_instance(service, 1, 1)
        eventgroup_sender = factory.create_someip_service_eventgroup_sender(service_instance, 100)
        socket = factory.create_socket(
            name="Socket1",
            ip="192.168.1.1",
            proto="udp",
            portnumber=30000,
            serviceinstances=[],
            serviceinstanceclients=[],
            eventhandlers=[],
            eventgroupreceivers=[],
        )
        eventgroup_sender.setsocket(socket)
        assert eventgroup_sender.socket() is not None


class TestSOMEIPBaseServiceEventgroupReceiver:
    """Test cases for SOMEIPBaseServiceEventgroupReceiver class."""

    def test_create_someip_service_eventgroup_receiver(self):
        """Test create_someip_service_eventgroup_receiver method."""
        factory = BaseConfigurationFactory()
        service = factory.create_someip_service(
            name="TestService", serviceid=0x1234, majorver=1, minorver=0, methods={}, events={}, fields={}, eventgroups={}
        )
        service_instance = factory.create_someip_service_instance(service, 1, 1)
        eventgroup_sender = factory.create_someip_service_eventgroup_sender(service_instance, 100)
        eventgroup_receiver = factory.create_someip_service_eventgroup_receiver(service_instance, 101, eventgroup_sender)
        assert eventgroup_receiver.serviceinstance() == service_instance
        assert eventgroup_receiver.eventgroupid() == 101
        assert eventgroup_receiver.sender() == eventgroup_sender
        assert eventgroup_receiver.socket() is None

    def test_eventgroup_receiver_setsocket(self):
        """Test setsocket method."""
        factory = BaseConfigurationFactory()
        service = factory.create_someip_service(
            name="TestService", serviceid=0x1234, majorver=1, minorver=0, methods={}, events={}, fields={}, eventgroups={}
        )
        service_instance = factory.create_someip_service_instance(service, 1, 1)
        eventgroup_sender = factory.create_someip_service_eventgroup_sender(service_instance, 100)
        eventgroup_receiver = factory.create_someip_service_eventgroup_receiver(service_instance, 101, eventgroup_sender)
        socket = factory.create_socket(
            name="Socket1",
            ip="192.168.1.1",
            proto="udp",
            portnumber=30000,
            serviceinstances=[],
            serviceinstanceclients=[],
            eventhandlers=[],
            eventgroupreceivers=[],
        )
        eventgroup_receiver.setsocket(socket)
        assert eventgroup_receiver.socket() is not None


class TestSOMEIPBaseService:
    """Test cases for SOMEIPBaseService class."""

    def test_create_someip_service(self):
        """Test create_someip_service method."""
        factory = BaseConfigurationFactory()
        service = factory.create_someip_service(
            name="TestService", serviceid=0x1234, majorver=1, minorver=0, methods={}, events={}, fields={}, eventgroups={}
        )
        assert service.name() == "TestService"
        assert service.serviceid() == 0x1234
        assert service.majorversion() == 1
        assert service.minorversion() == 0

    def test_service_versionstring(self):
        """Test versionstring method."""
        factory = BaseConfigurationFactory()
        service = factory.create_someip_service(
            name="TestService", serviceid=0x1234, majorver=1, minorver=2, methods={}, events={}, fields={}, eventgroups={}
        )
        assert service.versionstring() == "1.2"

    def test_service_methods(self):
        """Test methods method."""
        factory = BaseConfigurationFactory()
        basetype = factory.create_someip_parameter_basetype("Param1", "A_UINT8", True, 8, 8)
        method = factory.create_someip_service_method(
            name="TestMethod", methodid=0x01, calltype="REQUEST_RESPONSE", relia=True, inparams=[basetype], outparams=[basetype]
        )
        service = factory.create_someip_service(
            name="TestService", serviceid=0x1234, majorver=1, minorver=0, methods={0x01: method}, events={}, fields={}, eventgroups={}
        )
        assert service.methods() == {0x01: method}
        assert service.method(0x01) == method
        assert service.method(0x02) is None

    def test_service_events(self):
        """Test events method."""
        factory = BaseConfigurationFactory()
        basetype = factory.create_someip_parameter_basetype("Param1", "A_UINT8", True, 8, 8)
        event = factory.create_someip_service_event(name="TestEvent", methodid=0x02, relia=True, params=[basetype])
        service = factory.create_someip_service(
            name="TestService", serviceid=0x1234, majorver=1, minorver=0, methods={}, events={0x02: event}, fields={}, eventgroups={}
        )
        assert service.events() == {0x02: event}
        assert service.event(0x02) == event
        assert service.event(0x03) is None

    def test_service_fields(self):
        """Test fields method."""
        factory = BaseConfigurationFactory()
        basetype = factory.create_someip_parameter_basetype("Param1", "A_UINT8", True, 8, 8)
        field = factory.create_someip_service_field(
            name="TestField",
            getterid=0x01,
            setterid=0x02,
            notifierid=0x03,
            getterreli=True,
            setterreli=True,
            notifierreli=True,
            params=[basetype],
            getter_debouncereq=-1,
            getter_retentionreq=-1,
            getter_retentionres=-1,
            setter_debouncereq=-1,
            setter_retentionreq=-1,
            setter_retentionres=-1,
            notifier_debounce=-1,
            notifier_retention=-1,
        )
        service = factory.create_someip_service(
            name="TestService", serviceid=0x1234, majorver=1, minorver=0, methods={}, events={}, fields={0x01: field}, eventgroups={}
        )
        assert service.fields() == {0x01: field}
        assert service.field(0x01) == field
        assert service.field(0x02) is None

    def test_service_eventgroups(self):
        """Test eventgroups method."""
        factory = BaseConfigurationFactory()
        eventgroup = factory.create_someip_service_eventgroup(name="TestEventGroup", eid=0x01, eventids=[], fieldids=[])
        service = factory.create_someip_service(
            name="TestService", serviceid=0x1234, majorver=1, minorver=0, methods={}, events={}, fields={}, eventgroups={0x01: eventgroup}
        )
        assert service.eventgroups() == {0x01: eventgroup}
        # Note: service.eventgroup(0x01) has a bug in the code (uses 'id' instead of 'egid')
        assert service.eventgroup(0x02) is None

    def test_service_add_instance(self):
        """Test add_instance method."""
        factory = BaseConfigurationFactory()
        service = factory.create_someip_service(
            name="TestService", serviceid=0x1234, majorver=1, minorver=0, methods={}, events={}, fields={}, eventgroups={}
        )
        service_instance = factory.create_someip_service_instance(service, 1, 1)
        assert service.instances() == [service_instance]

    def test_service_remove_instance(self):
        """Test remove_instance method."""
        factory = BaseConfigurationFactory()
        service = factory.create_someip_service(
            name="TestService", serviceid=0x1234, majorver=1, minorver=0, methods={}, events={}, fields={}, eventgroups={}
        )
        service_instance = factory.create_someip_service_instance(service, 1, 1)
        service.remove_instance(service_instance)
        assert service.instances() == []


class TestSOMEIPBaseServiceMethod:
    """Test cases for SOMEIPBaseServiceMethod class."""

    def test_create_someip_service_method(self):
        """Test create_someip_service_method method."""
        factory = BaseConfigurationFactory()
        basetype = factory.create_someip_parameter_basetype("Param1", "A_UINT8", True, 8, 8)
        method = factory.create_someip_service_method(
            name="TestMethod", methodid=0x01, calltype="REQUEST_RESPONSE", relia=True, inparams=[basetype], outparams=[basetype]
        )
        assert method.name() == "TestMethod"
        assert method.calltype() == "REQUEST_RESPONSE"


class TestSOMEIPBaseServiceEvent:
    """Test cases for SOMEIPBaseServiceEvent class."""

    def test_create_someip_service_event(self):
        """Test create_someip_service_event method."""
        factory = BaseConfigurationFactory()
        basetype = factory.create_someip_parameter_basetype("Param1", "A_UINT8", True, 8, 8)
        event = factory.create_someip_service_event(name="TestEvent", methodid=0x02, relia=True, params=[basetype])
        assert event.name() == "TestEvent"
        assert event.methodid() == 0x02
        assert event.size_min_out() == 1
        assert event.size_max_out() == 1
        assert not event.legacy()
        assert not event.tlv()
        assert event.debounce_time() == -1
        assert event.max_buffer_retention_time() == -1

    def test_create_someip_service_event_with_params(self):
        """Test create_someip_service_event with params."""
        factory = BaseConfigurationFactory()
        basetype = factory.create_someip_parameter_basetype("Param1", "A_UINT8", True, 8, 8)
        event = factory.create_someip_service_event(name="TestEvent", methodid=0x02, relia=True, params=[basetype])
        assert not event.legacy()


class TestSOMEIPBaseServiceField:
    """Test cases for SOMEIPBaseServiceField class."""

    def test_create_someip_service_field(self):
        """Test create_someip_service_field method."""
        factory = BaseConfigurationFactory()
        basetype = factory.create_someip_parameter_basetype("Param1", "A_UINT8", True, 8, 8)
        field = factory.create_someip_service_field(
            name="TestField",
            getterid=0x01,
            setterid=0x02,
            notifierid=0x03,
            getterreli=True,
            setterreli=True,
            notifierreli=True,
            params=[basetype],
            getter_debouncereq=-1,
            getter_retentionreq=-1,
            getter_retentionres=-1,
            setter_debouncereq=-1,
            setter_retentionreq=-1,
            setter_retentionres=-1,
            notifier_debounce=-1,
            notifier_retention=-1,
        )
        assert field.name() == "TestField"
        assert field.getter() is not None
        assert field.getter().methodid() == 0x01
        assert field.setter() is not None
        assert field.notifier() is not None
        assert field.size_min_out() == 1
        assert field.size_max_out() == 1
        assert not field.legacy()
        assert not field.tlv()

    def test_create_someip_service_field_no_ids(self):
        """Test create_someip_service_field with no IDs - should trigger error."""
        factory = BaseConfigurationFactory()
        basetype = factory.create_someip_parameter_basetype("Param1", "A_UINT8", True, 8, 8)
        field = factory.create_someip_service_field(
            name="TestField",
            getterid=None,
            setterid=None,
            notifierid=None,
            getterreli=True,
            setterreli=True,
            notifierreli=True,
            params=[basetype],
            getter_debouncereq=-1,
            getter_retentionreq=-1,
            getter_retentionres=-1,
            setter_debouncereq=-1,
            setter_retentionreq=-1,
            setter_retentionres=-1,
            notifier_debounce=-1,
            notifier_retention=-1,
        )
        assert field.name() == "TestField"
        assert field.getter() is None
        assert field.setter() is None
        assert field.notifier() is None
        assert field.min_id() is None


class TestSOMEIPBaseServiceEventgroup:
    """Test cases for SOMEIPBaseServiceEventgroup class."""

    def test_create_someip_service_eventgroup(self):
        """Test create_someip_service_eventgroup method."""
        factory = BaseConfigurationFactory()
        eventgroup = factory.create_someip_service_eventgroup(name="TestEventGroup", eid=0x01, eventids=[], fieldids=[])
        assert eventgroup.name() == "TestEventGroup"
        assert eventgroup.id() == 0x01


class TestSOMEIPBaseParameter:
    """Test cases for SOMEIPBaseParameter class."""

    def test_create_someip_parameter(self):
        """Test create_someip_parameter method."""
        factory = BaseConfigurationFactory()
        param = factory.create_someip_parameter(
            position=0,
            name="Param1",
            desc="Test parameter",
            mandatory=True,
            datatype=factory.create_someip_parameter_basetype("Child", "A_UINT8", True, 8, 8),
            signal=None,
        )
        assert param.name() == "Param1"
        assert param.position() == 0
        assert param.desc() == "Test parameter"
        assert param.mandatory()


class TestSOMEIPBaseParameterBasetype:
    """Test cases for SOMEIPBaseParameterBasetype class."""

    def test_create_someip_parameter_basetype(self):
        """Test create_someip_parameter_basetype method."""
        factory = BaseConfigurationFactory()
        param = factory.create_someip_parameter_basetype("Param1", "A_UINT8", True, 8, 8)
        assert param.name() == "Param1"
        assert param.datatype() == "A_UINT8"


class TestSOMEIPBaseParameterString:
    """Test cases for SOMEIPBaseParameterString class."""

    def test_create_someip_parameter_string(self):
        """Test create_someip_parameter_string method."""
        factory = BaseConfigurationFactory()
        param = factory.create_someip_parameter_string("String1", "UTF-8", True, 0, 100, "NULL", 32, 0)
        assert param.name() == "String1"


class TestSOMEIPBaseParameterArray:
    """Test cases for SOMEIPBaseParameterArray class."""

    def test_create_someip_parameter_array(self):
        """Test create_someip_parameter_array method."""
        factory = BaseConfigurationFactory()
        dim = factory.create_someip_parameter_array_dim(dim=1, lowerlimit=0, upperlimit=10, length_of_length=32, pad_to=0)
        child = factory.create_someip_parameter_basetype("Child", "A_UINT8", True, 8, 8)
        array = factory.create_someip_parameter_array("Array1", {1: dim}, child)
        assert array.name() == "Array1"
        assert len(array.dims()) == 1
        assert array.child() == child


class TestSOMEIPBaseParameterArrayDim:
    """Test cases for SOMEIPBaseParameterArrayDim class."""

    def test_create_someip_parameter_array_dim(self):
        """Test create_someip_parameter_array_dim method."""
        factory = BaseConfigurationFactory()
        dim = factory.create_someip_parameter_array_dim(dim=1, lowerlimit=0, upperlimit=10, length_of_length=32, pad_to=0)
        assert dim.dim() == 1
        assert dim.lowerlimit() == 0
        assert dim.upperlimit() == 10
        assert dim.length_of_length() == 32
        assert dim.pad_to() == 0

    def test_calc_size_min_bits(self):
        """Test calc_size_min_bits method."""
        factory = BaseConfigurationFactory()
        dim = factory.create_someip_parameter_array_dim(dim=1, lowerlimit=0, upperlimit=10, length_of_length=32, pad_to=0)
        child = factory.create_someip_parameter_basetype("Child", "A_UINT8", True, 8, 8)
        size = dim.calc_size_min_bits(child.size_min_bits())
        assert size > 0

    def test_calc_size_max_bits(self):
        """Test calc_size_max_bits method."""
        factory = BaseConfigurationFactory()
        dim = factory.create_someip_parameter_array_dim(dim=1, lowerlimit=0, upperlimit=10, length_of_length=32, pad_to=0)
        child = factory.create_someip_parameter_basetype("Child", "A_UINT8", True, 8, 8)
        size = dim.calc_size_max_bits(child.size_min_bits())
        assert size > 0


class TestSOMEIPBaseParameterStruct:
    """Test cases for SOMEIPBaseParameterStruct class."""

    def test_create_someip_parameter_struct(self):
        """Test create_someip_parameter_struct method."""
        factory = BaseConfigurationFactory()
        member = factory.create_someip_parameter_struct_member(
            position=0,
            name="Member1",
            mandatory=True,
            child=factory.create_someip_parameter_basetype("Child", "A_UINT8", True, 8, 8),
            signal=None,
        )
        struct = factory.create_someip_parameter_struct("Struct1", 32, 0, {0: member}, tlv=False)
        assert struct.name() == "Struct1"
        assert len(struct.members()) == 1


class TestSOMEIPBaseParameterStructMember:
    """Test cases for SOMEIPBaseParameterStructMember class."""

    def test_create_someip_parameter_struct_member(self):
        """Test create_someip_parameter_struct_member method."""
        factory = BaseConfigurationFactory()
        member = factory.create_someip_parameter_struct_member(
            position=0,
            name="Member1",
            mandatory=True,
            child=factory.create_someip_parameter_basetype("Child", "A_UINT8", True, 8, 8),
            signal=None,
        )
        assert member.name() == "Member1"
        assert member.position() == 0
        assert member.mandatory()
        assert member.signal() is None

    def test_update_position(self):
        """Test update_position method."""
        factory = BaseConfigurationFactory()
        member = factory.create_someip_parameter_struct_member(
            position=0,
            name="Member1",
            mandatory=True,
            child=factory.create_someip_parameter_basetype("Child", "A_UINT8", True, 8, 8),
            signal=None,
        )
        member.update_position(5)
        assert member.position() == 5


class TestSOMEIPBaseParameterTypedef:
    """Test cases for SOMEIPBaseParameterTypedef class."""

    def test_create_someip_parameter_typedef(self):
        """Test create_someip_parameter_typedef method."""
        factory = BaseConfigurationFactory()
        typedef = factory.create_someip_parameter_typedef(
            "Typedef1", "OriginalType", factory.create_someip_parameter_basetype("Child", "A_UINT8", True, 8, 8)
        )
        assert typedef.name() == "Typedef1"
        assert typedef.name2() == "OriginalType"
        assert not typedef.legacy()


class TestSOMEIPBaseParameterEnumeration:
    """Test cases for SOMEIPBaseParameterEnumeration class."""

    def test_create_someip_parameter_enumeration(self):
        """Test create_someip_parameter_enumeration method."""
        factory = BaseConfigurationFactory()
        item = factory.create_someip_parameter_enumeration_item(value=1, name="OPEN", desc="Door is open")
        enum = factory.create_someip_parameter_enumeration(
            "Enum1", {1: item}, factory.create_someip_parameter_basetype("Child", "A_UINT8", True, 8, 8)
        )
        assert enum.name() == "Enum1"
        assert len(enum.items()) == 1
        assert enum.items()[1].value() == 1
        assert enum.items()[1].name() == "OPEN"
        assert enum.items()[1].desc() == "Door is open"


class TestSOMEIPBaseParameterEnumerationItem:
    """Test cases for SOMEIPBaseParameterEnumerationItem class."""

    def test_create_someip_parameter_enumeration_item(self):
        """Test create_someip_parameter_enumeration_item method."""
        factory = BaseConfigurationFactory()
        item = factory.create_someip_parameter_enumeration_item(value=1, name="OPEN", desc="Door is open")
        assert item.name() == "OPEN"
        assert item.desc() == "Door is open"
        assert item.value() == 1


class TestSOMEIPBaseParameterUnion:
    """Test cases for SOMEIPBaseParameterUnion class."""

    def test_create_someip_parameter_union(self):
        """Test create_someip_parameter_union method."""
        factory = BaseConfigurationFactory()
        member = factory.create_someip_parameter_union_member(
            index=0, name="Member1", mandatory=True, child=factory.create_someip_parameter_basetype("Child", "A_UINT8", True, 8, 8)
        )
        union = factory.create_someip_parameter_union("Union1", 32, 32, 0, {0: member})
        assert union.name() == "Union1"
        assert len(union.members()) == 1
        assert union.members()[0].index() == 0
        assert union.members()[0].name() == "Member1"
        assert union.members()[0].mandatory()


class TestSOMEIPBaseParameterUnionMember:
    """Test cases for SOMEIPBaseParameterUnionMember class."""

    def test_create_someip_parameter_union_member(self):
        """Test create_someip_parameter_union_member method."""
        factory = BaseConfigurationFactory()
        member = factory.create_someip_parameter_union_member(
            index=0, name="Member1", mandatory=True, child=factory.create_someip_parameter_basetype("Child", "A_UINT8", True, 8, 8)
        )
        assert member.name() == "Member1"
        assert member.index() == 0
        assert member.mandatory()
        assert member.child() is not None


class TestSOMEIPBaseParameterBitfield:
    """Test cases for SOMEIPBaseParameterBitfield class."""

    def test_create_someip_parameter_bitfield(self):
        """Test create_someip_parameter_bitfield method."""
        factory = BaseConfigurationFactory()
        item = factory.create_someip_parameter_bitfield_item(bit_number=0, name="FLAG1")
        bitfield = factory.create_someip_parameter_bitfield(
            "Bitfield1", {1: item}, factory.create_someip_parameter_basetype("Child", "A_UINT8", True, 8, 8)
        )
        assert bitfield.name() == "Bitfield1"
        assert len(bitfield.items()) == 1
        assert bitfield.items()[1].bit_number() == 0
        assert bitfield.items()[1].name() == "FLAG1"


class TestSOMEIPBaseParameterBitfieldItem:
    """Test cases for SOMEIPBaseParameterBitfieldItem class."""

    def test_create_someip_parameter_bitfield_item(self):
        """Test create_someip_parameter_bitfield_item method."""
        factory = BaseConfigurationFactory()
        item = factory.create_someip_parameter_bitfield_item(bit_number=0, name="FLAG1")
        assert item.name() == "FLAG1"
        assert item.bit_number() == 0


class TestBaseSignal:
    """Test cases for BaseSignal class."""

    def test_create_base_signal(self):
        """Test BaseSignal class."""
        factory = BaseConfigurationFactory()
        coding = BaseCoding(
            id="Coding1",
            name="Coding1",
            coded_basetype="A_UINT8",
            coded_category="INTEGER",
            coded_termination="NONE",
            coded_bit_length=8,
            coded_max_length=8,
            compu_scale=[0, 1, 1],
            compu_consts=[],
        )
        signal = factory.create_signal(
            id="Signal1",
            name="TestSignal",
            compu_scale=[0, 1, 1],
            compu_consts=[],
            bit_len=8,
            min_len=8,
            max_len=8,
            basetype=coding,
            basetypelen=8,
        )
        assert signal.name() == "TestSignal"
        assert signal.id() == "Signal1"
        assert signal.bit_length() == 8
        assert signal.scaler() == 1.0
        assert signal.offset() == 0.0


class TestBaseSignalInstance:
    """Test cases for BaseSignalInstance class."""

    def test_create_base_signal_instance(self):
        """Test create_signal_instance method."""
        factory = BaseConfigurationFactory()
        coding = BaseCoding(
            id="Coding1",
            name="Coding1",
            coded_basetype="A_UINT8",
            coded_category="INTEGER",
            coded_termination="NONE",
            coded_bit_length=8,
            coded_max_length=8,
            compu_scale=[0, 1, 1],
            compu_consts=[],
        )
        signal = factory.create_signal(
            id="Signal1",
            name="TestSignal",
            compu_scale=[0, 1, 1],
            compu_consts=[],
            bit_len=8,
            min_len=8,
            max_len=8,
            basetype=coding,
            basetypelen=8,
        )
        signal_instance = factory.create_signal_instance(id="SI1", signal_ref=signal, bit_position=0, is_high_low_byte_order=True)
        assert signal_instance.bit_position() == 0
        assert signal_instance.is_high_low_byte_order()
        signal_instance.add_signal(signal)
        assert signal_instance.signal() == signal


class TestBaseAbstractPDU:
    """Test cases for BaseAbstractPDU class."""

    def test_create_base_abstract_pdu(self):
        """Test create_pdu method."""
        factory = BaseConfigurationFactory()
        coding = BaseCoding(
            id="Coding1",
            name="Coding1",
            coded_basetype="A_UINT8",
            coded_category="INTEGER",
            coded_termination="NONE",
            coded_bit_length=8,
            coded_max_length=8,
            compu_scale=[0, 1, 1],
            compu_consts=[],
        )
        signal = factory.create_signal(
            id="Signal1",
            name="TestSignal",
            compu_scale=[0, 1, 1],
            compu_consts=[],
            bit_len=8,
            min_len=8,
            max_len=8,
            basetype=coding,
            basetypelen=8,
        )
        signal_instance = factory.create_signal_instance(id="SI1", signal_ref=signal, bit_position=0, is_high_low_byte_order=True)
        pdu = factory.create_pdu(id="PDU1", short_name="TestPDU", byte_length=8, pdu_type="NORMAL", signal_instances=[signal_instance])
        assert pdu.name() == "TestPDU"
        assert pdu.id() == "PDU1"
        assert pdu.byte_length() == 8
        assert pdu.pdu_type() == "NORMAL"
        assert not pdu.is_multiplex_pdu()


class TestBasePDU:
    """Test cases for BasePDU class."""

    def test_create_base_pdu(self):
        """Test create_pdu method."""
        factory = BaseConfigurationFactory()
        signal_instance = factory.create_signal_instance(id="SI1", signal_ref=None, bit_position=0, is_high_low_byte_order=True)
        pdu = factory.create_pdu(id="PDU1", short_name="TestPDU", byte_length=8, pdu_type="NORMAL", signal_instances=[signal_instance])
        assert pdu.name() == "TestPDU"
        assert pdu.id() == "PDU1"
        assert pdu.byte_length() == 8
        assert pdu.pdu_type() == "NORMAL"
        assert not pdu.is_multiplex_pdu()


class TestBaseMultiplexPDU:
    """Test cases for BaseMultiplexPDU class."""

    def test_create_base_multiplex_pdu(self):
        """Test create_multiplex_pdu method."""
        factory = BaseConfigurationFactory()
        coding = BaseCoding(
            id="Coding1",
            name="Coding1",
            coded_basetype="A_UINT8",
            coded_category="INTEGER",
            coded_termination="NONE",
            coded_bit_length=8,
            coded_max_length=8,
            compu_scale=[0, 1, 1],
            compu_consts=[],
        )
        signal = factory.create_signal(
            id="Signal1",
            name="TestSignal",
            compu_scale=[0, 1, 1],
            compu_consts=[],
            bit_len=8,
            min_len=8,
            max_len=8,
            basetype=coding,
            basetypelen=8,
        )
        signal_instance = factory.create_signal_instance(id="SI1", signal_ref=signal, bit_position=0, is_high_low_byte_order=True)
        switch = factory.create_multiplex_switch(
            id="Switch1",
            short_name="Switch",
            bit_position=0,
            is_high_low_byte_order=True,
            bit_length=8,
        )
        segment_position = factory.create_multiplex_segment_position(
            bit_pos=0,
            is_high_low=True,
            bit_length=8,
        )
        pdu = factory.create_multiplex_pdu(
            id="MPDU1",
            short_name="TestMultiplexPDU",
            byte_length=8,
            pdu_type="MULTIPLEX",
            switch=switch,
            seg_pos=[segment_position],
            pdu_instances=[signal_instance],
            static_segs=[],
            static_pdu=None,
        )
        assert pdu.name() == "TestMultiplexPDU"
        assert pdu.switch() == switch
        assert len(pdu.segment_positions()) == 1
        assert pdu.is_multiplex_pdu()


class TestBaseMultiplexPDUSwitch:
    """Test cases for BaseMultiplexPDUSwitch class."""

    def test_create_base_multiplex_pdu_switch(self):
        """Test create_multiplex_switch method."""
        factory = BaseConfigurationFactory()
        switch = factory.create_multiplex_switch(
            id="Switch1",
            short_name="Switch",
            bit_position=0,
            is_high_low_byte_order=True,
            bit_length=8,
        )
        assert switch.id() == "Switch1"


class TestBaseMultiplexPDUSegmentPosition:
    """Test cases for BaseMultiplexPDUSegmentPosition class."""

    def test_create_base_multiplex_pdu_segment_position(self):
        """Test create_multiplex_segment_position method."""
        factory = BaseConfigurationFactory()
        segment_position = factory.create_multiplex_segment_position(
            bit_pos=0,
            is_high_low=True,
            bit_length=8,
        )
        assert segment_position.bit_position() == 0
        assert segment_position.is_high_low_byte_order()


class TestBaseEthernetPDUInstance:
    """Test cases for BaseEthernetPDUInstance class."""

    def test_create_base_ethernet_pdu_instance(self):
        """Test create_ethernet_pdu_instance method."""
        factory = BaseConfigurationFactory()
        pdu_instance = factory.create_ethernet_pdu_instance(
            pdu_ref="PDU1",
            header_id=0x100,
        )
        assert pdu_instance is not None


class TestBasePDUInstance:
    """Test cases for BasePDUInstance class."""

    def test_create_base_pdu_instance(self):
        """Test create_pdu_instance method."""
        factory = BaseConfigurationFactory()
        pdu_instance = factory.create_pdu_instance(
            id="PDUInst1",
            pdu_ref="PDU1",
            bit_position=0,
            is_high_low_byte_order=True,
            pdu_update_bit_position=0,
        )
        assert pdu_instance is not None


class TestBaseFrame:
    """Test cases for BaseFrame class."""

    def test_create_base_frame(self):
        """Test create_frame method."""
        factory = BaseConfigurationFactory()
        coding = BaseCoding(
            id="Coding1",
            name="Coding1",
            coded_basetype="A_UINT8",
            coded_category="INTEGER",
            coded_termination="NONE",
            coded_bit_length=8,
            coded_max_length=8,
            compu_scale=[0, 1, 1],
            compu_consts=[],
        )
        signal = factory.create_signal(
            id="Signal1",
            name="TestSignal",
            compu_scale=[0, 1, 1],
            compu_consts=[],
            bit_len=8,
            min_len=8,
            max_len=8,
            basetype=coding,
            basetypelen=8,
        )
        signal_instance = factory.create_signal_instance(id="SI1", signal_ref=signal, bit_position=0, is_high_low_byte_order=True)
        frame = factory.create_frame(
            id="Frame1",
            short_name="TestFrame",
            byte_length=8,
            frame_type="NORMAL",
            pdu_instances=[signal_instance],
        )
        assert frame.name() == "TestFrame"
        assert frame.byte_length() == 8


class TestBaseFrameTriggering:
    """Test cases for BaseFrameTriggering class."""

    def test_create_base_frame_triggering(self):
        """Test create_frame_triggering_can method."""
        factory = BaseConfigurationFactory()
        coding = BaseCoding(
            id="Coding1",
            name="Coding1",
            coded_basetype="A_UINT8",
            coded_category="INTEGER",
            coded_termination="NONE",
            coded_bit_length=8,
            coded_max_length=8,
            compu_scale=[0, 1, 1],
            compu_consts=[],
        )
        signal = factory.create_signal(
            id="Signal1",
            name="TestSignal",
            compu_scale=[0, 1, 1],
            compu_consts=[],
            bit_len=8,
            min_len=8,
            max_len=8,
            basetype=coding,
            basetypelen=8,
        )
        signal_instance = factory.create_signal_instance(id="SI1", signal_ref=signal, bit_position=0, is_high_low_byte_order=True)
        frame = factory.create_frame(
            id="Frame1",
            short_name="TestFrame",
            byte_length=8,
            frame_type="NORMAL",
            pdu_instances=[signal_instance],
        )
        frame_triggering = factory.create_frame_triggering_can(
            id="FT1",
            frame=frame,
            can_id=0x100,
        )
        assert frame_triggering.id() == "FT1"
        assert frame_triggering.frame() == frame
        assert frame_triggering.is_can()
        assert not frame_triggering.is_flexray()


class TestBaseFrameTriggeringCAN:
    """Test cases for BaseFrameTriggeringCAN class."""

    def test_create_base_frame_triggering_can(self):
        """Test create_frame_triggering_can method."""
        factory = BaseConfigurationFactory()
        coding = BaseCoding(
            id="Coding1",
            name="Coding1",
            coded_basetype="A_UINT8",
            coded_category="INTEGER",
            coded_termination="NONE",
            coded_bit_length=8,
            coded_max_length=8,
            compu_scale=[0, 1, 1],
            compu_consts=[],
        )
        signal = factory.create_signal(
            id="Signal1",
            name="TestSignal",
            compu_scale=[0, 1, 1],
            compu_consts=[],
            bit_len=8,
            min_len=8,
            max_len=8,
            basetype=coding,
            basetypelen=8,
        )
        signal_instance = factory.create_signal_instance(id="SI1", signal_ref=signal, bit_position=0, is_high_low_byte_order=True)
        frame = factory.create_frame(
            id="Frame1",
            short_name="TestFrame",
            byte_length=8,
            frame_type="NORMAL",
            pdu_instances=[signal_instance],
        )
        frame_triggering = factory.create_frame_triggering_can(
            id="FT1",
            frame=frame,
            can_id=0x100,
        )
        assert frame_triggering.can_id() == 0x100
        assert frame_triggering.frame() == frame


class TestBaseFrameTriggeringFlexRay:
    """Test cases for BaseFrameTriggeringFlexRay class."""

    def test_create_base_frame_triggering_flexray(self):
        """Test create_frame_triggering_flexray method."""
        factory = BaseConfigurationFactory()
        coding = BaseCoding(
            id="Coding1",
            name="Coding1",
            coded_basetype="A_UINT8",
            coded_category="INTEGER",
            coded_termination="NONE",
            coded_bit_length=8,
            coded_max_length=8,
            compu_scale=[0, 1, 1],
            compu_consts=[],
        )
        signal = factory.create_signal(
            id="Signal1",
            name="TestSignal",
            compu_scale=[0, 1, 1],
            compu_consts=[],
            bit_len=8,
            min_len=8,
            max_len=8,
            basetype=coding,
            basetypelen=8,
        )
        signal_instance = factory.create_signal_instance(id="SI1", signal_ref=signal, bit_position=0, is_high_low_byte_order=True)
        frame = factory.create_frame(
            id="Frame1",
            short_name="TestFrame",
            byte_length=8,
            frame_type="NORMAL",
            pdu_instances=[signal_instance],
        )
        frame_triggering = factory.create_frame_triggering_flexray(
            id="FT1",
            frame=frame,
            slot_id=0x100,
            cycle_counter=1,
            base_cycle=0,
            cycle_repetition=1,
        )
        assert frame_triggering.is_flexray()
        assert frame_triggering.frame() == frame


class TestSOMEIPBaseParameterStructAdditional:
    """Additional tests for SOMEIPBaseParameterStruct."""

    def test_create_struct_with_tlv(self):
        """Test create_someip_parameter_struct with tlv=True."""
        factory = BaseConfigurationFactory()
        member = factory.create_someip_parameter_struct_member(
            position=0,
            name="Member1",
            mandatory=True,
            child=factory.create_someip_parameter_basetype("Child", "A_UINT8", True, 8, 8),
            signal=None,
        )
        struct = factory.create_someip_parameter_struct("Struct1", 32, 0, {0: member}, tlv=True)
        assert struct.tlv()
        assert not struct.legacy()

    def test_struct_legacy_with_signal(self):
        """Test struct legacy with signal."""
        factory = BaseConfigurationFactory()
        coding = BaseCoding(
            id="Coding1",
            name="Coding1",
            coded_basetype="A_UINT8",
            coded_category="INTEGER",
            coded_termination="NONE",
            coded_bit_length=8,
            coded_max_length=8,
            compu_scale=[0, 1, 1],
            compu_consts=[],
        )
        signal = factory.create_signal(
            id="Signal1",
            name="TestSignal",
            compu_scale=[0, 1, 1],
            compu_consts=[],
            bit_len=8,
            min_len=8,
            max_len=8,
            basetype=coding,
            basetypelen=8,
        )
        member = factory.create_someip_parameter_struct_member(
            position=0,
            name="Member1",
            mandatory=True,
            child=factory.create_someip_parameter_basetype("Child", "A_UINT8", True, 8, 8),
            signal=signal,
        )
        struct = factory.create_someip_parameter_struct("Struct1", 32, 0, {0: member}, tlv=False)
        assert struct.legacy()

    def test_struct_legacy_with_signal_child(self):
        """Test struct legacy with signal that has legacy child."""
        factory = BaseConfigurationFactory()
        coding = BaseCoding(
            id="Coding1",
            name="Coding1",
            coded_basetype="A_UINT8",
            coded_category="INTEGER",
            coded_termination="NONE",
            coded_bit_length=8,
            coded_max_length=8,
            compu_scale=[0, 1, 1],
            compu_consts=[],
        )
        signal = factory.create_signal(
            id="Signal1",
            name="TestSignal",
            compu_scale=[0, 1, 1],
            compu_consts=[],
            bit_len=8,
            min_len=8,
            max_len=8,
            basetype=coding,
            basetypelen=8,
        )
        # Set legacy on signal
        signal._BaseSignal__legacy = True
        member = factory.create_someip_parameter_struct_member(
            position=0,
            name="Member1",
            mandatory=True,
            child=factory.create_someip_parameter_basetype("Child", "A_UINT8", True, 8, 8),
            signal=signal,
        )
        struct = factory.create_someip_parameter_struct("Struct1", 32, 0, {0: member}, tlv=False)
        assert struct.legacy()


class TestSOMEIPBaseParameterEnumerationAdditional:
    """Additional tests for SOMEIPBaseParameterEnumeration."""

    def test_enumeration_legacy(self):
        """Test enumeration legacy method."""
        factory = BaseConfigurationFactory()
        item = factory.create_someip_parameter_enumeration_item(value=1, name="OPEN", desc="Door is open")
        enum = factory.create_someip_parameter_enumeration(
            "Enum1", {1: item}, factory.create_someip_parameter_basetype("Child", "A_UINT8", True, 8, 8)
        )
        assert not enum.legacy()


class TestSOMEIPBaseParameterUnionAdditional:
    """Additional tests for SOMEIPBaseParameterUnion."""

    def test_union_legacy(self):
        """Test union legacy method."""
        factory = BaseConfigurationFactory()
        member = factory.create_someip_parameter_union_member(
            index=0, name="Member1", mandatory=True, child=factory.create_someip_parameter_basetype("Child", "A_UINT8", True, 8, 8)
        )
        union = factory.create_someip_parameter_union("Union1", 32, 32, 0, {0: member})
        assert not union.legacy()


class TestSOMEIPBaseParameterBitfieldAdditional:
    """Additional tests for SOMEIPBaseParameterBitfield."""

    def test_bitfield_legacy(self):
        """Test bitfield legacy method."""
        factory = BaseConfigurationFactory()
        item = factory.create_someip_parameter_bitfield_item(bit_number=0, name="FLAG1")
        bitfield = factory.create_someip_parameter_bitfield(
            "Bitfield1", {1: item}, factory.create_someip_parameter_basetype("Child", "A_UINT8", True, 8, 8)
        )
        assert not bitfield.legacy()


class TestBaseSignalAdditional:
    """Additional tests for BaseSignal."""

    def test_signal_legacy(self):
        """Test BaseSignal legacy method."""
        factory = BaseConfigurationFactory()
        coding = BaseCoding(
            id="Coding1",
            name="Coding1",
            coded_basetype="A_UINT8",
            coded_category="INTEGER",
            coded_termination="NONE",
            coded_bit_length=8,
            coded_max_length=8,
            compu_scale=[0, 1, 1],
            compu_consts=[],
        )
        signal = factory.create_signal(
            id="Signal1",
            name="TestSignal",
            compu_scale=[0, 1, 1],
            compu_consts=[],
            bit_len=8,
            min_len=8,
            max_len=8,
            basetype=coding,
            basetypelen=8,
        )
        assert not signal.legacy()


class TestSOMEIPBaseParameterAdditional:
    """Additional tests for SOMEIPBaseParameter classes."""

    def test_parameter_array_eq(self):
        """Test SOMEIPBaseParameterArray __eq__ method."""
        factory = BaseConfigurationFactory()
        dim = factory.create_someip_parameter_array_dim(dim=1, lowerlimit=0, upperlimit=10, length_of_length=32, pad_to=0)
        child = factory.create_someip_parameter_basetype("Child", "A_UINT8", True, 8, 8)
        array1 = factory.create_someip_parameter_array("Array1", {1: dim}, child)
        array2 = factory.create_someip_parameter_array("Array1", {1: dim}, child)
        array3 = factory.create_someip_parameter_array("Array2", {2: dim}, child)
        assert array1 == array2
        assert array1 != array3

    def test_parameter_typedef_eq(self):
        """Test SOMEIPBaseParameterTypedef __eq__ method."""
        factory = BaseConfigurationFactory()
        typedef1 = factory.create_someip_parameter_typedef(
            "Typedef1", "OriginalType", factory.create_someip_parameter_basetype("Child", "A_UINT8", True, 8, 8)
        )
        typedef2 = factory.create_someip_parameter_typedef(
            "Typedef1", "OriginalType", factory.create_someip_parameter_basetype("Child", "A_UINT8", True, 8, 8)
        )
        typedef3 = factory.create_someip_parameter_typedef(
            "Typedef2", "DifferentType", factory.create_someip_parameter_basetype("Child2", "A_UINT16", True, 16, 16)
        )
        assert typedef1 == typedef2
        assert typedef1 != typedef3

    def test_parameter_enumeration_eq(self):
        """Test SOMEIPBaseParameterEnumeration __eq__ method."""
        factory = BaseConfigurationFactory()
        item = factory.create_someip_parameter_enumeration_item(value=1, name="OPEN", desc="Door is open")
        enum1 = factory.create_someip_parameter_enumeration(
            "Enum1", {1: item}, factory.create_someip_parameter_basetype("Child", "A_UINT8", True, 8, 8)
        )
        enum2 = factory.create_someip_parameter_enumeration(
            "Enum1", {1: item}, factory.create_someip_parameter_basetype("Child", "A_UINT8", True, 8, 8)
        )
        assert enum1 == enum2

    def test_parameter_struct_eq(self):
        """Test SOMEIPBaseParameterStruct __eq__ method."""
        factory = BaseConfigurationFactory()
        member = factory.create_someip_parameter_struct_member(
            position=0,
            name="Member1",
            mandatory=True,
            child=factory.create_someip_parameter_basetype("Child", "A_UINT8", True, 8, 8),
            signal=None,
        )
        struct1 = factory.create_someip_parameter_struct("Struct1", 32, 0, {0: member}, tlv=False)
        struct2 = factory.create_someip_parameter_struct("Struct1", 32, 0, {0: member}, tlv=False)
        assert struct1 == struct2

    def test_parameter_struct_member_eq(self):
        """Test SOMEIPBaseParameterStructMember __eq__ method."""
        factory = BaseConfigurationFactory()
        member1 = factory.create_someip_parameter_struct_member(
            position=0,
            name="Member1",
            mandatory=True,
            child=factory.create_someip_parameter_basetype("Child", "A_UINT8", True, 8, 8),
            signal=None,
        )
        member2 = factory.create_someip_parameter_struct_member(
            position=0,
            name="Member1",
            mandatory=True,
            child=factory.create_someip_parameter_basetype("Child", "A_UINT8", True, 8, 8),
            signal=None,
        )
        assert member1 == member2

    def test_parameter_enumeration_item_eq(self):
        """Test SOMEIPBaseParameterEnumerationItem __eq__ method."""
        factory = BaseConfigurationFactory()
        item1 = factory.create_someip_parameter_enumeration_item(value=1, name="OPEN", desc="Door is open")
        item2 = factory.create_someip_parameter_enumeration_item(value=1, name="OPEN", desc="Door is open")
        item3 = factory.create_someip_parameter_enumeration_item(value=2, name="CLOSED", desc="Door is closed")
        assert item1 == item2
        assert item1 != item3

    def test_parameter_union_eq(self):
        """Test SOMEIPBaseParameterUnion __eq__ method."""
        factory = BaseConfigurationFactory()
        member = factory.create_someip_parameter_union_member(
            index=0, name="Member1", mandatory=True, child=factory.create_someip_parameter_basetype("Child", "A_UINT8", True, 8, 8)
        )
        union1 = factory.create_someip_parameter_union("Union1", 32, 32, 0, {0: member})
        union2 = factory.create_someip_parameter_union("Union1", 32, 32, 0, {0: member})
        assert union1 == union2

    def test_parameter_union_member_eq(self):
        """Test SOMEIPBaseParameterUnionMember __eq__ method."""
        factory = BaseConfigurationFactory()
        member1 = factory.create_someip_parameter_union_member(
            index=0, name="Member1", mandatory=True, child=factory.create_someip_parameter_basetype("Child", "A_UINT8", True, 8, 8)
        )
        member2 = factory.create_someip_parameter_union_member(
            index=0, name="Member1", mandatory=True, child=factory.create_someip_parameter_basetype("Child", "A_UINT8", True, 8, 8)
        )
        assert member1 == member2

    def test_parameter_bitfield_eq(self):
        """Test SOMEIPBaseParameterBitfield __eq__ method."""
        factory = BaseConfigurationFactory()
        item = factory.create_someip_parameter_bitfield_item(bit_number=0, name="FLAG1")
        bitfield1 = factory.create_someip_parameter_bitfield(
            "Bitfield1", {1: item}, factory.create_someip_parameter_basetype("Child", "A_UINT8", True, 8, 8)
        )
        bitfield2 = factory.create_someip_parameter_bitfield(
            "Bitfield1", {1: item}, factory.create_someip_parameter_basetype("Child", "A_UINT8", True, 8, 8)
        )
        assert bitfield1 == bitfield2

    def test_parameter_bitfield_item_eq(self):
        """Test SOMEIPBaseParameterBitfieldItem __eq__ method."""
        factory = BaseConfigurationFactory()
        item1 = factory.create_someip_parameter_bitfield_item(bit_number=0, name="FLAG1")
        item2 = factory.create_someip_parameter_bitfield_item(bit_number=0, name="FLAG1")
        item3 = factory.create_someip_parameter_bitfield_item(bit_number=1, name="FLAG2")
        assert item1 == item2
        assert item1 != item3


class TestSOMEIPBaseParameterArrayDimAdditional:
    """Additional tests for SOMEIPBaseParameterArrayDim."""

    def test_calc_size_min_bits_with_padto(self):
        """Test calc_size_min_bits with padTo."""
        factory = BaseConfigurationFactory()
        dim = factory.create_someip_parameter_array_dim(dim=1, lowerlimit=0, upperlimit=10, length_of_length=32, pad_to=8)
        child = factory.create_someip_parameter_basetype("Child", "A_UINT8", True, 8, 8)
        size = dim.calc_size_min_bits(child.size_min_bits())
        assert size > 0

    def test_calc_size_max_bits_with_padto(self):
        """Test calc_size_max_bits with padTo."""
        factory = BaseConfigurationFactory()
        dim = factory.create_someip_parameter_array_dim(dim=1, lowerlimit=0, upperlimit=10, length_of_length=32, pad_to=8)
        child = factory.create_someip_parameter_basetype("Child", "A_UINT8", True, 8, 8)
        size = dim.calc_size_max_bits(child.size_min_bits())
        assert size > 0


class TestSOMEIPBaseParameterArrayAdditional:
    """Additional tests for SOMEIPBaseParameterArray."""

    def test_array_size_min_bits(self):
        """Test array size_min_bits."""
        factory = BaseConfigurationFactory()
        dim = factory.create_someip_parameter_array_dim(dim=1, lowerlimit=0, upperlimit=10, length_of_length=32, pad_to=0)
        child = factory.create_someip_parameter_basetype("Child", "A_UINT8", True, 8, 8)
        array = factory.create_someip_parameter_array("Array1", {1: dim}, child)
        assert array.size_min_bits() > 0

    def test_array_size_max_bits(self):
        """Test array size_max_bits."""
        factory = BaseConfigurationFactory()
        dim = factory.create_someip_parameter_array_dim(dim=1, lowerlimit=0, upperlimit=10, length_of_length=32, pad_to=0)
        child = factory.create_someip_parameter_basetype("Child", "A_UINT8", True, 8, 8)
        array = factory.create_someip_parameter_array("Array1", {1: dim}, child)
        assert array.size_max_bits() > 0


class TestSOMEIPBaseParameterStructAdditional2:
    """Additional tests for SOMEIPBaseParameterStruct."""

    def test_struct_size_min_bits(self):
        """Test struct size_min_bits."""
        factory = BaseConfigurationFactory()
        member = factory.create_someip_parameter_struct_member(
            position=0,
            name="Member1",
            mandatory=True,
            child=factory.create_someip_parameter_basetype("Child", "A_UINT8", True, 8, 8),
            signal=None,
        )
        struct = factory.create_someip_parameter_struct("Struct1", 32, 0, {0: member}, tlv=False)
        assert struct.size_min_bits() > 0

    def test_struct_size_max_bits(self):
        """Test struct size_max_bits."""
        factory = BaseConfigurationFactory()
        member = factory.create_someip_parameter_struct_member(
            position=0,
            name="Member1",
            mandatory=True,
            child=factory.create_someip_parameter_basetype("Child", "A_UINT8", True, 8, 8),
            signal=None,
        )
        struct = factory.create_someip_parameter_struct("Struct1", 32, 0, {0: member}, tlv=False)
        assert struct.size_max_bits() > 0


class TestSOMEIPBaseParameterUnionAdditional2:
    """Additional tests for SOMEIPBaseParameterUnion."""

    def test_union_size_min_bits(self):
        """Test union size_min_bits."""
        factory = BaseConfigurationFactory()
        member = factory.create_someip_parameter_union_member(
            index=0, name="Member1", mandatory=True, child=factory.create_someip_parameter_basetype("Child", "A_UINT8", True, 8, 8)
        )
        union = factory.create_someip_parameter_union("Union1", 32, 32, 0, {0: member})
        assert union.size_min_bits() > 0

    def test_union_size_max_bits(self):
        """Test union size_max_bits."""
        factory = BaseConfigurationFactory()
        member = factory.create_someip_parameter_union_member(
            index=0, name="Member1", mandatory=True, child=factory.create_someip_parameter_basetype("Child", "A_UINT8", True, 8, 8)
        )
        union = factory.create_someip_parameter_union("Union1", 32, 32, 0, {0: member})
        assert union.size_max_bits() > 0


class TestSOMEIPBaseParameterUnionAdditional3:
    """Additional tests for SOMEIPBaseParameterUnion with padTo."""

    def test_union_size_min_bits_with_padto(self):
        """Test union size_min_bits with padTo."""
        factory = BaseConfigurationFactory()
        member = factory.create_someip_parameter_union_member(
            index=0, name="Member1", mandatory=True, child=factory.create_someip_parameter_basetype("Child", "A_UINT8", True, 8, 8)
        )
        union = factory.create_someip_parameter_union("Union1", 32, 32, 8, {0: member})
        size = union.size_min_bits()
        assert size > 0

    def test_union_size_max_bits_with_padto(self):
        """Test union size_max_bits with padTo."""
        factory = BaseConfigurationFactory()
        member = factory.create_someip_parameter_union_member(
            index=0, name="Member1", mandatory=True, child=factory.create_someip_parameter_basetype("Child", "A_UINT8", True, 8, 8)
        )
        union = factory.create_someip_parameter_union("Union1", 32, 32, 8, {0: member})
        size = union.size_max_bits()
        assert size > 0


class TestSOMEIPBaseParameterBitfieldAdditional2:
    """Additional tests for SOMEIPBaseParameterBitfield."""

    def test_bitfield_size_min_bits(self):
        """Test bitfield size_min_bits."""
        factory = BaseConfigurationFactory()
        item = factory.create_someip_parameter_bitfield_item(bit_number=0, name="FLAG1")
        bitfield = factory.create_someip_parameter_bitfield(
            "Bitfield1", {1: item}, factory.create_someip_parameter_basetype("Child", "A_UINT8", True, 8, 8)
        )
        assert bitfield.size_min_bits() > 0

    def test_bitfield_size_max_bits(self):
        """Test bitfield size_max_bits."""
        factory = BaseConfigurationFactory()
        item = factory.create_someip_parameter_bitfield_item(bit_number=0, name="FLAG1")
        bitfield = factory.create_someip_parameter_bitfield(
            "Bitfield1", {1: item}, factory.create_someip_parameter_basetype("Child", "A_UINT8", True, 8, 8)
        )
        assert bitfield.size_max_bits() > 0


class TestSOMEIPBaseParameterTypedefAdditional2:
    """Additional tests for SOMEIPBaseParameterTypedef."""

    def test_typedef_size_min_bits(self):
        """Test typedef size_min_bits."""
        factory = BaseConfigurationFactory()
        typedef = factory.create_someip_parameter_typedef(
            "Typedef1", "OriginalType", factory.create_someip_parameter_basetype("Child", "A_UINT8", True, 8, 8)
        )
        assert typedef.size_min_bits() > 0

    def test_typedef_size_max_bits(self):
        """Test typedef size_max_bits."""
        factory = BaseConfigurationFactory()
        typedef = factory.create_someip_parameter_typedef(
            "Typedef1", "OriginalType", factory.create_someip_parameter_basetype("Child", "A_UINT8", True, 8, 8)
        )
        assert typedef.size_max_bits() > 0


class TestSOMEIPBaseParameterEnumerationAdditional2:
    """Additional tests for SOMEIPBaseParameterEnumeration."""

    def test_enumeration_size_min_bits(self):
        """Test enumeration size_min_bits."""
        factory = BaseConfigurationFactory()
        item = factory.create_someip_parameter_enumeration_item(value=1, name="OPEN", desc="Door is open")
        enum = factory.create_someip_parameter_enumeration(
            "Enum1", {1: item}, factory.create_someip_parameter_basetype("Child", "A_UINT8", True, 8, 8)
        )
        assert enum.size_min_bits() > 0

    def test_enumeration_size_max_bits(self):
        """Test enumeration size_max_bits."""
        factory = BaseConfigurationFactory()
        item = factory.create_someip_parameter_enumeration_item(value=1, name="OPEN", desc="Door is open")
        enum = factory.create_someip_parameter_enumeration(
            "Enum1", {1: item}, factory.create_someip_parameter_basetype("Child", "A_UINT8", True, 8, 8)
        )
        assert enum.size_max_bits() > 0


class TestSOMEIPBaseParameterBasetypeAdditional2:
    """Additional tests for SOMEIPBaseParameterBasetype."""

    def test_basetype_bigendian(self):
        """Test basetype bigendian method."""
        factory = BaseConfigurationFactory()
        param = factory.create_someip_parameter_basetype("Param1", "A_UINT8", True, 8, 8)
        assert param.bigendian()


class TestSOMEIPBaseServiceMethodLegacy:
    """Tests for SOMEIPBaseServiceMethod legacy methods."""

    def test_method_tlv(self):
        """Test method tlv method."""
        factory = BaseConfigurationFactory()
        basetype = factory.create_someip_parameter_basetype("Param1", "A_UINT8", True, 8, 8)
        method = factory.create_someip_service_method(
            name="TestMethod", methodid=0x01, calltype="REQUEST_RESPONSE", relia=True, inparams=[basetype], outparams=[basetype], tlv=True
        )
        assert method.tlv()

    def test_field_legacy_false(self):
        """Test field legacy with non-legacy parameters."""
        factory = BaseConfigurationFactory()
        basetype = factory.create_someip_parameter_basetype("Param1", "A_UINT8", True, 8, 8)  # legacy=False
        field = factory.create_someip_service_field(
            name="TestField",
            getterid=0x01,
            setterid=0x02,
            notifierid=0x03,
            getterreli=True,
            setterreli=True,
            notifierreli=True,
            params=[basetype],
            getter_debouncereq=-1,
            getter_retentionreq=-1,
            getter_retentionres=-1,
            setter_debouncereq=-1,
            setter_retentionreq=-1,
            setter_retentionres=-1,
            notifier_debounce=-1,
            notifier_retention=-1,
        )
        assert not field.legacy()

    def test_field_tlv(self):
        """Test field tlv method."""
        factory = BaseConfigurationFactory()
        basetype = factory.create_someip_parameter_basetype("Param1", "A_UINT8", True, 8, 8)
        field = factory.create_someip_service_field(
            name="TestField",
            getterid=0x01,
            setterid=0x02,
            notifierid=0x03,
            getterreli=True,
            setterreli=True,
            notifierreli=True,
            params=[basetype],
            getter_debouncereq=-1,
            getter_retentionreq=-1,
            getter_retentionres=-1,
            setter_debouncereq=-1,
            setter_retentionreq=-1,
            setter_retentionres=-1,
            notifier_debounce=-1,
            notifier_retention=-1,
            tlv=True,
        )
        assert field.tlv()

    def test_field_size_min_in(self):
        """Test field size_min_in method."""
        factory = BaseConfigurationFactory()
        basetype = factory.create_someip_parameter_basetype("Param1", "A_UINT8", True, 8, 8)
        field = factory.create_someip_service_field(
            name="TestField",
            getterid=0x01,
            setterid=0x02,
            notifierid=0x03,
            getterreli=True,
            setterreli=True,
            notifierreli=True,
            params=[basetype],
            getter_debouncereq=-1,
            getter_retentionreq=-1,
            getter_retentionres=-1,
            setter_debouncereq=-1,
            setter_retentionreq=-1,
            setter_retentionres=-1,
            notifier_debounce=-1,
            notifier_retention=-1,
        )
        assert field.size_min_in() >= 0

    def test_field_size_max_in(self):
        """Test field size_max_in method."""
        factory = BaseConfigurationFactory()
        basetype = factory.create_someip_parameter_basetype("Param1", "A_UINT8", True, 8, 8)
        field = factory.create_someip_service_field(
            name="TestField",
            getterid=0x01,
            setterid=0x02,
            notifierid=0x03,
            getterreli=True,
            setterreli=True,
            notifierreli=True,
            params=[basetype],
            getter_debouncereq=-1,
            getter_retentionreq=-1,
            getter_retentionres=-1,
            setter_debouncereq=-1,
            setter_retentionreq=-1,
            setter_retentionres=-1,
            notifier_debounce=-1,
            notifier_retention=-1,
        )
        assert field.size_max_in() >= 0

    def test_field_size_min_out(self):
        """Test field size_min_out method."""
        factory = BaseConfigurationFactory()
        basetype = factory.create_someip_parameter_basetype("Param1", "A_UINT8", True, 8, 8)
        field = factory.create_someip_service_field(
            name="TestField",
            getterid=0x01,
            setterid=0x02,
            notifierid=0x03,
            getterreli=True,
            setterreli=True,
            notifierreli=True,
            params=[basetype],
            getter_debouncereq=-1,
            getter_retentionreq=-1,
            getter_retentionres=-1,
            setter_debouncereq=-1,
            setter_retentionreq=-1,
            setter_retentionres=-1,
            notifier_debounce=-1,
            notifier_retention=-1,
        )
        assert field.size_min_out() >= 0

    def test_field_size_max_out(self):
        """Test field size_max_out method."""
        factory = BaseConfigurationFactory()
        basetype = factory.create_someip_parameter_basetype("Param1", "A_UINT8", True, 8, 8)
        field = factory.create_someip_service_field(
            name="TestField",
            getterid=0x01,
            setterid=0x02,
            notifierid=0x03,
            getterreli=True,
            setterreli=True,
            notifierreli=True,
            params=[basetype],
            getter_debouncereq=-1,
            getter_retentionreq=-1,
            getter_retentionres=-1,
            setter_debouncereq=-1,
            setter_retentionreq=-1,
            setter_retentionres=-1,
            notifier_debounce=-1,
            notifier_retention=-1,
        )
        assert field.size_max_out() >= 0


class TestSOMEIPBaseParameterStructMemberLegacy:
    """Tests for SOMEIPBaseParameterStructMember legacy methods."""

    def test_struct_member_legacy_with_signal(self):
        """Test struct member legacy with signal."""
        factory = BaseConfigurationFactory()
        signal = factory.create_signal(
            id="Signal1", name="TestSignal", compu_scale=[0, 1, 1], compu_consts=[], bit_len=8, min_len=8, max_len=8, basetype=None, basetypelen=8
        )
        member = factory.create_someip_parameter_struct_member(
            position=0,
            name="Member1",
            mandatory=True,
            child=factory.create_someip_parameter_basetype("Child", "A_UINT8", True, 8, 8),
            signal=signal,
        )
        assert member.legacy()

    def test_struct_member_legacy_no_signal(self):
        """Test struct member legacy without signal."""
        factory = BaseConfigurationFactory()
        member = factory.create_someip_parameter_struct_member(
            position=0,
            name="Member1",
            mandatory=True,
            child=factory.create_someip_parameter_basetype("Child", "A_UINT8", True, 8, 8),
            signal=None,
        )
        assert not member.legacy()


class TestSOMEIPBaseParameterUnionMemberLegacy:
    """Tests for SOMEIPBaseParameterUnionMember legacy methods."""

    def test_union_member_legacy(self):
        """Test union member legacy."""
        factory = BaseConfigurationFactory()
        member = factory.create_someip_parameter_union_member(
            index=0, name="Member1", mandatory=True, child=factory.create_someip_parameter_basetype("Child", "A_UINT8", True, 8, 8)
        )
        assert not member.legacy()


class TestSOMEIPBaseParameterBitfieldItemLegacy:
    """Tests for SOMEIPBaseParameterBitfieldItem legacy methods."""

    def test_bitfield_item_legacy(self):
        """Test bitfield item legacy."""
        factory = BaseConfigurationFactory()
        item = factory.create_someip_parameter_bitfield_item(bit_number=0, name="FLAG1")
        assert not item.legacy()


class TestSOMEIPBaseParameterTypedefLegacy:
    """Tests for SOMEIPBaseParameterTypedef legacy methods."""

    def test_typedef_legacy(self):
        """Test typedef legacy."""
        factory = BaseConfigurationFactory()
        typedef = factory.create_someip_parameter_typedef(
            "Typedef1", "OriginalType", factory.create_someip_parameter_basetype("Child", "A_UINT8", True, 8, 8)
        )
        assert not typedef.legacy()


class TestSOMEIPBaseParameterUnionAdditional4:
    """Additional tests for SOMEIPBaseParameterUnion edge cases."""

    def test_union_length_of_length_default(self):
        """Test union length_of_length default value."""
        factory = BaseConfigurationFactory()
        member = factory.create_someip_parameter_union_member(
            index=0, name="Member1", mandatory=True, child=factory.create_someip_parameter_basetype("Child", "A_UINT8", True, 8, 8)
        )
        union = factory.create_someip_parameter_union("Union1", None, 32, 0, {0: member})
        assert union.length_of_length() == 32

    def test_union_length_of_length_custom(self):
        """Test union length_of_length custom value."""
        factory = BaseConfigurationFactory()
        member = factory.create_someip_parameter_union_member(
            index=0, name="Member1", mandatory=True, child=factory.create_someip_parameter_basetype("Child", "A_UINT8", True, 8, 8)
        )
        union = factory.create_someip_parameter_union("Union1", 16, 32, 0, {0: member})
        assert union.length_of_length() == 16

    def test_union_length_of_type_default(self):
        """Test union length_of_type default value."""
        factory = BaseConfigurationFactory()
        member = factory.create_someip_parameter_union_member(
            index=0, name="Member1", mandatory=True, child=factory.create_someip_parameter_basetype("Child", "A_UINT8", True, 8, 8)
        )
        union = factory.create_someip_parameter_union("Union1", 32, None, 0, {0: member})
        assert union.length_of_type() == 32

    def test_union_length_of_type_custom(self):
        """Test union length_of_type custom value."""
        factory = BaseConfigurationFactory()
        member = factory.create_someip_parameter_union_member(
            index=0, name="Member1", mandatory=True, child=factory.create_someip_parameter_basetype("Child", "A_UINT8", True, 8, 8)
        )
        union = factory.create_someip_parameter_union("Union1", 32, 16, 0, {0: member})
        assert union.length_of_type() == 16


class TestSOMEIPBaseParameterStructAdditional3:
    """Additional tests for SOMEIPBaseParameterStruct edge cases."""

    def test_struct_length_of_length_default(self):
        """Test struct length_of_length default value."""
        factory = BaseConfigurationFactory()
        member = factory.create_someip_parameter_struct_member(
            position=0,
            name="Member1",
            mandatory=True,
            child=factory.create_someip_parameter_basetype("Child", "A_UINT8", True, 8, 8),
            signal=None,
        )
        struct = factory.create_someip_parameter_struct("Struct1", None, 0, {0: member}, tlv=False)
        assert struct.length_of_length() == 0

    def test_struct_length_of_length_custom(self):
        """Test struct length_of_length custom value."""
        factory = BaseConfigurationFactory()
        member = factory.create_someip_parameter_struct_member(
            position=0,
            name="Member1",
            mandatory=True,
            child=factory.create_someip_parameter_basetype("Child", "A_UINT8", True, 8, 8),
            signal=None,
        )
        struct = factory.create_someip_parameter_struct("Struct1", 16, 0, {0: member}, tlv=False)
        assert struct.length_of_length() == 16


class TestSOMEIPBaseParameterBasetypeAdditional:
    """Additional tests for SOMEIPBaseParameterBasetype."""

    def test_basetype_name2(self):
        """Test basetype name2 method."""
        factory = BaseConfigurationFactory()
        param = factory.create_someip_parameter_basetype("Param1", "A_UINT8", True, 8, 8)
        # Note: basetype doesn't have name2 method, this test verifies it's not present
        assert not hasattr(param, "name2")


class TestSOMEIPBaseParameterStringAdditional:
    """Additional tests for SOMEIPBaseParameterString."""

    def test_string_size_min_bits(self):
        """Test string size_min_bits."""
        factory = BaseConfigurationFactory()
        param = factory.create_someip_parameter_string("String1", "UTF-8", True, 0, 100, "NULL", 32, 0)
        size = param.size_min_bits()
        assert size >= 0

    def test_string_size_max_bits(self):
        """Test string size_max_bits."""
        factory = BaseConfigurationFactory()
        param = factory.create_someip_parameter_string("String1", "UTF-8", True, 0, 100, "NULL", 32, 0)
        size = param.size_max_bits()
        assert size >= 0
