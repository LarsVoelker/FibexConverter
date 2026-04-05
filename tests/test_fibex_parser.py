#!/usr/bin/python
"""Unit tests for FibexParser core functionality."""

import xml.etree.ElementTree as ET

from fibex_parser import FibexParser

# Sample FIBEX XML for testing
MINIMAL_FIBEX = """<?xml version="1.0" encoding="UTF-8"?>
<fx:FIBEX xmlns:fx="http://www.asam.net/xml/fbx" xmlns:ho="http://www.asam.net/xml" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <fx:PROJECT ID="PROJ1">
        <ho:SHORT-NAME>TestProject</ho:SHORT-NAME>
    </fx:PROJECT>
    <fx:CHANNELS>
        <fx:CHANNEL ID="CHAN1">
            <ho:SHORT-NAME>Ethernet1</ho:SHORT-NAME>
            <ethernet:VIRTUAL-LAN xmlns:ethernet="http://www.asam.net/xml/fbx/ethernet">
                <ethernet:VLAN-IDENTIFIER>100</ethernet:VLAN-IDENTIFIER>
                <ho:SHORT-NAME>VLAN100</ho:SHORT-NAME>
            </ethernet:VIRTUAL-LAN>
        </fx:CHANNEL>
    </fx:CHANNELS>
    <fx:ECUS>
        <fx:ECU ID="ECU1">
            <ho:SHORT-NAME>ECU1</ho:SHORT-NAME>
            <fx:CONTROLLERS>
                <fx:CONTROLLER ID="CTRL1">
                    <ho:SHORT-NAME>Controller1</ho:SHORT-NAME>
                </fx:CONTROLLER>
            </fx:CONTROLLERS>
            <fx:CONNECTORS>
                <fx:CONNECTOR ID="CONN1">
                    <fx:CHANNEL-REF ID-REF="CHAN1"/>
                    <fx:CONTROLLER-REF ID-REF="CTRL1"/>
                </fx:CONNECTOR>
            </fx:CONNECTORS>
        </fx:ECU>
    </fx:ECUS>
</fx:FIBEX>
"""

FIBEX_WITH_SIGNALS = """<?xml version="1.0" encoding="UTF-8"?>
<fx:FIBEX xmlns:fx="http://www.asam.net/xml/fbx" xmlns:ho="http://www.asam.net/xml" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <fx:PROJECT ID="PROJ1">
        <ho:SHORT-NAME>TestProject</ho:SHORT-NAME>
    </fx:PROJECT>
    <fx:CHANNELS>
        <fx:CHANNEL ID="CHAN1">
            <ho:SHORT-NAME>Ethernet1</ho:SHORT-NAME>
        </fx:CHANNEL>
    </fx:CHANNELS>
    <fx:CODINGS>
        <fx:CODING ID="COD1">
            <ho:SHORT-NAME>Coding1</ho:SHORT-NAME>
            <ho:CODED-TYPE CATEGORY="A_UINT8" BASE-DATA-TYPE="A_UINT8">
                <ho:BIT-LENGTH>8</ho:BIT-LENGTH>
            </ho:CODED-TYPE>
        </fx:CODING>
    </fx:CODINGS>
    <fx:SIGNALS>
        <fx:SIGNAL ID="SIG1">
            <ho:SHORT-NAME>Signal1</ho:SHORT-NAME>
            <fx:CODING-REF ID-REF="COD1"/>
        </fx:SIGNAL>
    </fx:SIGNALS>
    <fx:ECUS>
        <fx:ECU ID="ECU1">
            <ho:SHORT-NAME>ECU1</ho:SHORT-NAME>
            <fx:CONTROLLERS>
                <fx:CONTROLLER ID="CTRL1">
                    <ho:SHORT-NAME>Controller1</ho:SHORT-NAME>
                </fx:CONTROLLER>
            </fx:CONTROLLERS>
            <fx:CONNECTORS>
                <fx:CONNECTOR ID="CONN1">
                    <fx:CHANNEL-REF ID-REF="CHAN1"/>
                    <fx:CONTROLLER-REF ID-REF="CTRL1"/>
                </fx:CONNECTOR>
            </fx:CONNECTORS>
        </fx:ECU>
    </fx:ECUS>
</fx:FIBEX>
"""

FIBEX_WITH_PDU = """<?xml version="1.0" encoding="UTF-8"?>
<fx:FIBEX xmlns:fx="http://www.asam.net/xml/fbx" xmlns:ho="http://www.asam.net/xml" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <fx:PROJECT ID="PROJ1">
        <ho:SHORT-NAME>TestProject</ho:SHORT-NAME>
    </fx:PROJECT>
    <fx:CHANNELS>
        <fx:CHANNEL ID="CHAN1">
            <ho:SHORT-NAME>Ethernet1</ho:SHORT-NAME>
        </fx:CHANNEL>
    </fx:CHANNELS>
    <fx:CODINGS>
        <fx:CODING ID="COD1">
            <ho:SHORT-NAME>Coding1</ho:SHORT-NAME>
            <ho:CODED-TYPE CATEGORY="A_UINT8" BASE-DATA-TYPE="A_UINT8">
                <ho:BIT-LENGTH>8</ho:BIT-LENGTH>
            </ho:CODED-TYPE>
        </fx:CODING>
    </fx:CODINGS>
    <fx:SIGNALS>
        <fx:SIGNAL ID="SIG1">
            <ho:SHORT-NAME>Signal1</ho:SHORT-NAME>
            <fx:CODING-REF ID-REF="COD1"/>
        </fx:SIGNAL>
    </fx:SIGNALS>
    <fx:PDUS>
        <fx:PDU ID="PDU1">
            <ho:SHORT-NAME>TestPDU</ho:SHORT-NAME>
            <fx:BYTE-LENGTH>8</fx:BYTE-LENGTH>
            <fx:PDU-TYPE>SIGNAL</fx:PDU-TYPE>
            <fx:SIGNAL-INSTANCES>
                <fx:SIGNAL-INSTANCE ID="SIG_INST1">
                    <fx:BIT-POSITION>0</fx:BIT-POSITION>
                    <fx:SIGNAL-REF ID-REF="SIG1"/>
                </fx:SIGNAL-INSTANCE>
            </fx:SIGNAL-INSTANCES>
        </fx:PDU>
    </fx:PDUS>
    <fx:FRAMES>
        <fx:FRAME ID="FRAME1">
            <ho:SHORT-NAME>TestFrame</ho:SHORT-NAME>
            <fx:BYTE-LENGTH>8</fx:BYTE-LENGTH>
            <fx:FRAME-TYPE>UNSPECIFIED</fx:FRAME-TYPE>
            <fx:PDU-INSTANCES>
                <fx:PDU-INSTANCE ID="PDU_INST1">
                    <fx:BIT-POSITION>0</fx:BIT-POSITION>
                    <fx:PDU-REF ID-REF="PDU1"/>
                </fx:PDU-INSTANCE>
            </fx:PDU-INSTANCES>
        </fx:FRAME>
    </fx:FRAMES>
    <fx:FRAME-TRIGGERING>
        <fx:FRAME-TRIGGERING ID="FT1">
            <fx:FRAME-REF ID-REF="FRAME1"/>
            <fx:IDENTIFIER>
                <fx:IDENTIFIER-VALUE>123</fx:IDENTIFIER-VALUE>
            </fx:IDENTIFIER>
        </fx:FRAME-TRIGGERING>
    </fx:FRAME-TRIGGERING>
    <fx:ECUS>
        <fx:ECU ID="ECU1">
            <ho:SHORT-NAME>ECU1</ho:SHORT-NAME>
            <fx:CONTROLLERS>
                <fx:CONTROLLER ID="CTRL1">
                    <ho:SHORT-NAME>Controller1</ho:SHORT-NAME>
                </fx:CONTROLLER>
            </fx:CONTROLLERS>
            <fx:CONNECTORS>
                <fx:CONNECTOR ID="CONN1">
                    <fx:CHANNEL-REF ID-REF="CHAN1"/>
                    <fx:CONTROLLER-REF ID-REF="CTRL1"/>
                </fx:CONNECTOR>
            </fx:CONNECTORS>
        </fx:ECU>
    </fx:ECUS>
</fx:FIBEX>
"""


class TestFibexParserBasic:
    """Test cases for basic FibexParser functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        self.parser = FibexParser(plugin_file=None, ecu_name_replacement=None)

    def test_initialization(self):
        """Test parser initialization."""
        assert self.parser.__ns__ is not None
        assert self.parser.__services__ == {}
        assert self.parser.__codings__ == {}
        assert self.parser.__signals__ == {}
        assert self.parser.__frames__ == {}

    def test_get_attribute_with_namespace(self):
        """Test get_attribute with namespace prefix."""
        root = ET.fromstring("<fx:ELEMENT xmlns:fx='http://www.asam.net/xml/fbx' fx:ID='test-id'></fx:ELEMENT>")
        result = self.parser.get_attribute(root, "fx:ID")
        assert result == "test-id"

    def test_get_attribute_without_namespace(self):
        """Test get_attribute without namespace."""
        root = ET.fromstring("<ELEMENT ID='test-id'></ELEMENT>")
        result = self.parser.get_attribute(root, "ID")
        assert result == "test-id"


class TestFibexParserCodings:
    """Test cases for coding parsing."""

    def setup_method(self):
        """Set up test fixtures."""
        self.parser = FibexParser(plugin_file=None, ecu_name_replacement=None)

    def test_parse_coding(self):
        """Test parsing a single coding."""
        xml = """<?xml version="1.0" encoding="UTF-8"?>
<fx:FIBEX xmlns:fx="http://www.asam.net/xml/fbx" xmlns:ho="http://www.asam.net/xml">
    <fx:CODINGS>
        <fx:CODING ID="COD1">
            <ho:SHORT-NAME>Coding1</ho:SHORT-NAME>
            <ho:CODED-TYPE CATEGORY="A_UINT8" ho:BASE-DATA-TYPE="A_UINT8">
                <ho:BIT-LENGTH>8</ho:BIT-LENGTH>
            </ho:CODED-TYPE>
        </fx:CODING>
    </fx:CODINGS>
</fx:FIBEX>"""

        root = ET.fromstring(xml)
        self.parser.parse_codings(root)

        assert "COD1" in self.parser.__codings__
        coding = self.parser.__codings__["COD1"]
        assert coding["Name"] == "Coding1"
        assert coding["Basetype"] == "A_UINT8"
        assert coding["BitLength"] == 8

    def test_parse_codings_with_multiple(self):
        """Test parsing multiple codings."""
        xml = """<?xml version="1.0" encoding="UTF-8"?>
<fx:FIBEX xmlns:fx="http://www.asam.net/xml/fbx" xmlns:ho="http://www.asam.net/xml">
    <fx:CODINGS>
        <fx:CODING ID="COD1">
            <ho:SHORT-NAME>Coding1</ho:SHORT-NAME>
            <ho:CODED-TYPE CATEGORY="A_UINT8" BASE-DATA-TYPE="A_UINT8">
                <ho:BIT-LENGTH>8</ho:BIT-LENGTH>
            </ho:CODED-TYPE>
        </fx:CODING>
        <fx:CODING ID="COD2">
            <ho:SHORT-NAME>Coding2</ho:SHORT-NAME>
            <ho:CODED-TYPE CATEGORY="A_FLOAT32" BASE-DATA-TYPE="A_FLOAT32">
                <ho:BIT-LENGTH>32</ho:BIT-LENGTH>
            </ho:CODED-TYPE>
        </fx:CODING>
    </fx:CODINGS>
</fx:FIBEX>"""

        root = ET.fromstring(xml)
        self.parser.parse_codings(root)

        assert "COD1" in self.parser.__codings__
        assert "COD2" in self.parser.__codings__


class TestFibexParserSignals:
    """Test cases for signal parsing."""

    def setup_method(self):
        """Set up test fixtures."""
        self.parser = FibexParser(plugin_file=None, ecu_name_replacement=None)

    def test_parse_signal(self):
        """Test parsing a single signal."""
        xml = """<?xml version="1.0" encoding="UTF-8"?>
<fx:FIBEX xmlns:fx="http://www.asam.net/xml/fbx" xmlns:ho="http://www.asam.net/xml">
    <fx:CODINGS>
        <fx:CODING ID="COD1">
            <ho:SHORT-NAME>Coding1</ho:SHORT-NAME>
            <ho:CODED-TYPE CATEGORY="A_UINT8" BASE-DATA-TYPE="A_UINT8">
                <ho:BIT-LENGTH>8</ho:BIT-LENGTH>
            </ho:CODED-TYPE>
        </fx:CODING>
    </fx:CODINGS>
    <fx:SIGNALS>
        <fx:SIGNAL ID="SIG1">
            <ho:SHORT-NAME>Signal1</ho:SHORT-NAME>
            <fx:CODING-REF ID-REF="COD1"/>
        </fx:SIGNAL>
    </fx:SIGNALS>
</fx:FIBEX>"""

        root = ET.fromstring(xml)
        self.parser.parse_codings(root)

        # Mock a configuration factory
        class MockFactory:
            def create_signal(self, id, name, compu_scale, compu_consts, bit_len, min_len, max_len, basetype, basetypelen):
                return type("MockSignal", (), {"id": lambda self: id, "name": lambda self: name})()

        self.parser.__conf_factory__ = MockFactory()
        result = self.parser.parse_signal(root.find(".//fx:SIGNALS/fx:SIGNAL", self.parser.__ns__))

        assert result is not None
        assert result.id() == "SIG1"
        assert result.name() == "Signal1"


class TestFibexParserPDUs:
    """Test cases for PDU parsing."""

    def setup_method(self):
        """Set up test fixtures."""
        self.parser = FibexParser(plugin_file=None, ecu_name_replacement=None)

    def test_parse_signal_pdu(self):
        """Test parsing a simple signal PDU."""
        xml = """<?xml version="1.0" encoding="UTF-8"?>
<fx:FIBEX xmlns:fx="http://www.asam.net/xml/fbx" xmlns:ho="http://www.asam.net/xml">
    <fx:PDUS>
        <fx:PDU ID="PDU1">
            <ho:SHORT-NAME>TestPDU</ho:SHORT-NAME>
            <fx:BYTE-LENGTH>8</fx:BYTE-LENGTH>
            <fx:PDU-TYPE>SIGNAL</fx:PDU-TYPE>
        </fx:PDU>
    </fx:PDUS>
</fx:FIBEX>"""

        root = ET.fromstring(xml)
        pdu_element = root.find(".//fx:PDUS/fx:PDU", self.parser.__ns__)

        # Mock factory
        class MockFactory:
            def create_pdu(self, id, short_name, byte_length, pdu_type, signal_instances):
                return type("MockPDU", (), {"id": lambda self: id, "short_name": lambda self: short_name, "byte_length": lambda self: byte_length})()

        self.parser.__conf_factory__ = MockFactory()
        result = self.parser.parse_signal_pdu(pdu_element, verbose=False)

        assert result is not None
        assert result.id() == "PDU1"
        assert result.short_name() == "TestPDU"
        assert result.byte_length() == 8


class TestFibexParserFrames:
    """Test cases for frame parsing."""

    def setup_method(self):
        """Set up test fixtures."""
        self.parser = FibexParser(plugin_file=None, ecu_name_replacement=None)

    def test_parse_frame(self):
        """Test parsing a frame."""
        xml = """<?xml version="1.0" encoding="UTF-8"?>
<fx:FIBEX xmlns:fx="http://www.asam.net/xml/fbx" xmlns:ho="http://www.asam.net/xml">
    <fx:FRAMES>
        <fx:FRAME ID="FRAME1">
            <ho:SHORT-NAME>TestFrame</ho:SHORT-NAME>
            <fx:BYTE-LENGTH>8</fx:BYTE-LENGTH>
            <fx:FRAME-TYPE>UNSPECIFIED</fx:FRAME-TYPE>
        </fx:FRAME>
    </fx:FRAMES>
</fx:FIBEX>"""

        root = ET.fromstring(xml)
        frame_element = root.find(".//fx:FRAMES/fx:FRAME", self.parser.__ns__)

        # Mock factory
        class MockFactory:
            def create_frame(self, id, short_name, byte_length, frame_type, pdu_instances):
                return type(
                    "MockFrame",
                    (),
                    {
                        "id": lambda self: id,
                        "short_name": lambda self: short_name,
                        "byte_length": lambda self: byte_length,
                        "frame_type": lambda self: frame_type,
                    },
                )()

        self.parser.__conf_factory__ = MockFactory()
        result = self.parser.parse_frame(frame_element, verbose=False)

        assert result is not None
        assert result.id() == "FRAME1"
        assert result.short_name() == "TestFrame"


class TestFibexParserFrameTriggering:
    """Test cases for frame triggering parsing."""

    def setup_method(self):
        """Set up test fixtures."""
        self.parser = FibexParser(plugin_file=None, ecu_name_replacement=None)

    def test_parse_can_frame_triggering(self):
        """Test parsing a CAN frame triggering."""
        xml = """<?xml version="1.0" encoding="UTF-8"?>
<fx:FIBEX xmlns:fx="http://www.asam.net/xml/fbx" xmlns:ho="http://www.asam.net/xml">
    <fx:FRAME-TRIGGERINGS>
        <fx:FRAME-TRIGGERING ID="FT1">
            <fx:FRAME-REF ID-REF="FRAME1"/>
            <fx:IDENTIFIER>
                <fx:IDENTIFIER-VALUE>123</fx:IDENTIFIER-VALUE>
            </fx:IDENTIFIER>
        </fx:FRAME-TRIGGERING>
    </fx:FRAME-TRIGGERINGS>
</fx:FIBEX>"""

        root = ET.fromstring(xml)
        ft_element = root.find(".//fx:FRAME-TRIGGERING", self.parser.__ns__)

        # Mock factory
        class MockFactory:
            def create_frame_triggering_can(self, id, frame, can_id):
                return type("MockCANTriggering", (), {"id": lambda self: id, "frame": lambda self: frame, "can_id": lambda self: can_id})()

            def create_frame_triggering_flexray(self, id, frame, slot_id, cycle_counter, base_cycle, cycle_repetition):
                return None  # Not flexray

        self.parser.__conf_factory__ = MockFactory()
        result = self.parser.parse_frame_triggering(ft_element)

        assert result is not None
        assert result.id() == "FT1"
        assert result.can_id() == 123

    def test_parse_flexray_frame_triggering(self):
        """Test parsing a FlexRay frame triggering."""
        xml = """<?xml version="1.0" encoding="UTF-8"?>
<fx:FIBEX xmlns:fx="http://www.asam.net/xml/fbx" xmlns:ho="http://www.asam.net/xml">
    <fx:FRAME-TRIGGERINGS>
        <fx:FRAME-TRIGGERING ID="FT1">
            <fx:FRAME-REF ID-REF="FRAME1"/>
            <fx:TIMINGS>
                <fx:ABSOLUTELY-SCHEDULED-TIMING>
                    <fx:SLOT-ID>10</fx:SLOT-ID>
                    <fx:CYCLE-COUNTER>5</fx:CYCLE-COUNTER>
                </fx:ABSOLUTELY-SCHEDULED-TIMING>
            </fx:TIMINGS>
        </fx:FRAME-TRIGGERING>
    </fx:FRAME-TRIGGERINGS>
</fx:FIBEX>"""

        root = ET.fromstring(xml)
        ft_element = root.find(".//fx:FRAME-TRIGGERING", self.parser.__ns__)

        # Mock factory
        class MockFactory:
            def create_frame_triggering_can(self, id, frame, can_id):
                return None  # Not CAN

            def create_frame_triggering_flexray(self, id, frame, slot_id, cycle_counter, base_cycle, cycle_repetition):
                return type(
                    "MockFlexRayTriggering",
                    (),
                    {"id": lambda self: id, "slot_id": lambda self: slot_id, "cycle_counter": lambda self: cycle_counter},
                )()

        self.parser.__conf_factory__ = MockFactory()
        result = self.parser.parse_frame_triggering(ft_element)

        assert result is not None
        assert result.id() == "FT1"
        assert result.slot_id() == 10
        assert result.cycle_counter() == 5


class TestFibexParserECUs:
    """Test cases for ECU parsing."""

    def setup_method(self):
        """Set up test fixtures."""
        self.parser = FibexParser(plugin_file=None, ecu_name_replacement=None)

    def test_parse_channels(self):
        """Test parsing channels."""
        xml = """<?xml version="1.0" encoding="UTF-8"?>
<fx:FIBEX xmlns:fx="http://www.asam.net/xml/fbx" xmlns:ho="http://www.asam.net/xml">
    <fx:CHANNELS>
        <fx:CHANNEL ID="CHAN1">
            <ho:SHORT-NAME>Ethernet1</ho:SHORT-NAME>
            <ethernet:VIRTUAL-LAN xmlns:ethernet="http://www.asam.net/xml/fbx/ethernet">
                <ethernet:VLAN-IDENTIFIER>100</ethernet:VLAN-IDENTIFIER>
                <ho:SHORT-NAME>VLAN100</ho:SHORT-NAME>
            </ethernet:VIRTUAL-LAN>
        </fx:CHANNEL>
    </fx:CHANNELS>
</fx:FIBEX>"""

        root = ET.fromstring(xml)
        self.parser.parse_channels(root)

        assert "CHAN1" in self.parser.__channels__
        channel = self.parser.__channels__["CHAN1"]
        assert channel["name"] == "Ethernet1"
        assert channel["vlanid"] == "100"

    def test_parse_ecus(self):
        """Test parsing ECUs."""
        xml = """<?xml version="1.0" encoding="UTF-8"?>
<fx:FIBEX xmlns:fx="http://www.asam.net/xml/fbx" xmlns:ho="http://www.asam.net/xml">
    <fx:ECUS>
        <fx:ECU ID="ECU1">
            <ho:SHORT-NAME>ECU1</ho:SHORT-NAME>
            <fx:CONTROLLERS>
                <fx:CONTROLLER ID="CTRL1">
                    <ho:SHORT-NAME>Controller1</ho:SHORT-NAME>
                </fx:CONTROLLER>
            </fx:CONTROLLERS>
            <fx:CONNECTORS>
                <fx:CONNECTOR ID="CONN1">
                    <fx:CHANNEL-REF ID-REF="CHAN1"/>
                    <fx:CONTROLLER-REF ID-REF="CTRL1"/>
                </fx:CONNECTOR>
            </fx:CONNECTORS>
        </fx:ECU>
    </fx:ECUS>
</fx:FIBEX>"""

        root = ET.fromstring(xml)
        self.parser.parse_channels(root)

        # Mock factory for ECUs
        class MockFactory:
            def create_ecu(self, name, controllers):
                return type("MockECU", (), {"name": lambda self: name, "controllers": lambda self: controllers})()

            def create_controller(self, name, vlans):
                return type("MockController", (), {"name": lambda self: name, "vlans": lambda self: vlans})()

            def create_interface(self, name, vlanid, ips, sockets, input_frame_trigs, output_frame_trigs, fr_channel):
                return type("MockInterface", (), {"name": lambda self: name, "vlanid": lambda self: vlanid, "ips": lambda self: ips})()

            def create_socket(self, name, ip, proto, portnumber, psis, csis, ehs, cegs):
                return type("MockSocket", (), {"name": lambda self: name, "ip": lambda self: ip})()

        self.parser.__conf_factory__ = MockFactory()
        self.parser.parse_ecus(root)

        assert len(self.parser.__ecus__) > 0
        assert "ECU1" in self.parser.__ecus__


class TestBasetypeUtils:
    """Test cases for basetype utility functions."""

    def setup_method(self):
        """Set up test fixtures."""
        self.parser = FibexParser(plugin_file=None, ecu_name_replacement=None)

    def test_basetype_length(self):
        """Test basetype_length function."""
        # Test integer types
        assert self.parser.basetype_length({"Basetype": "A_UINT8"}) == 8
        assert self.parser.basetype_length({"Basetype": "A_INT16"}) == 16
        assert self.parser.basetype_length({"Basetype": "A_UINT32"}) == 32
        assert self.parser.basetype_length({"Basetype": "A_FLOAT64"}) == 64

        # Test string types
        assert self.parser.basetype_length({"Basetype": "A_ASCIISTRING"}) == -1
        assert self.parser.basetype_length({"Basetype": "A_BYTEFIELD"}) == -1

    def test_basetype_is_int(self):
        """Test basetype_is_int function."""
        assert self.parser.basetype_is_int({"Basetype": "A_UINT8"})
        assert self.parser.basetype_is_int({"Basetype": "A_INT16"})
        assert not self.parser.basetype_is_int({"Basetype": "A_FLOAT32"})
        assert not self.parser.basetype_is_int({"Basetype": "A_ASCIISTRING"})

    def test_basetype_is_float(self):
        """Test basetype_is_float function."""
        assert self.parser.basetype_is_float({"Basetype": "A_FLOAT32"})
        assert self.parser.basetype_is_float({"Basetype": "A_FLOAT64"})
        assert not self.parser.basetype_is_float({"Basetype": "A_UINT32"})

    def test_basetype_is_string(self):
        """Test basetype_is_string function."""
        assert self.parser.basetype_is_string({"Basetype": "A_ASCIISTRING"})
        assert self.parser.basetype_is_string({"Basetype": "A_UNICODE2STRING"})
        assert not self.parser.basetype_is_string({"Basetype": "A_UINT32"})


class TestFibexParserIntegration:
    """Integration tests for FibexParser with complete XML files."""

    def test_parse_minimal_fibex(self, tmpdir):
        """Test parsing a minimal FIBEX file."""
        # Create a temporary file
        fibex_file = tmpdir.join("minimal.xml")
        fibex_file.write(MINIMAL_FIBEX)

        from configuration_to_text import SimpleConfigurationFactory

        factory = SimpleConfigurationFactory()

        parser = FibexParser(plugin_file=None, ecu_name_replacement=None)
        parser.parse_file(factory, str(fibex_file), verbose=False)

        # Verify ECUs were parsed
        assert len(factory.__ecus__) > 0

    def test_parse_fibex_with_signals(self, tmpdir):
        """Test parsing a FIBEX file with signals."""
        fibex_file = tmpdir.join("signals.xml")
        fibex_file.write(FIBEX_WITH_SIGNALS)

        from configuration_to_text import SimpleConfigurationFactory

        factory = SimpleConfigurationFactory()

        parser = FibexParser(plugin_file=None, ecu_name_replacement=None)
        parser.parse_file(factory, str(fibex_file), verbose=False)

        # Verify signals were parsed
        assert len(parser.__signals__) > 0
