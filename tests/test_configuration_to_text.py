#!/usr/bin/python
"""Unit tests for configuration_to_text module."""

from configuration_to_text import SimpleConfigurationFactory


class TestSimpleConfigurationFactory:
    """Test cases for SimpleConfigurationFactory."""

    def setup_method(self):
        """Set up test fixtures."""
        self.factory = SimpleConfigurationFactory()

    def test_create_switch(self):
        """Test switch creation."""
        switch = self.factory.create_switch("Switch1", None, [])
        assert switch.name() == "Switch1"

    def test_create_controller(self):
        """Test controller creation."""
        controller = self.factory.create_controller("Controller1", [])
        assert controller.name() == "Controller1"

    def test_create_signal(self):
        """Test signal creation."""
        signal = self.factory.create_signal(
            id="SIG1",
            name="TestSignal",
            compu_scale=[1.0, 0.0],
            compu_consts=[("OPEN", "0", "1")],
            bit_len=8,
            min_len=1,
            max_len=8,
            basetype="A_UINT8",
            basetypelen=8,
        )
        assert signal.id() == "SIG1"
        assert signal.name() == "TestSignal"

    def test_create_pdu(self):
        """Test PDU creation."""
        pdu = self.factory.create_pdu(id="PDU1", short_name="TestPDU", byte_length=8, pdu_type="SIGNAL", signal_instances={})
        assert pdu.id() == "PDU1"

    def test_create_frame(self):
        """Test frame creation."""
        frame = self.factory.create_frame(id="FRAME1", short_name="TestFrame", byte_length=8, frame_type="UNSPECIFIED", pdu_instances={})
        assert frame.id() == "FRAME1"

    def test_create_signal_instance(self):
        """Test signal instance creation."""
        signal_instance = self.factory.create_signal_instance(id="SIG_INST1", signal_ref="SIG1", bit_position=0, is_high_low_byte_order=True)
        assert signal_instance.__id__ == "SIG_INST1"
        assert signal_instance.__signal_ref__ == "SIG1"


class TestTextOutput:
    """Test cases for text output generation."""

    def test_generate_text_output(self):
        """Test generating text output."""
        factory = SimpleConfigurationFactory()

        ecu = factory.create_ecu("ECU1", [])
        controller = factory.create_controller("Controller1", [])

        # Create simple text representation
        text = "ECU: " + ecu.name() + "\n"
        text += "Controller: " + controller.name() + "\n"

        assert "ECU: ECU1" in text
        assert "Controller: Controller1" in text

    def test_generate_frame_text(self):
        """Test generating frame text output."""
        factory = SimpleConfigurationFactory()

        frame = factory.create_frame(id="FRAME1", short_name="CAN_Message", byte_length=8, frame_type="CAN", pdu_instances={})

        # Generate text representation
        text = "Frame: " + frame.name() + "\n"
        text += "ID: " + frame.id() + "\n"
        text += "Size: " + str(frame.byte_length()) + " bytes\n"

        assert "Frame: CAN_Message" in text
        assert "ID: FRAME1" in text
        assert "Size: 8 bytes" in text

    def test_generate_pdu_text(self):
        """Test generating PDU text output."""
        factory = SimpleConfigurationFactory()

        pdu = factory.create_pdu(id="PDU1", short_name="TestDataPDU", byte_length=8, pdu_type="SIGNAL", signal_instances={})

        # Generate text representation
        text = "PDU: " + pdu.name() + "\n"
        text += "ID: " + pdu.id() + "\n"
        text += "Type: " + pdu.pdu_type() + "\n"

        assert "PDU: TestDataPDU" in text
        assert "ID: PDU1" in text
        assert "Type: SIGNAL" in text
