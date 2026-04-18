#!/usr/bin/python
"""Unit tests for configuration_to_text module."""

import pytest
from configuration_base_classes import BaseVLAN
from configuration_to_text import (
    SimpleConfigurationFactory,
    Switch,
    SwitchPort,
)
import configuration_to_text


class TestECUAndController:
    """Tests for ECU and Controller string representations."""

    def setup_method(self):
        self.factory = SimpleConfigurationFactory()

    def test_ecu_str(self):
        ecu = self.factory.create_ecu("TestECU", [])
        text = ecu.str(0, self.factory)
        assert "TestECU" in text

    def test_ecu_with_controller(self):
        controller = self.factory.create_controller("Controller1", [])
        ecu = self.factory.create_ecu("ECU1", [controller])
        text = ecu.str(0, self.factory)
        assert "ECU ECU1" in text
        assert "CTRL Controller1" in text

    def test_ecu_with_switch(self):
        switch = self.factory.create_switch("TestSwitch", None, [])
        ecu = self.factory.create_ecu("TestECU", [])
        ecu.add_switch(switch)
        text = ecu.str(0, self.factory)
        assert "TestECU" in text
        assert "TestSwitch" in text

    def test_controller_str(self):
        controller = self.factory.create_controller("TestCtrl", [])
        text = controller.str(0, self.factory)
        assert "TestCtrl" in text


class TestSwitchAndPort:
    """Tests for Switch and SwitchPort string representations."""

    def setup_method(self):
        self.factory = SimpleConfigurationFactory()

    def test_switch_str(self):
        switch = self.factory.create_switch("TestSwitch", None, [])
        text = switch.str(0, self.factory)
        assert "TestSwitch" in text

    def test_switch_str_with_ecu_name(self):
        ecu = self.factory.create_ecu("TestECU", [])
        switch = self.factory.create_switch("TestSwitch", ecu, [])
        text = switch.str(0, self.factory, print_ecu_name=True)
        assert "TestSwitch" in text
        assert "TestECU" in text

    def test_switch_port_str_no_port_no_ctrl(self):
        """SwitchPort with neither port nor controller connected."""
        configuration_to_text.g_gen_portid = False
        port = SwitchPort("port1", None, None, 0, [])
        text = port.str(0, self.factory)
        assert "SwitchPort" in text

    def test_switch_port_str_with_ctrl(self):
        """SwitchPort connected to a controller."""
        configuration_to_text.g_gen_portid = False
        controller = self.factory.create_controller("TestCtrl", [])
        ecu = self.factory.create_ecu("TestECU", [controller])
        port = SwitchPort("port1", controller, None, 0, [])
        text = port.str(0, self.factory)
        assert "TestCtrl" in text

    def test_switch_port_str_with_port_ref(self):
        """SwitchPort connected to another SwitchPort (inter-switch link)."""
        configuration_to_text.g_gen_portid = False
        other_port = SwitchPort("other_port", None, None, 0, [])
        # Attach other_port to a switch so switch().name() is available
        Switch("OtherSwitch", None, [other_port])
        port = SwitchPort("my_port", None, other_port, 0, [])
        text = port.str(0, self.factory)
        assert "OtherSwitch" in text

    def test_switch_port_vlan_str(self):
        """SwitchPort with a VLAN shows VLAN info via str_vlans()."""
        configuration_to_text.g_gen_portid = False
        vlan = BaseVLAN("VLAN10", 10, 5)
        port = SwitchPort("port1", None, None, 0, [vlan])
        text = port.str(0, self.factory)
        assert "VLAN" in text
        assert "0xa" in text  # vlanid 10 as hex


class TestInterface:
    """Tests for Interface string representations."""

    def setup_method(self):
        self.factory = SimpleConfigurationFactory()

    def test_interface_str(self):
        interface = self.factory.create_interface(
            name="EthIf1",
            vlanid=0,
            ips=["192.168.1.1"],
            sockets=[],
            input_frame_trigs={},
            output_frame_trigs={},
            fr_channel=None,
        )
        text = interface.str(0, self.factory)
        assert "EthIf1" in text

    def test_interface_str_with_vlan(self):
        interface = self.factory.create_interface(
            name="EthIf1",
            vlanid=10,
            ips=["192.168.1.1"],
            sockets=[],
            input_frame_trigs={},
            output_frame_trigs={},
            fr_channel=None,
        )
        text = interface.str(0, self.factory)
        assert "VLAN" in text
        assert "0xa" in text

    def test_interface_str_with_multicast_ip(self):
        """Multicast IPs are not shown in interface output."""
        interface = self.factory.create_interface(
            name="EthIf1",
            vlanid=0,
            ips=["224.0.0.1"],
            sockets=[],
            input_frame_trigs={},
            output_frame_trigs={},
            fr_channel=None,
        )
        text = interface.str(0, self.factory)
        assert "EthIf1" in text

    def test_interface_str_with_input_frames(self):
        frame = self.factory.create_frame(
            id="FRAME1",
            short_name="TestFrame",
            byte_length=8,
            frame_type="CAN",
            pdu_instances={},
        )
        frame_trigger = self.factory.create_frame_triggering_can(id="trig1", frame_ref=frame, can_id=0x123)
        interface = self.factory.create_interface(
            name="EthIf1",
            vlanid=0,
            ips=["192.168.1.1"],
            sockets=[],
            input_frame_trigs={"trig1": frame_trigger},
            output_frame_trigs={},
            fr_channel=None,
        )
        text = interface.str(0, self.factory)
        assert "Input Frames" in text

    def test_interface_str_with_output_frames(self):
        frame = self.factory.create_frame(
            id="FRAME1",
            short_name="TestFrame",
            byte_length=8,
            frame_type="CAN",
            pdu_instances={},
        )
        frame_trigger = self.factory.create_frame_triggering_can(id="trig1", frame_ref=frame, can_id=0x123)
        interface = self.factory.create_interface(
            name="EthIf1",
            vlanid=0,
            ips=["192.168.1.1"],
            sockets=[],
            input_frame_trigs={},
            output_frame_trigs={"trig1": frame_trigger},
            fr_channel=None,
        )
        text = interface.str(0, self.factory)
        assert "Output Frames" in text

    def test_interface_str_with_ip_netmask(self):
        """IP is shown with netmask suffix when configured in the factory."""
        self.factory.add_ipv4_address_config("10.0.0.1", "255.255.255.0")
        interface = self.factory.create_interface(
            name="IfNet",
            vlanid=0,
            ips=["10.0.0.1"],
            sockets=[],
            input_frame_trigs={},
            output_frame_trigs={},
            fr_channel=None,
        )
        text = interface.str(0, self.factory)
        assert "/255.255.255.0" in text


class TestSocket:
    """Tests for Socket string representations."""

    def setup_method(self):
        self.factory = SimpleConfigurationFactory()

    def test_socket_str(self):
        socket = self.factory.create_socket(
            name="Socket1",
            ip="192.168.1.1",
            proto="tcp",
            portnumber=30401,
            serviceinstances=[],
            serviceinstanceclients=[],
            eventhandlers=[],
            eventgroupreceivers=[],
        )
        text = socket.str(0)
        assert "Socket1" in text
        assert "192.168.1.1" in text
        assert "30401" in text

    def test_socket_with_pdus(self):
        """Socket with incoming and outgoing EthernetPDUInstances."""
        pdu = self.factory.create_pdu(
            id="P1",
            short_name="TestPDU",
            byte_length=8,
            pdu_type="SIGNAL",
            signal_instances={},
        )
        eth_pdu_in = self.factory.create_ethernet_pdu_instance(pdu_ref=pdu, header_id=0x0001)
        eth_pdu_out = self.factory.create_ethernet_pdu_instance(pdu_ref=pdu, header_id=0x0002)
        socket = self.factory.create_socket(
            name="Socket1",
            ip="192.168.1.1",
            proto="udp",
            portnumber=30490,
            serviceinstances=[],
            serviceinstanceclients=[],
            eventhandlers=[],
            eventgroupreceivers=[],
        )
        socket.add_incoming_pdu(eth_pdu_in)
        socket.add_outgoing_pdu(eth_pdu_out)
        text = socket.str(0)
        assert "PDUs in" in text
        assert "PDUs out" in text


class TestFrameAndPDU:
    """Tests for Frame, PDU, PDUInstance, EthernetPDUInstance, and MultiplexPDU."""

    def setup_method(self):
        self.factory = SimpleConfigurationFactory()

    def test_frame_str(self):
        frame = self.factory.create_frame(
            id="F1",
            short_name="TestFrame",
            byte_length=8,
            frame_type="CAN",
            pdu_instances={},
        )
        text = frame.str(0)
        assert "TestFrame" in text

    def test_frame_duplicate_name_handling(self):
        """Duplicate frame names receive an incremented suffix."""
        frame1 = self.factory.create_frame(
            id="F1",
            short_name="DuplicateFrame",
            byte_length=8,
            frame_type="CAN",
            pdu_instances={},
        )
        assert frame1.name() == "DuplicateFrame"
        frame2 = self.factory.create_frame(
            id="F2",
            short_name="DuplicateFrame",
            byte_length=8,
            frame_type="CAN",
            pdu_instances={},
        )
        assert frame2.name() == "DuplicateFrame__duplicate1"

    def test_pdu_str(self):
        pdu = self.factory.create_pdu(
            id="P1",
            short_name="TestPDU",
            byte_length=8,
            pdu_type="SIGNAL",
            signal_instances={},
        )
        text = pdu.str(0)
        assert "TestPDU" in text
        assert "SIGNAL" in text

    def test_pdu_str_without_signals(self):
        pdu = self.factory.create_pdu(
            id="P1",
            short_name="TestPDU",
            byte_length=8,
            pdu_type="SIGNAL",
            signal_instances={},
        )
        text = pdu.str(0, show_signals=False)
        assert "TestPDU" in text

    def test_pdu_str_with_signal_instance(self):
        """PDU.str() renders contained signal instances by default."""
        signal = self.factory.create_signal("S1", "MySig", None, [], 8, 1, 8, "UINT8", 8)
        signal_inst = self.factory.create_signal_instance("SI1", "S1", 0, True)
        signal_inst.add_signal(signal)
        pdu = self.factory.create_pdu("P1", "SigPDU", 1, "SIGNAL", {0: signal_inst})
        text = pdu.str(0)
        assert "SigPDU" in text
        assert "MySig" in text

    def test_pdu_warning_on_duplicate(self, capsys):
        """Creating a PDU with a duplicate ID prints a WARNING."""
        self.factory.create_pdu(
            id="P1",
            short_name="PDU1",
            byte_length=8,
            pdu_type="SIGNAL",
            signal_instances={},
        )
        self.factory.create_pdu(
            id="P1",
            short_name="PDU2",
            byte_length=8,
            pdu_type="SIGNAL",
            signal_instances={},
        )
        captured = capsys.readouterr()
        assert "WARNING" in captured.out

    def test_pdu_instance_str(self):
        """PDUInstance.str() shows bit-position range and the PDU name."""
        pdu = self.factory.create_pdu("P1", "TestPDU", 1, "SIGNAL", {})
        pdu_inst = self.factory.create_pdu_instance("PI1", "P1", 0, True, None)
        pdu_inst.add_pdu(pdu)
        text = pdu_inst.str(0)
        assert "Bit pos." in text
        assert "TestPDU" in text

    def test_ethernet_pdu_instance_str(self):
        pdu = self.factory.create_pdu(
            id="P1",
            short_name="EthPDU",
            byte_length=8,
            pdu_type="ETHERNET",
            signal_instances={},
        )
        eth_inst = self.factory.create_ethernet_pdu_instance(pdu_ref=pdu, header_id=0x1234)
        text = eth_inst.str(0)
        assert "0x1234" in text

    def test_ethernet_pdu_instance_str_no_pdu(self):
        eth_inst = self.factory.create_ethernet_pdu_instance(pdu_ref=None, header_id=0x5678)
        text = eth_inst.str(0)
        assert "0x5678" in text

    def test_multiplex_pdu_switch_str_high_low(self):
        mux_switch = self.factory.create_multiplex_switch(
            id="mux1",
            short_name="MuxSwitch",
            bit_position=0,
            is_high_low_byte_order=True,
            bit_length=4,
        )
        text = mux_switch.str(0)
        assert "MuxSwitch" in text
        assert "high low" in text

    def test_multiplex_pdu_switch_str_low_high(self):
        mux_switch = self.factory.create_multiplex_switch(
            id="mux1",
            short_name="MuxSwitch",
            bit_position=0,
            is_high_low_byte_order=False,
            bit_length=4,
        )
        text = mux_switch.str(0)
        assert "low high" in text

    def test_multiplex_segment_position_str(self):
        seg_pos = self.factory.create_multiplex_segment_position(
            bit_position=4,
            is_high_low_byte_order=True,
            bit_length=8,
        )
        text = seg_pos.str(0)
        assert "Segment" in text

    def test_multiplex_segment_position_str_with_prefix(self):
        seg_pos = self.factory.create_multiplex_segment_position(
            bit_position=4,
            is_high_low_byte_order=True,
            bit_length=8,
        )
        text = seg_pos.str(0, prefix="Dynamic")
        assert "Dynamic" in text

    def test_multiplex_pdu_str(self):
        """MultiplexPDU.str() with switch, dynamic segment, and PDU instances."""
        mux_switch = self.factory.create_multiplex_switch("mux1", "MuxSw", 0, True, 4)
        seg_pos = self.factory.create_multiplex_segment_position(4, True, 8)
        dyn_pdu0 = self.factory.create_pdu("DYN0", "DynPDU0", 1, "SIGNAL", {})
        dyn_pdu1 = self.factory.create_pdu("DYN1", "DynPDU1", 1, "SIGNAL", {})
        mux_pdu = self.factory.create_multiplex_pdu(
            id="MPDU1",
            short_name="TestMuxPDU",
            byte_length=16,
            pdu_type="MULTIPLEX",
            switch=mux_switch,
            seg_pos=[seg_pos],
            pdu_instances={0: dyn_pdu0, 1: dyn_pdu1},
            static_segs=[],
            static_pdu=None,
        )
        text = mux_pdu.str(0)
        assert "TestMuxPDU" in text
        assert "MuxSw" in text
        assert "Dynamic" in text
        assert "Switch Code" in text

    def test_multiplex_pdu_str_with_static(self):
        """MultiplexPDU.str() with static segment and static PDU."""
        mux_switch = self.factory.create_multiplex_switch("mux2", "MuxSw2", 0, True, 4)
        seg_pos = self.factory.create_multiplex_segment_position(4, True, 8)
        static_seg = self.factory.create_multiplex_segment_position(12, True, 8)
        dyn_pdu = self.factory.create_pdu("DYN2", "DynPDU2", 1, "SIGNAL", {})
        static_pdu = self.factory.create_pdu("STAT1", "StaticPDU", 1, "SIGNAL", {})
        mux_pdu = self.factory.create_multiplex_pdu(
            id="MPDU2",
            short_name="StaticMuxPDU",
            byte_length=16,
            pdu_type="MULTIPLEX",
            switch=mux_switch,
            seg_pos=[seg_pos],
            pdu_instances={0: dyn_pdu},
            static_segs=[static_seg],
            static_pdu=static_pdu,
        )
        text = mux_pdu.str(0)
        assert "StaticMuxPDU" in text
        assert "Static" in text
        assert "Static PDU" in text


class TestSignalAndSignalInstance:
    """Tests for Signal and SignalInstance string representations."""

    def setup_method(self):
        self.factory = SimpleConfigurationFactory()

    def test_signal_str(self):
        signal = self.factory.create_signal("S1", "TestSignal", None, [], 8, 1, 8, "A_UINT8", 8)
        text = signal.str(0)
        assert "TestSignal" in text

    def test_signal_str_with_basetype(self):
        signal = self.factory.create_signal("S1", "TestSignal", None, [], 8, 1, 8, "A_UINT8", 8)
        text = signal.str(0, show_basetype=True)
        assert "TestSignal" in text
        assert "A_UINT8" in text

    def test_signal_str_with_compu_scale(self):
        signal = self.factory.create_signal("S1", "ScaledSignal", [1.0, 2.0, 3.0], [], 8, 1, 8, "A_UINT8", 8)
        text = signal.str(0)
        assert "f(x)" in text

    def test_signal_str_compu_scale_not_three_elements(self):
        """compu_scale with length != 3 must not add f(x)."""
        signal = self.factory.create_signal("S1", "Sig", [1.0, 0.0], [], 8, 1, 8, "A_UINT8", 8)
        text = signal.str(0)
        assert "Sig" in text
        assert "f(x)" not in text

    def test_signal_str_with_compu_consts(self):
        signal = self.factory.create_signal(
            "S1",
            "EnumSignal",
            None,
            [("OFF", "0", "0"), ("ON", "1", "1"), ("ERROR", "2", "254"), ("INVALID", "255", "255")],
            8,
            1,
            8,
            "A_UINT8",
            8,
        )
        text = signal.str(0)
        assert "Consts:" in text
        assert "OFF" in text
        assert "ON" in text

    def test_signal_instance_str(self):
        """SignalInstance.str() shows bit-position range and signal name."""
        signal = self.factory.create_signal("S1", "MySig", None, [], 16, 2, 2, "UINT16", 16)
        signal_inst = self.factory.create_signal_instance("SI1", "S1", 8, True)
        signal_inst.add_signal(signal)
        text = signal_inst.str(0)
        assert "Bit pos." in text
        assert "MySig" in text
        assert "8..23" in text  # bit 8, length 16 → end bit 23

    def test_signal_instance_str_with_start_offset(self):
        """start_offset shifts the bit position displayed."""
        signal = self.factory.create_signal("S1", "MySig", None, [], 8, 1, 1, "UINT8", 8)
        signal_inst = self.factory.create_signal_instance("SI1", "S1", 0, True)
        signal_inst.add_signal(signal)
        text = signal_inst.str(0, start_offset=16)
        assert "16..23" in text  # 0 + 16 = 16, end = 16 + 8 - 1 = 23

    def test_signal_instance_str_negative_bit_length(self):
        """bit_length == -1 shows a single bit position without a range."""
        signal = self.factory.create_signal("S1", "VarSig", None, [], -1, 0, 0, "UINT8", 8)
        signal_inst = self.factory.create_signal_instance("SI1", "S1", 4, True)
        signal_inst.add_signal(signal)
        text = signal_inst.str(0)
        assert "Bit pos.: 4]" in text
        assert ".." not in text


class TestFrameTriggering:
    """Tests for CAN and FlexRay frame triggering string representations."""

    def setup_method(self):
        self.factory = SimpleConfigurationFactory()

    def test_frame_triggering_can_str(self):
        frame = self.factory.create_frame(
            id="F1",
            short_name="CANFrame",
            byte_length=8,
            frame_type="CAN",
            pdu_instances={},
        )
        frame_trigger = self.factory.create_frame_triggering_can(id="t1", frame_ref=frame, can_id=0x123)
        text = frame_trigger.str(0)
        assert "CAN-ID" in text
        assert "0x123" in text or "291" in text

    def test_frame_triggering_can_str_no_frame(self):
        frame_trigger = self.factory.create_frame_triggering_can(id="t1", frame_ref=None, can_id=0x456)
        text = frame_trigger.str(0)
        assert "undefined" in text

    def test_frame_triggering_flexray_str_cycle_counter(self):
        frame = self.factory.create_frame(
            id="F1",
            short_name="FRFrame",
            byte_length=16,
            frame_type="FLEXRAY",
            pdu_instances={},
        )
        frame_trigger = self.factory.create_frame_triggering_flexray(
            id="t1",
            frame_ref=frame,
            slot_id=10,
            cycle_counter=5,
            base_cycle=None,
            cycle_repetition=None,
        )
        text = frame_trigger.str(0)
        assert "Slot ID" in text
        assert "Cycle Counter" in text

    def test_frame_triggering_flexray_str_base_cycle(self):
        frame = self.factory.create_frame(
            id="F1",
            short_name="FRFrame",
            byte_length=16,
            frame_type="FLEXRAY",
            pdu_instances={},
        )
        frame_trigger = self.factory.create_frame_triggering_flexray(
            id="t1",
            frame_ref=frame,
            slot_id=10,
            cycle_counter=None,
            base_cycle=2,
            cycle_repetition=4,
        )
        text = frame_trigger.str(0)
        assert "Base Cycle" in text

    def test_frame_triggering_flexray_str_undefined_timing(self):
        frame_trigger = self.factory.create_frame_triggering_flexray(
            id="t1",
            frame_ref=None,
            slot_id=10,
            cycle_counter=None,
            base_cycle=None,
            cycle_repetition=None,
        )
        text = frame_trigger.str(0)
        assert "Undefined Timing" in text


class TestSOMEIPService:
    """Tests for SOME/IP service, method, event, field, and eventgroup."""

    def setup_method(self):
        self.factory = SimpleConfigurationFactory()

    def _make_service(self, serviceid=0x1234, name="TestService"):
        return self.factory.create_someip_service(
            name=name,
            serviceid=serviceid,
            majorver=1,
            minorver=0,
            methods={},
            events={},
            fields={},
            eventgroups={},
        )

    def test_service_str(self):
        service = self._make_service()
        text = service.str(0)
        assert "TestService" in text
        assert "0x1234" in text

    def test_service_str_with_method(self):
        method = self.factory.create_someip_service_method(
            name="GetValue",
            methodid=0x0001,
            calltype="REQUEST",
            relia=True,
            inparams=[],
            outparams=[],
        )
        service = self.factory.create_someip_service(
            name="SvcMethod",
            serviceid=0x1111,
            majorver=1,
            minorver=0,
            methods={0x0001: method},
            events={},
            fields={},
            eventgroups={},
        )
        text = service.str(0)
        assert "GetValue" in text

    def test_method_str(self):
        method = self.factory.create_someip_service_method(
            name="GetValue",
            methodid=0x0001,
            calltype="REQUEST",
            relia=True,
            inparams=[],
            outparams=[],
        )
        text = method.str(0)
        assert "GetValue" in text
        assert "0x0001" in text

    def test_method_str_with_in_params(self):
        param = self.factory.create_someip_parameter(
            position=0,
            name="InputParam",
            desc="",
            mandatory=True,
            datatype=None,
            signal=None,
        )
        method = self.factory.create_someip_service_method(
            name="SetValue",
            methodid=0x0002,
            calltype="REQUEST",
            relia=True,
            inparams=[param],
            outparams=[],
        )
        text = method.str(0)
        assert "In Parameters" in text

    def test_method_str_with_out_params(self):
        param = self.factory.create_someip_parameter(
            position=0,
            name="OutputParam",
            desc="",
            mandatory=True,
            datatype=None,
            signal=None,
        )
        method = self.factory.create_someip_service_method(
            name="GetResult",
            methodid=0x0003,
            calltype="REQUEST",
            relia=True,
            inparams=[],
            outparams=[param],
        )
        text = method.str(0)
        assert "Out Parameters" in text

    def test_method_str_with_timings(self):
        method = self.factory.create_someip_service_method(
            name="TimedMethod",
            methodid=0x0004,
            calltype="REQUEST",
            relia=True,
            inparams=[],
            outparams=[],
            reqdebounce=0.100,
            reqmaxretention=0.05,
            resmaxretention=0.05,
        )
        text = method.str(0)
        assert "debounce" in text
        assert "max_request_retention" in text
        assert "max_response_retention" in text

    def test_method_str_with_tlv(self):
        method = self.factory.create_someip_service_method(
            name="TLVMethod",
            methodid=0x0005,
            calltype="REQUEST",
            relia=True,
            inparams=[],
            outparams=[],
            tlv=True,
        )
        text = method.str(0)
        assert "TLV" in text

    def test_event_str(self):
        event = self.factory.create_someip_service_event(
            name="StatusEvent",
            methodid=0x8001,
            relia=True,
            params=[],
        )
        text = event.str(0)
        assert "StatusEvent" in text
        assert "0x8001" in text

    def test_event_str_with_debounce(self):
        event = self.factory.create_someip_service_event(
            name="DebouncedEvent",
            methodid=0x8002,
            relia=False,
            params=[],
            debounce=0.050,
            maxretention=0.100,
        )
        text = event.str(0)
        assert "debounce" in text

    def test_event_str_with_tlv(self):
        event = self.factory.create_someip_service_event(
            name="TLVEvent",
            methodid=0x8003,
            relia=False,
            params=[],
            tlv=True,
        )
        text = event.str(0)
        assert "TLV" in text

    def test_event_str_legacy(self):
        """Event carrying a signal-bound parameter is shown as Legacy PDU."""
        signal = self.factory.create_signal("S1", "LegacySig", None, [], 8, 1, 8, "UINT8", 8)
        param = self.factory.create_someip_parameter(
            position=0,
            name="LegacyParam",
            desc="",
            mandatory=True,
            datatype=None,
            signal=signal,
        )
        event = self.factory.create_someip_service_event(
            name="LegacyEvent",
            methodid=0x8004,
            relia=True,
            params=[param],
        )
        text = event.str(0)
        assert "Legacy PDU" in text

    def test_eventgroup_str(self):
        eg = self.factory.create_someip_service_eventgroup(
            name="TestEventgroup",
            eid=0x1000,
            eventids=[0x8001],
            fieldids=[],
        )
        text = eg.str(0)
        assert "TestEventgroup" in text
        assert "0x1000" in text

    def test_eventgroup_str_with_events(self):
        eg = self.factory.create_someip_service_eventgroup(
            name="EG",
            eid=0x1001,
            eventids=[0x8001, 0x8002],
            fieldids=[],
        )
        text = eg.str(0)
        assert "Events:" in text

    def test_eventgroup_str_with_fields(self):
        eg = self.factory.create_someip_service_eventgroup(
            name="FieldEG",
            eid=0x1002,
            eventids=[],
            fieldids=[0x0001],
        )
        text = eg.str(0)
        assert "Notifiers:" in text

    def test_field_with_getter_only(self):
        field = self.factory.create_someip_service_field(
            name="GetterField",
            getterid=0x0001,
            setterid=None,
            notifierid=None,
            getterreli=True,
            setterreli=True,
            notifierreli=True,
            params=[],
            getter_debouncereq=0.100,
            getter_retentionreq=0.05,
            getter_retentionres=0.05,
            setter_debouncereq=-1,
            setter_retentionreq=-1,
            setter_retentionres=-1,
            notifier_debounce=-1,
            notifier_retention=-1,
        )
        text = field.str(0)
        assert "GetterField" in text
        assert "Getter" in text
        assert "debounce" in text
        assert "max_request_retention" in text
        assert "max_response_retention" in text

    def test_field_with_setter_only(self):
        field = self.factory.create_someip_service_field(
            name="SetterField",
            getterid=None,
            setterid=0x0002,
            notifierid=None,
            getterreli=True,
            setterreli=True,
            notifierreli=True,
            params=[],
            getter_debouncereq=-1,
            getter_retentionreq=-1,
            getter_retentionres=-1,
            setter_debouncereq=-1,
            setter_retentionreq=-1,
            setter_retentionres=-1,
            notifier_debounce=-1,
            notifier_retention=-1,
        )
        text = field.str(0)
        assert "Setter" in text

    def test_field_with_notifier_only(self):
        field = self.factory.create_someip_service_field(
            name="NotifyField",
            getterid=None,
            setterid=None,
            notifierid=0x8001,
            getterreli=True,
            setterreli=True,
            notifierreli=True,
            params=[],
            getter_debouncereq=-1,
            getter_retentionreq=-1,
            getter_retentionres=-1,
            setter_debouncereq=-1,
            setter_retentionreq=-1,
            setter_retentionres=-1,
            notifier_debounce=-1,
            notifier_retention=-1,
        )
        text = field.str(0)
        assert "Notifier" in text

    def test_field_with_all_three(self):
        field = self.factory.create_someip_service_field(
            name="FullField",
            getterid=0x0001,
            setterid=0x0002,
            notifierid=0x8001,
            getterreli=True,
            setterreli=True,
            notifierreli=True,
            params=[],
            getter_debouncereq=-1,
            getter_retentionreq=-1,
            getter_retentionres=-1,
            setter_debouncereq=-1,
            setter_retentionreq=-1,
            setter_retentionres=-1,
            notifier_debounce=-1,
            notifier_retention=-1,
        )
        text = field.str(0)
        assert "Getter" in text
        assert "Setter" in text
        assert "Notifier" in text

    def test_field_with_all_three_and_timings(self):
        field = self.factory.create_someip_service_field(
            name="FullField",
            getterid=0x0001,
            setterid=0x0002,
            notifierid=0x8001,
            getterreli=True,
            setterreli=True,
            notifierreli=True,
            params=[],
            getter_debouncereq=1,
            getter_retentionreq=2,
            getter_retentionres=3,
            setter_debouncereq=4,
            setter_retentionreq=5,
            setter_retentionres=6,
            notifier_debounce=7,
            notifier_retention=8,
        )
        text = field.str(0)
        assert "Getter" in text
        assert "Setter" in text
        assert "Notifier" in text
        assert "debounce:1s" in text
        assert "max_request_retention:2s" in text
        assert "max_response_retention:3s" in text
        assert "debounce:4s" in text
        assert "max_request_retention:5s" in text
        assert "max_response_retention:6s" in text
        assert "debounce:7s" in text
        assert "max_retention:8s" in text

    def test_field_with_tlv(self):
        field = self.factory.create_someip_service_field(
            name="TLVField",
            getterid=0x0001,
            setterid=None,
            notifierid=None,
            getterreli=True,
            setterreli=True,
            notifierreli=True,
            params=[],
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
        text = field.str(0)
        assert "TLV" in text

    def test_field_with_getter_debounce(self):
        field = self.factory.create_someip_service_field(
            name="DebounceField",
            getterid=0x0001,
            setterid=None,
            notifierid=None,
            getterreli=True,
            setterreli=True,
            notifierreli=True,
            params=[],
            getter_debouncereq=50,
            getter_retentionreq=-1,
            getter_retentionres=-1,
            setter_debouncereq=-1,
            setter_retentionreq=-1,
            setter_retentionres=-1,
            notifier_debounce=-1,
            notifier_retention=-1,
        )
        text = field.str(0)
        assert "debounce" in text


class TestSOMEIPServiceInstances:
    """Tests for SOME/IP service instance, client, eventgroup sender, and receiver."""

    def setup_method(self):
        self.factory = SimpleConfigurationFactory()

    def _make_instance(self, serviceid=0x1234, instanceid=0x0001):
        service = self.factory.create_someip_service(
            name="TestService",
            serviceid=serviceid,
            majorver=1,
            minorver=0,
            methods={},
            events={},
            fields={},
            eventgroups={},
        )
        return service, self.factory.create_someip_service_instance(
            service=service,
            instanceid=instanceid,
            protover=1,
        )

    def test_service_instance_str(self):
        service, instance = self._make_instance()
        text = instance.str(0)
        assert "0x1234" in text
        assert "0x0001" in text

    def test_service_instance_client_str(self):
        service, server = self._make_instance(serviceid=0x2000, instanceid=0x0001)
        client = self.factory.create_someip_service_instance_client(
            service=service,
            instanceid=0x0002,
            protover=1,
            server=server,
        )
        text = client.str(0)
        assert "ServiceInstanceClient" in text
        assert "0x2000" in text

    def test_eventgroup_sender_str(self):
        _, instance = self._make_instance(serviceid=0x3000)
        sender = self.factory.create_someip_service_eventgroup_sender(
            serviceinstance=instance,
            eventgroupid=0x1000,
        )
        text = sender.str(0)
        assert "EventgroupSender" in text
        assert "0x1000" in text

    def test_eventgroup_receiver_str(self):
        _, instance = self._make_instance(serviceid=0x4000)
        sender = self.factory.create_someip_service_eventgroup_sender(
            serviceinstance=instance,
            eventgroupid=0x1001,
        )
        receiver = self.factory.create_someip_service_eventgroup_receiver(
            serviceinstance=instance,
            eventgroupid=0x1001,
            sender=sender,
        )
        text = receiver.str(0)
        assert "EventgroupReceiver" in text
        assert "0x1001" in text


class TestSOMEIPParameters:
    """Tests for all SOME/IP parameter type string representations."""

    def setup_method(self):
        self.factory = SimpleConfigurationFactory()

    def _make_basetype(self, name="BT", datatype="UINT32", bigendian=True, bits=32):
        return self.factory.create_someip_parameter_basetype(name, datatype, bigendian, bits, bits)

    def test_parameter_str(self):
        param = self.factory.create_someip_parameter(
            position=0,
            name="TestParam",
            desc="test",
            mandatory=True,
            datatype=None,
            signal=None,
        )
        text = param.str(0)
        assert "TestParam" in text
        assert "mandatory: True" in text

    def test_parameter_str_with_datatype(self):
        bt = self._make_basetype()
        param = self.factory.create_someip_parameter(
            position=0,
            name="TypedParam",
            desc="",
            mandatory=False,
            datatype=bt,
            signal=None,
        )
        text = param.str(0)
        assert "TypedParam" in text
        assert "UINT32" in text

    def test_parameter_str_with_signal(self):
        """Parameter with a signal reference renders the signal."""
        signal = self.factory.create_signal("S1", "ParamSig", None, [], 8, 1, 8, "UINT8", 8)
        param = self.factory.create_someip_parameter(
            position=0,
            name="SigParam",
            desc="",
            mandatory=True,
            datatype=None,
            signal=signal,
        )
        text = param.str(0)
        assert "SigParam" in text
        assert "ParamSig" in text

    def test_basetype_str_big_endian(self):
        bt = self._make_basetype(datatype="UINT32", bigendian=True)
        text = bt.str(0)
        assert "UINT32" in text
        assert "BE" in text

    def test_basetype_str_little_endian(self):
        bt = self._make_basetype(datatype="UINT16", bigendian=False, bits=16)
        text = bt.str(0)
        assert "LE" in text

    def test_string_param_str(self):
        sp = self.factory.create_someip_parameter_string(
            name="MyStr",
            chartype="UTF-8",
            bigendian=True,
            lowerlimit=0,
            upperlimit=255,
            termination="ZERO",
            length_of_length=1,
            pad_to=4,
        )
        text = sp.str(0)
        assert "MyStr" in text
        assert "UTF-8" in text

    def test_string_param_str_little_endian(self):
        sp = self.factory.create_someip_parameter_string(
            name="LEStr",
            chartype="UTF-16",
            bigendian=False,
            lowerlimit=0,
            upperlimit=100,
            termination="ZERO",
            length_of_length=2,
            pad_to=2,
        )
        text = sp.str(0)
        assert "LE" in text

    def test_array_str(self):
        child = self._make_basetype(name="Child", datatype="UINT8", bits=8)
        array = self.factory.create_someip_parameter_array(name="TestArray", dims={}, child=child)
        text = array.str(0)
        assert "TestArray" in text
        assert "Array" in text

    def test_array_str_with_dim(self):
        dim = self.factory.create_someip_parameter_array_dim(
            dim=0,
            lowerlimit=0,
            upperlimit=9,
            length_of_length=1,
            pad_to=4,
        )
        child = self._make_basetype(name="Child", datatype="UINT8", bits=8)
        array = self.factory.create_someip_parameter_array(name="DimArray", dims={0: dim}, child=child)
        text = array.str(0)
        assert "Dimension" in text

    def test_array_str_no_child(self):
        array = self.factory.create_someip_parameter_array(name="EmptyArray", dims={}, child=None)
        text = array.str(0)
        assert "EmptyArray" in text

    def test_array_dim_str(self):
        dim = self.factory.create_someip_parameter_array_dim(
            dim=0,
            lowerlimit=0,
            upperlimit=9,
            length_of_length=1,
            pad_to=4,
        )
        text = dim.str(0)
        assert "Dimension" in text

    def test_struct_str(self):
        struct = self.factory.create_someip_parameter_struct(
            name="TestStruct",
            length_of_length=2,
            pad_to=4,
            members={},
        )
        text = struct.str(0)
        assert "TestStruct" in text
        assert "Struct" in text

    def test_struct_str_tlv(self):
        struct = self.factory.create_someip_parameter_struct(
            name="TLVStruct",
            length_of_length=2,
            pad_to=4,
            members={},
            tlv=True,
        )
        text = struct.str(0)
        assert "TLV" in text

    def test_struct_str_with_member(self):
        child = self._make_basetype(name="MemberBT")
        member = self.factory.create_someip_parameter_struct_member(
            position=0,
            name="M1",
            mandatory=True,
            child=child,
            signal=None,
        )
        struct = self.factory.create_someip_parameter_struct(
            name="StructWithMember",
            length_of_length=0,
            pad_to=0,
            members={0: member},
        )
        text = struct.str(0)
        assert "M1" in text

    def test_struct_member_str(self):
        child = self._make_basetype()
        member = self.factory.create_someip_parameter_struct_member(
            position=0,
            name="StructMember",
            mandatory=True,
            child=child,
            signal=None,
        )
        text = member.str(0)
        assert "StructMember" in text
        assert "mandatory: True" in text

    def test_typedef_str(self):
        child = self._make_basetype()
        typedef = self.factory.create_someip_parameter_typedef(name="MyTypedef", name2="UINT32", child=child)
        text = typedef.str(0)
        assert "MyTypedef" in text

    def test_enumeration_str(self):
        child = self._make_basetype(name="Child", datatype="UINT8", bits=8)
        item = self.factory.create_someip_parameter_enumeration_item(value=0, name="ZERO", desc="zero")
        enum = self.factory.create_someip_parameter_enumeration(name="TestEnum", items=[item], child=child)
        text = enum.str(0)
        assert "TestEnum" in text
        assert "Enumeration" in text

    def test_enumeration_item_str(self):
        item = self.factory.create_someip_parameter_enumeration_item(value=5, name="VALUE_FIVE", desc="five")
        text = item.str(0)
        assert "VALUE_FIVE" in text
        assert "5:" in text

    def test_union_str(self):
        union = self.factory.create_someip_parameter_union(
            name="TestUnion",
            length_of_length=1,
            length_of_type=1,
            pad_to=4,
            members={},
        )
        text = union.str(0)
        assert "TestUnion" in text
        assert "Union" in text

    def test_union_str_with_member(self):
        child = self._make_basetype()
        member = self.factory.create_someip_parameter_union_member(
            index=0,
            name="UnionMember",
            mandatory=True,
            child=child,
        )
        union = self.factory.create_someip_parameter_union(
            name="UnionWithMember",
            length_of_length=1,
            length_of_type=1,
            pad_to=4,
            members={0: member},
        )
        text = union.str(0)
        assert "UnionMember" in text

    def test_union_member_str(self):
        child = self._make_basetype()
        member = self.factory.create_someip_parameter_union_member(
            index=0,
            name="UnionMember",
            mandatory=True,
            child=child,
        )
        text = member.str(0)
        assert "UnionMember" in text

    def test_bitfield_str(self):
        child = self._make_basetype(name="Child", datatype="UINT8", bits=8)
        item = self.factory.create_someip_parameter_bitfield_item(bit_number=0, name="Bit0")
        bitfield = self.factory.create_someip_parameter_bitfield(
            name="TestBitfield",
            items=[item],
            child=child,
        )
        text = bitfield.str(0)
        assert "TestBitfield" in text
        assert "Bitfield" in text

    def test_bitfield_item_str(self):
        item = self.factory.create_someip_parameter_bitfield_item(bit_number=3, name="Bit3")
        text = item.str(0)
        assert "Bit 3" in text
        assert "Bit3" in text


class TestFactoryManagement:
    """Tests for SimpleConfigurationFactory service registry, IP config, and __str__."""

    def setup_method(self):
        self.factory = SimpleConfigurationFactory()

    def test_add_service_and_get_without_minorver(self):
        service = self.factory.create_someip_service(
            name="Svc",
            serviceid=0xAAAA,
            majorver=1,
            minorver=0,
            methods={},
            events={},
            fields={},
            eventgroups={},
        )
        assert self.factory.get_service(0xAAAA, 1) is service

    def test_add_service_and_get_with_minorver(self):
        service = self.factory.create_someip_service(
            name="Svc",
            serviceid=0xBBBB,
            majorver=2,
            minorver=5,
            methods={},
            events={},
            fields={},
            eventgroups={},
        )
        assert self.factory.get_service(0xBBBB, 2, 5) is service

    def test_get_service_not_found_returns_none(self):
        assert self.factory.get_service(0xDEAD, 1) is None
        assert self.factory.get_service(0xDEAD, 1, 0) is None

    def test_add_service_duplicate_same_version(self, capsys):
        """Duplicate service ID+major+minor: add_service returns False and prints ERROR."""
        self.factory.create_someip_service(
            name="Svc1",
            serviceid=0xCCCC,
            majorver=1,
            minorver=0,
            methods={},
            events={},
            fields={},
            eventgroups={},
        )
        result = self.factory.add_service(0xCCCC, 1, 0, object())
        captured = capsys.readouterr()
        assert result is False
        assert "ERROR" in captured.out

    def test_add_service_duplicate_major_different_minor(self, capsys):
        """Same service ID+major but different minor: add_service returns False and prints ERROR."""
        self.factory.create_someip_service(
            name="Svc1",
            serviceid=0xDDDD,
            majorver=1,
            minorver=0,
            methods={},
            events={},
            fields={},
            eventgroups={},
        )
        result = self.factory.add_service(0xDDDD, 1, 1, object())
        captured = capsys.readouterr()
        assert result is False
        assert "ERROR" in captured.out

    def test_ipv4_config(self):
        self.factory.add_ipv4_address_config("10.0.0.1", "255.255.255.0")
        assert self.factory.get_ipv4_netmask("10.0.0.1") == "255.255.255.0"

    def test_ipv4_config_unknown_returns_none(self):
        assert self.factory.get_ipv4_netmask("1.2.3.4") is None

    def test_ipv6_config(self):
        self.factory.add_ipv6_address_config("::1", 64)
        assert self.factory.get_ipv6_prefix_length("::1") == 64

    def test_ipv6_config_unknown_returns_none(self):
        assert self.factory.get_ipv6_prefix_length("::2") is None

    def test_ip_suffix_ipv4(self):
        self.factory.add_ipv4_address_config("192.168.1.1", "255.255.255.0")
        suffix = self.factory.get_ipv4_netmask_or_ipv6_prefix_length("192.168.1.1")
        assert suffix == "/255.255.255.0"

    def test_ip_suffix_ipv6(self):
        self.factory.add_ipv6_address_config("fe80::1", 64)
        suffix = self.factory.get_ipv4_netmask_or_ipv6_prefix_length("fe80::1")
        assert suffix == "/64"

    def test_ip_suffix_no_config(self):
        suffix = self.factory.get_ipv4_netmask_or_ipv6_prefix_length("10.0.0.99")
        assert suffix == ""

    def test_factory_str(self):
        """str(factory) contains all major section headers and registered objects."""
        self.factory.create_someip_service(
            name="SvcStr",
            serviceid=0xEEEE,
            majorver=1,
            minorver=0,
            methods={},
            events={},
            fields={},
            eventgroups={},
        )
        self.factory.create_frame(
            id="FStr",
            short_name="FrmStr",
            byte_length=8,
            frame_type="CAN",
            pdu_instances={},
        )
        self.factory.create_pdu(
            id="PStr",
            short_name="PduStr",
            byte_length=8,
            pdu_type="SIGNAL",
            signal_instances={},
        )
        self.factory.create_ecu("ECUStr", [])
        text = str(self.factory)
        assert "Services:" in text
        assert "Frames:" in text
        assert "PDUs:" in text
        assert "ECUs:" in text
        assert "SvcStr" in text
        assert "FrmStr" in text
