#!/usr/bin/python

"""Regression tests: IS-HIGH-LOW-BYTE-ORDER must be parsed into a real bool.

Previously the raw XML text ("false") was passed on unchanged, which is truthy,
so little-endian CAN/FlexRay signals were treated as big-endian.
"""

from pathlib import Path

from abstract_parser import AbstractParser
from configuration_base_classes import (
    BaseConfigurationFactory,
    BaseMultiplexPDUSegmentPosition,
    BaseMultiplexPDUSwitch,
    BaseSignalInstance,
)
from configuration_to_wireshark_config import WiresharkConfigurationFactory
from fibex_parser import FibexParser

EXAMPLES_DIR = Path(__file__).parent.parent / "examples"


class RecordingFactory(BaseConfigurationFactory):
    """Collects every object carrying a byte order flag."""

    def __init__(self) -> None:
        super().__init__()
        self.signal_instances: list[BaseSignalInstance] = []
        self.switches: list[BaseMultiplexPDUSwitch] = []
        self.segments: list[BaseMultiplexPDUSegmentPosition] = []

    def create_signal_instance(self, id: str, signal_ref: str, bit_position: int, is_high_low_byte_order: bool) -> BaseSignalInstance:
        ret = super().create_signal_instance(id, signal_ref, bit_position, is_high_low_byte_order)
        self.signal_instances.append(ret)
        return ret

    def create_multiplex_switch(
        self, id: str, short_name: str, bit_position: int, is_high_low_byte_order: bool, bit_length: int
    ) -> BaseMultiplexPDUSwitch:
        ret = super().create_multiplex_switch(id, short_name, bit_position, is_high_low_byte_order, bit_length)
        self.switches.append(ret)
        return ret

    def create_multiplex_segment_position(self, bit_pos: int, is_high_low: bool, bit_length: int) -> BaseMultiplexPDUSegmentPosition:
        ret = super().create_multiplex_segment_position(bit_pos, is_high_low, bit_length)
        self.segments.append(ret)
        return ret


def _parse(filename: str) -> RecordingFactory:
    factory = RecordingFactory()
    FibexParser(None, None).parse_file(factory, str(EXAMPLES_DIR / filename))
    return factory


class TestParseBool:
    def test_values(self) -> None:
        assert AbstractParser.parse_bool("true") is True
        assert AbstractParser.parse_bool(" TRUE ") is True
        assert AbstractParser.parse_bool("false") is False
        assert AbstractParser.parse_bool(None) is False
        assert AbstractParser.parse_bool(None, default=True) is True


class TestFibexByteOrder:
    def test_signal_instances_little_endian(self) -> None:
        factory = _parse("CAN_multi_pdu_example.xml")
        assert len(factory.signal_instances) > 0
        assert all(si.is_high_low_byte_order() is False for si in factory.signal_instances)

    def test_multiplex_little_endian(self) -> None:
        factory = _parse("CAN_Multiplex_example.xml")
        assert len(factory.switches) > 0
        assert len(factory.segments) > 0
        assert all(sw.is_high_low_byte_order() is False for sw in factory.switches)
        assert all(seg.is_high_low_byte_order() is False for seg in factory.segments)


class TestWiresharkEndian:
    def test_configline_endian_column(self) -> None:
        factory = WiresharkConfigurationFactory()
        for endian, expected in ((True, '"TRUE"'), (False, '"FALSE"')):
            _, line = factory.generate_signal_configline_parts(0x123, "PDU", 0, "sig", "uint", endian, 8, 8, 1.0, 0.0, "FALSE")
            assert line.split(",")[5] == expected
