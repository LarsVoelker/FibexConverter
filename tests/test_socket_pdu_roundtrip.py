#!/usr/bin/python

"""Round-trip test for native Ethernet PDUs attached to sockets (PDUs in/out).

FIBEX socket PDUs are attached to sockets by manufacturer extensions (plugins)
via ``create_ethernet_pdu_instance`` + ``BaseSocket.add_incoming_pdu`` /
``add_outgoing_pdu``.  ``configuration_to_flync`` must carry these deployments
through the FLYNC container-PDU carrier mechanism so that a
FIBEX -> FLYNC -> TEXT round-trip preserves each socket's PDUs together with
their per-context network header IDs.
"""

from pathlib import Path

from configuration_to_flync import SimpleConfigurationFactory as FlyncFactory
from configuration_to_text import SimpleConfigurationFactory as TextFactory
from flync_parser import FlyncParser


def _build_factory_with_socket_pdus() -> FlyncFactory:
    """Build a minimal Ethernet-only factory with socket PDUs in and out.

    Two distinct EthernetPDUInstances reference the same underlying PDU but
    carry different header IDs, mirroring the real-world case where the same
    PDU is deployed on different sockets (or directions) with different
    "context" header IDs.
    """
    factory = FlyncFactory()

    pdu = factory.create_pdu(
        id="P1",
        short_name="TestPDU",
        byte_length=8,
        pdu_type="SIGNAL",
        signal_instances={},
    )
    eth_pdu_in = factory.create_ethernet_pdu_instance("TestPDU", 0x0A01)
    eth_pdu_in.add_pdu(pdu)
    eth_pdu_out = factory.create_ethernet_pdu_instance("TestPDU", 0x0A02)
    eth_pdu_out.add_pdu(pdu)

    socket = factory.create_socket(
        name="SockA",
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

    interface = factory.create_interface(
        name="IfA",
        vlanid=1,
        ips=["192.168.1.1"],
        sockets=[socket],
        input_frame_trigs={},
        output_frame_trigs={},
        fr_channel=None,
    )
    controller = factory.create_controller("CtrlA", [interface])
    factory.create_ecu("EcuA", [controller])
    factory.parsing_done()
    return factory


def test_socket_pdu_roundtrip(tmp_path: Path) -> None:
    """Socket PDUs in/out with per-context header IDs survive the round-trip."""
    factory = _build_factory_with_socket_pdus()
    factory.create_flync_model()
    ws_dir = tmp_path / "flync"
    ws_dir.mkdir()
    factory.save_flync_model(str(ws_dir.resolve()))

    text_factory = TextFactory()
    FlyncParser().parse_dir(text_factory, str(ws_dir), verbose=False)
    text_factory.parsing_done()

    socket_texts = []
    for ecu in text_factory.__ecus__.values():
        socket_texts.append(ecu.str(1, text_factory))
    combined = "\n".join(socket_texts)

    # Both a receiver and a sender with distinct header IDs must round-trip.
    assert "PDUs in:" in combined
    assert "PDUs out:" in combined
    assert "0xa01: PDU TestPDU" in combined
    assert "0xa02: PDU TestPDU" in combined


def test_socket_pdu_carrier_names() -> None:
    """Carrier names uniquely encode (PDU name, header id) per context."""
    factory = FlyncFactory()
    assert factory._socket_carrier_name("TestPDU", 0x0A01) == "TestPDU__hdr0xa01"
    assert factory._socket_carrier_name("TestPDU", 0x0A02) == "TestPDU__hdr0xa02"
