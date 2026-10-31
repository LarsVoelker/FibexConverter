#!/usr/bin/python

# Automotive configuration file scripts
# Copyright (C) 2015-2026  Dr. Lars Voelker
# Copyright (C) 2018-2019  Dr. Lars Voelker, BMW AG
# Copyright (C) 2020-2026  Dr. Lars Voelker, Technica Engineering GmbH

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

from __future__ import annotations

import csv
import ipaddress
from collections.abc import Iterable
from typing import Literal, Protocol

import macaddress  # type: ignore[import-untyped]

CallSemantic = Literal["REQUEST_RESPONSE", "FIRE_AND_FORGET"]
# an IP or MAC address, either as text or as ipaddress object
Address = str | ipaddress.IPv4Address | ipaddress.IPv6Address
# (text value, lower limit, upper limit) as given in the configuration
CompuConst = tuple[str | None, str | None, str | None]


class SOMEIPBaseDatatype(Protocol):
    def size_min_bits(self) -> int: ...

    def size_max_bits(self) -> int: ...

    def legacy(self) -> bool: ...


def bits_to_bytes(bits: int) -> int:
    if bits % 8 == 0:
        return bits // 8
    else:
        return (bits // 8) + 1


def is_mcast(addr: Address | None) -> bool:
    if is_ip_mcast(addr):
        return True

    if is_mac_mcast(addr):
        return True

    return False


def addr_to_key(addr: Address | None) -> str:
    if addr is None:
        return "None"

    if is_ip(addr):
        return ip_to_key(addr)

    if is_mac(addr):
        return mac_to_key(addr)

    print(f"Warning: addr_to_key was called with {addr} and this seems to be no IP or MAC Address!")
    return "None"


def is_mac(mac: Address | None) -> bool:
    if mac is None:
        return False

    try:
        macaddress.EUI48(mac)
    except ValueError:
        return False

    return True


def is_mac_mcast(mac: Address | None) -> bool:
    if mac is None:
        return False

    try:
        tmp = macaddress.EUI48(mac)
    except (ValueError, TypeError):
        return False

    return bool(int(tmp.__bytes__()[0]) & 0x01)


def mac_to_key(mac: Address | None) -> str:
    if mac is None:
        return "None"

    try:
        tmp = macaddress.EUI48(mac)
    except ValueError:
        return "None"

    return f"mac-{str(tmp)}"


def is_ip(ip: Address | None) -> bool:
    if ip is None:
        return False

    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return False

    return True


def is_ip_mcast(ip: Address | None) -> bool:
    if ip is None:
        return False

    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False

    return addr.is_multicast


def ip_to_key(ip: Address | None) -> str:
    if ip is None:
        return "None"

    try:
        tmp = ipaddress.ip_address(ip)
    except ValueError:
        return "None"

    key = f"ipvx-{ip}"

    if tmp.version == 4:
        key = f"ipv4-{tmp.packed[0]:03}.{tmp.packed[1]:03}.{tmp.packed[2]:03}.{tmp.packed[3]:03}"
    elif tmp.version == 6:
        key = f"ipv6-{tmp.exploded}"
    return key


def mcast_addr_to_mac_mcast(addr: str | None) -> str:
    if is_mac_mcast(addr):
        return str(macaddress.EUI48(addr))

    if is_ip_mcast(addr):
        ret = ""
        assert addr is not None
        tmp = ipaddress.ip_address(addr)
        if tmp.version == 4:
            ret = f"01-00-5e-{(tmp.packed[1] & 127):02x}-{tmp.packed[2]:02x}-{tmp.packed[3]:02x}"
        elif tmp.version == 6:
            ret = f"33-33-{(tmp.packed[12]):02x}-{(tmp.packed[13]):02x}-{(tmp.packed[14]):02x}-{(tmp.packed[15]):02x}"
        else:
            print("ERROR: IP Address has to be IPv4 or IPv6 to convert it to Ethernet Multicast!")

        return ret.upper()

    return ""


def read_csv_to_dict(f: Iterable[str], verbose: bool = False) -> dict[str, str]:
    ret: dict[str, str] = {}

    csvreader = csv.reader(f, delimiter=",", quotechar='"')
    skip_first_line = True
    for row in csvreader:
        if skip_first_line:
            skip_first_line = False
            continue

        # skip empty lines
        if len(row) == 0 or row[0] == "" or row[0] == "":
            continue

        if verbose:
            print("  " + ", ".join(row))

        if len(row) != 2:
            print(f"Error: Line in file too short/long: {', '.join(row)} ({len(row)})")
            continue

        key, value = row[:2]

        if key in ret.keys():
            print(f"Error: key {key} is present multiple times!")
            continue

        ret[key] = value

    print()

    return ret


class BaseConfigurationFactory(object):
    def create_vlan(self, name: str, vlanid: int | None, prio: int | None) -> BaseVLAN:
        return BaseVLAN(name, vlanid, prio)

    def create_multicast_path(
        self,
        switchport_tx: BaseSwitchPort | None,
        vlan_tx: int,
        src_addr: str,
        switchport_rx: BaseSwitchPort | None,
        vlan_rx: int,
        mcast_addr: str,
        comment: str,
    ) -> BaseMulticastPath:
        return BaseMulticastPath(
            switchport_tx,
            vlan_tx,
            src_addr,
            switchport_rx,
            vlan_rx,
            mcast_addr,
            comment,
        )

    def create_switch(self, name: str, ecu: BaseECU | None, ports: list[BaseSwitchPort]) -> BaseSwitch:
        return BaseSwitch(name, ecu, ports)

    def create_switch_port(
        self,
        portid: str,
        ctrl: BaseController | None,
        port: BaseSwitchPort | None,
        default_vlan: int | None,
        vlans: list[BaseVLAN],
    ) -> BaseSwitchPort:
        return BaseSwitchPort(portid, ctrl, port, default_vlan, vlans)

    def create_ethernet_bus(self, name: str, connected_ctrls: list[BaseController], switch_ports: list[BaseSwitchPort]) -> BaseEthernetBus:
        return BaseEthernetBus(name, connected_ctrls, switch_ports)

    def create_ecu(self, name: str, controllers: list[BaseController]) -> BaseECU:
        return BaseECU(name, controllers)

    def create_controller(self, name: str, interfaces: list[BaseInterface]) -> BaseController:
        return BaseController(name, interfaces)

    def create_interface(
        self,
        name: str,
        vlanid: int | None,
        ips: list[str],
        sockets: list[BaseSocket],
        input_frame_trigs: dict[str, BaseFrameTriggering],
        output_frame_trigs: dict[str, BaseFrameTriggering],
        fr_channel: int | None,
    ) -> BaseInterface:
        return BaseInterface(
            name,
            vlanid,
            ips,
            sockets,
            input_frame_trigs,
            output_frame_trigs,
            fr_channel,
        )

    def create_socket(
        self,
        name: str,
        ip: str,
        proto: int | str,
        portnumber: int | str,
        serviceinstances: list[SOMEIPBaseServiceInstance] | None,
        serviceinstanceclients: list[SOMEIPBaseServiceInstanceClient] | None,
        eventhandlers: list[SOMEIPBaseServiceEventgroupSender] | None,
        eventgroupreceivers: list[SOMEIPBaseServiceEventgroupReceiver] | None,
    ) -> BaseSocket:
        return BaseSocket(
            name,
            ip,
            proto,
            portnumber,
            serviceinstances,
            serviceinstanceclients,
            eventhandlers,
            eventgroupreceivers,
        )

    def create_someip_service_instance(self, service: SOMEIPBaseService, instanceid: int, protover: int) -> SOMEIPBaseServiceInstance:
        return SOMEIPBaseServiceInstance(service, instanceid, protover)

    def create_someip_service_instance_client(
        self, service: SOMEIPBaseService, instanceid: int, protover: int, server: SOMEIPBaseServiceInstance | None
    ) -> SOMEIPBaseServiceInstanceClient:
        return SOMEIPBaseServiceInstanceClient(service, instanceid, protover, server)

    def create_someip_service_eventgroup_sender(
        self, serviceinstance: SOMEIPBaseServiceInstance, eventgroupid: int
    ) -> SOMEIPBaseServiceEventgroupSender:
        return SOMEIPBaseServiceEventgroupSender(serviceinstance, eventgroupid)

    def create_someip_service_eventgroup_receiver(
        self,
        serviceinstance: SOMEIPBaseServiceInstance,
        eventgroupid: int,
        sender: SOMEIPBaseServiceEventgroupSender | None,
    ) -> SOMEIPBaseServiceEventgroupReceiver:
        return SOMEIPBaseServiceEventgroupReceiver(serviceinstance, eventgroupid, sender)

    def create_someip_service(
        self,
        name: str,
        serviceid: int,
        majorver: int,
        minorver: int,
        methods: dict[int, SOMEIPBaseServiceMethod],
        events: dict[int, SOMEIPBaseServiceEvent],
        fields: dict[int, SOMEIPBaseServiceField],
        eventgroups: dict[int, SOMEIPBaseServiceEventgroup],
    ) -> SOMEIPBaseService:
        return SOMEIPBaseService(name, serviceid, majorver, minorver, methods, events, fields, eventgroups)

    def create_someip_service_method(
        self,
        name: str,
        methodid: int,
        calltype: CallSemantic,
        relia: bool,
        inparams: list[SOMEIPBaseParameter],
        outparams: list[SOMEIPBaseParameter],
        reqdebounce: int = -1,
        reqmaxretention: int = -1,
        resmaxretention: int = -1,
        tlv: bool = False,
    ) -> SOMEIPBaseServiceMethod:
        return SOMEIPBaseServiceMethod(
            name,
            methodid,
            calltype,
            relia,
            inparams,
            outparams,
            reqdebounce,
            reqmaxretention,
            resmaxretention,
            tlv,
        )

    def create_someip_service_event(
        self,
        name: str,
        methodid: int,
        relia: bool,
        params: list[SOMEIPBaseParameter],
        debounce: int = -1,
        maxretention: int = -1,
        tlv: bool = False,
    ) -> SOMEIPBaseServiceEvent:
        return SOMEIPBaseServiceEvent(name, methodid, relia, params, debounce, maxretention, tlv)

    def create_someip_service_field(
        self,
        name: str,
        getterid: int | None,
        setterid: int | None,
        notifierid: int | None,
        getterreli: bool,
        setterreli: bool,
        notifierreli: bool,
        params: list[SOMEIPBaseParameter],
        getter_debouncereq: int,
        getter_retentionreq: int,
        getter_retentionres: int,
        setter_debouncereq: int,
        setter_retentionreq: int,
        setter_retentionres: int,
        notifier_debounce: int,
        notifier_retention: int,
        tlv: bool = False,
    ) -> SOMEIPBaseServiceField:
        ret = SOMEIPBaseServiceField(
            self,
            name,
            getterid,
            setterid,
            notifierid,
            getterreli,
            setterreli,
            notifierreli,
            params,
            getter_debouncereq,
            getter_retentionreq,
            getter_retentionres,
            setter_debouncereq,
            setter_retentionreq,
            setter_retentionres,
            notifier_debounce,
            notifier_retention,
            tlv,
        )
        return ret

    def create_someip_service_eventgroup(self, name: str, eid: int, eventids: list[int], fieldids: list[int]) -> SOMEIPBaseServiceEventgroup:
        return SOMEIPBaseServiceEventgroup(name, eid, eventids, fieldids)

    def create_someip_parameter(
        self,
        position: int,
        name: str,
        desc: str | None,
        mandatory: bool,
        datatype: SOMEIPBaseDatatype | None,
        signal: BaseSignal | None,
    ) -> SOMEIPBaseParameter:
        return SOMEIPBaseParameter(position, name, desc, mandatory, datatype, signal)

    def create_someip_parameter_basetype(
        self, name: str, datatype: str, bigendian: bool, bitlength_basetype: int, bitlength_encoded_type: int
    ) -> SOMEIPBaseParameterBasetype:
        return SOMEIPBaseParameterBasetype(name, datatype, bigendian, bitlength_basetype, bitlength_encoded_type)

    def create_someip_parameter_string(
        self,
        name: str,
        chartype: str,
        bigendian: bool,
        lowerlimit: int,
        upperlimit: int,
        termination: str | None,
        length_of_length: int | None,
        pad_to: int,
    ) -> SOMEIPBaseParameterString:
        return SOMEIPBaseParameterString(
            name,
            chartype,
            bigendian,
            lowerlimit,
            upperlimit,
            termination,
            length_of_length,
            pad_to,
        )

    def create_someip_parameter_array(
        self, name: str, dims: dict[int, SOMEIPBaseParameterArrayDim], child: SOMEIPBaseDatatype
    ) -> SOMEIPBaseParameterArray:
        return SOMEIPBaseParameterArray(name, dims, child)

    def create_someip_parameter_array_dim(
        self, dim: int, lowerlimit: int, upperlimit: int, length_of_length: int | None, pad_to: int
    ) -> SOMEIPBaseParameterArrayDim:
        return SOMEIPBaseParameterArrayDim(dim, lowerlimit, upperlimit, length_of_length, pad_to)

    def create_someip_parameter_struct(
        self, name: str, length_of_length: int | None, pad_to: int, members: dict[int, SOMEIPBaseParameterStructMember], tlv: bool = False
    ) -> SOMEIPBaseParameterStruct:
        return SOMEIPBaseParameterStruct(name, length_of_length, pad_to, members, tlv)

    def create_someip_parameter_struct_member(
        self, position: int, name: str, mandatory: bool, child: SOMEIPBaseDatatype, signal: BaseSignal | None
    ) -> SOMEIPBaseParameterStructMember:
        return SOMEIPBaseParameterStructMember(position, name, mandatory, child, signal)

    def create_someip_parameter_typedef(self, name: str, name2: str, child: SOMEIPBaseDatatype) -> SOMEIPBaseParameterTypedef:
        return SOMEIPBaseParameterTypedef(name, name2, child)

    def create_someip_parameter_enumeration(
        self, name: str, items: list[SOMEIPBaseParameterEnumerationItem], child: SOMEIPBaseDatatype
    ) -> SOMEIPBaseParameterEnumeration:
        return SOMEIPBaseParameterEnumeration(name, items, child)

    def create_someip_parameter_enumeration_item(self, value: int, name: str, desc: str | None) -> SOMEIPBaseParameterEnumerationItem:
        return SOMEIPBaseParameterEnumerationItem(value, name, desc)

    def create_someip_parameter_union(
        self,
        name: str,
        length_of_length: int | None,
        length_of_type: int | None,
        pad_to: int,
        members: dict[int, SOMEIPBaseParameterUnionMember],
    ) -> SOMEIPBaseParameterUnion:
        return SOMEIPBaseParameterUnion(name, length_of_length, length_of_type, pad_to, members)

    def create_someip_parameter_union_member(
        self, index: int, name: str, mandatory: bool, child: SOMEIPBaseDatatype
    ) -> SOMEIPBaseParameterUnionMember:
        return SOMEIPBaseParameterUnionMember(index, name, mandatory, child)

    def create_someip_parameter_bitfield(
        self, name: str, items: list[SOMEIPBaseParameterBitfieldItem], child: SOMEIPBaseDatatype
    ) -> SOMEIPBaseParameterBitfield:
        return SOMEIPBaseParameterBitfield(name, items, child)

    def create_someip_parameter_bitfield_item(self, bit_number: int, name: str) -> SOMEIPBaseParameterBitfieldItem:
        return SOMEIPBaseParameterBitfieldItem(bit_number, name)

    def create_signal(
        self,
        id: str,
        name: str,
        compu_scale: tuple[float, float, float] | None,
        compu_consts: list[CompuConst] | None,
        bit_len: int,
        min_len: int,
        max_len: int,
        basetype: str,
        basetypelen: int,
    ) -> BaseSignal:
        return BaseSignal(
            id,
            name,
            compu_scale,
            compu_consts,
            bit_len,
            min_len,
            max_len,
            basetype,
            basetypelen,
        )

    def create_signal_instance(self, id: str, signal_ref: str, bit_position: int, is_high_low_byte_order: bool) -> BaseSignalInstance:
        return BaseSignalInstance(id, signal_ref, bit_position, is_high_low_byte_order)

    def create_pdu(self, id: str, short_name: str, byte_length: int, pdu_type: str, signal_instances: dict[int, BaseSignalInstance]) -> BasePDU:
        return BasePDU(id, short_name, byte_length, pdu_type, signal_instances)

    def create_multiplex_pdu(
        self,
        id: str,
        short_name: str,
        byte_length: int,
        pdu_type: str,
        switch: BaseMultiplexPDUSwitch | None,
        seg_pos: list[BaseMultiplexPDUSegmentPosition],
        pdu_instances: dict[int, BaseAbstractPDU | None] | None,
        static_seg_pdu_combinations: list[tuple[list[BaseMultiplexPDUSegmentPosition], BasePDU]],
    ) -> BaseMultiplexPDU:
        return BaseMultiplexPDU(
            id,
            short_name,
            byte_length,
            pdu_type,
            switch,
            seg_pos,
            pdu_instances,
            static_seg_pdu_combinations,
        )

    def create_multiplex_switch(
        self, id: str, short_name: str, bit_position: int, is_high_low_byte_order: bool, bit_length: int
    ) -> BaseMultiplexPDUSwitch:
        return BaseMultiplexPDUSwitch(id, short_name, bit_position, is_high_low_byte_order, bit_length)

    def create_multiplex_segment_position(self, bit_pos: int, is_high_low: bool, bit_length: int) -> BaseMultiplexPDUSegmentPosition:
        return BaseMultiplexPDUSegmentPosition(bit_pos, is_high_low, bit_length)

    def create_ethernet_pdu_instance(self, pdu_ref: str, header_id: int | None) -> BaseEthernetPDUInstance:
        return BaseEthernetPDUInstance(pdu_ref, header_id)

    def create_pdu_instance(
        self, id: str, pdu_ref: str, bit_position: int, is_high_low_byte_order: bool, pdu_update_bit_position: int | None
    ) -> BasePDUInstance:
        return BasePDUInstance(id, pdu_ref, bit_position, is_high_low_byte_order, pdu_update_bit_position)

    def create_frame(self, id: str, short_name: str, byte_length: int, frame_type: str, pdu_instances: dict[str, BasePDUInstance]) -> BaseFrame:
        return BaseFrame(id, short_name, byte_length, frame_type, pdu_instances)

    def create_frame_triggering_can(self, id: str, frame: BaseFrame, can_id: int, is_extended_id: bool, is_can_fd: bool) -> BaseFrameTriggeringCAN:
        return BaseFrameTriggeringCAN(id, frame, can_id, is_extended_id, is_can_fd)

    def create_frame_triggering_flexray(
        self, id: str, frame: BaseFrame, slot_id: int, cycle_counter: int | None, base_cycle: int | None, cycle_repetition: int | None
    ) -> BaseFrameTriggeringFlexRay:
        return BaseFrameTriggeringFlexRay(id, frame, slot_id, cycle_counter, base_cycle, cycle_repetition)

    def add_cluster_info(self, cluster_id: str, name: str, speed: int, protocol: str, channel_refs: list[str]) -> None:
        pass

    def create_pdu_route(self, sender_socket: BaseSocket, receiving_socket: BaseSocket, pdu_name: str, pdu_id: int) -> bool:
        if sender_socket.is_multicast():
            print(
                f"ERROR: Multicast Sockets cannot be used for sending!"
                f" {sender_socket.ip()} -> {receiving_socket.ip()}: {pdu_name} 0x{pdu_id:08x}"
            )
            return False
        return True

    @staticmethod
    def socket_to_sw_port(socket: BaseSocket) -> BaseSwitchPort | None:
        # regular switch ethernet
        interface = socket.interface()
        if interface is None:
            print(f"WARNING: Socket {socket.name()} has no interface!")
            return None
        controller = interface.controller()
        if controller is None:
            print(f"WARNING: Interface {interface.vlanname()} has no controller!")
            return None

        ret = controller.get_switch_port()
        if ret is not None:
            return ret

        # ethernet bus
        eth_bus = controller.get_eth_bus()

        if eth_bus is None:
            print(f"WARNING: cannot find sw_port and not eth bus either for eth bus! " f"Ctrl: {controller.name()}")
            return None

        sw_ports = eth_bus.switch_ports()

        if len(sw_ports) == 0:
            print(f"WARNING: cannot find uplink port to eth bus! " f"Ctrl: {controller.name()}")
            return None

        if len(sw_ports) > 1:
            print("ERROR: Eth Bus with more than 1 uplink to switch is unsupported!")

        return sw_ports[0]

    def add_ipv4_address_config(self, ip: str, netmask: str) -> None:
        pass

    def get_ipv4_netmask(self, ip: str) -> str:
        return ""

    def add_ipv6_address_config(self, ip: str, prefixlen: str) -> None:
        pass

    def get_ipv6_prefix_length(self, ip: str) -> str:
        return ""

    def parsing_done(self) -> None:
        pass


class BaseItem(object):
    def legacy(self) -> bool:
        return False


class BaseCoding(BaseItem):
    def __init__(
        self,
        id: str,
        name: str,
        coded_basetype: str,
        coded_category: str,
        coded_termination: str,
        coded_bit_length: int | None,
        coded_max_length: int | None,
        compu_scale: tuple[object, ...] | None,
        compu_consts: list[CompuConst] | None,
    ):
        self._id = id
        self._name = name
        self._coded_basetype = coded_basetype
        self._coded_category = coded_category
        self._coded_termination = coded_termination
        self._coded_bit_length = coded_bit_length
        self._coded_max_length = coded_max_length
        self._compu_scale = compu_scale
        self._compu_consts = compu_consts

    def name(self) -> str:
        return self._name


class BaseVLAN(BaseItem):
    def __init__(self, vlan_name: str, vlan_id: int | None, priority: int | None):
        self._vlan_name = vlan_name
        self._vlan_id = vlan_id
        self._priority = priority

    def name(self) -> str:
        return self._vlan_name

    def vlanid(self) -> int | None:
        return self._vlan_id

    def vlanid_str(self) -> str:
        vlanid = self.vlanid()
        if vlanid is None:
            return "untagged"
        return f"0x{vlanid:x}"

    def priority(self) -> int | None:
        return self._priority


class BaseMulticastPath(BaseItem):
    def __init__(
        self,
        switchport_tx: BaseSwitchPort | None,
        vlanid_tx: int,
        source_addr: str,
        switchport_rx: BaseSwitchPort | None,
        vlanid_rx: int,
        multicast_addr: str,
        comment: str,
    ):
        if vlanid_tx != vlanid_rx:
            print(f"Currently only Multicast Path with same VLAN supported Addr:{multicast_addr} vlan_tx:{vlanid_tx} " f"vlan_rx:{vlanid_rx}!")
            raise ValueError

        self._vlanid = vlanid_tx
        self._tx_addr = source_addr
        self._mc_addr = multicast_addr
        self._swport_tx = switchport_tx
        self._swport_rx = switchport_rx
        self._comment = comment

    def vlanid(self) -> int:
        return self._vlanid

    def source_addr(self) -> str:
        return self._tx_addr

    def mc_addr(self) -> str:
        return self._mc_addr

    def switchport_tx(self) -> BaseSwitchPort | None:
        return self._swport_tx

    def switchport_tx_name(self) -> str | None:
        if self._swport_tx is None:
            return None
        else:
            return self._swport_tx.portid()

    def switchport_rx(self) -> BaseSwitchPort | None:
        return self._swport_rx

    def switchport_rx_name(self) -> str | None:
        if self._swport_rx is None:
            return None
        else:
            return self._swport_rx.portid()

    def comment(self) -> str:
        return self._comment

    def _append_to_comment(self, txt: str) -> None:
        self._comment += txt


class BaseSwitchPort(BaseItem):
    # TODO: we need to add ethernet_bus to init!?
    def __init__(
        self,
        portid: str,
        ctrl: BaseController | None,
        port: BaseSwitchPort | None,
        default_vlan: int | None,
        vlans: list[BaseVLAN],
    ):
        assert ctrl is None or port is None

        self._portid: str = portid
        self._ctrl: BaseController | None = None
        self._port: BaseSwitchPort | None = port
        self._eth_bus: BaseEthernetBus | None = None
        self._default_vlan: int | None = default_vlan
        self._vlans: list[BaseVLAN] = vlans
        self._switch: BaseSwitch | None = None

        if ctrl is not None:
            self.set_connected_ctrl(ctrl)

    def __repr__(self) -> str:
        switch_name = "<unknown>"
        if self._switch is not None:
            switch_name = self._switch.name()

        return f"{switch_name}.{self._portid}"

    def portid_full(self, gen_name: bool = False) -> str:
        portid = self.portid(gen_name=gen_name)
        sw = self.switch()
        if sw is not None:
            ecu = sw.ecu()
            if ecu is not None:
                return f"{ecu.name()}.{sw.name()}.{portid}"
            return f".{sw.name()}.{portid}"
        else:
            return f"..{portid}"

    def portid(self, gen_name: bool = False) -> str:
        if gen_name:
            return self.portid_generated()

        return self._portid

    def portid_generated(self) -> str:
        if self._port is not None:
            sw = self._port.switch()
            if sw is not None:
                return f"couplingPort_ConnectTo_{sw.name()}"
        if self._ctrl is not None:
            return f"couplingPort_ConnectTo_{self._ctrl.name()}"
        if self._eth_bus is not None:
            return f"couplingPort_ConnectTo_{self._eth_bus.name()}"

        return self._portid

    def set_parent_switch(self, switch: BaseSwitch) -> None:
        self._switch = switch

    def switch(self) -> BaseSwitch | None:
        return self._switch

    def set_connected_port(self, peer_port: BaseSwitchPort) -> None:
        assert peer_port is not None
        assert self._port is None

        if self._ctrl is not None or self._eth_bus is not None:
            print(f"WARNING: SwitchPort {self._portid} adds port but was connected before! Overwritting!")

        self._port = peer_port

    def connected_to_port(self) -> BaseSwitchPort | None:
        return self._port

    def set_ethernet_bus(self, eth_bus: BaseEthernetBus) -> None:
        assert eth_bus is not None
        assert self._eth_bus is None

        if self._ctrl is not None or self._eth_bus is not None:
            print(f"WARNING: SwitchPort {self._portid} adds eth bus but was connected before! Overwritting!")

        self._eth_bus = eth_bus

    def connected_to_eth_bus(self) -> BaseEthernetBus | None:
        return self._eth_bus

    def set_connected_ctrl(self, peer_ctrl: BaseController) -> None:
        assert peer_ctrl is not None
        assert self._ctrl is None

        if self._port is not None or self._eth_bus is not None:
            print(f"WARNING: SwitchPort {self._portid} adds ctrl to port but was connected before! Overwritting!")

        self._ctrl = peer_ctrl
        peer_ctrl.set_switch_port(self)

    def connected_to_ecu_ctrl(self) -> BaseController | None:
        return self._ctrl

    def vlans(self) -> list[int]:
        vlans = []

        for vlan in self._vlans:
            vlanid = vlan.vlanid()
            if vlanid is None:
                vlans += [0]
            else:
                vlans += [vlanid]

        return sorted(vlans)

    def vlans_objs(self) -> list[BaseVLAN]:
        vlans = []

        for vlan in self._vlans:
            vlans.append(vlan)

        def key(x: BaseVLAN) -> int:
            vid = x.vlanid()
            return -1 if vid is None else vid

        return sorted(vlans, key=key)


class BaseSwitch(BaseItem):
    def __init__(self, name: str, ecu: BaseECU | None, ports: list[BaseSwitchPort]):
        self._name: str = name
        self._ports: list[BaseSwitchPort] = ports
        self._ecu: BaseECU | None = ecu

        if ecu is not None:
            ecu.add_switch(self)

        for port in ports:
            port.set_parent_switch(self)

    def name(self) -> str:
        return self._name

    def ecu(self) -> BaseECU | None:
        return self._ecu

    def ports(self) -> list[BaseSwitchPort]:
        return self._ports

    def key(self) -> str:
        ecu = self.ecu()
        if ecu is None:
            return f"None.{self.name()}"

        return f"{ecu.name()}.{self.name()}"


class BaseEthernetBus(BaseItem):
    def __init__(self, name: str, connected_ctrls: list[BaseController], switch_ports: list[BaseSwitchPort]):
        self._name: str = name
        self._ctrls: list[BaseController] = connected_ctrls
        self._ports: list[BaseSwitchPort] = switch_ports

        # connect the controllers to us!
        for ctrl in connected_ctrls:
            ctrl.set_eth_bus(self)

    def name(self) -> str:
        return self._name

    def connected_controllers(self) -> list[BaseController]:
        return self._ctrls

    def switch_ports(self) -> list[BaseSwitchPort]:
        return self._ports


class BaseECU(BaseItem):
    def __init__(self, name: str, controllers: list[BaseController]):
        self._name: str = name
        self._controllers: list[BaseController] = controllers
        self._switches: list[BaseSwitch] = []

        for c in controllers:
            c.set_ecu(self)

    def name(self) -> str:
        return self._name

    def controllers(self) -> list[BaseController]:
        return self._controllers

    def add_switch(self, switch: BaseSwitch) -> None:
        self._switches.append(switch)

    def switches(self) -> list[BaseSwitch]:
        return self._switches


class BaseController(BaseItem):
    def __init__(self, name: str, interfaces: list[BaseInterface]):
        self._name: str = name
        self._interfaces: list[BaseInterface] = interfaces
        self._ecu: BaseECU | None = None
        self._peer_port: BaseSwitchPort | None = None
        self._eth_bus: BaseEthernetBus | None = None

        for i in interfaces:
            i.set_controller(self)

    def name(self) -> str:
        return self._name

    def interfaces(self) -> list[BaseInterface]:
        return self._interfaces

    def vlans(self) -> list[int]:
        vlans = []

        for interface in self._interfaces:
            if interface.vlanid() is None:
                vlans += [0]
            else:
                vlans += [int(interface.vlanid())]

        return sorted(vlans)

    def set_ecu(self, ecu: BaseECU) -> None:
        self._ecu = ecu

    def ecu(self) -> BaseECU | None:
        return self._ecu

    def set_switch_port(self, peer_port: BaseSwitchPort) -> None:
        assert self._peer_port is None
        assert self._eth_bus is None
        self._peer_port = peer_port

    def get_switch_port(self) -> BaseSwitchPort | None:
        return self._peer_port

    def set_eth_bus(self, eth_buf: BaseEthernetBus) -> None:
        assert self._peer_port is None
        assert self._eth_bus is None
        self._eth_bus = eth_buf

    def get_eth_bus(self) -> BaseEthernetBus | None:
        return self._eth_bus


class BaseInterface(BaseItem):
    def __init__(
        self,
        vlanname: str,
        vlanid: int | None,
        ips: list[str],
        sockets: list[BaseSocket],
        frame_triggerings_in: dict[str, BaseFrameTriggering],
        frame_triggerings_out: dict[str, BaseFrameTriggering],
        fr_channel: int | None,
    ):
        self._vlanname: str = vlanname
        self._sockets: list[BaseSocket] = sockets
        self._ips: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []

        for ip in ips:
            try:
                self._ips.append(ipaddress.ip_address(ip))
            except ValueError:
                print(f"ERROR: parser return illegal IP Address {ip}! We will need to skip that.")

        self._controller: BaseController | None = None

        if vlanid is None:
            self._vlanid: int = 0
        else:
            self._vlanid = int(vlanid)

        for s in sockets:
            s.set_interface(self)

        self._frame_triggerings_in: dict[str, BaseFrameTriggering] = frame_triggerings_in
        self._frame_triggerings_out: dict[str, BaseFrameTriggering] = frame_triggerings_out

        self._flexray_channel: int | None = fr_channel

    def vlanname(self) -> str:
        return self._vlanname

    def vlanid(self) -> int:
        return self._vlanid

    def ips(self) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
        return self._ips

    def ips_without_socket(self) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
        tmp = []
        for socket in self._sockets:
            tmp.append(socket.ip())

        ret = []
        for ip in self._ips:
            if ip not in tmp:
                ret.append(ip)

        return ret

    def sockets(self) -> list[BaseSocket]:
        return self._sockets

    def set_controller(self, controller: BaseController) -> None:
        self._controller = controller

    def controller(self) -> BaseController | None:
        return self._controller

    def frame_triggerings_in(self) -> dict[str, BaseFrameTriggering]:
        return self._frame_triggerings_in

    def frame_triggerings_out(self) -> dict[str, BaseFrameTriggering]:
        return self._frame_triggerings_out

    def flexray_channel(self) -> int | None:
        return self._flexray_channel

    def is_can(self) -> bool:
        for trig in self._frame_triggerings_in.values():
            if trig.is_can():
                return True

        for trig in self._frame_triggerings_out.values():
            if trig.is_can():
                return True

        return False

    def is_flexray(self) -> bool:
        for trig in self._frame_triggerings_in.values():
            if trig.is_flexray():
                return True

        for trig in self._frame_triggerings_out.values():
            if trig.is_flexray():
                return True

        return False

    def is_ethernet(self) -> bool:
        for trig in self._frame_triggerings_in.values():
            if trig.is_ethernet():
                return True

        for trig in self._frame_triggerings_out.values():
            if trig.is_ethernet():
                return True

        return False

    def is_more_than_one_type(self) -> bool:
        ret = 0

        if self.is_can():
            ret += 1
        if self.is_flexray():
            ret += 1
        if self.is_ethernet():
            ret += 1

        return ret > 1


class BaseSocket(BaseItem):
    def __init__(
        self,
        name: str,
        ip: str,
        proto: int | str,
        portnumber: int | str,
        serviceinstances: list[SOMEIPBaseServiceInstance] | None,
        serviceinstanceclients: list[SOMEIPBaseServiceInstanceClient] | None,
        eventhandlers: list[SOMEIPBaseServiceEventgroupSender] | None,
        eventgroupreceivers: list[SOMEIPBaseServiceEventgroupReceiver] | None,
    ):
        self._name: str = name
        self._ip: str = ip

        try:
            self._ipaddress: ipaddress.IPv4Address | ipaddress.IPv6Address | None = ipaddress.ip_address(ip)
        except ValueError:
            self._ipaddress = None

        self._proto: int | str = proto
        self._portnumber: int = int(portnumber)
        self._instances: list[SOMEIPBaseServiceInstance] | None = serviceinstances
        self._instanceclients: list[SOMEIPBaseServiceInstanceClient] | None = serviceinstanceclients
        self._ehs: list[SOMEIPBaseServiceEventgroupSender] | None = eventhandlers
        self._cegs: list[SOMEIPBaseServiceEventgroupReceiver] | None = eventgroupreceivers
        self._pdus_in: list[BaseEthernetPDUInstance] = []
        self._pdus_out: list[BaseEthernetPDUInstance] = []
        self._interface: BaseInterface | None = None

        if serviceinstances is not None:
            for inst in serviceinstances:
                inst.setsocket(self)

        if serviceinstanceclients is not None:
            for client in serviceinstanceclients:
                client.setsocket(self)

        if eventhandlers is not None:
            for eh in eventhandlers:
                eh.setsocket(self)

        if eventgroupreceivers is not None:
            for ceg in eventgroupreceivers:
                ceg.setsocket(self)

    # TODO: XXX REMOVE AGAIN?
    def __eq__(self, other: object) -> bool:
        if not isinstance(other, BaseSocket):
            # don't attempt to compare against unrelated types
            return NotImplemented

        self_if = None
        my_iface = self.interface()
        if my_iface is not None:
            my_ctrl = my_iface.controller()
            if my_ctrl is not None:
                self_if = my_ctrl.name()

        other_if = None
        other_iface = other.interface()
        if other_iface is not None:
            other_ctrl = other_iface.controller()
            if other_ctrl is not None:
                other_if = other_ctrl.name()

        return (
            self._name == other._name
            and self._ip == other._ip
            and self._ipaddress == other._ipaddress
            and self._proto == other._proto
            and self._portnumber == other._portnumber
            and self_if != other_if
        )

    def name(self) -> str:
        return self._name

    def ip(self) -> str:
        return self._ip

    def is_ipv4(self) -> bool:
        return isinstance(self._ipaddress, ipaddress.IPv4Address)

    def is_ipv6(self) -> bool:
        return isinstance(self._ipaddress, ipaddress.IPv6Address)

    def is_multicast(self) -> bool:
        return self._ipaddress is not None and self._ipaddress.is_multicast

    def proto(self) -> int | str:
        return self._proto

    def portnumber(self) -> int:
        return self._portnumber

    def instances(self) -> list[SOMEIPBaseServiceInstance] | None:
        return self._instances

    def serviceinstanceclients(self) -> list[SOMEIPBaseServiceInstanceClient] | None:
        return self._instanceclients

    def eventhandlers(self) -> list[SOMEIPBaseServiceEventgroupSender] | None:
        return self._ehs

    def eventgroupreceivers(self) -> list[SOMEIPBaseServiceEventgroupReceiver] | None:
        return self._cegs

    def add_incoming_pdu(self, pdu: BaseEthernetPDUInstance) -> None:
        if pdu not in self._pdus_in:
            self._pdus_in.append(pdu)

    def incoming_pdus(self) -> list[BaseEthernetPDUInstance]:
        return self._pdus_in

    def add_outgoing_pdu(self, pdu: BaseEthernetPDUInstance) -> None:
        if pdu not in self._pdus_out:
            self._pdus_out.append(pdu)

    def outgoing_pdus(self) -> list[BaseEthernetPDUInstance]:
        return self._pdus_out

    def set_interface(self, interface: BaseInterface) -> None:
        self._interface = interface

    def interface(self) -> BaseInterface | None:
        return self._interface


class SOMEIPBaseServiceInstance(BaseItem):
    def __init__(self, service: SOMEIPBaseService, instanceid: int, protover: int):
        self._service: SOMEIPBaseService = service
        self._instanceid: int = int(instanceid)
        self._protover: int = int(protover)
        self._socket: BaseSocket | None = None

        self._clients: list[SOMEIPBaseServiceInstanceClient] = []
        self._eventgroup_sender: list[SOMEIPBaseServiceEventgroupSender] = []
        self._eventgroup_receiver: list[SOMEIPBaseServiceEventgroupReceiver] = []

        service.add_instance(self)

    def service(self) -> SOMEIPBaseService:
        return self._service

    def instanceid(self) -> int:
        return self._instanceid

    def protover(self) -> int:
        return self._protover

    def serviceinstanceclients(self) -> list[SOMEIPBaseServiceInstanceClient]:
        return self._clients

    def addclient(self, client: SOMEIPBaseServiceInstanceClient) -> None:
        if client not in self._clients:
            self._clients.append(client)

    def eventgroupsender(self) -> list[SOMEIPBaseServiceEventgroupSender]:
        return self._eventgroup_sender

    def addeventgroupsender(self, eh: SOMEIPBaseServiceEventgroupSender) -> None:
        if eh not in self._eventgroup_sender:
            self._eventgroup_sender.append(eh)

    def eventgroupreceiver(self) -> list[SOMEIPBaseServiceEventgroupReceiver]:
        return self._eventgroup_receiver

    def addeventgroupreceiver(self, ceg: SOMEIPBaseServiceEventgroupReceiver) -> None:
        if ceg not in self._eventgroup_receiver:
            self._eventgroup_receiver.append(ceg)

    def setsocket(self, socket: BaseSocket) -> None:
        self._socket = socket

    def socket(self) -> BaseSocket | None:
        return self._socket


class SOMEIPBaseServiceInstanceClient(BaseItem):
    def __init__(self, service: SOMEIPBaseService, instanceid: int, protover: int, instance: SOMEIPBaseServiceInstance | None):
        self._service: SOMEIPBaseService = service
        self._instanceid: int = int(instanceid)
        self._protover: int = int(protover)
        self._instance: SOMEIPBaseServiceInstance | None = instance
        self._socket: BaseSocket | None = None

        if instance is not None:
            instance.addclient(self)

    def service(self) -> SOMEIPBaseService:
        return self._service

    def instanceid(self) -> int:
        return self._instanceid

    def protover(self) -> int:
        return self._protover

    def instance(self) -> SOMEIPBaseServiceInstance | None:
        return self._instance

    def setsocket(self, socket: BaseSocket) -> None:
        self._socket = socket

    def socket(self) -> BaseSocket | None:
        return self._socket


class SOMEIPBaseServiceEventgroupSender(BaseItem):
    def __init__(self, serviceinstance: SOMEIPBaseServiceInstance, eventgroupid: int):
        self._si: SOMEIPBaseServiceInstance = serviceinstance
        self._eventgroupid: int = int(eventgroupid)
        self._eventgroupreceivers: list[SOMEIPBaseServiceEventgroupReceiver] = []
        self._socket: BaseSocket | None = None

    def serviceinstance(self) -> SOMEIPBaseServiceInstance:
        return self._si

    def eventgroupid(self) -> int:
        return self._eventgroupid

    def eventgroupreceivers(self) -> list[SOMEIPBaseServiceEventgroupReceiver]:
        return self._eventgroupreceivers

    def addreceiver(self, receiver: SOMEIPBaseServiceEventgroupReceiver) -> None:
        if receiver not in self._eventgroupreceivers:
            self._eventgroupreceivers.append(receiver)

    def setsocket(self, socket: BaseSocket) -> None:
        self._socket = socket

    def socket(self) -> BaseSocket | None:
        return self._socket


class SOMEIPBaseServiceEventgroupReceiver(BaseItem):
    def __init__(
        self,
        serviceinstance: SOMEIPBaseServiceInstance,
        eventgroupid: int,
        sender: SOMEIPBaseServiceEventgroupSender | None,
    ):
        self._si: SOMEIPBaseServiceInstance = serviceinstance
        self._eventgroupid: int = int(eventgroupid)
        self._sender: SOMEIPBaseServiceEventgroupSender | None = sender
        self._socket: BaseSocket | None = None

        if sender is not None:
            sender.addreceiver(self)

    def serviceinstance(self) -> SOMEIPBaseServiceInstance:
        return self._si

    def eventgroupid(self) -> int:
        return self._eventgroupid

    def sender(self) -> SOMEIPBaseServiceEventgroupSender | None:
        return self._sender

    def setsocket(self, socket: BaseSocket) -> None:
        self._socket = socket

    def socket(self) -> BaseSocket | None:
        return self._socket


class SOMEIPBaseService(BaseItem):
    def __init__(
        self,
        name: str,
        serviceid: int,
        majorver: int,
        minorver: int,
        methods: dict[int, SOMEIPBaseServiceMethod],
        events: dict[int, SOMEIPBaseServiceEvent],
        fields: dict[int, SOMEIPBaseServiceField],
        eventgroups: dict[int, SOMEIPBaseServiceEventgroup],
    ):
        self._name: str = name
        self._serviceid: int = int(serviceid)
        self._major: int = int(majorver)
        self._minor: int = int(minorver)

        self._methods: dict[int, SOMEIPBaseServiceMethod] = methods
        self._events: dict[int, SOMEIPBaseServiceEvent] = events
        self._fields: dict[int, SOMEIPBaseServiceField] = fields
        self._eventgroups: dict[int, SOMEIPBaseServiceEventgroup] = eventgroups

        self._instances: list[SOMEIPBaseServiceInstance] = []

    def serviceid(self) -> int:
        return self._serviceid

    def majorversion(self) -> int:
        return self._major

    def minorversion(self) -> int:
        return self._minor

    def versionstring(self) -> str:
        return "%d.%d" % (self._major, self._minor)

    def name(self) -> str:
        return self._name

    def methods(self) -> dict[int, SOMEIPBaseServiceMethod]:
        return self._methods

    def method(self, mid: int) -> SOMEIPBaseServiceMethod | None:
        if mid in self._methods:
            return self._methods[mid]
        return None

    def events(self) -> dict[int, SOMEIPBaseServiceEvent]:
        return self._events

    def event(self, eid: int) -> SOMEIPBaseServiceEvent | None:
        if eid in self._events:
            return self._events[eid]
        return None

    def fields(self) -> dict[int, SOMEIPBaseServiceField]:
        return self._fields

    def field(self, fid: int) -> SOMEIPBaseServiceField | None:
        if fid in self._fields:
            return self._fields[fid]
        return None

    def eventgroups(self) -> dict[int, SOMEIPBaseServiceEventgroup]:
        return self._eventgroups

    def eventgroup(self, egid: int) -> SOMEIPBaseServiceEventgroup | None:
        if egid in self._eventgroups:
            return self._eventgroups[egid]
        return None

    def add_instance(self, serviceinstance: SOMEIPBaseServiceInstance) -> None:
        self._instances.append(serviceinstance)

    def remove_instance(self, serviceinstance: SOMEIPBaseServiceInstance) -> None:
        self._instances.remove(serviceinstance)

    def instances(self) -> list[SOMEIPBaseServiceInstance]:
        return self._instances


class SOMEIPBaseServiceMethod(BaseItem):
    def __init__(
        self,
        name: str,
        methodid: int,
        calltype: CallSemantic,
        relia: bool,
        inparams: list[SOMEIPBaseParameter],
        outparams: list[SOMEIPBaseParameter],
        reqdebounce: int = -1,
        reqmaxretention: int = -1,
        resmaxretention: int = -1,
        tlv: bool = False,
    ):
        self._name: str = name
        self._methodid: int = methodid
        self._calltype: CallSemantic = calltype
        self._reliable: bool = relia

        self._inparams: list[SOMEIPBaseParameter] = inparams
        self._outparams: list[SOMEIPBaseParameter] = outparams

        self._reqdebouncetime: int = reqdebounce
        self._reqretentiontime_: int = reqmaxretention
        self._resretentiontime_: int = resmaxretention
        self._tlv: bool = tlv

    def methodid(self) -> int:
        return self._methodid

    def name(self) -> str:
        return self._name

    def calltype(self) -> CallSemantic:
        return self._calltype

    def reliable(self) -> bool:
        return self._reliable

    def inparams(self) -> list[SOMEIPBaseParameter]:
        return self._inparams

    def outparams(self) -> list[SOMEIPBaseParameter]:
        return self._outparams

    def size_min_in(self) -> int:
        ret = 0
        for p in self._inparams:
            ret += p.size_min_bits()
        return bits_to_bytes(ret)

    def size_max_in(self) -> int:
        ret = 0
        for p in self._inparams:
            ret += p.size_max_bits()
        return bits_to_bytes(ret)

    def size_min_out(self) -> int:
        ret = 0
        for p in self._outparams:
            ret += p.size_min_bits()
        return bits_to_bytes(ret)

    def size_max_out(self) -> int:
        ret = 0
        for p in self._outparams:
            ret += p.size_max_bits()
        return bits_to_bytes(ret)

    def debounce_time_req(self) -> int:
        return self._reqdebouncetime

    def max_buffer_retention_time_req(self) -> int:
        return self._reqretentiontime_

    def max_buffer_retention_time_res(self) -> int:
        return self._resretentiontime_

    def legacy(self) -> bool:
        for p in self._inparams:
            if p.legacy():
                return True
        for p in self._outparams:
            if p.legacy():
                return True
        return False

    def tlv(self) -> bool:
        return self._tlv


class SOMEIPBaseServiceEvent(BaseItem):
    def __init__(
        self,
        name: str,
        methodid: int,
        relia: bool,
        params: list[SOMEIPBaseParameter],
        debouncetimerange: int = -1,
        maxbufferretentiontime: int = -1,
        tlv: bool = False,
    ):
        self._name: str = name
        self._methodid: int = methodid
        self._reliable: bool = relia
        self._params: list[SOMEIPBaseParameter] = params
        self._debouncetime: int = debouncetimerange
        self._retentiontime_: int = maxbufferretentiontime
        self._tlv: bool = tlv

    def methodid(self) -> int:
        return self._methodid

    def name(self) -> str:
        return self._name

    def reliable(self) -> bool:
        return self._reliable

    def params(self) -> list[SOMEIPBaseParameter]:
        return self._params

    @staticmethod
    def size_min_in() -> int:
        return 0

    @staticmethod
    def size_max_in() -> int:
        return 0

    def size_min_out(self) -> int:
        ret = 0
        for p in self._params:
            ret += p.size_min_bits()
        return bits_to_bytes(ret)

    def size_max_out(self) -> int:
        ret = 0
        for p in self._params:
            ret += p.size_max_bits()
        return bits_to_bytes(ret)

    def debounce_time(self) -> int:
        return self._debouncetime

    def max_buffer_retention_time(self) -> int:
        return self._retentiontime_

    def legacy(self) -> bool:
        for p in self._params:
            if p.legacy():
                return True
        return False

    def tlv(self) -> bool:
        return self._tlv


class SOMEIPBaseServiceField(BaseItem):
    def __init__(
        self,
        config_factory: BaseConfigurationFactory,
        name: str,
        getterid: int | None,
        setterid: int | None,
        notifierid: int | None,
        getterreli: bool,
        setterreli: bool,
        notifierreli: bool,
        params: list[SOMEIPBaseParameter] | None,
        getter_reqdebounce: int = -1,
        getter_reqmaxretention: int = -1,
        getter_resmaxretention: int = -1,
        setter_reqdebounce: int = -1,
        setter_reqmaxretention: int = -1,
        setter_resmaxretention: int = -1,
        notifier_debounce: int = -1,
        notifier_maxretention: int = -1,
        tlv: bool = False,
    ):
        self._name: str = name

        self._getter: SOMEIPBaseServiceMethod | None = None
        self._setter: SOMEIPBaseServiceMethod | None = None
        self._notifier: SOMEIPBaseServiceEvent | None = None
        self._params: list[SOMEIPBaseParameter] | None = params

        self._minimum_id: int | None = None

        self._tlv: bool = tlv

        assert params is not None

        if getterid is not None:
            self._getter = config_factory.create_someip_service_method(
                name + "-Getter",
                getterid,
                "REQUEST_RESPONSE",
                getterreli,
                [],
                params,
                getter_reqdebounce,
                getter_reqmaxretention,
                getter_resmaxretention,
            )

        if setterid is not None:
            self._setter = config_factory.create_someip_service_method(
                name + "-Setter",
                setterid,
                "REQUEST_RESPONSE",
                setterreli,
                params,
                params,
                setter_reqdebounce,
                setter_reqmaxretention,
                setter_resmaxretention,
            )

        if notifierid is not None:
            self._notifier = config_factory.create_someip_service_event(
                name + "-Notifier",
                notifierid,
                notifierreli,
                params,
                notifier_debounce,
                notifier_maxretention,
            )

        # find smallest ID after stripping None
        tmp = sorted([getterid, setterid, notifierid], key=lambda x: (x is None, x))
        if tmp[0] is None:
            print(f"ERROR: Field ({name}) without Getter/Setter/Notifier!")
            return

        self._minimum_id = tmp[0]

        if self._minimum_id == -1:
            self._minimum_id = None

    def name(self) -> str:
        return self._name

    def params(self) -> list[SOMEIPBaseParameter] | None:
        return self._params

    def getter(self) -> SOMEIPBaseServiceMethod | None:
        return self._getter

    def setter(self) -> SOMEIPBaseServiceMethod | None:
        return self._setter

    def notifier(self) -> SOMEIPBaseServiceEvent | None:
        return self._notifier

    def min_id(self) -> int | None:
        return self._minimum_id

    def notifierid(self) -> int | None:
        if self._notifier is None:
            return None
        return self._notifier.methodid()

    def id(self) -> int | None:
        if self.notifierid() is not None:
            return self.notifierid()
        return self.min_id()

    def size_min_in(self) -> int:
        assert self._params is not None
        ret = 0
        for p in self._params:
            ret += p.size_min_bits()
        return bits_to_bytes(ret)

    def size_max_in(self) -> int:
        assert self._params is not None
        ret = 0
        for p in self._params:
            ret += p.size_max_bits()
        return bits_to_bytes(ret)

    def size_min_out(self) -> int:
        assert self._params is not None
        ret = 0
        for p in self._params:
            ret += p.size_min_bits()
        return bits_to_bytes(ret)

    def size_max_out(self) -> int:
        assert self._params is not None
        ret = 0
        for p in self._params:
            ret += p.size_max_bits()
        return bits_to_bytes(ret)

    def legacy(self) -> bool:
        if self._params is None:
            return False

        for p in self._params:
            if p.legacy():
                return True

        return False

    def tlv(self) -> bool:
        return self._tlv


class SOMEIPBaseServiceEventgroup(BaseItem):
    def __init__(self, name: str, egid: int, eventids: list[int], fieldids: list[int]):
        self._name: str = name
        self._id: int = int(egid)
        self._eventids: list[int] = eventids
        self._fieldids: list[int] = fieldids

    def name(self) -> str:
        return self._name

    def id(self) -> int:
        return self._id

    def eventids(self) -> list[int]:
        return self._eventids

    def fieldids(self) -> list[int]:
        return self._fieldids


class SOMEIPBaseParameter(BaseItem):
    def __init__(
        self,
        position: int,
        name: str,
        desc: str | None,
        mandatory: bool,
        datatype: SOMEIPBaseDatatype | None,
        signal: BaseSignal | None,
    ):
        self._position: int = int(position)
        self._name: str = name
        self._desc: str | None = desc
        self._mandatory: bool = mandatory
        self._datatype: SOMEIPBaseDatatype | None = datatype
        self._signal: BaseSignal | None = signal

    def position(self) -> int:
        return self._position

    def name(self) -> str:
        return self._name

    def desc(self) -> str | None:
        return self._desc

    def mandatory(self) -> bool:
        return self._mandatory

    def datatype(self) -> SOMEIPBaseDatatype | None:
        return self._datatype

    def signal(self) -> BaseSignal | None:
        return self._signal

    def size_min_bits(self) -> int:
        assert self._datatype is not None
        return self._datatype.size_min_bits()

    def size_max_bits(self) -> int:
        assert self._datatype is not None
        return self._datatype.size_max_bits()

    def legacy(self) -> bool:
        if self._signal is not None:
            return True
        if self._datatype is None:
            return False
        return self._datatype.legacy()


class SOMEIPBaseParameterBasetype(BaseItem):
    def __init__(self, name: str, datatype: str, bigendian: bool, bitlength_basetype: int, bitlength_encoded_type: int):
        self._name: str = name
        self._datatype: str = datatype
        self._bigendian: bool = bigendian
        self._bitlength_basetype: int = int(bitlength_basetype)
        self._bitlength_encoded_type: int = int(bitlength_encoded_type)

    def name(self) -> str:
        return self._name

    def datatype(self) -> str:
        return self._datatype

    def bigendian(self) -> bool:
        return self._bigendian

    def bitlength_basetype(self) -> int:
        return self._bitlength_basetype

    def bitlength_encoded_type(self) -> int:
        return self._bitlength_encoded_type

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, self.__class__):
            return False

        return (
            self.name() == other.name()
            and self.datatype() == other.datatype()
            and self.bigendian() == other.bigendian()
            and self.bitlength_basetype() == other.bitlength_basetype()
            and self.bitlength_encoded_type() == other.bitlength_encoded_type()
        )

    def size_min_bits(self) -> int:
        return self._bitlength_encoded_type

    def size_max_bits(self) -> int:
        return self._bitlength_encoded_type


class SOMEIPBaseParameterString(BaseItem):
    def __init__(
        self,
        name: str,
        chartype: str,
        bigendian: bool,
        lowerlimit: int,
        upperlimit: int,
        termination: str | None,
        length_of_length: int | None,
        pad_to: int,
    ):
        self._name: str = name
        self._chartype: str = chartype
        self._bigendian: bool = bigendian
        self._lowerlimit: int = int(lowerlimit)
        self._upperlimit: int = int(upperlimit)
        self._termination: str | None = termination

        if length_of_length is None or length_of_length == -1:
            if lowerlimit == upperlimit:
                self._lengthOfLength: int = 0
            else:
                self._lengthOfLength = 32  # SOME/IP default
        else:
            self._lengthOfLength = int(length_of_length)

        self._padTo = int(pad_to)

    def name(self) -> str:
        return self._name

    def chartype(self) -> str:
        return self._chartype

    def bigendian(self) -> bool:
        return self._bigendian

    def lowerlimit(self) -> int:
        return self._lowerlimit

    def upperlimit(self) -> int:
        return self._upperlimit

    def termination(self) -> str | None:
        return self._termination

    def length_of_length(self) -> int:
        return self._lengthOfLength

    def pad_to(self) -> int:
        return self._padTo

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, self.__class__):
            return False

        return (
            self.name() == other.name()
            and self.chartype() == other.chartype()
            and self.bigendian() == other.bigendian()
            and self.lowerlimit() == other.lowerlimit()
            and self.upperlimit() == other.upperlimit()
            and self.termination() == other.termination()
            and self.length_of_length() == other.length_of_length()
            and self.pad_to() == other.pad_to()
        )

    def size_min_bits(self) -> int:
        # TODO: double check, if this is based on bytes or chars
        return self._lengthOfLength + 8 * self._lowerlimit

    def size_max_bits(self) -> int:
        # TODO: double check, if this is based on bytes or chars
        return self._lengthOfLength + 8 * self._upperlimit


class SOMEIPBaseParameterArray(BaseItem):
    def __init__(self, name: str, dims: dict[int, SOMEIPBaseParameterArrayDim], child: SOMEIPBaseDatatype):
        self._name: str = name
        self._dims: dict[int, SOMEIPBaseParameterArrayDim] = dims
        self._child: SOMEIPBaseDatatype = child

    def name(self) -> str:
        return self._name

    def dims(self) -> dict[int, SOMEIPBaseParameterArrayDim]:
        return self._dims

    def child(self) -> SOMEIPBaseDatatype:
        return self._child

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, self.__class__):
            return False

        return self.name() == other.name() and self.dims() == other.dims() and self.child() == other.child()

    def size_min_bits(self) -> int:
        ret = self._child.size_min_bits()

        # todo: is this the right order?
        for dim in self._dims.values():
            ret = dim.calc_size_min_bits(ret)

        return ret

    def size_max_bits(self) -> int:
        ret = self._child.size_min_bits()

        # todo: is this the right order?
        for dim in self._dims.values():
            ret = dim.calc_size_max_bits(ret)

        return ret


class SOMEIPBaseParameterArrayDim(BaseItem):
    def __init__(self, dim: int, lowerlimit: int, upperlimit: int, length_of_length: int | None, pad_to: int):
        self._dim: int = int(dim)
        self._lowerlimit: int = int(lowerlimit)
        self._upperlimit: int = int(upperlimit)
        if length_of_length is None or length_of_length == -1:
            if lowerlimit == upperlimit:
                self._lengthOfLength: int = 0
            else:
                self._lengthOfLength = 32  # SOME/IP default
        else:
            self._lengthOfLength = int(length_of_length)

        self._padTo = int(pad_to)

    def dim(self) -> int:
        return self._dim

    def lowerlimit(self) -> int:
        return self._lowerlimit

    def upperlimit(self) -> int:
        return self._upperlimit

    def length_of_length(self) -> int:
        return self._lengthOfLength

    def pad_to(self) -> int:
        return self._padTo

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, self.__class__):
            return False

        return (
            self.dim() == other.dim()
            and self.lowerlimit() == other.lowerlimit()
            and self.upperlimit() == other.upperlimit()
            and self.length_of_length() == other.length_of_length()
            and self.pad_to() == other.pad_to()
        )

    def calc_size_min_bits(self, inner_length: int) -> int:
        ret = self._lowerlimit * inner_length
        # XXX - padTo completly untested since export do not have BIT-ALIGNMENT set (its counted in bits)
        if self._padTo > 0:
            ret += ret % self._padTo

        return self._lengthOfLength + ret

    def calc_size_max_bits(self, inner_length: int) -> int:
        ret = self._upperlimit * inner_length
        # XXX - padTo completly untested since export do not have BIT-ALIGNMENT set (its counted in bits)
        if self._padTo > 0:
            ret += ret % self._padTo

        return self._lengthOfLength + ret


class SOMEIPBaseParameterStruct(BaseItem):
    def __init__(
        self,
        name: str,
        length_of_length: int | None,
        pad_to: int,
        members: dict[int, SOMEIPBaseParameterStructMember],
        tlv: bool = False,
    ):
        self._name: str = name
        self._members: dict[int, SOMEIPBaseParameterStructMember] = members
        self._tlv: bool = tlv

        if length_of_length is None or length_of_length == -1:
            self._lengthOfLength: int = 0
        else:
            self._lengthOfLength = int(length_of_length)

        self._padTo = int(pad_to)

    def name(self) -> str:
        return self._name

    def members(self) -> dict[int, SOMEIPBaseParameterStructMember]:
        return self._members

    def length_of_length(self) -> int:
        return self._lengthOfLength

    def pad_to(self) -> int:
        return self._padTo

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, self.__class__):
            return False

        return (
            self.name() == other.name()
            and self.members() == other.members()
            and self.length_of_length() == other.length_of_length()
            and self.pad_to() == other.pad_to()
            and self.tlv() == other.tlv()
        )

    def size_min_bits(self) -> int:
        ret = self._lengthOfLength
        for m in self._members.values():
            ret += m.child().size_min_bits()
        return ret

    def size_max_bits(self) -> int:
        ret = self._lengthOfLength
        for m in self._members.values():
            ret += m.child().size_max_bits()
        return ret

    def legacy(self) -> bool:
        for m in self._members.values():
            if m.legacy():
                return True
        return False

    def tlv(self) -> bool:
        return self._tlv


class SOMEIPBaseParameterStructMember(BaseItem):
    def __init__(
        self,
        position: int,
        name: str,
        mandatory: bool,
        child: SOMEIPBaseDatatype,
        signal: BaseSignal | None,
    ):
        self._name: str = name
        self._position: int = int(position)
        self._mandatory: bool = mandatory
        self._child: SOMEIPBaseDatatype = child
        self._signal: BaseSignal | None = signal

    def name(self) -> str:
        return self._name

    def position(self) -> int:
        return self._position

    def update_position(self, p: int) -> None:
        self._position = p

    def mandatory(self) -> bool:
        return self._mandatory

    def child(self) -> SOMEIPBaseDatatype:
        return self._child

    def signal(self) -> BaseSignal | None:
        return self._signal

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, self.__class__):
            return False

        return (
            self.name() == other.name()
            and self.position() == other.position()
            and self.mandatory() == other.mandatory()
            and self.child() == other.child()
            and self.signal() == other.signal()
        )

    def legacy(self) -> bool:
        if self._signal is not None:
            return True
        return False


class SOMEIPBaseParameterTypedef(BaseItem):
    def __init__(self, name: str, name2: str, child: SOMEIPBaseDatatype):
        self._name: str = name
        self._name2: str = name2
        self._child: SOMEIPBaseDatatype = child

    def name(self) -> str:
        return self._name

    def name2(self) -> str:
        return self._name2

    def child(self) -> SOMEIPBaseDatatype:
        return self._child

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, self.__class__):
            return False

        return self.name() == other.name() and self.name2() == other.name2() and self.child() == other.child()

    def size_min_bits(self) -> int:
        return self._child.size_min_bits()

    def size_max_bits(self) -> int:
        return self._child.size_max_bits()


class SOMEIPBaseParameterEnumeration(BaseItem):
    def __init__(self, name: str, items: list[SOMEIPBaseParameterEnumerationItem], child: SOMEIPBaseDatatype):
        self._name: str = name
        self._items: list[SOMEIPBaseParameterEnumerationItem] = items
        self._child: SOMEIPBaseDatatype = child

    def name(self) -> str:
        return self._name

    def items(self) -> list[SOMEIPBaseParameterEnumerationItem]:
        return self._items

    def child(self) -> SOMEIPBaseDatatype:
        return self._child

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, self.__class__):
            return False

        return self.name() == other.name() and self.items() == other.items() and self.child() == other.child()

    def size_min_bits(self) -> int:
        return self._child.size_min_bits()

    def size_max_bits(self) -> int:
        return self._child.size_max_bits()


class SOMEIPBaseParameterEnumerationItem(BaseItem):
    def __init__(self, value: int, name: str, desc: str | None):
        self._name: str = name
        self._desc: str | None = desc
        self._value: int = int(value)

    def name(self) -> str:
        return self._name

    def desc(self) -> str | None:
        return self._desc

    def value(self) -> int:
        return self._value

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, self.__class__):
            return False

        return self.name() == other.name() and self.desc() == other.desc() and self.value() == other.value()


class SOMEIPBaseParameterUnion(BaseItem):
    def __init__(
        self,
        name: str,
        length_of_length: int | None,
        length_of_type: int | None,
        pad_to: int,
        members: dict[int, SOMEIPBaseParameterUnionMember],
    ):
        self._name: str = name
        self._members: dict[int, SOMEIPBaseParameterUnionMember] = members

        if length_of_length is None or length_of_length == -1:
            self._lengthOfLength: int = 32  # SOME/IP default
        else:
            self._lengthOfLength = int(length_of_length)

        if length_of_type is None or length_of_type == -1:
            self._lengthOfType: int = 32  # SOME/IP default
        else:
            self._lengthOfType = int(length_of_type)

        self._padTo = int(pad_to)

    def name(self) -> str:
        return self._name

    def members(self) -> dict[int, SOMEIPBaseParameterUnionMember]:
        return self._members

    def length_of_length(self) -> int:
        return self._lengthOfLength

    def length_of_type(self) -> int:
        return self._lengthOfType

    def pad_to(self) -> int:
        return self._padTo

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, self.__class__):
            return False

        return (
            self.name() == other.name()
            and self.members() == other.members()
            and self.length_of_length() == other.length_of_length()
            and self.length_of_length() == other.length_of_length()
            and self.pad_to() == other.pad_to()
        )

    def size_min_bits(self) -> int:
        ret = -1

        for m in self._members.values():
            if ret == -1:
                ret = m.child().size_min_bits()
            else:
                if ret >= m.child().size_min_bits():
                    ret = m.child().size_min_bits()
            if self._padTo > 0:
                ret += ret % self.pad_to()
        return self._lengthOfLength + ret

    def size_max_bits(self) -> int:
        ret = -1

        for m in self._members.values():
            if ret == -1:
                ret = m.child().size_max_bits()
            else:
                if ret < m.child().size_max_bits():
                    ret = m.child().size_max_bits()
            if self._padTo > 0:
                ret += ret % self.pad_to()
        return self._lengthOfLength + ret


class SOMEIPBaseParameterUnionMember(BaseItem):
    def __init__(self, index: int, name: str, mandatory: bool, child: SOMEIPBaseDatatype):
        self._name: str = name
        self._index: int = int(index)
        self._mandatory: bool = mandatory
        self._child: SOMEIPBaseDatatype = child

    def name(self) -> str:
        return self._name

    def index(self) -> int:
        return self._index

    def mandatory(self) -> bool:
        return self._mandatory

    def child(self) -> SOMEIPBaseDatatype:
        return self._child

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, self.__class__):
            return False

        return (
            self.name() == other.name() and self.index() == other.index() and self.mandatory() == other.mandatory() and self.child() == other.child()
        )


class SOMEIPBaseParameterBitfield(BaseItem):
    def __init__(self, name: str, items: list[SOMEIPBaseParameterBitfieldItem], child: SOMEIPBaseDatatype):
        self._name: str = name
        self._items: list[SOMEIPBaseParameterBitfieldItem] = items
        self._child: SOMEIPBaseDatatype = child

    def name(self) -> str:
        return self._name

    def items(self) -> list[SOMEIPBaseParameterBitfieldItem]:
        return self._items

    def child(self) -> SOMEIPBaseDatatype:
        return self._child

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, self.__class__):
            return False

        return self.name() == other.name() and self.items() == other.items() and self.child() == other.child()

    def size_min_bits(self) -> int:
        return self._child.size_min_bits()

    def size_max_bits(self) -> int:
        return self._child.size_max_bits()


class SOMEIPBaseParameterBitfieldItem(BaseItem):
    def __init__(self, bit_number: int, name: str):
        self._name: str = name
        self._bit_number: int = int(bit_number)

    def name(self) -> str:
        return self._name

    def bit_number(self) -> int:
        return self._bit_number

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, self.__class__):
            return False

        return self.name() == other.name() and self.bit_number() == other.bit_number()


class BaseSignal(BaseItem):
    def __init__(
        self,
        id: str,
        name: str,
        compu_scale: tuple[float, float, float] | None,
        compu_const: list[CompuConst] | None,
        bit_length: int,
        min_length: int,
        max_length: int,
        basetype: str,
        basetypelen: int,
    ):
        self._id = id
        self._name = name
        self._compu_scale = compu_scale
        self._compu_consts = compu_const
        self._bit_length = bit_length
        self._min_length = min_length
        self._max_length = max_length
        self._basetype = basetype
        self._basetypelen = basetypelen

    def id(self) -> str:
        return self._id

    def name(self) -> str:
        return self._name

    def compu_scale(self) -> tuple[float, float, float] | None:
        return self._compu_scale

    def scaler(self) -> float:
        scale = self.compu_scale()
        if scale is not None and len(scale) == 3:
            num0, num1, denom = scale
            return float(num1) / float(denom)
        return 1

    def scaler_raw(self) -> float:
        scale = self.compu_scale()
        if scale is not None and len(scale) == 3:
            _, num1, _ = scale
            return float(num1)
        return 1

    def denom_raw(self) -> float:
        scale = self.compu_scale()
        if scale is not None and len(scale) == 3:
            _, _, denom = scale
            return float(denom)
        return 1

    def offset(self) -> float:
        scale = self.compu_scale()
        if scale is not None and len(scale) == 3:
            num0, num1, denom = scale
            return float(num0)
        return 0

    def compu_consts(self) -> list[CompuConst] | None:
        return self._compu_consts

    def bit_length(self) -> int:
        return self._bit_length

    def min_length(self) -> int:
        return self._min_length

    def max_length(self) -> int:
        return self._max_length

    def basetype(self) -> str:
        return self._basetype

    def basetype_length(self) -> int:
        return self._basetypelen

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, self.__class__):
            return False

        return (
            self.id() == self.id()
            and self.name() == other.name()
            and self.compu_scale() == other.compu_scale()
            and self.basetype() == other.basetype()
            and self.compu_consts() == other.compu_consts()
        )


class BaseSignalInstance(BaseItem):
    def __init__(self, id: str, signal_ref: str, bit_position: int, is_high_low_byte_order: bool):
        self._id = id
        self._signal_ref = signal_ref
        self._bit_position = bit_position
        self._is_high_low_byte_order = is_high_low_byte_order
        self._signal: BaseSignal | None = None

    def add_signal(self, signal: BaseSignal) -> None:
        self._signal = signal

    def bit_position(self) -> int:
        return self._bit_position

    def is_high_low_byte_order(self) -> bool:
        return self._is_high_low_byte_order

    def signal(self) -> BaseSignal | None:
        return self._signal


class BaseAbstractPDU(BaseItem):
    def __init__(self, id: str, short_name: str, byte_length: int, pdu_type: str):
        self._id = id
        self._short_name = short_name
        self._byte_length = byte_length
        self._pdu_type = pdu_type

    def id(self) -> str:
        return self._id

    def name(self) -> str:
        return self._short_name

    def byte_length(self) -> int:
        return self._byte_length

    def pdu_type(self) -> str:
        return self._pdu_type

    def is_multiplex_pdu(self) -> bool:
        return False


class BasePDU(BaseAbstractPDU):
    def __init__(self, id: str, short_name: str, byte_length: int, pdu_type: str, signal_instances: dict[int, BaseSignalInstance]):
        super(BasePDU, self).__init__(id, short_name, byte_length, pdu_type)

        self._signal_instances: dict[int, BaseSignalInstance] = signal_instances

    def signal_instances(self) -> dict[int, BaseSignalInstance]:
        return self._signal_instances

    def signal_instances_sorted_by_bit_position(self) -> list[BaseSignalInstance]:
        tmp: dict[int, BaseSignalInstance] = {}
        for si in self._signal_instances.values():
            if si.bit_position() in tmp.keys():
                print(f"ERROR: PDU {self.name()} has multiple Signals starting at same position! Overwritting!")
            tmp[si.bit_position()] = si

        ret = []
        for key in sorted(tmp.keys()):
            ret.append(tmp[key])

        return ret


class BaseMultiplexPDU(BaseAbstractPDU):
    def __init__(
        self,
        id: str,
        short_name: str,
        byte_length: int,
        pdu_type: str,
        switch: BaseMultiplexPDUSwitch | None,
        segment_positions: list[BaseMultiplexPDUSegmentPosition],
        pdu_instances: dict[int, BaseAbstractPDU | None] | None,
        static_seg_pdu_combinations: list[tuple[list[BaseMultiplexPDUSegmentPosition], BasePDU]],
    ):
        super(BaseMultiplexPDU, self).__init__(id, short_name, byte_length, pdu_type)

        if switch is None and len(segment_positions) != 0:
            print(f"ERROR: PDU: {short_name} has Dynamic Segments but no Switch!")
            raise ValueError

        if switch is not None and len(segment_positions) == 0:
            print(f"ERROR: PDU: {short_name} has a Switch but no Dynamic Segments!")
            # raise ValueError

        if len(segment_positions) > 1:
            print(f"ERROR: We only support up to 1 Dynamic Segment per PDU! " f"PDU {short_name} has {len(segment_positions)}")
            raise ValueError

        for combo_segs, combo_pdu in static_seg_pdu_combinations:
            if (combo_segs is None or len(combo_segs) == 0) and combo_pdu is not None:
                print(f"ERROR: PDU: {short_name} has a Static PDU but no Static Segments!")
                raise ValueError

        self._switch: BaseMultiplexPDUSwitch | None = switch
        self._segment_positions: list[BaseMultiplexPDUSegmentPosition] = segment_positions
        self._pdu_instances: dict[int, BaseAbstractPDU | None] | None = pdu_instances
        self._static_segment_pdu_combinations: list[tuple[list[BaseMultiplexPDUSegmentPosition], BasePDU]] = static_seg_pdu_combinations

    def switch(self) -> BaseMultiplexPDUSwitch | None:
        return self._switch

    def segment_positions(self) -> list[BaseMultiplexPDUSegmentPosition]:
        return self._segment_positions

    def pdu_instances(self) -> dict[int, BaseAbstractPDU | None] | None:
        return self._pdu_instances

    def is_multiplex_pdu(self) -> bool:
        return True

    def static_seg_pdu_combinations(self) -> list[tuple[list[BaseMultiplexPDUSegmentPosition], BasePDU]]:
        return self._static_segment_pdu_combinations


class BaseMultiplexPDUSwitch(BaseItem):
    def __init__(self, id: str, short_name: str, bit_position: int, is_high_low_byte_order: bool, bit_length: int):
        self._id = id
        self._short_name = short_name
        self._bit_position = bit_position
        self._is_high_low_byte_order = is_high_low_byte_order
        self._bit_length = bit_length

    def id(self) -> str:
        return self._id

    def name(self) -> str:
        return self._short_name

    def bit_position(self) -> int:
        return self._bit_position

    def is_high_low_byte_order(self) -> bool:
        return self._is_high_low_byte_order

    def bit_length(self) -> int:
        return self._bit_length


class BaseMultiplexPDUSegmentPosition(BaseItem):
    def __init__(self, bit_position: int, is_high_low_byte_order: bool, bit_length: int):
        self._bit_position = bit_position
        self._is_high_low_byte_order = is_high_low_byte_order
        self._bit_length = bit_length

    def bit_position(self) -> int:
        return self._bit_position

    def is_high_low_byte_order(self) -> bool:
        return self._is_high_low_byte_order

    def bit_length(self) -> int:
        return self._bit_length


class BaseEthernetPDUInstance(BaseItem):
    def __init__(self, pdu_ref: str, header_id: int | None):
        self._pdu_ref = pdu_ref
        self._bit_position = 0
        self._header_id = header_id
        self._pdu_update_bit_position = None
        self._pdu: BaseAbstractPDU | None = None

    def add_pdu(self, pdu: BaseAbstractPDU) -> None:
        self._pdu = pdu

    def pdu(self) -> BaseAbstractPDU | None:
        return self._pdu

    def bit_position(self) -> int:
        return self._bit_position

    def header_id(self) -> int | None:
        return self._header_id

    def pdu_update_bit_position(self) -> None:
        return self._pdu_update_bit_position


class BasePDUInstance(BaseItem):
    def __init__(self, id: str, pdu_ref: str, bit_position: int, is_high_low_byte_order: bool, pdu_update_bit_position: int | None):
        self._id = id
        self._pdu_ref = pdu_ref
        self._bit_position = bit_position
        self._is_high_low_byte_order = is_high_low_byte_order
        self._pdu_update_bit_position = pdu_update_bit_position
        self._pdu: BaseAbstractPDU | None = None

    def pdu_ref(self) -> str:
        return self._pdu_ref

    def add_pdu(self, pdu: BaseAbstractPDU) -> None:
        self._pdu = pdu

    def pdu(self) -> BaseAbstractPDU | None:
        return self._pdu

    def bit_position(self) -> int:
        return self._bit_position

    def pdu_update_bit_position(self) -> int | None:
        return self._pdu_update_bit_position


class BaseFrame(BaseItem):
    def __init__(self, id: str, short_name: str, byte_length: int, frame_type: str, pdu_instances: dict[str, BasePDUInstance]):
        self._id = id
        self._short_name = short_name
        self._byte_length = byte_length
        self._frame_type = frame_type
        self._pdu_instances = pdu_instances

    def add_pdu_instance(self, pdu_instance: BasePDUInstance) -> None:
        self._pdu_instances[pdu_instance.pdu_ref()] = pdu_instance

    def id(self) -> str:
        return self._id

    def name(self) -> str:
        return self._short_name

    def byte_length(self) -> int:
        return self._byte_length

    def frame_type(self) -> str:
        return self._frame_type

    def pdu_instances(self) -> dict[str, BasePDUInstance]:
        return self._pdu_instances


class BaseFrameTriggering(BaseItem):
    def __init__(self, id: str, frame: BaseFrame):
        self._id = id
        self._frame = frame

    def id(self) -> str:
        return self._id

    def calc_key(self) -> str:
        return self._id

    def frame(self) -> BaseFrame:
        return self._frame

    def is_can(self) -> bool:
        return False

    def is_flexray(self) -> bool:
        return False

    def is_ethernet(self) -> bool:
        return False


class BaseFrameTriggeringCAN(BaseFrameTriggering):
    def __init__(self, id: str, frame: BaseFrame, can_id: int, is_extended_id: bool, is_can_fd: bool):
        super(BaseFrameTriggeringCAN, self).__init__(id, frame)

        self._can_id = can_id
        self.__is_can_fd = is_can_fd
        self.__is_extended_id = is_extended_id

    def can_id(self) -> int:
        return self._can_id

    def calc_key(self) -> str:
        return f"CAN-0x{self._can_id:04x}"

    def is_can(self) -> bool:
        return True

    def is_extended_id(self) -> bool:
        return self.__is_extended_id

    def is_can_fd(self) -> bool:
        return self.__is_can_fd


class BaseFrameTriggeringFlexRay(BaseFrameTriggering):
    def __init__(self, id: str, frame: BaseFrame, slot_id: int, cycle_counter: int | None, base_cycle: int | None, cycle_repetition: int | None):
        super(BaseFrameTriggeringFlexRay, self).__init__(id, frame)

        self._slot_id = slot_id
        self._cycle_counter = cycle_counter
        self._base_cycle = base_cycle
        self._cycle_repetition = cycle_repetition

    def scheduling(self) -> tuple[int, int | None, int | None, int | None]:
        return (
            self._slot_id,
            self._cycle_counter,
            self._base_cycle,
            self._cycle_repetition,
        )

    def calc_key(self) -> str:
        tmp_cycle_counter = 0 if self._cycle_counter is None else self._cycle_counter
        tmp_base_cycle = 0 if self._base_cycle is None else self._base_cycle
        tmp_cycle_repetition = 0 if self._cycle_repetition is None else self._cycle_repetition

        ret = f"FlexRay-0x{self._slot_id:04x}-0x{tmp_cycle_counter:04x}-0x{tmp_base_cycle:04x}-" f"0x{tmp_cycle_repetition:04x}"
        return ret

    def is_flexray(self) -> bool:
        return True
