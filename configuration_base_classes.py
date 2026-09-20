#!/usr/bin/python

# Automotive configuration file scripts
# Copyright (C) 2015-2026  Dr. Lars Voelker
# Copyright (C) 2018-2019  Dr. Lars Voelker, BMW AG
# Copyright (C) 2020-2025  Dr. Lars Voelker, Technica Engineering GmbH

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
import logging
from collections.abc import Iterable
from typing import Literal, Protocol

import macaddress  # type: ignore[import-untyped]

logger = logging.getLogger(__name__)

CallSemantic = Literal["REQUEST_RESPONSE", "FIRE_AND_FORGET"]


class SOMEIPBaseDatatype(Protocol):
    def size_min_bits(self) -> int: ...

    def size_max_bits(self) -> int: ...

    def legacy(self) -> bool: ...


def bits_to_bytes(bits: int) -> int:
    if bits % 8 == 0:
        return bits // 8
    else:
        return (bits // 8) + 1


def is_mcast(addr: str | None) -> bool:
    if is_ip_mcast(addr):
        return True

    if is_mac_mcast(addr):
        return True

    return False


def addr_to_key(addr: str | None) -> str:
    if addr is None:
        return "None"

    if is_ip(addr):
        return ip_to_key(addr)

    if is_mac(addr):
        return mac_to_key(addr)

    print(f"Warning: addr_to_key was called with {addr} and this seems to be no IP or MAC Address!")
    return "None"


def is_mac(mac: str | None) -> bool:
    if mac is None:
        return False

    try:
        macaddress.EUI48(mac)
    except ValueError:
        return False

    return True


def is_mac_mcast(mac: str | None) -> bool:
    if mac is None:
        return False

    try:
        tmp = macaddress.EUI48(mac)
    except (ValueError, TypeError):
        return False

    return bool(int(tmp.__bytes__()[0]) & 0x01)


def mac_to_key(mac: str | None) -> str:
    if mac is None:
        return "None"

    try:
        tmp = macaddress.EUI48(mac)
    except ValueError:
        return "None"

    return f"mac-{str(tmp)}"


def is_ip(ip: str | None) -> bool:
    if ip is None:
        return False

    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return False

    return True


def is_ip_mcast(ip: str | None) -> bool:
    if ip is None:
        return False

    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False

    return addr.is_multicast


def ip_to_key(ip: str | None) -> str:
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
        compu_consts: list[object] | None,
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
        pdu_instances: list[BasePDUInstance] | None,
        static_segs: list[BaseMultiplexPDUSegmentPosition],
        static_pdu: BasePDU | None,
    ) -> BaseMultiplexPDU:
        return BaseMultiplexPDU(
            id,
            short_name,
            byte_length,
            pdu_type,
            switch,
            seg_pos,
            pdu_instances,
            static_segs,
            static_pdu,
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
        compu_consts: list[object] | None,
    ):
        self.__id__ = id
        self.__name__ = name
        self.__coded_basetype__ = coded_basetype
        self.__coded_category__ = coded_category
        self.__coded_termination__ = coded_termination
        self.__coded_bit_length__ = coded_bit_length
        self.__coded_max_length__ = coded_max_length
        self.__compu_scale__ = compu_scale
        self.__compu_consts__ = compu_consts

    def name(self) -> str:
        return self.__name__


class BaseVLAN(BaseItem):
    def __init__(self, vlan_name: str, vlan_id: int | None, priority: int | None):
        self.__vlan_name__ = vlan_name
        self.__vlan_id__ = vlan_id
        self.__priority__ = priority

    def name(self) -> str:
        return self.__vlan_name__

    def vlanid(self) -> int | None:
        return self.__vlan_id__

    def vlanid_str(self) -> str:
        vlanid = self.vlanid()
        if vlanid is None:
            return "untagged"
        return f"0x{vlanid:x}"

    def priority(self) -> int | None:
        return self.__priority__


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

        self.__vlanid__ = vlanid_tx
        self.__tx_addr__ = source_addr
        self.__mc_addr__ = multicast_addr
        self.__swport_tx__ = switchport_tx
        self.__swport_rx__ = switchport_rx
        self.__comment__ = comment

    def vlanid(self) -> int:
        return self.__vlanid__

    def source_addr(self) -> str:
        return self.__tx_addr__

    def mc_addr(self) -> str:
        return self.__mc_addr__

    def switchport_tx(self) -> BaseSwitchPort | None:
        return self.__swport_tx__

    def switchport_tx_name(self) -> str | None:
        if self.__swport_tx__ is None:
            return None
        else:
            return self.__swport_tx__.portid()

    def switchport_rx(self) -> BaseSwitchPort | None:
        return self.__swport_rx__

    def switchport_rx_name(self) -> str | None:
        if self.__swport_rx__ is None:
            return None
        else:
            return self.__swport_rx__.portid()

    def comment(self) -> str:
        return self.__comment__

    def __append_to_comment__(self, txt: str) -> None:
        self.__comment__ += txt


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

        self.__portid__: str = portid
        self.__ctrl__: BaseController | None = None
        self.__port__: BaseSwitchPort | None = port
        self.__eth_bus__: BaseEthernetBus | None = None
        self.__default_vlan__: int | None = default_vlan
        self.__vlans__: list[BaseVLAN] = vlans
        self.__switch__: BaseSwitch | None = None

        if ctrl is not None:
            self.set_connected_ctrl(ctrl)

    def __repr__(self) -> str:
        switch_name = "<unknown>"
        if self.__switch__ is not None:
            switch_name = self.__switch__.name()

        return f"{switch_name}.{self.__portid__}"

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

        return self.__portid__

    def portid_generated(self) -> str:
        if self.__port__ is not None:
            sw = self.__port__.switch()
            if sw is not None:
                return f"couplingPort_ConnectTo_{sw.name()}"
        if self.__ctrl__ is not None:
            return f"couplingPort_ConnectTo_{self.__ctrl__.name()}"
        if self.__eth_bus__ is not None:
            return f"couplingPort_ConnectTo_{self.__eth_bus__.name()}"

        return self.__portid__

    def set_parent_switch(self, switch: BaseSwitch) -> None:
        self.__switch__ = switch

    def switch(self) -> BaseSwitch | None:
        return self.__switch__

    def set_connected_port(self, peer_port: BaseSwitchPort) -> None:
        assert peer_port is not None
        assert self.__port__ is None

        if self.__ctrl__ is not None or self.__eth_bus__ is not None:
            print(f"WARNING: SwitchPort {self.__portid__} adds port but was connected before! Overwritting!")

        self.__port__ = peer_port

    def connected_to_port(self) -> BaseSwitchPort | None:
        return self.__port__

    def set_ethernet_bus(self, eth_bus: BaseEthernetBus) -> None:
        assert eth_bus is not None
        assert self.__eth_bus__ is None

        if self.__ctrl__ is not None or self.__eth_bus__ is not None:
            print(f"WARNING: SwitchPort {self.__portid__} adds eth bus but was connected before! Overwritting!")

        self.__eth_bus__ = eth_bus

    def connected_to_eth_bus(self) -> BaseEthernetBus | None:
        return self.__eth_bus__

    def set_connected_ctrl(self, peer_ctrl: BaseController) -> None:
        assert peer_ctrl is not None
        assert self.__ctrl__ is None

        if self.__port__ is not None or self.__eth_bus__ is not None:
            print(f"WARNING: SwitchPort {self.__portid__} adds ctrl to port but was connected before! Overwritting!")

        self.__ctrl__ = peer_ctrl
        peer_ctrl.set_switch_port(self)

    def connected_to_ecu_ctrl(self) -> BaseController | None:
        return self.__ctrl__

    def vlans(self) -> list[int]:
        vlans = []

        for vlan in self.__vlans__:
            vlanid = vlan.vlanid()
            if vlanid is None:
                vlans += [0]
            else:
                vlans += [vlanid]

        return sorted(vlans)

    def vlans_objs(self) -> list[BaseVLAN]:
        vlans = []

        for vlan in self.__vlans__:
            vlans.append(vlan)

        def key(x: BaseVLAN) -> int:
            vid = x.vlanid()
            return -1 if vid is None else vid

        return sorted(vlans, key=key)


class BaseSwitch(BaseItem):
    def __init__(self, name: str, ecu: BaseECU | None, ports: list[BaseSwitchPort]):
        self.__name__: str = name
        self.__ports__: list[BaseSwitchPort] = ports
        self.__ecu__: BaseECU | None = ecu

        if ecu is not None:
            ecu.add_switch(self)

        for port in ports:
            port.set_parent_switch(self)

    def name(self) -> str:
        return self.__name__

    def ecu(self) -> BaseECU | None:
        return self.__ecu__

    def ports(self) -> list[BaseSwitchPort]:
        return self.__ports__

    def key(self) -> str:
        ecu = self.ecu()
        if ecu is None:
            return f"None.{self.name()}"

        return f"{ecu.name()}.{self.name()}"


class BaseEthernetBus(BaseItem):
    def __init__(self, name: str, connected_ctrls: list[BaseController], switch_ports: list[BaseSwitchPort]):
        self.__name__: str = name
        self.__ctrls__: list[BaseController] = connected_ctrls
        self.__ports__: list[BaseSwitchPort] = switch_ports

        # connect the controllers to us!
        for ctrl in connected_ctrls:
            ctrl.set_eth_bus(self)

    def name(self) -> str:
        return self.__name__

    def connected_controllers(self) -> list[BaseController]:
        return self.__ctrls__

    def switch_ports(self) -> list[BaseSwitchPort]:
        return self.__ports__


class BaseECU(BaseItem):
    def __init__(self, name: str, controllers: list[BaseController]):
        self.__name__: str = name
        self.__controllers__: list[BaseController] = controllers
        self.__switches__: list[BaseSwitch] = []

        for c in controllers:
            c.set_ecu(self)

    def name(self) -> str:
        return self.__name__

    def controllers(self) -> list[BaseController]:
        return self.__controllers__

    def add_switch(self, switch: BaseSwitch) -> None:
        self.__switches__.append(switch)

    def switches(self) -> list[BaseSwitch]:
        return self.__switches__


class BaseController(BaseItem):
    def __init__(self, name: str, interfaces: list[BaseInterface]):
        self.__name__: str = name
        self.__interfaces__: list[BaseInterface] = interfaces
        self.__ecu__: BaseECU | None = None
        self.__peer_port__: BaseSwitchPort | None = None
        self.__eth_bus__: BaseEthernetBus | None = None

        for i in interfaces:
            i.set_controller(self)

    def name(self) -> str:
        return self.__name__

    def interfaces(self) -> list[BaseInterface]:
        return self.__interfaces__

    def vlans(self) -> list[int]:
        vlans = []

        for interface in self.__interfaces__:
            if interface.vlanid() is None:
                vlans += [0]
            else:
                vlans += [int(interface.vlanid())]

        return sorted(vlans)

    def set_ecu(self, ecu: BaseECU) -> None:
        self.__ecu__ = ecu

    def ecu(self) -> BaseECU | None:
        return self.__ecu__

    def set_switch_port(self, peer_port: BaseSwitchPort) -> None:
        assert self.__peer_port__ is None
        assert self.__eth_bus__ is None
        self.__peer_port__ = peer_port

    def get_switch_port(self) -> BaseSwitchPort | None:
        return self.__peer_port__

    def set_eth_bus(self, eth_buf: BaseEthernetBus) -> None:
        assert self.__peer_port__ is None
        assert self.__eth_bus__ is None
        self.__eth_bus__ = eth_buf

    def get_eth_bus(self) -> BaseEthernetBus | None:
        return self.__eth_bus__


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
        self.__vlanname__: str = vlanname
        self.__sockets__: list[BaseSocket] = sockets
        self.__ips__: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []

        for ip in ips:
            try:
                self.__ips__.append(ipaddress.ip_address(ip))
            except ValueError:
                print(f"ERROR: parser return illegal IP Address {ip}! We will need to skip that.")

        self.__controller__: BaseController | None = None

        if vlanid is None:
            self.__vlanid__: int = 0
        else:
            self.__vlanid__ = int(vlanid)

        for s in sockets:
            s.set_interface(self)

        self.__frame_triggerings_in__: dict[str, BaseFrameTriggering] = frame_triggerings_in
        self.__frame_triggerings_out__: dict[str, BaseFrameTriggering] = frame_triggerings_out

        self.__flexray_channel__: int | None = fr_channel

    def vlanname(self) -> str:
        return self.__vlanname__

    def vlanid(self) -> int:
        return self.__vlanid__

    def ips(self) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
        return self.__ips__

    def ips_without_socket(self) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
        tmp = []
        for socket in self.__sockets__:
            tmp.append(socket.ip())

        ret = []
        for ip in self.__ips__:
            if ip not in tmp:
                ret.append(ip)

        return ret

    def sockets(self) -> list[BaseSocket]:
        return self.__sockets__

    def set_controller(self, controller: BaseController) -> None:
        self.__controller__ = controller

    def controller(self) -> BaseController | None:
        return self.__controller__

    def frame_triggerings_in(self) -> dict[str, BaseFrameTriggering]:
        return self.__frame_triggerings_in__

    def frame_triggerings_out(self) -> dict[str, BaseFrameTriggering]:
        return self.__frame_triggerings_out__

    def flexray_channel(self) -> int | None:
        return self.__flexray_channel__

    def is_can(self) -> bool:
        for trig in self.__frame_triggerings_in__.values():
            if trig.is_can():
                return True

        for trig in self.__frame_triggerings_out__.values():
            if trig.is_can():
                return True

        return False

    def is_flexray(self) -> bool:
        for trig in self.__frame_triggerings_in__.values():
            if trig.is_flexray():
                return True

        for trig in self.__frame_triggerings_out__.values():
            if trig.is_flexray():
                return True

        return False

    def is_ethernet(self) -> bool:
        for trig in self.__frame_triggerings_in__.values():
            if trig.is_ethernet():
                return True

        for trig in self.__frame_triggerings_out__.values():
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
        self.__name__: str = name
        self.__ip__: str = ip

        try:
            self.__ipaddress__: ipaddress.IPv4Address | ipaddress.IPv6Address | None = ipaddress.ip_address(ip)
        except ValueError:
            self.__ipaddress__ = None

        self.__proto__: int | str = proto
        self.__portnumber__: int = int(portnumber)
        self.__instances__: list[SOMEIPBaseServiceInstance] | None = serviceinstances
        self.__instanceclients__: list[SOMEIPBaseServiceInstanceClient] | None = serviceinstanceclients
        self.__ehs__: list[SOMEIPBaseServiceEventgroupSender] | None = eventhandlers
        self.__cegs__: list[SOMEIPBaseServiceEventgroupReceiver] | None = eventgroupreceivers
        self.__pdus_in__: list[BaseAbstractPDU] = []
        self.__pdus_out__: list[BaseAbstractPDU] = []
        self.__interface__: BaseInterface | None = None

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
            self.__name__ == other.__name__
            and self.__ip__ == other.__ip__
            and self.__ipaddress__ == other.__ipaddress__
            and self.__proto__ == other.__proto__
            and self.__portnumber__ == other.__portnumber__
            and self_if != other_if
        )

    def name(self) -> str:
        return self.__name__

    def ip(self) -> str:
        return self.__ip__

    def is_ipv4(self) -> bool:
        return isinstance(self.__ipaddress__, ipaddress.IPv4Address)

    def is_ipv6(self) -> bool:
        return isinstance(self.__ipaddress__, ipaddress.IPv6Address)

    def is_multicast(self) -> bool:
        return self.__ipaddress__ is not None and self.__ipaddress__.is_multicast

    def proto(self) -> int | str:
        return self.__proto__

    def portnumber(self) -> int:
        return self.__portnumber__

    def instances(self) -> list[SOMEIPBaseServiceInstance] | None:
        return self.__instances__

    def serviceinstanceclients(self) -> list[SOMEIPBaseServiceInstanceClient] | None:
        return self.__instanceclients__

    def eventhandlers(self) -> list[SOMEIPBaseServiceEventgroupSender] | None:
        return self.__ehs__

    def eventgroupreceivers(self) -> list[SOMEIPBaseServiceEventgroupReceiver] | None:
        return self.__cegs__

    def add_incoming_pdu(self, pdu: BaseAbstractPDU) -> None:
        if pdu not in self.__pdus_in__:
            self.__pdus_in__.append(pdu)

    def incoming_pdus(self) -> list[BaseAbstractPDU]:
        return self.__pdus_in__

    def add_outgoing_pdu(self, pdu: BaseAbstractPDU) -> None:
        if pdu not in self.__pdus_out__:
            self.__pdus_out__.append(pdu)

    def outgoing_pdus(self) -> list[BaseAbstractPDU]:
        return self.__pdus_out__

    def set_interface(self, interface: BaseInterface) -> None:
        self.__interface__ = interface

    def interface(self) -> BaseInterface | None:
        return self.__interface__


class SOMEIPBaseServiceInstance(BaseItem):
    def __init__(self, service: SOMEIPBaseService, instanceid: int, protover: int):
        self.__service__: SOMEIPBaseService = service
        self.__instanceid__: int = int(instanceid)
        self.__protover__: int = int(protover)
        self.__socket__: BaseSocket | None = None

        self.__clients__: list[SOMEIPBaseServiceInstanceClient] = []
        self.__eventgroup_sender__: list[SOMEIPBaseServiceEventgroupSender] = []
        self.__eventgroup_receiver__: list[SOMEIPBaseServiceEventgroupReceiver] = []

        service.add_instance(self)

    def service(self) -> SOMEIPBaseService:
        return self.__service__

    def instanceid(self) -> int:
        return self.__instanceid__

    def protover(self) -> int:
        return self.__protover__

    def serviceinstanceclients(self) -> list[SOMEIPBaseServiceInstanceClient]:
        return self.__clients__

    def addclient(self, client: SOMEIPBaseServiceInstanceClient) -> None:
        if client not in self.__clients__:
            self.__clients__.append(client)

    def eventgroupsender(self) -> list[SOMEIPBaseServiceEventgroupSender]:
        return self.__eventgroup_sender__

    def addeventgroupsender(self, eh: SOMEIPBaseServiceEventgroupSender) -> None:
        if eh not in self.__eventgroup_sender__:
            self.__eventgroup_sender__.append(eh)

    def eventgroupreceiver(self) -> list[SOMEIPBaseServiceEventgroupReceiver]:
        return self.__eventgroup_receiver__

    def addeventgroupreceiver(self, ceg: SOMEIPBaseServiceEventgroupReceiver) -> None:
        if ceg not in self.__eventgroup_receiver__:
            self.__eventgroup_receiver__.append(ceg)

    def setsocket(self, socket: BaseSocket) -> None:
        self.__socket__ = socket

    def socket(self) -> BaseSocket | None:
        return self.__socket__


class SOMEIPBaseServiceInstanceClient(BaseItem):
    def __init__(self, service: SOMEIPBaseService, instanceid: int, protover: int, instance: SOMEIPBaseServiceInstance | None):
        self.__service__: SOMEIPBaseService = service
        self.__instanceid__: int = int(instanceid)
        self.__protover__: int = int(protover)
        self.__instance__: SOMEIPBaseServiceInstance | None = instance
        self.__socket__: BaseSocket | None = None

        if instance is not None:
            instance.addclient(self)

    def service(self) -> SOMEIPBaseService:
        return self.__service__

    def instanceid(self) -> int:
        return self.__instanceid__

    def protover(self) -> int:
        return self.__protover__

    def instance(self) -> SOMEIPBaseServiceInstance | None:
        return self.__instance__

    def setsocket(self, socket: BaseSocket) -> None:
        self.__socket__ = socket

    def socket(self) -> BaseSocket | None:
        return self.__socket__


class SOMEIPBaseServiceEventgroupSender(BaseItem):
    def __init__(self, serviceinstance: SOMEIPBaseServiceInstance, eventgroupid: int):
        self.__si__: SOMEIPBaseServiceInstance = serviceinstance
        self.__eventgroupid__: int = int(eventgroupid)
        self.__eventgroupreceivers__: list[SOMEIPBaseServiceEventgroupReceiver] = []
        self.__socket__: BaseSocket | None = None

    def serviceinstance(self) -> SOMEIPBaseServiceInstance:
        return self.__si__

    def eventgroupid(self) -> int:
        return self.__eventgroupid__

    def eventgroupreceivers(self) -> list[SOMEIPBaseServiceEventgroupReceiver]:
        return self.__eventgroupreceivers__

    def addreceiver(self, receiver: SOMEIPBaseServiceEventgroupReceiver) -> None:
        if receiver not in self.__eventgroupreceivers__:
            self.__eventgroupreceivers__.append(receiver)

    def setsocket(self, socket: BaseSocket) -> None:
        self.__socket__ = socket

    def socket(self) -> BaseSocket | None:
        return self.__socket__


class SOMEIPBaseServiceEventgroupReceiver(BaseItem):
    def __init__(
        self,
        serviceinstance: SOMEIPBaseServiceInstance,
        eventgroupid: int,
        sender: SOMEIPBaseServiceEventgroupSender | None,
    ):
        self.__si__: SOMEIPBaseServiceInstance = serviceinstance
        self.__eventgroupid__: int = int(eventgroupid)
        self.__sender__: SOMEIPBaseServiceEventgroupSender | None = sender
        self.__socket__: BaseSocket | None = None

        if sender is not None:
            sender.addreceiver(self)

    def serviceinstance(self) -> SOMEIPBaseServiceInstance:
        return self.__si__

    def eventgroupid(self) -> int:
        return self.__eventgroupid__

    def sender(self) -> SOMEIPBaseServiceEventgroupSender | None:
        return self.__sender__

    def setsocket(self, socket: BaseSocket) -> None:
        self.__socket__ = socket

    def socket(self) -> BaseSocket | None:
        return self.__socket__


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
        self.__name__: str = name
        self.__serviceid__: int = int(serviceid)
        self.__major__: int = int(majorver)
        self.__minor__: int = int(minorver)

        self.__methods__: dict[int, SOMEIPBaseServiceMethod] = methods
        self.__events__: dict[int, SOMEIPBaseServiceEvent] = events
        self.__fields__: dict[int, SOMEIPBaseServiceField] = fields
        self.__eventgroups__: dict[int, SOMEIPBaseServiceEventgroup] = eventgroups

        self.__instances__: list[SOMEIPBaseServiceInstance] = []

    def serviceid(self) -> int:
        return self.__serviceid__

    def majorversion(self) -> int:
        return self.__major__

    def minorversion(self) -> int:
        return self.__minor__

    def versionstring(self) -> str:
        return "%d.%d" % (self.__major__, self.__minor__)

    def name(self) -> str:
        return self.__name__

    def methods(self) -> dict[int, SOMEIPBaseServiceMethod]:
        return self.__methods__

    def method(self, mid: int) -> SOMEIPBaseServiceMethod | None:
        if mid in self.__methods__:
            return self.__methods__[mid]
        return None

    def events(self) -> dict[int, SOMEIPBaseServiceEvent]:
        return self.__events__

    def event(self, eid: int) -> SOMEIPBaseServiceEvent | None:
        if eid in self.__events__:
            return self.__events__[eid]
        return None

    def fields(self) -> dict[int, SOMEIPBaseServiceField]:
        return self.__fields__

    def field(self, fid: int) -> SOMEIPBaseServiceField | None:
        if fid in self.__fields__:
            return self.__fields__[fid]
        return None

    def eventgroups(self) -> dict[int, SOMEIPBaseServiceEventgroup]:
        return self.__eventgroups__

    def eventgroup(self, egid: int) -> SOMEIPBaseServiceEventgroup | None:
        if egid in self.__eventgroups__:
            return self.__eventgroups__[egid]
        return None

    def add_instance(self, serviceinstance: SOMEIPBaseServiceInstance) -> None:
        self.__instances__.append(serviceinstance)

    def remove_instance(self, serviceinstance: SOMEIPBaseServiceInstance) -> None:
        self.__instances__.remove(serviceinstance)

    def instances(self) -> list[SOMEIPBaseServiceInstance]:
        return self.__instances__


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
        self.__name__: str = name
        self.__methodid__: int = methodid
        self.__calltype__: CallSemantic = calltype
        self.__reliable__: bool = relia

        self.__inparams__: list[SOMEIPBaseParameter] = inparams
        self.__outparams__: list[SOMEIPBaseParameter] = outparams

        self.__reqdebouncetime__: int = reqdebounce
        self.__reqretentiontime___: int = reqmaxretention
        self.__resretentiontime___: int = resmaxretention
        self.__tlv__: bool = tlv

    def methodid(self) -> int:
        return self.__methodid__

    def name(self) -> str:
        return self.__name__

    def calltype(self) -> CallSemantic:
        return self.__calltype__

    def reliable(self) -> bool:
        return self.__reliable__

    def inparams(self) -> list[SOMEIPBaseParameter]:
        return self.__inparams__

    def outparams(self) -> list[SOMEIPBaseParameter]:
        return self.__outparams__

    def size_min_in(self) -> int:
        ret = 0
        for p in self.__inparams__:
            ret += p.size_min_bits()
        return bits_to_bytes(ret)

    def size_max_in(self) -> int:
        ret = 0
        for p in self.__inparams__:
            ret += p.size_max_bits()
        return bits_to_bytes(ret)

    def size_min_out(self) -> int:
        ret = 0
        for p in self.__outparams__:
            ret += p.size_min_bits()
        return bits_to_bytes(ret)

    def size_max_out(self) -> int:
        ret = 0
        for p in self.__outparams__:
            ret += p.size_max_bits()
        return bits_to_bytes(ret)

    def debounce_time_req(self) -> int:
        return self.__reqdebouncetime__

    def max_buffer_retention_time_req(self) -> int:
        return self.__reqretentiontime___

    def max_buffer_retention_time_res(self) -> int:
        return self.__resretentiontime___

    def legacy(self) -> bool:
        for p in self.__inparams__:
            if p.legacy():
                return True
        for p in self.__outparams__:
            if p.legacy():
                return True
        return False

    def tlv(self) -> bool:
        return self.__tlv__


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
        self.__name__: str = name
        self.__methodid__: int = methodid
        self.__reliable__: bool = relia
        self.__params__: list[SOMEIPBaseParameter] = params
        self.__debouncetime__: int = debouncetimerange
        self.__retentiontime___: int = maxbufferretentiontime
        self.__tlv__: bool = tlv

    def methodid(self) -> int:
        return self.__methodid__

    def name(self) -> str:
        return self.__name__

    def reliable(self) -> bool:
        return self.__reliable__

    def params(self) -> list[SOMEIPBaseParameter]:
        return self.__params__

    @staticmethod
    def size_min_in() -> int:
        return 0

    @staticmethod
    def size_max_in() -> int:
        return 0

    def size_min_out(self) -> int:
        ret = 0
        for p in self.__params__:
            ret += p.size_min_bits()
        return bits_to_bytes(ret)

    def size_max_out(self) -> int:
        ret = 0
        for p in self.__params__:
            ret += p.size_max_bits()
        return bits_to_bytes(ret)

    def debounce_time(self) -> int:
        return self.__debouncetime__

    def max_buffer_retention_time(self) -> int:
        return self.__retentiontime___

    def legacy(self) -> bool:
        for p in self.__params__:
            if p.legacy():
                return True
        return False

    def tlv(self) -> bool:
        return self.__tlv__


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
        self.__name__: str = name

        self.__getter__: SOMEIPBaseServiceMethod | None = None
        self.__setter__: SOMEIPBaseServiceMethod | None = None
        self.__notifier__: SOMEIPBaseServiceEvent | None = None
        self.__params__: list[SOMEIPBaseParameter] | None = params

        self.__minimum_id__: int | None = None

        self.__tlv__: bool = tlv

        assert params is not None

        if getterid is not None:
            self.__getter__ = config_factory.create_someip_service_method(
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
            self.__setter__ = config_factory.create_someip_service_method(
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
            self.__notifier__ = config_factory.create_someip_service_event(
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

        self.__minimum_id__ = tmp[0]

        if self.__minimum_id__ == -1:
            self.__minimum_id__ = None

    def name(self) -> str:
        return self.__name__

    def params(self) -> list[SOMEIPBaseParameter] | None:
        return self.__params__

    def getter(self) -> SOMEIPBaseServiceMethod | None:
        return self.__getter__

    def setter(self) -> SOMEIPBaseServiceMethod | None:
        return self.__setter__

    def notifier(self) -> SOMEIPBaseServiceEvent | None:
        return self.__notifier__

    def min_id(self) -> int | None:
        return self.__minimum_id__

    def notifierid(self) -> int | None:
        if self.__notifier__ is None:
            return None
        return self.__notifier__.methodid()

    def id(self) -> int | None:
        if self.notifierid() is not None:
            return self.notifierid()
        return self.min_id()

    def size_min_in(self) -> int:
        assert self.__params__ is not None
        ret = 0
        for p in self.__params__:
            ret += p.size_min_bits()
        return bits_to_bytes(ret)

    def size_max_in(self) -> int:
        assert self.__params__ is not None
        ret = 0
        for p in self.__params__:
            ret += p.size_max_bits()
        return bits_to_bytes(ret)

    def size_min_out(self) -> int:
        assert self.__params__ is not None
        ret = 0
        for p in self.__params__:
            ret += p.size_min_bits()
        return bits_to_bytes(ret)

    def size_max_out(self) -> int:
        assert self.__params__ is not None
        ret = 0
        for p in self.__params__:
            ret += p.size_max_bits()
        return bits_to_bytes(ret)

    def legacy(self) -> bool:
        if self.__params__ is None:
            return False

        for p in self.__params__:
            if p.legacy():
                return True

        return False

    def tlv(self) -> bool:
        return self.__tlv__


class SOMEIPBaseServiceEventgroup(BaseItem):
    def __init__(self, name: str, egid: int, eventids: list[int], fieldids: list[int]):
        self.__name__: str = name
        self.__id__: int = int(egid)
        self.__eventids__: list[int] = eventids
        self.__fieldids__: list[int] = fieldids

    def name(self) -> str:
        return self.__name__

    def id(self) -> int:
        return self.__id__

    def eventids(self) -> list[int]:
        return self.__eventids__

    def fieldids(self) -> list[int]:
        return self.__fieldids__


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
        self.__position__: int = int(position)
        self.__name__: str = name
        self.__desc__: str | None = desc
        self.__mandatory__: bool = mandatory
        self.__datatype__: SOMEIPBaseDatatype | None = datatype
        self.__signal__: BaseSignal | None = signal

    def position(self) -> int:
        return self.__position__

    def name(self) -> str:
        return self.__name__

    def desc(self) -> str | None:
        return self.__desc__

    def mandatory(self) -> bool:
        return self.__mandatory__

    def datatype(self) -> SOMEIPBaseDatatype | None:
        return self.__datatype__

    def signal(self) -> BaseSignal | None:
        return self.__signal__

    def size_min_bits(self) -> int:
        assert self.__datatype__ is not None
        return self.__datatype__.size_min_bits()

    def size_max_bits(self) -> int:
        assert self.__datatype__ is not None
        return self.__datatype__.size_max_bits()

    def legacy(self) -> bool:
        if self.__signal__ is not None:
            return True
        if self.__datatype__ is None:
            return False
        return self.__datatype__.legacy()


class SOMEIPBaseParameterBasetype(BaseItem):
    def __init__(self, name: str, datatype: str, bigendian: bool, bitlength_basetype: int, bitlength_encoded_type: int):
        self.__name__: str = name
        self.__datatype__: str = datatype
        self.__bigendian__: bool = bigendian
        self.__bitlength_basetype__: int = int(bitlength_basetype)
        self.__bitlength_encoded_type__: int = int(bitlength_encoded_type)

    def name(self) -> str:
        return self.__name__

    def datatype(self) -> str:
        return self.__datatype__

    def bigendian(self) -> bool:
        return self.__bigendian__

    def bitlength_basetype(self) -> int:
        return self.__bitlength_basetype__

    def bitlength_encoded_type(self) -> int:
        return self.__bitlength_encoded_type__

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
        return self.__bitlength_encoded_type__

    def size_max_bits(self) -> int:
        return self.__bitlength_encoded_type__


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
        self.__name__: str = name
        self.__chartype__: str = chartype
        self.__bigendian__: bool = bigendian
        self.__lowerlimit__: int = int(lowerlimit)
        self.__upperlimit__: int = int(upperlimit)
        self.__termination__: str | None = termination

        if length_of_length is None or length_of_length == -1:
            if lowerlimit == upperlimit:
                self.__lengthOfLength__: int = 0
            else:
                self.__lengthOfLength__ = 32  # SOME/IP default
        else:
            self.__lengthOfLength__ = int(length_of_length)

        self.__padTo__ = int(pad_to)

    def name(self) -> str:
        return self.__name__

    def chartype(self) -> str:
        return self.__chartype__

    def bigendian(self) -> bool:
        return self.__bigendian__

    def lowerlimit(self) -> int:
        return self.__lowerlimit__

    def upperlimit(self) -> int:
        return self.__upperlimit__

    def termination(self) -> str | None:
        return self.__termination__

    def length_of_length(self) -> int:
        return self.__lengthOfLength__

    def pad_to(self) -> int:
        return self.__padTo__

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
        return self.__lengthOfLength__ + 8 * self.__lowerlimit__

    def size_max_bits(self) -> int:
        # TODO: double check, if this is based on bytes or chars
        return self.__lengthOfLength__ + 8 * self.__upperlimit__


class SOMEIPBaseParameterArray(BaseItem):
    def __init__(self, name: str, dims: dict[int, SOMEIPBaseParameterArrayDim], child: SOMEIPBaseDatatype):
        self.__name__: str = name
        self.__dims__: dict[int, SOMEIPBaseParameterArrayDim] = dims
        self.__child__: SOMEIPBaseDatatype = child

    def name(self) -> str:
        return self.__name__

    def dims(self) -> dict[int, SOMEIPBaseParameterArrayDim]:
        return self.__dims__

    def child(self) -> SOMEIPBaseDatatype:
        return self.__child__

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, self.__class__):
            return False

        return self.name() == other.name() and self.dims() == other.dims() and self.child() == other.child()

    def size_min_bits(self) -> int:
        ret = self.__child__.size_min_bits()

        # todo: is this the right order?
        for dim in self.__dims__.values():
            ret = dim.calc_size_min_bits(ret)

        return ret

    def size_max_bits(self) -> int:
        ret = self.__child__.size_min_bits()

        # todo: is this the right order?
        for dim in self.__dims__.values():
            ret = dim.calc_size_max_bits(ret)

        return ret


class SOMEIPBaseParameterArrayDim(BaseItem):
    def __init__(self, dim: int, lowerlimit: int, upperlimit: int, length_of_length: int | None, pad_to: int):
        self.__dim__: int = int(dim)
        self.__lowerlimit__: int = int(lowerlimit)
        self.__upperlimit__: int = int(upperlimit)
        if length_of_length is None or length_of_length == -1:
            if lowerlimit == upperlimit:
                self.__lengthOfLength__: int = 0
            else:
                self.__lengthOfLength__ = 32  # SOME/IP default
        else:
            self.__lengthOfLength__ = int(length_of_length)

        self.__padTo__ = int(pad_to)

    def dim(self) -> int:
        return self.__dim__

    def lowerlimit(self) -> int:
        return self.__lowerlimit__

    def upperlimit(self) -> int:
        return self.__upperlimit__

    def length_of_length(self) -> int:
        return self.__lengthOfLength__

    def pad_to(self) -> int:
        return self.__padTo__

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
        ret = self.__lowerlimit__ * inner_length
        # XXX - padTo completly untested since export do not have BIT-ALIGNMENT set (its counted in bits)
        if self.__padTo__ > 0:
            ret += ret % self.__padTo__

        return self.__lengthOfLength__ + ret

    def calc_size_max_bits(self, inner_length: int) -> int:
        ret = self.__upperlimit__ * inner_length
        # XXX - padTo completly untested since export do not have BIT-ALIGNMENT set (its counted in bits)
        if self.__padTo__ > 0:
            ret += ret % self.__padTo__

        return self.__lengthOfLength__ + ret


class SOMEIPBaseParameterStruct(BaseItem):
    def __init__(
        self,
        name: str,
        length_of_length: int | None,
        pad_to: int,
        members: dict[int, SOMEIPBaseParameterStructMember],
        tlv: bool = False,
    ):
        self.__name__: str = name
        self.__members__: dict[int, SOMEIPBaseParameterStructMember] = members
        self.__tlv__: bool = tlv

        if length_of_length is None or length_of_length == -1:
            self.__lengthOfLength__: int = 0
        else:
            self.__lengthOfLength__ = int(length_of_length)

        self.__padTo__ = int(pad_to)

    def name(self) -> str:
        return self.__name__

    def members(self) -> dict[int, SOMEIPBaseParameterStructMember]:
        return self.__members__

    def length_of_length(self) -> int:
        return self.__lengthOfLength__

    def pad_to(self) -> int:
        return self.__padTo__

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
        ret = self.__lengthOfLength__
        for m in self.__members__.values():
            ret += m.child().size_min_bits()
        return ret

    def size_max_bits(self) -> int:
        ret = self.__lengthOfLength__
        for m in self.__members__.values():
            ret += m.child().size_max_bits()
        return ret

    def legacy(self) -> bool:
        for m in self.__members__.values():
            if m.legacy():
                return True
        return False

    def tlv(self) -> bool:
        return self.__tlv__


class SOMEIPBaseParameterStructMember(BaseItem):
    def __init__(
        self,
        position: int,
        name: str,
        mandatory: bool,
        child: SOMEIPBaseDatatype,
        signal: BaseSignal | None,
    ):
        self.__name__: str = name
        self.__position__: int = int(position)
        self.__mandatory__: bool = mandatory
        self.__child__: SOMEIPBaseDatatype = child
        self.__signal__: BaseSignal | None = signal

    def name(self) -> str:
        return self.__name__

    def position(self) -> int:
        return self.__position__

    def update_position(self, p: int) -> None:
        self.__position__ = p

    def mandatory(self) -> bool:
        return self.__mandatory__

    def child(self) -> SOMEIPBaseDatatype:
        return self.__child__

    def signal(self) -> BaseSignal | None:
        return self.__signal__

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
        if self.__signal__ is not None:
            return True
        return False


class SOMEIPBaseParameterTypedef(BaseItem):
    def __init__(self, name: str, name2: str, child: SOMEIPBaseDatatype):
        self.__name__: str = name
        self.__name2__: str = name2
        self.__child__: SOMEIPBaseDatatype = child

    def name(self) -> str:
        return self.__name__

    def name2(self) -> str:
        return self.__name2__

    def child(self) -> SOMEIPBaseDatatype:
        return self.__child__

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, self.__class__):
            return False

        return self.name() == other.name() and self.name2() == other.name2() and self.child() == other.child()

    def size_min_bits(self) -> int:
        return self.__child__.size_min_bits()

    def size_max_bits(self) -> int:
        return self.__child__.size_max_bits()


class SOMEIPBaseParameterEnumeration(BaseItem):
    def __init__(self, name: str, items: list[SOMEIPBaseParameterEnumerationItem], child: SOMEIPBaseDatatype):
        self.__name__: str = name
        self.__items__: list[SOMEIPBaseParameterEnumerationItem] = items
        self.__child__: SOMEIPBaseDatatype = child

    def name(self) -> str:
        return self.__name__

    def items(self) -> list[SOMEIPBaseParameterEnumerationItem]:
        return self.__items__

    def child(self) -> SOMEIPBaseDatatype:
        return self.__child__

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, self.__class__):
            return False

        return self.name() == other.name() and self.items() == other.items() and self.child() == other.child()

    def size_min_bits(self) -> int:
        return self.__child__.size_min_bits()

    def size_max_bits(self) -> int:
        return self.__child__.size_max_bits()


class SOMEIPBaseParameterEnumerationItem(BaseItem):
    def __init__(self, value: int, name: str, desc: str | None):
        self.__name__: str = name
        self.__desc__: str | None = desc
        self.__value__: int = int(value)

    def name(self) -> str:
        return self.__name__

    def desc(self) -> str | None:
        return self.__desc__

    def value(self) -> int:
        return self.__value__

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
        self.__name__: str = name
        self.__members__: dict[int, SOMEIPBaseParameterUnionMember] = members

        if length_of_length is None or length_of_length == -1:
            self.__lengthOfLength__: int = 32  # SOME/IP default
        else:
            self.__lengthOfLength__ = int(length_of_length)

        if length_of_type is None or length_of_type == -1:
            self.__lengthOfType__: int = 32  # SOME/IP default
        else:
            self.__lengthOfType__ = int(length_of_type)

        self.__padTo__ = int(pad_to)

    def name(self) -> str:
        return self.__name__

    def members(self) -> dict[int, SOMEIPBaseParameterUnionMember]:
        return self.__members__

    def length_of_length(self) -> int:
        return self.__lengthOfLength__

    def length_of_type(self) -> int:
        return self.__lengthOfType__

    def pad_to(self) -> int:
        return self.__padTo__

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

        for m in self.__members__.values():
            if ret == -1:
                ret = m.child().size_min_bits()
            else:
                if ret >= m.child().size_min_bits():
                    ret = m.child().size_min_bits()
            if self.__padTo__ > 0:
                ret += ret % self.pad_to()
        return self.__lengthOfLength__ + ret

    def size_max_bits(self) -> int:
        ret = -1

        for m in self.__members__.values():
            if ret == -1:
                ret = m.child().size_max_bits()
            else:
                if ret < m.child().size_max_bits():
                    ret = m.child().size_max_bits()
            if self.__padTo__ > 0:
                ret += ret % self.pad_to()
        return self.__lengthOfLength__ + ret


class SOMEIPBaseParameterUnionMember(BaseItem):
    def __init__(self, index: int, name: str, mandatory: bool, child: SOMEIPBaseDatatype):
        self.__name__: str = name
        self.__index__: int = int(index)
        self.__mandatory__: bool = mandatory
        self.__child__: SOMEIPBaseDatatype = child

    def name(self) -> str:
        return self.__name__

    def index(self) -> int:
        return self.__index__

    def mandatory(self) -> bool:
        return self.__mandatory__

    def child(self) -> SOMEIPBaseDatatype:
        return self.__child__

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, self.__class__):
            return False

        return (
            self.name() == other.name() and self.index() == other.index() and self.mandatory() == other.mandatory() and self.child() == other.child()
        )


class SOMEIPBaseParameterBitfield(BaseItem):
    def __init__(self, name: str, items: list[SOMEIPBaseParameterBitfieldItem], child: SOMEIPBaseDatatype):
        self.__name__: str = name
        self.__items__: list[SOMEIPBaseParameterBitfieldItem] = items
        self.__child__: SOMEIPBaseDatatype = child

    def name(self) -> str:
        return self.__name__

    def items(self) -> list[SOMEIPBaseParameterBitfieldItem]:
        return self.__items__

    def child(self) -> SOMEIPBaseDatatype:
        return self.__child__

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, self.__class__):
            return False

        return self.name() == other.name() and self.items() == other.items() and self.child() == other.child()

    def size_min_bits(self) -> int:
        return self.__child__.size_min_bits()

    def size_max_bits(self) -> int:
        return self.__child__.size_max_bits()


class SOMEIPBaseParameterBitfieldItem(BaseItem):
    def __init__(self, bit_number: int, name: str):
        self.__name__: str = name
        self.__bit_number__: int = int(bit_number)

    def name(self) -> str:
        return self.__name__

    def bit_number(self) -> int:
        return self.__bit_number__

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
        compu_const: list[object] | None,
        bit_length: int,
        min_length: int,
        max_length: int,
        basetype: str,
        basetypelen: int,
    ):
        self.__id__ = id
        self.__name__ = name
        self.__compu_scale__ = compu_scale
        self.__compu_consts__ = compu_const
        self.__bit_length__ = bit_length
        self.__min_length__ = min_length
        self.__max_length__ = max_length
        self.__basetype__ = basetype
        self.__basetypelen__ = basetypelen

    def id(self) -> str:
        return self.__id__

    def name(self) -> str:
        return self.__name__

    def compu_scale(self) -> tuple[float, float, float] | None:
        return self.__compu_scale__

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

    def compu_consts(self) -> list[object] | None:
        return self.__compu_consts__

    def bit_length(self) -> int:
        return self.__bit_length__

    def min_length(self) -> int:
        return self.__min_length__

    def max_length(self) -> int:
        return self.__max_length__

    def basetype(self) -> str:
        return self.__basetype__

    def basetype_length(self) -> int:
        return self.__basetypelen__

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
        self.__id__ = id
        self.__signal_ref__ = signal_ref
        self.__bit_position__ = bit_position
        self.__is_high_low_byte_order__ = is_high_low_byte_order
        self.__signal__: BaseSignal | None = None

    def add_signal(self, signal: BaseSignal) -> None:
        self.__signal__ = signal

    def bit_position(self) -> int:
        return self.__bit_position__

    def is_high_low_byte_order(self) -> bool:
        return self.__is_high_low_byte_order__

    def signal(self) -> BaseSignal | None:
        return self.__signal__


class BaseAbstractPDU(BaseItem):
    def __init__(self, id: str, short_name: str, byte_length: int, pdu_type: str):
        self.__id__ = id
        self.__short_name__ = short_name
        self.__byte_length__ = byte_length
        self.__pdu_type__ = pdu_type

    def id(self) -> str:
        return self.__id__

    def name(self) -> str:
        return self.__short_name__

    def byte_length(self) -> int:
        return self.__byte_length__

    def pdu_type(self) -> str:
        return self.__pdu_type__

    def is_multiplex_pdu(self) -> bool:
        return False


class BasePDU(BaseAbstractPDU):
    def __init__(self, id: str, short_name: str, byte_length: int, pdu_type: str, signal_instances: dict[int, BaseSignalInstance]):
        super(BasePDU, self).__init__(id, short_name, byte_length, pdu_type)

        self.__signal_instances__: dict[int, BaseSignalInstance] = signal_instances

    def signal_instances(self) -> dict[int, BaseSignalInstance]:
        return self.__signal_instances__

    def signal_instances_sorted_by_bit_position(self) -> list[BaseSignalInstance]:
        tmp: dict[int, BaseSignalInstance] = {}
        for si in self.__signal_instances__.values():
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
        pdu_instances: list[BasePDUInstance] | None,
        static_segs: list[BaseMultiplexPDUSegmentPosition],
        static_pdu: BasePDU | None,
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

        if static_pdu is None and len(static_segs) != 0:
            print(f"ERROR: PDU: {short_name} has Static Segments but no Static PDU!")
            raise ValueError

        if static_pdu is not None and len(static_segs) == 0:
            print(f"ERROR: PDU: {short_name} has a Static PDU but not Static Segments!")
            raise ValueError

        if len(static_segs) > 1:
            print(f"ERROR: We only support up to 1 Static Segment per PDU. " f"PDU {short_name} has {len(static_segs)}")
            raise ValueError

        self.__switch__: BaseMultiplexPDUSwitch | None = switch
        self.__segment_positions__: list[BaseMultiplexPDUSegmentPosition] = segment_positions
        self.__pdu_instances__: list[BasePDUInstance] | None = pdu_instances
        self.__static_segments__: list[BaseMultiplexPDUSegmentPosition] = static_segs
        self.__static_pdu__: BasePDU | None = static_pdu

    def switch(self) -> BaseMultiplexPDUSwitch | None:
        return self.__switch__

    def segment_positions(self) -> list[BaseMultiplexPDUSegmentPosition]:
        return self.__segment_positions__

    def pdu_instances(self) -> list[BasePDUInstance] | None:
        return self.__pdu_instances__

    def static_segments(self) -> list[BaseMultiplexPDUSegmentPosition]:
        return self.__static_segments__

    def static_pdu(self) -> BasePDU | None:
        return self.__static_pdu__

    def is_multiplex_pdu(self) -> bool:
        return True


class BaseMultiplexPDUSwitch(BaseItem):
    def __init__(self, id: str, short_name: str, bit_position: int, is_high_low_byte_order: bool, bit_length: int):
        self.__id__ = id
        self.__short_name__ = short_name
        self.__bit_position__ = bit_position
        self.__is_high_low_byte_order__ = is_high_low_byte_order
        self.__bit_length__ = bit_length

    def id(self) -> str:
        return self.__id__

    def name(self) -> str:
        return self.__short_name__

    def bit_position(self) -> int:
        return self.__bit_position__

    def is_high_low_byte_order(self) -> bool:
        return self.__is_high_low_byte_order__

    def bit_length(self) -> int:
        return self.__bit_length__


class BaseMultiplexPDUSegmentPosition(BaseItem):
    def __init__(self, bit_position: int, is_high_low_byte_order: bool, bit_length: int):
        self.__bit_position__ = bit_position
        self.__is_high_low_byte_order__ = is_high_low_byte_order
        self.__bit_length__ = bit_length

    def bit_position(self) -> int:
        return self.__bit_position__

    def is_high_low_byte_order(self) -> bool:
        return self.__is_high_low_byte_order__

    def bit_length(self) -> int:
        return self.__bit_length__


class BaseEthernetPDUInstance(BaseItem):
    def __init__(self, pdu_ref: str, header_id: int | None):
        self.__pdu_ref__ = pdu_ref
        self.__bit_position__ = 0
        self.__header_id__ = header_id
        self.__pdu_update_bit_position__ = None
        self.__pdu__: BaseAbstractPDU | None = None

    def add_pdu(self, pdu: BaseAbstractPDU) -> None:
        self.__pdu__ = pdu

    def pdu(self) -> BaseAbstractPDU | None:
        return self.__pdu__

    def bit_position(self) -> int:
        return self.__bit_position__

    def header_id(self) -> int | None:
        return self.__header_id__

    def pdu_update_bit_position(self) -> None:
        return self.__pdu_update_bit_position__


class BasePDUInstance(BaseItem):
    def __init__(self, id: str, pdu_ref: str, bit_position: int, is_high_low_byte_order: bool, pdu_update_bit_position: int | None):
        self.__id__ = id
        self.__pdu_ref__ = pdu_ref
        self.__bit_position__ = bit_position
        self.__is_high_low_byte_order__ = is_high_low_byte_order
        self.__pdu_update_bit_position__ = pdu_update_bit_position
        self.__pdu__: BaseAbstractPDU | None = None

    def pdu_ref(self) -> str:
        return self.__pdu_ref__

    def add_pdu(self, pdu: BaseAbstractPDU) -> None:
        self.__pdu__ = pdu

    def pdu(self) -> BaseAbstractPDU | None:
        return self.__pdu__

    def bit_position(self) -> int:
        return self.__bit_position__

    def pdu_update_bit_position(self) -> int | None:
        return self.__pdu_update_bit_position__


class BaseFrame(BaseItem):
    def __init__(self, id: str, short_name: str, byte_length: int, frame_type: str, pdu_instances: dict[str, BasePDUInstance]):
        self.__id__ = id
        self.__short_name__ = short_name
        self.__byte_length__ = byte_length
        self.__frame_type__ = frame_type
        self.__pdu_instances__ = pdu_instances

    def add_pdu_instance(self, pdu_instance: BasePDUInstance) -> None:
        self.__pdu_instances__[pdu_instance.pdu_ref()] = pdu_instance

    def id(self) -> str:
        return self.__id__

    def name(self) -> str:
        return self.__short_name__

    def byte_length(self) -> int:
        return self.__byte_length__

    def frame_type(self) -> str:
        return self.__frame_type__

    def pdu_instances(self) -> dict[str, BasePDUInstance]:
        return self.__pdu_instances__


class BaseFrameTriggering(BaseItem):
    def __init__(self, id: str, frame: BaseFrame):
        self.__id__ = id
        self.__frame__ = frame

    def id(self) -> str:
        return self.__id__

    def calc_key(self) -> str:
        return self.__id__

    def frame(self) -> BaseFrame:
        return self.__frame__

    def is_can(self) -> bool:
        return False

    def is_flexray(self) -> bool:
        return False

    def is_ethernet(self) -> bool:
        return False


class BaseFrameTriggeringCAN(BaseFrameTriggering):
    def __init__(self, id: str, frame: BaseFrame, can_id: int, is_extended_id: bool, is_can_fd: bool):
        super(BaseFrameTriggeringCAN, self).__init__(id, frame)

        self.__can_id__ = can_id
        self.__is_can_fd = is_can_fd
        self.__is_extended_id = is_extended_id

    def can_id(self) -> int:
        return self.__can_id__

    def calc_key(self) -> str:
        return f"CAN-0x{self.__can_id__:04x}"

    def is_can(self) -> bool:
        return True

    def is_extended_id(self) -> bool:
        return self.__is_extended_id

    def is_can_fd(self) -> bool:
        return self.__is_can_fd


class BaseFrameTriggeringFlexRay(BaseFrameTriggering):
    def __init__(self, id: str, frame: BaseFrame, slot_id: int, cycle_counter: int | None, base_cycle: int | None, cycle_repetition: int | None):
        super(BaseFrameTriggeringFlexRay, self).__init__(id, frame)

        self.__slot_id__ = slot_id
        self.__cycle_counter__ = cycle_counter
        self.__base_cycle__ = base_cycle
        self.__cycle_repetition__ = cycle_repetition

    def scheduling(self) -> tuple[int, int | None, int | None, int | None]:
        return (
            self.__slot_id__,
            self.__cycle_counter__,
            self.__base_cycle__,
            self.__cycle_repetition__,
        )

    def calc_key(self) -> str:
        tmp_cycle_counter = 0 if self.__cycle_counter__ is None else self.__cycle_counter__
        tmp_base_cycle = 0 if self.__base_cycle__ is None else self.__base_cycle__
        tmp_cycle_repetition = 0 if self.__cycle_repetition__ is None else self.__cycle_repetition__

        ret = f"FlexRay-0x{self.__slot_id__:04x}-0x{tmp_cycle_counter:04x}-0x{tmp_base_cycle:04x}-" f"0x{tmp_cycle_repetition:04x}"
        return ret

    def is_flexray(self) -> bool:
        return True
