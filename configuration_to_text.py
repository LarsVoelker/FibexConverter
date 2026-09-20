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

import argparse
import ipaddress
import os.path
import time
from typing import Any, cast

from configuration_base_classes import (
    BaseAbstractPDU,
    BaseConfigurationFactory,
    BaseController,
    BaseECU,
    BaseEthernetPDUInstance,
    BaseFrame,
    BaseFrameTriggering,
    BaseFrameTriggeringCAN,
    BaseFrameTriggeringFlexRay,
    BaseInterface,
    BaseMultiplexPDU,
    BaseMultiplexPDUSegmentPosition,
    BaseMultiplexPDUSwitch,
    BasePDU,
    BasePDUInstance,
    BaseSignal,
    BaseSignalInstance,
    BaseSocket,
    BaseSwitch,
    BaseSwitchPort,
    BaseVLAN,
    CallSemantic,
    SOMEIPBaseDatatype,
    SOMEIPBaseParameter,
    SOMEIPBaseParameterArray,
    SOMEIPBaseParameterArrayDim,
    SOMEIPBaseParameterBasetype,
    SOMEIPBaseParameterBitfield,
    SOMEIPBaseParameterBitfieldItem,
    SOMEIPBaseParameterEnumeration,
    SOMEIPBaseParameterEnumerationItem,
    SOMEIPBaseParameterString,
    SOMEIPBaseParameterStruct,
    SOMEIPBaseParameterStructMember,
    SOMEIPBaseParameterTypedef,
    SOMEIPBaseParameterUnion,
    SOMEIPBaseParameterUnionMember,
    SOMEIPBaseService,
    SOMEIPBaseServiceEvent,
    SOMEIPBaseServiceEventgroup,
    SOMEIPBaseServiceEventgroupReceiver,
    SOMEIPBaseServiceEventgroupSender,
    SOMEIPBaseServiceField,
    SOMEIPBaseServiceInstance,
    SOMEIPBaseServiceInstanceClient,
    SOMEIPBaseServiceMethod,
    ip_to_key,
    is_ip,
    is_ip_mcast,
    read_csv_to_dict,
)
from parser_dispatcher import (
    is_file_or_dir_valid,
    is_file_valid,
    parse_input_files,
    parser_formats,
)

g_gen_portid = False
g_show_datatype = False
g_skip_signal_based_communication = False


class SimpleConfigurationFactory(BaseConfigurationFactory):

    def __init__(self) -> None:
        self.__services__: dict[str, SOMEIPService] = dict()
        self.__services_long__: dict[str, SOMEIPService] = dict()
        self.__switches__: dict[str, Switch] = dict()
        self.__ecus__: dict[str, ECU] = dict()

        self.__codings__: dict[str, Any] = dict()
        self.__frame_triggerings__: dict[str, FrameTriggeringCAN | FrameTriggeringFlexRay] = dict()
        self.__frames__: dict[str, Frame] = dict()
        self.__pdus__: dict[str, PDU | MultiplexPDU] = dict()
        self.__channels__: dict[str, dict[str, Any]] = dict()

        self.__ipv4_netmasks__: dict[str, str] = {}
        self.__ipv6_prefix_lengths__: dict[str, str] = {}

    def create_switch(self, name: str, ecu: BaseECU | None, ports: list[BaseSwitchPort]) -> Switch:
        ret = Switch(name, ecu, ports)
        assert name not in self.__switches__
        self.__switches__[name] = ret
        return ret

    def create_switch_port(
        self, portid: str, ctrl: BaseController | None, port: BaseSwitchPort | None, default_vlan: int | None, vlans: list[BaseVLAN]
    ) -> SwitchPort:
        return SwitchPort(portid, ctrl, port, default_vlan, vlans)

    def create_ecu(self, name: str, controllers: list[BaseController]) -> ECU:
        ret = ECU(name, controllers)
        assert name not in self.__ecus__
        self.__ecus__[name] = ret
        return ret

    def create_controller(self, name: str, interfaces: list[BaseInterface]) -> Controller:
        ret = Controller(name, interfaces)
        return ret

    def create_interface(
        self,
        name: str,
        vlanid: int | None,
        ips: list[str],
        sockets: list[BaseSocket],
        input_frame_trigs: dict[str, BaseFrameTriggering],
        output_frame_trigs: dict[str, BaseFrameTriggering],
        fr_channel: int | None,
    ) -> Interface:
        ret = Interface(
            name,
            vlanid,
            ips,
            sockets,
            input_frame_trigs,
            output_frame_trigs,
            fr_channel,
        )
        channel = self.__channels__.setdefault(name, {})
        frame_triggerings = channel.setdefault("frametriggerings", {})

        for key, value in input_frame_trigs.items():
            frame_triggerings[key] = value
        for key, value in output_frame_trigs.items():
            frame_triggerings[key] = value

        return ret

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
    ) -> Socket:
        ret = Socket(
            name,
            ip,
            proto,
            portnumber,
            serviceinstances,
            serviceinstanceclients,
            eventhandlers,
            eventgroupreceivers,
        )
        return ret

    def create_someip_service_instance(self, service: SOMEIPBaseService, instanceid: int, protover: int) -> SOMEIPServiceInstance:
        ret = SOMEIPServiceInstance(service, instanceid, protover)
        return ret

    def create_someip_service_instance_client(
        self, service: SOMEIPBaseService, instanceid: int, protover: int, server: SOMEIPBaseServiceInstance | None
    ) -> SOMEIPServiceInstanceClient:
        ret = SOMEIPServiceInstanceClient(service, instanceid, protover, server)
        return ret

    def create_someip_service_eventgroup_sender(
        self, serviceinstance: SOMEIPBaseServiceInstance, eventgroupid: int
    ) -> SOMEIPServiceEventgroupSender:
        ret = SOMEIPServiceEventgroupSender(serviceinstance, eventgroupid)
        return ret

    def create_someip_service_eventgroup_receiver(
        self, serviceinstance: SOMEIPBaseServiceInstance, eventgroupid: int, sender: SOMEIPBaseServiceEventgroupSender | None
    ) -> SOMEIPServiceEventgroupReceiver:
        ret = SOMEIPServiceEventgroupReceiver(serviceinstance, eventgroupid, sender)
        return ret

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
    ) -> SOMEIPService:
        ret = SOMEIPService(name, serviceid, majorver, minorver, methods, events, fields, eventgroups)
        # print(f"Adding Service(Name: {name} ID: 0x{serviceid:04x} Ver: {majorver:d}.{minorver:d})")
        self.add_service(serviceid, majorver, minorver, ret)
        return ret

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
    ) -> SOMEIPServiceMethod:
        ret = SOMEIPServiceMethod(
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
        return ret

    def create_someip_service_event(
        self, name: str, methodid: int, relia: bool, params: list[SOMEIPBaseParameter], debounce: int = -1, maxretention: int = -1, tlv: bool = False
    ) -> SOMEIPServiceEvent:
        ret = SOMEIPServiceEvent(name, methodid, relia, params, debounce, maxretention, tlv)
        return ret

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
    ) -> SOMEIPServiceField:
        ret = SOMEIPServiceField(
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

    def create_someip_service_eventgroup(self, name: str, eid: int, eventids: list[int], fieldids: list[int]) -> SOMEIPServiceEventgroup:
        ret = SOMEIPServiceEventgroup(name, eid, eventids, fieldids)
        return ret

    def create_someip_parameter(
        self,
        position: int,
        name: str,
        desc: str | None,
        mandatory: bool,
        datatype: SOMEIPBaseDatatype | None,
        signal: BaseSignal | None,
    ) -> SOMEIPParameter:
        ret = SOMEIPParameter(position, name, desc, mandatory, datatype, signal)
        return ret

    def create_someip_parameter_basetype(
        self, name: str, datatype: str, bigendian: bool, bitlength_basetype: int, bitlength_encoded_type: int
    ) -> SOMEIPParameterBasetype:
        ret = SOMEIPParameterBasetype(name, datatype, bigendian, bitlength_basetype, bitlength_encoded_type)
        return ret

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
    ) -> SOMEIPParameterString:
        ret = SOMEIPParameterString(
            name,
            chartype,
            bigendian,
            lowerlimit,
            upperlimit,
            termination,
            length_of_length,
            pad_to,
        )
        return ret

    def create_someip_parameter_array(
        self, name: str, dims: dict[int, SOMEIPBaseParameterArrayDim], child: SOMEIPBaseDatatype
    ) -> SOMEIPParameterArray:
        ret = SOMEIPParameterArray(name, dims, child)
        return ret

    def create_someip_parameter_array_dim(
        self, dim: int, lowerlimit: int, upperlimit: int, length_of_length: int | None, pad_to: int
    ) -> SOMEIPParameterArrayDim:
        ret = SOMEIPParameterArrayDim(dim, lowerlimit, upperlimit, length_of_length, pad_to)
        return ret

    def create_someip_parameter_struct(
        self, name: str, length_of_length: int | None, pad_to: int, members: dict[int, SOMEIPBaseParameterStructMember], tlv: bool = False
    ) -> SOMEIPParameterStruct:
        ret = SOMEIPParameterStruct(name, length_of_length, pad_to, members, tlv)
        return ret

    def create_someip_parameter_struct_member(
        self, position: int, name: str, mandatory: bool, child: SOMEIPBaseDatatype, signal: BaseSignal | None
    ) -> SOMEIPParameterStructMember:
        ret = SOMEIPParameterStructMember(position, name, mandatory, child, signal)
        return ret

    def create_someip_parameter_typedef(self, name: str, name2: str, child: SOMEIPBaseDatatype) -> SOMEIPParameterTypedef:
        ret = SOMEIPParameterTypedef(name, name2, child)
        return ret

    def create_someip_parameter_enumeration(
        self, name: str, items: list[SOMEIPBaseParameterEnumerationItem], child: SOMEIPBaseDatatype
    ) -> SOMEIPParameterEnumeration:
        ret = SOMEIPParameterEnumeration(name, items, child)
        return ret

    def create_someip_parameter_enumeration_item(self, value: int, name: str, desc: str | None) -> SOMEIPParameterEnumerationItem:
        ret = SOMEIPParameterEnumerationItem(value, name, desc)
        return ret

    def create_someip_parameter_union(
        self,
        name: str,
        length_of_length: int | None,
        length_of_type: int | None,
        pad_to: int,
        members: dict[int, SOMEIPBaseParameterUnionMember],
    ) -> SOMEIPParameterUnion:
        ret = SOMEIPParameterUnion(name, length_of_length, length_of_type, pad_to, members)
        return ret

    def create_someip_parameter_union_member(self, index: int, name: str, mandatory: bool, child: SOMEIPBaseDatatype) -> SOMEIPParameterUnionMember:
        ret = SOMEIPParameterUnionMember(index, name, mandatory, child)
        return ret

    def create_someip_parameter_bitfield(
        self, name: str, items: list[SOMEIPBaseParameterBitfieldItem], child: SOMEIPBaseDatatype
    ) -> SOMEIPParameterBitfield:
        ret = SOMEIPParameterBitfield(name, items, child)
        return ret

    def create_someip_parameter_bitfield_item(self, bit_number: int, name: str) -> SOMEIPParameterBitfieldItem:
        ret = SOMEIPParameterBitfieldItem(bit_number, name)
        return ret

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
    ) -> Signal:
        ret = Signal(
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
        return ret

    def create_signal_instance(self, id: str, signal_ref: str, bit_position: int, is_high_low_byte_order: bool) -> SignalInstance:
        ret = SignalInstance(id, signal_ref, bit_position, is_high_low_byte_order)
        return ret

    def create_pdu(self, id: str, short_name: str, byte_length: int, pdu_type: str, signal_instances: dict[int, BaseSignalInstance]) -> PDU:
        ret = PDU(id, short_name, byte_length, pdu_type, signal_instances)

        if id in self.__pdus__:
            print(f"WARNING: Creating PDU with existing ID {id}!")

        self.__pdus__[id] = ret
        return ret

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
    ) -> MultiplexPDU:
        ret = MultiplexPDU(
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

        if id in self.__pdus__:
            print(f"WARNING: Creating Multiplex PDU with existing ID {id}!")
        self.__pdus__[id] = ret
        return ret

    def create_multiplex_switch(
        self, id: str, short_name: str, bit_position: int, is_high_low_byte_order: bool, bit_length: int
    ) -> MultiplexPDUSwitch:
        return MultiplexPDUSwitch(id, short_name, bit_position, is_high_low_byte_order, bit_length)

    def create_multiplex_segment_position(self, bit_position: int, is_high_low_byte_order: bool, bit_length: int) -> MultiplexPDUSegmentPosition:
        return MultiplexPDUSegmentPosition(bit_position, is_high_low_byte_order, bit_length)

    def create_ethernet_pdu_instance(self, pdu_ref: str, header_id: int | None) -> EthernetPDUInstance:
        return EthernetPDUInstance(pdu_ref, header_id)

    def create_pdu_instance(
        self, id: str, pdu_ref: str, bit_position: int, is_high_low_byte_order: bool, pdu_update_bit_position: int | None
    ) -> PDUInstance:
        ret = PDUInstance(id, pdu_ref, bit_position, is_high_low_byte_order, pdu_update_bit_position)
        return ret

    def create_frame(self, id: str, short_name: str, byte_length: int, frame_type: str, pdu_instances: dict[str, BasePDUInstance]) -> Frame:
        if short_name in self.__frames__:
            i = 1
            tmp_name = f"{short_name}__duplicate{i}"
            while i == 1 or tmp_name in self.__frames__:
                tmp_name = f"{short_name}__duplicate{i}"
                i += 1

            short_name = tmp_name

        assert short_name not in self.__frames__

        ret = Frame(id, short_name, byte_length, frame_type, pdu_instances)
        self.__frames__[short_name] = ret
        return ret

    def create_frame_triggering_can(self, id: str, frame_ref: BaseFrame, can_id: int, is_extended_id: bool, is_can_fd: bool) -> FrameTriggeringCAN:
        ret = FrameTriggeringCAN(id, frame_ref, can_id, is_extended_id, is_can_fd)

        self.__frame_triggerings__[id] = ret
        return ret

    def create_frame_triggering_flexray(
        self, id: str, frame_ref: BaseFrame, slot_id: int, cycle_counter: int | None, base_cycle: int | None, cycle_repetition: int | None
    ) -> FrameTriggeringFlexRay:
        ret = FrameTriggeringFlexRay(id, frame_ref, slot_id, cycle_counter, base_cycle, cycle_repetition)

        self.__frame_triggerings__[id] = ret
        return ret

    def add_service(self, serviceid: int, majorver: int, minorver: int, service: SOMEIPService) -> bool:
        sid = f"{serviceid:04x}-{majorver:02x}-{minorver:08x}"
        if sid in self.__services_long__:
            print(
                f"ERROR: Service (SID: 0x{serviceid:04x}, Major-Ver: {majorver:d}, " + f"Minor-Ver: {minorver:d}) already exists! Not overriding it!"
            )
            return False

        self.__services_long__[sid] = service

        sid = f"{serviceid:04x}-{majorver:02x}"
        if sid in self.__services__:
            print(
                f"ERROR: Service (SID: 0x{serviceid:04x}, Major-Ver: {majorver:d})"
                + f"already exists with a different Minor Version (not {minorver:d})! Not overriding it!"
            )
            return False

        self.__services__[sid] = service
        return True

    def get_service(self, serviceid: int, majorver: int, minorver: int | None = None) -> SOMEIPService | None:
        if minorver is None:
            sid = f"{serviceid:04x}-{majorver:02x}"
            if sid in self.__services__:
                return self.__services__[sid]
            else:
                return None
        else:
            sid = f"{serviceid:04x}-{majorver:02x}-{minorver:08x}"
            if sid in self.__services_long__:
                return self.__services_long__[sid]
            else:
                return None

    def add_ipv4_address_config(self, ip: str, netmask: str) -> None:
        self.__ipv4_netmasks__[ip] = netmask

    def get_ipv4_netmask(self, ip: str) -> str:
        try:
            return cast(str, self.__ipv4_netmasks__.get(str(ip)))
        except ValueError:
            return cast(str, None)

    def add_ipv6_address_config(self, ip: str, prefixlen: str) -> None:
        tmp = ipaddress.ip_address(ip).exploded
        self.__ipv6_prefix_lengths__[tmp] = prefixlen

    def get_ipv6_prefix_length(self, ip: str) -> str:
        try:
            tmp = ipaddress.ip_address(ip).exploded
            return cast(str, self.__ipv6_prefix_lengths__.get(tmp))
        except ValueError:
            return cast(str, None)

    def get_ipv4_netmask_or_ipv6_prefix_length(self, ip: str) -> str:
        if self.get_ipv4_netmask(ip) is not None:
            return f"/{self.get_ipv4_netmask(ip)}"

        if self.get_ipv6_prefix_length(ip) is not None:
            return f"/{self.get_ipv6_prefix_length(ip)}"

        return ""

    @staticmethod
    def dict_values_sorted_by_names(d: dict[str, Any]) -> list[Any]:
        keys = list(d.keys())
        keys.sort(key=lambda x: d[x].name())

        ret = []
        for k in keys:
            ret.append(d[k])

        return ret

    def __str__(self) -> str:
        ret = "Services: \n"
        for serviceid in sorted(self.__services__):
            ret += self.__services__[serviceid].str(2)

        if not g_skip_signal_based_communication:
            ret += "\nFrames: \n"
            for frame in self.dict_values_sorted_by_names(self.__frames__):
                ret += frame.str(2)

            ret += "\nPDUs: \n"
            for pdu in self.dict_values_sorted_by_names(self.__pdus__):
                ret += pdu.str(2)

        ret += "\nECUs: \n"
        for ecu in self.dict_values_sorted_by_names(self.__ecus__):
            ret += ecu.str(2, self)

        ret += "\nChannels/Busses/VLANs: \n"
        for name in sorted(self.__channels__):
            ret += f"  Channel {name}:\n"
            fts = self.__channels__[name]["frametriggerings"]
            for key in sorted(fts):
                ret += fts[key].str(4)
            ret += "\n"

        ret += "\nEthernet Topology: \n"
        for name in sorted(self.__switches__):
            ret += self.__switches__[name].str(2, self, print_ecu_name=True)

        return ret


class Switch(BaseSwitch):
    def str(self, indent: int, factory: SimpleConfigurationFactory, print_ecu_name: bool = False) -> str:
        ret = indent * " "
        tmp = f" of ECU {self.__ecu__.name()}" if self.__ecu__ is not None and print_ecu_name else ""
        ret += f"Switch {self.__name__}{tmp}\n"
        for port in cast(list[SwitchPort], self.__ports__):
            ret += port.str(indent + 2, factory)
        return ret


class SwitchPort(BaseSwitchPort):
    def str_vlans(self, indent: int) -> str:
        ret = ""

        for vlan in self.vlans_objs():
            ret += indent * " "
            ret += f"VLAN (ID: {vlan.vlanid_str()}, Prio: {vlan.priority()})\n"

        return ret

    def str(self, indent: int, factory: SimpleConfigurationFactory) -> str:
        ret = indent * " "
        ret += f"SwitchPort {self.portid(gen_name=g_gen_portid)} <-> "
        if self.__port__ is not None:
            sw = self.__port__.switch()
            tmp = f"of {sw.name()}" if sw is not None else ""
            ret += f"SwitchPort {self.__port__.portid(gen_name=g_gen_portid)} {tmp}\n"
        elif self.__ctrl__ is not None:
            ctrl_ecu = self.__ctrl__.ecu()
            assert ctrl_ecu is not None
            ret += f"Controller {self.__ctrl__.name()} of {ctrl_ecu.name()}\n"
        else:
            ret += "\n"

        ret += (indent + 2) * " "
        ret += "VLANs:\n"
        ret += self.str_vlans(indent + 4)
        return ret


class ECU(BaseECU):
    def str(self, indent: int, factory: SimpleConfigurationFactory) -> str:
        ret = indent * " "
        ret += f"ECU {self.__name__}\n"

        for c in sorted(cast(list[Controller], self.__controllers__), key=lambda x: x.name()):
            ret += c.str(indent + 2, factory)

        for s in sorted(cast(list[Switch], self.__switches__), key=lambda x: x.name()):
            ret += s.str(indent + 2, factory)

        return ret


class Controller(BaseController):
    def str(self, indent: int, factory: SimpleConfigurationFactory) -> str:
        ret = indent * " "
        ret += f"CTRL {self.__name__}\n"
        for i in sorted(cast(list[Interface], self.__interfaces__), key=lambda x: x.vlanname()):
            ret += i.str(indent + 2, factory)

        return ret


class Interface(BaseInterface):
    def str(self, indent: int, factory: SimpleConfigurationFactory) -> str:
        ret = indent * " "

        if self.__vlanid__ == 0:
            vlanstr = ""
        else:
            vlanstr = f" (VLAN-ID: 0x{self.__vlanid__:x})"
        ret += f"Interface/Channel {self.__vlanname__}{vlanstr}\n"
        for ip in sorted(self.ips(), key=lambda x: ip_to_key(str(x))):
            if is_ip(str(ip)) and not is_ip_mcast(str(ip)):
                ret += (indent + 2) * " "
                if ip.compressed in ("0.0.0.0", "::0", "::"):
                    ret += f"IP: {ip.compressed}\n"
                else:
                    ret += f"IP: {ip.compressed}{factory.get_ipv4_netmask_or_ipv6_prefix_length(str(ip))}\n"

        for s in sorted(cast(list[Socket], self.__sockets__), key=lambda x: (ip_to_key(x.ip()), x.portnumber())):
            ret += s.str(indent + 2)

        if self.__frame_triggerings_in__ is not None and len(self.__frame_triggerings_in__.keys()) > 0:
            ret += (indent + 2) * " "
            ret += "Input Frames:\n"
            for key in sorted(self.__frame_triggerings_in__.keys()):
                ret += cast(FrameTriggeringCAN | FrameTriggeringFlexRay, self.__frame_triggerings_in__[key]).str(indent + 4)

        if self.__frame_triggerings_out__ is not None and len(self.__frame_triggerings_out__.keys()) > 0:
            ret += (indent + 2) * " "
            ret += "Output Frames:\n"
            for key in sorted(self.__frame_triggerings_out__.keys()):
                ret += cast(FrameTriggeringCAN | FrameTriggeringFlexRay, self.__frame_triggerings_out__[key]).str(indent + 4)

        return ret


class Socket(BaseSocket):
    def str(self, indent: int) -> str:
        ret = indent * " "
        ret += f"Socket {self.__name__} {self.__ip__}:{self.__portnumber__}/{self.__proto__}\n"
        for inst in sorted(cast(list[SOMEIPServiceInstance], self.__instances__), key=lambda x: (x.service().serviceid(), x.instanceid())):
            ret += inst.str(indent + 2)
        for client in sorted(
            cast(list[SOMEIPServiceInstanceClient], self.__instanceclients__), key=lambda x: (x.service().serviceid(), x.instanceid())
        ):
            ret += client.str(indent + 2)
        for eh in sorted(
            cast(list[SOMEIPServiceEventgroupSender], self.__ehs__),
            key=lambda x: (x.serviceinstance().service().serviceid(), x.serviceinstance().instanceid(), x.eventgroupid()),
        ):
            ret += eh.str(indent + 2)
        if not self.is_multicast():
            for ceg in sorted(
                cast(list[SOMEIPServiceEventgroupReceiver], self.__cegs__),
                key=lambda x: (x.serviceinstance().service().serviceid(), x.serviceinstance().instanceid(), x.eventgroupid()),
            ):
                ret += ceg.str(indent + 2)

        if len(self.__pdus_in__) > 0:
            ret += (indent + 2) * " " + "PDUs in:\n"
            for p in sorted(cast(list[EthernetPDUInstance], self.__pdus_in__), key=lambda x: x.header_id() or 0):
                ret += p.str(indent + 4, show_signals=False)

        if len(self.__pdus_out__) > 0:
            ret += (indent + 2) * " " + "PDUs out:\n"
            for p in sorted(cast(list[EthernetPDUInstance], self.__pdus_out__), key=lambda x: x.header_id() or 0):
                ret += p.str(indent + 4, show_signals=False)

        return ret


class SOMEIPServiceInstance(SOMEIPBaseServiceInstance):
    def str(self, indent: int) -> str:
        ret = indent * " "
        ret += f"ServiceInstance Service-ID: 0x{self.__service__.serviceid():04x} "
        ret += f"Version: {self.__service__.versionstring()} "
        ret += f"Instance-ID: 0x{self.__instanceid__:04x} "
        ret += f"Protover: {self.__protover__:d}\n"
        return ret


class SOMEIPServiceInstanceClient(SOMEIPBaseServiceInstanceClient):
    def str(self, indent: int) -> str:
        ret = indent * " "
        ret += f"ServiceInstanceClient Service-ID: 0x{self.__service__.serviceid():04x} "
        ret += f"Version: {self.__service__.versionstring()} "
        ret += f"Instance-ID: 0x{self.__instanceid__:04x} "
        ret += f"Protover: {self.__protover__:d}\n"
        return ret


class SOMEIPServiceEventgroupSender(SOMEIPBaseServiceEventgroupSender):
    def str(self, indent: int) -> str:
        ret = indent * " "
        ret += f"EventgroupSender: Service-ID: 0x{self.__si__.service().serviceid():04x} "
        ret += f"Instance-ID: 0x{self.__si__.instanceid():04x} "
        ret += f"Eventgroup-ID: 0x{self.__eventgroupid__:04x}\n"
        return ret


class SOMEIPServiceEventgroupReceiver(SOMEIPBaseServiceEventgroupReceiver):
    def str(self, indent: int) -> str:
        ret = indent * " "
        ret += f"EventgroupReceiver: Service-ID: 0x{self.__si__.service().serviceid():04x} "
        ret += f"Instance-ID: 0x{self.__si__.instanceid():04x} "
        ret += f"Eventgroup-ID: 0x{self.__eventgroupid__:04x}\n"
        return ret


class SOMEIPService(SOMEIPBaseService):
    def str(self, indent: int) -> str:
        ret = indent * " "
        ret += f"Service {self.__name__} (id: 0x{self.__serviceid__:04x} ver: {self.__major__:d}.{self.__minor__:d})\n"

        for methodid in sorted(self.__methods__):
            ret += cast(SOMEIPServiceMethod, self.__methods__[methodid]).str(indent + 2)

        for eventsid in sorted(self.__events__):
            ret += cast(SOMEIPServiceEvent, self.__events__[eventsid]).str(indent + 2)

        for fieldid in sorted(self.__fields__, key=lambda x: (x is None, x)):
            ret += cast(SOMEIPServiceField, self.__fields__[fieldid]).str(indent + 2)

        for egid in sorted(self.__eventgroups__):
            ret += cast(SOMEIPServiceEventgroup, self.__eventgroups__[egid]).str(indent + 2)

        return ret


class SOMEIPServiceMethod(SOMEIPBaseServiceMethod):
    def str(self, indent: int) -> str:
        extra = ""
        if self.__reqdebouncetime__ >= 0:
            extra += f" debounce:{str(self.__reqdebouncetime__)}s"
        if self.__reqretentiontime___ >= 0:
            extra += f" max_request_retention:{str(self.__reqretentiontime___)}s"
        if self.__resretentiontime___ >= 0:
            extra += f" max_response_retention:{str(self.__resretentiontime___)}s"

        extra += " TLV" if self.__tlv__ else ""
        ret = indent * " "
        ret += f"Method {self.__name__} (id:0x{self.__methodid__:04x} type:{self.__calltype__} " + f"reli:{self.__reliable__}{extra})\n"

        ret += (indent + 2) * " "
        ret += "In Parameters: \n"
        for param in self.__inparams__:
            ret += cast(SOMEIPParameter, param).str(indent + 4)

        ret += (indent + 2) * " "
        ret += "Out Parameters: \n"
        for param in self.__outparams__:
            ret += cast(SOMEIPParameter, param).str(indent + 4)

        return ret


class SOMEIPServiceEvent(SOMEIPBaseServiceEvent):
    def str(self, indent: int) -> str:
        extra = ""
        if self.__debouncetime__ >= 0:
            extra += f" debounce:{str(self.__debouncetime__)}s"
        if self.__retentiontime___ >= 0:
            extra += f" max_retention:{str(self.__retentiontime___)}s"

        ret = indent * " "
        extra += ", TLV:True" if self.__tlv__ else ""
        if self.legacy():
            ret += f"Event {self.__name__} (id:0x{self.__methodid__:04x} reli:{self.__reliable__}{extra}, Legacy PDU)\n"
        else:
            ret += f"Event {self.__name__} (id:0x{self.__methodid__:04x} reli:{self.__reliable__}{extra})\n"

        for param in self.__params__:
            ret += cast(SOMEIPParameter, param).str(indent + 2)

        return ret


class SOMEIPServiceField(SOMEIPBaseServiceField):
    def str(self, indent: int) -> str:
        legacy = ""
        if self.legacy():
            legacy = ", Legacy PDU"

        ret = indent * " "
        ret += f"Field {self.__name__}{' TLV' if self.__tlv__ else ''}\n"

        indent += 2
        if self.__getter__ is not None:
            extra = ""
            if self.__getter__.debounce_time_req() >= 0:
                extra += f" debounce:{str(self.__getter__.debounce_time_req())}s"
            if self.__getter__.max_buffer_retention_time_req() >= 0:
                extra += f" max_request_retention:{str(self.__getter__.max_buffer_retention_time_req())}s"
            if self.__getter__.max_buffer_retention_time_res() >= 0:
                extra += f" max_response_retention:{str(self.__getter__.max_buffer_retention_time_res())}s"

            ret += indent * " "
            ret += f"Getter(id:0x{self.__getter__.methodid():04x} reli:{self.__getter__.reliable()}{extra}{legacy})\n"

        if self.__setter__ is not None:
            extra = ""
            if self.__setter__.debounce_time_req() >= 0:
                extra += f" debounce:{str(self.__setter__.debounce_time_req())}s"
            if self.__setter__.max_buffer_retention_time_req() >= 0:
                extra += f" max_request_retention:{str(self.__setter__.max_buffer_retention_time_req())}s"
            if self.__setter__.max_buffer_retention_time_res() >= 0:
                extra += f" max_response_retention:{str(self.__setter__.max_buffer_retention_time_res())}s"

            ret += indent * " "
            ret += f"Setter(id:0x{self.__setter__.methodid():04x} reli:{self.__setter__.reliable()}{extra}{legacy})\n"

        if self.__notifier__ is not None:
            extra = ""
            if self.__notifier__.__debouncetime__ >= 0:
                extra += f" debounce:{str(self.__notifier__.debounce_time())}s"
            if self.__notifier__.__retentiontime___ >= 0:
                extra += f" max_retention:{str(self.__notifier__.max_buffer_retention_time())}s"
            ret += indent * " "
            ret += f"Notifier(id:0x{self.__notifier__.methodid():04x} reli:{self.__notifier__.reliable()}{extra}" f"{legacy})\n"

        ret += indent * " "
        ret += "Parameters:\n"
        for param in cast(list[SOMEIPBaseParameter], self.__params__):
            if param is not None:
                ret += cast(SOMEIPParameter, param).str(indent + 2)

        return ret


class SOMEIPServiceEventgroup(SOMEIPBaseServiceEventgroup):
    def str(self, indent: int) -> str:
        ret = indent * " "
        ret += f"Eventgroup {self.__name__} (id: 0x{self.__id__:04x})\n"

        if len(self.__eventids__) > 0:
            ret += (2 + indent) * " "
            ret += "Events: "
            first = True
            # ordered and unique
            for eid in sorted(set(self.__eventids__)):
                if not first:
                    ret += ", "
                else:
                    first = False
                ret += f"0x{eid:04x}"
            ret += "\n"

        if len(self.__fieldids__) > 0:
            ret += (2 + indent) * " "
            ret += "Notifiers: "
            first = True
            for fid in sorted(set(self.__fieldids__)):
                if not first:
                    ret += ", "
                else:
                    first = False
                if fid is None:
                    print(f"ERROR: Field is referenced to Eventgroup {self.__name__} but does not have a Notifier!")
                    ret += "None"
                else:
                    ret += f"0x{fid:04x}"
            ret += "\n"

        return ret


class SOMEIPParameter(SOMEIPBaseParameter):
    def str(self, indent: int) -> str:
        ret = indent * " "
        ret += f"Parameter {self.__position__:d} {self.__name__} (mandatory: {self.__mandatory__})\n"
        if self.__datatype__ is None:
            ret += f"{(indent + 2) * ' '}None\n"
        else:
            ret += cast(str, cast(Any, self.__datatype__).str(indent + 2))
        if self.__signal__ is not None:
            ret += cast(Signal, self.__signal__).str(indent + 2)
        return ret


class SOMEIPParameterBasetype(SOMEIPBaseParameterBasetype):
    def str(self, indent: int) -> str:
        endian = "BE"
        if not self.__bigendian__:
            endian = "LE"

        ret = indent * " "
        if g_show_datatype:
            ret += f"{self.__name__} {self.__datatype__} {endian} ({self.__bitlength_basetype__:d};" + f"{self.__bitlength_encoded_type__:d})\n"
        else:
            ret += f"{self.__name__} {endian} ({self.__bitlength_basetype__:d};" + f"{self.__bitlength_encoded_type__:d})\n"
        return ret


class SOMEIPParameterString(SOMEIPBaseParameterString):
    def str(self, indent: int) -> str:
        endian = "BE"
        if not self.__bigendian__:
            endian = "LE"

        ret = indent * " "
        ret += (
            f"String {self.__name__} {self.__chartype__} {endian} ({self.__lowerlimit__:d};"
            + f"{self.__upperlimit__:d}) term: {self.__termination__} "
            + f"len: {self.__lengthOfLength__:d} pad: {self.__padTo__:d}\n"
        )
        return ret


class SOMEIPParameterArray(SOMEIPBaseParameterArray):
    def str(self, indent: int) -> str:
        ret = indent * " "
        ret += f"Array {self.__name__}:\n"
        for dim in self.__dims__:
            ret += cast(SOMEIPParameterArrayDim, self.__dims__[dim]).str(indent + 2)
        if self.__child__ is None:
            ret += f"{(indent + 2) * ' '}None\n"
        else:
            ret += cast(str, cast(Any, self.__child__).str(indent + 2))

        return ret


class SOMEIPParameterArrayDim(SOMEIPBaseParameterArrayDim):
    def str(self, indent: int) -> str:
        ret = indent * " "
        ret += (
            f"Dimension {self.__dim__:d} [{self.__lowerlimit__:d}-{self.__upperlimit__:d}] "
            + f"lengthOfLength: {self.__lengthOfLength__:d} padding: {self.__padTo__:d}\n"
        )
        return ret


class SOMEIPParameterStruct(SOMEIPBaseParameterStruct):
    def str(self, indent: int) -> str:
        ret = indent * " "
        tlv = " (TLV: True)" if self.__tlv__ else ""

        ret += f"Struct {self.__name__}{tlv}:\n"
        if self.__members__ is not None:
            for m in sorted(self.__members__.keys()):
                member = self.__members__[m]
                if member is not None:
                    ret += cast(SOMEIPParameterStructMember, member).str(indent + 2)
                else:
                    print("ERROR: struct member == None!")

        return ret


class SOMEIPParameterStructMember(SOMEIPBaseParameterStructMember):
    def str(self, indent: int) -> str:
        ret = indent * " "
        ret += f"{self.__position__:d} {self.__name__} (mandatory: {self.__mandatory__})\n"

        if self.__child__ is not None:
            ret += cast(str, cast(Any, self.__child__).str(indent + 2))
        if self.__signal__ is not None:
            ret += cast(Signal, self.__signal__).str(indent + 2)

        return ret


class SOMEIPParameterTypedef(SOMEIPBaseParameterTypedef):
    def str(self, indent: int) -> str:
        ret = indent * " "
        if g_show_datatype:
            ret += f"Typedef: {self.__name__} {self.__name2__}\n"
        else:
            ret += f"Typedef: {self.__name__}\n"
        if self.__child__ is not None:
            ret += cast(str, cast(Any, self.__child__).str(indent + 2))
        return ret


class SOMEIPParameterEnumeration(SOMEIPBaseParameterEnumeration):
    def str(self, indent: int) -> str:
        ret = indent * " "
        ret += f"Enumeration {self.__name__}\n"
        ret += cast(str, cast(Any, self.__child__).str(indent + 2))
        for i in self.__items__:
            ret += cast(SOMEIPParameterEnumerationItem, i).str(indent + 2)
        return ret


class SOMEIPParameterEnumerationItem(SOMEIPBaseParameterEnumerationItem):
    def str(self, indent: int) -> str:
        ret = indent * " "
        ret += f"{self.__value__}: {self.__name__}\n"
        return ret


class SOMEIPParameterUnion(SOMEIPBaseParameterUnion):
    def str(self, indent: int) -> str:
        ret = indent * " "
        ret += f"Union {self.__name__}:\n"
        if self.__members__ is not None:
            for m in sorted(self.__members__.keys()):
                member = self.__members__[m]
                if member is not None:
                    ret += cast(SOMEIPParameterUnionMember, member).str(indent + 2)
                else:
                    print("ERROR: union member == None!")

        return ret


class SOMEIPParameterUnionMember(SOMEIPBaseParameterUnionMember):
    def str(self, indent: int) -> str:
        ret = indent * " "

        ret += f"{self.__index__:d} {self.__name__} (mandatory: {self.__mandatory__})\n"

        if self.__child__ is not None:
            ret += cast(str, cast(Any, self.__child__).str(indent + 2))

        return ret


class SOMEIPParameterBitfield(SOMEIPBaseParameterBitfield):
    def str(self, indent: int) -> str:
        ret = indent * " "
        ret += f"Bitfield {self.__name__}\n"
        ret += cast(str, cast(Any, self.__child__).str(indent + 2))
        for i in self.__items__:
            ret += cast(SOMEIPParameterBitfieldItem, i).str(indent + 2)
        return ret


class SOMEIPParameterBitfieldItem(SOMEIPBaseParameterBitfieldItem):
    def str(self, indent: int) -> str:
        ret = indent * " "
        ret += f"Bit {self.__bit_number__}: {self.__name__}\n"
        return ret


class Signal(BaseSignal):
    def str(self, indent: int, indent_first_line: bool = True) -> str:
        if indent_first_line:
            ret = indent * " "
        else:
            ret = ""

        ret += f"Signal {self.__name__}"
        if g_show_datatype:
            ret += f" [{self.__basetype__}]"
        if self.__compu_scale__ is not None and len(self.__compu_scale__) == 3:
            ret += f", f(x) = {self.__compu_scale__[1]}/{self.__compu_scale__[2]} * x + {self.__compu_scale__[0]}"
        else:
            ret += f", f(x) = {1.0}/{1.0} * x + {0.0}"

        if self.__compu_consts__ is not None and len(self.__compu_consts__) > 0:
            ret += ", Consts: "
            first = True
            for name, start, end in cast(list[tuple[str, str, str]], self.__compu_consts__):
                if first:
                    first = False
                else:
                    ret += ", "
                ret += f"{name} ({start}-{end})"
            ret += " "
        return ret + "\n"


class Frame(BaseFrame):
    def str(self, indent: int) -> str:
        ret = indent * " "
        ret += f"Frame {self.__short_name__}\n"

        for p in self.__pdu_instances__.keys():
            ret += cast(PDUInstance, self.__pdu_instances__[p]).str(indent + 2)

        return ret


class PDU(BasePDU):
    def str(self, indent: int, indent_first_line: bool = True, start_offset: int = 0, show_signals: bool = True) -> str:
        if indent_first_line:
            ret = indent * " "
        else:
            ret = ""

        ret += f"PDU {self.__short_name__} ({self.__pdu_type__})\n"

        if show_signals:
            for sig_inst in self.signal_instances_sorted_by_bit_position():
                ret += cast(SignalInstance, sig_inst).str(indent + 2, start_offset=start_offset)

        return ret


class MultiplexPDU(BaseMultiplexPDU):
    def str(self, indent: int, indent_first_line: bool = True) -> str:
        if indent_first_line:
            ret = indent * " "
        else:
            ret = ""

        ret += f"MUX-PDU {self.__short_name__} ({self.__pdu_type__})\n"
        ret += cast(MultiplexPDUSwitch, self.__switch__).str(indent + 2)

        dyn_seg_start = 0
        for seg in self.__segment_positions__:
            ret += cast(MultiplexPDUSegmentPosition, seg).str(indent + 2, prefix="Dynamic")
            dyn_seg_start = seg.bit_position()

        for switch_code in sorted(cast(list[BasePDUInstance], self.__pdu_instances__)):  # type: ignore[type-var]
            pdu = self.__pdu_instances__[switch_code] if self.__pdu_instances__ is not None else None  # type: ignore[call-overload]
            pdu_str = cast(PDU, pdu).str(indent + 4, indent_first_line=False, start_offset=dyn_seg_start) if pdu is not None else "PDU NOT FOUND!\n"

            ret += (indent + 4) * " "
            ret += f"[Switch Code: {switch_code}]: {pdu_str}"

        static_seg_start = 0
        if self.__static_segments__ is not None:
            for seg in self.__static_segments__:
                ret += cast(MultiplexPDUSegmentPosition, seg).str(indent + 2, prefix="Static")
                static_seg_start = seg.bit_position()

        if self.__static_pdu__ is not None:
            pdu_str = cast(PDU, self.__static_pdu__).str(indent + 4, indent_first_line=False, start_offset=static_seg_start)

            ret += (indent + 4) * " "
            ret += f"[Static PDU] {pdu_str}"

        return ret


class MultiplexPDUSwitch(BaseMultiplexPDUSwitch):
    def str(self, indent: int, indent_first_line: bool = True) -> str:
        if indent_first_line:
            ret = indent * " "
        else:
            ret = ""

        end_bit = self.__bit_position__ + self.__bit_length__ - 1
        high_low = "high low byte order" if self.__is_high_low_byte_order__ else "low high byte order"
        ret += f"[Bit pos.: {self.__bit_position__}..{end_bit}] Switch {self.__short_name__} {self.__bit_length__} bits ({high_low})  \n"

        return ret


class MultiplexPDUSegmentPosition(BaseMultiplexPDUSegmentPosition):
    def str(self, indent: int, indent_first_line: bool = True, prefix: str = "") -> str:
        if indent_first_line:
            ret = indent * " "
        else:
            ret = ""

        end_bit = self.__bit_position__ + self.__bit_length__ - 1
        high_low = "high low byte order" if self.__is_high_low_byte_order__ else "low high byte order"
        ret += f"[Bit pos.: {self.__bit_position__}..{end_bit}] " f"{prefix} Segment {self.__bit_length__} bits ({high_low})  \n"

        return ret


class EthernetPDUInstance(BaseEthernetPDUInstance):
    def str(self, indent: int, show_signals: bool = False) -> str:
        ret = indent * " "
        ret += f"{hex(cast(int, self.__header_id__))}: "
        if self.__pdu__ is None:
            ret += "\n"
        else:
            ret += cast(PDU, self.__pdu__).str(indent + 2, indent_first_line=False, show_signals=show_signals)

        return ret


class PDUInstance(BasePDUInstance):
    def str(self, indent: int) -> str:
        ret = indent * " "
        pdu = cast(BaseAbstractPDU, self.__pdu__)
        end_bit = self.__bit_position__ + 8 * pdu.byte_length() - 1
        ret += f"[Bit pos.: {self.__bit_position__}..{end_bit}] "

        if self.__pdu__ is not None:
            ret += cast(PDU, self.__pdu__).str(indent + 2, indent_first_line=False)
        else:
            ret += " *** missing PDU ***\n"

        return ret


class SignalInstance(BaseSignalInstance):
    def str(self, indent: int, start_offset: int = 0) -> str:
        signal = cast(Signal, self.__signal__)
        bit_length = signal.bit_length()
        ret = indent * " "

        bit_start = int(self.__bit_position__) + start_offset

        if bit_length == -1:
            ret += f"[Bit pos.: {bit_start}] "
        else:
            bit_end = bit_start + bit_length - 1
            ret += f"[Bit pos.: {bit_start}..{bit_end}] "
        ret += signal.str(indent + 2, indent_first_line=False)
        return ret


class FrameTriggeringCAN(BaseFrameTriggeringCAN):
    def str(self, indent: int) -> str:
        ret = indent * " "

        frame = self.__frame__.name() if self.__frame__ is not None else "undefined"
        # frame_id = self.__frame__.id() if self.__frame__ is not None else "undefined"

        ext = "ext" if self.is_extended_id() else "std"
        fd = "[CAN-FD]" if self.is_can_fd() else "[CAN]"

        ret += f"FrameTriggeringCAN (CAN-ID: {self.__can_id__}, {ext}) for Frame {frame} {fd}\n"
        return ret


class FrameTriggeringFlexRay(BaseFrameTriggeringFlexRay):
    def str(self, indent: int) -> str:
        ret = indent * " "

        if self.__cycle_counter__ is not None:
            timing = f"Cycle Counter: {self.__cycle_counter__}"
        elif self.__base_cycle__ is not None and self.__cycle_repetition__ is not None:
            timing = f"Base Cycle: {self.__base_cycle__}, Cycle Rep: {self.__cycle_repetition__}"
        else:
            timing = "Undefined Timing"

        frame = self.__frame__.name() if self.__frame__ is not None else "undefined"
        # frame_id = self.__frame__.id() if self.__frame__ is not None else "undefined"

        ret += f"FrameTriggeringFlexRay (Slot ID: {self.__slot_id__}, {timing}) for Frame {frame}\n"
        return ret


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Converting configuration to text.")
    parser.add_argument("type", choices=parser_formats, help="format")
    parser.add_argument(
        "filename",
        help="filename or directory",
        type=lambda x: is_file_or_dir_valid(parser, x),
    )
    parser.add_argument(
        "--ecu-name-mapping",
        type=argparse.FileType("r"),
        default=None,
        help="Key/Value CSV file",
    )
    parser.add_argument("--generate-switch-port-names", action="store_true")
    parser.add_argument(
        "--plugin",
        help="filename of parser plugin",
        type=lambda x: is_file_valid(parser, x),
        default=None,
    )
    parser.add_argument("--show-original-datatype", action="store_true")
    parser.add_argument("--skip-signal-based-communication", action="store_true")

    args = parser.parse_args()
    return args


def main() -> None:
    global g_gen_portid
    global g_show_datatype
    global g_skip_signal_based_communication

    print("Converting configuration to text")
    args = parse_arguments()

    g_gen_portid = args.generate_switch_port_names
    g_show_datatype = args.show_original_datatype
    g_skip_signal_based_communication = args.skip_signal_based_communication

    ecu_name_mapping: dict[str, str] = {}
    if args.ecu_name_mapping is not None:
        ecu_name_mapping = read_csv_to_dict(args.ecu_name_mapping)

    conf_factory = SimpleConfigurationFactory()
    output_dir = parse_input_files(
        args.filename,
        args.type,
        conf_factory,
        plugin_file=args.plugin,
        ecu_name_replacement=ecu_name_mapping,
    )
    assert output_dir is not None

    print("Generating output directories:")

    if os.path.isdir(args.filename):
        target_dir = os.path.join(output_dir, "text")
        textfile = os.path.join(target_dir, "all_files" + ".txt")
    elif os.path.isfile(args.filename):
        path, f = os.path.split(args.filename)
        filenoext = ".".join(f.split(".")[:-1])
        target_dir = os.path.join(output_dir, "text")
        textfile = os.path.join(target_dir, filenoext + ".txt")

    if not os.path.exists(target_dir):
        os.makedirs(target_dir)
        time.sleep(0.5)

    with open(textfile, "w") as f:
        f.write("%s" % conf_factory)

    print("Done.")


# only call main, if we are started directly
if __name__ == "__main__":
    main()
