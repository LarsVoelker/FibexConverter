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

import argparse
import ipaddress
import os.path
import time

from configuration_base_classes import (
    BaseConfigurationFactory,
    BaseController,
    BaseECU,
    BaseEthernetPDUInstance,
    BaseFrame,
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
    SOMEIPBaseParameter,
    SOMEIPBaseParameterArray,
    SOMEIPBaseParameterArrayDimension,
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


class TextConfigurationFactory(BaseConfigurationFactory):

    def __init__(self):
        self.__services = dict()
        self.__services_long = dict()
        self.__switches = dict()
        self.__ecus = dict()

        self.__codings = dict()
        self.__frame_triggerings = dict()
        self.__frames = dict()
        self.__pdus = dict()
        self.__channels = dict()

        self.__ipv4_netmasks = {}
        self.__ipv6_prefix_lengths = {}

    def create_switch(self, name, ecu, ports):
        ret = Switch(name, ecu, ports)
        assert (name not in self.__switches)
        self.__switches[name] = ret
        return ret

    def create_switch_port(self, port_id, ctrl, port, default_vlan, vlans):
        return SwitchPort(port_id, ctrl, port, default_vlan, vlans)

    def create_ecu(self, name, controllers):
        ret = ECU(name, controllers)
        assert (name not in self.__ecus)
        self.__ecus[name] = ret
        return ret

    def create_controller(self, name, interfaces):
        ret = Controller(name, interfaces)
        return ret

    def create_interface(self, name, vlan_id, ips, sockets, input_frame_triggerings, output_frame_triggerings, fr_channel):
        ret = Interface(name, vlan_id, ips, sockets, input_frame_triggerings, output_frame_triggerings, fr_channel)
        channel = self.__channels.setdefault(name, {})
        frame_triggerings = channel.setdefault("frametriggerings", {})

        for key, value in input_frame_triggerings.items():
            frame_triggerings[key] = value
        for key, value in output_frame_triggerings.items():
            frame_triggerings[key] = value

        return ret

    def create_socket(self, name, ip, proto, port_number, service_instances, service_instance_clients, event_handlers,
                      event_group_receivers):
        ret = Socket(name, ip, proto, port_number, service_instances, service_instance_clients, event_handlers,
                     event_group_receivers)
        return ret

    def create_someip_service_instance(self, service, instance_id, protocol_version):
        ret = SOMEIPServiceInstance(service, instance_id, protocol_version)
        return ret

    def create_someip_service_instance_client(self, service, instance_id, protocol_version, server):
        ret = SOMEIPServiceInstanceClient(service, instance_id, protocol_version, server)
        return ret

    def create_someip_service_eventgroup_sender(self, service_instance, eventgroup_id):
        ret = SOMEIPServiceEventgroupSender(service_instance, eventgroup_id)
        return ret

    def create_someip_service_eventgroup_receiver(self, service_instance, eventgroup_id, sender):
        ret = SOMEIPServiceEventgroupReceiver(service_instance, eventgroup_id, sender)
        return ret

    def create_someip_service(self, name, service_id, major_version, minor_version, methods, events, fields, eventgroups):
        ret = SOMEIPService(name, service_id, major_version, minor_version, methods, events, fields, eventgroups)
        print(f"Adding Service(Name: {name} ID: 0x{service_id:04x} Ver: {major_version:d}.{minor_version:d})")
        self.add_service(service_id, major_version, minor_version, ret)
        return ret

    def create_someip_service_method(self, name, method_id, call_type, reliable, in_parameters, out_parameters,
                                     request_debounce=-1, request_max_retention=-1, response_max_retention=-1, tlv=False):
        ret = SOMEIPServiceMethod(name, method_id, call_type, reliable, in_parameters, out_parameters,
                                  request_debounce, request_max_retention, response_max_retention, tlv)
        return ret

    def create_someip_service_event(self, name, method_id, reliable, params,
                                    debounce=-1, max_retention=-1, tlv=False):
        ret = SOMEIPServiceEvent(name, method_id, reliable, params,
                                 debounce, max_retention, tlv)
        return ret

    def create_someip_service_field(self, name, getter_id, setter_id, notifier_id, getter_reliable, setter_reliable, notifier_reliable,
                                    params,
                                    getter_debounce_request, getter_retention_request, getter_retention_response,
                                    setter_debounce_request, setter_retention_request, setter_retention_response,
                                    notifier_debounce, notifier_retention, tlv=False):
        ret = SOMEIPServiceField(self, name, getter_id, setter_id, notifier_id, getter_reliable, setter_reliable, notifier_reliable,
                                 params,
                                 getter_debounce_request, getter_retention_request, getter_retention_response,
                                 setter_debounce_request, setter_retention_request, setter_retention_response,
                                 notifier_debounce, notifier_retention, tlv)
        return ret

    def create_someip_service_eventgroup(self, name, eid, event_ids, field_ids):
        ret = SOMEIPServiceEventgroup(name, eid, event_ids, field_ids)
        return ret

    def create_someip_parameter(self, position, name, desc, mandatory, data_type, signal):
        ret = SOMEIPParameter(position, name, desc, mandatory, data_type, signal)
        return ret

    def create_someip_parameter_basetype(self, name, data_type, bigendian, bitlength_basetype, bitlength_encoded_type):
        ret = SOMEIPParameterBasetype(name, data_type, bigendian, bitlength_basetype, bitlength_encoded_type)
        return ret

    def create_someip_parameter_string(self, name, char_type, big_endian, lower_limit, upper_limit, termination,
                                       length_of_length, pad_to):
        ret = SOMEIPParameterString(name, char_type, big_endian, lower_limit, upper_limit, termination, length_of_length,
                                    pad_to)
        return ret

    def create_someip_parameter_array(self, name, dims, child):
        ret = SOMEIPParameterArray(name, dims, child)
        return ret

    def create_someip_parameter_array_dim(self, dim, lower_limit, upper_limit, length_of_length, pad_to):
        ret = SOMEIPParameterArrayDim(dim, lower_limit, upper_limit, length_of_length, pad_to)
        return ret

    def create_someip_parameter_struct(self, name, length_of_length, pad_to, members, tlv=False):
        ret = SOMEIPParameterStruct(name, length_of_length, pad_to, members, tlv)
        return ret

    def create_someip_parameter_struct_member(self, position, name, mandatory, child, signal):
        ret = SOMEIPParameterStructMember(position, name, mandatory, child, signal)
        return ret

    def create_someip_parameter_typedef(self, name, name2, child):
        ret = SOMEIPParameterTypedef(name, name2, child)
        return ret

    def create_someip_parameter_enumeration(self, name, items, child):
        ret = SOMEIPParameterEnumeration(name, items, child)
        return ret

    def create_someip_parameter_enumeration_item(self, value, name, desc):
        ret = SOMEIPParameterEnumerationItem(value, name, desc)
        return ret

    def create_someip_parameter_union(self, name, length_of_length, length_of_type, pad_to, members):
        ret = SOMEIPParameterUnion(name, length_of_length, length_of_type, pad_to, members)
        return ret

    def create_someip_parameter_union_member(self, index, name, mandatory, child):
        ret = SOMEIPParameterUnionMember(index, name, mandatory, child)
        return ret

    def create_someip_parameter_bitfield(self, name, items, child):
        ret = SOMEIPParameterBitfield(name, items, child)
        return ret

    def create_someip_parameter_bitfield_item(self, bit_number, name):
        ret = SOMEIPParameterBitfieldItem(bit_number, name)
        return ret

    def create_signal(self, signal_id, name, compu_scale, compu_consts, bit_len, min_len, max_len, basetype, basetypelen):
        ret = Signal(signal_id, name, compu_scale, compu_consts, bit_len, min_len, max_len, basetype, basetypelen)
        return ret

    def create_signal_instance(self, signal_instance_id, signal_ref, bit_position, is_high_low_byte_order):
        ret = SignalInstance(signal_instance_id, signal_ref, bit_position, is_high_low_byte_order)
        return ret

    def create_pdu(self, pdu_id, short_name, byte_length, pdu_type, signal_instances):
        ret = PDU(pdu_id, short_name, byte_length, pdu_type, signal_instances)

        if pdu_id in self.__pdus:
            print(f"WARNING: Creating PDU with existing ID {pdu_id}!")

        self.__pdus[pdu_id] = ret
        return ret

    def create_multiplex_pdu(self, multiplexer_pdu_id, short_name, byte_length, pdu_type, switch, segment_position, pdu_instances,
                             static_segments, static_pdu):
        ret = MultiplexPDU(multiplexer_pdu_id, short_name, byte_length, pdu_type, switch, segment_position, pdu_instances,
                           static_segments, static_pdu)

        if multiplexer_pdu_id in self.__pdus:
            print(f"WARNING: Creating Multiplex PDU with existing ID {multiplexer_pdu_id}!")
        self.__pdus[multiplexer_pdu_id] = ret
        return ret

    def create_multiplex_switch(self, multiplex_switch_id, short_name, bit_position, is_high_low_byte_order, bit_length):
        return MultiplexPDUSwitch(multiplex_switch_id, short_name, bit_position, is_high_low_byte_order, bit_length)

    def create_multiplex_segment_position(self, bit_position, is_high_low_byte_order, bit_length):
        return MultiplexPDUSegmentPosition(bit_position, is_high_low_byte_order, bit_length)

    def create_ethernet_pdu_instance(self, pdu_ref, header_id):
        return EthernetPDUInstance(pdu_ref, header_id)

    def create_pdu_instance(self, pdu_instance_id, pdu_ref, bit_position, is_high_low_byte_order, pdu_update_bit_position):
        ret = PDUInstance(pdu_instance_id, pdu_ref, bit_position, is_high_low_byte_order, pdu_update_bit_position)
        return ret

    def create_frame(self, frame_id, short_name, byte_length, frame_type, pdu_instances):
        if short_name in self.__frames:
            i = 1

            while f"{short_name}__duplicate{i}" in self.__frames:
                i += 1

            short_name = f"{short_name}__duplicate{i}"

        assert (short_name not in self.__frames)

        ret = Frame(frame_id, short_name, byte_length, frame_type, pdu_instances)
        self.__frames[short_name] = ret
        return ret

    def create_frame_triggering_can(self, frame_trigger_id, frame_ref, can_id):
        ret = FrameTriggeringCAN(frame_trigger_id, frame_ref, can_id)

        self.__frame_triggerings[frame_trigger_id] = ret
        return ret

    def create_frame_triggering_flexray(self, frame_trigger_id, frame_ref, slot_id, cycle_counter, base_cycle, cycle_repetition):
        ret = FrameTriggeringFlexRay(frame_trigger_id, frame_ref, slot_id, cycle_counter, base_cycle, cycle_repetition)

        self.__frame_triggerings[frame_trigger_id] = ret
        return ret

    def add_service(self, serviceid, majorver, minorver, service):
        sid = f"{serviceid:04x}-{majorver:02x}-{minorver:08x}"
        if sid in self.__services_long:
            print(f"ERROR: Service (SID: 0x{serviceid:04x}, Major-Ver: {majorver:d}, " +
                  f"Minor-Ver: {minorver:d}) already exists! Not overriding it!")
            return False

        self.__services_long[sid] = service

        sid = f"{serviceid:04x}-{majorver:02x}"
        if sid in self.__services:
            print(f"ERROR: Service (SID: 0x{serviceid:04x}, Major-Ver: {majorver:d})" +
                  f"already exists with a different Minor Version (not {minorver:d})! Not overriding it!")
            return False

        self.__services[sid] = service
        return True

    def get_service(self, serviceid, majorver, minorver=None):
        if minorver is None:
            sid = f"{serviceid:04x}-{majorver:02x}"
            if sid in self.__services:
                return self.__services[sid]
            else:
                return None
        else:
            sid = f"{serviceid:04x}-{majorver:02x}-{minorver:08x}"
            if sid in self.__services_long:
                return self.__services_long[sid]
            else:
                return None

    def add_ipv4_address_config(self, ip, netmask):
        self.__ipv4_netmasks[ip] = netmask

    def get_ipv4_netmask(self, ip):
        try:
            return self.__ipv4_netmasks.get(ip)
        except ValueError:
            return None

    def add_ipv6_address_config(self, ip, prefix_len):
        tmp = ipaddress.ip_address(ip).exploded
        self.__ipv6_prefix_lengths[tmp] = prefix_len

    def get_ipv6_prefix_length(self, ip):
        try:
            tmp = ipaddress.ip_address(ip).exploded
            return self.__ipv6_prefix_lengths.get(tmp)
        except ValueError:
            return None

    def get_ipv4_netmask_or_ipv6_prefix_length(self, ip):
        if self.get_ipv4_netmask(ip) is not None:
            return f"/{self.get_ipv4_netmask(ip)}"

        if self.get_ipv6_prefix_length(ip) is not None:
            return f"/{self.get_ipv6_prefix_length(ip)}"

        return ""

    def __str__(self):
        ret = "Services: \n"
        for serviceid in sorted(self.__services):
            ret += self.__services[serviceid].str(2)

        ret += "\nFrames: \n"
        for name in sorted(self.__frames):
            ret += self.__frames[name].str(2)

        ret += "\nPDUs: \n"
        for name in sorted(self.__pdus):
            ret += self.__pdus[name].str(2)

        ret += "\nECUs: \n"
        for name in sorted(self.__ecus):
            ret += self.__ecus[name].str(2, self)

        ret += "\nChannels/Busses/VLANs: \n"
        for name in sorted(self.__channels):
            ret += f"  Channel {name}:\n"
            fts = self.__channels[name]["frametriggerings"]
            for key in sorted(fts):
                ret += fts[key].str(4)
            ret += "\n"

        ret += "\nEthernet Topology: \n"
        for name in sorted(self.__switches):
            ret += self.__switches[name].str(2, self, print_ecu_name=True)

        return ret


class Switch(BaseSwitch):
    def str(self, indent, factory, print_ecu_name=False):
        ret = indent * " "
        tmp = f" of ECU {self.ecu().name()}" if self.ecu() is not None and print_ecu_name else ""
        ret += f"Switch {self.name()}{tmp}\n"
        for port in self.ports():
            ret += port.str(indent + 2, factory)
        return ret


class SwitchPort(BaseSwitchPort):
    def str_vlans(self, indent):
        ret = ""

        for vlan in self.vlans_objs():
            ret += indent * " "
            ret += f"VLAN (ID: {vlan.vlan_id_str()}, Prio: {vlan.priority()})\n"

        return ret

    def str(self, indent, factory):
        ret = indent * " "
        ret += f"SwitchPort {self.portid(gen_name=g_gen_portid)} <-> "
        if self.port() is not None:
            tmp = f"of {self.port().switch().name()}" if self.port().switch() is not None else ""
            ret += f"SwitchPort {self.port().portid(gen_name=g_gen_portid)} {tmp}\n"
        elif self.controller() is not None:
            ret += f"Controller {self.controller().name()} of {self.controller().ecu().name()}\n"
        else:
            ret += "\n"

        ret += (indent + 2) * " "
        ret += "VLANs:\n"
        ret += self.str_vlans(indent + 4)
        return ret


class ECU(BaseECU):
    def str(self, indent, factory):
        ret = indent * " "
        ret += f"ECU {self.name()}\n"

        for c in sorted(self.controllers(), key=lambda x: x.name()):
            ret += c.str(indent + 2, factory)

        for s in sorted(self.switches(), key=lambda x: x.name()):
            ret += s.str(indent + 2, factory)

        return ret


class Controller(BaseController):
    def str(self, indent, factory):
        ret = indent * " "
        ret += f"CTRL {self.name()}\n"
        for i in self.interfaces():
            ret += i.str(indent + 2, factory)

        return ret


class Interface(BaseInterface):
    def str(self, indent, factory):
        ret = indent * " "

        if self.vlan_id() == 0:
            vlan_str = ""
        else:
            vlan_str = f" (VLAN-ID: 0x{self.vlan_id():x})"
        ret += f"Interface/Channel {self.vlan_name()}{vlan_str}\n"
        for ip in sorted(self.ips(), key=lambda x: ip_to_key(x)):
            if is_ip(ip) and not is_ip_mcast(ip):
                ret += (indent + 2) * " "
                ret += f"IP: {ip}{factory.get_ipv4_netmask_or_ipv6_prefix_length(ip)}\n"

        for s in self.sockets():
            ret += s.str(indent + 2)

        if self.frame_triggerings_in() is not None and len(self.frame_triggerings_in().keys()) > 0:
            ret += (indent + 2) * " "
            ret += "Input Frames:\n"
            for key in sorted(self.frame_triggerings_in().keys()):
                ret += self.frame_triggerings_in()[key].str(indent + 4)

        if self.frame_triggerings_out() is not None and len(self.frame_triggerings_out().keys()) > 0:
            ret += (indent + 2) * " "
            ret += "Output Frames:\n"
            for key in sorted(self.frame_triggerings_out().keys()):
                ret += self.frame_triggerings_out()[key].str(indent + 4)

        return ret


class Socket(BaseSocket):
    def str(self, indent):
        ret = indent * " "
        ret += f"Socket {self.name()} {self.ip()}:{self.port_number()}/{self.protocol()}\n"
        for i in self.instances():
            ret += i.str(indent + 2)
        for i in self.service_instance_clients():
            ret += i.str(indent + 2)
        for c in self.event_handlers():
            ret += c.str(indent + 2)
        for c in self.event_group_receivers():
            ret += c.str(indent + 2)

        if len(self.incoming_pdus()) > 0:
            ret += (indent + 2) * " " + "PDUs in:\n"
            for p in sorted(self.incoming_pdus(), key=lambda x: x.header_id()):
                ret += p.str(indent + 4, show_signals=False)

        if len(self.outgoing_pdus()) > 0:
            ret += (indent + 2) * " " + "PDUs out:\n"
            for p in sorted(self.outgoing_pdus(), key=lambda x: x.header_id()):
                ret += p.str(indent + 4, show_signals=False)

        return ret


class SOMEIPServiceInstance(SOMEIPBaseServiceInstance):
    def str(self, indent):
        ret = indent * " "
        ret += f"ServiceInstance Service-ID: 0x{self.service().service_id():04x} "
        ret += f"Version: {self.service().version_string()} "
        ret += f"Instance-ID: 0x{self.instance_id():04x} "
        ret += f"Protover: {self.protocol_version():d}\n"
        return ret


class SOMEIPServiceInstanceClient(SOMEIPBaseServiceInstanceClient):
    def str(self, indent):
        ret = indent * " "
        ret += f"ServiceInstanceClient Service-ID: 0x{self.service().service_id():04x} "
        ret += f"Version: {self.service().version_string()} "
        ret += f"Instance-ID: 0x{self.instance_id():04x} "
        ret += f"Protover: {self.protocol_version():d}\n"
        return ret


class SOMEIPServiceEventgroupSender(SOMEIPBaseServiceEventgroupSender):
    def str(self, indent):
        ret = indent * " "
        ret += f"EventgroupSender: Service-ID: 0x{self.service_instance().service().service_id():04x} "
        ret += f"Instance-ID: 0x{self.service_instance().instance_id():04x} "
        ret += f"Eventgroup-ID: 0x{self.eventgroup_id():04x}\n"
        return ret


class SOMEIPServiceEventgroupReceiver(SOMEIPBaseServiceEventgroupReceiver):
    def str(self, indent):
        ret = indent * " "
        ret += f"EventgroupReceiver: Service-ID: 0x{self.service_instance().service().service_id():04x} "
        ret += f"Instance-ID: 0x{self.service_instance().instance_id():04x} "
        ret += f"Eventgroup-ID: 0x{self.eventgroup_id():04x}\n"
        return ret


class SOMEIPService(SOMEIPBaseService):
    def str(self, indent):
        ret = indent * " "
        ret += f"Service {self.name()} (id: 0x{self.service_id():04x} ver: {self.major_version():d}.{self.minor_version():d})\n"

        for method_id in sorted(self.methods().keys()):
            ret += self.method(method_id).str(indent + 2)

        for event_id in sorted(self.events().keys()):
            ret += self.event(event_id).str(indent + 2)

        for field_id in sorted(self.fields().keys(), key=lambda x: (x is None, x)):
            ret += self.field(field_id).str(indent + 2)

        for eg_id in sorted(self.eventgroups().keys()):
            ret += self.eventgroup(eg_id).str(indent + 2)

        return ret


class SOMEIPServiceMethod(SOMEIPBaseServiceMethod):
    def str(self, indent):
        extra = ""
        if self.debounce_time_req() >= 0:
            extra += f" debounce:{str(self.debounce_time_req())}s"
        if self.max_buffer_retention_time_req() >= 0:
            extra += f" max_request_retention:{str(self.max_buffer_retention_time_req())}s"
        if self.max_buffer_retention_time_res() >= 0:
            extra += f" max_response_retention:{str(self.max_buffer_retention_time_res())}s"

        extra += ' TLV' if self.tlv() else ''
        ret = indent * " "
        ret += f"Method {self.name()} (id:0x{self.method_id():04x} type:{self.call_type()} " + \
               f"reli:{self.reliable()}{extra})\n"

        ret += (indent + 2) * " "
        ret += "In Parameters: \n"
        for param in self.in_parameters():
            ret += param.str(indent + 4)

        ret += (indent + 2) * " "
        ret += "Out Parameters: \n"
        for param in self.out_parameters():
            ret += param.str(indent + 4)

        return ret


class SOMEIPServiceEvent(SOMEIPBaseServiceEvent):
    def str(self, indent):
        extra = ""
        if self.debounce_time() >= 0:
            extra += f" debounce:{str(self.debounce_time())}s"
        if self.max_buffer_retention_time() >= 0:
            extra += f" max_retention:{str(self.max_buffer_retention_time())}s"

        ret = indent * " "
        extra += ', TLV:True' if self.tlv() else ''
        if self.legacy():
            ret += f"Event {self.name()} (id:0x{self.method_id():04x} reli:{self.reliable()}{extra}, Legacy PDU)\n"
        else:
            ret += f"Event {self.name()} (id:0x{self.method_id():04x} reli:{self.reliable()}{extra})\n"

        for param in self.params():
            ret += param.str(indent + 2)

        return ret


class SOMEIPServiceField(SOMEIPBaseServiceField):
    def str(self, indent):
        legacy = ""
        if self.legacy():
            legacy = ", Legacy PDU"

        ret = indent * " "
        ret += f"Field {self.name()}{' TLV' if self.tlv() else ''}\n"

        indent += 2
        if self.getter() is not None:
            getter = self.getter()
            extra = ""
            if getter.debounce_time_req() >= 0:
                extra += f" debounce:{str(getter.debounce_time_req())}s"
            if getter.max_buffer_retention_time_req() >= 0:
                extra += f" max_request_retention:{str(getter.max_buffer_retention_time_req())}s"
            if getter.max_buffer_retention_time_res() >= 0:
                extra += f" max_response_retention:{str(getter.max_buffer_retention_time_res())}s"

            ret += indent * " "
            ret += f"Getter(id:0x{getter.method_id():04x} reli:{getter.reliable()}{extra}{legacy})\n"

        if self.setter() is not None:
            setter = self.setter()
            extra = ""
            if setter.debounce_time_req() >= 0:
                extra += f" debounce:{str(setter.debounce_time_req())}s"
            if setter.max_buffer_retention_time_req() >= 0:
                extra += f" max_request_retention:{str(setter.max_buffer_retention_time_req())}s"
            if setter.max_buffer_retention_time_res() >= 0:
                extra += f" max_response_retention:{str(setter.max_buffer_retention_time_res())}s"

            ret += indent * " "
            ret += f"Setter(id:0x{setter.method_id():04x} reli:{setter.reliable()}{extra}{legacy})\n"

        if self.notifier() is not None:
            notifier = self.notifier()
            extra = ""
            if notifier.debounce_time() >= 0:
                extra += f" debounce:{str(notifier.debounce_time())}s"
            if notifier.max_buffer_retention_time() >= 0:
                extra += f" max_retention:{str(notifier.max_buffer_retention_time())}s"
            ret += indent * " "
            ret += f"Notifier(id:0x{notifier.method_id():04x} reli:{notifier.reliable()}{extra}" \
                   f"{legacy})\n"

        ret += indent * " "
        ret += "Parameters:\n"
        for param in self.params():
            if param is not None:
                ret += param.str(indent + 2)

        return ret


class SOMEIPServiceEventgroup(SOMEIPBaseServiceEventgroup):
    def str(self, indent):
        ret = indent * " "
        ret += f"Eventgroup {self.name()} (id: 0x{self.eventgroup_id():04x})\n"

        if len(self.event_ids()) > 0:
            ret += (2 + indent) * " "
            ret += "Events: "
            first = True
            for eid in self.event_ids():
                if not first:
                    ret += ", "
                else:
                    first = False
                ret += f"0x{eid:04x}"
            ret += "\n"

        if len(self.field_ids()) > 0:
            ret += (2 + indent) * " "
            ret += "Notifiers: "
            first = True
            for fid in self.field_ids():
                if not first:
                    ret += ", "
                else:
                    first = False
                ret += f"0x{fid:04x}"
            ret += "\n"

        return ret


class SOMEIPParameter(SOMEIPBaseParameter):
    def str(self, indent):
        ret = indent * " "
        ret += f"Parameter {self.position():d} {self.name()} (mandatory: {self.mandatory()})\n"
        if self.data_type() is None:
            ret += f"{(indent + 2) * ' '}None\n"
        else:
            ret += self.data_type().str(indent + 2)
        if self.signal() is not None:
            ret += self.signal().str(indent + 2)
        return ret


class SOMEIPParameterBasetype(SOMEIPBaseParameterBasetype):
    def str(self, indent):
        endian = "BE"
        if not self.big_endian():
            endian = "LE"

        ret = indent * " "
        ret += f"{self.name()} {self.data_type()} {endian} ({self.bit_length_base_type():d};" + \
               f"{self.bit_length_encoded_type():d})\n"
        return ret


class SOMEIPParameterString(SOMEIPBaseParameterString):
    def str(self, indent):
        endian = "BE"
        if not self.big_endian():
            endian = "LE"

        ret = indent * " "
        ret += f"String {self.name()} {self.char_type()} {endian} ({self.lower_limit():d};" + \
               f"{self.upper_limit():d}) term: {self.termination} " + \
               f"len: {self.length_of_length():d} pad: {self.pad_to():d}\n"
        return ret


class SOMEIPParameterArray(SOMEIPBaseParameterArray):
    def str(self, indent):
        ret = indent * " "
        ret += f"Array {self.name()}:\n"
        for dim in self.dimensions():
            ret += self.dimensions()[dim].str(indent + 2)
        if self.child() is None:
            ret += f"{(indent + 2) * ' '}None\n"
        else:
            ret += self.child().str(indent + 2)

        return ret


class SOMEIPParameterArrayDim(SOMEIPBaseParameterArrayDimension):
    def str(self, indent):
        ret = indent * " "
        ret += f"Dimension {self.dimension():d} [{self.lower_limit():d}-{self.upper_limit():d}] " + \
               f"lengthOfLength: {self.length_of_length():d} padding: {self.pad_to():d}\n"
        return ret


class SOMEIPParameterStruct(SOMEIPBaseParameterStruct):
    def str(self, indent):
        ret = indent * " "
        tlv = ' (TLV: True)' if self.tlv() else ''

        ret += f"Struct {self.name()}{tlv}:\n"
        if self.members() is not None:
            for m in sorted(self.members().keys()):
                member = self.members()[m]
                if member is not None:
                    ret += member.str(indent + 2)
                else:
                    print("ERROR: struct member == None!")

        return ret


class SOMEIPParameterStructMember(SOMEIPBaseParameterStructMember):
    def str(self, indent):
        ret = indent * " "
        ret += f"{self.position():d} {self.name()} (mandatory: {self.mandatory()})\n"

        if self.child() is not None:
            ret += self.child().str(indent + 2)
        if self.signal() is not None:
            ret += self.signal().str(indent + 2)

        return ret


class SOMEIPParameterTypedef(SOMEIPBaseParameterTypedef):
    def str(self, indent):
        ret = indent * " "
        ret += f"Typedef: {self.name()} {self.name2()}\n"
        if self.child() is not None:
            ret += self.child().str(indent + 2)
        return ret


class SOMEIPParameterEnumeration(SOMEIPBaseParameterEnumeration):
    def str(self, indent):
        ret = indent * " "
        ret += f"Enumeration {self.name()}\n"
        ret += self.child().str(indent + 2)
        for i in self.items():
            ret += i.str(indent + 2)
        return ret


class SOMEIPParameterEnumerationItem(SOMEIPBaseParameterEnumerationItem):
    def str(self, indent):
        ret = indent * " "
        ret += f"{self.value()}: {self.name()}\n"
        return ret


class SOMEIPParameterUnion(SOMEIPBaseParameterUnion):
    def str(self, indent):
        ret = indent * " "
        ret += f"Union {self.name()}:\n"
        if self.members() is not None:
            for m in sorted(self.members().keys()):
                member = self.members()[m]
                if member is not None:
                    ret += member.str(indent + 2)
                else:
                    print("ERROR: union member == None!")

        return ret


class SOMEIPParameterUnionMember(SOMEIPBaseParameterUnionMember):
    def str(self, indent):
        ret = indent * " "

        ret += f"{self.index():d} {self.name()} (mandatory: {self.mandatory()})\n"

        if self.child() is not None:
            ret += self.child().str(indent + 2)

        return ret


class SOMEIPParameterBitfield(SOMEIPBaseParameterBitfield):
    def str(self, indent):
        ret = indent * " "
        ret += f"Bitfield {self.name()}\n"
        ret += self.child().str(indent + 2)
        for i in self.items():
            ret += i.str(indent + 2)
        return ret


class SOMEIPParameterBitfieldItem(SOMEIPBaseParameterBitfieldItem):
    def str(self, indent):
        ret = indent * " "
        ret += f"Bit {self.bit_number()}: {self.name()}\n"
        return ret


class Signal(BaseSignal):
    def str(self, indent, indent_first_line=True, show_basetype=False):
        if indent_first_line:
            ret = indent * " "
        else:
            ret = ""

        ret += f"Signal {self.name()}"
        if show_basetype:
            ret += f" [{self.base_type()}]"
        if self.compu_scale() is not None and len(self.compu_scale()) == 3:
            ret += f", f(x) = {self.compu_scale()[1]}/{self.compu_scale()[2]} * x + {self.compu_scale()[0]}"
        if self.compu_consts() is not None and len(self.compu_consts()) > 0:
            ret += ", Consts: "
            first = True
            for name, start, end in self.compu_consts():
                if first:
                    first = False
                else:
                    ret += ", "
                ret += f"{name} ({start}-{end})"
            ret += " "
        return ret + "\n"


class Frame(BaseFrame):
    def str(self, indent):
        ret = indent * " "
        ret += f"Frame {self.short_name()}\n"

        for p in self.pdu_instances().keys():
            ret += self.pdu_instances()[p].str(indent + 2)

        return ret


class PDU(BasePDU):
    def str(self, indent, indent_first_line=True, start_offset=0, show_signals=True):
        if indent_first_line:
            ret = indent * " "
        else:
            ret = ""

        ret += f"PDU {self.short_name()} ({self.pdu_type()})\n"

        if show_signals:
            for sig_inst in self.signal_instances_sorted_by_bit_position():
                ret += sig_inst.str(indent + 2, start_offset=start_offset)

        return ret


class MultiplexPDU(BaseMultiplexPDU):
    def str(self, indent, indent_first_line=True):
        if indent_first_line:
            ret = indent * " "
        else:
            ret = ""

        ret += f"MUX-PDU {self.short_name()} ({self.pdu_type()})\n"
        ret += self.switch().str(indent + 2)

        dyn_seg_start = 0
        for seg in self.segment_positions():
            ret += seg.str(indent + 2, prefix="Dynamic")
            dyn_seg_start = seg.bit_position()

        for switch_code in sorted(self.pdu_instances()):
            pdu = self.pdu_instances()[switch_code]
            pdu_str = pdu.str(indent + 4, indent_first_line=False, start_offset=dyn_seg_start) \
                      if pdu is not None else "PDU NOT FOUND!\n"

            ret += (indent + 4) * " "
            ret += f"[Switch Code: {switch_code}]: {pdu_str}"

        static_seg_start = 0
        if self.static_segments() is not None:
            for seg in self.static_segments():
                ret += seg.str(indent + 2, prefix="Static")
                static_seg_start = seg.bit_position()

        if self.static_pdu() is not None:
            pdu_str = self.static_pdu().str(indent + 4, indent_first_line=False, start_offset=static_seg_start)\
                      if self.static_pdu() is not None else "PDU NOT FOUND!\n"

            ret += (indent + 4) * " "
            ret += f"[Static PDU] {pdu_str}"


        return ret


class MultiplexPDUSwitch(BaseMultiplexPDUSwitch):
    def str(self, indent, indent_first_line=True):
        if indent_first_line:
            ret = indent * " "
        else:
            ret = ""

        end_bit = self.bit_position() + self.bit_length() - 1
        high_low = "high low byte order" if self.is_high_low_byte_order() else "low high byte order"
        ret += (f"[Bit pos.: {self.bit_position()}..{end_bit}] "
                f"Switch {self.short_name()} {self.bit_length()} bits ({high_low})  \n")

        return ret


class MultiplexPDUSegmentPosition(BaseMultiplexPDUSegmentPosition):
    def str(self, indent, indent_first_line=True, prefix=""):
        if indent_first_line:
            ret = indent * " "
        else:
            ret = ""

        end_bit = self.bit_position() + self.bit_length() - 1
        high_low = "high low byte order" if self.is_high_low_byte_order() else "low high byte order"
        ret += f"[Bit pos.: {self.bit_position()}..{end_bit}] " \
               f"{prefix} Segment {self.bit_length()} bits ({high_low})  \n"

        return ret


class EthernetPDUInstance(BaseEthernetPDUInstance):
    def str(self, indent, show_signals=False):
        ret = indent * " "
        ret += f"{hex(self.header_id())}: "
        if self.pdu() is None:
            ret += "\n"
        else:
            ret += self.pdu().str(indent + 2, indent_first_line=False, show_signals=show_signals)

        return ret


class PDUInstance(BasePDUInstance):
    def str(self, indent):
        ret = indent * " "
        end_bit = self.bit_position() + 8 * self.pdu().byte_length() - 1
        ret += f"[Bit pos.: {self.bit_position()}..{end_bit}] "

        if self.pdu() is not None:
            ret += self.pdu().str(indent + 2, indent_first_line=False)
        else:
            ret += " *** missing PDU ***\n"

        return ret


class SignalInstance(BaseSignalInstance):
    def str(self, indent, start_offset=0):
        bit_length = self.signal().bit_length()
        ret = indent * " "

        bit_start = int(self.bit_position()) + start_offset

        if bit_length == -1:
            ret += f"[Bit pos.: {bit_start}] "
        else:
            bit_end = bit_start + bit_length - 1
            ret += f"[Bit pos.: {bit_start}..{bit_end}] "
        ret += self.signal().str(indent + 2, indent_first_line=False, show_basetype=True)
        return ret


class FrameTriggeringCAN(BaseFrameTriggeringCAN):
    def str(self, indent):
        ret = indent * " "

        frame = self.frame().name() if self.frame() is not None else "undefined"

        ret += f"FrameTriggeringCAN (CAN-ID: {self.can_id()}) for Frame {frame}\n"
        return ret


class FrameTriggeringFlexRay(BaseFrameTriggeringFlexRay):
    def str(self, indent):
        ret = indent * " "

        if self.cycle_counter() is not None:
            timing = f"Cycle Counter: {self.cycle_counter()}"
        elif self.base_cycle() is not None and self.cycle_repetition() is not None:
            timing = f"Base Cycle: {self.base_cycle()}, Cycle Rep: {self.cycle_repetition()}"
        else:
            timing = "Undefined Timing"

        frame = self.frame().name() if self.frame() is not None else "undefined"

        ret += f"FrameTriggeringFlexRay (Slot ID: {self.slot_id()}, {timing}) for Frame {frame}\n"
        return ret


def parse_arguments():
    parser = argparse.ArgumentParser(description='Converting configuration to text.')
    parser.add_argument('type', choices=parser_formats, help='format')
    parser.add_argument('filename', help='filename or directory', type=lambda x: is_file_or_dir_valid(parser, x))
    parser.add_argument('--ecu-name-mapping', type=argparse.FileType('r'), default=None, help='Key/Value CSV file')
    parser.add_argument('--generate-switch-port-names', action='store_true')
    parser.add_argument('--plugin', help='filename of parser plugin', type=lambda x: is_file_valid(parser, x),
                        default=None)

    args = parser.parse_args()
    return args


def main():
    global g_gen_portid

    print("Converting configuration to text")
    args = parse_arguments()

    g_gen_portid = args.generate_switch_port_names

    ecu_name_mapping = {}
    if args.ecu_name_mapping is not None:
        ecu_name_mapping = read_csv_to_dict(args.ecu_name_mapping)

    conf_factory = TextConfigurationFactory()
    output_dir = parse_input_files(args.filename, args.type, conf_factory, plugin_file=args.plugin,
                                   ecu_name_replacement=ecu_name_mapping)

    print("Generating output directories:")

    if os.path.isdir(args.filename):
        target_dir = os.path.join(output_dir, "text")
        textfile = os.path.join(target_dir, "all_files" + ".txt")
    elif os.path.isfile(args.filename):
        (path, f) = os.path.split(args.filename)
        filenoext = '.'.join(f.split('.')[:-1])
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
