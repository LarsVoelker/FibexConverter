#!/usr/bin/python

# Automotive configuration file scripts
# Copyright (C) 2015-2024  Dr. Lars Voelker
# Copyright (C) 2018-2019  Dr. Lars Voelker, BMW AG
# Copyright (C) 2020-2024  Dr. Lars Voelker, Technica Engineering GmbH

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
import os.path
import time

from configuration_base_classes import (
    BaseConfigurationFactory,
    BaseController,
    BaseECU,
    BaseInterface,
    BaseSocket,
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
)
from parser_dispatcher import (
    is_file_or_dir_valid,
    parse_input_files,
    parser_formats,
)


class SimpleConfigurationFactory(BaseConfigurationFactory):

    def __init__(self):
        self.__services__ = dict()
        self.__services_long__ = dict()
        self.__ecus__ = dict()

    def create_ecu(self, name, controllers):
        ret = ECU(name, controllers)
        assert (name not in self.__ecus__)
        self.__ecus__[name] = ret
        return ret

    def create_controller(self, name, interfaces):
        ret = Controller(name, interfaces)
        return ret

    def create_interface(self, name, vlan_id, ips, sockets, input_frame_triggerings, output_frame_triggerings, fr_channel):
        ret = Interface(name, vlan_id, ips, sockets, input_frame_triggerings, output_frame_triggerings, fr_channel)
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
        print("Adding Service(ID: 0x%04x Ver: %d.%d)" % (service_id, major_version, minor_version))
        #        assert(self.add_service(service_id, major_version, minor_version, ret))
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

    def add_service(self, service_id, major_version, minor_version, service):
        sid = "%04x-%02x-%08x" % (service_id, major_version, minor_version)
        if sid in self.__services_long__:
            print("ERROR: Service (SID: 0x%04x, Major-Ver: %d, Minor-Ver: %d) already exists! Not overriding it!" %
                  (service_id, major_version, minor_version))
            return False
        self.__services_long__[sid] = service

        sid = "%04x-%02x" % (service_id, major_version)
        if sid in self.__services__:
            print(f"ERROR: Service (SID: 0x{service_id:04x}, Major-Ver: {major_version}) " +
                  f"already exists with a different Minor Version (not {minor_version})! Not overriding it!")
            return False
        self.__services__[sid] = service
        return True

    def get_service(self, service_id, major_version, minor_version=None):
        if minor_version is None:
            sid = "%04x-%02x" % (service_id, major_version)
            if sid in self.__services__:
                return self.__services__[sid]
            else:
                return None
        else:
            sid = "%04x-%02x-%08x" % (service_id, major_version, minor_version)
            if sid in self.__services_long__:
                return self.__services_long__[sid]
            else:
                return None

    def get_services(self):
        return self.__services__

    def __str__(self):
        ret = "Services: \n"
        for service_id in sorted(self.__services__):
            ret += self.__services__[service_id].str(2)

        ret += "\nECUs: \n"
        for name in sorted(self.__ecus__):
            ret += self.__ecus__[name].str(2)

        return ret

    def get_ecu_names(self):
        return self.__ecus__.keys()

    def get_service_instance_client_relations(self):
        print("Looking at Service Instances...")
        ret = dict()

        for e in self.__ecus__.items():
            ecu = e[1]
            ecu_key = ecu.name()
            print(f"Looking at ECU: {ecu_key}")

            if ecu_key not in ret:
                ret[ecu_key] = dict()

            for c in ecu.controllers():
                for i in c.interfaces():
                    for s in i.sockets():
                        for si in s.instances():
                            si_key = si.key()
                            print(f"  SI key -> {si_key}")
                            if si_key not in ret[ecu_key]:
                                ret[ecu_key][si_key] = []

                            for sic in si.serviceinstanceclients():
                                if sic is None:
                                    print("Error: SIC = None!")
                                elif sic.socket() is None:
                                    print("Error: Socket in SIC (%s) = None!" % (str(sic)))
                                else:
                                    client_ecu_name = sic.socket().interface().controller().ecu().name()
                                    ret[ecu_key][si_key].append(client_ecu_name)
        return ret

    def get_size_of_methods(self):
        ret = []
        for i in sorted(self.__services__.keys()):
            service = self.__services__[i]
            for m in service.methods():
                ret.append([service, service.methods()[m], "Method"])
            for m in service.events():
                ret.append([service, service.events()[m], "Event"])
            for m in service.fields():
                ret.append([service, service.fields()[m], "Field"])
        return ret


class ECU(BaseECU):
    def str(self, indent):
        ret = indent * " "
        ret += f"ECU {self.__name}\n"

        for c in self.controllers():
            ret += c.str(indent + 2)

        return ret


class Controller(BaseController):
    def str(self, indent):
        ret = indent * " "
        ret += f"CTRL {self.__name}\n"
        for i in self.__interfaces:
            ret += i.str(indent + 2)

        return ret


class Interface(BaseInterface):
    def str(self, indent):
        ret = indent * " "
        ret += "Interface %s (VLAN-ID: 0x%x)\n" % (self.__vlan_name, self.__vlan_id)
        for s in self.__sockets:
            ret += s.str(indent + 2)
        return ret


class Socket(BaseSocket):
    def str(self, indent):
        ret = indent * " "
        ret += "Socket %s %s:%s/%s\n" % (self.__name, self.__ip, self.__port_number, self.__protocol)
        for i in self.__instances:
            ret += i.str(indent + 2)
        for i in self.__instance_clients:
            ret += i.str(indent + 2)
        for c in self.__event_handlers:
            ret += c.str(indent + 2)
        for c in self.__consumed_event_groups:
            ret += c.str(indent + 2)
        return ret


class SOMEIPServiceInstance(SOMEIPBaseServiceInstance):
    def str(self, indent):
        ret = indent * " "
        ret += f"ServiceInstance Service-ID: 0x{self.__service.serviceid():04x} "
        ret += f"Version: {self.__service.versionstring()} "
        ret += f"Instance-ID: 0x{self.__instance_id:04x} "
        ret += f"Protover: {self.__protocol_version}\n"
        return ret

    def key(self):
        return "0x%04x-0x%02x-0x%04x-%s" % (
            self.service().service_id(), self.service().major_version(), self.instance_id(), self.service().name())


class SOMEIPServiceInstanceClient(SOMEIPBaseServiceInstanceClient):
    def str(self, indent):
        ret = indent * " "
        ret += f"ServiceInstanceClient Service-ID: 0x{self.service().serviceid():04x} "
        ret += f"Version: {self.service().versionstring()} "
        ret += f"Instance-ID: 0x{self.instance_id():04x} "
        ret += f"Protover: {self.protocol_version()}\n"
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
        ret += "%s (id: 0x%04x  ver: %d.%d)\n" % (self.name(), self.service_id(),
                                                  self.major_version(), self.minor_version())

        for method in self.methods().values():
            ret += method.str(indent + 2)

        for event in self.events().values():
            ret += event.str(indent + 2)

        for field in self.fields().values():
            ret += field.str(indent + 2)

        for eg in self.eventgroups().values():
            ret += eg.str(indent + 2)

        return ret


class SOMEIPServiceMethod(SOMEIPBaseServiceMethod):
    def str(self, indent):
        ret = indent * " "
        ret += "Method %s (id: 0x%04x  type: %s  reli: %s)\n" % (self.name(),
                                                                 self.method_id(),
                                                                 self.call_type(),
                                                                 self.reliable())

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
        ret = indent * " "
        ret += "Event %s (id: 0x%04x  reli: %s)\n" % (self.name(),
                                                      self.method_id(),
                                                      self.reliable())

        for param in self.params():
            ret += param.str(indent + 2)

        return ret


class SOMEIPServiceField(SOMEIPBaseServiceField):
    def str(self, indent):
        ret = indent * " "
        ret += f"Field {self.name()}\n"

        indent += 2
        if self.getter() is not None:
            ret += indent * " "
            ret += "Getter(id: 0x%04x  reli: %s)\n" % (self.getter().method_id(), self.getter().reliable())

        if self.setter() is not None:
            ret += indent * " "
            ret += "Setter(id: 0x%04x  reli: %s)\n" % (self.setter().method_id(), self.setter().reliable())

        if self.notifier() is not None:
            ret += indent * " "
            ret += "Notifier(id: 0x%04x  reli: %s)\n" % (self.notifier().method_id(), self.notifier().reliable())

        ret += indent * " "
        ret += "Parameters:\n"
        for param in self.params():
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
        ret += "Parameter %d %s (mandatory: %s)\n" % (self.position(), self.name(), self.mandatory())
        if self.data_type() is None:
            ret += "%sNone\n" % ((indent + 2) * " ")
        else:
            ret += self.data_type().str(indent + 2)

        return ret


class SOMEIPParameterBasetype(SOMEIPBaseParameterBasetype):
    def str(self, indent):
        endian = "BE"
        if not self.big_endian():
            endian = "LE"

        ret = indent * " "
        ret += "%s %s %s (%d;%d)\n" % (self.name(), self.data_type(), endian,
                                       self.bit_length_base_type(), self.bit_length_encoded_type())
        return ret


class SOMEIPParameterString(SOMEIPBaseParameterString):
    def str(self, indent):
        endian = "BE" if self.big_endian() else "LE"

        ret = indent * " "
        ret += "String %s %s %s (%d;%d) term: %s len: %d pad: %d\n" % (self.name(), self.char_type(), endian,
                                                                       self.lower_limit(), self.upper_limit(),
                                                                       self.termination(), self.length_of_length(),
                                                                       self.pad_to())
        return ret


class SOMEIPParameterArray(SOMEIPBaseParameterArray):
    def str(self, indent):
        ret = indent * " "
        ret += f"Array {self.name()}:\n"
        for dim in self.dimensions():
            ret += self.dimensions()[dim].str(indent + 2)
        if self.child() is None:
            ret += "%sNone\n" % ((indent + 2) * " ")
        else:
            ret += self.child().str(indent + 2)

        return ret


class SOMEIPParameterArrayDim(SOMEIPBaseParameterArrayDimension):
    def str(self, indent):
        ret = indent * " "
        ret += "Dimension %d [%d-%d] lengthOfLength: %d padding: %d\n" % (self.dimension(),
                                                                          self.lower_limit(),
                                                                          self.upper_limit(),
                                                                          self.length_of_length(),
                                                                          self.pad_to())
        return ret


class SOMEIPParameterStruct(SOMEIPBaseParameterStruct):
    def str(self, indent):
        ret = indent * " "
        ret += f"Struct {self.name()}:\n"
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
        ret += "%d %s (mandatory: %s)\n" % (self.position(), self.name(), self.mandatory())

        if self.child() is not None:
            ret += self.child().str(indent + 2)

        return ret


class SOMEIPParameterTypedef(SOMEIPBaseParameterTypedef):
    def str(self, indent):
        ret = indent * " "
        ret += "Typedef: %s %s\n" % (self.name(), self.name2())
        if self.child() is not None:
            ret += self.child().str(indent + 2)
        return ret


class SOMEIPParameterEnumeration(SOMEIPBaseParameterEnumeration):
    def str(self, indent):
        ret = indent * " "
        ret += f"Enumeration {self.name()}\n"
        ret += self.child().str(indent + 2)
        for i in self.items():
            i.str(indent + 2)
        return ret


class SOMEIPParameterEnumerationItem(SOMEIPBaseParameterEnumerationItem):
    def str(self, indent):
        ret = indent * " "
        ret += f"{self.value()}: {self.name()}"
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

        ret += "%d %s (mandatory: %s)\n" % (self.index(), self.name(), self.mandatory())

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


def read_string_file(f):
    ret = []

    if f is not None:
        for line in f.readlines():
            if line[0] != "#":
                ret.append(line.rstrip())

    return ret


def read_hex_integer_file(f):
    ret = []

    if f is not None:
        for line in f.readlines():
            if line[0] != "#":
                try:
                    i = int(line.rstrip(), 16)
                    ret.append(i)
                except ValueError:
                    print("can't parse line: ", line)

    return ret


def order_ecu_names(ecu_names, ecu_order):
    ret = []

    for e in ecu_order:
        if e in ecu_names:
            ret.append(e)
            ecu_names.remove(e)

    # now add the rest
    for e in ecu_names:
        ret.append(e)

    return ret


def calc_matrix(ignored_ecus, ignore_services, ecu_names, data):
    # create a matrix of Server -> Client -> Service Instances
    # ignore the ECUs on the ignored ECU list
    matrix = {}
    for s in ecu_names:
        matrix[s] = {}
        for c in ecu_names:
            matrix[s][c] = []

    for server in data.keys():
        if server not in ignored_ecus:
            if server not in matrix:
                matrix[server] = {}
            for si in data[server].keys():
                sid = int(si[0:6], 16)
                if sid not in ignore_services:
                    for client in data[server][si]:
                        if client not in ignored_ecus:
                            if client not in matrix[server]:
                                matrix[server][client] = []
                            matrix[server][client].append(si)

    return matrix


# returns a list of affected service-ids
def generate_event_multiple_eg(target_dir, file_no_ext, postfix, conf_factory):
    ret = []

    textfile = os.path.join(target_dir, file_no_ext + postfix)
    f = open(textfile, "w")
    f.write("Service;Service-ID;Type;Event/Field; Method-ID; EGs of Event/Field;Provider\n")

    # stats
    num_services = 0
    num_events_fields = 0

    for service in sorted(conf_factory.get_services().values(), key=lambda x: x.str(0)):

        overlap_found = False
        refs_events = {}
        refs_fields = {}

        providers = []
        for si in service.instances():
            if si.socket() is not None:
                tmp = [si.instance_id(), si.socket().interface().controller().ecu().name()]
                if tmp not in providers:
                    providers.append(tmp)

        # transform into ref matrices
        for eg in service.eventgroups().values():
            for event_id in eg.event_ids():
                if event_id not in refs_events.keys():
                    refs_events[event_id] = []
                refs_events[event_id].append(eg.eventgroup_id())
            for notifier_id in eg.field_ids():
                if notifier_id not in refs_fields.keys():
                    refs_fields[notifier_id] = []
                refs_fields[notifier_id].append(eg.eventgroup_id())

        # now check for dupes
        for event_id in refs_events.keys():
            egs = refs_events[event_id]
            if len(egs) > 1:
                egs_text = ""
                for e in egs:
                    egs_text += f"0x{e:04x}, "

                prov_text = ""
                for pp in providers:
                    prov_text += ("0x%04x-%s, " % (pp[0], pp[1]))
                f.write("%s;0x%04x;Event;%s;0x%04x;%s;%s\n" %
                        (service.name(), service.service_id(), service.event(event_id).name(), event_id, egs_text,
                         prov_text))
                num_events_fields += 1
                overlap_found = True
        for field_id in refs_fields.keys():
            egs = refs_fields[field_id]

            if len(egs) > 1:
                egs_text = ""
                for e in egs:
                    egs_text += f"0x{e:04x}, "

                prov_text = ""
                for pp in providers:
                    prov_text += ("0x%04x-%s, " % (pp[0], pp[1]))

                f.write("%s;0x%04x;Field;%s;0x%04x;%s;%s\n" %
                        (service.name(), service.service_id(), service.field(field_id).name(), field_id, egs_text,
                         prov_text))
                num_events_fields += 1
                overlap_found = True
        if overlap_found:
            num_services += 1
            ret.append(service.service_id())
    f.close()

    return ret


def generate_count_file(target_dir, file_no_ext, postfix, conf_factory):
    # Count Events/Fields per EG
    textfile = os.path.join(target_dir, file_no_ext + postfix)
    f = open(textfile, "w")

    # write header
    f.write("Service; Service-ID; Service all Event/Notifier bytes; Eventgroup; Eventgroup-ID; Server;" +
            " Eventgroup Count; Event/Notifier Count; EG all Event/Notifier bytes\n")

    for service in sorted(conf_factory.get_services().values(), key=lambda x: x.str(0)):

        # First pass, we calculate all sizes
        max_size_egs = {}
        max_size_service = 0

        for eg in service.eventgroups().values():
            maxsize = 0
            for event_id in eg.event_ids():
                maxsize += service.event(event_id).size_max_out()

            for field_id in eg.field_ids():
                maxsize += service.field(field_id).size_max_out()
            max_size_egs[eg.eventgroup_id()] = maxsize
            max_size_service += maxsize

        # Second pass, get the rest.
        for eg in service.eventgroups().values():
            event_count = len(eg.event_ids()) + len(eg.field_ids())

            sis = ""
            for si in service.instances():
                sis = sis + si.socket().interface().controller().ecu().name() + ","

            f.write("%s;0x%04x;%d;%s;0x%04x;%s;%d;%d;%d\n" % (
                service.name(), service.service_id(), max_size_service, eg.name(), eg.eventgroup_id(), sis,
                len(service.eventgroups()),
                event_count, max_size_egs[eg.eventgroup_id()]))

    f.close()


def generate_size_file(target_dir, file_no_ext, postfix, conf_factory):
    tmp = conf_factory.get_size_of_methods()

    textfile = os.path.join(target_dir, file_no_ext + postfix)
    f = open(textfile, "w")

    # write header
    f.write(
        "Service; Service-ID; Service-Instances; Method/Event/Field; Type; Reliable; Method-ID/Event-ID/Notifier-ID;" +
        " Getter-ID; Setter-ID; In-Min-Size; In-Min-Size; Out-Min-Size; Out-Max-Size\n")

    for i in tmp:
        sis = ""
        method_id = -1
        getter_id = -1
        setter_id = -1

        for si in i[0].instances():
            sis = sis + si.socket().interface().controller().ecu().name() + ","

        if i[2] == "Field":
            reliable_true = False
            reliable_false = False
            if i[1].getter() is not None:
                getter_id = i[1].getter().method_id()
                if i[1].getter().reliable():
                    reliable_true = True
                else:
                    reliable_false = True
            if i[1].setter() is not None:
                setter_id = i[1].setter().method_id()
                if i[1].setter().reliable():
                    reliable_true = True
                else:
                    reliable_false = True
            if i[1].notifier() is not None:
                method_id = i[1].notifier().method_id()
                if i[1].notifier().reliable():
                    reliable_true = True
                else:
                    reliable_false = True
            if reliable_false and not reliable_true:
                reliable = "FALSE"
            elif not reliable_false and reliable_true:
                reliable = "TRUE"
            elif reliable_false and reliable_true:
                reliable = "MIXED"
            else:
                reliable = ""
        else:
            method_id = i[1].method_id()
            reliable = "TRUE" if i[1].reliable() else "FALSE"

        if method_id == -1:
            method_id = ""
        else:
            method_id = f"0x{method_id:04x}"

        if getter_id == -1:
            getter_id = ""
        else:
            getter_id = f"0x{getter_id:04x}"

        if setter_id == -1:
            setter_id = ""
        else:
            setter_id = f"0x{setter_id:04x}"

        f.write("%s;0x%04x;%s;%s;%s;%s;%s;%s;%s;%d;%d;%d;%d\n" % (
            i[0].name(), i[0].service_id(), sis, i[1].name(), i[2], reliable,
            method_id, getter_id, setter_id,
            i[1].size_min_in(), i[1].size_max_in(), i[1].size_min_out(), i[1].size_max_out()))
    f.close()


def generate_service_instance_matrix_file(target_dir, file_no_ext, postfix, ecu_names, ignore_services, data,
                                          service_with_overlapping_events):
    # dump out the service instance relations as a matrix: server+si x client
    textfile = os.path.join(target_dir, file_no_ext + postfix)
    f = open(textfile, "w")

    # write header
    f.write("%s;%s;%s;%s;" % ("Server", "Service Instances", "Overlapping Events/Fields?", "# Clients"))
    for client in ecu_names:
        f.write(f"{client};")
    f.write("\n")

    for server in ecu_names:
        if server in data.keys():
            for si in data[server].keys():
                sid = int(si[0:6], 16)
                overlap = 1 if sid in service_with_overlapping_events else 0
                if sid not in ignore_services:
                    client_count = 0
                    for client in ecu_names:
                        if client in data[server][si]:
                            client_count += 1
                    f.write("%s;%s;%d;%d;" % (server, si, overlap, client_count))
                    for client in ecu_names:
                        if client in data[server][si]:
                            f.write("1;")
                        else:
                            f.write("0;")
                    f.write("\n")
    f.close()


def generate_service_list(target_dir, file_no_ext, postfix, ignored_ecus, matrix):
    # dump out a list of service interfaces per Server-Client-Relation based on the matrix
    textfile = os.path.join(target_dir, file_no_ext + postfix)

    f = open(textfile, "w")
    f.write("%s;%s;%s\n" % ("Server", "Client", "Service Instances"))

    for server in matrix.keys():
        if server not in ignored_ecus:
            for client in matrix[server].keys():
                if client not in ignored_ecus:
                    si_list = list()
                    sis = ""
                    for si in matrix[server][client]:
                        si_list.append(si)
                    for si in sorted(si_list):
                        if sis != "":
                            sis += ","
                        sis += si

                    if sis != "":
                        f.write("%s;%s;%s\n" % (server, client, sis))
    f.close()


def generate_service_matrix(target_dir, file_no_ext, postfix, ecu_names, ignored_ecus, matrix):
    # dump out a matrix (=count of relations) based on the matrix
    textfile = os.path.join(target_dir, file_no_ext + postfix)
    f = open(textfile, "w")

    # header first
    for client in ecu_names:
        if client not in ignored_ecus:
            f.write(f";{client}")

    f.write(";\n")

    for server in ecu_names:
        if server not in ignored_ecus:
            f.write(f"{server};")

            for client in ecu_names:
                if client not in ignored_ecus:
                    f.write(f"{len(matrix[server][client])};")

        f.write("\n")
    f.close()


def parse_arguments():
    parser = argparse.ArgumentParser(description='Converting configuration to reports.')
    parser.add_argument('type', choices=parser_formats, help='format')
    parser.add_argument('filename', help='filename or directory', type=lambda x: is_file_or_dir_valid(parser, x))
    parser.add_argument('--ignore-ecus', type=argparse.FileType('r'), default=None, help='ignore-ecus-list')
    parser.add_argument('--ignore-services', type=argparse.FileType('r'), default=None, help='ignore-services-list')
    parser.add_argument('--ecu-order', type=argparse.FileType('r'), default=None, help='ecu-order')

    args = parser.parse_args()
    return args


def main():
    print("Converting configuration to reports")
    args = parse_arguments()

    # load configs
    ignored_ecus = read_string_file(args.ignore_ecus)
    ignore_services = read_hex_integer_file(args.ignore_services)
    ecu_order = read_string_file(args.ecu_order)

    conf_factory = SimpleConfigurationFactory()
    output_dir = parse_input_files(args.filename, args.type, conf_factory)

    # setup output path
    (path, f) = os.path.split(args.filename)
    file_no_ext = ".".join(f.split('.')[:-1])
    target_dir = os.path.join(output_dir, "reports")

    if not os.path.exists(target_dir):
        os.makedirs(target_dir)
        time.sleep(0.5)

    # get the names of all ECUs not on the ignored_ecus list
    ecu_names_all = sorted(conf_factory.get_ecu_names())
    ecu_names = sorted(conf_factory.get_ecu_names())
    for i in ignored_ecus:
        if i in ecu_names:
            ecu_names.remove(i)

    ecu_names = order_ecu_names(ecu_names, ecu_order)
    ecu_names_all = order_ecu_names(ecu_names_all, ecu_order)

    # get the data ready
    data = conf_factory.get_service_instance_client_relations()
    matrix = calc_matrix(ignored_ecus, ignore_services, ecu_names, data)

    # generate the outputs
    print("")
    print("Generating overlapping EG file")
    service_with_overlapping_events = generate_event_multiple_eg(target_dir, file_no_ext,
                                                                 "__events_fields_in_multiple_EGs.csv", conf_factory)

    print("Generating Eventgroup statistics")
    generate_count_file(target_dir, file_no_ext, "__eventgroup_stats.csv", conf_factory)

    print("Generating sizes file")
    generate_size_file(target_dir, file_no_ext, "__sizes.csv", conf_factory)

    print("Generating instance matrices")
    generate_service_instance_matrix_file(target_dir, file_no_ext, "__si_matrix_filtered.csv", ecu_names, ignore_services,
                                          data, service_with_overlapping_events)
    generate_service_instance_matrix_file(target_dir, file_no_ext, "__si_matrix_full.csv", ecu_names_all, [], data,
                                          service_with_overlapping_events)

    print("Generating service instance usage list")
    generate_service_list(target_dir, file_no_ext, "__service_instance_usage_list.csv", ignored_ecus, matrix)

    print("Generating service instance usage matrix")
    generate_service_matrix(target_dir, file_no_ext, "__service_instance_usage_matrix.csv", ecu_names, ignored_ecus,
                            matrix)

    print("Done.")


# only call main, if we are started directly
if __name__ == "__main__":
    main()
