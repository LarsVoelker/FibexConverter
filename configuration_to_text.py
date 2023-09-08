#!/usr/bin/python

# Automotive configuration file scripts
# Copyright (C) 2015-2022  Dr. Lars Voelker
# Copyright (C) 2018-2019  Dr. Lars Voelker, BMW AG
# Copyright (C) 2020-2022  Dr. Lars Voelker, Technica Engineering GmbH

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

import sys
import time
import os.path
import argparse

from parser_dispatcher import *  # @UnusedWildImport
from configuration_base_classes import *  # @UnusedWildImport


class SimpleConfigurationFactory(BaseConfigurationFactory):

    def __init__(self):
        self.__services__ = dict()
        self.__services_long__ = dict()
        self.__switches__ = dict()
        self.__ecus__ = dict()

    def create_switch(self, name, ecu, ports):
        ret = Switch(name, ecu, ports)
        assert (name not in self.__switches__)
        self.__switches__[name] = ret
        return ret

    def create_switch_port(self, portid, ctrl, port, default_vlan, vlans):
        return SwitchPort(portid, ctrl, port, default_vlan, vlans)

    def create_ecu(self, name, controllers):
        ret = ECU(name, controllers)
        assert (name not in self.__ecus__)
        self.__ecus__[name] = ret
        return ret

    def create_controller(self, name, interfaces):
        ret = Controller(name, interfaces)
        return ret

    def create_interface(self, name, vlanid, ips, sockets):
        ret = Interface(name, vlanid, ips, sockets)
        return ret

    def create_socket(self, name, ip, proto, portnumber, serviceinstances, serviceinstanceclients, eventhandlers,
                      eventgroupreceivers):
        ret = Socket(name, ip, proto, portnumber, serviceinstances, serviceinstanceclients, eventhandlers,
                     eventgroupreceivers)
        return ret

    def create_someip_service_instance(self, service, instanceid, protover):
        ret = SOMEIPServiceInstance(service, instanceid, protover)
        return ret

    def create_someip_service_instance_client(self, service, instanceid, protover, server):
        ret = SOMEIPServiceInstanceClient(service, instanceid, protover, server)
        return ret

    def create_someip_service_eventgroup_sender(self, serviceinstance, eventgroupid):
        ret = SOMEIPServiceEventgroupSender(serviceinstance, eventgroupid)
        return ret

    def create_someip_service_eventgroup_receiver(self, serviceinstance, eventgroupid, sender):
        ret = SOMEIPServiceEventgroupReceiver(serviceinstance, eventgroupid, sender)
        return ret

    def create_someip_service(self, name, serviceid, majorver, minorver, methods, events, fields, eventgroups):
        ret = SOMEIPService(name, serviceid, majorver, minorver, methods, events, fields, eventgroups)
        print(f"Adding Service(Name: {name} ID: 0x{serviceid:04x} Ver: {majorver:d}.{minorver:d})")
        self.add_service(serviceid, majorver, minorver, ret)
        return ret

    def create_someip_service_method(self, name, methodid, calltype, relia, inparams, outparams,
                                     reqdebounce=-1, reqmaxretention=-1, resmaxretention=-1, tlv=False):
        ret = SOMEIPServiceMethod(name, methodid, calltype, relia, inparams, outparams,
                                  reqdebounce, reqmaxretention, resmaxretention, tlv)
        return ret

    def create_someip_service_event(self, name, methodid, relia, params,
                                    debounce=-1, maxretention=-1, tlv=False):
        ret = SOMEIPServiceEvent(name, methodid, relia, params,
                                 debounce, maxretention, tlv)
        return ret

    def create_someip_service_field(self, name, getterid, setterid, notifierid, getterreli, setterreli, notifierreli,
                                    params,
                                    getter_debouncereq, getter_retentionreq, getter_retentionres,
                                    setter_debouncereq, setter_retentionreq, setter_retentionres,
                                    notifier_debounce, notifier_retention, tlv=False):
        ret = SOMEIPServiceField(self, name, getterid, setterid, notifierid, getterreli, setterreli, notifierreli,
                                 params,
                                 getter_debouncereq, getter_retentionreq, getter_retentionres,
                                 setter_debouncereq, setter_retentionreq, setter_retentionres,
                                 notifier_debounce, notifier_retention, tlv)
        return ret

    def create_someip_service_eventgroup(self, name, eid, eventids, fieldids):
        ret = SOMEIPServiceEventgroup(name, eid, eventids, fieldids)
        return ret

    def create_someip_parameter(self, position, name, desc, mandatory, datatype, signal):
        ret = SOMEIPParameter(position, name, desc, mandatory, datatype, signal)
        return ret

    def create_someip_parameter_basetype(self, name, datatype, bigendian, bitlength_basetype, bitlength_encoded_type):
        ret = SOMEIPParameterBasetype(name, datatype, bigendian, bitlength_basetype, bitlength_encoded_type)
        return ret

    def create_someip_parameter_string(self, name, chartype, bigendian, lowerlimit, upperlimit, termination,
                                       length_of_length, pad_to):
        ret = SOMEIPParameterString(name, chartype, bigendian, lowerlimit, upperlimit, termination, length_of_length,
                                    pad_to)
        return ret

    def create_someip_parameter_array(self, name, dims, child):
        ret = SOMEIPParameterArray(name, dims, child)
        return ret

    def create_someip_parameter_array_dim(self, dim, lowerlimit, upperlimit, length_of_length, pad_to):
        ret = SOMEIPParameterArrayDim(dim, lowerlimit, upperlimit, length_of_length, pad_to)
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

    def create_legacy_signal(self, id, name, compu_scale, compu_consts):
        ret = SOMEIPLegacySignal(id, name, compu_scale, compu_consts)
        return ret

    def add_service(self, serviceid, majorver, minorver, service):
        sid = f"{serviceid:04x}-{majorver:02x}-{minorver:08x}"
        if sid in self.__services_long__:
            print(
                f"ERROR: Service (SID: 0x{serviceid:04x}, Major-Ver: {majorver:d}, " +
                f"Minor-Ver: {minorver:d}) already exists! Not overriding it!"
            )
            return False
        self.__services_long__[sid] = service

        sid = f"{serviceid:04x}-{majorver:02x}"
        if sid in self.__services__:
            print(
                f"ERROR: Service (SID: 0x{serviceid:04x}, Major-Ver: {majorver:d})" +
                f"already exists with a different Minor Version (not {minorver:d})! Not overriding it!"
            )
            return False
        self.__services__[sid] = service
        return True

    def get_service(self, serviceid, majorver, minorver=None):
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

    def __str__(self):
        ret = "Services: \n"
        for serviceid in sorted(self.__services__):
            ret += self.__services__[serviceid].str(2)

        ret += "\nECUs: \n"
        for name in sorted(self.__ecus__):
            ret += self.__ecus__[name].str(2)

        ret += "\nSwitches: \n"
        for name in sorted(self.__switches__):
            ret += self.__switches__[name].str(2, print_ecu_name=True)

        return ret


class Switch(BaseSwitch):
    def str(self, indent, print_ecu_name=False):
        ret = indent * " "
        tmp = f" of ECU {self.__ecu__.name()}" if print_ecu_name else ""
        ret += f"Switch {self.__name__}{tmp}\n"
        for port in self.__ports__:
            ret += port.str(indent + 2)
        return ret


class SwitchPort(BaseSwitchPort):
    def str(self, indent):
        ret = indent * " "
        ret += f"SwitchPort {self.__portid__} <-> "
        if self.__port__ is not None:
            tmp = f"of {self.__port__.switch().name()}" if self.__port__.switch() is not None else ""
            ret += f"SwitchPort {self.__port__.portid()} {tmp}\n"
        elif self.__ctrl__ is not None:
            ret += f"Controller {self.__ctrl__.name()} of {self.__ctrl__.ecu().name()}\n"
        else:
            ret += "\n"

        ret += (indent + 2) * " "
        ret += f"VLANs ({','.join(self.vlans_as_strings())})\n"
        return ret


class ECU(BaseECU):
    def str(self, indent):
        ret = indent * " "
        ret += f"ECU {self.__name__}\n"

        for c in self.__controllers__:
            ret += c.str(indent + 2)

        for s in self.__switches__:
            ret += s.str(indent + 2)

        return ret


class Controller(BaseController):
    def str(self, indent):
        ret = indent * " "
        ret += f"CTRL {self.__name__}\n"
        for i in self.__interfaces__:
            ret += i.str(indent + 2)

        return ret


class Interface(BaseInterface):
    def str(self, indent):
        ret = indent * " "
        ret += f"Interface {self.__vlanname__} (VLAN-ID: 0x{self.__vlanid__:x})\n"

        for ip in sorted(self.ips(), key=lambda x: ip_to_key(x)):
            if is_ip(ip) and not is_ip_mcast(ip):
                ret += (indent + 2) * " "
                ret += f"IP: {ip}\n"

        for s in self.__sockets__:
            ret += s.str(indent + 2)

        return ret


class Socket(BaseSocket):
    def str(self, indent):
        ret = indent * " "
        ret += f"Socket {self.__name__} {self.__ip__}:{self.__portnumber__}/{self.__proto__}\n"
        for i in self.__instances__:
            ret += i.str(indent + 2)
        for i in self.__instanceclients__:
            ret += i.str(indent + 2)
        for c in self.__ehs__:
            ret += c.str(indent + 2)
        for c in self.__cegs__:
            ret += c.str(indent + 2)
        return ret


class SOMEIPServiceInstance(SOMEIPBaseServiceInstance):
    def str(self, indent):
        ret = indent * " "
        ret += f"ServiceInstance Service-ID: 0x{self.__service__.serviceid():04x} "
        ret += f"Version: {self.__service__.versionstring()} "
        ret += f"Instance-ID: 0x{self.__instanceid__:04x} "
        ret += f"Protover: {self.__protover__:d}\n"
        return ret


class SOMEIPServiceInstanceClient(SOMEIPBaseServiceInstanceClient):
    def str(self, indent):
        ret = indent * " "
        ret += f"ServiceInstanceClient Service-ID: 0x{self.__service__.serviceid():04x} "
        ret += f"Version: {self.__service__.versionstring()} "
        ret += f"Instance-ID: 0x{self.__instanceid__:04x} "
        ret += f"Protover: {self.__protover__:d}\n"
        return ret


class SOMEIPServiceEventgroupSender(SOMEIPBaseServiceEventgroupSender):
    def str(self, indent):
        ret = indent * " "
        ret += f"EventgroupSender: Service-ID: 0x{self.__si__.service().serviceid():04x} "
        ret += f"Instance-ID: 0x{self.__si__.instanceid():04x} "
        ret += f"Eventgroup-ID: 0x{self.__eventgroupid__:04x}\n"
        return ret


class SOMEIPServiceEventgroupReceiver(SOMEIPBaseServiceEventgroupReceiver):
    def str(self, indent):
        ret = indent * " "
        ret += f"EventgroupReceiver: Service-ID: 0x{self.__si__.service().serviceid():04x} "
        ret += f"Instance-ID: 0x{self.__si__.instanceid():04x} "
        ret += f"Eventgroup-ID: 0x{self.__eventgroupid__:04x}\n"
        return ret


class SOMEIPService(SOMEIPBaseService):
    def str(self, indent):
        ret = indent * " "
        ret += f"Service {self.__name__} (id: 0x{self.__serviceid__:04x} ver: {self.__major__:d}.{self.__minor__:d})\n"

        for methodid in sorted(self.__methods__):
            ret += self.__methods__[methodid].str(indent + 2)

        for eventsid in sorted(self.__events__):
            ret += self.__events__[eventsid].str(indent + 2)

        for fieldid in sorted(self.__fields__, key=lambda x: (x is None, x)):
            ret += self.__fields__[fieldid].str(indent + 2)

        for egid in sorted(self.__eventgroups__):
            ret += self.__eventgroups__[egid].str(indent + 2)

        return ret


class SOMEIPServiceMethod(SOMEIPBaseServiceMethod):
    def str(self, indent):
        extra = ""
        if self.__reqdebouncetime__ >= 0:
            extra += f" debounce:{str(self.__reqdebouncetime__)}s"
        if self.__reqretentiontime___ >= 0:
            extra += f" max_request_retention:{str(self.__reqretentiontime___)}s"
        if self.__resretentiontime___ >= 0:
            extra += f" max_response_retention:{str(self.__resretentiontime___)}s"

        extra += ' TLV' if self.__tlv__ else ''
        ret = indent * " "
        ret += f"Method {self.__name__} (id:0x{self.__methodid__:04x} type:{self.__calltype__} " + \
               f"reli:{self.__reliable__}{extra})\n"

        ret += (indent + 2) * " "
        ret += "In Parameters: \n"
        for param in self.__inparams__:
            ret += param.str(indent + 4)

        ret += (indent + 2) * " "
        ret += "Out Parameters: \n"
        for param in self.__outparams__:
            ret += param.str(indent + 4)

        return ret


class SOMEIPServiceEvent(SOMEIPBaseServiceEvent):
    def str(self, indent):
        extra = ""
        if self.__debouncetime__ >= 0:
            extra += f" debounce:{str(self.__debouncetime__)}s"
        if self.__retentiontime___ >= 0:
            extra += f" max_retention:{str(self.__retentiontime___)}s"

        ret = indent * " "
        extra += ', TLV:True' if self.__tlv__ else ''
        if self.legacy():
            ret += f"Event {self.__name__} (id:0x{self.__methodid__:04x} reli:{self.__reliable__}{extra}, Legacy PDU)\n"
        else:
            ret += f"Event {self.__name__} (id:0x{self.__methodid__:04x} reli:{self.__reliable__}{extra})\n"

        for param in self.__params__:
            ret += param.str(indent + 2)

        return ret


class SOMEIPServiceField(SOMEIPBaseServiceField):
    def str(self, indent):
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
            ret += f"Notifier(id:0x{self.__notifier__.methodid():04x} reli:{self.__notifier__.reliable()}{extra}" \
                   f"{legacy})\n"

        ret += indent * " "
        ret += "Parameters:\n"
        for param in self.__params__:
            if param is not None:
                ret += param.str(indent + 2)

        return ret


class SOMEIPServiceEventgroup(SOMEIPBaseServiceEventgroup):
    def str(self, indent):
        ret = indent * " "
        ret += f"Eventgroup {self.__name__} (id: 0x{self.__id__:04x})\n"

        if len(self.__eventids__) > 0:
            ret += (2 + indent) * " "
            ret += "Events: "
            first = True
            for eid in self.__eventids__:
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
            for fid in self.__fieldids__:
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
        ret += f"Parameter {self.__position__:d} {self.__name__} (mandatory: {self.__mandatory__})\n"
        if self.__datatype__ is None:
            ret += f"{(indent + 2) * ' '}None\n"
        else:
            ret += self.__datatype__.str(indent + 2)
        if self.__signal__ is not None:
            ret += self.__signal__.str(indent + 2)
        return ret


class SOMEIPParameterBasetype(SOMEIPBaseParameterBasetype):
    def str(self, indent):
        endian = "BE"
        if not self.__bigendian__:
            endian = "LE"

        ret = indent * " "
        ret += f"{self.__name__} {self.__datatype__} {endian} ({self.__bitlength_basetype__:d};" + \
               f"{self.__bitlength_encoded_type__:d})\n"
        return ret


class SOMEIPParameterString(SOMEIPBaseParameterString):
    def str(self, indent):
        endian = "BE"
        if not self.__bigendian__:
            endian = "LE"

        ret = indent * " "
        ret += f"String {self.__name__} {self.__chartype__} {endian} ({self.__lowerlimit__:d};" + \
               f"{self.__upperlimit__:d}) term: {self.__termination__} " + \
               f"len: {self.__lengthOfLength__:d} pad: {self.__padTo__:d}\n"
        return ret


class SOMEIPParameterArray(SOMEIPBaseParameterArray):
    def str(self, indent):
        ret = indent * " "
        ret += f"Array {self.__name__}:\n"
        for dim in self.__dims__:
            ret += self.__dims__[dim].str(indent + 2)
        if self.__child__ is None:
            ret += f"{(indent + 2) * ' '}None\n"
        else:
            ret += self.__child__.str(indent + 2)

        return ret


class SOMEIPParameterArrayDim(SOMEIPBaseParameterArrayDim):
    def str(self, indent):
        ret = indent * " "
        ret += f"Dimension {self.__dim__:d} [{self.__lowerlimit__:d}-{self.__upperlimit__:d}] " + \
               f"lengthOfLength: {self.__lengthOfLength__:d} padding: {self.__padTo__:d}\n"
        return ret


class SOMEIPParameterStruct(SOMEIPBaseParameterStruct):
    def str(self, indent):
        ret = indent * " "
        tlv = ' (TLV: True)' if self.__tlv__ else ''

        ret += f"Struct {self.__name__}{tlv}:\n"
        if self.__members__ is not None:
            for m in sorted(self.__members__.keys()):
                member = self.__members__[m]
                if member is not None:
                    ret += member.str(indent + 2)
                else:
                    print("ERROR: struct member == None!")

        return ret


class SOMEIPParameterStructMember(SOMEIPBaseParameterStructMember):
    def str(self, indent):
        ret = indent * " "
        ret += f"{self.__position__:d} {self.__name__} (mandatory: {self.__mandatory__})\n"

        if self.__child__ is not None:
            ret += self.__child__.str(indent + 2)
        if self.__signal__ is not None:
            ret += self.__signal__.str(indent + 2)

        return ret


class SOMEIPParameterTypedef(SOMEIPBaseParameterTypedef):
    def str(self, indent):
        ret = indent * " "
        ret += f"Typedef: {self.__name__} {self.__name2__}\n"
        if self.__child__ is not None:
            ret += self.__child__.str(indent + 2)
        return ret


class SOMEIPParameterEnumeration(SOMEIPBaseParameterEnumeration):
    def str(self, indent):
        ret = indent * " "
        ret += f"Enumeration {self.__name__}\n"
        ret += self.__child__.str(indent + 2)
        for i in self.__items__:
            i.str(indent + 2)
        return ret


class SOMEIPParameterEnumerationItem(SOMEIPBaseParameterEnumerationItem):
    def str(self, indent):
        ret = indent * " "
        ret += f"{self.__value__}: {self.__name__}"
        return ret


class SOMEIPParameterUnion(SOMEIPBaseParameterUnion):
    def str(self, indent):
        ret = indent * " "
        ret += f"Union {self.__name__}:\n"
        if self.__members__ is not None:
            for m in sorted(self.__members__.keys()):
                member = self.__members__[m]
                if member is not None:
                    ret += member.str(indent + 2)
                else:
                    print("ERROR: union member == None!")

        return ret


class SOMEIPParameterUnionMember(SOMEIPBaseParameterUnionMember):
    def str(self, indent):
        ret = indent * " "

        ret += f"{self.__index__:d} {self.__name__} (mandatory: {self.__mandatory__})\n"

        if self.__child__ is not None:
            ret += self.__child__.str(indent + 2)

        return ret


class SOMEIPLegacySignal(SOMEIPBaseLegacySignal):
    def str(self, indent):
        ret = indent * " "
        ret += f"Signal {self.__name__}"
        if self.__compu_scale__ is not None and len(self.__compu_scale__) == 3:
            ret += f", f(x) = {self.__compu_scale__[0]} + {self.__compu_scale__[1]}/{self.__compu_scale__[2]} * x"
        if self.__compu_consts__ is not None and len(self.__compu_consts__) > 0:
            ret += f", Consts: "
            first = True
            for name, start, end in self.__compu_consts__:
                if not first:
                    first = True
                else:
                    ret += ", "
                ret += f"{name} ({start}-{end})"
            ret += f" "
        return ret + "\n"


def parse_arguments():
    parser = argparse.ArgumentParser(description='Converting configuration to text.')
    parser.add_argument('type', choices=parser_formats, help='format')
    parser.add_argument('filename', help='filename or directory', type=lambda x: is_file_or_dir_valid(parser, x))

    args = parser.parse_args()
    return args


def main():
    print("Converting configuration to text")
    args = parse_arguments()

    conf_factory = SimpleConfigurationFactory()
    output_dir = parse_input_files(args.filename, args.type, conf_factory)

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
