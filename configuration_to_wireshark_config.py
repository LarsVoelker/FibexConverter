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
import os.path
import sys
import time

from configuration_base_classes import (
    BaseConfigurationFactory,
    BaseECU,
    BaseInterface,
    BaseSocket,
    SOMEIPBaseParameterArray,
    SOMEIPBaseParameterArrayDimension,
    SOMEIPBaseParameterBasetype,
    SOMEIPBaseParameterBitfield,
    SOMEIPBaseParameterEnumeration,
    SOMEIPBaseParameterEnumerationItem,
    SOMEIPBaseParameterString,
    SOMEIPBaseParameterStruct,
    SOMEIPBaseParameterTypedef,
    SOMEIPBaseParameterUnion,
    SOMEIPBaseService,
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

DEBUG_LEGACY_STRIPPING = False


class WiresharkParameterTypes:
    basetype = 1
    string = 2
    array = 3
    struct = 4
    union = 5
    typedef = 6
    enum = 7
    bitfield = 8


def cleanup_string(tmp):
    ret = tmp.replace("\"", "'")
    return ret


def cleanup_datatype_string(tmp):
    ret = tmp.lower()
    if ret.startswith("uint") or ret.startswith("a_uint"):
        ret = "uint"
    if ret.startswith("int") or ret.startswith("a_int"):
        ret = "int"
    if ret.startswith("float") or ret.startswith("a_float"):
        ret = "float"
    return ret

def translate_datatype(dt):
    if dt.lower().startswith("a_"):
        return dt[2:].lower()
    else:
        return dt.lower()

class WiresharkConfigurationFactory(BaseConfigurationFactory):

    def __init__(self):
        self.__services = dict()
        self.__services_long = dict()

        self.__param_arrays = dict()
        self.__param_base_types = dict()
        self.__param_enums = dict()
        self.__param_strings = dict()
        self.__param_structs = dict()
        self.__param_typedefs = dict()
        self.__param_unions = dict()
        self.__param_bitfields = dict()

        self.__global_id_arrays = 1
        self.__global_id_base_types = 1
        self.__global_id_enums = 1
        self.__global_id_strings = 1
        self.__global_id_structs = 1
        self.__global_id_typedefs = 1
        self.__global_id_unions = 1
        self.__global_id_bitfields = 1

        self.__global_id_signal_pdus = 1
        self.__global_id_bus = 1

        self.__space_optimized = True

        self.__ecus = dict()
        self.__channels = dict()
        self.__frame_id_pdu_id_mapping = dict()

        self.__eth_pdus = dict()

        self.__sockets = []

    def next_global_pdu_id(self):
        ret = self.__global_id_signal_pdus
        self.__global_id_signal_pdus += 1
        return ret

    def pdu_id_for_frame(self, frame):
        key = frame.original_id()
        present = key in self.__frame_id_pdu_id_mapping.keys()

        if not present:
            self.__frame_id_pdu_id_mapping[key] = self.next_global_pdu_id()

        return present, self.__frame_id_pdu_id_mapping[key]

    def next_global_bus_id(self):
        ret = self.__global_id_bus
        self.__global_id_bus += 1
        return ret

    def create_backlinks(self):
        for s in self.__services.values():
            s.create_backlinks(self)

    def create_ecu(self, name, controllers):
        tmp = BaseECU(name, controllers)
        print(f"Adding ECU {name}")
        if tmp in self.__ecus:
            print(f"Detected duplicate ECU {name}")
        self.__ecus[name] = tmp
        return tmp

    def create_interface(self, name, vlan_id, ips, sockets, input_frame_triggerings, output_frame_triggerings, fr_channel):
        ret = BaseInterface(name, vlan_id, ips, sockets, input_frame_triggerings, output_frame_triggerings, fr_channel)

        channel = self.__channels.setdefault(name, {})

        channel.setdefault("is_can", False)
        channel.setdefault("is_flexray", False)
        channel.setdefault("is_ethernet", False)

        if ret.is_can():
            channel["is_can"] = True
        if ret.is_flexray():
            channel["is_flexray"] = True
        if ret.is_ethernet():
            channel["is_ethernet"] = True

        channel["fr-channel"] = fr_channel

        frame_triggerings = channel.setdefault("frametriggerings", {})

        for key, value in input_frame_triggerings.items():
            frame_triggerings[key] = value
        for key, value in output_frame_triggerings.items():
            frame_triggerings[key] = value

        return ret

    def create_socket(self, name, ip, proto, port_number,
                      service_instances, service_instance_clients, event_handlers, event_group_receivers):
        tmp = BaseSocket(name, ip, proto, port_number,
                         service_instances, service_instance_clients, event_handlers, event_group_receivers)

        self.__sockets.append(tmp)
        return tmp

    def create_someip_service(self, name, service_id, major_version, minor_version, methods, events, fields, eventgroups):
        ret = SOMEIPBaseService(name, service_id, major_version, minor_version, methods, events, fields, eventgroups)
        print(f"Adding Service(ID: 0x{service_id:04x} Ver: {major_version:d}.{minor_version:d})")
        self.add_service(service_id, major_version, minor_version, ret)
        return ret

    def create_someip_parameter_basetype(self, name, data_type, bigendian, bitlength_basetype, bitlength_encoded_type):
        if bitlength_basetype != bitlength_encoded_type:
            name = "%s-%d" % (name, bitlength_encoded_type)

        ret = SOMEIPParameterBasetype(self.__global_id_base_types, name, data_type, bigendian, bitlength_basetype,
                                      bitlength_encoded_type)

        if self.__space_optimized:
            for key in self.__param_base_types:
                tmp = self.__param_base_types[key]
                if tmp == ret:
                    return tmp

        self.__param_base_types[self.__global_id_base_types] = ret
        self.__global_id_base_types += 1

        return ret

    def create_someip_parameter_string(self, name, char_type, big_endian, lower_limit, upper_limit, termination,
                                       length_of_length, pad_to):
        ret = SOMEIPParameterString(self.__global_id_strings, name, char_type, big_endian, lower_limit, upper_limit,
                                    termination, length_of_length, pad_to)

        if self.__space_optimized:
            for key in self.__param_strings:
                tmp = self.__param_strings[key]
                if tmp == ret:
                    return tmp

        self.__param_strings[self.__global_id_strings] = ret
        self.__global_id_strings += 1
        return ret

    def create_someip_parameter_array(self, name, dims, child):
        ret = SOMEIPParameterArray(self.__global_id_arrays, name, dims, child)

        #        if self.__space_optimized__:
        #            for key in self.__param_arrays__:
        #                tmp = self.__param_arrays__[key]
        #                if tmp == ret:

        self.__param_arrays[self.__global_id_arrays] = ret
        self.__global_id_arrays += 1
        return ret

    def create_someip_parameter_array_dim(self, dim, lower_limit, upper_limit, length_of_length, pad_to):
        return SOMEIPBaseParameterArrayDimension(dim, lower_limit, upper_limit, length_of_length, pad_to)

    def create_someip_parameter_struct(self, name, length_of_length, pad_to, members, tlv=False):
        ret = SOMEIPParameterStruct(self.__global_id_structs, name, length_of_length, pad_to, members, tlv)

        #        if self.__space_optimized__:
        #            for key in self.__param_structs__:
        #                tmp = self.__param_structs__[key]
        #                if tmp == ret:
        #                    return tmp

        self.__param_structs[self.__global_id_structs] = ret
        self.__global_id_structs += 1
        return ret

    def create_someip_parameter_typedef(self, name, name2, child):
        ret = SOMEIPParameterTypedef(self.__global_id_typedefs, name, name2, child)

        #        if self.__space_optimized__:
        #            for key in self.__param_typedefs__:
        #                tmp = self.__param_typedefs__[key]
        #                if tmp == ret:
        #                    return tmp

        self.__param_typedefs[self.__global_id_typedefs] = ret
        self.__global_id_typedefs += 1
        return ret

    def create_someip_parameter_enumeration(self, name, items, child):
        ret = SOMEIPParameterEnumeration(self.__global_id_enums, name, items, child)

        if self.__space_optimized:
            for key in self.__param_enums:
                tmp = self.__param_enums[key]
                if tmp == ret:
                    return tmp

        self.__param_enums[self.__global_id_enums] = ret
        self.__global_id_enums += 1
        return ret

    def create_someip_parameter_enumeration_item(self, value, name, desc):
        return SOMEIPBaseParameterEnumerationItem(value, name, desc)

    def create_someip_parameter_union(self, name, length_of_length, length_of_type, pad_to, members):
        ret = SOMEIPParameterUnion(self.__global_id_unions, name, length_of_length, length_of_type, pad_to, members)

        #        if self.__space_optimized__:
        #            for key in self.__param_unions__:
        #                tmp = self.__param_unions__[key]
        #                if tmp == ret:
        #                    return tmp

        self.__param_unions[self.__global_id_unions] = ret
        self.__global_id_unions += 1
        return ret

    def create_someip_parameter_bitfield(self, name, items, child):
        ret = SOMEIPParameterBitfield(self.__global_id_bitfields, name, items, child)

        self.__param_bitfields[self.__global_id_bitfields] = ret
        self.__global_id_bitfields += 1
        return ret

    def create_pdu_route(self, sender_socket, receiving_socket, pdu_name, pdu_id):
        pdu_d = dict()
        pdu_d['name'] = pdu_name
        pdu_d['id'] = pdu_id

        if pdu_id in self.__eth_pdus.keys() and self.__eth_pdus[pdu_id]['name'] != pdu_name:
            print(f"WARNING: Overwriting PDU with ID:{hex(pdu_id)}! {self.__eth_pdus[pdu_id]['name']} -> {pdu_name}")
            return False

        self.__eth_pdus[pdu_id] = pdu_d
        return True

    def add_service(self, serviceid, majorver, minorver, service):
        sid = "%04x-%02x-%08x" % (serviceid, majorver, minorver)
        if sid in self.__services_long:
            print(
                f"ERROR: Service (SID: 0x{serviceid:04x}, Major-Ver: {majorver:d}, " +
                f"Minor-Ver: {minorver:d}) already exists! Not overriding it!"
            )
            return False
        self.__services_long[sid] = service

        sid = "%04x-%02x" % (serviceid, majorver)
        if sid in self.__services:
            print(
                f"ERROR: Service (SID: 0x{serviceid:04x}, Major-Ver: {majorver:d}) " +
                f"already exists with a different Minor Version (not {minorver:d})! Not overriding it!"
            )
            return False
        self.__services[sid] = service
        return True

    def get_service(self, serviceid, majorver, minorver=None):
        if minorver is None:
            sid = "%04x-%02x" % (serviceid, majorver)
            if sid in self.__services:
                return self.__services[sid]
            else:
                return None
        else:
            sid = "%04x-%02x-%08x" % (serviceid, majorver, minorver)
            if sid in self.__services_long:
                return self.__services_long[sid]
            else:
                return None

    def __str__(self):
        ret = "Services: \n"
        for serviceid in self.__services:
            ret += self.__services[serviceid].str(2)

        ret += "\nECUs: \n"
        for name in self.__ecus:
            ret += self.__ecus[name].str(2)

        return ret

    def write_name_configs(self, conf_services, conf_methods, conf_eventgroups, version=1):
        count_services = 0
        count_events = 0
        count_methods = 0
        count_fields = 0

        d = dict()
        for sid in self.__services.keys():
            count_services += 1
            s = self.__services[sid]

            if s.service_id() in d.keys():
                if d[s.service_id()] != s.name():
                    print(
                        f"ERROR: We got the same Service-ID 0x{s.service_id():04x} " +
                        f"with different names {d[s.service_id()].name()} {s.name()}"
                    )
            else:
                d[s.service_id()] = s

        fs = open(conf_services, "w")
        fm = open(conf_methods, "w")
        fe = open(conf_eventgroups, "w")

        fs.write("# This file is automatically generated, DO NOT MODIFY. (LV)\n")
        fm.write("# This file is automatically generated, DO NOT MODIFY. (LV)\n")
        fe.write("# This file is automatically generated, DO NOT MODIFY. (LV)\n")

        for key in sorted(d.keys()):
            s = d[key]
            fs.write(f"\"{key:04x}\",\"{s.name()}\"\n")

            dm = dict()

            tmp = s.methods()
            for mid in tmp:
                count_methods += 1
                dm[tmp[mid].method_id()] = tmp[mid].name()

            tmp = s.events()
            for eid in tmp:
                count_events += 1
                dm[tmp[eid].method_id()] = tmp[eid].name()

            tmp = s.fields()
            for fid in tmp:
                count_fields += 1

                if tmp[fid].getter() is not None:
                    count_methods += 1
                    dm[tmp[fid].getter().method_id()] = tmp[fid].name() + "_Getter"

                if tmp[fid].setter() is not None:
                    count_methods += 1
                    dm[tmp[fid].setter().method_id()] = tmp[fid].name() + "_Setter"

                if tmp[fid].notifier() is not None:
                    count_events += 1
                    dm[tmp[fid].notifier().method_id()] = tmp[fid].name() + "_Notifier"

            for mkey in sorted(dm.keys()):
                fm.write(f"\"{key:04x}\",\"{mkey:04x}\",\"{dm[mkey]}\"\n")

            de = dict()

            tmp = s.eventgroups()
            for eg in tmp:
                de[tmp[eg].eventgroup_id()] = tmp[eg].name()

            for egkey in sorted(de.keys()):
                fe.write(f"\"{key:04x}\",\"{egkey:04x}\",\"{de[egkey]}\"\n")

        fs.close()
        fm.close()
        fe.close()

    @staticmethod
    def write_ws_config(filename, arr, version=1):
        f = open(filename, "w")
        f.write("# This file is automatically generated, DO NOT MODIFY. (LV)\n")

        for key in arr:
            i = arr[key]
            f.write(f"{i.ws_config_line(version)}")

        f.close()

    @staticmethod
    def write_parameter_configlines(f, service, method, msgtype, params, version):
        for p in params:
            if p.data_type() is not None:
                tmp = "\"%04x\",\"%04x\",\"%d\",\"%x\"" % (service.service_id(),
                                                           method.method_id(),
                                                           service.major_version(),
                                                           msgtype)
                if version > 1:
                    if method.tlv():
                        tmp += ",\"TRUE\""
                    else:
                        tmp += ",\"FALSE\""

                tmp += ",\"%d\"" % (len(params))

                tmp += ",\"%d\",\"%s\",\"%d\",\"%08x\"" % (p.position(),
                                                           p.name(),
                                                           p.data_type().parameter_type(version),
                                                           p.data_type().global_id(version))

                if version > 1:
                    tmp += f",\"{service.name()}.{method.name()}.{p.name()}\""

                tmp += "\n"
                f.write(tmp)
            else:
                print(f"ERROR: Cannot write config, if p.datatype() = None! "
                      f"Service: {service.name()} Method: {method.name()} Param: {p.name()} Pos: {p.position()}")

    def write_parameter_config(self, filename, version=1):
        # Service-ID,Method-ID,Version,MessageType,Num-Of-Params,Position,Name,Datatype,Datatype-ID

        f = open(filename, "w")
        f.write("# This file is automatically generated, DO NOT MODIFY. (LV)\n")

        for sid in sorted(self.__services):
            serv = self.__services[sid]

            for key in sorted(serv.methods()):
                method = serv.methods()[key]
                if version == 1 or not method.legacy():
                    if method.call_type() == "REQUEST_RESPONSE":
                        self.write_parameter_configlines(f, serv, method, 0x00, method.in_parameters(), version)
                        self.write_parameter_configlines(f, serv, method, 0x80, method.out_parameters(), version)
                    else:
                        self.write_parameter_configlines(f, serv, method, 0x01, method.in_parameters(), version)
                elif DEBUG_LEGACY_STRIPPING:
                    print(f"--> skipping legacy method: {serv.name()} (0x{serv.service_id():x}) {method.name()} (0x{method.method_id():x})")

            for key in sorted(serv.events()):
                event = serv.events()[key]
                if version == 1 or not serv.events()[key].legacy():
                    self.write_parameter_configlines(f, serv, event, 0x02, event.params(), version)
                elif DEBUG_LEGACY_STRIPPING:
                    print(f"--> skipping legacy event: {serv.name()} (0x{serv.service_id():x}) {event.name()} (0x{event.method_id():x})")

            for key in sorted(serv.fields(), key=lambda x: (x is None, x)):
                field = serv.fields()[key]
                if version == 1 or not field.legacy():
                    if field.getter() is not None:
                        self.write_parameter_configlines(f, serv, field.getter(), 0x00, field.getter().in_parameters(), version)
                        self.write_parameter_configlines(f, serv, field.getter(), 0x80, field.getter().out_parameters(), version)
                    if field.setter() is not None:
                        self.write_parameter_configlines(f, serv, field.setter(), 0x00, field.setter().in_parameters(), version)
                        self.write_parameter_configlines(f, serv, field.setter(), 0x80, field.setter().out_parameters(), version)
                    if field.notifier() is not None:
                        self.write_parameter_configlines(f, serv, field.notifier(), 0x02, field.notifier().params(),
                                                         version)
                elif DEBUG_LEGACY_STRIPPING:
                    print(f"--> skipping legacy field: {serv.name()} (0x{serv.service_id():x}) {field.name()}")

        f.close()

    def write_parameter_basetypes(self, filename, version=1):
        self.write_ws_config(filename, self.__param_base_types, version)

    def write_parameter_strings(self, filename, version=1):
        self.write_ws_config(filename, self.__param_strings, version)

    def write_parameter_arrays(self, filename, version=1):
        self.write_ws_config(filename, self.__param_arrays, version)

    def write_parameter_structs(self, filename, version=1):
        self.write_ws_config(filename, self.__param_structs, version)

    def write_parameter_typedefs(self, filename, version=1):
        self.write_ws_config(filename, self.__param_typedefs, version)

    def write_parameter_unions(self, filename, version=1):
        self.write_ws_config(filename, self.__param_unions, version)

    def write_parameter_enums(self, filename, version=1):
        self.write_ws_config(filename, self.__param_enums, version)

    def write_parameter_bitfields(self, filename, version=3):
        self.write_ws_config(filename, self.__param_bitfields, version)

    def write_hosts(self, filename, version=1):
        # ip name

        f = open(filename, "w")
        f.write("# This file is automatically generated, DO NOT MODIFY (LV).\n")

        ips = dict()

        for ecuname in self.__ecus:
            for controller in self.__ecus[ecuname].controllers():

                if len(self.__ecus[ecuname].controllers()) > 1:
                    if controller.name().startswith(ecuname):
                        ecuctrlname = controller.name()
                    else:
                        ecuctrlname = f"{ecuname}_{controller.name()}"

                    if "Controller" in ecuctrlname:
                        ecuctrlname = ecuctrlname.replace("Controller", "")
                    if "controller" in ecuctrlname:
                        ecuctrlname = ecuctrlname.replace("controller", "")
                else:
                    ecuctrlname = ecuname

                for interface in controller.interfaces():
                    for socket in interface.sockets():
                        if not is_ip_mcast(socket.ip()):
                            tmp = ips.setdefault(socket.ip(), {})
                            tmp[ecuctrlname] = ecuctrlname

                    # let us also include IPs without sockets
                    for ip in interface.ips():
                        if is_ip(ip) and not is_ip_mcast(ip):
                            tmp = ips.setdefault(ip, {})
                            tmp[ecuctrlname] = ecuctrlname

        for ip in sorted(ips.keys(), key=lambda x: ip_to_key(x)):
            ecu_names = "__".join(ips[ip])
            f.write(f"{ip}\t{ecu_names}\n")

        f.close()

    def write_vlanids(self, filename, version=1):
        # vlanids name

        f = open(filename, "w")
        f.write("# This file is automatically generated, DO NOT MODIFY. (LV)\n")

        vlans = dict()

        for ecu in self.__ecus:
            for controller in self.__ecus[ecu].controllers():
                for interface in controller.interfaces():
                    vlans[interface.vlan_id()] = interface.vlan_name()

        for vlan in sorted(vlans):
            if vlan != 0:
                f.write(f"{vlan}\t{vlans[vlan]}\n")

        f.close()

    def write_signal_pdu_configline(self, f, pdu_id, name):
        # Legacy-ID, Name

        f.write(f"\"{pdu_id:08x}\","
                f"\"{name}\"\n"
                )

    def write_can_busid_configline(self, f, interfaceid, busname, busid):
        if interfaceid is None:
            interfaceid = 0xffffffff

        f.write(f"\"{interfaceid:08x}\","
                f"\"{busname}\","
                f"\"{busid:04x}\"\n"
                )

    def write_signal_pdu_binding_someip_configline(self, f, service, method, msgtype, pdu_id):
        # Service-ID, Method-ID, MessageType, Version, Legacy-ID

        if not method.legacy():
            return

        f.write(f"\"{service.service_id():04x}\","
                f"\"{method.method_id():04x}\","
                f"\"{service.major_version():02x}\","
                f"\"{msgtype:02x}\","
                f"\"{pdu_id:08x}\"\n"
                )

    def write_signal_pdu_binding_can_configline(self, f, can_id, bus_id, pdu_id):
        # uint32 CAN-ID, uint16 Bus-ID, uint32 PDU-ID

        f.write(f"\"{can_id:08x}\","
                f"\"{bus_id:04x}\","
                f"\"{pdu_id:08x}\"\n"
                )

    def write_signal_pdu_binding_fr_configline(self, f, channel, slot_id, base_cycle, cycle_rep, cycle_cnt, pdu_id):
        # channel (0,1), uint8 Cycle, uint16 Frame-ID, uint32 PDU-ID

        # Channel A is default
        channel_cfg = 0
        if channel.upper() == "B":
            channel_cfg = 1

        if cycle_cnt is not None and cycle_cnt != 0:
            print(f"WARNING: FlexRay Cycle Count {cycle_cnt} currently not supported for Wireshark config!")

        MAX_CYCLE = 64

        cycle = base_cycle
        while cycle < MAX_CYCLE:
            f.write(f"\"{channel_cfg:02x}\","
                    f"\"{cycle:02x}\","
                    f"\"{slot_id:04x}\","
                    f"\"{pdu_id:08x}\"\n"
                    )
            if cycle_rep == 0:
                return

            cycle += cycle_rep

    def write_signal_value_configlines(self, f_enum, pdu_id, position, signal):
        cc = signal.compu_consts()

        if cc is None:
            return

        for value, start, end in cc:
            if 0 <= int(start) <= pow(2, 64) and 0 <= int(end) <= pow(2, 64):
                f_enum.write(f"\"{pdu_id:08x}\","
                             f"\"{position}\","
                             f"\"{len(cc)}\","
                             f"\"{int(start):x}\","
                             f"\"{int(end):x}\","
                             f"\"{cleanup_string(value)}\""
                             "\n"
                             )
            else:
                print(f"WARNING: CompuConst<0 or >2^64 not supported! "
                      f"{pdu_id:08x}:{position} {start}-{end} {value}")

    def write_someip_signal_configlines(self, f, f_enum, pdu_id, pdu_name, params):
        # signals (f)
        # ID, Num of Sigs, Pos, Name, Data Type, BE (TRUE/FALSE), bitlen base, bitlen coded, scaler, offset,
        # Multiplexer (FALSE), Muliplex value (-1), Hidden (FALSE)

        # enums (f_enum)
        # ID, Pos, Num of Values, Value start, Value end, Value Name

        if params is None or len(params) == 0:
            return

        # there might be exactly one struct as wrapper, if we are part of a field
        if isinstance(params[0].data_type(), SOMEIPParameterStruct):
            tmp = params[0].data_type().members()

            for k in sorted(tmp.keys()):
                m = tmp[k]

                endian = "TRUE" if m.child().big_endian() else "FALSE"
                hidden = "TRUE" if m.short_name().startswith("dummy") else "FALSE"
                scaler = 1
                offset = 0

                if m.signal() is not None:
                    offset = m.signal().offset()
                    scaler = m.signal().scaler()

                if m.signal() is not None:
                    self.write_signal_value_configlines(f_enum, pdu_id, m.position(), m.signal())

                f.write(f"\"{pdu_id:08x}\","
                        f"\"{len(tmp)}\","
                        f"\"{m.position()}\","
                        f"\"{m.short_name()}\","
                        f"\"{pdu_name}.{m.short_name()}\","
                        f"\"{cleanup_datatype_string(m.child().data_type())}\","
                        f"\"{endian}\","
                        f"\"{m.child().bit_length_base_type()}\","
                        f"\"{m.child().bit_length_encoded_type()}\","
                        f"\"{scaler}\","
                        f"\"{offset}\","
                        f"\"FALSE\","
                        f"\"-1\","
                        f"\"{hidden}\""
                        "\n"
                        )
            return

        for p in params:
            endian = "TRUE" if p.data_type().big_endian() else "FALSE"
            hidden = "TRUE" if p.short_name().startswith("dummy") else "FALSE"
            scaler = 1
            offset = 0

            if p.signal() is not None:
                offset = p.signal().offset()
                scaler = p.signal().scaler()

            if p.signal() is not None:
                self.write_signal_value_configlines(f_enum, pdu_id, p.position(), p.signal())

            f.write(f"\"{pdu_id:08x}\","
                    f"\"{len(params)}\","
                    f"\"{p.position()}\","
                    f"\"{p.short_name()}\","
                    f"\"{pdu_name}.{p.short_name()}\","
                    f"\"{cleanup_datatype_string(p.data_type().data_type())}\","
                    f"\"{endian}\","
                    f"\"{p.data_type().bit_length_base_type()}\","
                    f"\"{p.data_type().bit_length_encoded_type()}\","
                    f"\"{scaler}\","
                    f"\"{offset}\","
                    f"\"FALSE\","
                    f"\"-1\","
                    f"\"{hidden}\""
                    "\n"
                    )

    def generate_signal_configline_parts(self, pdu_id, pdu_name, pos, name, dt, endian,
                                         bitlength_basetype, bitlength_encoded_type,
                                         scaler, offset, hidden):
        endian_upper = "TRUE" if endian else "FALSE"

        tmp1 = f"\"{pdu_id:08x}\",\""
        tmp2 = f"\"," \
               f"\"{pos}\"," \
               f"\"{name}\"," \
               f"\"{pdu_name}.{name}\"," \
               f"\"{cleanup_datatype_string(dt)}\"," \
               f"\"{endian_upper}\"," \
               f"\"{bitlength_basetype}\"," \
               f"\"{bitlength_encoded_type}\"," \
               f"\"{scaler}\"," \
               f"\"{offset}\"," \
               f"\"FALSE\"," \
               f"\"-1\"," \
               f"\"{hidden}\"" \
               "\n"

        return tmp1, tmp2

    def write_signal_pdu_signal_configlines(self, f_sig, f_sigv, pdu_id, name, pdu_instances, debug=False):
        if len(pdu_instances) == 0:
            return

        if debug and len(pdu_instances) > 1:
            print(f"WARNING: We might need to merge the PDUs of {name} pdu_id: {pdu_id}.")
            # TODO: we could use the AUTOSAR I-PDU-M config to have different PDUs...

        for pdu_instance in pdu_instances.values():
            if pdu_instance.pdu_update_bit_position() is not None:
                print(f"WARNING: Update Bits currently not supported! "
                      f"{name} PDU: {pdu_instance.pdu().short_name()}. Ignoring the Update Bits!")
                # TODO: We need to generate the AUTOSAR I-PDU-M config to support Update Bits

        # check and sort pdu intances of frame
        tmp_pdu_instances = {}
        for pdu_inst in pdu_instances.values():
            pdu_start_pos = pdu_inst.bit_position()

            if pdu_start_pos in tmp_pdu_instances.keys():
                print(f"ERROR: {name} has multiple PDUs starting at same position! Overwritting!")

            if pdu_inst.pdu() is None:
                print(f"ERROR: {name} has a PDU Instance without PDU! Skipping!")
            else:
                tmp_pdu_instances[pdu_start_pos] = pdu_inst

        tmp = []
        pos = 0
        dummy_number = 0
        current_bit_pos = 0
        for pdu_start_pos in sorted(tmp_pdu_instances.keys()):
            pdu = tmp_pdu_instances[pdu_start_pos].pdu()

            if pdu.is_multiplex_pdu():
                print(f"WARNING: Not supporting Multiplex PDUs yet! Skipping Frame: {name}!")
                # TODO: Parse the Switch and set it to Multiplexer. Generate the rest. Update gap detection.
                return
            else:
                for signal_instance in pdu.signal_instances_sorted_by_bit_position():
                    start_pos = pdu_start_pos + signal_instance.bit_position()

                    while start_pos > current_bit_pos:
                        if debug:
                            print(f"DEBUG: found a gap in PDU {pdu_id} {current_bit_pos} {start_pos}")

                        dummy_length = min(start_pos - current_bit_pos, 32)

                        tmp1, tmp2 = self.generate_signal_configline_parts(pdu_id, pdu.short_name(), pos,
                                                                           f"dummy_{dummy_number}",
                                                                           "uint",
                                                                           "TRUE",
                                                                           32,
                                                                           dummy_length,
                                                                           1.0, 0.0, "TRUE")
                        tmp.append((tmp1, tmp2))

                        pos += 1
                        current_bit_pos += dummy_length
                        dummy_number += 1

                    if start_pos != current_bit_pos:
                        print(f"ERROR: The signals seem to be overlapping in PDU {pdu.short_name()} {pdu_id}! Skipping!")
                        return

                    signal = signal_instance.signal()
                    signal_length = signal.bit_length()

                    if debug:
                        print(f"DEBUG: {pdu_id} {signal.short_name()} {current_bit_pos} {start_pos} {signal_length}")

                    # Workaround for a_bytefield
                    basetype = signal.base_type()
                    bitlen_base = signal.base_type_length()

                    if basetype.lower() in ("asciistring", "a_asciistring"):
                        basetype = "STRING"
                        bitlen_base = 8

                    if basetype.lower() in ("bytefield", "a_bytefield"):
                        print("        WARNING: bytefield support is not complete. Results may be not correct!")
                        basetype = "UINT"
                        bitlen_base = 64

                    tmp1, tmp2 = self.generate_signal_configline_parts(pdu_id, pdu.short_name(), pos, signal.short_name(),
                                                                       basetype,
                                                                       signal_instance.is_high_low_byte_order(),
                                                                       bitlen_base,
                                                                       signal_length,
                                                                       signal.scaler(), signal.offset(), "FALSE")
                    tmp.append((tmp1, tmp2))

                    pos += 1
                    current_bit_pos = start_pos + signal_length

        for left_part, right_part in tmp:
            f_sig.write(left_part + f"{len(tmp)}" + right_part)

    def has_channel_more_than_one_type(self, key):
        channel = self.__channels[key]

        tmp = 0
        if channel["is_can"]:
            tmp += 1
        if channel["is_flexray"]:
            tmp += 1
        if channel["is_ethernet"]:
            tmp += 1

        return tmp > 1

    def write_signal_pdu(self, f_pdu, f_sig, f_sigv, frame):
        frame_known, pdu_id = self.pdu_id_for_frame(frame)
        if not frame_known:
            # we have not written this Signal PDU before, so do it now:
            self.write_signal_pdu_configline(f_pdu, pdu_id, frame.short_name())
            self.write_signal_pdu_signal_configlines(f_sig, f_sigv, pdu_id, frame.short_name(), frame.pdu_instances())

        return pdu_id

    def write_pdus_over_legacy_bus_configs(self, f_pdu, f_sig, f_sigv, f_can_if, f_bind_can, f_bind_fr, version=2):
        for name in sorted(self.__channels.keys()):
            if self.has_channel_more_than_one_type(name):
                print(f"WARNING: Channel {name} use more than 1 technology (CAN, FlexRay, Ethernet, ...)! Skipping!")
                continue

            channel = self.__channels[name]
            bus_id = self.next_global_bus_id()
            frame_triggerings = channel["frametriggerings"]

            if channel["is_can"]:
                self.write_can_busid_configline(f_can_if, None, name, bus_id)

                for key in sorted(frame_triggerings.keys()):
                    ft = frame_triggerings[key]
                    frame = ft.frame()
                    if frame is None:
                        print(f"WARNING: FrameTriggering {ft.original_id()} has no valid frame attached! Skipping!")
                        continue

                    pdu_id = self.write_signal_pdu(f_pdu, f_sig, f_sigv, frame)

                    self.write_signal_pdu_binding_can_configline(f_bind_can, ft.can_id(), bus_id, pdu_id)

            if channel["is_flexray"]:
                for key in sorted(frame_triggerings.keys()):
                    ft = frame_triggerings[key]
                    frame = ft.frame()
                    if frame is None:
                        print(f"WARNING: FrameTriggering {ft.original_id()} has no valid frame attached! Skipping!")
                        continue

                    pdu_id = self.write_signal_pdu(f_pdu, f_sig, f_sigv, frame)

                    slot_id, cycle_cnt, base_cycle, cycle_rep = ft.scheduling()
                    self.write_signal_pdu_binding_fr_configline(f_bind_fr, channel["fr-channel"],
                                                                slot_id, base_cycle, cycle_rep, cycle_cnt, pdu_id)

    def write_pdus_over_someip_config(self, f_id, f_sig, f_sigv, f_bind, version=2):
        for sid in sorted(self.__services):
            serv = self.__services[sid]

            for key in sorted(serv.methods()):
                method = serv.methods()[key]

                if not method.legacy():
                    continue

                if method.call_type() == "REQUEST_RESPONSE":
                    # Request:
                    pdu_id = self.next_global_pdu_id()

                    # signal pdu
                    self.write_signal_pdu_configline(f_id, pdu_id, method.name())

                    # signals
                    self.write_someip_signal_configlines(f_sig, f_sigv, pdu_id, method.name(), method.in_parameters())
                    # binding
                    self.write_signal_pdu_binding_someip_configline(f_bind, serv, method, 0x00, pdu_id)


                    # Response:
                    pdu_id = self.next_global_pdu_id()

                    # signal pdu
                    self.write_signal_pdu_configline(f_id, pdu_id, method.name())

                    # signals
                    self.write_someip_signal_configlines(f_sig, f_sigv, pdu_id, method.name(), method.out_parameters())
                    # binding
                    self.write_signal_pdu_binding_someip_configline(f_bind, serv, method, 0x80, pdu_id)
                else:
                    pdu_id = self.next_global_pdu_id()
                    # signal pdu
                    self.write_signal_pdu_configline(f_id, pdu_id, method.name())

                    # signals
                    self.write_someip_signal_configlines(f_sig, f_sigv, pdu_id, method.name(), method.in_parameters())
                    # binding
                    self.write_signal_pdu_binding_someip_configline(f_bind, serv, method, 0x01, pdu_id)

            for key in sorted(serv.events()):
                event = serv.events()[key]

                if not event.legacy():
                    continue

                pdu_id = self.next_global_pdu_id()

                # signal pdu
                self.write_signal_pdu_configline(f_id, pdu_id, event.name())

                # signals
                self.write_someip_signal_configlines(f_sig, f_sigv, pdu_id, event.name(), event.params())

                # binding
                self.write_signal_pdu_binding_someip_configline(f_bind, serv, event, 0x02, pdu_id)

            for key in sorted(serv.fields(), key=lambda x: (x is None, x)):
                field = serv.fields()[key]

                if not field.legacy():
                    continue

                if field.getter() is not None or field.setter() is not None or field.notifier() is not None:
                    pdu_id = self.next_global_pdu_id()

                    # signal pdu
                    self.write_signal_pdu_configline(f_id, pdu_id, field.name())

                    # signals
                    self.write_someip_signal_configlines(f_sig, f_sigv, pdu_id, field.name(), field.params())

                    if field.getter() is not None:
                        # binding (only response has payload)
                        self.write_signal_pdu_binding_someip_configline(f_bind, serv, field.getter(), 0x80, pdu_id)

                    if field.setter() is not None:
                        # binding
                        self.write_signal_pdu_binding_someip_configline(f_bind, serv, field.setter(), 0x00, pdu_id)
                        self.write_signal_pdu_binding_someip_configline(f_bind, serv, field.setter(), 0x80, pdu_id)

                    if field.notifier() is not None:
                        # binding
                        self.write_signal_pdu_binding_someip_configline(f_bind, serv, field.notifier(), 0x02, pdu_id)

    def write_pdus_over_ethernet_config(self, f_id, f_sig, f_sigv, f_bind, version=2):
        eth_pdus = {}

        for socket in self.__sockets:
            for p in socket.incoming_pdus():
                if p.pdu() is not None:
                    eth_pdus[p.header_id()] = p

            for p in socket.outgoing_pdus():
                if p.pdu() is not None:
                    eth_pdus[p.header_id()] = p

        for p_key in sorted(eth_pdus):
            p = eth_pdus[p_key]
            header_id = p.header_id()
            pdu = p.pdu()
            pdu_id = self.next_global_pdu_id()

            self.write_signal_pdu_configline(f_id, pdu_id, pdu.short_name())

            # signals
            self.write_signal_pdu_signal_configlines(f_sig, f_sigv, pdu_id, pdu.short_name(), {0: p})

            # binding
            f_bind.write(f"\"{header_id:08x}\","
                         f"\"{pdu_id:08x}\"\n")

    def write_pdu_configs(self, target_dir, fn_id, fn_sig, fn_sigv,
                          fn_bind_someip, fn_bind_eth_pdus, fn_can_if, fn_bind_can, fn_bind_fr, version=2):
        f_id = open(os.path.join(target_dir, fn_id), "w")
        f_id.write("# This file is automatically generated, DO NOT MODIFY. (LV)\n")
        f_sig = open(os.path.join(target_dir, fn_sig), "w")
        f_sig.write("# This file is automatically generated, DO NOT MODIFY. (LV)\n")
        f_sigv = open(os.path.join(target_dir, fn_sigv), "w")
        f_sigv.write("# This file is automatically generated, DO NOT MODIFY. (LV)\n")

        f_bind_someip = open(os.path.join(target_dir, fn_bind_someip), "w")
        f_bind_someip.write("# This file is automatically generated, DO NOT MODIFY. (LV)\n")

        f_bind_eth_pdus = open(os.path.join(target_dir, fn_bind_eth_pdus), "w")
        f_bind_eth_pdus.write("# This file is automatically generated, DO NOT MODIFY. (LV)\n")

        f_can_if = open(os.path.join(target_dir, fn_can_if), "w")
        f_can_if.write("# This file is automatically generated, DO NOT MODIFY. (LV)\n")

        f_bind_can = open(os.path.join(target_dir, fn_bind_can), "w")
        f_bind_can.write("# This file is automatically generated, DO NOT MODIFY. (LV)\n")

        f_bind_fr = open(os.path.join(target_dir, fn_bind_fr), "w")
        f_bind_fr.write("# This file is automatically generated, DO NOT MODIFY. (LV)\n")

        print(f"  --> PDUs on SOME/IP: {fn_id}, {fn_sig}, {fn_sigv}, {fn_bind_someip}")
        self.write_pdus_over_someip_config(f_id, f_sig, f_sigv, f_bind_someip, version=version)

        print(f"  --> PDUs on Ethernet: {fn_id}, {fn_sig}, {fn_sigv}, {fn_bind_eth_pdus}")
        self.write_pdus_over_ethernet_config(f_id, f_sig, f_sigv, f_bind_eth_pdus, version=version)

        print(f"  --> PDUs on CAN/FR: {fn_id}, {fn_sig}, {fn_sigv}, {fn_can_if}, {fn_bind_can}, {fn_bind_fr}")
        self.write_pdus_over_legacy_bus_configs(f_id, f_sig, f_sigv, f_can_if, f_bind_can, f_bind_fr, version=version)

        f_id.close()
        f_sig.close()
        f_sigv.close()
        f_bind_someip.close()
        f_bind_eth_pdus.close()
        f_can_if.close()
        f_bind_can.close()
        f_bind_fr.close()

    def write_transport_pdu_config(self, filename, version=2):
        if version < 2:
            return

        # ID, Name
        f = open(filename, "w")
        f.write("# This file is automatically generated, DO NOT MODIFY. (LV)\n")

        for pdu_id in sorted(self.__eth_pdus):
            pdu = self.__eth_pdus[pdu_id]
            pdu_name = pdu['name']

            f.write(f"\"{pdu_id:08x}\","
                    f"\"{pdu_name}\"\n")

        f.close()

class SOMEIPParameterBasetype(SOMEIPBaseParameterBasetype):
    def __init__(self, global_id, name, data_type, big_endian, bit_length_base_type, bit_length_encoded_type):
        super(SOMEIPParameterBasetype, self).__init__(name, data_type, big_endian, bit_length_base_type,
                                                      bit_length_encoded_type)
        self.__global_id = int(global_id)

    def global_id(self, version):
        return self.__global_id

    @staticmethod
    def parameter_type(version):
        return WiresharkParameterTypes.basetype

    def ws_config_line(self, version=1):
        # Type-ID,Name,Datatype,BigEndian,BitlengthBase,BiglengthEncoded

        if version == 1:
            endianess = 1 if self.big_endian() else 0
            return "\"%08x\",\"%s\",\"%s\",\"%d\",\"%d\",\"%d\"\n" % (self.global_id(version),
                                                                      self.name(),
                                                                      translate_datatype(self.data_type()),
                                                                      endianess,
                                                                      self.bit_length_base_type(),
                                                                      self.bit_length_encoded_type())
        else:
            # remove non SOME/IP datatypes since they are configured as Signal-PDU configs
            if self.bit_length_base_type() not in (8, 16, 32, 64):
                return ""
            if self.bit_length_base_type() != self.bit_length_encoded_type():
                return ""

            endianess = "TRUE" if self.big_endian() else "FALSE"
            return "\"%08x\",\"%s\",\"%s\",\"%s\",\"%d\",\"%d\"\n" % (self.global_id(version),
                                                                      self.name(),
                                                                      translate_datatype(self.data_type()),
                                                                      endianess,
                                                                      self.bit_length_base_type(),
                                                                      self.bit_length_encoded_type())


class SOMEIPParameterString(SOMEIPBaseParameterString):
    def __init__(self, global_id, name, char_type, bigendian, lower_limit, upper_limit, termination, length_of_length,
                 pad_to):
        super(SOMEIPParameterString, self).__init__(name, char_type, bigendian, lower_limit, upper_limit, termination,
                                                    length_of_length, pad_to)
        self.__global_id = int(global_id)

    def global_id(self, version):
        return self.__global_id

    @staticmethod
    def parameter_type(version):
        return WiresharkParameterTypes.string

    def ws_config_line(self, version=1):
        if version == 1:
            # String-ID,Name,Encoding,Dynamic_Length,Max-Length,Length-Field-Size,Big-Endian,Bit-Alignment
            dynlength = 0 if self.lower_limit() == self.upper_limit() else 1
            endianess = 1 if self.big_endian() else 0
            return "\"%08x\",\"%s\",\"%s\",\"%d\",\"%d\",\"%d\",\"%d\",\"%d\"\n" % (self.global_id(version),
                                                                                    self.name(),
                                                                                    self.char_type().lower(),
                                                                                    dynlength,  # self.lowerlimit(),
                                                                                    self.upper_limit(),
                                                                                    self.length_of_length(),
                                                                                    endianess,
                                                                                    self.pad_to())
        else:
            # String-ID,Name,Encoding,Dynamic_Length,Max-Length,Length-Field-Size,Big-Endian,Bit-Alignment
            dynlength = "FALSE" if self.lower_limit() == self.upper_limit() else "TRUE"
            endianess = "TRUE" if self.big_endian() else "FALSE"
            return "\"%08x\",\"%s\",\"%s\",\"%s\",\"%d\",\"%d\",\"%s\",\"%d\"\n" % (self.global_id(version),
                                                                                    self.name(),
                                                                                    self.char_type().lower(),
                                                                                    dynlength,  # self.lowerlimit(),
                                                                                    self.upper_limit(),
                                                                                    self.length_of_length(),
                                                                                    endianess,
                                                                                    self.pad_to())


class SOMEIPParameterArray(SOMEIPBaseParameterArray):
    def __init__(self, global_id, name, dimensions, child):
        super(SOMEIPParameterArray, self).__init__(name, dimensions, child)
        self.__global_id = int(global_id)

    def global_id(self, version):
        return self.__global_id

    @staticmethod
    def parameter_type(version):
        return WiresharkParameterTypes.array

    def ws_config_line(self, version=1):
        # Array-ID,Name,DT-Type,DT-ID,MaxDim,Dim,Min,Max,LenOfLen,PadTo

        if self.parent_service() is None or self.parent_method() is None:
            print(f"    WARNING: array ({self.name()}) is not attached to service!")

        ret = ""
        for key in self.dimensions():
            d = self.dimensions()[key]
            ret += "\"%08x\",\"%s\",\"%d\",\"%08x\",\"%d\"" % (self.global_id(version),
                                                               self.name(),
                                                               self.child().parameter_type(version),
                                                               self.child().global_id(version),
                                                               len(self.dimensions()))
            if version > 1:
                if self.parent_service() is None or self.parent_method() is None:
                    ret += f",\"invalid.invalid.{self.name()}\""
                else:
                    ret += f",\"{self.parent_service().name()}.{self.parent_method().name()}.{self.name()}\""

            ret += ",\"%d\",\"%d\",\"%d\",\"%d\",\"%d\"\n" % (d.dimension() - 1,
                                                              d.lower_limit(),
                                                              d.upper_limit(),
                                                              d.length_of_length(),
                                                              d.pad_to())
        return ret


class SOMEIPParameterStruct(SOMEIPBaseParameterStruct):
    def __init__(self, global_id, name, length_of_length, pad_to, members, tlv):
        super(SOMEIPParameterStruct, self).__init__(name, length_of_length, pad_to, members, tlv)
        self.__global_id = int(global_id)

    def global_id(self, version):
        return self.__global_id

    @staticmethod
    def parameter_type(version):
        return WiresharkParameterTypes.struct

    def ws_config_line(self, version=1):
        # Struct-ID,Struct Name,Length of length field,Align to,Number of items,Position,Name,Data Type,Datatype ID
        ret = ""

        if self.parent_service() is None or self.parent_method() is None:
            print(f"    WARNING: struct ({self.name()}) is not attached to service!")
        else:
            if version == 2 and self.parent_method().legacy():
                if DEBUG_LEGACY_STRIPPING:
                    print(f"--> Skipping struct {self.name()} of Service {self.parent_service().name()} and Method {self.parent_method().name()}")
                return ret

        number_of_entries = len(self.members())

        # first pass: check numbering and that all positions are below numbers_of_entries
        error_found = False
        last_pos = -1
        for key in sorted(self.members().keys()):
            m = self.members()[key]

            #check position
            if last_pos != -1 and m.position() - last_pos > 1:
                error_found = True
                print(f"\nERROR: Position skipped by SOME/IP Struct Member {m.name()} {last_pos} -> {m.position()}")
                print("  Current members:")
                for k2, m2 in self.members().items():
                    print(f"    {m2.position()}: {m2.name()}")

                print("\n  Adjusting positioning!")
                m.update_position(last_pos + 1)
            last_pos = m.position()

            if m.position() >= number_of_entries:
                print(f"\n  ERROR: Position of SOME/IP Struct Member {m.name()} {m.position()} > number_of_entries {number_of_entries}!\n"
                      f"  Adjusting number_of_entries to {m.position() + 1} [{self.name()}]")
                number_of_entries = m.position() + 1
                error_found = True

        if error_found:
            print("  Resulting members:")
            for key in self.members():
                m = self.members()[key]
                print(f"    {m.position()}: {m.name()}")
            print("\n")

        for key in sorted(self.members().keys()):
            m = self.members()[key]
            ret += "\"%08x\",\"%s\",\"%d\",\"%d\"" % (self.global_id(version),
                                                      self.name(),
                                                      self.length_of_length(),
                                                      self.pad_to())

            if version > 1:
                if self.tlv():
                    ret += ",\"TRUE\""
                else:
                    ret += ",\"FALSE\""

            ret += ",\"%d\"" % number_of_entries

            ret += ",\"%d\",\"%s\",\"%d\",\"%08x\"" % (m.position(),
                                                       m.name(),
                                                       m.child().parameter_type(version),
                                                       m.child().global_id(version))
            if version > 1:
                if self.parent_service() is None or self.parent_method() is None:
                    ret += f",\"invalid.invalid.{m.name()}\""
                else:
                    ret += f",\"{self.parent_service().name()}.{self.parent_method().name()}.{m.name()}\""

            ret += "\n"
        return ret


class SOMEIPParameterTypedef(SOMEIPBaseParameterTypedef):
    def __init__(self, global_id, name, name2, child):
        super(SOMEIPParameterTypedef, self).__init__(name, name2, child)
        self.__global_id = int(global_id)

    def global_id(self, version):
        return self.__global_id

    @staticmethod
    def parameter_type(version):
        return WiresharkParameterTypes.typedef

    def ws_config_line(self, version=1):
        # Typedef ID,Typedef Name,Data Type,Datatype ID

        ret = "\"%08x\",\"%s\",\"%d\",\"%08x\"\n" % (self.global_id(version),
                                                     self.name(),
                                                     self.child().parameter_type(version),
                                                     self.child().global_id(version))
        return ret


class SOMEIPParameterEnumeration(SOMEIPBaseParameterEnumeration):
    def __init__(self, global_id, name, items, child):
        super(SOMEIPParameterEnumeration, self).__init__(name, items, child)
        self.__global_id = int(global_id)

        assert (isinstance(child, SOMEIPParameterBasetype))

    def global_id(self, version):
        return self.__global_id

    @staticmethod
    def parameter_type(version):
        return WiresharkParameterTypes.enum

    def ws_config_line(self, version=1):
        # Enum-ID,Name,Datatype,Datatype ID,NumOfEntries,Value,Value-Name
        # "136c9","Enumeration1","1","12ff6","6","2","One"
        # "136c9","Enumeration1","1","12ff6","6","3","Two"
        ret = ""
        for i in self.items():
            ret += "\"%08x\",\"%s\",\"%d\",\"%08x\",\"%d\",\"%x\",\"%s\"\n" % (self.global_id(version),
                                                                               self.name(),
                                                                               self.child().parameter_type(version),
                                                                               self.child().global_id(version),
                                                                               len(self.items()),
                                                                               i.value(),
                                                                               i.name())
        return ret


class SOMEIPParameterUnion(SOMEIPBaseParameterUnion):
    def __init__(self, global_id, name, length_of_length, length_of_type, pad_to, members):
        super(SOMEIPParameterUnion, self).__init__(name, length_of_length, length_of_type, pad_to, members)
        self.__global_id = int(global_id)

    def global_id(self, version):
        return self.__global_id

    @staticmethod
    def parameter_type(version):
        return WiresharkParameterTypes.union

    def ws_config_line(self, version=1):
        # Union-ID,Name,Length of length,Length of Type,Align to,Number of items,Index,Name,Data Type,Datatype ID

        if self.parent_service() is None or self.parent_method() is None:
            print(f"    WARNING: union ({self.name()}) is not attached to service!")

        ret = ""
        for key in self.members():
            m = self.members()[key]
            ret += "\"%08x\",\"%s\",\"%d\",\"%d\",\"%d\",\"%d\"" % (self.global_id(version),
                                                                    self.name(),
                                                                    self.length_of_length(),
                                                                    self.length_of_type(),
                                                                    self.pad_to(),
                                                                    len(self.members()))
            ret += ",\"%d\",\"%s\",\"%d\",\"%08x\"" % (m.index(),
                                                       m.name(),
                                                       m.child().parameter_type(version),
                                                       m.child().global_id(version))
            if version > 1:
                if self.parent_service() is None or self.parent_method() is None:
                    ret += f",\"invalid.invalid.{m.name()}\""
                else:
                    ret += f",\"{self.parent_service().name()}.{self.parent_method().name()}.{m.name()}\""
            ret += "\n"
        return ret


class SOMEIPParameterBitfield(SOMEIPBaseParameterBitfield):
    def __init__(self, global_id, name, items, child):
        super(SOMEIPParameterBitfield, self).__init__(name, items, child)
        self.__global_id = int(global_id)

        assert (isinstance(child, SOMEIPParameterBasetype))

    def global_id(self, version):
        if version >= 3:
            return self.__global_id
        else:
            return self.child().global_id(version)

    def parameter_type(self, version):
        if version >= 3:
            return WiresharkParameterTypes.bitfield
        else:
            return self.child().parameter_type(version)

    def ws_config_line(self, version=3):
        # "ID","Name","Number of Bits","Number of Items","Bit Number","Bit Name"
        # "0", "BF8", "8", "8", "0", "bit_0", "BF8.bit_0"
        ret = ""
        for i in self.items():
            ret += "\"%08x\",\"%s\",\"%d\",\"%d\",\"%d\",\"%s\",\"%s\"\n" % (self.global_id(version),
                                                                               self.name(),
                                                                               self.child().bit_length_base_type(),
                                                                               len(self.items()),
                                                                               i.bit_number(),
                                                                               i.name(),
                                                                               f"{self.name()}.{i.name()}")
        return ret


def help_and_exit():
    print("illegal arguments!")
    print(f"  {sys.argv[0]} type filename")
    print(f"  example: {sys.argv[0]} FIBEX test.xml")
    sys.exit(-1)


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

    print("Converting configuration to Wireshark Configs")
    args = parse_arguments()

    g_gen_portid = args.generate_switch_port_names

    ecu_name_mapping = {}
    if args.ecu_name_mapping is not None:
        ecu_name_mapping = read_csv_to_dict(args.ecu_name_mapping)

    conf_factory = WiresharkConfigurationFactory()

    # add common basetypes already here, so they have fixed IDs
    conf_factory.create_someip_parameter_basetype("BOOL", "uint8", True, 8, 8)
    conf_factory.create_someip_parameter_basetype("UINT8", "uint8", True, 8, 8)
    conf_factory.create_someip_parameter_basetype("UINT16", "uint16", True, 16, 16)
    conf_factory.create_someip_parameter_basetype("UINT32", "uint32", True, 32, 32)
    conf_factory.create_someip_parameter_basetype("UINT64", "uint64", True, 64, 64)
    conf_factory.create_someip_parameter_basetype("INT8", "int8", True, 8, 8)
    conf_factory.create_someip_parameter_basetype("INT16", "int16", True, 16, 16)
    conf_factory.create_someip_parameter_basetype("INT32", "int32", True, 32, 32)
    conf_factory.create_someip_parameter_basetype("INT64", "int64", True, 64, 64)
    conf_factory.create_someip_parameter_basetype("FLOAT32", "float32", True, 32, 32)
    conf_factory.create_someip_parameter_basetype("FLOAT64", "float64", True, 64, 64)

    output_dir = parse_input_files(args.filename, args.type, conf_factory, plugin_file=args.plugin,
                                   ecu_name_replacement=ecu_name_mapping)

    if output_dir is None:
        help_and_exit()

    print("Generating output directories:")

    target_dir = os.path.join(output_dir, "wireshark_3.4_and_earlier")
    target_dir2 = os.path.join(output_dir, "wireshark_3.5_to_4.4")
    target_dir3 = os.path.join(output_dir, "wireshark_4.5_and_later")

    if not os.path.exists(target_dir):
        os.makedirs(target_dir)

    if not os.path.exists(target_dir2):
        os.makedirs(target_dir2)

    if not os.path.exists(target_dir3):
        os.makedirs(target_dir3)

    # we had race conditions in the past
    time.sleep(0.5)

    print("")
    print("Generating back links...")
    conf_factory.create_backlinks()

    print("Generating configs:")

    print("  SOME/IP configs:")

    print("  --> SOMEIP_service_identifiers")
    print("  --> SOMEIP_method_event_identifiers")
    print("  --> SOMEIP_eventgroup_identifiers")
    conf_services = os.path.join(target_dir, "SOMEIP_service_identifiers")
    conf_methods = os.path.join(target_dir, "SOMEIP_method_event_identifiers")
    conf_eventgroups = os.path.join(target_dir, "SOMEIP_eventgroup_identifiers")
    conf_factory.write_name_configs(conf_services, conf_methods, conf_eventgroups)

    conf_services = os.path.join(target_dir2, "SOMEIP_service_identifiers")
    conf_methods = os.path.join(target_dir2, "SOMEIP_method_event_identifiers")
    conf_eventgroups = os.path.join(target_dir2, "SOMEIP_eventgroup_identifiers")
    conf_factory.write_name_configs(conf_services, conf_methods, conf_eventgroups, 2)

    conf_services = os.path.join(target_dir3, "SOMEIP_service_identifiers")
    conf_methods = os.path.join(target_dir3, "SOMEIP_method_event_identifiers")
    conf_eventgroups = os.path.join(target_dir3, "SOMEIP_eventgroup_identifiers")
    conf_factory.write_name_configs(conf_services, conf_methods, conf_eventgroups, 3)

    fn = "SOMEIP_parameter_list"
    print(f"  --> {fn}")
    conf_factory.write_parameter_config(os.path.join(target_dir, fn))
    conf_factory.write_parameter_config(os.path.join(target_dir2, fn), 2)
    conf_factory.write_parameter_config(os.path.join(target_dir3, fn), 3)

    fn = "SOMEIP_parameter_base_types"
    print(f"  --> {fn}")
    conf_factory.write_parameter_basetypes(os.path.join(target_dir, fn))
    conf_factory.write_parameter_basetypes(os.path.join(target_dir2, fn), 2)
    conf_factory.write_parameter_basetypes(os.path.join(target_dir3, fn), 3)

    fn = "SOMEIP_parameter_arrays"
    print(f"  --> {fn}")
    conf_factory.write_parameter_arrays(os.path.join(target_dir, fn))
    conf_factory.write_parameter_arrays(os.path.join(target_dir2, fn), 2)
    conf_factory.write_parameter_arrays(os.path.join(target_dir3, fn), 3)

    fn = "SOMEIP_parameter_enums"
    print(f"  --> {fn}")
    conf_factory.write_parameter_enums(os.path.join(target_dir, fn))
    conf_factory.write_parameter_enums(os.path.join(target_dir2, fn), 2)
    conf_factory.write_parameter_enums(os.path.join(target_dir3, fn), 3)

    fn = "SOMEIP_parameter_strings"
    print(f"  --> {fn}")
    conf_factory.write_parameter_strings(os.path.join(target_dir, fn))
    conf_factory.write_parameter_strings(os.path.join(target_dir2, fn), 2)
    conf_factory.write_parameter_strings(os.path.join(target_dir3, fn), 3)

    fn = "SOMEIP_parameter_structs"
    print(f"  --> {fn}")
    conf_factory.write_parameter_structs(os.path.join(target_dir, fn))
    conf_factory.write_parameter_structs(os.path.join(target_dir2, fn), 2)
    conf_factory.write_parameter_structs(os.path.join(target_dir3, fn), 3)

    fn = "SOMEIP_parameter_typedefs"
    print(f"  --> {fn}")
    conf_factory.write_parameter_typedefs(os.path.join(target_dir, fn))
    conf_factory.write_parameter_typedefs(os.path.join(target_dir2, fn), 2)
    conf_factory.write_parameter_typedefs(os.path.join(target_dir3, fn), 3)

    fn = "SOMEIP_parameter_unions"
    print(f"  --> {fn}")
    conf_factory.write_parameter_unions(os.path.join(target_dir, fn))
    conf_factory.write_parameter_unions(os.path.join(target_dir2, fn), 2)
    conf_factory.write_parameter_unions(os.path.join(target_dir3, fn), 3)

    fn = "SOMEIP_parameter_bitfields"
    print(f"  --> {fn}")
    conf_factory.write_parameter_bitfields(os.path.join(target_dir3, fn), 3)

    # PDUs over SOME/IP
    fn1 = "Signal_PDU_identifiers"
    fn2 = "Signal_PDU_signal_list"
    fn3 = "Signal_PDU_signal_values"
    fn4 = "Signal_PDU_Binding_SOMEIP"
    fn5 = "Signal_PDU_Binding_PDU_Transport"
    fn6 = "CAN_interface_mapping"
    fn7 = "Signal_PDU_Binding_CAN"
    fn8 = "Signal_PDU_Binding_FlexRay"
    print("\n  PDUs Configs:")
    conf_factory.write_pdu_configs(target_dir2, fn1, fn2, fn3, fn4, fn5, fn6, fn7, fn8, 2)
    conf_factory.write_pdu_configs(target_dir3, fn1, fn2, fn3, fn4, fn5, fn6, fn7, fn8, 3)

    fn = "PDU_Transport_identifiers"
    print(f"  --> PDUs on Ethernet: {fn}")
    conf_factory.write_transport_pdu_config(os.path.join(target_dir2, fn), 2)
    conf_factory.write_transport_pdu_config(os.path.join(target_dir3, fn), 3)

    print("\n  Other Configs:")

    fn = "hosts"
    print(f"  --> {fn}")
    conf_factory.write_hosts(os.path.join(target_dir, fn))
    conf_factory.write_hosts(os.path.join(target_dir2, fn), 2)
    conf_factory.write_hosts(os.path.join(target_dir3, fn), 3)

    fn = "vlans"
    print(f"  --> {fn}")
    conf_factory.write_vlanids(os.path.join(target_dir, fn))
    conf_factory.write_vlanids(os.path.join(target_dir2, fn), 2)
    conf_factory.write_vlanids(os.path.join(target_dir3, fn), 3)

    print("Done.")


# only call main, if we are started directly
if __name__ == "__main__":
    main()
