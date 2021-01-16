#!/usr/bin/python

# Automotive configuration file scripts
# Copyright (C) 2015-2021  Dr. Lars Voelker
# Copyright (C) 2018-2019  Dr. Lars Voelker, BMW AG
# Copyright (C) 2020-2021  Dr. Lars Voelker, Technica Engineering GmbH

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

from configuration_base_classes import *  # @UnusedWildImport

from fibex_parser import FibexParser


class WiresharkParameterTypes:
    basetype = 1
    string = 2
    array = 3
    struct = 4
    union = 5
    typedef = 6
    enum = 7


def cleanup_string(tmp):
    ret = tmp.replace("\"", "'")
    return ret


def cleanup_datatype_string(tmp):
    ret = tmp[2:].lower()
    if ret.startswith("uint"):
        ret = "uint"
    if ret.startswith("int"):
        ret = "int"
    if ret.startswith("float"):
        ret = "float"
    return ret


class WiresharkConfigurationFactory(BaseConfigurationFactory):

    def __init__(self):
        self.__services__ = dict()
        self.__services_long__ = dict()

        self.__param_arrays__ = dict()
        self.__param_basetypes__ = dict()
        self.__param_enums__ = dict()
        self.__param_strings__ = dict()
        self.__param_structs__ = dict()
        self.__param_typedefs__ = dict()
        self.__param_unions__ = dict()

        self.__globalid_arrays__ = 1
        self.__globalid_basetypes__ = 1
        self.__globalid_enums__ = 1
        self.__globalid_strings__ = 1
        self.__globalid_structs__ = 1
        self.__globalid_typedefs__ = 1
        self.__globalid_unions__ = 1

        self.__space_optimized__ = True

        self.__ecus__ = dict()

    def create_ecu(self, name, controllers):
        tmp = BaseECU(name, controllers)
        print(f"Adding ECU {name}")
        if tmp in self.__ecus__:
            print(f"Detected duplicate ECU {name}")
        self.__ecus__[name] = tmp
        return tmp

    def create_someip_service(self, name, serviceid, majorver, minorver, methods, events, fields, eventgroups):
        ret = SOMEIPBaseService(name, serviceid, majorver, minorver, methods, events, fields, eventgroups)
        print(f"Adding Service(ID: 0x{serviceid:04x} Ver: {majorver:d}.{minorver:d})")
        self.add_service(serviceid, majorver, minorver, ret)
        return ret

    def create_someip_parameter(self, position, name, desc, mandatory, datatype, signal):
        return SOMEIPBaseParameter(position, name, desc, mandatory, datatype, signal)

    def create_someip_parameter_basetype(self, name, datatype, bigendian, bitlength_basetype, bitlength_encoded_type):
        if bitlength_basetype != bitlength_encoded_type:
            name = "%s-%d" % (name, bitlength_encoded_type)

        ret = SOMEIPParameterBasetype(self.__globalid_basetypes__, name, datatype, bigendian, bitlength_basetype,
                                      bitlength_encoded_type)

        if self.__space_optimized__:
            for key in self.__param_basetypes__:
                tmp = self.__param_basetypes__[key]
                if tmp == ret:
                    return tmp

        self.__param_basetypes__[self.__globalid_basetypes__] = ret
        self.__globalid_basetypes__ += 1

        return ret

    def create_someip_parameter_string(self, name, chartype, bigendian, lowerlimit, upperlimit, termination,
                                       length_of_length, pad_to):
        ret = SOMEIPParameterString(self.__globalid_strings__, name, chartype, bigendian, lowerlimit, upperlimit,
                                    termination, length_of_length, pad_to)

        if self.__space_optimized__:
            for key in self.__param_strings__:
                tmp = self.__param_strings__[key]
                if tmp == ret:
                    return tmp

        self.__param_strings__[self.__globalid_strings__] = ret
        self.__globalid_strings__ += 1
        return ret

    def create_someip_parameter_array(self, name, dims, child):
        ret = SOMEIPParameterArray(self.__globalid_arrays__, name, dims, child)

        if self.__space_optimized__:
            for key in self.__param_arrays__:
                tmp = self.__param_arrays__[key]
                if tmp == ret:
                    return tmp

        self.__param_arrays__[self.__globalid_arrays__] = ret
        self.__globalid_arrays__ += 1
        return ret

    def create_someip_parameter_array_dim(self, dim, lowerlimit, upperlimit, length_of_length, pad_to):
        return SOMEIPBaseParameterArrayDim(dim, lowerlimit, upperlimit, length_of_length, pad_to)

    def create_someip_parameter_struct(self, name, length_of_length, pad_to, members):
        ret = SOMEIPParameterStruct(self.__globalid_structs__, name, length_of_length, pad_to, members)

        if self.__space_optimized__:
            for key in self.__param_structs__:
                tmp = self.__param_structs__[key]
                if tmp == ret:
                    return tmp

        self.__param_structs__[self.__globalid_structs__] = ret
        self.__globalid_structs__ += 1
        return ret

    def create_someip_parameter_struct_member(self, position, name, mandatory, child, signal):
        return SOMEIPBaseParameterStructMember(position, name, mandatory, child, signal)

    def create_someip_parameter_typedef(self, name, name2, child):
        ret = SOMEIPParameterTypedef(self.__globalid_typedefs__, name, name2, child)

        if self.__space_optimized__:
            for key in self.__param_typedefs__:
                tmp = self.__param_typedefs__[key]
                if tmp == ret:
                    return tmp

        self.__param_typedefs__[self.__globalid_typedefs__] = ret
        self.__globalid_typedefs__ += 1
        return ret

    def create_someip_parameter_enumeration(self, name, items, child):
        ret = SOMEIPParameterEnumeration(self.__globalid_enums__, name, items, child)

        if self.__space_optimized__:
            for key in self.__param_enums__:
                tmp = self.__param_enums__[key]
                if tmp == ret:
                    return tmp

        self.__param_enums__[self.__globalid_enums__] = ret
        self.__globalid_enums__ += 1
        return ret

    def create_someip_parameter_enumeration_item(self, value, name, desc):
        return SOMEIPBaseParameterEnumerationItem(value, name, desc)

    def create_someip_parameter_union(self, name, length_of_length, length_of_type, pad_to, members):
        ret = SOMEIPParameterUnion(self.__globalid_unions__, name, length_of_length, length_of_type, pad_to, members)

        if self.__space_optimized__:
            for key in self.__param_unions__:
                tmp = self.__param_unions__[key]
                if tmp == ret:
                    return tmp

        self.__param_unions__[self.__globalid_unions__] = ret
        self.__globalid_unions__ += 1
        return ret

    def create_someip_parameter_union_member(self, index, name, mandatory, child):
        return SOMEIPBaseParameterUnionMember(index, name, mandatory, child)

    def add_service(self, serviceid, majorver, minorver, service):
        sid = "%04x-%02x-%08x" % (serviceid, majorver, minorver)
        if sid in self.__services_long__:
            print(
                f"ERROR: Service (SID: 0x{serviceid:04x}, Major-Ver: {majorver:d}, " +
                f"Minor-Ver: {minorver:d}) already exists! Not overriding it!"
            )
            return False
        self.__services_long__[sid] = service

        sid = "%04x-%02x" % (serviceid, majorver)
        if sid in self.__services__:
            print(
                f"ERROR: Service (SID: 0x{serviceid:04x}, Major-Ver: {majorver:d}) " +
                f"already exists with a different Minor Version (not {minorver:d})! Not overriding it!"
            )
            return False
        self.__services__[sid] = service
        return True

    def get_service(self, serviceid, majorver, minorver=None):
        if minorver is None:
            sid = "%04x-%02x" % (serviceid, majorver)
            if sid in self.__services__:
                return self.__services__[sid]
            else:
                return None
        else:
            sid = "%04x-%02x-%08x" % (serviceid, majorver, minorver)
            if sid in self.__services_long__:
                return self.__services_long__[sid]
            else:
                return None

    def __str__(self):
        ret = "Services: \n"
        for serviceid in self.__services__:
            ret += self.__services__[serviceid].str(2)

        ret += "\nECUs: \n"
        for name in self.__ecus__:
            ret += self.__ecus__[name].str(2)

        return ret

    def write_name_configs(self, conf_services, conf_methods, conf_eventgroups, version=1):
        d = dict()

        for sid in self.__services__.keys():
            s = self.__services__[sid]

            if s.serviceid() in d.keys():
                if d[s.serviceid()] != s.name():
                    print(
                        f"ERROR: We got the same Service-ID 0x{s.serviceid():04x} " +
                        f"with different names {d[s.serviceid()].name()} {s.name()}"
                    )
            else:
                d[s.serviceid()] = s

        keys = sorted(d.keys())

        fs = open(conf_services, "w")
        fm = open(conf_methods, "w")
        fe = open(conf_eventgroups, "w")

        fs.write("# This file is automatically generated, DO NOT MODIFY. (LV)\n")
        fm.write("# This file is automatically generated, DO NOT MODIFY. (LV)\n")
        fe.write("# This file is automatically generated, DO NOT MODIFY. (LV)\n")

        for key in keys:
            s = d[key]
            fs.write(f"\"{key:04x}\",\"{s.name()}\"\n")

            dm = dict()

            tmp = s.methods()
            for mid in tmp:
                dm[tmp[mid].methodid()] = tmp[mid].name()

            tmp = s.events()
            for eid in tmp:
                dm[tmp[eid].methodid()] = tmp[eid].name()

            tmp = s.fields()
            for fid in tmp:
                if tmp[fid].getter() is not None:
                    dm[tmp[fid].getter().methodid()] = tmp[fid].name() + "_Getter"

                if tmp[fid].setter() is not None:
                    dm[tmp[fid].setter().methodid()] = tmp[fid].name() + "_Setter"

                if tmp[fid].notifier() is not None:
                    dm[tmp[fid].notifier().methodid()] = tmp[fid].name() + "_Notifier"

            for mkey in sorted(dm.keys()):
                fm.write(f"\"{key:04x}\",\"{mkey:04x}\",\"{dm[mkey]}\"\n")

            de = dict()

            tmp = s.eventgroups()
            for eg in tmp:
                de[tmp[eg].id()] = tmp[eg].name()

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
    def write_parameter_configlines(f, service, method, msgtype, params):
        for p in params:
            tmp = "\"%04x\",\"%04x\",\"%d\",\"%x\",\"%d\"" % (service.serviceid(),
                                                              method.methodid(),
                                                              service.majorversion(),
                                                              msgtype,
                                                              len(params))

            tmp += ",\"%d\",\"%s\",\"%d\",\"%08x\"\n" % (p.position(),
                                                         p.name(),
                                                         p.datatype().paramtype(),
                                                         p.datatype().globalid())
            f.write(tmp)

    def write_parameter_config(self, filename, version=1):
        # Service-ID,Method-ID,Version,MessageType,Num-Of-Params,Position,Name,Datatype,Datatype-ID

        f = open(filename, "w")
        f.write("# This file is automatically generated, DO NOT MODIFY. (LV)\n")

        for sid in sorted(self.__services__):
            serv = self.__services__[sid]

            for key in sorted(serv.methods()):
                method = serv.methods()[key]
                if method.calltype() == "REQUEST_RESPONSE":
                    self.write_parameter_configlines(f, serv, method, 0x00, method.inparams())
                    self.write_parameter_configlines(f, serv, method, 0x80, method.outparams())
                else:
                    self.write_parameter_configlines(f, serv, method, 0x01, method.inparams())

            for key in sorted(serv.events()):
                self.write_parameter_configlines(f, serv, serv.events()[key], 0x02, serv.events()[key].params())

            for key in sorted(serv.fields(), key=lambda x: (x is None, x)):
                field = serv.fields()[key]
                if field.getter() is not None:
                    self.write_parameter_configlines(f, serv, field.getter(), 0x00, field.getter().inparams())
                    self.write_parameter_configlines(f, serv, field.getter(), 0x80, field.getter().outparams())
                if field.setter() is not None:
                    self.write_parameter_configlines(f, serv, field.setter(), 0x00, field.setter().inparams())
                    self.write_parameter_configlines(f, serv, field.setter(), 0x80, field.setter().outparams())
                if field.notifier() is not None:
                    self.write_parameter_configlines(f, serv, field.notifier(), 0x02, field.notifier().params())

        f.close()

    def write_parameter_basetypes(self, filename, version=1):
        self.write_ws_config(filename, self.__param_basetypes__, version)

    def write_parameter_strings(self, filename, version=1):
        self.write_ws_config(filename, self.__param_strings__, version)

    def write_parameter_arrays(self, filename, version=1):
        self.write_ws_config(filename, self.__param_arrays__, version)

    def write_parameter_structs(self, filename, version=1):
        self.write_ws_config(filename, self.__param_structs__, version)

    def write_parameter_typedefs(self, filename, version=1):
        self.write_ws_config(filename, self.__param_typedefs__, version)

    def write_parameter_unions(self, filename, version=1):
        self.write_ws_config(filename, self.__param_unions__, version)

    def write_parameter_enums(self, filename, version=1):
        self.write_ws_config(filename, self.__param_enums__, version)

    def write_hosts(self, filename, version=1):
        # ip name

        f = open(filename, "w")
        f.write("# This file is automatically generated, DO NOT MODIFY (LV).\n")

        ips = dict()

        for ecuname in self.__ecus__:
            for controller in self.__ecus__[ecuname].controllers():
                for interface in controller.interfaces():
                    for socket in interface.sockets():
                        try:
                            ip = socket.ip()
                            # check for multicast!
                            # assume IPv4
                            tmp = ip.split('.')
                            if len(tmp) == 4:
                                start = int(tmp[0])
                                if start < 224:
                                    ips[ip] = ecuname
                            else:
                                # assume IPv6
                                if not ip.startswith("ff00"):
                                    ips[ip] = ecuname
                        except ValueError:
                            pass

        for ip in sorted(ips):
            f.write(f"{ip}\t{ips[ip]}\n")

        f.close()

    def write_vlanids(self, filename, version=1):
        # vlanids name

        f = open(filename, "w")
        f.write("# This file is automatically generated, DO NOT MODIFY. (LV)\n")

        vlans = dict()

        for ecu in self.__ecus__:
            for controller in self.__ecus__[ecu].controllers():
                for interface in controller.interfaces():
                    vlans[interface.vlanid()] = interface.vlanname()

        for vlan in sorted(vlans):
            if vlan != 0:
                f.write(f"{vlan}\t{vlans[vlan]}\n")

        f.close()

    def write_legacy_pdu_mapping_configlines(self, f, service, method, msgtype):
        if method.legacy() is False:
            return

        f.write(f"\"{service.serviceid():04x}\","
                f"\"{method.methodid():04x}\","
                f"\"{service.majorversion():02x}\","
                f"\"{msgtype:02x}\","
                f"\"{service.serviceid():04x}{method.methodid():04x}\"\n"
                )

    def write_legacy_pdu_mapping_config(self, filename, version=1):
        # Service-ID,Method-ID,MessageType,Version,Legacy-ID

        f = open(filename, "w")
        f.write("# This file is automatically generated, DO NOT MODIFY. (LV)\n")

        for sid in sorted(self.__services__):
            serv = self.__services__[sid]

            for key in sorted(serv.methods()):
                method = serv.methods()[key]
                if method.calltype() == "REQUEST_RESPONSE":
                    self.write_legacy_pdu_mapping_configlines(f, serv, method, 0x00)
                    self.write_legacy_pdu_mapping_configlines(f, serv, method, 0x80)
                else:
                    self.write_legacy_pdu_mapping_configlines(f, serv, method, 0x01)

            for key in sorted(serv.events()):
                self.write_legacy_pdu_mapping_configlines(f, serv, serv.events()[key], 0x02)

            for key in sorted(serv.fields(), key=lambda x: (x is None, x)):
                field = serv.fields()[key]
                if field.getter() is not None:
                    self.write_legacy_pdu_mapping_configlines(f, serv, field.getter(), 0x00)
                    self.write_legacy_pdu_mapping_configlines(f, serv, field.getter(), 0x80)
                if field.setter() is not None:
                    self.write_legacy_pdu_mapping_configlines(f, serv, field.setter(), 0x00)
                    self.write_legacy_pdu_mapping_configlines(f, serv, field.setter(), 0x80)
                if field.notifier() is not None:
                    self.write_legacy_pdu_mapping_configlines(f, serv, field.notifier(), 0x02)

        f.close()

    def write_legacy_pdunames_config(self, filename, version=1):
        # Legacy-ID, Name

        f = open(filename, "w")
        f.write("# This file is automatically generated, DO NOT MODIFY. (LV)\n")

        for sid in sorted(self.__services__):
            service = self.__services__[sid]

            for key in sorted(service.methods()):
                method = service.methods()[key]
                if method.legacy():
                    f.write(f"\"{service.serviceid():04x}{method.methodid():04x}\","
                            f"\"{method.name()}\"\n")

            for key in sorted(service.events()):
                method = service.events()[key]
                if method.legacy():
                    f.write(f"\"{service.serviceid():04x}{method.methodid():04x}\","
                            f"\"{method.name()}\"\n")

            for key in sorted(service.fields(), key=lambda x: (x is None, x)):
                field = service.fields()[key]
                if field.legacy():
                    if field.getter() is not None:
                        f.write(f"\"{service.serviceid():04x}{field.getter().methodid():04x}\","
                                f"\"{field.name()}\"\n")
                    if field.setter() is not None:
                        f.write(f"\"{service.serviceid():04x}{field.setter().methodid():04x}\","
                                f"\"{field.name()}\"\n")
                    if field.notifier() is not None:
                        f.write(f"\"{service.serviceid():04x}{field.notifier().methodid():04x}\","
                                f"\"{field.name()}\"\n")

        f.close()

    def write_legacy_pdu_signal_configlines(self, f, f_enum, pdu_id, service, method, params):
        if method.legacy() is False:
            return

        if params is None or len(params) == 0:
            return

        # ID, Num of Sigs, Pos, Name, Data Type, BE (TRUE/FALSE), bitlen base, bitlen coded, scaler, offset,
        # Multiplexer (FALSE), Muliplex value (-1), Hidden (FALSE)

        # there might be exactly one struct as wrapper, if we are part of a field
        tmp = params
        if isinstance(params[0].datatype(), SOMEIPParameterStruct):
            tmp = params[0].datatype().members()

            for k in sorted(tmp.keys()):
                m = tmp[k]

                endian = "TRUE" if m.child().bigendian() else "FALSE"
                hidden = "TRUE" if m.name().startswith("dummy") else "FALSE"
                scaler = 1
                offset = 0

                s = m.signal()
                if m.signal() is not None and m.signal().compu_scale() is not None and \
                        len(m.signal().compu_scale()) == 3:
                    num0, num1, denom = m.signal().compu_scale()
                    offset = float(num0)
                    scaler = float(num1) / float(denom)

                if m.signal() is not None and m.signal().compu_consts() is not None:
                    cc = m.signal().compu_consts()
                    for value, start, end in m.signal().compu_consts():
                        if int(start) >= 0:
                            f_enum.write(f"\"{pdu_id}\","
                                         f"\"{m.position()}\","
                                         f"\"{len(cc)}\","
                                         f"\"{start}\","
                                         f"\"{end}\","
                                         f"\"{cleanup_string(value)}\""
                                         "\n"
                                         )
                        else:
                            print(f"Warning: CompuConst<0 not supported! {pdu_id}:{m.position()} {start}-{end} {value}")

                f.write(f"\"{pdu_id}\","
                        f"\"{len(tmp)}\","
                        f"\"{m.position()}\","
                        f"\"{m.name()}\","
                        f"\"{cleanup_datatype_string(m.child().datatype())}\","
                        f"\"{endian}\","
                        f"\"{m.child().bitlength_basetype()}\","
                        f"\"{m.child(). bitlength_encoded_type()}\","
                        f"\"{scaler}\","
                        f"\"{offset}\","
                        f"\"FALSE\","
                        f"\"-1\","
                        f"\"{hidden}\""
                        "\n"
                        )
            return

        for p in params:
            endian = "TRUE" if p.datatype().bigendian() else "FALSE"
            hidden = "TRUE" if p.name().startswith("dummy") else "FALSE"
            scaler = 1
            offset = 0

            s = p.signal()
            if p.signal() is not None and p.signal().compu_scale() is not None and len(p.signal().compu_scale()) == 3:
                num0, num1, denom = p.signal().compu_scale()
                offset = float(num0)
                scaler = float(num1) / float(denom)

                if p.signal() is not None and p.signal().compu_consts() is not None:
                    cc = p.signal().compu_consts()
                    for value, start, end in p.signal().compu_consts():
                        if int(start) >= 0:
                            f_enum.write(f"\"{pdu_id}\","
                                         f"\"{p.position()}\","
                                         f"\"{len(cc)}\","
                                         f"\"{start}\","
                                         f"\"{end}\","
                                         f"\"{cleanup_string(value)}\""
                                         "\n"
                                         )
                        else:
                            print(f"Warning: CompuConst<0 not supported! {pdu_id}:{p.position()} {start}-{end} {value}")

            f.write(f"\"{pdu_id}\","
                    f"\"{len(params)}\","
                    f"\"{p.position()}\","
                    f"\"{p.name()}\","
                    f"\"{cleanup_datatype_string(p.datatype().datatype())}\","
                    f"\"{endian}\","
                    f"\"{p.datatype().bitlength_basetype()}\","
                    f"\"{p.datatype().bitlength_encoded_type()}\","
                    f"\"{scaler}\","
                    f"\"{offset}\","
                    f"\"FALSE\","
                    f"\"-1\","
                    f"\"{hidden}\""
                    "\n"
                    )

    def write_legacy_pdu_signal_config(self, filename, filename_enum, version=1):
        # signals (filename)
        # ID, Num of Sigs, Pos, Name, Data Type, BE (TRUE/FALSE), bitlen base, bitlen coded, scaler, offset,
        # Multiplexer (FALSE), Muliplex value (-1), Hidden (FALSE)

        # enums (filename_enum)
        # ID, Pos, Num of Values, Value start, Value end, Value Name

        f = open(filename, "w")
        f2 = open(filename_enum, "w")
        f.write("# This file is automatically generated, DO NOT MODIFY. (LV)\n")
        f2.write("# This file is automatically generated, DO NOT MODIFY. (LV)\n")

        for sid in sorted(self.__services__):
            serv = self.__services__[sid]

            for key in sorted(serv.methods()):
                method = serv.methods()[key]
                pid = f"{serv.serviceid():04x}{method.methodid():04x}"
                if method.calltype() == "REQUEST_RESPONSE":
                    self.write_legacy_pdu_signal_configlines(f, f2, pid, serv, method, method.inparams())
                    self.write_legacy_pdu_signal_configlines(f, f2, pid, serv, method, method.outparams())
                else:
                    self.write_legacy_pdu_signal_configlines(f, f2, pid, serv, method, method.inparams())

            for key in sorted(serv.events()):
                pid = f"{serv.serviceid():04x}{serv.events()[key].methodid():04x}"
                self.write_legacy_pdu_signal_configlines(f, f2, pid, serv, serv.events()[key],
                                                         serv.events()[key].params())

            for key in sorted(serv.fields(), key=lambda x: (x is None, x)):
                field = serv.fields()[key]
                if field.getter() is not None:
                    pid = f"{serv.serviceid():04x}{field.getter().methodid():04x}"
                    self.write_legacy_pdu_signal_configlines(f, f2, pid, serv, field.getter(),
                                                             field.getter().inparams())
                    self.write_legacy_pdu_signal_configlines(f, f2, pid, serv, field.getter(),
                                                             field.getter().outparams())
                if field.setter() is not None:
                    pid = f"{serv.serviceid():04x}{field.setter().methodid():04x}"
                    self.write_legacy_pdu_signal_configlines(f, f2, pid, serv, field.setter(),
                                                             field.setter().inparams())
                    self.write_legacy_pdu_signal_configlines(f, f2, pid, serv, field.setter(),
                                                             field.setter().outparams())
                if field.notifier() is not None:
                    pid = f"{serv.serviceid():04x}{field.notifier().methodid():04x}"
                    self.write_legacy_pdu_signal_configlines(f, f2, pid, serv, field.notifier(),
                                                             field.notifier().params())

        f.close()
        f2.close()


class SOMEIPParameterBasetype(SOMEIPBaseParameterBasetype):
    def __init__(self, globalid, name, datatype, bigendian, bitlength_basetype, bitlength_encoded_type):
        super(SOMEIPParameterBasetype, self).__init__(name, datatype, bigendian, bitlength_basetype,
                                                      bitlength_encoded_type)
        self.__globalid__ = int(globalid)

    def globalid(self):
        return self.__globalid__

    @staticmethod
    def paramtype():
        return WiresharkParameterTypes.basetype

    @staticmethod
    def translate_datatype(dt):
        return dt[2:].lower()

    def ws_config_line(self, version=1):
        # Type-ID,Name,Datatype,BigEndian,BitlengthBase,BiglengthEncoded

        if version == 1:
            endianess = 1 if self.bigendian() else 0
            return "\"%08x\",\"%s\",\"%s\",\"%d\",\"%d\",\"%d\"\n" % (self.globalid(),
                                                                      self.name(),
                                                                      self.translate_datatype(self.datatype()),
                                                                      endianess,
                                                                      self.bitlength_basetype(),
                                                                      self.bitlength_encoded_type())
        else:
            endianess = "TRUE" if self.bigendian() else "FALSE"
            return "\"%08x\",\"%s\",\"%s\",\"%s\",\"%d\",\"%d\"\n" % (self.globalid(),
                                                                      self.name(),
                                                                      self.translate_datatype(self.datatype()),
                                                                      endianess,
                                                                      self.bitlength_basetype(),
                                                                      self.bitlength_encoded_type())


class SOMEIPParameterString(SOMEIPBaseParameterString):
    def __init__(self, globalid, name, chartype, bigendian, lowerlimit, upperlimit, termination, length_of_length,
                 pad_to):
        super(SOMEIPParameterString, self).__init__(name, chartype, bigendian, lowerlimit, upperlimit, termination,
                                                    length_of_length, pad_to)
        self.__globalid__ = int(globalid)

    def globalid(self):
        return self.__globalid__

    @staticmethod
    def paramtype():
        return WiresharkParameterTypes.string

    def ws_config_line(self, version=1):
        if version == 1:
            # String-ID,Name,Encoding,Dynamic_Length,Max-Length,Length-Field-Size,Big-Endian,Bit-Alignment
            dynlength = 0 if self.lowerlimit() == self.upperlimit() else 1
            endianess = 1 if self.bigendian() else 0
            return "\"%08x\",\"%s\",\"%s\",\"%d\",\"%d\",\"%d\",\"%d\",\"%d\"\n" % (self.globalid(),
                                                                                    self.name(),
                                                                                    self.chartype().lower(),
                                                                                    dynlength,  # self.lowerlimit(),
                                                                                    self.upperlimit(),
                                                                                    self.length_of_length(),
                                                                                    endianess,
                                                                                    self.pad_to())
        else:
            # String-ID,Name,Encoding,Dynamic_Length,Max-Length,Length-Field-Size,Big-Endian,Bit-Alignment
            dynlength = "FALSE" if self.lowerlimit() == self.upperlimit() else "TRUE"
            endianess = "TRUE" if self.bigendian() else "FALSE"
            return "\"%08x\",\"%s\",\"%s\",\"%s\",\"%d\",\"%d\",\"%s\",\"%d\"\n" % (self.globalid(),
                                                                                    self.name(),
                                                                                    self.chartype().lower(),
                                                                                    dynlength,  # self.lowerlimit(),
                                                                                    self.upperlimit(),
                                                                                    self.length_of_length(),
                                                                                    endianess,
                                                                                    self.pad_to())


class SOMEIPParameterArray(SOMEIPBaseParameterArray):
    def __init__(self, globalid, name, dims, child):
        super(SOMEIPParameterArray, self).__init__(name, dims, child)
        self.__globalid__ = int(globalid)

    def globalid(self):
        return self.__globalid__

    @staticmethod
    def paramtype():
        return WiresharkParameterTypes.array

    def ws_config_line(self, version=1):
        # Array-ID,Name,DT-Type,DT-ID,MaxDim,Dim,Min,Max,LenOfLen,PadTo

        ret = ""
        for key in self.dims():
            d = self.dims()[key]
            ret += "\"%08x\",\"%s\",\"%d\",\"%08x\",\"%d\"," % (self.globalid(),
                                                                self.name(),
                                                                self.child().paramtype(),
                                                                self.child().globalid(),
                                                                len(self.dims()))
            ret += "\"%d\",\"%d\",\"%d\",\"%d\",\"%d\"\n" % (d.dim() - 1,
                                                             d.lowerlimit(),
                                                             d.upperlimit(),
                                                             d.length_of_length(),
                                                             d.pad_to())
        return ret


class SOMEIPParameterStruct(SOMEIPBaseParameterStruct):
    def __init__(self, globalid, name, length_of_length, pad_to, members):
        super(SOMEIPParameterStruct, self).__init__(name, length_of_length, pad_to, members)
        self.__globalid__ = int(globalid)

    def globalid(self):
        return self.__globalid__

    @staticmethod
    def paramtype():
        return WiresharkParameterTypes.struct

    def ws_config_line(self, version=1):
        # Struct-ID,Struct Name,Length of length field,Align to,Number of items,Position,Name,Data Type,Datatype ID

        ret = ""
        for key in self.members():
            m = self.members()[key]
            ret += "\"%08x\",\"%s\",\"%d\",\"%d\",\"%d\"" % (self.globalid(),
                                                             self.name(),
                                                             self.length_of_length(),
                                                             self.pad_to(),
                                                             len(self.members()))
            ret += ",\"%d\",\"%s\",\"%d\",\"%08x\"\n" % (m.position(),
                                                         m.name(),
                                                         m.child().paramtype(),
                                                         m.child().globalid())
        return ret


class SOMEIPParameterTypedef(SOMEIPBaseParameterTypedef):
    def __init__(self, globalid, name, name2, child):
        super(SOMEIPParameterTypedef, self).__init__(name, name2, child)
        self.__globalid__ = int(globalid)

    def globalid(self):
        return self.__globalid__

    @staticmethod
    def paramtype():
        return WiresharkParameterTypes.typedef

    def ws_config_line(self, version=1):
        # Typedef ID,Typedef Name,Data Type,Datatype ID

        ret = "\"%08x\",\"%s\",\"%d\",\"%08x\"\n" % (self.globalid(),
                                                     self.name(),
                                                     self.child().paramtype(),
                                                     self.child().globalid())
        return ret


class SOMEIPParameterEnumeration(SOMEIPBaseParameterEnumeration):
    def __init__(self, globalid, name, items, child):
        super(SOMEIPParameterEnumeration, self).__init__(name, items, child)
        self.__globalid__ = int(globalid)

    def globalid(self):
        return self.__globalid__

    @staticmethod
    def paramtype():
        return WiresharkParameterTypes.enum

    def ws_config_line(self, version=1):
        # Enum-ID,Name,Datatype,Datatype ID,NumOfEntries,Value,Value-Name
        # "136c9","Enumeration1","1","12ff6","6","2","One"
        # "136c9","Enumeration1","1","12ff6","6","3","Two"
        ret = ""
        for i in self.items():
            ret += "\"%08x\",\"%s\",\"%d\",\"%08x\",\"%d\",\"%x\",\"%s\"\n" % (self.globalid(),
                                                                               self.name(),
                                                                               self.child().paramtype(),
                                                                               self.child().globalid(),
                                                                               len(self.items()),
                                                                               i.value(),
                                                                               i.name())
        return ret


class SOMEIPParameterUnion(SOMEIPBaseParameterUnion):
    def __init__(self, globalid, name, length_of_length, length_of_type, pad_to, members):
        super(SOMEIPParameterUnion, self).__init__(name, length_of_length, length_of_type, pad_to, members)
        self.__globalid__ = int(globalid)

    def globalid(self):
        return self.__globalid__

    @staticmethod
    def paramtype():
        return WiresharkParameterTypes.union

    def ws_config_line(self, version=1):
        # Union-ID,Name,Length of length,Length of Type,Align to,Number of items,Index,Name,Data Type,Datatype ID

        ret = ""
        for key in self.members():
            m = self.members()[key]
            ret += "\"%08x\",\"%s\",\"%d\",\"%d\",\"%d\",\"%d\"" % (self.globalid(),
                                                                    self.name(),
                                                                    self.length_of_length(),
                                                                    self.length_of_type(),
                                                                    self.pad_to(),
                                                                    len(self.members()))
            ret += ",\"%d\",\"%s\",\"%d\",\"%08x\"\n" % (m.index(),
                                                         m.name(),
                                                         m.child().paramtype(),
                                                         m.child().globalid())
        return ret


def help_and_exit():
    print("illegal arguments!")
    print(f"  {sys.argv[0]} type filename")
    print(f"  example: {sys.argv[0]} FIBEX test.xml")
    sys.exit(-1)


def main():
    print("Converting configuration to Wireshark Configs")

    if len(sys.argv) != 3:
        help_and_exit()

    (t, filename) = sys.argv[1:]

    if not os.path.isfile(filename):
        help_and_exit()

    (path, f) = os.path.split(filename)
    filenoext = ".".join(f.split('.')[:-1])
    target_dir = os.path.join(path, filenoext, "wireshark_3.4_and_earlier")
    target_dir2 = os.path.join(path, filenoext, "wireshark_later")

    if not os.path.exists(target_dir):
        os.makedirs(target_dir)

    if not os.path.exists(target_dir2):
        os.makedirs(target_dir2)

    # we had race conditions in the past
    time.sleep(0.5)

    conf_factory = WiresharkConfigurationFactory()

    if t.upper() == "FIBEX":
        fb = FibexParser()
        fb.parse_file(conf_factory, filename)
    else:
        help_and_exit()

    print("")

    print("Generating configs:")

    print("  SOMEIP_service_identifiers / SOMEIP_method_event_identifiers / SOMEIP_eventgroup_identifiers")
    conf_services = os.path.join(target_dir, "SOMEIP_service_identifiers")
    conf_methods = os.path.join(target_dir, "SOMEIP_method_event_identifiers")
    conf_eventgroups = os.path.join(target_dir, "SOMEIP_eventgroup_identifiers")
    conf_factory.write_name_configs(conf_services, conf_methods, conf_eventgroups)

    conf_services = os.path.join(target_dir2, "SOMEIP_service_identifiers")
    conf_methods = os.path.join(target_dir2, "SOMEIP_method_event_identifiers")
    conf_eventgroups = os.path.join(target_dir2, "SOMEIP_eventgroup_identifiers")
    conf_factory.write_name_configs(conf_services, conf_methods, conf_eventgroups, 2)

    fn = "SOMEIP_parameter_list"
    print(f"  {fn}")
    conf_factory.write_parameter_config(os.path.join(target_dir, fn))
    conf_factory.write_parameter_config(os.path.join(target_dir2, fn), 2)

    fn = "SOMEIP_parameter_base_types"
    print(f"  {fn}")
    conf_factory.write_parameter_basetypes(os.path.join(target_dir, fn))
    conf_factory.write_parameter_basetypes(os.path.join(target_dir2, fn), 2)

    fn = "SOMEIP_parameter_arrays"
    print(f"  {fn}")
    conf_factory.write_parameter_arrays(os.path.join(target_dir, fn))
    conf_factory.write_parameter_arrays(os.path.join(target_dir2, fn), 2)

    fn = "SOMEIP_parameter_enums"
    print(f"  {fn}")
    conf_factory.write_parameter_enums(os.path.join(target_dir, fn))
    conf_factory.write_parameter_enums(os.path.join(target_dir2, fn), 2)

    fn = "SOMEIP_parameter_strings"
    print(f"  {fn}")
    conf_factory.write_parameter_strings(os.path.join(target_dir, fn))
    conf_factory.write_parameter_strings(os.path.join(target_dir2, fn), 2)

    fn = "SOMEIP_parameter_structs"
    print(f"  {fn}")
    conf_factory.write_parameter_structs(os.path.join(target_dir, fn))
    conf_factory.write_parameter_structs(os.path.join(target_dir2, fn), 2)

    fn = "SOMEIP_parameter_typedefs"
    print(f"  {fn}")
    conf_factory.write_parameter_typedefs(os.path.join(target_dir, fn))
    conf_factory.write_parameter_typedefs(os.path.join(target_dir2, fn), 2)

    fn = "SOMEIP_parameter_unions"
    print(f"  {fn}")
    conf_factory.write_parameter_unions(os.path.join(target_dir, fn))
    conf_factory.write_parameter_unions(os.path.join(target_dir2, fn), 2)

    fn = "Legacy_PDU_SOMEIP"
    print(f"  {fn}")
    conf_factory.write_legacy_pdu_mapping_config(os.path.join(target_dir2, fn), 2)

    fn = "Legacy_PDU_identifiers"
    print(f"  {fn}")
    conf_factory.write_legacy_pdunames_config(os.path.join(target_dir2, fn), 2)

    fn = "Legacy_PDU_signal_list"
    fn2 = "Legacy_PDU_signal_values"
    print(f"  {fn}")
    print(f"  {fn2}")
    conf_factory.write_legacy_pdu_signal_config(os.path.join(target_dir2, fn),
                                                os.path.join(target_dir2, fn2),
                                                2)

    fn = "hosts"
    print(f"  {fn}")
    conf_factory.write_hosts(os.path.join(target_dir, fn))
    conf_factory.write_hosts(os.path.join(target_dir2, fn), 2)

    fn = "vlanids"
    print(f"  {fn}")
    conf_factory.write_vlanids(os.path.join(target_dir, fn))
    conf_factory.write_vlanids(os.path.join(target_dir2, fn), 2)

    print("Done.")


# only call main, if we are started directly
if __name__ == "__main__":
    main()
