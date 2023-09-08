#!/usr/bin/python

# Automotive configuration file scripts
# Copyright (C) 2015-2023  Dr. Lars Voelker
# Copyright (C) 2018-2019  Dr. Lars Voelker, BMW AG
# Copyright (C) 2020-2023  Dr. Lars Voelker, Technica Engineering GmbH

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

from parser_dispatcher import * # @UnusedWildImport
from configuration_base_classes import *  # @UnusedWildImport

DEBUG_LEGACY_STRIPPING = False


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

        self.__globalid_signal_pdus__ = 1

        self.__space_optimized__ = True

        self.__ecus__ = dict()

    def create_backlinks(self):
        for s in self.__services__.values():
            s.create_backlinks(self)

    def create_ecu(self, name, controllers):
        tmp = BaseECU(name, controllers)
        print(f"Adding ECU {name}")
        if tmp in self.__ecus__:
            print(f"Detected duplicate ECU {name}")
        self.__ecus__[name] = tmp
        return tmp

    def create_someip_service(self, name, serviceid, majorver, minorver, methods, events, fields, eventgroups):
        ret = SOMEIPService(name, serviceid, majorver, minorver, methods, events, fields, eventgroups)
        print(f"Adding Service(ID: 0x{serviceid:04x} Ver: {majorver:d}.{minorver:d})")
        self.add_service(serviceid, majorver, minorver, ret)
        return ret

    def create_someip_service_method(self, name, methodid, calltype, relia, inparams, outparams,
                                     reqdebounce=-1, reqmaxretention=-1, resmaxretention=-1, tlv=False):
        return SOMEIPServiceMethod(name, methodid, calltype, relia, inparams, outparams,
                                   reqdebounce, reqmaxretention, resmaxretention, tlv)

    def create_someip_service_event(self, name, methodid, relia, params,
                                    debounce=-1, maxretention=-1, tlv=False):
        return SOMEIPServiceEvent(name, methodid, relia, params,
                                  debounce, maxretention, tlv)

    def create_someip_service_field(self, name, getterid, setterid, notifierid,
                                    getterreli, setterreli, notifierreli, params,
                                    getter_debouncereq, getter_retentionreq, getter_retentionres,
                                    setter_debouncereq, setter_retentionreq, setter_retentionres,
                                    notifier_debounce, notifier_retention, tlv=False):
        ret = SOMEIPServiceField(self, name, getterid, setterid, notifierid,
                                 getterreli, setterreli, notifierreli, params,
                                 getter_debouncereq, getter_retentionreq, getter_retentionres,
                                 setter_debouncereq, setter_retentionreq, setter_retentionres,
                                 notifier_debounce, notifier_retention, tlv)
        return ret

    def create_someip_parameter(self, position, name, desc, mandatory, datatype, signal):
        return SOMEIPParameter(position, name, desc, mandatory, datatype, signal)

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

        #        if self.__space_optimized__:
        #            for key in self.__param_arrays__:
        #                tmp = self.__param_arrays__[key]
        #                if tmp == ret:

        self.__param_arrays__[self.__globalid_arrays__] = ret
        self.__globalid_arrays__ += 1
        return ret

    def create_someip_parameter_array_dim(self, dim, lowerlimit, upperlimit, length_of_length, pad_to):
        return SOMEIPBaseParameterArrayDim(dim, lowerlimit, upperlimit, length_of_length, pad_to)

    def create_someip_parameter_struct(self, name, length_of_length, pad_to, members, tlv=False):
        ret = SOMEIPParameterStruct(self.__globalid_structs__, name, length_of_length, pad_to, members, tlv)

        #        if self.__space_optimized__:
        #            for key in self.__param_structs__:
        #                tmp = self.__param_structs__[key]
        #                if tmp == ret:
        #                    return tmp

        self.__param_structs__[self.__globalid_structs__] = ret
        self.__globalid_structs__ += 1
        return ret

    def create_someip_parameter_struct_member(self, position, name, mandatory, child, signal):
        return SOMEIPParameterStructMember(position, name, mandatory, child, signal)

    def create_someip_parameter_typedef(self, name, name2, child):
        ret = SOMEIPParameterTypedef(self.__globalid_typedefs__, name, name2, child)

        #        if self.__space_optimized__:
        #            for key in self.__param_typedefs__:
        #                tmp = self.__param_typedefs__[key]
        #                if tmp == ret:
        #                    return tmp

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

        #        if self.__space_optimized__:
        #            for key in self.__param_unions__:
        #                tmp = self.__param_unions__[key]
        #                if tmp == ret:
        #                    return tmp

        self.__param_unions__[self.__globalid_unions__] = ret
        self.__globalid_unions__ += 1
        return ret

    def create_someip_parameter_union_member(self, index, name, mandatory, child):
        return SOMEIPParameterUnionMember(index, name, mandatory, child)

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
        count_services = 0
        count_events = 0
        count_methods = 0
        count_fields = 0

        d = dict()

        for sid in self.__services__.keys():
            count_services += 1
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
                count_methods += 1
                dm[tmp[mid].methodid()] = tmp[mid].name()

            tmp = s.events()
            for eid in tmp:
                count_events += 1
                dm[tmp[eid].methodid()] = tmp[eid].name()

            tmp = s.fields()
            for fid in tmp:
                count_fields += 1

                if tmp[fid].getter() is not None:
                    count_methods += 1
                    dm[tmp[fid].getter().methodid()] = tmp[fid].name() + "_Getter"

                if tmp[fid].setter() is not None:
                    count_methods += 1
                    dm[tmp[fid].setter().methodid()] = tmp[fid].name() + "_Setter"

                if tmp[fid].notifier() is not None:
                    count_events += 1
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

        if version == 1:
            print(f"  Found {count_services} services, {count_methods} methods, and {count_events} events. "
                  f"This includes the methods and events of {count_fields} fields.")

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
            if p.datatype() is not None:
                tmp = "\"%04x\",\"%04x\",\"%d\",\"%x\"" % (service.serviceid(),
                                                           method.methodid(),
                                                           service.majorversion(),
                                                           msgtype)
                if version > 1:
                    if method.tlv():
                        tmp += f",\"TRUE\""
                    else:
                        tmp += f",\"FALSE\""

                tmp += ",\"%d\"" % (len(params))

                tmp += ",\"%d\",\"%s\",\"%d\",\"%08x\"" % (p.position(),
                                                           p.name(),
                                                           p.datatype().paramtype(),
                                                           p.datatype().globalid())

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

        for sid in sorted(self.__services__):
            serv = self.__services__[sid]

            for key in sorted(serv.methods()):
                method = serv.methods()[key]
                if version == 1 or not method.legacy():
                    if method.calltype() == "REQUEST_RESPONSE":
                        self.write_parameter_configlines(f, serv, method, 0x00, method.inparams(), version)
                        self.write_parameter_configlines(f, serv, method, 0x80, method.outparams(), version)
                    else:
                        self.write_parameter_configlines(f, serv, method, 0x01, method.inparams(), version)
                elif DEBUG_LEGACY_STRIPPING:
                    print(f"--> skipping legacy method: {serv.name()} (0x{serv.serviceid():x}) {method.name()} (0x{method.methodid():x})")

            for key in sorted(serv.events()):
                if version == 1 or not serv.events()[key].legacy():
                    self.write_parameter_configlines(f, serv, serv.events()[key], 0x02, serv.events()[key].params(),
                                                     version)
                elif DEBUG_LEGACY_STRIPPING:
                    print(f"--> skipping legacy event: {serv.name()} (0x{serv.serviceid():x}) {method.name()} (0x{method.methodid():x})")

            for key in sorted(serv.fields(), key=lambda x: (x is None, x)):
                field = serv.fields()[key]
                if version == 1 or not field.legacy():
                    if field.getter() is not None:
                        self.write_parameter_configlines(f, serv, field.getter(), 0x00, field.getter().inparams(), version)
                        self.write_parameter_configlines(f, serv, field.getter(), 0x80, field.getter().outparams(), version)
                    if field.setter() is not None:
                        self.write_parameter_configlines(f, serv, field.setter(), 0x00, field.setter().inparams(), version)
                        self.write_parameter_configlines(f, serv, field.setter(), 0x80, field.setter().outparams(), version)
                    if field.notifier() is not None:
                        self.write_parameter_configlines(f, serv, field.notifier(), 0x02, field.notifier().params(),
                                                         version)
                elif DEBUG_LEGACY_STRIPPING:
                    print(f"--> skipping legacy field: {serv.name()} (0x{serv.serviceid():x}) {field.name()}")

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
                        if not is_ip_mcast(socket.ip()):
                            tmp = ips.setdefault(socket.ip(), {})
                            tmp[ecuname] = ecuname

                    # let us also include IPs without sockets
                    for ip in interface.ips():
                        if is_ip(ip) and not is_ip_mcast(ip):
                            tmp = ips.setdefault(ip, {})
                            tmp[ecuname] = ecuname

        for ip in sorted(ips.keys(), key=lambda x: ip_to_key(x)):
            ecu_names = "__".join(ips[ip])
            f.write(f"{ip}\t{ecu_names}\n")

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

    def write_signal_pdu_binding_someip_configline(self, f, service, method, msgtype, pdu_id):
        # Service-ID, Method-ID, MessageType, Version, Legacy-ID

        if not method.legacy():
            return

        f.write(f"\"{service.serviceid():04x}\","
                f"\"{method.methodid():04x}\","
                f"\"{service.majorversion():02x}\","
                f"\"{msgtype:02x}\","
                f"\"{pdu_id:08x}\"\n"
                )

    def write_someip_signal_pdunames_configline(self, f, pdu_id, name):
        # Legacy-ID, Name

        f.write(f"\"{pdu_id:08x}\","
                f"\"{name}\"\n"
                )

    def write_someip_signals_configlines(self, f, f_enum, pdu_id, pdu_name, params):
        # signals (f)
        # ID, Num of Sigs, Pos, Name, Data Type, BE (TRUE/FALSE), bitlen base, bitlen coded, scaler, offset,
        # Multiplexer (FALSE), Muliplex value (-1), Hidden (FALSE)

        # enums (f_enum)
        # ID, Pos, Num of Values, Value start, Value end, Value Name

        if params is None or len(params) == 0:
            return

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
                        if 0 <= int(start) <= pow(2, 64) and 0 <= int(end) <= pow(2, 64):
                            f_enum.write(f"\"{pdu_id:08x}\","
                                         f"\"{m.position()}\","
                                         f"\"{len(cc)}\","
                                         f"\"{int(start):x}\","
                                         f"\"{int(end):x}\","
                                         f"\"{cleanup_string(value)}\""
                                         "\n"
                                         )
                        else:
                            print(f"Warning: CompuConst<0 or >2^64 not supported! "
                                  f"{pdu_id:08x}:{m.position()} {start}-{end} {value}")

                f.write(f"\"{pdu_id:08x}\","
                        f"\"{len(tmp)}\","
                        f"\"{m.position()}\","
                        f"\"{m.name()}\","
                        f"\"{pdu_name}.{m.name()}\","
                        f"\"{cleanup_datatype_string(m.child().datatype())}\","
                        f"\"{endian}\","
                        f"\"{m.child().bitlength_basetype()}\","
                        f"\"{m.child().bitlength_encoded_type()}\","
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
                            f_enum.write(f"\"{pdu_id:08x}\","
                                         f"\"{p.position()}\","
                                         f"\"{len(cc)}\","
                                         f"\"{start}\","
                                         f"\"{end}\","
                                         f"\"{cleanup_string(value)}\""
                                         "\n"
                                         )
                        else:
                            print(f"Warning: CompuConst<0 unsupported! {pdu_id:08x}:{p.position()} {start}-{end} {value}")

            f.write(f"\"{pdu_id:08x}\","
                    f"\"{len(params)}\","
                    f"\"{p.position()}\","
                    f"\"{p.name()}\","
                    f"\"{pdu_name}.{p.name()}\","
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

    def someip_pdu_id(self):

        ret = self.__globalid_signal_pdus__
        self.__globalid_signal_pdus__ += 1

        return ret

    def write_pdus_over_someip_config(self, target_dir, fn_bind, fn_id, fn_sig_list, fn_sig_values, version=1):
        f_bind = open(os.path.join(target_dir, fn_bind), "w")
        f_bind.write("# This file is automatically generated, DO NOT MODIFY. (LV)\n")

        f_id = open(os.path.join(target_dir, fn_id), "w")
        f_id.write("# This file is automatically generated, DO NOT MODIFY. (LV)\n")

        f_sig = open(os.path.join(target_dir, fn_sig_list), "w")
        f_sig.write("# This file is automatically generated, DO NOT MODIFY. (LV)\n")

        f_sigv = open(os.path.join(target_dir, fn_sig_values), "w")
        f_sigv.write("# This file is automatically generated, DO NOT MODIFY. (LV)\n")

        for sid in sorted(self.__services__):
            serv = self.__services__[sid]

            for key in sorted(serv.methods()):
                method = serv.methods()[key]

                if not method.legacy():
                    continue

                if method.calltype() == "REQUEST_RESPONSE":
                    # Request:
                    pdu_id = self.someip_pdu_id()

                    # signal pdu
                    self.write_someip_signal_pdunames_configline(f_id, pdu_id, method.name())

                    # signals
                    self.write_someip_signals_configlines(f_sig, f_sigv, pdu_id, method.name(), method.inparams())
                    # binding
                    self.write_signal_pdu_binding_someip_configline(f_bind, serv, method, 0x00, pdu_id)


                    # Response:
                    pdu_id = self.someip_pdu_id()

                    # signal pdu
                    self.write_someip_signal_pdunames_configline(f_id, pdu_id, method.name())

                    # signals
                    self.write_someip_signals_configlines(f_sig, f_sigv, pdu_id, method.name(), method.outparams())
                    # binding
                    self.write_signal_pdu_binding_someip_configline(f_bind, serv, method, 0x80, pdu_id)
                else:
                    pdu_id = self.someip_pdu_id()
                    # signal pdu
                    self.write_someip_signal_pdunames_configline(f_id, pdu_id, method.name())

                    # signals
                    self.write_someip_signals_configlines(f_sig, f_sigv, pdu_id, method.name(), method.inparams())
                    # binding
                    self.write_signal_pdu_binding_someip_configline(f_bind, serv, method, 0x01, pdu_id)

            for key in sorted(serv.events()):
                event = serv.events()[key]

                if not event.legacy():
                    continue

                pdu_id = self.someip_pdu_id()

                # signal pdu
                self.write_someip_signal_pdunames_configline(f_id, pdu_id, event.name())

                # signals
                self.write_someip_signals_configlines(f_sig, f_sigv, pdu_id, event.name(), event.params())

                # binding
                self.write_signal_pdu_binding_someip_configline(f_bind, serv, event, 0x02, pdu_id)

            for key in sorted(serv.fields(), key=lambda x: (x is None, x)):
                field = serv.fields()[key]

                if not field.legacy():
                    continue

                if field.getter() is not None or field.setter() is not None or field.notifier() is not None:
                    pdu_id = self.someip_pdu_id()

                    # signal pdu
                    self.write_someip_signal_pdunames_configline(f_id, pdu_id, field.name())

                    # signals
                    self.write_someip_signals_configlines(f_sig, f_sigv, pdu_id, field.name(), field.params())

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

        f_bind.close()
        f_id.close()
        f_sig.close()
        f_sigv.close()


class SOMEIPService(SOMEIPBaseService):
    def create_backlinks(self, factory):
        for i in self.__methods__.values():
            i.create_backlinks(factory, self)
        for i in self.__events__.values():
            i.create_backlinks(factory, self)
        for i in self.__fields__.values():
            i.create_backlinks(factory, self)


class SOMEIPServiceMethod(SOMEIPBaseServiceMethod):
    def create_backlinks(self, factory, service):
        tmp = []
        for p in self.__inparams__:
            if p is not None:
                tmp.append(p.create_backlinks(factory, service, self))
        self.__inparams__ = tmp

        tmp = []
        for p in self.__outparams__:
            if p is not None:
                tmp.append(p.create_backlinks(factory, service, self))
        self.__outparams__ = tmp


class SOMEIPServiceEvent(SOMEIPBaseServiceEvent):
    def create_backlinks(self, factory, service):
        tmp = []
        for p in self.__params__:
            if p is not None:
                tmp.append(p.create_backlinks(factory, service, self))
        self.__params__ = tmp


class SOMEIPServiceField(SOMEIPBaseServiceField):
    def create_backlinks(self, factory, service):
        if self.__getter__ is not None:
            self.__getter__.create_backlinks(factory, service)
        if self.__setter__ is not None:
            self.__setter__.create_backlinks(factory, service)
        if self.__notifier__ is not None:
            self.__notifier__.create_backlinks(factory, service)


class SOMEIPParameter(SOMEIPBaseParameter):
    def __init__(self, position, name, desc, mandatory, datatype, signal):
        super(SOMEIPParameter, self).__init__(position, name, desc, mandatory, datatype, signal)

        self.__parent_service__ = None
        self.__parent_method__ = None

    def create_backlinks(self, factory, service, method):
        if factory is None or (self.__parent_service__ is None and self.__parent_method__ is None):
            self.__parent_service__ = service
            self.__parent_method__ = method

            if self.__datatype__ is None:
                print(f"ERROR: create_backlinks __datatype__ is None {service.name()} {method.name()}")
                return self

            self.__datatype__ = self.__datatype__.create_backlinks(factory, service, method)
            return self
        else:
            ret = factory.create_someip_parameter(self.__position__,
                                                  self.__name__,
                                                  self.__desc__,
                                                  self.__mandatory__,
                                                  self.__datatype__,
                                                  self.__signal__)
            return ret.create_backlinks(factory, service, method)

    def parent_service(self):
        return self.__parent_service__

    def parent_method(self):
        return self.__parent_method__


class SOMEIPParameterBasetype(SOMEIPBaseParameterBasetype):
    def __init__(self, globalid, name, datatype, bigendian, bitlength_basetype, bitlength_encoded_type):
        super(SOMEIPParameterBasetype, self).__init__(name, datatype, bigendian, bitlength_basetype,
                                                      bitlength_encoded_type)
        self.__globalid__ = int(globalid)

    def create_backlinks(self, factory, service, method):
        return self

    def globalid(self):
        return self.__globalid__

    @staticmethod
    def paramtype():
        return WiresharkParameterTypes.basetype

    @staticmethod
    def translate_datatype(dt):
        if dt.lower().startswith("a_"):
            return dt[2:].lower()
        else:
            return dt.lower()

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
            # remove non SOME/IP datatypes since they are configured as Signal-PDU configs
            if self.bitlength_basetype() not in (8, 16, 32, 64):
                return ""
            if self.bitlength_basetype() != self.bitlength_encoded_type():
                return ""

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

    def create_backlinks(self, factory, service, method):
        return self

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

        self.__parent_service__ = None
        self.__parent_method__ = None

    def create_backlinks(self, factory, service, method):
        if factory is None or (self.__parent_service__ is None and self.__parent_method__ is None):
            self.__parent_service__ = service
            self.__parent_method__ = method

            self.__child__ = self.__child__.create_backlinks(factory, service, method)

            return self
        else:
            ret = factory.create_someip_parameter_array(self.__name__, self.__dims__, self.__child__)

            return ret.create_backlinks(factory, service, method)

    def globalid(self):
        return self.__globalid__

    @staticmethod
    def paramtype():
        return WiresharkParameterTypes.array

    def ws_config_line(self, version=1):
        # Array-ID,Name,DT-Type,DT-ID,MaxDim,Dim,Min,Max,LenOfLen,PadTo

        if self.__parent_service__ is None or self.__parent_method__ is None:
            print(f"    Warning: array ({self.name()}) is not attached to service!")

        ret = ""
        for key in self.dims():
            d = self.dims()[key]
            ret += "\"%08x\",\"%s\",\"%d\",\"%08x\",\"%d\"" % (self.globalid(),
                                                               self.name(),
                                                               self.child().paramtype(),
                                                               self.child().globalid(),
                                                               len(self.dims()))
            if version > 1:
                if self.__parent_service__ is None or self.__parent_method__ is None:
                    ret += f",\"invalid.invalid.{self.name()}\""
                else:
                    ret += f",\"{self.__parent_service__.name()}.{self.__parent_method__.name()}.{self.name()}\""

            ret += ",\"%d\",\"%d\",\"%d\",\"%d\",\"%d\"\n" % (d.dim() - 1,
                                                              d.lowerlimit(),
                                                              d.upperlimit(),
                                                              d.length_of_length(),
                                                              d.pad_to())
        return ret


class SOMEIPParameterStruct(SOMEIPBaseParameterStruct):
    def __init__(self, globalid, name, length_of_length, pad_to, members, tlv):
        super(SOMEIPParameterStruct, self).__init__(name, length_of_length, pad_to, members, tlv)
        self.__globalid__ = int(globalid)

        self.__parent_service__ = None
        self.__parent_method__ = None

    def create_backlinks(self, factory, service, method):
        if factory is None or (self.__parent_service__ is None and self.__parent_method__ is None):
            self.__parent_service__ = service
            self.__parent_method__ = method

            tmp = {}
            for k in self.__members__.keys():
                tmp[k] = self.__members__[k].create_backlinks(factory, service, method)
            self.__members__ = tmp

            return self
        else:
            ret = factory.create_someip_parameter_struct(self.__name__, self.__lengthOfLength__, self.__padTo__,
                                                         self.__members__, self.__tlv__)

            return ret.create_backlinks(factory, service, method)

    def globalid(self):
        return self.__globalid__

    @staticmethod
    def paramtype():
        return WiresharkParameterTypes.struct

    def ws_config_line(self, version=1):
        # Struct-ID,Struct Name,Length of length field,Align to,Number of items,Position,Name,Data Type,Datatype ID
        ret = ""

        if self.__parent_service__ is None or self.__parent_method__ is None:
            print(f"    Warning: struct ({self.name()}) is not attached to service!")
        else:
            if version == 2 and self.__parent_method__.legacy():
                if DEBUG_LEGACY_STRIPPING:
                    print(f"--> Skipping struct {self.name()} of Service {self.__parent_service__.name()} and Method {self.__parent_method__.name()}")
                return ret

        number_of_entries = len(self.members())

        # first pass: check that all positions are below numbers_of_entries
        for key in self.members():
            m = self.members()[key]
            m_pos = m.position()
            if m_pos >= number_of_entries:
                print(f"Position of SOME/IP Struct Member > len(members)! Adjusting ({m_pos+1})")
                number_of_entries = m_pos + 1

        for key in self.members():
            m = self.members()[key]
            ret += "\"%08x\",\"%s\",\"%d\",\"%d\"" % (self.globalid(),
                                                      self.name(),
                                                      self.length_of_length(),
                                                      self.pad_to())

            if version > 1:
                if self.tlv():
                    ret += f",\"TRUE\""
                else:
                    ret += f",\"FALSE\""

            ret += ",\"%d\"" % number_of_entries

            ret += ",\"%d\",\"%s\",\"%d\",\"%08x\"" % (m.position(),
                                                       m.name(),
                                                       m.child().paramtype(),
                                                       m.child().globalid())
            if version > 1:
                if self.__parent_service__ is None or self.__parent_method__ is None:
                    ret += f",\"invalid.invalid.{m.name()}\""
                else:
                    ret += f",\"{self.__parent_service__.name()}.{self.__parent_method__.name()}.{m.name()}\""

            ret += "\n"
        return ret


class SOMEIPParameterStructMember(SOMEIPBaseParameterStructMember):
    def __init__(self, position, name, mandatory, child, signal):
        super(SOMEIPParameterStructMember, self).__init__(position, name, mandatory, child, signal)

        self.__parent_service__ = None
        self.__parent_method__ = None

    def create_backlinks(self, factory, service, method):
        if factory is None or (self.__parent_service__ is None and self.__parent_method__ is None):
            self.__parent_service__ = service
            self.__parent_method__ = method

            if self.__child__ is not None:
                self.__child__ = self.__child__.create_backlinks(factory, service, method)

            return self
        else:
            ret = factory.create_someip_parameter_struct_member(self.__position__, self.__name__, self.__mandatory__,
                                                                self.__child__, self.__signal__)

            return ret.create_backlinks(factory, service, method)


class SOMEIPParameterTypedef(SOMEIPBaseParameterTypedef):
    def __init__(self, globalid, name, name2, child):
        super(SOMEIPParameterTypedef, self).__init__(name, name2, child)
        self.__globalid__ = int(globalid)

        self.__parent_service__ = None
        self.__parent_method__ = None

    def create_backlinks(self, factory, service, method):
        if factory is None or (self.__parent_service__ is None and self.__parent_method__ is None):
            self.__parent_service__ = service
            self.__parent_method__ = method

            self.__child__ = self.__child__.create_backlinks(factory, service, method)

            return self
        else:
            ret = factory.create_someip_parameter_typedef(self.__name__, self.__name2__, self.__child__)

            return ret.create_backlinks(factory, service, method)

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

        assert (isinstance(child, SOMEIPParameterBasetype))

    def create_backlinks(self, factory, service, method):
        return self

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

        self.__parent_service__ = None
        self.__parent_method__ = None

    def create_backlinks(self, factory, service, method):
        if factory is None or (self.__parent_service__ is None and self.__parent_method__ is None):
            self.__parent_service__ = service
            self.__parent_method__ = method

            tmp = {}
            for k in self.__members__.keys():
                tmp[k] = self.__members__[k].create_backlinks(factory, service, method)
            self.__members__ = tmp

            return self
        else:
            ret = factory.create_someip_parameter_union(self.__name__, self.__lengthOfLength__, self.__lengthOfType__,
                                                        self.__padTo__, self.__members__)

            return ret.create_backlinks(factory, service, method)

    def globalid(self):
        return self.__globalid__

    @staticmethod
    def paramtype():
        return WiresharkParameterTypes.union

    def ws_config_line(self, version=1):
        # Union-ID,Name,Length of length,Length of Type,Align to,Number of items,Index,Name,Data Type,Datatype ID

        if self.__parent_service__ is None or self.__parent_method__ is None:
            print(f"    Warning: union ({self.name()}) is not attached to service!")

        ret = ""
        for key in self.members():
            m = self.members()[key]
            ret += "\"%08x\",\"%s\",\"%d\",\"%d\",\"%d\",\"%d\"" % (self.globalid(),
                                                                    self.name(),
                                                                    self.length_of_length(),
                                                                    self.length_of_type(),
                                                                    self.pad_to(),
                                                                    len(self.members()))
            ret += ",\"%d\",\"%s\",\"%d\",\"%08x\"" % (m.index(),
                                                       m.name(),
                                                       m.child().paramtype(),
                                                       m.child().globalid())
            if version > 1:
                if self.__parent_service__ is None or self.__parent_method__ is None:
                    ret += f",\"invalid.invalid.{m.name()}\""
                else:
                    ret += f",\"{self.__parent_service__.name()}.{self.__parent_method__.name()}.{m.name()}\""
            ret += "\n"
        return ret


class SOMEIPParameterUnionMember(SOMEIPBaseParameterUnionMember):
    def __init__(self, index, name, mandatory, child):
        super(SOMEIPParameterUnionMember, self).__init__(index, name, mandatory, child)

        self.__parent_service__ = None
        self.__parent_method__ = None

    def create_backlinks(self, factory, service, method):
        if factory is None or (self.__parent_service__ is None and self.__parent_method__ is None):
            self.__parent_service__ = service
            self.__parent_method__ = method

            self.__child__ = self.__child__.create_backlinks(factory, service, method)

            return self
        else:
            ret = factory.create_someip_parameter_union_member(self.__index__, self.__name__, self.__mandatory__,
                                                               self.__child__)

            return ret.create_backlinks(factory, service, method)


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

    output_dir = parse_input_files(filename, t, conf_factory)

    if output_dir is None:
        help_and_exit()

    print("Generating output directories:")

    target_dir = os.path.join(output_dir, "wireshark_3.4_and_earlier")
    target_dir2 = os.path.join(output_dir, "wireshark_later")

    if not os.path.exists(target_dir):
        os.makedirs(target_dir)

    if not os.path.exists(target_dir2):
        os.makedirs(target_dir2)

    # we had race conditions in the past
    time.sleep(0.5)

    print("")
    print("Generating back links...")
    conf_factory.create_backlinks()

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

    # PDUs over SOME/IP
    fn1 = "Signal_PDU_Binding_SOMEIP"
    fn2 = "Signal_PDU_identifiers"
    fn3 = "Signal_PDU_signal_list"
    fn4 = "Signal_PDU_signal_values"
    print(f"  PDUs over SOME/IP: {fn1}, {fn2}, {fn3}, {fn4}")
    conf_factory.write_pdus_over_someip_config(target_dir2, fn1, fn2, fn3, fn4)

    fn = "hosts"
    print(f"  {fn}")
    conf_factory.write_hosts(os.path.join(target_dir, fn))
    conf_factory.write_hosts(os.path.join(target_dir2, fn), 2)

    fn = "vlans"
    print(f"  {fn}")
    conf_factory.write_vlanids(os.path.join(target_dir, fn))
    conf_factory.write_vlanids(os.path.join(target_dir2, fn), 2)

    print("Done.")


# only call main, if we are started directly
if __name__ == "__main__":
    main()
