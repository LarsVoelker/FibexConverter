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
import time

from configuration_base_classes import (
    BaseConfigurationFactory,
    BaseECU,
    SOMEIPBaseParameter,
    SOMEIPBaseParameterArray,
    SOMEIPBaseParameterBasetype,
    SOMEIPBaseParameterBitfield,
    SOMEIPBaseParameterEnumeration,
    SOMEIPBaseParameterString,
    SOMEIPBaseParameterStruct,
    SOMEIPBaseParameterTypedef,
    SOMEIPBaseParameterUnion,
    SOMEIPBaseService,
    read_csv_to_dict,
)
from parser_dispatcher import (
    is_file_or_dir_valid,
    is_file_valid,
    parse_input_files,
    parser_formats,
)


class PeachConfigurationFactory(BaseConfigurationFactory):
    def __init__(self):
        self.__services = dict()
        self.__services_long = dict()
        self.__ecus = dict()

    def create_ecu(self, name, controllers):
        ret = BaseECU(name, controllers)
        assert name not in self.__ecus
        self.__ecus[name] = ret
        return ret

    def create_someip_service(
        self, name, service_id, major_ver, minor_ver, methods, events, fields, eventgroups
    ):
        ret = SOMEIPBaseService(
            name, service_id, major_ver, minor_ver, methods, events, fields, eventgroups
        )
        print("Adding Service(ID: 0x%04x Ver: %d.%d)" % (service_id, major_ver, minor_ver))
        self.add_service(service_id, major_ver, minor_ver, ret)
        return ret

    def create_someip_parameter(
        self, position, name, desc, mandatory, data_type, signal
    ):
        ret = SOMEIPParameter(position, name, desc, mandatory, data_type, signal)
        return ret

    def create_someip_parameter_basetype(
        self, name, data_type, bigendian, bitlength_basetype, bitlength_encoded_type
    ):
        ret = SOMEIPParameterBasetype(
            name, data_type, bigendian, bitlength_basetype, bitlength_encoded_type
        )
        return ret

    def create_someip_parameter_string(
        self,
        name,
        char_type,
        big_endian,
        lower_limit,
        upper_limit,
        termination,
        length_of_length,
        pad_to,
    ):
        ret = SOMEIPParameterString(
            name,
            char_type,
            big_endian,
            lower_limit,
            upper_limit,
            termination,
            length_of_length,
            pad_to,
        )
        return ret

    def create_someip_parameter_array(self, name, dims, child):
        ret = SOMEIPParameterArray(name, dims, child)
        return ret

    def create_someip_parameter_struct(
        self, name, length_of_length, pad_to, members, tlv=False
    ):
        ret = SOMEIPParameterStruct(name, length_of_length, pad_to, members, tlv)
        return ret

    def create_someip_parameter_typedef(self, name, name2, child):
        ret = SOMEIPParameterTypedef(name, name2, child)
        return ret

    def create_someip_parameter_enumeration(self, name, items, child):
        ret = SOMEIPParameterEnumeration(name, items, child)
        return ret

    def create_someip_parameter_union(
        self, name, length_of_length, length_of_type, pad_to, members
    ):
        ret = SOMEIPParameterUnion(
            name, length_of_length, length_of_type, pad_to, members
        )
        return ret

    def create_someip_parameter_bitfield(self, name, items, child):
        ret = SOMEIPParameterBitfield(name, items, child)
        return ret

    def add_service(self, service_id, major_ver, minor_ver, service):
        sid = "%04x-%02x-%08x" % (service_id, major_ver, minor_ver)
        if sid in self.__services_long:
            print(
                "ERROR: Service (SID: 0x%04x, Major-Ver: %d, Minor-Ver: %d) already exists! Not overriding it!"
                % (service_id, major_ver, minor_ver)
            )
            return False
        self.__services_long[sid] = service

        sid = "%04x-%02x" % (service_id, major_ver)
        if sid in self.__services:
            print(
                "ERROR: Service (SID: 0x%04x, Major-Ver: %d) already exists with a different Minor Version (not %d)!"
                " Not overriding it!" % (service_id, major_ver, minor_ver)
            )
            return False
        self.__services[sid] = service
        return True

    def get_service(self, service_id, major_ver, minor_ver=None):
        if minor_ver is None:
            sid = "%04x-%02x" % (service_id, major_ver)
            if sid in self.__services:
                return self.__services[sid]
            else:
                return None
        else:
            sid = "%04x-%02x-%08x" % (service_id, major_ver, minor_ver)
            if sid in self.__services_long:
                return self.__services_long[sid]
            else:
                return None

    def generate_configs(self, target_dir):
        for ecu_key in sorted(self.__ecus.keys()):
            ecu = self.__ecus[ecu_key]

            for ctrl in ecu.controllers():
                for iface in ctrl.interfaces():
                    vlan_id = int(iface.vlan_id())
                    for socket in iface.sockets():

                        for si in socket.instances():
                            serv = si.service()

                            for m in serv.methods():
                                self.write_configfile_method_request(
                                    target_dir,
                                    ecu,
                                    vlan_id,
                                    socket,
                                    si,
                                    serv.methods()[m],
                                    "-Request",
                                )

                            for e in serv.events():
                                self.write_configfile_event(
                                    target_dir,
                                    ecu,
                                    vlan_id,
                                    socket,
                                    si,
                                    serv.events()[e],
                                    "-Event",
                                )

                            for f in serv.fields():
                                field = serv.fields()[f]
                                if field.notifier() is not None:
                                    self.write_configfile_event(
                                        target_dir,
                                        ecu,
                                        vlan_id,
                                        socket,
                                        si,
                                        field.notifier(),
                                        "",
                                    )
                                # getter has empty request anyhow
                                if field.getter() is not None:
                                    self.write_configfile_method_request(
                                        target_dir,
                                        ecu,
                                        vlan_id,
                                        socket,
                                        si,
                                        field.getter(),
                                        "-Request",
                                    )
                                if field.setter() is not None:
                                    self.write_configfile_method_request(
                                        target_dir,
                                        ecu,
                                        vlan_id,
                                        socket,
                                        si,
                                        field.setter(),
                                        "-Request",
                                    )

    def write_configfile_method_request(
        self, target_dir, ecu, vlan_id, socket, si, method, postfix
    ):
        if (socket.protocol() == "udp" and not method.reliable()) or (
                socket.protocol() == "tcp" and method.reliable()
        ):
            if method.call_type() == "REQUEST_RESPONSE":
                msg_type = 0x00
            elif method.call_type() == "FIRE_AND_FORGET":
                msg_type = 0x01
            else:
                print(
                    "ERROR: cannot figure out call type of Method: %s 0x%04x 0x%04x"
                    % (method.name(), method.method_id(), si.service().service_id())
                )
                msg_type = 0xFF

            filename = "SOMEIP-%s-0x%04x-0x%04x-%s%s.xml" % (
                ecu.name(),
                si.service().service_id(),
                method.method_id(),
                method.name(),
                postfix,
            )

            print("  writing file %s" % filename)
            f = open(os.path.join(target_dir, filename), "w")

            msg_name = method.name() + postfix
            # peach is somewhat picky about names :-(
            msg_name = msg_name.replace("-", "").replace("_", "")
            self.write_header(
                f,
                msg_name,
                si.service().service_id(),
                method.method_id(),
                si.protocol_version(),
                si.service().major_version(),
                msg_type,
                0,
            )

            for param in method.in_parameters():
                self.write_parameter(f, param)

            self.write_footer(
                f,
                msg_name,
                self.cap_dev_string(vlan_id),
                self.filter_string(socket.protocol(), socket.port_number()),
                self.publisher_string(socket.protocol()),
                socket.ip(),
                socket.port_number(),
            )

            f.close()

    def write_configfile_event(
        self, target_dir, ecu, vlan_id, socket, si, event, postfix
    ):
        if (socket.protocol() == "udp" and not event.reliable()) or (
                socket.protocol() == "tcp" and event.reliable()
        ):
            filename = "SOMEIP-%s-0x%04x-0x%04x-%s%s.xml" % (
                ecu.name(),
                si.service().service_id(),
                event.method_id(),
                event.name(),
                postfix,
            )

            print("  writing file %s" % filename)
            f = open(os.path.join(target_dir, filename), "w")

            msg_name = event.name() + postfix
            # peach is somewhat picky about names :-(
            msg_name = msg_name.replace("-", "").replace("_", "")
            self.write_header(
                f,
                msg_name,
                si.service().service_id(),
                event.method_id(),
                si.protocol_version(),
                si.service().major_version(),
                0x02,
                0,
            )

            for param in event.params():
                self.write_parameter(f, param)

            self.write_footer(
                f,
                msg_name,
                self.cap_dev_string(vlan_id),
                self.filter_string(socket.protocol(), socket.port_number()),
                self.publisher_string(socket.protocol()),
                socket.ip(),
                socket.port_number(),
            )

            f.close()

    @staticmethod
    def write_parameter(f, param):
        param.peach_out(f)

    @staticmethod
    def write_header(
        f, msg_name, service_id, method_id, proto_ver, interface_ver, msg_type, return_code
    ):

        xml_header = """<?xml version="1.0" encoding="utf-8"?>
<Peach xmlns="http://peachfuzzer.com/2012/Peach" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://peachfuzzer.com/2012/Peach ../peach.xsd">
"""
        # start with SOME/IP Header
        f.write(xml_header + "\n")
        f.write('	<DataModel name="%s" mutable="false">\n' % msg_name)
        f.write('		<Block name="Magic" mutable="false">\n')
        # Service ID
        f.write(
            '			<Number name="ServiceId" size="16" signed="false" value="0x%04x" mutable="false" '
            'valueType="hex" endian="big" />\n' % service_id
        )
        # Method ID
        f.write(
            '			<Number name="MethodId" size="16" signed="false" value="0x%04x" mutable="false" '
            'valueType="hex" endian="big" />\n' % method_id
        )

        block = """			<!-- Length of Payload -->
			<Number name="Len" size="32" mutable="false" endian="big">
				<Relation type="size" of="Payload" />
			</Number>
		</Block>

		<Block name="Payload">
			<Block name="Header" mutable="false">
				<!-- Random RequestId -->
				<Number name="RequestId" size="32" endian="big">
					<Fixup class="SequenceRandomFixup" />
				</Number>
"""

        f.write(block)

        # last header line
        f.write(
            '				<Number name="ProtocolVersion" size="8" value="0x%02x" mutable="false" valueType="hex" endian="big" />\n'
            % proto_ver
        )
        f.write(
            '				<Number name="InterfaceVersion" size="8" value="0x%02x" mutable="false" valueType="hex" endian="big" />\n'
            % interface_ver
        )
        f.write(
            '				<Number name="MessageType" size="8" value="0x%02x" mutable="false" valueType="hex" endian="big" />\n'
            % msg_type
        )
        f.write(
            '				<Number name="ReturnCode" size="8" value="0x%02x" mutable="false" valueType="hex" endian="big" />\n'
            % return_code
        )

        block = """			</Block>
		
			<Block name="DataBytes" minOccurs=\"1\" maxOccurs=\"1\" >
"""
        f.write(block)

    @staticmethod
    def cap_dev_string(vlan_id):
        return "eth0.%d" % vlan_id

    @staticmethod
    def filter_string(proto, port_number):
        if port_number == -1:
            port_number = 30491
        return "%s and port %d" % (proto, port_number)

    @staticmethod
    def publisher_string(proto):
        if proto == "udp":
            return "Udp"
        if proto == "tcp":
            return "Tcp"
        return None

    @staticmethod
    def write_footer(f, msg_name, cap_dev, cap_filter, publisher, ip, port_number):

        block = """			</Block>
			
		</Block>
	</DataModel>

	<StateModel name="TestState" initialState="Initial">
		<State name="Initial">
			<Action type="output" name="InitialOutput">
"""
        f.write(block)

        f.write('				<DataModel ref="%s" />\n' % msg_name)

        block = """			</Action>
		</State>
	</StateModel>
	
	<Agent name="Local">
        <Monitor class="Pcap">
"""
        f.write(block)

        f.write('			<Param name="Device" value="%s" />\n' % cap_dev)
        f.write('			<Param name="Filter" value="%s" />\n' % cap_filter)

        block = """		</Monitor>
	</Agent>

	<Test name="Default">
		<StateModel ref="TestState" />
		<Exclude/>
		<Include xpath="//DataBytes" />

"""
        f.write(block)

        f.write('		<Publisher class="%s">\n' % publisher)
        f.write('			<Param name="Host" value="%s" />\n' % ip)
        f.write('			<Param name="Port" value="%s" />\n' % port_number)

        block = """		</Publisher>

		<Strategy class="Random">
			<Param name="MaxFieldsToMutate" value="5" />
			<Param name="SwitchCount" value="50" />
		</Strategy>

		<Logger class="File">
			<Param name="Path" value="Logs" />
		</Logger>
	</Test>	

</Peach>
"""
        f.write(block + "\n")


class SOMEIPParameter(SOMEIPBaseParameter):
    def peach_out(self, f):
        if self.data_type() is not None:
            self.data_type().peach_out(f, 4, self.name(), 1, 1)


class SOMEIPParameterBasetype(SOMEIPBaseParameterBasetype):
    def peach_out(self, f, indent, param_name, min_num, max_num):
        endian = "little"
        if self.big_endian():
            endian = "big"

        f.write(
            '%s<Number name="%s" size="%d" endian="%s" minOccurs="%d" maxOccurs="%d" />\n'
            % (
                indent * " ",
                param_name,
                self.bit_length_encoded_type(),
                endian,
                min_num,
                max_num,
            )
        )


class SOMEIPParameterString(SOMEIPBaseParameterString):
    def peach_out_bom(self, f, indent, block_id):
        ident_tabs = indent * "	"
        t = self.char_type()

        if t.upper() == "UTF-8":
            f.write(
                '%s<Number name="%s_BOM1" size="8" value="0xEF" minOccurs="1" maxOccurs="1" />\n'
                % (ident_tabs, block_id)
            )
            f.write(
                '%s<Number name="%s_BOM2" size="8" value="0xBB" minOccurs="1" maxOccurs="1" />\n'
                % (ident_tabs, block_id)
            )
            f.write(
                '%s<Number name="%s_BOM3" size="8" value="0xBF" minOccurs="1" maxOccurs="1" />\n'
                % (ident_tabs, block_id)
            )
            return 3
        elif t.upper() == "UTF-16":
            endian = "big" if self.big_endian() else "little"
            f.write(
                '%s<Number name="%s_BOM" size="16" value="0xFEFF" endian="%s" minOccurs="1" '
                'maxOccurs="1" />\n' % (ident_tabs, block_id, endian)
            )
            return 2

        print("ERROR: Cannot generate BOM for this string %s" % (self.name()))
        return 0

    def peach_out(self, f, indent, param_name, min_num, max_num):
        ident_tabs = indent * "	"

        endian = "BE"
        if not self.big_endian():
            endian = "LE"

        t = self.char_type()
        if t.upper() == "UTF-8":
            t = "utf8"
        elif t.upper() == "UTF-16":
            if endian == "BE":
                t = "utf16be"
            else:
                t = "utf16"
        elif t.upper() == "ASCII":
            t = "ascii"
        else:
            # it's probably wrong. but we leave it
            pass

        if self.termination() == "ZERO":
            term = 'nullTerminated="true"'
        else:
            print("WARNING: unknown termination for string: %s" % self.__termination)
            term = ""

        block_id = "String_%s_%x" % (param_name, id(self))

        if self.length_of_length() != 0:
            f.write(
                '%s<Number name="%s_Len" size="%d" endian="big" minOccurs="1" maxOccurs="1" >\n'
                % (ident_tabs, block_id, self.length_of_length())
            )
            f.write('%s	<Relation type="size" of="%s" />\n' % (ident_tabs, block_id))
            f.write("%s</Number>\n" % ident_tabs)

        f.write(
            '%s<Block name="%s" minOccurs="1" maxOccurs="1" >\n' % (ident_tabs, block_id)
        )

        if self.length_of_length() != 0:
            f.write(
                "%s	<!-- String %s %s %s (%d..%d) len:%d pad:%d %s -->\n"
                % (
                    ident_tabs,
                    self.name(),
                    self.char_type(),
                    endian,
                    self.lower_limit(),
                    self.upper_limit(),
                    self.length_of_length(),
                    self.pad_to(),
                    term,
                )
            )

            if self.pad_to() != 0:
                print(
                    "ERROR: String %s has padTo set to %d but we do not support!!"
                    % (self.name(), self.pad_to())
                )
                f.write(
                    "%s<!-- PadTo Parameter set to %d! -->"
                    % (ident_tabs, self.pad_to())
                )

            bom_len = self.peach_out_bom(f, indent + 1, block_id)

            lower = self.lower_limit() - bom_len
            upper = self.upper_limit() - bom_len

            if lower < 0:
                lower = 0

            if upper < 1:
                print("ERROR: String %s does not have valid length." % (self.name()))
                f.write(
                    "%s	<!-- UPPER LIMIT INCORRECT!!! upper:%d after BOM correction %d -->\n"
                    % (ident_tabs, upper, bom_len)
                )

            f.write(
                '%s	<String name="%s_string" type="%s" %s minOccurs="1" maxOccurs="1" />\n'
                % (ident_tabs, block_id, t, term)
            )

        else:
            # fixed length string
            assert self.lower_limit() == self.upper_limit()
            bom_len = self.peach_out_bom(f, indent + 1, block_id)

            lower = self.lower_limit() - bom_len

            if lower < 1:
                print("ERROR: String %s does not have valid length." % (self.name()))

            f.write(
                '%s	<String name="%s_string" type="%s" length="%d" %s minOccurs="1" maxOccurs="1" />\n'
                % (ident_tabs, block_id, t, lower, term)
            )
        f.write("%s</Block>\n" % ident_tabs)


class SOMEIPParameterArray(SOMEIPBaseParameterArray):
    def peach_out(self, f, indent, param_name, min_num, max_num):
        counter = 0
        ident_tabs = indent * "	"

        if len(self.dimensions()) != 1:
            f.write("%s<!--TODO: Multi-Dim Arrays-->\n" % ident_tabs)
        else:
            block_id = "Array%s%x%x" % (self.name(), id(self), counter)
            counter += 1

            # there is only one dim and this should have the key 1
            for i in self.dimensions().keys():
                dim = self.dimensions()[i]
            min2 = dim.lower_limit()
            max2 = dim.upper_limit()
            length_of_length = dim.length_of_length()

            if length_of_length != 0:
                f.write(
                    '%s<Number name="ArrayLen%s" size="%d" endian="big" minOccurs="1" maxOccurs="1" >\n'
                    % (ident_tabs, block_id, dim.length_of_length())
                )
                f.write(
                    '%s	<Relation type="size" of="%s" />\n' % (ident_tabs, block_id)
                )
                f.write("%s</Number>\n" % ident_tabs)

            f.write(
                '%s<Block name="%s" minOccurs="1" maxOccurs="1" >\n'
                % (ident_tabs, block_id)
            )
            f.write(
                '%s	<Block name="%s" minOccurs="%d" maxOccurs="%d">\n'
                % (ident_tabs, "Data" + block_id, min2, max2)
            )
            self.child().peach_out(f, indent + 2, param_name, 1, 1)
            f.write("%s	</Block>\n" % ident_tabs)
            f.write("%s</Block>\n" % ident_tabs)


class SOMEIPParameterStruct(SOMEIPBaseParameterStruct):
    def peach_out(self, f, indent, param_name, min_num, max_num):
        ident_tabs = indent * "	"
        block_id = "Struct%s%x" % (self.name(), id(self))

        if self.length_of_length() != 0:
            f.write(
                '%s<Number name="StructLen%x" size="%d" mutable="false" endian="big" minOccurs="1" '
                'maxOccurs="1" >\n' % (ident_tabs, id(self), self.length_of_length())
            )
            f.write('%s	<Relation type="size" of="%s" />\n' % (ident_tabs, block_id))
            f.write("%s</Number>\n" % ident_tabs)

        f.write(
            '%s<Block name="%s" minOccurs="%d" maxOccurs="%d">\n'
            % (ident_tabs, block_id, min_num, max_num)
        )
        # f.write("%s<!-- Struct %s start -->\n" % (ident_tabs, self.__name__))
        for m in sorted(self.members().keys()):
            member = self.members()[m]
            child = member.child()
            child.peach_out(f, indent + 1, member.name(), 1, 1)
        f.write("%s</Block>\n" % ident_tabs)
        # f.write("%s<!-- Struct %s end -->\n" % (ident_tabs, self.__name__))


class SOMEIPParameterTypedef(SOMEIPBaseParameterTypedef):
    def peach_out(self, f, indent, param_name, min_num, max_num):
        if self.child() is not None:
            self.child().peach_out(f, indent, param_name, min_num, max_num)


class SOMEIPParameterEnumeration(SOMEIPBaseParameterEnumeration):
    def peach_out(self, f, indent, param_name, min_num, max_num):
        if self.child() is not None:
            self.child().peach_out(f, indent, param_name, min_num, max_num)


class SOMEIPParameterUnion(SOMEIPBaseParameterUnion):
    def peach_out(self, f, indent, param_name, min_num, max_num):
        ident_tabs = indent * "	"

        block_id_choice = "Union%s%x" % (self.name(), id(self))

        f.write(
            '%s<Choice name="%s" minOccurs="%d" maxOccurs="%d">\n'
            % (ident_tabs, block_id_choice, min_num, max_num)
        )

        for m in self.members():
            member = self.members()[m]
            block_id = "Union%s0x%xType0x%04x" % (self.name(), id(self), member.index())

            f.write(
                '%s	<Block name="%sWrapper" minOccurs="1" maxOccurs="1" >\n'
                % (ident_tabs, block_id)
            )

            if self.length_of_length() != 0:
                f.write(
                    '%s		<Number name="UnionLen%s" size="%d" endian="big" minOccurs="1" '
                    'maxOccurs="1" >\n' % (ident_tabs, block_id, self.length_of_length())
                )
                f.write(
                    '%s			<Relation type="size" of="%s" />\n'
                    % (ident_tabs, block_id)
                )
                f.write("%s		</Number>\n" % ident_tabs)

            if self.length_of_type() != 0:
                f.write(
                    '%s		<Number name="UnionType%s" size="%d" value="0x%04x" endian="big" '
                    'minOccurs="1" maxOccurs="1" />\n'
                    % (ident_tabs, block_id, self.length_of_type(), member.index())
                )
            else:
                print(
                    "ERROR: Union %s thinks that TypeField can be 0 bytes long!!!!"
                    % (self.name())
                )
                f.write("%s		<!-- TypeField with len:0!!! -->\n" % ident_tabs)
                return

            f.write(
                '%s		<Block name="%s" minOccurs="1" maxOccurs="1" >\n'
                % (ident_tabs, block_id)
            )
            member.child().peach_out(f, indent + 3, member.name(), 1, 1)
            f.write("%s		</Block>\n" % ident_tabs)

            f.write("	%s</Block>\n" % ident_tabs)

        f.write("%s</Choice>\n" % ident_tabs)


class SOMEIPParameterBitfield(SOMEIPBaseParameterBitfield):
    def peach_out(self, f, indent, param_name, min_num, max_num):
        if self.child() is not None:
            self.child().peach_out(f, indent, param_name, min_num, max_num)


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Converting configuration to peach xml."
    )
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

    args = parser.parse_args()
    return args


def main():
    global g_gen_portid

    print("Converting configuration to peach xml\n")
    args = parse_arguments()

    g_gen_portid = args.generate_switch_port_names

    ecu_name_mapping = {}
    if args.ecu_name_mapping is not None:
        ecu_name_mapping = read_csv_to_dict(args.ecu_name_mapping)

    conf_factory = PeachConfigurationFactory()
    output_dir = parse_input_files(
        args.filename,
        args.type,
        conf_factory,
        plugin_file=args.plugin,
        ecu_name_replacement=ecu_name_mapping,
    )

    target_dir = os.path.join(output_dir, "peach")

    if not os.path.exists(target_dir):
        os.makedirs(target_dir)
        time.sleep(0.5)

    conf_factory.generate_configs(target_dir)

    print("Done.")


# only call main, if we are started directly
if __name__ == "__main__":
    main()
