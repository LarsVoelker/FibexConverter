#!/usr/bin/python

# Automotive configuration file scripts
# Copyright (C) 2015-2025  Dr. Lars Voelker
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

import sys
import time
import os.path
import argparse

from parser_dispatcher import *  # @UnusedWildImport
from configuration_base_classes import *  # @UnusedWildImport


class PeachConfigurationFactory(BaseConfigurationFactory):
    def __init__(self):
        self.__services__ = dict()
        self.__services_long__ = dict()
        self.__ecus__ = dict()

    def create_ecu(self, name, controllers):
        ret = BaseECU(name, controllers)
        assert (name not in self.__ecus__)
        self.__ecus__[name] = ret
        return ret

    def create_someip_service(self, name, serviceid, majorver, minorver, methods, events, fields, eventgroups):
        ret = SOMEIPBaseService(name, serviceid, majorver, minorver, methods, events, fields, eventgroups)
        logger.debug("Adding Service(Name: %s ID: 0x%04x Ver: %d.%d)", name, serviceid, majorver, minorver)
        self.add_service(serviceid, majorver, minorver, ret)
        return ret

    def create_someip_parameter(self, position, name, desc, mandatory, datatype, signal):
        ret = SOMEIPParameter(position, name, desc, mandatory, datatype, signal)
        return ret

    def create_someip_parameter_basetype(self, name, datatype, bigendian, bitlength_basetype, bitlength_encoded_type):
        ret = SOMEIPParameterBasetype(name, datatype, bigendian, bitlength_basetype, bitlength_encoded_type)
        return ret

    def create_someip_parameter_string(self, name, chartype, bigendian, lowerlimit, upperlimit, termination,
                                       length_of_length, pad_to):
        ret = SOMEIPParameterString(name, chartype, bigendian, lowerlimit, upperlimit, termination,
                                    length_of_length, pad_to)
        return ret

    def create_someip_parameter_array(self, name, dims, child):
        ret = SOMEIPParameterArray(name, dims, child)
        return ret

    def create_someip_parameter_struct(self, name, length_of_length, pad_to, members, tlv=False):
        ret = SOMEIPParameterStruct(name, length_of_length, pad_to, members, tlv)
        return ret

    def create_someip_parameter_typedef(self, name, name2, child):
        ret = SOMEIPParameterTypedef(name, name2, child)
        return ret

    def create_someip_parameter_enumeration(self, name, items, child):
        ret = SOMEIPParameterEnumeration(name, items, child)
        return ret

    def create_someip_parameter_union(self, name, length_of_length, length_of_type, pad_to, members):
        ret = SOMEIPParameterUnion(name, length_of_length, length_of_type, pad_to, members)
        return ret

    def create_someip_parameter_bitfield(self, name, items, child):
        ret = SOMEIPParameterBitfield(name, items, child)
        return ret

    def add_service(self, serviceid, majorver, minorver, service):
        sid = "%04x-%02x-%08x" % (serviceid, majorver, minorver)
        if sid in self.__services_long__:
            print("ERROR: Service (SID: 0x%04x, Major-Ver: %d, Minor-Ver: %d) already exists! Not overriding it!" %
                  (serviceid, majorver, minorver))
            return False
        self.__services_long__[sid] = service

        sid = "%04x-%02x" % (serviceid, majorver)
        if sid in self.__services__:
            print("ERROR: Service (SID: 0x%04x, Major-Ver: %d) already exists with a different Minor Version (not %d)!"
                  " Not overriding it!" % (serviceid, majorver, minorver))
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

    def generate_configs(self, target_dir):
        for ecukey in sorted(self.__ecus__.keys()):
            ecu = self.__ecus__[ecukey]
            # ecu_name = ecu.name()

            for ctrl in ecu.controllers():
                for iface in ctrl.interfaces():
                    vlanid = int(iface.vlanid())
                    # vlanname = iface.vlanname()
                    for socket in iface.sockets():
                        # ip = socket.ip()
                        # portnumber = socket.portnumber()
                        # proto = socket.proto()
                        # print "%s eth0.%d %s:%d/%s" % (ecu_name, vlanid, ip, portnumber, proto)

                        for si in socket.instances():
                            serv = si.service()

                            for m in serv.methods():
                                self.write_configfile_method_request(target_dir, ecu, vlanid, socket, si,
                                                                     serv.methods()[m], "-Request")

                            for e in serv.events():
                                self.write_configfile_event(target_dir, ecu, vlanid, socket, si,
                                                            serv.events()[e], "-Event")

                            for f in serv.fields():
                                field = serv.fields()[f]
                                if field.notifier() is not None:
                                    self.write_configfile_event(target_dir, ecu, vlanid, socket, si,
                                                                field.notifier(), "")
                                # getter has empty request anyhow
                                if field.getter() is not None:
                                    self.write_configfile_method_request(target_dir, ecu, vlanid, socket, si,
                                                                         field.getter(), "-Request")
                                if field.setter() is not None:
                                    self.write_configfile_method_request(target_dir, ecu, vlanid, socket, si,
                                                                         field.setter(), "-Request")

    def write_configfile_method_request(self, target_dir, ecu, vlanid, socket, si, method, postfix):
        if (socket.proto() == "udp" and not method.reliable()) or (socket.proto() == "tcp" and method.reliable()):
            if method.calltype() == "REQUEST_RESPONSE":
                msgtype = 0x00
            elif method.calltype() == "FIRE_AND_FORGET":
                msgtype = 0x01
            else:
                print("ERROR: cannot figure out calltype of Method: %s 0x%04x 0x%04x" %
                      (method.name(), method.methodid(), si.service().serviceid()))
                msgtype = 0xff

            filename = "SOMEIP-%s-0x%04x-0x%04x-%s%s.xml" % \
                       (ecu.name(), si.service().serviceid(), method.methodid(), method.name(), postfix)

            print("  writing file %s" % filename)
            f = open(os.path.join(target_dir, filename), "w")

            msgname = method.name() + postfix
            # peach is somewhat picky about names :-(
            msgname = msgname.replace("-", "").replace("_", "")
            self.write_header(f, msgname, si.service().serviceid(), method.methodid(), si.protover(),
                              si.service().majorversion(), msgtype, 0)

            for param in method.inparams():
                self.write_parameter(f, param)

            self.write_footer(f, msgname, self.capdevstring(vlanid),
                              self.filterstring(socket.proto(), socket.portnumber()),
                              self.publisherstring(socket.proto()), socket.ip(), socket.portnumber())

            f.close()

    def write_configfile_event(self, target_dir, ecu, vlanid, socket, si, event, postfix):
        if (socket.proto() == "udp" and not event.reliable()) or (socket.proto() == "tcp" and event.reliable()):
            filename = "SOMEIP-%s-0x%04x-0x%04x-%s%s.xml" % \
                       (ecu.name(), si.service().serviceid(), event.methodid(), event.name(), postfix)

            print("  writing file %s" % filename)
            f = open(os.path.join(target_dir, filename), "w")

            msgname = event.name() + postfix
            # peach is somewhat picky about names :-(
            msgname = msgname.replace("-", "").replace("_", "")
            self.write_header(f, msgname, si.service().serviceid(), event.methodid(), si.protover(),
                              si.service().majorversion(), 0x02, 0)

            for param in event.params():
                self.write_parameter(f, param)

            self.write_footer(f, msgname, self.capdevstring(vlanid),
                              self.filterstring(socket.proto(), socket.portnumber()),
                              self.publisherstring(socket.proto()), socket.ip(), socket.portnumber())

            f.close()

    @staticmethod
    def write_parameter(f, param):
        param.peachout(f)

    @staticmethod
    def write_header(f, msgname, serviceid, methodid, protover, interfacever, msgtype, returncode):

        xml_header = """<?xml version="1.0" encoding="utf-8"?>
<Peach xmlns="http://peachfuzzer.com/2012/Peach" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://peachfuzzer.com/2012/Peach ../peach.xsd">
"""
        # start with SOME/IP Header
        f.write(xml_header + "\n")
        f.write("	<DataModel name=\"%s\" mutable=\"false\">\n" % msgname)
        f.write("		<Block name=\"Magic\" mutable=\"false\">\n")
        # Service ID
        f.write("			<Number name=\"ServiceId\" size=\"16\" signed=\"false\" value=\"0x%04x\" mutable=\"false\" "
                "valueType=\"hex\" endian=\"big\" />\n" % serviceid)
        # Method ID
        f.write("			<Number name=\"MethodId\" size=\"16\" signed=\"false\" value=\"0x%04x\" mutable=\"false\" "
                "valueType=\"hex\" endian=\"big\" />\n" % methodid)

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
            "				<Number name=\"ProtocolVersion\" size=\"8\" value=\"0x%02x\" mutable=\"false\" valueType=\"hex\" endian=\"big\" />\n" % (
                protover))
        f.write(
            "				<Number name=\"InterfaceVersion\" size=\"8\" value=\"0x%02x\" mutable=\"false\" valueType=\"hex\" endian=\"big\" />\n" % (
                interfacever))
        f.write(
            "				<Number name=\"MessageType\" size=\"8\" value=\"0x%02x\" mutable=\"false\" valueType=\"hex\" endian=\"big\" />\n" % (
                msgtype))
        f.write(
            "				<Number name=\"ReturnCode\" size=\"8\" value=\"0x%02x\" mutable=\"false\" valueType=\"hex\" endian=\"big\" />\n" % (
                returncode))

        block = """			</Block>
		
			<Block name="DataBytes" minOccurs=\"1\" maxOccurs=\"1\" >
"""
        f.write(block)

    @staticmethod
    def capdevstring(vlanid):
        return "eth0.%d" % vlanid

    @staticmethod
    def filterstring(proto, portnumber):
        if portnumber == -1:
            portnumber = 30491
        return "%s and port %d" % (proto, portnumber)

    @staticmethod
    def publisherstring(proto):
        if proto == "udp":
            return "Udp"
        if proto == "tcp":
            return "Tcp"
        return None

    @staticmethod
    def write_footer(f, msgname, capdev, capfilter, publisher, ip, portnumber):

        block = """			</Block>
			
		</Block>
	</DataModel>

	<StateModel name="TestState" initialState="Initial">
		<State name="Initial">
			<Action type="output" name="InitialOutput">
"""
        f.write(block)

        f.write("				<DataModel ref=\"%s\" />\n" % msgname)

        block = """			</Action>
		</State>
	</StateModel>
	
	<Agent name="Local">
        <Monitor class="Pcap">
"""
        f.write(block)

        f.write("			<Param name=\"Device\" value=\"%s\" />\n" % capdev)
        f.write("			<Param name=\"Filter\" value=\"%s\" />\n" % capfilter)

        block = """		</Monitor>
	</Agent>

	<Test name="Default">
		<StateModel ref="TestState" />
		<Exclude/>
		<Include xpath="//DataBytes" />

"""
        f.write(block)

        f.write("		<Publisher class=\"%s\">\n" % publisher)
        f.write("			<Param name=\"Host\" value=\"%s\" />\n" % ip)
        f.write("			<Param name=\"Port\" value=\"%s\" />\n" % portnumber)

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
    def peachout(self, f):
        if self.__datatype__ is not None:
            self.__datatype__.peachout(f, 4, self.name(), 1, 1)


class SOMEIPParameterBasetype(SOMEIPBaseParameterBasetype):
    def peachout(self, f, indent, paramname, minnum, maxnum):
        endian = "little"
        if self.bigendian():
            endian = "big"

        f.write("%s<Number name=\"%s\" size=\"%d\" endian=\"%s\" minOccurs=\"%d\" maxOccurs=\"%d\" />\n" %
                (indent * " ", paramname, self.__bitlength_encoded_type__, endian, minnum, maxnum))


class SOMEIPParameterString(SOMEIPBaseParameterString):
    def peachout_bom(self, f, indent, blockid):
        identtabs = indent * "	"
        t = self.__chartype__

        if t.upper() == "UTF-8":
            f.write("%s<Number name=\"%s_BOM1\" size=\"8\" value=\"0xEF\" minOccurs=\"1\" maxOccurs=\"1\" />\n" %
                    (identtabs, blockid))
            f.write("%s<Number name=\"%s_BOM2\" size=\"8\" value=\"0xBB\" minOccurs=\"1\" maxOccurs=\"1\" />\n" %
                    (identtabs, blockid))
            f.write("%s<Number name=\"%s_BOM3\" size=\"8\" value=\"0xBF\" minOccurs=\"1\" maxOccurs=\"1\" />\n" %
                    (identtabs, blockid))
            return 3
        elif t.upper() == "UTF-16":
            endian = "big" if self.__bigendian__ else "little"
            f.write("%s<Number name=\"%s_BOM\" size=\"16\" value=\"0xFEFF\" endian=\"%s\" minOccurs=\"1\" "
                    "maxOccurs=\"1\" />\n" % (identtabs, blockid, endian))
            return 2

        print("ERROR: Cannot generate BOM for this string %s" % (self.name()))
        return 0

    def peachout(self, f, indent, paramname, minnum, maxnum):
        identtabs = indent * "	"

        endian = "BE"
        if not self.__bigendian__:
            endian = "LE"

        t = self.__chartype__
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
            # its probably wrong. but we leave it
            pass

        if self.__termination__ == "ZERO":
            term = "nullTerminated=\"true\""
        else:
            print("WARNING: unknown termination for string: %s" % self.__termination__)
            term = ""

        blockid = "String_%s_%x" % (paramname, id(self))

        if self.__lengthOfLength__ != 0:
            f.write("%s<Number name=\"%s_Len\" size=\"%d\" endian=\"big\" minOccurs=\"1\" maxOccurs=\"1\" >\n" %
                    (identtabs, blockid, self.__lengthOfLength__))
            f.write("%s	<Relation type=\"size\" of=\"%s\" />\n" % (identtabs, blockid))
            f.write("%s</Number>\n" % identtabs)

        f.write("%s<Block name=\"%s\" minOccurs=\"1\" maxOccurs=\"1\" >\n" % (identtabs, blockid))

        if self.__lengthOfLength__ != 0:
            f.write("%s	<!-- String %s %s %s (%d..%d) len:%d pad:%d %s -->\n" %
                    (identtabs, self.__name__, self.__chartype__, endian, self.__lowerlimit__, self.__upperlimit__,
                     self.__lengthOfLength__, self.__padTo__, term))

            if self.__padTo__ != 0:
                print("ERROR: String %s has padto set to %d but we do not support!!" % (self.name(), self.__padTo__))
                f.write("%s<!-- Padto Parameter set to %d! -->" % (identtabs, self.__padTo__))

            bomlen = self.peachout_bom(f, indent + 1, blockid)

            lower = self.__lowerlimit__ - bomlen
            upper = self.__upperlimit__ - bomlen

            if lower < 0:
                lower = 0

            if upper < 1:
                print("ERROR: String %s does not have valid length." % (self.name()))
                f.write("%s	<!-- UPPER LIMIT INCORRECT!!! upper:%d after BOM correction %d -->\n" %
                        (identtabs, upper, bomlen))

            f.write("%s	<String name=\"%s_string\" type=\"%s\" %s minOccurs=\"1\" maxOccurs=\"1\" />\n" %
                    (identtabs, blockid, t, term))

        else:
            # fixed length string
            assert (self.__lowerlimit__ == self.__upperlimit__)
            bomlen = self.peachout_bom(f, indent + 1, blockid)

            lower = self.__lowerlimit__ - bomlen

            if lower < 1:
                print("ERROR: String %s does not have valid length." % (self.name()))

            f.write("%s	<String name=\"%s_string\" type=\"%s\" length=\"%d\" %s minOccurs=\"1\" maxOccurs=\"1\" />\n" %
                    (identtabs, blockid, t, lower, term))
        f.write("%s</Block>\n" % identtabs)


class SOMEIPParameterArray(SOMEIPBaseParameterArray):
    def peachout(self, f, indent, paramname, minnum, maxnum):
        counter = 0
        identtabs = indent * "	"

        if len(self.__dims__) != 1:
            f.write("%s<!--TODO: Multi-Dim Arrays-->\n" % identtabs)
        else:
            blockid = "Array%s%x%x" % (self.name(), id(self), counter)
            counter += 1

            # there is only one dim and this should have the key 1
            for i in self.__dims__.keys():
                dim = self.__dims__[i]
            min2 = dim.lowerlimit()
            max2 = dim.upperlimit()
            lengthOfLength = dim.length_of_length()

            if lengthOfLength != 0:
                f.write("%s<Number name=\"ArrayLen%s\" size=\"%d\" endian=\"big\" minOccurs=\"1\" maxOccurs=\"1\" >\n" %
                        (identtabs, blockid, dim.length_of_length()))
                f.write("%s	<Relation type=\"size\" of=\"%s\" />\n" % (identtabs, blockid))
                f.write("%s</Number>\n" % identtabs)

            f.write("%s<Block name=\"%s\" minOccurs=\"1\" maxOccurs=\"1\" >\n" % (identtabs, blockid))
            f.write("%s	<Block name=\"%s\" minOccurs=\"%d\" maxOccurs=\"%d\">\n" %
                    (identtabs, "Data" + blockid, min2, max2))
            self.child().peachout(f, indent + 2, paramname, 1, 1)
            f.write("%s	</Block>\n" % identtabs)
            f.write("%s</Block>\n" % identtabs)


class SOMEIPParameterStruct(SOMEIPBaseParameterStruct):
    def peachout(self, f, indent, paramname, minnum, maxnum):
        identtabs = indent * "	"
        blockid = "Struct%s%x" % (self.name(), id(self))

        if self.__lengthOfLength__ != 0:
            f.write("%s<Number name=\"StructLen%x\" size=\"%d\" mutable=\"false\" endian=\"big\" minOccurs=\"1\" "
                    "maxOccurs=\"1\" >\n" % (identtabs, id(self), self.__lengthOfLength__))
            f.write("%s	<Relation type=\"size\" of=\"%s\" />\n" % (identtabs, blockid))
            f.write("%s</Number>\n" % identtabs)

        f.write("%s<Block name=\"%s\" minOccurs=\"%d\" maxOccurs=\"%d\">\n" % (identtabs, blockid, minnum, maxnum))
        # f.write("%s<!-- Struct %s start -->\n" % (identtabs, self.__name__))
        for m in sorted(self.__members__.keys()):
            member = self.__members__[m]
            # print "struct-member: ", member
            child = member.child()
            # print "struct-member-child: ", child
            child.peachout(f, indent + 1, member.name(), 1, 1)
        f.write("%s</Block>\n" % identtabs)
        # f.write("%s<!-- Struct %s end -->\n" % (identtabs, self.__name__))


class SOMEIPParameterTypedef(SOMEIPBaseParameterTypedef):
    def peachout(self, f, indent, paramname, minnum, maxnum):
        if self.__child__ is not None:
            self.__child__.peachout(f, indent, paramname, minnum, maxnum)


class SOMEIPParameterEnumeration(SOMEIPBaseParameterEnumeration):
    def peachout(self, f, indent, paramname, minnum, maxnum):
        if self.__child__ is not None:
            self.__child__.peachout(f, indent, paramname, minnum, maxnum)


class SOMEIPParameterUnion(SOMEIPBaseParameterUnion):
    def peachout(self, f, indent, paramname, minnum, maxnum):
        identtabs = indent * "	"

        blockidchoice = "Union%s%x" % (self.name(), id(self))

        f.write(
            "%s<Choice name=\"%s\" minOccurs=\"%d\" maxOccurs=\"%d\">\n" % (identtabs, blockidchoice, minnum, maxnum))

        for m in self.__members__:
            member = self.__members__[m]
            blockid = "Union%s0x%xType0x%04x" % (self.name(), id(self), member.index())

            f.write("%s	<Block name=\"%sWrapper\" minOccurs=\"1\" maxOccurs=\"1\" >\n" % (identtabs, blockid))

            if self.__lengthOfLength__ != 0:
                f.write("%s		<Number name=\"UnionLen%s\" size=\"%d\" endian=\"big\" minOccurs=\"1\" "
                        "maxOccurs=\"1\" >\n" % (identtabs, blockid, self.__lengthOfLength__))
                f.write("%s			<Relation type=\"size\" of=\"%s\" />\n" % (identtabs, blockid))
                f.write("%s		</Number>\n" % identtabs)

            if self.__lengthOfType__ != 0:
                f.write("%s		<Number name=\"UnionType%s\" size=\"%d\" value=\"0x%04x\" endian=\"big\" "
                        "minOccurs=\"1\" maxOccurs=\"1\" />\n" %
                        (identtabs, blockid, self.__lengthOfType__, member.index()))
            else:
                print("ERROR: Union %s thinks that typefield can be 0 bytes long!!!!" % (self.name()))
                f.write("%s		<!-- TypeField with len:0!!! -->\n" % identtabs)
                return

            f.write("%s		<Block name=\"%s\" minOccurs=\"1\" maxOccurs=\"1\" >\n" % (identtabs, blockid))
            member.child().peachout(f, indent + 3, member.name(), 1, 1)
            f.write("%s		</Block>\n" % identtabs)

            f.write("	%s</Block>\n" % identtabs)

        f.write("%s</Choice>\n" % identtabs)


class SOMEIPParameterBitfield(SOMEIPBaseParameterBitfield):
    def peachout(self, f, indent, paramname, minnum, maxnum):
        if self.__child__ is not None:
            self.__child__.peachout(f, indent, paramname, minnum, maxnum)


def parse_arguments():
    parser = argparse.ArgumentParser(description='Converting configuration to peach xml.')
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

    print("Converting configuration to peach xml\n")
    args = parse_arguments()

    g_gen_portid = args.generate_switch_port_names

    ecu_name_mapping = {}
    if args.ecu_name_mapping is not None:
        ecu_name_mapping = read_csv_to_dict(args.ecu_name_mapping)

    conf_factory = PeachConfigurationFactory()
    output_dir = parse_input_files(args.filename, args.type, conf_factory, plugin_file=args.plugin,
                                   ecu_name_replacement=ecu_name_mapping)

    target_dir = os.path.join(output_dir, "peach")

    if not os.path.exists(target_dir):
        os.makedirs(target_dir)
        time.sleep(0.5)

    conf_factory.generate_configs(target_dir)

    print("Done.")


# only call main, if we are started directly
if __name__ == "__main__":
    main()
