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
import xml.etree.ElementTree
from abstract_parser import AbstractParser


class FibexParser(AbstractParser):
    def __init__(self):
        super().__init__()
        self.__conf_factory__ = None

        self.__ns__ = {'fx': 'http://www.asam.net/xml/fbx',
                       'ho': 'http://www.asam.net/xml',
                       'xsi': 'http://www.w3.org/2001/XMLSchema-instance',
                       'ethernet': 'http://www.asam.net/xml/fbx/ethernet',
                       'it': 'http://www.asam.net/xml/fbx/it',
                       'service': 'http://www.asam.net/xml/fbx/services'}

        self.__services__ = dict()
        self.__codings__ = dict()
        self.__signals__ = dict()
        self.__datatypes__ = dict()
        self.__channels__ = dict()
        self.__controllers__ = dict()
        self.__ecus__ = dict()
        self.__coupling_ports__ = dict()

        # FIBEX-ID -> (FIBEX-ID of Service, Eventgroup-ID)
        self.__eventgrouprefs__ = dict()

        # FIBEX-ID -> ServiceInstance
        self.__ServiceInstances__ = dict()

        # FIBEX-ID -> ServiceEventgroupReceiver
        self.__ServiceEventgroupReceiver__ = dict()

        # FIBEX-ID -> (PSIS[], CSIS[], EH[], CEGS[])
        self.__aeps__ = dict()

    def get_id(self, element):
        return self.get_attribute(element, 'ID')

    def get_oid(self, element):
        return self.get_attribute(element, 'ho:OID')

    def parse_utilization(self, element):
        ret = dict()

        if element is not None:
            coding = self.get_child_attribute(element, 'fx:UTILIZATION/fx:CODING-REF', 'ID-REF')
            ret["Coding"] = self.get_from_dict_or_none(self.__codings__, coding)

            high_low_byte_order = element.find('fx:UTILIZATION/fx:IS-HIGH-LOW-BYTE-ORDER', self.__ns__)
            if high_low_byte_order is not None:
                high_low_byte_order = ('true' == high_low_byte_order.text.lower())
            ret["HighLowByteOrder"] = high_low_byte_order

            ret["BitLength"] = self.element_text_to_int(element.find('fx:UTILIZATION/fx:BIT-LENGTH',
                                                                     self.__ns__), -1)
            ret["MinBitLength"] = self.element_text_to_int(element.find('fx:UTILIZATION/fx:MIN-BIT-LENGTH',
                                                                        self.__ns__), -1)
            ret["MaxBitLength"] = self.element_text_to_int(element.find('fx:UTILIZATION/fx:MAX-BIT-LENGTH',
                                                                        self.__ns__), -1)

        return ret

    def merge_utilizations(self, util1, util2):
        ret = dict()

        # copy over util2s
        for key in util2:
            ret[key] = util2[key]

        # override, if values are more specific (not default)!
        if "BitLength" in util1 and util1["BitLength"] != -1:
            ret["BitLength"] = util1["BitLength"]
        if "MinBitLength" in util1 and util1["MinBitLength"] != -1:
            ret["MinBitLength"] = util1["MinBitLength"]
        if "MaxBitLength" in util1 and util1["MaxBitLength"] != -1:
            ret["MaxBitLength"] = util1["MaxBitLength"]

        if "Coding" in util1 and util1["Coding"] is not None and \
                "Coding" in util2 and util2["Coding"] is not None:
            ret["Coding"] = self.merge_utilizations(util1["Coding"], util2["Coding"])

        return ret

    def parse_serialization_attributes(self, element):
        ret = dict()

        if element is not None:
            ret["ArrayLengthSize"] = self.element_text_to_int(element.find(
                './fx:UTILIZATION/fx:SERIALIZATION-ATTRIBUTES/fx:ARRAY-LENGTH-FIELD-SIZE', self.__ns__), -1)
            ret["LengthFieldSize"] = self.element_text_to_int(element.find(
                './fx:UTILIZATION/fx:SERIALIZATION-ATTRIBUTES/fx:LENGTH-FIELD-SIZE', self.__ns__), -1)
            ret["TypeFieldSize"] = self.element_text_to_int(element.find(
                './fx:UTILIZATION/fx:SERIALIZATION-ATTRIBUTES/fx:TYPE-FIELD-SIZE', self.__ns__), 32)
            ret["BitAlignment"] = self.element_text_to_int(element.find(
                './fx:UTILIZATION/fx:SERIALIZATION-ATTRIBUTES/fx:BIT-ALIGNMENT', self.__ns__), 0)

        return ret

    def parse_coding(self, element):
        id = self.get_id(element)
        oid = self.get_oid(element)
        name = self.get_child_text(element, './ho:SHORT-NAME')

        coded_basetype = None
        coded_category = None
        coded_encoding = None
        coded_termination = None
        coded_bit_length = -1
        coded_min_length = -1
        coded_max_length = -1

        compu_scale = None

        ct = element.find('./ho:CODED-TYPE', self.__ns__)
        if ct is not None:
            coded_basetype = self.get_attribute(ct, 'ho:BASE-DATA-TYPE')
            coded_category = self.get_attribute(ct, 'CATEGORY')
            coded_encoding = self.get_attribute(ct, 'ENCODING')
            coded_termination = self.get_attribute(ct, 'TERMINATION')
            bl = ct.find('./ho:BIT-LENGTH', self.__ns__)
            if bl is not None and bl.text is not None:
                coded_bit_length = int(bl.text)
            bl = ct.find('./ho:MIN-LENGTH', self.__ns__)
            if bl is not None and bl.text is not None:
                coded_min_length = int(bl.text)
            bl = ct.find('./ho:MAX-LENGTH', self.__ns__)
            if bl is not None and bl.text is not None:
                coded_max_length = int(bl.text)

        cs = element.find('./ho:COMPU-METHODS/ho:COMPU-METHOD/ho:COMPU-INTERNAL-TO-PHYS/ho:COMPU-SCALES/ho:COMPU-SCALE/'
                          'ho:COMPU-RATIONAL-COEFFS', self.__ns__)
        if cs is not None:
            compu_scale = []
            for num in cs.findall('./ho:COMPU-NUMERATOR/ho:V', self.__ns__):
                compu_scale.append(float(num.text))
            if len(compu_scale) != 2:
                print(f"WARNING: We did not find to nums in the compu-numerator but {len(compu_scale)}!")
            num = cs.find('./ho:COMPU-DENOMINATOR/ho:V', self.__ns__)
            if num is not None:
                compu_scale.append(float(num.text))
            else:
                compu_scale.append(None)

        compu_consts = []
        for cs in element.findall('./ho:COMPU-METHODS/ho:COMPU-METHOD/ho:COMPU-INTERNAL-TO-PHYS/ho:COMPU-SCALES/',
                                  self.__ns__):

            cc = cs.find('./ho:COMPU-CONST/ho:VT', self.__ns__)

            if cc is not None:
                compu_const = (cc.text,
                               self.get_child_text(cs, "ho:LOWER-LIMIT"),
                               self.get_child_text(cs, "ho:UPPER-LIMIT"))
                compu_consts.append(compu_const)

        if id is None:
            print(f"ERROR: Coding does not have ID!\n{element.text}")

        d = {'ID': id,
             'OID': oid,
             'Name': name,
             'Basetype': coded_basetype,
             'Category': coded_category,
             'Encoding': coded_encoding,
             'Termination': coded_termination,
             'BitLength': coded_bit_length,
             'MinLength': coded_min_length,
             'MaxLength': coded_max_length,
             'CompuScale': compu_scale,
             'CompuConsts': compu_consts}
        return d

    def parse_codings(self, root):
        for coding in root.findall('.//fx:CODINGS/fx:CODING', self.__ns__):
            d = self.parse_coding(coding)
            if d is not None and 'ID' in d:
                self.__codings__[d['ID']] = d

    def parse_signal(self, element):
        id = self.get_id(element)
        oid = self.get_oid(element)
        name = self.get_child_text(element, './ho:SHORT-NAME')
        code_id = self.get_child_attribute(element, './fx:CODING-REF', 'ID-REF')
        coding = self.get_from_dict_or_none(self.__codings__, code_id)
        if coding is None:
            print(f"Warning: Signal Coding == None!")
        compu_scale = self.get_from_dict_or_none(coding, 'CompuScale')
        compu_consts = self.get_from_dict_or_none(coding, 'CompuConsts')
        ret = self.__conf_factory__.create_legacy_signal(id, name, compu_scale, compu_consts)

        return ret

    def parse_signals(self, root):
        for signal in root.findall('.//fx:SIGNALS/fx:SIGNAL', self.__ns__):
            s = self.parse_signal(signal)
            if s is not None:
                self.__signals__[s.id()] = s

    def interpret_datatype(self, element, utils, serialization_attributes):
        ret = None
        p = dict()

        p["ID"] = self.get_id(element)
        p["OID"] = self.get_oid(element)
        p["Name"] = self.get_child_text(element, './ho:SHORT-NAME')
        p["Type"] = self.get_attribute(element, 'xsi:type')

        if p["ID"] is None or p["Type"] is None:
            print("ERROR: Datatype should have ID and Type!!!")
            return None

        # coding1 = self.get_from_dict_or_none(utils, "Coding")
        coding2 = None
        coding_ref = element.find('fx:CODING-REF', self.__ns__)
        if coding_ref is not None:
            coding2 = self.__codings__[self.get_attribute(coding_ref, 'ID-REF')]

        if p["Type"] == "fx:COMMON-DATATYPE-TYPE" or p["Type"] == "fx:ENUM-DATATYPE-TYPE":

            t_ints = ['A_UINT8', 'A_INT8', 'A_UINT16', 'A_INT16', 'A_UINT32', 'A_INT32', 'A_UINT64', 'A_INT64']
            t_floats = ['A_FLOAT32', 'A_FLOAT64']
            t_strings = ['A_ASCIISTRING', 'A_UNICODE2STRING']
            # t_other = ['A_BYTEFIELD', 'A_BITFIELD', 'OTHER']

            basetype = self.get_from_dict(coding2, "Basetype", "--INVALID--")
            if basetype in (t_ints + t_floats):
                bitlenbase = self.get_from_dict(coding2, "BitLength", -1)
                bitlenenct = self.get_from_dict(utils, "BitLength", -1)
                if bitlenenct == -1:
                    bitlenenct = bitlenbase

                if p["Type"] == "fx:COMMON-DATATYPE-TYPE":
                    ret = self.__conf_factory__.create_someip_parameter_basetype(
                        self.get_from_dict_or_none(p, "Name"),
                        self.get_from_dict_or_none(coding2, "Basetype"),
                        self.get_from_dict_or_none(utils, "HighLowByteOrder"),
                        bitlenbase,
                        bitlenenct
                    )

                elif p["Type"] == "fx:ENUM-DATATYPE-TYPE":
                    ret = self.__conf_factory__.create_someip_parameter_basetype(
                        self.get_from_dict_or_none(coding2, "Name"),
                        self.get_from_dict_or_none(coding2, "Basetype"),
                        self.get_from_dict_or_none(utils, "HighLowByteOrder"),
                        bitlenbase,
                        bitlenenct
                    )

            elif basetype in t_strings:
                bitlen = self.get_from_dict(utils, "BitLength", -1)
                minlen = self.get_from_dict(utils, "MinBitLength", -1)
                maxlen = self.get_from_dict(utils, "MaxBitLength", -1)

                # this basically gives us the smallest char
                if minlen == -1:
                    minlen = self.get_from_dict(coding2, "MinLength", -1)

                # this should never yield more than -1
                if maxlen == -1:
                    maxlen = self.get_from_dict(coding2, "MaxLength", -1)
                    if maxlen != -1:
                        print("WARNING: FIBEX seems strange. I found a MaxLength in Coding!")

                if minlen != -1:
                    minlen = minlen / 8

                if maxlen != -1:
                    maxlen = maxlen / 8

                cat = self.get_from_dict(coding2, "Category", None)
                enc = self.get_from_dict(coding2, "Encoding", None)
                term = self.get_from_dict(coding2, "Termination", None)

                if cat == "A_ASCIISTRING" and enc is None:
                    enc = "ASCII"
                if enc == "UCS-2":
                    enc = "UTF-16"

                if bitlen != -1:
                    lenoflen = 0
                    minlen = bitlen / 8
                    maxlen = bitlen / 8
                else:
                    lenoflen = 32

                if cat == "LEADING-LENGTH-INFO-TYPE":
                    lenoflen = self.get_from_dict(serialization_attributes, "LengthFieldSize", 32)

                pad_to = 0
                ret = self.__conf_factory__.create_someip_parameter_string(
                    self.get_from_dict_or_none(p, "Name"),
                    enc,
                    self.get_from_dict_or_none(utils, "HighLowByteOrder"),
                    minlen,
                    maxlen,
                    term,
                    lenoflen,
                    pad_to
                )

            if p["Type"] == "fx:ENUM-DATATYPE-TYPE":

                items = {}

                for i in element.findall('./fx:ENUMERATION-ELEMENTS/fx:ENUM-ELEMENT', self.__ns__):
                    value = self.get_child_text(i, "fx:VALUE")
                    name = self.get_child_text(i, "fx:SYNONYM")
                    desc = self.get_child_text(i, "ho:DESC")
                    items[value] = self.__conf_factory__.create_someip_parameter_enumeration_item(value, name, desc)

                enumitems = self.dict_to_sorted_set(items)

                ret = self.__conf_factory__.create_someip_parameter_enumeration(
                    self.get_from_dict_or_none(p, "Name"),
                    enumitems,
                    ret
                )

        if p["Type"] == "fx:COMPLEX-DATATYPE-TYPE":
            p["ComplexClass"] = self.get_child_text(element, 'fx:COMPLEX-DATATYPE-CLASS')

            members = dict()

            for member in element.findall('fx:MEMBERS/fx:MEMBER', self.__ns__):
                (pos, m) = self.parse_member(member, p["ComplexClass"])
                members[pos] = m

            p["Members"] = self.dict_to_sorted_set(members)

            if "Members" in p:
                if self.get_from_dict_or_none(p, "ComplexClass") == "STRUCTURE":
                    members = dict()
                    for m in p["Members"]:

                        child = self.interpret_datatype(
                            self.get_from_dict_or_none(self.__datatypes__,
                                                       self.get_from_dict_or_none(m, "DatatypeRef")),
                            self.get_from_dict_or_none(m, "Utilization"),
                            self.get_from_dict_or_none(m, "SerializationAttributes")
                        )

                        if "Array" in m and m["Array"] is not None:
                            child = self.build_array(
                                m["Name"],
                                self.get_from_dict(serialization_attributes, "ArrayLengthSize", -1),
                                m["Array"],
                                child
                            )

                        signal = self.get_from_dict_or_none(self.__signals__,
                                                            self.get_from_dict_or_none(m, "SignalRef"))

                        member = self.__conf_factory__.create_someip_parameter_struct_member(
                            m["Position"],
                            m["Name"],
                            m["Mandatory"],
                            child,
                            signal
                        )
                        members[m["Position"]] = member
                    len_of_len = self.get_from_dict(serialization_attributes, "LengthFieldSize", 0)
                    padto = 0
                    ret = self.__conf_factory__.create_someip_parameter_struct(p["Name"], len_of_len, padto, members)

                elif self.get_from_dict_or_none(p, "ComplexClass") == "UNION":

                    members = dict()
                    for m in p["Members"]:
                        child = self.interpret_datatype(
                            self.get_from_dict_or_none(self.__datatypes__,
                                                       self.get_from_dict_or_none(m, "DatatypeRef")),
                            self.get_from_dict_or_none(m, "Utilization"),
                            self.get_from_dict_or_none(m, "SerializationAttributes")
                        )

                        if "Array" in m and m["Array"] is not None:
                            child = self.build_array(
                                m["Name"],
                                self.get_from_dict(serialization_attributes, "ArrayLengthSize", -1),
                                m["Array"],
                                child
                            )

                        member = self.__conf_factory__.create_someip_parameter_union_member(
                            m["Index"],
                            m["Name"],
                            m["Mandatory"],
                            child
                        )

                        members[m["Index"]] = member

                    len_of_len = self.get_from_dict(serialization_attributes, "LengthFieldSize", 32)
                    len_of_type = self.get_from_dict(serialization_attributes, "TypeFieldSize", 32)
                    padto = 0
                    ret = self.__conf_factory__.create_someip_parameter_union(
                        p["Name"],
                        len_of_len,
                        len_of_type,
                        padto,
                        members
                    )

                elif self.get_from_dict_or_none(p, "ComplexClass") == "TYPEDEF":
                    child = None
                    childname = None
                    for m in p["Members"]:

                        if "Position" in m and m["Position"] == 0:

                            child = self.interpret_datatype(
                                self.get_from_dict_or_none(self.__datatypes__,
                                                           self.get_from_dict_or_none(m, "DatatypeRef")),
                                self.merge_utilizations(utils, self.get_from_dict_or_none(m, "Utilization")),
                                self.get_from_dict_or_none(m, "SerializationAttributes")
                            )

                            childname = self.get_from_dict(m, "Name", "")

                            if "Array" in m and m["Array"] is not None:
                                child = self.build_array(
                                    m["Name"],
                                    self.get_from_dict(serialization_attributes, "ArrayLengthSize", -1),
                                    m["Array"],
                                    child
                                )

                        ret = self.__conf_factory__.create_someip_parameter_typedef(p["Name"], childname, child)

            else:
                print(f"ERROR: ComplexClass: %s Members: %d is not understood" %
                      (self.get_from_dict_or_none(p, "ComplexClass"), len(p))
                      )

        if ret is None:
            print("WARNING: interpretDatatype(%s, %s, %s, %s, %s, %s) returns None!!!!!!!" %
                  (element, utils, serialization_attributes, p["ID"], p["Name"], p["Type"])
                  )

        return ret

    def parse_datatypes(self, root):
        self.__datatypes__ = dict()

        for datatype in root.findall('.//fx:DATATYPES/fx:DATATYPE', self.__ns__):
            did = self.get_id(datatype)
            if did is not None:
                self.__datatypes__[did] = datatype

    def parse_array(self, element):
        ret = None

        for dimension in element.findall('./fx:ARRAY-DECLARATION/fx:ARRAY-DIMENSION', self.__ns__):
            if ret is None:
                ret = dict()
            minsize = self.element_text_to_int(dimension.find('fx:MINIMUM-SIZE', self.__ns__), 0)
            maxsize = self.element_text_to_int(dimension.find('fx:MAXIMUM-SIZE', self.__ns__), -1)
            dim = self.element_text_to_int(dimension.find('fx:DIMENSION', self.__ns__), -1)
            bit = self.element_text_to_int(dimension.find('fx:BIT-ALIGNMENT', self.__ns__), 0)

            if dim > 0:
                ret[dim] = {'dim': dim, 'max': maxsize, 'min': minsize, 'bitalignment': bit}
            else:
                print(f"ERROR: dim {dim} is less than 1!")

        return ret

    def build_array(self, name, lengthoflength, arrayspec, child):
        dims = dict()
        for a in sorted(arrayspec.keys()):
            arraydim = arrayspec[a]
            dim = self.get_from_dict_or_none(arraydim, "dim")

            d = self.__conf_factory__.create_someip_parameter_array_dim(dim,
                                                                        self.get_from_dict(arraydim, "min", 0),
                                                                        self.get_from_dict(arraydim, "max", -1),
                                                                        lengthoflength,
                                                                        self.get_from_dict(arraydim, "bitalignment", 0)
                                                                        )
            dims[dim] = d

        return self.__conf_factory__.create_someip_parameter_array(name, dims, child)

    def parse_parameter(self, param):

        p = dict()
        p["ID"] = self.get_id(param)
        p["OID"] = self.get_oid(param)
        p["Name"] = self.get_child_text(param, './ho:SHORT-NAME')
        p["Desc"] = self.element_text(param.find('./ho:DESC', self.__ns__))
        p["Mandatory"] = self.element_text(param.find('./service:MANDATORY', self.__ns__))
        p["Position"] = self.element_text(param.find('./service:POSITION', self.__ns__))
        if p["Position"] is not None:
            p["Position"] = int(p["Position"])

        dt = self.get_child_attribute(param, './fx:DATATYPE-REF', 'ID-REF')
        p["Datatype"] = self.get_from_dict_or_none(self.__datatypes__, dt)
        if p["Datatype"] is None:
            print("ERROR: Parameter without datatype is kind of strange!!!")

        s = self.get_child_attribute(param, './fx:SIGNAL-REF', 'ID-REF')
        signal = None
        if s is not None:
            signal = self.get_from_dict_or_none(self.__signals__, s)

        p["Array"] = self.parse_array(param)
        utils = self.parse_utilization(param)
        serialization_attributes = self.parse_serialization_attributes(param)

        dt = self.get_from_dict_or_none(p, "Datatype")

        ret = self.interpret_datatype(dt, utils, serialization_attributes)

        if "Array" in p and p["Array"] is not None:
            ret = self.build_array(p["Name"], serialization_attributes["ArrayLengthSize"], p["Array"], ret)

        return p["Position"], self.__conf_factory__.create_someip_parameter(p["Position"], p["Name"], p["Desc"],
                                                                            p["Mandatory"], ret, signal), p

    def parse_method(self, element):
        id = self.get_id(element)
        name = self.get_child_text(element, './ho:SHORT-NAME')
        method_id = int(self.get_child_text(element, './service:METHOD-IDENTIFIER'))

        reliable = ("true" == self.get_child_text(element, './service:RELIABLE'))
        call_type = self.get_child_text(element, './service:CALL-SEMANTIC')
        if call_type is None:
            call_type = "REQUEST_RESPONSE"

        inparams = dict()
        for param in element.findall('./service:INPUT-PARAMETERS/service:INPUT-PARAMETER', self.__ns__):
            (pos, p) = self.parse_parameter(param)[:2]
            inparams[pos] = p

        outparams = dict()
        for param in element.findall('./service:RETURN-PARAMETERS/service:RETURN-PARAMETER', self.__ns__):
            (pos, p) = self.parse_parameter(param)[:2]
            outparams[pos] = p

        debouncereq = -1
        retentionreq = -1
        retentionres = -1

        m = self.__conf_factory__.create_someip_service_method(
            name,
            method_id,
            call_type,
            reliable,
            sorted(inparams.values(), key=lambda x: x.position()),
            sorted(outparams.values(), key=lambda x: x.position()),
            debouncereq,
            retentionreq,
            retentionres
        )
        return id, m

    def parse_event(self, element):
        id = self.get_id(element)
        name = self.get_child_text(element, './ho:SHORT-NAME')
        method_id = int(self.get_child_text(element, './service:METHOD-IDENTIFIER'))

        reliable = ("true" == self.get_child_text(element, './service:RELIABLE'))

        debounce = -1
        retention = -1

        params = dict()
        for param in element.findall('./service:INPUT-PARAMETERS/service:INPUT-PARAMETER', self.__ns__):
            (pos, p) = self.parse_parameter(param)[:2]
            params[pos] = p

        m = self.__conf_factory__.create_someip_service_event(
            name,
            method_id,
            reliable,
            sorted(params.values(), key=lambda x: x.position()),
            debounce,
            retention
        )
        return id, m

    def parse_field(self, element):
        id = self.get_id(element)
        name = self.get_child_text(element, './ho:SHORT-NAME')

        getter_id = (self.get_child_text(element, './service:GETTER/service:METHOD-IDENTIFIER'))
        setter_id = (self.get_child_text(element, './service:SETTER/service:METHOD-IDENTIFIER'))
        notifier_id = (self.get_child_text(element, './service:NOTIFIER/service:NOTIFICATION-IDENTIFIER'))

        if getter_id is not None:
            getter_id = int(getter_id)
        if setter_id is not None:
            setter_id = int(setter_id)
        if notifier_id is not None:
            notifier_id = int(notifier_id)

        getter_reli = ("true" == self.get_child_text(element, './service:GETTER/service:RELIABLE'))
        setter_reli = ("true" == self.get_child_text(element, './service:SETTER/service:RELIABLE'))
        notifier_reli = ("true" == self.get_child_text(element, './service:NOTIFIER/service:RELIABLE'))

        dt = self.get_child_attribute(element, './fx:DATATYPE-REF', 'ID-REF')
        if dt is None:
            print(f"ERROR: We are missing a datatype for {element}")
            return None

        datatype = self.get_from_dict_or_none(self.__datatypes__, dt)
        if datatype is None:
            print(f"ERROR: Unknown Datatype: {dt}")
            return None

        signal = None
        s = self.get_child_attribute(element, './fx:SIGNAL-REF', 'ID-REF')
        if s is not None:
            signal = self.get_from_dict_or_none(self.__signals__, s)
            if signal is None:
                print(f"ERROR: Unknown Signal: {s}")
                return None

        utils = self.parse_utilization(element)
        serialization_attributes = self.parse_serialization_attributes(element)

        params = []
        child = self.interpret_datatype(datatype, utils, serialization_attributes)
        params += [self.__conf_factory__.create_someip_parameter(0, 'fieldparam', '', True, child, signal)]

        getter_debouncereq = -1
        getter_retentionreq = -1
        getter_retentionres = -1
        setter_debouncereq = -1
        setter_retentionreq = -1
        setter_retentionres = -1
        notifier_debounce = -1
        notifier_retention = -1

        f = self.__conf_factory__.create_someip_service_field(
            name, getter_id, setter_id, notifier_id,
            getter_reli, setter_reli, notifier_reli, params,
            getter_debouncereq, getter_retentionreq, getter_retentionres,
            setter_debouncereq, setter_retentionreq, setter_retentionres,
            notifier_debounce, notifier_retention
        )
        return id, f

    def parse_eventgroup(self, element, serviceid, events, fields):
        id = self.get_id(element)
        name = self.get_child_text(element, './ho:SHORT-NAME')
        egid = self.get_child_text(element, './fx:SERVICE-IDENTIFIER')
        eventids = []
        notifierids = []

        for eventref in element.findall('./service:EVENT-REFS/service:EVENT-REF', self.__ns__):
            ref = self.get_attribute(eventref, 'ID-REF')
            if events is not None and ref in events:
                eventids += [events[ref]]
            else:
                print(f"ERROR: Eventgroup {id} has EVENT-REF to {ref} but I cannot find the Event!")

        for fieldref in element.findall('./service:FIELD-REFS/service:FIELD-REF', self.__ns__):
            ref = self.get_attribute(fieldref, 'ID-REF')
            if fields is not None and ref in fields:
                notifierids += [fields[ref]]
            else:
                print("ERROR: Eventgroup %s has FIELD-REF to %s but I cannot find the Field!" % (id, ref))

        self.__eventgrouprefs__[id] = (serviceid, egid)
        return id, self.__conf_factory__.create_someip_service_eventgroup(name, egid, eventids, notifierids)

    def parse_service(self, service):
        id = None
        sid = self.get_id(service)
        name = self.get_child_text(service, './ho:SHORT-NAME')
        service_id = int(self.get_child_text(service, './fx:SERVICE-IDENTIFIER'))
        major_version = int(self.get_child_text(service, './service:API-VERSION/service:MAJOR'))
        minor_version = int(self.get_child_text(service, './service:API-VERSION/service:MINOR'))

        methods = dict()
        for method in service.findall('./service:METHODS/service:METHOD', self.__ns__):
            id, m = self.parse_method(method)
            methods[m.methodid()] = m

        eventids = dict()
        events = dict()
        for event in service.findall('./service:EVENTS/service:EVENT', self.__ns__):
            id, e = self.parse_event(event)
            events[e.methodid()] = e
            eventids[id] = e.methodid()

        fieldids = dict()
        fields = dict()
        for field in service.findall('./service:FIELDS/service:FIELD', self.__ns__):
            id, f = self.parse_field(field)
            fields[f.id()] = f
            fieldids[id] = f.notifierid()

        eventgroups = dict()
        for eg in service.findall('./service:EVENT-GROUPS/service:EVENT-GROUP', self.__ns__):
            id, eg = self.parse_eventgroup(eg, id, eventids, fieldids)
            eventgroups[eg.id()] = eg

        s = self.__conf_factory__.create_someip_service(name, service_id, major_version, minor_version, methods, events,
                                                        fields, eventgroups)
        return sid, s

    def parse_member(self, element, t):
        p = dict()

        p["ID"] = self.get_id(element)
        p["OID"] = self.get_oid(element)
        p["Name"] = self.get_child_text(element, './ho:SHORT-NAME')

        p["DatatypeRef"] = self.get_child_attribute(element, 'fx:DATATYPE-REF', 'ID-REF')
        p["SignalRef"] = self.get_child_attribute(element, 'fx:SIGNAL-REF', 'ID-REF')

        p["Index"] = self.element_text_to_int(element.find('fx:INDEX', self.__ns__), -1)

        position = element.find('fx:POSITION', self.__ns__)
        if position is not None:
            position = int(position.text)
        p["Position"] = position

        mandatory = element.find('fx:MANDATORY', self.__ns__)
        if mandatory is not None:
            mandatory = "true" == mandatory.text or "True" == mandatory.text or "TRUE" == mandatory.text
        p["Mandatory"] = mandatory

        p["Utilization"] = self.parse_utilization(element)
        p["SerializationAttributes"] = self.parse_serialization_attributes(element)
        p["Array"] = self.parse_array(element)

        pos = -1
        if t == "STRUCTURE" or t == "TYPEDEF":
            pos = p["Position"]
        elif t == "UNION":
            pos = p["Index"]

        return pos, p

    def parse_services(self, root):
        self.__services__ = dict()

        for service in root.findall('.//fx:SERVICE-INTERFACE', self.__ns__):
            id, s = self.parse_service(service)
            self.__services__[id] = s

    def parse_channels(self, root):
        for ch in root.findall('.//fx:CHANNELS/fx:CHANNEL', self.__ns__):
            channel = dict()
            channel["id"] = self.get_id(ch)
            channel["name"] = self.get_child_text(ch, "ho:SHORT-NAME")

            channel["vlanid"] = None
            channel["vlanname"] = None

            for v in ch.findall('ethernet:VIRTUAL-LAN', self.__ns__):
                # = self.ID(v)
                if channel["vlanid"] is not None:
                    print("WARNING: We have found a channel with more than 1 VLAN. We are skipping those.")
                else:
                    channel["vlanid"] = self.get_child_text(v, "ethernet:VLAN-IDENTIFIER")
                    channel["vlanname"] = self.get_child_text(v, "ho:SHORT-NAME")

            self.__channels__[channel["id"]] = channel

    def parse_neps(self, element):
        neps = dict()
        for n in element.findall('it:NETWORK-ENDPOINTS/it:NETWORK-ENDPOINT', self.__ns__):
            nep = dict()
            nep["id"] = self.get_id(n)
            nep["name"] = self.get_child_text(n, "it:MANUFACTURER-EXTENSION/ho:SHORT-NAME")

            ipsv4 = []
            for i in n.findall('it:NETWORK-ENDPOINT-ADDRESSES/it:NETWORK-ENDPOINT-ADDRESS/it:IPV4', self.__ns__):
                ip = dict()
                ip["addr"] = self.get_child_text(i, "it:IP-ADDRESS")
                ip["addrsrc"] = self.get_child_text(i, "it:IPV4-ADDRESS-SOURCE")
                ip["netmask"] = self.get_child_text(i, "it:NETWORKMASK")
                ipsv4 += [ip]
            nep["ipsv4"] = ipsv4

            ipsv6 = []
            for i in n.findall('it:NETWORK-ENDPOINT-ADDRESSES/it:NETWORK-ENDPOINT-ADDRESS/it:IPV6', self.__ns__):
                ip = dict()
                ip["addr"] = self.get_child_text(i, "it:IPV6-ADDRESS")
                ip["addrsrc"] = self.get_child_text(i, "it:IPV6-ADDRESS-SOURCE")
                ip["netmask"] = self.get_child_text(i, "it:IPV6-ADDRESS-PREFIX-LENGTH")
                ipsv6 += [ip]
            nep["ipsv6"] = ipsv6

            neps[nep["id"]] = nep

        return neps

    def parse_psis(self, root):
        for aep in root.findall('.//it:APPLICATION-ENDPOINT', self.__ns__):
            protover = self.get_child_text(aep, 'it:SERIALIZATION-TECHNOLOGY/it:VERSION')
            if protover is None:
                protover = 1

            aepid = self.get_id(aep)
            for psi in aep.findall('it:PROVIDED-SERVICE-INSTANCES/it:PROVIDED-SERVICE-INSTANCE', self.__ns__):
                id = self.get_id(psi)
                instanceid = self.get_child_text(psi, 'it:INSTANCE-IDENTIFIER')
                servref = self.get_child_attribute(psi, 'service:SERVICE-INTERFACE-REF', 'ID-REF')
                if servref not in self.__services__:
                    print(f"ERROR in FIBEX: I cannot find Service {servref}")
                else:
                    service = self.__services__[servref]

                    si = self.__conf_factory__.create_someip_service_instance(service, instanceid, protover)
                    self.__ServiceInstances__[id] = si

                    if aepid not in self.__aeps__:
                        self.__aeps__[aepid] = ([], [], [], [])

                    psis, csis, ehs, cegs = self.__aeps__[aepid]
                    self.__aeps__[aepid] = (psis + [si], csis, ehs, cegs)

    def parse_psis_pass_two(self, root):
        for aep in root.findall('.//it:APPLICATION-ENDPOINT', self.__ns__):
            # protover = self.get_child_text(aep, 'it:SERIALIZATION-TECHNOLOGY/it:VERSION')
            # if protover is None:
            #    protover = 1

            aepid = self.get_id(aep)
            for cegrefs in aep.findall(
                    'it:PROVIDED-SERVICE-INSTANCES/it:PROVIDED-SERVICE-INSTANCE/' +
                    'it:EVENT-HANDLERS/it:EVENT-HANDLER/it:CONSUMED-EVENT-GROUP-REFS',
                    self.__ns__
            ):

                eh = None
                ref = None
                for cegref in cegrefs.findall('it:CONSUMED-EVENT-GROUP-REF', self.__ns__):
                    ref = self.get_attribute(cegref, 'ID-REF')

                if ref not in self.__ServiceEventgroupReceiver__:
                    print(f"ERROR in FIBEX: I cannot find the CEGREF {ref}!")
                else:
                    egreceiver = self.__ServiceEventgroupReceiver__[ref]

                    if eh is None:
                        eh = self.__conf_factory__.create_someip_service_eventgroup_sender(egreceiver.serviceinstance(),
                                                                                           egreceiver.eventgroupid())
                        eh.addreceiver(egreceiver)

                    if aepid not in self.__aeps__:
                        self.__aeps__[aepid] = ([], [], [], [])

                    psis, csis, ehs, cegs = self.__aeps__[aepid]
                    self.__aeps__[aepid] = (psis, csis, ehs + [eh], cegs)

    def parse_csis_and_cegs(self, root):
        for aep in root.findall('.//it:APPLICATION-ENDPOINT', self.__ns__):

            aepid = self.get_id(aep)
            for csi in aep.findall('it:CONSUMED-SERVICE-INSTANCES/it:CONSUMED-SERVICE-INSTANCE', self.__ns__):
                psiid = self.get_child_attribute(csi, 'it:PROVIDED-SERVICE-INSTANCE-REF', 'ID-REF')

                if psiid in self.__ServiceInstances__:
                    si = self.__ServiceInstances__[psiid]

                    tmp = self.__conf_factory__.create_someip_service_instance_client(si.service(), si.instanceid(),
                                                                                      si.protover(), si)

                    if aepid not in self.__aeps__:
                        self.__aeps__[aepid] = ([], [], [], [])

                    psis, csis, ehs, cegs = self.__aeps__[aepid]
                    self.__aeps__[aepid] = (psis, csis + [tmp], ehs, cegs)

                    for ceg in csi.findall('it:CONSUMED-EVENT-GROUPS/it:CONSUMED-EVENT-GROUP', self.__ns__):
                        cegid = self.get_id(ceg)
                        egref = self.get_child_attribute(ceg, 'service:EVENT-GROUP-REF', 'ID-REF')
                        aepref = self.get_child_attribute(ceg, 'it:APPLICATION-ENDPOINT-REF', 'ID-REF')

                        if egref not in self.__eventgrouprefs__:
                            print(f"ERROR in FIBEX: I cannot find Eventgroup {egref}!")

                        else:
                            egid = self.__eventgrouprefs__[egref][1]
                            tmp = self.__conf_factory__.create_someip_service_eventgroup_receiver(si, egid, None)

                            if cegid not in self.__ServiceEventgroupReceiver__.keys():
                                self.__ServiceEventgroupReceiver__[cegid] = tmp
                            else:
                                print(f"ERROR in FIBEX: The CEG ID seems to be not unique {egid}!")

                            if aepref not in self.__aeps__:
                                self.__aeps__[aepref] = ([], [], [], [])

                            psis, csis, ehs, cegs = self.__aeps__[aepref]
                            self.__aeps__[aepref] = (psis, csis, ehs, cegs + [tmp])

                else:
                    print(f"ERROR in FIBEX: Cannot find PSI {psiid}")

    @staticmethod
    def lookup_dyn_port(name):
        # we could add code here to determine real port based on name
        return -1

    def parse_ecus(self, root):
        self.parse_psis(root)
        self.parse_csis_and_cegs(root)
        self.parse_psis_pass_two(root)

        for e in root.findall('.//fx:ECUS/fx:ECU', self.__ns__):
            ecu_name = self.get_child_text(e, "ho:SHORT-NAME")
            ecu_id = self.get_attribute(e, "ID")

            ctrls = dict()
            for c in e.findall('fx:CONTROLLERS/fx:CONTROLLER', self.__ns__):
                ctrl = dict()
                ctrl["id"] = self.get_id(c)
                ctrl["name"] = self.get_child_text(c, "ho:SHORT-NAME")
                ctrl["conns"] = []
                ctrl["ifaces"] = []
                ctrls[ctrl["id"]] = ctrl

            for c in e.findall('fx:CONNECTORS/fx:CONNECTOR', self.__ns__):
                channelref = self.get_child_attribute(c, 'fx:CHANNEL-REF', 'ID-REF')
                ctrlref = self.get_child_attribute(c, 'fx:CONTROLLER-REF', 'ID-REF')

                ctrl = None
                if ctrlref in ctrls:
                    ctrl = ctrls[ctrlref]
                else:
                    print(f"FIBEX WARNING: I cannot find controller with ref {ctrlref} "
                          f"for connector {self.get_id(c)}! Creating dummy myself!")

                    # creating dummy controller since we need to link ECU and Interface
                    ctrl = dict()
                    ctrl["id"] = self.get_id(c)
                    ctrl["name"] = self.get_id(c)
                    ctrl["conns"] = []
                    ctrl["ifaces"] = []
                    ctrls[ctrl["id"]] = ctrl

                if channelref in self.__channels__:
                    channel = self.__channels__[channelref]
                else:
                    channel = None
                    print(f"ERROR in FIBEX: I cannot find channel {channelref}")

                interface_ips = []
                sockets = []
                neps = self.parse_neps(c)

                for nepref, nep in neps.items():
                    ips = []
                    if "ipsv4" in nep:
                        for ip in nep["ipsv4"]:
                            ips += [ip["addr"]]
                    if "ipsv6" in nep:
                        for ip in nep["ipsv6"]:
                            ips += [ip["addr"]]

                    for ip in ips:
                        if ip not in interface_ips:
                            interface_ips.append(ip)

                for aep in c.findall('it:APPLICATION-ENDPOINTS/it:APPLICATION-ENDPOINT', self.__ns__):
                    aep_id = self.get_id(aep)

                    if aep_id in self.__aeps__:
                        sis, csis, ehs, cegs = self.__aeps__[aep_id]

                        aep_name = self.get_child_text(aep, 'it:MANUFACTURER-EXTENSION/ho:SHORT-NAME')
                        nepref = self.get_child_attribute(aep, 'it:NETWORK-ENDPOINT-REF', 'ID-REF')

                        if nepref in neps:
                            nep = neps[nepref]
                        else:
                            nep = None
                            print("ERROR in FIBEX: I cannot find NEP %s" % nepref)

                        ips = []
                        if "ipsv4" in nep:
                            for ip in nep["ipsv4"]:
                                ips += [ip["addr"]]
                        if "ipsv6" in nep:
                            for ip in nep["ipsv6"]:
                                ips += [ip["addr"]]

                        udpport = self.get_child_text(
                            aep,
                            'it:IT-TRANSPORT-PROTOCOL-CONFIGURATION/it:UDP-TP/it:UDP-PORT/it:PORT-NUMBER'
                        )
                        if udpport is None and self.get_child_text(
                                aep,
                                'it:IT-TRANSPORT-PROTOCOL-CONFIGURATION/it:UDP-TP/it:UDP-PORT/it:DYNAMICALLY-ASSIGNED'
                        ) == "true":
                            udpport = self.lookup_dyn_port(aep_name)

                        tcpport = self.get_child_text(
                            aep,
                            'it:IT-TRANSPORT-PROTOCOL-CONFIGURATION/it:TCP-TP/it:TCP-PORT/it:PORT-NUMBER'
                        )
                        if tcpport is None and self.get_child_text(
                                aep,
                                'it:IT-TRANSPORT-PROTOCOL-CONFIGURATION/it:TCP-TP/it:TCP-PORT/it:DYNAMICALLY-ASSIGNED'
                        ) == "true":
                            tcpport = self.lookup_dyn_port(aep_name)

                        # only one can be existing
                        assert (udpport is None or tcpport is None)

                        if udpport is not None or tcpport is not None:

                            if udpport is not None:
                                portnumber = udpport
                                proto = "udp"
                            else:
                                portnumber = tcpport
                                proto = "tcp"

                            # build sockets
                            for ip in ips:
                                socket = self.__conf_factory__.create_socket(aep_name, ip, proto, portnumber, sis, csis,
                                                                             ehs, cegs)
                                sockets += [socket]

                # build interfaces
                if channel is not None:
                    iface = self.__conf_factory__.create_interface(channel["name"], channel["vlanid"], interface_ips,
                                                                   sockets)
                    if ctrl is not None:
                        ctrl["ifaces"] += [iface]

            # build Controllers
            ctrllist = []
            for key in sorted(ctrls.keys()):
                ctrl = ctrls[key]
                tmp = self.__conf_factory__.create_controller(ctrl["name"], ctrl["ifaces"])
                ctrllist += [tmp]

                assert (tmp not in self.__controllers__)
                self.__controllers__[key] = tmp

            self.__ecus__[ecu_id] = self.__conf_factory__.create_ecu(ecu_name, ctrllist)

    def parse_topology(self, root, verbose=False):
        for e in root.findall('.//fx:COUPLING-ELEMENTS/fx:COUPLING-ELEMENT', self.__ns__):
            switch_name = self.get_child_text(e, "ho:SHORT-NAME")
            cluster_ref = self.get_child_attribute(e, "fx:CLUSTER-REF", "ID-REF")
            ecu_ref = self.get_child_attribute(e, "fx:ECU-REF", "ID-REF")
            coupling_element_type = self.get_child_text(e, "ethernet:COUPLING-ELEMENT-TYPE")

            ecu = self.__ecus__.get(ecu_ref, None)

            if verbose:
                print(f"{switch_name} cluster_ref:{cluster_ref} ecu_ref:{ecu_ref} "
                      f"coupling_element_type: {coupling_element_type}")

            if coupling_element_type != "SWITCH":
                print(f"Found unsupported Coupling Element with coupling_element_type={coupling_element_type}!")
                continue

            coupling_ports = []
            for c in e.findall('fx:COUPLING-PORTS/fx:COUPLING-PORT', self.__ns__):
                coupling_port_id = self.get_attribute(c, "ID")
                controller_ref = self.get_child_attribute(c, "fx:CONTROLLER-REF", "ID-REF")
                controller = self.__controllers__.get(controller_ref, None)

                if controller is None:
                    controller_ref_name = ""
                else:
                    controller_ref_name = controller.name()

                coupling_port_ref = self.get_child_attribute(c, "fx:COUPLING-PORT-REF", "ID-REF")
                coupling_port = self.__coupling_ports__.get(coupling_port_ref, None)

                default_vlan_ref = self.get_child_attribute(c, "ethernet:DEFAULT-VLAN/fx:CHANNEL-REF", "ID-REF")

                if verbose:
                    default_vlan_name = (self.__channels__.get(default_vlan_ref, {})).get("name", "")
                    print(f"  Port ID:{coupling_port_id} CTRL-REF:{controller_ref} ({controller_ref_name}) "
                          f"PORT-REF:{coupling_port_ref} DEFAULT-VLAN:{default_vlan_ref} ({default_vlan_name})")

                # a port can only be connected to an ecu port or a switch port
                assert (controller is None or coupling_port is None)

                vlans = []
                for v in c.findall('ethernet:VLAN-MEMBERSHIPS/ethernet:VLAN-MEMBERSHIP', self.__ns__):
                    channel_ref = self.get_child_attribute(v, "fx:CHANNEL-REF", "ID-REF")
                    channel_ref_name = (self.__channels__.get(channel_ref, {})).get("name", "")
                    default_prio = self.get_child_text(v, "ethernet:DEFAULT-PRIORITY/fx:PRIORITY")
                    if verbose:
                        print(f"    VLAN Channel:{channel_ref} ({channel_ref_name}) Default-Prio:{default_prio}")

                    channel = self.__channels__.get(channel_ref, {})
                    vlans.append(self.__conf_factory__.create_vlan(channel["name"], channel["vlanid"], default_prio))

                tmp = self.__conf_factory__.create_switch_port(coupling_port_id, controller, coupling_port,
                                                               default_vlan_ref, vlans)
                if coupling_port is not None:
                    coupling_port.set_connected_port(tmp)

                coupling_ports.append(tmp)
                self.__coupling_ports__[coupling_port_id] = tmp

            self.__conf_factory__.create_switch(switch_name, ecu, coupling_ports)

    def parse_file(self, conf_factory, filename, verbose=False):
        self.__conf_factory__ = conf_factory

        tree = xml.etree.ElementTree.parse(filename)
        root = tree.getroot()

        if verbose:
            print("*** Parsing Channels ***")
        self.parse_channels(root)
        if verbose:
            for k, v in self.__channels__.items():
                print(f"{k}: {v}")
            print("")

        if verbose:
            print("*** Parsing Codings ***")
        self.parse_codings(root)
        if verbose:
            print(self.__codings__)
            print("")

        if verbose:
            print("*** Parsing Signals ***")
        self.parse_signals(root)
        if verbose:
            print("")

        if verbose:
            print("*** Parsing Datatypes ***")
        self.parse_datatypes(root)
        if verbose:
            print("")

        if verbose:
            print("*** Parsing Services ***")
        self.parse_services(root)
        if verbose:
            print("")

        if verbose:
            print("*** Parsing ECUs ***")
        self.parse_ecus(root)
        if verbose:
            print("")

        if verbose:
            print("*** Parsing Topology ***")
        self.parse_topology(root, verbose)
        if verbose:
            print("")


def main():
    print("You cannot call me directly!")


# only call main, if we are started directly
if __name__ == "__main__":
    main()
