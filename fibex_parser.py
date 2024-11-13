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
import xml.etree.ElementTree
from abstract_parser import AbstractParser

import importlib.util
import sys
import os

class FibexParser(AbstractParser):
    def __init__(self, plugin_file, ecu_name_replacement):
        super().__init__()
        self.__conf_factory__ = None

        self.__ns__ = {'fx': 'http://www.asam.net/xml/fbx',
                       'ho': 'http://www.asam.net/xml',
                       'xsi': 'http://www.w3.org/2001/XMLSchema-instance',
                       'ethernet': 'http://www.asam.net/xml/fbx/ethernet',
                       'flexray': 'http://www.asam.net/xml/fbx/flexray',
                       'it': 'http://www.asam.net/xml/fbx/it',
                       'service': 'http://www.asam.net/xml/fbx/services'}

        self.__services__ = dict()
        self.__codings__ = dict()
        self.__signals__ = dict()
        self.__datatypes__ = dict()
        self.__channels__ = dict()
        self.__controllers__ = dict()
        self.__coupling_ports__ = dict()

        self.__ecu_name_replacement__ = ecu_name_replacement
        self.__ecu_data__ = dict()
        self.__ecus__ = dict()
        self.__ecu_id_to_ecu_name_mapping__ = dict()
        self.__ecus_ready__ = False

        self.__frames__ = dict()
        self.__frame_triggerings__ = dict()
        self.__pdus__ = dict()
        self.__signals__ = dict()

        # FIBEX-ID -> (FIBEX-ID of Service, Eventgroup-ID)
        self.__eventgrouprefs__ = dict()

        # FIBEX-ID -> ServiceInstance
        self.__ServiceInstances__ = dict()

        # FIBEX-ID -> ServiceEventgroupReceiver
        self.__ServiceEventgroupReceiver__ = dict()

        # FIBEX-ID -> (PSIS[], CSIS[], EH[], CEGS[])
        self.__aeps__ = dict()

        # AEP-ID -> Socket
        self.__sockets__ = dict()

        self.__plugin__ = None
        # Load plugin
        if plugin_file is not None:
            if not os.path.isfile(plugin_file):
                print(f"Plugin {plugin_file} cannot be found!")
                sys.exit(-1)

            print(f"Loading plugin {plugin_file}")
            module_name = "fibex_parser_plugin"
            spec = importlib.util.spec_from_file_location(module_name, plugin_file)
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)

            self.__plugin__ = module

    def create_ecu(self, ecu_id, ecu_name, ctrllist):
        ret = None

        if ecu_name in self.__ecu_data__:
            print(f"ERROR: Duplicate ecu_id: {ecu_name} during create_ecu")

        self.__ecu_data__[ecu_name] = (ecu_id, ctrllist)
        #ret = self.__conf_factory__.create_ecu(ecu_name, ctrllist)
        #self.__ecus__[ecu_id] = ret

    def finalize_ecus(self):

        # name -> ([ecu_id], [ctrl])
        tmp_data = dict()

        for ecu_name, data in self.__ecu_data__.items():
            # replace ecu_name, if in replacement data
            if self.__ecu_name_replacement__ is not None and ecu_name in self.__ecu_name_replacement__.keys():
                ecu_name = self.__ecu_name_replacement__[ecu_name]

            ecu_id, ctrllist = data

            ecu_data = tmp_data.get(ecu_name, ([],[]))

            if ecu_id not in ecu_data[0]:
                ecu_data[0].append(ecu_id)

            # controllers should be unique but just in case
            tmp_ctrllist = list(set(ctrllist + ecu_data[1]))

            if len(tmp_ctrllist) != len(ctrllist) + len(ecu_data[1]):
                print(f"INTERNAL ERROR: Merging Controller lists reveals duplicates during finalize_ecus!")

            tmp_data[ecu_name] =  (ecu_data[0], tmp_ctrllist)

        for ecu_name, ecu_data in tmp_data.items():
            self.__ecus__[ecu_name] = self.__conf_factory__.create_ecu(ecu_name, ecu_data[1])

            for ecu_id in ecu_data[0]:
                self.__ecu_id_to_ecu_name_mapping__[ecu_id] = ecu_name

        self.__ecus_ready__ = True
        pass

    def get_ecu(self, ecu_ref):

        if not self.__ecus_ready__:
            print(f"INTERNAL ERROR: get_ecu is called before ECUs are finalized!")

        return self.__ecus__.get(self.__ecu_id_to_ecu_name_mapping__.get(ecu_ref, None), None)

    def get_signal(self, signal_ref):
        for _, value in self.__signals__.items():
            if value.__id__ == signal_ref:
                return value

        return None

    def add_pdu(self, pdu):
        self.__pdus__[pdu.id()] = pdu

    def get_pdu(self, pdu_ref):
        return self.__pdus__.get(pdu_ref)

    def add_socket(self, aep_id, socket):
        self.__sockets__[aep_id] = socket

    def get_socket_by_aep_id(self, aep_id):
        return self.__sockets__.get(aep_id)

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
            print(f"WARNING: Signal Coding for Signal {name} is None")
        basetype = self.get_from_dict_or_none(coding, 'Basetype')
        compu_scale = self.get_from_dict_or_none(coding, 'CompuScale')
        compu_consts = self.get_from_dict_or_none(coding, 'CompuConsts')
        bit_len = self.get_from_dict_or_none(coding, 'BitLength')
        min_len = self.get_from_dict_or_none(coding, 'MinLength')
        max_len = self.get_from_dict_or_none(coding, 'MaxLength')

        basetypelen = self.basetype_length(coding)

        ret = self.__conf_factory__.create_signal(id, name, compu_scale, compu_consts, bit_len, min_len, max_len,
                                                  basetype, basetypelen)
        self.__signals__[name] = ret
        return ret

    def parse_signals(self, root):
        for signal in root.findall('.//fx:SIGNALS/fx:SIGNAL', self.__ns__):
            s = self.parse_signal(signal)
            if s is not None:
                self.__signals__[s.id()] = s

    def parse_signal_instance(self, element):
        id = self.get_id(element)
        bit_position = self.get_child_text(element, './fx:BIT-POSITION')
        is_high_low_byte_order = self.get_child_text(element, './fx:IS-HIGH-LOW-BYTE-ORDER')
        signal_ref = self.get_child_attribute(element, './fx:SIGNAL-REF', 'ID-REF')

        ret = self.__conf_factory__.create_signal_instance(id, signal_ref, int(bit_position), is_high_low_byte_order)
        return ret

    def parse_multiplexer(self, element):
        # Switch
        id = self.get_child_attribute(element, './fx:SWITCH', 'ID')
        name = self.get_child_text(element, './fx:SWITCH/ho:SHORT-NAME')
        bit_pos = int(self.get_child_text(element, './fx:SWITCH/fx:BIT-POSITION'))
        is_high_low_byte_order = self.get_child_text(element, './fx:SWITCH/fx:IS-HIGH-LOW-BYTE-ORDER')
        bit_length = int(self.get_child_text(element, './fx:SWITCH/ho:BIT-LENGTH'))
        switch = self.__conf_factory__.create_multiplex_switch(id, name, bit_pos, is_high_low_byte_order, bit_length)

        # segment positions
        segs = []
        for seg in element.findall('./fx:DYNAMIC-PART/fx:SEGMENT-POSITIONS/fx:SEGMENT-POSITION', self.__ns__):
            bit_pos = int(self.get_child_text(seg, './fx:BIT-POSITION'))
            high_low = self.get_child_text(seg, './fx:IS-HIGH-LOW-BYTE-ORDER')
            bit_len = int(self.get_child_text(seg, './ho:BIT-LENGTH'))
            segs.append(self.__conf_factory__.create_multiplex_segment_position(bit_pos, high_low, bit_len))

        # switched pdu instances
        pdus = {}
        for switched_pdu in element.findall('./fx:DYNAMIC-PART/fx:SWITCHED-PDU-INSTANCES/fx:SWITCHED-PDU-INSTANCE',
                                            self.__ns__):
            switch_code = self.get_child_text(switched_pdu, './fx:SWITCH-CODE')
            pdu_ref = self.get_child_attribute(switched_pdu, './fx:PDU-REF', 'ID-REF')
            pdus[int(switch_code)] = self.get_pdu(pdu_ref)

        # static segment positions
        static_segs = []
        for seg in element.findall('./fx:STATIC-PART/fx:SEGMENT-POSITIONS/fx:SEGMENT-POSITION', self.__ns__):
            bit_pos = int(self.get_child_text(seg, './fx:BIT-POSITION'))
            high_low = self.get_child_text(seg, './fx:IS-HIGH-LOW-BYTE-ORDER')
            bit_len = int(self.get_child_text(seg, './ho:BIT-LENGTH'))
            static_segs.append(self.__conf_factory__.create_multiplex_segment_position(bit_pos, high_low, bit_len))

        # static pdu instances
        static_pdu = self.get_child_attribute(element, './fx:STATIC-PART/fx:STATIC-PDU-INSTANCE/fx:PDU-REF', 'ID-REF')

        return switch, segs, pdus, static_segs, static_pdu

    def parse_signal_pdu(self, element, verbose):
        id = self.get_id(element)
        short_name = self.get_child_text(element, 'ho:SHORT-NAME')
        byte_length = int(self.get_child_text(element, 'fx:BYTE-LENGTH'))
        pdu_type = self.get_child_text(element, 'fx:PDU-TYPE')

        if verbose:
            print(f"DEBUG: parse_pdu: {short_name} byte_length:{byte_length} pdu_type:{pdu_type}")

        signal_instances = dict()
        for signal_instance in element.findall('./fx:SIGNAL-INSTANCES/fx:SIGNAL-INSTANCE', self.__ns__):
            si = self.parse_signal_instance(signal_instance)
            si.add_signal(self.get_signal(si.__signal_ref__))
            if si is not None:
                signal_instances[si.__id__] = si

        ret = self.__conf_factory__.create_pdu(id, short_name, byte_length, pdu_type, signal_instances)
        self.add_pdu(ret)
        return ret

    def parse_multiplex_pdu(self, element, verbose):
        pdu_id = self.get_id(element)
        short_name = self.get_child_text(element, 'ho:SHORT-NAME')
        byte_length = int(self.get_child_text(element, 'fx:BYTE-LENGTH'))
        pdu_type = self.get_child_text(element, 'fx:PDU-TYPE')

        if verbose:
            print(f"DEBUG: parse_pdu:{short_name} byte_length:{byte_length} pdu_type:{pdu_type}")

        multiplexer = element.find('./fx:MULTIPLEXER', self.__ns__)

        switch, seg_pos, pdu_instances, static_segs, static_pdu_id = self.parse_multiplexer(multiplexer)

        static_pdu = self.get_pdu(static_pdu_id)
        ret = self.__conf_factory__.create_multiplex_pdu(pdu_id, short_name, byte_length, pdu_type,
                                                         switch, seg_pos, pdu_instances, static_segs, static_pdu)

        self.add_pdu(ret)
        return ret

    def parse_pdus(self, root, verbose):
        # first pass without MULTIPLEXER
        for pdu in root.findall('.//fx:PDUS/fx:PDU', self.__ns__):
            if pdu.find('./fx:MULTIPLEXER', self.__ns__) is None:
                p = self.parse_signal_pdu(pdu, verbose)
                if p is not None:
                    self.add_pdu(p)

        # second pass MULTIPLEXER only, since static PDUs need to already be parsed
        for pdu in root.findall('.//fx:PDUS/fx:PDU/fx:MULTIPLEXER/..', self.__ns__):
            p = self.parse_multiplex_pdu(pdu, verbose)
            if p is not None:
                self.add_pdu(p)

    def parse_pdu_instance(self, element):
        id = self.get_id(element)
        pdu_ref = self.get_child_attribute(element, './fx:PDU-REF', 'ID-REF')

        bit_position = int(self.get_child_text(element, './fx:BIT-POSITION'))
        is_high_low_byte_order = self.get_child_text(element, './fx:IS-HIGH-LOW-BYTE-ORDER')
        pdu_update_bit_position = self.get_child_text(element, './/fx:PDU-UPDATE-BIT-POSITION')
        if pdu_update_bit_position is not None:
            pdu_update_bit_position = int(pdu_update_bit_position)

        ret = self.__conf_factory__.create_pdu_instance(id, pdu_ref, bit_position, is_high_low_byte_order, pdu_update_bit_position)
        return ret

    def parse_frame_triggering(self, element):
        id = self.get_id(element)
        frame_ref = self.get_child_attribute(element, './fx:FRAME-REF', 'ID-REF')
        frame = self.__frames__.get(frame_ref, None)

        # let us find out what we have here...

        # CAN:
        identifier_tmp = self.get_child_text(element, './fx:IDENTIFIER/fx:IDENTIFIER-VALUE')

        # FlexRay
        slot_id_tmp = self.get_child_text(element, './fx:TIMINGS/fx:ABSOLUTELY-SCHEDULED-TIMING/fx:SLOT-ID')
        cycle_counter_tmp = self.get_child_text(element, './fx:TIMINGS/fx:ABSOLUTELY-SCHEDULED-TIMING/fx:CYCLE-COUNTER')
        base_cycle_tmp = self.get_child_text(element, './fx:TIMINGS/fx:ABSOLUTELY-SCHEDULED-TIMING/fx:BASE-CYCLE')
        cycle_repetition_tmp = self.get_child_text(element, './fx:TIMINGS/fx:ABSOLUTELY-SCHEDULED-TIMING/fx:CYCLE-REPETITION')

        if slot_id_tmp is not None and ((cycle_counter_tmp is not None) or
                                        (base_cycle_tmp is not None and cycle_repetition_tmp is not None)):
            # FlexRay
            slot_id = int(slot_id_tmp)

            # two options in standard: CYCLE-COUNTER or BASE-CYCLE + REPETITION
            cycle_counter = None if cycle_counter_tmp is None else int(cycle_counter_tmp)
            base_cycle = None if base_cycle_tmp is None else int(base_cycle_tmp)
            cycle_repetition = None if cycle_repetition_tmp is None else int(cycle_repetition_tmp)

            ret = self.__conf_factory__.create_frame_triggering_flexray(id, frame, slot_id, cycle_counter,
                                                                        base_cycle, cycle_repetition)
            return ret

        elif identifier_tmp is not None:
            can_id = int(identifier_tmp)

            ret = self.__conf_factory__.create_frame_triggering_can(id, frame, can_id)
            return ret

        return None

    def parse_frame_triggerings(self, root):
        for frame_triggering in root.findall('.//fx:FRAME-TRIGGERING', self.__ns__):
            f = self.parse_frame_triggering(frame_triggering)
            if f is not None:
                if f.id() in self.__frame_triggerings__.keys():
                    print(f"WARNING: creating another Frame Triggering with ID: {f.id()}")
                self.__frame_triggerings__[f.id()] = f

    def parse_frame(self, element, verbose):
        id = self.get_id(element)
        short_name = self.get_child_text(element, './ho:SHORT-NAME')
        byte_length = self.get_child_text(element, './fx:BYTE-LENGTH')
        frame_type = self.get_child_text(element, './fx:FRAME-TYPE')

        pdu_instances = dict()
        for pdu_instance in element.findall('./fx:PDU-INSTANCES/fx:PDU-INSTANCE', self.__ns__):
            pi = self.parse_pdu_instance(pdu_instance)
            if pi is not None:
                pdu = self.get_pdu(pi.__pdu_ref__)
                if pdu is None:
                    print(f"ERROR: Frame {short_name} references unknown PDU {pi.__pdu_ref__}!")
                else:
                    pi.add_pdu(pdu)

                pdu_instances[pi.__id__] = pi

        ret = self.__conf_factory__.create_frame(id, short_name, byte_length, frame_type, pdu_instances)
        return ret

    def parse_frames(self, root, verbose):
        for frame in root.findall('.//fx:FRAMES/fx:FRAME', self.__ns__):
            f = self.parse_frame(frame, verbose)
            if f is not None:
                self.__frames__[f.id()] = f

    def basetype_length(self, coding_dict):
        basetype = self.get_from_dict(coding_dict, "Basetype", "--INVALID--")

        if basetype in ['A_UINT8', 'A_INT8']:
            return 8

        if basetype in ['A_UINT16', 'A_INT16']:
            return 16

        if basetype in ['A_UINT32', 'A_INT32', 'A_FLOAT32']:
            return 32

        if basetype in ['A_UINT64', 'A_INT64', 'A_FLOAT64']:
            return 64

        # 'A_ASCIISTRING', 'A_UNICODE2STRING', 'A_BYTEFIELD', 'A_BITFIELD', 'OTHER'
        return -1

    def basetype_is_int(self, coding_dict):
        basetype = self.get_from_dict(coding_dict, "Basetype", "--INVALID--")
        return basetype in ['A_UINT8', 'A_INT8', 'A_UINT16', 'A_INT16', 'A_UINT32', 'A_INT32', 'A_UINT64', 'A_INT64']

    def basetype_is_float(self, coding_dict):
        basetype = self.get_from_dict(coding_dict, "Basetype", "--INVALID--")
        return basetype in ['A_FLOAT32', 'A_FLOAT64']

    def basetype_is_string(self, coding_dict):
        basetype = self.get_from_dict(coding_dict, "Basetype", "--INVALID--")
        return basetype in ['A_ASCIISTRING', 'A_UNICODE2STRING']

    def basetype_is_other(self, coding_dict):
        basetype = self.get_from_dict(coding_dict, "Basetype", "--INVALID--")
        return basetype in ['A_BYTEFIELD', 'A_BITFIELD', 'OTHER']

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
            if self.basetype_is_int(coding2) or self. basetype_is_float(coding2):
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

            elif self.basetype_is_string(coding2):
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

            channel["flexray-channel-name"] = self.get_child_text(ch, "flexray:FLEXRAY-CHANNEL-NAME")

            channel["vlanid"] = None
            channel["vlanname"] = None

            channel["frametriggerings"] = {}

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

                if ip["addr"] is not None and ip["netmask"] is not None:
                    self.__conf_factory__.add_ipv4_address_config(ip["addr"], ip["netmask"] )
            nep["ipsv4"] = ipsv4

            ipsv6 = []
            for i in n.findall('it:NETWORK-ENDPOINT-ADDRESSES/it:NETWORK-ENDPOINT-ADDRESS/it:IPV6', self.__ns__):
                ip = dict()
                ip["addr"] = self.get_child_text(i, "it:IPV6-ADDRESS")
                ip["addrsrc"] = self.get_child_text(i, "it:IPV6-ADDRESS-SOURCE")
                ip["prefixlen"] = self.get_child_text(i, "it:IP-ADDRESS-PREFIX-LENGTH")
                ipsv6 += [ip]

                if ip["addr"] is not None and ip["prefixlen"] is not None:
                    self.__conf_factory__.add_ipv6_address_config(ip["addr"], ip["prefixlen"] )
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

    def parse_generic_frame_triggering_ref(self, root, path, frametriggerings):
        ret = {}
        for port in root.findall(path, self.__ns__):
            frame_triggering_id = self.get_child_attribute(port, "./fx:FRAME-TRIGGERING-REF", "ID-REF")

            tmp = self.__frame_triggerings__.get(frame_triggering_id, None)
            if tmp is None:
                print(f"WARNING: FrameTriggering {frame_triggering_id} not found!")
            else:
                ret[tmp.calc_key()] = tmp
                frametriggerings[tmp.calc_key()] = tmp

        return ret

    def parse_inputs_outputs(self, root, channel_fts):
        input_ports = self.parse_generic_frame_triggering_ref(root, "./fx:INPUTS/fx:INPUT-PORT", channel_fts)
        output_ports = self.parse_generic_frame_triggering_ref(root, "./fx:OUTPUTS/fx:OUTPUT-PORT", channel_fts)

        return input_ports, output_ports

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
                    channel_fts = channel.get("frametriggerings", {})
                else:
                    channel = None
                    print(f"ERROR in FIBEX: I cannot find channel '{channelref}' (ID: {self.get_id(c)})")
                    channel_fts = {}

                input_frame_trigs, output_frame_trigs = self.parse_inputs_outputs(c, channel_fts)

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
                    else:
                        sis, csis, ehs, cegs = [], [], [], []

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

                    udpport = self.get_child_text(aep, 'it:IT-TRANSPORT-PROTOCOL-CONFIGURATION/it:UDP-TP/'
                                                       'it:UDP-PORT/it:PORT-NUMBER')
                    if udpport is None and self.get_child_text(aep, 'it:IT-TRANSPORT-PROTOCOL-CONFIGURATION/it:UDP-TP/'
                                                                    'it:UDP-PORT/it:DYNAMICALLY-ASSIGNED') == "true":
                        udpport = self.lookup_dyn_port(aep_name)

                    tcpport = self.get_child_text(aep, 'it:IT-TRANSPORT-PROTOCOL-CONFIGURATION/it:TCP-TP/'
                                                       'it:TCP-PORT/it:PORT-NUMBER')
                    if tcpport is None and self.get_child_text(aep, 'it:IT-TRANSPORT-PROTOCOL-CONFIGURATION/it:TCP-TP/'
                                                                    'it:TCP-PORT/it:DYNAMICALLY-ASSIGNED') == "true":
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
                            self.add_socket(aep_id, socket)

                # build interfaces
                if channel is not None:
                    iface = self.__conf_factory__.create_interface(channel["name"], channel["vlanid"], interface_ips,
                                                                   sockets, input_frame_trigs, output_frame_trigs,
                                                                   channel["flexray-channel-name"])
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

            self.create_ecu(ecu_id, ecu_name, ctrllist)
        self.finalize_ecus()

    def parse_topology(self, root, verbose=False):
        for e in root.findall('.//fx:COUPLING-ELEMENTS/fx:COUPLING-ELEMENT', self.__ns__):
            switch_name = self.get_child_text(e, "ho:SHORT-NAME")
            cluster_ref = self.get_child_attribute(e, "fx:CLUSTER-REF", "ID-REF")
            ecu_ref = self.get_child_attribute(e, "fx:ECU-REF", "ID-REF")
            coupling_element_type = self.get_child_text(e, "ethernet:COUPLING-ELEMENT-TYPE")

            ecu = self.get_ecu(ecu_ref)

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
                    default_prio = 0 if default_prio is None else int(default_prio)

                    if verbose:
                        print(f"    VLAN Channel:{channel_ref} ({channel_ref_name}) Default-Prio:{default_prio}")

                    channel = self.__channels__.get(channel_ref, {})
                    channel["vlanid"] = None if channel.get("vlanid", None) is None else int(channel["vlanid"])
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
            print("*** Parsing PDUs ***")
        self.parse_pdus(root, verbose)
        if verbose:
            for k, v in self.__pdus__.items():
                print(f"{k}: {v}")
            print("")

        if verbose:
            print("*** Parsing Frames ***")
        self.parse_frames(root, verbose)
        if verbose:
            print("")

        if verbose:
            print("*** Parsing FrameTriggering ***")
        self.parse_frame_triggerings(root)
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

        if self.__plugin__ is not None:
            plugin = self.__plugin__.FibexParserPlugin()
            plugin.parse_file(self, conf_factory, filename, verbose=verbose)


def main():
    print("You cannot call me directly!")


# only call main, if we are started directly
if __name__ == "__main__":
    main()
