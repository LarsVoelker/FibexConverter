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

import importlib.util
import ipaddress
import os
import pprint
import sys
import xml.etree.ElementTree
from typing import Any, cast

from lxml.etree import _Element

from abstract_parser import AbstractParser
from configuration_base_classes import (
    BaseAbstractPDU,
    BaseConfigurationFactory,
    BaseController,
    BaseECU,
    BaseFrame,
    BaseFrameTriggering,
    BaseMultiplexPDU,
    BaseMultiplexPDUSegmentPosition,
    BaseMultiplexPDUSwitch,
    BasePDU,
    BasePDUInstance,
    BaseSignal,
    BaseSignalInstance,
    BaseSocket,
    BaseSwitchPort,
    BaseVLAN,
    CallSemantic,
    SOMEIPBaseDatatype,
    SOMEIPBaseParameter,
    SOMEIPBaseParameterArray,
    SOMEIPBaseParameterArrayDim,
    SOMEIPBaseParameterBitfieldItem,
    SOMEIPBaseParameterEnumerationItem,
    SOMEIPBaseParameterStructMember,
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


class FibexParser(AbstractParser):
    def __init__(
        self,
        plugin_file: str | None,
        ecu_name_replacement: dict[str, str] | None,
        keep_duplicates: bool = False,
    ) -> None:
        super().__init__()
        self.__conf_factory__ = None
        self.__keep_duplicates__: bool = keep_duplicates

        self.__ns__ = {
            "fx": "http://www.asam.net/xml/fbx",
            "ho": "http://www.asam.net/xml",
            "xsi": "http://www.w3.org/2001/XMLSchema-instance",
            "ethernet": "http://www.asam.net/xml/fbx/ethernet",
            "flexray": "http://www.asam.net/xml/fbx/flexray",
            "it": "http://www.asam.net/xml/fbx/it",
            "service": "http://www.asam.net/xml/fbx/services",
        }

        self.__services__: dict[str, SOMEIPBaseService] = {}
        self.__codings__: dict[str, dict[str, Any]] = {}
        self.__signals__: dict[str, BaseSignal] = {}
        self.__datatypes__: dict[str, _Element] = {}
        self.__channels__: dict[str, dict[str, Any]] = {}
        self.__controllers__: dict[str, BaseController] = {}
        self.__coupling_ports__: dict[str, BaseSwitchPort] = {}

        self.__ecu_name_replacement__ = ecu_name_replacement
        self.__ecu_data__: dict[str, tuple[str, list[BaseController]]] = {}
        self.__ecus__: dict[str, BaseECU] = {}
        self.__ecu_id_to_ecu_name_mapping__: dict[str, str] = {}
        self.__ecus_ready__ = False

        self.__frames__: dict[str, BaseFrame] = {}
        self.__frame_triggerings__: dict[str, BaseFrameTriggering] = {}
        self.__pdus__: dict[str, BaseAbstractPDU] = {}
        self.__eth_pdu_header_id_counter = 0

        # FIBEX-ID -> (FIBEX-ID of Service, Eventgroup-ID)
        self.__eventgrouprefs__: dict[str, tuple[str | None, int | None]] = {}

        # FIBEX-ID -> ServiceInstance
        self.__ServiceInstances__: dict[str, SOMEIPBaseServiceInstance] = {}

        # FIBEX-ID -> ServiceEventgroupReceiver
        self.__ServiceEventgroupReceiver__: dict[str, SOMEIPBaseServiceEventgroupReceiver] = {}

        # FIBEX-ID -> (PSIS[], CSIS[], EH[], CEGS[])
        self.__aeps__: dict[
            str,
            tuple[
                list[SOMEIPBaseServiceInstance],
                list[SOMEIPBaseServiceInstanceClient],
                list[SOMEIPBaseServiceEventgroupSender],
                list[SOMEIPBaseServiceEventgroupReceiver],
            ],
        ] = {}

        # AEP-ID -> Socket
        self.__sockets__: dict[str, BaseSocket] = {}

        self.__plugin__: Any = None
        # Load plugin
        if plugin_file is not None:
            if not os.path.isfile(plugin_file):
                print(f"Plugin {plugin_file} cannot be found!")
                sys.exit(-1)

            print(f"Loading plugin {plugin_file}")
            module_name = "fibex_parser_plugin"
            spec = importlib.util.spec_from_file_location(module_name, plugin_file)
            assert spec is not None and spec.loader is not None
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)

            self.__plugin__ = module

    def create_ecu(self, ecu_id: str, ecu_name: str, ctrllist: list[BaseController]) -> None:
        # ret = None

        if ecu_name in self.__ecu_data__:
            print(f"ERROR: Duplicate ecu_id: {ecu_name} during create_ecu")

        self.__ecu_data__[ecu_name] = (ecu_id, ctrllist)
        # ret = self.__conf_factory__.create_ecu(ecu_name, ctrllist)
        # self.__ecus__[ecu_id] = ret

    def finalize_ecus(self) -> None:

        # name -> ([ecu_id], [ctrl])
        tmp_data: dict[str, tuple[list[str], list[BaseController]]] = {}

        for ecu_name, data in self.__ecu_data__.items():
            # replace ecu_name, if in replacement data
            if self.__ecu_name_replacement__ is not None and ecu_name in self.__ecu_name_replacement__.keys():
                ecu_name = self.__ecu_name_replacement__[ecu_name]

            ecu_id, ctrllist = data

            ecu_data = tmp_data.get(ecu_name, ([], []))

            if ecu_id not in ecu_data[0]:
                ecu_data[0].append(ecu_id)

            # controllers should be unique but just in case
            tmp_ctrllist = list(set(ctrllist + ecu_data[1]))

            if len(tmp_ctrllist) != len(ctrllist) + len(ecu_data[1]):
                print("INTERNAL ERROR: Merging Controller lists reveals duplicates during finalize_ecus!")

            tmp_data[ecu_name] = (ecu_data[0], tmp_ctrllist)

        conf_factory = self.__conf_factory__
        assert conf_factory is not None
        for ecu_name, ecu_data in tmp_data.items():
            self.__ecus__[ecu_name] = conf_factory.create_ecu(ecu_name, ecu_data[1])

            for ecu_id in ecu_data[0]:
                self.__ecu_id_to_ecu_name_mapping__[ecu_id] = ecu_name

        self.__ecus_ready__ = True
        pass

    def get_ecu(self, ecu_ref: str | None) -> BaseECU | None:

        if not self.__ecus_ready__:
            print("INTERNAL ERROR: get_ecu is called before ECUs are finalized!")

        name = self.__ecu_id_to_ecu_name_mapping__.get(cast(str, ecu_ref), "")
        return self.__ecus__.get(name)

    def get_signal(self, signal_ref: str) -> BaseSignal | None:
        for _, value in self.__signals__.items():
            if value.__id__ == signal_ref:
                return value

        return None

    def add_pdu(self, pdu: BaseAbstractPDU) -> None:
        self.__pdus__[pdu.id()] = pdu

    def get_pdu(self, pdu_ref: str) -> BaseAbstractPDU | None:
        return self.__pdus__.get(pdu_ref)

    def add_socket(self, aep_id: str, socket: BaseSocket) -> None:
        self.__sockets__[aep_id] = socket

    def get_socket_by_aep_id(self, aep_id: str) -> BaseSocket | None:
        return self.__sockets__.get(aep_id)

    def get_id(self, element: _Element) -> str | None:
        return self.get_attribute(element, "ID")

    def get_oid(self, element: _Element) -> str | None:
        return self.get_attribute(element, "ho:OID")

    def parse_utilization(self, element: _Element | None) -> dict[str, Any]:
        ret: dict[str, Any] = {}

        if element is not None:
            coding = self.get_child_attribute(element, "fx:UTILIZATION/fx:CODING-REF", "ID-REF")
            ret["Coding"] = self.get_from_dict_or_none(self.__codings__, cast(str, coding))

            high_low_byte_order_elem = element.find("fx:UTILIZATION/fx:IS-HIGH-LOW-BYTE-ORDER", self.__ns__)
            if high_low_byte_order_elem is not None:
                high_low_byte_order = "true" == cast(str, high_low_byte_order_elem.text).lower()
            else:
                # set True as default as SOME/IP states that BigEndian is default
                high_low_byte_order = True

            ret["HighLowByteOrder"] = high_low_byte_order

            bit_length_elem = element.find("fx:UTILIZATION/fx:BIT-LENGTH", self.__ns__)
            min_bit_length_elem = element.find("fx:UTILIZATION/fx:MIN-BIT-LENGTH", self.__ns__)
            max_bit_length_elem = element.find("fx:UTILIZATION/fx:MAX-BIT-LENGTH", self.__ns__)
            ret["BitLength"] = -1 if bit_length_elem is None else self.element_text_to_int(bit_length_elem, -1)
            ret["MinBitLength"] = -1 if min_bit_length_elem is None else self.element_text_to_int(min_bit_length_elem, -1)
            ret["MaxBitLength"] = -1 if max_bit_length_elem is None else self.element_text_to_int(max_bit_length_elem, -1)

        return ret

    def merge_utilizations(self, util1: dict[str, Any], util2: dict[str, Any]) -> dict[str, Any]:
        ret: dict[str, Any] = {}

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

        if "Coding" in util1 and util1["Coding"] is not None and "Coding" in util2 and util2["Coding"] is not None:
            ret["Coding"] = self.merge_utilizations(util1["Coding"], util2["Coding"])

        return ret

    def parse_serialization_attributes(self, element: _Element | None) -> dict[str, Any]:
        ret: dict[str, Any] = {}

        if element is not None:
            array_len_elem = element.find(
                "./fx:UTILIZATION/fx:SERIALIZATION-ATTRIBUTES/fx:ARRAY-LENGTH-FIELD-SIZE",
                self.__ns__,
            )
            length_field_elem = element.find(
                "./fx:UTILIZATION/fx:SERIALIZATION-ATTRIBUTES/fx:LENGTH-FIELD-SIZE",
                self.__ns__,
            )
            type_field_elem = element.find(
                "./fx:UTILIZATION/fx:SERIALIZATION-ATTRIBUTES/fx:TYPE-FIELD-SIZE",
                self.__ns__,
            )
            bit_align_elem = element.find(
                "./fx:UTILIZATION/fx:SERIALIZATION-ATTRIBUTES/fx:BIT-ALIGNMENT",
                self.__ns__,
            )
            ret["ArrayLengthSize"] = -1 if array_len_elem is None else self.element_text_to_int(array_len_elem, -1)
            ret["LengthFieldSize"] = -1 if length_field_elem is None else self.element_text_to_int(length_field_elem, -1)
            ret["TypeFieldSize"] = 32 if type_field_elem is None else self.element_text_to_int(type_field_elem, 32)
            ret["BitAlignment"] = 0 if bit_align_elem is None else self.element_text_to_int(bit_align_elem, 0)

        return ret

    def parse_coding(self, element: _Element) -> dict[str, Any]:
        id = self.get_id(element)
        oid = self.get_oid(element)
        name = self.get_child_text(element, "./ho:SHORT-NAME")

        coded_basetype = None
        coded_basetype2 = None
        coded_category = None
        coded_encoding = None
        coded_termination = None
        coded_bit_length = -1
        coded_min_length = -1
        coded_max_length = -1

        ct = element.find("./ho:CODED-TYPE", self.__ns__)
        if ct is not None:
            coded_basetype = self.get_attribute(ct, "ho:BASE-DATA-TYPE")
            coded_category = self.get_attribute(ct, "CATEGORY")
            coded_encoding = self.get_attribute(ct, "ENCODING")
            coded_termination = self.get_attribute(ct, "TERMINATION")
            bl = ct.find("./ho:BIT-LENGTH", self.__ns__)
            if bl is not None and bl.text is not None:
                coded_bit_length = int(bl.text)
            bl = ct.find("./ho:MIN-LENGTH", self.__ns__)
            if bl is not None and bl.text is not None:
                coded_min_length = int(bl.text)
            bl = ct.find("./ho:MAX-LENGTH", self.__ns__)
            if bl is not None and bl.text is not None:
                coded_max_length = int(bl.text)

        pt = element.find("./ho:PHYSICAL-TYPE", self.__ns__)
        if pt is not None:
            coded_basetype2 = self.get_attribute(pt, "ho:BASE-DATA-TYPE")

        compu_scale: list[float | None] | None = None
        compu_consts = []
        cm_cat: str | None = ""

        for cm in element.findall("./ho:COMPU-METHODS/", self.__ns__):
            cm_cat = self.get_child_text(cm, "ho:CATEGORY")

            cs = cm.find(
                "./ho:COMPU-INTERNAL-TO-PHYS/ho:COMPU-SCALES/ho:COMPU-SCALE/ho:COMPU-RATIONAL-COEFFS",
                self.__ns__,
            )
            if cs is not None:
                if compu_scale is not None:
                    print(f"ERROR: I am overwritting the compu-scale! {name=}")

                compu_scale = []
                for num in cs.findall("./ho:COMPU-NUMERATOR/ho:V", self.__ns__):
                    compu_scale.append(float(cast(str, num.text)))
                if len(compu_scale) != 2:
                    print(f"WARNING: We did not find to nums in the compu-numerator but {len(compu_scale)}!")
                denom = cs.find("./ho:COMPU-DENOMINATOR/ho:V", self.__ns__)
                if denom is not None:
                    compu_scale.append(float(cast(str, denom.text)))
                else:
                    compu_scale.append(None)

            if cm_cat == "BITFIELD-TEXTTABLE":
                print(f"WARNING: BITFIELD-TEXTTABLE is currently not supported! {name=}")
            else:
                for cs in cm.findall(
                    "./ho:COMPU-INTERNAL-TO-PHYS/ho:COMPU-SCALES/",
                    self.__ns__,
                ):

                    cc = cs.find("./ho:COMPU-CONST/ho:VT", self.__ns__)
                    if cc is not None:
                        compu_const = (
                            cc.text,
                            self.get_child_text(cs, "ho:LOWER-LIMIT"),
                            self.get_child_text(cs, "ho:UPPER-LIMIT"),
                        )
                        compu_consts.append(compu_const)

        if id is None:
            print(f"ERROR: Coding does not have ID!\n{element.text}")

        d = {
            "ID": id,
            "OID": oid,
            "Name": name,
            "Basetype": coded_basetype,
            "Basetype2": coded_basetype2,
            "Category": coded_category,
            "Encoding": coded_encoding,
            "Termination": coded_termination,
            "BitLength": coded_bit_length,
            "MinLength": coded_min_length,
            "MaxLength": coded_max_length,
            "CompuScale": compu_scale,
            "CompuConsts": compu_consts,
            "CompuMethod_Category": cm_cat,
        }
        return d

    def parse_codings(self, root: _Element) -> None:
        for coding in root.findall(".//fx:CODINGS/fx:CODING", self.__ns__):
            d = self.parse_coding(coding)
            if d is not None and "ID" in d:
                self.__codings__[d["ID"]] = d

    def parse_signal(self, element: _Element) -> BaseSignal:
        id = self.get_id(element)
        # oid = self.get_oid(element)
        name = self.get_child_text(element, "./ho:SHORT-NAME")
        code_id = self.get_child_attribute(element, "./fx:CODING-REF", "ID-REF")
        coding = self.get_from_dict_or_none(self.__codings__, cast(str, code_id))
        if coding is None:
            print(f"WARNING: Signal Coding for Signal {name} is None")
        basetype = self.get_from_dict_or_none(coding, "Basetype")
        compu_scale = self.get_from_dict_or_none(coding, "CompuScale")
        compu_consts = self.get_from_dict_or_none(coding, "CompuConsts")
        bit_len = self.get_from_dict_or_none(coding, "BitLength")
        min_len = self.get_from_dict_or_none(coding, "MinLength")
        max_len = self.get_from_dict_or_none(coding, "MaxLength")

        basetypelen = self.basetype_length(coding)

        conf_factory = self.__conf_factory__
        assert conf_factory is not None
        ret = conf_factory.create_signal(
            cast(str, id),
            cast(str, name),
            compu_scale,
            compu_consts,
            cast(int, bit_len),
            cast(int, min_len),
            cast(int, max_len),
            cast(str, basetype),
            basetypelen,
        )
        self.__signals__[cast(str, name)] = ret
        return ret

    def parse_signals(self, root: _Element) -> None:
        for signal in root.findall(".//fx:SIGNALS/fx:SIGNAL", self.__ns__):
            s = self.parse_signal(signal)
            if s is not None:
                self.__signals__[s.id()] = s

    def parse_signal_instance(self, element: _Element) -> BaseSignalInstance:
        id = self.get_id(element)
        bit_position = self.get_child_text(element, "./fx:BIT-POSITION")
        is_high_low_byte_order = self.get_child_text(element, "./fx:IS-HIGH-LOW-BYTE-ORDER")
        signal_ref = self.get_child_attribute(element, "./fx:SIGNAL-REF", "ID-REF")

        conf_factory = self.__conf_factory__
        assert conf_factory is not None
        ret = conf_factory.create_signal_instance(
            cast(str, id), cast(str, signal_ref), int(cast(str, bit_position)), cast(bool, is_high_low_byte_order)
        )
        return ret

    def parse_multiplexer(self, element: _Element) -> tuple[
        BaseMultiplexPDUSwitch,
        list[BaseMultiplexPDUSegmentPosition],
        dict[int, BaseAbstractPDU | None],
        list[tuple[list[BaseMultiplexPDUSegmentPosition], BasePDU]],
    ]:
        # Switch
        id = self.get_child_attribute(element, "./fx:SWITCH", "ID")
        name = self.get_child_text(element, "./fx:SWITCH/ho:SHORT-NAME")
        bit_pos = int(cast(str, self.get_child_text(element, "./fx:SWITCH/fx:BIT-POSITION")))
        is_high_low_byte_order = self.get_child_text(element, "./fx:SWITCH/fx:IS-HIGH-LOW-BYTE-ORDER")
        bit_length = int(cast(str, self.get_child_text(element, "./fx:SWITCH/ho:BIT-LENGTH")))
        conf_factory = self.__conf_factory__
        assert conf_factory is not None
        switch = conf_factory.create_multiplex_switch(cast(str, id), cast(str, name), bit_pos, cast(bool, is_high_low_byte_order), bit_length)

        # segment positions
        segs: list[BaseMultiplexPDUSegmentPosition] = []
        for seg in element.findall("./fx:DYNAMIC-PART/fx:SEGMENT-POSITIONS/fx:SEGMENT-POSITION", self.__ns__):
            bit_pos = int(cast(str, self.get_child_text(seg, "./fx:BIT-POSITION")))
            high_low = self.get_child_text(seg, "./fx:IS-HIGH-LOW-BYTE-ORDER")
            bit_len = int(cast(str, self.get_child_text(seg, "./ho:BIT-LENGTH")))
            segs.append(conf_factory.create_multiplex_segment_position(bit_pos, cast(bool, high_low), bit_len))

        # switched pdu instances
        pdus: dict[int, BaseAbstractPDU | None] = {}
        for switched_pdu in element.findall(
            "./fx:DYNAMIC-PART/fx:SWITCHED-PDU-INSTANCES/fx:SWITCHED-PDU-INSTANCE",
            self.__ns__,
        ):
            switch_code = self.get_child_text(switched_pdu, "./fx:SWITCH-CODE")
            pdu_ref = self.get_child_attribute(switched_pdu, "./fx:PDU-REF", "ID-REF")
            pdus[int(cast(str, switch_code))] = self.get_pdu(cast(str, pdu_ref))

        # static segment positions
        static_segs: list[BaseMultiplexPDUSegmentPosition] = []
        for seg in element.findall("./fx:STATIC-PART/fx:SEGMENT-POSITIONS/fx:SEGMENT-POSITION", self.__ns__):
            bit_pos = int(cast(str, self.get_child_text(seg, "./fx:BIT-POSITION")))
            high_low = self.get_child_text(seg, "./fx:IS-HIGH-LOW-BYTE-ORDER")
            bit_len = int(cast(str, self.get_child_text(seg, "./ho:BIT-LENGTH")))
            static_segs.append(conf_factory.create_multiplex_segment_position(bit_pos, cast(bool, high_low), bit_len))

        # static pdu instances
        static_pdu_id = self.get_child_attribute(element, "./fx:STATIC-PART/fx:STATIC-PDU-INSTANCE/fx:PDU-REF", "ID-REF")

        static_seg_pdu_combinations = []

        if len(static_segs) > 0 and static_pdu_id is not None:
            static_pdu = self.get_pdu(static_pdu_id)

            if static_pdu is None:
                print(f"ERROR: PDU Multiplexer {id=} {name=}: {static_pdu_id=} does not reference PDU!")
            else:
                # we only can have up to one combination anyhow (limitation of FIBEX)
                static_seg_pdu_combinations.append((static_segs, cast(BasePDU, static_pdu)))
        elif len(static_segs) > 0 or static_pdu_id is not None:
            print(f"ERROR: PDU Multiplexer {id=} {name=}: combination of {static_pdu_id=} and {len(static_segs)=} makes no sense!")

        return switch, segs, pdus, static_seg_pdu_combinations

    def parse_signal_pdu(self, element: _Element, verbose: bool) -> BasePDU:
        id = self.get_id(element)
        short_name = self.get_child_text(element, "ho:SHORT-NAME")
        byte_length = int(cast(str, self.get_child_text(element, "fx:BYTE-LENGTH")))
        pdu_type = self.get_child_text(element, "fx:PDU-TYPE")

        if verbose:
            print(f"DEBUG: parse_pdu: {short_name} byte_length:{byte_length} pdu_type:{pdu_type}")

        signal_instances: dict[str, BaseSignalInstance] = dict()
        for signal_instance in element.findall("./fx:SIGNAL-INSTANCES/fx:SIGNAL-INSTANCE", self.__ns__):
            si = self.parse_signal_instance(signal_instance)
            si.add_signal(cast(BaseSignal, self.get_signal(si.__signal_ref__)))
            if si is not None:
                signal_instances[si.__id__] = si

        conf_factory = self.__conf_factory__
        assert conf_factory is not None
        ret = conf_factory.create_pdu(
            cast(str, id),
            cast(str, short_name),
            byte_length,
            cast(str, pdu_type),
            cast(dict[int, BaseSignalInstance], signal_instances),
        )
        self.add_pdu(ret)
        return ret

    def parse_multiplex_pdu(self, element: _Element, verbose: bool) -> BaseMultiplexPDU:
        pdu_id = self.get_id(element)
        short_name = self.get_child_text(element, "ho:SHORT-NAME")
        byte_length = int(cast(str, self.get_child_text(element, "fx:BYTE-LENGTH")))
        pdu_type = self.get_child_text(element, "fx:PDU-TYPE")

        if verbose:
            print(f"DEBUG: parse_pdu:{short_name} byte_length:{byte_length} pdu_type:{pdu_type}")

        multiplexer = element.find("./fx:MULTIPLEXER", self.__ns__)

        switch, seg_pos, pdu_instances, static_seg_pdu_combinations = self.parse_multiplexer(cast(_Element, multiplexer))

        conf_factory = self.__conf_factory__
        assert conf_factory is not None
        ret = conf_factory.create_multiplex_pdu(
            cast(str, pdu_id),
            cast(str, short_name),
            byte_length,
            cast(str, pdu_type),
            switch,
            seg_pos,
            pdu_instances,
            static_seg_pdu_combinations,
        )

        self.add_pdu(ret)
        return ret

    def parse_pdus(self, root: _Element, verbose: bool) -> None:
        # first pass without MULTIPLEXER
        for pdu in root.findall(".//fx:PDUS/fx:PDU", self.__ns__):
            if pdu.find("./fx:MULTIPLEXER", self.__ns__) is None:
                p = self.parse_signal_pdu(pdu, verbose)
                if p is not None:
                    self.add_pdu(p)

        # second pass MULTIPLEXER only, since static PDUs need to already be parsed
        for pdu in root.findall(".//fx:PDUS/fx:PDU/fx:MULTIPLEXER/..", self.__ns__):
            p_mux = self.parse_multiplex_pdu(pdu, verbose)
            if p_mux is not None:
                self.add_pdu(p_mux)

    def parse_pdu_instance(self, element: _Element) -> BasePDUInstance:
        id = self.get_id(element)
        pdu_ref = self.get_child_attribute(element, "./fx:PDU-REF", "ID-REF")

        bit_position = int(cast(str, self.get_child_text(element, "./fx:BIT-POSITION")))
        is_high_low_byte_order = self.get_child_text(element, "./fx:IS-HIGH-LOW-BYTE-ORDER")
        pdu_update_bit_position_str = self.get_child_text(element, ".//fx:PDU-UPDATE-BIT-POSITION")
        pdu_update_bit_position: int | None = None
        if pdu_update_bit_position_str is not None:
            pdu_update_bit_position = int(pdu_update_bit_position_str)

        conf_factory = self.__conf_factory__
        assert conf_factory is not None
        ret = conf_factory.create_pdu_instance(
            cast(str, id),
            cast(str, pdu_ref),
            bit_position,
            cast(bool, is_high_low_byte_order),
            pdu_update_bit_position,
        )
        return ret

    def parse_frame_triggering(self, element: _Element) -> BaseFrameTriggering | None:
        id = self.get_id(element)
        frame_ref = self.get_child_attribute(element, "./fx:FRAME-REF", "ID-REF")
        frame = self.__frames__.get(cast(str, frame_ref), None)

        # let us find out what we have here...

        # CAN:
        identifier_tmp = self.get_child_text(element, "./fx:IDENTIFIER/fx:IDENTIFIER-VALUE")
        id_ext_tmp = self.get_child_attribute(element, "./fx:IDENTIFIER/fx:IDENTIFIER-VALUE", "EXTENDED-ADDRESSING")
        fd_frame_rx_tmp = self.get_child_text(element, "./fx:CAN-FRAME-RX-BEHAVIOR")
        fd_frame_tx_tmp = self.get_child_text(element, "./fx:CAN-FRAME-TX-BEHAVIOR")

        # FlexRay
        slot_id_tmp = self.get_child_text(element, "./fx:TIMINGS/fx:ABSOLUTELY-SCHEDULED-TIMING/fx:SLOT-ID")
        cycle_counter_tmp = self.get_child_text(element, "./fx:TIMINGS/fx:ABSOLUTELY-SCHEDULED-TIMING/fx:CYCLE-COUNTER")
        base_cycle_tmp = self.get_child_text(element, "./fx:TIMINGS/fx:ABSOLUTELY-SCHEDULED-TIMING/fx:BASE-CYCLE")
        cycle_repetition_tmp = self.get_child_text(element, "./fx:TIMINGS/fx:ABSOLUTELY-SCHEDULED-TIMING/fx:CYCLE-REPETITION")

        if slot_id_tmp is not None and ((cycle_counter_tmp is not None) or (base_cycle_tmp is not None and cycle_repetition_tmp is not None)):
            # FlexRay
            slot_id = int(slot_id_tmp)

            # two options in standard: CYCLE-COUNTER or BASE-CYCLE + REPETITION
            cycle_counter = None if cycle_counter_tmp is None else int(cycle_counter_tmp)
            base_cycle = None if base_cycle_tmp is None else int(base_cycle_tmp)
            cycle_repetition = None if cycle_repetition_tmp is None else int(cycle_repetition_tmp)

            conf_factory = self.__conf_factory__
            assert conf_factory is not None
            ret: BaseFrameTriggering = conf_factory.create_frame_triggering_flexray(
                cast(str, id),
                cast(BaseFrame, frame),
                slot_id,
                cycle_counter,
                base_cycle,
                cycle_repetition,
            )
            return ret

        elif identifier_tmp is not None:
            can_id = int(identifier_tmp)
            can_id_ext = str(id_ext_tmp).lower() == "true"
            can_fd = str(fd_frame_rx_tmp).lower() == "can-fd" or str(fd_frame_tx_tmp).lower() == "can-fd"

            conf_factory = self.__conf_factory__
            assert conf_factory is not None
            ret = conf_factory.create_frame_triggering_can(
                cast(str, id), cast(BaseFrame, frame), can_id, is_extended_id=can_id_ext, is_can_fd=can_fd
            )
            return ret

        # Ethernet (or other non-CAN, non-FlexRay) frame — register each PDU instance
        # so that __eth_pdu_insts is populated for FLYNC ContainerPDU generation.
        if frame is not None:
            conf_factory = self.__conf_factory__
            assert conf_factory is not None
            for pi in frame.pdu_instances().values():
                if pi.pdu() is not None:
                    eth_inst = conf_factory.create_ethernet_pdu_instance(pi.__pdu_ref__, self.__eth_pdu_header_id_counter)
                    eth_inst.add_pdu(cast(BaseAbstractPDU, pi.pdu()))
                    self.__eth_pdu_header_id_counter += 1
        return None

    def parse_frame_triggerings(self, root: _Element) -> None:
        for frame_triggering in root.findall(".//fx:FRAME-TRIGGERING", self.__ns__):
            f = self.parse_frame_triggering(frame_triggering)
            if f is not None:
                if f.id() in self.__frame_triggerings__.keys():
                    print(f"WARNING: creating another Frame Triggering with ID: {f.id()}")
                self.__frame_triggerings__[f.id()] = f

    def parse_frame(self, element: _Element, verbose: bool) -> BaseFrame:
        id = self.get_id(element)
        short_name = self.get_child_text(element, "./ho:SHORT-NAME")
        byte_length = self.get_child_text(element, "./fx:BYTE-LENGTH")
        frame_type = self.get_child_text(element, "./fx:FRAME-TYPE")

        pdu_instances: dict[str, BasePDUInstance] = dict()
        for pdu_instance in element.findall("./fx:PDU-INSTANCES/fx:PDU-INSTANCE", self.__ns__):
            pi = self.parse_pdu_instance(pdu_instance)
            if pi is not None:
                pdu = self.get_pdu(pi.__pdu_ref__)
                if pdu is None:
                    print(f"ERROR: Frame {short_name} references unknown PDU {pi.__pdu_ref__}!")
                else:
                    pi.add_pdu(pdu)

                pdu_instances[pi.__id__] = pi

        conf_factory = self.__conf_factory__
        assert conf_factory is not None
        ret = conf_factory.create_frame(
            cast(str, id),
            cast(str, short_name),
            int(cast(str, byte_length)),
            cast(str, frame_type),
            pdu_instances,
        )
        return ret

    def parse_frames(self, root: _Element, verbose: bool) -> None:
        for frame in root.findall(".//fx:FRAMES/fx:FRAME", self.__ns__):
            f = self.parse_frame(frame, verbose)
            if f is not None:
                self.__frames__[f.id()] = f

    def basetype_length(self, coding_dict: dict[str, Any] | None) -> int:
        basetype = self.get_from_dict(coding_dict, "Basetype", "--INVALID--")

        if basetype in ["A_UINT8", "A_INT8"]:
            return 8

        if basetype in ["A_UINT16", "A_INT16"]:
            return 16

        if basetype in ["A_UINT32", "A_INT32", "A_FLOAT32"]:
            return 32

        if basetype in ["A_UINT64", "A_INT64", "A_FLOAT64"]:
            return 64

        # 'A_ASCIISTRING', 'A_UNICODE2STRING', 'A_BYTEFIELD', 'A_BITFIELD', 'OTHER'
        return -1

    def basetype_is_int(self, coding_dict: dict[str, Any] | None) -> bool:
        basetype = self.get_from_dict(coding_dict, "Basetype", "--INVALID--")
        return basetype in [
            "A_UINT8",
            "A_INT8",
            "A_UINT16",
            "A_INT16",
            "A_UINT32",
            "A_INT32",
            "A_UINT64",
            "A_INT64",
        ]

    def basetype_is_float(self, coding_dict: dict[str, Any] | None) -> bool:
        basetype = self.get_from_dict(coding_dict, "Basetype", "--INVALID--")
        return basetype in ["A_FLOAT32", "A_FLOAT64"]

    def basetype_is_string(self, coding_dict: dict[str, Any] | None) -> bool:
        basetype = self.get_from_dict(coding_dict, "Basetype", "--INVALID--")
        return basetype in ["A_ASCIISTRING", "A_UNICODE2STRING"]

    def basetype_is_bitfield(self, coding_dict: dict[str, Any] | None) -> bool:
        basetype = self.get_from_dict(coding_dict, "Basetype", "--INVALID--")
        basetype2 = self.get_from_dict(coding_dict, "Basetype2", "--INVALID--")
        return basetype in ["A_BITFIELD"] or basetype2 in ["A_BITFIELD"]

    def basetype_is_other(self, coding_dict: dict[str, Any] | None) -> bool:
        basetype = self.get_from_dict(coding_dict, "Basetype", "--INVALID--")
        return basetype in ["A_BYTEFIELD", "OTHER"]

    def interpret_datatype(
        self, element: _Element | None, utils: dict[str, Any], serialization_attributes: dict[str, Any]
    ) -> SOMEIPBaseDatatype | None:
        ret: SOMEIPBaseDatatype | None = None
        p: dict[str, Any] = dict()

        assert element is not None
        p["ID"] = self.get_id(element)
        p["OID"] = self.get_oid(element)
        p["Name"] = self.get_child_text(element, "./ho:SHORT-NAME")
        p["Type"] = self.get_attribute(element, "xsi:type")

        if p["ID"] is None or p["Type"] is None:
            print("ERROR: Datatype should have ID and Type!!!")
            return None

        coding1 = cast(dict[str, Any], self.get_from_dict_or_none(utils, "Coding"))
        coding2: dict[str, Any] | None = None
        coding_ref = element.find("fx:CODING-REF", self.__ns__)
        if coding_ref is not None:
            coding2 = self.__codings__[cast(str, self.get_attribute(coding_ref, "ID-REF"))]

        if p["Type"] == "fx:COMMON-DATATYPE-TYPE" or p["Type"] == "fx:ENUM-DATATYPE-TYPE":
            if self.basetype_is_bitfield(coding1):
                bitlenbase = self.get_from_dict(coding2, "BitLength", -1)
                bitlenenct = self.get_from_dict(utils, "BitLength", -1)
                if bitlenenct == -1:
                    bitlenenct = bitlenbase

                # basically a fallback to encode as regular UINT
                conf_factory = self.__conf_factory__
                assert conf_factory is not None
                child = conf_factory.create_someip_parameter_basetype(
                    cast(str, self.get_from_dict_or_none(p, "Name")),
                    cast(str, self.get_from_dict_or_none(coding2, "Basetype")),
                    cast(bool, self.get_from_dict_or_none(utils, "HighLowByteOrder")),
                    bitlenbase,
                    bitlenenct,
                )

                items: dict[int, SOMEIPBaseParameterBitfieldItem] = {}

                for name, value_min, value_max in coding1["CompuConsts"]:
                    if coding1["CompuMethod_Category"] == "BITFIELD-TEXTTABLE":
                        print(f"WARNING: BITFIELD-TEXTTABLE is not supported! Skipping {name}!")
                        continue

                    if not value_min.isdigit() or not value_max.isdigit():
                        continue

                    vmin = int(value_min)
                    vmax = int(value_max)

                    if vmin != vmax:
                        print(f"ERROR: Bitfield ID {coding1['ID']} has for name {name}: min {vmin} != max {vmax}!")
                    elif vmin == 0 and coding1["CompuMethod_Category"] != "BITFIELD-TEXTTABLE":
                        print(f"ERROR: Bitfield ID {coding1['ID']} has for name {name}: value {vmin} is 0!")
                    elif vmin.bit_count() == 1:
                        bit_number = self.value_to_bit(vmin)
                        if bit_number is not None:
                            items[vmin] = conf_factory.create_someip_parameter_bitfield_item(bit_number, name)

                ret = conf_factory.create_someip_parameter_bitfield(
                    cast(str, self.get_from_dict_or_none(p, "Name")),
                    cast(list[SOMEIPBaseParameterBitfieldItem], self.dict_to_sorted_set(items)),
                    child,
                )

            elif self.basetype_is_int(coding2) or self.basetype_is_float(coding2):
                bitlenbase = self.get_from_dict(coding2, "BitLength", -1)
                bitlenenct = self.get_from_dict(utils, "BitLength", -1)
                if bitlenenct == -1:
                    bitlenenct = bitlenbase

                conf_factory = self.__conf_factory__
                assert conf_factory is not None
                if p["Type"] == "fx:COMMON-DATATYPE-TYPE":
                    ret = conf_factory.create_someip_parameter_basetype(
                        cast(str, self.get_from_dict_or_none(p, "Name")),
                        cast(str, self.get_from_dict_or_none(coding2, "Basetype")),
                        cast(bool, self.get_from_dict_or_none(utils, "HighLowByteOrder")),
                        bitlenbase,
                        bitlenenct,
                    )

                elif p["Type"] == "fx:ENUM-DATATYPE-TYPE":
                    ret = conf_factory.create_someip_parameter_basetype(
                        cast(str, self.get_from_dict_or_none(coding2, "Name")),
                        cast(str, self.get_from_dict_or_none(coding2, "Basetype")),
                        cast(bool, self.get_from_dict_or_none(utils, "HighLowByteOrder")),
                        bitlenbase,
                        bitlenenct,
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
                conf_factory = self.__conf_factory__
                assert conf_factory is not None
                ret = conf_factory.create_someip_parameter_string(
                    cast(str, self.get_from_dict_or_none(p, "Name")),
                    enc,
                    cast(bool, self.get_from_dict_or_none(utils, "HighLowByteOrder")),
                    minlen,
                    maxlen,
                    term,
                    lenoflen,
                    pad_to,
                )

            if p["Type"] == "fx:ENUM-DATATYPE-TYPE":

                enum_items: dict[int, SOMEIPBaseParameterEnumerationItem] = {}

                for i in element.findall("./fx:ENUMERATION-ELEMENTS/fx:ENUM-ELEMENT", self.__ns__):
                    value = int(cast(str, self.get_child_text(i, "fx:VALUE")))
                    name = self.get_child_text(i, "fx:SYNONYM")
                    desc = self.get_child_text(i, "ho:DESC")
                    conf_factory = self.__conf_factory__
                    assert conf_factory is not None
                    enum_items[value] = conf_factory.create_someip_parameter_enumeration_item(value, cast(str, name), desc)

                enumitems = self.dict_to_sorted_set(enum_items)

                conf_factory = self.__conf_factory__
                assert conf_factory is not None
                ret = conf_factory.create_someip_parameter_enumeration(
                    cast(str, self.get_from_dict_or_none(p, "Name")),
                    cast(list[SOMEIPBaseParameterEnumerationItem], enumitems),
                    cast(SOMEIPBaseDatatype, ret),
                )

        if p["Type"] == "fx:COMPLEX-DATATYPE-TYPE":
            p["ComplexClass"] = self.get_child_text(element, "fx:COMPLEX-DATATYPE-CLASS")

            member_map: dict[Any, dict[str, Any]] = dict()

            for member in element.findall("fx:MEMBERS/fx:MEMBER", self.__ns__):
                pos, m = self.parse_member(member, p["ComplexClass"])
                member_map[pos] = m

            p["Members"] = self.dict_to_sorted_set(member_map)

            if "Members" in p:
                conf_factory = self.__conf_factory__
                assert conf_factory is not None
                if self.get_from_dict_or_none(p, "ComplexClass") == "STRUCTURE":
                    struct_members: dict[int, SOMEIPBaseParameterStructMember] = dict()
                    for m in p["Members"]:

                        member_child: SOMEIPBaseDatatype | None = self.interpret_datatype(
                            self.get_from_dict_or_none(
                                self.__datatypes__,
                                cast(str, self.get_from_dict_or_none(m, "DatatypeRef")),
                            ),
                            cast(dict[str, Any], self.get_from_dict_or_none(m, "Utilization")),
                            cast(dict[str, Any], self.get_from_dict_or_none(m, "SerializationAttributes")),
                        )

                        if "Array" in m and m["Array"] is not None:
                            member_child = self.build_array(
                                m["Name"],
                                self.get_from_dict(serialization_attributes, "ArrayLengthSize", -1),
                                m["Array"],
                                cast(SOMEIPBaseDatatype, member_child),
                            )

                        signal = self.get_from_dict_or_none(self.__signals__, cast(str, self.get_from_dict_or_none(m, "SignalRef")))

                        member_obj = conf_factory.create_someip_parameter_struct_member(
                            int(m["Position"]), m["Name"], bool(m["Mandatory"]), cast(SOMEIPBaseDatatype, member_child), signal
                        )
                        struct_members[int(m["Position"])] = member_obj
                    len_of_len = self.get_from_dict(serialization_attributes, "LengthFieldSize", 0)
                    padto = 0
                    ret = conf_factory.create_someip_parameter_struct(p["Name"], len_of_len, padto, struct_members)

                elif self.get_from_dict_or_none(p, "ComplexClass") == "UNION":
                    union_members: dict[int, SOMEIPBaseParameterUnionMember] = dict()
                    for m in p["Members"]:
                        union_child = self.interpret_datatype(
                            self.get_from_dict_or_none(
                                self.__datatypes__,
                                cast(str, self.get_from_dict_or_none(m, "DatatypeRef")),
                            ),
                            cast(dict[str, Any], self.get_from_dict_or_none(m, "Utilization")),
                            cast(dict[str, Any], self.get_from_dict_or_none(m, "SerializationAttributes")),
                        )

                        if "Array" in m and m["Array"] is not None:
                            union_child = self.build_array(
                                m["Name"],
                                self.get_from_dict(serialization_attributes, "ArrayLengthSize", -1),
                                m["Array"],
                                cast(SOMEIPBaseDatatype, union_child),
                            )

                        member_union = conf_factory.create_someip_parameter_union_member(
                            int(m["Index"]), m["Name"], bool(m["Mandatory"]), cast(SOMEIPBaseDatatype, union_child)
                        )

                        union_members[int(m["Index"])] = member_union

                    len_of_len = self.get_from_dict(serialization_attributes, "LengthFieldSize", 32)
                    len_of_type = self.get_from_dict(serialization_attributes, "TypeFieldSize", 32)
                    padto = 0
                    ret = conf_factory.create_someip_parameter_union(p["Name"], len_of_len, len_of_type, padto, union_members)

                elif self.get_from_dict_or_none(p, "ComplexClass") == "TYPEDEF":
                    typedef_child: SOMEIPBaseDatatype | None = None
                    childname: str | None = None
                    for m in p["Members"]:

                        if "Position" in m and m["Position"] == 0:

                            typedef_child = self.interpret_datatype(
                                self.get_from_dict_or_none(
                                    self.__datatypes__,
                                    cast(str, self.get_from_dict_or_none(m, "DatatypeRef")),
                                ),
                                self.merge_utilizations(utils, cast(dict[str, Any], self.get_from_dict_or_none(m, "Utilization"))),
                                cast(dict[str, Any], self.get_from_dict_or_none(m, "SerializationAttributes")),
                            )

                            childname = self.get_from_dict(m, "Name", "")

                            if "Array" in m and m["Array"] is not None:
                                typedef_child = self.build_array(
                                    m["Name"],
                                    self.get_from_dict(serialization_attributes, "ArrayLengthSize", -1),
                                    m["Array"],
                                    cast(SOMEIPBaseDatatype, typedef_child),
                                )

                        ret = conf_factory.create_someip_parameter_typedef(p["Name"], cast(str, childname), cast(SOMEIPBaseDatatype, typedef_child))

            else:
                print("ERROR: ComplexClass: %s Members: %d is not understood" % (self.get_from_dict_or_none(p, "ComplexClass"), len(p)))

        if ret is None:
            print(
                "WARNING: interpretDatatype(%s, %s, %s, %s, %s, %s) returns None!!!!!!!"
                % (
                    element,
                    utils,
                    serialization_attributes,
                    p["ID"],
                    p["Name"],
                    p["Type"],
                )
            )

        return ret

    def parse_datatypes(self, root: _Element) -> None:
        self.__datatypes__ = dict()

        for datatype in root.findall(".//fx:DATATYPES/fx:DATATYPE", self.__ns__):
            did = self.get_id(datatype)
            if did is not None:
                self.__datatypes__[did] = datatype

    def parse_array(self, element: _Element) -> dict[int, dict[str, Any]] | None:
        ret: dict[int, dict[str, Any]] | None = None

        for dimension in element.findall("./fx:ARRAY-DECLARATION/fx:ARRAY-DIMENSION", self.__ns__):
            if ret is None:
                ret = dict()
            minsize_elem = dimension.find("fx:MINIMUM-SIZE", self.__ns__)
            maxsize_elem = dimension.find("fx:MAXIMUM-SIZE", self.__ns__)
            dim_elem = dimension.find("fx:DIMENSION", self.__ns__)
            bit_elem = dimension.find("fx:BIT-ALIGNMENT", self.__ns__)
            minsize = 0 if minsize_elem is None else self.element_text_to_int(minsize_elem, 0)
            maxsize = -1 if maxsize_elem is None else self.element_text_to_int(maxsize_elem, -1)
            dim = -1 if dim_elem is None else self.element_text_to_int(dim_elem, -1)
            bit = 0 if bit_elem is None else self.element_text_to_int(bit_elem, 0)

            if dim > 0:
                ret[dim] = {
                    "dim": dim,
                    "max": maxsize,
                    "min": minsize,
                    "bitalignment": bit,
                }
            else:
                print(f"ERROR: dim {dim} is less than 1!")

        return ret

    def build_array(
        self,
        name: str,
        lengthoflength: int,
        arrayspec: dict[int, dict[str, Any]],
        child: SOMEIPBaseDatatype,
    ) -> SOMEIPBaseParameterArray:
        dims: dict[int, SOMEIPBaseParameterArrayDim] = dict()
        for a in sorted(arrayspec.keys()):
            arraydim = arrayspec[a]
            dim = self.get_from_dict_or_none(arraydim, "dim")

            conf_factory = self.__conf_factory__
            assert conf_factory is not None
            d = conf_factory.create_someip_parameter_array_dim(
                cast(int, dim),
                self.get_from_dict(arraydim, "min", 0),
                self.get_from_dict(arraydim, "max", -1),
                lengthoflength,
                self.get_from_dict(arraydim, "bitalignment", 0),
            )
            dims[cast(int, dim)] = d

        conf_factory = self.__conf_factory__
        assert conf_factory is not None
        return conf_factory.create_someip_parameter_array(name, dims, child)

    def parse_parameter(self, param: _Element) -> tuple[int | None, SOMEIPBaseParameter, dict[str, Any]]:
        p: dict[str, Any] = dict()
        p["ID"] = self.get_id(param)
        p["OID"] = self.get_oid(param)
        p["Name"] = self.get_child_text(param, "./ho:SHORT-NAME")
        p["Desc"] = self.element_text(param.find("./ho:DESC", self.__ns__))
        p["Mandatory"] = self.element_text(param.find("./service:MANDATORY", self.__ns__))
        p["Mandatory"] = str(p["Mandatory"]).upper() == "TRUE"

        p["Position"] = self.element_text(param.find("./service:POSITION", self.__ns__))
        if p["Position"] is not None:
            p["Position"] = int(p["Position"])

        dt = self.get_child_attribute(param, "./fx:DATATYPE-REF", "ID-REF")
        p["Datatype"] = self.get_from_dict_or_none(self.__datatypes__, cast(str, dt))
        if p["Datatype"] is None:
            print("ERROR: Parameter without datatype is kind of strange!!!")

        s = self.get_child_attribute(param, "./fx:SIGNAL-REF", "ID-REF")
        signal = None
        if s is not None:
            signal = self.get_from_dict_or_none(self.__signals__, s)

        p["Array"] = self.parse_array(param)
        utils = self.parse_utilization(param)
        serialization_attributes = self.parse_serialization_attributes(param)

        dt = self.get_from_dict_or_none(p, "Datatype")

        ret = self.interpret_datatype(dt, utils, serialization_attributes)

        if "Array" in p and p["Array"] is not None:
            ret = self.build_array(
                cast(str, p["Name"]),
                serialization_attributes["ArrayLengthSize"],
                cast(dict[int, dict[str, Any]], p["Array"]),
                cast(SOMEIPBaseDatatype, ret),
            )

        conf_factory = self.__conf_factory__
        assert conf_factory is not None
        return (
            cast(int | None, p["Position"]),
            conf_factory.create_someip_parameter(p["Position"], p["Name"], p["Desc"], p["Mandatory"], ret, cast(BaseSignal | None, signal)),
            p,
        )

    def parse_method(self, element: _Element) -> tuple[str | None, SOMEIPBaseServiceMethod]:
        id = self.get_id(element)
        name = self.get_child_text(element, "./ho:SHORT-NAME")
        method_id = int(cast(str, self.get_child_text(element, "./service:METHOD-IDENTIFIER")))

        reliable = "true" == self.get_child_text(element, "./service:RELIABLE")
        call_type = self.get_child_text(element, "./service:CALL-SEMANTIC")
        if call_type is None:
            call_type = "REQUEST_RESPONSE"

        inparams: dict[int, SOMEIPBaseParameter] = dict()
        for param in element.findall("./service:INPUT-PARAMETERS/service:INPUT-PARAMETER", self.__ns__):
            pos, p = self.parse_parameter(param)[:2]
            inparams[cast(int, pos)] = p

        outparams: dict[int, SOMEIPBaseParameter] = dict()
        for param in element.findall("./service:RETURN-PARAMETERS/service:RETURN-PARAMETER", self.__ns__):
            pos, p = self.parse_parameter(param)[:2]
            outparams[cast(int, pos)] = p

        debouncereq = -1
        retentionreq = -1
        retentionres = -1

        conf_factory = self.__conf_factory__
        assert conf_factory is not None
        m = conf_factory.create_someip_service_method(
            cast(str, name),
            method_id,
            cast(CallSemantic, call_type),
            reliable,
            sorted(inparams.values(), key=lambda x: x.position()),
            sorted(outparams.values(), key=lambda x: x.position()),
            debouncereq,
            retentionreq,
            retentionres,
        )
        return id, m

    def parse_event(self, element: _Element) -> tuple[str | None, SOMEIPBaseServiceEvent]:
        id = self.get_id(element)
        name = self.get_child_text(element, "./ho:SHORT-NAME")
        method_id = int(cast(str, self.get_child_text(element, "./service:METHOD-IDENTIFIER")))

        reliable = "true" == self.get_child_text(element, "./service:RELIABLE")

        debounce = -1
        retention = -1

        params: dict[int, SOMEIPBaseParameter] = dict()
        for param in element.findall("./service:INPUT-PARAMETERS/service:INPUT-PARAMETER", self.__ns__):
            pos, p = self.parse_parameter(param)[:2]
            params[cast(int, pos)] = p

        conf_factory = self.__conf_factory__
        assert conf_factory is not None
        m = conf_factory.create_someip_service_event(
            cast(str, name),
            method_id,
            reliable,
            sorted(params.values(), key=lambda x: x.position()),
            debounce,
            retention,
        )
        return id, m

    def parse_field(self, element: _Element) -> tuple[str | None, SOMEIPBaseServiceField] | None:
        id = self.get_id(element)
        name = self.get_child_text(element, "./ho:SHORT-NAME")

        getter_id_txt = self.get_child_text(element, "./service:GETTER/service:METHOD-IDENTIFIER")
        setter_id_txt = self.get_child_text(element, "./service:SETTER/service:METHOD-IDENTIFIER")
        notifier_id_txt = self.get_child_text(element, "./service:NOTIFIER/service:NOTIFICATION-IDENTIFIER")

        getter_id: int | None = int(getter_id_txt) if getter_id_txt is not None else None
        setter_id: int | None = int(setter_id_txt) if setter_id_txt is not None else None
        notifier_id: int | None = int(notifier_id_txt) if notifier_id_txt is not None else None

        getter_reli = "true" == self.get_child_text(element, "./service:GETTER/service:RELIABLE")
        setter_reli = "true" == self.get_child_text(element, "./service:SETTER/service:RELIABLE")
        notifier_reli = "true" == self.get_child_text(element, "./service:NOTIFIER/service:RELIABLE")

        dt = self.get_child_attribute(element, "./fx:DATATYPE-REF", "ID-REF")
        if dt is None:
            print(f"ERROR: We are missing a datatype for {element}")
            return None

        datatype = self.get_from_dict_or_none(self.__datatypes__, dt)
        if datatype is None:
            print(f"ERROR: Unknown Datatype: {dt}")
            return None

        signal: BaseSignal | None = None
        s = self.get_child_attribute(element, "./fx:SIGNAL-REF", "ID-REF")
        if s is not None:
            signal = self.get_from_dict_or_none(self.__signals__, s)
            if signal is None:
                print(f"ERROR: Unknown Signal: {s}")
                return None

        array_declaration = self.parse_array(element)

        utils = self.parse_utilization(element)
        serialization_attributes = self.parse_serialization_attributes(element)

        params: list[SOMEIPBaseParameter] = []
        child = self.interpret_datatype(datatype, utils, serialization_attributes)

        if array_declaration is not None:
            child = self.build_array(
                f"{name}_array",
                serialization_attributes["ArrayLengthSize"],
                array_declaration,
                cast(SOMEIPBaseDatatype, child),
            )

        conf_factory = self.__conf_factory__
        assert conf_factory is not None
        params += [conf_factory.create_someip_parameter(0, "fieldparam", "", True, child, signal)]

        getter_debouncereq = -1
        getter_retentionreq = -1
        getter_retentionres = -1
        setter_debouncereq = -1
        setter_retentionreq = -1
        setter_retentionres = -1
        notifier_debounce = -1
        notifier_retention = -1

        f = conf_factory.create_someip_service_field(
            cast(str, name),
            getter_id,
            setter_id,
            notifier_id,
            getter_reli,
            setter_reli,
            notifier_reli,
            params,
            getter_debouncereq,
            getter_retentionreq,
            getter_retentionres,
            setter_debouncereq,
            setter_retentionreq,
            setter_retentionres,
            notifier_debounce,
            notifier_retention,
        )
        return id, f

    def parse_eventgroup(
        self,
        element: _Element,
        serviceid: str | None,
        events: dict[str, int] | None,
        fields: dict[str, int | None] | None,
    ) -> tuple[str | None, SOMEIPBaseServiceEventgroup]:
        id = self.get_id(element)
        name = self.get_child_text(element, "./ho:SHORT-NAME")
        egid = self.get_child_text(element, "./fx:SERVICE-IDENTIFIER")
        eventids: list[int] = []
        notifierids: list[int] = []

        for eventref in element.findall("./service:EVENT-REFS/service:EVENT-REF", self.__ns__):
            ref = self.get_attribute(eventref, "ID-REF")
            if events is not None and ref in events:
                eventids += [events[ref]]
            else:
                print(f"ERROR: Eventgroup {id} has EVENT-REF to {ref} but I cannot find the Event!")

        for fieldref in element.findall("./service:FIELD-REFS/service:FIELD-REF", self.__ns__):
            ref = self.get_attribute(fieldref, "ID-REF")
            if fields is not None and ref in fields:
                notifierids += [cast(int, fields[ref])]
            else:
                print("ERROR: Eventgroup %s has FIELD-REF to %s but I cannot find the Field!" % (id, ref))

        self.__eventgrouprefs__[cast(str, id)] = (serviceid, cast(int | None, egid))
        conf_factory = self.__conf_factory__
        assert conf_factory is not None
        return (
            id,
            conf_factory.create_someip_service_eventgroup(cast(str, name), cast(int, egid), eventids, notifierids),
        )

    def parse_service(self, service: _Element) -> tuple[str | None, SOMEIPBaseService]:
        id: str | None = None
        sid = self.get_id(service)
        name = self.get_child_text(service, "./ho:SHORT-NAME")
        service_id = int(cast(str, self.get_child_text(service, "./fx:SERVICE-IDENTIFIER")))

        try:
            major_version = int(cast(str, self.get_child_text(service, "./service:API-VERSION/service:MAJOR")))
        except TypeError:
            print(f"ERROR: Service {name} does not have a major version! Using 1!")
            major_version = 1

        try:
            minor_version = int(cast(str, self.get_child_text(service, "./service:API-VERSION/service:MINOR")))
        except TypeError:
            print(f"ERROR: Service {name} does not have a minor version! Using 0!")
            minor_version = 0

        methods: dict[int, SOMEIPBaseServiceMethod] = dict()
        for method in service.findall("./service:METHODS/service:METHOD", self.__ns__):
            id, m = self.parse_method(method)
            methods[m.methodid()] = m

        eventids: dict[str, int] = dict()
        events: dict[int, SOMEIPBaseServiceEvent] = dict()
        for event in service.findall("./service:EVENTS/service:EVENT", self.__ns__):
            id, e = self.parse_event(event)
            events[e.methodid()] = e
            eventids[cast(str, id)] = e.methodid()

        fieldids: dict[str, int | None] = dict()
        fields: dict[int, SOMEIPBaseServiceField] = dict()
        for field in service.findall("./service:FIELDS/service:FIELD", self.__ns__):
            field_result = self.parse_field(field)
            assert field_result is not None
            id, f = field_result
            fields[cast(int, f.id())] = f
            fieldids[cast(str, id)] = f.notifierid()

        eventgroups: dict[int, SOMEIPBaseServiceEventgroup] = dict()
        for eg_el in service.findall("./service:EVENT-GROUPS/service:EVENT-GROUP", self.__ns__):
            id, eg = self.parse_eventgroup(eg_el, id, eventids, fieldids)
            eventgroups[eg.id()] = eg

        conf_factory = self.__conf_factory__
        assert conf_factory is not None
        s = conf_factory.create_someip_service(
            cast(str, name),
            service_id,
            major_version,
            minor_version,
            methods,
            events,
            fields,
            eventgroups,
        )
        return sid, s

    def parse_member(self, element: _Element, t: str | None) -> tuple[int | None, dict[str, Any]]:
        p: dict[str, Any] = dict()

        p["ID"] = self.get_id(element)
        p["OID"] = self.get_oid(element)
        p["Name"] = self.get_child_text(element, "./ho:SHORT-NAME")

        p["DatatypeRef"] = self.get_child_attribute(element, "fx:DATATYPE-REF", "ID-REF")
        p["SignalRef"] = self.get_child_attribute(element, "fx:SIGNAL-REF", "ID-REF")

        index_elem = element.find("fx:INDEX", self.__ns__)
        p["Index"] = -1 if index_elem is None else self.element_text_to_int(index_elem, -1)

        position_elem = element.find("fx:POSITION", self.__ns__)
        position = int(cast(str, position_elem.text)) if position_elem is not None else None
        p["Position"] = position

        mandatory_elem = element.find("fx:MANDATORY", self.__ns__)
        mandatory = (str(mandatory_elem.text).upper() == "TRUE") if mandatory_elem is not None else None
        p["Mandatory"] = mandatory

        p["Utilization"] = self.parse_utilization(element)
        p["SerializationAttributes"] = self.parse_serialization_attributes(element)
        p["Array"] = self.parse_array(element)

        pos: int | None = -1
        if t == "STRUCTURE" or t == "TYPEDEF":
            pos = int(p["Position"])
        elif t == "UNION":
            pos = int(p["Index"])

        return pos, p

    def parse_services(self, root: _Element) -> None:
        self.__services__ = dict()

        for service in root.findall(".//fx:SERVICE-INTERFACE", self.__ns__):
            id, s = self.parse_service(service)
            self.__services__[cast(str, id)] = s

    def parse_channels(self, root: _Element) -> None:
        for ch in root.findall(".//fx:CHANNELS/fx:CHANNEL", self.__ns__):
            channel: dict[str, Any] = dict()
            channel["id"] = self.get_id(ch)
            channel["name"] = self.get_child_text(ch, "ho:SHORT-NAME")

            channel["flexray-channel-name"] = self.get_child_text(ch, "flexray:FLEXRAY-CHANNEL-NAME")

            channel["vlanid"] = None
            channel["vlanname"] = None

            channel["frametriggerings"] = {}

            for v in ch.findall("ethernet:VIRTUAL-LAN", self.__ns__):
                # = self.ID(v)
                if channel["vlanid"] is not None:
                    print("WARNING: We have found a channel with more than 1 VLAN. We are skipping those.")
                else:
                    channel["vlanid"] = self.get_child_text(v, "ethernet:VLAN-IDENTIFIER")
                    channel["vlanname"] = self.get_child_text(v, "ho:SHORT-NAME")

            self.__channels__[channel["id"]] = channel

    def parse_neps(self, element: _Element) -> dict[str, dict[str, Any]]:
        neps: dict[str, dict[str, Any]] = dict()
        for n in element.findall("it:NETWORK-ENDPOINTS/it:NETWORK-ENDPOINT", self.__ns__):
            nep: dict[str, Any] = dict()
            nep["id"] = self.get_id(n)
            nep["name"] = self.get_child_text(n, "it:MANUFACTURER-EXTENSION/ho:SHORT-NAME")

            ipsv4: list[dict[str, Any]] = []
            for i in n.findall(
                "it:NETWORK-ENDPOINT-ADDRESSES/it:NETWORK-ENDPOINT-ADDRESS/it:IPV4",
                self.__ns__,
            ):
                ip: dict[str, Any] = dict()
                ip["addr"] = self.get_child_text(i, "it:IP-ADDRESS")
                ip["addrsrc"] = self.get_child_text(i, "it:IPV4-ADDRESS-SOURCE")
                ip["netmask"] = self.get_child_text(i, "it:NETWORKMASK")
                ipsv4 += [ip]

                if ip["addr"] is not None and ip["netmask"] is not None:
                    conf_factory = self.__conf_factory__
                    assert conf_factory is not None
                    conf_factory.add_ipv4_address_config(ip["addr"], ip["netmask"])
            nep["ipsv4"] = ipsv4

            ipsv6: list[dict[str, Any]] = []
            for i in n.findall(
                "it:NETWORK-ENDPOINT-ADDRESSES/it:NETWORK-ENDPOINT-ADDRESS/it:IPV6",
                self.__ns__,
            ):
                ip = dict()
                ip["addr"] = self.get_child_text(i, "it:IPV6-ADDRESS")
                ip["addrsrc"] = self.get_child_text(i, "it:IPV6-ADDRESS-SOURCE")
                ip["prefixlen"] = self.get_child_text(i, "it:IP-ADDRESS-PREFIX-LENGTH")
                ipsv6 += [ip]

                if ip["addr"] is not None and ip["prefixlen"] is not None:
                    conf_factory = self.__conf_factory__
                    assert conf_factory is not None
                    conf_factory.add_ipv6_address_config(ip["addr"], ip["prefixlen"])
            nep["ipsv6"] = ipsv6

            neps[cast(str, nep["id"])] = nep

        return neps

    def parse_psis(self, root: _Element) -> None:
        seen_providers: dict[str, set[tuple[int, int, int]]] = {}
        for aep in root.findall(".//it:APPLICATION-ENDPOINT", self.__ns__):
            protover_txt = self.get_child_text(aep, "it:SERIALIZATION-TECHNOLOGY/it:VERSION")
            protover = 1 if protover_txt is None else protover_txt

            aepid = self.get_id(aep)
            for psi in aep.findall(
                "it:PROVIDED-SERVICE-INSTANCES/it:PROVIDED-SERVICE-INSTANCE",
                self.__ns__,
            ):
                id = self.get_id(psi)
                instanceid = self.get_child_text(psi, "it:INSTANCE-IDENTIFIER")
                servref = self.get_child_attribute(psi, "service:SERVICE-INTERFACE-REF", "ID-REF")
                if servref not in self.__services__:
                    print(f"ERROR in FIBEX: I cannot find Service {servref}")
                else:
                    service = self.__services__[servref]

                    conf_factory = self.__conf_factory__
                    assert conf_factory is not None
                    si = conf_factory.create_someip_service_instance(service, cast(int, instanceid), cast(int, protover))
                    self.__ServiceInstances__[cast(str, id)] = si

                    if aepid not in self.__aeps__:
                        self.__aeps__[cast(str, aepid)] = ([], [], [], [])

                    pkey = (service.serviceid(), service.majorversion(), si.instanceid())
                    if pkey in seen_providers.setdefault(cast(str, aepid), set()):
                        print(
                            f"WARNING: SOME/IP ServiceInstance (service=0x{service.serviceid():04x}, "
                            f"major_version={service.majorversion()}, instance_id={si.instanceid()}) "
                            f"is provided more than once in application endpoint {cast(str, aepid)!r}."
                        )
                    else:
                        seen_providers[cast(str, aepid)].add(pkey)

                    psis, csis, ehs, cegs = self.__aeps__[cast(str, aepid)]
                    self.__aeps__[cast(str, aepid)] = (psis + [si], csis, ehs, cegs)

    def parse_psis_pass_two(self, root: _Element) -> None:
        for aep in root.findall(".//it:APPLICATION-ENDPOINT", self.__ns__):
            # protover = self.get_child_text(aep, 'it:SERIALIZATION-TECHNOLOGY/it:VERSION')
            # if protover is None:
            #    protover = 1

            aepid = self.get_id(aep)
            for cegrefs in aep.findall(
                "it:PROVIDED-SERVICE-INSTANCES/it:PROVIDED-SERVICE-INSTANCE/" + "it:EVENT-HANDLERS/it:EVENT-HANDLER/it:CONSUMED-EVENT-GROUP-REFS",
                self.__ns__,
            ):

                eh: SOMEIPBaseServiceEventgroupSender | None = None
                ref: str | None = None
                for cegref in cegrefs.findall("it:CONSUMED-EVENT-GROUP-REF", self.__ns__):
                    ref = self.get_attribute(cegref, "ID-REF")

                if ref not in self.__ServiceEventgroupReceiver__:
                    print(f"ERROR in FIBEX: I cannot find the CEGREF {ref}!")
                else:
                    egreceiver = self.__ServiceEventgroupReceiver__[ref]

                    if eh is None:
                        conf_factory = self.__conf_factory__
                        assert conf_factory is not None
                        eh = conf_factory.create_someip_service_eventgroup_sender(egreceiver.serviceinstance(), egreceiver.eventgroupid())
                        eh.addreceiver(egreceiver)

                    if aepid not in self.__aeps__:
                        self.__aeps__[cast(str, aepid)] = ([], [], [], [])

                    psis, csis, ehs, cegs = self.__aeps__[cast(str, aepid)]
                    self.__aeps__[cast(str, aepid)] = (psis, csis, ehs + [eh], cegs)

    @staticmethod
    def _client_key(client: SOMEIPBaseServiceInstanceClient) -> tuple[int, int, int]:
        return (client.service().serviceid(), client.service().majorversion(), client.instanceid())

    @staticmethod
    def _receiver_key(receiver: SOMEIPBaseServiceEventgroupReceiver) -> tuple[int, int, int]:
        si = receiver.serviceinstance()
        return (si.service().serviceid(), si.instanceid(), receiver.eventgroupid())

    def parse_csis_and_cegs(self, root: _Element) -> None:
        seen_clients: dict[str, set[tuple[int, int, int]]] = {}
        seen_receivers: dict[str, set[tuple[int, int, int]]] = {}
        for aep in root.findall(".//it:APPLICATION-ENDPOINT", self.__ns__):

            aepid = self.get_id(aep)
            for csi in aep.findall(
                "it:CONSUMED-SERVICE-INSTANCES/it:CONSUMED-SERVICE-INSTANCE",
                self.__ns__,
            ):
                psiid = self.get_child_attribute(csi, "it:PROVIDED-SERVICE-INSTANCE-REF", "ID-REF")

                if psiid in self.__ServiceInstances__:
                    si = self.__ServiceInstances__[psiid]

                    conf_factory = self.__conf_factory__
                    assert conf_factory is not None
                    tmp = conf_factory.create_someip_service_instance_client(si.service(), si.instanceid(), si.protover(), si)

                    if aepid not in self.__aeps__:
                        self.__aeps__[cast(str, aepid)] = ([], [], [], [])

                    psis, csis, ehs, cegs = self.__aeps__[cast(str, aepid)]
                    if self.__keep_duplicates__:
                        self.__aeps__[cast(str, aepid)] = (psis, csis + [tmp], ehs, cegs)
                    else:
                        ckey = self._client_key(tmp)
                        if ckey in seen_clients.setdefault(cast(str, aepid), set()):
                            print(
                                f"WARNING: Skipping duplicate SOME/IP ServiceInstanceClient for "
                                f"(service=0x{tmp.service().serviceid():04x}, major_version={tmp.service().majorversion()}, "
                                f"instance_id={tmp.instanceid()}) in application endpoint {cast(str, aepid)!r}."
                            )
                        else:
                            seen_clients[cast(str, aepid)].add(ckey)
                            self.__aeps__[cast(str, aepid)] = (psis, csis + [tmp], ehs, cegs)

                    for ceg in csi.findall("it:CONSUMED-EVENT-GROUPS/it:CONSUMED-EVENT-GROUP", self.__ns__):
                        cegid = self.get_id(ceg)
                        egref = self.get_child_attribute(ceg, "service:EVENT-GROUP-REF", "ID-REF")
                        aepref = self.get_child_attribute(ceg, "it:APPLICATION-ENDPOINT-REF", "ID-REF")

                        if egref not in self.__eventgrouprefs__:
                            print(f"ERROR in FIBEX: I cannot find Eventgroup {egref}!")

                        else:
                            egid = self.__eventgrouprefs__[egref][1]
                            conf_factory = self.__conf_factory__
                            assert conf_factory is not None
                            tmp2 = conf_factory.create_someip_service_eventgroup_receiver(si, cast(int, egid), None)

                            if cegid not in self.__ServiceEventgroupReceiver__.keys():
                                self.__ServiceEventgroupReceiver__[cast(str, cegid)] = tmp2
                            else:
                                print(f"ERROR in FIBEX: The CEG ID seems to be not unique {egid}!")

                            if aepref not in self.__aeps__:
                                self.__aeps__[cast(str, aepref)] = ([], [], [], [])

                            psis, csis, ehs, cegs = self.__aeps__[cast(str, aepref)]
                            if self.__keep_duplicates__:
                                self.__aeps__[cast(str, aepref)] = (psis, csis, ehs, cegs + [tmp2])
                            else:
                                rkey = self._receiver_key(tmp2)
                                if rkey in seen_receivers.setdefault(cast(str, aepref), set()):
                                    print(
                                        f"WARNING: Skipping duplicate SOME/IP EventgroupReceiver for "
                                        f"(service=0x{tmp2.serviceinstance().service().serviceid():04x}, "
                                        f"instance_id={tmp2.serviceinstance().instanceid()}, "
                                        f"eventgroup_id={tmp2.eventgroupid()}) in application endpoint {cast(str, aepref)!r}."
                                    )
                                else:
                                    seen_receivers[cast(str, aepref)].add(rkey)
                                    self.__aeps__[cast(str, aepref)] = (psis, csis, ehs, cegs + [tmp2])

                else:
                    print(f"ERROR in FIBEX: Cannot find PSI {psiid}")

    def parse_generic_frame_triggering_ref(
        self, root: _Element, path: str, frametriggerings: dict[str, BaseFrameTriggering]
    ) -> dict[str, BaseFrameTriggering]:
        ret: dict[str, BaseFrameTriggering] = {}
        for port in root.findall(path, self.__ns__):
            frame_triggering_id = self.get_child_attribute(port, "./fx:FRAME-TRIGGERING-REF", "ID-REF")

            tmp = self.__frame_triggerings__.get(cast(str, frame_triggering_id), None)
            if tmp is None:
                print(f"WARNING: FrameTriggering {frame_triggering_id} not found!")
            else:
                ret[tmp.calc_key()] = tmp
                frametriggerings[tmp.calc_key()] = tmp

        return ret

    def parse_inputs_outputs(
        self, root: _Element, channel_fts: dict[str, BaseFrameTriggering]
    ) -> tuple[dict[str, BaseFrameTriggering], dict[str, BaseFrameTriggering]]:
        input_ports = self.parse_generic_frame_triggering_ref(root, "./fx:INPUTS/fx:INPUT-PORT", channel_fts)
        output_ports = self.parse_generic_frame_triggering_ref(root, "./fx:OUTPUTS/fx:OUTPUT-PORT", channel_fts)

        return input_ports, output_ports

    @staticmethod
    def lookup_dyn_port(name: str) -> int:
        # we could add code here to determine real port based on name
        return -1

    @staticmethod
    def convert_to_ip_address(ip: dict[str, Any], none_value: str, extra_info: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
        try:
            if ip["addr"] is None:
                return ipaddress.ip_address(none_value)
            else:
                return ipaddress.ip_address(ip["addr"])
        except ValueError:
            print(f"ERROR: FIBEX has illegal IP address definition: {ip} {extra_info}! Skipping!")
        return None

    def parse_ecus(self, root: _Element) -> None:
        self.parse_psis(root)
        self.parse_csis_and_cegs(root)
        self.parse_psis_pass_two(root)

        for e in root.findall(".//fx:ECUS/fx:ECU", self.__ns__):
            ecu_name = self.get_child_text(e, "ho:SHORT-NAME")
            ecu_id = self.get_attribute(e, "ID")

            ctrls: dict[str, dict[str, Any]] = dict()
            for c in e.findall("fx:CONTROLLERS/fx:CONTROLLER", self.__ns__):
                ctrl_info: dict[str, Any] = dict()
                ctrl_info["id"] = self.get_id(c)
                ctrl_info["name"] = self.get_child_text(c, "ho:SHORT-NAME")
                ctrl_info["conns"] = []
                ctrl_info["ifaces"] = []
                ctrls[cast(str, ctrl_info["id"])] = ctrl_info

            for c in e.findall("fx:CONNECTORS/fx:CONNECTOR", self.__ns__):
                channelref = self.get_child_attribute(c, "fx:CHANNEL-REF", "ID-REF")
                ctrlref = self.get_child_attribute(c, "fx:CONTROLLER-REF", "ID-REF")

                ctrl = None
                if ctrlref in ctrls:
                    ctrl = ctrls[ctrlref]
                else:
                    print(f"FIBEX WARNING: I cannot find controller with ref {ctrlref} " f"for connector {self.get_id(c)}! Creating dummy myself!")

                    # creating dummy controller since we need to link ECU and Interface
                    ctrl = dict()
                    ctrl["id"] = self.get_id(c)
                    ctrl["name"] = self.get_id(c)
                    ctrl["conns"] = []
                    ctrl["ifaces"] = []
                    ctrls[cast(str, ctrl["id"])] = ctrl
                assert ctrl is not None

                channel: dict[str, Any] | None
                channel_fts: dict[str, BaseFrameTriggering]
                if channelref in self.__channels__:
                    channel = self.__channels__[channelref]
                    channel_fts = channel.get("frametriggerings", {})
                else:
                    channel = None
                    print(f"ERROR in FIBEX: I cannot find channel '{channelref}' (ID: {self.get_id(c)})")
                    channel_fts = {}

                input_frame_trigs, output_frame_trigs = self.parse_inputs_outputs(c, channel_fts)

                interface_ips: list[ipaddress.IPv4Address | ipaddress.IPv6Address | None] = []
                sockets: list[BaseSocket] = []
                neps = self.parse_neps(c)

                for nepref, nep in neps.items():
                    ips: list[ipaddress.IPv4Address | ipaddress.IPv6Address | None] = []
                    if "ipsv4" in nep:
                        for ip in nep["ipsv4"]:
                            ips.append(self.convert_to_ip_address(ip, "0.0.0.0", f"IPv4. ctrl: {ctrl["name"]}"))
                    if "ipsv6" in nep:
                        for ip in nep["ipsv6"]:
                            ips.append(self.convert_to_ip_address(ip, "::0", f"IPv6. ctrl: {ctrl["name"]}"))

                    for ip in ips:
                        if ip not in interface_ips:
                            interface_ips.append(ip)

                for aep in c.findall("it:APPLICATION-ENDPOINTS/it:APPLICATION-ENDPOINT", self.__ns__):
                    aep_id = self.get_id(aep)

                    if aep_id in self.__aeps__:
                        sis, csis, ehs, cegs = self.__aeps__[aep_id]
                    else:
                        sis, csis, ehs, cegs = [], [], [], []

                    aep_name = self.get_child_text(aep, "it:MANUFACTURER-EXTENSION/ho:SHORT-NAME")
                    if aep_name is None:
                        aep_name = self.get_child_text(aep, "ho:SHORT-NAME")
                    aep_nepref = self.get_child_attribute(aep, "it:NETWORK-ENDPOINT-REF", "ID-REF")

                    if aep_nepref in neps:
                        nep = neps[aep_nepref]
                    else:
                        print("ERROR in FIBEX: I cannot find NEP %s — skipping AEP %s" % (aep_nepref, aep_name))
                        continue

                    ips = []
                    if "ipsv4" in nep:
                        for ip in nep["ipsv4"]:
                            ips.append(self.convert_to_ip_address(ip, "0.0.0.0", f"IPv4. AEP: {aep_name}"))
                    if "ipsv6" in nep:
                        for ip in nep["ipsv6"]:
                            ips.append(self.convert_to_ip_address(ip, "::0", f"IPv6. AEP: {aep_name}"))

                    udpport: str | int | None = self.get_child_text(
                        aep,
                        "it:IT-TRANSPORT-PROTOCOL-CONFIGURATION/it:UDP-TP/" "it:UDP-PORT/it:PORT-NUMBER",
                    )
                    if (
                        udpport is None
                        and self.get_child_text(
                            aep,
                            "it:IT-TRANSPORT-PROTOCOL-CONFIGURATION/it:UDP-TP/" "it:UDP-PORT/it:DYNAMICALLY-ASSIGNED",
                        )
                        == "true"
                    ):
                        udpport = self.lookup_dyn_port(cast(str, aep_name))

                    tcpport: str | int | None = self.get_child_text(
                        aep,
                        "it:IT-TRANSPORT-PROTOCOL-CONFIGURATION/it:TCP-TP/" "it:TCP-PORT/it:PORT-NUMBER",
                    )
                    if (
                        tcpport is None
                        and self.get_child_text(
                            aep,
                            "it:IT-TRANSPORT-PROTOCOL-CONFIGURATION/it:TCP-TP/" "it:TCP-PORT/it:DYNAMICALLY-ASSIGNED",
                        )
                        == "true"
                    ):
                        tcpport = self.lookup_dyn_port(cast(str, aep_name))

                    # only one can be existing
                    assert udpport is None or tcpport is None

                    if udpport is not None or tcpport is not None:
                        if udpport is not None:
                            portnumber: str | int | None = udpport
                            proto: str = "udp"
                        else:
                            portnumber = tcpport
                            proto = "tcp"

                        # build sockets
                        conf_factory = self.__conf_factory__
                        assert conf_factory is not None
                        for ip in ips:
                            socket = conf_factory.create_socket(
                                cast(str, aep_name),
                                cast(str, ip),
                                proto,
                                cast(int | str, portnumber),
                                sis,
                                csis,
                                ehs,
                                cegs,
                            )
                            sockets += [socket]
                            self.add_socket(cast(str, aep_id), socket)

                # build interfaces
                if channel is not None:
                    conf_factory = self.__conf_factory__
                    assert conf_factory is not None
                    iface = conf_factory.create_interface(
                        channel["name"],
                        channel["vlanid"],
                        cast(list[str], interface_ips),
                        sockets,
                        input_frame_trigs,
                        output_frame_trigs,
                        channel["flexray-channel-name"],
                    )
                    if ctrl is not None:
                        ctrl["ifaces"] += [iface]

            # build Controllers
            ctrllist: list[BaseController] = []
            conf_factory = self.__conf_factory__
            assert conf_factory is not None
            for key in sorted(ctrls.keys()):
                ctrl = ctrls[key]
                tmp = conf_factory.create_controller(ctrl["name"], ctrl["ifaces"])
                ctrllist += [tmp]

                assert cast(str, tmp) not in self.__controllers__
                self.__controllers__[key] = tmp

            self.create_ecu(cast(str, ecu_id), cast(str, ecu_name), ctrllist)
        self.finalize_ecus()

    def parse_topology(self, root: _Element, verbose: bool = False) -> None:
        for e in root.findall(".//fx:COUPLING-ELEMENTS/fx:COUPLING-ELEMENT", self.__ns__):
            switch_name = self.get_child_text(e, "ho:SHORT-NAME")
            cluster_ref = self.get_child_attribute(e, "fx:CLUSTER-REF", "ID-REF")
            ecu_ref = self.get_child_attribute(e, "fx:ECU-REF", "ID-REF")
            coupling_element_type = self.get_child_text(e, "ethernet:COUPLING-ELEMENT-TYPE")

            ecu = self.get_ecu(ecu_ref)

            if verbose:
                print(f"{switch_name} cluster_ref:{cluster_ref} ecu_ref:{ecu_ref} " f"coupling_element_type: {coupling_element_type}")

            if coupling_element_type != "SWITCH":
                print(f"Found unsupported Coupling Element with coupling_element_type={coupling_element_type}!")
                continue

            coupling_ports: list[BaseSwitchPort] = []
            for c in e.findall("fx:COUPLING-PORTS/fx:COUPLING-PORT", self.__ns__):
                coupling_port_id = self.get_attribute(c, "ID")
                controller_ref = self.get_child_attribute(c, "fx:CONTROLLER-REF", "ID-REF")
                controller = self.__controllers__.get(cast(str, controller_ref), None)

                if controller is None:
                    controller_ref_name = ""
                else:
                    controller_ref_name = controller.name()

                coupling_port_ref = self.get_child_attribute(c, "fx:COUPLING-PORT-REF", "ID-REF")
                coupling_port = self.__coupling_ports__.get(cast(str, coupling_port_ref), None)

                default_vlan_ref = self.get_child_attribute(c, "ethernet:DEFAULT-VLAN/fx:CHANNEL-REF", "ID-REF")

                if verbose:
                    default_vlan_name = (self.__channels__.get(cast(str, default_vlan_ref), {})).get("name", "")
                    print(
                        f"  Port ID:{coupling_port_id} CTRL-REF:{controller_ref} ({controller_ref_name}) "
                        f"PORT-REF:{coupling_port_ref} DEFAULT-VLAN:{default_vlan_ref} ({default_vlan_name})"
                    )

                # a port can only be connected to an ecu port or a switch port
                assert controller is None or coupling_port is None

                vlans: list[BaseVLAN] = []
                for v in c.findall("ethernet:VLAN-MEMBERSHIPS/ethernet:VLAN-MEMBERSHIP", self.__ns__):
                    channel_ref = self.get_child_attribute(v, "fx:CHANNEL-REF", "ID-REF")
                    channel_ref_name = (self.__channels__.get(cast(str, channel_ref), {})).get("name", "")
                    default_prio_txt = self.get_child_text(v, "ethernet:DEFAULT-PRIORITY/fx:PRIORITY")
                    default_prio = 0 if default_prio_txt is None else int(default_prio_txt)

                    if verbose:
                        print(f"    VLAN Channel:{channel_ref} ({channel_ref_name}) Default-Prio:{default_prio}")

                    channel = self.__channels__.get(cast(str, channel_ref), {})
                    channel["vlanid"] = None if channel.get("vlanid", None) is None else int(channel["vlanid"])
                    conf_factory = self.__conf_factory__
                    assert conf_factory is not None
                    vlans.append(conf_factory.create_vlan(channel["name"], channel["vlanid"], default_prio))

                conf_factory = self.__conf_factory__
                assert conf_factory is not None
                tmp = conf_factory.create_switch_port(
                    cast(str, coupling_port_id), controller, coupling_port, cast(int | None, default_vlan_ref), vlans
                )
                if coupling_port is not None:
                    coupling_port.set_connected_port(tmp)

                coupling_ports.append(tmp)
                self.__coupling_ports__[cast(str, coupling_port_id)] = tmp

            conf_factory = self.__conf_factory__
            assert conf_factory is not None
            conf_factory.create_switch(cast(str, switch_name), ecu, coupling_ports)

    def parse_file(self, conf_factory: BaseConfigurationFactory, filename: str, verbose: bool = False) -> None:
        self.__conf_factory__ = conf_factory

        tree = xml.etree.ElementTree.parse(filename)
        root = cast(_Element, tree.getroot())

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
            pprint.pprint(self.__codings__)
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
            for k, pdu in self.__pdus__.items():
                print(f"{k}: {pdu}")
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


def main() -> None:
    print("You cannot call me directly!")


# only call main, if we are started directly
if __name__ == "__main__":
    main()
