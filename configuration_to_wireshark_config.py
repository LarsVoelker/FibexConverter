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

from __future__ import annotations

import argparse
import ipaddress
import logging
import os.path
import sys
import time
from collections.abc import Mapping
from typing import NoReturn, Protocol, TextIO, cast

from configuration_base_classes import (
    BaseAbstractPDU,
    BaseConfigurationFactory,
    BaseController,
    BaseECU,
    BaseEthernetPDUInstance,
    BaseFrame,
    BaseFrameTriggering,
    BaseFrameTriggeringCAN,
    BaseFrameTriggeringFlexRay,
    BaseInterface,
    BaseSignal,
    BaseSignalInstance,
    BaseSocket,
    CallSemantic,
    SOMEIPBaseDatatype,
    SOMEIPBaseParameter,
    SOMEIPBaseParameterArray,
    SOMEIPBaseParameterArrayDim,
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
    ip_to_key,
    is_ip,
    is_ip_mcast,
    read_csv_to_dict,
)
from parser_dispatcher import is_file_or_dir_valid, is_file_valid, parse_input_files, parser_formats

logger = logging.getLogger(__name__)

DEBUG_LEGACY_STRIPPING = False

g_gen_portid: bool = False


class _WSBacklinkServiceItem(Protocol):
    def create_backlinks(self, factory: BaseConfigurationFactory | None, service: SOMEIPBaseService | None) -> None: ...


class _WSBacklinkService(Protocol):
    def create_backlinks(self, factory: BaseConfigurationFactory | None) -> None: ...


class _WSBacklinkDatatype(Protocol):
    def create_backlinks(
        self, factory: BaseConfigurationFactory | None, service: SOMEIPBaseService | None, method: object | None
    ) -> SOMEIPBaseDatatype: ...


class _WSBacklinkParam(Protocol):
    def create_backlinks(
        self, factory: BaseConfigurationFactory | None, service: SOMEIPBaseService | None, method: object
    ) -> SOMEIPBaseParameter: ...


class _WSBacklinkStructMember(Protocol):
    def create_backlinks(
        self, factory: BaseConfigurationFactory | None, service: SOMEIPBaseService | None, method: object
    ) -> SOMEIPBaseParameterStructMember: ...


class _WSBacklinkUnionMember(Protocol):
    def create_backlinks(
        self, factory: BaseConfigurationFactory | None, service: SOMEIPBaseService | None, method: object
    ) -> SOMEIPBaseParameterUnionMember: ...


class _WSMethodLike(Protocol):
    def methodid(self) -> int: ...

    def name(self) -> str: ...

    def legacy(self) -> bool: ...

    def tlv(self) -> bool: ...


class _WSBasetypeLike(Protocol):
    def bigendian(self) -> bool: ...

    def datatype(self) -> str: ...

    def bitlength_basetype(self) -> int: ...

    def bitlength_encoded_type(self) -> int: ...


class _WSDatatype(Protocol):
    def paramtype(self, version: int) -> int: ...

    def globalid(self, version: int) -> int: ...

    def ws_config_line(self, version: int = 1) -> str: ...


class _WSFramePDU(Protocol):
    def name(self) -> str: ...

    def is_multiplex_pdu(self) -> bool: ...

    def signal_instances_sorted_by_bit_position(self) -> list[BaseSignalInstance]: ...


class _PduLike(Protocol):
    def pdu(self) -> BaseAbstractPDU | None: ...

    def bit_position(self) -> int: ...

    def pdu_update_bit_position(self) -> int | None: ...


class _StrItem(Protocol):
    def str(self, indent: int = 0) -> str: ...


class WiresharkParameterTypes:
    basetype = 1
    string = 2
    array = 3
    struct = 4
    union = 5
    typedef = 6
    enum = 7
    bitfield = 8


def cleanup_string(tmp: str) -> str:
    ret = tmp.replace('"', "'")
    return ret


def cleanup_datatype_string(tmp: str) -> str:
    ret = tmp.lower()
    if ret.startswith("uint") or ret.startswith("a_uint"):
        ret = "uint"
    if ret.startswith("int") or ret.startswith("a_int"):
        ret = "int"
    if ret.startswith("float") or ret.startswith("a_float"):
        ret = "float"
    return ret


def translate_datatype(dt: str) -> str:
    ret = dt.lower()

    if ret.lower().startswith("a_"):
        ret = dt[2:].lower()

    # Wireshark only supports uint8 but not bool and boolean directly
    if ret in ("bool", "boolean"):
        ret = "uint8"

    return ret


class WiresharkConfigurationFactory(BaseConfigurationFactory):

    def __init__(self) -> None:
        self.__services__: dict[str, SOMEIPBaseService] = dict()
        self.__services_long__: dict[str, SOMEIPBaseService] = dict()

        self.__param_arrays__: dict[int, SOMEIPBaseDatatype] = dict()
        self.__param_basetypes__: dict[int, SOMEIPBaseDatatype] = dict()
        self.__param_enums__: dict[int, SOMEIPBaseDatatype] = dict()
        self.__param_strings__: dict[int, SOMEIPBaseDatatype] = dict()
        self.__param_structs__: dict[int, SOMEIPBaseDatatype] = dict()
        self.__param_typedefs__: dict[int, SOMEIPBaseDatatype] = dict()
        self.__param_unions__: dict[int, SOMEIPBaseDatatype] = dict()
        self.__param_bitfields__: dict[int, SOMEIPBaseDatatype] = dict()

        self.__globalid_arrays__: int = 1
        self.__globalid_basetypes__: int = 1
        self.__globalid_enums__: int = 1
        self.__globalid_strings__: int = 1
        self.__globalid_structs__: int = 1
        self.__globalid_typedefs__: int = 1
        self.__globalid_unions__: int = 1
        self.__globalid_bitfields__: int = 1

        self.__globalid_signal_pdus__: int = 1
        self.__globalid_bus__: int = 1

        self.__space_optimized__: bool = True

        self.__ecus__: dict[str, BaseECU] = dict()
        self.__channels__: dict[str, dict[str, object]] = dict()
        self.__frame_id_pdu_id_mapping__: dict[str, int] = dict()

        self.__eth_pdus__: dict[int, dict[str, object]] = dict()

        self.__sockets__: list[BaseSocket] = []

    def next_global_pdu_id(self) -> int:
        ret = self.__globalid_signal_pdus__
        self.__globalid_signal_pdus__ += 1
        return ret

    def pdu_id_for_frame(self, frame: BaseFrame) -> tuple[bool, int]:
        key = frame.id()
        present = key in self.__frame_id_pdu_id_mapping__.keys()

        if not present:
            self.__frame_id_pdu_id_mapping__[key] = self.next_global_pdu_id()

        return present, self.__frame_id_pdu_id_mapping__[key]

    def next_global_bus_id(self) -> int:
        ret = self.__globalid_bus__
        self.__globalid_bus__ += 1
        return ret

    def create_backlinks(self) -> None:
        for s in self.__services__.values():
            cast(_WSBacklinkService, s).create_backlinks(self)

    def create_ecu(self, name: str, controllers: list[BaseController]) -> BaseECU:
        tmp = BaseECU(name, controllers)
        logger.debug("Adding ECU %s", name)
        if cast(str, tmp) in self.__ecus__:
            print(f"Detected duplicate ECU {name}")
        self.__ecus__[name] = tmp
        return tmp

    def create_interface(
        self,
        name: str,
        vlanid: int | None,
        ips: list[str],
        sockets: list[BaseSocket],
        input_frame_trigs: dict[str, BaseFrameTriggering],
        output_frame_trigs: dict[str, BaseFrameTriggering],
        fr_channel: int | None,
    ) -> BaseInterface:
        ret = BaseInterface(
            name,
            vlanid,
            ips,
            sockets,
            input_frame_trigs,
            output_frame_trigs,
            fr_channel,
        )

        channel = self.__channels__.setdefault(name, {})

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

        frame_triggerings: dict[str, BaseFrameTriggering] = channel.setdefault("frametriggerings", {})  # type: ignore[assignment]

        for key, value in input_frame_trigs.items():
            frame_triggerings[key] = value
        for key, value in output_frame_trigs.items():
            frame_triggerings[key] = value

        return ret

    def create_socket(
        self,
        name: str,
        ip: str,
        proto: int | str,
        portnumber: int | str,
        serviceinstances: list[SOMEIPBaseServiceInstance] | None,
        serviceinstanceclients: list[SOMEIPBaseServiceInstanceClient] | None,
        eventhandlers: list[SOMEIPBaseServiceEventgroupSender] | None,
        eventgroupreceivers: list[SOMEIPBaseServiceEventgroupReceiver] | None,
    ) -> BaseSocket:
        tmp = BaseSocket(
            name,
            ip,
            proto,
            portnumber,
            serviceinstances,
            serviceinstanceclients,
            eventhandlers,
            eventgroupreceivers,
        )

        self.__sockets__.append(tmp)
        return tmp

    def create_someip_service(
        self,
        name: str,
        serviceid: int,
        majorver: int,
        minorver: int,
        methods: dict[int, SOMEIPBaseServiceMethod],
        events: dict[int, SOMEIPBaseServiceEvent],
        fields: dict[int, SOMEIPBaseServiceField],
        eventgroups: dict[int, SOMEIPBaseServiceEventgroup],
    ) -> SOMEIPService:
        ret = SOMEIPService(name, serviceid, majorver, minorver, methods, events, fields, eventgroups)
        logger.debug("Adding Service(Name: %s ID: 0x%04x Ver: %d.%d)", name, serviceid, majorver, minorver)
        self.add_service(serviceid, majorver, minorver, ret)
        return ret

    def create_someip_service_method(
        self,
        name: str,
        methodid: int,
        calltype: CallSemantic,
        relia: bool,
        inparams: list[SOMEIPBaseParameter],
        outparams: list[SOMEIPBaseParameter],
        reqdebounce: int = -1,
        reqmaxretention: int = -1,
        resmaxretention: int = -1,
        tlv: bool = False,
    ) -> SOMEIPServiceMethod:
        return SOMEIPServiceMethod(
            name,
            methodid,
            calltype,
            relia,
            inparams,
            outparams,
            reqdebounce,
            reqmaxretention,
            resmaxretention,
            tlv,
        )

    def create_someip_service_event(
        self,
        name: str,
        methodid: int,
        relia: bool,
        params: list[SOMEIPBaseParameter],
        debounce: int = -1,
        maxretention: int = -1,
        tlv: bool = False,
    ) -> SOMEIPServiceEvent:
        return SOMEIPServiceEvent(name, methodid, relia, params, debounce, maxretention, tlv)

    def create_someip_service_field(
        self,
        name: str,
        getterid: int | None,
        setterid: int | None,
        notifierid: int | None,
        getterreli: bool,
        setterreli: bool,
        notifierreli: bool,
        params: list[SOMEIPBaseParameter],
        getter_debouncereq: int,
        getter_retentionreq: int,
        getter_retentionres: int,
        setter_debouncereq: int,
        setter_retentionreq: int,
        setter_retentionres: int,
        notifier_debounce: int,
        notifier_retention: int,
        tlv: bool = False,
    ) -> SOMEIPServiceField:
        ret = SOMEIPServiceField(
            self,
            name,
            getterid,
            setterid,
            notifierid,
            getterreli,
            setterreli,
            notifierreli,
            params,
            getter_debouncereq,
            getter_retentionreq,
            getter_retentionres,
            setter_debouncereq,
            setter_retentionreq,
            setter_retentionres,
            notifier_debounce,
            notifier_retention,
            tlv,
        )
        return ret

    def create_someip_parameter(
        self,
        position: int,
        name: str,
        desc: str | None,
        mandatory: bool,
        datatype: SOMEIPBaseDatatype | None,
        signal: BaseSignal | None,
    ) -> SOMEIPParameter:
        return SOMEIPParameter(position, name, desc, mandatory, datatype, signal)

    def create_someip_parameter_basetype(
        self, name: str, datatype: str, bigendian: bool, bitlength_basetype: int, bitlength_encoded_type: int
    ) -> SOMEIPParameterBasetype:
        if bitlength_basetype != bitlength_encoded_type:
            name = "%s-%d" % (name, bitlength_encoded_type)

        datatype = translate_datatype(datatype)

        ret = SOMEIPParameterBasetype(
            self.__globalid_basetypes__,
            name,
            datatype,
            bigendian,
            bitlength_basetype,
            bitlength_encoded_type,
        )

        if self.__space_optimized__:
            for key in self.__param_basetypes__:
                tmp = self.__param_basetypes__[key]
                if tmp == ret:
                    return cast(SOMEIPParameterBasetype, tmp)

        self.__param_basetypes__[self.__globalid_basetypes__] = ret
        self.__globalid_basetypes__ += 1

        return ret

    def create_someip_parameter_string(
        self,
        name: str,
        chartype: str,
        bigendian: bool,
        lowerlimit: int,
        upperlimit: int,
        termination: str | None,
        length_of_length: int | None,
        pad_to: int,
    ) -> SOMEIPParameterString:
        ret = SOMEIPParameterString(
            self.__globalid_strings__,
            name,
            chartype,
            bigendian,
            lowerlimit,
            upperlimit,
            termination,
            length_of_length,
            pad_to,
        )

        if self.__space_optimized__:
            for key in self.__param_strings__:
                tmp = self.__param_strings__[key]
                if tmp == ret:
                    return cast(SOMEIPParameterString, tmp)

        self.__param_strings__[self.__globalid_strings__] = ret
        self.__globalid_strings__ += 1
        return ret

    def create_someip_parameter_array(
        self, name: str, dims: dict[int, SOMEIPBaseParameterArrayDim], child: SOMEIPBaseDatatype
    ) -> SOMEIPParameterArray:
        ret = SOMEIPParameterArray(self.__globalid_arrays__, name, dims, child)

        #        if self.__space_optimized__:
        #            for key in self.__param_arrays__:
        #                tmp = self.__param_arrays__[key]
        #                if tmp == ret:

        self.__param_arrays__[self.__globalid_arrays__] = ret
        self.__globalid_arrays__ += 1
        return ret

    def create_someip_parameter_array_dim(
        self, dim: int, lowerlimit: int, upperlimit: int, length_of_length: int | None, pad_to: int
    ) -> SOMEIPBaseParameterArrayDim:
        return SOMEIPBaseParameterArrayDim(dim, lowerlimit, upperlimit, length_of_length, pad_to)

    def create_someip_parameter_struct(
        self, name: str, length_of_length: int | None, pad_to: int, members: dict[int, SOMEIPBaseParameterStructMember], tlv: bool = False
    ) -> SOMEIPParameterStruct:
        ret = SOMEIPParameterStruct(self.__globalid_structs__, name, length_of_length, pad_to, members, tlv)

        #        if self.__space_optimized__:
        #            for key in self.__param_structs__:
        #                tmp = self.__param_structs__[key]
        #                if tmp == ret:
        #                    return tmp

        self.__param_structs__[self.__globalid_structs__] = ret
        self.__globalid_structs__ += 1
        return ret

    def create_someip_parameter_struct_member(
        self, position: int, name: str, mandatory: bool, child: SOMEIPBaseDatatype, signal: BaseSignal | None
    ) -> SOMEIPParameterStructMember:
        return SOMEIPParameterStructMember(position, name, mandatory, child, signal)

    def create_someip_parameter_typedef(self, name: str, name2: str, child: SOMEIPBaseDatatype) -> SOMEIPParameterTypedef:
        ret = SOMEIPParameterTypedef(self.__globalid_typedefs__, name, name2, child)

        #        if self.__space_optimized__:
        #            for key in self.__param_typedefs__:
        #                tmp = self.__param_typedefs__[key]
        #                if tmp == ret:
        #                    return tmp

        self.__param_typedefs__[self.__globalid_typedefs__] = ret
        self.__globalid_typedefs__ += 1
        return ret

    def create_someip_parameter_enumeration(
        self, name: str, items: list[SOMEIPBaseParameterEnumerationItem], child: SOMEIPBaseDatatype
    ) -> SOMEIPParameterEnumeration:
        ret = SOMEIPParameterEnumeration(self.__globalid_enums__, name, items, child)

        if self.__space_optimized__:
            for key in self.__param_enums__:
                tmp = self.__param_enums__[key]
                if tmp == ret:
                    return cast(SOMEIPParameterEnumeration, tmp)

        self.__param_enums__[self.__globalid_enums__] = ret
        self.__globalid_enums__ += 1
        return ret

    def create_someip_parameter_enumeration_item(self, value: int, name: str, desc: str | None) -> SOMEIPBaseParameterEnumerationItem:
        return SOMEIPBaseParameterEnumerationItem(value, name, desc)

    def create_someip_parameter_union(
        self,
        name: str,
        length_of_length: int | None,
        length_of_type: int | None,
        pad_to: int,
        members: dict[int, SOMEIPBaseParameterUnionMember],
    ) -> SOMEIPParameterUnion:
        ret = SOMEIPParameterUnion(
            self.__globalid_unions__,
            name,
            length_of_length,
            length_of_type,
            pad_to,
            members,
        )

        #        if self.__space_optimized__:
        #            for key in self.__param_unions__:
        #                tmp = self.__param_unions__[key]
        #                if tmp == ret:
        #                    return tmp

        self.__param_unions__[self.__globalid_unions__] = ret
        self.__globalid_unions__ += 1
        return ret

    def create_someip_parameter_union_member(self, index: int, name: str, mandatory: bool, child: SOMEIPBaseDatatype) -> SOMEIPParameterUnionMember:
        return SOMEIPParameterUnionMember(index, name, mandatory, child)

    def create_someip_parameter_bitfield(
        self, name: str, items: list[SOMEIPBaseParameterBitfieldItem], child: SOMEIPBaseDatatype
    ) -> SOMEIPParameterBitfield:
        ret = SOMEIPParameterBitfield(self.__globalid_bitfields__, name, items, child)

        self.__param_bitfields__[self.__globalid_bitfields__] = ret
        self.__globalid_bitfields__ += 1
        return ret

    def add_ethernet_pdu(self, pdu_name: str, header_id: int) -> bool:
        pdu_d: dict[str, object] = dict()
        pdu_d["name"] = pdu_name
        pdu_d["id"] = header_id

        if header_id in self.__eth_pdus__.keys() and self.__eth_pdus__[header_id]["name"] != pdu_name:
            print(f"WARNING: Overwriting PDU with ID:{hex(header_id)}! {self.__eth_pdus__[header_id]['name']} -> {pdu_name}")
            return False

        self.__eth_pdus__[header_id] = pdu_d
        return True

    def create_pdu_route(self, sender_socket: BaseSocket, receiving_socket: BaseSocket, pdu_name: str, pdu_id: int) -> bool:
        return self.add_ethernet_pdu(pdu_name, pdu_id)

    def add_service(self, serviceid: int, majorver: int, minorver: int, service: SOMEIPBaseService) -> bool:
        sid = "%04x-%02x-%08x" % (serviceid, majorver, minorver)
        if sid in self.__services_long__:
            print(
                f"ERROR: Service (SID: 0x{serviceid:04x}, Major-Ver: {majorver:d}, " + f"Minor-Ver: {minorver:d}) already exists! Not overriding it!"
            )
            return False
        self.__services_long__[sid] = service

        sid = "%04x-%02x" % (serviceid, majorver)
        if sid in self.__services__:
            print(
                f"ERROR: Service (SID: 0x{serviceid:04x}, Major-Ver: {majorver:d}) "
                + f"already exists with a different Minor Version (not {minorver:d})! Not overriding it!"
            )
            return False
        self.__services__[sid] = service
        return True

    def get_service(self, serviceid: int, majorver: int, minorver: int | None = None) -> SOMEIPBaseService | None:
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

    def __str__(self) -> str:
        ret = "Services: \n"
        for serviceid in self.__services__:
            ret += cast(_StrItem, self.__services__[serviceid]).str(2)

        ret += "\nECUs: \n"
        for name in self.__ecus__:
            ret += cast(_StrItem, self.__ecus__[name]).str(2)

        return ret

    def write_name_configs(self, conf_services: str, conf_methods: str, conf_eventgroups: str, version: int = 1) -> None:
        count_services = 0
        count_events = 0
        count_methods = 0
        count_fields = 0

        d: dict[int, SOMEIPBaseService] = dict()

        for sid in self.__services__.keys():
            count_services += 1
            s = self.__services__[sid]

            if s.serviceid() in d.keys():
                if cast(str, d[s.serviceid()]) != s.name():
                    print(f"ERROR: We got the same Service-ID 0x{s.serviceid():04x} " + f"with different names {d[s.serviceid()].name()} {s.name()}")
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
            fs.write(f'"{key:04x}","{s.name()}"\n')

            dm: dict[int, str] = dict()

            methods_tmp = s.methods()
            for mid in methods_tmp:
                count_methods += 1
                dm[methods_tmp[mid].methodid()] = methods_tmp[mid].name()

            events_tmp = s.events()
            for eid in events_tmp:
                count_events += 1
                dm[events_tmp[eid].methodid()] = events_tmp[eid].name()

            fields_tmp = s.fields()
            for fid in fields_tmp:
                count_fields += 1

                getter = fields_tmp[fid].getter()
                if getter is not None:
                    count_methods += 1
                    dm[getter.methodid()] = fields_tmp[fid].name() + "_Getter"

                setter = fields_tmp[fid].setter()
                if setter is not None:
                    count_methods += 1
                    dm[setter.methodid()] = fields_tmp[fid].name() + "_Setter"

                notifier = fields_tmp[fid].notifier()
                if notifier is not None:
                    count_events += 1
                    dm[notifier.methodid()] = fields_tmp[fid].name() + "_Notifier"

            for mkey in sorted(dm.keys()):
                fm.write(f'"{key:04x}","{mkey:04x}","{dm[mkey]}"\n')

            de: dict[int, str] = dict()

            egroups_tmp = s.eventgroups()
            for eg in egroups_tmp:
                de[egroups_tmp[eg].id()] = egroups_tmp[eg].name()

            for egkey in sorted(de.keys()):
                fe.write(f'"{key:04x}","{egkey:04x}","{de[egkey]}"\n')

        fs.close()
        fm.close()
        fe.close()

    @staticmethod
    def write_ws_config(filename: str, arr: Mapping[int, SOMEIPBaseDatatype], version: int = 1) -> None:
        f = open(filename, "w")
        f.write("# This file is automatically generated, DO NOT MODIFY. (LV)\n")

        for key in arr:
            i = arr[key]
            f.write(f"{cast(_WSDatatype, i).ws_config_line(version)}")

        f.close()

    @staticmethod
    def write_parameter_configlines(
        f: TextIO,
        service: SOMEIPBaseService,
        method: _WSMethodLike,
        msgtype: int,
        params: list[SOMEIPBaseParameter],
        version: int,
    ) -> None:
        for p in params:
            if p.datatype() is not None:
                tmp = '"%04x","%04x","%d","%x"' % (
                    service.serviceid(),
                    method.methodid(),
                    service.majorversion(),
                    msgtype,
                )
                if version > 1:
                    if method.tlv():
                        tmp += ',"TRUE"'
                    else:
                        tmp += ',"FALSE"'

                tmp += ',"%d"' % (len(params))

                tmp += ',"%d","%s","%d","%08x"' % (
                    p.position(),
                    p.name(),
                    cast(_WSDatatype, p.datatype()).paramtype(version),
                    cast(_WSDatatype, p.datatype()).globalid(version),
                )

                if version > 1:
                    tmp += f',"{service.name()}.{method.name()}.{p.name()}"'.replace(" ", "")

                tmp += "\n"
                f.write(tmp)
            else:
                print(
                    f"ERROR: Cannot write config, if p.datatype() = None! "
                    f"Service: {service.name()} Method: {method.name()} Param: {p.name()} Pos: {p.position()}"
                )

    def write_parameter_config(self, filename: str, version: int = 1) -> None:
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
                evt = serv.events()[key]
                if version == 1 or not evt.legacy():
                    self.write_parameter_configlines(
                        f,
                        serv,
                        evt,
                        0x02,
                        evt.params(),
                        version,
                    )
                elif DEBUG_LEGACY_STRIPPING:
                    print(f"--> skipping legacy event: {serv.name()} (0x{serv.serviceid():x}) {evt.name()} (0x{evt.methodid():x})")

            for key in sorted(serv.fields(), key=lambda x: (x is None, x)):
                field = serv.fields()[key]
                if version == 1 or not field.legacy():
                    getter = field.getter()
                    if getter is not None:
                        self.write_parameter_configlines(f, serv, getter, 0x00, getter.inparams(), version)
                        self.write_parameter_configlines(f, serv, getter, 0x80, getter.outparams(), version)
                    setter = field.setter()
                    if setter is not None:
                        self.write_parameter_configlines(f, serv, setter, 0x00, setter.inparams(), version)
                        self.write_parameter_configlines(f, serv, setter, 0x80, setter.outparams(), version)
                    notifier = field.notifier()
                    if notifier is not None:
                        self.write_parameter_configlines(f, serv, notifier, 0x02, notifier.params(), version)
                elif DEBUG_LEGACY_STRIPPING:
                    print(f"--> skipping legacy field: {serv.name()} (0x{serv.serviceid():x}) {field.name()}")

        f.close()

    def write_parameter_basetypes(self, filename: str, version: int = 1) -> None:
        self.write_ws_config(filename, self.__param_basetypes__, version)

    def write_parameter_strings(self, filename: str, version: int = 1) -> None:
        self.write_ws_config(filename, self.__param_strings__, version)

    def write_parameter_arrays(self, filename: str, version: int = 1) -> None:
        self.write_ws_config(filename, self.__param_arrays__, version)

    def write_parameter_structs(self, filename: str, version: int = 1) -> None:
        self.write_ws_config(filename, self.__param_structs__, version)

    def write_parameter_typedefs(self, filename: str, version: int = 1) -> None:
        self.write_ws_config(filename, self.__param_typedefs__, version)

    def write_parameter_unions(self, filename: str, version: int = 1) -> None:
        self.write_ws_config(filename, self.__param_unions__, version)

    def write_parameter_enums(self, filename: str, version: int = 1) -> None:
        self.write_ws_config(filename, self.__param_enums__, version)

    def write_parameter_bitfields(self, filename: str, version: int = 3) -> None:
        self.write_ws_config(filename, self.__param_bitfields__, version)

    def write_hosts(self, filename: str, version: int = 1) -> None:
        # ip name

        f = open(filename, "w")
        f.write("# This file is automatically generated, DO NOT MODIFY (LV).\n")

        ips: dict[str | ipaddress.IPv4Address | ipaddress.IPv6Address, dict[str, str]] = {}

        for ecuname in self.__ecus__:
            for controller in self.__ecus__[ecuname].controllers():

                if len(self.__ecus__[ecuname].controllers()) > 1:
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
                            tmp: dict[str, str] = ips.setdefault(socket.ip(), {})
                            tmp[ecuctrlname] = ecuctrlname

                    # let us also include IPs without sockets
                    for ip in interface.ips():
                        if is_ip(cast(str, ip)) and not is_ip_mcast(cast(str, ip)):
                            tmp = ips.setdefault(ip, {})
                            tmp[ecuctrlname] = ecuctrlname

        for ipkey in sorted(ips.keys(), key=lambda x: ip_to_key(cast(str, x))):
            ecu_names = "__".join(ips[ipkey])
            f.write(f"{ipkey}\t{ecu_names}\n")

        f.close()

    def write_vlanids(self, filename: str, version: int = 1) -> None:
        # vlanids name

        f = open(filename, "w")
        f.write("# This file is automatically generated, DO NOT MODIFY. (LV)\n")

        vlans: dict[int, str] = dict()

        for ecu in self.__ecus__:
            for controller in self.__ecus__[ecu].controllers():
                for interface in controller.interfaces():
                    vlans[interface.vlanid()] = interface.vlanname()

        for vlan in sorted(vlans):
            if vlan != 0:
                f.write(f"{vlan}\t{vlans[vlan]}\n")

        f.close()

    def write_signal_pdu_configline(self, f: TextIO, pdu_id: int, name: str) -> None:
        # Legacy-ID, Name

        f.write(f'"{pdu_id:08x}",' f'"{name}"\n')

    def write_can_busid_configline(self, f: TextIO, interfaceid: int | None, busname: str, busid: int) -> None:
        if interfaceid is None:
            interfaceid = 0xFFFFFFFF

        f.write(f'"{interfaceid:08x}",' f'"{busname}",' f'"{busid:04x}"\n')

    def write_signal_pdu_binding_someip_configline(
        self, f: TextIO, service: SOMEIPBaseService, method: _WSMethodLike, msgtype: int, pdu_id: int
    ) -> None:
        # Service-ID, Method-ID, MessageType, Version, Legacy-ID

        if not method.legacy():
            return

        f.write(
            f'"{service.serviceid():04x}",' f'"{method.methodid():04x}",' f'"{service.majorversion():02x}",' f'"{msgtype:02x}",' f'"{pdu_id:08x}"\n'
        )

    def write_signal_pdu_binding_can_configline(self, f: TextIO, can_id: int, bus_id: int, pdu_id: int) -> None:
        # uint32 CAN-ID, uint16 Bus-ID, uint32 PDU-ID

        f.write(f'"{can_id:08x}",' f'"{bus_id:04x}",' f'"{pdu_id:08x}"\n')

    def write_signal_pdu_binding_fr_configline(
        self, f: TextIO, channel: str, slot_id: int, base_cycle: int | None, cycle_rep: int | None, cycle_cnt: int | None, pdu_id: int
    ) -> None:
        # channel (0,1), uint8 Cycle, uint16 Frame-ID, uint32 PDU-ID

        # Channel A is default
        channel_cfg = 0
        if channel.upper() == "B":
            channel_cfg = 1

        if cycle_cnt is not None and cycle_cnt != 0:
            print(f"WARNING: FlexRay Cycle Count {cycle_cnt} currently not supported for Wireshark config!")

        MAX_CYCLE = 64

        cycle = 0 if base_cycle is None else base_cycle
        while cycle < MAX_CYCLE:
            f.write(f'"{channel_cfg:02x}",' f'"{cycle:02x}",' f'"{slot_id:04x}",' f'"{pdu_id:08x}"\n')
            if cycle_rep == 0:
                return

            cycle += cast(int, cycle_rep)

    def write_signal_value_configlines(self, f_enum: TextIO, pdu_id: int, position: int, signal: BaseSignal) -> None:
        cc = signal.compu_consts()

        if cc is None:
            return

        for value, start, end in cast(list[tuple[object, object, object]], cc):
            if 0 <= int(cast(float, start)) <= pow(2, 64) and 0 <= int(cast(float, end)) <= pow(2, 64):
                f_enum.write(
                    f'"{pdu_id:08x}",'
                    f'"{position}",'
                    f'"{len(cc)}",'
                    f'"{int(cast(float, start)):x}",'
                    f'"{int(cast(float, end)):x}",'
                    f'"{cleanup_string(cast(str, value))}"'
                    "\n"
                )
            else:
                print(f"WARNING: CompuConst<0 or >2^64 not supported! " f"{pdu_id:08x}:{position} {start}-{end} {value}")

    def write_someip_signal_configlines(
        self, f: TextIO, f_enum: TextIO, pdu_id: int, pdu_name: str, params: list[SOMEIPBaseParameter] | None
    ) -> None:
        # signals (f)
        # ID, Num of Sigs, Pos, Name, Data Type, BE (TRUE/FALSE), bitlen base, bitlen coded, scaler, offset,
        # Multiplexer (FALSE), Muliplex value (-1), Hidden (FALSE)

        # enums (f_enum)
        # ID, Pos, Num of Values, Value start, Value end, Value Name

        if params is None or len(params) == 0:
            return

        # there might be exactly one struct as wrapper, if we are part of a field
        p0_dt = params[0].datatype()
        if isinstance(p0_dt, SOMEIPParameterStruct):
            tmp = p0_dt.members()

            for k in sorted(tmp.keys()):
                m = tmp[k]
                mchild = cast(_WSBasetypeLike, m.child())
                msig = m.signal()

                endian = "TRUE" if mchild.bigendian() else "FALSE"
                hidden = "TRUE" if m.name().startswith("dummy") else "FALSE"
                scaler: float = 1
                offset: float = 0

                if msig is not None:
                    offset = msig.offset()
                    scaler = msig.scaler()

                if msig is not None:
                    self.write_signal_value_configlines(f_enum, pdu_id, m.position(), msig)

                f.write(
                    f'"{pdu_id:08x}",'
                    f'"{len(tmp)}",'
                    f'"{m.position()}",'
                    f'"{m.name()}",'
                    f'"{pdu_name}.{m.name()}",'
                    f'"{cleanup_datatype_string(mchild.datatype())}",'
                    f'"{endian}",'
                    f'"{mchild.bitlength_basetype()}",'
                    f'"{mchild.bitlength_encoded_type()}",'
                    f'"{scaler}",'
                    f'"{offset}",'
                    f'"FALSE",'
                    f'"-1",'
                    f'"{hidden}"'
                    "\n"
                )
            return

        for p in params:
            pdt = cast(_WSBasetypeLike, p.datatype())
            psig = p.signal()

            endian = "TRUE" if pdt.bigendian() else "FALSE"
            hidden = "TRUE" if p.name().startswith("dummy") else "FALSE"
            scaler = 1
            offset = 0

            if psig is not None:
                offset = psig.offset()
                scaler = psig.scaler()

            if psig is not None:
                self.write_signal_value_configlines(f_enum, pdu_id, p.position(), psig)

            f.write(
                f'"{pdu_id:08x}",'
                f'"{len(params)}",'
                f'"{p.position()}",'
                f'"{p.name()}",'
                f'"{pdu_name}.{p.name()}",'
                f'"{cleanup_datatype_string(pdt.datatype())}",'
                f'"{endian}",'
                f'"{pdt.bitlength_basetype()}",'
                f'"{pdt.bitlength_encoded_type()}",'
                f'"{scaler}",'
                f'"{offset}",'
                f'"FALSE",'
                f'"-1",'
                f'"{hidden}"'
                "\n"
            )

    def generate_signal_configline_parts(
        self,
        pdu_id: int,
        pdu_name: str,
        pos: int,
        name: str,
        dt: str,
        endian: str | bool,
        bitlength_basetype: int,
        bitlength_encoded_type: int,
        scaler: float,
        offset: float,
        hidden: str,
    ) -> tuple[str, str]:
        endian_upper = "TRUE" if endian else "FALSE"

        tmp1 = f'"{pdu_id:08x}","'
        tmp2 = (
            f'",'
            f'"{pos}",'
            f'"{name}",'
            f'"{pdu_name}.{name}",'
            f'"{cleanup_datatype_string(dt)}",'
            f'"{endian_upper}",'
            f'"{bitlength_basetype}",'
            f'"{bitlength_encoded_type}",'
            f'"{scaler}",'
            f'"{offset}",'
            f'"FALSE",'
            f'"-1",'
            f'"{hidden}"'
            "\n"
        )

        return tmp1, tmp2

    def write_signal_pdu_signal_configlines(
        self,
        f_sig: TextIO,
        f_sigv: TextIO,
        pdu_id: int,
        name: str,
        pdu_instances: Mapping[str, _PduLike] | Mapping[int, _PduLike],
        debug: bool = False,
    ) -> None:
        if len(pdu_instances) == 0:
            return

        if debug and len(pdu_instances) > 1:
            print(f"WARNING: We might need to merge the PDUs of {name} pdu_id: {pdu_id}.")
            # TODO: we could use the AUTOSAR I-PDU-M config to have different PDUs...

        for pdu_instance in pdu_instances.values():
            pdu_nn = pdu_instance.pdu()
            if pdu_nn is not None and pdu_instance.pdu_update_bit_position() is not None:
                print(f"WARNING: Update Bits currently not supported! " f"{name} PDU: {pdu_nn.name()}. Ignoring the Update Bits!")
                # TODO: We need to generate the AUTOSAR I-PDU-M config to support Update Bits

        # check and sort pdu intances of frame
        tmp_pdu_instances: dict[int, _PduLike] = {}
        for pdu_inst in pdu_instances.values():
            pdu_start_pos = pdu_inst.bit_position()

            if pdu_start_pos in tmp_pdu_instances.keys():
                print(f"ERROR: {name} has multiple PDUs starting at same position! Overwritting!")

            if pdu_inst.pdu() is None:
                print(f"ERROR: {name} has a PDU Instance without PDU! Skipping!")
            else:
                tmp_pdu_instances[pdu_start_pos] = pdu_inst

        tmp: list[tuple[str, str]] = []
        pos = 0
        dummy_number = 0
        current_bit_pos = 0
        for pdu_start_pos in sorted(tmp_pdu_instances.keys()):
            pdu = tmp_pdu_instances[pdu_start_pos].pdu()

            if pdu is None:
                continue

            fpdu = cast(_WSFramePDU, pdu)

            if fpdu.is_multiplex_pdu():
                print(f"WARNING: Not supporting Multiplex PDUs yet! Skipping Frame: {name}!")
                # TODO: Parse the Switch and set it to Multiplexer. Generate the rest. Update gap detection.
                return
            else:
                for signal_instance in fpdu.signal_instances_sorted_by_bit_position():
                    start_pos = pdu_start_pos + signal_instance.bit_position()

                    while start_pos > current_bit_pos:
                        if debug:
                            print(f"DEBUG: found a gap in PDU {pdu_id} {current_bit_pos} {start_pos}")

                        dummy_length = min(start_pos - current_bit_pos, 32)

                        tmp1, tmp2 = self.generate_signal_configline_parts(
                            pdu_id,
                            fpdu.name(),
                            pos,
                            f"dummy_{dummy_number}",
                            "uint",
                            "TRUE",
                            32,
                            dummy_length,
                            1.0,
                            0.0,
                            "TRUE",
                        )
                        tmp.append((tmp1, tmp2))

                        pos += 1
                        current_bit_pos += dummy_length
                        dummy_number += 1

                    if start_pos != current_bit_pos:
                        print(f"ERROR: The signals seem to be overlapping in PDU {fpdu.name()} {pdu_id}! Skipping!")
                        return

                    signal = cast(BaseSignal, signal_instance.signal())
                    signal_length = signal.bit_length()

                    if debug:
                        print(f"DEBUG: {pdu_id} {signal.name()} {current_bit_pos} {start_pos} {signal_length}")

                    # Workaround for a_bytefield
                    basetype = signal.basetype()
                    bitlen_base = signal.basetype_length()

                    if bitlen_base not in (8, 16, 32, 64):
                        print(f"        WARNING: {bitlen_base=} is not a multiple of 8! Wireshark might not like this. {name=}")
                        print(f"        {pdu_id=} {signal.name()=} {current_bit_pos=} {start_pos=} {signal_length=}")

                    if basetype.lower() in ("asciistring", "a_asciistring"):
                        basetype = "STRING"
                        bitlen_base = 8

                    if basetype.lower() in ("bytefield", "a_bytefield"):
                        print("        WARNING: bytefield support is not complete. Results may be not correct!")
                        basetype = "UINT"
                        bitlen_base = 64

                    tmp1, tmp2 = self.generate_signal_configline_parts(
                        pdu_id,
                        fpdu.name(),
                        pos,
                        signal.name(),
                        basetype,
                        signal_instance.is_high_low_byte_order(),
                        bitlen_base,
                        signal_length,
                        signal.scaler(),
                        signal.offset(),
                        "FALSE",
                    )
                    tmp.append((tmp1, tmp2))

                    pos += 1
                    current_bit_pos = start_pos + signal_length

        for left_part, right_part in tmp:
            f_sig.write(left_part + f"{len(tmp)}" + right_part)

    def has_channel_more_than_one_type(self, key: str) -> bool:
        channel = self.__channels__[key]

        tmp = 0
        if channel["is_can"]:
            tmp += 1
        if channel["is_flexray"]:
            tmp += 1
        if channel["is_ethernet"]:
            tmp += 1

        return tmp > 1

    def write_signal_pdu(self, f_pdu: TextIO, f_sig: TextIO, f_sigv: TextIO, frame: BaseFrame) -> int:
        frame_known, pdu_id = self.pdu_id_for_frame(frame)
        if not frame_known:
            # we have not written this Signal PDU before, so do it now:
            self.write_signal_pdu_configline(f_pdu, pdu_id, frame.name())
            self.write_signal_pdu_signal_configlines(f_sig, f_sigv, pdu_id, frame.name(), frame.pdu_instances())

        return pdu_id

    def write_pdus_over_legacy_bus_configs(
        self,
        f_pdu: TextIO,
        f_sig: TextIO,
        f_sigv: TextIO,
        f_can_if: TextIO,
        f_bind_can: TextIO,
        f_bind_fr: TextIO,
        version: int = 2,
    ) -> None:
        for name in sorted(self.__channels__.keys()):
            if self.has_channel_more_than_one_type(name):
                print(f"WARNING: Channel {name} use more than 1 technology (CAN, FlexRay, Ethernet, ...)! Skipping!")
                continue

            channel = self.__channels__[name]
            bus_id = self.next_global_bus_id()
            frame_triggerings: dict[str, BaseFrameTriggering] = cast(dict[str, BaseFrameTriggering], channel["frametriggerings"])

            if channel["is_can"]:
                self.write_can_busid_configline(f_can_if, None, name, bus_id)

                for key in sorted(frame_triggerings.keys()):
                    ft = frame_triggerings[key]
                    frame = ft.frame()
                    if frame is None:
                        print(f"WARNING: FrameTriggering {ft.id()} has no valid frame attached! Skipping!")
                        continue

                    pdu_id = self.write_signal_pdu(f_pdu, f_sig, f_sigv, frame)

                    self.write_signal_pdu_binding_can_configline(f_bind_can, cast(BaseFrameTriggeringCAN, ft).can_id(), bus_id, pdu_id)

            if channel["is_flexray"]:
                for key in sorted(frame_triggerings.keys()):
                    ft = frame_triggerings[key]
                    frame = ft.frame()
                    if frame is None:
                        print(f"WARNING: FrameTriggering {ft.id()} has no valid frame attached! Skipping!")
                        continue

                    pdu_id = self.write_signal_pdu(f_pdu, f_sig, f_sigv, frame)

                    slot_id, cycle_cnt, base_cycle, cycle_rep = cast(BaseFrameTriggeringFlexRay, ft).scheduling()
                    self.write_signal_pdu_binding_fr_configline(
                        f_bind_fr,
                        cast(str, channel["fr-channel"]),
                        slot_id,
                        base_cycle,
                        cycle_rep,
                        cycle_cnt,
                        pdu_id,
                    )

    def write_pdus_over_someip_config(self, f_id: TextIO, f_sig: TextIO, f_sigv: TextIO, f_bind: TextIO, version: int = 2) -> None:
        for sid in sorted(self.__services__):
            serv = self.__services__[sid]

            for key in sorted(serv.methods()):
                method = serv.methods()[key]

                if not method.legacy():
                    continue

                if method.calltype() == "REQUEST_RESPONSE":
                    # Request:
                    pdu_id = self.next_global_pdu_id()

                    # signal pdu
                    self.write_signal_pdu_configline(f_id, pdu_id, method.name())

                    # signals
                    self.write_someip_signal_configlines(f_sig, f_sigv, pdu_id, method.name(), method.inparams())
                    # binding
                    self.write_signal_pdu_binding_someip_configline(f_bind, serv, method, 0x00, pdu_id)

                    # Response:
                    pdu_id = self.next_global_pdu_id()

                    # signal pdu
                    self.write_signal_pdu_configline(f_id, pdu_id, method.name())

                    # signals
                    self.write_someip_signal_configlines(f_sig, f_sigv, pdu_id, method.name(), method.outparams())
                    # binding
                    self.write_signal_pdu_binding_someip_configline(f_bind, serv, method, 0x80, pdu_id)
                else:
                    pdu_id = self.next_global_pdu_id()
                    # signal pdu
                    self.write_signal_pdu_configline(f_id, pdu_id, method.name())

                    # signals
                    self.write_someip_signal_configlines(f_sig, f_sigv, pdu_id, method.name(), method.inparams())
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

                    getter = field.getter()
                    if getter is not None:
                        # binding (only response has payload)
                        self.write_signal_pdu_binding_someip_configline(f_bind, serv, getter, 0x80, pdu_id)

                    setter = field.setter()
                    if setter is not None:
                        # binding
                        self.write_signal_pdu_binding_someip_configline(f_bind, serv, setter, 0x00, pdu_id)
                        self.write_signal_pdu_binding_someip_configline(f_bind, serv, setter, 0x80, pdu_id)

                    notifier = field.notifier()
                    if notifier is not None:
                        # binding
                        self.write_signal_pdu_binding_someip_configline(f_bind, serv, notifier, 0x02, pdu_id)

    def collect_all_ethernet_pdus_from_sockets(self) -> dict[int, BaseEthernetPDUInstance]:
        eth_pdus: dict[int, BaseEthernetPDUInstance] = {}

        # We assume that Ethernet PDUs have globally unique IDs...
        for socket in self.__sockets__:
            for p in socket.incoming_pdus():
                peth = cast(BaseEthernetPDUInstance, p)
                if peth.pdu() is not None:
                    header_id = peth.header_id()
                    assert header_id is not None
                    eth_pdus[header_id] = peth

            for p in socket.outgoing_pdus():
                peth = cast(BaseEthernetPDUInstance, p)
                if peth.pdu() is not None:
                    header_id = peth.header_id()
                    assert header_id is not None
                    eth_pdus[header_id] = peth

        return eth_pdus

    def write_pdus_over_ethernet_config(self, f_id: TextIO, f_sig: TextIO, f_sigv: TextIO, f_bind: TextIO, version: int = 2) -> None:
        eth_pdus = self.collect_all_ethernet_pdus_from_sockets()

        for p_key in sorted(eth_pdus):
            p = eth_pdus[p_key]
            header_id = p.header_id()
            pdu = p.pdu()
            assert pdu is not None
            assert header_id is not None
            pdu_id = self.next_global_pdu_id()

            self.write_signal_pdu_configline(f_id, pdu_id, pdu.name())

            # signals
            self.write_signal_pdu_signal_configlines(f_sig, f_sigv, pdu_id, pdu.name(), {0: p})

            # binding
            f_bind.write(f'"{header_id:08x}",' f'"{pdu_id:08x}"\n')

    def write_pdu_configs(
        self,
        target_dir: str,
        fn_id: str,
        fn_sig: str,
        fn_sigv: str,
        fn_bind_someip: str,
        fn_bind_eth_pdus: str,
        fn_can_if: str,
        fn_bind_can: str,
        fn_bind_fr: str,
        version: int = 2,
    ) -> None:
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

    def write_transport_pdu_config(self, filename: str, version: int = 2) -> None:
        if version < 2:
            return

        eth_pdus = self.collect_all_ethernet_pdus_from_sockets()

        # ID, Name
        f = open(filename, "w")
        f.write("# This file is automatically generated, DO NOT MODIFY. (LV)\n")

        for p_key in sorted(eth_pdus):
            p = eth_pdus[p_key]
            header_id = p.header_id()
            pdu = p.pdu()
            assert pdu is not None

            f.write(f'"{header_id:08x}",' f'"{pdu.name()}"\n')

        f.close()


class SOMEIPService(SOMEIPBaseService):
    def create_backlinks(self, factory: BaseConfigurationFactory) -> None:
        for mi in self.__methods__.values():
            cast(_WSBacklinkServiceItem, mi).create_backlinks(factory, self)
        for ei in self.__events__.values():
            cast(_WSBacklinkServiceItem, ei).create_backlinks(factory, self)
        for fi in self.__fields__.values():
            cast(_WSBacklinkServiceItem, fi).create_backlinks(factory, self)


class SOMEIPServiceMethod(SOMEIPBaseServiceMethod):
    def create_backlinks(self, factory: BaseConfigurationFactory, service: SOMEIPBaseService) -> None:
        tmp: list[SOMEIPBaseParameter] = []
        for p in self.__inparams__:
            if p is not None:
                tmp.append(cast(_WSBacklinkParam, p).create_backlinks(factory, service, self))
        self.__inparams__ = tmp

        tmp = []
        for p in self.__outparams__:
            if p is not None:
                tmp.append(cast(_WSBacklinkParam, p).create_backlinks(factory, service, self))
        self.__outparams__ = tmp


class SOMEIPServiceEvent(SOMEIPBaseServiceEvent):
    def create_backlinks(self, factory: BaseConfigurationFactory, service: SOMEIPBaseService) -> None:
        tmp: list[SOMEIPBaseParameter] = []
        for p in self.__params__:
            if p is not None:
                tmp.append(cast(_WSBacklinkParam, p).create_backlinks(factory, service, self))
        self.__params__ = tmp


class SOMEIPServiceField(SOMEIPBaseServiceField):
    def create_backlinks(self, factory: BaseConfigurationFactory, service: SOMEIPBaseService) -> None:
        if self.__getter__ is not None:
            cast(_WSBacklinkServiceItem, self.__getter__).create_backlinks(factory, service)
        if self.__setter__ is not None:
            cast(_WSBacklinkServiceItem, self.__setter__).create_backlinks(factory, service)
        if self.__notifier__ is not None:
            cast(_WSBacklinkServiceItem, self.__notifier__).create_backlinks(factory, service)


class SOMEIPParameter(SOMEIPBaseParameter):
    def __init__(
        self,
        position: int,
        name: str,
        desc: str | None,
        mandatory: bool,
        datatype: SOMEIPBaseDatatype | None,
        signal: BaseSignal | None,
    ) -> None:
        super(SOMEIPParameter, self).__init__(position, name, desc, mandatory, datatype, signal)

        self.__parent_service__: SOMEIPBaseService | None = None
        self.__parent_method__: _WSMethodLike | None = None

    def create_backlinks(self, factory: BaseConfigurationFactory | None, service: SOMEIPBaseService | None, method: object) -> SOMEIPBaseParameter:
        if factory is None or (self.__parent_service__ is None and self.__parent_method__ is None):
            self.__parent_service__ = service
            self.__parent_method__ = cast(_WSMethodLike | None, method)

            if self.__datatype__ is None:
                print(f"ERROR: create_backlinks __datatype__ is None {cast(SOMEIPBaseService, service).name()} {cast(_WSMethodLike, method).name()}")
                return self

            self.__datatype__ = cast(_WSBacklinkDatatype, self.__datatype__).create_backlinks(factory, service, method)
            return self
        else:
            ret = factory.create_someip_parameter(
                self.__position__,
                self.__name__,
                self.__desc__,
                self.__mandatory__,
                self.__datatype__,
                self.__signal__,
            )
            return cast(_WSBacklinkParam, ret).create_backlinks(factory, service, method)

    def parent_service(self) -> SOMEIPBaseService | None:
        return self.__parent_service__

    def parent_method(self) -> _WSMethodLike | None:
        return self.__parent_method__


class SOMEIPParameterBasetype(SOMEIPBaseParameterBasetype):
    def __init__(
        self,
        globalid: int,
        name: str,
        datatype: str,
        bigendian: bool,
        bitlength_basetype: int,
        bitlength_encoded_type: int,
    ) -> None:
        super(SOMEIPParameterBasetype, self).__init__(name, datatype, bigendian, bitlength_basetype, bitlength_encoded_type)
        self.__globalid__ = int(globalid)

    def create_backlinks(
        self, factory: BaseConfigurationFactory | None, service: SOMEIPBaseService | None, method: object
    ) -> SOMEIPParameterBasetype:
        return self

    def globalid(self, version: int) -> int:
        return self.__globalid__

    @staticmethod
    def paramtype(version: int) -> int:
        return WiresharkParameterTypes.basetype

    def ws_config_line(self, version: int = 1) -> str:
        # Type-ID,Name,Datatype,BigEndian,BitlengthBase,BiglengthEncoded

        if version == 1:
            endianess = 1 if self.bigendian() else 0
            return '"%08x","%s","%s","%d","%d","%d"\n' % (
                self.globalid(version),
                self.name(),
                translate_datatype(self.datatype()),
                endianess,
                self.bitlength_basetype(),
                self.bitlength_encoded_type(),
            )
        else:
            # remove non SOME/IP datatypes since they are configured as Signal-PDU configs
            if self.bitlength_basetype() not in (8, 16, 32, 64):
                return ""
            if self.bitlength_basetype() != self.bitlength_encoded_type():
                return ""

            endianess_str = "TRUE" if self.bigendian() else "FALSE"
            return '"%08x","%s","%s","%s","%d","%d"\n' % (
                self.globalid(version),
                self.name(),
                translate_datatype(self.datatype()),
                endianess_str,
                self.bitlength_basetype(),
                self.bitlength_encoded_type(),
            )


class SOMEIPParameterString(SOMEIPBaseParameterString):
    def __init__(
        self,
        globalid: int,
        name: str,
        chartype: str,
        bigendian: bool,
        lowerlimit: int,
        upperlimit: int,
        termination: str | None,
        length_of_length: int | None,
        pad_to: int,
    ) -> None:
        super(SOMEIPParameterString, self).__init__(
            name,
            chartype,
            bigendian,
            lowerlimit,
            upperlimit,
            termination,
            length_of_length,
            pad_to,
        )
        self.__globalid__ = int(globalid)

    def create_backlinks(self, factory: BaseConfigurationFactory | None, service: SOMEIPBaseService | None, method: object) -> SOMEIPParameterString:
        return self

    def globalid(self, version: int) -> int:
        return self.__globalid__

    @staticmethod
    def paramtype(version: int) -> int:
        return WiresharkParameterTypes.string

    def ws_config_line(self, version: int = 1) -> str:
        if version == 1:
            # String-ID,Name,Encoding,Dynamic_Length,Max-Length,Length-Field-Size,Big-Endian,Bit-Alignment
            dynlength = 0 if self.lowerlimit() == self.upperlimit() else 1
            endianess = 1 if self.bigendian() else 0
            return '"%08x","%s","%s","%d","%d","%d","%d","%d"\n' % (
                self.globalid(version),
                self.name(),
                self.chartype().lower(),
                dynlength,  # self.lowerlimit(),
                self.upperlimit() if self.upperlimit() >= 0 else 0,
                self.length_of_length(),
                endianess,
                self.pad_to(),
            )
        else:
            # String-ID,Name,Encoding,Dynamic_Length,Max-Length,Length-Field-Size,Big-Endian,Bit-Alignment
            dynlength_str = "FALSE" if self.lowerlimit() == self.upperlimit() else "TRUE"
            endianess_str = "TRUE" if self.bigendian() else "FALSE"
            return '"%08x","%s","%s","%s","%d","%d","%s","%d"\n' % (
                self.globalid(version),
                self.name(),
                self.chartype().lower(),
                dynlength_str,  # self.lowerlimit(),
                self.upperlimit() if self.upperlimit() >= 0 else 0,
                self.length_of_length(),
                endianess_str,
                self.pad_to(),
            )


class SOMEIPParameterArray(SOMEIPBaseParameterArray):
    def __init__(
        self,
        globalid: int,
        name: str,
        dims: dict[int, SOMEIPBaseParameterArrayDim],
        child: SOMEIPBaseDatatype,
    ) -> None:
        super(SOMEIPParameterArray, self).__init__(name, dims, child)
        self.__globalid__ = int(globalid)

        self.__parent_service__: SOMEIPBaseService | None = None
        self.__parent_method__: _WSMethodLike | None = None

    def create_backlinks(self, factory: BaseConfigurationFactory | None, service: SOMEIPBaseService | None, method: object) -> SOMEIPBaseDatatype:
        if factory is None or (self.__parent_service__ is None and self.__parent_method__ is None):
            self.__parent_service__ = service
            self.__parent_method__ = cast(_WSMethodLike | None, method)

            self.__child__ = cast(_WSBacklinkDatatype, self.__child__).create_backlinks(factory, service, method)

            return self
        else:
            ret = factory.create_someip_parameter_array(self.__name__, self.__dims__, self.__child__)

            return cast(_WSBacklinkDatatype, ret).create_backlinks(factory, service, method)

    def globalid(self, version: int) -> int:
        return self.__globalid__

    @staticmethod
    def paramtype(version: int) -> int:
        return WiresharkParameterTypes.array

    def ws_config_line(self, version: int = 1) -> str:
        # Array-ID,Name,DT-Type,DT-ID,MaxDim,Dim,Min,Max,LenOfLen,PadTo

        if self.__parent_service__ is None or self.__parent_method__ is None:
            print(f"    WARNING: array ({self.name()}) is not attached to service!")

        ret = ""
        for key in self.dims():
            d = self.dims()[key]
            ret += '"%08x","%s","%d","%08x","%d"' % (
                self.globalid(version),
                self.name(),
                cast(_WSDatatype, self.child()).paramtype(version),
                cast(_WSDatatype, self.child()).globalid(version),
                len(self.dims()),
            )
            if version > 1:
                filter_string = f',"invalid.invalid.{self.name()}"'
                if self.__parent_service__ is not None and self.__parent_method__ is not None:
                    filter_string = f',"{self.__parent_service__.name()}.{self.__parent_method__.name()}.{self.name()}"'

                ret += filter_string.replace(" ", "")

            ret += ',"%d","%d","%d","%d","%d"\n' % (
                d.dim() - 1,
                d.lowerlimit(),
                d.upperlimit(),
                d.length_of_length(),
                d.pad_to(),
            )
        return ret


class SOMEIPParameterStruct(SOMEIPBaseParameterStruct):
    def __init__(
        self,
        globalid: int,
        name: str,
        length_of_length: int | None,
        pad_to: int,
        members: dict[int, SOMEIPBaseParameterStructMember],
        tlv: bool,
    ) -> None:
        super(SOMEIPParameterStruct, self).__init__(name, length_of_length, pad_to, members, tlv)
        self.__globalid__ = int(globalid)

        self.__parent_service__: SOMEIPBaseService | None = None
        self.__parent_method__: _WSMethodLike | None = None

    def create_backlinks(self, factory: BaseConfigurationFactory | None, service: SOMEIPBaseService | None, method: object) -> SOMEIPBaseDatatype:
        if factory is None or (self.__parent_service__ is None and self.__parent_method__ is None):
            self.__parent_service__ = service
            self.__parent_method__ = cast(_WSMethodLike | None, method)

            tmp: dict[int, SOMEIPBaseParameterStructMember] = {}
            for k in self.__members__.keys():
                tmp[k] = cast(_WSBacklinkStructMember, self.__members__[k]).create_backlinks(factory, service, method)
            self.__members__ = tmp

            return self
        else:
            ret = factory.create_someip_parameter_struct(
                self.__name__,
                self.__lengthOfLength__,
                self.__padTo__,
                self.__members__,
                self.__tlv__,
            )

            return cast(_WSBacklinkDatatype, ret).create_backlinks(factory, service, method)

    def globalid(self, version: int) -> int:
        return self.__globalid__

    @staticmethod
    def paramtype(version: int) -> int:
        return WiresharkParameterTypes.struct

    def ws_config_line(self, version: int = 1) -> str:
        # Struct-ID,Struct Name,Length of length field,Align to,Number of items,Position,Name,Data Type,Datatype ID
        ret = ""

        if self.__parent_service__ is None or self.__parent_method__ is None:
            print(f"    WARNING: struct ({self.name()}) is not attached to service!")
        else:
            if version == 2 and self.__parent_method__.legacy():
                if DEBUG_LEGACY_STRIPPING:
                    print(
                        f"--> Skipping struct {self.name()} of Service {self.__parent_service__.name()} and Method {self.__parent_method__.name()}"
                    )
                return ret

        number_of_entries = len(self.members())

        # first pass: check numbering and that all positions are below numbers_of_entries
        error_found = False
        last_pos = -1
        for key in sorted(self.members().keys()):
            m = self.members()[key]

            # check position
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
                print(
                    f"\n  ERROR: Position of SOME/IP Struct Member {m.name()} {m.position()} > number_of_entries {number_of_entries}!\n"
                    f"  Adjusting number_of_entries to {m.position() + 1} [{self.name()}]"
                )
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
            ret += '"%08x","%s","%d","%d"' % (
                self.globalid(version),
                self.name(),
                self.length_of_length(),
                self.pad_to(),
            )

            if version > 1:
                if self.tlv():
                    ret += ',"TRUE"'
                else:
                    ret += ',"FALSE"'

            ret += ',"%d"' % number_of_entries

            ret += ',"%d","%s","%d","%08x"' % (
                m.position(),
                m.name(),
                cast(_WSDatatype, m.child()).paramtype(version),
                cast(_WSDatatype, m.child()).globalid(version),
            )
            if version > 1:
                if self.__parent_service__ is None or self.__parent_method__ is None:
                    ret += f',"invalid.invalid.{m.name()}"'
                else:
                    ret += f',"{self.__parent_service__.name()}.{self.__parent_method__.name()}.{m.name()}"'

            ret += "\n"
        return ret


class SOMEIPParameterStructMember(SOMEIPBaseParameterStructMember):
    def __init__(
        self,
        position: int,
        name: str,
        mandatory: bool,
        child: SOMEIPBaseDatatype,
        signal: BaseSignal | None,
    ) -> None:
        super(SOMEIPParameterStructMember, self).__init__(position, name, mandatory, child, signal)

        self.__parent_service__: SOMEIPBaseService | None = None
        self.__parent_method__: _WSMethodLike | None = None

    def create_backlinks(
        self, factory: BaseConfigurationFactory | None, service: SOMEIPBaseService | None, method: object
    ) -> SOMEIPBaseParameterStructMember:
        if factory is None or (self.__parent_service__ is None and self.__parent_method__ is None):
            self.__parent_service__ = service
            self.__parent_method__ = cast(_WSMethodLike | None, method)

            if self.__child__ is not None:
                self.__child__ = cast(_WSBacklinkDatatype, self.__child__).create_backlinks(factory, service, method)

            return self
        else:
            ret = factory.create_someip_parameter_struct_member(
                self.__position__,
                self.__name__,
                self.__mandatory__,
                self.__child__,
                self.__signal__,
            )

            return cast(_WSBacklinkStructMember, ret).create_backlinks(factory, service, method)


class SOMEIPParameterTypedef(SOMEIPBaseParameterTypedef):
    def __init__(self, globalid: int, name: str, name2: str, child: SOMEIPBaseDatatype) -> None:
        super(SOMEIPParameterTypedef, self).__init__(name, name2, child)
        self.__globalid__ = int(globalid)

        self.__parent_service__: SOMEIPBaseService | None = None
        self.__parent_method__: _WSMethodLike | None = None

    def create_backlinks(self, factory: BaseConfigurationFactory | None, service: SOMEIPBaseService | None, method: object) -> SOMEIPBaseDatatype:
        if factory is None or (self.__parent_service__ is None and self.__parent_method__ is None):
            self.__parent_service__ = service
            self.__parent_method__ = cast(_WSMethodLike | None, method)

            self.__child__ = cast(_WSBacklinkDatatype, self.__child__).create_backlinks(factory, service, method)

            return self
        else:
            ret = factory.create_someip_parameter_typedef(self.__name__, self.__name2__, self.__child__)

            return cast(_WSBacklinkDatatype, ret).create_backlinks(factory, service, method)

    def globalid(self, version: int) -> int:
        return self.__globalid__

    @staticmethod
    def paramtype(version: int) -> int:
        return WiresharkParameterTypes.typedef

    def ws_config_line(self, version: int = 1) -> str:
        # Typedef ID,Typedef Name,Data Type,Datatype ID

        ret = '"%08x","%s","%d","%08x"\n' % (
            self.globalid(version),
            self.name(),
            cast(_WSDatatype, self.child()).paramtype(version),
            cast(_WSDatatype, self.child()).globalid(version),
        )
        return ret


class SOMEIPParameterEnumeration(SOMEIPBaseParameterEnumeration):
    def __init__(
        self,
        globalid: int,
        name: str,
        items: list[SOMEIPBaseParameterEnumerationItem],
        child: SOMEIPBaseDatatype,
    ) -> None:
        super(SOMEIPParameterEnumeration, self).__init__(name, items, child)
        self.__globalid__ = int(globalid)

        assert isinstance(child, SOMEIPParameterBasetype)

    def create_backlinks(
        self, factory: BaseConfigurationFactory | None, service: SOMEIPBaseService | None, method: object
    ) -> SOMEIPParameterEnumeration:
        return self

    def globalid(self, version: int) -> int:
        return self.__globalid__

    @staticmethod
    def paramtype(version: int) -> int:
        return WiresharkParameterTypes.enum

    def ws_config_line(self, version: int = 1) -> str:
        # Enum-ID,Name,Datatype,Datatype ID,NumOfEntries,Value,Value-Name
        # "136c9","Enumeration1","1","12ff6","6","2","One"
        # "136c9","Enumeration1","1","12ff6","6","3","Two"
        ret = ""
        for i in self.items():
            ret += '"%08x","%s","%d","%08x","%d","%x","%s"\n' % (
                self.globalid(version),
                self.name(),
                cast(_WSDatatype, self.child()).paramtype(version),
                cast(_WSDatatype, self.child()).globalid(version),
                len(self.items()),
                i.value(),
                i.name(),
            )
        return ret


class SOMEIPParameterUnion(SOMEIPBaseParameterUnion):
    def __init__(
        self,
        globalid: int,
        name: str,
        length_of_length: int | None,
        length_of_type: int | None,
        pad_to: int,
        members: dict[int, SOMEIPBaseParameterUnionMember],
    ) -> None:
        super(SOMEIPParameterUnion, self).__init__(name, length_of_length, length_of_type, pad_to, members)
        self.__globalid__ = int(globalid)

        self.__parent_service__: SOMEIPBaseService | None = None
        self.__parent_method__: _WSMethodLike | None = None

    def create_backlinks(self, factory: BaseConfigurationFactory | None, service: SOMEIPBaseService | None, method: object) -> SOMEIPBaseDatatype:
        if factory is None or (self.__parent_service__ is None and self.__parent_method__ is None):
            self.__parent_service__ = service
            self.__parent_method__ = cast(_WSMethodLike | None, method)

            tmp: dict[int, SOMEIPBaseParameterUnionMember] = {}
            for k in self.__members__.keys():
                tmp[k] = cast(_WSBacklinkUnionMember, self.__members__[k]).create_backlinks(factory, service, method)
            self.__members__ = tmp

            return self
        else:
            ret = factory.create_someip_parameter_union(
                self.__name__, self.__lengthOfLength__, self.__lengthOfType__, self.__padTo__, self.__members__
            )

            return cast(_WSBacklinkDatatype, ret).create_backlinks(factory, service, method)

    def globalid(self, version: int) -> int:
        return self.__globalid__

    @staticmethod
    def paramtype(version: int) -> int:
        return WiresharkParameterTypes.union

    def ws_config_line(self, version: int = 1) -> str:
        # Union-ID,Name,Length of length,Length of Type,Align to,Number of items,Index,Name,Data Type,Datatype ID

        if self.__parent_service__ is None or self.__parent_method__ is None:
            print(f"    WARNING: union ({self.name()}) is not attached to service!")

        ret = ""
        for key in self.members():
            m = self.members()[key]
            ret += '"%08x","%s","%d","%d","%d","%d"' % (
                self.globalid(version),
                self.name(),
                self.length_of_length(),
                self.length_of_type(),
                self.pad_to(),
                len(self.members()),
            )
            ret += ',"%d","%s","%d","%08x"' % (
                m.index(),
                m.name(),
                cast(_WSDatatype, m.child()).paramtype(version),
                cast(_WSDatatype, m.child()).globalid(version),
            )
            if version > 1:
                filter_string = f',"invalid.invalid.{m.name()}"'
                if self.__parent_service__ is not None and self.__parent_method__ is not None:
                    filter_string = f',"{self.__parent_service__.name()}.{self.__parent_method__.name()}.{m.name()}"'
                ret += filter_string.replace(" ", "")
            ret += "\n"
        return ret


class SOMEIPParameterUnionMember(SOMEIPBaseParameterUnionMember):
    def __init__(self, index: int, name: str, mandatory: bool, child: SOMEIPBaseDatatype) -> None:
        super(SOMEIPParameterUnionMember, self).__init__(index, name, mandatory, child)

        self.__parent_service__: SOMEIPBaseService | None = None
        self.__parent_method__: _WSMethodLike | None = None

    def create_backlinks(
        self, factory: BaseConfigurationFactory | None, service: SOMEIPBaseService | None, method: object
    ) -> SOMEIPBaseParameterUnionMember:
        if factory is None or (self.__parent_service__ is None and self.__parent_method__ is None):
            self.__parent_service__ = service
            self.__parent_method__ = cast(_WSMethodLike | None, method)

            self.__child__ = cast(_WSBacklinkDatatype, self.__child__).create_backlinks(factory, service, method)

            return self
        else:
            ret = factory.create_someip_parameter_union_member(self.__index__, self.__name__, self.__mandatory__, self.__child__)

            return cast(_WSBacklinkUnionMember, ret).create_backlinks(factory, service, method)


class SOMEIPParameterBitfield(SOMEIPBaseParameterBitfield):
    def __init__(
        self,
        globalid: int,
        name: str,
        items: list[SOMEIPBaseParameterBitfieldItem],
        child: SOMEIPBaseDatatype,
    ) -> None:
        super(SOMEIPParameterBitfield, self).__init__(name, items, child)
        self.__globalid__ = int(globalid)

        assert isinstance(child, SOMEIPParameterBasetype)

    def create_backlinks(
        self, factory: BaseConfigurationFactory | None, service: SOMEIPBaseService | None, method: object
    ) -> SOMEIPParameterBitfield:
        return self

    def globalid(self, version: int) -> int:
        if version >= 3:
            return self.__globalid__
        else:
            return cast(_WSDatatype, self.child()).globalid(version)

    def paramtype(self, version: int) -> int:
        if version >= 3:
            return WiresharkParameterTypes.bitfield
        else:
            return cast(_WSDatatype, self.child()).paramtype(version)

    def ws_config_line(self, version: int = 3) -> str:
        # "ID","Name","Number of Bits","Number of Items","Bit Number","Bit Name"
        # "0", "BF8", "8", "8", "0", "bit_0", "BF8.bit_0"
        ret = ""
        for i in self.items():
            ret += '"%08x","%s","%d","%d","%d","%s","%s"\n' % (
                self.globalid(version),
                self.name(),
                cast(SOMEIPParameterBasetype, self.child()).bitlength_basetype(),
                len(self.items()),
                i.bit_number(),
                i.name(),
                f"{self.name()}.{i.name()}".replace(" ", ""),
            )
        return ret


def help_and_exit() -> NoReturn:
    print("illegal arguments!")
    print(f"  {sys.argv[0]} type filename")
    print(f"  example: {sys.argv[0]} FIBEX test.xml")
    sys.exit(-1)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Converting configuration to text.")
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


def main() -> None:
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

    output_dir = parse_input_files(
        args.filename,
        args.type,
        conf_factory,
        plugin_file=args.plugin,
        ecu_name_replacement=ecu_name_mapping,
    )

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
