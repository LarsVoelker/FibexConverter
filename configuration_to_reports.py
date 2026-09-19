#!/usr/bin/python

# Automotive configuration file scripts
# Copyright (C) 2015-2026  Dr. Lars Voelker
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

from __future__ import annotations

import argparse
import os.path
import time
from builtins import str as builtin_str
from collections.abc import Iterable
from typing import Protocol, TextIO, cast

from configuration_base_classes import (
    BaseConfigurationFactory,
    BaseController,
    BaseECU,
    BaseFrameTriggering,
    BaseInterface,
    BaseSignal,
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
)
from parser_dispatcher import (
    is_file_or_dir_valid,
    parse_input_files,
    parser_formats,
)


class _HasStr(Protocol):
    def str(self, indent: int) -> str: ...


class SimpleConfigurationFactory(BaseConfigurationFactory):

    def __init__(self) -> None:
        self.__services__: dict[str, SOMEIPService] = dict()
        self.__services_long__: dict[str, SOMEIPService] = dict()
        self.__ecus__: dict[str, ECU] = dict()

    def create_ecu(self, name: str, controllers: list[BaseController]) -> ECU:
        ret = ECU(name, controllers)
        assert name not in self.__ecus__
        self.__ecus__[name] = ret
        return ret

    def create_controller(self, name: str, interfaces: list[BaseInterface]) -> Controller:
        ret = Controller(name, interfaces)
        return ret

    def create_interface(
        self,
        name: str,
        vlanid: int | None,
        ips: list[str],
        sockets: list[BaseSocket],
        input_frame_trigs: dict[str, BaseFrameTriggering],
        output_frame_trigs: dict[str, BaseFrameTriggering],
        fr_channel: int | None,
    ) -> Interface:
        ret = Interface(
            name,
            vlanid,
            ips,
            sockets,
            input_frame_trigs,
            output_frame_trigs,
            fr_channel,
        )
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
    ) -> Socket:
        ret = Socket(
            name,
            ip,
            proto,
            portnumber,
            serviceinstances,
            serviceinstanceclients,
            eventhandlers,
            eventgroupreceivers,
        )
        return ret

    def create_someip_service_instance(self, service: SOMEIPBaseService, instanceid: int, protover: int) -> SOMEIPServiceInstance:
        ret = SOMEIPServiceInstance(service, instanceid, protover)
        return ret

    def create_someip_service_instance_client(
        self, service: SOMEIPBaseService, instanceid: int, protover: int, server: SOMEIPBaseServiceInstance | None
    ) -> SOMEIPServiceInstanceClient:
        ret = SOMEIPServiceInstanceClient(service, instanceid, protover, server)
        return ret

    def create_someip_service_eventgroup_sender(
        self, serviceinstance: SOMEIPBaseServiceInstance, eventgroupid: int
    ) -> SOMEIPServiceEventgroupSender:
        ret = SOMEIPServiceEventgroupSender(serviceinstance, eventgroupid)
        return ret

    def create_someip_service_eventgroup_receiver(
        self,
        serviceinstance: SOMEIPBaseServiceInstance,
        eventgroupid: int,
        sender: SOMEIPBaseServiceEventgroupSender | None,
    ) -> SOMEIPServiceEventgroupReceiver:
        ret = SOMEIPServiceEventgroupReceiver(serviceinstance, eventgroupid, sender)
        return ret

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
        print("Adding Service(ID: 0x%04x Ver: %d.%d)" % (serviceid, majorver, minorver))
        #        assert(self.add_service(serviceid, majorver, minorver, ret))
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
        ret = SOMEIPServiceMethod(
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
        return ret

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
        ret = SOMEIPServiceEvent(name, methodid, relia, params, debounce, maxretention, tlv)
        return ret

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

    def create_someip_service_eventgroup(self, name: str, eid: int, eventids: list[int], fieldids: list[int]) -> SOMEIPServiceEventgroup:
        ret = SOMEIPServiceEventgroup(name, eid, eventids, fieldids)
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
        ret = SOMEIPParameter(position, name, desc, mandatory, datatype, signal)
        return ret

    def create_someip_parameter_basetype(
        self, name: str, datatype: str, bigendian: bool, bitlength_basetype: int, bitlength_encoded_type: int
    ) -> SOMEIPParameterBasetype:
        ret = SOMEIPParameterBasetype(name, datatype, bigendian, bitlength_basetype, bitlength_encoded_type)
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
            name,
            chartype,
            bigendian,
            lowerlimit,
            upperlimit,
            termination,
            length_of_length,
            pad_to,
        )
        return ret

    def create_someip_parameter_array(
        self, name: str, dims: dict[int, SOMEIPBaseParameterArrayDim], child: SOMEIPBaseDatatype
    ) -> SOMEIPParameterArray:
        ret = SOMEIPParameterArray(name, dims, child)
        return ret

    def create_someip_parameter_array_dim(
        self, dim: int, lowerlimit: int, upperlimit: int, length_of_length: int | None, pad_to: int
    ) -> SOMEIPParameterArrayDim:
        ret = SOMEIPParameterArrayDim(dim, lowerlimit, upperlimit, length_of_length, pad_to)
        return ret

    def create_someip_parameter_struct(
        self,
        name: str,
        length_of_length: int | None,
        pad_to: int,
        members: dict[int, SOMEIPBaseParameterStructMember],
        tlv: bool = False,
    ) -> SOMEIPParameterStruct:
        ret = SOMEIPParameterStruct(name, length_of_length, pad_to, members, tlv)
        return ret

    def create_someip_parameter_struct_member(
        self, position: int, name: str, mandatory: bool, child: SOMEIPBaseDatatype, signal: BaseSignal | None
    ) -> SOMEIPParameterStructMember:
        ret = SOMEIPParameterStructMember(position, name, mandatory, child, signal)
        return ret

    def create_someip_parameter_typedef(self, name: str, name2: str, child: SOMEIPBaseDatatype) -> SOMEIPParameterTypedef:
        ret = SOMEIPParameterTypedef(name, name2, child)
        return ret

    def create_someip_parameter_enumeration(
        self, name: str, items: list[SOMEIPBaseParameterEnumerationItem], child: SOMEIPBaseDatatype
    ) -> SOMEIPParameterEnumeration:
        ret = SOMEIPParameterEnumeration(name, items, child)
        return ret

    def create_someip_parameter_enumeration_item(self, value: int, name: str, desc: str | None) -> SOMEIPParameterEnumerationItem:
        ret = SOMEIPParameterEnumerationItem(value, name, desc)
        return ret

    def create_someip_parameter_union(
        self,
        name: str,
        length_of_length: int | None,
        length_of_type: int | None,
        pad_to: int,
        members: dict[int, SOMEIPBaseParameterUnionMember],
    ) -> SOMEIPParameterUnion:
        ret = SOMEIPParameterUnion(name, length_of_length, length_of_type, pad_to, members)
        return ret

    def create_someip_parameter_union_member(self, index: int, name: str, mandatory: bool, child: SOMEIPBaseDatatype) -> SOMEIPParameterUnionMember:
        ret = SOMEIPParameterUnionMember(index, name, mandatory, child)
        return ret

    def create_someip_parameter_bitfield(
        self, name: str, items: list[SOMEIPBaseParameterBitfieldItem], child: SOMEIPBaseDatatype
    ) -> SOMEIPParameterBitfield:
        ret = SOMEIPParameterBitfield(name, items, child)
        return ret

    def create_someip_parameter_bitfield_item(self, bit_number: int, name: str) -> SOMEIPParameterBitfieldItem:
        ret = SOMEIPParameterBitfieldItem(bit_number, name)
        return ret

    def add_service(self, serviceid: int, majorver: int, minorver: int, service: SOMEIPService) -> bool:
        sid = "%04x-%02x-%08x" % (serviceid, majorver, minorver)
        if sid in self.__services_long__:
            print("ERROR: Service (SID: 0x%04x, Major-Ver: %d, Minor-Ver: %d) already exists! Not overriding it!" % (serviceid, majorver, minorver))
            return False
        self.__services_long__[sid] = service

        sid = "%04x-%02x" % (serviceid, majorver)
        if sid in self.__services__:
            print(
                f"ERROR: Service (SID: 0x{serviceid:04x}, Major-Ver: {majorver}) "
                + "already exists with a different Minor Version (not {minorver})! Not overriding it!"
            )
            return False
        self.__services__[sid] = service
        return True

    def get_service(self, serviceid: int, majorver: int, minorver: int | None = None) -> SOMEIPService | None:
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

    def get_services(self) -> dict[str, SOMEIPService]:
        return self.__services__

    def __str__(self) -> str:
        ret = "Services: \n"
        for serviceid in sorted(self.__services__):
            ret += self.__services__[serviceid].str(2)

        ret += "\nECUs: \n"
        for name in sorted(self.__ecus__):
            ret += self.__ecus__[name].str(2)

        return ret

    def get_ecu_names(self) -> Iterable[str]:
        return self.__ecus__.keys()

    def get_service_instance_client_relations(self) -> dict[str, dict[str, list[str]]]:
        print("Looking at Service Instances...")
        ret: dict[str, dict[str, list[str]]] = dict()

        for e in self.__ecus__.items():
            ecu = e[1]
            ecu_key = ecu.name()
            print(f"Looking at ECU: {ecu_key}")

            if ecu_key not in ret:
                ret[ecu_key] = dict()

            for c in ecu.controllers():
                for i in c.interfaces():
                    for s in i.sockets():
                        instances = s.instances()
                        if instances is None:
                            continue
                        for si in instances:
                            si_key = cast(SOMEIPServiceInstance, si).key()
                            print(f"  SI key -> {si_key}")
                            if si_key not in ret[ecu_key]:
                                ret[ecu_key][si_key] = []

                            for sic in si.serviceinstanceclients():
                                if sic is None:
                                    print("Error: SIC = None!")
                                elif sic.socket() is None:
                                    print("Error: Socket in SIC (%s) = None!" % (str(sic)))
                                else:
                                    client_ecu_name: str = sic.socket().interface().controller().ecu().name()  # type: ignore[union-attr]
                                    ret[ecu_key][si_key].append(client_ecu_name)
        return ret

    def get_size_of_methods(
        self,
    ) -> list[tuple[SOMEIPService, SOMEIPBaseServiceMethod | SOMEIPBaseServiceEvent | SOMEIPBaseServiceField, str]]:
        ret: list[tuple[SOMEIPService, SOMEIPBaseServiceMethod | SOMEIPBaseServiceEvent | SOMEIPBaseServiceField, str]] = []
        for i in sorted(self.__services__.keys()):
            service = self.__services__[i]
            for m in service.methods():
                ret.append((service, service.methods()[m], "Method"))
            for m in service.events():
                ret.append((service, service.events()[m], "Event"))
            for m in service.fields():
                ret.append((service, service.fields()[m], "Field"))
        return ret


class ECU(BaseECU):
    def str(self, indent: int) -> str:
        ret = indent * " "
        ret += f"ECU {self.__name__}\n"

        for c in cast(list[_HasStr], self.__controllers__):
            ret += c.str(indent + 2)

        return ret


class Controller(BaseController):
    def str(self, indent: int) -> str:
        ret = indent * " "
        ret += f"CTRL {self.__name__}\n"
        for i in cast(list[_HasStr], self.__interfaces__):
            ret += i.str(indent + 2)

        return ret


class Interface(BaseInterface):
    def str(self, indent: int) -> str:
        ret = indent * " "
        ret += "Interface %s (VLAN-ID: 0x%x)\n" % (self.__vlanname__, self.__vlanid__)
        for s in cast(list[_HasStr], self.__sockets__):
            ret += s.str(indent + 2)
        return ret


class Socket(BaseSocket):
    def str(self, indent: int) -> str:
        ret = indent * " "
        ret += "Socket %s %s:%s/%s\n" % (
            self.__name__,
            self.__ip__,
            self.__portnumber__,
            self.__proto__,
        )
        for i in cast(list[_HasStr], self.__instances__):
            ret += i.str(indent + 2)
        for i in cast(list[_HasStr], self.__instanceclients__):
            ret += i.str(indent + 2)
        for c in cast(list[_HasStr], self.__ehs__):
            ret += c.str(indent + 2)
        for c in cast(list[_HasStr], self.__cegs__):
            ret += c.str(indent + 2)
        return ret


class SOMEIPServiceInstance(SOMEIPBaseServiceInstance):
    def str(self, indent: int) -> str:
        ret = indent * " "
        ret += f"ServiceInstance Service-ID: 0x{self.__service__.serviceid():04x} "
        ret += f"Version: {self.__service__.versionstring()} "
        ret += f"Instance-ID: 0x{self.__instanceid__:04x} "
        ret += f"Protover: {self.__protover__}\n"
        return ret

    def key(self) -> builtin_str:
        return "0x%04x-0x%02x-0x%04x-%s" % (
            self.__service__.serviceid(),
            self.__service__.majorversion(),
            self.__instanceid__,
            self.__service__.name(),
        )


class SOMEIPServiceInstanceClient(SOMEIPBaseServiceInstanceClient):
    def str(self, indent: int) -> str:
        ret = indent * " "
        ret += f"ServiceInstanceClient Service-ID: 0x{self.__service__.serviceid():04x} "
        ret += f"Version: {self.__service__.versionstring()} "
        ret += f"Instance-ID: 0x{self.__instanceid__:04x} "
        ret += f"Protover: {self.__protover__}\n"
        return ret


class SOMEIPServiceEventgroupSender(SOMEIPBaseServiceEventgroupSender):
    def str(self, indent: int) -> str:
        ret = indent * " "
        ret += f"EventgroupSender: Service-ID: 0x{self.__si__.service().serviceid():04x} "
        ret += f"Instance-ID: 0x{self.__si__.instanceid():04x} "
        ret += f"Eventgroup-ID: 0x{self.__eventgroupid__:04x}\n"
        return ret


class SOMEIPServiceEventgroupReceiver(SOMEIPBaseServiceEventgroupReceiver):
    def str(self, indent: int) -> str:
        ret = indent * " "
        ret += f"EventgroupReceiver: Service-ID: 0x{self.__si__.service().serviceid():04x} "
        ret += f"Instance-ID: 0x{self.__si__.instanceid():04x} "
        ret += f"Eventgroup-ID: 0x{self.__eventgroupid__:04x}\n"
        return ret


class SOMEIPService(SOMEIPBaseService):
    def str(self, indent: int) -> str:
        ret = indent * " "
        ret += "%s (id: 0x%04x  ver: %d.%d)\n" % (
            self.__name__,
            self.__serviceid__,
            self.__major__,
            self.__minor__,
        )

        for methodid in self.__methods__:
            ret += cast(_HasStr, self.__methods__[methodid]).str(indent + 2)

        for eventsid in self.__events__:
            ret += cast(_HasStr, self.__events__[eventsid]).str(indent + 2)

        for fieldid in self.__fields__:
            ret += cast(_HasStr, self.__fields__[fieldid]).str(indent + 2)

        for egid in self.__eventgroups__:
            ret += cast(_HasStr, self.__eventgroups__[egid]).str(indent + 2)

        return ret


class SOMEIPServiceMethod(SOMEIPBaseServiceMethod):
    def str(self, indent: int) -> str:
        ret = indent * " "
        ret += "Method %s (id: 0x%04x  type: %s  reli: %s)\n" % (
            self.__name__,
            self.__methodid__,
            self.__calltype__,
            self.__reliable__,
        )

        ret += (indent + 2) * " "
        ret += "In Parameters: \n"
        for param in cast(list[_HasStr], self.__inparams__):
            ret += param.str(indent + 4)

        ret += (indent + 2) * " "
        ret += "Out Parameters: \n"
        for param in cast(list[_HasStr], self.__outparams__):
            ret += param.str(indent + 4)

        return ret


class SOMEIPServiceEvent(SOMEIPBaseServiceEvent):
    def str(self, indent: int) -> str:
        ret = indent * " "
        ret += "Event %s (id: 0x%04x  reli: %s)\n" % (
            self.__name__,
            self.__methodid__,
            self.__reliable__,
        )

        for param in cast(list[_HasStr], self.__params__):
            ret += param.str(indent + 2)

        return ret


class SOMEIPServiceField(SOMEIPBaseServiceField):
    def str(self, indent: int) -> str:
        ret = indent * " "
        ret += f"Field {self.__name__}\n"

        indent += 2
        if self.__getter__ is not None:
            ret += indent * " "
            ret += "Getter(id: 0x%04x  reli: %s)\n" % (
                self.__getter__.methodid(),
                self.__getter__.reliable(),
            )

        if self.__setter__ is not None:
            ret += indent * " "
            ret += "Setter(id: 0x%04x  reli: %s)\n" % (
                self.__setter__.methodid(),
                self.__setter__.reliable(),
            )

        if self.__notifier__ is not None:
            ret += indent * " "
            ret += "Notifier(id: 0x%04x  reli: %s)\n" % (
                self.__notifier__.methodid(),
                self.__notifier__.reliable(),
            )

        ret += indent * " "
        ret += "Parameters:\n"
        if self.__params__ is not None:
            for param in cast(list[_HasStr], self.__params__):
                ret += param.str(indent + 2)

        return ret


class SOMEIPServiceEventgroup(SOMEIPBaseServiceEventgroup):
    def str(self, indent: int) -> str:
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
    def str(self, indent: int) -> str:
        ret = indent * " "
        ret += "Parameter %d %s (mandatory: %s)\n" % (
            self.__position__,
            self.__name__,
            self.__mandatory__,
        )
        if self.__datatype__ is None:
            ret += "%sNone\n" % ((indent + 2) * " ")
        else:
            ret += cast(_HasStr, self.__datatype__).str(indent + 2)

        return ret


class SOMEIPParameterBasetype(SOMEIPBaseParameterBasetype):
    #     def str(self):
    #         self.str(0)

    def str(self, indent: int) -> str:
        endian = "BE"
        if not self.__bigendian__:
            endian = "LE"

        ret = indent * " "
        ret += "%s %s %s (%d;%d)\n" % (
            self.__name__,
            self.__datatype__,
            endian,
            self.__bitlength_basetype__,
            self.__bitlength_encoded_type__,
        )
        return ret


class SOMEIPParameterString(SOMEIPBaseParameterString):
    def str(self, indent: int) -> str:
        endian = "BE"
        if not self.__bigendian__:
            endian = "LE"

        ret = indent * " "
        ret += "String %s %s %s (%d;%d) term: %s len: %d pad: %d\n" % (
            self.__name__,
            self.__chartype__,
            endian,
            self.__lowerlimit__,
            self.__upperlimit__,
            self.__termination__,
            self.__lengthOfLength__,
            self.__padTo__,
        )
        return ret


class SOMEIPParameterArray(SOMEIPBaseParameterArray):
    def str(self, indent: int) -> str:
        ret = indent * " "
        ret += "Array {self.__name__}:\n"
        for dim in self.__dims__:
            ret += cast(_HasStr, self.__dims__[dim]).str(indent + 2)
        if self.__child__ is None:
            ret += "%sNone\n" % ((indent + 2) * " ")
        else:
            ret += cast(_HasStr, self.__child__).str(indent + 2)

        return ret


class SOMEIPParameterArrayDim(SOMEIPBaseParameterArrayDim):
    def str(self, indent: int) -> str:
        ret = indent * " "
        ret += "Dimension %d [%d-%d] lengthOfLength: %d padding: %d\n" % (
            self.__dim__,
            self.__lowerlimit__,
            self.__upperlimit__,
            self.__lengthOfLength__,
            self.__padTo__,
        )
        return ret


class SOMEIPParameterStruct(SOMEIPBaseParameterStruct):
    def str(self, indent: int) -> str:
        ret = indent * " "
        ret += f"Struct {self.__name__}:\n"
        if self.__members__ is not None:
            for m in sorted(self.__members__.keys()):
                member = self.__members__[m]
                if member is not None:
                    ret += cast(_HasStr, member).str(indent + 2)
                else:
                    print("ERROR: struct member == None!")

        return ret


class SOMEIPParameterStructMember(SOMEIPBaseParameterStructMember):
    def str(self, indent: int) -> str:
        ret = indent * " "
        ret += "%d %s (mandatory: %s)\n" % (
            self.__position__,
            self.__name__,
            self.__mandatory__,
        )

        if self.__child__ is not None:
            ret += cast(_HasStr, self.__child__).str(indent + 2)

        return ret


class SOMEIPParameterTypedef(SOMEIPBaseParameterTypedef):
    def str(self, indent: int) -> str:
        ret = indent * " "
        ret += "Typedef: %s %s\n" % (self.__name__, self.__name2__)
        if self.__child__ is not None:
            ret += cast(_HasStr, self.__child__).str(indent + 2)
        return ret


class SOMEIPParameterEnumeration(SOMEIPBaseParameterEnumeration):
    def str(self, indent: int) -> str:
        ret = indent * " "
        ret += f"Enumeration {self.__name__}\n"
        ret += cast(_HasStr, self.__child__).str(indent + 2)
        for i in cast(list[_HasStr], self.__items__):
            i.str(indent + 2)
        return ret


class SOMEIPParameterEnumerationItem(SOMEIPBaseParameterEnumerationItem):
    def str(self, indent: int) -> str:
        ret = indent * " "
        ret += f"{self.__value__}: {self.__name__}"
        return ret


class SOMEIPParameterUnion(SOMEIPBaseParameterUnion):
    def str(self, indent: int) -> str:
        ret = indent * " "
        ret += "Union {self.__name__}:\n"
        if self.__members__ is not None:
            for m in sorted(self.__members__.keys()):
                member = self.__members__[m]
                if member is not None:
                    ret += cast(_HasStr, member).str(indent + 2)
                else:
                    print("ERROR: union member == None!")

        return ret


class SOMEIPParameterUnionMember(SOMEIPBaseParameterUnionMember):
    def str(self, indent: int) -> str:
        ret = indent * " "

        ret += "%d %s (mandatory: %s)\n" % (
            self.__index__,
            self.__name__,
            self.__mandatory__,
        )

        if self.__child__ is not None:
            ret += cast(_HasStr, self.__child__).str(indent + 2)

        return ret


class SOMEIPParameterBitfield(SOMEIPBaseParameterBitfield):
    def str(self, indent: int) -> str:
        ret = indent * " "
        ret += f"Bitfield {self.__name__}\n"
        ret += cast(_HasStr, self.__child__).str(indent + 2)
        for i in cast(list[_HasStr], self.__items__):
            ret += i.str(indent + 2)
        return ret


class SOMEIPParameterBitfieldItem(SOMEIPBaseParameterBitfieldItem):
    def str(self, indent: int) -> str:
        ret = indent * " "
        ret += f"Bit {self.__bit_number__}: {self.__name__}\n"
        return ret


def read_string_file(f: TextIO | None) -> list[str]:
    ret: list[str] = []

    if f is not None:
        for line in f.readlines():
            if line[0] != "#":
                ret.append(line.rstrip())

    return ret


def read_hex_integer_file(f: TextIO | None) -> list[int]:
    ret: list[int] = []

    if f is not None:
        for line in f.readlines():
            if line[0] != "#":
                try:
                    i = int(line.rstrip(), 16)
                    ret.append(i)
                except ValueError:
                    print("can't parse line: ", line)

    return ret


def order_ecunames(ecunames: list[str], ecu_order: list[str]) -> list[str]:
    ret: list[str] = []

    for e in ecu_order:
        if e in ecunames:
            ret.append(e)
            ecunames.remove(e)

    # now add the rest
    for e in ecunames:
        ret.append(e)

    return ret


def calc_matrix(
    ignored_ecus: list[str], ignore_services: list[int], ecunames: list[str], data: dict[str, dict[str, list[str]]]
) -> dict[str, dict[str, list[str]]]:
    # create a matrix of Server -> Client -> Service Instances
    # ignore the ECUs on the ignored ECU list
    matrix: dict[str, dict[str, list[str]]] = {}
    for s in ecunames:
        matrix[s] = {}
        for c in ecunames:
            matrix[s][c] = []

    for server in data.keys():
        if server not in ignored_ecus:
            if server not in matrix:
                matrix[server] = {}
            for si in data[server].keys():
                sid = int(si[0:6], 16)
                if sid not in ignore_services:
                    for client in data[server][si]:
                        if client not in ignored_ecus:
                            if client not in matrix[server]:
                                matrix[server][client] = []
                            matrix[server][client].append(si)

    return matrix


# returns a list of affected service-ids
def generate_event_multiple_eg(target_dir: str, filenoext: str, postfix: str, conf_factory: SimpleConfigurationFactory) -> list[int]:
    ret: list[int] = []

    textfile = os.path.join(target_dir, filenoext + postfix)
    f = open(textfile, "w")
    f.write("Service;Service-ID;Type;Event/Field; Method-ID; EGs of Event/Field;Provider\n")

    # stats
    num_services = 0
    num_eventsfields = 0

    for service in sorted(conf_factory.get_services().values(), key=lambda x: x.str(0)):

        overlap_found = False
        refs_events: dict[int, list[int]] = {}
        refs_fields: dict[int, list[int]] = {}

        providers: list[tuple[int, str]] = []
        for si in service.instances():
            if si.socket() is not None:
                ecuname: str = si.socket().interface().controller().ecu().name()  # type: ignore[union-attr]
                tmp = (
                    si.instanceid(),
                    ecuname,
                )
                if tmp not in providers:
                    providers.append(tmp)

        # transform into ref matrices
        for eg in service.eventgroups().values():
            for eventid in eg.eventids():
                if eventid not in refs_events.keys():
                    refs_events[eventid] = []
                refs_events[eventid].append(eg.id())
            for notifierid in eg.fieldids():
                if notifierid not in refs_fields.keys():
                    refs_fields[notifierid] = []
                refs_fields[notifierid].append(eg.id())

        # now check for dupes
        for eventid in refs_events.keys():
            egs = refs_events[eventid]
            if len(egs) > 1:
                egs_text = ""
                for e in egs:
                    egs_text += f"0x{e:04x}, "

                prov_text = ""
                for pp in providers:
                    prov_text += "0x%04x-%s, " % (pp[0], pp[1])
                ev_name: str = service.event(eventid).name()  # type: ignore[union-attr]
                f.write(
                    "%s;0x%04x;Event;%s;0x%04x;%s;%s\n"
                    % (
                        service.name(),
                        service.serviceid(),
                        ev_name,
                        eventid,
                        egs_text,
                        prov_text,
                    )
                )
                num_eventsfields += 1
                overlap_found = True
        for fieldid in refs_fields.keys():
            egs = refs_fields[fieldid]

            if len(egs) > 1:
                egs_text = ""
                for e in egs:
                    egs_text += f"0x{e:04x}, "

                prov_text = ""
                for pp in providers:
                    prov_text += "0x%04x-%s, " % (pp[0], pp[1])

                fd_name: str = service.field(fieldid).name()  # type: ignore[union-attr]
                f.write(
                    "%s;0x%04x;Field;%s;0x%04x;%s;%s\n"
                    % (
                        service.name(),
                        service.serviceid(),
                        fd_name,
                        fieldid,
                        egs_text,
                        prov_text,
                    )
                )
                num_eventsfields += 1
                overlap_found = True
        if overlap_found:
            num_services += 1
            ret.append(service.serviceid())
    f.close()

    return ret


def generate_count_file(target_dir: str, filenoext: str, postfix: str, conf_factory: SimpleConfigurationFactory) -> None:
    # Count Events/Fields per EG
    textfile = os.path.join(target_dir, filenoext + postfix)
    f = open(textfile, "w")

    # write header
    f.write(
        "Service; Service-ID; Service all Event/Notifier bytes; Eventgroup; Eventgroup-ID; Server;"
        + " Eventgroup Count; Event/Notifier Count; EG all Event/Notifier bytes\n"
    )

    for service in sorted(conf_factory.get_services().values(), key=lambda x: x.str(0)):

        # First pass, we calculate all sizes
        max_size_egs: dict[int, int] = {}
        max_size_service = 0

        for eg in service.eventgroups().values():
            maxsize = 0
            for eventid in eg.eventids():
                maxsize += service.event(eventid).size_max_out()  # type: ignore[union-attr]

            for fieldid in eg.fieldids():
                maxsize += service.field(fieldid).size_max_out()  # type: ignore[union-attr]
            max_size_egs[eg.id()] = maxsize
            max_size_service += maxsize

        # Second pass, get the rest.
        for eg in service.eventgroups().values():
            eventcount = len(eg.eventids()) + len(eg.fieldids())

            sis = ""
            for si in service.instances():
                ecuname: str = si.socket().interface().controller().ecu().name()  # type: ignore[union-attr]
                sis = sis + ecuname + ","

            f.write(
                "%s;0x%04x;%d;%s;0x%04x;%s;%d;%d;%d\n"
                % (
                    service.name(),
                    service.serviceid(),
                    max_size_service,
                    eg.name(),
                    eg.id(),
                    sis,
                    len(service.eventgroups()),
                    eventcount,
                    max_size_egs[eg.id()],
                )
            )

    f.close()


def generate_size_file(target_dir: str, filenoext: str, postfix: str, conf_factory: SimpleConfigurationFactory) -> None:
    tmp = conf_factory.get_size_of_methods()

    textfile = os.path.join(target_dir, filenoext + postfix)
    f = open(textfile, "w")

    # write header
    f.write(
        "Service; Service-ID; Service-Instances; Method/Event/Field; Type; Reliable; Method-ID/Event-ID/Notifier-ID;"
        + " Getter-ID; Setter-ID; In-Min-Size; In-Min-Size; Out-Min-Size; Out-Max-Size\n"
    )

    for i in tmp:
        sis = ""
        method_id = -1
        getter_id = -1
        setter_id = -1

        for si in i[0].instances():
            ecuname: str = si.socket().interface().controller().ecu().name()  # type: ignore[union-attr]
            sis = sis + ecuname + ","

        if i[2] == "Field":
            field = i[1]
            assert isinstance(field, SOMEIPBaseServiceField)
            reliable_true = False
            reliable_false = False
            getter = field.getter()
            if getter is not None:
                getter_id = getter.methodid()
                if getter.reliable():
                    reliable_true = True
                else:
                    reliable_false = True
            setter = field.setter()
            if setter is not None:
                setter_id = setter.methodid()
                if setter.reliable():
                    reliable_true = True
                else:
                    reliable_false = True
            notifier = field.notifier()
            if notifier is not None:
                method_id = notifier.methodid()
                if notifier.reliable():
                    reliable_true = True
                else:
                    reliable_false = True
            if reliable_false and not reliable_true:
                reliable = "FALSE"
            elif not reliable_false and reliable_true:
                reliable = "TRUE"
            elif reliable_false and reliable_true:
                reliable = "MIXED"
            else:
                reliable = ""
        else:
            member = i[1]
            assert isinstance(member, (SOMEIPBaseServiceMethod, SOMEIPBaseServiceEvent))
            method_id = member.methodid()
            reliable = "TRUE" if member.reliable() else "FALSE"

        if method_id == -1:
            method_id_str = ""
        else:
            method_id_str = f"0x{method_id:04x}"

        if getter_id == -1:
            getter_id_str = ""
        else:
            getter_id_str = f"0x{getter_id:04x}"

        if setter_id == -1:
            setter_id_str = ""
        else:
            setter_id_str = f"0x{setter_id:04x}"

        f.write(
            "%s;0x%04x;%s;%s;%s;%s;%s;%s;%s;%d;%d;%d;%d\n"
            % (
                i[0].name(),
                i[0].serviceid(),
                sis,
                i[1].name(),
                i[2],
                reliable,
                method_id_str,
                getter_id_str,
                setter_id_str,
                i[1].size_min_in(),
                i[1].size_max_in(),
                i[1].size_min_out(),
                i[1].size_max_out(),
            )
        )
    f.close()


def generate_service_instance_matrix_file(
    target_dir: str,
    filenoext: str,
    postfix: str,
    ecunames: list[str],
    ignore_services: list[int],
    data: dict[str, dict[str, list[str]]],
    service_with_overlapping_events: list[int],
) -> None:
    # dump out the service instance relations as a matrix: server+si x client
    textfile = os.path.join(target_dir, filenoext + postfix)
    f = open(textfile, "w")

    # write header
    f.write("%s;%s;%s;%s;" % ("Server", "Service Instances", "Overlapping Events/Fields?", "# Clients"))
    for client in ecunames:
        f.write(f"{client};")
    f.write("\n")

    for server in ecunames:
        if server in data.keys():
            for si in data[server].keys():
                sid = int(si[0:6], 16)
                overlap = 1 if sid in service_with_overlapping_events else 0
                if sid not in ignore_services:
                    client_count = 0
                    for client in ecunames:
                        if client in data[server][si]:
                            client_count += 1
                    f.write("%s;%s;%d;%d;" % (server, si, overlap, client_count))
                    for client in ecunames:
                        if client in data[server][si]:
                            f.write("1;")
                        else:
                            f.write("0;")
                    f.write("\n")
    f.close()


def generate_service_list(target_dir: str, filenoext: str, postfix: str, ignored_ecus: list[str], matrix: dict[str, dict[str, list[str]]]) -> None:
    # dump out a list of service interfaces per Server-Client-Relation based on the matrix
    textfile = os.path.join(target_dir, filenoext + postfix)

    f = open(textfile, "w")
    f.write("%s;%s;%s\n" % ("Server", "Client", "Service Instances"))

    for server in matrix.keys():
        if server not in ignored_ecus:
            for client in matrix[server].keys():
                if client not in ignored_ecus:
                    silist = list()
                    sis = ""
                    for si in matrix[server][client]:
                        silist.append(si)
                    for si in sorted(silist):
                        if sis != "":
                            sis += ","
                        sis += si

                    if sis != "":
                        f.write("%s;%s;%s\n" % (server, client, sis))
    f.close()


def generate_service_matrix(
    target_dir: str, filenoext: str, postfix: str, ecunames: list[str], ignored_ecus: list[str], matrix: dict[str, dict[str, list[str]]]
) -> None:
    # dump out a matrix (=count of relations) based on the matrix
    textfile = os.path.join(target_dir, filenoext + postfix)
    f = open(textfile, "w")

    # header first
    for client in ecunames:
        if client not in ignored_ecus:
            f.write(f";{client}")

    f.write(";\n")

    for server in ecunames:
        if server not in ignored_ecus:
            f.write(f"{server};")

            for client in ecunames:
                if client not in ignored_ecus:
                    f.write(f"{len(matrix[server][client])};")

        f.write("\n")
    f.close()


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Converting configuration to reports.")
    parser.add_argument("type", choices=parser_formats, help="format")
    parser.add_argument(
        "filename",
        help="filename or directory",
        type=lambda x: is_file_or_dir_valid(parser, x),
    )
    parser.add_argument(
        "--ignore-ecus",
        type=argparse.FileType("r"),
        default=None,
        help="ignore-ecus-list",
    )
    parser.add_argument(
        "--ignore-services",
        type=argparse.FileType("r"),
        default=None,
        help="ignore-services-list",
    )
    parser.add_argument("--ecu-order", type=argparse.FileType("r"), default=None, help="ecu-order")

    args = parser.parse_args()
    return args


def main() -> None:
    print("Converting configuration to reports")
    args = parse_arguments()

    # load configs
    ignored_ecus = read_string_file(args.ignore_ecus)
    ignore_services = read_hex_integer_file(args.ignore_services)
    ecu_order = read_string_file(args.ecu_order)

    conf_factory = SimpleConfigurationFactory()
    output_dir = parse_input_files(args.filename, args.type, conf_factory)
    assert output_dir is not None

    # setup output path
    path, f = os.path.split(args.filename)
    filenoext = ".".join(f.split(".")[:-1])
    target_dir = os.path.join(output_dir, "reports")

    if not os.path.exists(target_dir):
        os.makedirs(target_dir)
        time.sleep(0.5)

    # get the names of all ECUs not on the ignored_ecus list
    ecunamesall = sorted(conf_factory.get_ecu_names())
    ecunames = sorted(conf_factory.get_ecu_names())
    for i in ignored_ecus:
        if i in ecunames:
            ecunames.remove(i)

    ecunames = order_ecunames(ecunames, ecu_order)
    ecunamesall = order_ecunames(ecunamesall, ecu_order)

    # get the data ready
    data = conf_factory.get_service_instance_client_relations()
    matrix = calc_matrix(ignored_ecus, ignore_services, ecunames, data)

    # generate the outputs
    print("")
    print("Generating overlapping EG file")
    service_with_overlapping_events = generate_event_multiple_eg(target_dir, filenoext, "__events_fields_in_multiple_EGs.csv", conf_factory)

    print("Generating Eventgroup statistics")
    generate_count_file(target_dir, filenoext, "__eventgroup_stats.csv", conf_factory)

    print("Generating sizes file")
    generate_size_file(target_dir, filenoext, "__sizes.csv", conf_factory)

    print("Generating instance matrices")
    generate_service_instance_matrix_file(
        target_dir,
        filenoext,
        "__si_matrix_filtered.csv",
        ecunames,
        ignore_services,
        data,
        service_with_overlapping_events,
    )
    generate_service_instance_matrix_file(
        target_dir,
        filenoext,
        "__si_matrix_full.csv",
        ecunamesall,
        [],
        data,
        service_with_overlapping_events,
    )

    print("Generating service instance usage list")
    generate_service_list(target_dir, filenoext, "__service_instance_usage_list.csv", ignored_ecus, matrix)

    print("Generating service instance usage matrix")
    generate_service_matrix(
        target_dir,
        filenoext,
        "__service_instance_usage_matrix.csv",
        ecunames,
        ignored_ecus,
        matrix,
    )

    print("Done.")


# only call main, if we are started directly
if __name__ == "__main__":
    main()
