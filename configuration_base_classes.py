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


def bits_to_bytes(bits):
    if bits % 8 == 0:
        return bits // 8
    else:
        return (bits // 8) + 1


class BaseConfigurationFactory(object):

    def create_ecu(self, name, controllers):
        return BaseECU(name, controllers)

    def create_controller(self, name, vlans):
        return BaseController(name, vlans)

    def create_interface(self, name, vlanid, sockets):
        return BaseInterface(name, vlanid, sockets)

    def create_socket(self, name, ip, proto, portnumber,
                      serviceinstances, serviceinstanceclients, eventhandlers, evengroupreceivers
                      ):
        return BaseSocket(name, ip, proto, portnumber,
                          serviceinstances, serviceinstanceclients, eventhandlers, evengroupreceivers
                          )

    def create_someip_service_instance(self, service, instanceid, protover):
        return SOMEIPBaseServiceInstance(service, instanceid, protover)

    def create_someip_service_instance_client(self, service, instanceid, protover, server):
        return SOMEIPBaseServiceInstanceClient(service, instanceid, protover, server)

    def create_someip_service_eventgroup_sender(self, serviceinstance, eventgroupid):
        return SOMEIPBaseServiceEventgroupSender(serviceinstance, eventgroupid)

    def create_someip_service_eventgroup_receiver(self, serviceinstance, eventgroupid, sender):
        return SOMEIPBaseServiceEventgroupReceiver(serviceinstance, eventgroupid, sender)

    def create_someip_service(self, name, serviceid, majorver, minorver, methods, events, fields, eventgroups):
        return SOMEIPBaseService(name, serviceid, majorver, minorver, methods, events, fields, eventgroups)

    def create_someip_service_method(self, name, methodid, calltype, relia, inparams, outparams,
                                     reqdebounce=-1, reqmaxretention=-1, resmaxretention=-1):
        return SOMEIPBaseServiceMethod(name, methodid, calltype, relia, inparams, outparams,
                                       reqdebounce, reqmaxretention, resmaxretention)

    def create_someip_service_event(self, name, methodid, relia, params,
                                    debounce=-1, maxretention=-1):
        return SOMEIPBaseServiceEvent(name, methodid, relia, params,
                                      debounce, maxretention)

    def create_someip_service_field(self, name, getterid, setterid, notifierid,
                                    getterreli, setterreli, notifierreli, params,
                                    getter_debouncereq, getter_retentionreq, getter_retentionres,
                                    setter_debouncereq, setter_retentionreq, setter_retentionres,
                                    notifier_debounce, notifier_retention):
        ret = SOMEIPBaseServiceField(self, name, getterid, setterid, notifierid,
                                     getterreli, setterreli, notifierreli, params,
                                     getter_debouncereq, getter_retentionreq, getter_retentionres,
                                     setter_debouncereq, setter_retentionreq, setter_retentionres,
                                     notifier_debounce, notifier_retention)
        return ret

    def create_someip_service_eventgroup(self, name, eid, eventids, fieldids):
        return SOMEIPBaseServiceEventgroup(name, eid, eventids, fieldids)

    def create_someip_parameter(self, position, name, desc, mandatory, datatype, signal):
        return SOMEIPBaseParameter(position, name, desc, mandatory, datatype, signal)

    def create_someip_parameter_basetype(self, name, datatype, bigendian, bitlength_basetype, bitlength_encoded_type):
        return SOMEIPBaseParameterBasetype(name, datatype, bigendian, bitlength_basetype, bitlength_encoded_type)

    def create_someip_parameter_string(self, name, chartype, bigendian, lowerlimit, upperlimit, termination,
                                       length_of_length, pad_to
                                       ):
        return SOMEIPBaseParameterString(name, chartype, bigendian, lowerlimit, upperlimit, termination,
                                         length_of_length, pad_to
                                         )

    def create_someip_parameter_array(self, name, dims, child):
        return SOMEIPBaseParameterArray(name, dims, child)

    def create_someip_parameter_array_dim(self, dim, lowerlimit, upperlimit, length_of_length, pad_to):
        return SOMEIPBaseParameterArrayDim(dim, lowerlimit, upperlimit, length_of_length, pad_to)

    def create_someip_parameter_struct(self, name, length_of_length, pad_to, members):
        return SOMEIPBaseParameterStruct(name, length_of_length, pad_to, members)

    def create_someip_parameter_struct_member(self, position, name, mandatory, child, signal):
        return SOMEIPBaseParameterStructMember(position, name, mandatory, child, signal)

    def create_someip_parameter_typedef(self, name, name2, child):
        return SOMEIPBaseParameterTypedef(name, name2, child)

    def create_someip_parameter_enumeration(self, name, items, child):
        return SOMEIPBaseParameterEnumeration(name, items, child)

    def create_someip_parameter_enumeration_item(self, value, name, desc):
        return SOMEIPBaseParameterEnumerationItem(value, name, desc)

    def create_someip_parameter_union(self, name, length_of_length, length_of_type, pad_to, members):
        return SOMEIPBaseParameterUnion(name, length_of_length, length_of_type, pad_to, members)

    def create_someip_parameter_union_member(self, index, name, mandatory, child):
        return SOMEIPBaseParameterUnionMember(index, name, mandatory, child)

    def create_legacy_signal(self, id, name, compu_scale, compu_consts):
        return SOMEIPBaseLegacySignal(id, name, compu_scale, compu_consts)


class BaseItem(object):
    def legacy(self):
        return False


class BaseECU(BaseItem):
    def __init__(self, name, controllers):
        self.__name__ = name
        self.__controllers__ = controllers

        for c in controllers:
            c.set_ecu(self)

    def name(self):
        return self.__name__

    def controllers(self):
        return self.__controllers__


class BaseController(BaseItem):
    def __init__(self, name, interfaces):
        self.__name__ = name
        self.__interfaces__ = interfaces
        self.__ecu__ = None

        for i in interfaces:
            i.set_controller(self)

    def name(self):
        return self.__name__

    def interfaces(self):
        return self.__interfaces__

    def set_ecu(self, ecu):
        self.__ecu__ = ecu

    def ecu(self):
        return self.__ecu__


class BaseInterface(BaseItem):
    def __init__(self, vlanname, vlanid, sockets):
        self.__vlanname__ = vlanname
        self.__sockets__ = sockets

        self.__controller__ = None

        if vlanid is None:
            self.__vlanid__ = 0
        else:
            self.__vlanid__ = int(vlanid)

        for s in sockets:
            s.set_interface(self)

    def vlanname(self):
        return self.__vlanname__

    def vlanid(self):
        return self.__vlanid__

    def sockets(self):
        return self.__sockets__

    def set_controller(self, controller):
        self.__controller__ = controller

    def controller(self):
        return self.__controller__


class BaseSocket(BaseItem):
    def __init__(self, name, ip, proto, portnumber, serviceinstances, serviceinstanceclients, eventhandlers,
                 eventgroupreceivers):
        self.__name__ = name
        self.__ip__ = ip
        self.__proto__ = proto
        self.__portnumber__ = int(portnumber)
        self.__instances__ = serviceinstances
        self.__instanceclients__ = serviceinstanceclients
        self.__ehs__ = eventhandlers
        self.__cegs__ = eventgroupreceivers
        self.__interface__ = None

        if serviceinstances is not None:
            for i in serviceinstances:
                i.setsocket(self)

        if serviceinstanceclients is not None:
            for i in serviceinstanceclients:
                i.setsocket(self)

        if eventhandlers is not None:
            for i in eventhandlers:
                i.setsocket(self)

        if eventgroupreceivers is not None:
            for i in eventgroupreceivers:
                i.setsocket(self)

    def name(self):
        return self.__name__

    def ip(self):
        return self.__ip__

    def proto(self):
        return self.__proto__

    def portnumber(self):
        return self.__portnumber__

    def instances(self):
        return self.__instances__

    def serviceinstanceclients(self):
        return self.__instanceclients__

    def eventhandlers(self):
        return self.__ehs__

    def eventgroupreceivers(self):
        return self.__cegs__

    def set_interface(self, interface):
        self.__interface__ = interface

    def interface(self):
        return self.__interface__


class SOMEIPBaseServiceInstance(BaseItem):
    def __init__(self, service, instanceid, protover):
        self.__service__ = service
        self.__instanceid__ = int(instanceid)
        self.__protover__ = int(protover)
        self.__socket__ = None

        self.__clients__ = []
        self.__eventgroup_sender__ = []
        self.__eventgroup_receiver__ = []

        service.add_instance(self)

    def service(self):
        return self.__service__

    def instanceid(self):
        return self.__instanceid__

    def protover(self):
        return self.__protover__

    def serviceinstanceclients(self):
        return self.__clients__

    def addclient(self, client):
        if client not in self.__clients__:
            self.__clients__.append(client)

    def eventgroupsender(self):
        return self.__eventgroup_sender__

    def addeventgroupsender(self, eh):
        if eh not in self.__eventgroup_sender__:
            self.__eventgroup_sender__.append(eh)

    def eventgroupreceiver(self):
        return self.__eventgroup_receiver__

    def addeventgroupreceiver(self, ceg):
        if ceg not in self.__eventgroup_receiver__:
            self.__eventgroup_receiver__.append(ceg)

    def setsocket(self, socket):
        self.__socket__ = socket

    def socket(self):
        return self.__socket__


class SOMEIPBaseServiceInstanceClient(BaseItem):
    def __init__(self, service, instanceid, protover, instance):
        self.__service__ = service
        self.__instanceid__ = int(instanceid)
        self.__protover__ = int(protover)
        self.__instance__ = instance
        self.__socket__ = None

        if instance is not None:
            instance.addclient(self)

    def service(self):
        return self.__service__

    def instanceid(self):
        return self.__instanceid__

    def protover(self):
        return self.__protover__

    def instance(self):
        return self.__instance__

    def setsocket(self, socket):
        self.__socket__ = socket

    def socket(self):
        return self.__socket__


class SOMEIPBaseServiceEventgroupSender(BaseItem):
    def __init__(self, serviceinstance, eventgroupid):
        self.__si__ = serviceinstance
        self.__eventgroupid__ = int(eventgroupid)
        self.__eventgroupreceivers__ = []
        self.__socket__ = None

    def serviceinstance(self):
        return self.__si__

    def eventgroupid(self):
        return self.__eventgroupid__

    def eventgroupreceivers(self):
        return self.__eventgroupreceivers__

    def addreceiver(self, receiver):
        if receiver not in self.__eventgroupreceivers__:
            self.__eventgroupreceivers__.append(receiver)

    def setsocket(self, socket):
        self.__socket__ = socket

    def socket(self):
        return self.__socket__


class SOMEIPBaseServiceEventgroupReceiver(BaseItem):
    def __init__(self, serviceinstance, eventgroupid, sender):
        self.__si__ = serviceinstance
        self.__eventgroupid__ = int(eventgroupid)
        self.__sender__ = sender
        self.__socket__ = None

        if sender is not None:
            sender.addreceiver(self)

    def serviceinstance(self):
        return self.__si__

    def eventgroupid(self):
        return self.__eventgroupid__

    def sender(self):
        return self.__sender__

    def setsocket(self, socket):
        self.__socket__ = socket

    def socket(self):
        return self.__socket__


class SOMEIPBaseService(BaseItem):
    def __init__(self, name, serviceid, majorver, minorver, methods, events, fields, eventgroups):
        self.__name__ = name
        self.__serviceid__ = int(serviceid)
        self.__major__ = int(majorver)
        self.__minor__ = int(minorver)

        self.__methods__ = methods
        self.__events__ = events
        self.__fields__ = fields
        self.__eventgroups__ = eventgroups

        self.__instances__ = []

    def serviceid(self):
        return self.__serviceid__

    def majorversion(self):
        return self.__major__

    def minorversion(self):
        return self.__minor__

    def versionstring(self):
        return "%d.%d" % (self.__major__, self.__minor__)

    def name(self):
        return self.__name__

    def methods(self):
        return self.__methods__

    def method(self, mid):
        if mid in self.__methods__:
            return self.__methods__[mid]
        return None

    def events(self):
        return self.__events__

    def event(self, eid):
        if eid in self.__events__:
            return self.__events__[eid]
        return None

    def fields(self):
        return self.__fields__

    def field(self, fid):
        if fid in self.__fields__:
            return self.__fields__[fid]
        return None

    def eventgroups(self):
        return self.__eventgroups__

    def eventgroup(self, egid):
        if egid in self.__eventgroups__:
            return self.__eventgroups__[id]
        return None

    def add_instance(self, serviceinstance):
        self.__instances__.append(serviceinstance)

    def remove_instance(self, serviceinstance):
        self.__instances__.remove(serviceinstance)

    def instances(self):
        return self.__instances__


class SOMEIPBaseServiceMethod(BaseItem):
    def __init__(self, name, methodid, calltype, relia, inparams, outparams, reqdebounce=-1, reqmaxretention=-1,
                 resmaxretention=-1):
        self.__name__ = name
        self.__methodid__ = methodid
        self.__calltype__ = calltype
        self.__reliable__ = relia

        self.__inparams__ = inparams
        self.__outparams__ = outparams

        self.__reqdebouncetime__ = reqdebounce
        self.__reqretentiontime___ = reqmaxretention
        self.__resretentiontime___ = resmaxretention

    def methodid(self):
        return self.__methodid__

    def name(self):
        return self.__name__

    def calltype(self):
        return self.__calltype__

    def reliable(self):
        return self.__reliable__

    def inparams(self):
        return self.__inparams__

    def outparams(self):
        return self.__outparams__

    def size_min_in(self):
        ret = 0
        for p in self.__inparams__:
            ret += p.size_min_bits()
        return bits_to_bytes(ret)

    def size_max_in(self):
        ret = 0
        for p in self.__inparams__:
            ret += p.size_max_bits()
        return bits_to_bytes(ret)

    def size_min_out(self):
        ret = 0
        for p in self.__outparams__:
            ret += p.size_min_bits()
        return bits_to_bytes(ret)

    def size_max_out(self):
        ret = 0
        for p in self.__outparams__:
            ret += p.size_max_bits()
        return bits_to_bytes(ret)

    def debounce_time_req(self):
        return self.__reqdebouncetime__

    def max_buffer_retention_time_req(self):
        return self.__reqretentiontime___

    def max_buffer_retention_time_res(self):
        return self.__resretentiontime___

    def legacy(self):
        for p in self.__inparams__:
            if p.legacy():
                return True
        for p in self.__outparams__:
            if p.legacy():
                return True
        return False


class SOMEIPBaseServiceEvent(BaseItem):
    def __init__(self, name, methodid, relia, params, debouncetimerange=-1, maxbufferretentiontime=-1):
        self.__name__ = name
        self.__methodid__ = methodid
        self.__reliable__ = relia
        self.__params__ = params
        self.__debouncetime__ = debouncetimerange
        self.__retentiontime___ = maxbufferretentiontime

    def methodid(self):
        return self.__methodid__

    def name(self):
        return self.__name__

    def reliable(self):
        return self.__reliable__

    def params(self):
        return self.__params__

    @staticmethod
    def size_min_in():
        return 0

    @staticmethod
    def size_max_in():
        return 0

    def size_min_out(self):
        ret = 0
        for p in self.__params__:
            ret += p.size_min_bits()
        return bits_to_bytes(ret)

    def size_max_out(self):
        ret = 0
        for p in self.__params__:
            ret += p.size_max_bits()
        return bits_to_bytes(ret)

    def debounce_time(self):
        return self.__debouncetime__

    def max_buffer_retention_time(self):
        return self.__retentiontime___

    def legacy(self):
        for p in self.__params__:
            if p.legacy():
                return True
        return False


class SOMEIPBaseServiceField(BaseItem):
    def __init__(self, config_factory, name, getterid, setterid, notifierid, getterreli, setterreli, notifierreli,
                 params,
                 getter_reqdebounce=-1, getter_reqmaxretention=-1, getter_resmaxretention=-1,
                 setter_reqdebounce=-1, setter_reqmaxretention=-1, setter_resmaxretention=-1,
                 notifier_debounce=-1, notifier_maxretention=-1):
        self.__name__ = name

        self.__getter__ = None
        self.__setter__ = None
        self.__notifier__ = None
        self.__params__ = params

        self.__minimum_id__ = None

        if getterid is not None:
            self.__getter__ = config_factory.create_someip_service_method(
                name + "-Getter", getterid, "REQUEST_RESPONSE", getterreli, [], params,
                getter_reqdebounce, getter_reqmaxretention, getter_resmaxretention
            )

        if setterid is not None:
            self.__setter__ = config_factory.create_someip_service_method(
                name + "-Setter", setterid, "REQUEST_RESPONSE", setterreli, params, params,
                setter_reqdebounce, setter_reqmaxretention, setter_resmaxretention
            )

        if notifierid is not None:
            self.__notifier__ = config_factory.create_someip_service_event(
                name + "-Notifier", notifierid, notifierreli, params,
                notifier_debounce, notifier_maxretention
            )

        # find smallest ID after stripping None
        tmp = sorted([getterid, setterid, notifierid], key=lambda x: (x is None, x))
        if tmp[0] is None:
            print(f"ERROR: Field ({name}) without Getter/Setter/Notifier!")
            return

        self.__minimum_id__ = tmp[0]

        if self.__minimum_id__ == -1:
            self.__minimum_id__ = None

    def name(self):
        return self.__name__

    def getter(self):
        return self.__getter__

    def setter(self):
        return self.__setter__

    def notifier(self):
        return self.__notifier__

    def min_id(self):
        return self.__minimum_id__

    def notifierid(self):
        if self.__notifier__ is None:
            return None
        return self.__notifier__.methodid()

    def id(self):
        if self.notifierid() is not None:
            return self.notifierid()
        return self.min_id()

    def size_min_in(self):
        ret = 0
        for p in self.__params__:
            ret += p.size_min_bits()
        return bits_to_bytes(ret)

    def size_max_in(self):
        ret = 0
        for p in self.__params__:
            ret += p.size_max_bits()
        return bits_to_bytes(ret)

    def size_min_out(self):
        ret = 0
        for p in self.__params__:
            ret += p.size_min_bits()
        return bits_to_bytes(ret)

    def size_max_out(self):
        ret = 0
        for p in self.__params__:
            ret += p.size_max_bits()
        return bits_to_bytes(ret)

    def legacy(self):
        if self.__params__ is None:
            return False

        for p in self.__params__:
            if p.legacy():
                return True

        return False


class SOMEIPBaseServiceEventgroup(BaseItem):
    def __init__(self, name, egid, eventids, fieldids):
        self.__name__ = name
        self.__id__ = int(egid)
        self.__eventids__ = eventids
        self.__fieldids__ = fieldids

    def name(self):
        return self.__name__

    def id(self):
        return self.__id__

    def eventids(self):
        return self.__eventids__

    def fieldids(self):
        return self.__fieldids__


class SOMEIPBaseParameter(BaseItem):
    def __init__(self, position, name, desc, mandatory, datatype, signal):
        self.__position__ = int(position)
        self.__name__ = name
        self.__desc__ = desc
        self.__mandatory__ = mandatory
        self.__datatype__ = datatype
        self.__signal__ = signal

    def position(self):
        return self.__position__

    def name(self):
        return self.__name__

    def desc(self):
        return self.__desc__

    def mandatory(self):
        return self.__mandatory__

    def datatype(self):
        return self.__datatype__

    def signal(self):
        return self.__signal__

    def size_min_bits(self):
        return self.__datatype__.size_min_bits()

    def size_max_bits(self):
        return self.__datatype__.size_max_bits()

    def legacy(self):
        if self.__signal__ is not None:
            return True
        return self.__datatype__.legacy()


class SOMEIPBaseParameterBasetype(BaseItem):
    def __init__(self, name, datatype, bigendian, bitlength_basetype, bitlength_encoded_type):
        self.__name__ = name
        self.__datatype__ = datatype
        self.__bigendian__ = bigendian
        self.__bitlength_basetype__ = int(bitlength_basetype)
        self.__bitlength_encoded_type__ = int(bitlength_encoded_type)

    def name(self):
        return self.__name__

    def datatype(self):
        return self.__datatype__

    def bigendian(self):
        return self.__bigendian__

    def bitlength_basetype(self):
        return self.__bitlength_basetype__

    def bitlength_encoded_type(self):
        return self.__bitlength_encoded_type__

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False

        return (
                self.name() == other.name() and
                self.datatype() == other.datatype() and
                self.bigendian() == other.bigendian() and
                self.bitlength_basetype() == other.bitlength_basetype() and
                self.bitlength_encoded_type() == other.bitlength_encoded_type()
        )

    def size_min_bits(self):
        return self.__bitlength_encoded_type__

    def size_max_bits(self):
        return self.__bitlength_encoded_type__


class SOMEIPBaseParameterString(BaseItem):
    def __init__(self, name, chartype, bigendian, lowerlimit, upperlimit, termination, length_of_length, pad_to):
        self.__name__ = name
        self.__chartype__ = chartype
        self.__bigendian__ = bigendian
        self.__lowerlimit__ = int(lowerlimit)
        self.__upperlimit__ = int(upperlimit)
        self.__termination__ = termination

        if length_of_length is None or length_of_length == -1:
            if lowerlimit == upperlimit:
                self.__lengthOfLength__ = 0
            else:
                self.__lengthOfLength__ = 32  # SOME/IP default
        else:
            self.__lengthOfLength__ = int(length_of_length)

        self.__padTo__ = int(pad_to)

    def name(self):
        return self.__name__

    def chartype(self):
        return self.__chartype__

    def bigendian(self):
        return self.__bigendian__

    def lowerlimit(self):
        return self.__lowerlimit__

    def upperlimit(self):
        return self.__upperlimit__

    def termination(self):
        return self.__termination__

    def length_of_length(self):
        return self.__lengthOfLength__

    def pad_to(self):
        return self.__padTo__

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False

        return (
                self.name() == other.name() and
                self.chartype() == other.chartype() and
                self.bigendian() == other.bigendian() and
                self.lowerlimit() == other.lowerlimit() and
                self.upperlimit() == other.upperlimit() and
                self.termination() == other.termination() and
                self.length_of_length() == other.length_of_length() and
                self.pad_to() == other.pad_to()
        )

    def size_min_bits(self):
        # TODO: double check, if this is based on bytes or chars
        return self.__lengthOfLength__ + 8 * self.__lowerlimit__

    def size_max_bits(self):
        # TODO: double check, if this is based on bytes or chars
        return self.__lengthOfLength__ + 8 * self.__upperlimit__


class SOMEIPBaseParameterArray(BaseItem):
    def __init__(self, name, dims, child):
        self.__name__ = name
        self.__dims__ = dims
        self.__child__ = child

    def name(self):
        return self.__name__

    def dims(self):
        return self.__dims__

    def child(self):
        return self.__child__

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False

        return self.name() == other.name() and self.dims() == other.dims() and self.child() == other.child()

    def size_min_bits(self):
        ret = self.__child__.size_min_bits()

        # todo: is this the right order?
        for dim in self.__dims__.values():
            ret = dim.calc_size_min_bits(ret)

        return ret

    def size_max_bits(self):
        ret = self.__child__.size_min_bits()

        # todo: is this the right order?
        for dim in self.__dims__.values():
            ret = dim.calc_size_max_bits(ret)

        return ret


class SOMEIPBaseParameterArrayDim(BaseItem):
    def __init__(self, dim, lowerlimit, upperlimit, length_of_length, pad_to):
        self.__dim__ = int(dim)
        self.__lowerlimit__ = int(lowerlimit)
        self.__upperlimit__ = int(upperlimit)
        if length_of_length is None or length_of_length == -1:
            if lowerlimit == upperlimit:
                self.__lengthOfLength__ = 0
            else:
                self.__lengthOfLength__ = 32  # SOME/IP default
        else:
            self.__lengthOfLength__ = int(length_of_length)

        self.__padTo__ = int(pad_to)

    def dim(self):
        return self.__dim__

    def lowerlimit(self):
        return self.__lowerlimit__

    def upperlimit(self):
        return self.__upperlimit__

    def length_of_length(self):
        return self.__lengthOfLength__

    def pad_to(self):
        return self.__padTo__

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False

        return (
                self.dim() == other.dim() and
                self.lowerlimit() == other.lowerlimit() and
                self.upperlimit() == other.upperlimit() and
                self.length_of_length() == other.length_of_length() and
                self.pad_to() == other.pad_to()
        )

    def calc_size_min_bits(self, inner_length):
        ret = self.__lowerlimit__ * inner_length
        # XXX - padTo completly untested since export dont have BIT-ALIGNMENT set (its counted in bits)
        if self.__padTo__ > 0:
            ret += ret % self.__padTo__

        return self.__lengthOfLength__ + ret

    def calc_size_max_bits(self, inner_length):
        ret = self.__upperlimit__ * inner_length
        # XXX - padTo completly untested since export dont have BIT-ALIGNMENT set (its counted in bits)
        if self.__padTo__ > 0:
            ret += ret % self.__padTo__

        return self.__lengthOfLength__ + ret


class SOMEIPBaseParameterStruct(BaseItem):
    def __init__(self, name, length_of_length, pad_to, members):
        self.__name__ = name
        self.__members__ = members

        if length_of_length is None or length_of_length == -1:
            self.__lengthOfLength__ = 0
        else:
            self.__lengthOfLength__ = int(length_of_length)

        self.__padTo__ = int(pad_to)

    def name(self):
        return self.__name__

    def members(self):
        return self.__members__

    def length_of_length(self):
        return self.__lengthOfLength__

    def pad_to(self):
        return self.__padTo__

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False

        return (
                self.name() == other.name() and
                self.members() == other.members() and
                self.length_of_length() == other.length_of_length() and
                self.pad_to() == other.pad_to()
        )

    def size_min_bits(self):
        ret = self.__lengthOfLength__
        for m in self.__members__.values():
            ret += m.child().size_min_bits()
        return ret

    def size_max_bits(self):
        ret = self.__lengthOfLength__
        for m in self.__members__.values():
            ret += m.child().size_max_bits()
        return ret

    def legacy(self):
        for m in self.__members__.values():
            if m.legacy():
                return True
        return False


class SOMEIPBaseParameterStructMember(BaseItem):
    def __init__(self, position, name, mandatory, child, signal):
        self.__name__ = name
        self.__position__ = int(position)
        self.__mandatory__ = mandatory
        self.__child__ = child
        self.__signal__ = signal

    def name(self):
        return self.__name__

    def position(self):
        return self.__position__

    def mandatory(self):
        return self.__mandatory__

    def child(self):
        return self.__child__

    def signal(self):
        return self.__signal__

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False

        return (
                self.name() == other.name() and
                self.position() == other.position() and
                self.mandatory() == other.mandatory() and
                self.child() == other.child() and
                self.signal() == self.signal()
        )

    def legacy(self):
        if self.__signal__ is not None:
            return True
        return False


class SOMEIPBaseParameterTypedef(BaseItem):
    def __init__(self, name, name2, child):
        self.__name__ = name
        self.__name2__ = name2
        self.__child__ = child

    def name(self):
        return self.__name__

    def name2(self):
        return self.__name2__

    def child(self):
        return self.__child__

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False

        return (
                self.name() == other.name() and
                self.name2() == other.name2() and
                self.child() == other.child()
        )

    def size_min_bits(self):
        return self.__child__.size_min_bits()

    def size_max_bits(self):
        return self.__child__.size_max_bits()


class SOMEIPBaseParameterEnumeration(BaseItem):
    def __init__(self, name, items, child):
        self.__name__ = name
        self.__items__ = items
        self.__child__ = child

    def name(self):
        return self.__name__

    def items(self):
        return self.__items__

    def child(self):
        return self.__child__

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False

        return (
                self.name() == other.name() and
                self.items() == other.items() and
                self.child() == other.child()
        )

    def size_min_bits(self):
        return self.__child__.size_min_bits()

    def size_max_bits(self):
        return self.__child__.size_max_bits()


class SOMEIPBaseParameterEnumerationItem(BaseItem):
    def __init__(self, value, name, desc):
        self.__name__ = name
        self.__desc__ = desc
        self.__value__ = int(value)

    def name(self):
        return self.__name__

    def desc(self):
        return self.__desc__

    def value(self):
        return self.__value__

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False

        return (
                self.name() == other.name() and
                self.desc() == other.desc() and
                self.value() == other.value()
        )


class SOMEIPBaseParameterUnion(BaseItem):
    def __init__(self, name, length_of_length, length_of_type, pad_to, members):
        self.__name__ = name
        self.__members__ = members

        if length_of_length is None or length_of_length == -1:
            self.__lengthOfLength__ = 32  # SOME/IP default
        else:
            self.__lengthOfLength__ = int(length_of_length)

        if length_of_type is None or length_of_type == -1:
            self.__lengthOfType__ = 32  # SOME/IP default
        else:
            self.__lengthOfType__ = int(length_of_type)

        self.__padTo__ = int(pad_to)

    def name(self):
        return self.__name__

    def members(self):
        return self.__members__

    def length_of_length(self):
        return self.__lengthOfLength__

    def length_of_type(self):
        return self.__lengthOfType__

    def pad_to(self):
        return self.__padTo__

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False

        return (
                self.name() == other.name() and
                self.members() == other.members() and
                self.length_of_length() == other.length_of_length() and
                self.length_of_length() == other.length_of_length() and
                self.pad_to() == other.pad_to()
        )

    def size_min_bits(self):
        ret = -1

        for m in self.__members__.values():
            if ret == -1:
                ret = m.child().size_min_bits()
            else:
                if ret >= m.child().size_min_bits():
                    ret = m.child().size_min_bits()
            if self.__padTo__ > 0:
                ret += ret % self.pad_to()
        return self.__lengthOfLength__ + ret

    def size_max_bits(self):
        ret = -1

        for m in self.__members__.values():
            if ret == -1:
                ret = m.child().size_max_bits()
            else:
                if ret < m.child().size_max_bits():
                    ret = m.child().size_max_bits()
            if self.__padTo__ > 0:
                ret += ret % self.pad_to()
        return self.__lengthOfLength__ + ret


class SOMEIPBaseParameterUnionMember(BaseItem):
    def __init__(self, index, name, mandatory, child):
        self.__name__ = name
        self.__index__ = int(index)
        self.__mandatory__ = mandatory
        self.__child__ = child

    def name(self):
        return self.__name__

    def index(self):
        return self.__index__

    def mandatory(self):
        return self.__mandatory__

    def child(self):
        return self.__child__

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False

        return (
                self.name() == other.name() and
                self.index() == other.index() and
                self.mandatory() == other.mandatory() and
                self.child() == other.child()
        )


class SOMEIPBaseLegacySignal(BaseItem):
    def __init__(self, id, name, compu_scale, compu_const):
        self.__id__ = id
        self.__name__ = name
        self.__compu_scale__ = compu_scale
        self.__compu_consts__ = compu_const

    def id(self):
        return self.__id__

    def name(self):
        return self.__name__

    def compu_scale(self):
        return self.__compu_scale__

    def compu_consts(self):
        return self.__compu_consts__

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False

        return (
                self.id() == self.id() and
                self.name() == other.name() and
                self.compu_scale() == other.compu_scale() and
                self.compu_consts() == other.compu_consts()
        )