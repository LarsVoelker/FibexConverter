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

import csv
import ipaddress

import macaddress


def bits_to_bytes(bits):
    if bits % 8 == 0:
        return bits // 8
    else:
        return (bits // 8) + 1


def is_mcast(addr):
    if is_ip_mcast(addr):
        return True

    if is_mac_mcast(addr):
        return True

    return False


def addr_to_key(addr):
    if addr is None:
        return "None"

    if is_ip(addr):
        return ip_to_key(addr)

    if is_mac(addr):
        return mac_to_key(addr)

    print(
        f"Warning: addr_to_key was called with {addr} and this seems to be no IP or MAC Address!"
    )
    return "None"


def is_mac(mac):
    if mac is None:
        return False

    try:
        macaddress.EUI48(mac)
    except ValueError:
        return False

    return True


def is_mac_mcast(mac):
    if mac is None:
        return False

    try:
        tmp = macaddress.EUI48(mac)
    except ValueError:
        return False

    return (tmp.__bytes__()[0] & 0x01) == 0x01


def mac_to_key(mac):
    if mac is None:
        return "None"

    try:
        tmp = macaddress.EUI48(mac)
    except ValueError:
        return False

    return f"mac-{str(tmp)}"


def is_ip(ip):
    if ip is None:
        return False

    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return False

    return True


def is_ip_mcast(ip):
    try:
        ip = ipaddress.ip_address(ip)
    except ValueError:
        return False

    return ip.is_multicast


def ip_to_key(ip):
    if ip is None:
        return "None"

    try:
        tmp = ipaddress.ip_address(ip)
    except ValueError:
        return "None"

    key = f"ipvx-{ip}"

    if tmp.version == 4:
        key = f"ipv4-{tmp.packed[0]:03}.{tmp.packed[1]:03}.{tmp.packed[2]:03}.{tmp.packed[3]:03}"
    elif tmp.version == 6:
        key = f"ipv6-{tmp.exploded}"
    return key


def mcast_addr_to_mac_mcast(addr):
    if is_mac_mcast(addr):
        return addr

    if is_ip_mcast(addr):
        ret = ""
        tmp = ipaddress.ip_address(addr)
        if tmp.version == 4:
            ret = f"01-00-5e-{(tmp.packed[1] & 127):02x}-{tmp.packed[2]:02x}-{tmp.packed[3]:02x}"
        elif tmp.version == 6:
            ret = f"33-33-{(tmp.packed[12]):02x}-{(tmp.packed[13]):02x}-{(tmp.packed[14]):02x}-{(tmp.packed[15]):02x}"
        else:
            print(
                "ERROR: IP Address has to be IPv4 or IPv6 to convert it to Ethernet Multicast!"
            )

        return ret.upper()

    return ""


def read_csv_to_dict(f, verbose=False):
    ret = {}

    csvreader = csv.reader(f, delimiter=",", quotechar='"')
    skip_first_line = True
    for row in csvreader:
        if skip_first_line:
            skip_first_line = False
            continue

        # skip empty lines
        if len(row) == 0 or row[0] == "" or row[0] == "":
            continue

        if verbose:
            print("  " + ", ".join(row))

        if len(row) != 2:
            print(f"Error: Line in file too short/long: {', '.join(row)} ({len(row)})")
            continue

        key, value = row[:2]

        if key in ret.keys():
            print(f"Error: key {key} is present multiple times!")
            continue

        ret[key] = value

    print()

    return ret


class BaseConfigurationFactory(object):
    def create_vlan(self, name, vlan_id, prio):
        return BaseVLAN(name, vlan_id, prio)

    def create_multicast_path(
        self,
        switchport_tx,
        vlan_tx,
        src_addr,
        switchport_rx,
        vlan_rx,
        mcast_addr,
        comment,
    ):
        return BaseMulticastPath(
            switchport_tx,
            vlan_tx,
            src_addr,
            switchport_rx,
            vlan_rx,
            mcast_addr,
            comment,
        )

    def create_switch(self, name, ecu, ports):
        return BaseSwitch(name, ecu, ports)

    def create_switch_port(self, port_id, ctrl, port, default_vlan, vlans):
        return BaseSwitchPort(port_id, ctrl, port, default_vlan, vlans)

    def create_ethernet_bus(self, name, connected_ctrls, switch_ports):
        return BaseEthernetBus(name, connected_ctrls, switch_ports)

    def create_ecu(self, name, controllers):
        return BaseECU(name, controllers)

    def create_controller(self, name, interfaces):
        return BaseController(name, interfaces)

    def create_interface(
        self,
        name,
        vlan_id,
        ips,
        sockets,
        input_frame_triggerings,
        output_frame_triggerings,
        fr_channel,
    ):
        return BaseInterface(
            name,
            vlan_id,
            ips,
            sockets,
            input_frame_triggerings,
            output_frame_triggerings,
            fr_channel,
        )

    def create_socket(
        self,
        name,
        ip,
        proto,
        port_number,
        service_instances,
        service_instance_clients,
        event_handlers,
        event_group_receivers,
    ):
        return BaseSocket(
            name,
            ip,
            proto,
            port_number,
            service_instances,
            service_instance_clients,
            event_handlers,
            event_group_receivers,
        )

    def create_someip_service_instance(self, service, instance_id, protocol_version):
        return SOMEIPBaseServiceInstance(service, instance_id, protocol_version)

    def create_someip_service_instance_client(
        self, service, instance_id, protocol_version, server
    ):
        return SOMEIPBaseServiceInstanceClient(service, instance_id, protocol_version, server)

    def create_someip_service_eventgroup_sender(self, service_instance, eventgroup_id):
        return SOMEIPBaseServiceEventgroupSender(service_instance, eventgroup_id)

    def create_someip_service_eventgroup_receiver(
        self, service_instance, eventgroup_id, sender
    ):
        return SOMEIPBaseServiceEventgroupReceiver(
            service_instance, eventgroup_id, sender
        )

    def create_someip_service(
        self, name, service_id, major_version, minor_version, methods, events, fields, eventgroups
    ):
        return SOMEIPBaseService(
            name, service_id, major_version, minor_version, methods, events, fields, eventgroups
        )

    def create_someip_service_method(
        self,
        name,
        method_id,
        call_type,
        reliable,
        in_parameters,
        out_parameters,
        request_debounce=-1,
        request_max_retention=-1,
        response_max_retention=-1,
        tlv=False,
    ):
        return SOMEIPBaseServiceMethod(
            name,
            method_id,
            call_type,
            reliable,
            in_parameters,
            out_parameters,
            request_debounce,
            request_max_retention,
            response_max_retention,
            tlv,
        )

    def create_someip_service_event(
        self, name, method_id, reliable, params, debounce=-1, max_retention=-1, tlv=False
    ):
        return SOMEIPBaseServiceEvent(
            name, method_id, reliable, params, debounce, max_retention, tlv
        )

    def create_someip_service_field(
        self,
        name,
        getter_id,
        setter_id,
        notifier_id,
        getter_reliable,
        setter_reliable,
        notifier_reliable,
        params,
        getter_debounce_request,
        getter_retention_request,
        getter_retention_response,
        setter_debounce_request,
        setter_retention_request,
        setter_retention_response,
        notifier_debounce,
        notifier_retention,
        tlv=False,
    ):
        ret = SOMEIPBaseServiceField(
            self,
            name,
            getter_id,
            setter_id,
            notifier_id,
            getter_reliable,
            setter_reliable,
            notifier_reliable,
            params,
            getter_debounce_request,
            getter_retention_request,
            getter_retention_response,
            setter_debounce_request,
            setter_retention_request,
            setter_retention_response,
            notifier_debounce,
            notifier_retention,
            tlv,
        )
        return ret

    def create_someip_service_eventgroup(self, name, eid, event_ids, field_ids):
        return SOMEIPBaseServiceEventgroup(name, eid, event_ids, field_ids)

    def create_someip_parameter(
        self, position, name, desc, mandatory, data_type, signal
    ):
        return SOMEIPBaseParameter(position, name, desc, mandatory, data_type, signal)

    def create_someip_parameter_basetype(
        self, name, data_type, bigendian, bitlength_basetype, bitlength_encoded_type
    ):
        return SOMEIPBaseParameterBasetype(
            name, data_type, bigendian, bitlength_basetype, bitlength_encoded_type
        )

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
        return SOMEIPBaseParameterString(
            name,
            char_type,
            big_endian,
            lower_limit,
            upper_limit,
            termination,
            length_of_length,
            pad_to,
        )

    def create_someip_parameter_array(self, name, dims, child):
        return SOMEIPBaseParameterArray(name, dims, child)

    def create_someip_parameter_array_dim(
        self, dim, lower_limit, upper_limit, length_of_length, pad_to
    ):
        return SOMEIPBaseParameterArrayDimension(
            dim, lower_limit, upper_limit, length_of_length, pad_to
        )

    def create_someip_parameter_struct(
        self, name, length_of_length, pad_to, members, tlv=False
    ):
        return SOMEIPBaseParameterStruct(name, length_of_length, pad_to, members, tlv)

    def create_someip_parameter_struct_member(
        self, position, name, mandatory, child, signal
    ):
        return SOMEIPBaseParameterStructMember(position, name, mandatory, child, signal)

    def create_someip_parameter_typedef(self, name, name2, child):
        return SOMEIPBaseParameterTypedef(name, name2, child)

    def create_someip_parameter_enumeration(self, name, items, child):
        return SOMEIPBaseParameterEnumeration(name, items, child)

    def create_someip_parameter_enumeration_item(self, value, name, desc):
        return SOMEIPBaseParameterEnumerationItem(value, name, desc)

    def create_someip_parameter_union(
        self, name, length_of_length, length_of_type, pad_to, members
    ):
        return SOMEIPBaseParameterUnion(
            name, length_of_length, length_of_type, pad_to, members
        )

    def create_someip_parameter_union_member(self, index, name, mandatory, child):
        return SOMEIPBaseParameterUnionMember(index, name, mandatory, child)

    def create_someip_parameter_bitfield(self, name, items, child):
        return SOMEIPBaseParameterBitfield(name, items, child)

    def create_someip_parameter_bitfield_item(self, bit_number, name):
        return SOMEIPBaseParameterBitfieldItem(bit_number, name)

    def create_signal(
        self,
        signal_id,
        name,
        compu_scale,
        compu_consts,
        bit_len,
        min_len,
        max_len,
        basetype,
        basetypelen,
    ):
        return BaseSignal(
            signal_id,
            name,
            compu_scale,
            compu_consts,
            bit_len,
            min_len,
            max_len,
            basetype,
            basetypelen,
        )

    def create_signal_instance(
        self, signal_instance_id, signal_ref, bit_position, is_high_low_byte_order
    ):
        return BaseSignalInstance(signal_instance_id, signal_ref, bit_position, is_high_low_byte_order)

    def create_pdu(self, pdu_id, short_name, byte_length, pdu_type, signal_instances):
        return BasePDU(pdu_id, short_name, byte_length, pdu_type, signal_instances)

    def create_multiplex_pdu(
        self,
        multiplexer_pdu_id,
        short_name,
        byte_length,
        pdu_type,
        switch,
        segment_position,
        pdu_instances,
        static_segments,
        static_pdu,
    ):
        return BaseMultiplexPDU(
            multiplexer_pdu_id,
            short_name,
            byte_length,
            pdu_type,
            switch,
            segment_position,
            pdu_instances,
            static_segments,
            static_pdu,
        )

    def create_multiplex_switch(
        self, multiplex_switch_id, short_name, bit_position, is_high_low_byte_order, bit_length
    ):
        return BaseMultiplexPDUSwitch(
            multiplex_switch_id, short_name, bit_position, is_high_low_byte_order, bit_length
        )

    def create_multiplex_segment_position(self, bit_pos, is_high_low, bit_length):
        return BaseMultiplexPDUSegmentPosition(bit_pos, is_high_low, bit_length)

    def create_ethernet_pdu_instance(self, pdu_ref, header_id):
        return BaseEthernetPDUInstance(pdu_ref, header_id)

    def create_pdu_instance(
        self, pdu_instance_id, pdu_ref, bit_position, is_high_low_byte_order, pdu_update_bit_position
    ):
        return BasePDUInstance(
            pdu_instance_id, pdu_ref, bit_position, is_high_low_byte_order, pdu_update_bit_position
        )

    def create_frame(self, frame_id, short_name, byte_length, frame_type, pdu_instances):
        return BaseFrame(frame_id, short_name, byte_length, frame_type, pdu_instances)

    def create_frame_triggering_can(self, frame_trigger_id, frame, can_id):
        return BaseFrameTriggeringCAN(frame_trigger_id, frame, can_id)

    def create_frame_triggering_flexray(
        self, frame_trigger_id, frame, slot_id, cycle_counter, base_cycle, cycle_repetition
    ):
        return BaseFrameTriggeringFlexRay(
            frame_trigger_id, frame, slot_id, cycle_counter, base_cycle, cycle_repetition
        )

    def create_pdu_route(self, sender_socket, receiving_socket, pdu_name, pdu_id):
        if sender_socket.is_multicast():
            print(
                f"ERROR: Multicast Sockets cannot be used for sending!"
                f" {sender_socket.ip()} -> {receiving_socket.ip()}: {pdu_name} 0x{pdu_id:08x}"
            )
            return False
        return True

    @staticmethod
    def socket_to_sw_port(socket):
        # regular switch ethernet
        ret = socket.interface().controller().get_switch_port()
        if ret is not None:
            return ret

        # ethernet bus
        eth_bus = socket.interface().controller().get_eth_bus()

        if eth_bus is None:
            print(
                f"WARNING: cannot find sw_port and not eth bus either for eth bus! "
                f"Ctrl: {socket.interface().controller().name()}"
            )
            return None

        sw_ports = eth_bus.switch_ports()

        if len(sw_ports) == 0:
            print(
                f"WARNING: cannot find uplink port to eth bus! "
                f"Ctrl: {socket.interface().controller().name()}"
            )
            return None

        if len(sw_ports) > 1:
            print("ERROR: Eth Bus with more than 1 uplink to switch is unsupported!")

        return sw_ports[0]

    def add_ipv4_address_config(self, ip, netmask):
        pass

    def get_ipv4_netmask(self, ip):
        return ""

    def add_ipv6_address_config(self, ip, prefix_len):
        pass

    def get_ipv6_prefix_length(self, ip):
        return ""

    def parsing_done(self):
        pass


class BaseItem(object):
    def legacy(self):
        return False


class BaseCoding(BaseItem):
    def __init__(
        self,
        original_id,
        name,
        coded_basetype,
        coded_category,
        coded_termination,
        coded_bit_length,
        coded_max_length,
        compu_scale,
        compu_consts,
    ):
        self.__id = original_id
        self.__name = name
        self.__coded_basetype = coded_basetype
        self.__coded_category = coded_category
        self.__coded_termination = coded_termination
        self.__coded_bit_length = coded_bit_length
        self.__coded_max_length = coded_max_length
        self.__compu_scale = compu_scale
        self.__compu_consts = compu_consts

    def name(self):
        return self.__name


class BaseVLAN(BaseItem):
    def __init__(self, vlan_name, vlan_id, priority):
        self.__vlan_name = vlan_name
        self.__vlan_id = vlan_id
        self.__priority = priority

    def name(self):
        return self.__vlan_name

    def vlan_id(self):
        return self.__vlan_id

    def vlan_id_str(self):
        if self.vlan_id() is None:
            return "untagged"
        else:
            return f"0x{int(self.vlan_id()):x}"

    def priority(self):
        return self.__priority


class BaseMulticastPath(BaseItem):
    def __init__(
        self,
        switchport_tx,
        vlan_id_tx,
        source_addr,
        switchport_rx,
        vlan_id_rx,
        multicast_addr,
        comment,
    ):
        if vlan_id_tx != vlan_id_rx:
            print(
                f"Currently only Multicast Path with same VLAN supported Addr:{multicast_addr} vlan_tx:{vlan_id_tx} "
                f"vlan_rx:{vlan_id_rx}!"
            )
            raise ValueError

        self.__vlan_id = vlan_id_tx
        self.__tx_address = source_addr
        self.__mc_address = multicast_addr
        self.__switchport_tx = switchport_tx
        self.__switchport_rx = switchport_rx
        self.__comment = comment

    def vlan_id(self):
        return self.__vlan_id

    def source_addr(self):
        return self.__tx_address

    def mc_addr(self):
        return self.__mc_address

    def switchport_tx(self):
        return self.__switchport_tx

    def switchport_tx_name(self):
        if self.__switchport_tx is None:
            return None
        else:
            return self.__switchport_tx.portid()

    def switchport_rx(self):
        return self.__switchport_rx

    def switchport_rx_name(self):
        if self.__switchport_rx is None:
            return None
        else:
            return self.__switchport_rx.portid()

    def comment(self):
        return self.__comment

    def __append_to_comment__(self, txt):
        self.__comment += txt


class BaseSwitchPort(BaseItem):
    # TODO: we need to add ethernet_bus to init!?
    def __init__(self, port_id, controller, port, default_vlan, vlans):
        assert controller is None or port is None

        self.__port_id = port_id
        self.__controller = None
        self.__port = port
        self.__eth_bus = None
        self.__default_vlan = default_vlan
        self.__vlans = vlans
        self.__switch = None

        if controller is not None:
            self.set_connected_ctrl(controller)

    def __repr__(self):
        switch_name = "<unknown>"
        if self.__switch is not None:
            switch_name = self.__switch.name()

        return f"{switch_name}.{self.__port_id}"

    def controller(self):
        return self.__controller

    def port(self):
        return self.__port

    def portid_full(self, gen_name=False):
        port_id = self.portid(gen_name=gen_name)
        if self.switch() is not None:
            if self.switch().ecu() is not None:
                return f"{self.switch().ecu().name()}.{self.switch().name()}.{port_id}"
            return f".{self.switch().name()}.{port_id}"
        else:
            return f"..{port_id}"

    def portid(self, gen_name=False):
        if gen_name:
            return self.portid_generated()

        return self.__port_id

    def portid_generated(self):
        if self.__port is not None:
            return f"couplingPort_ConnectTo_{self.__port.switch().name()}"
        if self.__controller is not None:
            return f"couplingPort_ConnectTo_{self.__controller.name()}"
        if self.__eth_bus is not None:
            return f"couplingPort_ConnectTo_{self.__eth_bus.name()}"

        return self.__port_id

    def set_parent_switch(self, switch):
        self.__switch = switch

    def switch(self):
        return self.__switch

    def set_connected_port(self, peer_port):
        assert peer_port is not None
        assert self.__port is None

        if self.__controller is not None or self.__eth_bus is not None != 0:
            print(
                f"WARNING: SwitchPort {self.__port_id} adds port but was connected before! Overwriting!"
            )

        self.__port = peer_port

    def connected_to_port(self):
        return self.__port

    def set_ethernet_bus(self, eth_bus):
        assert eth_bus is not None
        assert self.__eth_bus is None

        if self.__controller is not None or self.__eth_bus is not None:
            print(
                f"WARNING: SwitchPort {self.__port_id} adds eth bus but was connected before! Overwriting!"
            )

        self.__eth_bus = eth_bus

    def connected_to_eth_bus(self):
        return self.__eth_bus

    def set_connected_ctrl(self, peer_ctrl):
        assert peer_ctrl is not None
        assert self.__controller is None

        if self.__port is not None or self.__eth_bus is not None:
            print(
                f"WARNING: SwitchPort {self.__port_id} adds ctrl to port but was connected before! Overwriting!"
            )

        self.__controller = peer_ctrl
        peer_ctrl.set_switch_port(self)

    def connected_to_ecu_ctrl(self):
        return self.__controller

    def vlans(self):
        vlans = []

        for vlan in self.__vlans:
            if vlan.vlan_id() is None:
                vlans += [0]
            else:
                vlans += [int(vlan.vlan_id())]

        return sorted(vlans)

    def vlans_objs(self):
        vlans = []

        for vlan in self.__vlans:
            vlans.append(vlan)

        return sorted(vlans, key=lambda x: -1 if x.vlan_id() is None else x.vlan_id())


class BaseSwitch(BaseItem):
    def __init__(self, name, ecu, ports):
        self.__name = name
        self.__ports = ports
        self.__ecu = ecu

        if ecu is not None:
            ecu.add_switch(self)

        for port in ports:
            port.set_parent_switch(self)

    def name(self):
        return self.__name

    def ecu(self):
        return self.__ecu

    def ports(self):
        return self.__ports

    def key(self):
        if self.__ecu is None:
            return f"None.{self.name()}"

        return f"{self.ecu().name()}.{self.name()}"


class BaseEthernetBus(BaseItem):
    def __init__(self, name, connected_ctrls, switch_ports):
        self.__name = name
        self.__ctrls = connected_ctrls
        self.__ports = switch_ports

        # connect the controllers to us!
        for ctrl in connected_ctrls:
            ctrl.set_eth_bus(self)

    def name(self):
        return self.__name

    def connected_controllers(self):
        return self.__ctrls

    def switch_ports(self):
        return self.__ports


class BaseECU(BaseItem):
    def __init__(self, name, controllers):
        self.__name = name
        self.__controllers = controllers
        self.__switches = []

        for c in controllers:
            c.set_ecu(self)

    def name(self):
        return self.__name

    def controllers(self):
        return self.__controllers

    def add_switch(self, switch):
        self.__switches.append(switch)

    def switches(self):
        return self.__switches


class BaseController(BaseItem):
    def __init__(self, name, interfaces):
        self.__name = name
        self.__interfaces = interfaces
        self.__ecu = None
        self.__peer_port = None
        self.__eth_bus = None

        for i in interfaces:
            i.set_controller(self)

    def name(self):
        return self.__name

    def interfaces(self):
        return self.__interfaces

    def vlans(self):
        vlans = []

        for interface in self.__interfaces:
            if interface.vlan_id() is None:
                vlans += [0]
            else:
                vlans += [int(interface.vlan_id())]

        return sorted(vlans)

    def set_ecu(self, ecu):
        self.__ecu = ecu

    def ecu(self):
        return self.__ecu

    def set_switch_port(self, peer_port):
        assert self.__peer_port is None
        assert self.__eth_bus is None
        self.__peer_port = peer_port

    def get_switch_port(self):
        return self.__peer_port

    def set_eth_bus(self, eth_buf):
        assert self.__peer_port is None
        assert self.__eth_bus is None
        self.__eth_bus = eth_buf

    def get_eth_bus(self):
        return self.__eth_bus


class BaseInterface(BaseItem):
    def __init__(
        self,
        vlan_name,
        vlan_id,
        ips,
        sockets,
        frame_triggerings_in,
        frame_triggerings_out,
        fr_channel,
    ):
        self.__vlan_name = vlan_name
        self.__sockets = sockets
        self.__ips = ips

        self.__controller = None

        if vlan_id is None:
            self.__vlan_id = 0
        else:
            self.__vlan_id = int(vlan_id)

        for s in sockets:
            s.set_interface(self)

        self.__frame_triggerings_in = frame_triggerings_in
        self.__frame_triggerings_out = frame_triggerings_out

        self.__flexray_channel = fr_channel

    def vlan_name(self):
        return self.__vlan_name

    def vlan_id(self):
        return self.__vlan_id

    def ips(self):
        return self.__ips

    def ips_without_socket(self):
        tmp = []
        for socket in self.__sockets:
            tmp.append(socket.ip())

        ret = []
        for ip in self.__ips:
            if ip not in tmp:
                ret.append(ip)

        return ret

    def sockets(self):
        return self.__sockets

    def set_controller(self, controller):
        self.__controller = controller

    def controller(self):
        return self.__controller

    def frame_triggerings_in(self):
        return self.__frame_triggerings_in

    def frame_triggerings_out(self):
        return self.__frame_triggerings_out

    def flexray_channel(self):
        return self.__flexray_channel

    def is_can(self):
        for trig in self.__frame_triggerings_in.values():
            if trig.is_can():
                return True

        for trig in self.__frame_triggerings_out.values():
            if trig.is_can():
                return True

        return False

    def is_flexray(self):
        for trig in self.__frame_triggerings_in.values():
            if trig.is_flexray():
                return True

        for trig in self.__frame_triggerings_out.values():
            if trig.is_flexray():
                return True

        return False

    def is_ethernet(self):
        for trig in self.__frame_triggerings_in.values():
            if trig.is_ethernet():
                return True

        for trig in self.__frame_triggerings_out.values():
            if trig.is_ethernet():
                return True

        return False

    def is_more_than_one_type(self):
        ret = 0

        if self.is_can():
            ret += 1
        if self.is_flexray():
            ret += 1
        if self.is_ethernet():
            ret += 1

        return ret > 1


class BaseSocket(BaseItem):
    def __init__(
        self,
        name,
        ip,
        layer_4_protocol,
        port_number,
        service_instances,
        service_instance_clients,
        event_handlers,
        eventgroup_receivers,
    ):
        self.__name = name
        self.__ip = ip

        try:
            self.__ipaddress = ipaddress.ip_address(ip)
        except ValueError:
            self.__ipaddress = None

        self.__protocol = layer_4_protocol
        self.__port_number = int(port_number)
        self.__instances = service_instances
        self.__instance_clients = service_instance_clients
        self.__event_handlers = event_handlers
        self.__consumed_event_groups = eventgroup_receivers
        self.__pdus_in = []
        self.__pdus_out = []
        self.__interface = None

        if service_instances is not None:
            for i in service_instances:
                i.set_socket(self)

        if service_instance_clients is not None:
            for i in service_instance_clients:
                i.set_socket(self)

        if event_handlers is not None:
            for i in event_handlers:
                i.set_socket(self)

        if eventgroup_receivers is not None:
            for i in eventgroup_receivers:
                i.set_socket(self)

    # TODO: XXX REMOVE AGAIN?
    def __eq__(self, other):
        if not isinstance(other, BaseSocket):
            # don't attempt to compare against unrelated types
            return NotImplemented

        self_if = (
            None
            if self.__interface is None
            else self.__interface.controller().name()
        )
        other_if = (
            None
            if other.__interface is None
            else other.__interface.controller().name()
        )

        return (
                self.__name == other.__name
                and self.__ip == other.__ip
                and self.__ipaddress == other.__ipaddress
                and self.__protocol == other.__protocol
                and self.__port_number == other.__port_number
                and self_if != other_if
        )

    def name(self):
        return self.__name

    def ip(self):
        return self.__ip

    def is_ipv4(self):
        return type(self.__ipaddress) is ipaddress.IPv4Address

    def is_ipv6(self):
        return type(self.__ipaddress) is ipaddress.IPv6Address

    def is_multicast(self):
        return self.__ipaddress is not None and self.__ipaddress.is_multicast

    def protocol(self):
        return self.__protocol

    def port_number(self):
        return self.__port_number

    def instances(self):
        return self.__instances

    def service_instance_clients(self):
        return self.__instance_clients

    def event_handlers(self):
        return self.__event_handlers

    def event_group_receivers(self):
        return self.__consumed_event_groups

    def add_incoming_pdu(self, pdu):
        if pdu not in self.__pdus_in:
            self.__pdus_in.append(pdu)

    def incoming_pdus(self):
        return self.__pdus_in

    def add_outgoing_pdu(self, pdu):
        if pdu not in self.__pdus_out:
            self.__pdus_out.append(pdu)

    def outgoing_pdus(self):
        return self.__pdus_out

    def set_interface(self, interface):
        self.__interface = interface

    def interface(self):
        return self.__interface


class SOMEIPBaseServiceInstance(BaseItem):
    def __init__(self, service, instance_id, protocol_version):
        self.__service = service
        self.__instance_id = int(instance_id)
        self.__protocol_version = int(protocol_version)
        self.__socket = None

        self.__clients = []
        self.__eventgroup_sender = []
        self.__eventgroup_receiver = []

        service.add_instance(self)

    def service(self):
        return self.__service

    def instance_id(self):
        return self.__instance_id

    def protocol_version(self):
        return self.__protocol_version

    def serviceinstanceclients(self):
        return self.__clients

    def add_client(self, client):
        if client not in self.__clients:
            self.__clients.append(client)

    def eventgroup_sender(self):
        return self.__eventgroup_sender

    def add_eventgroup_sender(self, eh):
        if eh not in self.__eventgroup_sender:
            self.__eventgroup_sender.append(eh)

    def eventgroup_receiver(self):
        return self.__eventgroup_receiver

    def add_eventgroup_receiver(self, ceg):
        if ceg not in self.__eventgroup_receiver:
            self.__eventgroup_receiver.append(ceg)

    def set_socket(self, socket):
        self.__socket = socket

    def socket(self):
        return self.__socket


class SOMEIPBaseServiceInstanceClient(BaseItem):
    def __init__(self, service, instance_id, protocol_version, instance):
        self.__service = service
        self.__instance_id = int(instance_id)
        self.__protocol_version = int(protocol_version)
        self.__instance = instance
        self.__socket = None

        if instance is not None:
            instance.add_client(self)

    def service(self):
        return self.__service

    def instance_id(self):
        return self.__instance_id

    def protocol_version(self):
        return self.__protocol_version

    def instance(self):
        return self.__instance

    def set_socket(self, socket):
        self.__socket = socket

    def socket(self):
        return self.__socket


class SOMEIPBaseServiceEventgroupSender(BaseItem):
    def __init__(self, service_instance, eventgroup_id):
        self.__si = service_instance
        self.__eventgroup_id = int(eventgroup_id)
        self.__eventgroup_receivers = []
        self.__socket = None

    def service_instance(self):
        return self.__si

    def eventgroup_id(self):
        return self.__eventgroup_id

    def eventgroup_receivers(self):
        return self.__eventgroup_receivers

    def add_receiver(self, receiver):
        if receiver not in self.__eventgroup_receivers:
            self.__eventgroup_receivers.append(receiver)

    def set_socket(self, socket):
        self.__socket = socket

    def socket(self):
        return self.__socket


class SOMEIPBaseServiceEventgroupReceiver(BaseItem):
    def __init__(self, service_instance, eventgroup_id, sender):
        self.__si = service_instance
        self.__eventgroup_id = int(eventgroup_id)
        self.__sender = sender
        self.__socket = None

        if sender is not None:
            sender.add_receiver(self)

    def service_instance(self):
        return self.__si

    def eventgroup_id(self):
        return self.__eventgroup_id

    def sender(self):
        return self.__sender

    def set_socket(self, socket):
        self.__socket = socket

    def socket(self):
        return self.__socket


class SOMEIPBaseService(BaseItem):
    def __init__(
        self, name, service_id, major_ver, minor_ver, methods, events, fields, eventgroups, register_service=True
    ):
        self.__name = name
        self.__service_id = int(service_id)
        self.__major_ver = int(major_ver)
        self.__minor_ver = int(minor_ver)

        self.__methods = methods
        self.__events = events
        self.__fields = fields

        self.__eventgroups = eventgroups

        self.__instances = []

        if register_service:
            self.register_service()

    def register_service(self):
        for m in self.__methods.values():
            m.register_service(self)

        for e in self.__events.values():
            e.register_service(self)

        for f in self.__fields.values():
            f.register_service(self)

    def create_backlinks(self, factory):
        tmp = {}
        for k, m in self.__methods.items():
            tmp[k] = m.create_backlinks(factory)
        self.__methods = tmp

        tmp = {}
        for k, m in self.__events.items():
            tmp[k] = m.create_backlinks(factory)
        self.__events = tmp

        tmp = {}
        for k, m in self.__fields.items():
            tmp[k] = m.create_backlinks(factory)
        self.__fields = tmp

    def service_id(self):
        return self.__service_id

    def major_version(self):
        return self.__major_ver

    def minor_version(self):
        return self.__minor_ver

    def version_string(self):
        return "%d.%d" % (self.__major_ver, self.__minor_ver)

    def name(self):
        return self.__name

    def methods(self):
        return self.__methods

    def method(self, mid):
        if mid in self.__methods:
            return self.__methods[mid]
        return None

    def events(self):
        return self.__events

    def event(self, eid):
        if eid in self.__events:
            return self.__events[eid]
        return None

    def fields(self):
        return self.__fields

    def field(self, fid):
        if fid in self.__fields:
            return self.__fields[fid]
        return None

    def eventgroups(self):
        return self.__eventgroups

    def eventgroup(self, eg_id):
        if eg_id in self.__eventgroups:
            return self.__eventgroups[eg_id]
        return None

    def add_instance(self, service_instance):
        self.__instances.append(service_instance)

    def remove_instance(self, service_instance):
        self.__instances.remove(service_instance)

    def instances(self):
        return self.__instances


class SOMEIPBaseServiceMethod(BaseItem):
    def __init__(
        self,
        name,
        method_id,
        call_type,
        reliable,
        in_params,
        out_params,
        req_debounce=-1,
        req_max_retention=-1,
        res_max_retention=-1,
        tlv=False,
    ):
        self.__name = name
        self.__method_id = method_id
        self.__call_type = call_type
        self.__reliable = reliable

        self.__in_params = in_params
        self.__out_params = out_params

        self.__req_debounce_time = req_debounce
        self.__req_retention_time = req_max_retention
        self.__res_retention_time = res_max_retention
        self.__tlv = tlv

        self.__service = None

    def register_service(self, service):
        self.__service = service

    def parent_service(self):
        return self.__service

    def create_backlinks(self, factory):
        for i in range(len(self.__in_params)):
            self.__in_params[i] = self.__in_params[i].create_backlinks(self, factory)

        for i in range(len(self.__out_params)):
            self.__out_params[i] = self.__out_params[i].create_backlinks(self, factory)

        return self

    def method_id(self):
        return self.__method_id

    def name(self):
        return self.__name

    def call_type(self):
        return self.__call_type

    def reliable(self):
        return self.__reliable

    def in_parameters(self):
        return self.__in_params

    def out_parameters(self):
        return self.__out_params

    def size_min_in(self):
        ret = 0
        for p in self.__in_params:
            ret += p.size_min_bits()
        return bits_to_bytes(ret)

    def size_max_in(self):
        ret = 0
        for p in self.__in_params:
            ret += p.size_max_bits()
        return bits_to_bytes(ret)

    def size_min_out(self):
        ret = 0
        for p in self.__out_params:
            ret += p.size_min_bits()
        return bits_to_bytes(ret)

    def size_max_out(self):
        ret = 0
        for p in self.__out_params:
            ret += p.size_max_bits()
        return bits_to_bytes(ret)

    def debounce_time_req(self):
        return self.__req_debounce_time

    def max_buffer_retention_time_req(self):
        return self.__req_retention_time

    def max_buffer_retention_time_res(self):
        return self.__res_retention_time

    def legacy(self):
        for p in self.__in_params:
            if p.legacy():
                return True
        for p in self.__out_params:
            if p.legacy():
                return True
        return False

    def tlv(self):
        return self.__tlv


class SOMEIPBaseServiceEvent(BaseItem):
    def __init__(
        self,
        name,
        method_id,
        reliable,
        params,
        debounce_time_range=-1,
        max_buffer_retention_time=-1,
        tlv=False,
    ):
        self.__name = name
        self.__method_id = method_id
        self.__reliable = reliable
        self.__params = params
        self.__debounce_time = debounce_time_range
        self.__retention_time = max_buffer_retention_time
        self.__tlv = tlv

        self.__service = None

    def register_service(self, service):
        self.__service = service

    def parent_service(self):
        return self.__service

    def create_backlinks(self, factory):
        for i in range(len(self.__params)):
            self.__params[i] = self.__params[i].create_backlinks(self, factory)

        return self

    def method_id(self):
        return self.__method_id

    def name(self):
        return self.__name

    def reliable(self):
        return self.__reliable

    def params(self):
        return self.__params

    @staticmethod
    def size_min_in():
        return 0

    @staticmethod
    def size_max_in():
        return 0

    def size_min_out(self):
        ret = 0
        for p in self.__params:
            ret += p.size_min_bits()
        return bits_to_bytes(ret)

    def size_max_out(self):
        ret = 0
        for p in self.__params:
            ret += p.size_max_bits()
        return bits_to_bytes(ret)

    def debounce_time(self):
        return self.__debounce_time

    def max_buffer_retention_time(self):
        return self.__retention_time

    def legacy(self):
        for p in self.__params:
            if p.legacy():
                return True
        return False

    def tlv(self):
        return self.__tlv


class SOMEIPBaseServiceField(BaseItem):
    def __init__(
        self,
        config_factory,
        name,
        getter_id,
        setter_id,
        notifier_id,
        getter_reliable,
        setter_reliable,
        notifier_reliable,
        params,
        getter_req_debounce=-1,
        getter_req_max_retention=-1,
        getter_res_max_retention=-1,
        setter_req_debounce=-1,
        setter_req_max_retention=-1,
        setter_res_max_retention=-1,
        notifier_debounce=-1,
        notifier_max_retention=-1,
        tlv=False,
    ):
        self.__name = name

        self.__getter = None
        self.__setter = None
        self.__notifier = None
        self.__params = params

        self.__minimum_id = None

        self.__tlv = tlv

        if getter_id is not None:
            self.__getter = config_factory.create_someip_service_method(
                name + "-Getter",
                getter_id,
                "REQUEST_RESPONSE",
                getter_reliable,
                [],
                params,
                getter_req_debounce,
                getter_req_max_retention,
                getter_res_max_retention,
            )

        if setter_id is not None:
            self.__setter = config_factory.create_someip_service_method(
                name + "-Setter",
                setter_id,
                "REQUEST_RESPONSE",
                setter_reliable,
                params,
                params,
                setter_req_debounce,
                setter_req_max_retention,
                setter_res_max_retention,
            )

        if notifier_id is not None:
            self.__notifier = config_factory.create_someip_service_event(
                name + "-Notifier",
                notifier_id,
                notifier_reliable,
                params,
                notifier_debounce,
                notifier_max_retention,
            )

        # find the smallest identifier after stripping None
        tmp = sorted([getter_id, setter_id, notifier_id], key=lambda x: (x is None, x))
        if tmp[0] is None:
            print(f"ERROR: Field ({name}) without Getter/Setter/Notifier!")
            return

        self.__minimum_id = tmp[0]

        if self.__minimum_id == -1:
            self.__minimum_id = None

            self.__service = None

    def register_service(self, service):
        self.__service = service

        if self.__getter is not None:
            self.__getter.register_service(service)

        if self.__setter is not None:
            self.__setter.register_service(service)

        if self.__notifier is not None:
            self.__notifier.register_service(service)

    def parent_service(self):
        return self.__service

    def create_backlinks(self, factory):
        if self.__getter is not None:
            self.__getter.create_backlinks(factory)

        if self.__setter is not None:
            self.__setter.create_backlinks(factory)

        if self.__notifier is not None:
            self.__notifier.create_backlinks(factory)

        return self

    def name(self):
        return self.__name

    def params(self):
        return self.__params

    def getter(self):
        return self.__getter

    def setter(self):
        return self.__setter

    def notifier(self):
        return self.__notifier

    def min_id(self):
        return self.__minimum_id

    def notifier_id(self):
        if self.__notifier is None:
            return None
        return self.__notifier.method_id()

    def internal_id(self):
        if self.notifier_id() is not None:
            return self.notifier_id()
        return self.min_id()

    def size_min_in(self):
        ret = 0
        for p in self.__params:
            ret += p.size_min_bits()
        return bits_to_bytes(ret)

    def size_max_in(self):
        ret = 0
        for p in self.__params:
            ret += p.size_max_bits()
        return bits_to_bytes(ret)

    def size_min_out(self):
        ret = 0
        for p in self.__params:
            ret += p.size_min_bits()
        return bits_to_bytes(ret)

    def size_max_out(self):
        ret = 0
        for p in self.__params:
            ret += p.size_max_bits()
        return bits_to_bytes(ret)

    def legacy(self):
        if self.__params is None:
            return False

        for p in self.__params:
            if p.legacy():
                return True

        return False

    def tlv(self):
        return self.__tlv


class SOMEIPBaseServiceEventgroup(BaseItem):
    def __init__(self, name, eventgroup_id, event_ids, field_ids):
        self.__name = name
        self.__eventgroup_id = int(eventgroup_id)
        self.__event_ids = event_ids
        self.__field_ids = field_ids

    def name(self):
        return self.__name

    def eventgroup_id(self):
        return self.__eventgroup_id

    def event_ids(self):
        return self.__event_ids

    def field_ids(self):
        return self.__field_ids


class SOMEIPBaseParameter(BaseItem):
    def __init__(self, position, name, desc, mandatory, data_type, signal):
        self.__position = int(position)
        self.__name = name
        self.__description = desc
        self.__mandatory = mandatory
        self.__data_type = data_type
        self.__signal = signal

        self.__parent_method = None

    def deep_copy(self, factory):
        """ create a deep copy of this SOMEIPBaseParameter

        :param factory: The ConfigurationFactory to create objects
        :return: a copied SOMEIPBaseParameter
        """

        data_type_copy = None if self.__data_type is None else self.__data_type.deep_copy(factory)
        signal_copy = None if self.__signal is None else self.__signal.deep_copy(factory)

        return factory.create_someip_parameter(self.__position,
                                               self.__name,
                                               self.__description,
                                               self.__mandatory,
                                               data_type_copy,
                                               signal_copy)

    def parent_service(self):
        if self.__parent_method is None:
            return None

        return self.__parent_method.parent_service()

    def parent_method(self):
        return self.__parent_method

    def create_backlinks(self, method, factory):
        if self.__parent_method is None:
            self.__parent_method = method

            if self.__data_type is not None:
                self.__data_type.create_backlinks(method, factory)

            if self.__signal is not None:
                self.__signal.create_backlinks(method, factory)

            return self
        else:
            ret = self.deep_copy(factory)
            # a new parameter has __parent_method set to None, so it will not fail
            return ret.create_backlinks(method, factory)

    def position(self):
        return self.__position

    def name(self):
        return self.__name

    def desc(self):
        return self.__description

    def mandatory(self):
        return self.__mandatory

    def data_type(self):
        return self.__data_type

    def signal(self):
        return self.__signal

    def size_min_bits(self):
        return self.__data_type.size_min_bits()

    def size_max_bits(self):
        return self.__data_type.size_max_bits()

    def legacy(self):
        if self.__signal is not None:
            return True
        if self.__data_type is None:
            return False
        return self.__data_type.legacy()


class SOMEIPBaseParameterBasetype(BaseItem):
    def __init__(
        self, name, data_type, big_endian, bit_length_basetype, bit_length_encoded_type
    ):
        self.__name = name
        self.__data_type = data_type
        self.__big_endian = big_endian
        self.__bit_length_base_type = int(bit_length_basetype)
        self.__bit_length_encoded_type = int(bit_length_encoded_type)

    def deep_copy(self, factory):
        # BaseTypes should be reused and not copied and linked!
        return self

    def create_backlinks(self, method, factory):
        # BaseTypes should be reused and not copied and linked!
        return self

    def name(self):
        return self.__name

    def data_type(self):
        return self.__data_type

    def big_endian(self):
        return self.__big_endian

    def bit_length_base_type(self):
        return self.__bit_length_base_type

    def bit_length_encoded_type(self):
        return self.__bit_length_encoded_type

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False

        return (
                self.name() == other.name()
                and self.data_type() == other.data_type()
                and self.big_endian() == other.big_endian()
                and self.bit_length_base_type() == other.bit_length_base_type()
                and self.bit_length_encoded_type() == other.bit_length_encoded_type()
        )

    def size_min_bits(self):
        return self.__bit_length_encoded_type

    def size_max_bits(self):
        return self.__bit_length_encoded_type


class SOMEIPBaseParameterString(BaseItem):
    def __init__(
        self,
        name,
        char_type,
        bigendian,
        lower_limit,
        upper_limit,
        termination,
        length_of_length,
        pad_to,
    ):
        self.__name = name
        self.__char_type = char_type
        self.__big_endian = bigendian
        self.__lower_limit = int(lower_limit)
        self.__upper_limit = int(upper_limit)
        self.__termination = termination

        if length_of_length is None or length_of_length == -1:
            if lower_limit == upper_limit:
                self.__length_of_length = 0
            else:
                self.__length_of_length = 32  # SOME/IP default
        else:
            self.__length_of_length = int(length_of_length)

        self.__pad_to = int(pad_to)

    def deep_copy(self, factory):
        # Strings should be reused and not copied and linked!
        return self

    def create_backlinks(self, method, factory):
        # Strings should be reused and not copied and linked!
        return self

    def name(self):
        return self.__name

    def char_type(self):
        return self.__char_type

    def big_endian(self):
        return self.__big_endian

    def lower_limit(self):
        return self.__lower_limit

    def upper_limit(self):
        return self.__upper_limit

    def termination(self):
        return self.__termination

    def length_of_length(self):
        return self.__length_of_length

    def pad_to(self):
        return self.__pad_to

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False

        return (
                self.name() == other.name()
                and self.char_type() == other.char_type()
                and self.big_endian() == other.big_endian()
                and self.lower_limit() == other.lower_limit()
                and self.upper_limit() == other.upper_limit()
                and self.termination() == other.termination()
                and self.length_of_length() == other.length_of_length()
                and self.pad_to() == other.pad_to()
        )

    def size_min_bits(self):
        # TODO: double check, if this is based on bytes or chars
        return self.__length_of_length + 8 * self.__lower_limit

    def size_max_bits(self):
        # TODO: double check, if this is based on bytes or chars
        return self.__length_of_length + 8 * self.__upper_limit


class SOMEIPBaseParameterArray(BaseItem):
    def __init__(self, name, dimensions, child):
        self.__name = name
        self.__dimensions = dimensions
        self.__child = child

        self.__parent_method = None

    def deep_copy(self, factory):
        """ create a deep copy of this SOMEIPBaseParameterArray

        :param factory: The ConfigurationFactory to create objects
        :return: a copied SOMEIPBaseParameterArray
        """

        child_copy = None if self.__child is None else self.__child.deep_copy(factory)

        return factory.create_someip_parameter_array(self.__name,
                                                     self.__dimensions,
                                                     child_copy)

    def parent_service(self):
        if self.__parent_method is None:
            return None

        return self.__parent_method.parent_service()

    def parent_method(self):
        return self.__parent_method

    def create_backlinks(self, method, factory):
        if self.__parent_method is None:
            self.__parent_method = method

            if self.__child is None:
                print(f"ERROR: create_backlinks child is None {method.parent_service().name()} {method.name()}")
                return self

            self.__child = self.__child.create_backlinks(method, factory)

            return self
        else:
            ret = self.deep_copy(factory)
            # a new parameter has __parent_method set to None, so it will not fail
            return ret.create_backlinks(method, factory)

    def name(self):
        return self.__name

    def dimensions(self):
        return self.__dimensions

    def child(self):
        return self.__child

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False

        return (
                self.name() == other.name()
                and self.dimensions() == other.dimensions()
                and self.child() == other.child()
        )

    def size_min_bits(self):
        ret = self.__child.size_min_bits()

        # todo: is this the right order?
        for dim in self.__dimensions.values():
            ret = dim.calc_size_min_bits(ret)

        return ret

    def size_max_bits(self):
        ret = self.__child.size_min_bits()

        # todo: is this the right order?
        for dim in self.__dimensions.values():
            ret = dim.calc_size_max_bits(ret)

        return ret


class SOMEIPBaseParameterArrayDimension(BaseItem):
    def __init__(self, dimension, lower_limit, upper_limit, length_of_length, pad_to):
        self.__dimension = int(dimension)
        self.__lower_limit = int(lower_limit)
        self.__upper_limit = int(upper_limit)
        if length_of_length is None or length_of_length == -1:
            if lower_limit == upper_limit:
                self.__length_of_length = 0
            else:
                self.__length_of_length = 32  # SOME/IP default
        else:
            self.__length_of_length = int(length_of_length)

        self.__pad_to = int(pad_to)

        self.__parent_method = None

    def deep_copy(self, factory):
        """ create a deep copy of this SOMEIPBaseParameterArrayDimension

        :param factory: The ConfigurationFactory to create objects
        :return: a copied SOMEIPBaseParameterArrayDimension
        """

        return factory.create_someip_parameter_array_dim(self.__dimension,
                                                         self.__lower_limit,
                                                         self.__upper_limit,
                                                         self.__length_of_length,
                                                         self.__pad_to)

    def parent_service(self):
        if self.__parent_method is None:
            return None

        return self.__parent_method.parent_service()

    def parent_method(self):
        return self.__parent_method

    def create_backlinks(self, method, factory):
        if self.__parent_method is None:
            self.__parent_method = method
            return self
        else:
            ret = self.deep_copy(factory)
            # a new parameter has __parent_method set to None, so it will not fail
            return ret.create_backlinks(method, factory)

    def dimension(self):
        return self.__dimension

    def lower_limit(self):
        return self.__lower_limit

    def upper_limit(self):
        return self.__upper_limit

    def length_of_length(self):
        return self.__length_of_length

    def pad_to(self):
        return self.__pad_to

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False

        return (
                self.dimension() == other.dimension()
                and self.lower_limit() == other.lower_limit()
                and self.upper_limit() == other.upper_limit()
                and self.length_of_length() == other.length_of_length()
                and self.pad_to() == other.pad_to()
        )

    def calc_size_min_bits(self, inner_length):
        ret = self.__lower_limit * inner_length
        # XXX - padTo completely untested since export do not have BIT-ALIGNMENT set (its counted in bits)
        if self.__pad_to > 0:
            ret += ret % self.__pad_to

        return self.__length_of_length + ret

    def calc_size_max_bits(self, inner_length):
        ret = self.__upper_limit * inner_length
        # XXX - padTo completely untested since export do not have BIT-ALIGNMENT set (its counted in bits)
        if self.__pad_to > 0:
            ret += ret % self.__pad_to

        return self.__length_of_length + ret


class SOMEIPBaseParameterStruct(BaseItem):
    def __init__(self, name, length_of_length, pad_to, members, tlv=False):
        self.__name = name
        self.__members = members
        self.__tlv = tlv

        if length_of_length is None or length_of_length == -1:
            self.__length_of_length = 0
        else:
            self.__length_of_length = int(length_of_length)

        self.__pad_to = int(pad_to)

        self.__parent_method = None

    def deep_copy(self, factory):
        """ create a deep copy of this SOMEIPBaseParameterArray

        :param factory: The ConfigurationFactory to create objects
        :return: a copied SOMEIPBaseParameterArray
        """

        members_copy = None
        if self.__members is not None:
            members_copy = {}

            for key, member in self.__members.items():
                if member is None:
                    members_copy[key] = member
                else:
                    members_copy[key] = member.deep_copy(factory)

        return factory.create_someip_parameter_struct(self.__name,
                                                      self.__length_of_length,
                                                      self.__pad_to,
                                                      members_copy,
                                                      self.__tlv)

    def parent_service(self):
        if self.__parent_method is None:
            return None

        return self.__parent_method.parent_service()

    def parent_method(self):
        return self.__parent_method

    def create_backlinks(self, method, factory):
        if self.__parent_method is None:
            self.__parent_method = method

            if self.__members is None:
                print(f"ERROR: create_backlinks members is None {method.parent_service().name()} {method.name()}")
                return self

            new_members = {}
            for key, member in self.__members.items():
                if member is None:
                    print(f"ERROR: create_backlinks a member is None {method.parent_service().name()} {method.name()} "
                          f"key_{key}")
                    new_members[key] = member
                else:
                    new_members[key] = member.create_backlinks(method, factory)
            self.__members = new_members

            return self
        else:
            ret = self.deep_copy(factory)
            # a new parameter has __parent_method set to None, so it will not fail
            return ret.create_backlinks(method, factory)

    def name(self):
        return self.__name

    def members(self):
        return self.__members

    def length_of_length(self):
        return self.__length_of_length

    def pad_to(self):
        return self.__pad_to

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False

        return (
            self.name() == other.name()
            and self.members() == other.members()
            and self.length_of_length() == other.length_of_length()
            and self.pad_to() == other.pad_to()
            and self.tlv() == other.tlv()
        )

    def size_min_bits(self):
        ret = self.__length_of_length
        for m in self.__members.values():
            ret += m.child().size_min_bits()
        return ret

    def size_max_bits(self):
        ret = self.__length_of_length
        for m in self.__members.values():
            ret += m.child().size_max_bits()
        return ret

    def legacy(self):
        for m in self.__members.values():
            if m.legacy():
                return True
        return False

    def tlv(self):
        return self.__tlv


class SOMEIPBaseParameterStructMember(BaseItem):
    def __init__(self, position, name, mandatory, child, signal):
        self.__position = int(position)
        self.__name = name
        self.__mandatory = mandatory
        self.__child = child
        self.__signal = signal

        self.__parent_method = None

    def deep_copy(self, factory):
        """ create a deep copy of this SOMEIPBaseParameterStructMember

        :param factory: The ConfigurationFactory to create objects
        :return: a copied SOMEIPBaseParameterStructMember
        """

        child_copy = None if self.__child is None else self.__child.deep_copy(factory)
        signal_copy = None if self.__signal is None else self.__signal.deep_copy(factory)

        return factory.create_someip_parameter_struct_member(self.__position,
                                                             self.__name,
                                                             self.__mandatory,
                                                             child_copy,
                                                             signal_copy)

    def parent_service(self):
        if self.__parent_method is None:
            return None

        return self.__parent_method.parent_service()

    def parent_method(self):
        return self.__parent_method

    def create_backlinks(self, method, factory):
        if self.__parent_method is None:
            self.__parent_method = method

            if self.__child is None and self.__signal is None:
                print(f"ERROR: create_backlinks with child and signal None "
                      f"{method.parent_service().name()} {method.name()}")

            if self.__child is not None:
                self.__child = self.__child.create_backlinks(method, factory)

            if self.__signal is not None:
                self.__signal = self.__signal.create_backlinks(method, factory)

            return self
        else:
            ret = self.deep_copy(factory)
            # a new parameter has __parent_method set to None, so it will not fail
            return ret.create_backlinks(method, factory)

    def name(self):
        return self.__name

    def position(self):
        return self.__position

    def update_position(self, p):
        self.__position = p

    def mandatory(self):
        return self.__mandatory

    def child(self):
        return self.__child

    def signal(self):
        return self.__signal

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False

        return (
            self.name() == other.name()
            and self.position() == other.position()
            and self.mandatory() == other.mandatory()
            and self.child() == other.child()
            and self.signal() == self.signal()
        )

    def legacy(self):
        if self.__signal is not None:
            return True
        return False


class SOMEIPBaseParameterTypedef(BaseItem):
    def __init__(self, name, name2, child):
        self.__name = name
        self.__name2 = name2
        self.__child = child

        self.__parent_method = None

    def deep_copy(self, factory):
        """ create a deep copy of this SOMEIPBaseParameterTypedef

        :param factory: The ConfigurationFactory to create objects
        :return: a copied SOMEIPBaseParameterTypedef
        """

        child_copy = None if self.__child is None else self.__child.deep_copy(factory)

        return factory.create_someip_parameter_typedef(self.__name,
                                                       self.__name2,
                                                       child_copy)

    def parent_service(self):
        if self.__parent_method is None:
            return None

        return self.__parent_method.parent_service()

    def parent_method(self):
        return self.__parent_method

    def create_backlinks(self, method, factory):
        if self.__parent_method is None:
            self.__parent_method = method

            if self.__child is None:
                print(f"ERROR: create_backlinks child is None {method.parent_service().name()} {method.name()}")
            else:
                self.__child = self.__child.create_backlinks(method, factory)

            return self
        else:
            ret = self.deep_copy(factory)
            # a new parameter has __parent_method set to None, so it will not fail
            return ret.create_backlinks(method, factory)

    def name(self):
        return self.__name

    def name2(self):
        return self.__name2

    def child(self):
        return self.__child

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False

        return (
            self.name() == other.name()
            and self.name2() == other.name2()
            and self.child() == other.child()
        )

    def size_min_bits(self):
        return self.__child.size_min_bits()

    def size_max_bits(self):
        return self.__child.size_max_bits()


class SOMEIPBaseParameterEnumeration(BaseItem):
    def __init__(self, name, items, child):
        self.__name = name
        self.__items = items
        self.__child = child

    def deep_copy(self, factory):
        # Enumerations should be reused and not copied and linked!
        return self

    def create_backlinks(self, method, factory):
        # Enumerations should be reused and not copied and linked!
        return self

    def name(self):
        return self.__name

    def items(self):
        return self.__items

    def child(self):
        return self.__child

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False

        return (
            self.name() == other.name()
            and self.items() == other.items()
            and self.child() == other.child()
        )

    def size_min_bits(self):
        return self.__child.size_min_bits()

    def size_max_bits(self):
        return self.__child.size_max_bits()


class SOMEIPBaseParameterEnumerationItem(BaseItem):
    def __init__(self, value, name, description):
        self.__value = int(value)
        self.__name = name
        self.__description = description

    def name(self):
        return self.__name

    def description(self):
        return self.__description

    def value(self):
        return self.__value

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False

        return (
                self.name() == other.name()
                and self.description() == other.description()
                and self.value() == other.value()
        )


class SOMEIPBaseParameterUnion(BaseItem):
    def __init__(self, name, length_of_length, length_of_type, pad_to, members):
        self.__name = name
        self.__members = members

        if length_of_length is None or length_of_length == -1:
            self.__length_of_length = 32  # SOME/IP default
        else:
            self.__length_of_length = int(length_of_length)

        if length_of_type is None or length_of_type == -1:
            self.__length_of_type = 32  # SOME/IP default
        else:
            self.__length_of_type = int(length_of_type)

        self.__pad_to = int(pad_to)

        self.__parent_method = None

    def deep_copy(self, factory):
        """ create a deep copy of this SOMEIPBaseParameterUnion

        :param factory: The ConfigurationFactory to create objects
        :return: a copied SOMEIPBaseParameterUnion
        """

        members_copy = None
        if self.__members is not None:
            members_copy = {}

            for key, member in self.__members.items():
                if member is None:
                    members_copy[key] = member
                else:
                    members_copy[key] = member.deep_copy(factory)

        return factory.create_someip_parameter_union(self.__name,
                                                     self.__length_of_length,
                                                     self.__length_of_type,
                                                     self.__pad_to,
                                                     members_copy)

    def parent_service(self):
        if self.__parent_method is None:
            return None

        return self.__parent_method.parent_service()

    def parent_method(self):
        return self.__parent_method

    def create_backlinks(self, method, factory):
        if self.__parent_method is None:
            self.__parent_method = method

            if self.__members is None:
                print(f"ERROR: create_backlinks members is None {method.parent_service().name()} {method.name()}")
            else:
                members_copy = {}

                for key, member in self.__members.items():
                    if member is None:
                        print(
                            f"ERROR: create_backlinks member is None "
                            f"{method.parent_service().name()} {method.name()} key:{key}")
                        members_copy[key] = member
                    else:
                        members_copy[key] = member.create_backlinks(method, factory)

                self.__members = members_copy

            return self
        else:
            ret = self.deep_copy(factory)
            # a new parameter has __parent_method set to None, so it will not fail
            return ret.create_backlinks(method, factory)

    def name(self):
        return self.__name

    def members(self):
        return self.__members

    def length_of_length(self):
        return self.__length_of_length

    def length_of_type(self):
        return self.__length_of_type

    def pad_to(self):
        return self.__pad_to

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False

        return (
            self.name() == other.name()
            and self.members() == other.members()
            and self.length_of_length() == other.length_of_length()
            and self.length_of_length() == other.length_of_length()
            and self.pad_to() == other.pad_to()
        )

    def size_min_bits(self):
        ret = -1

        for m in self.__members.values():
            if ret == -1:
                ret = m.child().size_min_bits()
            else:
                if ret >= m.child().size_min_bits():
                    ret = m.child().size_min_bits()
            if self.__pad_to > 0:
                ret += ret % self.pad_to()
        return self.__length_of_length + ret

    def size_max_bits(self):
        ret = -1

        for m in self.__members.values():
            if ret == -1:
                ret = m.child().size_max_bits()
            else:
                if ret < m.child().size_max_bits():
                    ret = m.child().size_max_bits()
            if self.__pad_to > 0:
                ret += ret % self.pad_to()
        return self.__length_of_length + ret


class SOMEIPBaseParameterUnionMember(BaseItem):
    def __init__(self, index, name, mandatory, child):
        self.__index = int(index)
        self.__name = name
        self.__mandatory = mandatory
        self.__child = child

        self.__parent_method = None

    def deep_copy(self, factory):
        """ create a deep copy of this SOMEIPBaseParameterUnionMember

        :param factory: The ConfigurationFactory to create objects
        :return: a copied SOMEIPBaseParameterUnionMember
        """

        child_copy = None if self.__child is None else self.__child.deep_copy(factory)

        return factory.create_someip_parameter_union_member(self.__index,
                                                            self.__name,
                                                            self.__mandatory,
                                                            child_copy)

    def parent_service(self):
        if self.__parent_method is None:
            return None

        return self.__parent_method.parent_service()

    def parent_method(self):
        return self.__parent_method

    def create_backlinks(self, method, factory):
        if self.__parent_method is None:
            self.__parent_method = method

            if self.__child is None:
                print(f"ERROR: create_backlinks child is None {method.parent_service().name()} {method.name()}")
            else:
                self.__child.create_backlinks(method, factory)

            return self
        else:
            ret = self.deep_copy(factory)
            # a new parameter has __parent_method set to None, so it will not fail
            return ret.create_backlinks(method, factory)

    def name(self):
        return self.__name

    def index(self):
        return self.__index

    def mandatory(self):
        return self.__mandatory

    def child(self):
        return self.__child

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False

        return (
            self.name() == other.name()
            and self.index() == other.index()
            and self.mandatory() == other.mandatory()
            and self.child() == other.child()
        )


class SOMEIPBaseParameterBitfield(BaseItem):
    def __init__(self, name, items, child):
        self.__name = name
        self.__items = items
        self.__child = child

        self.__parent_method = None

    def deep_copy(self, factory):
        """ create a deep copy of this SOMEIPBaseParameterBitfield

        :param factory: The ConfigurationFactory to create objects
        :return: a copied SOMEIPBaseParameterBitfield
        """

        child_copy = None if self.__child is None else self.__child.deep_copy(factory)

        return factory.create_someip_parameter_bitfield(self.__name,
                                                        self.__items,
                                                        child_copy)

    def parent_service(self):
        if self.__parent_method is None:
            return None

        return self.__parent_method.parent_service()

    def parent_method(self):
        return self.__parent_method

    def create_backlinks(self, method, factory):
        if self.__parent_method is None:
            self.__parent_method = method

            if self.__child is None:
                print(f"ERROR: create_backlinks child is None {method.parent_service().name()} {method.name()}")
            else:
                self.__child.create_backlinks(method, factory)

            return self
        else:
            ret = self.deep_copy(factory)
            # a new parameter has __parent_method set to None, so it will not fail
            return ret.create_backlinks(method, factory)

    def name(self):
        return self.__name

    def items(self):
        return self.__items

    def child(self):
        return self.__child

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False

        return (
            self.name() == other.name()
            and self.items() == other.items()
            and self.child() == other.child()
        )

    def size_min_bits(self):
        return self.__child.size_min_bits()

    def size_max_bits(self):
        return self.__child.size_max_bits()


class SOMEIPBaseParameterBitfieldItem(BaseItem):
    def __init__(self, bit_number, name):
        self.__name = name
        self.__bit_number = int(bit_number)

    def name(self):
        return self.__name

    def bit_number(self):
        return self.__bit_number

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False

        return self.name() == other.name() and self.bit_number() == other.bit_number()


class BaseSignal(BaseItem):
    def __init__(
        self,
        original_id,
        name,
        compu_scale,
        compu_const,
        bit_length,
        min_length,
        max_length,
        base_type,
        base_type_len,
    ):
        self.__original_id = original_id
        self.__name = name
        self.__compu_scale = compu_scale
        self.__compu_consts = compu_const
        self.__bit_length = bit_length
        self.__min_length = min_length
        self.__max_length = max_length
        self.__base_type = base_type
        self.__base_type_len = base_type_len

    def deep_copy(self, factory):
        return factory.create_signal(
            self.__original_id,
            self.__name,
            self.__compu_scale,
            self.__compu_consts,
            self.__bit_length,
            self.__max_length,
            self.__base_type,
            self.__base_type_len
        )

    def original_id(self):
        return self.__original_id

    def name(self):
        return self.__name

    def compu_scale(self):
        return self.__compu_scale

    def scaler(self):
        if self.compu_scale() is not None and len(self.compu_scale()) == 3:
            num0, num1, denom = self.compu_scale()
            return float(num1) / float(denom)
        return 1

    def offset(self):
        if self.compu_scale() is not None and len(self.compu_scale()) == 3:
            num0, num1, denom = self.compu_scale()
            return float(num0)
        return 0

    def compu_consts(self):
        return self.__compu_consts

    def bit_length(self):
        return self.__bit_length

    def min_length(self):
        return self.__min_length

    def max_length(self):
        return self.__max_length

    def base_type(self):
        return self.__base_type

    def base_type_length(self):
        return self.__base_type_len

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False

        return (
                self.original_id() == self.original_id()
                and self.name() == other.name()
                and self.compu_scale() == other.compu_scale()
                and self.base_type() == other.base_type()
                and self.compu_consts() == other.compu_consts()
        )


class BaseSignalInstance(BaseItem):
    def __init__(self, original_id, signal_reference, bit_position, is_high_low_byte_order):
        self.__original_id = original_id
        self.__signal_ref = signal_reference
        self.__bit_position = bit_position
        self.__is_high_low_byte_order = is_high_low_byte_order
        self.__signal = None

    def original_id(self):
        return self.__original_id

    def add_signal(self, signal):
        self.__signal = signal

    def bit_position(self):
        return self.__bit_position

    def is_high_low_byte_order(self):
        return self.__is_high_low_byte_order

    def signal(self):
        return self.__signal

    def signal_ref(self):
        return self.__signal_ref


class BaseAbstractPDU(BaseItem):
    def __init__(self, original_id, short_name, byte_length, pdu_type):
        self.__original_id = original_id
        self.__short_name = short_name
        self.__byte_length = byte_length
        self.__pdu_type = pdu_type

    def original_id(self):
        return self.__original_id

    def short_name(self):
        return self.__short_name

    def byte_length(self):
        return self.__byte_length

    def pdu_type(self):
        return self.__pdu_type

    def is_multiplex_pdu(self):
        return False


class BasePDU(BaseAbstractPDU):
    def __init__(self, original_id, short_name, byte_length, pdu_type, signal_instances):
        super(BasePDU, self).__init__(original_id, short_name, byte_length, pdu_type)

        self.__signal_instances = signal_instances

    def signal_instances(self):
        return self.__signal_instances

    def signal_instances_sorted_by_bit_position(self):
        tmp = {}
        for si in self.__signal_instances.values():
            if si.bit_position() in tmp.keys():
                print(
                    f"ERROR: PDU {self.short_name()} has multiple Signals starting at same position! Overwriting!"
                )
            tmp[si.bit_position()] = si

        ret = []
        for key in sorted(tmp.keys()):
            ret.append(tmp[key])

        return ret


class BaseMultiplexPDU(BaseAbstractPDU):
    def __init__(
        self,
        original_id,
        short_name,
        byte_length,
        pdu_type,
        switch,
        segment_positions,
        pdu_instances,
        static_segments,
        static_pdu,
    ):
        super(BaseMultiplexPDU, self).__init__(original_id, short_name, byte_length, pdu_type)

        if switch is None and len(segment_positions) != 0:
            print(f"ERROR: PDU: {short_name} has Dynamic Segments but no Switch!")
            raise ValueError

        if switch is not None and len(segment_positions) == 0:
            print(f"ERROR: PDU: {short_name} has a Switch but no Dynamic Segments!")
            # raise ValueError

        if len(segment_positions) > 1:
            print(
                f"ERROR: We only support up to 1 Dynamic Segment per PDU! "
                f"PDU {short_name} has {len(segment_positions)}"
            )
            raise ValueError

        if static_pdu is None and len(static_segments) != 0:
            print(f"ERROR: PDU: {short_name} has Static Segments but no Static PDU!")
            raise ValueError

        if static_pdu is not None and len(static_segments) == 0:
            print(f"ERROR: PDU: {short_name} has a Static PDU but not Static Segments!")
            raise ValueError

        if len(static_segments) > 1:
            print(
                f"ERROR: We only support up to 1 Static Segment per PDU. "
                f"PDU {short_name} has {len(static_segments)}"
            )
            raise ValueError

        self.__switch = switch
        self.__segment_positions = segment_positions
        self.__pdu_instances = pdu_instances
        self.__static_segments = static_segments
        self.__static_pdu = static_pdu

    def switch(self):
        return self.__switch

    def segment_positions(self):
        return self.__segment_positions

    def pdu_instances(self):
        return self.__pdu_instances

    def static_segments(self):
        return self.__static_segments

    def static_pdu(self):
        return self.__static_pdu

    def is_multiplex_pdu(self):
        return True


class BaseMultiplexPDUSwitch(BaseItem):
    def __init__(
        self, original_id, short_name, bit_position, is_high_low_byte_order, bit_length
    ):
        self.__original_id = original_id
        self.__short_name = short_name
        self.__bit_position = bit_position
        self.__is_high_low_byte_order = is_high_low_byte_order
        self.__bit_length = bit_length

    def original_id(self):
        return self.__original_id

    def short_name(self):
        return self.__short_name

    def bit_position(self):
        return self.__bit_position

    def is_high_low_byte_order(self):
        return self.__is_high_low_byte_order

    def bit_length(self):
        return self.__bit_length


class BaseMultiplexPDUSegmentPosition(BaseItem):
    def __init__(self, bit_position, is_high_low_byte_order, bit_length):
        self.__bit_position = bit_position
        self.__is_high_low_byte_order = is_high_low_byte_order
        self.__bit_length = bit_length

    def bit_position(self):
        return self.__bit_position

    def is_high_low_byte_order(self):
        return self.__is_high_low_byte_order

    def bit_length(self):
        return self.__bit_length


class BaseEthernetPDUInstance(BaseItem):
    def __init__(self, pdu_ref, header_id):
        self.__pdu_ref = pdu_ref
        self.__bit_position = 0
        self.__header_id = header_id
        self.__pdu_update_bit_position = None
        self.__pdu = None

    def add_pdu(self, pdu):
        self.__pdu = pdu

    def pdu(self):
        return self.__pdu

    def bit_position(self):
        return self.__bit_position

    def header_id(self):
        return self.__header_id

    def pdu_update_bit_position(self):
        return self.__pdu_update_bit_position


class BasePDUInstance(BaseItem):
    def __init__(
        self, original_id, pdu_ref, bit_position, is_high_low_byte_order, pdu_update_bit_position
    ):
        self.__original_id = original_id
        self.__pdu_ref = pdu_ref
        self.__bit_position = bit_position
        self.__is_high_low_byte_order = is_high_low_byte_order
        self.__pdu_update_bit_position = pdu_update_bit_position
        self.__pdu = None

    def original_id(self):
        return self.__original_id

    def add_pdu(self, pdu):
        self.__pdu = pdu

    def pdu(self):
        return self.__pdu

    def pdu_ref(self):
        return self.__pdu_ref

    def bit_position(self):
        return self.__bit_position

    def pdu_update_bit_position(self):
        return self.__pdu_update_bit_position


class BaseFrame(BaseItem):
    def __init__(self, original_id, short_name, frame_type, byte_length, pdu_instances):
        self.__original_id = original_id
        self.__short_name = short_name
        self.__byte_length = byte_length
        self.__frame_type = frame_type
        self.__pdu_instances = pdu_instances

    def add_pdu_instance(self, pdu_instance):
        self.__pdu_instances[pdu_instance.__pdu_ref] = pdu_instance

    def original_id(self):
        return self.__original_id

    def short_name(self):
        return self.__short_name

    def byte_length(self):
        return self.__byte_length

    def frame_type(self):
        return self.__frame_type

    def pdu_instances(self):
        return self.__pdu_instances


class BaseFrameTriggering(BaseItem):
    def __init__(self, original_id, frame):
        self.__original_id = original_id
        self.__frame = frame

    def original_id(self):
        return self.__original_id

    def calc_key(self):
        return self.__original_id

    def frame(self):
        return self.__frame

    def is_can(self):
        return False

    def is_flexray(self):
        return False

    def is_ethernet(self):
        return False


class BaseFrameTriggeringCAN(BaseFrameTriggering):
    def __init__(self, original_id, frame, can_id):
        super(BaseFrameTriggeringCAN, self).__init__(original_id, frame)

        self.__can_id = can_id

    def can_id(self):
        return self.__can_id

    def calc_key(self):
        return f"CAN-0x{self.__can_id:04x}"

    def is_can(self):
        return True


class BaseFrameTriggeringFlexRay(BaseFrameTriggering):
    def __init__(self, original_id, frame, slot_id, cycle_counter, base_cycle, cycle_repetition):
        super(BaseFrameTriggeringFlexRay, self).__init__(original_id, frame)

        self.__slot_id = slot_id
        self.__cycle_counter = cycle_counter
        self.__base_cycle = base_cycle
        self.__cycle_repetition = cycle_repetition

    def slot_id(self):
        return self.__slot_id

    def cycle_counter(self):
        return self.__cycle_counter

    def base_cycle(self):
        return self.__base_cycle

    def cycle_repetition(self):
        return self.__cycle_repetition

    def scheduling(self):
        return (
            self.__slot_id,
            self.__cycle_counter,
            self.__base_cycle,
            self.__cycle_repetition,
        )

    def calc_key(self):
        tmp_cycle_counter = (
            0 if self.__cycle_counter is None else self.__cycle_counter
        )
        tmp_base_cycle = 0 if self.__base_cycle is None else self.__base_cycle
        tmp_cycle_repetition = (
            0 if self.__cycle_repetition is None else self.__cycle_repetition
        )

        ret = (
            f"FlexRay-0x{self.__slot_id:04x}-0x{tmp_cycle_counter:04x}-0x{tmp_base_cycle:04x}-"
            f"0x{tmp_cycle_repetition:04x}"
        )
        return ret

    def is_flexray(self):
        return True
