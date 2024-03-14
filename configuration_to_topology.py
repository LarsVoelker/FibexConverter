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

import argparse
import csv
import json
from graphviz import Graph
import os.path
import pprint
import sys
import time

from parser_dispatcher import *  # @UnusedWildImport
from configuration_base_classes import *  # @UnusedWildImport

DUMMY_SWITCH_NAME = ""
CSV_DELIM = ","
g_gen_portid = False

class TopologyTableEntry:
    # only ctrl or switch+swport can be used each (from/to)
    # vlans must be set of ints
    def __init__(self, ecu_from, ctrl_from, switch_from, swport_from, ecu_to, ctrl_to, switch_to, swport_to, vlans):
        self.__init_finished__ = False

        if ctrl_from is not None and (switch_from is not None or swport_from is not None):
            print(f"GenericTopologyTableEntry: invalid on from side! "
                  f"ecu_from:{ecu_from} ctrl_from:{ctrl_from} switch_from:{switch_from} swport_from:{swport_from} ecu_to:{ecu_to}")
            #raise Exception("GenericTopologyTableEntry: invalid on from side!")
            return
        if ctrl_to is not None and (switch_to is not None or swport_to is not None):
            print(f"GenericTopologyTableEntry: invalid on to side! "
                  f"ecu_from:{ecu_from} ctrl_to:{ctrl_to} ecu_to:{ecu_to} switch_to:{switch_to} swport_to:{swport_to}")
            #raise Exception("GenericTopologyTableEntry: invalid on to side!")
            return

        self.__ecu_from__ = ecu_from
        self.__ctrl_from__ = ctrl_from
        self.__switch_from__ = switch_from
        self.__switch_port_from__ = swport_from
        self.__ecu_to__ = ecu_to
        self.__ctrl_to__ = ctrl_to
        self.__switch_to__ = switch_to
        self.__switch_port_to__ = swport_to
        self.__vlans__ = vlans

        self.__init_finished__ = True

    def ecu_from(self):
        if not self.__init_finished__:
            print(f"ERROR: ecu_from: Calling uninitialized TopologyTableEntry. Input file not ok!")
            return None

        return self.__ecu_from__

    def ecu_to(self):
        if not self.__init_finished__:
            print(f"ERROR: ecu_to: Calling uninitialized TopologyTableEntry. Input file not ok!")
            return None

        return self.__ecu_to__

    @staticmethod
    def __to_half_output_set__(ecu, ctrl, switch, swport):
        if ctrl is not None:
            ret = ["Controller", ecu, ctrl, ""]
        elif switch is not None and swport is not None:
            ret = ["SwitchPort", ecu, switch, swport]
        else:
            ret = ["Etherner Bus", ecu, "", ""]
        return ret

    def to_output_set(self, vlan_columns):
        if not self.__init_finished__:
            print(f"ERROR: to_output_set: Calling uninitialized TopologyTableEntry. Input file not ok!")
            return None

        ret = self.__to_half_output_set__(self.__ecu_from__, self.__ctrl_from__,
                                          self.__switch_from__, self.__switch_port_from__)

        ret += self.__to_half_output_set__(self.__ecu_to__, self.__ctrl_to__,
                                           self.__switch_to__, self.__switch_port_to__)

        for vlan_id in vlan_columns:
            if vlan_id in self.__vlans__:
                if vlan_id == 0:
                    ret += ["untagged"]
                else:
                    ret += [f"0x{vlan_id:x}"]
            else:
                ret += [""]

        return ret


class AccessControlTableEntries:
    # vlans must be set of ints
    def __init__(self, ecu_from, switch_from, swport_from, ecu_to, ctrl_to, ips_per_vlans):
        self.__ecu_from__ = ecu_from
        self.__switch_from__ = switch_from
        self.__switch_port_from__ = swport_from
        self.__ecu_to__ = ecu_to
        self.__ctrl_to__ = ctrl_to
        self.__addrs_per_vlans__ = ips_per_vlans


    def to_output_set_dict(self, delim):
        ret = {}

        if self.__addrs_per_vlans__ is not None:
            for vlan, addrs in self.__addrs_per_vlans__.items():
                if addrs is not None:
                    for addr in addrs:
                        if is_ip_mcast(addr) or is_mac_mcast(addr):
                            key = f"{self.__ecu_from__}{delim}{self.__switch_from__}{delim}{self.__switch_port_from__}" \
                                  f"{delim}0x{vlan:x}"

                            data = (key, [])
                            tmp = ret.setdefault(key, data)
                            tmp[1].append(str(addr))

        return ret



    def to_output_set(self, factory, escape_for_excel):
        ret = []

        if self.__addrs_per_vlans__ is not None:
            for vlan, addrs in self.__addrs_per_vlans__.items():
                if addrs is not None:
                    for addr in addrs:
                        mask_prefix = factory.get_ipv4_netmask_or_ipv6_prefix_length(addr)
                        escaped_addr = f"\"=\"\"{addr}\"\"\"" if escape_for_excel else f"{addr}"
                        ret += [(f"{self.__ecu_from__}", f"{self.__switch_from__}", f"{self.__switch_port_from__}",
                                f"{self.__ecu_to__}", f"{self.__ctrl_to__}",
                                f"0x{vlan:x}", escaped_addr,
                                mask_prefix,
                                f"{mcast_addr_to_mac_mcast(addr)}")]

        return ret


class MulticastPathEntry:
    def __init__(self, sid_iid, tx_swport, tx_socket, rx_swport, rx_socket):
        if tx_socket.interface().vlanid() != rx_socket.interface().vlanid():
            print(f"WARNING: RX and TX vlan differ for Service-ID/Instance-ID 0x{sid_iid:08x}! Not supported!")
            return

        self.__sid_iid__ = sid_iid
        self.__tx_swport__ = tx_swport
        self.__tx_socket__ = tx_socket
        self.__rx_swport__ = rx_swport
        self.__rx_socket__ = rx_socket

    def to_output_set(self):
        ret = (f"0x{self.__sid_iid__:08x}",
               f"{self.__tx_swport__}", f"{self.__tx_socket__.interface().vlanid()}", f"{self.__tx_socket__.ip()}",
               f"{self.__rx_swport__}", f"{self.__rx_socket__.interface().vlanid()}", f"{self.__rx_socket__.ip()}")
        return ret

    def to_csv_line(self):
        ret = (f"0x{self.__sid_iid__:08x}{CSV_DELIM}"
               f"{self.__tx_swport__}{CSV_DELIM}"
               f"{self.__tx_socket__.interface().vlanid()}{CSV_DELIM}"
               f"{self.__tx_socket__.ip()}{CSV_DELIM}"
               f"{self.__rx_swport__}{CSV_DELIM}"
               f"{self.__rx_socket__.interface().vlanid()}{CSV_DELIM}"
               f"{self.__rx_socket__.ip()}")
        return ret

    def to_key_string(self):
        ret = (f"{self.__tx_swport__}{CSV_DELIM}"
               f"{self.__tx_socket__.interface().vlanid()}{CSV_DELIM}"
               f"{self.__tx_socket__.ip()}{CSV_DELIM}"
               f"{self.__rx_swport__}{CSV_DELIM}"
               f"{self.__rx_socket__.interface().vlanid()}{CSV_DELIM}"
               f"{self.__rx_socket__.ip()}")
        return ret

    def sid_iid(self):
        return self.__sid_iid__


class SimpleConfigurationFactory(BaseConfigurationFactory):
    def __init__(self):
        self.__switch_ports__ = dict()
        self.__switches__ = dict()
        self.__ethernet_busses__ = dict()
        self.__ecus__ = dict()
        self.__vlans__ = dict()
        self.__multicast_paths__ = dict()
        self.__mcast_entries__ = None

        # we need these to trace the topology (multicast) -- ONLY EGs are Multicast!!!
        # key is service-id << 16 + service-instance-id
        self.__service_instance_provider_sockets__ = dict()
        self.__service_instance_consumer_sockets__ = dict()
        self.__eg_senders__ = []

        #self.__pdu_relations__ = dict()

        # create dummy ECU for unconnected switches
        self.__dummy_ecu__ = self.create_ecu(DUMMY_SWITCH_NAME, ())

        self.__ipv4_netmasks__ = {}
        self.__ipv6_prefix_lengths__ = {}

    def __add_service_instance_provider_socket__(self, serviceid, instanceid, swport, socket):
        key = (serviceid << 16) + instanceid
        if key not in self.__service_instance_provider_sockets__.keys():
            self.__service_instance_provider_sockets__[key] = []

        self.__service_instance_provider_sockets__[key].append((swport, socket))

    def __add_service_instance_consumer_socket__(self, serviceid, instanceid, swport, socket):
        key = (serviceid << 16) + instanceid
        if key not in self.__service_instance_consumer_sockets__.keys():
            self.__service_instance_consumer_sockets__[key] = []

        self.__service_instance_consumer_sockets__[key].append((swport, socket))

    def create_vlan(self, name, vlanid, prio):
        vlan = BaseVLAN(name, vlanid, prio)
        if vlanid is None:
            vlanid = 0
        # we are just overwritting
        if int(vlanid) in self.__vlans__.keys() and self.__vlans__[int(vlanid)].name() != vlan.name():
            print(f"ERROR: Name collision on VLAN ID:{vlanid} "
                  f"Name:{self.__vlans__[int(vlanid)].name()} vs Name:{vlan.name()}")

        self.__vlans__[int(vlanid)] = vlan
        return vlan

    def get_vlan_columns(self):
        return sorted(self.__vlans__.keys())

    def get_multicast_columns(self, sort_columns=True):
        if sort_columns:
            return sorted(self.all_multicast_addresses(), key=lambda x: addr_to_key(x))
        else:
            return sorted(self.all_multicast_addresses())

    def create_multicast_path(self, switchport_tx, vlan_tx, src_addr, switchport_rx, vlan_rx, mcast_addr, comment):
        tmp = MulticastPath(switchport_tx, vlan_tx, src_addr, switchport_rx, vlan_rx, mcast_addr, comment)

        if tmp.to_key() not in self.__multicast_paths__.keys():
            self.__multicast_paths__[tmp.to_key()] = tmp
        elif comment is not None and comment != "":
            # do not use CSV_DELIM here since we want to merge
            self.__multicast_paths__[tmp.to_key()].__append_to_comment__(f"; {comment}")

        return tmp

    def calc_mcast_topology(self):
        if self.__mcast_entries__ is not None:
            # we need to stop or the results are wrong (wrong entries in mcast matrix)
            return

        mcast_entries = dict()

        # TODO: Support MAC Addresses too

        # let us make sure to reduce the duplicates...
        for k, p in self.__multicast_paths__.items():
            vlan_id = p.vlanid()
            mc_ip = p.mc_addr()
            sw_port_tx = p.switchport_tx()
            sw_port_rx = p.switchport_rx()

            key = f"{vlan_id}-{mc_ip}"

            mcast_entry = mcast_entries.setdefault(key, dict())
            mcast_entry.setdefault("vlan_id", vlan_id)
            mcast_entry.setdefault("mc_ip", mc_ip)

            sw_ports_tx = mcast_entry.setdefault("sw_ports_tx", [])
            sw_ports_rx = mcast_entry.setdefault("sw_ports_rx", [])

            if sw_port_tx not in sw_ports_tx:
                sw_ports_tx.append(sw_port_tx)

            if sw_port_rx not in sw_ports_rx:
                sw_ports_rx.append(sw_port_rx)

        for key in sorted(mcast_entries.keys()):
            vlan_id = mcast_entries[key]["vlan_id"]
            mc_ip = mcast_entries[key]["mc_ip"]
            for rx_port in mcast_entries[key]["sw_ports_rx"]:
                if rx_port is None:
                    print(f"DEBUG: mcast_entries: {mcast_entries}")
                    print(f"DEBUG: key: {key}")
                rx_port.require_mcast_address(vlan_id, mc_ip)

        for key in sorted(mcast_entries.keys()):
            vlan_id = mcast_entries[key]["vlan_id"]
            mc_ip = mcast_entries[key]["mc_ip"]
            for tx_port in mcast_entries[key]["sw_ports_tx"]:
                tx_port.calc_mcast_topology(vlan_id, mc_ip)

        self.__mcast_entries__ = mcast_entries

    def ecu_switch_key(self, switch):
        if switch is None:
            print(f"Warning: ecu_switch_key cannot generate key with Switch = None")
            return "None.None"

        return switch.key()

    def create_switch(self, name, ecu, ports):
        if ecu is None:
            ecu = self.__dummy_ecu__

        ret = Switch(name, ecu, ports)

        assert (self.ecu_switch_key(ret) not in self.__switches__)
        self.__switches__[self.ecu_switch_key(ret)] = ret

        return ret

    def create_switch_port(self, portid, ctrl, port, default_vlan, vlans):
        # the portid is not unique and may be reused!
        return SwitchPort(portid, ctrl, port, default_vlan, vlans)

    def create_ethernet_bus(self, name, connected_ctrls, switch_ports):
        ret = EthernetBus(name, connected_ctrls, switch_ports)
        assert (name not in self.__ethernet_busses__)
        self.__ethernet_busses__[name] = ret
        return ret

    def create_ecu(self, name, controllers):
        ret = ECU(name, controllers)
        assert (name not in self.__ecus__)
        self.__ecus__[name] = ret
        return ret

    def create_controller(self, name, interfaces):
        ret = Controller(name, interfaces)
        return ret

    def create_interface(self, name, vlanid, ips, sockets, input_frame_trigs, output_frame_trigs, fr_channel):
        ret = Interface(name, vlanid, ips, sockets, input_frame_trigs, output_frame_trigs, fr_channel)
        return ret

    def create_socket(self, name, ip, proto, portnumber, serviceinstances, serviceinstanceclients, eventhandlers,
                      eventgroupreceivers):

        ret = Socket(name, ip, proto, portnumber, serviceinstances, serviceinstanceclients, eventhandlers,
                     eventgroupreceivers)
        return ret

    def graphviz(self, filename, vlans=None, show=True, label_links=False):
        # g = Graph('G', filename=filename)
        g = Graph('G', filename=filename, engine='dot', graph_attr={'splines': 'true'})

        connections = []
        for ecu in self.__ecus__.values():
            connections += ecu.graphviz(g, vlans)

        for eth_bus in self.__ethernet_busses__.values():
            connections += eth_bus.graphviz(g, vlans)

        connections_cleaned = []
        for (a, b, v) in connections:
            if (a, b, v) not in connections_cleaned and (b, a, v) not in connections_cleaned:
                connections_cleaned += [(a, b, v)]

        for (a, b, v) in connections_cleaned:
            vlan_label = ""
            if label_links:
                if vlans is not None:
                    v = vlans
                for vlan in v:
                    if vlan_label != "":
                        vlan_label += f"{CSV_DELIM} "
                    vlan_label += f"0x{vlan:x}"
            g.edge(a, b, label=vlan_label)

        u = g.unflatten(stagger=100, fanout=True, chain=10)
        u.render()
        if show:
            # g.view()
            u.view()

    def topology_table(self):
        vlan_cols = self.get_vlan_columns()

        header = f"Type{CSV_DELIM}ECU{CSV_DELIM}Switch{CSV_DELIM}SwPort{CSV_DELIM}" \
                 f"Type{CSV_DELIM}ECU{CSV_DELIM}Switch|Ctrl{CSV_DELIM}SwPort|None"
        for vlan in sorted(vlan_cols):
            if vlan == 0:
                header += f"{CSV_DELIM}Untagged"
            else:
                vlanname = self.__vlans__[vlan].name()
                header += f"{CSV_DELIM}0x{vlan:x} {vlanname}"

        ret = [header]

        for ecu in sorted(self.__ecus__.keys()):
            ret += self.__ecus__[ecu].topology_table(vlan_cols)

        return ret

    def calc_fwd_tables(self):
        for ecuname, ecu in sorted(self.__ecus__.items()):
            ecu.calc_fwd_tables()

    def print_fwd_tables(self, fn_prefix, fn_postfix):
        for ecuname, ecu in sorted(self.__ecus__.items()):
            ecu.print_fwd_tables(fn_prefix, fn_postfix)

    def access_control_table(self, factory):
        header = f"ECU{CSV_DELIM}Switch{CSV_DELIM}SwPort{CSV_DELIM}ECU{CSV_DELIM}Ctrl{CSV_DELIM}" \
                 f"VLAN{CSV_DELIM}IP{CSV_DELIM}Netmask/Prefix"
        ret = [header]

        for ecuname, ecu in sorted(self.__ecus__.items()):
            ret += ecu.access_control_table(factory)

        return ret

    def extended_access_control_table(self, factory, skip_multicast=False, escape_for_excel=True, file_format="csv"):
        if file_format == "json":
            ret = dict()
            for ecuname, ecu in sorted(self.__ecus__.items()):
                if ecuname is None or ecuname == "":
                    continue

                ret[ecuname] = ecu.extended_access_control_table(factory,
                                                                 skip_multicast=skip_multicast,
                                                                 escape_for_excel=escape_for_excel,
                                                                 file_format="json")

            return ret

        # default = csv
        header = f"ECU{CSV_DELIM}Switch{CSV_DELIM}SwPort{CSV_DELIM}" \
                 f"ECU{CSV_DELIM}Ctrl{CSV_DELIM}VLAN{CSV_DELIM}" \
                 f"IP{CSV_DELIM}Netmask/Prefix{CSV_DELIM}MAC{CSV_DELIM}"
        ret = [header]

        for ecuname, ecu in sorted(self.__ecus__.items()):
            ret += ecu.extended_access_control_table(factory,
                                                     skip_multicast=skip_multicast,
                                                     escape_for_excel=escape_for_excel)
        return ret

    def extended_access_control_matrix(self, factory):
        multicast_cols = self.get_multicast_columns()
        header = f"ECU{CSV_DELIM}Switch{CSV_DELIM}SwPort{CSV_DELIM}VLAN"

        for mcast_addr in self.get_multicast_columns():
            header += f"{CSV_DELIM}{mcast_addr}"

        ret = [header]

        for ecuname, ecu in sorted(self.__ecus__.items()):
            ret += ecu.extended_access_control_matrix(factory)

        return ret

    def __get_someip_multicast_and_swport__(self, swport, ctrl):
        if ctrl is None or swport is None:
            return

        for iface in ctrl.interfaces():
            for socket in iface.sockets():
                if socket.proto() == "udp":
                    for si in socket.instances():
                        if si.service().serviceid() == 0xfffe:
                            print(f"WARNING: skipping 0xfffe at PSI:" f"{socket.ip()}:{socket.portnumber()} ({socket.proto()})")
                        else:
                            self.__add_service_instance_provider_socket__(si.service().serviceid(),
                                                                          si.instanceid(),
                                                                          swport.portid_full(gen_name=g_gen_portid),
                                                                          socket)
                    if socket.is_multicast():
                        for si in socket.serviceinstanceclients():
                            sid = si.service().serviceid()
                            # this can be only other serv 0xfffe
                            print(f"WARNING: skipping 0x{sid:04x} at CSI:{socket.ip()}:{socket.portnumber()} ({socket.proto()})")

                        for ceg in socket.eventgroupreceivers():
                            si = ceg.serviceinstance()
                            if si.service().serviceid() == 0xfffe:
                                print(f"WARNING: skipping 0xfffe at CEG:{socket.ip()}:{socket.portnumber()} ({socket.proto()})")
                            else:
                                # TODO
                                # this might be easier since the ceg references to the eh
                                # relation should be ceg.socket() -> ceg.sender().socket()
                                self.__add_service_instance_consumer_socket__(si.service().serviceid(),
                                                                              si.instanceid(),
                                                                              swport.portid_full(gen_name=g_gen_portid),
                                                                              socket)

    def __check_busports_someip_multicast__(self):
        for ethbus in self.__ethernet_busses__.values():
            for swport in ethbus.switch_ports():
                for ctrl in ethbus.connected_controllers():
                    self.__get_someip_multicast_and_swport__(swport, ctrl)

    def __check_swports_for_someip_multicast__(self):
        for swport in self.__switch_ports__.values():
            ctrl = swport.connected_to_ecu_ctrl()

            if ctrl is None:
                continue

            self.__get_someip_multicast_and_swport__(swport, ctrl)

    def add_multicast_someip(self, verbose=False):
        self.__check_swports_for_someip_multicast__()
        self.__check_busports_someip_multicast__()

        tmp = dict()

        if verbose:
            print(f"\nService Instance Consumer Sockets")
        for key, data in self.__service_instance_consumer_sockets__.items():
            sid_iid = f"0x{key:08x}"
            for swport, socket in data:
                if verbose:
                    print(f"C: {sid_iid}: {swport} 0x{socket.interface().vlanid():x} {socket.ip()}")
                senders = self.__service_instance_provider_sockets__.get(key)
                if senders is not None and len(senders) > 0:
                    for snd_port, snd_socket in senders:
                        if verbose:
                            print(f"  S: {snd_port} 0x{snd_socket.interface().vlanid():x} {snd_socket.ip()}")

                        swport_tx = self.__switch_ports__.get(snd_port, None)
                        swport_rx = self.__switch_ports__.get(swport, None)
                        vlanid_tx = snd_socket.interface().vlanid()
                        vlanid_rx = socket.interface().vlanid()

                        if swport_tx is None or swport_rx is None:
                            print(f"DEBUG: self.__switch_ports__: {self.__switch_ports__}")

                        assert(swport_tx is not None)
                        assert(swport_rx is not None)

                        ip_string = socket.ip()
                        comment_str = f"MC SOME/IP {sid_iid}"
                        mcpath = self.create_multicast_path(swport_tx, vlanid_tx, snd_socket.ip(),
                                                            swport_rx, vlanid_rx, ip_string, comment_str)

                        if mcpath.to_key() not in tmp.keys():
                            tmp[mcpath.to_key()] = mcpath

                        tmp[mcpath.to_key()].add_sid_iid(sid_iid)

    def all_multicast_addresses(self):
        ret = []

        for key, item in self.__multicast_paths__.items():
            mc_addr = item.mc_addr()
            if mc_addr not in ret:
                ret.append(mc_addr)

        return ret

    def create_multicast_csv(self, mc_addr=None):
        ret = []

        for key in sorted(self.__multicast_paths__.keys()):
            if mc_addr is None or self.__multicast_paths__[key].mc_addr() == mc_addr:
                ret.append(self.__multicast_paths__[key].to_csv_line())

        return ret

    def add_ipv4_address_config(self, ip, netmask):
        self.__ipv4_netmasks__[ip] = netmask

    def get_ipv4_netmask(self, ip):
        try:
            return self.__ipv4_netmasks__.get(ip)
        except ValueError:
            return None

    def add_ipv6_address_config(self, ip, prefixlen):
        tmp = ipaddress.ip_address(ip).exploded
        self.__ipv6_prefix_lengths__[tmp] = prefixlen

    def get_ipv6_prefix_length(self, ip):
        try:
            tmp = ipaddress.ip_address(ip).exploded
            return self.__ipv6_prefix_lengths__.get(tmp)
        except ValueError:
            return None

    def get_ipv4_netmask_or_ipv6_prefix_length(self, ip):
        if self.get_ipv4_netmask(ip) is not None:
            return str(self.get_ipv4_netmask(ip))

        if self.get_ipv6_prefix_length(ip) is not None:
            return str(self.get_ipv6_prefix_length(ip))

        return ""

    def parsing_done(self):
        # fill switch_ports

        for sw in self.__switches__.values():
            for port in sw.ports():
                self.__switch_ports__[port.portid_full(gen_name=g_gen_portid)] = port

    def endpoints(self):
        header = ("ECU", "Controller", "VLAN", "VLAN NAME", "IP", "Netmask/Prefix")
        ret = [header]

        for ecuname in sorted(self.__ecus__):
            ret = self.__ecus__[ecuname].export_endpoints(self, ret)

        return ret

class MulticastPath(BaseMulticastPath):
    def __init__(self, switchport_tx, vlan_tx, source_addr, switchport_rx, vlan_rx, multicast_addr, comment):
        self.__sid_iids__ = []
        super().__init__(switchport_tx, vlan_tx, source_addr, switchport_rx, vlan_rx, multicast_addr, comment)

    def add_sid_iid(self, sid_iid):
        if sid_iid not in self.__sid_iids__:
            self.__sid_iids__.append(sid_iid)

    def sid_iids_to_string(self):
        if len(self.__sid_iids__) == 0:
            return ""

        return "__".join(sorted(self.__sid_iids__))

    def to_key(self):
        ret = f"{self.switchport_tx_name()}{CSV_DELIM}{self.vlanid()}{CSV_DELIM}{self.source_addr()}{CSV_DELIM}" \
              f"{self.switchport_rx_name()}{CSV_DELIM}{self.vlanid()}{CSV_DELIM}{self.mc_addr()}{CSV_DELIM}"
        return ret

    def to_csv_line(self):
        ret = f"{self.switchport_tx_name()}{CSV_DELIM}{self.vlanid()}{CSV_DELIM}" \
              f"\"=\"\"{self.source_addr()}\"\"\"{CSV_DELIM}" \
              f"{self.switchport_rx_name()}{CSV_DELIM}{self.vlanid()}{CSV_DELIM}" \
              f"\"=\"\"{self.mc_addr()}\"\"\"{CSV_DELIM}" \
              f"{self.comment()}{self.sid_iids_to_string()}"
        return ret


class Switch(BaseSwitch):
    def __init__(self, name, ecu, ports):
        self.__fwd_table__ = {}
        self.__fwd_table_local_ready__ = False
        self.__init_count__ = 42
        super().__init__(name, ecu, ports)

    # fwd table:
    # dict: vlan -> dict:
    #           address -> dict:
    #               local -> true/false
    #               remote -> true/false (optional)
    #               sw_ports -> [sw_ports]            // these ports have that address / mc receiver
    #               sw_ports_peer -> [sw_ports] ??    // these ports communicate with that address / mc sender
    #               ctrl???

    def __add_local_fwd_entry__(self, vlan_id, address, sw_port, ecu, ctrl):
        vlan_entries = self.__fwd_table__.setdefault(vlan_id, {})
        entry = vlan_entries.setdefault(address, {})
        entry['local'] = True

        if ecu not in entry.keys() or ecu is not None:
            entry['ecu'] = ecu

        if ctrl not in entry.keys() or ctrl is not None:
            entry['ctrl'] = ctrl

        sw_ports = entry.setdefault('sw_ports', [])
        if sw_port is not None and sw_port not in sw_ports:
            sw_ports.append(sw_port)

    def __add_local_fwd_entries__(self, add_multicast):
        #if self.__fwd_table_local_ready__:
        #    print(f"WARNING: Recalculating Forwarding Table for Switch {self.name()}")

        for swport in self.ports():
            ctrls = []

            direct_ctrl = swport.connected_to_ecu_ctrl()
            eth_bus = swport.connected_to_eth_bus()

            if eth_bus is not None:
                for ctrl in eth_bus.connected_controllers():
                    ctrls.append(ctrl)
            elif direct_ctrl is not None:
                ctrls.append(direct_ctrl)

            for ctrl in ctrls:
                ctrl_name = ctrl.name()
                ecu_name = ctrl.ecu().name()
                for intf in ctrl.interfaces():
                    vlanid = intf.vlanid()

                    ips_seen = []
                    for ip in intf.ips():
                        if ip is not None and is_ip(ip):
                            if (add_multicast or not is_ip_mcast(ip)) and ip not in ips_seen:
                                self.__add_local_fwd_entry__(vlanid, ip, swport, ecu_name, ctrl_name)
                                ips_seen.append(ip)
                                if not is_ip_mcast(ip):
                                    self.__populate_other_fwd_tables_ucast__(vlanid, ip, swport, ecu_name, ctrl_name)

        self.__fwd_table_local_ready__ = True

    def incoming_fwd_info(self, vlan_id, address, sw_port, ecu, ctrl, multicast, count):
        # unicast is pushed: sw_port with address pushes it out to the rest
        # multicast is pulled: sender sw_port asks recursively, who needs and builds tree on return

        if count < 1:
            print(f"WARNING: When tracing forwarding, counter expired! Loop in Topology?")
            return

        vlan_entries = self.__fwd_table__.setdefault(vlan_id, {})
        entry = vlan_entries.setdefault(address, {})
        entry['remote'] = True
        if ecu not in entry.keys():
            entry['ecu'] = ecu
        if ctrl not in entry.keys():
            entry['ctrl'] = ctrl

        sw_ports = entry.setdefault('sw_ports', [])

        if not multicast:
            if sw_port not in sw_ports:
                sw_ports.append(sw_port)

        # forward to more switches!?
        ret = False
        for port in self.__ports__:
            if port == sw_port:
                continue

            remote_port = port.connected_to_port()
            if remote_port is not None and remote_port.switch() is not None:
                # does one of my ports already need it?
                requested = remote_port.incoming_fwd_info(vlan_id, address, ecu, ctrl, multicast, count-1)

                if requested:
                    ret = True

                    if multicast:
                        if port not in sw_ports:
                            sw_ports.append(port)

        # does one of my ports already need it?
        if len(sw_ports) > 0:
            # if the incoming port is the only one, this does not count!
            if len(sw_ports) > 1 or sw_ports[0] != sw_port:
                ret = True

        return ret

    def require_mcast_address(self, vlan_id, address, receiver_port):
        self.__add_local_fwd_entry__(vlan_id, address, receiver_port, None, None)

    def calc_mcast_topology(self, vlan_id, address, sender_port):
        ret = self.incoming_fwd_info(vlan_id, address, sender_port, None, None, True, self.__init_count__)

    def __populate_other_fwd_tables_ucast__(self, vlan_id, address, sw_port, ecu, ctrl):
        for port in self.__ports__:
            if port == sw_port:
                continue
            remote_port = port.connected_to_port()
            if remote_port is not None:
                remote_port.incoming_fwd_info(vlan_id, address, ecu, ctrl, False, self.__init_count__)

    def calc_fwd_table(self):
        self.__add_local_fwd_entries__(True)

    def print_fwd_table(self, fn_prefix, fn_postfix, ecuname):
        fn = f"{fn_prefix}{ecuname}_{self.name()}{fn_postfix}"
        with open(fn, "w") as f:
            pprint.pprint(self.__fwd_table__, stream=f)

    def extended_access_control_matrix(self, factory):
        tmp = {}
        for vlan_id, entries in self.__fwd_table__.items():
            for address, entry in entries.items():
                sw_ports = entry.get("sw_ports", [])
                ecu_name = entry.get("ecu", "unknown")
                ctrl_name = entry.get("ctrl", "unknown")
                for sw_port in sw_ports:
                    actes = AccessControlTableEntries(self.ecu().name(), self.name(),
                                                      sw_port.portid(gen_name=g_gen_portid),
                                                      ecu_name, ctrl_name, {vlan_id: [address]})

                    for i in actes.to_output_set_dict(CSV_DELIM).values():
                        ips = tmp.setdefault(i[0], [])
                        for ip in i[1]:
                            if ip not in ips:
                                ips.append(ip)

        ret = []
        for key in sorted(tmp.keys()):
            output_line = key

            for ip in factory.get_multicast_columns():
                if ip in tmp[key]:
                    output_line += f"{CSV_DELIM}{ip}"
                else:
                    output_line += f"{CSV_DELIM}"

            ret.append(output_line)

        return ret

    def extended_access_control_table(self, factory, skip_multicast=False, escape_for_excel=True, file_format="csv"):
        if file_format == "json":
            ret = dict()

            for vlan_id in sorted(self.__fwd_table__.keys()):
                for address in sorted(self.__fwd_table__[vlan_id].keys(), key=lambda x: addr_to_key(x)):
                    if skip_multicast and is_ip_mcast(address):
                        continue

                    entry = self.__fwd_table__[vlan_id][address]
                    sw_ports = entry.get("sw_ports", [])

                    for sw_port in sw_ports:
                        portid = sw_port.portid(gen_name=g_gen_portid)
                        vlan_addresses = (ret.setdefault(portid, {})).setdefault(vlan_id, [])
                        vlan_addresses.append(address)

            return ret

        # default = csv
        ret = []

        for vlan_id in sorted(self.__fwd_table__.keys()):
            for address in sorted(self.__fwd_table__[vlan_id].keys(), key=lambda x: addr_to_key(x)):

                if skip_multicast and is_ip_mcast(address):
                    continue

                entry = self.__fwd_table__[vlan_id][address]

                sw_ports = entry.get("sw_ports", [])
                ecu_name = entry.get("ecu", "unknown")
                ctrl_name = entry.get("ctrl", "unknown")
                for sw_port in sorted(sw_ports, key=lambda x: x.portid_full(gen_name=g_gen_portid)):
                    tmp = AccessControlTableEntries(self.ecu().name(), self.name(),
                                                    sw_port.portid(gen_name=g_gen_portid),
                                                    ecu_name, ctrl_name, {vlan_id: [address]})
                    for i in tmp.to_output_set(factory, escape_for_excel):
                        ret.append(CSV_DELIM.join(i))

        return ret

    def access_control_table(self, factory, escape_for_excel=True):
        ret = []

        for swport in self.ports():
            ctrls = []

            direct_ctrl = swport.connected_to_ecu_ctrl()
            eth_bus = swport.connected_to_eth_bus()

            if eth_bus is not None:
                for ctrl in eth_bus.connected_controllers():
                    ctrls.append(ctrl)
            elif direct_ctrl is not None:
                ctrls.append(direct_ctrl)

            for ctrl in ctrls:
                ips_per_vlan = dict()

                for intf in ctrl.interfaces():
                    vlanid = intf.vlanid()
                    if vlanid not in ips_per_vlan.keys():
                        ips_per_vlan[vlanid] = []
                    if len(intf.ips()) == 0:
                        ips_per_vlan[vlanid].append("None")
                    for ip in intf.ips():
                        if is_ip(ip):
                            if not is_ip_mcast(ip) and ip not in ips_per_vlan[vlanid]:
                                ips_per_vlan[vlanid].append(ip)


                tmp = AccessControlTableEntries(self.ecu().name(), self.name(),
                                                swport.portid(gen_name=g_gen_portid),
                                                ctrl.ecu().name(), ctrl.name(), ips_per_vlan)
                for entry in tmp.to_output_set(factory, escape_for_excel):
                    ret.append(CSV_DELIM.join(entry))

        return ret

    def graphviz(self, ecu, vlans):
        connections = []
        ecu.node(self.name())
        for port in self.ports():
            connections += port.graphviz(ecu, self, vlans)

        return connections

    def forward_table(self):
        return self.__fwd_table__

class SwitchPort(BaseSwitchPort):
    def incoming_fwd_info(self, vlan_id, address, ecu, ctrl, multicast, count):
        return self.switch().incoming_fwd_info(vlan_id, address, self, ecu, ctrl, multicast, count)

    def require_mcast_address(self, vlan_id, address):
        return self.switch().require_mcast_address(vlan_id, address, self)

    def calc_mcast_topology(self, vlan_id, address):
        return self.switch().calc_mcast_topology(vlan_id, address, self)

    def graphviz(self, parent, switch_or_bus, vlans):
        ret = []

        if vlans is not None:
            for vlan in vlans:
                if vlan not in self.vlans():
                    return ret

        ret += [(switch_or_bus.name(), self.portid_full(gen_name=g_gen_portid), self.vlans())]
        parent.node(self.portid_full(gen_name=g_gen_portid), label=self.portid(gen_name=g_gen_portid))
        if self.__port__ is not None and self.__port__.switch() is not None:
            ret += [(self.portid_full(gen_name=g_gen_portid),
                     self.__port__.portid_full(gen_name=g_gen_portid),
                     self.vlans())]
        elif self.__ctrl__ is not None:
            ret += [(self.portid_full(gen_name=g_gen_portid), self.__ctrl__.name(), self.vlans())]

        return ret


class EthernetBus(BaseEthernetBus):
    def graphviz(self, parent, vlans):
        ret = []

        # XXX We do not check the VLANs of the Ethernet Bus, since we cannot know if they are present everywhere!
        #     We assume that the controller and switch ports know...

        me = parent.node(self.name())

        for port in self.switch_ports():
            if vlans is None:
                ret += [(self.name(), port.portid_full(gen_name=g_gen_portid), port.vlans())]
            else:
                for vlan in vlans:
                    if vlan in port.vlans():
                        ret += [(self.name(), port.portid_full(gen_name=g_gen_portid), port.vlans())]
                        continue

        for ctrl in self.__ctrls__:
            if vlans is None:
                ret += [(self.name(), ctrl.name(), ctrl.vlans())]
            else:
                for vlan in vlans:
                    if vlan in ctrl.vlans():
                        ret += [(self.name(), ctrl.name(), ctrl.vlans())]
                        continue

        return ret


class ECU(BaseECU):
    def graphviz(self, g, vlans):
        connections = []
        with g.subgraph(name=f"cluster_{self.name()}") as c:
            c.node_attr['style'] = 'filled'
            c.attr(label=self.name())
            for ctrl in self.controllers():
                c.node(ctrl.name())
            for switch in self.switches():
                connections += switch.graphviz(c, vlans)

        return connections

    def calc_fwd_tables(self):
        for switch in self.__switches__:
            switch.calc_fwd_table()

    def print_fwd_tables(self, fn_prefix, fn_postfix):
        for switch in self.__switches__:
            switch.print_fwd_table(fn_prefix, fn_postfix, self.name())

    def topology_table(self, vlan_cols):
        ret = []

        for switch in self.__switches__:
            for swport in switch.ports():
                ctrl = swport.connected_to_ecu_ctrl()
                peerport = swport.connected_to_port()
                if ctrl is not None:
                    tmp = TopologyTableEntry(self.name(), None, switch.name(), swport.portid(gen_name=g_gen_portid),
                                             ctrl.ecu().name(), ctrl.name(), None, None,
                                             swport.vlans())
                    ret.append(CSV_DELIM.join(tmp.to_output_set(vlan_cols)))
                elif peerport is not None:
                    peerswitch = peerport.switch()
                    if peerswitch is None:
                        print(f"ERROR: topology_table: peerswitch is None for peerport "
                              f"{peerport.portid(gen_name=g_gen_portid)}")
                    elif peerswitch.ecu() is None:
                        print(f"ERROR: topology_table: peerswitch.ecu() is None for peerport "
                              f"{peerport.portid(gen_name=g_gen_portid)}")
                    else:
                        tmp = TopologyTableEntry(self.name(), None, switch.name(),
                                                 swport.portid(gen_name=g_gen_portid),
                                                 peerswitch.ecu().name(), None, peerswitch.name(),
                                                 peerport.portid(gen_name=g_gen_portid),
                                                 swport.vlans())
                        tmp2 = tmp.to_output_set(vlan_cols)

                        if tmp2 is not None:
                            ret.append(CSV_DELIM.join(tmp2))

                        # checking for asymmetry
                        if len(swport.vlans()) != len(peerport.vlans()):
                            print(f"Warning: Different number of vlans for "
                                  f"{self.name()} {switch.name()} {swport.portid(gen_name=g_gen_portid)} -> "
                                  f"{peerswitch.ecu().name()} {peerswitch.name()} "
                                  f"{peerport.portid(gen_name=g_gen_portid)}")
                        else:
                            for v in swport.vlans():
                                if v not in peerport.vlans():
                                    print(f"Warning: VLAN {v} not found in peer port "
                                          f"{self.name()} {switch.name()} {swport.portid(gen_name=g_gen_portid)}"
                                          f" -> "
                                          f"{peerswitch.ecu().name()} {peerswitch.name()} "
                                          f"{peerport.portid(gen_name=g_gen_portid)}")
                else:
                    tmp = TopologyTableEntry(self.name(), None, switch.name(),
                                             swport.portid(gen_name=g_gen_portid),
                                             "...", None, None, None,
                                             swport.vlans())
                    ret.append(CSV_DELIM.join(tmp.to_output_set(vlan_cols)))

        return ret

    def access_control_table(self, factory):
        ret = []

        for switch in self.__switches__:
            ret += switch.access_control_table(factory)

        return ret

    def extended_access_control_table(self, factory, skip_multicast=False, escape_for_excel=True, file_format="csv"):
        if file_format == "json":
            ret = {}

            switches = ret.setdefault("switches", {})
            for switch in self.__switches__:
                switches[switch.name()] = switch.extended_access_control_table(factory,
                                                                               skip_multicast=skip_multicast,
                                                                               escape_for_excel=escape_for_excel,
                                                                               file_format=file_format)

            ctrls = ret.setdefault("controllers", {})
            for ctrl in self.__controllers__:
                ctrls[ctrl.name()] = ctrl.extended_access_control_table(factory,
                                                                        skip_multicast=skip_multicast,
                                                                        escape_for_excel=escape_for_excel,
                                                                        file_format=file_format)

            return ret

        # default = csv
        ret = []

        for switch in self.__switches__:
            ret += switch.extended_access_control_table(factory,
                                                        skip_multicast=skip_multicast,
                                                        escape_for_excel=escape_for_excel)

        return ret

    def extended_access_control_matrix(self, factory):
        ret = []

        for switch in self.__switches__:
            ret += switch.extended_access_control_matrix(factory)

        return ret

    def export_endpoints(self, factory, ret):
        for controller in self.__controllers__:
            for interface in controller.interfaces():
                for ip in interface.ips():
                    if ip is not None:
                        str_ip = str(ip)
                        str_netmask_prefix = factory.get_ipv4_netmask_or_ipv6_prefix_length(ip)
                    else:
                        str_ip = "dynamic"
                        str_netmask_prefix = "dynamic"

                    ret.append((self.name(),
                                controller.name(),
                                hex(interface.vlanid()) if interface.vlanid() is not None else hex(0),
                                interface.vlanname(),
                                str_ip,
                                str_netmask_prefix))
        return ret

class Controller(BaseController):

    def extended_access_control_table(self, factory, skip_multicast=False, escape_for_excel=True, file_format="csv"):
        if file_format == "json":
            ret = {}

            for iface in self.interfaces():
                addresses = ret.setdefault(hex(iface.vlanid()), [])
                for address in sorted(iface.ips(), key=lambda x: addr_to_key(x)):
                    if skip_multicast and is_ip_mcast(address):
                        continue

                    addresses.append(address)

            return ret

        return None


class Interface(BaseInterface):
    pass


class Socket(BaseSocket):
    pass


def parse_arguments():
    parser = argparse.ArgumentParser(description='Converting configuration to topology.')
    parser.add_argument('type', choices=parser_formats, help='format')
    parser.add_argument('filename', help='filename or directory', type=lambda x: is_file_or_dir_valid(parser, x))
    parser.add_argument('--mcast-list', type=argparse.FileType('r'), default=None,
                        help='Semicolon Separated List of Static Multicast Entries')
    parser.add_argument('--generate-switch-port-names', action='store_true')
    parser.add_argument('--plugin', help='filename of parser plugin', type=lambda x: is_file_valid(parser, x),
                        default=None)

    args = parser.parse_args()
    return args


def add_multicast_file(conf_factory, f, verbose=False):
    if verbose:
        print(f"Reading multicast file...")

    csvreader = csv.reader(f, delimiter=',', quotechar='|')
    skip_first_line = True
    for row in csvreader:
        if skip_first_line:
            skip_first_line = False
            continue

        # skip empty lines
        if len(row) == 0 or row[0] == "" or row[0] == "":
            continue

        if verbose:
            print("  " + ', '.join(row))

        if len(row) < 7:
            print(f"Error: Line in Multicast File too short: {', '.join(row)}")
            continue

        swport_src, vlanid_src, addr_src, swport_dst, vlanid_dst, addr_dst, comment = row[:7]

        if swport_src not in conf_factory.__switch_ports__.keys():
            print(f"Error: {swport_src} not a valid Switchport! Expected Format: ecu_name.switch_name.port_name!")
            continue

        try:
            vlanid_src = int(vlanid_src)
        except ValueError:
            print(f"Error: {vlanid_src} not a valid VLAN ID! Expected Format: integer")
            continue

        if not is_mac(addr_src) and not is_ip(addr_src):
            print(f"Error: {addr_src} not a valid IP or MAC Address!")
            continue

        if swport_dst not in conf_factory.__switch_ports__.keys():
            print(f"Error: {swport_dst} not a valid Switchport! Expected Format: ecu_name.switch_name.port_name!")
            continue

        try:
            vlanid_dst = int(vlanid_dst)
        except ValueError:
            print(f"Error: {vlanid_dst} not a valid VLAN ID! Expected Format: integer")
            continue

        if not is_mac(addr_dst) and not is_ip(addr_dst):
            print(f"Error: {addr_dst} not a valid IP or MAC Address!")
            continue

        conf_factory.create_multicast_path(conf_factory.__switch_ports__[swport_src], vlanid_src, addr_src,
                                           conf_factory.__switch_ports__[swport_dst], vlanid_dst, addr_dst,
                                           comment)

    print()

    return


def main():
    global g_gen_portid

    remove_gv = True

    print("Converting configuration to topology")
    args = parse_arguments()

    g_gen_portid = args.generate_switch_port_names

    conf_factory = SimpleConfigurationFactory()
    output_dir = parse_input_files(args.filename, args.type, conf_factory, plugin_file=args.plugin)

    print("Making sure output directory exists...")
    if os.path.isdir(args.filename):
        target_dir = os.path.join(output_dir, "topology")
        target_dir_details = os.path.join(target_dir, "details")

        gvfile = os.path.join(target_dir, "all_files" + ".gv")
        gvfile_prefix = os.path.join(target_dir, "all_files")
        gvfile_prefix_details = os.path.join(target_dir_details, "all_files")
        fwdtableprefix = os.path.join(target_dir_details, "all_files" + "_fwd_table_")
        fwdtablepostfix = ".txt"
        topofile = os.path.join(target_dir, "all_files" + "_topology.csv")
        aclfile = os.path.join(target_dir, "all_files" + "_switch_port_addresses.csv")
        aclfile2 = os.path.join(target_dir, "all_files" + "_switch_port_addresses_ext.csv")
        aclfile2u = os.path.join(target_dir, "all_files" + "_access_control_ext.csv")
        aclfile2uj = os.path.join(target_dir, "all_files" + "_access_control_ext.json")
        aclfile3 = os.path.join(target_dir, "all_files" + "_switch_port_mcast_matrix.csv")
        mcrfile = os.path.join(target_dir, "all_files" + "_multicast_routes.csv")
        mcrfiles = os.path.join(target_dir_details, "all_files" + "_multicast_routes")
        endpfile = os.path.join(target_dir, "all_files" + "_endpoints.csv")
    elif os.path.isfile(args.filename):
        (path, f) = os.path.split(args.filename)

        if "#" in f:
            print("Warning: Removing illegal character '#' from filename...")
            f = f.replace("#", "_")

        filenoext = '.'.join(f.split('.')[:-1])
        target_dir = os.path.join(output_dir, "topology")
        target_dir_details = os.path.join(target_dir, "details")

        gvfile = os.path.join(target_dir, filenoext + ".gv")
        gvfile_prefix = os.path.join(target_dir, filenoext)
        gvfile_prefix_details = os.path.join(target_dir_details, filenoext)
        fwdtableprefix = os.path.join(target_dir_details, filenoext + "_fwd_table_")
        fwdtablepostfix = ".txt"
        topofile = os.path.join(target_dir, filenoext + "_topology.csv")
        aclfile = os.path.join(target_dir, filenoext + "_switch_port_addresses.csv")
        aclfile2 = os.path.join(target_dir, filenoext + "_switch_port_addresses_ext.csv")
        aclfile2u = os.path.join(target_dir, filenoext + "_access_control_ext.csv")
        aclfile2uj = os.path.join(target_dir, filenoext + "_access_control_ext.json")
        aclfile3 = os.path.join(target_dir, filenoext + "_switch_port_mcast_matrix.csv")
        mcrfile = os.path.join(target_dir, filenoext + "_multicast_routes.csv")
        mcrfiles = os.path.join(target_dir_details, filenoext + "_multicast_routes")
        endpfile = os.path.join(target_dir, filenoext + "_endpoints.csv")
    else:
        return

    if not os.path.exists(target_dir):
        os.makedirs(target_dir)
        time.sleep(0.5)

    if not os.path.exists(target_dir_details):
        os.makedirs(target_dir_details)
        time.sleep(0.5)

    print("Calculating unicast and multicast relations...")
    conf_factory.add_multicast_someip()

    if args.mcast_list is not None:
        add_multicast_file(conf_factory, args.mcast_list, verbose=True)

    # yes, we must call calc_fwd_tables twice or else the result is wrong (mcast with any)
    conf_factory.calc_fwd_tables()
    conf_factory.calc_mcast_topology()
    conf_factory.calc_fwd_tables()
    conf_factory.print_fwd_tables(fwdtableprefix, fwdtablepostfix)

    print("Generating outputs...")
    for vlan in sorted(conf_factory.__vlans__):
        print(f"Generating plot for VLAN {vlan}")
        fn_tmp = gvfile_prefix_details + f"__vlan_0x{vlan:x}.gv"
        conf_factory.graphviz(fn_tmp, vlans=[vlan], show=False, label_links=True)
        if remove_gv:
            os.remove(fn_tmp)

    print(f"Generating plot")
    fn_tmp = gvfile_prefix + f"__vlans_all.gv"
    conf_factory.graphviz(fn_tmp, show=False, label_links=True)
    conf_factory.graphviz(gvfile, show=False)
    if remove_gv:
        os.remove(fn_tmp)
        os.remove(gvfile)

    with open(topofile, "w") as f:
        tmp = conf_factory.topology_table()
        for i in tmp:
            f.write(f"{i}\n")

    with open(aclfile, "w") as f:
        tmp = conf_factory.access_control_table(conf_factory)
        for i in tmp:
            f.write(f"{i}\n")

    with open(aclfile2, "w") as f:
        tmp = conf_factory.extended_access_control_table(conf_factory)
        for i in tmp:
            f.write(f"{i}\n")

    with open(aclfile2u, "w") as f:
        tmp = conf_factory.extended_access_control_table(conf_factory,
                                                         skip_multicast=True,
                                                         escape_for_excel=False)
        for i in tmp:
            f.write(f"{i}\n")

    with open(aclfile2uj, "w") as f:
        tmp = conf_factory.extended_access_control_table(conf_factory,
                                                         skip_multicast=True,
                                                         escape_for_excel=False,
                                                         file_format="json")
        json.dump(tmp, f, indent=4)

    with open(aclfile3, "w") as f:
        tmp = conf_factory.extended_access_control_matrix(conf_factory)
        for i in tmp:
            f.write(f"{i}\n")

    csv_header = f"Source Switch Port{CSV_DELIM}Source VLAN{CSV_DELIM}Source IP{CSV_DELIM}Dest Switch Port{CSV_DELIM}" \
                 f"Dest VLAN{CSV_DELIM}Dest IP{CSV_DELIM}Comments\n"
    with open(mcrfile, "w") as f:
        tmp = conf_factory.create_multicast_csv()
        f.write(csv_header)
        for i in tmp:
            f.write(f"{i}\n")

    for mc_addr in sorted(conf_factory.all_multicast_addresses(), key=lambda x: addr_to_key(x)):
        file_name = f"{mcrfiles}_{mc_addr}.csv"
        with open(file_name, "w") as f:
            tmp = conf_factory.create_multicast_csv(mc_addr=mc_addr)
            f.write(csv_header)
            for i in tmp:
                f.write(f"{i}\n")

    print(f"Exporting endpoints..")
    with open(endpfile, "w") as f:
        endpoints = conf_factory.endpoints()

        for line in endpoints:
            f.write(CSV_DELIM.join(line) + "\n")

    print("Done.")


# only call main, if we are started directly
if __name__ == "__main__":
    main()
