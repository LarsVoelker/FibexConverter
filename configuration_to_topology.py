#!/usr/bin/python

# Automotive configuration file scripts
# Copyright (C) 2015-2022  Dr. Lars Voelker
# Copyright (C) 2018-2019  Dr. Lars Voelker, BMW AG
# Copyright (C) 2020-2022  Dr. Lars Voelker, Technica Engineering GmbH

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
from graphviz import Graph

from parser import *  # @UnusedWildImport
from configuration_base_classes import *  # @UnusedWildImport


class TopologyTableEntry:
    # only ctrl or switch+swport can be used each (from/to)
    # vlans must be set of ints
    def __init__(self, ecu_from, ctrl_from, switch_from, swport_from, ecu_to, ctrl_to, switch_to, swport_to, vlans):
        if ctrl_from is not None and (switch_from is not None or swport_from is not None):
            print(f"GenericTopologyTableEntry: invalid on from side! "
                  f"ecu_from:{ecu_from} ecu_to: {ecu_to}")
            return
        if ctrl_to is not None and (switch_to is not None or swport_to is not None):
            print(f"GenericTopologyTableEntry: invalid on to side! "
                  f"ecu_from:{ecu_from} ecu_to: {ecu_to}")
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

    def ecu_from(self):
        return self.__ecu_from__

    def ecu_to(self):
        return self.__ecu_to__

    @staticmethod
    def __to_half_output_set__(ecu, ctrl, switch, swport):
        if ctrl is not None:
            ret = ["Controller", ecu, ctrl, ""]
        elif switch is not None and swport is not None:
            ret = ["SwitchPort", ecu, switch, swport]
        else:
            ret = ["Unknown", ecu, "", ""]
        return ret

    def to_output_set(self, vlan_columns):
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
        self.__ips_per_vlans__ = ips_per_vlans

    def to_output_set(self):
        ret = []

        if self.__ips_per_vlans__ is not None:
            for vlan, ips in self.__ips_per_vlans__.items():
                if ips is not None:
                    for ip in ips:
                        ret += [(f"{self.__ecu_from__}", f"{self.__switch_from__}", f"{self.__switch_port_from__}",
                                f"{self.__ecu_to__}", f"{self.__ctrl_to__}", f"0x{vlan:x}", f"{ip}")]

        return ret


class MulticastPathEntry:
    def __init__(self, sid_iid, tx_swport, tx_socket, rx_swport, rx_socket):
        if tx_socket.interface().vlanid() != rx_socket.interface().vlanid():
            print(f"WARNING: RX and TX vlan differ for Service-ID/Instance-ID 0x{sid_iid:08x}")
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
        ret = (f"0x{self.__sid_iid__:08x};"
               f"{self.__tx_swport__};{self.__tx_socket__.interface().vlanid()};{self.__tx_socket__.ip()};"
               f"{self.__rx_swport__};{self.__rx_socket__.interface().vlanid()};{self.__rx_socket__.ip()}")
        return ret

    def to_key_string(self):
        ret = (f"{self.__tx_swport__};{self.__tx_socket__.interface().vlanid()};{self.__tx_socket__.ip()};"
               f"{self.__rx_swport__};{self.__rx_socket__.interface().vlanid()};{self.__rx_socket__.ip()}")
        return ret

    def sid_iid(self):
        return self.__sid_iid__


class SimpleConfigurationFactory(BaseConfigurationFactory):
    def __init__(self):
        self.__switch_ports__ = dict()
        self.__switches__ = dict()
        self.__ecus__ = dict()
        self.__vlans__ = dict()
        self.__multicast_paths__ = dict()

        # we need these to trace the topology (multicast)
        # key is service-id << 16 + service-instance-id
        self.__service_instance_provider_sockets__ = dict()
        self.__service_instance_consumer_sockets__ = dict()

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

    def create_multicast_path(self, switchport_tx, vlan_tx, source_ip, switchport_rx, vlan_rx, multicast_ip, comment):
        tmp = MulticastPath(switchport_tx, vlan_tx, source_ip, switchport_rx, vlan_rx, multicast_ip, comment)
        if tmp.to_key() not in self.__multicast_paths__.keys():
            self.__multicast_paths__[tmp.to_key()] = tmp

        return tmp

    def create_switch(self, name, ecu, ports):
        ret = Switch(name, ecu, ports)
        assert (name not in self.__switches__)
        self.__switches__[name] = ret
        return ret

    def create_switch_port(self, portid, ctrl, port, default_vlan, vlans):
        ret = SwitchPort(portid, ctrl, port, default_vlan, vlans)

        if ctrl is None:
            return ret

        for iface in ctrl.interfaces():
            for socket in iface.sockets():
                if socket.proto() == "udp":
                    for si in socket.instances():
                        if si.service().serviceid() == 0xfffe:
                            print(f"skipping 0xfffe at PSI:" f"{socket.ip()}:{socket.portnumber()} ({socket.proto()})")
                        else:
                            self.__add_service_instance_provider_socket__(si.service().serviceid(),
                                                                          si.instanceid(),
                                                                          portid, socket)
                    if socket.is_multicast():
                        for si in socket.serviceinstanceclients():
                            sid = si.service().serviceid()
                            # this can be only other serv 0xfffe
                            print(f"skipping 0x{sid:04x} at CSI:{socket.ip()}:{socket.portnumber()} ({socket.proto()})")

                        for ceg in socket.eventgroupreceivers():
                            si = ceg.serviceinstance()
                            if si.service().serviceid() == 0xfffe:
                                print(f"skipping 0xfffe at CEG:{socket.ip()}:{socket.portnumber()} ({socket.proto()})")
                            else:
                                self.__add_service_instance_consumer_socket__(si.service().serviceid(),
                                                                              si.instanceid(),
                                                                              portid, socket)

        self.__switch_ports__[portid] = ret
        return ret

    def create_ecu(self, name, controllers):
        ret = ECU(name, controllers)
        assert (name not in self.__ecus__)
        self.__ecus__[name] = ret
        return ret

    def create_controller(self, name, interfaces):
        ret = Controller(name, interfaces)
        return ret

    def create_interface(self, name, vlanid, ips, sockets):
        ret = Interface(name, vlanid, ips, sockets)
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
                        vlan_label += "; "
                    vlan_label += f"0x{vlan:x}"
            g.edge(a, b, label=vlan_label)

        u = g.unflatten(stagger=100, fanout=True, chain=10)
        u.render()
        if show:
            # g.view()
            u.view()

    def topology_table(self):
        vlan_cols = self.get_vlan_columns()

        header = "Type;ECU;Switch;SwPort;Type;ECU;Switch|Ctrl;SwPort|None"
        for vlan in sorted(vlan_cols):
            if vlan == 0:
                header += ";Untagged"
            else:
                vlanname = self.__vlans__[vlan].name()
                header += f";0x{vlan:x} {vlanname}"

        ret = [header]

        for ecu in sorted(self.__ecus__.keys()):
            ret += self.__ecus__[ecu].topology_table(vlan_cols)

        return ret

    def access_control_table(self):
        header = "ECU;Switch;SwPort;ECU;Ctrl;VLAN;IP"
        ret = [header]

        for ecuname, ecu in sorted(self.__ecus__.items()):
            ret += ecu.access_control_table()

        return ret

    def trace_multicast_someip(self, verbose=False):
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

                        mcpath = self.create_multicast_path(swport_tx, vlanid_tx, snd_socket.ip(),
                                                            swport_rx, vlanid_rx, socket.ip(), "")

                        if mcpath.to_key() not in tmp.keys():
                            tmp[mcpath.to_key()] = mcpath

                        tmp[mcpath.to_key()].add_sid_iid(sid_iid)

    def create_multicast_csv(self):
        ret = []

        for key in sorted(self.__multicast_paths__.keys()):
            ret.append(self.__multicast_paths__[key].to_csv_line())

        return ret

    def trace_multicast(self, verbose=False):
        tmp = dict()

        if verbose:
            print(f"\nService Instance Consumer Sockets")
        for key, data in self.__service_instance_consumer_sockets__.items():
            for swport, socket in data:
                if verbose:
                    print(f"C: 0x{key:08x}: {swport} 0x{socket.interface().vlanid():x} {socket.ip()}")
                senders = self.__service_instance_provider_sockets__.get(key)
                if senders is not None and len(senders) > 0:
                    for snd_port, snd_socket in senders:
                        if verbose:
                            print(f"  S: {snd_port} 0x{snd_socket.interface().vlanid():x} {snd_socket.ip()}")
                        entry = MulticastPathEntry(key, snd_port, snd_socket, swport, socket)

                        if entry.to_key_string() not in tmp.keys():
                            tmp[entry.to_key_string()] = []

                        sid_iid = f"0x{entry.sid_iid():08x}"
                        if sid_iid not in tmp[entry.to_key_string()]:
                            tmp[entry.to_key_string()].append(sid_iid)

        ret = []

        for k in sorted(tmp.keys()):
            ids = "__".join(tmp[k])
            ret.append(k+";"+ids)
        return ret


class MulticastPath(BaseMulticastPath):
    def __init__(self, switchport_tx, vlan_tx, source_ip, switchport_rx, vlan_rx, multicast_ip, comment):
        self.__sid_iids__ = []
        super().__init__(switchport_tx, vlan_tx, source_ip, switchport_rx, vlan_rx, multicast_ip, comment)

    def add_sid_iid(self, sid_iid):
        if sid_iid not in self.__sid_iids__:
            self.__sid_iids__.append(sid_iid)

    def sid_iids_to_string(self):
        if len(self.__sid_iids__) == 0:
            return ""

        return "__".join(sorted(self.__sid_iids__))

    def to_key(self):
        ret = f"{self.switchport_tx()};{self.vlanid()};{self.source_ip()};" \
              f"{self.switchport_rx()};{self.vlanid()};{self.mc_ip()};"
        return ret

    def to_csv_line(self):
        ret = f"{self.switchport_tx()};{self.vlanid()};{self.source_ip()};" \
              f"{self.switchport_rx()};{self.vlanid()};{self.mc_ip()};" \
              f"{self.comment()}{self.sid_iids_to_string()}"
        return ret


class Switch(BaseSwitch):
    def graphviz(self, ecu, vlans):
        connections = []
        ecu.node(self.name())
        for port in self.ports():
            connections += port.graphviz(ecu, self, vlans)

        return connections


class SwitchPort(BaseSwitchPort):
    def portid_full(self):
        if self.switch() is not None:
            return f"{self.switch().name()}__{self.__portid__}"
        else:
            return f"__{self.__portid__}"

    def graphviz(self, parent, switch, vlans):
        ret = []

        if vlans is not None:
            for vlan in vlans:
                if vlan not in self.vlans():
                    return ret

        ret += [(switch.name(), self.portid_full(), self.vlans())]
        parent.node(self.portid_full(), label=self.__portid__)
        if self.__port__ is not None and self.__port__.switch() is not None:
            ret += [(self.portid_full(), self.__port__.portid_full(), self.vlans())]
        elif self.__ctrl__ is not None:
            ret += [(self.portid_full(), self.__ctrl__.name(), self.vlans())]

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

    def topology_table(self, vlan_cols):
        ret = []

        for switch in self.__switches__:
            for swport in switch.ports():
                ctrl = swport.connected_to_ecu_ctrl()
                peerport = swport.connected_to_port()
                if ctrl is not None:
                    tmp = TopologyTableEntry(self.name(), None, switch.name(), swport.portid(),
                                             ctrl.ecu().name(), ctrl.name(), None, None,
                                             swport.vlans())
                    ret.append(';'.join(tmp.to_output_set(vlan_cols)))
                elif peerport is not None:
                    peerswitch = peerport.switch()
                    tmp = TopologyTableEntry(self.name(), None, switch.name(), swport.portid(),
                                             peerswitch.ecu().name(), None, peerswitch.name(), peerport.portid(),
                                             swport.vlans())
                    ret.append(';'.join(tmp.to_output_set(vlan_cols)))

                    # checking for asymmetry
                    if len(swport.vlans()) != len(peerport.vlans()):
                        print(f"Warning: Different number of vlans for "
                              f"{self.name()} {switch.name()} {swport.portid()} -> "
                              f"{peerswitch.ecu().name()} {peerswitch.name()} {peerport.portid()}")
                    else:
                        for v in swport.vlans():
                            if v not in peerport.vlans():
                                print(f"Warning: VLAN {v} not found in peer port "
                                      f"{self.name()} {switch.name()} {swport.portid()} -> "
                                      f"{peerswitch.ecu().name()} {peerswitch.name()} {peerport.portid()}")

        return ret

    def access_control_table(self):
        ret = []

        for switch in self.__switches__:
            for swport in switch.ports():
                ctrl = swport.connected_to_ecu_ctrl()
                if ctrl is not None:
                    ips_per_vlan = dict()

                    for intf in ctrl.interfaces():
                        vlanid = intf.vlanid()
                        if vlanid not in ips_per_vlan.keys():
                            ips_per_vlan[vlanid] = []
                        if len(intf.ips()) == 0:
                            ips_per_vlan[vlanid].append("None")
                        for ip in intf.ips():
                            if ip is not None:
                                try:
                                    ip = ipaddress.ip_address(ip)
                                    if not ip.is_multicast and ip not in ips_per_vlan[vlanid]:
                                        ips_per_vlan[vlanid].append(ip)
                                except ValueError:
                                    pass

                    tmp = AccessControlTableEntries(self.name(), switch.name(), swport.portid(),
                                                    ctrl.ecu().name(), ctrl.name(), ips_per_vlan)
                    for entry in tmp.to_output_set():
                        ret.append(";".join(entry))

        return ret


class Controller(BaseController):
    pass


class Interface(BaseInterface):
    pass


class Socket(BaseSocket):
    pass


################################################################################
# just a simple main for testing the code of this file ...
#

def help_and_exit():
    print("illegal arguments!")
    print(f"  {sys.argv[0]} type filename")
    print(f"  example: {sys.argv[0]} FIBEX test.xml")
    sys.exit(-1)


def main():
    print("Converting configuration to topology")

    if len(sys.argv) != 3:
        help_and_exit()

    (t, filename) = sys.argv[1:]

    conf_factory = SimpleConfigurationFactory()
    output_dir = parse_input_files(filename, t, conf_factory)

    if output_dir is None:
        help_and_exit()

    print("Making sure output directory exists...")

    if os.path.isdir(filename):
        target_dir_gv = os.path.join(output_dir, "topology")
        gvfile = os.path.join(target_dir_gv, "all_files" + ".gv")
        gvfile_prefix = os.path.join(target_dir_gv, "all_files")
        topofile = os.path.join(target_dir_gv, "all_files" + "_topology.csv")
        aclfile = os.path.join(target_dir_gv, "all_files" + "_access_control.csv")
        mcrfile = os.path.join(target_dir_gv, "all_files" + "_multicast_routes.csv")
    elif os.path.isfile(filename):
        (path, f) = os.path.split(filename)
        filenoext = '.'.join(f.split('.')[:-1])
        target_dir_gv = os.path.join(output_dir, "topology")
        gvfile = os.path.join(target_dir_gv, filenoext + ".gv")
        gvfile_prefix = os.path.join(target_dir_gv, filenoext)
        topofile = os.path.join(target_dir_gv, filenoext + "_topology.csv")
        aclfile = os.path.join(target_dir_gv, filenoext + "_access_control.csv")
        mcrfile = os.path.join(target_dir_gv, filenoext + "_multicast_routes.csv")
    else:
        return

    if not os.path.exists(target_dir_gv):
        os.makedirs(target_dir_gv)
        time.sleep(0.5)

    print("Generating outputs...")
    for vlan in conf_factory.__vlans__:
        print(f"Generating plot for VLAN {vlan}")
        conf_factory.graphviz(gvfile_prefix + f"__vlan_0x{vlan:x}.gv", vlans=[vlan], show=False, label_links=True)

    print(f"Generating plot")
    conf_factory.graphviz(gvfile_prefix + f"__vlans_all.gv", show=False, label_links=True)
    conf_factory.graphviz(gvfile, show=False)

    with open(topofile, "w") as f:
        tmp = conf_factory.topology_table()
        for i in tmp:
            f.write(f"{i}\n")

    with open(aclfile, "w") as f:
        tmp = conf_factory.access_control_table()
        for i in tmp:
            f.write(f"{i}\n")

    with open(mcrfile, "w") as f:
        conf_factory.trace_multicast_someip()
        tmp = conf_factory.create_multicast_csv()
        f.write(f"Source Switch Port;Source VLAN;Source IP;Dest Switch Port;Dest VLAN;Dest IP;Comments\n")
        for i in tmp:
            f.write(f"{i}\n")

    print("Done.")


# only call main, if we are started directly
if __name__ == "__main__":
    main()
