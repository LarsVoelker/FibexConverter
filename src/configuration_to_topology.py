#!/usr/bin/python

# Automotive configuration file scripts
# Copyright (C) 2015-2026  Dr. Lars Voelker
# Copyright (C) 2018-2019  Dr. Lars Voelker, BMW AG
# Copyright (C) 2020-2026  Dr. Lars Voelker, Technica Engineering GmbH

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
import csv
import ipaddress
import json
import os.path
import pprint
import time
from typing import Any, TextIO, cast

from graphviz import Graph  # type: ignore[import-untyped]
from xlsxwriter.workbook import Workbook  # type: ignore[import-untyped]

from configuration_base_classes import (
    BaseConfigurationFactory,
    BaseController,
    BaseECU,
    BaseEthernetBus,
    BaseFrameTriggering,
    BaseInterface,
    BaseMulticastPath,
    BaseSocket,
    BaseSwitch,
    BaseSwitchPort,
    BaseVLAN,
    SOMEIPBaseServiceEventgroupReceiver,
    SOMEIPBaseServiceEventgroupSender,
    SOMEIPBaseServiceInstance,
    SOMEIPBaseServiceInstanceClient,
    addr_to_key,
    is_ip,
    is_ip_mcast,
    is_mac,
    is_mcast,
    mcast_addr_to_mac_mcast,
    read_csv_to_dict,
)
from parser_dispatcher import (
    is_file_or_dir_valid,
    is_file_valid,
    parse_input_files,
    parser_formats,
)

DUMMY_SWITCH_NAME = ""
KEY_DELIM = ","
g_gen_portid = False

FwdAddr = str | ipaddress.IPv4Address | ipaddress.IPv6Address
FwdTable = dict[int, dict[FwdAddr, dict[str, Any]]]


class TopologyTableEntry:
    # only ctrl or switch+swport can be used each (from/to)
    # vlans must be set of ints
    def __init__(
        self,
        ecu_from: str | None,
        ctrl_from: str | None,
        switch_from: str | None,
        swport_from: str | None,
        ecu_to: str | None,
        ctrl_to: str | None,
        switch_to: str | None,
        swport_to: str | None,
        vlans: set[int] | list[int],
    ) -> None:
        self._init_finished = False

        if ctrl_from is not None and (switch_from is not None or swport_from is not None):
            print(
                f"GenericTopologyTableEntry: invalid on from side! "
                f"ecu_from:{ecu_from} ctrl_from:{ctrl_from} switch_from:{switch_from} swport_from:{swport_from} ecu_to:{ecu_to}"
            )
            # raise Exception("GenericTopologyTableEntry: invalid on from side!")
            return
        if ctrl_to is not None and (switch_to is not None or swport_to is not None):
            print(
                f"GenericTopologyTableEntry: invalid on to side! "
                f"ecu_from:{ecu_from} ctrl_to:{ctrl_to} ecu_to:{ecu_to} switch_to:{switch_to} swport_to:{swport_to}"
            )
            # raise Exception("GenericTopologyTableEntry: invalid on to side!")
            return

        self._ecu_from = ecu_from
        self._ctrl_from = ctrl_from
        self._switch_from = switch_from
        self._switch_port_from = swport_from
        self._ecu_to = ecu_to
        self._ctrl_to = ctrl_to
        self._switch_to = switch_to
        self._switch_port_to = swport_to
        self._vlans = vlans

        self._init_finished = True

    def ecu_from(self) -> str | None:
        if not self._init_finished:
            print("ERROR: ecu_from: Calling uninitialized TopologyTableEntry. Input file not ok!")
            return None

        return self._ecu_from

    def ecu_to(self) -> str | None:
        if not self._init_finished:
            print("ERROR: ecu_to: Calling uninitialized TopologyTableEntry. Input file not ok!")
            return None

        return self._ecu_to

    @staticmethod
    def _to_half_output_set(
        ecu: str | None,
        ctrl: str | None,
        switch: str | None,
        swport: str | None,
    ) -> list[str]:
        if ctrl is not None:
            ret = ["Controller", ecu, ctrl, ""]
        elif switch is not None and swport is not None:
            ret = ["SwitchPort", ecu, switch, swport]
        else:
            ret = ["Etherner Bus", ecu, "", ""]
        return ret  # type: ignore[return-value]

    def to_output_set(self, vlan_columns: list[int]) -> list[str] | None:
        if not self._init_finished:
            print("ERROR: to_output_set: Calling uninitialized TopologyTableEntry. Input file not ok!")
            return None

        ret = self._to_half_output_set(
            self._ecu_from,
            self._ctrl_from,
            self._switch_from,
            self._switch_port_from,
        )

        ret += self._to_half_output_set(
            self._ecu_to,
            self._ctrl_to,
            self._switch_to,
            self._switch_port_to,
        )

        for vlan_id in vlan_columns:
            if vlan_id in self._vlans:
                if vlan_id == 0:
                    ret += ["untagged"]
                else:
                    ret += [f"0x{vlan_id:x}"]
            else:
                ret += [""]

        return ret


class AccessControlTableEntries:
    # vlans must be set of ints
    def __init__(
        self,
        ecu_from: str | None,
        switch_from: str,
        swport_from: str,
        ecu_to: str | None,
        ctrl_to: str | None,
        ips_per_vlans: dict[int, list[Any]] | None,
    ) -> None:
        self._ecu_from = ecu_from
        self._switch_from = switch_from
        self._switch_port_from = swport_from
        self._ecu_to = ecu_to
        self._ctrl_to = ctrl_to
        self._addrs_per_vlans = ips_per_vlans

    def to_output_set_dict(self, delim: str) -> dict[str, tuple[str, list[str], list[str]]]:
        ret: dict[str, tuple[str, list[str], list[str]]] = {}

        if self._addrs_per_vlans is not None:
            for vlan, addrs in self._addrs_per_vlans.items():
                if addrs is not None:
                    for addr in addrs:
                        if is_mcast(addr):
                            key = f"{self._ecu_from}{delim}{self._switch_from}{delim}{self._switch_port_from}" f"{delim}{vlan:#x}"

                            cols = [
                                self._ecu_from,
                                self._switch_from,
                                self._switch_port_from,
                                f"{vlan:#x}",
                            ]
                            tmp = ret.setdefault(key, (key, cols, []))  # type: ignore[arg-type]
                            tmp[2].append(str(addr))

        return ret

    def to_output_set(self, factory: SimpleConfigurationFactory) -> list[tuple[str, ...]]:
        ret: list[tuple[str, ...]] = []

        if self._addrs_per_vlans is not None:
            for vlan, addrs in self._addrs_per_vlans.items():
                if addrs is not None:
                    for addr in addrs:
                        mask_prefix = factory.get_ipv4_netmask_or_ipv6_prefix_length(addr)
                        ret += [
                            (
                                f"{self._ecu_from}",
                                f"{self._switch_from}",
                                f"{self._switch_port_from}",
                                f"{self._ecu_to}",
                                f"{self._ctrl_to}",
                                f"{vlan:#x}",
                                f"{addr}",
                                mask_prefix,
                                f"{mcast_addr_to_mac_mcast(addr)}",
                            )
                        ]

        return ret


class MulticastPathEntry:
    def __init__(self, sid_iid: int, tx_swport: BaseSwitchPort, tx_socket: BaseSocket, rx_swport: BaseSwitchPort, rx_socket: BaseSocket) -> None:
        tx_if = tx_socket.interface()
        rx_if = rx_socket.interface()
        assert tx_if is not None and rx_if is not None
        if tx_if.vlanid() != rx_if.vlanid():
            print(f"WARNING: RX and TX vlan differ for Service-ID/Instance-ID 0x{sid_iid:08x}! Not supported!")
            return

        self._sid_iid = sid_iid
        self._tx_swport = tx_swport
        self._tx_socket = tx_socket
        self._rx_swport = rx_swport
        self._rx_socket = rx_socket

    def to_output_set(self) -> tuple[str, str, int, str, str, int, str]:
        tx_if = self._tx_socket.interface()
        rx_if = self._rx_socket.interface()
        assert tx_if is not None and rx_if is not None
        ret = (
            f"0x{self._sid_iid:08x}",
            f"{self._tx_swport}",
            tx_if.vlanid(),
            f"{self._tx_socket.ip()}",
            f"{self._rx_swport}",
            rx_if.vlanid(),
            f"{self._rx_socket.ip()}",
        )
        return ret

    def to_csv_line(self) -> list[Any]:
        tx_if = self._tx_socket.interface()
        rx_if = self._rx_socket.interface()
        assert tx_if is not None and rx_if is not None
        ret = [
            f"{self._sid_iid:#08x}",
            self._tx_swport,
            tx_if.vlanid(),
            str(self._tx_socket.ip()),
            self._rx_swport,
            rx_if.vlanid(),
            str(self._rx_socket.ip()),
        ]

        return ret

    def to_key_string(self) -> str:
        tx_if = self._tx_socket.interface()
        rx_if = self._rx_socket.interface()
        assert tx_if is not None and rx_if is not None
        ret = (
            f"{self._tx_swport}{KEY_DELIM}"
            f"{tx_if.vlanid()}{KEY_DELIM}"
            f"{self._tx_socket.ip()}{KEY_DELIM}"
            f"{self._rx_swport}{KEY_DELIM}"
            f"{rx_if.vlanid()}{KEY_DELIM}"
            f"{self._rx_socket.ip()}"
        )
        return ret

    def sid_iid(self) -> int:
        return self._sid_iid


class SimpleConfigurationFactory(BaseConfigurationFactory):
    def __init__(self) -> None:
        self._switch_ports: dict[str, BaseSwitchPort] = dict()
        self._switches: dict[str, Switch] = dict()
        self._ethernet_busses: dict[str, EthernetBus] = dict()
        self._ecus: dict[str, ECU] = dict()
        self._vlans: dict[int, BaseVLAN] = dict()
        self._multicast_paths: dict[str, MulticastPath] = dict()
        self._mcast_entries: dict[str, dict[str, Any]] | None = None

        self._mcast_senders: dict[str, list[str]] = dict()
        self._all_mcast_sender_swports: list[str] = []

        # we need these to trace the topology (multicast) -- ONLY EGs are Multicast!!!
        # key is service-id << 16 + service-instance-id
        self._service_instance_provider_sockets: dict[int, list[tuple[str, BaseSocket]]] = dict()
        self._service_instance_consumer_sockets: dict[int, list[tuple[str, BaseSocket]]] = dict()
        self._eg_senders: list[BaseSocket] = []

        # self._pdu_relations = dict()

        # create dummy ECU for unconnected switches
        self._dummy_ecu = self.create_ecu(DUMMY_SWITCH_NAME, [])

        self._ipv4_netmasks: dict[str, str] = {}
        self._ipv6_prefix_lengths: dict[str, str] = {}

    def _add_service_instance_provider_socket(self, serviceid: int, instanceid: int, swport: str, socket: BaseSocket) -> None:
        key = (serviceid << 16) + instanceid
        if key not in self._service_instance_provider_sockets.keys():
            self._service_instance_provider_sockets[key] = []

        self._service_instance_provider_sockets[key].append((swport, socket))

    def _add_service_instance_consumer_socket(self, serviceid: int, instanceid: int, swport: str, socket: BaseSocket) -> None:
        key = (serviceid << 16) + instanceid
        if key not in self._service_instance_consumer_sockets.keys():
            self._service_instance_consumer_sockets[key] = []

        self._service_instance_consumer_sockets[key].append((swport, socket))

    def create_vlan(self, name: str, vlanid: int | None, prio: int | None) -> BaseVLAN:
        vlan = BaseVLAN(name, vlanid, prio)
        if vlanid is None:
            vlanid = 0
        # we are just overwritting
        if int(vlanid) in self._vlans.keys() and self._vlans[int(vlanid)].name() != vlan.name():
            print(f"ERROR: Name collision on VLAN ID:{vlanid} " f"Name:{self._vlans[int(vlanid)].name()} vs Name:{vlan.name()}")

        self._vlans[int(vlanid)] = vlan
        return vlan

    def get_vlan_columns(self) -> list[int]:
        return sorted(self._vlans.keys())

    def get_vlan_mapping(self) -> dict[int, str]:
        ret: dict[int, str] = {}

        for ecu in self._ecus:
            for controller in self._ecus[ecu].controllers():
                for interface in controller.interfaces():
                    ret[interface.vlanid()] = interface.vlanname()

        return ret

    def get_multicast_columns(self, sort_columns: bool = True) -> list[str]:
        if sort_columns:
            return sorted(self.all_multicast_addresses(), key=lambda x: addr_to_key(x))
        else:
            return sorted(self.all_multicast_addresses())

    def create_multicast_path(
        self,
        switchport_tx: BaseSwitchPort | None,
        vlan_tx: int,
        src_addr: str,
        switchport_rx: BaseSwitchPort | None,
        vlan_rx: int,
        mcast_addr: str,
        comment: str,
    ) -> MulticastPath:
        tmp = MulticastPath(
            switchport_tx,
            vlan_tx,
            src_addr,
            switchport_rx,
            vlan_rx,
            mcast_addr,
            comment,
        )

        if tmp.to_key() not in self._multicast_paths.keys():
            self._multicast_paths[tmp.to_key()] = tmp
        elif comment is not None and comment != "":
            self._multicast_paths[tmp.to_key()]._append_to_comment(f"; {comment}")

        switchport_vlan = f"{switchport_tx.portid_full(gen_name=g_gen_portid)}.{vlan_tx:#x}"  # type: ignore[union-attr]
        self.add_multicast_sender(mcast_addr, switchport_vlan)

        return tmp

    def add_multicast_sender(self, mcast_addr: str, switchport: str, verbose: bool = False) -> None:
        if verbose:
            print(f"DEBUG: adding mcast sender {switchport} for Address {mcast_addr}")
        senders: list[str] = self._mcast_senders.setdefault(mcast_addr, [])
        senders.append(switchport)

        if switchport not in self._all_mcast_sender_swports:
            self._all_mcast_sender_swports.append(switchport)

    def get_multicast_senders(self, mcast_addr: str, verbose: bool = False) -> list[str]:
        ret = self._mcast_senders.get(mcast_addr, [])
        if verbose:
            print(f"DEBUG: found mcast senders for {mcast_addr}: {ret}")
        return ret

    def get_all_mcast_sender_swports(self, prefix: str | None = None) -> list[str]:
        ret: list[str] = []
        for swport in self._all_mcast_sender_swports:
            if prefix is None or swport.startswith(prefix):
                ret.append(swport)

        return ret

    def calc_mcast_topology(self) -> None:
        if self._mcast_entries is not None:
            # we need to stop or the results are wrong (wrong entries in mcast matrix)
            return

        mcast_entries: dict[str, dict[str, Any]] = dict()

        # TODO: Support MAC Addresses too

        # let us make sure to reduce the duplicates...
        for k, p in self._multicast_paths.items():
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

        self._mcast_entries = mcast_entries

    def ecu_switch_key(self, switch: BaseSwitch | None) -> str:
        if switch is None:
            print("Warning: ecu_switch_key cannot generate key with Switch = None")
            return "None.None"

        return switch.key()

    def create_switch(self, name: str, ecu: BaseECU | None, ports: list[BaseSwitchPort]) -> Switch:
        if ecu is None:
            ecu = self._dummy_ecu

        ret = Switch(name, ecu, ports)

        assert self.ecu_switch_key(ret) not in self._switches
        self._switches[self.ecu_switch_key(ret)] = ret

        return ret

    def create_switch_port(
        self, portid: str, ctrl: BaseController | None, port: BaseSwitchPort | None, default_vlan: int | None, vlans: list[BaseVLAN]
    ) -> SwitchPort:
        # the portid is not unique and may be reused!
        return SwitchPort(portid, ctrl, port, default_vlan, vlans)

    def create_ethernet_bus(self, name: str, connected_ctrls: list[BaseController], switch_ports: list[BaseSwitchPort]) -> EthernetBus:
        ret = EthernetBus(name, connected_ctrls, switch_ports)
        assert name not in self._ethernet_busses
        self._ethernet_busses[name] = ret
        return ret

    def create_ecu(self, name: str, controllers: list[BaseController]) -> ECU:
        ret = ECU(name, controllers)
        assert name not in self._ecus
        self._ecus[name] = ret
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

        if ret.is_multicast() and ip not in self._mcast_senders:
            self._mcast_senders[ip] = []

        return ret

    def graphviz(self, filename: str, vlans: list[int] | None = None, show: bool = True, label_links: bool = False) -> None:
        # g = Graph('G', filename=filename)
        g = Graph("G", filename=filename, engine="dot", graph_attr={"splines": "true"})

        connections: list[tuple[str, str, list[int]]] = []
        for ecu in self._ecus.values():
            connections += ecu.graphviz(g, vlans)

        for eth_bus in self._ethernet_busses.values():
            connections += eth_bus.graphviz(g, vlans)

        connections_cleaned: list[tuple[str, str, list[int]]] = []
        for a, b, v in connections:
            if (a, b, v) not in connections_cleaned and (
                b,
                a,
                v,
            ) not in connections_cleaned:
                connections_cleaned += [(a, b, v)]

        for a, b, v in connections_cleaned:
            vlan_label = ""
            if label_links:
                if vlans is not None:
                    v = vlans
                for vlan in v:
                    if vlan_label != "":
                        vlan_label += f"{KEY_DELIM} "
                    vlan_label += f"0x{vlan:x}"
            g.edge(a, b, label=vlan_label)

        u = g.unflatten(stagger=100, fanout=True, chain=10)
        u.render()
        if show:
            # g.view()
            u.view()

    def topology_table(self) -> list[Any]:
        vlan_cols = self.get_vlan_columns()

        header = [
            "Type",
            "ECU",
            "Switch",
            "SwPort",
            "Type",
            "ECU",
            "Switch|Ctrl",
            "SwPort|None",
        ]

        for vlan in sorted(vlan_cols):
            if vlan == 0:
                header.append("Untagged")
            else:
                vlanname = self._vlans[vlan].name()
                header.append(f"{vlan:#x} {vlanname}")

        ret: list[Any] = [header]

        for ecu in sorted(self._ecus.keys()):
            ret += self._ecus[ecu].topology_table(vlan_cols)

        return ret

    def vlan_table(self) -> list[Any]:
        header = ["ECU", "Switch|Ctrl", "SwitchPort", "VLAN-ID", "Name", "DefaultPrio"]
        ret: list[Any] = [header]

        for ecu_name in sorted(self._ecus.keys()):
            ecu = self._ecus[ecu_name]

            for ctrl in sorted(ecu.controllers(), key=lambda x: x.name()):
                for iface in sorted(ctrl.interfaces(), key=lambda x: x.vlanid()):
                    ret += [
                        [
                            ecu_name,
                            ctrl.name(),
                            "",
                            f"0x{int(iface.vlanid()):x}",
                            iface.vlanname(),
                            "",
                        ]
                    ]

            for switch in ecu.switches():
                for switch_port in switch.ports():
                    port_id = switch_port.portid_generated()
                    for vlan in switch_port.vlans_objs():
                        ret += [
                            [
                                ecu_name,
                                switch.name(),
                                port_id,
                                vlan.vlanid_str(),
                                vlan.name(),
                                vlan.priority(),
                            ]
                        ]

        return ret

    def calc_fwd_tables(self) -> None:
        for ecuname, ecu in sorted(self._ecus.items()):
            ecu.calc_fwd_tables()

    def print_fwd_tables(self, fn_prefix: str, fn_postfix: str) -> None:
        for ecuname, ecu in sorted(self._ecus.items()):
            ecu.print_fwd_tables(fn_prefix, fn_postfix)

    def access_control_table(self) -> list[Any]:
        header = [
            "ECU",
            "Switch",
            "SwPort",
            "ECU",
            "Ctrl",
            "VLAN",
            "IP",
            "Netmask/Prefix",
        ]
        ret: list[Any] = [header]

        for ecuname, ecu in sorted(self._ecus.items()):
            ret += ecu.access_control_table(self)

        return ret

    def extended_access_control_table(self, skip_multicast: bool = False, file_format: str = "csv") -> list[Any]:
        if file_format == "json":
            ret_json: dict[str, Any] = dict()
            for ecuname, ecu in sorted(self._ecus.items()):
                if ecuname is None or ecuname == "":
                    continue

                ret_json[ecuname] = ecu.extended_access_control_table(self, skip_multicast=skip_multicast, file_format="json")

            return ret_json  # type: ignore[return-value]

        # default = csv
        header = [
            "ECU",
            "Switch",
            "SwPort",
            "ECU",
            "Ctrl",
            "VLAN",
            "IP",
            "Netmask/Prefix",
            "MAC",
        ]
        ret: list[Any] = [header]

        for ecuname, ecu in sorted(self._ecus.items()):
            ret += ecu.extended_access_control_table(self, skip_multicast=skip_multicast)

        return ret

    def extended_access_control_matrix(
        self, multicast_names: dict[str, str], tx_delimiter: str = ",", vlan_mapping: dict[str, str] | None = None
    ) -> list[Any]:
        header = ["ECU", "Switch", "SwPort", "VLAN"]
        vlan_pos = header.index("VLAN")

        if vlan_mapping is not None:
            header.append("VLAN Name")
            vlan_name_pos = header.index("VLAN Name")
        else:
            vlan_mapping = dict[str, str]()
            vlan_name_pos = -1

        for mcast_addr in self.get_multicast_columns():
            header.append(f"{multicast_names.get(mcast_addr, mcast_addr)}")

        ret: list[Any] = [header]

        for ecuname, ecu in sorted(self._ecus.items()):
            tmp = ecu.extended_access_control_matrix(self, tx_delimiter=tx_delimiter)

            for line in tmp:
                # adding VLAN name
                if 0 <= vlan_name_pos < len(line):
                    key = line[vlan_pos]
                    vlan_name = vlan_mapping.get(key, f"{key} ({int(key, 16)})")
                    line = line[:vlan_name_pos] + [vlan_name] + line[vlan_name_pos:]

                ret += [line]

        return ret

    def _get_someip_multicast_and_swport(self, swport: BaseSwitchPort | None, ctrl: BaseController | None) -> None:
        if ctrl is None or swport is None:
            return

        for iface in ctrl.interfaces():
            for socket in iface.sockets():
                if socket.proto() == "udp":
                    instances = socket.instances()
                    if instances is not None:
                        for si in instances:
                            if si.service().serviceid() == 0xFFFE:
                                print(f"WARNING: skipping 0xfffe at PSI:" f"{socket.ip()}:{socket.portnumber()} ({socket.proto()})")
                            else:
                                self._add_service_instance_provider_socket(
                                    si.service().serviceid(),
                                    si.instanceid(),
                                    swport.portid_full(gen_name=g_gen_portid),
                                    socket,
                                )
                    if socket.is_multicast():
                        sics = socket.serviceinstanceclients()
                        if sics is not None:
                            for sic in sics:
                                sid = sic.service().serviceid()
                                # this can be only other serv 0xfffe
                                print(f"WARNING: skipping 0x{sid:04x} at CSI:{socket.ip()}:{socket.portnumber()} ({socket.proto()})")

                        cegs = socket.eventgroupreceivers()
                        if cegs is not None:
                            for ceg in cegs:
                                si = ceg.serviceinstance()
                                if si.service().serviceid() == 0xFFFE:
                                    print(f"WARNING: skipping 0xfffe at CEG:{socket.ip()}:{socket.portnumber()} ({socket.proto()})")
                                else:
                                    # TODO
                                    # this might be easier since the ceg references to the eh
                                    # relation should be ceg.socket() -> ceg.sender().socket()
                                    self._add_service_instance_consumer_socket(
                                        si.service().serviceid(),
                                        si.instanceid(),
                                        swport.portid_full(gen_name=g_gen_portid),
                                        socket,
                                    )

    def _check_busports_someip_multicast(self) -> None:
        for ethbus in self._ethernet_busses.values():
            for swport in ethbus.switch_ports():
                for ctrl in ethbus.connected_controllers():
                    self._get_someip_multicast_and_swport(swport, ctrl)

    def _check_swports_for_someip_multicast(self) -> None:
        for swport in self._switch_ports.values():
            ctrl = swport.connected_to_ecu_ctrl()

            if ctrl is None:
                continue

            self._get_someip_multicast_and_swport(swport, ctrl)

    def add_multicast_someip(self, verbose: bool = False) -> None:
        self._check_swports_for_someip_multicast()
        self._check_busports_someip_multicast()

        tmp: dict[str, MulticastPath] = dict()

        if verbose:
            print("\nService Instance Consumer Sockets")
        for key, data in self._service_instance_consumer_sockets.items():
            sid_iid = f"0x{key:08x}"
            for swport, socket in data:
                if verbose:
                    print(f"C: {sid_iid}: {swport} 0x{socket.interface().vlanid():x} {socket.ip()}")  # type: ignore[union-attr]
                senders = self._service_instance_provider_sockets.get(key)
                if senders is not None and len(senders) > 0:
                    for snd_port, snd_socket in senders:
                        if verbose:
                            print(f"  S: {snd_port} 0x{snd_socket.interface().vlanid():x} {snd_socket.ip()}")  # type: ignore[union-attr]

                        swport_tx = self._switch_ports.get(snd_port, None)
                        swport_rx = self._switch_ports.get(swport, None)
                        vlanid_tx = snd_socket.interface().vlanid()  # type: ignore[union-attr]
                        vlanid_rx = socket.interface().vlanid()  # type: ignore[union-attr]

                        if swport_tx is None or swport_rx is None:
                            print(f"DEBUG: self._switch_ports: {self._switch_ports}")

                        assert swport_tx is not None
                        assert swport_rx is not None

                        ip_string = socket.ip()
                        comment_str = f"MC SOME/IP {sid_iid}"
                        mcpath = self.create_multicast_path(
                            swport_tx,
                            vlanid_tx,
                            snd_socket.ip(),
                            swport_rx,
                            vlanid_rx,
                            ip_string,
                            comment_str,
                        )

                        if mcpath.to_key() not in tmp.keys():
                            tmp[mcpath.to_key()] = mcpath

                        tmp[mcpath.to_key()].add_sid_iid(sid_iid)

    def all_multicast_addresses(self) -> list[str]:
        ret: list[str] = []

        for key, item in self._multicast_paths.items():
            mc_addr = item.mc_addr()
            if mc_addr not in ret:
                ret.append(mc_addr)

        # adding addresses even though we could not construct a path
        for mcast_addr in self._mcast_senders:
            if mcast_addr not in ret:
                ret.append(mcast_addr)

        return ret

    def create_multicast_csv(self, mc_addr: str | None = None) -> list[Any]:
        ret: list[Any] = []

        for key in sorted(self._multicast_paths.keys()):
            if mc_addr is None or self._multicast_paths[key].mc_addr() == mc_addr:
                ret.append(self._multicast_paths[key].to_csv_line())

        return ret

    def add_ipv4_address_config(self, ip: str, netmask: str) -> None:
        self._ipv4_netmasks[ip] = netmask

    def get_ipv4_netmask(self, ip: str | ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:  # type: ignore[override]
        try:
            return self._ipv4_netmasks.get(str(ip))
        except ValueError:
            return None

    def add_ipv6_address_config(self, ip: str, prefixlen: str) -> None:
        tmp = ipaddress.ip_address(ip).exploded
        self._ipv6_prefix_lengths[tmp] = prefixlen

    def get_ipv6_prefix_length(self, ip: str | ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:  # type: ignore[override]
        try:
            tmp = ipaddress.ip_address(ip).exploded
            return self._ipv6_prefix_lengths.get(tmp)
        except ValueError:
            return None

    def get_ipv4_netmask_or_ipv6_prefix_length(self, ip: str | ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
        if self.get_ipv4_netmask(ip) is not None:
            return str(self.get_ipv4_netmask(ip))

        if self.get_ipv6_prefix_length(ip) is not None:
            return str(self.get_ipv6_prefix_length(ip))

        return ""

    def parsing_done(self) -> None:
        # fill switch_ports

        for sw in self._switches.values():
            for port in sw.ports():
                self._switch_ports[port.portid_full(gen_name=g_gen_portid)] = port

    def endpoints(self) -> list[Any]:
        header = ("ECU", "Controller", "VLAN", "VLAN NAME", "IP", "Netmask/Prefix")
        ret: list[Any] = [header]

        for ecuname in sorted(self._ecus):
            ret = self._ecus[ecuname].export_endpoints(self, ret)

        return ret


class MulticastPath(BaseMulticastPath):
    def __init__(
        self,
        switchport_tx: BaseSwitchPort | None,
        vlanid_tx: int,
        source_addr: str,
        switchport_rx: BaseSwitchPort | None,
        vlanid_rx: int,
        multicast_addr: str,
        comment: str,
    ) -> None:
        self._sid_iids: list[str] = []
        super().__init__(
            switchport_tx,
            vlanid_tx,
            source_addr,
            switchport_rx,
            vlanid_rx,
            multicast_addr,
            comment,
        )

    def add_sid_iid(self, sid_iid: str) -> None:
        if sid_iid not in self._sid_iids:
            self._sid_iids.append(sid_iid)

    def sid_iids_to_string(self) -> str:
        if len(self._sid_iids) == 0:
            return ""

        return "__".join(sorted(self._sid_iids))

    def to_key(self) -> str:
        ret = (
            f"{self.switchport_tx_name()}{KEY_DELIM}{self.vlanid()}{KEY_DELIM}{self.source_addr()}{KEY_DELIM}"
            f"{self.switchport_rx_name()}{KEY_DELIM}{self.vlanid()}{KEY_DELIM}{self.mc_addr()}{KEY_DELIM}"
        )
        return ret

    def to_csv_line(self) -> list[str | int | None]:
        ret = [
            self.switchport_tx_name(),
            self.vlanid(),
            str(self.source_addr()),
            self.switchport_rx_name(),
            self.vlanid(),
            str(self.mc_addr()),
            f"{self.comment()}{self.sid_iids_to_string()}",
        ]

        return ret


class Switch(BaseSwitch):
    def __init__(self, name: str, ecu: BaseECU | None, ports: list[BaseSwitchPort]) -> None:
        self._fwd_table: FwdTable = {}
        self._fwd_table_local_ready = False
        self._init_count = 42
        super().__init__(name, ecu, ports)

    # fwd table:
    # dict: vlan -> dict:
    #           address -> dict:
    #               local -> true/false
    #               remote -> true/false (optional)
    #               sw_ports -> [sw_ports]            // these ports have that address / mc receiver
    #               sw_ports_peer -> [sw_ports] ??    // these ports communicate with that address / mc sender
    #               ctrl???

    def _add_local_fwd_entry(self, vlan_id: int, address: FwdAddr, sw_port: BaseSwitchPort | None, ecu: str | None, ctrl: str | None) -> None:
        vlan_entries = self._fwd_table.setdefault(vlan_id, {})
        entry = vlan_entries.setdefault(address, {})
        entry["local"] = True

        if ecu not in entry.keys() or ecu is not None:
            entry["ecu"] = ecu

        if ctrl not in entry.keys() or ctrl is not None:
            entry["ctrl"] = ctrl

        sw_ports = entry.setdefault("sw_ports", [])
        if sw_port is not None and sw_port not in sw_ports:
            sw_ports.append(sw_port)

    def _add_local_fwd_entries(self, add_multicast: bool) -> None:
        # if self._fwd_table_local_ready:
        #    print(f"WARNING: Recalculating Forwarding Table for Switch {self.name()}")

        for swport in self.ports():
            ctrls: list[BaseController] = []

            direct_ctrl = swport.connected_to_ecu_ctrl()
            eth_bus = swport.connected_to_eth_bus()

            if eth_bus is not None:
                for ctrl in eth_bus.connected_controllers():
                    ctrls.append(ctrl)
            elif direct_ctrl is not None:
                ctrls.append(direct_ctrl)

            for ctrl in ctrls:
                ctrl_name = ctrl.name()
                ecu_obj = ctrl.ecu()
                ecu_name = ecu_obj.name() if ecu_obj is not None else None
                for intf in ctrl.interfaces():
                    vlanid = intf.vlanid()

                    ips_seen: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
                    for ip in intf.ips():
                        if ip is not None and is_ip(str(ip)):
                            if (add_multicast or not is_ip_mcast(str(ip))) and ip not in ips_seen:
                                self._add_local_fwd_entry(vlanid, ip, swport, ecu_name, ctrl_name)
                                ips_seen.append(ip)
                                if not is_ip_mcast(str(ip)):
                                    self._populate_other_fwd_tables_ucast(vlanid, ip, swport, ecu_name, ctrl_name)

        self._fwd_table_local_ready = True

    def incoming_fwd_info(
        self, vlan_id: int, address: FwdAddr, sw_port: BaseSwitchPort, ecu: str | None, ctrl: str | None, multicast: bool, count: int
    ) -> bool | None:
        # unicast is pushed: sw_port with address pushes it out to the rest
        # multicast is pulled: sender sw_port asks recursively, who needs it and builds tree on return

        if count < 1:
            print("WARNING: When tracing forwarding, counter expired! Loop in Topology?")
            return None

        vlan_entries = self._fwd_table.setdefault(vlan_id, {})
        entry = vlan_entries.setdefault(address, {})
        entry["remote"] = True
        if ecu not in entry.keys():
            entry["ecu"] = ecu
        if ctrl not in entry.keys():
            entry["ctrl"] = ctrl

        sw_ports = entry.setdefault("sw_ports", [])

        if not multicast:
            if sw_port not in sw_ports:
                sw_ports.append(sw_port)

        # forward to more switches!?
        ret = False
        for port in self._ports:
            if port == sw_port:
                continue

            remote_port = port.connected_to_port()
            if remote_port is not None and remote_port.switch() is not None:
                # does one of my ports already need it?
                requested = cast("SwitchPort", remote_port).incoming_fwd_info(vlan_id, address, ecu, ctrl, multicast, count - 1)

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

    def require_mcast_address(self, vlan_id: int, address: FwdAddr, receiver_port: BaseSwitchPort) -> None:
        self._add_local_fwd_entry(vlan_id, address, receiver_port, None, None)

    def calc_mcast_topology(self, vlan_id: int, address: FwdAddr, sender_port: BaseSwitchPort) -> bool | None:
        ret = self.incoming_fwd_info(vlan_id, address, sender_port, None, None, True, self._init_count)
        return ret

    def _populate_other_fwd_tables_ucast(self, vlan_id: int, address: FwdAddr, sw_port: BaseSwitchPort, ecu: str | None, ctrl: str | None) -> None:
        for port in self._ports:
            if port == sw_port:
                continue
            remote_port = port.connected_to_port()
            if remote_port is not None:
                remote_port2 = cast("SwitchPort", remote_port)
                remote_port2.incoming_fwd_info(vlan_id, address, ecu, ctrl, False, self._init_count)

    def calc_fwd_table(self) -> None:
        self._add_local_fwd_entries(True)

    def print_fwd_table(self, fn_prefix: str, fn_postfix: str, ecuname: str) -> None:
        fn = f"{fn_prefix}{ecuname}_{self.name()}{fn_postfix}"
        with open(fn, "w") as f:
            pprint.pprint(self._fwd_table, stream=f)

    def extended_access_control_matrix(self, factory: SimpleConfigurationFactory, tx_delimiter: str) -> list[Any]:
        tmp: dict[str, tuple[list[str], list[str]]] = {}
        for vlan_id, entries in self._fwd_table.items():
            for address, row in entries.items():
                sw_ports = row.get("sw_ports", [])
                ecu_name = row.get("ecu", "unknown")
                ctrl_name = row.get("ctrl", "unknown")
                for sw_port in sw_ports:
                    actes = AccessControlTableEntries(
                        self.ecu().name(),  # type: ignore[union-attr]
                        self.name(),
                        sw_port.portid(gen_name=g_gen_portid),
                        ecu_name,
                        ctrl_name,
                        {vlan_id: [address]},
                    )

                    for i in actes.to_output_set_dict(".").values():
                        cols, ips = tmp.setdefault(i[0], (i[1], []))
                        for ip in i[2]:
                            if ip not in ips:
                                ips.append(ip)

        # Make sure sender ports exist
        for tx_swport in factory.get_all_mcast_sender_swports(prefix=self.key()):
            tmp.setdefault(tx_swport, (tx_swport.split("."), []))

        ret: list[Any] = []
        for key in sorted(tmp.keys()):
            cols, ips = tmp[key]
            output_line = cols

            for ip in factory.get_multicast_columns():
                if ip in ips:
                    entry = ip
                else:
                    entry = ""

                senders = factory.get_multicast_senders(ip)
                if f"{cols[0]}.{cols[1]}.{cols[2]}.{cols[3]}" in senders:
                    if entry != "":
                        entry += f"{tx_delimiter} "
                    entry += "TX"
                output_line.append(entry)

            ret.append(output_line)

        return ret

    def extended_access_control_table(
        self, factory: SimpleConfigurationFactory, skip_multicast: bool = False, file_format: str = "csv"
    ) -> list[Any]:
        if file_format == "json":
            ret_json: dict[str, Any] = dict()

            for vlan_id in sorted(self._fwd_table.keys()):
                for address in sorted(self._fwd_table[vlan_id].keys(), key=lambda x: addr_to_key(x)):
                    if skip_multicast and is_mcast(address):
                        continue

                    entry = self._fwd_table[vlan_id][address]
                    sw_ports = entry.get("sw_ports", [])

                    for sw_port in sw_ports:
                        portid = sw_port.portid(gen_name=g_gen_portid)
                        vlan_addresses = (ret_json.setdefault(portid, {})).setdefault(vlan_id, [])
                        vlan_addresses.append(str(address))

            return ret_json  # type: ignore[return-value]

        # default = csv
        ret: list[Any] = []

        for vlan_id in sorted(self._fwd_table.keys()):
            for address in sorted(self._fwd_table[vlan_id].keys(), key=lambda x: addr_to_key(x)):

                if skip_multicast and is_mcast(address):
                    continue

                entry = self._fwd_table[vlan_id][address]

                sw_ports = entry.get("sw_ports", [])
                ecu_name = entry.get("ecu", "unknown")
                ctrl_name = entry.get("ctrl", "unknown")
                for sw_port in sorted(sw_ports, key=lambda x: x.portid_full(gen_name=g_gen_portid)):
                    tmp = AccessControlTableEntries(
                        self.ecu().name(),  # type: ignore[union-attr]
                        self.name(),
                        sw_port.portid(gen_name=g_gen_portid),
                        ecu_name,
                        ctrl_name,
                        {vlan_id: [address]},
                    )
                    for i in tmp.to_output_set(factory):
                        ret.append(list(i))

        return ret

    def access_control_table(self, factory: SimpleConfigurationFactory) -> list[Any]:
        ret: list[Any] = []

        for swport in self.ports():
            ctrls: list[BaseController] = []

            direct_ctrl = swport.connected_to_ecu_ctrl()
            eth_bus = swport.connected_to_eth_bus()

            if eth_bus is not None:
                for ctrl in eth_bus.connected_controllers():
                    ctrls.append(ctrl)
            elif direct_ctrl is not None:
                ctrls.append(direct_ctrl)

            for ctrl in ctrls:
                ips_per_vlan: dict[int, list[Any]] = dict()

                for intf in ctrl.interfaces():
                    vlanid = intf.vlanid()
                    if vlanid not in ips_per_vlan.keys():
                        ips_per_vlan[vlanid] = []
                    if len(intf.ips()) == 0:
                        ips_per_vlan[vlanid].append("None")
                    for ip in intf.ips():
                        if is_ip(str(ip)):
                            if not is_ip_mcast(str(ip)) and ip not in ips_per_vlan[vlanid]:
                                ips_per_vlan[vlanid].append(ip)

                tmp = AccessControlTableEntries(
                    self.ecu().name(),  # type: ignore[union-attr]
                    self.name(),
                    swport.portid(gen_name=g_gen_portid),
                    ctrl.ecu().name(),  # type: ignore[union-attr]
                    ctrl.name(),
                    ips_per_vlan,
                )
                for entry in tmp.to_output_set(factory):
                    ret.append(entry)

        return ret

    def graphviz(self, ecu: Any, vlans: list[int] | None) -> list[tuple[str, str, list[int]]]:
        connections: list[tuple[str, str, list[int]]] = []
        ecu.node(self.name())
        for port in self.ports():
            connections += cast("SwitchPort", port).graphviz(ecu, self, vlans)

        return connections

    def forward_table(self) -> FwdTable:
        return self._fwd_table


class SwitchPort(BaseSwitchPort):
    def incoming_fwd_info(self, vlan_id: int, address: FwdAddr, ecu: str | None, ctrl: str | None, multicast: bool, count: int) -> bool | None:
        sw = self.switch()
        assert sw is not None
        return cast("Switch", sw).incoming_fwd_info(vlan_id, address, self, ecu, ctrl, multicast, count)

    def require_mcast_address(self, vlan_id: int, address: FwdAddr) -> None:
        sw = self.switch()
        assert sw is not None
        cast("Switch", sw).require_mcast_address(vlan_id, address, self)

    def calc_mcast_topology(self, vlan_id: int, address: FwdAddr) -> bool | None:
        sw = self.switch()
        assert sw is not None
        return cast("Switch", sw).calc_mcast_topology(vlan_id, address, self)

    def graphviz(self, parent: Any, switch_or_bus: BaseSwitch, vlans: list[int] | None) -> list[tuple[str, str, list[int]]]:
        ret: list[tuple[str, str, list[int]]] = []

        if vlans is not None:
            for vlan in vlans:
                if vlan not in self.vlans():
                    return ret

        ret += [
            (
                switch_or_bus.name(),
                self.portid_full(gen_name=g_gen_portid),
                self.vlans(),
            )
        ]
        parent.node(
            self.portid_full(gen_name=g_gen_portid),
            label=self.portid(gen_name=g_gen_portid),
        )
        if self._port is not None and self._port.switch() is not None:
            ret += [
                (
                    self.portid_full(gen_name=g_gen_portid),
                    self._port.portid_full(gen_name=g_gen_portid),
                    self.vlans(),
                )
            ]
        elif self._ctrl is not None:
            ret += [
                (
                    self.portid_full(gen_name=g_gen_portid),
                    self._ctrl.name(),
                    self.vlans(),
                )
            ]

        return ret


class EthernetBus(BaseEthernetBus):
    def graphviz(self, parent: Any, vlans: list[int] | None) -> list[tuple[str, str, list[int]]]:
        ret: list[tuple[str, str, list[int]]] = []

        # XXX We do not check the VLANs of the Ethernet Bus, since we cannot know if they are present everywhere!
        #     We assume that the controller and switch ports know...

        # me = parent.node(self.name())

        for port in self.switch_ports():
            if vlans is None:
                ret += [(self.name(), port.portid_full(gen_name=g_gen_portid), port.vlans())]
            else:
                for vlan in vlans:
                    if vlan in port.vlans():
                        ret += [
                            (
                                self.name(),
                                port.portid_full(gen_name=g_gen_portid),
                                port.vlans(),
                            )
                        ]
                        continue

        for ctrl in self._ctrls:
            if vlans is None:
                ret += [(self.name(), ctrl.name(), ctrl.vlans())]
            else:
                for vlan in vlans:
                    if vlan in ctrl.vlans():
                        ret += [(self.name(), ctrl.name(), ctrl.vlans())]
                        continue

        return ret


class ECU(BaseECU):
    def graphviz(self, g: Any, vlans: list[int] | None) -> list[tuple[str, str, list[int]]]:
        connections: list[tuple[str, str, list[int]]] = []
        with g.subgraph(name=f"cluster_{self.name()}") as c:
            c.node_attr["style"] = "filled"
            c.attr(label=self.name())
            for ctrl in self.controllers():
                c.node(ctrl.name())
            for switch in self.switches():
                connections += cast("Switch", switch).graphviz(c, vlans)

        return connections

    def calc_fwd_tables(self) -> None:
        for switch in self._switches:
            cast("Switch", switch).calc_fwd_table()

    def print_fwd_tables(self, fn_prefix: str, fn_postfix: str) -> None:
        for switch in self._switches:
            cast("Switch", switch).print_fwd_table(fn_prefix, fn_postfix, self.name())

    def topology_table(self, vlan_cols: list[int]) -> list[Any]:
        ret: list[Any] = []

        for switch in self._switches:
            switch_obj = cast("Switch", switch)
            for swport in switch_obj.ports():
                ctrl = swport.connected_to_ecu_ctrl()
                peerport = swport.connected_to_port()
                if ctrl is not None:
                    tmp = TopologyTableEntry(
                        self.name(),
                        None,
                        switch.name(),
                        swport.portid(gen_name=g_gen_portid),
                        ctrl.ecu().name(),  # type: ignore[union-attr]
                        ctrl.name(),
                        None,
                        None,
                        swport.vlans(),
                    )
                    ret.append(tmp.to_output_set(vlan_cols))
                elif peerport is not None:
                    peerswitch = peerport.switch()
                    if peerswitch is None:
                        print(f"ERROR: topology_table: peerswitch is None for peerport " f"{peerport.portid(gen_name=g_gen_portid)}")
                    elif peerswitch.ecu() is None:
                        print(f"ERROR: topology_table: peerswitch.ecu() is None for peerport " f"{peerport.portid(gen_name=g_gen_portid)}")
                    else:
                        tmp = TopologyTableEntry(
                            self.name(),
                            None,
                            switch.name(),
                            swport.portid(gen_name=g_gen_portid),
                            peerswitch.ecu().name(),  # type: ignore[union-attr]
                            None,
                            peerswitch.name(),
                            peerport.portid(gen_name=g_gen_portid),
                            swport.vlans(),
                        )
                        tmp2 = tmp.to_output_set(vlan_cols)

                        if tmp2 is not None:
                            ret.append(tmp2)

                        # checking for asymmetry
                        if len(swport.vlans()) != len(peerport.vlans()):
                            print(
                                f"Warning: Different number of vlans for "
                                f"{self.name()} {switch.name()} {swport.portid(gen_name=g_gen_portid)} -> "
                                f"{peerswitch.ecu().name()} {peerswitch.name()} "  # type: ignore[union-attr]
                                f"{peerport.portid(gen_name=g_gen_portid)}"
                            )
                        else:
                            for v in swport.vlans():
                                if v not in peerport.vlans():
                                    print(
                                        f"Warning: VLAN {v} not found in peer port "
                                        f"{self.name()} {switch.name()} {swport.portid(gen_name=g_gen_portid)}"
                                        f" -> "
                                        f"{peerswitch.ecu().name()} {peerswitch.name()} "  # type: ignore[union-attr]
                                        f"{peerport.portid(gen_name=g_gen_portid)}"
                                    )
                else:
                    tmp = TopologyTableEntry(
                        self.name(),
                        None,
                        switch.name(),
                        swport.portid(gen_name=g_gen_portid),
                        "...",
                        None,
                        None,
                        None,
                        swport.vlans(),
                    )
                    ret.append(tmp.to_output_set(vlan_cols))

        return ret

    def access_control_table(self, factory: SimpleConfigurationFactory) -> list[Any]:
        ret: list[Any] = []

        for switch in self._switches:
            ret += cast("Switch", switch).access_control_table(factory)

        return ret

    def extended_access_control_table(self, factory: SimpleConfigurationFactory, skip_multicast: bool = False, file_format: str = "csv") -> Any:
        if file_format == "json":
            ret_json: dict[str, Any] = {}

            switches = ret_json.setdefault("switches", {})
            for switch in self._switches:
                switches[switch.name()] = cast("Switch", switch).extended_access_control_table(
                    factory, skip_multicast=skip_multicast, file_format=file_format
                )

            ctrls = ret_json.setdefault("controllers", {})
            for ctrl in self._controllers:
                ctrls[ctrl.name()] = cast("Controller", ctrl).extended_access_control_table(
                    factory, skip_multicast=skip_multicast, file_format=file_format
                )

            return ret_json

        # default = csv
        ret: list[Any] = []

        for switch in self._switches:
            ret += cast("Switch", switch).extended_access_control_table(factory, skip_multicast=skip_multicast)

        return ret

    def extended_access_control_matrix(self, factory: SimpleConfigurationFactory, tx_delimiter: str = ",") -> list[Any]:
        ret: list[Any] = []

        for switch in self._switches:
            ret += cast("Switch", switch).extended_access_control_matrix(factory, tx_delimiter=tx_delimiter)

        return ret

    def export_endpoints(self, factory: SimpleConfigurationFactory, ret: list[Any]) -> list[Any]:
        for controller in sorted(self._controllers, key=lambda x: x.name()):
            for interface in sorted(controller.interfaces(), key=lambda x: x.vlanid()):
                for ip in sorted(interface.ips(), key=lambda x: str(x)):
                    if ip is not None:
                        str_ip = str(ip)
                        str_netmask_prefix = factory.get_ipv4_netmask_or_ipv6_prefix_length(ip)
                    else:
                        str_ip = "dynamic"
                        str_netmask_prefix = "dynamic"

                    ret.append(
                        (
                            self.name(),
                            controller.name(),
                            (hex(interface.vlanid()) if interface.vlanid() is not None else hex(0)),
                            interface.vlanname(),
                            str_ip,
                            str_netmask_prefix,
                        )
                    )
        return ret


class Controller(BaseController):
    def extended_access_control_table(
        self, factory: SimpleConfigurationFactory, skip_multicast: bool = False, file_format: str = "csv"
    ) -> dict[str, Any] | None:
        if file_format == "json":
            ret_json: dict[str, Any] = {}

            for iface in self.interfaces():
                addresses = ret_json.setdefault(hex(iface.vlanid()), [])
                for address in sorted(iface.ips(), key=lambda x: addr_to_key(x)):
                    if skip_multicast and is_mcast(address):
                        continue

                    addresses.append(str(address))

            return ret_json

        return None


class Interface(BaseInterface):
    pass


class Socket(BaseSocket):
    pass


def write_to_csv(filename: str, data: list[Any]) -> None:
    with open(filename, "w", newline="") as f:
        writer = csv.writer(f, delimiter=",", escapechar="\\", quoting=csv.QUOTE_NONE)
        for i in data:
            writer.writerow(i)


def write_to_xslx(filename: str, data: list[Any], metadata: dict[str, str], freeze_row: int = 1, freeze_col: int = 0) -> None:
    workbook = Workbook(filename)
    worksheet = workbook.add_worksheet()

    headerformat = workbook.add_format({"bg_color": "#0B72B5", "font_color": "white"})

    for r, row in enumerate(data):
        for c, col in enumerate(row):
            if r == 0:
                worksheet.write(r, c, col, headerformat)
            else:
                worksheet.write(r, c, col)

    if len(data) > 0:
        worksheet.autofilter(0, 0, len(data) - 1, len(data[0]) - 1)

    worksheet.autofit()
    if freeze_row != 0 or freeze_col != 0:
        worksheet.freeze_panes(freeze_row, freeze_col)

    workbook.set_properties(
        metadata
        | {
            "title": os.path.basename(filename),
            "comments": "generated by FibexConverter",
        }
    )
    workbook.close()


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Converting configuration to topology.")
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
    parser.add_argument(
        "--mcast-list",
        type=argparse.FileType("r"),
        default=None,
        help="Semicolon Separated List of Static Multicast Entries",
    )
    parser.add_argument(
        "--metadata",
        type=argparse.FileType("r"),
        default=None,
        help="Key/Value CSV file",
    )
    parser.add_argument(
        "--multicast-names",
        type=argparse.FileType("r"),
        default=None,
        help="Address/Name CSV file",
    )
    parser.add_argument("--generate-switch-port-names", action="store_true")
    parser.add_argument("--generate-vlan-names", action="store_true")
    parser.add_argument(
        "--plugin",
        help="filename of parser plugin",
        type=lambda x: is_file_valid(parser, x),
        default=None,
    )

    args = parser.parse_args()
    return args


def read_multicast_names_file(conf_factory: SimpleConfigurationFactory, f: TextIO, verbose: bool = False) -> dict[str, str]:
    if verbose:
        print("Reading multicast names file...")

    ret = read_csv_to_dict(f, verbose=verbose)

    return ret


def read_metadata_file(conf_factory: SimpleConfigurationFactory, f: TextIO, verbose: bool = False) -> dict[str, str]:
    if verbose:
        print("Reading metadata file...")

    ret = read_csv_to_dict(f, verbose=verbose)

    for key in ret.keys():
        if key not in (
            "title",
            "subject",
            "author",
            "manager",
            "company",
            "category",
            "keywords",
            "comments",
            "status",
        ):
            print(
                f"Error: key {key} not a valid key! Currently supported: "
                f"title, subject, author, manager, company, category, keywords, comments, status"
            )
            ret.pop(key, None)

    return ret


def add_multicast_file(conf_factory: SimpleConfigurationFactory, f: Any, verbose: bool = False) -> None:
    if verbose:
        print("Reading multicast file...")

    csvreader = csv.reader(f, delimiter=",", quotechar="|")
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

        if len(row) < 7:
            print(f"Error: Line in Multicast File too short: {', '.join(row)}")
            continue

        swport_src, vlanid_src_str, addr_src, swport_dst, vlanid_dst_str, addr_dst, comment = row[:7]

        if swport_src not in conf_factory._switch_ports.keys():
            print(f"Error: {swport_src} not a valid Switchport! Expected Format: ecu_name.switch_name.port_name!")
            continue

        try:
            vlanid_src = int(vlanid_src_str)
        except ValueError:
            print(f"Error: {vlanid_src_str} not a valid VLAN ID! Expected Format: integer")
            continue

        if not is_mac(addr_src) and not is_ip(addr_src):
            print(f"Error: {addr_src} not a valid IP or MAC Address!")
            continue

        if swport_dst not in conf_factory._switch_ports.keys():
            print(f"Error: {swport_dst} not a valid Switchport! Expected Format: ecu_name.switch_name.port_name!")
            continue

        try:
            vlanid_dst = int(vlanid_dst_str)
        except ValueError:
            print(f"Error: {vlanid_dst_str} not a valid VLAN ID! Expected Format: integer")
            continue

        if not is_mac(addr_dst) and not is_ip(addr_dst):
            print(f"Error: {addr_dst} not a valid IP or MAC Address!")
            continue

        conf_factory.create_multicast_path(
            conf_factory._switch_ports[swport_src],
            vlanid_src,
            addr_src,
            conf_factory._switch_ports[swport_dst],
            vlanid_dst,
            addr_dst,
            comment,
        )

    print()

    return


def main() -> None:
    global g_gen_portid

    remove_gv = True

    print("Converting configuration to topology")
    args = parse_arguments()

    g_gen_portid = args.generate_switch_port_names

    ecu_name_mapping: dict[str, str] = {}
    if args.ecu_name_mapping is not None:
        ecu_name_mapping = read_csv_to_dict(args.ecu_name_mapping)

    conf_factory = SimpleConfigurationFactory()
    output_dir = parse_input_files(
        args.filename,
        args.type,
        conf_factory,
        plugin_file=args.plugin,
        ecu_name_replacement=ecu_name_mapping,
    )

    assert output_dir is not None

    vlan_name_mapping: dict[str, str] | None = None
    if args.generate_vlan_names:
        vlan_name_mapping = {}
        vlans = conf_factory.get_vlan_mapping()
        for vlan_id, vlan_name in vlans.items():
            key = f"{vlan_id:#x}"
            vlan_name_mapping[key] = f"{vlan_name} ({vlan_id})"

    print("Making sure output directory exists...")
    if os.path.isdir(args.filename):
        target_dir = os.path.join(output_dir, "topology")
        target_dir_details = os.path.join(target_dir, "details")

        gvfile = os.path.join(target_dir, "all_files" + ".gv")
        gvfile_prefix = os.path.join(target_dir, "all_files")
        gvfile_prefix_details = os.path.join(target_dir_details, "all_files")
        fwdtableprefix = os.path.join(target_dir_details, "all_files" + "_fwd_table_")
        fwdtablepostfix = ".txt"
        topofile = os.path.join(target_dir, "all_files" + "_topology")
        swportaddr = os.path.join(target_dir, "all_files" + "_switch_port_addresses")
        swportaddrext = os.path.join(target_dir, "all_files" + "_switch_port_addresses_ext")
        aclfile2u = os.path.join(target_dir, "all_files" + "_access_control_ext")
        matrixfile = os.path.join(target_dir, "all_files" + "_switch_port_mcast_matrix")
        mcrfile = os.path.join(target_dir, "all_files" + "_multicast_routes")
        mcrfiles = os.path.join(target_dir_details, "all_files" + "_multicast_routes")
        endpfile = os.path.join(target_dir, "all_files" + "_endpoints")
        vlanfile = os.path.join(target_dir, "all_files" + "_vlans")
    elif os.path.isfile(args.filename):
        path, f = os.path.split(args.filename)

        if "#" in f:
            print("Warning: Removing illegal character '#' from filename...")
            f = f.replace("#", "_")

        filenoext = ".".join(f.split(".")[:-1])
        target_dir = os.path.join(output_dir, "topology")
        target_dir_details = os.path.join(target_dir, "details")

        gvfile = os.path.join(target_dir, filenoext + ".gv")
        gvfile_prefix = os.path.join(target_dir, filenoext)
        gvfile_prefix_details = os.path.join(target_dir_details, filenoext)
        fwdtableprefix = os.path.join(target_dir_details, filenoext + "_fwd_table_")
        fwdtablepostfix = ".txt"
        topofile = os.path.join(target_dir, filenoext + "_topology")
        swportaddr = os.path.join(target_dir, filenoext + "_switch_port_addresses")
        swportaddrext = os.path.join(target_dir, filenoext + "_switch_port_addresses_ext")
        aclfile2u = os.path.join(target_dir, filenoext + "_access_control_ext")
        matrixfile = os.path.join(target_dir, filenoext + "_switch_port_mcast_matrix")
        mcrfile = os.path.join(target_dir, filenoext + "_multicast_routes")
        mcrfiles = os.path.join(target_dir_details, filenoext + "_multicast_routes")
        endpfile = os.path.join(target_dir, filenoext + "_endpoints")
        vlanfile = os.path.join(target_dir, filenoext + "_vlans")
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

    xlsx_metadata: dict[str, str] = dict()
    if args.metadata is not None:
        xlsx_metadata = read_metadata_file(conf_factory, args.metadata, verbose=True)

    multicast_names: dict[str, str] = dict()
    if args.multicast_names is not None:
        multicast_names = read_multicast_names_file(conf_factory, args.multicast_names, verbose=True)

    # yes, we must call calc_fwd_tables twice or else the result is wrong (mcast with any)
    conf_factory.calc_fwd_tables()
    conf_factory.calc_mcast_topology()
    conf_factory.calc_fwd_tables()
    conf_factory.print_fwd_tables(fwdtableprefix, fwdtablepostfix)

    print("Generating outputs...")

    print("Generating tables...")
    write_to_csv(f"{vlanfile}.csv", conf_factory.vlan_table())
    write_to_xslx(f"{vlanfile}.xlsx", conf_factory.vlan_table(), xlsx_metadata)

    write_to_csv(f"{topofile}.csv", conf_factory.topology_table())
    write_to_xslx(f"{topofile}.xlsx", conf_factory.topology_table(), xlsx_metadata)

    write_to_csv(f"{swportaddr}.csv", conf_factory.access_control_table())
    write_to_xslx(f"{swportaddr}.xlsx", conf_factory.access_control_table(), xlsx_metadata)

    write_to_csv(f"{swportaddrext}.csv", conf_factory.extended_access_control_table())
    write_to_xslx(
        f"{swportaddrext}.xlsx",
        conf_factory.extended_access_control_table(),
        xlsx_metadata,
    )
    write_to_csv(
        f"{aclfile2u}.csv",
        conf_factory.extended_access_control_table(skip_multicast=True),
    )
    write_to_xslx(
        f"{aclfile2u}.xlsx",
        conf_factory.extended_access_control_table(skip_multicast=True),
        xlsx_metadata,
    )

    with open(f"{aclfile2u}.json", "w") as f:
        tmp = conf_factory.extended_access_control_table(skip_multicast=True, file_format="json")
        json.dump(tmp, f, indent=4, sort_keys=True)

    matrix_data = conf_factory.extended_access_control_matrix(multicast_names, tx_delimiter=";", vlan_mapping=vlan_name_mapping)
    write_to_csv(f"{matrixfile}.csv", matrix_data)

    matrix_data = conf_factory.extended_access_control_matrix(multicast_names, vlan_mapping=vlan_name_mapping)
    freeze_col = 4 if vlan_name_mapping is None else 5
    write_to_xslx(
        f"{matrixfile}.xlsx",
        matrix_data,
        xlsx_metadata,
        freeze_row=1,
        freeze_col=freeze_col,
    )

    # multicast routes
    header = [
        "Source Switch Port",
        "Source VLAN",
        "Source IP",
        "Dest Switch Port",
        "Dest VLAN",
        "Dest IP",
        "Comments",
    ]
    data: list[Any] = [header]
    data += conf_factory.create_multicast_csv()
    write_to_csv(f"{mcrfile}.csv", data)
    write_to_xslx(f"{mcrfile}.xlsx", data, xlsx_metadata)

    # multicast route files
    for mc_addr in sorted(conf_factory.all_multicast_addresses(), key=lambda x: addr_to_key(x)):
        file_name = f"{mcrfiles}_{mc_addr}"
        data = [header]
        data += conf_factory.create_multicast_csv(mc_addr=mc_addr)
        write_to_csv(f"{file_name}.csv", data)
        write_to_xslx(f"{file_name}.xlsx", data, xlsx_metadata)

    print("Exporting endpoints...")
    write_to_csv(f"{endpfile}.csv", conf_factory.endpoints())
    write_to_xslx(f"{endpfile}.xlsx", conf_factory.endpoints(), xlsx_metadata)

    for vlan in sorted(conf_factory._vlans):
        print(f"Generating plot for VLAN {vlan}")
        fn_tmp = gvfile_prefix_details + f"__vlan_0x{vlan:x}.gv"
        conf_factory.graphviz(fn_tmp, vlans=[vlan], show=False, label_links=True)
        if remove_gv:
            os.remove(fn_tmp)

    print("Generating plot for all VLANs")
    fn_tmp = gvfile_prefix + "__vlans_all.gv"
    conf_factory.graphviz(fn_tmp, show=False, label_links=True)
    conf_factory.graphviz(gvfile, show=False)
    if remove_gv:
        os.remove(fn_tmp)
        os.remove(gvfile)

    print("Done.")


# only call main, if we are started directly
if __name__ == "__main__":
    main()
