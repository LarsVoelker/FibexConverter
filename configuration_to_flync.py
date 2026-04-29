#!/usr/bin/python

# Automotive configuration file scripts
# Copyright (C) 2015-2026  Dr. Lars Voelker
# Copyright (C) 2018-2019  Dr. Lars Voelker, BMW AG
# Copyright (C) 2020-2026  Dr. Lars Voelker, Technica Engineering GmbH
# Copyright (C) 2025-2026  Regina Leis, Technica Engineering GmbH
# Copyright (C) 2025-2026  Yav Tomar, Technica Engineering GmbH

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
import ipaddress
import os.path
import re
import time

from flync.model.flync_4_ecu import BASET1, ECU, RGMII, Controller, ECUPort, InternalTopology
from flync.model.flync_4_ecu.controller import ControllerInterface, VirtualControllerInterface
from flync.model.flync_4_ecu.internal_topology import (
    ECUPortToControllerInterface,
    ECUPortToSwitchPort,
    InternalConnectionUnion,
    SwitchPortToControllerInterface,
)
from flync.model.flync_4_ecu.socket_container import SocketContainer
from flync.model.flync_4_ecu.sockets import DeploymentUnion, IPv4AddressEndpoint, IPv6AddressEndpoint, SocketTCP, SocketUDP, TCPOption
from flync.model.flync_4_ecu.switch import Switch as FLYNCSwitch
from flync.model.flync_4_ecu.switch import SwitchPort as FLYNCSwitchPort
from flync.model.flync_4_ecu.switch import VLANEntry
from flync.model.flync_4_general_configuration import FLYNCGeneralConfig
from flync.model.flync_4_metadata import BaseVersion, ECUMetadata, EmbeddedMetadata, SOMEIPServiceMetadata, SystemMetadata
from flync.model.flync_4_someip import (
    SDConfig,
    SDTimings,
    SOMEIPConfig,
    SOMEIPEvent,
    SOMEIPEventgroup,
    SOMEIPEventTimings,
    SOMEIPField,
    SOMEIPFieldTimings,
    SOMEIPFireAndForgetMethod,
    SOMEIPMethodTimings,
    SOMEIPParameter,
    SOMEIPRequestResponseMethod,
    SOMEIPServiceConsumer,
    SOMEIPServiceInterface,
    SOMEIPServiceProvider,
    SOMEIPTimingProfile,
)

# Import FLYNC datatypes for parameter conversion
from flync.model.flync_4_someip.someip_datatypes import (
    Boolean,
    DynamicLengthString,
    Enum,
    EnumEntry,
    FixedLengthString,
    Float32,
    Float64,
    Int8,
    Int16,
    Int32,
    Int64,
    Typedef,
    UInt8,
    UInt16,
    UInt32,
    UInt64,
)
from flync.model.flync_4_topology import FLYNCTopology, SystemTopology
from flync.model.flync_4_topology.system_topology import ExternalConnection
from flync.model.flync_model import FLYNCModel
from flync.sdk.workspace.flync_workspace import FLYNCWorkspace

from configuration_base_classes import (
    BaseConfigurationFactory,
    SOMEIPBaseParameter,
    SOMEIPBaseParameterArray,
    SOMEIPBaseParameterBasetype,
    SOMEIPBaseParameterBitfield,
    SOMEIPBaseParameterEnumeration,
    SOMEIPBaseParameterString,
    SOMEIPBaseParameterStruct,
    SOMEIPBaseParameterTypedef,
    SOMEIPBaseParameterUnion,
    SOMEIPBaseService,
    read_csv_to_dict,
)
from parser_dispatcher import (
    is_file_or_dir_valid,
    is_file_valid,
    parse_input_files,
    parser_formats,
)

FLYNC_VERSION = "0.10.0"

g_gen_portid = False


class SOMEIPParameterTypedef(SOMEIPBaseParameterTypedef):
    def __init__(self, globalid, name, name2, child):
        super(SOMEIPParameterTypedef, self).__init__(name, name2, child)
        self.__globalid__ = int(globalid)

    def globalid(self):
        return self.__globalid__


class SimpleConfigurationFactory(BaseConfigurationFactory):
    def __init__(self):
        self.__param_typedefs_children = dict()
        self.__globalid_typedefs = 1

        self.__flync_model = None
        self.__flync_workspace = None

        self.__flync_ecus = list()
        self.__flync_connections = list()

        self.__base_ecus__ = {}  # ecu_name -> BaseECU
        self.__base_vlan_name_to_id__ = {}  # vlan_name -> int vlan_id
        self.__ipv4_netmasks__ = {}  # ip_str -> netmask_str
        self.__ipv6_prefix_lengths__ = {}  # exploded_ip_str -> prefixlen_str
        self.__mac_counter__ = 0

        self.__flync_someip_services = list()
        self.__flync_tcp_profile = TCPOption(tcp_profile_id=1)
        self.__flync_someip_timings = SOMEIPTimingProfile(
            profiles=[
                SOMEIPEventTimings(type="event", profile_id="event_default", debounce=5, max_retention=5),
                SOMEIPFieldTimings(type="field", profile_id="field_default", notifier_debounce=5, notifier_max_retention=5),
                SOMEIPMethodTimings(type="method", profile_id="method_default", req_debounce=5, req_max_retention=5, res_max_retention=5),
            ]
        )

        self.__flync_someipsd_addr = ipaddress.IPv4Address("224.0.0.1")
        self.__flync_someipsd_port = 30490
        self.__flync_someipsd_timings = list()

        self.__flync_someipsd_timings.append(
            SDTimings(
                profile_id="default",
                initial_delay_min=10,
                initial_delay_max=10,
                repetitions_base_delay=30,
                repetitions_max=3,
                request_response_delay_min=10,
                request_response_delay_max=10,
                offer_ttl=3,
                subscribe_ttl=3,
            )
        )

    # -------------------------------------------------------------------------
    # Overrides to track FIBEX base objects for topology generation
    # -------------------------------------------------------------------------

    def create_ecu(self, name, controllers):
        ret = super().create_ecu(name, controllers)
        self.__base_ecus__[name] = ret
        return ret

    def create_vlan(self, name, vlanid, prio):
        ret = super().create_vlan(name, vlanid, prio)
        if vlanid is not None and name:
            self.__base_vlan_name_to_id__[name] = int(vlanid)
        return ret

    def create_switch_port(self, portid, ctrl, port, default_vlan, vlans):
        ret = super().create_switch_port(portid, ctrl, port, default_vlan, vlans)
        ret._flync_default_vlan_ref = default_vlan
        return ret

    # -------------------------------------------------------------------------
    # Helpers for topology conversion
    # -------------------------------------------------------------------------

    @staticmethod
    def _safe_name(s):
        return re.sub(r"[^a-zA-Z0-9]", "_", s) if s else "unknown"

    def _get_default_vlan_id(self, base_switch_port):
        default_ref = getattr(base_switch_port, "_flync_default_vlan_ref", None)
        vlans = base_switch_port.vlans_objs()
        if default_ref:
            for vlan in vlans:
                if vlan.name() and vlan.name() in default_ref:
                    return int(vlan.vlanid()) if vlan.vlanid() is not None else 0
        ids = base_switch_port.vlans()
        return ids[0] if ids else 0

    def add_ipv4_address_config(self, ip, netmask):
        self.__ipv4_netmasks__[ip] = netmask

    def get_ipv4_netmask(self, ip):
        return self.__ipv4_netmasks__.get(str(ip), "255.255.255.0")

    def add_ipv6_address_config(self, ip, prefixlen):
        tmp = ipaddress.ip_address(ip).exploded
        self.__ipv6_prefix_lengths__[tmp] = prefixlen

    def get_ipv6_prefix_length(self, ip):
        try:
            tmp = ipaddress.ip_address(ip).exploded
            return self.__ipv6_prefix_lengths__.get(tmp)
        except ValueError:
            return None

    def _next_mac(self):
        """Generate a unique locally-administered placeholder MAC address."""
        mac_int = 0x020000000000 | (self.__mac_counter__ & 0xFFFFFFFFFF)
        self.__mac_counter__ += 1
        hex_str = f"{mac_int:012x}"
        return ":".join(hex_str[i : i + 2] for i in range(0, 12, 2))

    def _to_flync_socket(self, fibex_socket):
        """Convert a FIBEX BaseSocket to a FLYNC SocketUDP/SocketTCP, or None if not supported."""
        if fibex_socket.is_multicast():
            # Multicast sockets use IPv4 multicast addresses; only UDP is valid.
            if not fibex_socket.is_ipv4():
                print(f"WARNING: Only IPv4 multicast sockets are supported! Address: {fibex_socket.ip()}")
                return None
            ip = ipaddress.IPv4Address(fibex_socket.ip())
            deployments = []
            for client in fibex_socket.serviceinstanceclients() or []:
                svc = client.service()
                try:
                    svc_receivers = [
                        r
                        for r in (fibex_socket.eventgroupreceivers() or [])
                        if r.serviceinstance().service().serviceid() == svc.serviceid() and r.serviceinstance().instanceid() == client.instanceid()
                    ]
                    receiver_eg_ids = {r.eventgroupid() for r in svc_receivers}
                    consumed_egs = [svc.eventgroups()[egid].name() for egid in sorted(receiver_eg_ids) if egid in svc.eventgroups()]
                    dep = SOMEIPServiceConsumer(
                        deployment_type="someip_consumer",
                        service=svc.serviceid(),
                        major_version=svc.majorversion(),
                        instance_id=client.instanceid(),
                        someip_sd_timings_profile="default",
                        consumed_eventgroups=consumed_egs,
                    )
                    deployments.append(DeploymentUnion(root=dep))
                except Exception as e:
                    print(f"WARNING: Could not create SOMEIPServiceConsumer for 0x{svc.serviceid():04x}: {e}")
            sock_name = str(fibex_socket.name()) if fibex_socket.name() is not None else "None"
            return SocketUDP(
                name=sock_name,
                endpoint_address=ip,
                protocol="udp",
                port_no=fibex_socket.portnumber(),
                deployments=deployments,
            )

        if fibex_socket.is_ipv4():
            ip = ipaddress.IPv4Address(fibex_socket.ip())
        elif fibex_socket.is_ipv6():
            ip = ipaddress.IPv6Address(fibex_socket.ip())
        else:
            print(f"WARNING: Only support sockets with IPv4 or IPv6 addresses! Address: {fibex_socket.ip()}")
            return None

        proto = (fibex_socket.proto() or "udp").lower()

        deployments = []

        for instance in fibex_socket.instances() or []:
            svc = instance.service()
            try:
                svc_senders = [
                    eh
                    for eh in (fibex_socket.eventhandlers() or [])
                    if eh.serviceinstance().service().serviceid() == svc.serviceid() and eh.serviceinstance().instanceid() == instance.instanceid()
                ]
                all_eg_ids = set(svc.eventgroups().keys())
                sender_eg_ids = {s.eventgroupid() for s in svc_senders}
                if svc_senders and sender_eg_ids < all_eg_ids:
                    provided_egs = [svc.eventgroups()[egid].name() for egid in sorted(sender_eg_ids) if egid in svc.eventgroups()]
                else:
                    provided_egs = None
                dep = SOMEIPServiceProvider(
                    deployment_type="someip_provider",
                    service=svc.serviceid(),
                    major_version=svc.majorversion(),
                    minor_version=svc.minorversion(),
                    instance_id=instance.instanceid(),
                    someip_sd_timings_profile="default",
                    provided_eventgroups=provided_egs,
                )
                deployments.append(DeploymentUnion(root=dep))
            except Exception as e:
                print(f"WARNING: Could not create SOMEIPServiceProvider for 0x{svc.serviceid():04x}: {e}")

        for client in fibex_socket.serviceinstanceclients() or []:
            svc = client.service()
            try:
                svc_receivers = [
                    r
                    for r in (fibex_socket.eventgroupreceivers() or [])
                    if r.serviceinstance().service().serviceid() == svc.serviceid() and r.serviceinstance().instanceid() == client.instanceid()
                ]
                receiver_eg_ids = {r.eventgroupid() for r in svc_receivers}
                consumed_egs = [svc.eventgroups()[egid].name() for egid in sorted(receiver_eg_ids) if egid in svc.eventgroups()]
                dep = SOMEIPServiceConsumer(
                    deployment_type="someip_consumer",
                    service=svc.serviceid(),
                    major_version=svc.majorversion(),
                    instance_id=client.instanceid(),
                    someip_sd_timings_profile="default",
                    consumed_eventgroups=consumed_egs,
                )
                deployments.append(DeploymentUnion(root=dep))
            except Exception as e:
                print(f"WARNING: Could not create SOMEIPServiceConsumer for 0x{svc.serviceid():04x}: {e}")

        sock_name = str(fibex_socket.name()) if fibex_socket.name() is not None else "None"
        if proto == "tcp":
            return SocketTCP(
                name=sock_name,
                endpoint_address=ip,
                protocol="tcp",
                port_no=fibex_socket.portnumber(),
                deployments=deployments,
                tcp_profile=self.__flync_tcp_profile.tcp_profile_id,
            )
        return SocketUDP(
            name=sock_name,
            endpoint_address=ip,
            protocol="udp",
            port_no=fibex_socket.portnumber(),
            deployments=deployments,
        )

    def create_flync_ecus(self):
        """Convert FIBEX ECU/switch topology into FLYNC ECU objects."""

        # cpu_port_ctrl_name_map[(ecu_name, port_id)] = ctrl_name
        # Populated in Step 2; used in Step 3 to create SwitchPortToControllerInterface.
        cpu_port_ctrl_name_map = {}

        # ------------------------------------------------------------------
        # Step 1: Collect external connections and assign MDI roles
        # Each entry: (sw_ecu_name, sw_port_id, peer_ecu_name, peer_port_id)
        # The issue is that we do know the role and have to set something.
        # ------------------------------------------------------------------
        # role_map[(ecu_name, port_id)] = "master" | "slave"
        role_map = {}
        # ext_connections: list of (ecu1_name, port1_id, ecu2_name, port2_id)
        ext_connections = []
        seen_pairs = set()

        for ecu_name, base_ecu in sorted(self.__base_ecus__.items()):
            for base_switch in base_ecu.switches():
                for base_port in base_switch.ports():
                    peer_port = base_port.connected_to_port()
                    peer_ctrl = base_port.connected_to_ecu_ctrl()

                    if peer_port is not None:
                        # Switch-to-switch connection
                        peer_ecu = peer_port.switch().ecu()
                        if peer_ecu is None:
                            continue
                        peer_ecu_name = peer_ecu.name()
                        peer_port_id = peer_port.portid(gen_name=g_gen_portid)
                        pair = frozenset({(ecu_name, base_port.portid(gen_name=g_gen_portid)), (peer_ecu_name, peer_port_id)})
                        if pair in seen_pairs:
                            continue
                        seen_pairs.add(pair)
                        # Assign roles via heuristics: alphabetically smaller ECU name is master
                        if ecu_name <= peer_ecu_name:
                            role_map[(ecu_name, base_port.portid(gen_name=g_gen_portid))] = "master"
                            role_map[(peer_ecu_name, peer_port_id)] = "slave"
                        else:
                            role_map[(ecu_name, base_port.portid(gen_name=g_gen_portid))] = "slave"
                            role_map[(peer_ecu_name, peer_port_id)] = "master"
                        ext_connections.append((ecu_name, base_port.portid(gen_name=g_gen_portid), peer_ecu_name, peer_port_id))

                    elif peer_ctrl is not None:
                        peer_ctrl_ecu = peer_ctrl.ecu()
                        if peer_ctrl_ecu is None:
                            print(f"WARNING: Switch port {base_port.portid()} connects to None! Skipping!")
                            continue
                        if peer_ctrl_ecu.name() == ecu_name:
                            # TODO: Connection to local Controller
                            continue
                        # Switch-to-endpoint ECU
                        peer_ecu_name = peer_ctrl_ecu.name()
                        pair = frozenset({(ecu_name, base_port.portid(gen_name=g_gen_portid)), (peer_ecu_name, "_port")})
                        if pair in seen_pairs:
                            continue
                        seen_pairs.add(pair)
                        role_map[(ecu_name, base_port.portid(gen_name=g_gen_portid))] = "master"
                        role_map[(peer_ecu_name, "_port")] = "slave"
                        ext_connections.append((ecu_name, base_port.portid(gen_name=g_gen_portid), peer_ecu_name, "_port"))

        # ------------------------------------------------------------------
        # Step 2: Build FLYNC SwitchPorts, VLANEntries, and Switches per ECU
        # ------------------------------------------------------------------
        # flync_switches_per_ecu[ecu_name] = [FLYNCSwitch, ...]
        flync_switches_per_ecu = {}
        # flync_swport_name_map[(ecu_name, base_port_id)] = flync_sw_port_name
        flync_swport_name_map = {}
        # flync_ecuport_name_map[(ecu_name, base_port_id)] = flync_ecu_port_name
        flync_ecuport_name_map = {}

        for ecu_name, base_ecu in sorted(self.__base_ecus__.items()):
            flync_sw_list = []
            for base_switch in base_ecu.switches():
                sw_name = self._safe_name(base_switch.name())

                flync_sw_ports = []
                # vlan_id -> {name, priority, [port_names]}
                vlan_groups = {}

                for i, base_port in enumerate(base_switch.ports()):
                    port_id = base_port.portid(gen_name=g_gen_portid)
                    sp_name = self._safe_name(port_id)
                    flync_swport_name_map[(ecu_name, port_id)] = sp_name
                    default_vid = self._get_default_vlan_id(base_port)

                    # Identify CPU/management ports: switch port connects to the
                    # ECU's own controller (not an external ECU's controller).
                    local_ctrl = base_port.connected_to_ecu_ctrl()
                    is_cpu_port = local_ctrl is not None and local_ctrl.ecu() is not None and local_ctrl.ecu().name() == ecu_name
                    if is_cpu_port:
                        cpu_port_ctrl_name_map[(ecu_name, port_id)] = local_ctrl.name()

                    sp = FLYNCSwitchPort(
                        name=sp_name,
                        silicon_port_no=i,
                        default_vlan_id=default_vid,
                        # CPU port uses RGMII MAC-side; external ports have no MII config.
                        mii_config=RGMII(type="rgmii", mode="mac", speed=1000) if is_cpu_port else None,
                    )
                    flync_sw_ports.append(sp)

                    # Aggregate VLAN memberships
                    for vlan_obj in base_port.vlans_objs():
                        vid = int(vlan_obj.vlanid()) if vlan_obj.vlanid() is not None else 0
                        prio = int(vlan_obj.priority()) if vlan_obj.priority() is not None else 0
                        vlan_name = vlan_obj.name() or f"VLAN{vid}"
                        if vid not in vlan_groups:
                            vlan_groups[vid] = {"name": vlan_name, "priority": prio, "ports": []}
                        vlan_groups[vid]["ports"].append(sp_name)

                vlan_entries = [
                    VLANEntry(
                        name=info["name"],
                        id=vid,
                        default_priority=info["priority"],
                        ports=info["ports"],
                    )
                    for vid, info in sorted(vlan_groups.items())
                ]

                meta = self.embedded_metadata(self._safe_name(ecu_name))
                flync_switch = FLYNCSwitch(
                    name=sw_name,
                    ports=flync_sw_ports,
                    vlans=vlan_entries,
                    meta=meta,
                )
                flync_sw_list.append(flync_switch)

            flync_switches_per_ecu[ecu_name] = flync_sw_list

        # ------------------------------------------------------------------
        # Step 3: Build ECUPorts, InternalTopology, Controllers, ECUs
        #
        # Controllers are built FIRST so ControllerInterface objects are in
        # ControllerInterface.INSTANCES before SwitchPortToControllerInterface /
        # ECUPortToControllerInterface connections are validated.
        # ------------------------------------------------------------------
        int_conn_id = 0
        for ecu_name, base_ecu in sorted(self.__base_ecus__.items()):
            ecu_ports = []
            internal_connections = []
            has_switches = bool(base_ecu.switches())

            # Step 3a: Build FLYNC controllers first.
            # ctrl_iface_map[fibex_ctrl_name] = iface_name  (only for ctrlrs with interfaces)
            fibex_controllers = base_ecu.controllers()
            flync_controllers = []
            all_sockets_by_vlan = {}  # vlan_id -> [SocketUDP]
            ctrl_iface_map = {}

            # Identify which controllers own a CPU/management switch port for this ECU.
            cpu_ctrl_names = {ctrl_name for (e_name, _port_id), ctrl_name in cpu_port_ctrl_name_map.items() if e_name == ecu_name}

            for fibex_ctrl in sorted(fibex_controllers, key=lambda c: c.name()):
                ctrl_ifaces = []
                fibex_ifaces = fibex_ctrl.interfaces()

                if fibex_ifaces:
                    virt_ifaces = []
                    for fibex_iface in sorted(fibex_ifaces, key=lambda i: i.vlanid()):
                        addresses = []
                        multicast_ips = []
                        for ip_str in fibex_iface.ips():
                            try:
                                ip_obj = ipaddress.ip_address(ip_str)
                            except ValueError:
                                continue
                            if ip_obj.version == 4:
                                ip_addr = ipaddress.IPv4Address(ip_str)
                                if ip_addr.is_multicast:
                                    multicast_ips.append(ip_addr)
                                else:
                                    netmask_str = self.get_ipv4_netmask(ip_str)
                                    addresses.append(
                                        IPv4AddressEndpoint(
                                            address=ip_addr,
                                            ipv4netmask=ipaddress.IPv4Address(netmask_str),
                                        )
                                    )
                            elif ip_obj.version == 6:
                                ip_addr = ipaddress.IPv6Address(ip_str)
                                if ip_addr.is_multicast:
                                    multicast_ips.append(ip_addr)
                                else:
                                    prefix_len = self.get_ipv6_prefix_length(ip_str)
                                    addresses.append(
                                        IPv6AddressEndpoint(
                                            address=ip_addr,
                                            ipv6prefix=int(prefix_len) if prefix_len else 128,
                                        )
                                    )

                        virt_ifaces.append(
                            VirtualControllerInterface(
                                name=fibex_iface.vlanname() or f"vlan{fibex_iface.vlanid()}",
                                vlanid=fibex_iface.vlanid(),
                                addresses=addresses,
                                multicast=multicast_ips,
                            )
                        )

                        # Collect sockets grouped by VLAN ID
                        vlan_id = fibex_iface.vlanid()
                        for fibex_sock in fibex_iface.sockets():
                            flync_sock = self._to_flync_socket(fibex_sock)
                            if flync_sock is not None:
                                all_sockets_by_vlan.setdefault(vlan_id, []).append(flync_sock)

                    if virt_ifaces:
                        iface_name = f"{self._safe_name(ecu_name)}_" f"{self._safe_name(fibex_ctrl.name())}_iface"
                        ctrl_iface_map[fibex_ctrl.name()] = iface_name
                        # CPU port controller gets RGMII PHY-side MII config so the
                        # SwitchPortToControllerInterface compulsory MII check passes.
                        is_cpu_ctrl = fibex_ctrl.name() in cpu_ctrl_names
                        ctrl_ifaces.append(
                            ControllerInterface(
                                name=iface_name,
                                mac_address=self._next_mac(),
                                mii_config=RGMII(type="rgmii", mode="phy", speed=1000) if is_cpu_ctrl else None,
                                virtual_interfaces=virt_ifaces,
                            )
                        )

                # Sort controller interfaces by name for deterministic output
                ctrl_ifaces.sort(key=lambda iface: iface.name)
                flync_controllers.append(
                    Controller(
                        name=fibex_ctrl.name(),
                        interfaces=ctrl_ifaces,
                        meta=self.embedded_metadata(self._safe_name(ecu_name)),
                    )
                )

            if not flync_controllers:
                ctrl_name = f"{self._safe_name(ecu_name)}_ctrl"
                flync_controllers.append(
                    Controller(
                        name=ctrl_name,
                        interfaces=[],
                        meta=self.embedded_metadata(self._safe_name(ecu_name)),
                    )
                )

            # Step 3b: Build ECU ports and internal topology connections.
            if has_switches:
                # External switch ports → ECUPort + ECUPortToSwitchPort
                for base_switch in base_ecu.switches():
                    sw_name = self._safe_name(base_switch.name())
                    for base_port in base_switch.ports():
                        port_id = base_port.portid(gen_name=g_gen_portid)
                        role = role_map.get((ecu_name, port_id))

                        if role is not None:
                            # External switch port: physical connector + topology link
                            ep_name = f"{self._safe_name(ecu_name)}_{sw_name}_{self._safe_name(port_id)}_ep"
                            flync_ecuport_name_map[(ecu_name, port_id)] = ep_name

                            ep = ECUPort(name=ep_name, mdi_config=BASET1(mode="base_t1", role=role))
                            ecu_ports.append(ep)

                            sp_name = flync_swport_name_map[(ecu_name, port_id)]
                            conn = ECUPortToSwitchPort(
                                type="ecu_port_to_switch_port",
                                id=f"int_conn_{int_conn_id}",
                                ecu_port=ep_name,
                                switch_port=sp_name,
                            )
                            internal_connections.append(InternalConnectionUnion(root=conn))
                            int_conn_id += 1
                        else:
                            # CPU/management port → SwitchPortToControllerInterface
                            ctrl_name_for_port = cpu_port_ctrl_name_map.get((ecu_name, port_id))
                            if ctrl_name_for_port is not None:
                                iface_name = ctrl_iface_map.get(ctrl_name_for_port)
                                if iface_name is not None:
                                    sp_name = flync_swport_name_map[(ecu_name, port_id)]
                                    conn = SwitchPortToControllerInterface(
                                        type="switch_port_to_controller_interface",
                                        id=f"int_conn_{int_conn_id}",
                                        switch_port=sp_name,
                                        controller_interface=iface_name,
                                    )
                                    internal_connections.append(InternalConnectionUnion(root=conn))
                                    int_conn_id += 1

                # Corner case "incoherent modeling":
                # A switch ECU's controller may also connect directly to another ECU's switch
                # (i.e. the ECU appears as an endpoint from the other ECU's perspective).
                # Create the endpoint ECUPort for that connection if needed.
                endpoint_role = role_map.get((ecu_name, "_port"))
                if endpoint_role is not None:
                    ep_name = f"{self._safe_name(ecu_name)}_port"
                    ep = ECUPort(name=ep_name, mdi_config=BASET1(mode="base_t1", role=endpoint_role))
                    ecu_ports.append(ep)
            else:
                # Endpoint ECU: one ECUPort + ECUPortToControllerInterface per interface
                role = role_map.get((ecu_name, "_port"), "slave")
                ep_name = f"{self._safe_name(ecu_name)}_port"
                ep = ECUPort(name=ep_name, mdi_config=BASET1(mode="base_t1", role=role))
                ecu_ports.append(ep)

                for iface_name in ctrl_iface_map.values():
                    conn = ECUPortToControllerInterface(
                        type="ecu_port_to_controller_interface",
                        id=f"int_conn_{int_conn_id}",
                        ecu_port=ep_name,
                        controller_interface=iface_name,
                    )
                    internal_connections.append(InternalConnectionUnion(root=conn))
                    int_conn_id += 1

            if not ecu_ports:
                # ECU has no external connections (e.g. isolated or management-only)
                # Still need at least one port for FLYNC ECU validity
                ep_name = f"{self._safe_name(ecu_name)}_port"
                ecu_ports.append(ECUPort(name=ep_name, mdi_config=BASET1(mode="base_t1", role="slave")))

            # Sort each socket list by name for deterministic output
            for vlan_id in all_sockets_by_vlan:
                all_sockets_by_vlan[vlan_id].sort(key=lambda s: s.name)
            # Create SocketContainers sorted by vlan_id
            socket_containers = [
                SocketContainer(
                    name=f"{self._safe_name(ecu_name)}_vlan{vlan_id if vlan_id is not None else 0}",
                    vlan_id=vlan_id,
                    sockets=sockets_list,
                )
                for vlan_id, sockets_list in sorted(
                    all_sockets_by_vlan.items(),
                    key=lambda item: item[0] if item[0] is not None else -1,
                )
            ]

            topology = InternalTopology(connections=internal_connections)
            flync_ecu = ECU(
                name=ecu_name,
                ports=ecu_ports,
                controllers=flync_controllers,
                switches=flync_switches_per_ecu.get(ecu_name, []),
                topology=topology,
                ecu_metadata=self.ecu_metadata(),
                sockets=socket_containers,
            )
            self.__flync_ecus.append(flync_ecu)

        # ------------------------------------------------------------------
        # Step 4: ExternalConnections (after all ECUPorts are in INSTANCES)
        # ------------------------------------------------------------------
        for i, (ecu1_name, port1_id, ecu2_name, port2_id) in enumerate(ext_connections):
            if port1_id == "_port":
                ep1_name = f"{self._safe_name(ecu1_name)}_port"
            else:
                ep1_name = flync_ecuport_name_map.get((ecu1_name, port1_id), f"{self._safe_name(ecu1_name)}_{self._safe_name(port1_id)}_ep")
            if port2_id == "_port":
                ep2_name = f"{self._safe_name(ecu2_name)}_port"
            else:
                ep2_name = flync_ecuport_name_map.get((ecu2_name, port2_id), f"{self._safe_name(ecu2_name)}_{self._safe_name(port2_id)}_ep")

            conn = ExternalConnection(
                id=f"ext_conn_{i}",
                ecu1_port=ep1_name,
                ecu2_port=ep2_name,
            )
            self.__flync_connections.append(conn)

    # Helper function to convert internal parameter type to FLYNC type
    def to_flync_base_datatype(self, datatype, name):
        dt = datatype.datatype()

        if datatype.bitlength_basetype() != datatype.bitlength_encoded_type():
            print(f"WARNING: Not supporting shortened datatypes! {name=}")

        endian = "BE" if datatype.bigendian() else "LE"

        match dt:
            case "A_UINT8":
                # Unfortunately, FIBEX does not model BOOLEAN so we need a heuristic
                if datatype.name().upper() in ("BOOLEAN", "BOOL"):
                    return Boolean(name=datatype.name(), type="boolean")
                return UInt8(name=datatype.name(), type="uint8", endianness="BE", signed=False, bit_size=8)
            case "A_UINT16":
                return UInt16(name=datatype.name(), type="uint16", endianness=endian, signed=False, bit_size=16)
            case "A_UINT32":
                return UInt32(name=datatype.name(), type="uint32", endianness=endian, signed=False, bit_size=32)
            case "A_UINT64":
                return UInt64(name=datatype.name(), type="uint64", endianness=endian, signed=False, bit_size=64)
            case "A_INT8":
                return Int8(name=datatype.name(), type="int8", endianness="BE", signed=True, bit_size=8)
            case "A_INT16":
                return Int16(name=datatype.name(), type="int16", endianness=endian, signed=True, bit_size=16)
            case "A_INT32":
                return Int32(name=datatype.name(), type="int32", endianness=endian, signed=True, bit_size=32)
            case "A_INT64":
                return Int64(name=datatype.name(), type="int64", endianness=endian, signed=True, bit_size=64)
            case "A_FLOAT32":
                return Float32(name=datatype.name(), type="float32", endianness=endian, signed=True, bit_size=32)
            case "A_FLOAT64":
                return Float64(name=datatype.name(), type="float64", endianness=endian, signed=True, bit_size=64)

        print(f"WARNING: Unsupported Base Datatype {dt=}")
        return None

    def to_flync_parameter(self, param, name_override=None):
        if isinstance(param, SOMEIPParameterTypedef):
            tmp = self.__param_typedefs_children.setdefault(param.globalid(), self.to_flync_parameter(param.child()))
            effective_name = name_override if name_override is not None else param.name()
            return SOMEIPParameter(name=effective_name, datatype=Typedef(name=param.name(), type="typedef", datatyperef=tmp.datatype))

        if isinstance(param, SOMEIPBaseParameter):
            datatype = param.datatype()
            description = param.desc() or ""
        else:
            datatype = param
            description = ""

        name = name_override if name_override is not None else param.name()

        if isinstance(datatype, SOMEIPBaseParameterTypedef):
            child = datatype.child()
            tmp = self.to_flync_parameter(child)
            if tmp is None:
                return None
            # TODO: This should be a ref to the datatype and not a copy of the datatype!!!
            return SOMEIPParameter(
                name=name, description=description, datatype=Typedef(name=datatype.name(), type="typedef", datatyperef=tmp.datatype)
            )

        elif isinstance(datatype, SOMEIPBaseParameterBasetype):
            return SOMEIPParameter(name=name, description=description, datatype=self.to_flync_base_datatype(datatype, name))

        elif isinstance(datatype, SOMEIPBaseParameterEnumeration):
            child_dt = datatype.child()
            dt = self.to_flync_base_datatype(child_dt, child_dt.name())
            if dt is None:
                print(f"WARNING: Not supporting enumerations with unknown basetype! {name=}")
                return None
            endian = dt.endianness

            entries = list()
            for item in datatype.items():
                descr = "" if item.desc() is None else str(item.desc())
                entries.append(EnumEntry(name=item.name(), value=item.value(), description=descr))

            return SOMEIPParameter(
                name=name,
                description=description,
                datatype=Enum(name=datatype.name(), type="enum", endianness=endian, base_type=dt, entries=entries),
            )

        elif isinstance(datatype, SOMEIPBaseParameterString):
            return self.to_flync_string(datatype, name, description)

        elif isinstance(datatype, SOMEIPBaseParameterBitfield):
            return self.to_flync_bitfield(datatype, name, description)

        elif isinstance(datatype, SOMEIPBaseParameterStruct):
            return self.to_flync_struct(datatype, name, description)

        elif isinstance(datatype, SOMEIPBaseParameterUnion):
            return self.to_flync_union(datatype, name, description)

        elif isinstance(datatype, SOMEIPBaseParameterArray):
            return self.to_flync_array(datatype, name, description)

        else:
            # Fallback to UInt8 for unknown types
            print(f"WARNING: Unknown datatype '{datatype}' for parameter '{name}', using UInt8")
            return SOMEIPParameter(name=name, description=description, datatype=UInt8(type="UInt8"))

    def to_flync_string(self, datatype, name, description=""):
        """Convert a FIBEX string to a FLYNC string type."""
        encoding = datatype.chartype() or "UTF-8"

        if encoding == "UTF-16":
            encoding = "UTF-16BE" if datatype.bigendian() else "UTF-16LE"

        if encoding not in ("UTF-8", "UTF-16BE", "UTF-16LE"):
            print(f"WARNING: Unsupported string encoding '{encoding}' for '{name}', defaulting to UTF-8")
            encoding = "UTF-8"

        if datatype.lowerlimit() > datatype.upperlimit():
            print(f"WARNING: String {name} has lowerlimit: {datatype.lowerlimit()} > upperlimit: {datatype.upperlimit()}")
        elif datatype.upperlimit() < 0:
            print(f"WARNING: String {name} has upperlimit: {datatype.upperlimit()} and lowerlimit: {datatype.lowerlimit()}")

        if datatype.lowerlimit() == datatype.upperlimit():
            # fixed length
            tmp = FixedLengthString(
                name=datatype.name(),
                type="fixed_length_string",
                length=datatype.upperlimit(),
                length_of_length_field=datatype.length_of_length(),
                encoding=encoding,
            )
        else:
            # variable length
            pad_to = datatype.pad_to()
            if pad_to == 0:
                pad_to = 8

            max_len = datatype.upperlimit() if datatype.upperlimit() >= 0 else None
            min_len = datatype.lowerlimit() if datatype.lowerlimit() > 0 else None
            tmp = DynamicLengthString(
                name=datatype.name(),
                type="dynamic_length_string",
                length_of_length_field=datatype.length_of_length(),
                bit_alignment=pad_to,
                encoding=encoding,
                max_length=max_len,
                min_length=min_len,
            )
        return SOMEIPParameter(name=name, description=description, datatype=tmp)

    def to_flync_bitfield(self, datatype, name, description=""):
        """Convert a FIBEX bitfield to a FLYNC Bitfield."""
        from flync.model.flync_4_someip.someip_datatypes import Bitfield, BitfieldEntry

        entries = []
        for item in datatype.items():
            entries.append(BitfieldEntry(name=item.name(), bitposition=item.bit_number(), description="", values=[]))

        child = datatype.child()
        if isinstance(child, SOMEIPBaseParameterBasetype):
            length = child.bitlength_encoded_type()
        else:
            # Fallback: use 8 bits
            length = 8

        return SOMEIPParameter(
            name=name, description=description, datatype=Bitfield(name=child.name(), type="bitfield", length=length, fields=entries)
        )

    def to_flync_struct(self, datatype, name, description=""):
        """Convert a FIBEX struct to a FLYNC Struct."""
        from flync.model.flync_4_someip.someip_datatypes import Struct

        members = []
        for m in datatype.members().values():
            child = m.child()

            # Recursively convert the child datatype, using the member's name
            child_datatype = self.to_flync_parameter(child, name_override=m.name())
            if child_datatype is None:
                print(f"WARNING: Skipping struct member '{m.name()}' (unsupported datatype)")
                continue

            # FLYNC Struct.members is a flat list of datatypes; the member name
            # is taken from member_name (if set) or the datatype's own `name` field.
            # Store the FIBEX member name in member_name so the type's own name
            # (e.g. the union type name) is preserved for display.
            flync_member_type = child_datatype.datatype.model_copy(update={"member_name": m.name()})
            members.append(flync_member_type)

        bit_alignment = datatype.pad_to()
        if bit_alignment == 0:
            bit_alignment = 8  # default
        return SOMEIPParameter(
            name=name,
            description=description,
            datatype=Struct(
                name=datatype.name(), type="struct", members=members, length_of_length_field=datatype.length_of_length(), bit_alignment=bit_alignment
            ),
        )

    def to_flync_union(self, datatype, name, description=""):
        """Convert a FIBEX union to a FLYNC Union."""
        from flync.model.flync_4_someip.someip_datatypes import Union, UnionMember

        members = []
        for m in datatype.members().values():
            child = m.child()

            # Recursively convert the child datatype, using the member's name
            child_datatype = self.to_flync_parameter(child, name_override=m.name())
            if child_datatype is None:
                print(f"WARNING: Skipping union member '{m.name()}' (unsupported datatype)")
                continue

            members.append(UnionMember(type=child_datatype.datatype, index=m.index(), name=m.name(), mandatory=m.mandatory()))

        bit_alignment = datatype.pad_to()
        if bit_alignment == 0:
            bit_alignment = 8  # default

        return SOMEIPParameter(
            name=name,
            description=description,
            datatype=Union(
                name=datatype.name(),
                type="union",
                members=members,
                length_of_length_field=datatype.length_of_length(),
                length_of_type_field=datatype.length_of_type(),
                bit_alignment=bit_alignment,
            ),
        )

    def to_flync_array(self, datatype, name, description=""):
        """Convert a FIBEX array to a FLYNC ArrayType."""
        from flync.model.flync_4_someip.someip_datatypes import ArrayDimension, ArrayType

        child = datatype.child()

        # Recursively convert the child datatype
        child_datatype = self.to_flync_parameter(child)
        if child_datatype is None:
            print(f"WARNING: Array '{name}' has unsupported element type, skipping")
            return None

        # Build dimensions from the array
        dimensions = []
        for dim in datatype.dims().values():
            kind = "fixed" if dim.lowerlimit() == dim.upperlimit() else "dynamic"
            # Only set bit_alignment if non-zero
            bit_alignment = dim.pad_to() if dim.pad_to() > 0 else None
            dimension = ArrayDimension(
                kind=kind,
                length=dim.upperlimit() if kind == "fixed" else None,
                length_of_length_field=dim.length_of_length() if kind == "dynamic" else None,
                upper_limit=dim.upperlimit(),
                lower_limit=dim.lowerlimit(),
                bit_alignment=bit_alignment,
            )
            dimensions.append(dimension)

        return SOMEIPParameter(
            name=name,
            description=description,
            datatype=ArrayType(name=datatype.name(), type="array", dimensions=dimensions, element_type=child_datatype.datatype),
        )

    def create_someip_parameter_typedef(self, name, name2, child):
        ret = SOMEIPParameterTypedef(self.__globalid_typedefs, name, name2, child)
        self.__globalid_typedefs += 1
        return ret

    def create_someip_service(self, name, serviceid, majorver, minorver, methods, events, fields, eventgroups):
        ret = SOMEIPBaseService(name, serviceid, majorver, minorver, methods, events, fields, eventgroups)

        # Methods
        flync_methods = list()
        for m in methods.values():
            call_type = m.calltype()
            # Map calltype to FLYNC type
            if call_type == "REQUEST_RESPONSE":
                method_type = "request_response"
            elif call_type == "FIRE_AND_FORGET":
                method_type = "fire_and_forget"
            else:
                method_type = "request_response"  # default

            # Convert in/out params to FLYNC parameters
            input_params = []
            for p in m.inparams():
                result = self.to_flync_parameter(p)
                if result is not None:
                    input_params.append(result)
                else:
                    print(f"WARNING: Skipping unsupported input parameter in method '{m.name()}'")

            output_params = []
            for p in m.outparams():
                result = self.to_flync_parameter(p)
                if result is not None:
                    output_params.append(result)
                else:
                    print(f"WARNING: Skipping unsupported output parameter in method '{m.name()}'")

            # Create FLYNC method
            if method_type == "request_response":
                flync_methods.append(
                    SOMEIPRequestResponseMethod(
                        name=m.name(),
                        id=m.methodid(),
                        reliable=m.reliable(),
                        input_parameters=input_params,
                        output_parameters=output_params,
                    )
                )
            else:
                flync_methods.append(
                    SOMEIPFireAndForgetMethod(
                        name=m.name(),
                        id=m.methodid(),
                        reliable=m.reliable(),
                        input_parameters=input_params,
                    )
                )
            # print(f"INFO: Created FLYNC method '{m.name()}' (id: 0x{m.methodid():04x}, type: {method_type})")

        # Events
        flync_events = dict()
        for e in events.values():
            params = list()
            for p in e.params():
                result = self.to_flync_parameter(p)
                if result is not None:
                    params.append(result)
                else:
                    print(f"WARNING: Skipping unsupported parameter in event '{e.name()}'")

            flync_events[e.methodid()] = SOMEIPEvent(
                name=e.name(),
                id=e.methodid(),
                reliable=e.reliable(),
                parameters=params,
            )

        # Fields
        flync_fields = dict()  # keyed by f.id() (unique per field)
        flync_fields_by_notifier = dict()  # keyed by notifier_id (for eventgroup lookup)
        for f in fields.values():
            notifier_id = f.notifierid()
            getter_id = None
            setter_id = None

            if f.getter() is not None:
                getter_id = f.getter().methodid()
            if f.setter() is not None:
                setter_id = f.setter().methodid()

            # Determine reliability based on field type
            reliable = False
            getter_reliable = f.getter().reliable() if f.getter() else None
            setter_reliable = f.setter().reliable() if f.setter() else None
            notifier_reliable = f.notifier().reliable() if f.notifier() else None

            # Check if all reliable values are the same
            reliable_values = {getter_reliable, setter_reliable, notifier_reliable}
            if len(reliable_values) > 1 and None not in reliable_values:
                print(
                    f"WARNING: Field '{f.name()}' has mismatched reliability values: getter={getter_reliable}, setter={setter_reliable}, "
                    f"notifier={notifier_reliable}"
                )

            if f.getter() is not None and f.getter().reliable():
                reliable = f.getter().reliable()
            elif f.setter() is not None and f.setter().reliable():
                reliable = f.setter().reliable()
            elif f.notifier() is not None and f.notifier().reliable():
                reliable = f.notifier().reliable()

            params = list()
            for p in f.params():
                result = self.to_flync_parameter(p)
                if result is not None:
                    params.append(result)
                else:
                    print(f"WARNING: Skipping unsupported parameter in field '{f.name()}'")

            # Create FLYNC field; use f.id() as the unique key so that fields
            # without a notifier (notifier_id=None) don't overwrite each other.
            field_key = f.id()
            flync_field = SOMEIPField(
                name=f.name(),
                getter_id=getter_id,
                setter_id=setter_id,
                notifier_id=notifier_id,
                reliable=reliable,
                parameters=params,
            )
            flync_fields[field_key] = flync_field
            if notifier_id is not None:
                flync_fields_by_notifier[notifier_id] = flync_field

        # Eventgroups
        flync_eventgroups = list()
        for eg in eventgroups.values():
            eg_events = list()
            eg_fields = list()
            for eid in eg.eventids():
                if eid in flync_events:
                    eg_events.append(flync_events[eid])
                else:
                    print(f"WARNING: Service 0x{serviceid:04x} Evengroup 0x{eg.id():04x} references unknown Event ID: 0x{eid:04x}")
            for fid in eg.fieldids():
                # Fields are referenced by their notifier ID
                if fid in flync_fields_by_notifier:
                    # Add field to eventgroup
                    eg_fields.append(flync_fields_by_notifier[fid])
                else:
                    print(f"WARNING: Service 0x{serviceid:04x} Evengroup 0x{eg.id():04x} references unknown Field Notifier ID: 0x{fid:04x}")

            flync_eventgroups.append(
                SOMEIPEventgroup(
                    name=eg.name(),
                    id=eg.id(),
                    # multicast_treshold
                    events=list(eg_events + eg_fields),
                )
            )

        tmp = SOMEIPServiceInterface(
            name=name,
            id=serviceid,
            major_version=majorver,
            minor_version=minorver,
            fields=list(flync_fields.values()),
            events=list(flync_events.values()),
            eventgroups=flync_eventgroups,
            methods=flync_methods,
            meta=self.someip_metadata(),
        )

        self.__flync_someip_services.append(tmp)

        return ret

    @staticmethod
    def embedded_metadata(target_system):
        return EmbeddedMetadata(
            type="embedded",
            author="FIBEXConverter",
            compatible_flync_version=BaseVersion(version_schema="semver", version=FLYNC_VERSION),
            target_system=target_system,
        )

    @staticmethod
    def ecu_metadata():
        return ECUMetadata(
            type="ecu",
            author="FIBEXConverter",
            compatible_flync_version=BaseVersion(version_schema="semver", version=FLYNC_VERSION),
        )

    @staticmethod
    def someip_metadata():
        return SOMEIPServiceMetadata(
            type="someip_service",
            author="FIBEXConverter",
            compatible_flync_version=BaseVersion(version_schema="semver", version=FLYNC_VERSION),
        )

    @staticmethod
    def system_metadata():
        return SystemMetadata(
            type="system",
            author="FIBEXConverter",
            compatible_flync_version=BaseVersion(version_schema="semver", version=FLYNC_VERSION),
            release=BaseVersion(version_schema="semver", version=FLYNC_VERSION),
        )

    def ecus(self):
        return self.__flync_ecus

    def someipsd_config(self):
        return SDConfig(ip_address=self.__flync_someipsd_addr, port=self.__flync_someipsd_port, sd_timings=self.__flync_someipsd_timings)

    def someip_config(self):
        return SOMEIPConfig(sd_config=self.someipsd_config(), services=self.__flync_someip_services, someip_timings=self.__flync_someip_timings)

    def topology(self):
        st = SystemTopology(connections=self.__flync_connections)
        return FLYNCTopology(system_topology=st)

    def create_flync_model(self):
        self.create_flync_ecus()
        # general should be optional but FLYNCWorkspace does not respect that
        general_config = FLYNCGeneralConfig(someip_config=self.someip_config(), tcp_profiles=[self.__flync_tcp_profile])
        self.__flync_model = FLYNCModel(ecus=self.ecus(), general=general_config, topology=self.topology(), metadata=self.system_metadata())

    def save_flync_model(self, target_dir):
        self.__flync_workspace = FLYNCWorkspace("FLYNC_WORKSPACE", workspace_path=target_dir)
        self.__flync_workspace.load_model(flync_model=self.__flync_model, file_path=target_dir)


def parse_arguments():
    parser = argparse.ArgumentParser(description="Converting configuration to FLYNC model.")
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
    parser.add_argument("--generate-vlan-names", action="store_true")
    parser.add_argument(
        "--mcast-list",
        type=argparse.FileType("r"),
        default=None,
        help="Semicolon Separated List of Static Multicast Entries",
    )
    parser.add_argument(
        "--multicast-names",
        type=argparse.FileType("r"),
        default=None,
        help="Address/Name CSV file",
    )
    parser.add_argument(
        "--plugin",
        help="filename of parser plugin",
        type=lambda x: is_file_valid(parser, x),
        default=None,
    )

    args = parser.parse_args()
    return args


def main():
    global g_gen_portid

    print("Converting configuration to FLYNC Model")
    args = parse_arguments()

    g_gen_portid = args.generate_switch_port_names

    ecu_name_mapping = {}
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

    print("Generating output directories:")
    target_dir = os.path.join(output_dir, "flync")
    if not os.path.exists(target_dir):
        os.makedirs(target_dir)
        time.sleep(0.5)

    print("Creating FLYNC model:")
    conf_factory.create_flync_model()

    print("Saving FLYNC model:")
    conf_factory.save_flync_model(os.path.abspath(target_dir))

    print("Done.")


# only call main, if we are started directly
if __name__ == "__main__":
    main()
