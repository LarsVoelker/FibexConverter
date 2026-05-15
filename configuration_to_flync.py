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
import json
import os.path
import re
import time

from flync.core.base_models.instances_registery import Registry, registry_context
from flync.model.flync_4_bus.can_bus import CANBus
from flync.model.flync_4_ecu import BASET1, ECU, RGMII, Controller, ECUPort, EthernetInterface, InternalTopology
from flync.model.flync_4_ecu.can_interface import CANFrameRef, CANInterfaceConfig
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
from flync.model.flync_4_general_configuration import FLYNCChannelConfig, FLYNCGeneralConfig
from flync.model.flync_4_metadata import BaseVersion, ECUMetadata, EmbeddedMetadata, SOMEIPServiceMetadata, SystemMetadata
from flync.model.flync_4_signal.frame import CANFDFrame, CANFrame
from flync.model.flync_4_signal.pdu import ContainedPDURef, ContainerPDU, ContainerPDUHeader, MultiplexedPDU, MuxGroup, PDUInstance, StandardPDU
from flync.model.flync_4_signal.signal import Signal, SignalDataType, SignalInstance, ValueDescription
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
from flync.sdk.workspace.flync_workspace import FLYNCWorkspace, WorkspaceConfiguration

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

FLYNC_VERSION = "0.11.0"

g_gen_portid = False


def _fibex_endianness_to_flync(value):
    """Map a FIBEX is-high-low-byte-order value (bool or truthy string) to FLYNC 'BE'/'LE'."""
    return "BE" if str(value).lower() == "true" else "LE"


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

        self.__base_ecus = {}  # ecu_name -> BaseECU
        self.__base_vlan_name_to_id = {}  # vlan_name -> int vlan_id
        self.__ipv4_netmasks = {}  # ip_str -> netmask_str
        self.__ipv6_prefix_lengths = {}  # exploded_ip_str -> prefixlen_str
        self.__mac_counter = 0

        # CAN signal/PDU/frame/cluster data collected during FIBEX parsing
        self.__cluster_info = {}  # cluster_id → {name, speed, protocol, channel_refs}
        self.__channel_to_cluster = {}  # channel_ref → cluster_id
        self.__can_signals = {}  # signal_id → BaseSignal
        self.__can_pdus = {}  # pdu_id → BasePDU
        self.__mux_sub_pdu_ids = set()  # IDs of PDUs that are sub-PDUs of a mux PDU (not written as standalone FLYNC files)
        self.__can_frames = {}  # frame_id → BaseFrame
        self.__eth_pdu_insts = {}  # header_id → BaseEthernetPDUInstance
        self.__can_fts = {}  # ft_id → BaseFrameTriggeringCAN
        self.__ft_to_channel = {}  # ft.id() → channel_name
        self.__ecu_frame_fts = {}  # ecu_name → {out: [ft,...], in: [ft,...]}

        # Each factory instance owns its own registry so that FLYNC model
        # objects (services, ports, interfaces, …) from different factory
        # instances never collide in the global name/instances tables.
        self.__registry = Registry()

        self.__flync_someip_services = list()
        with registry_context(self.__registry):
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

    def base_ecus(self):
        return self.__base_ecus

    # -------------------------------------------------------------------------
    # Overrides to track FIBEX base objects for topology generation
    # -------------------------------------------------------------------------

    def create_ecu(self, name, controllers):
        ret = super().create_ecu(name, controllers)
        self.base_ecus()[name] = ret
        # Collect per-ECU frame triggerings for CAN bus building
        out_fts, in_fts = [], []
        for ctrl in controllers:
            for iface in ctrl.interfaces():
                out_fts.extend(iface.frame_triggerings_out().values())
                in_fts.extend(iface.frame_triggerings_in().values())
        self.__ecu_frame_fts[name] = {"out": out_fts, "in": in_fts}
        return ret

    def add_cluster_info(self, cluster_id, name, speed, protocol, channel_refs):
        self.__cluster_info[cluster_id] = {"name": name, "speed": speed, "protocol": protocol, "channel_refs": channel_refs}
        for ch_ref in channel_refs:
            self.__channel_to_cluster[ch_ref] = cluster_id

    def create_signal(self, id, name, compu_scale, compu_consts, bit_len, min_len, max_len, basetype, basetypelen):
        ret = super().create_signal(id, name, compu_scale, compu_consts, bit_len, min_len, max_len, basetype, basetypelen)
        self.__can_signals[id] = ret
        return ret

    def create_pdu(self, id, short_name, byte_length, pdu_type, signal_instances):
        ret = super().create_pdu(id, short_name, byte_length, pdu_type, signal_instances)
        self.__can_pdus[id] = ret
        return ret

    def create_multiplex_pdu(self, id, short_name, byte_length, pdu_type, switch, seg_pos, pdu_instances, static_segs, static_pdu):
        ret = super().create_multiplex_pdu(id, short_name, byte_length, pdu_type, switch, seg_pos, pdu_instances, static_segs, static_pdu)
        self.__can_pdus[id] = ret
        # Sub-PDUs must NOT be written as standalone FLYNC files; their signal names clash
        # with the same names embedded inside the MultiplexedPDU's mux groups, causing the
        # FLYNC workspace loader's UniqueName registry to raise assertion errors.
        for sub_pdu in (pdu_instances or {}).values():
            if sub_pdu is not None:
                self.__mux_sub_pdu_ids.add(sub_pdu.id())
        if static_pdu is not None:
            self.__mux_sub_pdu_ids.add(static_pdu.id())
        return ret

    def create_frame(self, id, short_name, byte_length, frame_type, pdu_instances):
        ret = super().create_frame(id, short_name, byte_length, frame_type, pdu_instances)
        self.__can_frames[id] = ret
        return ret

    def create_frame_triggering_can(self, id, frame, can_id, is_extended_id=False, is_can_fd=False):
        ret = super().create_frame_triggering_can(id, frame, can_id, is_extended_id=is_extended_id, is_can_fd=is_can_fd)
        self.__can_fts[id] = ret
        return ret

    def create_ethernet_pdu_instance(self, pdu_ref, header_id):
        ret = super().create_ethernet_pdu_instance(pdu_ref, header_id)
        self.__eth_pdu_insts[header_id] = ret
        return ret

    def create_interface(self, name, vlanid, ips, sockets, input_frame_trigs, output_frame_trigs, fr_channel):
        ret = super().create_interface(name, vlanid, ips, sockets, input_frame_trigs, output_frame_trigs, fr_channel)
        # Map frame triggering IDs → channel name so we can group frames by channel
        for ft in list((input_frame_trigs or {}).values()) + list((output_frame_trigs or {}).values()):
            self.__ft_to_channel[ft.id()] = name
        return ret

    def create_vlan(self, name, vlanid, prio):
        ret = super().create_vlan(name, vlanid, prio)
        if vlanid is not None and name:
            self.__base_vlan_name_to_id[name] = int(vlanid)
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
        self.__ipv4_netmasks[ip] = netmask

    def get_ipv4_netmask(self, ip):
        return self.__ipv4_netmasks.get(str(ip), "255.255.255.0")

    def add_ipv6_address_config(self, ip, prefixlen):
        tmp = ipaddress.ip_address(ip).exploded
        self.__ipv6_prefix_lengths[tmp] = prefixlen

    def get_ipv6_prefix_length(self, ip):
        try:
            tmp = ipaddress.ip_address(ip).exploded
            return self.__ipv6_prefix_lengths.get(tmp)
        except ValueError:
            return None

    def _next_mac(self):
        """Generate a unique locally-administered placeholder MAC address."""
        mac_int = 0x020000000000 | (self.__mac_counter & 0xFFFFFFFFFF)
        self.__mac_counter += 1
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
                    print(f"WARNING: Could not create SOMEIPServiceConsumer for 0x{svc.serviceid():04x}: {type(e).__name__}: {e}")
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
                if sender_eg_ids < all_eg_ids:
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
                print(f"WARNING: Could not create SOMEIPServiceProvider for 0x{svc.serviceid():04x}: {type(e).__name__}: {e}")

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
                print(f"WARNING: Could not create SOMEIPServiceConsumer for 0x{svc.serviceid():04x}: {type(e).__name__}: {e}")

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
        with registry_context(self.__registry):
            self._create_flync_ecus_impl()

    def _create_flync_ecus_impl(self):
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

        for ecu_name, base_ecu in sorted(self.base_ecus().items()):
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
                            # Self-loop: a switch port connects back to a controller on
                            # the same ECU. FLYNC's internal-topology model does not yet
                            # express this case, so skip the connection.
                            continue
                        # Switch-to-endpoint ECU: use a per-controller key so that
                        # two switch ports connecting to two different controllers of
                        # the same endpoint ECU each get their own ECUPort.
                        peer_ecu_name = peer_ctrl_ecu.name()
                        peer_port_key = f"_port_{peer_ctrl.name()}"
                        pair = frozenset({(ecu_name, base_port.portid(gen_name=g_gen_portid)), (peer_ecu_name, peer_port_key)})
                        if pair in seen_pairs:
                            continue
                        seen_pairs.add(pair)
                        role_map[(ecu_name, base_port.portid(gen_name=g_gen_portid))] = "master"
                        role_map[(peer_ecu_name, peer_port_key)] = "slave"
                        ext_connections.append((ecu_name, base_port.portid(gen_name=g_gen_portid), peer_ecu_name, peer_port_key))

        # ------------------------------------------------------------------
        # Step 2: Build FLYNC SwitchPorts, VLANEntries, and Switches per ECU
        # ------------------------------------------------------------------
        # flync_switches_per_ecu[ecu_name] = [FLYNCSwitch, ...]
        flync_switches_per_ecu = {}
        # flync_swport_name_map[(ecu_name, base_port_id)] = flync_sw_port_name
        flync_swport_name_map = {}
        # flync_ecuport_name_map[(ecu_name, base_port_id)] = flync_ecu_port_name
        flync_ecuport_name_map = {}

        for ecu_name, base_ecu in sorted(self.base_ecus().items()):
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
        for ecu_name, base_ecu in sorted(self.__base_ecus.items()):
            ecu_ports = []
            internal_connections = []
            has_switches = bool(base_ecu.switches())

            # Step 3a: Build FLYNC controllers first.
            # ctrl_iface_map[fibex_ctrl_name] = iface_name  (only for ctrlrs with interfaces)
            fibex_controllers = base_ecu.controllers()
            flync_controllers = []
            ctrl_iface_map = {}

            # Identify which controllers own a CPU/management switch port for this ECU.
            cpu_ctrl_names = {ctrl_name for (e_name, _port_id), ctrl_name in cpu_port_ctrl_name_map.items() if e_name == ecu_name}

            for fibex_ctrl in sorted(fibex_controllers, key=lambda c: c.name()):
                eth_interfaces = []
                fibex_ifaces = fibex_ctrl.interfaces()

                if fibex_ifaces:
                    virt_ifaces = []
                    ctrl_vlan_sockets = {}  # vlan_id -> [sockets] for this controller
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
                                    try:
                                        netmask_addr = ipaddress.IPv4Address(netmask_str)
                                    except (ipaddress.AddressValueError, ValueError) as e:
                                        print(
                                            f"WARNING: Invalid IPv4 netmask {netmask_str!r} for {ip_str}: {e}; "
                                            f"falling back to 255.255.255.0"
                                        )
                                        netmask_addr = ipaddress.IPv4Address("255.255.255.0")
                                    addresses.append(
                                        IPv4AddressEndpoint(
                                            address=ip_addr,
                                            ipv4netmask=netmask_addr,
                                        )
                                    )
                            elif ip_obj.version == 6:
                                ip_addr = ipaddress.IPv6Address(ip_str)
                                if ip_addr.is_multicast:
                                    multicast_ips.append(ip_addr)
                                else:
                                    prefix_len = self.get_ipv6_prefix_length(ip_str)
                                    try:
                                        ipv6prefix = int(prefix_len) if prefix_len else 128
                                    except (TypeError, ValueError) as e:
                                        print(
                                            f"WARNING: Invalid IPv6 prefix length {prefix_len!r} for {ip_str}: {e}; "
                                            f"falling back to 128"
                                        )
                                        ipv6prefix = 128
                                    addresses.append(
                                        IPv6AddressEndpoint(
                                            address=ip_addr,
                                            ipv6prefix=ipv6prefix,
                                        )
                                    )

                        # Collect sockets for this controller grouped by VLAN ID
                        vlan_id = fibex_iface.vlanid()
                        for fibex_sock in fibex_iface.sockets():
                            flync_sock = self._to_flync_socket(fibex_sock)
                            if flync_sock is not None:
                                ctrl_vlan_sockets.setdefault(vlan_id, []).append(flync_sock)

                        # Skip Ethernet VirtualControllerInterface for CAN-only interfaces
                        # (identified by having CAN frame triggerings — handled via can_interfaces).
                        has_can_fts = any(
                            ft.is_can()
                            for fts in [
                                fibex_iface.frame_triggerings_out().values(),
                                fibex_iface.frame_triggerings_in().values(),
                            ]
                            for ft in fts
                        )
                        if not has_can_fts:
                            virt_ifaces.append(
                                VirtualControllerInterface(
                                    name=fibex_iface.vlanname() or f"vlan{fibex_iface.vlanid()}",
                                    vlanid=fibex_iface.vlanid(),
                                    addresses=addresses,
                                    multicast=multicast_ips,
                                )
                            )

                    if virt_ifaces:
                        iface_name = f"{self._safe_name(ecu_name)}_" f"{self._safe_name(fibex_ctrl.name())}_iface"
                        ctrl_iface_map[fibex_ctrl.name()] = iface_name
                        # CPU port controller gets RGMII PHY-side MII config so the
                        # SwitchPortToControllerInterface compulsory MII check passes.
                        is_cpu_ctrl = fibex_ctrl.name() in cpu_ctrl_names
                        ctrl_iface = ControllerInterface(
                            name=iface_name,
                            mac_address=self._next_mac(),
                            mii_config=RGMII(type="rgmii", mode="phy", speed=1000) if is_cpu_ctrl else None,
                            virtual_interfaces=virt_ifaces,
                        )

                        # Sort sockets by name for deterministic output
                        for vlan_id in ctrl_vlan_sockets:
                            ctrl_vlan_sockets[vlan_id].sort(key=lambda s: s.name)
                        iface_socket_containers = [
                            SocketContainer(
                                name=f"{self._safe_name(ecu_name)}_vlan{vlan_id if vlan_id is not None else 0}",
                                vlan_id=vlan_id,
                                sockets=sockets_list,
                            )
                            for vlan_id, sockets_list in sorted(
                                ctrl_vlan_sockets.items(),
                                key=lambda item: item[0] if item[0] is not None else -1,
                            )
                        ]

                        eth_interfaces.append(
                            EthernetInterface(
                                interface_config=ctrl_iface,
                                sockets=iface_socket_containers,
                            )
                        )

                # Sort ethernet interfaces by interface name for deterministic output
                eth_interfaces.sort(key=lambda ei: ei.interface_config.name)

                # Build CAN interfaces for this controller from its FIBEX frame triggerings
                can_iface_frames: dict = {}  # bus_ref → {"sender": set, "receiver": set}
                for fibex_iface in fibex_ctrl.interfaces():
                    for ft in fibex_iface.frame_triggerings_out().values():
                        if ft.is_can() and ft.frame() is not None:
                            ch = self.__ft_to_channel.get(ft.id())
                            if ch:
                                can_iface_frames.setdefault(ch, {"sender": set(), "receiver": set()})["sender"].add(ft.frame().name())
                    for ft in fibex_iface.frame_triggerings_in().values():
                        if ft.is_can() and ft.frame() is not None:
                            ch = self.__ft_to_channel.get(ft.id())
                            if ch:
                                can_iface_frames.setdefault(ch, {"sender": set(), "receiver": set()})["receiver"].add(ft.frame().name())
                can_interfaces = [
                    CANInterfaceConfig(
                        bus_ref=bus_ref,
                        sender_frames=[CANFrameRef(frame_ref=n) for n in sorted(fdata["sender"])],
                        receiver_frames=[CANFrameRef(frame_ref=n) for n in sorted(fdata["receiver"])],
                    )
                    for bus_ref, fdata in sorted(can_iface_frames.items())
                ]

                flync_controllers.append(
                    Controller(
                        name=fibex_ctrl.name(),
                        ethernet_interfaces=eth_interfaces,
                        can_interfaces=can_interfaces if can_interfaces else None,
                        controller_metadata=self.embedded_metadata(self._safe_name(ecu_name)),
                    )
                )

            if not flync_controllers:
                ctrl_name = f"{self._safe_name(ecu_name)}_ctrl"
                flync_controllers.append(
                    Controller(
                        name=ctrl_name,
                        ethernet_interfaces=[],
                        controller_metadata=self.embedded_metadata(self._safe_name(ecu_name)),
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
                # Create one ECUPort per such controller connection with an
                # ECUPortToControllerInterface so the parser can resolve it unambiguously.
                for (ecn, port_key), endpoint_role in role_map.items():
                    if ecn != ecu_name or not port_key.startswith("_port_"):
                        continue
                    ctrl_name_key = port_key.removeprefix("_port_")
                    ep_name = f"{self._safe_name(ecu_name)}_{self._safe_name(ctrl_name_key)}_port"
                    ep = ECUPort(name=ep_name, mdi_config=BASET1(mode="base_t1", role=endpoint_role))
                    ecu_ports.append(ep)
                    iface_name = ctrl_iface_map.get(ctrl_name_key)
                    if iface_name is not None:
                        conn = ECUPortToControllerInterface(
                            type="ecu_port_to_controller_interface",
                            id=f"int_conn_{int_conn_id}",
                            ecu_port=ep_name,
                            controller_interface=iface_name,
                        )
                        internal_connections.append(InternalConnectionUnion(root=conn))
                        int_conn_id += 1
            else:
                # Endpoint ECU: one ECUPort per controller connection
                # (each connecting switch port gets its own ECUPort so the parser can
                # tell exactly which controller a given switch port leads to).
                endpoint_entries = {
                    port_key: role for (ecn, port_key), role in role_map.items() if ecn == ecu_name and port_key.startswith("_port_")
                }
                if not endpoint_entries:
                    # Fallback: single anonymous port (no switch connection info)
                    endpoint_entries = {"_port_": role_map.get((ecu_name, "_port_"), "slave")}

                for port_key, role in endpoint_entries.items():
                    ctrl_name_key = port_key.removeprefix("_port_")
                    if ctrl_name_key:
                        ep_name = f"{self._safe_name(ecu_name)}_{self._safe_name(ctrl_name_key)}_port"
                    else:
                        ep_name = f"{self._safe_name(ecu_name)}_port"
                    ep = ECUPort(name=ep_name, mdi_config=BASET1(mode="base_t1", role=role))
                    ecu_ports.append(ep)

                    iface_name = ctrl_iface_map.get(ctrl_name_key) if ctrl_name_key else None
                    if iface_name is not None:
                        conn = ECUPortToControllerInterface(
                            type="ecu_port_to_controller_interface",
                            id=f"int_conn_{int_conn_id}",
                            ecu_port=ep_name,
                            controller_interface=iface_name,
                        )
                        internal_connections.append(InternalConnectionUnion(root=conn))
                        int_conn_id += 1
                    else:
                        # Controller has no virtual interfaces: connect all known interfaces
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

            topology = InternalTopology(connections=internal_connections)
            flync_ecu = ECU(
                name=ecu_name,
                ports=ecu_ports,
                controllers=flync_controllers,
                switches=flync_switches_per_ecu.get(ecu_name, []),
                topology=topology,
                ecu_metadata=self.ecu_metadata(),
            )
            self.__flync_ecus.append(flync_ecu)

        # ------------------------------------------------------------------
        # Step 4: ExternalConnections (after all ECUPorts are in INSTANCES)
        # ------------------------------------------------------------------
        for i, (ecu1_name, port1_id, ecu2_name, port2_id) in enumerate(ext_connections):
            if port1_id.startswith("_port_"):
                ctrl_name_key = port1_id[len("_port_") :]
                ep1_name = (
                    f"{self._safe_name(ecu1_name)}_{self._safe_name(ctrl_name_key)}_port" if ctrl_name_key else f"{self._safe_name(ecu1_name)}_port"
                )
            else:
                ep1_name = flync_ecuport_name_map.get((ecu1_name, port1_id), f"{self._safe_name(ecu1_name)}_{self._safe_name(port1_id)}_ep")
            if port2_id.startswith("_port_"):
                ctrl_name_key = port2_id[len("_port_") :]
                ep2_name = (
                    f"{self._safe_name(ecu2_name)}_{self._safe_name(ctrl_name_key)}_port" if ctrl_name_key else f"{self._safe_name(ecu2_name)}_port"
                )
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

    # -------------------------------------------------------------------------
    # CAN channel/frame/PDU/signal conversion
    # -------------------------------------------------------------------------

    _FIBEX_TO_SIGNAL_DATA_TYPE = {
        "A_UINT8": SignalDataType.UINT8,
        "A_UINT16": SignalDataType.UINT16,
        "A_UINT32": SignalDataType.UINT32,
        "A_UINT64": SignalDataType.UINT64,
        "A_INT8": SignalDataType.INT8,
        "A_INT16": SignalDataType.INT16,
        "A_INT32": SignalDataType.INT32,
        "A_INT64": SignalDataType.INT64,
        "A_FLOAT32": SignalDataType.FLOAT32,
        "A_FLOAT64": SignalDataType.FLOAT64,
        "A_BYTEFIELD": SignalDataType.BYTEARRAY,
        "A_ASCIISTRING": SignalDataType.CHAR,
    }
    _SIGNAL_DATA_TYPE_TO_FIBEX = {v: k for k, v in _FIBEX_TO_SIGNAL_DATA_TYPE.items()}

    _ALLOWED_CAN_BAUD_RATES = (10_000, 20_000, 50_000, 100_000, 125_000, 250_000, 500_000, 1_000_000)

    @classmethod
    def _basetype_to_signal_data_type(cls, basetype):
        """Map a FIBEX BASE-DATA-TYPE string directly to a FLYNC SignalDataType.

        A_UINT8 → UINT8, A_UINT16 → UINT16, … The bit_length for the FLYNC
        Signal should come from the returned type's natural_bit_width().
        """

        return cls._FIBEX_TO_SIGNAL_DATA_TYPE.get(basetype, SignalDataType.UINT8)

    @classmethod
    def _nearest_can_baud_rate(cls, speed):
        if speed is None:
            return 500_000
        if speed in cls._ALLOWED_CAN_BAUD_RATES:
            return speed
        nearest = min(cls._ALLOWED_CAN_BAUD_RATES, key=lambda r: abs(r - speed))
        print(f"WARNING: CAN speed {speed} not in allowed FLYNC baud rates; using {nearest}")
        return nearest

    def _cluster_speed_for_channel(self, channel_name):
        cluster_id = self.__channel_to_cluster.get(channel_name)
        if cluster_id is None:
            return 500_000
        speed = self.__cluster_info.get(cluster_id, {}).get("speed")
        return self._nearest_can_baud_rate(speed)

    def _build_flync_multiplexed_pdu(self, base_pdu, pdu_byte_len, flync_sigs):
        """Convert a BaseMultiplexPDU into a FLYNC MultiplexedPDU.

        Sub-PDU signal positions in mux groups are stored as absolute bit offsets
        within the overall PDU.  Metadata needed for round-trip (segment layout and
        sub-PDU names per switch code) is JSON-encoded in the description field.
        """
        switch = base_pdu.switch()
        seg_positions = base_pdu.segment_positions()
        pdu_instances_map = base_pdu.pdu_instances()

        if switch is None or not seg_positions:
            print(f"WARNING: Multiplex PDU {base_pdu.name()} is missing switch or segment info. Skipping.")
            return None

        seg = seg_positions[0]
        seg_offset = int(seg.bit_position())
        seg_bit_len = int(seg.bit_length())
        seg_is_high_low = seg.is_high_low_byte_order() in (True, "true", "TRUE")

        # Selector signal (synthetic — not a regular FIBEX signal)
        _sel_dt = {8: SignalDataType.UINT8, 16: SignalDataType.UINT16, 32: SignalDataType.UINT32}
        sel_dt = _sel_dt.get(int(switch.bit_length()), SignalDataType.UINT8)
        try:
            selector_flync_sig = Signal(
                name=switch.name(),
                bit_length=int(switch.bit_length()),
                data_type=sel_dt,
                factor=1.0,
                offset=0.0,
            )
        except Exception as e:
            print(f"WARNING: Could not create selector signal for {base_pdu.name()}: {type(e).__name__}: {e}")
            return None

        sel_endianness = _fibex_endianness_to_flync(switch.is_high_low_byte_order())
        selector_si = SignalInstance(
            signal=selector_flync_sig,
            bit_position=int(switch.bit_position()),
            endianness=sel_endianness,
        )

        # Build one MuxGroup per switch code; signals use absolute bit positions
        mux_groups = []
        for switch_code in sorted(pdu_instances_map.keys()):
            sub_pdu = pdu_instances_map[switch_code]
            if sub_pdu is None:
                continue
            group_sigs = []
            for si in sub_pdu.signal_instances_sorted_by_bit_position():
                sig = si.signal()
                if sig is None:
                    continue
                flync_sig = flync_sigs.get(sig.id())
                if flync_sig is None:
                    continue
                abs_bit_pos = int(si.bit_position() or 0) + seg_offset
                group_sigs.append(
                    SignalInstance(
                        signal=flync_sig,
                        bit_position=abs_bit_pos,
                        endianness=_fibex_endianness_to_flync(si.is_high_low_byte_order()),
                    )
                )
            try:
                group_pdu = StandardPDU(
                    type="standard",
                    name=sub_pdu.name(),
                    length=pdu_byte_len,
                    pdu_usage=base_pdu.pdu_type(),
                    signals=group_sigs,
                )
                mux_groups.append(MuxGroup(selector_value=switch_code, pdu=group_pdu))
            except Exception as e:
                print(f"WARNING: Could not create MuxGroup for {base_pdu.name()} switch_code={switch_code}: {type(e).__name__}: {e}")

        if not mux_groups:
            print(f"WARNING: Multiplex PDU {base_pdu.name()} has no valid mux groups. Skipping.")
            return None

        # Build static_group PDU if a static PDU exists
        static_flync_pdu = None
        static_base_pdu = base_pdu.static_pdu()
        if static_base_pdu is not None:
            static_segs = base_pdu.static_segments()
            static_seg = static_segs[0] if static_segs else None
            static_seg_offset = int(static_seg.bit_position()) if static_seg else 0
            static_sigs = []
            for si in static_base_pdu.signal_instances_sorted_by_bit_position():
                sig = si.signal()
                if sig is None:
                    continue
                flync_sig = flync_sigs.get(sig.id())
                if flync_sig is None:
                    continue
                abs_bit_pos = int(si.bit_position() or 0) + static_seg_offset
                static_sigs.append(
                    SignalInstance(
                        signal=flync_sig,
                        bit_position=abs_bit_pos,
                        endianness=_fibex_endianness_to_flync(si.is_high_low_byte_order()),
                    )
                )
            try:
                static_flync_pdu = StandardPDU(
                    type="standard",
                    name=static_base_pdu.name(),
                    length=pdu_byte_len,
                    pdu_usage=base_pdu.pdu_type(),
                    signals=static_sigs,
                )
            except Exception as e:
                print(f"WARNING: Could not create static group PDU for {base_pdu.name()}: {type(e).__name__}: {e}")

        # Encode round-trip metadata: segment layout and static segment info when present.
        # Endianness is stored as "true"/"false" strings so that the read-back value is a
        # non-empty string (truthy), matching the FIBEX parser's convention of storing the
        # raw XML text "false"/"true" in is_high_low_byte_order fields.
        meta = {
            "seg_bit_pos": seg_offset,
            "seg_bit_len": seg_bit_len,
            "seg_is_high_low": "true" if seg_is_high_low else "false",
        }
        if static_base_pdu is not None and static_seg is not None:
            static_seg_is_high_low = static_seg.is_high_low_byte_order() in (True, "true", "TRUE")
            meta["static_seg_bit_pos"] = static_seg_offset
            meta["static_seg_bit_len"] = int(static_seg.bit_length())
            meta["static_seg_is_high_low"] = "true" if static_seg_is_high_low else "false"
        description = json.dumps(meta)

        try:
            return MultiplexedPDU(
                type="multiplexed",
                name=base_pdu.name(),
                length=pdu_byte_len,
                pdu_usage=base_pdu.pdu_type(),
                description=description,
                selector_signal=selector_si,
                static_group=static_flync_pdu,
                mux_groups=mux_groups,
            )
        except Exception as e:
            print(f"WARNING: Could not create FLYNC MultiplexedPDU for {base_pdu.name()}: {type(e).__name__}: {e}")
            return None

    def _create_flync_channels(self):
        if not self.__can_frames:
            return None

        # Map ft.id() → channel_name (already built in create_interface overrides)
        # Map frame_id → CANFrame info
        ft_by_frame_id = {ft.frame().id(): ft for ft in self.__can_fts.values() if ft.frame() is not None}

        # Map frame_id → publisher ECU name (first ECU with an output FT for this frame)
        frame_to_publisher = {}
        for ecu_name, fts in self.__ecu_frame_fts.items():
            for ft in fts["out"]:
                if ft.is_can() and ft.frame() is not None:
                    frame_to_publisher.setdefault(ft.frame().id(), ecu_name)

        # Build FLYNC Signal objects (keyed by signal ID).
        # The FLYNC type is derived directly from the FIBEX BASE-DATA-TYPE.
        # Use the coded bit length from the original FIBEX signal (bit_length()),
        # falling back to the natural width of the data type if unset or invalid.
        flync_sigs = {}
        for sig_id, base_sig in self.__can_signals.items():
            dt = self._basetype_to_signal_data_type(base_sig.basetype())
            # Preserve the exact bit length from FIBEX; default to natural width
            bit_len = base_sig.bit_length()
            if bit_len is None or bit_len <= 0:
                bit_len = dt.natural_bit_width() or 8
            try:
                value_dict = dict()
                for name, start, end in base_sig.compu_consts() or []:
                    try:
                        lo, hi = int(start), int(end)
                        if lo == hi:
                            if lo in value_dict:
                                print(
                                    f"WARNING: Overwriting ValueDescription for value {lo}: "
                                    f"{value_dict[lo].description} -> {name}. "
                                    f"Signal: {base_sig.name()}!"
                                )
                            value_dict[lo] = ValueDescription(value=lo, description=name)
                    except (TypeError, ValueError):
                        print(f"WARNING: Signal {base_sig.name()} has invalid range: {start=} {end=}")
                        pass

                flync_sigs[sig_id] = Signal(
                    name=base_sig.name(),
                    bit_length=bit_len,
                    data_type=dt,
                    factor=float(base_sig.scaler() or 1.0),
                    offset=float(base_sig.offset() or 0.0),
                    value_descriptions=value_dict.values(),
                )
            except Exception as e:
                print(f"WARNING: Could not create FLYNC Signal for {base_sig.name()}: {type(e).__name__}: {e}")
                print(f"   {base_sig.basetype()=}")
                print(f"   Signal(name={base_sig.name()},")
                print(f"          bit_length={bit_len},")
                print(f"          data_type={dt},")
                print(f"          factor={float(base_sig.scaler() or 1.0)},")
                print(f"          offset={float(base_sig.offset() or 0.0)},")
                print(f"          value_descriptions={value_dict.values()})")

        # Build FLYNC PDU objects (StandardPDU for regular PDUs, MultiplexedPDU for mux PDUs).
        # Sub-PDUs of a mux PDU are embedded inside the MultiplexedPDU's mux_groups and must
        # NOT be written as standalone files to avoid FLYNC UniqueName registry conflicts.
        flync_pdus = []
        flync_pdu_by_id = {}
        for pdu_id, base_pdu in self.__can_pdus.items():
            if pdu_id in self.__mux_sub_pdu_ids:
                continue
            pdu_byte_len = base_pdu.byte_length()
            try:
                pdu_byte_len = int(pdu_byte_len)
            except (TypeError, ValueError):
                pdu_byte_len = 1
            if base_pdu.is_multiplex_pdu():
                flync_pdu = self._build_flync_multiplexed_pdu(base_pdu, pdu_byte_len, flync_sigs)
            else:
                sig_insts = []
                for si in base_pdu.signal_instances_sorted_by_bit_position():
                    sig = si.signal()
                    if sig is None:
                        continue
                    flync_sig = flync_sigs.get(sig.id())
                    if flync_sig is None:
                        continue
                    bit_pos = si.bit_position()
                    if bit_pos is None:
                        bit_pos = 0
                    sig_insts.append(
                        SignalInstance(
                            signal=flync_sig,
                            bit_position=int(bit_pos),
                            endianness=_fibex_endianness_to_flync(si.is_high_low_byte_order()),
                        )
                    )
                try:
                    flync_pdu = StandardPDU(
                        type="standard",
                        name=base_pdu.name(),
                        length=pdu_byte_len,
                        pdu_usage=base_pdu.pdu_type(),
                        signals=sig_insts,
                    )
                except Exception as e:
                    print(f"WARNING: Could not create FLYNC PDU for {base_pdu.name()}: {type(e).__name__}: {e}")
                    continue

            if flync_pdu is not None:
                flync_pdus.append(flync_pdu)
                flync_pdu_by_id[pdu_id] = flync_pdu

        # Build FLYNC CANFrame objects grouped by channel
        flync_frames_by_channel = {}
        for frame_id, base_frame in self.__can_frames.items():
            ft = ft_by_frame_id.get(frame_id)
            if ft is None:
                continue
            channel_name = self.__ft_to_channel.get(ft.id())
            if channel_name is None:
                continue
            packed_pdus = []
            for pi in base_frame.pdu_instances().values():
                pdu = pi.pdu()
                if pdu is None:
                    continue
                flync_pdu = flync_pdu_by_id.get(pdu.id())
                if flync_pdu is None:
                    continue
                bit_pos = pi.bit_position()
                if bit_pos is None:
                    bit_pos = 0
                packed_pdus.append(PDUInstance(pdu_ref=flync_pdu.name, bit_position=int(bit_pos)))
            frame_byte_len = base_frame.byte_length()
            try:
                frame_byte_len = int(frame_byte_len)
            except (TypeError, ValueError):
                frame_byte_len = 8
            try:
                if ft.is_can_fd():
                    # What about the bit_rate_switch?
                    flync_frame = CANFDFrame(
                        type="can_fd",
                        name=base_frame.name(),
                        can_id=ft.can_id(),
                        id_format="extended_29bit" if ft.is_extended_id() else "standard_11bit",
                        length=frame_byte_len,
                        packed_pdus=packed_pdus,
                        frame_usage=base_frame.frame_type(),
                    )
                    flync_frames_by_channel.setdefault(channel_name, []).append(flync_frame)
                else:
                    flync_frame = CANFrame(
                        type="can",
                        name=base_frame.name(),
                        can_id=ft.can_id(),
                        id_format="extended_29bit" if ft.is_extended_id() else "standard_11bit",
                        length=frame_byte_len,
                        packed_pdus=packed_pdus,
                        frame_usage=base_frame.frame_type(),
                    )
                    flync_frames_by_channel.setdefault(channel_name, []).append(flync_frame)
            except Exception as e:
                print(f"WARNING: Could not create FLYNC CANFrame for {base_frame.name()}: {type(e).__name__}: {e}")

        # Build FLYNC ContainerPDU objects for Ethernet frames (no CAN frame triggering).
        # Use header_ids from __eth_pdu_insts; fall back to enumeration index if not found.
        eth_header_by_pdu_id = {inst.pdu().id(): h_id for h_id, inst in self.__eth_pdu_insts.items() if inst.pdu() is not None}
        flync_eth_containers = []
        for frame_id, base_frame in self.__can_frames.items():
            if frame_id in ft_by_frame_id:
                continue  # already handled as a CAN frame
            contained_pdus = []
            for idx, pi in enumerate(base_frame.pdu_instances().values()):
                pdu = pi.pdu()
                if pdu is None:
                    continue
                flync_pdu = flync_pdu_by_id.get(pdu.id())
                if flync_pdu is None:
                    continue
                pdu_header_id = eth_header_by_pdu_id.get(pdu.id(), idx)
                contained_pdus.append(ContainedPDURef(pdu_id=pdu_header_id, pdu_ref=flync_pdu.name, offset=pi.bit_position()))
            frame_byte_len = base_frame.byte_length()
            try:
                frame_byte_len = int(frame_byte_len)
            except (TypeError, ValueError):
                frame_byte_len = 8
            # ContainerPDU requires length >= len(contained_pdus) * header_overhead (8 bytes at 32+32 bits)
            min_length = len(contained_pdus) * 8
            try:
                flync_eth_containers.append(
                    ContainerPDU(
                        name=base_frame.name(),
                        pdu_id=0,
                        length=max(frame_byte_len, min_length),
                        header=ContainerPDUHeader(id_length_bits=32, length_field_bits=32),
                        contained_pdus=contained_pdus,
                    )
                )
            except Exception as e:
                print(f"WARNING: Could not create FLYNC ContainerPDU for {base_frame.name()}: {type(e).__name__}: {e}")

        if not flync_frames_by_channel and not flync_eth_containers:
            return None

        # Build one CANBus per channel
        can_buses = []
        for channel_name, frames in sorted(flync_frames_by_channel.items()):
            baud_rate = self._cluster_speed_for_channel(channel_name)
            fd_enabled = False
            for f in frames:
                if f.type == "can_fd":
                    fd_enabled = True
                    fd_speed = 2_000_000
            try:
                if fd_enabled:
                    can_buses.append(CANBus(name=channel_name, baud_rate=baud_rate, frames=frames, fd_enabled=fd_enabled, fd_baud_rate=fd_speed))
                else:
                    can_buses.append(CANBus(name=channel_name, baud_rate=baud_rate, frames=frames))
            except Exception as e:
                print(f"WARNING: Could not create FLYNC CANBus for {channel_name}: {type(e).__name__}: {e}")

        return FLYNCChannelConfig(
            pdus=flync_pdus,
            can_buses=can_buses if can_buses else None,
            ethernet_pdu_containers=flync_eth_containers if flync_eth_containers else None,
        )

    def create_someip_service(self, name, serviceid, majorver, minorver, methods, events, fields, eventgroups):
        ret = SOMEIPBaseService(name, serviceid, majorver, minorver, methods, events, fields, eventgroups)
        with registry_context(self.__registry):
            self._create_flync_service_interface(name, serviceid, majorver, minorver, methods, events, fields, eventgroups)
        return ret

    def _create_flync_service_interface(self, name, serviceid, majorver, minorver, methods, events, fields, eventgroups):

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

            # Check if all reliable values are the same (ignore absent accessors)
            reliable_values = {
                v for v in (getter_reliable, setter_reliable, notifier_reliable) if v is not None
            }
            if len(reliable_values) > 1:
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
        missing_events = 0
        missing_fields = 0
        for eg in eventgroups.values():
            eg_events = list()
            eg_fields = list()
            for eid in eg.eventids():
                if eid in flync_events:
                    eg_events.append(flync_events[eid])
                else:
                    missing_events += 1
                    print(f"WARNING: Service 0x{serviceid:04x} Evengroup 0x{eg.id():04x} references unknown Event ID: 0x{eid:04x}")
            for fid in eg.fieldids():
                # Fields are referenced by their notifier ID
                if fid in flync_fields_by_notifier:
                    # Add field to eventgroup
                    eg_fields.append(flync_fields_by_notifier[fid])
                else:
                    missing_fields += 1
                    print(f"WARNING: Service 0x{serviceid:04x} Evengroup 0x{eg.id():04x} references unknown Field Notifier ID: 0x{fid:04x}")

            flync_eventgroups.append(
                SOMEIPEventgroup(
                    name=eg.name(),
                    id=eg.id(),
                    # multicast_treshold
                    events=list(eg_events + eg_fields),
                )
            )

        if missing_events or missing_fields:
            print(
                f"WARNING: Service 0x{serviceid:04x}: {missing_events} dangling event refs, "
                f"{missing_fields} dangling field refs across {len(flync_eventgroups)} eventgroup(s)"
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
        with registry_context(self.__registry):
            self._create_flync_ecus_impl()
            channel_config = self._create_flync_channels()
            # general should be optional but FLYNCWorkspace does not respect that
            general_config = FLYNCGeneralConfig(
                someip_config=self.someip_config(),
                tcp_profiles=[self.__flync_tcp_profile],
                channels=channel_config,
            )
            self.__flync_model = FLYNCModel(ecus=self.ecus(), general=general_config, topology=self.topology(), metadata=self.system_metadata())

    def save_flync_model(self, target_dir):
        workspace_config = WorkspaceConfiguration(exclude_unset=False)
        self.__flync_workspace = FLYNCWorkspace("FLYNC_WORKSPACE", workspace_path=target_dir, configuration=workspace_config)
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
        type=lambda x: is_file_valid(parser, x),
        default=None,
        help="Key/Value CSV file",
    )
    parser.add_argument("--generate-switch-port-names", action="store_true")
    parser.add_argument("--generate-vlan-names", action="store_true")
    parser.add_argument(
        "--mcast-list",
        type=lambda x: is_file_valid(parser, x),
        default=None,
        help="Semicolon Separated List of Static Multicast Entries",
    )
    parser.add_argument(
        "--multicast-names",
        type=lambda x: is_file_valid(parser, x),
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

    print("Converting configuration to FLYNC Model (experimental!)")
    args = parse_arguments()

    g_gen_portid = args.generate_switch_port_names

    ecu_name_mapping = {}
    if args.ecu_name_mapping is not None:
        with open(args.ecu_name_mapping, "r") as f:
            ecu_name_mapping = read_csv_to_dict(f)

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
