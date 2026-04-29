#!/usr/bin/python

# Automotive configuration file scripts
# Copyright (C) 2015-2026  Dr. Lars Voelker
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

import os

from flync.model.flync_4_ecu.sockets import IPv4AddressEndpoint
from flync.model.flync_4_someip import (
    SOMEIPEvent,
    SOMEIPField,
    SOMEIPRequestResponseMethod,
    SOMEIPServiceConsumer,
    SOMEIPServiceProvider,
)
from flync.sdk.workspace.flync_workspace import FLYNCWorkspace


class FlyncParser:
    def parse_dir(self, conf_factory, directory, verbose=False):
        """Parse a FLYNC workspace directory and populate conf_factory."""
        workspace_name = os.path.basename(directory.rstrip(os.sep))
        if verbose:
            print(f"Loading FLYNC workspace: {workspace_name} from {directory}")
        workspace = FLYNCWorkspace.load_workspace(workspace_name, directory)
        flync_model = workspace.flync_model
        self._services_by_id = {}  # (service_id, major_version) -> SOMEIPBaseService
        self._ecu_by_name = {}  # ecu_name -> base_ecu
        self._parse_services(conf_factory, flync_model, verbose)
        self._parse_ecus(conf_factory, flync_model, verbose)
        self._parse_switches(conf_factory, flync_model, verbose)

    def _parse_services(self, conf_factory, flync_model, verbose=False):
        if flync_model.general is None:
            return
        if flync_model.general.someip_config is None:
            return
        for svc in flync_model.general.someip_config.services:
            if verbose:
                print(f"  Parsing service: {svc.name} (0x{svc.id:04x})")
            methods = self._parse_methods(conf_factory, svc.methods or [])
            events = self._parse_events(conf_factory, svc.events or [])
            fields = self._parse_fields(conf_factory, svc.fields or [])
            eventgroups = self._parse_eventgroups(conf_factory, svc.eventgroups or [])
            svc_obj = conf_factory.create_someip_service(
                svc.name,
                svc.id,
                svc.major_version,
                svc.minor_version,
                methods,
                events,
                fields,
                eventgroups,
            )
            self._services_by_id[(svc.id, svc.major_version)] = svc_obj

    def _parse_methods(self, conf_factory, flync_methods):
        methods = {}
        for method in flync_methods:
            if isinstance(method, SOMEIPRequestResponseMethod):
                calltype = "REQUEST_RESPONSE"
                outparams = [self._parse_parameter(conf_factory, p, i) for i, p in enumerate(method.output_parameters or [])]
            else:
                calltype = "FIRE_AND_FORGET"
                outparams = []
            inparams = [self._parse_parameter(conf_factory, p, i) for i, p in enumerate(method.input_parameters or [])]
            m = conf_factory.create_someip_service_method(
                method.name,
                method.id,
                calltype,
                method.reliable,
                inparams,
                outparams,
            )
            methods[method.id] = m
        return methods

    def _parse_events(self, conf_factory, flync_events):
        events = {}
        for event in flync_events:
            params = [self._parse_parameter(conf_factory, p, i) for i, p in enumerate(event.parameters or [])]
            e = conf_factory.create_someip_service_event(
                event.name,
                event.id,
                event.reliable,
                params,
            )
            events[event.id] = e
        return events

    def _parse_fields(self, conf_factory, flync_fields):
        fields = {}
        for field in flync_fields:
            params = [self._parse_parameter(conf_factory, p, i) for i, p in enumerate(field.parameters or [])]
            f = conf_factory.create_someip_service_field(
                field.name,
                field.getter_id,
                field.setter_id,
                field.notifier_id,
                field.reliable,
                field.reliable,
                field.reliable,
                params,
                -1,
                -1,
                -1,
                -1,
                -1,
                -1,
                -1,
                -1,
            )
            key = field.notifier_id or field.getter_id or field.setter_id
            if key is not None:
                fields[key] = f
        return fields

    def _parse_eventgroups(self, conf_factory, flync_eventgroups):
        eventgroups = {}
        for eg in flync_eventgroups:
            eventids = set()
            fieldids = set()
            for item in eg.events or []:
                if isinstance(item, SOMEIPEvent):
                    eventids.add(item.id)
                elif isinstance(item, SOMEIPField):
                    if item.notifier_id is not None:
                        fieldids.add(item.notifier_id)
            eg_obj = conf_factory.create_someip_service_eventgroup(
                eg.name,
                eg.id,
                sorted(eventids),
                sorted(fieldids),
            )
            eventgroups[eg.id] = eg_obj
        return eventgroups

    def _parse_parameter(self, conf_factory, param, position):
        datatype = self._convert_datatype(conf_factory, param.datatype)
        return conf_factory.create_someip_parameter(
            position,
            param.name,
            param.description or "",
            True,  # we currently only support mandatory in FLYNC
            datatype,
            None,
        )

    @staticmethod
    def _normalize_string_encoding(encoding):
        """Map FLYNC encoding names to (chartype, bigendian) as expected by the text factory.

        FLYNC stores directional UTF-16 names ("UTF-16BE", "UTF-16LE") while FIBEX uses
        the plain "UTF-16" chartype with a separate bigendian flag.
        """
        if encoding == "UTF-16BE":
            return "UTF-16", True
        elif encoding == "UTF-16LE":
            return "UTF-16", False
        else:
            return encoding, True

    def _convert_datatype(self, conf_factory, dt):
        bigendian = getattr(dt, "endianness", "BE") == "BE"

        match dt.type:
            case "uint8":
                return conf_factory.create_someip_parameter_basetype(dt.name, dt.type, bigendian, 8, 8)
            case "uint16":
                return conf_factory.create_someip_parameter_basetype(dt.name, dt.type, bigendian, 16, 16)
            case "uint32":
                return conf_factory.create_someip_parameter_basetype(dt.name, dt.type, bigendian, 32, 32)
            case "uint64":
                return conf_factory.create_someip_parameter_basetype(dt.name, dt.type, bigendian, 64, 64)
            case "int8":
                return conf_factory.create_someip_parameter_basetype(dt.name, dt.type, bigendian, 8, 8)
            case "int16":
                return conf_factory.create_someip_parameter_basetype(dt.name, dt.type, bigendian, 16, 16)
            case "int32":
                return conf_factory.create_someip_parameter_basetype(dt.name, dt.type, bigendian, 32, 32)
            case "int64":
                return conf_factory.create_someip_parameter_basetype(dt.name, dt.type, bigendian, 64, 64)
            case "float32":
                return conf_factory.create_someip_parameter_basetype(dt.name, dt.type, bigendian, 32, 32)
            case "float64":
                return conf_factory.create_someip_parameter_basetype(dt.name, dt.type, bigendian, 64, 64)
            case "boolean":
                return conf_factory.create_someip_parameter_basetype(dt.name, dt.type, True, 8, 8)
            case "fixed_length_string":
                encoding, str_bigendian = self._normalize_string_encoding(dt.encoding)
                return conf_factory.create_someip_parameter_string(
                    dt.name,
                    encoding,
                    str_bigendian,
                    dt.length,
                    dt.length,
                    "ZERO",
                    dt.length_of_length_field,
                    0,
                )
            case "dynamic_length_string":
                encoding, str_bigendian = self._normalize_string_encoding(dt.encoding)
                # Map bit_alignment=8 (FLYNC default/"no alignment") back to pad_to=0 (FIBEX convention)
                pad_to = dt.bit_alignment if dt.bit_alignment > 8 else 0
                return conf_factory.create_someip_parameter_string(
                    dt.name,
                    encoding,
                    str_bigendian,
                    dt.min_length if dt.min_length is not None else 0,
                    dt.max_length if dt.max_length is not None else -1,
                    "ZERO",
                    dt.length_of_length_field,
                    pad_to,
                )
            case "enum":
                base = dt.base_type
                base_bigendian = getattr(base, "endianness", "BE") == "BE"
                _bit_sizes = {
                    "uint8": 8,
                    "uint16": 16,
                    "uint32": 32,
                    "uint64": 64,
                    "int8": 8,
                    "int16": 16,
                    "int32": 32,
                    "int64": 64,
                }
                child = conf_factory.create_someip_parameter_basetype(
                    base.name,
                    base.type,
                    base_bigendian,
                    _bit_sizes.get(base.type, 8),
                    _bit_sizes.get(base.type, 8),
                )
                items = [
                    conf_factory.create_someip_parameter_enumeration_item(entry.value, entry.name, entry.description or "")
                    for entry in (dt.entries or [])
                ]
                return conf_factory.create_someip_parameter_enumeration(dt.name, items, child)
            case "struct":
                members = {}
                for pos, member in enumerate(dt.members or []):
                    member_name = member.member_name if member.member_name is not None else member.name
                    m_obj = conf_factory.create_someip_parameter_struct_member(
                        pos, member_name, True, self._convert_datatype(conf_factory, member), None
                    )
                    members[pos] = m_obj
                return conf_factory.create_someip_parameter_struct(dt.name, dt.length_of_length_field, dt.bit_alignment, members)
            case "union":
                members = {}
                for m in dt.members or []:
                    m_obj = conf_factory.create_someip_parameter_union_member(
                        m.index, m.name, m.mandatory, self._convert_datatype(conf_factory, m.type)
                    )
                    members[m.index] = m_obj
                return conf_factory.create_someip_parameter_union(
                    dt.name,
                    dt.length_of_length_field,
                    dt.length_of_type_field,
                    dt.bit_alignment,
                    members,
                )
            case "array":
                dims = {}
                for i, dim in enumerate(dt.dimensions or []):
                    if dim.kind == "fixed":
                        lower = dim.length or 0
                        upper = dim.length or 0
                        lol = 0
                    else:
                        lower = dim.lower_limit or 0
                        upper = dim.upper_limit or 0
                        lol = dim.length_of_length_field or 0
                    pad = dim.bit_alignment or 0
                    dim_num = i + 1  # FIBEX uses 1-based dimension numbering
                    dims[dim_num] = conf_factory.create_someip_parameter_array_dim(dim_num, lower, upper, lol, pad)
                child = self._convert_datatype(conf_factory, dt.element_type)
                return conf_factory.create_someip_parameter_array(dt.name, dims, child)
            case "bitfield":
                items = [conf_factory.create_someip_parameter_bitfield_item(entry.bitposition, entry.name) for entry in (dt.fields or [])]
                # Create a basetype child based on bitfield length
                length = getattr(dt, "length", 8)
                child = conf_factory.create_someip_parameter_basetype(dt.name, dt.type, True, length, length)
                return conf_factory.create_someip_parameter_bitfield(dt.name, items, child)
            case "typedef":
                child = self._convert_datatype(conf_factory, dt.datatyperef)
                return conf_factory.create_someip_parameter_typedef(dt.name, dt.name, child)
            case _:
                # Fallback for unknown types: treat as UINT8
                return conf_factory.create_someip_parameter_basetype(getattr(dt, "name", "unknown"), "A_UINT8", True, 8, 8)

    def _parse_ecus(self, conf_factory, flync_model, verbose=False):
        for ecu in flync_model.ecus:
            if verbose:
                print(f"  Parsing ECU: {ecu.name}")
            controllers = []
            for controller in ecu.controllers:
                interfaces = []
                for ctrl_iface in controller.interfaces:
                    for virt_iface in ctrl_iface.virtual_interfaces:
                        ips = []
                        for addr in virt_iface.addresses:
                            ip_str = str(addr.address)
                            ips.append(ip_str)
                            if isinstance(addr, IPv4AddressEndpoint):
                                conf_factory.add_ipv4_address_config(ip_str, str(addr.ipv4netmask))
                            elif hasattr(addr, "ipv6prefix"):
                                # Handle IPv6AddressEndpoint
                                conf_factory.add_ipv6_address_config(ip_str, addr.ipv6prefix)
                        sockets = self._parse_sockets_for_vlan(conf_factory, ecu, virt_iface.vlanid, set(ips))
                        iface = conf_factory.create_interface(
                            virt_iface.name,
                            virt_iface.vlanid,
                            ips,
                            sockets,
                            {},
                            {},
                            None,
                        )
                        interfaces.append(iface)
                ctrl = conf_factory.create_controller(controller.name, interfaces)
                controllers.append(ctrl)
            base_ecu = conf_factory.create_ecu(ecu.name, controllers)
            self._ecu_by_name[ecu.name] = base_ecu

    def _parse_sockets_for_vlan(self, conf_factory, ecu, vlanid, virt_ips=None):
        sockets = []
        for socket_container in ecu.sockets or []:
            if socket_container.vlan_id != vlanid:
                continue
            for socket in socket_container.sockets or []:
                # Filter unicast sockets by endpoint IP so that only the owning
                # virtual interface (controller) shows them, not every interface
                # on the same VLAN.
                print(f"DEBUG: _parse_sockets_for_vlan {ecu.name=} {socket.name=} {virt_ips=}")
                if virt_ips and socket.endpoint_type != "multicast":
                    if str(socket.endpoint_address) not in virt_ips:
                        continue
                proto = socket.protocol
                serviceinstances = []
                serviceinstanceclients = []
                eventhandlers = []
                eventgroupreceivers = []

                for dep_union in socket.deployments or []:
                    dep = dep_union.root
                    if isinstance(dep, SOMEIPServiceProvider):
                        svc_id = dep.service.id if hasattr(dep.service, "id") else int(dep.service)
                        svc_obj = self._services_by_id.get((svc_id, dep.major_version))
                        if svc_obj is not None:
                            try:
                                si = conf_factory.create_someip_service_instance(svc_obj, dep.instance_id, 1)
                                serviceinstances.append(si)
                                provided_names = dep.provided_eventgroups
                                for eg in svc_obj.eventgroups().values():
                                    if provided_names is None or eg.name() in provided_names:
                                        sender = conf_factory.create_someip_service_eventgroup_sender(si, eg.id())
                                        eventhandlers.append(sender)
                            except Exception as e:
                                print(f"WARNING: Could not create service instance: {e}")
                    elif isinstance(dep, SOMEIPServiceConsumer):
                        svc_id = dep.service.id if hasattr(dep.service, "id") else int(dep.service)
                        svc_obj = self._services_by_id.get((svc_id, dep.major_version))
                        if svc_obj is not None:
                            try:
                                sic = conf_factory.create_someip_service_instance_client(svc_obj, dep.instance_id, 1, None)
                                serviceinstanceclients.append(sic)
                                consumed_names = dep.consumed_eventgroups
                                for eg in svc_obj.eventgroups().values():
                                    if consumed_names is None or eg.name() in consumed_names:
                                        receiver = conf_factory.create_someip_service_eventgroup_receiver(sic, eg.id(), None)
                                        eventgroupreceivers.append(receiver)
                            except Exception as e:
                                print(f"WARNING: Could not create service instance client: {e}")

                s = conf_factory.create_socket(
                    socket.name,
                    str(socket.endpoint_address),
                    proto,
                    socket.port_no,
                    serviceinstances,
                    serviceinstanceclients,
                    eventhandlers,
                    eventgroupreceivers,
                )
                sockets.append(s)
        return sockets

    def _find_unused_controller(self, base_ecu):
        """Find a controller on the ECU that is not yet connected to a switch port.
        Returns the controller or None if all are used."""
        for ctrl in base_ecu.controllers():
            if ctrl.get_switch_port() is None:
                return ctrl
        return None

    def _parse_switches(self, conf_factory, flync_model, verbose=False):
        """Parse FLYNC switches and reconstruct BaseSwitchPort connections."""
        # Pass 1: Create all BaseSwitchPorts (unconnected) and BaseSwitches.
        # swport_map: (ecu_name, sp_name) -> BaseSwitchPort
        swport_map = {}

        for ecu in flync_model.ecus:
            if not ecu.switches:
                continue
            base_ecu = self._ecu_by_name.get(ecu.name)
            if base_ecu is None:
                continue
            for sw in ecu.switches:
                if verbose:
                    print(f"  Parsing switch: {sw.name} in ECU {ecu.name}")
                sp_list = []
                for flync_sp in sw.ports:
                    # Collect VLAN memberships for this port from the switch's VLANEntry list.
                    vlans = []
                    for vlan_entry in sw.vlans or []:
                        if flync_sp.name in (vlan_entry.ports or []):
                            # Convert FLYNC's VLAN ID 0 (untagged) to None for FIBEX compatibility
                            vlan_id = vlan_entry.id if vlan_entry.id != 0 else None
                            vlans.append(conf_factory.create_vlan(vlan_entry.name, vlan_id, vlan_entry.default_priority))
                    sp = conf_factory.create_switch_port(flync_sp.name, None, None, None, vlans)
                    sp_list.append(sp)
                    swport_map[(ecu.name, flync_sp.name)] = sp
                conf_factory.create_switch(sw.name, base_ecu, sp_list)

        # Pass 2: Wire connections between switch ports.
        for ecu in flync_model.ecus:
            if not ecu.switches:
                continue
            base_ecu = self._ecu_by_name.get(ecu.name)
            if base_ecu is None:
                continue
            for sw in ecu.switches:
                for flync_sp in sw.ports:
                    base_sp = swport_map.get((ecu.name, flync_sp.name))
                    if base_sp is None:
                        continue

                    comp = flync_sp.connected_component

                    if comp is None:
                        # Management port (no topology entry): connect to an unused controller.
                        if base_sp.connected_to_ecu_ctrl() is None:
                            unused_ctrl = self._find_unused_controller(base_ecu)
                            if unused_ctrl is not None:
                                base_sp.set_connected_ctrl(unused_ctrl)
                            elif verbose:
                                print(f"WARNING: No unused controller available for switch port {base_sp.name()} on ECU {base_ecu.name()}")

                    elif comp.type == "controller_interface":
                        # CPU/management port wired via SwitchPortToControllerInterface.
                        # Find the matching FIBEX BaseController by name and connect.
                        if base_sp.connected_to_ecu_ctrl() is None:
                            try:
                                flync_ctrl = comp.get_controller()
                            except Exception:
                                flync_ctrl = None
                            if flync_ctrl is not None:
                                for base_ctrl in base_ecu.controllers():
                                    if base_ctrl.name() == flync_ctrl.name:
                                        base_sp.set_connected_ctrl(base_ctrl)
                                        break
                            elif verbose:
                                print(f"WARNING: Could not resolve controller for CPU switch port {base_sp.name()} on ECU {base_ecu.name()}")

                    elif comp.type == "ecu_port":
                        # Find the external ECUPort peer via connected_components.
                        peer_ecu_port = next(
                            (c for c in comp.connected_components if c.type == "ecu_port"),
                            None,
                        )
                        if peer_ecu_port is None:
                            continue

                        # Check if peer has an internal switch port (switch-to-switch).
                        peer_internal = peer_ecu_port.get_internal_connected_component(None)

                        if peer_internal is not None and peer_internal.type == "switch_port":
                            # Switch-to-switch connection.
                            peer_ecu_obj = peer_ecu_port.ecu
                            if peer_ecu_obj is None:
                                continue
                            peer_base_sp = swport_map.get((peer_ecu_obj.name, peer_internal.name))
                            if peer_base_sp is not None:
                                if base_sp.connected_to_port() is None:
                                    base_sp.set_connected_port(peer_base_sp)
                                if peer_base_sp.connected_to_port() is None:
                                    peer_base_sp.set_connected_port(base_sp)
                        else:
                            # Incoherent: peer ECU has no switch port → connect to peer's controller.
                            peer_ecu_obj = peer_ecu_port.ecu
                            if peer_ecu_obj is None:
                                continue
                            peer_base_ecu = self._ecu_by_name.get(peer_ecu_obj.name)
                            if peer_base_ecu is not None:
                                if base_sp.connected_to_ecu_ctrl() is None:
                                    unused_ctrl = self._find_unused_controller(peer_base_ecu)
                                    if unused_ctrl is not None:
                                        base_sp.set_connected_ctrl(unused_ctrl)
                                    elif verbose:
                                        print(
                                            f"WARNING: No unused controller available for switch port {base_sp.name()} on ECU {peer_base_ecu.name()}"
                                        )
