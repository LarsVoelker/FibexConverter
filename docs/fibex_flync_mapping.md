# FIBEX ↔ FLYNC Mapping Reference

This document describes how automotive network configuration concepts map between FIBEX 4 (XML) and the FLYNC model. The FibexConverter project uses **configuration base classes** as an intermediate representation, so every mapping passes through them.

```
FIBEX XML  ──(fibex_parser.py)──►  Base Classes  ──(configuration_to_flync.py)──►  FLYNC files
FLYNC files  ──(flync_parser.py)──►  Base Classes  ──(configuration_to_*.py)──►  outputs
```

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [ECU and Topology Mapping](#ecu-and-topology-mapping)
3. [SOME/IP Service Mapping](#someip-service-mapping)
4. [SOME/IP Method Mapping](#someip-method-mapping)
5. [SOME/IP Event Mapping](#someip-event-mapping)
6. [SOME/IP Field Mapping](#someip-field-mapping)
7. [SOME/IP Eventgroup Mapping](#someip-eventgroup-mapping)
8. [Datatype Mapping](#datatype-mapping)
9. [String Mapping](#string-mapping)
10. [Complex Datatype Mapping](#complex-datatype-mapping)
11. [Limitations and Gaps](#limitations-and-gaps)

---

## Architecture Overview

| Layer | FIBEX | Base Class | FLYNC |
|---|---|---|---|
| Parser | `fibex_parser.py` | — | `flync_parser.py` |
| Writer | — | — | `configuration_to_flync.py` |
| Model | XML elements (`fx:*`, `service:*`, `ethernet:*`) | `configuration_base_classes.py` | `external/FLYNC/src/flync/model/` |
| Workspace | Single `.xml` file or directory of `.xml` files | — | Directory of `.flync.yaml` files |

---

## ECU and Topology Mapping

### ECU

| FIBEX element / attribute | Base class | FLYNC class / field |
|---|---|---|
| `<fx:COMPONENT>` | `BaseECU` | `ECU` |
| `<fx:SHORT-NAME>` | `BaseECU.name()` | `ECU.name` |
| controllers list | `BaseECU.controllers()` | `ECU.controllers` |
| switches list | `BaseECU.switches()` | `ECU.switches` |
| — | — | `ECU.ports` (physical MDI ports) |
| — | — | `ECU.topology` (internal connectivity) |
| — | — | `ECU.ecu_metadata` |

### Controller

| FIBEX element / attribute | Base class | FLYNC class / field |
|---|---|---|
| `<fx:CONNECTOR>` | `BaseController` | `Controller` |
| `<fx:SHORT-NAME>` | `BaseController.name()` | `Controller.name` |
| interfaces list | `BaseController.interfaces()` | `Controller.interfaces` (`ControllerInterface` list) |

### Network Interface / Virtual Interface

| FIBEX element / attribute | Base class | FLYNC class / field |
|---|---|---|
| `<fx:CHANNEL>` / VLAN entry | `BaseInterface` | `VirtualControllerInterface` (inside `ControllerInterface`) |
| VLAN name | `BaseInterface.vlanname()` | `VirtualControllerInterface.name` |
| VLAN ID | `BaseInterface.vlanid()` | `VirtualControllerInterface.vlanid` |
| IP addresses | `BaseInterface.ips()` | `VirtualControllerInterface.addresses` (`IPv4AddressEndpoint` / `IPv6AddressEndpoint`) |
| Frame triggerings in/out | `BaseInterface.frame_triggerings_in/out()` | — (not represented in FLYNC) |

### Switch

| FIBEX element / attribute | Base class | FLYNC class / field |
|---|---|---|
| Integrated switch component | `BaseSwitch` | `Switch` (inside `ECU.switches`) |
| Switch port | `BaseSwitchPort` | `SwitchPort` |
| Port ID | `BaseSwitchPort.portid()` | `SwitchPort.name` (derived: `<ecu>_<switch>_<portid>`) |
| Port index | — | `SwitchPort.silicon_port_no` |
| Default VLAN | `BaseSwitchPort.vlans()[0]` | `SwitchPort.default_vlan_id` |
| VLAN memberships | `BaseSwitchPort.vlans_objs()` | `VLANEntry` list inside `Switch` |

### Sockets

| FIBEX element / attribute | Base class | FLYNC class / field |
|---|---|---|
| Socket definition | `BaseSocket` | `SocketTCP` or `SocketUDP` (inside `SocketContainer`) |
| Socket name | `BaseSocket.name()` | `Socket.name` |
| IP address | `BaseSocket.ip()` | `Socket.endpoint_address` |
| Protocol | `BaseSocket.proto()` (`"TCP"` / `"UDP"`) | `SocketTCP.protocol = "tcp"` / `SocketUDP.protocol = "udp"` |
| Port number | `BaseSocket.portnumber()` | `Socket.port_no` |
| VLAN association | via `BaseInterface` | `SocketContainer.vlan_id` |
| Service deployments | `BaseSocket.instances()` | `Socket.deployments` (`SOMEIPServiceProvider` / `SOMEIPServiceConsumer`) |

### External Topology Connections

| FIBEX element / attribute | Base class | FLYNC class / field |
|---|---|---|
| Physical link between ports | `BaseSwitchPort.connected_to_port()` | `ExternalConnection` (in `SystemTopology`) |
| Switch port → ECU controller | `BaseSwitchPort.connected_to_ecu_ctrl()` | `ExternalConnection` (in `SystemTopology`) |
| ECUPort name | derived from switch port | `ExternalConnection.ecu1_port` / `ecu2_port` |
| MDI role (master/slave) | heuristic: alphabetically smaller ECU = master | `ECUPort.mdi_config.mode` |

### Internal Topology

| FIBEX concept | Base class | FLYNC class / field |
|---|---|---|
| Controller ↔ switch port connection | `BaseController.get_switch_port()` | `ECUPortToSwitchPort` (inside `InternalTopology`) |
| ECU port | derived from switch port | `ECUPort` |
| Switch port reference | `BaseSwitchPort` | `SwitchPort` reference |

---

## SOME/IP Service Mapping

| FIBEX element / attribute | Base class | FLYNC class / field |
|---|---|---|
| `<service:SERVICE-INTERFACE>` | `SOMEIPBaseService` | `SOMEIPServiceInterface` |
| `<service:SERVICE-IDENTIFIER>` | `SOMEIPBaseService.serviceid()` | `SOMEIPServiceInterface.id` |
| `<service:MAJOR-VERSION>` | `SOMEIPBaseService.majorversion()` | `SOMEIPServiceInterface.major_version` |
| `<service:MINOR-VERSION>` | `SOMEIPBaseService.minorversion()` | `SOMEIPServiceInterface.minor_version` |
| `<service:SHORT-NAME>` | `SOMEIPBaseService.name()` | `SOMEIPServiceInterface.name` |
| methods dict | `SOMEIPBaseService.methods()` | `SOMEIPServiceInterface.methods` |
| events dict | `SOMEIPBaseService.events()` | `SOMEIPServiceInterface.events` |
| fields dict | `SOMEIPBaseService.fields()` | `SOMEIPServiceInterface.fields` |
| eventgroups dict | `SOMEIPBaseService.eventgroups()` | `SOMEIPServiceInterface.eventgroups` |
| — | — | `SOMEIPServiceInterface.meta` (`SOMEIPServiceMetadata`) |

---

## SOME/IP Method Mapping

| FIBEX element / attribute | Base class | FLYNC class / field |
|---|---|---|
| `<service:METHOD>` | `SOMEIPBaseServiceMethod` | `SOMEIPRequestResponseMethod` or `SOMEIPFireAndForgetMethod` |
| `<service:METHOD-IDENTIFIER>` | `SOMEIPBaseServiceMethod.methodid()` | `SOMEIPMethod.id` |
| `<service:SHORT-NAME>` | `SOMEIPBaseServiceMethod.name()` | `SOMEIPMethod.name` |
| `<service:CALL-SEMANTIC>` | `SOMEIPBaseServiceMethod.calltype()` | `SOMEIPMethod.type` (see table below) |
| `<service:RELIABLE>` | `SOMEIPBaseServiceMethod.reliable()` | `SOMEIPMethod.reliable` |
| in-parameters | `SOMEIPBaseServiceMethod.inparams()` | `SOMEIPMethod.input_parameters` |
| out-parameters | `SOMEIPBaseServiceMethod.outparams()` | `SOMEIPRequestResponseMethod.output_parameters` |
| request debounce | `SOMEIPBaseServiceMethod.debounce_time_req()` | referenced via `SOMEIPMethod.someip_timing` profile |
| request max retention | `SOMEIPBaseServiceMethod.max_buffer_retention_time_req()` | referenced via timing profile |
| response max retention | `SOMEIPBaseServiceMethod.max_buffer_retention_time_res()` | referenced via timing profile |

### Call Type / Method Type Mapping

| FIBEX `CALL-SEMANTIC` | Base class `calltype()` | FLYNC class | FLYNC `type` |
|---|---|---|---|
| `REQUEST_RESPONSE` | `"REQUEST_RESPONSE"` | `SOMEIPRequestResponseMethod` | `"request_response"` |
| `FIRE_AND_FORGET` | `"FIRE_AND_FORGET"` | `SOMEIPFireAndForgetMethod` | `"fire_and_forget"` |

---

## SOME/IP Event Mapping

| FIBEX element / attribute | Base class | FLYNC class / field |
|---|---|---|
| `<service:EVENT>` | `SOMEIPBaseServiceEvent` | `SOMEIPEvent` |
| `<service:METHOD-IDENTIFIER>` | `SOMEIPBaseServiceEvent.methodid()` | `SOMEIPEvent.id` |
| `<service:SHORT-NAME>` | `SOMEIPBaseServiceEvent.name()` | `SOMEIPEvent.name` |
| `<service:RELIABLE>` | `SOMEIPBaseServiceEvent.reliable()` | `SOMEIPEvent.reliable` |
| parameters | `SOMEIPBaseServiceEvent.params()` | `SOMEIPEvent.parameters` |
| debounce time | `SOMEIPBaseServiceEvent.debounce_time()` | referenced via `SOMEIPEvent.someip_timing` profile |
| max retention | `SOMEIPBaseServiceEvent.max_buffer_retention_time()` | referenced via timing profile |

---

## SOME/IP Field Mapping

| FIBEX element / attribute | Base class | FLYNC class / field |
|---|---|---|
| `<service:FIELD>` | `SOMEIPBaseServiceField` | `SOMEIPField` |
| `<service:SHORT-NAME>` | `SOMEIPBaseServiceField.name()` | `SOMEIPField.name` |
| Getter method ID | `SOMEIPBaseServiceField.getter().methodid()` | `SOMEIPField.getter_id` |
| Setter method ID | `SOMEIPBaseServiceField.setter().methodid()` | `SOMEIPField.setter_id` |
| Notifier event ID | `SOMEIPBaseServiceField.notifierid()` | `SOMEIPField.notifier_id` |
| Reliability | from getter / setter / notifier | `SOMEIPField.reliable` |
| parameters | `SOMEIPBaseServiceField.params()` | `SOMEIPField.parameters` |

> **Note:** FLYNC collapses getter, setter, and notifier into a single `SOMEIPField` object. The FIBEX model stores getter and setter as `SOMEIPBaseServiceMethod` objects and the notifier as a `SOMEIPBaseServiceEvent`.  FLYNC only exposes a single `reliable` flag; a warning is emitted during conversion if getter, setter, and notifier have mismatched reliability values.

---

## SOME/IP Eventgroup Mapping

| FIBEX element / attribute | Base class | FLYNC class / field |
|---|---|---|
| `<service:EVENT-GROUP>` | `SOMEIPBaseServiceEventgroup` | `SOMEIPEventgroup` |
| `<service:EVENT-GROUP-IDENTIFIER>` | `SOMEIPBaseServiceEventgroup.id()` | `SOMEIPEventgroup.id` |
| `<service:SHORT-NAME>` | `SOMEIPBaseServiceEventgroup.name()` | `SOMEIPEventgroup.name` |
| referenced event IDs | `SOMEIPBaseServiceEventgroup.eventids()` | `SOMEIPEventgroup.events` (resolved `SOMEIPEvent` objects) |
| referenced field notifier IDs | `SOMEIPBaseServiceEventgroup.fieldids()` | `SOMEIPEventgroup.events` (resolved `SOMEIPField` objects) |

> **Note:** FLYNC's `SOMEIPEventgroup.events` holds a mixed list of `SOMEIPEvent` and `SOMEIPField` objects. In FIBEX, fields are referenced by their notifier ID; there is no separate list for fields in an eventgroup.

---

## Datatype Mapping

### Primitive / Base Types

| FIBEX `ENCODING` / type string | Base class `datatype()` | FLYNC class | FLYNC `type` | Bit size | Signed |
|---|---|---|---|---|---|
| `A_UINT8` | `"A_UINT8"` | `UInt8` | `"uint8"` | 8 | No |
| `A_UINT16` | `"A_UINT16"` | `UInt16` | `"uint16"` | 16 | No |
| `A_UINT32` | `"A_UINT32"` | `UInt32` | `"uint32"` | 32 | No |
| `A_UINT64` | `"A_UINT64"` | `UInt64` | `"uint64"` | 64 | No |
| `A_INT8` | `"A_INT8"` | `Int8` | `"int8"` | 8 | Yes |
| `A_INT16` | `"A_INT16"` | `Int16` | `"int16"` | 16 | Yes |
| `A_INT32` | `"A_INT32"` | `Int32` | `"int32"` | 32 | Yes |
| `A_INT64` | `"A_INT64"` | `Int64` | `"int64"` | 64 | Yes |
| `A_FLOAT32` | `"A_FLOAT32"` | `Float32` | `"float32"` | 32 | Yes |
| `A_FLOAT64` | `"A_FLOAT64"` | `Float64` | `"float64"` | 64 | Yes |
| — (no FIBEX equivalent) | `"A_UINT8"` mapped to `Boolean` | `Boolean` | `"boolean"` | 8 | No |

> **Endianness:** FIBEX uses a `HIGH-LOW-BYTE-ORDER` boolean. FLYNC uses `"BE"` (big-endian) or `"LE"` (little-endian).
> `HIGH-LOW-BYTE-ORDER = true` → `bigendian = true` → FLYNC `endianness = "BE"`.
> UInt8 and Int8 are always `"BE"` since byte order is irrelevant for single-byte types.

---

## String Mapping

| Attribute | FIBEX / Base class | FLYNC `FixedLengthString` | FLYNC `DynamicLengthString` |
|---|---|---|---|
| Condition | `lowerlimit == upperlimit` | ✓ | — |
| Condition | `lowerlimit != upperlimit` | — | ✓ |
| Length | `lowerlimit` / `upperlimit` | `length = upperlimit` | — (no length field) |
| Length-of-length field | `BaseInterface.length_of_length()` | `length_of_length_field` | `length_of_length_field` |
| Encoding | `chartype()` (e.g. `"UTF-8"`, `"UTF-16"`) | `encoding` | `encoding` |
| Byte order for UTF-16 | `bigendian()` | absorbed into `"UTF-16BE"` / `"UTF-16LE"` | absorbed into `"UTF-16BE"` / `"UTF-16LE"` |
| Padding alignment | `pad_to()` | — | `bit_alignment` (minimum 8 if 0) |

---

## Complex Datatype Mapping

### Struct

| Attribute | Base class (`SOMEIPBaseParameterStruct`) | FLYNC (`Struct`) |
|---|---|---|
| Name | `name()` | `name` |
| Members | `members()` — `dict[int, SOMEIPBaseParameterStructMember]` | `members` — `List[AllTypes]` (ordered, each member's `name` is preserved) |
| Length-of-length | `length_of_length()` | `length_of_length_field` |
| Padding alignment | `pad_to()` | `bit_alignment` (minimum 8 if 0) |

### Union

| Attribute | Base class (`SOMEIPBaseParameterUnion`) | FLYNC (`Union`) |
|---|---|---|
| Name | `name()` | `name` |
| Members | `members()` — `dict[int, SOMEIPBaseParameterUnionMember]` | `members` — `List[UnionMember]` |
| Member index | `SOMEIPBaseParameterUnionMember.index()` | `UnionMember.index` |
| Length-of-length | `length_of_length()` | `length_of_length_field` (default 32) |
| Length-of-type | `length_of_type()` | `length_of_type_field` (default 32) |
| Padding alignment | `pad_to()` | `bit_alignment` (minimum 8 if 0) |

### Array

| Attribute | Base class (`SOMEIPBaseParameterArray`) | FLYNC (`ArrayType`) |
|---|---|---|
| Name | `name()` | `name` |
| Dimensions | `dims()` — `dict[int, SOMEIPBaseParameterArrayDim]` | `dimensions` — `List[ArrayDimension]` |
| Element type | `child()` | `element_type` |

#### Array Dimension Mapping

| Attribute | Base class (`SOMEIPBaseParameterArrayDim`) | FLYNC (`ArrayDimension`) |
|---|---|---|
| Kind | `lowerlimit() == upperlimit()` → `"fixed"`, else `"dynamic"` | `kind` (`"fixed"` / `"dynamic"`) |
| Fixed length | `upperlimit()` | `length` (only if `kind="fixed"`) |
| Lower bound | `lowerlimit()` | `lower_limit` |
| Upper bound | `upperlimit()` | `upper_limit` |
| Length-of-length | `length_of_length()` | `length_of_length_field` (only if `kind="dynamic"`) |
| Padding | `pad_to()` | `bit_alignment` (only if non-zero) |

### Enumeration

| Attribute | Base class (`SOMEIPBaseParameterEnumeration`) | FLYNC (`Enum`) |
|---|---|---|
| Name | `name()` | `name` |
| Base type | `child()` | `base_type` (an integer type, e.g. `UInt8`) |
| Entries | `items()` — list | `entries` — `List[EnumEntry]` |
| Entry value | `SOMEIPBaseParameterEnumerationItem.value()` | `EnumEntry.value` |
| Entry name | `SOMEIPBaseParameterEnumerationItem.name()` | `EnumEntry.name` |
| Entry description | `SOMEIPBaseParameterEnumerationItem.desc()` | `EnumEntry.description` |

### Bitfield

| Attribute | Base class (`SOMEIPBaseParameterBitfield`) | FLYNC (`Bitfield`) |
|---|---|---|
| Name | `name()` | `name` |
| Underlying integer type | `child()` — `SOMEIPBaseParameterBasetype` | `length` (derived from `bitlength_encoded_type()`) |
| Entries | `items()` — list | `fields` — `List[BitfieldEntry]` |
| Entry bit position | `SOMEIPBaseParameterBitfieldItem.bit_number()` | `BitfieldEntry.bitposition` |
| Entry name | `SOMEIPBaseParameterBitfieldItem.name()` | `BitfieldEntry.name` |

### Typedef

| Attribute | Base class (`SOMEIPBaseParameterTypedef`) | FLYNC (`Typedef`) |
|---|---|---|
| Alias name | `name()` | `name` |
| Original name | `name2()` | `name` (same field; FLYNC uses one name) |
| Referenced type | `child()` | `datatyperef` |

---

## Limitations and Gaps

The following concepts exist in one format but have no direct counterpart in the other.

### FIBEX → FLYNC (concepts lost or approximated)

| FIBEX concept | Reason not mapped |
|---|---|
| CAN / FlexRay frames, PDUs, signals | FLYNC is Ethernet/SOME/IP focused; no CAN or FlexRay model |
| Frame triggerings | Not part of the FLYNC model |
| Service instances (client/server sockets) | Converted to `SOMEIPServiceProvider`/`SOMEIPServiceConsumer` deployments on sockets, but only when socket data is present |
| SOME/IP-TP configuration | Partially: base class carries `tlv` flag; full TP segment length not mapped |
| Shortened datatypes (`bitlength_basetype != bitlength_encoded_type`) | A warning is printed; FLYNC uses a single `bit_size` |
| MDI role assignment | Determined heuristically (alphabetically smaller ECU name = master); not stored in FIBEX |
| E2E protection | Present in FLYNC (`SOMEIPEvent.e2e`, `SOMEIPField.notifier_e2e`) but not sourced from FIBEX |

### FLYNC → FIBEX (concepts not yet reverse-mapped)

| FLYNC concept | Reason not mapped |
|---|---|
| `ECUPort` MDI/MII physical layer config | No equivalent in `BaseECU`; topology connects ECUs only |
| `SOMEIPSDDeployment` (Service Discovery socket) | No equivalent in base socket model |
| SOME/IP timing profiles (`SOMEIPTimingProfile`, `SDTimings`) | Base class stores raw debounce/retention integers; profiles are not preserved |
| TSN configuration (`HTBInstance`, `PTPConfig`, `Stream`, `TrafficClass`) | Not in base classes |
| Security (`Firewall`, `MACsec`) | Not in base classes |
| Safety (`E2EConfig`) | Not in base classes |
| `SystemMetadata` / `ECUMetadata` | Generated with fixed author `"FIBEXConverter"` on write; not parsed on read |
| Multicast group memberships (`MulticastGroupMembership`) | Derived automatically by FLYNC from socket and interface config; not explicit in base classes |
