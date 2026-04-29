# FibexConverter

Convert SOME/IP configuration from FIBEX 4 XML files (ASAM standard) to various output formats, including human-readable text, Wireshark dissector configs, CSV/XLSX reports, network topology visualizations, Peach fuzzing definitions, and FLYNC models.

## Installation

Install dependencies with:

    pip install -r requirements.txt
    pip install -r tests/requirements.txt
    git submodule init
    git submodule update
    pip install external/FLYNC/

Dependencies: `isodate`, `graphviz`, `macaddress`, `xlsxwriter`

## Usage

All tools share the same basic invocation pattern:

    python3 <script>.py FIBEX <file-or-directory> [options]

You can pass either a single XML file or a directory containing multiple FIBEX files.

**Common options (available in most tools):**

| Option | Description |
|--------|-------------|
| `--ecu-name-mapping FILE` | CSV file for ECU name replacements |
| `--generate-switch-port-names` | Auto-generate switch port names |
| `--plugin FILE` | Custom parser plugin file |

---

### Convert to text

    python3 configuration_to_text.py FIBEX example-file.xml

Output:

    example-file/text/example-file.txt

---

### Convert to Wireshark configs

    python3 configuration_to_wireshark_config.py FIBEX example-file.xml

Output (three version-specific directories):

    example-file/wireshark_3.4_and_earlier/
    example-file/wireshark_3.5_to_4.4/
    example-file/wireshark_4.5_and_later/

Each directory contains hosts, VLAN IDs, and SOME/IP service/method/event/eventgroup configs. Copy the contents of the appropriate directory to your Wireshark configuration folder:
- Linux/macOS: `~/.config/wireshark/`
- Windows: `%APPDATA%\Wireshark\`

**Notes:**
- SOME/IP dissector support was added in Wireshark 3.2; a custom plugin is needed for older versions.
- Stop Wireshark before copying config files — it only loads them on startup.

---

### Convert to CSV reports

    python3 configuration_to_reports.py FIBEX example-file.xml

Output:

    example-file/reports/

Generates service instance matrices, statistics, and size reports.

**Additional options:**

| Option | Description |
|--------|-------------|
| `--ignore-ecus FILE` | File listing ECU names to exclude |
| `--ignore-services FILE` | File listing service IDs to exclude (hex format) |
| `--ecu-order FILE` | File specifying ECU ordering in reports |

---

### Convert to topology

    python3 configuration_to_topology.py FIBEX example-file.xml

Output:

    example-file/topology/

Generates topology tables (CSV and XLSX), endpoint lists, forwarding tables for switches, multicast route mappings, and Graphviz PDF network diagrams per VLAN.

**Additional options:**

| Option | Description |
|--------|-------------|
| `--mcast-list FILE` | Multicast entries (semicolon-separated) |
| `--metadata FILE` | CSV metadata file |
| `--multicast-names FILE` | CSV file mapping multicast addresses to names |
| `--generate-vlan-names` | Auto-generate VLAN names |

---

### Convert to Peach fuzzing definitions

    python3 configuration_to_peach.py FIBEX example-file.xml

Output:

    example-file/peach/

Generates Peach framework XML files for SOME/IP fuzzing.

---

### Convert to FLYNC model

    python3 configuration_to_flync.py FIBEX example-file.xml

Output:

    example-file/flync/

Generates a FLYNC workspace with ECU, socket, SOME/IP service, and topology models. Requires the FLYNC package (`pip install external/FLYNC/`).

**Additional options:**

| Option | Description |
|--------|-------------|
| `--mcast-list FILE` | Multicast entries (semicolon-separated) |
| `--multicast-names FILE` | CSV file mapping multicast addresses to names |
| `--generate-vlan-names` | Auto-generate VLAN names |

---

## Examples

The `examples/` directory contains ready-to-use FIBEX XML files:

| File | Description |
|------|-------------|
| `examples/SOMEIP_simple_service.xml` | Minimal SOME/IP service definition |
| `examples/SOMEIP_Enhanced_Testability_Service.xml` | SOME/IP Enhanced Testability Service |
| `examples/Ethernet_Topology_with_Switches.xml` | Ethernet network with switches and VLANs |

Pre-generated outputs for `Ethernet_Topology_with_Switches.xml` are included in `examples/Ethernet_Topology_with_Switches/`.

---

## Project Structure

| File | Description |
|------|-------------|
| `configuration_to_text.py` | Convert to human-readable text |
| `configuration_to_wireshark_config.py` | Generate Wireshark dissector configs |
| `configuration_to_reports.py` | Generate CSV/XLSX statistical reports |
| `configuration_to_topology.py` | Generate network topology visualizations |
| `configuration_to_peach.py` | Generate Peach fuzzing XML definitions |
| `configuration_to_flync.py` | Convert to FLYNC model |
| `fibex_parser.py` | FIBEX 4 XML parser |
| `flync_parser.py` | FLYNC model parser |
| `configuration_base_classes.py` | Shared data model and base classes |
| `parser_dispatcher.py` | Routes input files to the appropriate parser |
| `abstract_parser.py` | Abstract base class for XML parsing |
| `examples/` | Example FIBEX files with pre-generated outputs |
| `tests/` | pytest test suite |

## Running Tests

    pytest tests/ -v
