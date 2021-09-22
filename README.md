# FibexConverter
Convert SOME/IP config in FIBEX 4 to different configuration formats (e.g. Wireshark).

## Convert a FIBEX4 file to text:
Just call it like this:
    
    python3 configuration_to_text.py FIBEX example-file.xml

The result will be:
    
    example-file/text/example-file.txt

## Convert a FIBEX4 file to wireshark configs:
Just call it like this:
    
    python3 configuration_to_wireshark_config.py FIBEX example-file.xml

The results (hosts, vlanids, SOMEIP...) will be in:
    
    example-file/wireshark/

Copy the result files to your wireshark configuration directory (e.g. ~/.config/wireshark for MacOS X or %appdata%\Wireshark for Windows).

Important:
* SOME/IP support was added to Wireshark 3.2, you need a custom plugin before.
* Wireshark loads the config on start. So you better stop Wireshark while copying the configs in.

## Convert a FIBEX4 file to CSV reports:
Just call it like this:

    python3 configuration_to_reports.py FIBEX example-file.xml

The result will be:

    example-file/reports/
