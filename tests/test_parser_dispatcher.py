#!/usr/bin/python
"""Unit tests for parser_dispatcher module."""

import os

import pytest

from parser_dispatcher import is_file_or_dir_valid, is_file_valid, parse_input_files


class MockParser:
    """Mock parser object."""

    def __init__(self):
        """Init."""
        self.msg = None

    def error(self, msg):
        self.msg = msg


class TestIsFileOrDirValid:
    """Test cases for is_file_or_dir_valid function."""

    def test_existing_directory(self, tmpdir):
        """Test with existing directory."""
        dir_path = tmpdir.mkdir("testdir")
        result = is_file_or_dir_valid(None, str(dir_path))
        assert result == str(dir_path)

    def test_existing_file(self, tmpdir):
        """Test with existing file."""
        file_path = tmpdir.join("testfile.txt")
        file_path.write("content")
        result = is_file_or_dir_valid(None, str(file_path))
        assert result == str(file_path)

    def test_nonexistent_path(self, tmpdir):
        """Test with nonexistent path."""
        mp = MockParser()

        path = str(tmpdir.join("nonexistent"))
        result = is_file_or_dir_valid(mp, str(path))
        assert mp.msg is not None


class TestIsFileValid:
    """Test cases for is_file_valid function."""

    def test_existing_file(self, tmpdir):
        """Test with existing file."""
        file_path = tmpdir.join("testfile.txt")
        file_path.write("content")
        result = is_file_valid(None, str(file_path))
        assert result == str(file_path)

    def test_directory_instead_of_file(self, tmpdir):
        """Test with directory instead of file."""
        dir_path = tmpdir.mkdir("testdir")
        assert os.path.exists(dir_path)

        mp = MockParser()
        is_file_valid(mp, str(dir_path))
        assert mp.msg is not None

    def test_nonexistent_file(self, tmpdir):
        """Test with nonexistent file."""
        path = str(tmpdir.join("nonexistent.txt"))
        assert not os.path.exists(path)

        mp = MockParser()
        is_file_or_dir_valid(mp, str(path))
        assert mp.msg is not None


class TestParseInputFiles:
    """Test cases for parse_input_files function."""

    def test_parse_directory_with_fibex_files(self, tmpdir):
        """Test parsing a directory with FIBEX files."""
        # Create a directory with FIBEX XML files
        test_dir = tmpdir.mkdir("testproject")
        fibex_file = test_dir.join("FBX412_1234.xml")
        fibex_file.write("""<?xml version="1.0" encoding="UTF-8"?>
<fx:FIBEX xmlns:fx="http://www.asam.net/xml/fbx" xmlns:ho="http://www.asam.net/xml">
    <fx:PROJECT ID="PROJ1">
        <ho:SHORT-NAME>TestProject</ho:SHORT-NAME>
    </fx:PROJECT>
</fx:FIBEX>
""")

        from configuration_to_text import SimpleConfigurationFactory

        factory = SimpleConfigurationFactory()

        result = parse_input_files(filename=str(test_dir), t="FIBEX", conf_factory=factory, print_filename=True, verbose=False)
        assert result == str(test_dir)

    def test_parse_single_file(self, tmpdir):
        """Test parsing a single file."""
        test_dir = tmpdir.mkdir("testproject")
        fibex_file = test_dir.join("test.xml")
        fibex_file.write("""<?xml version="1.0" encoding="UTF-8"?>
<fx:FIBEX xmlns:fx="http://www.asam.net/xml/fbx" xmlns:ho="http://www.asam.net/xml">
    <fx:PROJECT ID="PROJ1">
        <ho:SHORT-NAME>TestProject</ho:SHORT-NAME>
    </fx:PROJECT>
</fx:FIBEX>
""")

        from configuration_to_text import SimpleConfigurationFactory

        factory = SimpleConfigurationFactory()

        result = parse_input_files(filename=str(fibex_file), t="FIBEX", conf_factory=factory, print_filename=False, verbose=False)
        # The function returns the directory with the filename without extension
        expected = str(test_dir.join("test"))
        assert result == expected

    def test_parse_invalid_type(self, tmpdir):
        """Test parsing with invalid type."""
        file_path = tmpdir.join("test.xml")
        file_path.write("<root/>")

        from configuration_to_text import SimpleConfigurationFactory

        factory = SimpleConfigurationFactory()

        with pytest.raises(SystemExit):
            parse_input_files(filename=str(file_path), t="INVALID", conf_factory=factory, print_filename=False, verbose=False)

    def test_parse_nonexistent_file(self, tmpdir):
        """Test parsing nonexistent file."""
        from configuration_to_text import SimpleConfigurationFactory

        factory = SimpleConfigurationFactory()

        with pytest.raises(SystemExit):
            parse_input_files(filename=str(tmpdir.join("nonexistent.xml")), t="FIBEX", conf_factory=factory, print_filename=False, verbose=False)

    def test_parse_directory_with_file_filter(self, tmpdir):
        """Test parsing with file filter."""
        test_dir = tmpdir.mkdir("testproject")

        # Create FIBEX file
        fibex_file = test_dir.join("FBX412_1234.xml")
        fibex_file.write("""<?xml version="1.0" encoding="UTF-8"?>
<fx:FIBEX xmlns:fx="http://www.asam.net/xml/fbx" xmlns:ho="http://www.asam.net/xml">
    <fx:PROJECT ID="PROJ1">
        <ho:SHORT-NAME>TestProject</ho:SHORT-NAME>
    </fx:PROJECT>
</fx:FIBEX>
""")

        # Create non-FIBEX file (should be filtered out)
        other_file = test_dir.join("other.txt")
        other_file.write("not a fibex file")

        from configuration_to_text import SimpleConfigurationFactory

        factory = SimpleConfigurationFactory()

        result = parse_input_files(
            filename=str(test_dir), t="FIBEX", conf_factory=factory, file_filter="**/FBX*.xml", print_filename=False, verbose=False
        )
        assert result == str(test_dir)
