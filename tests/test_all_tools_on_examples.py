#!/usr/bin/python
"""Smoke tests: run every configuration_to_* tool against every example XML file.

Each test verifies only that the tool exits with return code 0.  The input file
is copied to a temporary directory so that generated output does not end up
inside the repository's examples/ folder.
"""

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
EXAMPLES_DIR = REPO_ROOT / "examples"

TOOLS = [
    "configuration_to_text.py",
    "configuration_to_reports.py",
    "configuration_to_wireshark_config.py",
    "configuration_to_topology.py",
    "configuration_to_peach.py",
]

EXAMPLE_FILES = sorted(EXAMPLES_DIR.glob("*.xml"))


def _tool_ids():
    return [Path(t).stem for t in TOOLS]


def _file_ids():
    return [f.name for f in EXAMPLE_FILES]


@pytest.mark.parametrize("example_file", EXAMPLE_FILES, ids=_file_ids())
@pytest.mark.parametrize("tool", TOOLS, ids=_tool_ids())
def test_tool_exits_cleanly(tool, example_file):
    """Each tool must exit with code 0 on every example file."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_file = Path(tmp_dir) / example_file.name
        shutil.copy(example_file, tmp_file)

        result = subprocess.run(
            [sys.executable, str(REPO_ROOT / tool), "FIBEX", str(tmp_file)],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
        )

    assert result.returncode == 0, f"{tool} failed on {example_file.name}\n" f"--- stdout ---\n{result.stdout}\n" f"--- stderr ---\n{result.stderr}"
