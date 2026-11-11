import os
from pathlib import Path
import subprocess
import sys

import pytest

from guardian import parse_nmap_file, generate_html_report


ROOT = Path(__file__).resolve().parents[1]


def run_guardian(*args):
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT / "src") + os.pathsep + env.get("PYTHONPATH", "")
    return subprocess.run(
        [sys.executable, "-m", "guardian", *map(str, args)],
        capture_output=True, text=True, env=env, cwd=ROOT, timeout=30,
    )


def test_module_report_writes_existing_report_output(tmp_path):
    source = ROOT / "samples" / "example_scan.xml"
    output = tmp_path / "report with spaces.html"
    result = run_guardian("report", source, "--output", output)
    assert result.returncode == 0, result.stderr
    assert output.read_text(encoding="utf-8") == generate_html_report(parse_nmap_file(source))
    assert str(output) in result.stdout


@pytest.mark.parametrize("failure", ["missing-input", "invalid-xml", "missing-output-directory"])
def test_module_report_explains_io_errors(tmp_path, failure):
    source = tmp_path / "scan.xml"
    output = tmp_path / "report.html"
    if failure == "invalid-xml":
        source.write_text("<invalid>", encoding="utf-8")
    elif failure == "missing-output-directory":
        source.write_text("<nmaprun/>", encoding="utf-8")
        output = tmp_path / "missing" / "report.html"
    result = run_guardian("report", source, "--output", output)
    assert result.returncode == 1
    assert "guardian: error:" in result.stderr
    assert "Traceback" not in result.stderr
    assert not output.exists()


def test_module_report_requires_output_path():
    result = run_guardian("report", "samples/example_scan.xml")
    assert result.returncode == 2
    assert "--output" in result.stderr
