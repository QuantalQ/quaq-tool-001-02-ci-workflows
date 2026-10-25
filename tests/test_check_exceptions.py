"""Tests of the exception-entry check (ORG-BE-ADR-0015 §4)."""

import datetime
import pathlib
import subprocess
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))

import check_exceptions  # noqa: E402

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "check_exceptions.py"
TODAY = datetime.date(2026, 10, 25)


def valid_entry(**changes):
    entry = {
        "id": "CVE-2026-00001",
        "paths": ["usr/local/lib/python3.13/site-packages/pillow-12.0.0.dist-info/METADATA"],
        "statement": "Only the PNG decoder is affected; the product decodes no user images.",
        "expired_at": datetime.date(2026, 12, 31),
    }
    entry.update(changes)
    return entry


def run(tmp_path, content):
    path = tmp_path / ".trivyignore.yaml"
    path.write_text(content, encoding="utf-8")
    return subprocess.run([sys.executable, str(SCRIPT), str(path), ".trivyignore.yaml"],
                          capture_output=True, text=True, check=False)


def test_a_complete_entry_is_valid():
    assert check_exceptions.check({"vulnerabilities": [valid_entry()]}, TODAY) == ([], [])


def test_an_empty_or_commented_file_is_valid():
    assert check_exceptions.check(None, TODAY) == ([], [])
    assert check_exceptions.check({"vulnerabilities": None}, TODAY) == ([], [])


@pytest.mark.parametrize("statement", [None, "", "   ", 42])
def test_an_entry_without_a_statement_is_refused(statement):
    entry = valid_entry(statement=statement)
    problems, _ = check_exceptions.check({"vulnerabilities": [entry]}, TODAY)
    assert problems == ["vulnerabilities[1] CVE-2026-00001: has no statement saying why it does not apply"]


def test_an_entry_without_expired_at_is_refused():
    entry = valid_entry()
    del entry["expired_at"]
    problems, _ = check_exceptions.check({"vulnerabilities": [entry]}, TODAY)
    assert problems == ["vulnerabilities[1] CVE-2026-00001: has no expired_at"]


@pytest.mark.parametrize("value", ["soon", "31.12.2026", None, 20261231])
def test_an_expired_at_that_is_not_a_date_is_refused(value):
    problems, _ = check_exceptions.check({"vulnerabilities": [valid_entry(expired_at=value)]}, TODAY)
    assert len(problems) == 1
    assert "is not a date" in problems[0]


def test_a_quoted_iso_date_is_accepted():
    assert check_exceptions.check({"vulnerabilities": [valid_entry(expired_at="2026-12-31")]}, TODAY) == ([], [])


def test_an_expired_entry_is_valid_but_noted():
    entry = valid_entry(expired_at=datetime.date(2026, 10, 1))
    problems, notes = check_exceptions.check({"vulnerabilities": [entry]}, TODAY)
    assert problems == []
    assert notes and "expired on 2026-10-01" in notes[0]


def test_an_entry_without_an_id_is_refused():
    entry = valid_entry()
    del entry["id"]
    problems, _ = check_exceptions.check({"vulnerabilities": [entry]}, TODAY)
    assert problems == ["vulnerabilities[1]: has no id"]


def test_every_section_is_checked():
    entry = valid_entry(statement="")
    problems, _ = check_exceptions.check({"secrets": [entry], "licenses": [valid_entry()]}, TODAY)
    assert problems == ["secrets[1] CVE-2026-00001: has no statement saying why it does not apply"]


@pytest.mark.parametrize("document, problem", [
    (["CVE-2026-00001"], "the file must be a mapping of sections (vulnerabilities, ...)"),
    ({"vulns": []}, "unknown section 'vulns'; Trivy reads vulnerabilities, misconfigurations, secrets, licenses"),
    ({"vulnerabilities": {"id": "x"}}, "vulnerabilities: must be a list of entries"),
    ({"vulnerabilities": ["CVE-2026-00001"]},
     "vulnerabilities[1]: must be a mapping with id, statement and expired_at"),
])
def test_a_malformed_structure_is_refused(document, problem):
    assert check_exceptions.check(document, TODAY)[0] == [problem]


def test_the_command_passes_a_valid_file(tmp_path):
    result = run(tmp_path, "vulnerabilities:\n  - id: CVE-2026-00001\n"
                           "    statement: Not reachable.\n    expired_at: 2099-01-01\n")
    assert result.returncode == 0
    assert result.stdout.strip() == ".trivyignore.yaml: valid"


def test_the_command_refuses_an_invalid_entry(tmp_path):
    result = run(tmp_path, "vulnerabilities:\n  - id: CVE-2026-00001\n")
    assert result.returncode == 1
    assert ".trivyignore.yaml: error: vulnerabilities[1] CVE-2026-00001: has no statement" in result.stdout
    assert "the scan does not run with this file" in result.stdout


def test_the_command_refuses_invalid_yaml(tmp_path):
    result = run(tmp_path, "vulnerabilities:\n  - id: [unclosed\n")
    assert result.returncode == 1
    assert ".trivyignore.yaml: not valid YAML" in result.stdout


def test_the_command_accepts_a_missing_file(tmp_path):
    result = subprocess.run([sys.executable, str(SCRIPT), str(tmp_path / "absent.yaml")],
                            capture_output=True, text=True, check=False)
    assert result.returncode == 0
    assert "not present, no exceptions apply" in result.stdout


def test_the_command_refuses_wrong_usage():
    result = subprocess.run([sys.executable, str(SCRIPT)], capture_output=True, text=True, check=False)
    assert result.returncode == 2
