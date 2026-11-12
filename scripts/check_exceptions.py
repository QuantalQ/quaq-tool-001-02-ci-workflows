"""Check the entries of a repository's exception file before a scan uses it.

Trivy applies an entry of ``.trivyignore.yaml`` whether or not it says why, and an entry without
``expired_at`` applies forever. The scan therefore refuses a file in which an entry lacks a non-empty
``statement`` or a valid ``expired_at``, or that is not valid YAML, so an invalid file never silently
weakens a verdict. A missing file is valid: the repository has no exceptions.

Usage: check_exceptions.py <file> [name shown in messages]
Exit code 0: the file is valid. 1: it is not; every problem is printed. 2: usage error.
"""

import datetime
import sys

import yaml

# The sections of Trivy's ignore file; each holds a list of entries of the same shape.
SECTIONS = ("vulnerabilities", "misconfigurations", "secrets", "licenses")


def parse_date(value):
    """Return the date of an ``expired_at`` value, or None when it is not a date."""
    if isinstance(value, datetime.datetime):
        return value.date()
    if isinstance(value, datetime.date):
        return value
    if isinstance(value, str):
        try:
            return datetime.date.fromisoformat(value.strip())
        except ValueError:
            return None
    return None


def check(document, today):
    """Return (problems, notes) for a parsed exception file."""
    problems = []
    notes = []
    if document is None:
        return problems, notes
    if not isinstance(document, dict):
        return ["the file must be a mapping of sections (vulnerabilities, ...)"], notes
    for section, entries in document.items():
        if section not in SECTIONS:
            problems.append(f"unknown section '{section}'; Trivy reads {', '.join(SECTIONS)}")
            continue
        if entries is None:
            continue
        if not isinstance(entries, list):
            problems.append(f"{section}: must be a list of entries")
            continue
        for index, entry in enumerate(entries, start=1):
            where = f"{section}[{index}]"
            if not isinstance(entry, dict):
                problems.append(f"{where}: must be a mapping with id, statement and expired_at")
                continue
            entry_id = entry.get("id")
            if entry_id:
                where = f"{where} {entry_id}"
            else:
                problems.append(f"{where}: has no id")
            statement = entry.get("statement")
            if not isinstance(statement, str) or not statement.strip():
                problems.append(f"{where}: has no statement saying why it does not apply")
            if "expired_at" not in entry:
                problems.append(f"{where}: has no expired_at")
                continue
            expires = parse_date(entry["expired_at"])
            if expires is None:
                problems.append(f"{where}: expired_at '{entry['expired_at']}' is not a date (YYYY-MM-DD)")
            elif expires < today:
                notes.append(f"{where}: expired on {expires.isoformat()}, the finding blocks again;"
                             " remove the entry or renew it with a new statement")
    return problems, notes


def main(argv):
    if len(argv) not in (2, 3):
        print("usage: check_exceptions.py <path to .trivyignore.yaml> [name shown in messages]",
              file=sys.stderr)
        return 2
    # The scan copies the file into a container; the messages name it as the repository does.
    path = argv[2] if len(argv) == 3 else argv[1]
    try:
        with open(argv[1], encoding="utf-8") as handle:
            document = yaml.safe_load(handle)
    except FileNotFoundError:
        print(f"{path}: not present, no exceptions apply")
        return 0
    except yaml.YAMLError as error:
        print(f"{path}: not valid YAML: {error}")
        return 1
    problems, notes = check(document, datetime.date.today())
    for note in notes:
        print(f"{path}: note: {note}")
    for problem in problems:
        print(f"{path}: error: {problem}")
    if problems:
        print(f"{path}: {len(problems)} invalid exception entr{'y' if len(problems) == 1 else 'ies'};"
              " the scan does not run with this file")
        return 1
    print(f"{path}: valid")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
