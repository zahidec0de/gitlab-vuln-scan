"""Dependency-free key/value lines, tables, and color for terminal output."""
import os
import sys

_SEVERITY_COLOR = {
    "critical": "\033[1;41;97m",  # bold white on red
    "high": "\033[1;31m",         # bold red
    "medium": "\033[33m",         # yellow
    "low": "\033[32m",            # green
    "unknown": "\033[2m",         # dim
}
_LABEL_COLOR = {
    "VULNERABLE": "\033[1;31m",
    "NOT VULNERABLE": "\033[32m",
    "NEEDS VERIFICATION": "\033[33m",
    "IDENTIFIED": "\033[32m",
    "CONFIRMED": "\033[32m",
    "MISMATCH": "\033[1;31m",
    "ERROR": "\033[1;31m",
    "GITLAB DETECTED, HASH NOT IN LOCAL DATABASE": "\033[33m",
    "NOT GITLAB OR UNREACHABLE": "\033[2m",
}
_RESET = "\033[0m"


def color_enabled():
    return sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def color_severity(text, severity):
    if not color_enabled():
        return text
    c = _SEVERITY_COLOR.get(severity, "")
    return f"{c}{text}{_RESET}" if c else text


def color_label(text, label):
    if not color_enabled():
        return text
    c = _LABEL_COLOR.get(label, "")
    return f"{c}{text}{_RESET}" if c else text


# kept as an alias so existing call sites that pass a CVE status label keep working
color_status = color_label


def kv(label, value, width=14, indent="  "):
    """One 'Label : value' line, labels left-padded to a fixed width so a
    block of them lines up in a column, e.g.:
        Asset   : gitlab.example.com:443
        Status  : IDENTIFIED
    """
    return f"{indent}{label:<{width}}: {value}"


def kv_wrapped(label, lines, width=14, indent="  "):
    """
    Like kv(), but the value spans multiple lines. `lines` is a list of
    strings; the first is printed after the label, the rest are indented to
    line up under it.
    """
    pad = " " * (len(indent) + width + 2)
    out = [f"{indent}{label:<{width}}: {lines[0]}"]
    out += [f"{pad}{line}" for line in lines[1:]]
    return "\n".join(out)


def render_table(headers, rows):
    """
    headers: list[str]
    rows: list[list[str]], plain text, no ANSI codes (color after padding)
    Returns padded row cell lists (header first, then a dashed separator
    row, then data rows) so the caller can wrap individual cells in color
    codes without breaking alignment.
    """
    widths = [len(str(h)) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))

    def pad_row(cells):
        return [str(c).ljust(w) for c, w in zip(cells, widths)]

    padded_header = pad_row(headers)
    separator = ["-" * w for w in widths]
    padded_rows = [pad_row(row) for row in rows]
    return padded_header, separator, padded_rows


def print_table(headers, rows, indent="  "):
    header, sep, data_rows = render_table(headers, rows)
    print((indent + "  ".join(header)).rstrip())
    print((indent + "  ".join(sep)).rstrip())
    for row in data_rows:
        print((indent + "  ".join(row)).rstrip())


def print_cve_table(findings, indent="  ", show_all=False):
    """
    findings: list of dicts as returned by lib.cve_db.audit(). This is the
    full audit, every CVE in the database, which can be hundreds of rows.

    By default only rows that need attention are printed (VULNERABLE and
    NEEDS VERIFICATION), since that is almost always what's useful at the
    terminal. Pass show_all=True to also list every CVE checked and found
    NOT VULNERABLE. The JSON output always has the full list regardless of
    this flag.
    """
    from lib import cve_db  # local import: cve_db does not import format, avoid a load-order dependency

    if not findings:
        print(f"{indent}CVE audit: no CVEs in the local database matched the --cve filter")
        return

    actionable = [f for f in findings if f["status"] != cve_db.NOT_VULNERABLE]
    shown = findings if show_all else actionable
    skipped = len(findings) - len(shown)

    print(f"{indent}CVE audit ({len(findings)} checked, {len(actionable)} flagged):")
    if not shown:
        print(f"{indent}  None flagged. Pass --all-cves to list all {len(findings)} checked as NOT VULNERABLE.")
        return

    rows = []
    for f in shown:
        label = cve_db.STATUS_LABEL[f["status"]]
        rows.append([
            f["cve"],
            f"{f['cvss']:.1f}" if f["cvss"] is not None else "-",
            f["severity"],
            label,
            "; ".join(f["fixed_versions"]) if label != "NOT VULNERABLE" else "-",
        ])
    header, sep, data_rows = render_table(["CVE", "CVSS", "SEVERITY", "STATUS", "FIXED IN"], rows)
    print((f"{indent}  " + "  ".join(header)).rstrip())
    print((f"{indent}  " + "  ".join(sep)).rstrip())
    for f, row in zip(shown, data_rows):
        row = list(row)
        row[-1] = row[-1].rstrip()
        row[2] = color_severity(row[2], f["severity"])
        row[3] = color_label(row[3], cve_db.STATUS_LABEL[f["status"]])
        print(f"{indent}  " + "  ".join(row))
    if skipped:
        print(f"{indent}  {skipped} more checked and found NOT VULNERABLE. Pass --all-cves to list them.")
