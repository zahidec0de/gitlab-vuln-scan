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
_HEADER = "\033[1m"   # bold, used for section headers like "Evidence:"
_DIM = "\033[2m"      # dim, used for de-emphasized helper text
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


def header(text):
    """A section heading, e.g. 'Evidence:' or 'CVE audit (...)'. Bold when colored."""
    return f"{_HEADER}{text}{_RESET}" if color_enabled() else text


def dim(text):
    """De-emphasized helper text, e.g. an aside explaining a note or a skipped-rows count."""
    return f"{_DIM}{text}{_RESET}" if color_enabled() else text


def kv(label, value, width=14, indent="  "):
    """One 'Label : value' line, labels left-padded to a fixed width so a
    block of them lines up in a column, e.g.:
        Asset   : gitlab.example.com:443
        Status  : IDENTIFIED
    """
    return f"{indent}{label:<{width}}: {value}"


def render_table(headers, rows, align=None):
    """
    headers: list[str]
    rows: list[list[str]], plain text, no ANSI codes (color after padding)
    align: optional list of 'l'/'r' per column, default left for all.
           Numeric-looking columns (CVSS, counts) read better right-aligned.
    Returns padded row cell lists (header first, then a dashed separator
    row, then data rows) so the caller can wrap individual cells in color
    codes without breaking alignment.
    """
    widths = [len(str(h)) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))
    align = align or ["l"] * len(headers)

    def pad_row(cells):
        return [
            str(c).rjust(w) if a == "r" else str(c).ljust(w)
            for c, w, a in zip(cells, widths, align)
        ]

    padded_header = pad_row(headers)
    separator = ["-" * w for w in widths]
    padded_rows = [pad_row(row) for row in rows]
    return padded_header, separator, padded_rows


def print_table(headers, rows, indent="  ", align=None):
    header_row, sep, data_rows = render_table(headers, rows, align=align)
    print((indent + "  ".join(header_row)).rstrip())
    print((indent + "  ".join(sep)).rstrip())
    for row in data_rows:
        print((indent + "  ".join(row)).rstrip())


_CVE_HEADERS = ["CVE", "CVSS", "SEVERITY", "STATUS", "FIXED IN"]
_CVE_ALIGN = ["l", "r", "l", "l", "l"]


def _cve_row(f):
    from lib import cve_db

    label = cve_db.STATUS_LABEL[f["status"]]
    return [
        f["cve"],
        f"{f['cvss']:.1f}" if f["cvss"] is not None else "-",
        f["severity"],
        label,
        "; ".join(f["fixed_versions"]) if label != "NOT VULNERABLE" else "-",
    ]


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
    from lib import cve_db

    if not findings:
        print(f"{indent}{header('CVE audit:')} no CVEs in the local database matched the --cve filter")
        return

    actionable = [f for f in findings if f["status"] != cve_db.NOT_VULNERABLE]
    shown = findings if show_all else actionable
    skipped = len(findings) - len(shown)

    print(f"{indent}{header(f'CVE audit ({len(findings)} checked, {len(actionable)} flagged):')}")
    if not shown:
        print(f"{indent}  {dim(f'None flagged. Pass --all-cves to list all {len(findings)} checked as NOT VULNERABLE.')}")
        return

    rows = [_cve_row(f) for f in shown]
    header_row, sep, data_rows = render_table(_CVE_HEADERS, rows, align=_CVE_ALIGN)
    print((f"{indent}  " + "  ".join(header_row)).rstrip())
    print((f"{indent}  " + "  ".join(sep)).rstrip())
    for f, row in zip(shown, data_rows):
        row = list(row)
        row[-1] = row[-1].rstrip()
        row[2] = color_severity(row[2], f["severity"])
        row[3] = color_label(row[3], cve_db.STATUS_LABEL[f["status"]])
        print(f"{indent}  " + "  ".join(row))
    if skipped:
        print(f"{indent}  {dim(f'{skipped} more checked and found NOT VULNERABLE. Pass --all-cves to list them.')}")


def print_findings_table(results, indent="  "):
    """
    One flat table of every VULNERABLE / NEEDS VERIFICATION finding across
    all targets in a multi-target run, each row carrying its own target and
    version so the table is self-contained (no need to cross-reference the
    per-target sections above it). Useful for pasting into a report.
    """
    from lib import cve_db

    rows = []
    for r in results:
        if r["status"] != "identified" or not r["cve_audit"]:
            continue
        version = r["confirmed_floor"] or "-"
        for f in r["cve_audit"]:
            if f["status"] == cve_db.NOT_VULNERABLE:
                continue
            rows.append([r["target"], version] + _cve_row(f))

    if not rows:
        return

    headers = ["TARGET", "VERSION"] + _CVE_HEADERS
    align = ["l", "l"] + _CVE_ALIGN
    print(f"{indent}{header('Findings:')}")
    header_row, sep, data_rows = render_table(headers, rows, align=align)
    print((f"{indent}  " + "  ".join(header_row)).rstrip())
    print((f"{indent}  " + "  ".join(sep)).rstrip())
    for row_data, row in zip(rows, data_rows):
        severity, status_label = row_data[4], row_data[5]
        row = list(row)
        row[-1] = row[-1].rstrip()
        row[4] = color_severity(row[4], severity)
        row[5] = color_label(row[5], status_label)
        print(f"{indent}  " + "  ".join(row))
    print()
