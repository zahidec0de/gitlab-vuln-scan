#!/usr/bin/env python3
"""
Detect the GitLab version(s) running on one or more targets, show the
evidence behind the result so it can be checked by hand, and optionally
audit the result against known CVEs with documented affected version
ranges.

No nmap required. This uses the same fingerprinting technique as
gitlab_version.nse, runnable directly against a host:port list.

DETECTION METHOD (tried in this order, per target):
  1. Fetch /assets/webpack/manifest.json  -> webpack asset hash.
     Fetch /users/sign_in                 -> gon.revision commit hash, if present.
  2. If a commit hash was found, resolve it directly against gitlab.com's
     own API. No local dictionary needed, always current, exact. This only
     works on targets that still expose gon.revision.
  3. Otherwise, look the webpack hash up in gitlab_hashes.json (local file,
     or --remote-db to pull the upstream copy from GitHub).

A result can legitimately map to more than one version. Some patch
releases don't change the frontend bundle or the gitlab-rails build at
all, for example a base-image-only rebuild, so several versions can share
an identical fingerprint. When that happens the tool says so explicitly
and reports the lowest version as the confirmed floor. Run
verify_version.py against a specific candidate to narrow further.

CVE AUDIT (--cves): each candidate version is checked against every
documented "from X before Y" affected range in gitlab_cves.json. If all
candidates fall in the affected range, the result is VULNERABLE. If none
do, it's NOT VULNERABLE. If the candidates straddle a fix boundary, the
result is NEEDS VERIFICATION, since the true verdict depends on the exact
patch level. Pin it with verify_version.py first.

USAGE
  python3 scan.py HOST:PORT [HOST:PORT ...]
  python3 scan.py --cves HOST:PORT [HOST:PORT ...]       # + CVE audit table
  python3 scan.py --cves --cve CVE-2026-15217 HOST:PORT  # audit one CVE only
  python3 scan.py --subdir /gitlab HOST:PORT             # GitLab under a sub-path
  python3 scan.py --json HOST:PORT                       # machine-readable output
  python3 scan.py --remote-db HOST:PORT                  # use upstream gitlab_hashes.json
  python3 scan.py --no-gitlab-com HOST:PORT              # local dictionary only, no lookup beyond the target

EXIT CODE
  0  every target was identified, and with --cves, nothing came back VULNERABLE or NEEDS VERIFICATION
  1  a target could not be identified, or with --cves, at least one risky finding was found

EXAMPLES
  python3 scan.py gitlab.example.com:443
  python3 scan.py --cves 203.0.113.10:443 203.0.113.11:443
  python3 scan.py --json --cves gitlab.example.com:443 | jq '.[0].cve_audit'
"""
import argparse
import json
import sys

from lib import cve_db, format as fmt, gitlab_com, hashdb, target

LABEL_WIDTH = 13
EDITION_FLAG = {"enterprise": "ee", "community": "ce"}


def edition_flag_for(edition):
    """'ee'/'ce' for --edition when known, a placeholder only when it genuinely isn't."""
    return EDITION_FLAG.get(edition, "[ce|ee]")


def scan_one(hostport, subdir, timeout, insecure, db, db_source, no_gitlab_com):
    if ":" in hostport:
        host, port = hostport.rsplit(":", 1)
    else:
        host, port = hostport, "443"

    fp = target.fetch_target_fingerprint(host, port, subdir=subdir, timeout=timeout, insecure=insecure)

    result = {
        "target": f"{host}:{port}",
        "status": None,          # identified | hash_not_in_db | not_gitlab_or_unreachable
        "edition": None,
        "versions": None,
        "confirmed_floor": None,  # lowest version in `versions`, the one it is at least running
        "ambiguous": None,        # true if versions has more than one entry
        "evidence": {
            "manifest_url": fp["manifest_url"],
            "signin_url": fp["signin_url"],
            "webpack_hash": fp["webpack_hash"],
            "commit_hash": fp["commit_hash"],
            "method": None,
            "gitlab_com_queries": None,
            "hashdb_source": None,
            "hashdb_matched_key": None,
            "hashdb_match_type": None,
        },
        "verify_hint": None,
        "cve_audit": None,
        "errors": fp["errors"],
    }

    if fp["webpack_hash"] is None and fp["commit_hash"] is None:
        result["status"] = "not_gitlab_or_unreachable"
        return result

    # Prefer resolving the commit hash directly against gitlab.com: exact,
    # always current, no local dictionary needed. Only some instances still
    # expose gon.revision, so this isn't always available.
    if fp["commit_hash"] and not no_gitlab_com:
        resolved = gitlab_com.resolve_commit_to_versions(fp["commit_hash"])
        result["evidence"]["gitlab_com_queries"] = resolved["queries"]
        if resolved["versions"]:
            hits = resolved["versions"]
            result["status"] = "identified"
            result["evidence"]["method"] = "gitlab.com commit-hash lookup"
            editions = {h["edition"] for h in hits}
            result["edition"] = editions.pop() if len(editions) == 1 else "/".join(sorted(editions))
            result["versions"] = sorted({h["version"] for h in hits})
            result["confirmed_floor"] = result["versions"][0]
            result["ambiguous"] = len(result["versions"]) > 1
            return result

    banner, matched_key, match_type = hashdb.lookup(db, webpack_hash=fp["webpack_hash"], commit_hash=fp["commit_hash"])
    result["evidence"]["hashdb_source"] = db_source
    if banner is None:
        result["status"] = "hash_not_in_db"
        if fp["webpack_hash"]:
            result["verify_hint"] = (
                f"python3 verify_version.py --target {host}:{port} --version [X.Y.Z] --edition [ce|ee]"
            )
        return result

    result["status"] = "identified"
    result["evidence"]["method"] = "gitlab_hashes.json lookup"
    result["evidence"]["hashdb_matched_key"] = matched_key
    result["evidence"]["hashdb_match_type"] = match_type
    result["edition"] = hashdb.edition_for(banner["build"])
    result["versions"] = sorted(banner["versions"])
    result["confirmed_floor"] = result["versions"][0]
    result["ambiguous"] = len(result["versions"]) > 1
    return result


def print_text(r, show_all_cves=False):
    kv = lambda label, value: print(fmt.kv(label, value, width=LABEL_WIDTH))

    kv("Asset", r["target"])

    if r["status"] == "identified":
        floor = r["confirmed_floor"]
        kv("Status", fmt.color_label("IDENTIFIED", "IDENTIFIED"))
        kv("Edition", f"GitLab {r['edition']}")
        if r["ambiguous"]:
            others = ", ".join(v for v in r["versions"] if v != floor)
            kv("Version", f"{floor} (floor, exact patch not distinguishable remotely)")
            kv("Also possible", fmt.dim(f"{others} (same build fingerprint as {floor}, see Verify manually below)"))
        else:
            kv("Version", floor)
        kv("Method", r["evidence"]["method"])
        print()

        evidence_rows = [
            ("webpack manifest hash", r["evidence"]["webpack_hash"],
             [("fetched from", r["evidence"]["manifest_url"])]),
        ]
        if r["evidence"]["commit_hash"]:
            evidence_rows.append((
                "build commit hash", r["evidence"]["commit_hash"],
                [("fetched from", f"{r['evidence']['signin_url']} (gon.revision)")],
            ))
        for q in r["evidence"]["gitlab_com_queries"] or []:
            if q["matched_tags"]:
                evidence_rows.append((
                    "resolved via", q["url"],
                    [("matching tags", ", ".join(q["matched_tags"]))],
                ))
        if r["evidence"]["hashdb_matched_key"]:
            evidence_rows.append((
                "matched in", r["evidence"]["hashdb_source"],
                [(f"key ({r['evidence']['hashdb_match_type']})", r["evidence"]["hashdb_matched_key"])],
            ))
        print(f"  {fmt.header('Evidence:')}")
        fmt.print_kv_block(evidence_rows)

        verify_rows = [[
            "Webpack hash",
            f"curl -sk {r['evidence']['manifest_url']} | python3 -c \"import json,sys; print(json.load(sys.stdin)['hash'])\"",
        ]]
        for q in r["evidence"]["gitlab_com_queries"] or []:
            if q["matched_tags"]:
                verify_rows.append(["gitlab.com lookup", f"curl -s '{q['url']}'"])
        if r["ambiguous"]:
            verify_rows.append([
                "Pin exact version",
                f"python3 verify_version.py --target {r['target']} --version {floor} --edition {edition_flag_for(r['edition'])}",
            ])
        print()
        print(f"  {fmt.header('Verify manually (copy and run):')}")
        fmt.print_table(["CHECK", "COMMAND"], verify_rows, indent="    ")

        if r["cve_audit"] is not None:
            print()
            fmt.print_cve_table(r["cve_audit"], show_all=show_all_cves)

    elif r["status"] == "hash_not_in_db":
        kv("Status", fmt.color_label("GITLAB DETECTED, HASH NOT IN LOCAL DATABASE", "GITLAB DETECTED, HASH NOT IN LOCAL DATABASE"))
        print()
        evidence_rows = [
            ("webpack manifest hash", r["evidence"]["webpack_hash"],
             [("fetched from", r["evidence"]["manifest_url"])]),
        ]
        if r["evidence"]["commit_hash"]:
            evidence_rows.append((
                "build commit hash", f"{r['evidence']['commit_hash']} (not resolvable on gitlab.com either)", None,
            ))
        print(f"  {fmt.header('Evidence:')}")
        fmt.print_kv_block(evidence_rows)
        print()
        kv("Next step", r["verify_hint"])

    else:
        kv("Status", fmt.color_label("NOT GITLAB OR UNREACHABLE", "NOT GITLAB OR UNREACHABLE"))

    for err in r["errors"]:
        print(f"  ! {err}")
    print()


def print_summary(results, show_cves):
    if len(results) < 2:
        return
    print(fmt.header("Summary:"))
    if show_cves:
        rows = []
        for r in results:
            if r["status"] != "identified":
                rows.append([r["target"], "-", "-", r["status"].replace("_", " "), "-"])
                continue
            audit = r["cve_audit"] or []
            vuln = [f for f in audit if f["status"] == cve_db.VULNERABLE]
            needs = [f for f in audit if f["status"] == cve_db.NEEDS_VERIFICATION]
            highest = max((f["cvss"] for f in vuln if f["cvss"] is not None), default=None)
            flag = f"{len(vuln)} vulnerable" + (f", {len(needs)} unverified" if needs else "")
            rows.append([
                r["target"], r["edition"] or "-", r["confirmed_floor"] or "-",
                flag, f"{highest:.1f}" if highest is not None else "-",
            ])
        fmt.print_table(["TARGET", "EDITION", "VERSION", "CVE FINDINGS", "MAX CVSS"], rows, indent="  ", align=["l", "l", "l", "l", "r"])
        print()
        fmt.print_findings_table(results, indent="  ")
    else:
        rows = [
            [r["target"], r["edition"] or "-", r["confirmed_floor"] or "-", r["status"].replace("_", " ")]
            for r in results
        ]
        fmt.print_table(["TARGET", "EDITION", "VERSION", "STATUS"], rows, indent="  ")
        print()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("targets", nargs="+", help="host:port, e.g. gitlab.example.com:443")
    ap.add_argument("--subdir", default="", help="GitLab installed under a sub-path, e.g. /gitlab")
    ap.add_argument("--timeout", type=float, default=15, help="per-request timeout in seconds (default: 15)")
    ap.add_argument("--no-insecure", action="store_true", help="verify TLS certs (off by default, since many internal instances use self-signed certs)")
    ap.add_argument("--remote-db", action="store_true", help="fetch gitlab_hashes.json from GitHub instead of using the local copy")
    ap.add_argument("--db", default=None, help="path to a local gitlab_hashes.json (default: the one next to this script)")
    ap.add_argument("--no-gitlab-com", action="store_true", help="skip the gitlab.com commit-hash cross-check, use only the local hash database")
    ap.add_argument("--cves", action="store_true", help="audit each identified target against gitlab_cves.json")
    ap.add_argument("--cve", default=None, help="with --cves, restrict the audit to one CVE ID (e.g. CVE-2026-15217)")
    ap.add_argument("--cve-db", default=None, help="path to a local gitlab_cves.json (default: the one next to this script)")
    ap.add_argument("--remote-cve-db", action="store_true", help="fetch gitlab_cves.json from GitHub instead of using the local copy")
    ap.add_argument("--all-cves", action="store_true", help="with --cves, also list CVEs checked as NOT VULNERABLE (default: only show flagged ones)")
    ap.add_argument("--json", action="store_true", help="output machine-readable JSON instead of text")
    args = ap.parse_args()

    db = hashdb.load(path=args.db, remote=args.remote_db)
    db_source = hashdb.REMOTE_URL if args.remote_db else (args.db or hashdb.LOCAL_PATH)

    cdb = None
    if args.cves:
        cdb = cve_db.load(path=args.cve_db, remote=args.remote_cve_db)

    results = []
    for t in args.targets:
        r = scan_one(t, args.subdir, args.timeout, not args.no_insecure, db, db_source, args.no_gitlab_com)
        if args.cves and r["status"] == "identified":
            r["cve_audit"] = cve_db.audit(r["versions"], cdb, cve_filter=args.cve)
        results.append(r)

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for r in results:
            print_text(r, show_all_cves=args.all_cves)
        print_summary(results, args.cves)

    all_identified = all(r["status"] == "identified" for r in results)
    any_risk = args.cves and any(
        f["status"] in (cve_db.VULNERABLE, cve_db.NEEDS_VERIFICATION)
        for r in results for f in (r["cve_audit"] or [])
    )
    sys.exit(0 if (all_identified and not any_risk) else 1)


if __name__ == "__main__":
    main()
