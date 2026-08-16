#!/usr/bin/env python3
"""
Confirm or refute one specific claimed GitLab version against a live
target. No dictionary lookup, no guessing: this pulls the exact webpack
manifest hash for the claimed version straight from Docker Hub's registry
(streamed, no `docker pull` or Docker daemon needed) and diffs it
byte-for-byte against what the live host actually serves.

Use this when:
  - a vendor or scanner claims a specific version and you want a hard yes or no
  - scan.py returned "hash not in database" (a release too new for the
    local dictionary) or an ambiguous range, and you want to test one candidate

USAGE
  python3 verify_version.py --target HOST:PORT --version 18.11.7 --edition ee
  python3 verify_version.py --target HOST:PORT --version 19.1.2 --edition ce --subdir /gitlab
  python3 verify_version.py --target HOST:PORT --version 18.11.7 --edition ee --json

EXIT CODE
  0  confirmed match
  1  mismatch, the target is running something else
  2  error, e.g. the target is unreachable or the claimed version's docker tag does not exist

Add --cves to also audit the pinned version against gitlab_cves.json once
confirmed. Since this checks one exact version rather than a range, the
result is never NEEDS VERIFICATION the way scan.py's can be.

EXAMPLE
  $ python3 verify_version.py --target gitlab.example.com:443 --version 18.11.7 --edition ee --cves
  Asset          : gitlab.example.com:443
  Status         : CONFIRMED
  Live hash      : d6a77cf456c325839dc9 (from https://gitlab.example.com:443/assets/webpack/manifest.json)
  Reference hash : d6a77cf456c325839dc9 (from gitlab/gitlab-ee:18.11.7-ee.0, Docker Hub registry, streamed)

  CVE audit (427 checked, 1 flagged):
    CVE             CVSS  SEVERITY  STATUS      FIXED IN
    --------------  ----  --------  ----------  ----------------------
    CVE-2026-15217  8.7   high      VULNERABLE  19.0.6; 19.1.4; 19.2.2
"""
import argparse
import json
import sys

from lib import cve_db, format as fmt, registry, target

REPO_BY_EDITION = {"ce": "gitlab/gitlab-ce", "ee": "gitlab/gitlab-ee"}
LABEL_WIDTH = 14


def log(msg, quiet):
    if not quiet:
        print(msg, file=sys.stderr)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", required=True, help="host:port")
    ap.add_argument("--version", required=True, help="claimed version, e.g. 18.11.7")
    ap.add_argument("--edition", required=True, choices=["ce", "ee"])
    ap.add_argument("--tag-suffix", default=".0", help="docker tag suffix (default: .0, i.e. VERSION-ce.0)")
    ap.add_argument("--subdir", default="")
    ap.add_argument("--timeout", type=float, default=15)
    ap.add_argument("--no-insecure", action="store_true", help="verify TLS certs (off by default)")
    ap.add_argument("--cves", action="store_true", help="audit the pinned version against gitlab_cves.json once confirmed")
    ap.add_argument("--cve", default=None, help="with --cves, restrict the audit to one CVE ID")
    ap.add_argument("--cve-db", default=None, help="path to a local gitlab_cves.json (default: the one next to this script)")
    ap.add_argument("--remote-cve-db", action="store_true", help="fetch gitlab_cves.json from GitHub instead of using the local copy")
    ap.add_argument("--all-cves", action="store_true", help="with --cves, also list CVEs checked as NOT VULNERABLE")
    ap.add_argument("--json", action="store_true", help="output machine-readable JSON instead of text")
    args = ap.parse_args()

    if ":" in args.target:
        host, port = args.target.rsplit(":", 1)
    else:
        host, port = args.target, "443"

    repo = REPO_BY_EDITION[args.edition]
    tag = f"{args.version}-{args.edition}{args.tag_suffix}"
    docker_ref = f"{repo}:{tag}"

    result = {
        "target": args.target,
        "claimed_version": args.version,
        "claimed_edition": args.edition,
        "docker_ref": docker_ref,
        "live_hash": None,
        "live_hash_source": None,
        "reference_hash": None,
        "reference_hash_source": f"{docker_ref}, Docker Hub registry, streamed",
        "result": None,
        "cve_audit": None,
        "errors": [],
    }

    log(f"Fetching live fingerprint from {args.target}", args.json)
    fp = target.fetch_target_fingerprint(host, port, subdir=args.subdir, timeout=args.timeout, insecure=not args.no_insecure)
    result["errors"].extend(fp["errors"])
    result["live_hash"] = fp["webpack_hash"]
    result["live_hash_source"] = fp["manifest_url"]

    if fp["webpack_hash"] is None:
        result["result"] = "error"
        result["error"] = "could not read a webpack manifest hash from the target"
        _emit(result, args.json, args.all_cves)
        sys.exit(2)

    log(f"Live webpack hash: {fp['webpack_hash']}", args.json)
    log(f"Pulling the reference hash for {docker_ref} from Docker Hub (streaming, no docker pull)...", args.json)

    try:
        webpack_hash, commit_hash = registry.fetch_manifest_hash(repo, tag, log=lambda m: log(m, args.json))
    except Exception as e:
        result["result"] = "error"
        result["error"] = f"failed to fetch {docker_ref}: {e}"
        _emit(result, args.json, args.all_cves)
        sys.exit(2)

    result["reference_hash"] = webpack_hash
    result["reference_commit_hash"] = commit_hash

    if webpack_hash is None:
        result["result"] = "error"
        result["error"] = f"could not extract manifest.json from {docker_ref}. Check that this tag exists."
        _emit(result, args.json, args.all_cves)
        sys.exit(2)

    log(f"Reference webpack hash for {tag}: {webpack_hash}", args.json)

    if fp["webpack_hash"] == webpack_hash:
        result["result"] = "confirmed"
        if args.cves:
            cdb = cve_db.load(path=args.cve_db, remote=args.remote_cve_db)
            result["cve_audit"] = cve_db.audit([args.version], cdb, cve_filter=args.cve)
        _emit(result, args.json, args.all_cves)
        sys.exit(0)
    else:
        result["result"] = "mismatch"
        _emit(result, args.json, args.all_cves)
        sys.exit(1)


def _emit(result, as_json, show_all_cves=False):
    if as_json:
        print(json.dumps(result, indent=2))
        return

    kv = lambda label, value: print(fmt.kv(label, value, width=LABEL_WIDTH, indent=""))
    t, v, e = result["target"], result["claimed_version"], result["claimed_edition"]

    print()  # separate the output from the shell command that produced it
    kv("Asset", t)
    if result["result"] == "confirmed":
        kv("Status", fmt.color_label("CONFIRMED", "CONFIRMED"))
        kv("Claimed", f"GitLab {e} {fmt.highlight(v)}")
        kv("Live hash", f"{result['live_hash']} (from {result['live_hash_source']})")
        kv("Reference hash", f"{result['reference_hash']} (from {result['reference_hash_source']})")
        if result["cve_audit"] is not None:
            print()
            fmt.print_cve_table(result["cve_audit"], show_all=show_all_cves)
    elif result["result"] == "mismatch":
        kv("Status", fmt.color_label("MISMATCH", "MISMATCH"))
        kv("Claimed", f"GitLab {e} {v} (not a match)")
        kv("Live hash", f"{result['live_hash']} (from {result['live_hash_source']})")
        kv("Reference hash", f"{result['reference_hash']} (from {result['reference_hash_source']})")
        kv("Next step", f"python3 scan.py {t} to determine the running version")
    else:
        kv("Status", fmt.color_label("ERROR", "ERROR"))
        kv("Reason", result.get("error"))
    for err in result["errors"]:
        print(f"  ! {err}")


if __name__ == "__main__":
    main()
