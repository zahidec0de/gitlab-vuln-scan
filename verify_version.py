#!/usr/bin/env python3
"""
Confirm or refute one specific claimed GitLab version against a live target.
No dictionary lookup, no guessing: pulls the *exact* webpack manifest hash
for the claimed version straight from Docker Hub's registry (streamed --
no `docker pull` / Docker daemon needed) and diffs it byte-for-byte against
what the live host actually serves.

Use this when:
  - a vendor/scanner claims a specific version and you want a hard yes/no
  - scan.py returned "hash not in db" (a release too new for the local
    dictionary) or an ambiguous range and you want to test one candidate

USAGE
  python3 verify_version.py --target HOST:PORT --version 18.11.7 --edition ee
  python3 verify_version.py --target HOST:PORT --version 19.1.2 --edition ce --subdir /gitlab
  python3 verify_version.py --target HOST:PORT --version 18.11.7 --edition ee --json

EXIT CODE
  0  confirmed match
  1  mismatch (target is running something else)
  2  error (target unreachable, or the claimed version's docker tag doesn't exist)

Add --cves to also audit the pinned version against gitlab_cves.json once
confirmed -- since this is an exact single version (not a range), the
verdict is never "needs verification" the way scan.py's can be.

EXAMPLE
  $ python3 verify_version.py --target gitlab-g.drahim.sa:443 --version 18.11.7 --edition ee --cves
  CONFIRMED: gitlab-g.drahim.sa:443 is running GitLab ee 18.11.7
    live hash      : d6a77cf456c325839dc9  (from https://gitlab-g.drahim.sa:443/assets/webpack/manifest.json)
    reference hash : d6a77cf456c325839dc9  (from gitlab/gitlab-ee:18.11.7-ee.0 (Docker Hub registry, streamed))

  CVE audit:
    CVE            CVSS  SEVERITY  STATUS       FIXED IN
    ----------------------------------------------------
    CVE-2026-15217  8.7  high      VULNERABLE   19.0.6; 19.1.4; 19.2.2
"""
import argparse
import json
import sys

from lib import cve_db, format as fmt, registry, target

REPO_BY_EDITION = {"ce": "gitlab/gitlab-ce", "ee": "gitlab/gitlab-ee"}


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
    ap.add_argument("--no-insecure", action="store_true", help="verify TLS certs (default: don't)")
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
        "reference_hash_source": f"{docker_ref} (Docker Hub registry, streamed)",
        "result": None,
        "cve_audit": None,
        "errors": [],
    }

    log(f"[*] fetching live fingerprint from {args.target}", args.json)
    fp = target.fetch_target_fingerprint(host, port, subdir=args.subdir, timeout=args.timeout, insecure=not args.no_insecure)
    result["errors"].extend(fp["errors"])
    result["live_hash"] = fp["webpack_hash"]
    result["live_hash_source"] = fp["manifest_url"]

    if fp["webpack_hash"] is None:
        result["result"] = "error"
        result["error"] = "could not read a webpack manifest hash from the target"
        _emit(result, args.json, args.all_cves)
        sys.exit(2)

    log(f"[*] live webpack hash:   {fp['webpack_hash']}", args.json)
    log(f"[*] pulling ground-truth hash for {docker_ref} from Docker Hub (streaming, no docker pull)...", args.json)

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
        result["error"] = f"couldn't extract manifest.json from {docker_ref} -- does that tag exist?"
        _emit(result, args.json, args.all_cves)
        sys.exit(2)

    log(f"[*] {tag} webpack hash:  {webpack_hash}", args.json)
    log("", args.json)

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

    t, v, e = result["target"], result["claimed_version"], result["claimed_edition"]
    if result["result"] == "confirmed":
        print(f"CONFIRMED: {t} is running GitLab {e} {v}")
        print(f"  live hash      : {result['live_hash']}  (from {result['live_hash_source']})")
        print(f"  reference hash : {result['reference_hash']}  (from {result['reference_hash_source']})")
        if result["cve_audit"] is not None:
            print()
            fmt.print_cve_table(result["cve_audit"], show_all=show_all_cves)
    elif result["result"] == "mismatch":
        print(f"MISMATCH: {t} is NOT running GitLab {e} {v}")
        print(f"  live hash      : {result['live_hash']}  (from {result['live_hash_source']})")
        print(f"  reference hash : {result['reference_hash']}  (from {result['reference_hash_source']})")
        print(f"  Next step: python3 scan.py {t}  -- to find what it's actually running")
    else:
        print(f"ERROR: {result.get('error')}")
    for err in result["errors"]:
        print(f"  ! {err}")


if __name__ == "__main__":
    main()
