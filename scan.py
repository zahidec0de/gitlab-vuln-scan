#!/usr/bin/env python3
"""
Detect the GitLab version(s) running on one or more targets, with a full
evidence trail so every result can be independently re-checked by hand.

No nmap required -- same fingerprinting technique as gitlab_version.nse,
runnable directly against a host:port list.

METHOD (tried in this order, per target):
  1. Fetch /assets/webpack/manifest.json  -> webpack asset hash.
     Fetch /users/sign_in                 -> gon.revision commit hash, if present.
  2. If a commit hash was found: resolve it directly against gitlab.com's
     own API (no local dictionary, always current, exact -- but only works
     on targets that still expose gon.revision).
  3. Otherwise: look the webpack hash up in gitlab_hashes.json (local file,
     or --remote-db to pull the upstream copy from GitHub).

A result can legitimately map to MORE THAN ONE version: some patch releases
don't change the frontend bundle or the gitlab-rails build at all (e.g. a
base-image-only rebuild), so several versions can share an identical
fingerprint. When that happens the tool tells you so explicitly and reports
the lowest version as the confirmed floor -- run verify_version.py against
a specific candidate if you need to narrow further.

USAGE
  python3 scan.py HOST:PORT [HOST:PORT ...]
  python3 scan.py --subdir /gitlab HOST:PORT       # GitLab under a sub-path
  python3 scan.py --json HOST:PORT                 # machine-readable output
  python3 scan.py --remote-db HOST:PORT            # use upstream gitlab_hashes.json
  python3 scan.py --no-gitlab-com HOST:PORT        # local dictionary only, no internet lookup beyond the target

EXIT CODE
  0  every target was identified
  1  at least one target could not be identified (still worth reading -- see its evidence)

EXAMPLES
  python3 scan.py gitlab-g.drahim.sa:443
  python3 scan.py 34.166.164.101:80 34.166.164.101:443 176.98.32.189:443
  python3 scan.py --json gitlab-g.drahim.sa:443 | jq '.[0].versions'
"""
import argparse
import json
import sys

from lib import gitlab_com, hashdb, target


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
        "confirmed_floor": None,  # lowest version in `versions` -- the one you know it's AT LEAST
        "ambiguous": None,        # true if versions has >1 entry
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
        "errors": fp["errors"],
    }

    if fp["webpack_hash"] is None and fp["commit_hash"] is None:
        result["status"] = "not_gitlab_or_unreachable"
        return result

    # Prefer resolving the commit hash directly against gitlab.com -- exact,
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
                f"python3 verify_version.py --target {host}:{port} --version X.Y.Z --edition ce|ee"
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


def print_text(r):
    print(f"=== {r['target']} ===")

    if r["status"] == "identified":
        floor = r["confirmed_floor"]
        print(f"  Status     : IDENTIFIED")
        print(f"  Edition    : GitLab {r['edition']}")
        if r["ambiguous"]:
            print(f"  Confirmed  : {floor}  (floor -- definitely at least this version)")
            print(f"  Candidates : {', '.join(r['versions'])}")
        else:
            print(f"  Version    : {floor}")
        print(f"  Method     : {r['evidence']['method']}")
        print()
        print(f"  Evidence:")
        print(f"    webpack manifest hash : {r['evidence']['webpack_hash']}")
        print(f"      fetched from        : {r['evidence']['manifest_url']}")
        if r["evidence"]["commit_hash"]:
            print(f"    build commit hash     : {r['evidence']['commit_hash']}")
            print(f"      fetched from        : {r['evidence']['signin_url']}  (gon.revision)")
        if r["evidence"]["gitlab_com_queries"]:
            for q in r["evidence"]["gitlab_com_queries"]:
                if q["matched_tags"]:
                    print(f"    resolved via          : {q['url']}")
                    print(f"      matching tags        : {', '.join(q['matched_tags'])}")
        if r["evidence"]["hashdb_matched_key"]:
            print(f"    matched in            : {r['evidence']['hashdb_source']}")
            print(f"      key ({r['evidence']['hashdb_match_type']})   : {r['evidence']['hashdb_matched_key']}")
        print()
        print(f"  Verify by hand:")
        print(f"    curl -sk {r['evidence']['manifest_url']} | python3 -c \"import json,sys; print(json.load(sys.stdin)['hash'])\"")
        if r["evidence"]["gitlab_com_queries"]:
            for q in r["evidence"]["gitlab_com_queries"]:
                if q["matched_tags"]:
                    print(f"    curl -s '{q['url']}'")
        if r["ambiguous"]:
            print(f"    python3 verify_version.py --target {r['target']} --version {floor} --edition <ce|ee>")

    elif r["status"] == "hash_not_in_db":
        print(f"  Status     : GITLAB DETECTED, but hash not in local database")
        print(f"  Evidence:")
        print(f"    webpack manifest hash : {r['evidence']['webpack_hash']}")
        print(f"      fetched from        : {r['evidence']['manifest_url']}")
        if r["evidence"]["commit_hash"]:
            print(f"    build commit hash     : {r['evidence']['commit_hash']}  (not resolvable on gitlab.com either)")
        print()
        print(f"  Next step:")
        print(f"    {r['verify_hint']}")

    else:
        print(f"  Status     : NOT GITLAB / UNREACHABLE")

    for err in r["errors"]:
        print(f"  ! {err}")
    print()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("targets", nargs="+", help="host:port, e.g. gitlab-g.drahim.sa:443")
    ap.add_argument("--subdir", default="", help="GitLab installed under a sub-path, e.g. /gitlab")
    ap.add_argument("--timeout", type=float, default=15, help="per-request timeout in seconds (default: 15)")
    ap.add_argument("--no-insecure", action="store_true", help="verify TLS certs (default: don't -- most internal instances use self-signed certs)")
    ap.add_argument("--remote-db", action="store_true", help="fetch gitlab_hashes.json from GitHub instead of using the local copy")
    ap.add_argument("--db", default=None, help="path to a local gitlab_hashes.json (default: the one next to this script)")
    ap.add_argument("--no-gitlab-com", action="store_true", help="skip the gitlab.com commit-hash cross-check, use only the local hash DB")
    ap.add_argument("--json", action="store_true", help="output machine-readable JSON instead of text")
    args = ap.parse_args()

    db = hashdb.load(path=args.db, remote=args.remote_db)
    db_source = hashdb.REMOTE_URL if args.remote_db else (args.db or hashdb.LOCAL_PATH)

    results = [
        scan_one(t, args.subdir, args.timeout, not args.no_insecure, db, db_source, args.no_gitlab_com)
        for t in args.targets
    ]

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for r in results:
            print_text(r)

    sys.exit(0 if all(r["status"] == "identified" for r in results) else 1)


if __name__ == "__main__":
    main()
