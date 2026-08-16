#!/usr/bin/env python3
"""
Scan one or more GitLab instances and report their likely version(s) by
matching the live webpack static-assets manifest hash (and, on older
instances, the sign-in page commit hash) against gitlab_hashes.json.

No nmap required -- this is the same fingerprinting technique as
gitlab_version.nse, runnable directly against a host:port list.

Usage:
    python3 scan.py HOST:PORT [HOST:PORT ...]
    python3 scan.py --subdir /gitlab HOST:PORT
    python3 scan.py --remote-db HOST:PORT   # use the upstream hashes DB instead of local
    python3 scan.py --json HOST:PORT

Exit code is nonzero if any target could not be identified.
"""
import argparse
import json
import sys

from lib import gitlab_com, hashdb, target


def scan_one(hostport, subdir, timeout, insecure, db, no_gitlab_com):
    if ":" in hostport:
        host, port = hostport.rsplit(":", 1)
    else:
        host, port = hostport, "443"

    fp = target.fetch_target_fingerprint(host, port, subdir=subdir, timeout=timeout, insecure=insecure)

    result = {
        "target": f"{host}:{port}",
        "webpack_hash": fp["webpack_hash"],
        "commit_hash": fp["commit_hash"],
        "errors": fp["errors"],
        "source": None,
        "edition": None,
        "versions": None,
    }

    if fp["webpack_hash"] is None and fp["commit_hash"] is None:
        result["status"] = "not-gitlab-or-unreachable"
        return result

    # Prefer resolving the commit hash directly against gitlab.com -- exact,
    # always current, no local dictionary needed. Only some instances still
    # expose gon.revision, so this isn't always available.
    if fp["commit_hash"] and not no_gitlab_com:
        hits = gitlab_com.resolve_commit_to_versions(fp["commit_hash"])
        if hits:
            result["status"] = "identified"
            result["source"] = "gitlab.com commit lookup"
            editions = {h["edition"] for h in hits}
            result["edition"] = editions.pop() if len(editions) == 1 else "/".join(sorted(editions))
            result["versions"] = sorted(h["version"] for h in hits)
            return result

    banner = hashdb.lookup(db, webpack_hash=fp["webpack_hash"], commit_hash=fp["commit_hash"])
    if banner is None:
        result["status"] = "hash-not-in-db"
        return result

    result["status"] = "identified"
    result["source"] = "gitlab_hashes.json"
    result["edition"] = hashdb.edition_for(banner["build"])
    result["versions"] = sorted(banner["versions"])
    return result


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("targets", nargs="+", help="host:port, e.g. 34.166.164.101:443")
    ap.add_argument("--subdir", default="", help="GitLab installed under a sub-path, e.g. /gitlab")
    ap.add_argument("--timeout", type=float, default=15)
    ap.add_argument("--no-insecure", action="store_true", help="verify TLS certs (default: don't)")
    ap.add_argument("--remote-db", action="store_true", help="fetch gitlab_hashes.json from GitHub instead of using the local copy")
    ap.add_argument("--db", default=None, help="path to a local gitlab_hashes.json")
    ap.add_argument("--no-gitlab-com", action="store_true", help="skip the gitlab.com commit-hash cross-check, use only the local hash DB")
    ap.add_argument("--json", action="store_true", help="output JSON instead of text")
    args = ap.parse_args()

    db = hashdb.load(path=args.db, remote=args.remote_db)

    results = []
    for t in args.targets:
        results.append(scan_one(t, args.subdir, args.timeout, not args.no_insecure, db, args.no_gitlab_com))

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for r in results:
            print(f"== {r['target']} ==")
            if r["status"] == "identified":
                versions = "/".join(r["versions"])
                print(f"  GitLab {r['edition']} {versions}  [via {r['source']}]")
                if len(r["versions"]) > 1:
                    print(f"  note: earliest is the confirmed floor ({r['versions'][0]}); {len(r['versions'])} releases")
                    print(f"        share this exact build, so an exact patch can't be pinned from this signal alone")
            elif r["status"] == "hash-not-in-db":
                print(f"  GitLab detected (webpack_hash={r['webpack_hash']}, commit_hash={r['commit_hash']})")
                print(f"  but this hash isn't in gitlab_hashes.json yet -- use verify_version.py to check")
                print(f"  against a specific version you suspect it is")
            else:
                print(f"  not identified as GitLab, or unreachable")
            for err in r["errors"]:
                print(f"  ! {err}")
            print()

    sys.exit(0 if all(r["status"] == "identified" for r in results) else 1)


if __name__ == "__main__":
    main()
