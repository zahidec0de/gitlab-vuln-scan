#!/usr/bin/env python3
"""
Directly verify a claimed GitLab version against a live target -- no
dictionary lookup, no guessing. Pulls the *exact* webpack manifest hash for
the claimed version straight from Docker Hub's registry (streamed, no
`docker pull` needed) and diffs it against what the live host actually
serves.

Use this when:
  - a vendor/scanner claims a specific version and you want to confirm it
  - the hash isn't in gitlab_hashes.json yet (brand new release)

Usage:
    python3 verify_version.py --target HOST:PORT --version 18.11.7 --edition ee
    python3 verify_version.py --target HOST:PORT --version 19.1.2 --edition ce --subdir /gitlab
"""
import argparse
import sys

from lib import registry, target

REPO_BY_EDITION = {"ce": "gitlab/gitlab-ce", "ee": "gitlab/gitlab-ee"}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", required=True, help="host:port")
    ap.add_argument("--version", required=True, help="claimed version, e.g. 18.11.7")
    ap.add_argument("--edition", required=True, choices=["ce", "ee"])
    ap.add_argument("--tag-suffix", default=".0", help="docker tag suffix (default: .0, i.e. VERSION-ce.0)")
    ap.add_argument("--subdir", default="")
    ap.add_argument("--timeout", type=float, default=15)
    ap.add_argument("--no-insecure", action="store_true")
    args = ap.parse_args()

    if ":" in args.target:
        host, port = args.target.rsplit(":", 1)
    else:
        host, port = args.target, "443"

    repo = REPO_BY_EDITION[args.edition]
    tag = f"{args.version}-{args.edition}{args.tag_suffix}"

    print(f"[*] fetching live fingerprint from {host}:{port}", file=sys.stderr)
    fp = target.fetch_target_fingerprint(host, port, subdir=args.subdir, timeout=args.timeout, insecure=not args.no_insecure)
    for err in fp["errors"]:
        print(f"    ! {err}", file=sys.stderr)

    if fp["webpack_hash"] is None:
        print("ERROR: could not read a webpack manifest hash from the target", file=sys.stderr)
        sys.exit(2)

    print(f"[*] live webpack hash:   {fp['webpack_hash']}", file=sys.stderr)
    print(f"[*] pulling ground-truth hash for {repo}:{tag} from Docker Hub (streaming, no docker pull)...", file=sys.stderr)

    webpack_hash, commit_hash = registry.fetch_manifest_hash(repo, tag, log=lambda m: print(m, file=sys.stderr))

    if webpack_hash is None:
        print(f"ERROR: couldn't extract manifest.json from {repo}:{tag} -- does that tag exist?", file=sys.stderr)
        sys.exit(2)

    print(f"[*] {tag} webpack hash:  {webpack_hash}", file=sys.stderr)
    print()

    if fp["webpack_hash"] == webpack_hash:
        print(f"CONFIRMED: {host}:{port} is running GitLab {args.edition} {args.version}")
        print(f"  (webpack manifest hash matches exactly: {webpack_hash})")
        sys.exit(0)
    else:
        print(f"MISMATCH: {host}:{port} is NOT running GitLab {args.edition} {args.version}")
        print(f"  target hash:  {fp['webpack_hash']}")
        print(f"  {args.version} hash: {webpack_hash}")
        print(f"  Run scan.py against this target to find its actual version, or try adjacent")
        print(f"  patch versions with this script if you suspect it's just off by a patch level.")
        sys.exit(1)


if __name__ == "__main__":
    main()
