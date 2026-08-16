# gitlab-version-nse

Remotely fingerprint the version of a self-managed GitLab instance —
**without authentication, without nmap, with a full evidence trail** so
every result can be re-checked by hand.

```
$ python3 scan.py gitlab-g.drahim.sa:443
=== gitlab-g.drahim.sa:443 ===
  Status     : IDENTIFIED
  Edition    : GitLab enterprise
  Confirmed  : 18.11.7  (floor -- definitely at least this version)
  Candidates : 18.11.7, 18.11.8, 18.11.9
  Method     : gitlab.com commit-hash lookup

  Evidence:
    webpack manifest hash : d6a77cf456c325839dc9
      fetched from        : https://gitlab-g.drahim.sa:443/assets/webpack/manifest.json
    build commit hash     : 2a5d30c85c9
      fetched from        : https://gitlab-g.drahim.sa:443/users/sign_in  (gon.revision)
    resolved via          : https://gitlab.com/api/v4/projects/278964/repository/commits/2a5d30c85c9/refs?type=tag
      matching tags        : v18.11.7-ee, v18.11.8-ee, v18.11.9-ee

  Verify by hand:
    curl -sk https://gitlab-g.drahim.sa:443/assets/webpack/manifest.json | python3 -c "import json,sys; print(json.load(sys.stdin)['hash'])"
    curl -s 'https://gitlab.com/api/v4/projects/278964/repository/commits/2a5d30c85c9/refs?type=tag'
```

## Why this is hard in the first place

GitLab does not expose its version number to unauthenticated visitors on
current releases:
- `/help` used to print it — GitLab removed that.
- `/users/sign_in` used to embed the build commit as `gon.revision` —
  recent releases no longer emit it (some older/self-hosted instances
  still do; the tools use it opportunistically when present).
- There's no `Server` header or public API endpoint that leaks it without
  a session.

Two signals survive on (almost) every version:
1. **The webpack static-assets manifest hash**, at
   `/assets/webpack/manifest.json` — unauthenticated by necessity, since
   the browser needs it to load the UI at all, before login.
2. **The `gon.revision` build commit**, on `/users/sign_in` — present on
   older/some releases only, but when it's there it's gold: it resolves
   directly against GitLab's own public repository, with no local
   dictionary required at all.

Both hashes change only when the underlying build changes. A patch release
that's backend-only, or a base-image rebuild with no application code
change, can leave one or both identical to the previous release — so a
result sometimes has to legitimately report a **range** of possible
versions rather than one exact patch. The tools tell you explicitly when
that's happening; they never silently guess.

---

## Quickstart

```
git clone <your fork>
cd gitlab-version-nse
python3 scan.py HOST:PORT
```

That's it — no dependencies beyond Python 3's standard library for `scan.py`
and `verify_version.py` (`automation/get_gitlab_hashes.py` needs `requests`).

---

## `scan.py` — detect what a target is running

This is the tool for "I don't know what this is, find out."

```
python3 scan.py HOST:PORT [HOST:PORT ...]
```

**What it does, in order, per target:**
1. `GET /assets/webpack/manifest.json` → webpack asset hash.
2. `GET /users/sign_in` → `gon.revision` commit hash, if the target still emits it.
3. If a commit hash was found: ask **gitlab.com's own API** which release
   tag(s) contain that exact commit. Exact, always current, no local file
   involved. (Only works when step 2 found something.)
4. Otherwise: look the webpack hash up in `gitlab_hashes.json`, a local
   dictionary built by `automation/get_gitlab_hashes.py` from every
   published `gitlab/gitlab-ce` / `gitlab/gitlab-ee` Docker tag.

**Every result shows its evidence** — the hash values, the exact URLs
fetched, and (when applicable) the gitlab.com API URL and the tag names it
returned — plus ready-to-paste `curl` commands so you can reproduce the
result yourself without touching this tool.

### Flags

| Flag | Effect |
|---|---|
| `--subdir /path` | GitLab is installed under a sub-path, e.g. behind a reverse proxy at `/gitlab` |
| `--timeout N` | per-request timeout in seconds (default 15) |
| `--no-insecure` | verify TLS certificates (default: don't — most internal instances use self-signed certs) |
| `--remote-db` | use the upstream `gitlab_hashes.json` from GitHub instead of the local copy |
| `--db PATH` | use a specific local `gitlab_hashes.json` |
| `--no-gitlab-com` | skip the gitlab.com cross-check; local dictionary only (no outbound calls besides the target itself) |
| `--json` | machine-readable output — see below |

### Reading the output

- **`Status: IDENTIFIED`, single `Version:` line** — exact match, one version, done.
- **`Status: IDENTIFIED`, `Confirmed:` / `Candidates:` lines** — the
  fingerprint is shared by more than one release (see "Why this is hard"
  above). `Confirmed` is the lowest version in the candidate set — the
  target is *at least* that version. To narrow further, pick a candidate
  and run it through `verify_version.py` (below) — that uses a stronger,
  single-version-specific check.
- **`Status: GITLAB DETECTED, but hash not in local database`** — it's
  definitely GitLab, but this exact build hasn't been catalogued yet
  (usually a release from the last day or two, or `--no-gitlab-com` was
  used on a target with no `gon.revision`). The output gives you the exact
  `verify_version.py` command to run against your best guess.
- **`Status: NOT GITLAB / UNREACHABLE`** — connection failed, timed out, or
  the response wasn't GitLab (e.g. a cPanel port, a different app on that
  port). Check the `!` error lines underneath.

### Scanning a full asset list

```
python3 scan.py \
  34.166.164.101:80 34.166.164.101:443 \
  176.98.32.189:443 \
  gitlab-g.drahim.sa:80 gitlab-g.drahim.sa:443
```

Every target is independent — mix hosts, ports, and unrelated services in
one invocation. Non-GitLab ports just come back `NOT GITLAB / UNREACHABLE`;
that's a correct result, not an error, if you're sweeping a whole port list
from a vendor/scanner.

### JSON output

```
python3 scan.py --json HOST:PORT
```

```json
[
  {
    "target": "gitlab-g.drahim.sa:443",
    "status": "identified",
    "edition": "enterprise",
    "versions": ["18.11.7", "18.11.8", "18.11.9"],
    "confirmed_floor": "18.11.7",
    "ambiguous": true,
    "evidence": {
      "manifest_url": "https://gitlab-g.drahim.sa:443/assets/webpack/manifest.json",
      "signin_url": "https://gitlab-g.drahim.sa:443/users/sign_in",
      "webpack_hash": "d6a77cf456c325839dc9",
      "commit_hash": "2a5d30c85c9",
      "method": "gitlab.com commit-hash lookup",
      "gitlab_com_queries": [
        {
          "project": "gitlab-org/gitlab",
          "url": "https://gitlab.com/api/v4/projects/278964/repository/commits/2a5d30c85c9/refs?type=tag",
          "http_status": 200,
          "matched_tags": ["v18.11.7-ee", "v18.11.8-ee", "v18.11.9-ee"]
        },
        { "project": "gitlab-org/gitlab-foss", "...": "..." }
      ],
      "hashdb_source": null,
      "hashdb_matched_key": null,
      "hashdb_match_type": null
    },
    "verify_hint": null,
    "errors": []
  }
]
```

`status` is one of `identified` / `hash_not_in_db` / `not_gitlab_or_unreachable`.
Pipe into `jq` to build a report, e.g.:

```
python3 scan.py --json $(cat targets.txt) | jq -r '.[] | "\(.target)\t\(.edition)\t\(.confirmed_floor // "unknown")"'
```

Exit code: `0` if every target was identified, `1` otherwise (still check
the output — a `hash_not_in_db` target was still positively detected as
GitLab, it just needs `verify_version.py` for the last step).

---

## `verify_version.py` — confirm or refute one specific version

This is the tool for "I think it's exactly X — prove it or disprove it."

```
python3 verify_version.py --target HOST:PORT --version 18.11.7 --edition ee
```

It streams the *exact* webpack manifest hash for `gitlab/gitlab-ee:18.11.7-ee.0`
straight out of Docker Hub's registry (no `docker pull`, no local Docker
daemon — it reads only the one file it needs out of the image layers) and
diffs it byte-for-byte against what the live target serves.

```
$ python3 verify_version.py --target gitlab-g.drahim.sa:443 --version 18.11.7 --edition ee
[*] fetching live fingerprint from gitlab-g.drahim.sa:443
[*] live webpack hash:   d6a77cf456c325839dc9
[*] pulling ground-truth hash for gitlab/gitlab-ee:18.11.7-ee.0 from Docker Hub (streaming, no docker pull)...
  scanning layer 9/9 sha256:018cd9809513...
[*] 18.11.7-ee.0 webpack hash:  d6a77cf456c325839dc9

CONFIRMED: gitlab-g.drahim.sa:443 is running GitLab ee 18.11.7
  live hash      : d6a77cf456c325839dc9  (from https://gitlab-g.drahim.sa:443/assets/webpack/manifest.json)
  reference hash : d6a77cf456c325839dc9  (from gitlab/gitlab-ee:18.11.7-ee.0 (Docker Hub registry, streamed))
```

An exact hash match here is as close to certain as this technique gets —
it's not a lookup, it's a direct diff against the real published artifact.

### When to reach for this instead of `scan.py`

- `scan.py` gave you a candidate range and you want to test one specific
  member of it.
- A vendor, scanner, or ticket claims a specific version and you want a
  hard yes/no.
- `scan.py` reported `hash_not_in_db` (brand-new release).

### Flags

| Flag | Effect |
|---|---|
| `--tag-suffix` | Docker tag suffix, default `.0` (i.e. `VERSION-ce.0` / `VERSION-ee.0`) |
| `--subdir /path` | same as `scan.py` |
| `--timeout N` | per-request timeout for the *live target* fetch (the Docker Hub side has its own longer internal timeout, since layers can be 1-2 GB) |
| `--no-insecure` | verify TLS certs |
| `--json` | machine-readable output |

### JSON output

```json
{
  "target": "gitlab-g.drahim.sa:443",
  "claimed_version": "18.11.7",
  "claimed_edition": "ee",
  "docker_ref": "gitlab/gitlab-ee:18.11.7-ee.0",
  "live_hash": "d6a77cf456c325839dc9",
  "live_hash_source": "https://gitlab-g.drahim.sa:443/assets/webpack/manifest.json",
  "reference_hash": "d6a77cf456c325839dc9",
  "reference_hash_source": "gitlab/gitlab-ee:18.11.7-ee.0 (Docker Hub registry, streamed)",
  "reference_commit_hash": "2a5d30c85c9dce93e4d6beebf3c5d83f4519441a",
  "result": "confirmed",
  "errors": []
}
```

`result` is one of `confirmed` / `mismatch` / `error`. Exit codes: `0`
confirmed, `1` mismatch, `2` error (target unreachable, or the claimed
version's Docker tag doesn't exist — double check the version string).

---

## `gitlab_version.nse` — the original Nmap script

Same core technique (webpack hash + local dictionary only — no gitlab.com
cross-check), packaged as an Nmap NSE script for use inside a broader Nmap
scan:

```
nmap <target> --script ./gitlab_version.nse [--script-args="subdir=/custom-subdir"]
```

Prefer `scan.py` for anything beyond a quick check — it has the gitlab.com
cross-check, evidence output, and JSON mode this script doesn't.

---

## `gitlab_hashes.json` / `automation/` — keeping the dictionary current

`automation/get_gitlab_hashes.py` keeps `gitlab_hashes.json` current by
walking every non-rc/nightly Docker tag for `gitlab-ce`/`gitlab-ee` and
recording its webpack manifest hash and build commit hash — streamed
directly from the Docker registry, no Docker daemon required. It runs on a
schedule via GitHub Actions (`.github/workflows/main.yml`) and only commits
when the dictionary actually changed.

```
cd automation
python3 get_gitlab_hashes.py ../gitlab_hashes.json [--fetch-all-tags] [--budget-minutes=100]
```

- `--fetch-all-tags` — walk every page of Docker Hub's tag list instead of
  just the most recent page (needed once, for a from-scratch rebuild).
- `--budget-minutes=N` — stop gracefully after N minutes and let the next
  scheduled run pick up where it left off (default 100, under the 120-minute
  GitHub Actions job timeout). Progress is written after every tag, so an
  interruption never loses work.

---

## Practical workflow

```
# 1. Sweep an asset list to see what's actually there
python3 scan.py host1:443 host2:443 host3:80 host3:443

# 2. Got a range back? Pin it against your best-guess candidate
python3 verify_version.py --target host1:443 --version 18.11.7 --edition ee

# 3. Automate a report
python3 scan.py --json $(cat hosts.txt) > report.json
jq -r '.[] | [.target, .edition, .confirmed_floor] | @tsv' report.json
```
