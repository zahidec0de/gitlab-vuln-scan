# gitlab-sentinel

Remotely fingerprint the version of a self-managed GitLab instance and audit
it against known CVEs — **without authentication, without nmap, with a full
evidence trail** so every result can be independently re-checked by hand.

```
$ python3 scan.py --cves gitlab-g.drahim.sa:443
=== gitlab-g.drahim.sa:443 ===
  Status     : IDENTIFIED
  Edition    : GitLab enterprise
  Version    : 18.11.7  (confirmed floor)
  Also possible: 18.11.8, 18.11.9
               these releases share an identical build fingerprint and cannot be
               told apart remotely -- run verify_version.py to pin one exactly
  Method     : gitlab.com commit-hash lookup

  Evidence:
    webpack manifest hash : d6a77cf456c325839dc9
      fetched from        : https://gitlab-g.drahim.sa:443/assets/webpack/manifest.json
    build commit hash     : 2a5d30c85c9
      fetched from        : https://gitlab-g.drahim.sa:443/users/sign_in  (gon.revision)
    resolved via          : https://gitlab.com/api/v4/projects/278964/repository/commits/2a5d30c85c9/refs?type=tag
      matching tags        : v18.11.7-ee, v18.11.8-ee, v18.11.9-ee

  Verify manually:
    curl -sk https://gitlab-g.drahim.sa:443/assets/webpack/manifest.json \
      | python3 -c "import json,sys; print(json.load(sys.stdin)['hash'])"
    curl -s 'https://gitlab.com/api/v4/projects/278964/repository/commits/2a5d30c85c9/refs?type=tag'
    python3 verify_version.py --target gitlab-g.drahim.sa:443 --version 18.11.7 --edition <ce|ee>

  CVE audit (427 checked, 20 flagged):
    CVE             CVSS  SEVERITY  STATUS      FIXED IN
    --------------  ----  --------  ----------  ----------------------
    CVE-2026-15217  8.7   high      VULNERABLE  19.0.6; 19.1.4; 19.2.2
    CVE-2026-15216  8.7   high      VULNERABLE  19.0.6; 19.1.4; 19.2.2
    CVE-2026-10053  8.5   high      VULNERABLE  19.0.6; 19.1.4; 19.2.2
    ...
    (407 more checked as NOT VULNERABLE -- pass --all-cves to list them)
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
   the browser needs it to load the UI before login.
2. **The `gon.revision` build commit**, on `/users/sign_in` — present on
   some releases only, but when it's there it resolves directly against
   GitLab's own public repository, with no local dictionary at all.

Both hashes change only when the underlying build changes. A patch release
that's backend-only, or a base-image rebuild with no application code
change, can leave one or both identical to the previous release — so a
result sometimes legitimately reports a **range** of possible versions
rather than one exact patch. The tools say so explicitly; they never
silently guess.

---

## Quickstart

```
git clone <your fork>
cd gitlab-sentinel
python3 scan.py HOST:PORT               # detect
python3 scan.py --cves HOST:PORT        # detect + CVE audit
```

No dependencies beyond Python 3's standard library for `scan.py` and
`verify_version.py`. `automation/*.py` needs `requests`.

---

## `scan.py` — detect what a target is running, optionally audit it

This is the tool for "I don't know what this is, find out, and tell me if
it's vulnerable."

```
python3 scan.py HOST:PORT [HOST:PORT ...]
python3 scan.py --cves HOST:PORT [HOST:PORT ...]
```

**Detection, in order, per target:**
1. `GET /assets/webpack/manifest.json` → webpack asset hash.
2. `GET /users/sign_in` → `gon.revision` commit hash, if the target still emits it.
3. If a commit hash was found: ask **gitlab.com's own API** which release
   tag(s) contain that exact commit. Exact, always current, no local file
   involved.
4. Otherwise: look the webpack hash up in `gitlab_hashes.json`, a local
   dictionary built by `automation/get_gitlab_hashes.py` from every
   published `gitlab/gitlab-ce` / `gitlab/gitlab-ee` Docker tag.

**CVE audit (`--cves`):** each candidate version from detection is checked
against every documented affected-version range in `gitlab_cves.json`
(real "from X before Y" ranges per CVE, sourced from NVD — see
[CVE database](#gitlab_hashesjson--gitlab_cvesjson--automation--keeping-both-databases-current)
below). A finding is:

| Status | Meaning |
|---|---|
| `VULNERABLE` | every candidate version detection returned falls inside an affected range |
| `NOT VULNERABLE` | no candidate falls inside any affected range |
| `NEEDS VERIFICATION` | detection returned a range that straddles the fix boundary — some candidates are affected, some aren't, so the real verdict depends on the exact patch. Pin it with `verify_version.py` first. |

Every result — detection and CVE audit alike — shows its evidence and gives
ready-to-paste `curl` commands so you can reproduce it without trusting
this tool.

### Flags

| Flag | Effect |
|---|---|
| `--subdir /path` | GitLab is installed under a sub-path, e.g. behind a reverse proxy at `/gitlab` |
| `--timeout N` | per-request timeout in seconds (default 15) |
| `--no-insecure` | verify TLS certificates (default: don't — most internal instances use self-signed certs) |
| `--remote-db` | use the upstream `gitlab_hashes.json` from GitHub instead of the local copy |
| `--db PATH` | use a specific local `gitlab_hashes.json` |
| `--no-gitlab-com` | skip the gitlab.com cross-check; local dictionary only (no outbound calls besides the target itself) |
| `--cves` | audit each identified target against `gitlab_cves.json` |
| `--cve CVE-ID` | with `--cves`, restrict the audit to one CVE |
| `--cve-db PATH` | use a specific local `gitlab_cves.json` |
| `--remote-cve-db` | fetch `gitlab_cves.json` from GitHub instead of the local copy |
| `--all-cves` | with `--cves`, also list every CVE checked as `NOT VULNERABLE` (default: only flagged ones — the database has 400+ entries, most targets are only affected by a handful) |
| `--json` | machine-readable output — see below |

### Reading the output

- **`Status: IDENTIFIED`, single `Version:` line** — exact match, one version, done.
- **`Status: IDENTIFIED`, `Also possible:` line** — the fingerprint is
  shared by more than one release (see "Why this is hard" above). The
  `Version:` line is the confirmed floor — the target is *at least* that
  version. Pin it exactly with `verify_version.py`.
- **`Status: GITLAB DETECTED, hash not in local database`** — definitely
  GitLab, but this exact build hasn't been catalogued yet (usually a
  release from the last day or two). The output gives the exact
  `verify_version.py` command to run against your best guess.
- **`Status: NOT GITLAB / UNREACHABLE`** — connection failed, timed out, or
  the response wasn't GitLab. Check the `!` error lines underneath.

### Scanning a full asset list, and the summary table

```
python3 scan.py --cves \
  34.166.164.101:443 176.98.32.189:443 gitlab-g.drahim.sa:443
```

Any run with more than one target prints a summary table at the end:

```
=== Summary ===
TARGET               EDITION     VERSION  CVE FINDINGS   MAX CVSS
--------------------  ----------  -------  -------------  --------
34.166.164.101:443   enterprise  18.11.7  20 vulnerable  8.7
176.98.32.189:443    community   19.1.2   26 vulnerable  8.7
```

Non-GitLab ports just come back `NOT GITLAB / UNREACHABLE` in their own
section and `not gitlab or unreachable` in the summary row — that's a
correct result, not an error, when sweeping a mixed port list.

### JSON output

```
python3 scan.py --json --cves HOST:PORT
```

JSON is kept strictly structured — no prose, no narrative strings, stable
field names — so it's safe to feed to other tooling. `status` and CVE
`status` are fixed enums (`identified` / `hash_not_in_db` /
`not_gitlab_or_unreachable`, and `vulnerable` / `not_vulnerable` /
`needs_verification`), never free text. `cve_audit` always contains the
**full** audit (all CVEs checked, not just flagged ones) regardless of
`--all-cves`, which only affects the text table.

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
        }
      ],
      "hashdb_source": null,
      "hashdb_matched_key": null,
      "hashdb_match_type": null
    },
    "verify_hint": null,
    "cve_audit": [
      {
        "cve": "CVE-2026-15217",
        "title": "Cross-site Scripting in Analytics Dashboards table cell content",
        "cvss": 8.7,
        "severity": "high",
        "status": "vulnerable",
        "matched_ranges": ["18.2 ≤ v < 19.0.6"],
        "fixed_versions": ["19.0.6", "19.1.4", "19.2.2"],
        "references": ["https://docs.gitlab.com/releases/patches/patch-release-gitlab-19-2-2-released/", "..."]
      }
    ],
    "errors": []
  }
]
```

Pipe into `jq` to build a report, e.g.:

```
python3 scan.py --json --cves $(cat targets.txt) \
  | jq -r '.[] | .target as $t | .cve_audit[]? | select(.status=="vulnerable") | [$t, .cve, .severity, .cvss] | @csv'
```

Exit code: `0` if every target was identified and (with `--cves`) nothing
came back `vulnerable`/`needs_verification`; `1` otherwise.

---

## `verify_version.py` — confirm or refute one specific version

This is the tool for "I think it's exactly X — prove it or disprove it."

```
python3 verify_version.py --target HOST:PORT --version 18.11.7 --edition ee
python3 verify_version.py --target HOST:PORT --version 18.11.7 --edition ee --cves
```

It streams the *exact* webpack manifest hash for `gitlab/gitlab-ee:18.11.7-ee.0`
straight out of Docker Hub's registry (no `docker pull`, no local Docker
daemon — it reads only the one file it needs out of the image layers) and
diffs it byte-for-byte against what the live target serves. An exact hash
match here is as close to certain as this technique gets — it's not a
lookup, it's a direct diff against the real published artifact.

```
$ python3 verify_version.py --target gitlab-g.drahim.sa:443 --version 18.11.7 --edition ee --cves
[*] fetching live fingerprint from gitlab-g.drahim.sa:443
[*] live webpack hash:   d6a77cf456c325839dc9
[*] pulling ground-truth hash for gitlab/gitlab-ee:18.11.7-ee.0 from Docker Hub (streaming, no docker pull)...
  scanning layer 9/9 sha256:018cd9809513...
[*] 18.11.7-ee.0 webpack hash:  d6a77cf456c325839dc9

CONFIRMED: gitlab-g.drahim.sa:443 is running GitLab ee 18.11.7
  live hash      : d6a77cf456c325839dc9  (from https://gitlab-g.drahim.sa:443/assets/webpack/manifest.json)
  reference hash : d6a77cf456c325839dc9  (from gitlab/gitlab-ee:18.11.7-ee.0 (Docker Hub registry, streamed))

  CVE audit (427 checked, 20 flagged):
    ...
```

### When to reach for this instead of `scan.py`

- `scan.py` gave you a candidate range and you want to test one specific member.
- A vendor, scanner, or ticket claims a specific version and you want a hard yes/no.
- `scan.py` reported `hash_not_in_db` (brand-new release).

Because this checks one exact version rather than a range, its CVE audit
never returns `NEEDS VERIFICATION` — only `VULNERABLE` or `NOT VULNERABLE`.

### Flags

Same `--cves` / `--cve` / `--cve-db` / `--remote-cve-db` / `--all-cves` /
`--json` as `scan.py`, plus:

| Flag | Effect |
|---|---|
| `--tag-suffix` | Docker tag suffix, default `.0` (i.e. `VERSION-ce.0` / `VERSION-ee.0`) |
| `--subdir /path` | same as `scan.py` |
| `--timeout N` | per-request timeout for the *live target* fetch (Docker Hub side has its own longer internal timeout, since layers can be 1-2 GB) |
| `--no-insecure` | verify TLS certs |

Exit codes: `0` confirmed, `1` mismatch, `2` error (target unreachable, or
the claimed version's Docker tag doesn't exist — double-check the version
string).

---

## `gitlab_version.nse` — the original Nmap script

Same core technique (webpack hash + local dictionary only — no gitlab.com
cross-check, no CVE audit), packaged as an Nmap NSE script for use inside a
broader Nmap scan:

```
nmap <target> --script ./gitlab_version.nse [--script-args="subdir=/custom-subdir"]
```

Prefer `scan.py` for anything beyond a quick check — it has the gitlab.com
cross-check, evidence output, CVE audit, and JSON mode this script doesn't.

---

## `gitlab_hashes.json` / `gitlab_cves.json` / `automation/` — keeping both databases current

**`automation/get_gitlab_hashes.py`** keeps `gitlab_hashes.json` current by
walking every non-rc/nightly Docker tag for `gitlab-ce`/`gitlab-ee` and
recording its webpack manifest hash and build commit hash — streamed
directly from the Docker registry, no Docker daemon required.

```
cd automation
python3 get_gitlab_hashes.py ../gitlab_hashes.json [--fetch-all-tags] [--budget-minutes=100]
```

- `--fetch-all-tags` — walk every page of Docker Hub's tag list instead of
  just the most recent page (needed once, for a from-scratch rebuild).
- `--budget-minutes=N` — stop gracefully after N minutes and let the next
  scheduled run continue (default 100, under the 120-minute GitHub Actions
  job timeout). Progress is written after every tag, so an interruption
  never loses work.

**`automation/get_gitlab_cves.py`** keeps `gitlab_cves.json` current by
querying [NVD's public CVE API](https://nvd.nist.gov/developers) for
recently published GitLab CVEs and parsing GitLab's standard advisory
phrasing ("affecting all versions from X before Y[, A before B, ...]",
older-style "starting from X prior to Y", or an unbounded "all versions
before Y") into the structured ranges the rest of this tool consumes. This
is what makes `--cves` more current than a scanner that only queries
Vulners or another third-party aggregator at scan time — new CVEs land in
this database within a day of NVD publishing them, with exact per-branch
fixed versions, not just a CVSS score.

```
cd automation
python3 get_gitlab_cves.py ../gitlab_cves.json [--since-days 400] [--api-key KEY]
```

- `--since-days N` — how far back to search NVD publish dates (default
  400; the scheduled job uses 14, since it runs daily).
- `--api-key` / `NVD_API_KEY` env var — optional, raises NVD's rate limit
  from 5 req/30s to 50 req/30s. [Free to request](https://nvd.nist.gov/developers/request-an-api-key).
- Entries whose description doesn't match any known phrasing are still
  recorded, with `"affected": []` and `"needs_manual_review": true`,
  rather than silently dropped — check those against the linked GitLab
  patch-release notes and fill in the ranges by hand.
- Never overwrites a hand-curated entry that NVD doesn't have yet (see
  `CVE-2026-10053` in `gitlab_cves.json` — added from GitLab's own
  patch-release notes ahead of NVD publishing it).

Both scripts run on a daily schedule via GitHub Actions
(`.github/workflows/main.yml`) and only commit when a database actually
changed.

---

## Practical workflow

```
# 1. Sweep an asset list, with CVE audit, to see what's there and what's exposed
python3 scan.py --cves host1:443 host2:443 host3:80 host3:443

# 2. Got a range back, or want a hard yes/no on a vendor's claim?
python3 verify_version.py --target host1:443 --version 18.11.7 --edition ee --cves

# 3. Automate a report
python3 scan.py --json --cves $(cat hosts.txt) > report.json
jq -r '.[] | .target as $t | .cve_audit[]? | select(.status!="not_vulnerable") | [$t, .cve, .status, .cvss] | @tsv' report.json
```

---

## Credits

Built on the fingerprinting technique and hash-dictionary approach
pioneered by [righel/gitlab-version-nse](https://github.com/righel/gitlab-version-nse)
(Apache-2.0), and informed by [Simpuar/gitlab-cve-scanner](https://github.com/Simpuar/gitlab-cve-scanner)
(Apache-2.0), which extended the same idea toward CVE reporting. This
project keeps the core detection method, and adds the gitlab.com direct
commit-resolution path, a Docker-registry-streaming verifier, and a
self-updating range-based CVE database sourced from NVD rather than a live
third-party lookup at scan time.
