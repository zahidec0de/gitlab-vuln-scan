# gitlab-version-nse

Tools to fingerprint the version of a (self-managed) GitLab instance remotely,
without authentication.

## Why this is hard

GitLab does not expose its version number to unauthenticated visitors on
current releases:
- `/help` used to print it, GitLab removed that.
- `/users/sign_in` used to embed the build commit as `gon.revision`; recent
  releases no longer emit it (older/some self-hosted instances still do).
- There's no `Server` header or API endpoint that leaks it without a session.

The one signal that's still there on every version we've tested is the
**webpack static-assets manifest hash** at `/assets/webpack/manifest.json`,
which is unauthenticated by necessity (browsers need to fetch it to load the
UI). It changes whenever GitLab's frontend bundle changes, which is most
releases but not always every patch release — patch/security releases that
only touch backend Ruby code can leave it unchanged across several
consecutive versions, so this signal narrows you down to a small candidate
set rather than always a single exact patch.

## Tools

### `scan.py` — identify what a target is running

```
python3 scan.py HOST:PORT [HOST:PORT ...]
python3 scan.py --subdir /gitlab HOST:PORT
python3 scan.py --json HOST:PORT
```

For each target it:
1. Fetches the live webpack manifest hash (and, if present, the legacy
   `gon.revision` commit hash).
2. If a commit hash is present, resolves it **directly against gitlab.com's
   own API** — no local dictionary involved, always current, exact. This
   only works on instances that still expose `gon.revision`.
3. Otherwise, falls back to looking the webpack hash up in `gitlab_hashes.json`,
   a local dictionary of (hash -> version) built by pulling every published
   `gitlab/gitlab-ce` and `gitlab/gitlab-ee` Docker tag (see `automation/`).

### `verify_version.py` — confirm or refute a specific claimed version

Use this when you (or a vendor, or a scanner) already suspect a specific
version and just want a yes/no answer, or when the hash isn't in
`gitlab_hashes.json` yet (e.g. a release from the last day or two).

```
python3 verify_version.py --target HOST:PORT --version 18.11.7 --edition ee
```

It pulls the *exact* webpack manifest hash for that version straight from
Docker Hub's registry — streamed directly from the image layer, no `docker
pull`/daemon needed — and diffs it against what the live target actually
serves. An exact hash match is as close to certain as this technique gets.

### `gitlab_version.nse` — the original Nmap script

Same technique as `scan.py`, as an Nmap NSE script, for use inside an Nmap
scan:

```
nmap <target> --script ./gitlab_version.nse [--script-args="subdir=/custom-subdir"]
```

## `gitlab_hashes.json` / `automation/`

`automation/get_gitlab_hashes.py` keeps `gitlab_hashes.json` current by
pulling every non-rc/nightly Docker tag for `gitlab-ce`/`gitlab-ee` and
recording its webpack manifest hash and build commit hash, streamed directly
from the Docker registry (no Docker daemon required). It runs on a schedule
via GitHub Actions (`.github/workflows/main.yml`) and only commits when the
dictionary actually changes.

```
cd automation
python3 get_gitlab_hashes.py ../gitlab_hashes.json [--fetch-all-tags] [--budget-minutes=100]
```
