"""
Resolve a GitLab commit hash to release tag(s) using gitlab.com's own public
API. This needs no local dictionary at all and is always current: as soon as
a version ships, its tag is on gitlab.com.

Caveat: only works when the target still exposes `gon.revision` on its
sign-in page. GitLab has been removing that from some deployments/versions,
so treat this as a bonus high-confidence signal, not the primary method --
the webpack manifest hash (lib/hashdb.py, lib/registry.py) is what still
works everywhere.
"""
import json
import urllib.request

API = "https://gitlab.com/api/v4"

# gitlab-org/gitlab (id 278964) is the EE monorepo -- release tags there are
# suffixed "-ee" (e.g. v18.11.7-ee). gitlab-org/gitlab-foss (id 13083) is the
# CE mirror -- tags there have no suffix (e.g. v19.1.2). A given commit will
# only resolve on whichever repo it was actually built/tagged from, so we
# check both regardless of what edition the caller thinks it is.
PROJECT_IDS = [278964, 13083]


def resolve_commit_to_versions(commit_hash, timeout=15):
    """
    Returns a sorted list of {"version": "18.11.7", "edition": "enterprise"}
    dicts for every release tag containing this commit, across both the EE
    and CE-foss repos. Empty list if it couldn't be resolved anywhere.
    """
    results = {}

    for project_id in PROJECT_IDS:
        url = f"{API}/projects/{project_id}/repository/commits/{commit_hash}/refs?type=tag"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "gitlab-version-scan/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                if r.status != 200:
                    continue
                refs = json.load(r)
        except Exception:
            continue

        for ref in refs:
            name = ref.get("name", "")
            if "rc" in name or "nightly" in name:
                continue
            v = name.lstrip("v")
            edition = "community"
            if v.endswith("-ee"):
                edition = "enterprise"
                v = v[: -len("-ee")]
            elif v.endswith("-ce"):
                v = v[: -len("-ce")]
            if v and v[0].isdigit():
                results[(v, edition)] = True

    return sorted(({"version": v, "edition": e} for (v, e) in results.keys()), key=lambda r: (r["version"], r["edition"]))
