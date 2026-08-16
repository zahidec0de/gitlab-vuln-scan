"""
Resolve a GitLab commit hash to release tag(s) using gitlab.com's own public
API. This needs no local dictionary at all and is always current: as soon as
a version ships, its tag is on gitlab.com.

Caveat: this only works when the target still exposes `gon.revision` on
its sign-in page. GitLab has been removing that from some deployments and
versions, so treat this as a bonus high-confidence signal rather than the
primary method. The webpack manifest hash (lib/hashdb.py, lib/registry.py)
is what still works everywhere.
"""
import json
import urllib.error
import urllib.request

API = "https://gitlab.com/api/v4"

# gitlab-org/gitlab (id 278964) is the EE monorepo. Release tags there are
# suffixed "-ee" (e.g. v18.11.7-ee). gitlab-org/gitlab-foss (id 13083) is
# the CE mirror, where tags have no suffix (e.g. v19.1.2). A given commit
# will only resolve on whichever repo it was actually built and tagged
# from, so both are checked regardless of what edition the caller thinks
# it is.
PROJECTS = [
    (278964, "gitlab-org/gitlab"),
    (13083, "gitlab-org/gitlab-foss"),
]


def resolve_commit_to_versions(commit_hash, timeout=15):
    """
    Queries gitlab.com for every release tag containing `commit_hash`.

    Returns a dict:
      {
        "versions": [{"version": "18.11.7", "edition": "enterprise", "tag": "v18.11.7-ee"}, ...],
        "queries": [{"project": "gitlab-org/gitlab", "url": "...", "http_status": 200, "matched_tags": [...]}, ...],
      }
    `queries` is included even on a miss, so callers can see exactly which
    URL was hit and re-run it themselves with `curl <url>`.
    """
    versions = {}
    queries = []

    for project_id, project_path in PROJECTS:
        url = f"{API}/projects/{project_id}/repository/commits/{commit_hash}/refs?type=tag"
        query_record = {"project": project_path, "url": url, "http_status": None, "matched_tags": []}
        queries.append(query_record)

        try:
            req = urllib.request.Request(url, headers={"User-Agent": "gitlab-vuln-scan/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                query_record["http_status"] = r.status
                if r.status != 200:
                    continue
                refs = json.load(r)
        except urllib.error.HTTPError as e:
            query_record["http_status"] = e.code
            continue
        except Exception as e:
            query_record["http_status"] = f"error: {e}"
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
                query_record["matched_tags"].append(name)
                versions[(v, edition)] = name

    version_list = sorted(
        ({"version": v, "edition": e, "tag": tag} for (v, e), tag in versions.items()),
        key=lambda r: (r["version"], r["edition"]),
    )
    return {"versions": version_list, "queries": queries}
