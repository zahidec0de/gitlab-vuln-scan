"""
Resolve a GitLab commit hash to release tag(s) using gitlab.com's own public
API. This needs no local dictionary at all and is always current: as soon as
a version ships, its tag is on gitlab.com.

Caveat: this only works when the target still exposes `gon.revision` on
its sign-in page. GitLab has been removing that from some deployments and
versions, so treat this as a bonus high-confidence signal rather than the
primary method. The webpack manifest hash (lib/hashdb.py, lib/registry.py)
is what still works everywhere.

IMPORTANT: `/repository/commits/:sha/refs?type=tag` returns every tag the
commit is an ANCESTOR of, not just tags whose own tip is that exact commit.
Since patch releases are cumulative (each later patch's tip descends from
the previous one), a commit that is the exact tip of v18.11.7-ee is also,
trivially, an ancestor of v18.11.8-ee, v18.11.9-ee, and v18.11.11-ee -
those later tags simply have additional commits on top. Treating that
whole list as "the target could be running any of these" is wrong; it
would only be right if those later tags' own tip commits were the SAME
commit, which does genuinely happen (a patch that ships no gitlab-rails
changes re-tags the prior commit) but has to be verified, not assumed.
So every candidate tag from `refs` is confirmed here by fetching its own
`/repository/tags/:name` and keeping only the ones whose own commit id
matches `commit_hash` exactly. What's left after that really is
identical-build ambiguity; anything filtered out was just a later
descendant release, not a possible match.
"""
import json
import urllib.error
import urllib.parse
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


def _get_json(url, timeout):
    req = urllib.request.Request(url, headers={"User-Agent": "gitlab-vuln-scan/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, json.load(r)


def _tag_commit_id(project_id, tag_name, timeout):
    """Full commit sha that `tag_name` itself points at, or None on any failure."""
    url = f"{API}/projects/{project_id}/repository/tags/{urllib.parse.quote(tag_name, safe='')}"
    try:
        status, data = _get_json(url, timeout)
        if status != 200:
            return None
        return data.get("commit", {}).get("id")
    except Exception:
        return None


def resolve_commit_to_versions(commit_hash, timeout=15):
    """
    Queries gitlab.com for every release tag containing `commit_hash`, then
    confirms each one by checking whether its own tip commit actually is
    `commit_hash` (see module docstring for why the first list alone
    overclaims: it includes later tags that merely descend from this commit).

    Returns a dict:
      {
        "versions": [{"version": "18.11.7", "edition": "enterprise", "tag": "v18.11.7-ee"}, ...],
        "queries": [{"project": "gitlab-org/gitlab", "url": "...", "http_status": 200,
                      "matched_tags": [...], "confirmed_tags": [...], "descendant_tags": [...]}, ...],
      }
    `matched_tags` is the raw, ancestor-inclusive list gitlab.com returned
    (what `curl <url>` reproduces). `confirmed_tags` is the subset whose own
    commit is exactly `commit_hash` - that's what `versions` is built from.
    `descendant_tags` is the rest: real releases, just not this one.
    `queries` is included even on a miss, so callers can see exactly which
    URL was hit and re-run it themselves with `curl <url>`.
    """
    versions = {}
    queries = []

    for project_id, project_path in PROJECTS:
        url = f"{API}/projects/{project_id}/repository/commits/{commit_hash}/refs?type=tag"
        query_record = {
            "project": project_path, "project_id": project_id, "url": url, "http_status": None,
            "matched_tags": [], "confirmed_tags": [], "descendant_tags": [],
        }
        queries.append(query_record)

        try:
            status, refs = _get_json(url, timeout)
            query_record["http_status"] = status
            if status != 200:
                continue
        except urllib.error.HTTPError as e:
            query_record["http_status"] = e.code
            continue
        except Exception as e:
            query_record["http_status"] = f"error: {e}"
            continue

        candidates = []
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
                candidates.append((name, v, edition))

        for name, v, edition in candidates:
            tag_commit = _tag_commit_id(project_id, name, timeout)
            if tag_commit is not None and tag_commit.startswith(commit_hash):
                query_record["confirmed_tags"].append(name)
                versions[(v, edition)] = name
            else:
                query_record["descendant_tags"].append(name)

    version_list = sorted(
        ({"version": v, "edition": e, "tag": tag} for (v, e), tag in versions.items()),
        key=lambda r: (r["version"], r["edition"]),
    )
    return {"versions": version_list, "queries": queries}
