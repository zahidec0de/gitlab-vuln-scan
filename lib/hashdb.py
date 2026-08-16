"""Load and query gitlab_hashes.json (webpack/commit hash -> {build, versions})."""
import json
import os
import urllib.request

LOCAL_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "gitlab_hashes.json")
REMOTE_URL = "https://raw.githubusercontent.com/righel/gitlab-version-nse/main/gitlab_hashes.json"

EDITION_BY_BUILD = {"gitlab-ce": "community", "gitlab-ee": "enterprise"}


def load(path=None, remote=False, timeout=15):
    if remote:
        with urllib.request.urlopen(REMOTE_URL, timeout=timeout) as r:
            return json.load(r)
    with open(path or LOCAL_PATH) as f:
        return json.load(f)


def lookup(db, webpack_hash=None, commit_hash=None):
    """
    Mirrors gitlab_version.nse's get_banner(): prefer a commit-hash prefix
    match (more specific, when available), fall back to exact webpack hash.

    Returns (banner, matched_key, match_type) where match_type is
    "commit_hash" or "webpack_hash", or (None, None, None) if nothing hit.
    """
    if commit_hash:
        for key, value in db.items():
            if isinstance(key, str) and key.startswith(commit_hash):
                return value, key, "commit_hash"
    if webpack_hash and webpack_hash in db:
        return db[webpack_hash], webpack_hash, "webpack_hash"
    return None, None, None


def edition_for(build):
    return EDITION_BY_BUILD.get(build, "*")
