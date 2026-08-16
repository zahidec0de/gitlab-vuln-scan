"""
Fetch GitLab version fingerprints straight off a live target: the webpack
static-assets manifest hash, which works on every version tested so far
including current 18.x/19.x releases, and the legacy `gon.revision` commit
hash from the sign-in page. That commit hash is only present on older
GitLab releases (current versions no longer emit it), but the fallback is
kept here for old instances that still do.
"""
import json
import re
import ssl
import urllib.request

DEFAULT_TIMEOUT = 15
UA = "Mozilla/5.0 (compatible; gitlab-version-scan/1.0)"


def _get(url, timeout, insecure):
    ctx = None
    if url.startswith("https://") and insecure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
        return r.status, r.read()


def fetch_target_fingerprint(host, port, scheme=None, subdir="", timeout=DEFAULT_TIMEOUT, insecure=True):
    """
    Returns dict: {webpack_hash, commit_hash, manifest_url, signin_url, errors}
    scheme is inferred from the port if not given (443/8443/2083 etc -> https).
    """
    if scheme is None:
        scheme = "http" if str(port) == "80" else "https"

    subdir = subdir.rstrip("/")
    base = f"{scheme}://{host}:{port}{subdir}"
    manifest_url = f"{base}/assets/webpack/manifest.json"
    signin_url = f"{base}/users/sign_in"

    result = {
        "webpack_hash": None,
        "commit_hash": None,
        "manifest_url": manifest_url,
        "signin_url": signin_url,
        "errors": [],
    }

    try:
        status, body = _get(manifest_url, timeout, insecure)
        if status == 200:
            data = json.loads(body)
            if isinstance(data, dict) and "hash" in data:
                result["webpack_hash"] = str(data["hash"])
        else:
            result["errors"].append(f"manifest.json HTTP {status}")
    except Exception as e:
        result["errors"].append(f"manifest.json fetch failed: {e}")

    try:
        status, body = _get(signin_url, timeout, insecure)
        if status == 200:
            m = re.search(rb'gon\.revision\s*=\s*"([0-9a-f]+)"', body)
            if m:
                result["commit_hash"] = m.group(1).decode()
        else:
            result["errors"].append(f"sign_in HTTP {status}")
    except Exception as e:
        result["errors"].append(f"sign_in fetch failed: {e}")

    return result
