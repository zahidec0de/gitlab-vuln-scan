"""
Docker Hub registry v2 helpers to pull a single file out of an image tag
without needing a local Docker daemon, `docker pull`, or full image export.

We stream each layer blob straight from the registry, decompress it on the
fly, and read the tar stream member-by-member, stopping as soon as we hit
the file we're looking for. Nothing is written to disk.
"""
import gzip
import json
import tarfile
import urllib.request

REGISTRY = "https://registry-1.docker.io"
AUTH = "https://auth.docker.io/token"

WEBPACK_MANIFEST_PATH = "opt/gitlab/embedded/service/gitlab-rails/public/assets/webpack/manifest.json"
VERSION_MANIFEST_PATH = "opt/gitlab/version-manifest.json"


def get_token(repo):
    url = f"{AUTH}?service=registry.docker.io&scope=repository:{repo}:pull"
    with urllib.request.urlopen(url, timeout=30) as r:
        return json.load(r)["token"]


def get_amd64_layers(repo, tag, token):
    req = urllib.request.Request(
        f"{REGISTRY}/v2/{repo}/manifests/{tag}",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.docker.distribution.manifest.list.v2+json,"
            "application/vnd.oci.image.index.v1+json",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        top = json.load(r)

    if top.get("mediaType", "").endswith("manifest.list.v2+json") or "manifests" in top:
        digest = next(
            m["digest"] for m in top["manifests"] if m.get("platform", {}).get("architecture") == "amd64"
        )
        req = urllib.request.Request(
            f"{REGISTRY}/v2/{repo}/manifests/{digest}",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.docker.distribution.manifest.v2+json",
            },
        )
        with urllib.request.urlopen(req, timeout=30) as r:
            top = json.load(r)

    return [layer["digest"] for layer in top["layers"]]


def _find_in_layer(repo, digest, token, target_path):
    req = urllib.request.Request(
        f"{REGISTRY}/v2/{repo}/blobs/{digest}",
        headers={"Authorization": f"Bearer {token}"},
    )
    resp = urllib.request.urlopen(req, timeout=120)
    try:
        gz = gzip.GzipFile(fileobj=resp, mode="rb")
        tf = tarfile.open(fileobj=gz, mode="r|")
        for member in tf:
            if member.name.lstrip("./") == target_path.lstrip("/"):
                f = tf.extractfile(member)
                return f.read() if f else None
        return None
    finally:
        resp.close()


def extract_files(repo, tag, target_paths, log=lambda *a, **k: None):
    """
    Fetch multiple files from one image tag in a single pass over its layers.
    Returns {path: bytes or None}.
    """
    token = get_token(repo)
    layers = get_amd64_layers(repo, tag, token)
    found = {}
    remaining = set(target_paths)

    for i, digest in enumerate(layers):
        if not remaining:
            break
        log(f"  scanning layer {i + 1}/{len(layers)} {digest[:19]}...")
        for path in list(remaining):
            try:
                data = _find_in_layer(repo, digest, token, path)
            except Exception as e:
                log(f"    error reading layer for {path}: {e}")
                continue
            if data is not None:
                found[path] = data
                remaining.discard(path)

    for path in remaining:
        found[path] = None
    return found


def fetch_manifest_hash(repo, tag, log=lambda *a, **k: None):
    """Return (webpack_hash, commit_hash) for a given docker repo:tag, either may be None."""
    files = extract_files(repo, tag, [WEBPACK_MANIFEST_PATH, VERSION_MANIFEST_PATH], log=log)

    webpack_hash = None
    raw = files.get(WEBPACK_MANIFEST_PATH)
    if raw:
        try:
            webpack_hash = str(json.loads(raw)["hash"])
        except Exception:
            pass

    commit_hash = None
    raw = files.get(VERSION_MANIFEST_PATH)
    if raw:
        try:
            commit_hash = str(json.loads(raw)["software"]["gitlab-rails"]["locked_version"])
        except Exception:
            pass

    return webpack_hash, commit_hash
