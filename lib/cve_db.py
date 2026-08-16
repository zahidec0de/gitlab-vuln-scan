"""
Load gitlab_cves.json and check a detected version (or range of candidate
versions) against each CVE's documented affected ranges.

Range format, matching how GitLab and NVD actually publish these (see
gitlab_cves.json): a CVE can affect several disjoint "from X before Y"
intervals at once, e.g. CVE-2026-15217 affects [18.2, 19.0.6), [19.1, 19.1.4),
and [19.2, 19.2.2) simultaneously -- three different release lines, three
different fixed versions. "from" is inclusive, "before" is exclusive.
"""
import json
import os
import re
import urllib.request

LOCAL_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "gitlab_cves.json")
# Placeholder until this repo is actually pushed to a fork -- update once you
# know the real remote path, or just always pass --db/skip --remote-db.
REMOTE_URL = "https://raw.githubusercontent.com/zahidec0de/gitlab-sentinel/main/gitlab_cves.json"

VULNERABLE = "vulnerable"
NOT_VULNERABLE = "not_vulnerable"
NEEDS_VERIFICATION = "needs_verification"

STATUS_LABEL = {
    VULNERABLE: "VULNERABLE",
    NOT_VULNERABLE: "NOT VULNERABLE",
    NEEDS_VERIFICATION: "NEEDS VERIFICATION",
}


def load(path=None, remote=False, timeout=15):
    if remote:
        with urllib.request.urlopen(REMOTE_URL, timeout=timeout) as r:
            data = json.load(r)
    else:
        with open(path or LOCAL_PATH) as f:
            data = json.load(f)
    return data["cves"]


def version_tuple(v):
    """'18.11.7' -> (18, 11, 7); '19.1' -> (19, 1, 0). Non-numeric input -> (0, 0, 0)."""
    parts = [int(p) for p in re.findall(r"\d+", v)][:3]
    parts += [0] * (3 - len(parts))
    return tuple(parts)


def _in_range(version, rng):
    v = version_tuple(version)
    return version_tuple(rng["from"]) <= v < version_tuple(rng["before"])


def severity_for(cvss):
    if cvss is None:
        return "unknown"
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    return "low"


def _check_one_cve(candidate_versions, entry):
    """
    candidate_versions: one or more version strings the target might be
    (>1 when scan.py couldn't pin an exact patch level).

    Returns (status, matched_ranges): status is VULNERABLE if every
    candidate falls in an affected range, NOT_VULNERABLE if none do, and
    NEEDS_VERIFICATION if the candidates straddle a fix boundary -- i.e. the
    verdict actually depends on which exact patch it is.
    """
    per_candidate = []
    matched = []
    for v in candidate_versions:
        hit = next((rng for rng in entry["affected"] if _in_range(v, rng)), None)
        per_candidate.append(hit is not None)
        if hit is not None:
            matched.append(f"{hit['from']} ≤ v < {hit['before']}")

    if all(per_candidate):
        status = VULNERABLE
    elif not any(per_candidate):
        status = NOT_VULNERABLE
    else:
        status = NEEDS_VERIFICATION

    # de-duplicate, keep order
    seen = []
    for m in matched:
        if m not in seen:
            seen.append(m)
    return status, seen


def audit(candidate_versions, db, cve_filter=None):
    """
    Returns a list of finding dicts, most severe first:
      {cve, title, cvss, severity, status, matched_ranges, fixed_versions, references}
    """
    items = db.items()
    if cve_filter:
        items = [(cve_filter, db[cve_filter])] if cve_filter in db else []

    findings = []
    for cve_id, entry in items:
        status, matched_ranges = _check_one_cve(candidate_versions, entry)
        findings.append({
            "cve": cve_id,
            "title": entry.get("title"),
            "cvss": entry.get("cvss"),
            "severity": entry.get("severity") or severity_for(entry.get("cvss")),
            "status": status,
            "matched_ranges": matched_ranges,
            "fixed_versions": sorted({rng["before"] for rng in entry["affected"]}),
            "references": entry.get("references", []),
        })

    findings.sort(key=lambda f: (-(f["cvss"] or 0), f["cve"]))
    return findings
