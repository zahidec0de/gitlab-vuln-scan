#!/usr/bin/env python3
"""
Keep gitlab_cves.json current by querying NVD's public CVE API for recently
published GitLab CVEs and parsing GitLab's standard advisory phrasing --
"affecting all versions from X before Y[, A before B, ...]" -- into the
structured affected-range format the rest of this tool consumes.

CVEs whose description doesn't match that phrasing (rare, but happens) are
still recorded, with "affected": [] and "needs_manual_review": true, rather
than silently dropped -- check those by hand against the linked GitLab
patch-release notes and fill in the ranges.

This never touches an existing entry that NVD doesn't (yet) know about --
so a CVE you've hand-entered from GitLab's own release notes ahead of NVD
publishing it (see CVE-2026-10053 in gitlab_cves.json) is left alone until
NVD actually has it.

USAGE
  cd automation
  python3 get_gitlab_cves.py ../gitlab_cves.json [--since-days 400] [--api-key KEY]

An NVD API key (free, https://nvd.nist.gov/developers/request-an-api-key)
raises the rate limit from 5 req/30s to 50 req/30s -- only matters if
--since-days spans enough pages to need more than a couple requests. Set it
via --api-key or the NVD_API_KEY environment variable.
"""
import argparse
import datetime
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
VER = r"\d+(?:\.\d+){0,2}"
# GitLab's advisory phrasing has changed over the years -- newer ones read
# "from 18.2 before 19.0.6", older ones "starting from 15.5 prior to 16.9.7"
# -- and either way, "from"/"starting from" only appears before the *first*
# range in a comma-separated list ("from 18.2 before 19.0.6, 19.1 before
# 19.1.4, and 19.2 before 19.2.2"), so it must be optional here, not
# required, or every range after the first gets silently dropped.
BOUNDED_RANGE_RE = re.compile(rf"({VER})\s+(?:before|prior to|to)\s+({VER})", re.IGNORECASE)
# Some (mostly older) advisories have no lower bound at all: "affecting all
# versions before 17.6.0". Treat that as open from 0.0.0.
UNBOUNDED_RANGE_RE = re.compile(rf"all versions\s+(?:before|prior to)\s+({VER})", re.IGNORECASE)
TITLE_MAX_LEN = 140
# NVD descriptions are one long sentence built from a fixed template:
# "<lead-in> in GitLab CE/EE affecting all versions from X before Y[, ...]
# that/which/where <the actual vulnerability>." A title made by truncating
# that from the start is just the boilerplate lead-in -- the useful part is
# whichever side of the version-range clause isn't boilerplate.
_TITLE_LEADING_FILLER_RE = re.compile(
    r"^[\s,;:]*(?:and|that|which|where|in which|with|under certain conditions|"
    r"could have allowed|could allow|may have allowed|may lead to|"
    r"allows?|when|is vulnerable to)?[\s,;:]*",
    re.IGNORECASE,
)
_TITLE_LEAD_IN_RE = re.compile(
    r"^(?:GitLab has remediated an issue in|An? issue (?:was|has been) discovered(?:\s+in)?|"
    r"An? .*? vulnerability in)\s*",
    re.IGNORECASE,
)
# NVD's keyword search for "GitLab" pulls in unrelated CVEs that merely
# mention it in passing (a third-party tool's GitLab integration, a random
# reference URL, ...). Require GitLab's own standard advisory phrasing --
# "GitLab CE", "GitLab EE", or "GitLab CE/EE" -- not just the bare word.
GITLAB_ADVISORY_RE = re.compile(r"gitlab\s+(?:ce/ee|ce|ee)\b", re.IGNORECASE)


def fetch_nvd_page(keyword, start_index, pub_start, pub_end, api_key, retries=3):
    params = {
        "keywordSearch": keyword,
        "startIndex": str(start_index),
        "resultsPerPage": "200",
        "pubStartDate": pub_start,
        "pubEndDate": pub_end,
    }
    url = f"{NVD_API}?{urllib.parse.urlencode(params)}"
    headers = {"User-Agent": "gitlab-vuln-scan-cve-updater/1.0"}
    if api_key:
        headers["apiKey"] = api_key

    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code in (403, 429) and attempt < retries - 1:
                time.sleep(10 * (attempt + 1))
                continue
            raise


def cvss_from(cve):
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            data = metrics[key][0]["cvssData"]
            return data.get("baseScore"), data.get("vectorString")
    return None, None


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


def parse_ranges(description):
    ranges = [{"from": frm, "before": before} for frm, before in BOUNDED_RANGE_RE.findall(description)]
    if not ranges:
        ranges = [{"from": "0.0.0", "before": before} for before in UNBOUNDED_RANGE_RE.findall(description)]
    return ranges


def extract_title(description, max_len=TITLE_MAX_LEN):
    """
    Pull the actual vulnerability description out of NVD's boilerplate
    sentence, instead of just truncating from the start (which only ever
    yields "GitLab has remediated an issue in GitLab CE/EE affecting all
    versions from ..." -- the version-range clause, not the vulnerability).

    Strategy: find where the version-range clause ends, take everything
    after it (usually "... that could allow X due to Y"), strip the
    connective words. If that's too short (the range clause was at the very
    end of the sentence instead), fall back to everything before the range
    clause, stripping the generic lead-in phrase.
    """
    range_matches = list(BOUNDED_RANGE_RE.finditer(description)) + list(UNBOUNDED_RANGE_RE.finditer(description))

    tail = ""
    if range_matches:
        tail = description[max(m.end() for m in range_matches):]
        prev = None
        while prev != tail:
            prev = tail
            tail = _TITLE_LEADING_FILLER_RE.sub("", tail)
        tail = tail.strip(" .")

    if len(tail) >= 20:
        title = tail
    else:
        # Cut right before the version-range clause starts, not at the
        # first occurrence of "affecting"/"starting" anywhere in the text --
        # those words can legitimately appear earlier too, e.g. "discovered
        # affecting service availability ... affecting all versions from ...".
        head = description[: min(m.start() for m in range_matches)] if range_matches else description
        # strip the trailing "affecting all versions (starting) from" clause
        # that leads into the range itself, however much of it is present
        head = re.sub(
            r"(?:affecting\s+all\s+versions\s+(?:starting\s+)?(?:from\s+)?|starting\s+(?:from\s+)?|affecting\s+)\s*$",
            "", head, flags=re.IGNORECASE,
        ).strip(" ,")
        head = _TITLE_LEAD_IN_RE.sub("", head).strip(" ,")
        head = re.sub(r"^affecting\s+", "", head, flags=re.IGNORECASE)
        title = head if len(head) >= 15 else description

    if title:
        title = title[0].upper() + title[1:]
    if len(title) > max_len:
        title = title[:max_len].rsplit(" ", 1)[0] + "..."
    return title.rstrip(". ")


def build_entry(cve):
    desc = next((d["value"] for d in cve["descriptions"] if d["lang"] == "en"), "")
    cvss, vector = cvss_from(cve)
    ranges = parse_ranges(desc)

    entry = {
        "title": extract_title(desc),
        "cvss": cvss,
        "cvss_vector": vector,
        "severity": severity_for(cvss),
        "published": cve.get("published", "")[:10],
        "description": desc,
        "affected": ranges,
        "references": [r["url"] for r in cve.get("references", [])[:5]],
    }
    if not ranges:
        entry["needs_manual_review"] = True
    return entry


NVD_MAX_WINDOW_DAYS = 120  # NVD rejects pubStartDate/pubEndDate spans wider than this


def _date_windows(since_days, window_days=NVD_MAX_WINDOW_DAYS):
    now = datetime.datetime.utcnow()
    start = now - datetime.timedelta(days=since_days)
    while start < now:
        end = min(start + datetime.timedelta(days=window_days), now)
        yield start, end
        start = end


def find_gitlab_cves(keyword, since_days, api_key, log):
    found = {}
    first_request = True
    rate_limit_delay = 0.6 if api_key else 6  # stay under NVD's unauthenticated 5-req/30s limit

    for window_start, window_end in _date_windows(since_days):
        pub_start = window_start.strftime("%Y-%m-%dT%H:%M:%S.000")
        pub_end = window_end.strftime("%Y-%m-%dT%H:%M:%S.000")

        start_index = 0
        total = None
        while total is None or start_index < total:
            if not first_request:
                time.sleep(rate_limit_delay)
            first_request = False

            page = fetch_nvd_page(keyword, start_index, pub_start, pub_end, api_key)
            total = page.get("totalResults", 0)
            batch = page.get("vulnerabilities", [])
            log(f"NVD {pub_start[:10]}..{pub_end[:10]} offset {start_index}: {len(batch)} of {total} results")

            for item in batch:
                cve = item["cve"]
                desc = next((d["value"] for d in cve["descriptions"] if d["lang"] == "en"), "")
                if not GITLAB_ADVISORY_RE.search(desc):
                    continue
                found[cve["id"]] = build_entry(cve)

            start_index += len(batch)

    return found


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cves_file")
    ap.add_argument("--since-days", type=int, default=400, help="how far back to search NVD publish dates (default: 400)")
    ap.add_argument("--keyword", default="GitLab")
    ap.add_argument("--api-key", default=os.environ.get("NVD_API_KEY"))
    args = ap.parse_args()

    with open(args.cves_file) as f:
        db = json.load(f)

    found = find_gitlab_cves(args.keyword, args.since_days, args.api_key, log=lambda m: print(m, file=sys.stderr))

    added, updated, review = 0, 0, 0
    for cve_id, entry in found.items():
        if cve_id not in db["cves"]:
            added += 1
        elif db["cves"][cve_id] != entry:
            updated += 1
        if entry.get("needs_manual_review"):
            review += 1
        db["cves"][cve_id] = entry

    db["updated"] = datetime.date.today().isoformat()

    with open(args.cves_file, "w") as f:
        json.dump(db, f, indent=4, sort_keys=True)
        f.write("\n")

    print(f"Checked {len(found)} GitLab CVE(s) published in the last {args.since_days} days: "
          f"{added} new, {updated} updated, {review} need manual range review.")


if __name__ == "__main__":
    main()
