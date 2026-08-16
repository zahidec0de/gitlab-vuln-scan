#!/usr/bin/env python3
import json
import os
import sys
import time

import requests

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from lib import registry  # noqa: E402

global builds
global ignore_list
builds = ["gitlab-ce", "gitlab-ee"]
ignore_list = ["rc", "nightly", "latest"]


def main(argv):
    if(len(argv) == 0):
        exit("hashes_dict_file file missing")
    hashes_dict_file = argv[0]

    fetch_all_tags = False
    budget_minutes = 100
    if (len(argv) > 1):
        fetch_all_tags = "--fetch-all-tags" in argv[1:]
        for arg in argv[1:]:
            if arg.startswith("--budget-minutes="):
                budget_minutes = float(arg.split("=", 1)[1])

    hashes = process_missing_tags(hashes_dict_file, fetch_all_tags, budget_minutes)
    write_hashes_dict(hashes, hashes_dict_file)


def get_manifest_hashes(build, version):
    repo = f"gitlab/{build}"
    print("Processing image: %s:%s" % (repo, version))

    def log(msg):
        print("  " + msg)

    try:
        webpack_hash, commit_hash = registry.fetch_manifest_hash(repo, version, log=log)
    except Exception as e:
        print("Failed to fetch %s:%s (%s)" % (repo, version, e))
        webpack_hash, commit_hash = None, None

    if webpack_hash is None:
        print("Failed to get webpack hash for %s:%s" % (repo, version))
    if commit_hash is None:
        print("Failed to get commit hash for %s:%s" % (repo, version))

    return {
        "webpack_hash": webpack_hash,
        "commit_hash": commit_hash
    }


def load_hashes_dict(hashes_dict_file):
    with open(hashes_dict_file, "r") as file:
        raw_hashes = file.read()
    hashes = json.loads(raw_hashes)

    return hashes


def write_hashes_dict(hashes, path):
    with open(path, "w") as output:
        json.dump(hashes, output, indent=4, sort_keys=True)


def load_tags(build, fetch_all_tags=False):
    # get tags from docker hub
    tags_endpoint = "https://registry.hub.docker.com/v2/repositories/gitlab/%s/tags?page_size=100" % build

    tags = []

    while True:
        response = requests.get(tags_endpoint)
        if response.status_code == 200:
            print("Fetching tags page %s" % tags_endpoint)
            tags.extend(response.json()["results"])

            if response.json()["next"] and fetch_all_tags:
                tags_endpoint = response.json()["next"]
                time.sleep(1)
            else:
                break
        else:
            print(response.json())
            exit("Failed to fetch tags for %s" % build)

    return tags


def load_processed_tags():
    with open("tags_processed.json", "r") as file:
        raw_processed_tags = file.read()
    processed_tags = json.loads(raw_processed_tags)

    return processed_tags


def write_processed_tags(processed):
    for build in builds:
        processed[build] = sorted(processed[build])

    with open("tags_processed.json", "w") as output:
        json.dump(processed, output, indent=4, sort_keys=True)


def process_missing_tags(hashes_dict_file, fetch_all_tags=False, budget_minutes=100):
    hashes = load_hashes_dict(hashes_dict_file)
    processed = load_processed_tags()
    deadline = time.monotonic() + budget_minutes * 60

    # process missing tags
    for build in builds:
        tags = load_tags(build, fetch_all_tags)
        for tag in tags:
            version = str(tag["name"])
            if(
                not any(ignore in version for ignore in ignore_list)
                and
                version not in processed[build]
            ):
                if time.monotonic() > deadline:
                    print("Time budget (%s min) exhausted, stopping. Remaining tags will be picked up next run." % budget_minutes)
                    write_processed_tags(processed)
                    write_hashes_dict(hashes, hashes_dict_file)
                    return hashes

                clean_version = version[:version.index('-')]
                hash = get_manifest_hashes(build, version)

                if hash['webpack_hash'] is not None:
                    if hashes.get(hash['webpack_hash']):
                        hashes[hash['webpack_hash']]["versions"].append(clean_version)
                        hashes[hash['webpack_hash']]["versions"] = list(set(hashes[hash['webpack_hash']]["versions"]))
                    else:
                        hashes[hash['webpack_hash']] = {"build": build, "versions": [clean_version]}

                if hash['commit_hash'] is not None:
                    if hashes.get(hash['commit_hash']):
                        hashes[hash['commit_hash']]["versions"].append(clean_version)
                        hashes[hash['commit_hash']]["versions"] = list(set(hashes[hash['commit_hash']]["versions"]))
                    else:
                        hashes[hash['commit_hash']] = {"build": build, "versions": [clean_version]}

                processed[build].append(version)

            # do partial writes to avoid losing progress
            write_processed_tags(processed)
            write_hashes_dict(hashes, hashes_dict_file)

    return hashes


if __name__ == "__main__":
    main(sys.argv[1:])
