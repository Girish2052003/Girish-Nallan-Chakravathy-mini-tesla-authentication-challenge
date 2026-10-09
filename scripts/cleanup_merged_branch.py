"""Delete only the exact head of this merged PR, using an atomic Git lease.

There is deliberately no scan of historical PRs or unrelated branches. API reads
establish merge provenance; the server-side expected-SHA check prevents TOCTOU
loss of new work. The token is inherited by Git from actions/checkout and used
in memory for API reads; it is never interpolated into a command or printed.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, urlopen


SHA = re.compile(r"[0-9a-f]{40}\Z")


def valid_branch(name):
    return (type(name) is str and name != "main"
            and subprocess.run(["git", "check-ref-format", "--branch", name],
                               capture_output=True).returncode == 0)


def candidate(event, repository, pull, branch):
    """Return (name, exact PR head, merge commit), or conservatively keep it."""
    try:
        event_pr = event["pull_request"]
        repo = repository["full_name"]
        name, head, merge = pull["head"]["ref"], pull["head"]["sha"], pull["merge_commit_sha"]
        if not (event["action"] == "closed" and event_pr["merged"] is True
                and pull["merged"] is True and repository["default_branch"] == "main"
                and event["repository"]["full_name"] == repo
                and event["number"] == pull["number"] == event_pr["number"]
                and pull["head"]["repo"]["full_name"] == repo
                and event_pr["head"]["repo"]["full_name"] == repo
                and pull["base"]["repo"]["full_name"] == repo
                and event_pr["base"]["repo"]["full_name"] == repo
                and pull["base"]["ref"] == event_pr["base"]["ref"] == "main"
                and branch["protected"] is False
                and name == branch["name"] == event_pr["head"]["ref"]
                and head == branch["commit"]["sha"] == event_pr["head"]["sha"]
                and merge == event_pr["merge_commit_sha"]
                and type(head) is str and SHA.fullmatch(head)
                and type(merge) is str and SHA.fullmatch(merge)
                and valid_branch(name)):
            return None
        return name, head, merge
    except (KeyError, TypeError):
        return None


def delete_with_lease(directory, name, head, merge):
    """Check integration, then let Git atomically compare and delete the ref."""
    if not valid_branch(name) or not SHA.fullmatch(head) or not SHA.fullmatch(merge):
        raise ValueError("invalid deletion candidate")
    def git(*args):
        return subprocess.run(["git", "-C", str(directory), *args], check=True,
                              capture_output=True, text=True)
    git("fetch", "--no-tags", "origin", "refs/heads/main")
    git("merge-base", "--is-ancestor", merge, "FETCH_HEAD")
    git("push", f"--force-with-lease=refs/heads/{name}:{head}",
        "origin", f":refs/heads/{name}")


def main():
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    repo = os.environ["GITHUB_REPOSITORY"]
    if (not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo)
            or event.get("action") != "closed"
            or event.get("pull_request", {}).get("merged") is not True):
        print("KEEP: not a merged PR event")
        return

    def api(path):
        request = Request(f"https://api.github.com/repos/{repo}{path}", headers={
            "Authorization": "Bearer " + os.environ["GITHUB_TOKEN"],
            "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
        })
        with urlopen(request, timeout=30) as response:
            return json.load(response)

    repository = api("")
    pull = api(f"/pulls/{int(event['number'])}")
    name = pull["head"]["ref"]
    if not valid_branch(name):
        print("KEEP: invalid or main branch")
        return
    try:
        branch = api("/branches/" + quote(name, safe=""))
    except HTTPError as exc:
        if exc.code == 404:
            print("KEEP: branch already absent")
            return
        raise
    selected = candidate(event, repository, pull, branch)
    if selected is None:
        print("KEEP: exact merged head, same repository, and unprotected branch not established")
        return
    delete_with_lease(Path.cwd(), *selected)
    print("Deleted the verified merged head with an expected-SHA lease")


if __name__ == "__main__":
    main()
