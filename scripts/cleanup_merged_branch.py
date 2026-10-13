"""Delete only the exact head of this merged PR, using an atomic Git lease.

There is deliberately no scan of historical PRs or unrelated branches. API reads
establish merge provenance; the server-side expected-SHA check prevents TOCTOU
loss of new work. The token is inherited by Git from actions/checkout and used
in memory for API reads; it is never interpolated into a command or printed.
"""
# This maintenance script runs after a pull request (a proposed code change)
# is merged. It may delete that change's branch only after checking its exact
# commit ID. A branch is a movable name; a commit ID identifies saved content.
# It must keep a branch if new work has moved the name since the merge.

# Allow type hints to be stored for later interpretation instead of evaluated now.
from __future__ import annotations

# JSON converts GitHub's text records into Python dictionaries (named fields).
import json
# os reads the environment values GitHub supplies to this running job.
import os
# Path handles file and directory names without manual slash handling.
from pathlib import Path
# re checks text against patterns, such as the exact shape of a commit ID.
import re
# subprocess runs Git as a separate program and collects its result.
import subprocess
# HTTPError represents a failed web request, including a missing branch (404).
from urllib.error import HTTPError
# quote makes a branch name safe to put into one part of a web address.
from urllib.parse import quote
# Request describes a web request; urlopen actually sends it and opens the reply.
from urllib.request import Request, urlopen


# Compile one reusable pattern: exactly 40 lowercase hexadecimal characters.
# \Z means the text must end here; a partly matching commit ID is not enough.
SHA = re.compile(r"[0-9a-f]{40}\Z")


# A function groups reusable steps. This one answers whether a branch name is
# a real string, is not main, and follows Git's own branch-naming rules.
def valid_branch(name):
    # "and" stops at the first false condition, so bad types never reach Git.
    return (type(name) is str and name != "main"
            # Pass arguments as a list; no shell interprets the branch as commands.
            and subprocess.run(["git", "check-ref-format", "--branch", name],
                               # Hide Git's output; exit code 0 means a valid name.
                               capture_output=True).returncode == 0)


# Compare the event that triggered this job with fresh GitHub records. Never
# assume an old merged pull request means today's branch content is also merged.
def candidate(event, repository, pull, branch):
    """Return (name, exact PR head, merge commit), or conservatively keep it."""
    # Missing or incorrectly shaped fields are handled below by keeping the branch.
    try:
        # Extract the pull-request snapshot recorded in the triggering event.
        event_pr = event["pull_request"]
        # The full repository name is owner/name, not just the shorter project name.
        repo = repository["full_name"]
        # Unpack the branch name, its proposed final commit, and the merge commit.
        name, head, merge = pull["head"]["ref"], pull["head"]["sha"], pull["merge_commit_sha"]
        # Every condition below must be true. "not" reverses the combined answer:
        # if any check fails, return None (meaning do not select a branch).
        if not (event["action"] == "closed" and event_pr["merged"] is True
                # Both the fresh pull request and default branch must agree.
                and pull["merged"] is True and repository["default_branch"] == "main"
                # The event must belong to the repository we just looked up.
                and event["repository"]["full_name"] == repo
                # All three copies of the pull-request number must identify one PR.
                and event["number"] == pull["number"] == event_pr["number"]
                # The proposed branch must belong to this repository, not a fork.
                and pull["head"]["repo"]["full_name"] == repo
                # The original event must say the same thing about branch ownership.
                and event_pr["head"]["repo"]["full_name"] == repo
                # The destination repository must also be this same repository.
                and pull["base"]["repo"]["full_name"] == repo
                # Recheck that destination against the event's saved snapshot.
                and event_pr["base"]["repo"]["full_name"] == repo
                # Both records must say the work was merged into main.
                and pull["base"]["ref"] == event_pr["base"]["ref"] == "main"
                # Do not select a branch reported as protected by GitHub.
                and branch["protected"] is False
                # The current branch name must match both pull-request records.
                and name == branch["name"] == event_pr["head"]["ref"]
                # Its current commit must still be the EXACT merged PR head.
                and head == branch["commit"]["sha"] == event_pr["head"]["sha"]
                # The event and fresh record must name the same merge commit.
                and merge == event_pr["merge_commit_sha"]
                # Require ordinary strings with complete valid commit-ID shapes.
                and type(head) is str and SHA.fullmatch(head)
                and type(merge) is str and SHA.fullmatch(merge)
                # Finally apply the branch-name check, which also excludes main.
                and valid_branch(name)):
            # None is Python's "no value" marker: this branch will be kept.
            return None
        # A tuple groups the three verified values for the next function.
        return name, head, merge
    # KeyError means a missing field; TypeError means an unusable data shape.
    except (KeyError, TypeError):
        # Uncertainty must preserve work, so never guess which branch to delete.
        return None


# This is the only function that asks Git to delete a remote branch.
def delete_with_lease(directory, name, head, merge):
    """Check integration, then let Git atomically compare and delete the ref."""
    # Recheck the inputs at this destructive operation's boundary.
    if not valid_branch(name) or not SHA.fullmatch(head) or not SHA.fullmatch(merge):
        # Raise stops processing; the caller does not proceed to a deletion.
        raise ValueError("invalid deletion candidate")
    # A nested helper avoids repeating subprocess options. *args gathers the
    # caller's separate arguments; *args in the list expands them again.
    def git(*args):
        # -C chooses the working directory. check=True turns a failed Git command
        # into an exception, preventing later commands from running after failure.
        return subprocess.run(["git", "-C", str(directory), *args], check=True,
                              # Capture messages as text instead of printing them.
                              capture_output=True, text=True)
    # Read the current remote main; FETCH_HEAD records the fetched commit.
    git("fetch", "--no-tags", "origin", "refs/heads/main")
    # Require the claimed merge commit to be in the fetched main's history.
    git("merge-base", "--is-ancestor", merge, "FETCH_HEAD")
    # The empty source before ':' requests deletion. The expected-SHA lease says
    # "delete only if the server STILL sees this exact head". Git checks that
    # condition and deletion together, protecting a concurrent branch update.
    git("push", f"--force-with-lease=refs/heads/{name}:{head}",
        "origin", f":refs/heads/{name}")


# Start here when GitHub runs this file as a program.
def main():
    # Read GitHub's event file and turn its JSON text into Python data.
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    # Read the repository name GitHub supplies to this job.
    repo = os.environ["GITHUB_REPOSITORY"]
    # Reject an unexpected repository-name shape or an event that is not a merge.
    if (not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo)
            # .get returns a default rather than failing when an optional key is absent.
            or event.get("action") != "closed"
            or event.get("pull_request", {}).get("merged") is not True):
        # Explain the conservative decision in the job log, then leave main().
        print("KEEP: not a merged PR event")
        # Finish without looking up or deleting any branch.
        return

    # This helper fetches one current record from this repository's GitHub API.
    def api(path):
        # Add authorization in a request header, never in a printed URL or command.
        request = Request(f"https://api.github.com/repos/{repo}{path}", headers={
            # GitHub provides a short-lived token through the job environment.
            "Authorization": "Bearer " + os.environ["GITHUB_TOKEN"],
            # Ask for GitHub JSON using the specified API contract version.
            "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
        })
        # Apply a 30-second timeout to blocking network operations. The with block
        # closes the reply afterward; this is not a total workflow time limit.
        with urlopen(request, timeout=30) as response:
            # Parse the reply directly into dictionaries/lists and return it.
            return json.load(response)

    # Fetch current repository settings and this specific pull request.
    repository = api("")
    # int requires a numeric PR number before inserting it into the URL.
    pull = api(f"/pulls/{int(event['number'])}")
    # The head is the source branch proposed by the pull request.
    name = pull["head"]["ref"]
    # Stop before even looking up an invalid name or main itself.
    if not valid_branch(name):
        # Record why the proposed name is not eligible for cleanup.
        print("KEEP: invalid or main branch")
        # Leave this run before any destructive Git operation.
        return
    # A branch may already have been deleted by a person or another workflow.
    try:
        # Encode '/' and other special characters as part of one branch-name field.
        branch = api("/branches/" + quote(name, safe=""))
    except HTTPError as exc:
        # HTTP status 404 means no such branch record was found.
        if exc.code == 404:
            # A previously removed branch needs no additional deletion request.
            print("KEEP: branch already absent")
            # End normally because there is nothing left to clean up.
            return
        # Other web errors are real failures; report them rather than guessing.
        raise
    # Compare all event and live records using the conservative checks above.
    selected = candidate(event, repository, pull, branch)
    # A failed check returns None, so no deletion request will be made.
    if selected is None:
        # State that the necessary merge/ownership/head evidence was not established.
        print("KEEP: exact merged head, same repository, and unprotected branch not established")
        # Preserve the branch when any required evidence is missing.
        return
    # Path.cwd() is the current checkout; *selected unpacks the three checked values.
    delete_with_lease(Path.cwd(), *selected)
    # Print success only after Git has completed its guarded deletion successfully.
    print("Deleted the verified merged head with an expected-SHA lease")


# Importing this file for tests exposes its functions without running cleanup.
if __name__ == "__main__":
    # Run cleanup only when this file is launched as a program.
    main()
