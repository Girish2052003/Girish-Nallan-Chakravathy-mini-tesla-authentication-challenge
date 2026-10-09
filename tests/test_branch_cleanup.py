"""Cleanup policy tests and real Git server race regressions (F02)."""
import copy
import importlib.util
from pathlib import Path
import subprocess

import pytest

spec = importlib.util.spec_from_file_location("cleanup", Path(__file__).parents[1] / "scripts/cleanup_merged_branch.py")
cleanup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cleanup)


@pytest.fixture
def inputs():
    repo = {"full_name": "owner/repo", "default_branch": "main"}
    pull = {"number": 2, "merged": True, "merge_commit_sha": "b"*40,
            "head": {"ref": "repair/topic", "sha": "a"*40, "repo": repo},
            "base": {"ref": "main", "repo": repo}}
    event = {"action": "closed", "number": 2, "repository": repo, "pull_request": copy.deepcopy(pull)}
    branch = {"name": "repair/topic", "protected": False, "commit": {"sha": "a"*40}}
    return copy.deepcopy((event, repo, pull, branch))


def test_exact_merged_head_is_eligible(inputs):
    assert cleanup.candidate(*inputs) == ("repair/topic", "a"*40, "b"*40)


@pytest.mark.parametrize("case", ["new_tip", "reused_name", "protected", "default", "main", "fork",
                                 "unmerged", "wrong_base", "wrong_event", "stale_merge", "wrong_number",
                                 "invalid_name", "invalid_sha", "other_repo"])
def test_cleanup_refuses_unproved_or_protected_branch(inputs, case):
    event, repo, pull, branch = inputs
    if case == "new_tip":
        branch["commit"]["sha"] = "c"*40
    elif case == "reused_name":
        event["pull_request"]["head"]["sha"] = "c"*40
    elif case == "protected":
        branch["protected"] = True
    elif case == "default":
        repo["default_branch"] = "repair/topic"
    elif case == "main":
        branch["name"] = pull["head"]["ref"] = event["pull_request"]["head"]["ref"] = "main"
    elif case == "fork":
        pull["head"]["repo"] = {"full_name": "attacker/fork"}
    elif case == "unmerged":
        pull["merged"] = False
    elif case == "wrong_base":
        pull["base"]["ref"] = "other"
    elif case == "wrong_event":
        event["action"] = "opened"
    elif case == "stale_merge":
        event["pull_request"]["merge_commit_sha"] = "c"*40
    elif case == "wrong_number":
        pull["number"] = 999
    elif case == "invalid_name":
        branch["name"] = pull["head"]["ref"] = event["pull_request"]["head"]["ref"] = "-bad"
    elif case == "invalid_sha":
        pull["head"]["sha"] = "not-a-sha"
    else:
        event["repository"] = {"full_name": "different/repo"}
    assert cleanup.candidate(event, repo, pull, branch) is None


def git(directory, *args, check=True):
    return subprocess.run(["git", "-C", str(directory), *args], check=check,
                          text=True, capture_output=True).stdout.strip()


@pytest.fixture
def remote(tmp_path):
    bare, work = tmp_path / "remote.git", tmp_path / "work"
    subprocess.run(["git", "init", "--bare", str(bare)], check=True, capture_output=True)
    subprocess.run(["git", "clone", str(bare), str(work)], check=True, capture_output=True)
    git(work, "config", "user.name", "Test")
    git(work, "config", "user.email", "test@example.invalid")
    git(work, "switch", "-c", "main")
    (work / "base").write_text("base")
    git(work, "add", ".")
    git(work, "commit", "-m", "base")
    git(work, "push", "origin", "main")
    git(work, "switch", "-c", "repair/topic")
    (work / "change").write_text("merged change")
    git(work, "add", ".")
    git(work, "commit", "-m", "topic")
    head = git(work, "rev-parse", "HEAD")
    git(work, "push", "origin", "repair/topic")
    git(work, "switch", "main")
    git(work, "merge", "--squash", "repair/topic")
    git(work, "commit", "-m", "squash merge")
    merge = git(work, "rev-parse", "HEAD")
    git(work, "push", "origin", "main")
    return work, head, merge


def test_exact_squash_head_can_be_deleted_with_a_lease(remote):
    work, head, merge = remote
    cleanup.delete_with_lease(work, "repair/topic", head, merge)
    assert git(work, "ls-remote", "--heads", "origin", "refs/heads/repair/topic") == ""
    assert git(work, "ls-remote", "--heads", "origin", "refs/heads/main")


def test_concurrent_update_survives_atomic_deletion_attempt(remote):
    work, head, merge = remote
    git(work, "switch", "repair/topic")
    (work / "new-work").write_text("unmerged work")
    git(work, "add", ".")
    git(work, "commit", "-m", "concurrent update after API checks")
    new_head = git(work, "rev-parse", "HEAD")
    git(work, "push", "origin", "repair/topic")
    with pytest.raises(subprocess.CalledProcessError):
        cleanup.delete_with_lease(work, "repair/topic", head, merge)
    assert new_head in git(work, "ls-remote", "--heads", "origin", "refs/heads/repair/topic")


def test_unintegrated_merge_commit_cannot_authorize_deletion(remote):
    work, head, _ = remote
    with pytest.raises(subprocess.CalledProcessError):
        cleanup.delete_with_lease(work, "repair/topic", head, head)
    assert head in git(work, "ls-remote", "--heads", "origin", "refs/heads/repair/topic")
