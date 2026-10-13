# These tests check when it is safe to delete a Git branch after merging a pull request.
# Git saves project snapshots called commits; a branch is a name pointing to one commit.
# A pull request (PR) asks to bring one branch's changes into another branch, here main.
# A commit's SHA is its identifying string; these examples use 40-character identifiers.
# A race happens when a branch changes between checking it and trying to delete it.
# Some tests use made-up records; others create real temporary Git repositories.
# The triple-quoted text below is this file's short description, called a docstring.
#
# Python reading guide: (...) calls a function; a dot selects an object's named part.
# = stores a value; == compares values; [...] can select an entry from a list or dictionary.
# Indented lines belong to the def, if, with, or other statement just above them.
"""Cleanup policy tests and real Git server race regressions (F02)."""
# Import copying tools so tests can duplicate nested records before changing them.
import copy
# Import tools that can load Python code directly from a file path.
import importlib.util
# Import Path, which represents file and folder locations and joins them with /.
from pathlib import Path
# Import subprocess so these tests can run real Git commands as separate programs.
import subprocess

# Import pytest, the test runner that supplies test preparation and expected-error checks.
import pytest

# Describe how to import the cleanup script under the local Python name cleanup.
# __file__ is this test file's path; parents[1] goes up from tests to the project folder.
# The / operation joins that folder to the script path; it is not numeric division here.
spec = importlib.util.spec_from_file_location("cleanup", Path(__file__).parents[1] / "scripts/cleanup_merged_branch.py")
# Make a Python module object, a container for the functions and names in that script.
cleanup = importlib.util.module_from_spec(spec)
# Execute the script's definitions inside the module so tests can call cleanup.candidate
# and cleanup.delete_with_lease. Importing this way does not run the script's main() entry point.
spec.loader.exec_module(cleanup)


# The @ instruction registers the following function as a pytest fixture.
# A fixture prepares data for tests; pytest runs this one afresh for each test case.
@pytest.fixture
# Define the preparation function requested by tests with an inputs argument.
def inputs():
    # Create a dictionary, a collection of names paired with values, describing the repository.
    # It is named owner/repo and its default branch, the usual destination, is main.
    repo = {"full_name": "owner/repo", "default_branch": "main"}
    # Describe pull request number 2 as already merged. True means yes.
    # "b"*40 repeats b forty times to stand in for the commit that integrated its changes.
    pull = {"number": 2, "merged": True, "merge_commit_sha": "b"*40,
            # head describes the PR's source branch, repair/topic, and its last commit, forty a's.
            # The source branch belongs to the same repo object defined above.
            "head": {"ref": "repair/topic", "sha": "a"*40, "repo": repo},
            # base describes the merge destination: main in that same repository.
            "base": {"ref": "main", "repo": repo}}
    # Make the event record as though GitHub just announced that PR 2 was closed.
    # A closed PR might be unmerged, so the nested PR record also records its merge status.
    # deepcopy duplicates the nested PR data so later changes to pull do not rewrite this event.
    event = {"action": "closed", "number": 2, "repository": repo, "pull_request": copy.deepcopy(pull)}
    # Describe the currently observed branch: the same name and last commit as the merged PR.
    # protected=False means no branch-protection flag is set in this test data.
    branch = {"name": "repair/topic", "protected": False, "commit": {"sha": "a"*40}}
    # Return fresh copies of all four records as a tuple, a fixed-order group of values.
    # Nested dictionaries are copied too, so test changes stay within this fixture's data.
    return copy.deepcopy((event, repo, pull, branch))


# Check the safe case: the current branch still exactly matches the merged PR's head.
# The inputs argument asks pytest for the four matching records made by the fixture.
def test_exact_merged_head_is_eligible(inputs):
    # assert fails the test if the comparison is false. *inputs passes its four records
    # as four separate arguments. Expect the branch name, exact head, and merge commit;
    # this function selects a deletion candidate but does not itself delete anything.
    assert cleanup.candidate(*inputs) == ("repair/topic", "a"*40, "b"*40)


# parametrize runs the next test once for every case name in this list.
# The first group covers moved commits, a reused name, protection, the default branch,
# main itself, and a branch coming from a different repository (a fork).
@pytest.mark.parametrize("case", ["new_tip", "reused_name", "protected", "default", "main", "fork",
                                 # These cases cover an unmerged PR, a wrong destination, a wrong event action,
                                 # a disagreeing merge commit, and a mismatched PR number.
                                 "unmerged", "wrong_base", "wrong_event", "stale_merge", "wrong_number",
                                 # The final cases cover an invalid branch name, invalid commit identifier,
                                 # and an event naming a different repository. Each selected name is passed as case.
                                 "invalid_name", "invalid_sha", "other_repo"])
# Check that any missing or conflicting safety evidence makes cleanup keep the branch.
# Pytest supplies fresh matching inputs and one case name for each separate run.
def test_cleanup_refuses_unproved_or_protected_branch(inputs, case):
    # Unpack the fixture's tuple into the event, repository, PR, and live branch records.
    event, repo, pull, branch = inputs
    # if starts a choice: run the next indented line only for the new_tip case.
    if case == "new_tip":
        # Change the live branch's latest commit to forty c's, simulating new work after merge.
        # The two pairs of brackets first select commit, then its sha field.
        branch["commit"]["sha"] = "c"*40
    # elif means "otherwise, if"; this choice tests a branch name reused for another commit.
    elif case == "reused_name":
        # Make the event remember a different PR head from the current PR and branch records.
        # Identical branch names alone must not be enough evidence for deletion.
        event["pull_request"]["head"]["sha"] = "c"*40
    # Choose this branch when the requested case is a protected branch.
    elif case == "protected":
        # Mark the branch protected with True (yes), which must forbid cleanup.
        branch["protected"] = True
    # Choose the case where the repository's default branch is the proposed deletion target.
    elif case == "default":
        # Set the default branch to repair/topic; this must fail the policy requiring main.
        repo["default_branch"] = "repair/topic"
    # Choose the case where all records consistently name main as the deletion target.
    elif case == "main":
        # Assign main to all three branch-name fields in one chained assignment.
        # Even matching records must never authorize deleting main.
        branch["name"] = pull["head"]["ref"] = event["pull_request"]["head"]["ref"] = "main"
    # Choose the fork case, where a PR's source branch belongs to a different repository.
    elif case == "fork":
        # Replace the PR head's repository record with attacker/fork, breaking same-repository proof.
        pull["head"]["repo"] = {"full_name": "attacker/fork"}
    # Choose the case where the current PR record says it was not merged.
    elif case == "unmerged":
        # Set merged to False (no); a closed or named PR alone cannot justify deletion.
        pull["merged"] = False
    # Choose the case where the PR's destination branch is not main.
    elif case == "wrong_base":
        # Change the base ref, meaning the destination branch name, to other.
        pull["base"]["ref"] = "other"
    # Choose the case where the event does not announce a closed PR.
    elif case == "wrong_event":
        # Report opened instead, which is not an event that should trigger merged-branch cleanup.
        event["action"] = "opened"
    # Choose the case where event and current PR disagree about the integrating commit.
    elif case == "stale_merge":
        # Replace the event's merge identifier with forty c's while the PR still reports forty b's.
        event["pull_request"]["merge_commit_sha"] = "c"*40
    # Choose the case where the current PR record has a different request number.
    elif case == "wrong_number":
        # Set that number to 999, while the event still identifies PR 2.
        pull["number"] = 999
    # Choose the case where every record agrees on a branch name that Git disallows.
    elif case == "invalid_name":
        # Set all three names to -bad. Starting with a hyphen makes this an invalid branch name;
        # agreement between records cannot make an invalid name safe.
        branch["name"] = pull["head"]["ref"] = event["pull_request"]["head"]["ref"] = "-bad"
    # Choose the case where the PR's head does not contain a valid commit identifier.
    elif case == "invalid_sha":
        # Use ordinary text instead of the required 40-character hexadecimal SHA.
        pull["head"]["sha"] = "not-a-sha"
    # else handles the remaining listed case, other_repo, when no earlier choice matched.
    else:
        # Make the event name a different repository from the records being checked.
        event["repository"] = {"full_name": "different/repo"}
    # assert requires the candidate function to return None, Python's "no value" marker.
    # For every case above, None means no branch was proved safe to delete.
    assert cleanup.candidate(event, repo, pull, branch) is None


# Define a small helper for running Git inside a chosen repository directory.
# *args collects the remaining command arguments; check=True is the default setting
# that makes a failed Git command raise an error instead of silently continuing.
def git(directory, *args, check=True):
    # Run Git with -C and the directory converted to text, followed by each supplied argument.
    # The list gives separate arguments directly to Git; check decides whether failures raise errors.
    return subprocess.run(["git", "-C", str(directory), *args], check=check,
                          # text=True reads output as text; capture_output=True keeps it out of the test terminal.
                          # stdout is the command's normal output; strip() removes surrounding whitespace.
                          # Return that cleaned output so tests can compare commit IDs or detect an empty result.
                          text=True, capture_output=True).stdout.strip()


# Register another fixture, this time building a real isolated Git test environment.
@pytest.fixture
# Define the fixture requested as remote. Pytest supplies tmp_path, a fresh temporary
# folder for this test; these repositories do not use the project's real remote server.
def remote(tmp_path):
    # Create two paths inside that folder: a server repository and a working checkout.
    # The comma assignment stores the two paths as bare and work; / joins path components.
    bare, work = tmp_path / "remote.git", tmp_path / "work"
    # Run git init --bare to create a repository that stores commits and branch names
    # without checked-out project files, like a Git server. Raise on failure and capture output.
    subprocess.run(["git", "init", "--bare", str(bare)], check=True, capture_output=True)
    # Clone that temporary server into work, creating an editable checkout with origin
    # pointing back to the temporary server. Again, raise on failure and capture output.
    subprocess.run(["git", "clone", str(bare), str(work)], check=True, capture_output=True)
    # Set the commit author's name inside this temporary checkout so Git can make commits.
    git(work, "config", "user.name", "Test")
    # Set a test-only author email in the same checkout; this is commit metadata, not an email send.
    git(work, "config", "user.email", "test@example.invalid")
    # Create and switch to main with git switch -c; it will hold the integrated project.
    git(work, "switch", "-c", "main")
    # Write the text base into a file named base in the working checkout.
    (work / "base").write_text("base")
    # Stage the current files with git add .; staging selects content for the next saved commit.
    git(work, "add", ".")
    # Save the initial snapshot with git commit; -m supplies its description, base.
    git(work, "commit", "-m", "base")
    # Push main to origin, publishing it to this test's temporary server repository.
    git(work, "push", "origin", "main")
    # Create and switch to a new repair/topic branch where the simulated PR work will happen.
    git(work, "switch", "-c", "repair/topic")
    # Write a new change file containing the work that will later be merged.
    (work / "change").write_text("merged change")
    # Stage that new file so the next commit includes it.
    git(work, "add", ".")
    # Save the topic branch's work as a commit whose description is topic.
    git(work, "commit", "-m", "topic")
    # Ask Git for HEAD, the current checked-out commit's full identifier, and save it as head.
    # This is the exact PR head that cleanup will later be allowed to delete.
    head = git(work, "rev-parse", "HEAD")
    # Publish repair/topic to the temporary server, creating the branch cleanup will inspect.
    git(work, "push", "origin", "repair/topic")
    # Switch the editable checkout back to main to integrate the topic changes.
    git(work, "switch", "main")
    # Apply the topic branch's combined changes with a squash merge. This stages the changes
    # without making the original topic commit part of main's commit-parent history.
    git(work, "merge", "--squash", "repair/topic")
    # Commit those staged changes on main under the description squash merge.
    git(work, "commit", "-m", "squash merge")
    # Read the new main commit's identifier and save it as merge, the integration evidence.
    merge = git(work, "rev-parse", "HEAD")
    # Publish updated main to the temporary server so cleanup can verify that merge is included.
    git(work, "push", "origin", "main")
    # Return the checkout path, original topic head, and integrating main commit as a tuple.
    # Pytest rebuilds this whole scenario for each test that requests remote.
    return work, head, merge


# Check a safely integrated, unchanged topic branch can be deleted with a Git lease.
# A lease here says "delete only if the server still points to this exact expected commit."
# The remote fixture provides a temporary server with the topic changes squash-merged into main.
def test_exact_squash_head_can_be_deleted_with_a_lease(remote):
    # Unpack the checkout path, original topic commit, and squash-merge commit from the fixture.
    work, head, merge = remote
    # Ask cleanup to verify the merge is on main, then delete exactly that topic commit
    # using the server's compare-and-delete operation so a changed branch would be protected.
    cleanup.delete_with_lease(work, "repair/topic", head, merge)
    # assert checks that querying the server for this exact branch returns no text.
    # ls-remote --heads lists matching remote branches; refs/heads/ is Git's full branch prefix.
    assert git(work, "ls-remote", "--heads", "origin", "refs/heads/repair/topic") == ""
    # Query main too and require nonempty output. In an assert, nonempty text counts as true,
    # proving the integration branch still exists after deleting repair/topic.
    assert git(work, "ls-remote", "--heads", "origin", "refs/heads/main")


# Check the race where someone pushes new work after the cleanup checks selected a head.
# The remote fixture gives a temporary server, the old merged head, and its squash-merge commit.
def test_concurrent_update_survives_atomic_deletion_attempt(remote):
    # Keep those original identifiers so the deletion attempt will still expect the old head.
    work, head, merge = remote
    # Switch the temporary checkout back to repair/topic to simulate another developer's work.
    git(work, "switch", "repair/topic")
    # Write a new file containing work that has not been merged into main.
    (work / "new-work").write_text("unmerged work")
    # Stage that new work for the next commit.
    git(work, "add", ".")
    # Save a new topic commit, described as arriving after API checks.
    # An API is how software requests records from a service; here the ordering is simulated
    # by keeping the old head value while creating a newer commit before the deletion call.
    git(work, "commit", "-m", "concurrent update after API checks")
    # Read and remember the new topic commit's identifier so its survival can be checked.
    new_head = git(work, "rev-parse", "HEAD")
    # Push the newer commit to the temporary server, moving the branch beyond the expected head.
    git(work, "push", "origin", "repair/topic")
    # with pytest.raises expects the indented action to fail with CalledProcessError,
    # the error subprocess reports when a command fails with check=True.
    with pytest.raises(subprocess.CalledProcessError):
        # Try deleting while still naming the old head. Git must reject the stale lease.
        # Its atomic check and deletion happen as one server operation, so there is no gap
        # in which a newer branch value can be accepted and then accidentally deleted.
        cleanup.delete_with_lease(work, "repair/topic", head, merge)
    # assert and in require the new commit ID to appear in the server's branch listing.
    # This proves the unmerged concurrent work and its branch survived the failed deletion.
    assert new_head in git(work, "ls-remote", "--heads", "origin", "refs/heads/repair/topic")


# Check that cleanup refuses a claimed integrating commit which is absent from main's history.
# The fixture squash-merges the changes, so the original topic commit itself is not an
# ancestor of main; an ancestor is a commit reachable by following earlier-commit links.
def test_unintegrated_merge_commit_cannot_authorize_deletion(remote):
    # Keep the checkout and original topic head. _ marks the real squash-merge ID as unused.
    work, head, _ = remote
    # Expect CalledProcessError, meaning a checked Git command refused the attempted operation.
    with pytest.raises(subprocess.CalledProcessError):
        # Deliberately pass the topic head as both the branch head and alleged merge commit.
        # The check that the alleged merge belongs to main must fail before branch deletion.
        cleanup.delete_with_lease(work, "repair/topic", head, head)
    # Query the temporary server and assert its topic branch still lists the original head.
    # The in comparison checks that commit ID appears in the returned text, proving it was kept.
    assert head in git(work, "ls-remote", "--heads", "origin", "refs/heads/repair/topic")
