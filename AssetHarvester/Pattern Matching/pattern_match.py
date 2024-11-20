from git import Repo
from git import NULL_TREE
from urllib.parse import urlparse, parse_qs
import hashlib
import re
import os
from sys import *
import pandas as pd
import csv

# Regular Expressions
RULES = {
    r"(?i)(?P<dbms>mysql|mysqlx|mysql+srv|postgresql|postgres|mongodb|mongodb\+srv):\/\/(?P<credentials>[^:@\s]*(?::[^@\s]*)?@)?(?P<server>[^\/\?\s`'\";]+)": "Group1",
    r"(?i)(?:(Provider|Driver)=[^;]*);[\s]*(?:(?:Data Source|Server)=(?P<server>[^;]+);)(?:(?:Initial Catalog|Database)=(?P<database>[^;]+);)?(?:(?:User Id|UID)=(?P<user>[^;]+);)?(?:(?:Password|PWD=)(?P<password>[^;]+);)?": "Group2",
    r"(?i)(?P<dbms>mysql|postgresql|mongodb|sqlserver):[/]{2,3}(?P<credentials>[^:@\s]*(?::[^@\s]*)?@)?(?P<server>[^\?\s`'\";]+)\?user=(?P<user>[^\s&;<>]+)(?:&amp;)?(?:\&?password=(?P<password>[^\s&;\]<>]+))?": "Group3",
    
}

# Compile the regex patterns
PATTERNS = list(RULES.keys())
TAG_LOOKUP = list(RULES.values())
RE_PATTERNS = [re.compile(pattern) for pattern in PATTERNS]


# Scan a repository 
def _scan(repo, since_timestamp, max_depth):
    already_searched = set()
    discoveries = []

    branches = repo.remotes.origin.fetch()
    print("No of Branches:", len(branches))
    branch_counter = 0

    for remote_branch in branches:
        branch_name = remote_branch.name
        branch_counter += 1
        print(
            f"Working with Branch: {branch_name} ({str(branch_counter)} / {str(len(branches))})"
        )
        prev_commit = None

        no_of_commits = len(list(repo.iter_commits(branch_name, max_count=max_depth)))
        commit_counter = 0

        # Note that the iteration of the commits is backwards, so the
        # prev_commit is newer than curr_commit
        for curr_commit in repo.iter_commits(branch_name, max_count=max_depth):
            commit_counter += 1
            stdout.write(
                f"\rCommit in Progress: {str(commit_counter)}/{str(no_of_commits)}"
            )
            stdout.flush()
            # if not prev_commit, then curr_commit is the newest commit
            # (and we have nothing to diff with).
            # But we will diff the first commit with NULL_TREE here to
            # check the oldest code. In this way, no commit will be missed.
            if not prev_commit:
                # The current commit is the latest one
                prev_commit = curr_commit
                continue

            if prev_commit.committed_date <= since_timestamp:
                # We have reached the (chosen) oldest timestamp, so
                # continue with another branch
                break

            # This is useful for git merge: in case of a merge, we have the
            # same commits (prev and current) in two different branches.
            # This trick avoids scanning twice the same commits
            diff_hash = hashlib.md5(
                (str(prev_commit) + str(curr_commit)).encode("utf-8")
            ).digest()
            if diff_hash in already_searched:
                prev_commit = curr_commit
                continue
            else:
                # Avoid searching the same diffs
                already_searched.add(diff_hash)

            # Get the diff between two commits
            # Ignore possible submodules (they are independent from
            # this repo)
            diff = curr_commit.diff(
                prev_commit,
                create_patch=True,
                ignore_submodules="all",
                ignore_all_space=True,
                unified=0,
                diff_filter="AM",
            )

            # Diff between the current commit and the previous one
            discoveries.extend(_diff_worker(diff, prev_commit))

            prev_commit = curr_commit

        # Handling the first commit (either from since_timestamp or the
        # oldest).
        # If `since_timestamp` is set, then there is no need to scan it
        # (because we have already scanned this diff at the previous step).
        # If `since_timestamp` is 0, we have reached the first commit of
        # the repo, and the diff here must be calculated with an empty tree
        if since_timestamp == 0:
            diff = curr_commit.diff(
                NULL_TREE,
                create_patch=True,
                ignore_submodules="all",
                ignore_all_space=True,
            )

            discoveries = discoveries + _diff_worker(diff, prev_commit)
        print(f"\n")
    return discoveries


# Worker for computing the diff between two commits
def _diff_worker(diff, commit):
    detections = []
    for blob in diff:
        # new file: a_path is None, deleted file: b_path is None
        old_path = blob.b_path if blob.b_path else blob.a_path

        printable_diff = blob.diff.decode("utf-8", errors="replace")

        if printable_diff.startswith("Binary files"):
            # Do not scan binary files
            continue

        detections = detections + _regex_check(printable_diff, old_path, commit.hexsha)
    return detections


# Search for with pattern is matched
def search_pattern(line):
    for idx, pattern in enumerate(RE_PATTERNS):
        match = re.search(pattern, line)

        if match:
            return (match, TAG_LOOKUP[idx])

    return (None, None)


# Find the db types
def find_db_type(match_info, matched_part, rule_id):
    dbname = ""

    if rule_id in ["Group1", "Group3"]:
        dbname = match_info.groupdict().get("dbms")
    else:
        matched_part = matched_part.lower()

        if "postgresql" in matched_part or "postgres" in matched_part:
            dbname = "postgresql"
        if "mysql" in matched_part:
            dbname = "mysql"
        if "mongo" in matched_part:
            dbname = "mongodb"
        if "sqlserver" in matched_part or "sql server" in matched_part:
            dbname = "sqlserver"

    return dbname


def find_connection_string_parts(match_info, matched_part, rule_id):
    dbtype = host = port = dbname = username = password = ""

    if rule_id != "Group2":
        r = urlparse(matched_part)
        host = r.hostname
        port = r.port
        dbname = r.path
        username = r.username
        password = r.password

        # If query parameters are present
        if r.query != "":
            params = parse_qs(rquery)
            # Update username and password from query parameters if present
            username = (
                params["user"]
                if "user" in params and params["user"] != ""
                else username
            )
            password = (
                params["password"]
                if "password" in params and params["password"] != ""
                else password
            )
    else:
        kv_pattern = r"(?i)(?P<Key>[^=;]+)=(?P<Val>[^;]+)"
        match_dict = {}
        matches = re.findall(kv_pattern, matched_part)
        for key, value in matches:
            match_dict[key.lower().trim()] = value

        # Find Host
        if "data source" in match_dict:
            host = match_dict["data source"]
        elif "datasource" in match_dict:
            host = match_dict["datasource"]
        elif "server" in match_dict:
            host = match_dict["server"]

        # Find Port
        if "port" in match_dict:
            port = match_dict["port"]

        # Find DB Name
        if "initial catalog" in match_dict:
            dbname = match_dict["initial catalog"]
        elif "database" in match_dict:
            dbname = match_dict["database"]

        # Find Username
        if "user id" in match_dict:
            username = match_dict["user id"]
        elif "uid" in match_dict:
            username = match_dict["uid"]

        # Find Password
        if "password" in match_dict:
            password = match_dict["password"]
        elif "pwd" in match_dict:
            password = match_dict["pwd"]

    # Find DB Type
    dbtype = find_db_type(match_info, matched_part, rule_id)

    return (dbtype, host, port, dbname, username, password)


# Create a secret-asset pair
def create_match_entry(line, match_info, file_name, line_number, commit_hash, rule_id):
    matched_part = line[match_info.start() : match_info.end()]
    dbtype, host, port, dbname, username, password = find_connection_string_parts(
        match_info, matched_part, rule_id
    )

    entry = {
        "commit_id": commit_hash,
        "file_path": file_name,
        "start_line": line_number,
        "start_column": match_info.start(),
        "end_column": match_info.end(),
        "matched_part": matched_part,
        "dbtype": dbtype,
        "host": host,
        "port": port,
        "dbname": dbname,
        "username": username,
        "password": password,
        "rule_id": rule_id,
    }

    return entry


# Run the regex on the diff of specific commit
def _regex_check(printable_diff, filename, commit_hash):
    detections = []
    r_hunkheader = re.compile(r"@@\s*\-\d+(\,\d+)?\s\+(\d+)((\,\d+)?).*@@")
    r_hunkaddition = re.compile(r"^\+\s*(\S(.*\S)?)\s*$")
    rows = printable_diff.splitlines()
    line_number = 1
    for row in rows:
        if row.startswith("-") and len(row) > 25000:
            # Take into consideration only added lines that are shorter
            # than 500 characters
            continue
        if row.startswith("@@"):
            # If the row is a git diff hunk header, get the first addition
            # line number in the header and go to the next line
            r_groups = re.search(r_hunkheader, row)
            if r_groups is not None:
                line_number = int(r_groups.group(2))
                continue
        elif row.startswith("+"):
            # Remove '+' character from diff hunk and trim row
            r_groups = re.search(r_hunkaddition, row)
            if r_groups is not None:
                row = r_groups.group(1)

        # Add the result if searched patterns are found in this line
        matched, rule_id = search_pattern(row)
        if matched:
            try:
                new_entry = create_match_entry(
                    row, matched, filename, line_number, commit_hash, rule_id
                )
                detections.append(new_entry)
            except:
                pass

        line_number += 1

    return detections


directory = "AssetBench/Repos/"
repos = pd.read_csv("repo-list.csv")
repo_name_dict = repos.set_index("sanitized_repo_name")["repo_name"].to_dict()
filter_repos = repos[repos["status"] != "Done"]
repo_names = filter_repos["sanitized_repo_name"].tolist()


# Run the regex in each repository
for idx, repo_name in enumerate(repo_names):
    print(f"Working with repo: {repo_name} - ({str(idx + 1)}/{len(repo_names)})")
    repo = Repo(directory + repo_name)
    output = _scan(repo, 0, 2000000)
    df = pd.DataFrame(output)

    if df.empty:
        continue

    df["repo_name"] = repo_name_dict[repo_name]
    df["sanitized_repo_name"] = repo_name
    df["file_identifier"] = df[["sanitized_repo_name", "commit_id", "file_path"]].apply(
        lambda x: x.sanitized_repo_name
        + "_"
        + x.commit_id
        + "_"
        + "-".join(x.file_path.split("/")),
        axis=1,
    )
    df.to_csv("Outputs/" + repo_name + ".csv", index=False)

print("Done........")
