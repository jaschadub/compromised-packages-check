---
description: Scan the current repository for known-malicious npm/PyPI package versions
argument-hint: "[path]  (optional; defaults to current working directory)"
---

Run the `check_compromised_packages.py` scanner from this plugin against the
target path. The user's argument (if any) is in `$ARGUMENTS` — treat it as a
directory path. If empty, scan the current working directory.

Steps:

1. Locate the scanner. Prefer, in order:
   - `${CLAUDE_PLUGIN_ROOT}/check_compromised_packages.py` if set
   - A copy in the current repo root (`./check_compromised_packages.py`)
   - The system path (`which check_compromised_packages.py`)
   - As a last resort, fetch the latest from
     `https://raw.githubusercontent.com/jaschadub/compromised-packages-check/main/check_compromised_packages.py`
     into a temp file and run from there.
2. Resolve the target directory:
   - If `$ARGUMENTS` is non-empty, use it (expand `~` and relative paths).
   - Otherwise use the current working directory.
   - Confirm the path exists before running.
3. Execute `python3 <scanner> <target>` via the Bash tool. Capture stdout
   and the exit code.
4. Summarise the result to the user in a few lines:
   - **Exit 0:** repo is clean against the tracked advisories.
   - **Exit 1:** list each hit with `package@version (file)` and recommend
     the next steps: remove/downgrade, run `npm ci` / `pip install` again
     to refresh the lockfile, and **rotate any credentials reachable from
     a host that installed the bad version** (GitHub tokens, npm tokens,
     SSH keys, cloud creds).
   - **Exit 2:** report the usage error.
5. If suspect-scope warnings appear (e.g. `@uipath/`, `@mistralai/`,
   `@opensearch-project/` packages whose version is unknown to the BAD
   list), flag them and suggest running `/update-bad-list` to refresh.

Do **not** auto-edit any package files. This command is read-only.
