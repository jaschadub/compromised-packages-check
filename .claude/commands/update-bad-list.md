---
description: Research new supply-chain advisories and update NPM_BAD / PYPI_BAD in the scanner
argument-hint: "[advisory id, scope, or URL]  (optional; otherwise sweeps the standard sources)"
---

Help the user add newly-disclosed compromised package versions to
`check_compromised_packages.py`. The user's argument (if any) is in
`$ARGUMENTS` — it may be a GHSA id, a CVE id, an npm scope, a package
name, or a URL to a vendor writeup.

Follow the workflow documented in `SKILLS.md`:

## 1. Gather candidates

- If `$ARGUMENTS` is **a URL**: fetch it with `WebFetch` and extract a
  `package | versions` table.
- If `$ARGUMENTS` is **a GHSA id** (e.g. `GHSA-xxxx-yyyy-zzzz`): fetch
  `https://github.com/advisories/<id>` with `WebFetch`.
- If `$ARGUMENTS` is **a CVE id**: search GHSA and OSV for the matching
  advisory.
- If `$ARGUMENTS` is **a package name or scope**: query OSV
  (`https://api.osv.dev/v1/query`) and search GHSA for affected versions.
- If `$ARGUMENTS` **is empty**: do a sweep — use `WebSearch` to look for
  npm / PyPI supply-chain advisories newer than the most recent commit in
  this repo, then dig into the top hits.

Always prefer primary sources. Useful starting points (also listed in
`SKILLS.md`):

- GitHub Advisory Database: https://github.com/advisories
- OSV.dev API: https://api.osv.dev/v1/query
- pypa/advisory-database: https://github.com/pypa/advisory-database
- Aikido, Socket, Snyk, Wiz, Mend, StepSecurity, Phylum, ReversingLabs,
  Checkmarx, JFrog, SafeDep, Corgea, Unit 42, Microsoft Security Blog

## 2. Meet the evidence threshold

Per `SKILLS.md`, before adding any entry require **one** of:

- A GHSA / OSV / CVE record naming the package and exact versions.
- A primary-source maintainer postmortem with versions enumerated.
- Two independent vendor writeups that agree on the version list.

If only a scope name is known (no exact versions yet), do **not** invent
entries — leave the scope to the existing `NPM_SUSPECT_SCOPES` safety net
and stop here.

## 3. Show the user the diff before editing

Present a proposed diff: which entries you want to add, grouped by wave,
with the source URL(s) you used for each. Ask for confirmation before
editing `check_compromised_packages.py`.

## 4. Apply the edit

After confirmation:

1. Edit `check_compromised_packages.py` — add entries to `NPM_BAD` or
   `PYPI_BAD`, grouped under an existing wave comment or under a new
   `# <wave name> (<date>)` block if it's a new campaign.
2. Update the "What's tracked" table in `README.md` if the new entries
   represent a new wave.
3. Run the synthetic-manifest sanity check:
   ```bash
   tmp=$(mktemp -d)
   echo '{"dependencies":{"<pkg>":"<version>"}}' > "$tmp/package.json"
   python3 check_compromised_packages.py "$tmp"    # expect exit 1
   rm -rf "$tmp"
   ```
   For PyPI entries, use a `requirements.txt` instead.
4. Run `python3 -m py_compile check_compromised_packages.py` to confirm
   no syntax errors.

## 5. Commit

Stage and commit with a message that cites every source URL used. Example:

```
Add @scope/foo 1.2.3, 1.2.4 (Mini Shai-Hulud wave N)

Sources:
- GHSA-xxxx-yyyy-zzzz
- https://www.aikido.dev/blog/...
```

Per repo policy (and the user's global `CLAUDE.md`), do **not** mention
Claude or any AI assistant in the commit message.

Do not push automatically — let the user open a PR or push themselves.
