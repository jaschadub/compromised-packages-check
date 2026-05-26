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

### Always cross-check OSV directly

Vendor articles (The Hacker News, Socket blog, SafeDep, etc.) routinely
list package names without versions, which makes it look like the
evidence threshold can't be met. OSV almost always has a per-package
`MAL-YYYY-NNNN` record with `affected.versions` and/or `affected.ranges`
populated within hours of the takedown — query it directly for every
named package before giving up:

```bash
curl -sS -X POST https://api.osv.dev/v1/query \
  -H "Content-Type: application/json" \
  -d '{"package":{"name":"<pkg>","ecosystem":"npm"}}' \
  | python3 -c "import sys,json; d=json.load(sys.stdin); \
    [print(v['id'], v.get('aliases'), \
           [(a.get('versions'), a.get('ranges')) for a in v.get('affected',[])]) \
     for v in d.get('vulns',[])]"
```

(Swap ecosystem to `PyPI` or `crates.io` as needed.) Read the
`Interpreting OSV affected shapes` section in `SKILLS.md` — pay particular
attention to `ranges: [{events:[{introduced:"0"}]}]`, which means *any
version is malicious* and calls for the empty-set wildcard.

## 2. Meet the evidence threshold

Per `SKILLS.md`, before adding any entry require **one** of:

- A GHSA / OSV / CVE record naming the package and exact versions
  (or a `>=0` range, which is OSV's any-version wildcard — see below).
- A primary-source maintainer postmortem with versions enumerated.
- Two independent vendor writeups that agree on the version list.

If a vendor article names a package but no version, **always query OSV by
package name first** (step 1) — OSV often has versions or a `>=0` range
the article omitted. Only fall back to `NPM_SUSPECT_SCOPES` if both the
vendor source *and* OSV are silent on versions.

For pure-malware typosquats where OSV's `affected.ranges` is `>=0`, use
the empty-set wildcard in `NPM_BAD` / `PYPI_BAD`:

```python
"evil-typosquat": set(),   # any installed version is treated as malicious
```

Do **not** use the wildcard for legitimate packages with one bad release
(e.g. `axios`, `node-ipc`) — those must stay version-pinned.

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
