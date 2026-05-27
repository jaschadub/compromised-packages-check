---
description: Research new supply-chain advisories and update NPM_BAD / PYPI_BAD / CRATES_BAD in the scanner
argument-hint: "[advisory id, scope, or URL]  (optional; otherwise sweeps the standard sources)"
---

Help the user add newly-disclosed compromised package versions to
`check_compromised_packages.py`. The user's argument (if any) is in
`$ARGUMENTS` — it may be a GHSA id, a CVE id, a RUSTSEC id, an npm scope,
a package name, or a URL to a vendor writeup.

Follow the workflow documented in `SKILLS.md`:

## 1. Gather candidates

- If `$ARGUMENTS` is **a URL**: fetch it with `WebFetch` and extract a
  `package | versions` table.
- If `$ARGUMENTS` is **a GHSA id** (e.g. `GHSA-xxxx-yyyy-zzzz`): fetch
  `https://github.com/advisories/<id>` with `WebFetch`.
- If `$ARGUMENTS` is **a RUSTSEC id** (e.g. `RUSTSEC-2026-0017`): fetch
  `https://rustsec.org/advisories/<id>.html` or read the corresponding
  `crates/<pkg>/<id>.md` file from a checkout of
  `https://github.com/rustsec/advisory-db`.
- If `$ARGUMENTS` is **a CVE id**: search GHSA and OSV for the matching
  advisory.
- If `$ARGUMENTS` is **a package name or scope**: query OSV
  (`https://api.osv.dev/v1/query`) and search GHSA for affected versions.
- If `$ARGUMENTS` **is empty**: do a sweep — use `WebSearch` to look for
  npm / PyPI / crates.io supply-chain advisories newer than the most
  recent commit in this repo, then dig into the top hits. For crates.io,
  also `grep -lE '^categories *=.*"malicious"' crates/*/RUSTSEC-*.md` in
  a sparse checkout of `rustsec/advisory-db` and diff against the names
  already in `CRATES_BAD`.

Always prefer primary sources. The reliable ones — all machine-readable,
none behind Cloudflare bot-protection:

- **OSV.dev bulk export (GCS)** — one ZIP per ecosystem, contains every `MAL-*` record:
  - `https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip`
  - `https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip`
  - `https://osv-vulnerabilities.storage.googleapis.com/crates.io/all.zip`
- **OSV.dev API**: `https://api.osv.dev/v1/query` — for verifying a single candidate.
- **GitHub Advisory Database** via `gh api '/advisories?type=malware&ecosystem={npm,pip,rust}'`.
- **`github/advisory-database` git mirror** via `gh api '/repos/github/advisory-database/contents/advisories/github-reviewed/<YYYY>/<MM>'`.
- **`ossf/malicious-packages` git tree** via `gh api '/repos/ossf/malicious-packages/contents/osv/malicious/<eco>'`.
- **`pypa/advisory-database`** and **`rustsec/advisory-db`** git trees via the same `gh api .../contents/...` pattern.

Vendor blogs (Aikido, Socket, Snyk, Wiz, Mend, StepSecurity, SafeDep,
Phylum, ReversingLabs, Checkmarx, JFrog, Corgea, Unit 42, Microsoft
Security Blog) are **secondary** — only fetch a specific vendor URL if
a primary record (OSV/GHSA) cites it. Their indexes and RSS feeds 403
the sandbox UA, so don't iterate them.

### Use the bulk OSV export for sweeps; per-package query for verification

For an `$ARGUMENTS`-less sweep, download the OSV bulk ZIPs once, then
filter to `MAL-*` IDs whose `modified` timestamp is on/after the floor
date:

```bash
FLOOR=$(git log -1 --pretty=format:'%ad' --date=short)
mkdir -p /tmp/osv && cd /tmp/osv
for eco in npm PyPI crates.io; do
  curl -fsSL -o "${eco/\//_}.zip" "https://osv-vulnerabilities.storage.googleapis.com/${eco}/all.zip"
done

FLOOR="$FLOOR" python3 - <<'PY'
import zipfile, json, os
floor = os.environ['FLOOR']
for f, label in [('npm.zip','npm'), ('PyPI.zip','PyPI'), ('crates.io.zip','crates.io')]:
    z = zipfile.ZipFile(f'/tmp/osv/{f}')
    for name in z.namelist():
        if not name.startswith('MAL-'): continue
        d = json.loads(z.read(name))
        if d.get('modified','')[:10] < floor: continue
        for aff in d.get('affected', []):
            pkg = aff.get('package',{}).get('name')
            versions = aff.get('versions') or [
                f"range:{e}" for r in aff.get('ranges',[]) for e in r.get('events',[])
            ]
            print(f"{label}\t{d['id']}\t{d['modified'][:10]}\t{pkg}\t{versions}")
PY
```

For verifying a single candidate that came from somewhere else (a vendor
writeup, an issue, etc.), the per-package OSV API is still the right tool:

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
   For PyPI entries use a `requirements.txt`; for crates.io use a
   `Cargo.toml` with `[dependencies]\n<pkg> = "0.1.0"` or a `Cargo.lock`
   with a `[[package]]` block sourced from
   `registry+https://github.com/rust-lang/crates.io-index`.
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
