# Routine: compromised-packages-check advisory sweep

A scheduled remote Claude Code agent (claude.ai routine) that sweeps for
newly-disclosed npm/PyPI/crates.io supply-chain advisories every 6 hours
and, if any qualify, edits `check_compromised_packages.py` + `README.md`,
commits, and pushes to `main`.

This file documents the routine for version control. The canonical state
lives on the claude.ai control plane and can be managed at the routine
URL below. **Edits to this file do NOT auto-apply** — they need to be
propagated via the `RemoteTrigger` API (or via the web UI). Use this
file as the source of truth when updating the routine: change it here,
review in a PR, then mirror the new prompt / tool list into the live
routine.

## Identity

| Field | Value |
| --- | --- |
| Name | `compromised-packages-check: advisory sweep` |
| Routine ID | `trig_01JSf6Txy8EP79b9PdD6cRCH` |
| Manage | https://claude.ai/code/routines/trig_01JSf6Txy8EP79b9PdD6cRCH |
| Cron | `0 */6 * * *` UTC (every 6h at :00) |
| Local cadence | 5pm, 11pm, 5am, 11am America/Los_Angeles |
| Model | `claude-sonnet-4-6` |
| Environment | Default Cloud Environment (`env_017Ka1uQJ3mdThQv7FU1ev4E`) |
| Repo | `https://github.com/jaschadub/compromised-packages-check` (clones `main`) |
| Allowed tools | `Bash`, `Read`, `Write`, `Edit`, `Glob`, `Grep`, `WebFetch` |
| MCP connectors | none |

## Source policy

**Reliable = machine-readable + no anti-bot.** Every source below is
either (a) the OSV.dev bulk export on GCS, (b) a git repo accessible via
`gh api`, or (c) the GitHub REST API. None require WebFetch against
Cloudflare-protected vendor sites — those (Snyk/Aikido/Xygeni/Socket/
StepSecurity/SafeDep/Openwall) return 403 from the sandbox UA and have
been removed from the sweep. Vendor writeups are still consulted, but
only when a primary source (OSV/GHSA) points at one as a reference.

### Primary sources (always queried)

| Source | Access | Why |
| --- | --- | --- |
| OSV.dev bulk export — npm | `curl https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip` | Single download, contains every npm `MAL-YYYY-NNNN` ever published with exact `affected` data. ~200MB. |
| OSV.dev bulk export — PyPI | `curl https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip` | Same as above for PyPI. |
| OSV.dev bulk export — crates.io | `curl https://osv-vulnerabilities.storage.googleapis.com/crates.io/all.zip` | Same as above for crates.io. |
| OSV.dev per-package query | `curl -X POST https://api.osv.dev/v1/query -d '{"package":{"name":"<pkg>","ecosystem":"npm"}}'` | Used to verify a candidate surfaced by other sources. |
| GitHub Advisory Database — npm malware | `gh api '/advisories?type=malware&ecosystem=npm&per_page=50'` | Fresh GHSA `MAL-*` records. |
| GitHub Advisory Database — PyPI malware | `gh api '/advisories?type=malware&ecosystem=pip&per_page=50'` | Same for pip. |
| `github/advisory-database` git mirror | `gh api '/repos/github/advisory-database/contents/advisories/github-reviewed/<YYYY>/<MM>'` | Direct file listing for the current month; lets us pull `MAL-*` JSON without rate-limit pain. |
| `ossf/malicious-packages` git tree | `gh api '/repos/ossf/malicious-packages/contents/osv/malicious/<ecosystem>'` | Browse the malware-only tree per ecosystem; complements OSV when it hasn't ingested yet. |
| `rustsec/advisory-db` git tree | `gh api '/repos/rustsec/advisory-db/contents/crates'` then grep for `categories.*"malicious"` in candidate `RUSTSEC-*.md` files | Authoritative for crates.io. |

### Secondary sources (only consulted when a primary points to them)

| Source | Access | Why |
| --- | --- | --- |
| GitHub issue search | `gh search issues '<query>' --updated '>=<floor>' --limit 30` | Maintainer postmortems before formal advisories. Works because `gh` uses authenticated GitHub API, not scraping. |
| Vendor blog URL referenced from an OSV/GHSA record | `WebFetch <url>` | Only if the primary record cites it — we already trust the record at this point and just want the human context. |

### Removed (do not re-add unless something fundamental changes)

| Source | Why removed |
| --- | --- |
| Snyk RSS / blog | 403 from sandbox UA (Cloudflare bot protection). Snyk advisories land in GHSA/OSV anyway. |
| Aikido RSS / blog | 403 from sandbox UA. |
| Xygeni RSS / blog | 403 from sandbox UA. |
| Socket blog HTML | 403 from sandbox UA. Socket data is in OSV. |
| StepSecurity blog HTML | 403 from sandbox UA. |
| SafeDep blog HTML | 403 from sandbox UA. |
| Openwall oss-security | 403 from sandbox UA. Rarely first-source for package supply-chain anyway. |
| Microsoft Security Blog RSS | Low signal for npm/PyPI/crates malware specifically. |
| Palo Alto Unit 42 RSS | Same — broad threat intel, not package-focused. |
| Phylum | Domain acquired by Veracode; no usable feed. |

If a primary source surfaces a vendor URL we want to read, that's fine
(WebFetch on a specific URL sometimes works even when the index is
blocked). But we do not start with the vendor — we start with OSV/GHSA.

## Prompt (mirrored from the live routine)

The prompt below is what the routine sends to the remote agent on each
fire. Keep this in sync with the live routine — diverging this file from
the live config defeats the purpose.

```
You are a scheduled remote agent running every 6 hours in a fresh clone of
https://github.com/jaschadub/compromised-packages-check on `main`. Your job
is to sweep newly-disclosed npm/PyPI/crates.io supply-chain advisories
and, if any qualify, add them to the scanner, commit, and push.

## Setup
1. `cd` to the repo root. Read `SKILLS.md` and `.claude/commands/update-bad-list.md` — these are the authoritative workflow.
2. Get the floor date: `FLOOR=$(git log -1 --pretty=format:'%ad' --date=short)`. Anything published or last-modified before that is already covered.
3. Note every key already in `NPM_BAD`, `PYPI_BAD`, `CRATES_BAD`, and `NPM_SUSPECT_SCOPES` so you don't propose duplicates.

## Sweep order (primary sources first, secondary only when justified)

### 1. OSV.dev bulk exports (highest signal — every ecosystem in one shot each)

Download once per ecosystem and filter to `MAL-*` IDs modified on/after `$FLOOR`. The exports are large but reliable.

```bash
mkdir -p /tmp/osv && cd /tmp/osv
for eco in npm PyPI crates.io; do
  curl -fsSL -o "${eco/\//_}.zip" "https://osv-vulnerabilities.storage.googleapis.com/${eco}/all.zip"
done

python3 - <<'PY'
import zipfile, json, os, datetime, sys
floor = os.environ['FLOOR']
for eco_file, label in [('npm.zip','npm'), ('PyPI.zip','PyPI'), ('crates.io.zip','crates.io')]:
    z = zipfile.ZipFile(f'/tmp/osv/{eco_file}')
    for name in z.namelist():
        if not name.startswith('MAL-'):
            continue
        data = json.loads(z.read(name))
        modified = data.get('modified','')[:10]
        if modified < floor:
            continue
        for aff in data.get('affected', []):
            pkg = aff.get('package',{}).get('name')
            versions = aff.get('versions') or [
                f"range:{e}" for r in aff.get('ranges',[]) for e in r.get('events',[])
            ]
            print(f"{label}\t{data['id']}\t{modified}\t{pkg}\t{versions}")
PY
```

For every row whose package isn't already covered, this is your candidate list.

### 2. GitHub Advisory Database malware filter (backstop for OSV lag)

- `gh api '/advisories?type=malware&ecosystem=npm&per_page=50' --jq '.[] | select(.published >= env.FLOOR) | {id, summary, vulnerabilities}'`
- Same with `ecosystem=pip` and `ecosystem=rust`.

Any GHSA `MAL-*` returned but not in your OSV results from step 1 is a candidate.

### 3. ossf/malicious-packages tree diff (catches things OSV hasn't ingested yet)

```bash
for eco in npm pypi crates.io; do
  gh api "/repos/ossf/malicious-packages/contents/osv/malicious/${eco}?ref=main" \
    --paginate --jq '.[] | .name' > /tmp/ossf-${eco}.txt
done
```

Diff against the names already in `NPM_BAD`/`PYPI_BAD`/`CRATES_BAD`. For new names, fetch the per-package directory to find the `MAL-*.json` and read it via `gh api '/repos/ossf/malicious-packages/contents/osv/malicious/<eco>/<pkg>'`.

### 4. rustsec/advisory-db check (crates.io specifically)

```bash
gh api '/repos/rustsec/advisory-db/contents/crates' --jq '.[] | .name' > /tmp/rustsec-crates.txt
```

For each crate name not already in `CRATES_BAD`, fetch `crates/<name>/` and look for any `RUSTSEC-*.md` whose front-matter `categories` includes `"malicious"`. Any such advisory modified ≥ `$FLOOR` is a candidate.

### 5. GitHub issue search (maintainer postmortems)

Only do this if steps 1–4 returned candidates that need corroboration, OR as a final sanity pass:

- `gh search issues 'compromised package' --updated ">=$FLOOR" --limit 30`
- `gh search issues 'malicious release' --updated ">=$FLOOR" --limit 30`
- `gh search issues 'supply chain compromise' --updated ">=$FLOOR" --limit 30`

### 6. Targeted WebFetch — only when a primary record points there

If an OSV/GHSA record cites a vendor writeup (Aikido/Socket/Snyk/etc.) and you want the human context for the commit message, WebFetch that specific URL. Do NOT iterate vendor blog indexes — they 403 the sandbox UA and you'll waste the run. If a single URL also 403s, note it and move on; the primary record is the source of truth.

## Evidence threshold (from SKILLS.md)

For each candidate package version, require ONE of:
- A GHSA/OSV/CVE record with exact versions, OR `affected.ranges` with `>=0` (which means the whole package is malicious — use the empty-set wildcard `set()`).
- A primary-source maintainer postmortem with versions enumerated.
- Two independent vendor writeups that agree on the version list.

Use `set()` ONLY for pure-malware typosquats where OSV says any version is malicious. Pin exact versions for legitimate-package compromises (axios, node-ipc, pytorch-lightning, intercom-client, etc).

Skip anything already in `NPM_BAD`, `PYPI_BAD`, `CRATES_BAD`, or covered by `NPM_SUSPECT_SCOPES`. If only a scope is known (no exact versions), add to `NPM_SUSPECT_SCOPES` rather than inventing entries.

## If qualifying entries are found
1. Edit `check_compromised_packages.py` — add entries under an existing wave comment, or create a new `# <wave name> (<date>)` block.
2. Update the `## What's tracked` table in `README.md` and append source URLs to `## Sources`.
3. Run sanity checks:
   ```
   python3 -m py_compile check_compromised_packages.py
   tmp=$(mktemp -d)
   printf '{"dependencies":{"<pkg>":"<ver>"}}' > "$tmp/package.json"
   python3 check_compromised_packages.py "$tmp"   # expect exit 1
   rm -rf "$tmp"
   ```
   For PyPI use a `requirements.txt` with `pkg==ver` lines. For crates.io use a `Cargo.toml` with `[dependencies]\n<pkg> = "0.1.0"` or a `Cargo.lock` block sourced from `registry+https://github.com/rust-lang/crates.io-index`.
4. `git add` only modified files (never `-A` or `.`). Commit with:
   - Subject: wave name + headline packages (<= 72 chars).
   - Body: every primary source URL used (OSV `MAL-YYYY-NNNN`, GHSA, CVE, RUSTSEC, plus any vendor URL the primary record cited).
   - **NEVER mention Claude, AI, an assistant, or Anthropic** — repo policy and the user's global CLAUDE.md forbid this.
5. `git push origin main`. If push fails for credential reasons, leave the commit local and report the failure — do not retry destructively.

## If nothing qualifies
Do not commit. End with a short report:
- The floor date you used.
- Which primary sources (1–4) you actually queried, and how many candidates each surfaced.
- Any borderline candidates that didn't meet the threshold and why.
- Any URL that 404'd, 403'd, timed out, or otherwise failed — so the routine can be tuned next time.

## Hard rules
- Never invent versions.
- Never `git push --force` or `git commit --amend`.
- Never `--no-verify` or skip hooks.
- Never mention Claude, AI, or Anthropic in commits.
- Stay on `main` — do not create branches or PRs.
- If a vendor URL fails, log it and keep going — the primary sources (1–4) are the source of truth, vendor pages are just colour.
```

## Re-applying this routine via the API

If the live routine is ever deleted or you want to recreate it elsewhere,
the `RemoteTrigger` API body looks like this (generate a fresh UUID for
the event):

```json
{
  "name": "compromised-packages-check: advisory sweep",
  "cron_expression": "0 */6 * * *",
  "enabled": true,
  "job_config": {
    "ccr": {
      "environment_id": "env_017Ka1uQJ3mdThQv7FU1ev4E",
      "session_context": {
        "model": "claude-sonnet-4-6",
        "sources": [
          {"git_repository": {"url": "https://github.com/jaschadub/compromised-packages-check"}}
        ],
        "allowed_tools": ["Bash", "Read", "Write", "Edit", "Glob", "Grep", "WebFetch"]
      },
      "events": [
        {"data": {
          "uuid": "<fresh-uuid-v4>",
          "session_id": "",
          "type": "user",
          "parent_tool_use_id": null,
          "message": {"role": "user", "content": "<prompt from the section above>"}
        }}
      ]
    }
  }
}
```
