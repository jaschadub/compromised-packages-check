# Routine: compromised-packages-check advisory sweep

A scheduled remote Claude Code agent (claude.ai routine) that sweeps for
newly-disclosed npm/PyPI supply-chain advisories every 6 hours and, if
any qualify, edits `check_compromised_packages.py` + `README.md`, commits,
and pushes to `main`.

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

## Sources the agent checks

Categorized A–E for the agent's reference.

### A. Primary advisory databases (authoritative, machine-readable)

| Source | Access |
| --- | --- |
| OSV.dev API | `curl -X POST https://api.osv.dev/v1/query` per candidate package |
| GitHub Advisory Database — npm malware | `gh api '/advisories?type=malware&ecosystem=npm&per_page=50'` |
| GitHub Advisory Database — PyPI malware | `gh api '/advisories?type=malware&ecosystem=pip&per_page=50'` |
| ossf/malicious-packages | `gh api '/repos/ossf/malicious-packages/commits?per_page=30'` |

### B. Vendor RSS feeds (early disclosure, often before GHSA)

| Source | URL |
| --- | --- |
| Snyk blog | https://snyk.io/blog/feed/ |
| Aikido blog | https://www.aikido.dev/feed |
| Xygeni Malicious Code Digest | https://xygeni.io/blog/feed/ |
| Microsoft Security Blog | https://www.microsoft.com/en-us/security/blog/feed/ |
| Palo Alto Unit 42 | https://unit42.paloaltonetworks.com/feed/ |

### C. Vendor blog indexes (no public RSS, scrape HTML)

| Source | URL |
| --- | --- |
| Socket blog | https://socket.dev/blog |
| StepSecurity blog | https://www.stepsecurity.io/blog |
| SafeDep blog | https://safedep.io/blog |

### D. GitHub issue search (maintainer postmortems before formal advisories)

Run with `--updated '>=<floor-date>'` where the floor is the date of the
repo's most recent commit:

- `gh search issues 'compromised package'`
- `gh search issues 'malicious release'`
- `gh search issues 'supply chain compromise'`
- `gh search issues 'supply chain attack'`

### E. Mailing list aggregator

| Source | URL |
| --- | --- |
| Openwall oss-security | https://www.openwall.com/lists/oss-security/ |

### Skipped / unavailable

| Source | Why |
| --- | --- |
| Phylum | Domain acquired by Veracode; no usable RSS post-migration |
| Socket public RSS | `/blog/rss` and `/feed` both return 4xx; HTML index is used instead |
| StepSecurity public RSS | `/blog/feed.xml` and `/rss.xml` both 404 |

## Prompt (mirrored from the live routine)

The prompt below is what the routine sends to the remote agent on each
fire. Keep this in sync with the live routine — diverging this file from
the live config defeats the purpose.

```
You are a scheduled remote agent running every 6 hours in a fresh clone of
https://github.com/jaschadub/compromised-packages-check on `main`. Your job
is to sweep newly-disclosed npm/PyPI supply-chain advisories and, if any
qualify, add them to the scanner, commit, and push.

## Setup
1. `cd` to the repo root. Read `SKILLS.md` and `.claude/commands/update-bad-list.md` — these are the authoritative workflow.
2. Get the floor date: `git log -1 --pretty=format:'%ad' --date=short`. Anything published before that is already covered.
3. Note every key already in `NPM_BAD`, `PYPI_BAD`, and `NPM_SUSPECT_SCOPES` so you don't propose duplicates.

## Sweep (run roughly in this order)

### A. Primary advisory databases (authoritative, machine-readable)
- **OSV.dev** — `curl -X POST https://api.osv.dev/v1/query -H 'Content-Type: application/json' -d '{"package":{"name":"<pkg>","ecosystem":"npm"}}'` for any candidate package name (swap ecosystem to `PyPI` as needed).
- **GitHub Advisory Database malware filter** — `gh api '/advisories?type=malware&ecosystem=npm&per_page=50'` and the same for `ecosystem=pip`. These return the freshest GHSA `MAL-YYYY-NNNN` records.
- **ossf/malicious-packages** — `gh api '/repos/ossf/malicious-packages/commits?per_page=30'` for the most recent ingestions; new advisories sometimes land here before OSV picks them up.

### B. Vendor RSS feeds (early disclosure, often before GHSA)
Fetch each with WebFetch and scan for post titles dated after the floor:
- `https://snyk.io/blog/feed/`
- `https://www.aikido.dev/feed`
- `https://xygeni.io/blog/feed/` — high signal: their weekly Malicious Code Digest is specifically npm/PyPI malware
- `https://www.microsoft.com/en-us/security/blog/feed/`
- `https://unit42.paloaltonetworks.com/feed/`

### C. Vendor blog indexes (no public RSS, fetch HTML and skim)
- `https://socket.dev/blog`
- `https://www.stepsecurity.io/blog`
- `https://safedep.io/blog`

When one of these surfaces a candidate, fetch the specific post URL and then verify against OSV/GHSA before adding.

### D. GitHub issue search (maintainer postmortems before formal advisories)
Replace `<floor>` with the date from Setup step 2:
- `gh search issues 'compromised package' --updated '>=<floor>' --limit 30`
- `gh search issues 'malicious release' --updated '>=<floor>' --limit 30`
- `gh search issues 'supply chain compromise' --updated '>=<floor>' --limit 30`
- `gh search issues 'supply chain attack' --updated '>=<floor>' --limit 30`

### E. Mailing list aggregator
- WebFetch `https://www.openwall.com/lists/oss-security/` — scan the listing for new package-poisoning threads since the floor.

## Evidence threshold (from SKILLS.md)
For each candidate package version, require ONE of:
- A GHSA/OSV/CVE record with exact versions, OR `affected.ranges` with `>=0` (which means the whole package is malicious — use the empty-set wildcard `set()`).
- A primary-source maintainer postmortem with versions enumerated.
- Two independent vendor writeups that agree on the version list.

Use `set()` ONLY for pure-malware typosquats where OSV says any version is malicious. Pin exact versions for legitimate-package compromises (axios, node-ipc, pytorch-lightning, etc).

Skip anything already in `NPM_BAD`, `PYPI_BAD`, or covered by `NPM_SUSPECT_SCOPES`. If only a scope is known (no exact versions), add to `NPM_SUSPECT_SCOPES` rather than inventing entries.

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
   For PyPI use a `requirements.txt` with `pkg==ver` lines.
4. `git add` only modified files (never `-A` or `.`). Commit with:
   - Subject: wave name + headline packages (<= 72 chars).
   - Body: every source URL used (OSV `MAL-YYYY-NNNN`, GHSA, CVE, vendor blog URLs).
   - **NEVER mention Claude, AI, an assistant, or Anthropic** — repo policy and the user's global CLAUDE.md forbid this.
5. `git push origin main`. If push fails for credential reasons, leave the commit local and report the failure — do not retry destructively.

## If nothing qualifies
Do not commit. End with a short report:
- The floor date you used.
- Which sources (A–E) you actually queried and how many results each returned.
- Any borderline candidates that didn't meet the threshold and why.
- Any source URL that 404'd, timed out, or otherwise failed — so the routine can be tuned next time.

## Hard rules
- Never invent versions.
- Never `git push --force` or `git commit --amend`.
- Never `--no-verify` or skip hooks.
- Never mention Claude, AI, or Anthropic in commits.
- Stay on `main` — do not create branches or PRs.
- If a vendor URL repeatedly fails, log it in the report and keep going; one bad feed shouldn't sink the whole run.
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
