# SKILLS.md — keeping the BAD list current

This file is a working guide for whoever (or whatever) is maintaining
`NPM_BAD`, `PYPI_BAD`, and `CRATES_BAD` in `check_compromised_packages.py`.
Supply-chain incidents are continuous; the list is only as good as the
cadence at which it's refreshed.

## Slash commands

Two Claude Code slash commands ship in `.claude/commands/`. They activate
automatically when this repo is cloned into a project (or installed as a
plugin):

| Command | Purpose |
| --- | --- |
| `/check-packages [path]` | Runs `check_compromised_packages.py` against the current repo (or `path`) and explains the result, including remediation hints if hits are found. Read-only. |
| `/update-bad-list [advisory id / scope / URL]` | Researches a new advisory (or sweeps the standard sources when called with no argument), shows a proposed diff against the evidence threshold below, then — after confirmation — edits `NPM_BAD` / `PYPI_BAD`, updates the README's tracked-waves table, and runs a synthetic-manifest sanity check before committing. Does not push. |

Both commands are thin wrappers over the workflow documented below; nothing
in this file changes whether you invoke them by slash command or by hand.

## What "good evidence" looks like

Before adding an entry to `NPM_BAD` / `PYPI_BAD` / `CRATES_BAD`, get at
least one of:

- **A GHSA / OSV / CVE record** with the package name and exact version(s).
- **A primary-source maintainer postmortem** (e.g. the TanStack blog post)
  naming versions explicitly.
- **Two independent security-vendor writeups** that agree on the package
  list and versions.

Single-vendor blog posts with no enumerated versions are not enough — log
the scope under `NPM_SUSPECT_SCOPES` instead and wait for a precise list.

**Always cross-check OSV directly by package name** before trusting (or
giving up on) a vendor article's version data. Many vendor writeups —
including The Hacker News, Socket blog posts and SafeDep digests — list
package names without versions, while OSV almost always has a per-package
`MAL-YYYY-NNNN` record with structured `affected.versions` and
`affected.ranges` populated within hours of the takedown. The fastest
recipe:

```bash
curl -sS -X POST https://api.osv.dev/v1/query \
  -H "Content-Type: application/json" \
  -d '{"package":{"name":"<pkg>","ecosystem":"npm"}}' \
  | python3 -c "import sys,json; d=json.load(sys.stdin); \
    [print(v['id'], v.get('aliases'), \
           [(a.get('versions'), a.get('ranges')) for a in v.get('affected',[])]) \
     for v in d.get('vulns',[])]"
```

(Same for `"ecosystem":"PyPI"` or `"ecosystem":"crates.io"`.)

### Interpreting OSV `affected` shapes

- `versions: ["1.2.3", "1.2.4"]` → pin those exact strings.
- `versions: ["1.0.12"]` *combined with* `ranges: [{events:[{introduced:"0"}]}]`
  → the *whole* package is malicious; `1.0.12` is just what was published
  before the takedown. Use the **empty-set wildcard** (see below), not
  just `1.0.12` — re-uploads under different versions will otherwise be
  missed. The npm registry's `0.0.1-security` placeholder is a strong tell
  that a takedown happened and this case applies.
- `ranges` only, no `versions` → same story; empty-set wildcard.

### Empty-set wildcard convention

`NPM_BAD[pkg] = set()` (and the same for `PYPI_BAD` / `CRATES_BAD`) means
*any installed version of this package is malicious*. Use it for
pure-malware typosquats where OSV's `affected.ranges` is `>=0` — i.e.
the package has no legitimate use whatsoever. Examples already in the
list: the entire TrapDoor npm cluster (`async-pipeline-builder`,
`chain-key-validator`, etc.), and the entire `CRATES_BAD` dict (every
RustSec advisory tagged `categories = ["malicious"]` has
`[versions] patched = []`, i.e. the crate was removed from the registry).
For legitimate packages with a single bad release (e.g. `axios`,
`node-ipc`), **always pin exact versions** — do not wildcard.

### crates.io specifics

The RustSec advisory database (`github.com/rustsec/advisory-db`) is the
canonical source — it cross-publishes to OSV with the `crates.io`
ecosystem string. To enumerate every crate currently flagged as
supply-chain malware:

```bash
git clone --depth 1 --filter=blob:none --sparse \
  https://github.com/rustsec/advisory-db.git /tmp/rustsec-adv
cd /tmp/rustsec-adv && git sparse-checkout set crates
grep -lE '^categories *=.*"malicious"' crates/*/RUSTSEC-*.md
```

Any file from that grep is a candidate for `CRATES_BAD`. Cross-check that
the body contains `expect-deleted = true` and `[versions] patched = []`
before adding it — that's RustSec's signal that the package was pulled
from crates.io entirely (and therefore the empty-set wildcard is correct).
Vulnerability advisories tagged `code-execution` or `memory-corruption`
in legitimate crates (e.g. `rkyv`, `starship`, `age`) are out of scope
— this tool only tracks malicious supply-chain incidents, not CVEs in
otherwise-legitimate crates.

## Where to look for new compromises

### Primary advisory databases (authoritative, machine-readable)

| Source | Notes |
| --- | --- |
| [GitHub Advisory Database](https://github.com/advisories) | Filter by ecosystem (npm / pip). Each GHSA links to the affected versions. Searchable via `gh api /advisories`. |
| [OSV.dev](https://osv.dev) | Aggregates GHSA, PYSEC, npm, etc. Has a JSON API: `https://api.osv.dev/v1/query` |
| [npm Security Advisories](https://www.npmjs.com/advisories) | Vendor list for the npm registry. |
| [PYSEC / pypa/advisory-database](https://github.com/pypa/advisory-database) | Canonical PyPI advisory source. |
| [CVE.org / NVD](https://www.cve.org/) | Slower to publish, but useful for cross-referencing. |

### Security-vendor research blogs (often first to enumerate versions)

| Source | URL |
| --- | --- |
| Aikido | https://www.aikido.dev/blog |
| Socket | https://socket.dev/blog |
| Snyk | https://snyk.io/blog/ |
| Wiz | https://www.wiz.io/blog |
| Mend | https://www.mend.io/blog/ |
| StepSecurity | https://www.stepsecurity.io/blog |
| Phylum | https://blog.phylum.io/ |
| ReversingLabs | https://www.reversinglabs.com/blog |
| Checkmarx Zero | https://checkmarx.com/blog/ |
| JFrog Security Research | https://jfrog.com/blog/category/security-research/ |
| SafeDep | https://safedep.io/blog |
| Corgea Research | https://corgea.com/research |
| Microsoft Security Blog | https://www.microsoft.com/en-us/security/blog/ |
| Palo Alto Unit 42 | https://unit42.paloaltonetworks.com/ |
| Red Hat (supply-chain digest) | https://access.redhat.com/security/supply-chain-attacks-NPM-packages |

### Aggregators / news

- [The Hacker News](https://thehackernews.com/) — fast tag for ongoing waves.
- [CyberScoop](https://cyberscoop.com/) — incident timelines.
- [Security Boulevard](https://securityboulevard.com/) — republishes many vendor writeups.
- [@vxunderground](https://twitter.com/vxunderground), [@malwrhunterteam](https://twitter.com/malwrhunterteam) and the npm/pypi security tags on Mastodon/Bluesky often surface things before formal advisories.

### Affected-project incident pages (when a campaign targets a specific scope)

- Look for an **incident** / **security** post on the project's own blog or
  the **GitHub Issues** of its main repo (e.g. `TanStack/router#7383`,
  `opensearch-project/opensearch-js#1116`). Maintainers usually publish
  the precise malicious versions there first.

## Workflow to add a new entry

1. **Confirm the evidence threshold above is met.** Cross-check OSV by
   package name even when a vendor article looks complete — that's how
   you'll catch any-version typosquats whose vendor coverage only lists
   names.
2. **Add the entry to the right dict** in `check_compromised_packages.py`:
   ```python
   "@scope/pkg": {"1.2.3", "1.2.4"},   # specific malicious versions
   "evil-typosquat": set(),            # any version is malicious
   ```
   Use `CRATES_BAD` for crates.io entries (almost always empty-set), and
   group entries by wave under the existing comments.
3. **Sanity-check parsing** against a synthetic manifest:
   ```bash
   tmp=$(mktemp -d)
   echo '{"dependencies":{"@scope/pkg":"1.2.3"}}' > "$tmp/package.json"
   python3 check_compromised_packages.py "$tmp"   # expect exit 1
   rm -rf "$tmp"
   ```
4. **Update README.md** "What's tracked" if the wave isn't already listed.
5. **Cite the source(s)** in the commit message — GHSA / CVE id and the
   vendor URL(s) used. Example:
   `Add @foo/bar 1.2.3 (GHSA-xxxx-yyyy-zzzz; src: aikido.dev/...)`.
6. **Open a PR.** Smaller PRs (one wave per PR) review faster than bulk
   updates.

## Heuristics for triage

- **Watch for scope-wide compromises.** If three or more packages from the
  same npm scope drop within a 24h window, assume the maintainer account
  or its CI is compromised and check the *whole* scope.
- **Check the "latest" tag.** Many of these attacks target `latest` rather
  than older releases — the malicious version is almost always above the
  most recent known-good one.
- **Sub-1.0 versions are not safe by default.** Several waves have hit
  `0.0.x` "tool" packages where downstream installs are sparse but blast
  radius (CI tokens) is huge.
- **Look at `preinstall` / `postinstall` scripts** in `package.json` of any
  suspicious version — that's the most common payload-delivery path for
  this campaign family.
- **For PyPI, check `setup.py` for non-trivial network or subprocess calls**
  at install time.

## Things this scanner deliberately does *not* do

- Resolve semver ranges. We match exact pinned versions only. A loose range
  like `"^1.0.0"` will not be flagged even if a compromised version sits
  inside the range — that's why we encourage running scans against
  lockfiles (`package-lock.json`, `yarn.lock`, `poetry.lock`), which pin
  exact resolved versions.
- Reach out to the network. The scanner is fully offline so it's safe to
  run in air-gapped CI.
- Replace a full SCA tool (Snyk, Socket, OSV-Scanner). It is intentionally
  a focused, auditable, single-file fallback for the recent high-impact
  waves.
