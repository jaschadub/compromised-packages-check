# compromised-packages-check

A single-file Python scanner that flags known-malicious package versions from
recent npm and PyPI supply-chain compromises in any repository.

Pure stdlib. No dependencies. Drop into CI or run locally.

## Usage

```bash
python3 check_compromised_packages.py [path]   # defaults to current dir
```

Exit codes:

| Code | Meaning |
| --- | --- |
| `0` | clean |
| `1` | at least one malicious package version found |
| `2` | usage error |

The scanner walks the tree (skipping `node_modules`, `.venv`, `.git`,
`dist`, `build`, etc.) and parses:

- **npm:** `package.json`, `package-lock.json` (v1/v2/v3), `yarn.lock`,
  `pnpm-lock.yaml`
- **PyPI:** `requirements*.txt`, `pyproject.toml`, `Pipfile`,
  `Pipfile.lock`, `poetry.lock`, `setup.py`

Output:

```
FOUND 2 MALICIOUS PACKAGE VERSION(S):
  [npm]  @tanstack/react-router@1.169.8  (web-app/package-lock.json)
  [pypi] durabletask@1.4.2               (requirements.txt)

1 package(s) in advisory-affected scopes (verify versions manually):
  @uipath/new-pkg@0.0.1  (services/foo/package.json)
```

The scanner also emits a warning (no failure) for any package living under
an advisory-affected npm scope (`@mistralai/`, `@uipath/`, `@opensearch-project/`)
where the version doesn't exactly match the malicious list — useful for
catching newly-disclosed entries before this repo has been updated.

## What's tracked

| Wave | Scope / Packages |
| --- | --- |
| TanStack — May 2026 (GHSA-g7cv-rxg3-hmpx, CVE-2026-45321) | 42 `@tanstack/*` packages, 84 versions |
| Mini Shai-Hulud — May 2026 | `@mistralai/mistralai`, `@mistralai/mistralai-gcp`, `@mistralai/mistralai-azure`; `@opensearch-project/opensearch`; 66 `@uipath/*` packages |
| PyPI — May 2026 | `durabletask` 1.4.1 – 1.4.3, `mistralai` 2.4.6, `guardrails-ai` 0.10.1 |
| @cap-js / mbt — April 2026 | `@cap-js/sqlite` 2.2.2, `@cap-js/postgres` 2.2.2, `@cap-js/db-service` 2.10.1, `mbt` 1.2.48 |

Per Corgea research, the `@uipath/*` and `@mistralai/*` payloads contain a
bug that renders the malware non-functional. Installed versions should still
be removed and credentials rotated, but the realised impact differs from the
working `@tanstack/*` payloads.

## Contributing

New advisory? Open an issue or PR adding entries to `NPM_BAD` / `PYPI_BAD`
in `check_compromised_packages.py`. Please include:

- The advisory URL (GHSA, CVE, OSV, or a primary security-vendor writeup)
- Exact package names and version strings

## Sources

- [TanStack postmortem](https://tanstack.com/blog/npm-supply-chain-compromise-postmortem)
- [GHSA-g7cv-rxg3-hmpx](https://github.com/advisories/GHSA-g7cv-rxg3-hmpx)
- [Snyk — TanStack npm packages hit by Mini Shai-Hulud](https://snyk.io/blog/tanstack-npm-packages-compromised/)
- [Wiz — Mini Shai-Hulud strikes again](https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised)
- [Aikido — Mini Shai-Hulud is back](https://www.aikido.dev/blog/mini-shai-hulud-is-back-tanstack-compromised)
- [Corgea — Mini Shai-Hulud supply-chain worm](https://corgea.com/research/tanstack-supply-chain-attack-mini-shai-hulud)
- [The Hacker News — Mini Shai-Hulud worm coverage](https://thehackernews.com/2026/05/mini-shai-hulud-worm-compromises.html)

## License

MIT — see [LICENSE](LICENSE).

Author: Jascha Wanger / Tarnover, LLC
