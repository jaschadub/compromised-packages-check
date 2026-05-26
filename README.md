# compromised-packages-check

A single-file Python scanner that flags known-malicious package versions from
recent npm, PyPI, and crates.io supply-chain compromises in any repository.

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
`target`, `dist`, `build`, etc.) and parses:

- **npm:** `package.json`, `package-lock.json` (v1/v2/v3), `yarn.lock`,
  `pnpm-lock.yaml`
- **PyPI:** `requirements*.txt`, `pyproject.toml`, `Pipfile`,
  `Pipfile.lock`, `poetry.lock`, `setup.py`
- **crates.io:** `Cargo.toml` (inline, table, sub-table, and
  target-prefixed dependency forms), `Cargo.lock` (only entries sourced
  from the crates.io registry — path/git dependencies are skipped)

Output:

```
FOUND 3 MALICIOUS PACKAGE VERSION(S):
  [npm]       @tanstack/react-router@1.169.8  (web-app/package-lock.json)
  [pypi]      durabletask@1.4.2               (requirements.txt)
  [crates.io] rustdecimal@0.5.0               (Cargo.lock)

1 package(s) in advisory-affected scopes (verify versions manually):
  @uipath/new-pkg@0.0.1  (services/foo/package.json)
```

The scanner also emits a warning (no failure) for any package living under
an advisory-affected npm scope (`@mistralai/`, `@uipath/`, `@opensearch-project/`,
`@antv/`) where the version doesn't exactly match the malicious list —
useful for catching newly-disclosed entries before this repo has been updated.

## What's tracked

| Wave | Scope / Packages |
| --- | --- |
| dYdX — January 27 2026 (PYSEC-2026-1) | `@dydxprotocol/v4-client-js` 3.4.1, 1.22.1, 1.15.2, 1.0.31 (npm); `dydx-v4-client` 1.1.5.post1 (PyPI) |
| TeamPCP / Trivy cascade — March 2026 (GHSA-5mg7-485q-xm76, GHSA-955r-262c-33jc) | `litellm` 1.82.7, 1.82.8; `telnyx` 4.87.1, 4.87.2 (PyPI) |
| elementary-data — April 24 2026 | `elementary-data` 0.23.3 (PyPI) — GitHub Actions script-injection |
| TanStack — May 2026 (GHSA-g7cv-rxg3-hmpx, CVE-2026-45321) | 42 `@tanstack/*` packages, 84 versions |
| Mini Shai-Hulud — May 2026 | `@mistralai/mistralai`, `@mistralai/mistralai-gcp`, `@mistralai/mistralai-azure`; `@opensearch-project/opensearch`; 66 `@uipath/*` packages; `@squawk/{mcp,weather,flightplan}`; `@tallyui/connector-{medusa,vendure}` |
| @antv / atool mass wave — May 19 2026 (317 packages, 631 versions) | `@antv/{g2,g6,l7,s2,x6,scale}`, `size-sensor`, `echarts-for-react`, `timeago.js` (high-impact subset); rest covered by `@antv/` suspect scope |
| node-ipc — May 14 2026 (GHSA-g7cv-rxg3-hmpx) | `node-ipc` 9.1.6, 9.2.3, 12.0.1 |
| @bitwarden/cli — April 22 2026 (GHSA-g98r-qjhg-4fmr) | `@bitwarden/cli` 2026.4.0 |
| axios — March 31 2026 (GHSA-fw8c-xr5c-95f9, Sapphire Sleet / DPRK) | `axios` 0.30.4, 1.14.1; `plain-crypto-js` 4.2.0, 4.2.1 |
| PyPI — May 2026 | `durabletask` 1.4.1 – 1.4.3, `mistralai` 2.4.6, `guardrails-ai` 0.10.1 |
| PyTorch Lightning — April 30 2026 (GHSA-w37p-236h-pfx3, CVE-2026-44484) | `pytorch-lightning` 2.6.2, 2.6.3 |
| intercom-client — April 30 2026 (GHSA-54pg-9963-v8vg) | `intercom-client` 7.0.4 (npm) — maintainer credential compromise, Shai-Hulud campaign |
| @cap-js / mbt — April 2026 | `@cap-js/sqlite` 2.2.2, `@cap-js/postgres` 2.2.2, `@cap-js/db-service` 2.10.1, `mbt` 1.2.48 |
| TrapDoor crypto-stealer — May 22 2026 | 21 npm typosquats (`async-pipeline-builder`, `build-scripts-utils`, `chain-key-validator`, …) flagged any-version; 7 PyPI typosquats (`eth-security-auditor`, `cryptowallet-safety`, `defi-risk-scanner`, `solidity-build-guard` @ 0.1.0; `data-pipeline-check`, `env-loader-cli`, `git-config-sync` @ 0.1.0, 0.1.1) |
| Multi-cluster npm typosquat wave — May 25 2026 | 25 malicious-from-creation npm packages across 5 sub-clusters: 6 `ts-*` utilities (`ts-stream-compose`, `ts-result-pipe`, `ts-typeguard-utils`, `ts-config-mapper`, `ts-iter-utils`, `ts-schema-config`); 3 `@gbrlxvii/ts-*`; 6 `auth0-*` SDK typosquats; 2 `webservices.rest*`; 2 `vite-plugin-env-compat*`; 6 miscellaneous (`fivem-monitor`, `jules-standard`, `internallib_v95`, `chai-as-redeploy`, `expo-config-plugin-typescript`, `unique-string-64`) |
| crates.io — RustSec malicious advisories | 64 crates removed from crates.io and tagged `categories = ["malicious"]` in `rustsec/advisory-db`. Includes `rustdecimal` (2022 typosquat of `rust_decimal`), the 2023 `amaperf` typosquat cluster (`xrvrv`, `oncecell`, `serd`, `lazystatic`, `if-cfg`, `envlogger`, `postgress`, `postgresderive`, `tauri-winrt-notifications`, `windows-service-rs`, `monero-rpc-rs`, `acceptxmr-rs`, …), the 2026 Polymarket credential-stealer campaign (`polymarket-clients-sdk`, `polymarket-client-sdks`, `polymarkets-client-sdk`, `polymarkets-rs-clob-client`, `clob-sdk`, `rpc-check`), the timeapi.io impersonation cluster (`time_calibrator`, `time_calibrators`, `dnp3times`, `time-sync`, `chrono_anchor`, `tracings`, `tracing-check`, `tracing_checks`, `tracing-ethers`), and build.rs droppers (`mysten-metrics`, `sui-execution-cut`, `pretty-changelog-logger`, `logtrace`, `replit_ruspty`, `finch_cli_rust`, `safe-agent-rs`, `microsoftsystem64`, …). All entries are any-version wildcards (`patched = []` in RustSec). |

Per Corgea research, the `@uipath/*` and `@mistralai/*` payloads contain a
bug that renders the malware non-functional. Installed versions should still
be removed and credentials rotated, but the realised impact differs from the
working `@tanstack/*` payloads.

## Contributing

New advisory? Open an issue or PR adding entries to `NPM_BAD` / `PYPI_BAD`
/ `CRATES_BAD` in `check_compromised_packages.py`. Please include:

- The advisory URL (GHSA, CVE, OSV, or a primary security-vendor writeup)
- Exact package names and version strings

## Sources

- [Socket — malicious dYdX packages (npm + PyPI)](https://socket.dev/blog/malicious-dydx-packages-published-to-npm-and-pypi)
- [The Hacker News — dYdX wallet stealer and RAT](https://thehackernews.com/2026/02/compromised-dydx-npm-and-pypi-packages.html)
- [PYSEC-2026-1 — dydx-v4-client](https://github.com/pypa/advisory-database/blob/main/vulns/dydx-v4-client/PYSEC-2026-1.yaml)
- [GHSA-5mg7-485q-xm76 — litellm malicious versions](https://github.com/advisories/GHSA-5mg7-485q-xm76)
- [Datadog — LiteLLM and Telnyx TeamPCP campaign](https://securitylabs.datadoghq.com/articles/litellm-compromised-pypi-teampcp-supply-chain-campaign/)
- [Snyk — poisoned security scanner backdooring LiteLLM](https://snyk.io/blog/poisoned-security-scanner-backdooring-litellm/)
- [GHSA-955r-262c-33jc — telnyx malicious versions](https://github.com/team-telnyx/telnyx-python/security/advisories/GHSA-955r-262c-33jc)
- [Akamai — Telnyx SDK PyPI compromise](https://www.akamai.com/blog/security-research/telnyx-sdk-pypi-2026-teampcp-supply-chain-attacks)
- [StepSecurity — elementary-data PyPI compromise](https://www.stepsecurity.io/blog/elementary-data-compromised-on-pypi-and-ghcr-forged-release-pushed-via-github-actions-script-injection)
- [Snyk — elementary-data steals cloud credentials](https://snyk.io/blog/malicious-release-of-elementary-data-pypi-package-steals-cloud-credentials-from-data-engineers/)
- [Bleeping Computer — elementary-data 1.1M download package hacked](https://www.bleepingcomputer.com/news/security/pypi-package-with-11m-monthly-downloads-hacked-to-push-infostealer/)
- [TanStack postmortem](https://tanstack.com/blog/npm-supply-chain-compromise-postmortem)
- [GHSA-g7cv-rxg3-hmpx](https://github.com/advisories/GHSA-g7cv-rxg3-hmpx)
- [Snyk — TanStack npm packages hit by Mini Shai-Hulud](https://snyk.io/blog/tanstack-npm-packages-compromised/)
- [Wiz — Mini Shai-Hulud strikes again](https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised)
- [Aikido — Mini Shai-Hulud is back](https://www.aikido.dev/blog/mini-shai-hulud-is-back-tanstack-compromised)
- [Corgea — Mini Shai-Hulud supply-chain worm](https://corgea.com/research/tanstack-supply-chain-attack-mini-shai-hulud)
- [The Hacker News — Mini Shai-Hulud worm coverage](https://thehackernews.com/2026/05/mini-shai-hulud-worm-compromises.html)
- [Snyk — Mini Shai-Hulud hits AntV (300+ packages)](https://snyk.io/blog/mini-shai-hulud-antv-npm-supply-chain-attack/)
- [SafeDep — Mini Shai-Hulud 314 npm packages compromised](https://safedep.io/mini-shai-hulud-strikes-again-314-npm-packages-compromised/)
- [StepSecurity — node-ipc supply chain attack](https://www.stepsecurity.io/blog/node-ipc-npm-supply-chain-attack)
- [The Hacker News — node-ipc stealer backdoor](https://thehackernews.com/2026/05/stealer-backdoor-found-in-3-node-ipc.html)
- [Microsoft Security Blog — axios npm supply chain compromise](https://www.microsoft.com/en-us/security/blog/2026/04/01/mitigating-the-axios-npm-supply-chain-compromise/)
- [Huntress — axios supply chain compromise](https://www.huntress.com/blog/supply-chain-compromise-axios-npm-package)
- [CISA — Supply chain compromise impacts axios npm package](https://www.cisa.gov/news-events/alerts/2026/04/20/supply-chain-compromise-impacts-axios-node-package-manager)
- [The Hacker News — Bitwarden CLI compromised](https://thehackernews.com/2026/04/bitwarden-cli-compromised-in-ongoing.html)
- [Palo Alto Unit 42 — Bitwarden CLI impersonation attack](https://www.paloaltonetworks.com/blog/cloud-security/bitwardencli-supply-chain-attack/)
- [GHSA-w37p-236h-pfx3 — pytorch-lightning compromise](https://github.com/Lightning-AI/pytorch-lightning/security/advisories/GHSA-w37p-236h-pfx3)
- [GHSA-54pg-9963-v8vg — intercom-client 7.0.4 compromise](https://github.com/advisories/GHSA-54pg-9963-v8vg)
- [StepSecurity — intercom-client Shai-Hulud hijack](https://www.stepsecurity.io/blog/shai-hulud-worm-pivots-to-multi-cloud-intercom-client-hijacked)
- [Socket — intercom-client npm supply chain attack](https://socket.dev/blog/intercom-s-npm-package-compromised-in-supply-chain-attack)
- [The Hacker News — TrapDoor supply chain attack](https://thehackernews.com/2026/05/trapdoor-supply-chain-attack-spreads.html)
- [Socket — TrapDoor crypto-stealer](https://socket.dev/blog/trapdoor-crypto-stealer-npm-pypi-crates)
- [GHSA-jp5r-76w9-2rvh — ts-stream-compose](https://github.com/advisories/GHSA-jp5r-76w9-2rvh)
- [GHSA-66j8-7w8q-vvf5 — ts-result-pipe](https://github.com/advisories/GHSA-66j8-7w8q-vvf5)
- [GHSA-xqpr-hv2v-6pfj — ts-typeguard-utils](https://github.com/advisories/GHSA-xqpr-hv2v-6pfj)
- [GHSA-qgfv-9wmq-m4f7 — ts-config-mapper](https://github.com/advisories/GHSA-qgfv-9wmq-m4f7)
- [GHSA-f6hr-rvf9-ch6p — ts-iter-utils](https://github.com/advisories/GHSA-f6hr-rvf9-ch6p)
- [GHSA-vxrv-934h-xj6q — ts-schema-config](https://github.com/advisories/GHSA-vxrv-934h-xj6q)
- [GHSA-pvrm-mpcj-2mcp — @gbrlxvii/ts-project-lint](https://github.com/advisories/GHSA-pvrm-mpcj-2mcp)
- [GHSA-362c-qm74-42gg — @gbrlxvii/ts-form-utils](https://github.com/advisories/GHSA-362c-qm74-42gg)
- [GHSA-59j3-wvx3-w9hx — @gbrlxvii/ts-env-validator](https://github.com/advisories/GHSA-59j3-wvx3-w9hx)
- [GHSA-4xqv-4874-rxx6 — auth0-aspnetcore-utils](https://github.com/advisories/GHSA-4xqv-4874-rxx6)
- [GHSA-g8jx-g4j9-hh3w — auth0-internal-collector](https://github.com/advisories/GHSA-g8jx-g4j9-hh3w)
- [GHSA-cwjp-2mq2-6xp6 — auth0-android-helper-utils](https://github.com/advisories/GHSA-cwjp-2mq2-6xp6)
- [GHSA-xm89-4mqj-hfrq — auth0-net-sdk-utils](https://github.com/advisories/GHSA-xm89-4mqj-hfrq)
- [GHSA-c8ph-73mc-f5p8 — auth0-sample-dus-utils](https://github.com/advisories/GHSA-c8ph-73mc-f5p8)
- [GHSA-jfp3-8vwj-7g9v — auth0-common-telemetry](https://github.com/advisories/GHSA-jfp3-8vwj-7g9v)
- [GHSA-2qjx-pgq9-vx24 — webservices.rest](https://github.com/advisories/GHSA-2qjx-pgq9-vx24)
- [GHSA-v62r-4vqp-f32g — webservices.rest-utils](https://github.com/advisories/GHSA-v62r-4vqp-f32g)
- [GHSA-7v58-43rg-wjwq — vite-plugin-env-compat-1.5](https://github.com/advisories/GHSA-7v58-43rg-wjwq)
- [GHSA-2rh6-x7fc-2fr4 — vite-plugin-env-compat-plus](https://github.com/advisories/GHSA-2rh6-x7fc-2fr4)
- [GHSA-fc78-r45j-m7f5 — fivem-monitor](https://github.com/advisories/GHSA-fc78-r45j-m7f5)
- [GHSA-6pxr-857g-mr97 — jules-standard](https://github.com/advisories/GHSA-6pxr-857g-mr97)
- [GHSA-qcrh-87jf-mm39 — internallib_v95](https://github.com/advisories/GHSA-qcrh-87jf-mm39)
- [GHSA-w6gc-fhv9-53hq — chai-as-redeploy](https://github.com/advisories/GHSA-w6gc-fhv9-53hq)
- [GHSA-rj44-v8w3-c5q5 — expo-config-plugin-typescript](https://github.com/advisories/GHSA-rj44-v8w3-c5q5)
- [GHSA-gqvh-j8hx-425w — unique-string-64](https://github.com/advisories/GHSA-gqvh-j8hx-425w)
- [rustsec/advisory-db](https://github.com/rustsec/advisory-db) — canonical RustSec advisories (filter for `categories = ["malicious"]`)
- [Veracode (Phylum) — Rust malware staged on crates.io](https://www.veracode.com/blog/rust-malware-staged-on-crates-io/) (amaperf 2023 cluster)
- [Socket — 5 malicious Rust crates posed as time utilities](https://socket.dev/blog/5-malicious-rust-crates-posed-as-time-utilities-to-exfiltrate-env-files) (timeapi.io campaign)
- [crates.io blog — security incidents](https://blog.rust-lang.org/inside-rust/) — primary source for Polymarket and Mysten takedowns

## License

MIT — see [LICENSE](LICENSE).

Author: Jascha Wanger / Tarnover, LLC
