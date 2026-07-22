#!/usr/bin/env python3
"""
check_compromised_packages.py

Scan a repository for known-malicious package versions from recent npm,
PyPI, and crates.io supply-chain incidents (Mini Shai-Hulud / TanStack
May 2026, the April 2026 @cap-js / mbt wave, axios DPRK takeover March
2026, @bitwarden/cli April 2026, node-ipc May 2026, the @antv / atool
May 19 mass wave, the TrapDoor crypto-stealer typosquats from May 22
2026, the 25-package multi-cluster npm typosquat wave from May 25 2026,
the toskypi npm RAT/infostealer campaign May 25 2026, the CLOB IPFS
dropper campaign May 26 2026, the DPRK js-logger-pack / terminal-logger
npm stealer cluster April–May 2026, the leaked Shai-Hulud
deadcode09284814 npm infostealer/DDoS cluster May 26 2026, the TrapDoor
crates.io Sui/Move build.rs dropper cluster May 2026, intercom-client
April 2026, the dYdX supply-chain attack January 2026, TeamPCP
Trivy-cascade litellm and telnyx March 2026, elementary-data April 2026,
the Polymarket / Mysten / timeapi crates.io campaigns, the 2023 amaperf
crates typosquat cluster, the Nx build-system supply-chain compromise
May 27 2026, the @limebike dependency-confusion campaign May 27 2026, the
CanisterSprawl TeamPCP npm worm / Namastex Labs packages April 2026,
the @velora-dex/sdk registry-only macOS backdoor April 2026, the DevTap
user0001 typosquat cluster April–May 2026, the xinference PyPI TeamPCP
compromise April 2026, the dependency-confusion 99.x batch May 27 2026,
and related Mistral / Guardrails / durabletask / pytorch-lightning
poisonings, the May 26 2026 17-package pure-malware batch covering
Web3/DeFi, JSON-utility, Solidity/Hardhat, and document-library
typosquats, the September 8 2025 Qix phishing attack on the
chalk/debug/color/ansi npm ecosystem (19 packages, >2B weekly downloads,
crypto-wallet interceptor), the September 15 2025 Shai-Hulud worm wave via
@ctrl/tinycolor and ngx-bootstrap account takeovers, the Moika Tech
out-of-band dependency confusion campaign May 28 2026 (five private
scopes, 164 npm packages: @car-loans, @cloudplatform-single-spa,
@debit-ib, @fb-deposit, @mlspace), the vpmdhaj OpenSearch/CI typosquat
cluster May 28 2026 (14 npm packages targeting OpenSearch, ElasticSearch,
and CI/CD environments), the Roblox/robase PyPI typosquat cluster May 29
2026 (52 packages impersonating Roblox API / database helper libraries),
and the oob-moika-tech dependency-confusion npm sub-wave May 29 2026
(@databus-service-ui, @service-suppliers, @service-user-notifications,
@polka-ui, @pulse-web-platform-core, @loans, nemo-reporter), the
oob-moika-tech Wave 2 npm dependency-confusion cluster May 29 2026
(17 packages by actor t-in-one / nath.dr4k3@gmail.com, C2 oob.moika.tech:
15 @t-in-one/* Angular DI token packages, @capibar.chat/ui-kit,
@sber-ecom-core/sberpay-widget; OSV MAL-2026-3337, 5031–5046), the
mixed npm malware batch May 29 2026 (buffer-util-extend GHSA-g44v-3gq3-j8p6,
hellowornd GHSA-4f9q-ffgq-5w82, tiny-naturalsort GHSA-mqp5-9r9w-8hg4,
@neon-i18n/core-ui and sorenson-webfonts dependency-confusion;
OSV MAL-2026-2920/4839/5027/5028/5030), and the modulebuild3240234t
PyPI Roblox infostealer May 29 2026 (OSV MAL-2026-5029), the puppeteer
25.0.1 maintainer-account compromise May 29 2026 (GHSA-8r2f-2qg4-cv9v),
Mini Shai-Hulud additional packages @beproduct/nestjs-auth and
@tallyui/storage-sqlite (May 2026; GHSA-cqpw-mfqj-f2j7 / MAL-2026-3433/3604),
supplemental @antv-wave non-@antv npm packages May 19 2026 (@lint-md/*,
canvas-nest.js, onfire.js, etc.; OSV MAL-2026-4123-4159), and the May 29-30
2026 multi-campaign dependency confusion + typosquat batch (100 new npm
packages across @clearpool, axis-*, ally-*, @breezeai-frontend,
@citi-icg-158830, apexomni/apexpro, @cplace-*, @rsi-community, @timelycare,
ethers.js/EVM typosquats, chai/tailwind plugin typosquats, zod-to-js, and
misc; OSV MAL-2026-3056 through MAL-2026-5085)), and the
polymarket-data PyPI crypto/credentials infostealer May 30 2026
(OSV MAL-2026-5086), and the crypto-helper / cryptolock PyPI install-time
malware batch May 30 2026 (OSV MAL-2026-5088/5089), the discord-ban PyPI
browser-credential infostealer May 30 2026 (OSV MAL-2026-5091), and the
neuralforge-ml PyPI env-variable exfiltrator May 30 2026 (OSV MAL-2026-5090),
and the retail-location-strategy-frontend npm malware May 30 2026
(OSV MAL-2026-5092), and the js-shared-modules npm malware May 31 2026
(OSV MAL-2026-5098), and the discord-massban PyPI browser-credential infostealer
May 31 2026 (OSV MAL-2026-5099), and the obfuscation PyPI install-time malware
May 31 2026 (OSV MAL-2026-5100), and the June 1 2026 npm batch: CMS-dropper
typosquat cluster (to-cms, cms-github, cms-helpgit, shopifyto-cms; OSV
MAL-2026-4693/5107/5108/5109), Amazon Inspector postinstall-exfiltration batch
(collected-forms-embed-js, audit-logsss, chainix; OSV MAL-2026-4175/4487/4817),
chai-as-minted Chai typosquat (OSV MAL-2026-5106), AWS/CLI typosquats
(@antoncallahan/aws-user-helper, @tmecontinue/cli; OSV MAL-2026-5101/5105),
and three GHSA-confirmed test-scope malware packages
(@ewfewfewf/testhackerrr, @osamdefeirrighs/testhackfrrferrr,
@pcldpvkoewpogw/testhacker; OSV MAL-2026-5102/5103/5104), the
@redhat-cloud-services scope account compromise June 1 2026 (nine packages:
chrome, eslint-config, frontend-components, frontend-components-config-utilities,
quickstarts-client, rbac-client, rule-components, topological-inventory-client,
types; OSV MAL-2026-5111 through MAL-2026-5119), loading-session npm package
compromise June 1 2026 (OSV MAL-2026-4600 / GHSA-7vwr-8v2c-gjvr), jingmeideshishi
npm throwaway malware June 1 2026 (OSV MAL-2026-5110 / GHSA-pc3j-w4f9-94hj), and
redteam-qxz7-utils PyPI malware June 1 2026 (OSV MAL-2026-5120), and
rookie-security-test-pkg npm malware June 1 2026 (OSV MAL-2026-5132), and
the June 2 2026 dep-confusion + PyPI RAT batch: @aonunited/angular dependency
confusion (OSV MAL-2026-5150), @att-ebiz/abs-components-bc dependency confusion
(OSV MAL-2026-5153), parsimonius Telegram-RAT typosquat of parsimonious
(OSV MAL-2026-5151), quant-backtest-helpers env/cloud-token exfiltrator
(OSV MAL-2026-5152), and bt-signal-utils env/cloud-token exfiltrator
(OSV MAL-2026-5160; same campaign as quant-backtest-helpers),
the @antv/color-util npm infostealer (Mini Shai-Hulud supplemental, June 2 2026;
OSV MAL-2026-3862 / GHSA-rh6v-hwr4-6jcp), the Scandinavian telecom dep-confusion
npm cluster June 2 2026 (@customer-threesixty/assets, @ownit/core, @telenor-se/core,
@tse-digital/core; actor debating0166; OSV MAL-2026-5154/5155/5156/5157), the
oob-moika-tech EMCD-impersonation Wave 3 npm dep-confusion cluster June 2 2026
(@emcd-vue/auth, @emcd-vue/b2b-pay-form, @emcd-vue/loans; OSV MAL-2026-5163/5164/5165),
the dep-confusion 99.x npm batch June 2 2026 (page-info-service 99.9.1,
po-ops-local-dev 99.9.1, sourceflow-tracker 99.91.9; OSV MAL-2026-5158/5159/5166),
and the jules-test-utils PyPI host-info exfiltrator June 2 2026 (OSV MAL-2026-5167),
vg-interaction-model npm dep-confusion June 2 2026 (OSV MAL-2026-5168; updated June 3
2026 to add version 40.0.4), chai-parse Chai typosquat any-version malware June 2 2026
(OSV MAL-2026-5169), and fundraiserserv npm malware June 3 2026 (OSV MAL-2026-5172;
communicates with a malicious domain; detected by OpenSSF Package Analysis),
and brave-search-mcp-server npm malware June 3 2026 (OSV MAL-2026-5182;
communicates with a malicious domain and executes malicious commands; detected
by OpenSSF Package Analysis), the sf-silly-goose-requests PyPI TruffleHog-based
secret exfiltrator June 4 2026 (OSV MAL-2026-5184), and the June 4 2026 npm
full-compromise batch: @jagreehal/workflow (OSV MAL-2026-5185 / GHSA-6w7v-23mf-65g3),
autotel-terminal (OSV MAL-2026-5186 / GHSA-cw9v-v9rh-r449), and supabase CLI
(OSV MAL-2026-5187 / GHSA-x96m-c5fj-q75c; fresh single-source advisory filed on
the same day version 2.105.0 was published), and the binding.gyp npm worm campaign
June 5 2026 (73 packages across multiple publishers: ai-sdk-ollama, @ethlete/* scope,
@forjacms/* scope, @vapi-ai/server-sdk, autotel/awaitly/executable-stories/
node-env-resolver ecosystems, Cloudflare Workers tools, and miscellaneous packages;
OSV MAL-2026-5195 through MAL-2026-5267; StepSecurity + Endor Labs disclosure),
and the ulid-os npm full-compromise typosquat June 5 2026
(OSV MAL-2026-5268 / GHSA-fxhm-35h8-7jc7), the utils-mf npm WhatsApp-bot
credential-exfiltration package June 5 2026 (OSV MAL-2026-4699 /
GHSA-4c54-hwv9-c5xm; 10 specific versions), the react-ui-polyfills remote-eval
backdoor npm package June 5 2026 (OSV MAL-2026-4784 / GHSA-v7mj-pmr3-7x4p),
and the June 5 2026 GHSA full-compromise npm pair glyphr
(OSV MAL-2026-5269 / GHSA-c988-j68q-h8h4) and reactvora
(OSV MAL-2026-5270 / GHSA-x4gw-cjrp-c89f), the goodoldtoulas / goodoltoulas
PyPI install-time droppers June 5 2026 (OSV MAL-2026-5271/5272), and the
anthropy PyPI reverse-shell infostealer June 5 2026 (OSV MAL-2026-5273), and
the Woodpecker PyPI infostealer campaign June 6 2026 (twelve legitimate scientific /
systems packages: dynamo-release, napari-ufish, nucbox, pantheon-toolsets,
spateo-release, uprobe, bramin, executor-http, mrbios, okite, synago, ufish;
obfuscated Bun-runtime JS payload exfiltrating credentials and crypto wallet data;
OSV MAL-2026-5274 through MAL-2026-5285), and the dep-confusion 99.x npm batch
extension June 6 2026 (unifi-portal 99.0.0; OSV MAL-2026-5289), and the
clip-logger PyPI clipboard-stealing crypto campaign June 7 2026 (clip-logger
8 versions, bittensor-burn-watch 16 versions; OSV MAL-2026-5292/5293), the
Woodpecker PyPI campaign additional packages June 7 2026 (cmd2func 0.2.2/0.2.3,
magique-ai 0.4.5; OSV MAL-2026-5290/5294), four more Woodpecker packages June 7 2026
(coolbox 0.4.1/0.4.2, magique 0.6.8/0.6.9, executor-engine 0.3.4/0.3.5,
pantheon-agents 0.6.1/0.6.2; OSV MAL-2026-5295/5296/5298/5299),
sequoia-engineering npm malware June 7 2026 (OSV MAL-2026-5291), and
consumerweb-authflow npm malware June 7 2026 (OSV MAL-2026-5297), and
additional Woodpecker PyPI infostealer campaign packages June 8–9 2026
(funcdesc, mflux-streamlit, nhmpy, rlask, rsquests, tlask, dreamgen, mem8,
orchestr8-platform, dstill; OSV MAL-2026-5300 through MAL-2026-5305, 5313,
5319, 5321, 5345), and a bioinformatics supply-chain compromise June 8–9 2026
targeting phenotype-analysis packages (embiggen, ensmallen, gpsea,
phenopacket-store-toolkit, ppkt2synergy, pyphetools; OSV MAL-2026-5314 through
MAL-2026-5316, 5322 through 5324), and the MCP-namespace PyPI typosquat cluster
June 8–9 2026 (instructor-mcp, langchain-core-mcp, openai-mcp, ray-mcp-server,
tiktoken-mcp; OSV MAL-2026-5317/5318/5320/5325/5326), and the Solana ecosystem
PyPI typosquat cluster June 9 2026 (solana-cli-py, solana-web3, solana-web3-py,
spl-token-py; OSV MAL-2026-5336 through MAL-2026-5339), and the Bittensor/crypto
clipboard-stealer extension campaign June 8–27 2026 (bittensor-burn-monitor 7
versions, bt-burn-watch, bittensor-burn-alert, bittensor-burn, bittensor-burn-message,
bittensor-emission-tracker, trongap, trongapy, spaysdatarbx, spaysrbx,
tao-subnet-metrics; OSV MAL-2026-5311/5312/5329/5330/5331/5334/5457/5489/
5680/5681/5683), and the @langgraphjs/toolkit npm any-version wildcard malware
(OSV MAL-2026-2509; SEMVER >=0 range), and June 8 2026 npm dep-confusion batches
(@listings/energy-labels + @zimmo/last_search 99.0.x; @bancolonbia/menu-filter-
widget-web 0.0.1; @demica/{core,resources,shared} 99.99.x;
@doaction/* 15 packages 9.9.9/99.99.99; @0xlr/* 7 packages 999.0.0;
@klapp-*/@easy-entry/@shell-* 12 packages 99.x; @nstrlabs/* 6 packages 99.x;
@oplus/* 3 packages 99.99.99; @orion-design-system/* 3 packages 9999.x;
@solana-labs/* 6 typosquat packages; @403name/* 3 packages;
@onum-releases/* 6 packages; OSV MAL-2026-5327/5328/5344/5349 through 5383/
5385 through 5391/5408 through 5429/5522 through 5525/5547 through 5549/
5786 through 5788/6122 through 6127), and the @mastra npm scope compromise
June 20–27 2026 (89 packages across the @mastra/* namespace, injecting a
credential-exfiltration payload into the Mastra AI agent framework; OSV
MAL-2026-5939 through 5964, 5996 through 6057, 6072 through 6074), and the
easyaillm LLM-utility PyPI typosquat cluster June 18–23 2026 (easyaillm,
easyaillm2, easyllmai, ezllmgen, llmgenerator, llamagenerator, generatellm,
fastgptmini, gptminifast, llmfree; OSV MAL-2026-5756/5765/5766/5769 through
5771/5773/5776/5795/5796), and dep-confusion PyPI batches June 8–27 2026
(nerfstudio-gs 99.0.x, requests-toolbelt-plus 99.9.x, icinga 99.x,
datacamp-light 99.0.0; OSV MAL-2026-5333/5519/5532/5868), and the
AI/LLM toolkit impersonation campaign June 29–30 2026 (anthropic-toolkit
21 versions, ai-sdk-helpers/ollama-helpers/openai-agents-helpers any-version;
OSV MAL-2026-6673/5565/6581/6582), the ts-einkle/ts-ankle TypeScript exploit
cluster June 29 2026 (ts-einkle, ts-einkle-slot, ts-ankle; OSV MAL-2026-6524/
6525/6548), the @thone33 credential-injector scope June 29 2026 (@thone33/
analytics-injector, @thone33/core-utils; OSV MAL-2026-6563/6564), the
@epic-common/observability-node dep-confusion June 29 2026 (OSV MAL-2026-6562),
the Gartner GX dep-confusion cluster June 29 2026 (gx-npm-feature-flags,
gx-npm-lib, gx-npm-ui; OSV MAL-2026-6466/6480/6481), the large dep-confusion
wave June 29 2026 (79 packages across scopes targeting Deel, Postman, Rakuten,
Experian, LexisNexis, Sixt, Gallup, PlanetLabs and others; OSV MAL-2026-6594
through MAL-2026-6672), 25 additional targeted dep-confusion packages June 29 2026
(ing-web-v5, eslint-plugin-totara, @ataslkit/profilecard, @shoobx/types,
@source-row/source-container, @serasa/core, @citi-icg-171632/*, @cloudways-lab/*,
@webd-infra/*, @webda-features/*, uipath-sugar-sell and others; OSV MAL-2026-2822/
2846/2855/2856/2857/2858/2952/2956/2978/4171/4172/4256/4257/4389/4425/4432/4826/
4827/5431/5432/5433/5453/5454/5455/5456), and the miscellaneous npm malware batch
June 29 2026 (55 packages: path-internal-util, http-uploader-dev, react-json-chalk,
tailwind-form, react-pinojs, node-denv, chain-chai-test, ssr-auth-sync, quirky-token,
swift-parse-stream, uol-simple-api-futebol, stackus, clx-cookie-signature, routecraft,
hunsterx-package, hardhat-test-log, base58-core, @vpms/design-system,
unsafe-malicious-package, velocityfix, wellnpm, @appupdate/cdn-sync, chai-as-assured,
crossmint-wallets-sdk, @uisp/utils, date-uuid, eslint-commit-parser, express-mocha-test,
longzy-basic-ui, pkg-fallback (npm), react-wp-viewer, rebrandly-domains-digger/
rebrandly-domains-search-client, yandex-geobase, @ibrahim1337/baksen,
checkmarx-claude-cache, int_sezzle_sfra, layerd-unit-codec-parser, lessload, loadutils,
pino-debugging, poly-kelly, stake-math, yastatic-s3, clob-client-math, endpointmap,
envfile-sync, envfile-sync-cli, ledgerflow-deploy-utils, maplibre-gl-vue3, vkzmn;
OSV MAL-2026-3312/4580/4792/5487/5488/5734/5908/5934/6066/6068/6087/6098/6141/6229/
6337/6369/6445/6467/6486/6487/6501/6524/6525/6531/6532/6545/6548/6562/6563/6564/6565/
6566/6567/6568/6569/6570/6571/6572/6573/6574/6575/6576/6577/6578/6579/6580/6581/6582/
6583/6584/6585/6586/6587/6588/6589/6590/6591/6592/6594 through 6672/6673), and the
PyPI malware batch June 29 2026 (sqligen, inlifegram, pdf-converter-pro any-version;
django-bkvision 1.2.0; OSV MAL-2026-6515/6516/6541/6593), the Polymarket typosquat
cluster June 30 – July 1 2026 (polymarket-clob-maths, polymarket-trading-developer-tools,
polymarket-risk-manager, polymarket-toolkit, polymarket-trading-developer-tool;
OSV MAL-2026-6691/6692/6712/6713/6714), the TypeScript / ESLint / CLOB typosquat
cluster June 30 – July 1 2026 (ts-lint-builders-v2.1, ts-linting-builder, ts-bn-proto,
ts-elinter, ts-eslint-helper, ts-clob-math-v2; OSV MAL-2026-6677/6678/6695/6719/6720/6721),
frontend framework typosquats July 1 2026 (date-fns-lite, svgson-lite, vega-lite-next,
vue-demi-fix, electron-orbit, svgcraft-core; OSV MAL-2026-6702/6707/6709/6715/6722/6723),
Hardhat/Solidity typosquats July 1 2026 (hardhat-compile-ethers, hardhat-plugin-solidity;
OSV MAL-2026-6705/6706), a 16-package GHSA full-compromise batch July 1 2026
(rs-biginteger, terminal-prettier, agent-starter-pack, brock-loader, brock-react-alerts,
confluent-kafka-javascript, nbmolviz-js, postcss-property-rollup, quoting, setup-cicd,
procwire, console-fmt-cli, decimal-format-core, log-taker1, thirdwb, thirdwebb;
OSV MAL-2026-6675/6676/6679/6680/6681/6682/6683/6684/6685/6686/6687/6688/6689/6690/6693/6694),
miscellaneous npm malware June 30 – July 1 2026 (pp-react-v5, triage-bot, sypoi1,
ripshakti, ripshakti1, ecto-corsair-flag-7kq3mz, module-index-cache, zyncmap,
vitest-agent, base65-85x, test-pkg-pnpm, test-pkg-x0, test-pkg-yarn;
OSV MAL-2026-3509/6346/6405/6674/6699/6700/6701/6704/6708/6710/6716/6717/6718),
dependency-confusion packages June 30 – July 1 2026
(@businessapp-microsites/apis, @sudoughnym/enviro-demo, @andes-tools/colors,
cursed-modules; OSV MAL-2026-6696/6697/6698/6703), and Woodpecker campaign update
July 1 2026 (magique-ai 0.4.4 added to existing 0.4.5 entry;
OSV MAL-2026-5294) and new PyPI malware twrap-tool (OSV MAL-2026-6711) and
starlette-healthcheck (OSV MAL-2026-6724), and the July 4–5 2026 batch:
yt-api-dlp PyPI crypto-stealer typosquat (OSV MAL-2026-6754),
httpprobe PyPI malware (OSV MAL-2026-6758), urlllib321 urllib3 PyPI
typosquat (OSV MAL-2026-6759), and the vps-maintenance / paperclip2
npm malware cluster (paperclip2, vps-maintenance,
vps-maintenance-paperclip-adapter; OSV MAL-2026-6755/6756/6757), and the
July 9-10 2026 batch: @wagni_bot/* DeFi/crypto SDK typosquat cluster
(16 packages; OSV MAL-2026-10022 through 10037), paysafe-* npm credential-
stealer cluster (8 packages; OSV MAL-2026-10166 through 10173), notify-*
npm malware cluster (7 packages; OSV MAL-2026-10152 through 10158),
type-slint/type-plint/type-elint/type-async/type-atob type-* npm malware
(OSV MAL-2026-10077/10130/10137/10164/10174), sidecar-mcp (OSV MAL-2026-10161),
@injectivelabs/sdk-ts 1.20.21 compromise (OSV MAL-2026-10165),
@bcryptln/becryptjs bcrypt typosquat (OSV MAL-2026-10162),
stella-ai-cli/stella-coder AI-tool malware (OSV MAL-2026-10133/10134),
chai-as/chain-chai new typosquat batch (22 packages; OSV MAL-2026-10039
through 10056/2339/2641/10082/10175), nodemon-gulp/nodemon-patch/nodemon-slint
(OSV MAL-2026-10065/10110/10117), polymarket-apis/kelly/kit/gamma new batch
(9 packages; OSV MAL-2026-10067 through 10072/10147/10148/10149), moonbit-*
PyPI cluster (OSV MAL-2026-2945/2946/2947), playwrightr PyPI typosquat
(OSV MAL-2026-10020), telegramlite/telegram-lite-grabber Telegram grabbers
(OSV MAL-2026-5531/6051), d0rk3r/nagios-xi/security-alerts-sdk/sufiagent/
pwn-control/web3-py-checksum PyPI batch (OSV MAL-2026-6246/5698/6327/3370/
3248/3411), and the July 11–12 2026 npm batch: auth-next-gen/authvaultx auth
typosquats (OSV MAL-2026-10180/10185), awesome-ts-jest ts-jest typosquat
(OSV MAL-2026-10188), client-cookies-agent/google-caja-bower dep-confusion
packages (OSV MAL-2026-10019/10186), jscrambler maintainer-account compromise
injecting a crypto-wallet/browser-session stealer (OSV MAL-2026-10187),
tinymask-js/tinyparrot single-version malware (OSV MAL-2026-10189/10190),
and svgcraft-core updated with versions 1.0.5/1.0.6 (OSV MAL-2026-6715),
and the July 12–13 2026 batch: fastify-addone Fastify plugin typosquat
(OSV MAL-2026-10098), 19 additional npm malware/dep-confusion packages
(polymarket-kelly-math-stake, api-changelly, chain-await-dom, giantswarm,
gptcore, library-explorer, nullrift, react-dom-v17, @meziizana/frontend-logger,
auto-debug-tool, mcp-notes-server-poc-praetorian, react-next-vite, vuln-package,
babel-preset-lib-client, polylabel-web-lib, bugexploit; OSV MAL-2026-10198
through MAL-2026-10214; node-sysmetrics GHSA-w2wx-f2m6-332m / MAL-2026-10216,
dotnet-runtime-base GHSA-9gr8-wg29-9wvv / MAL-2026-10217, pure-folder-three
GHSA-9w58-3cgj-jw7v / MAL-2026-10218), and 10 PyPI DeFi/crypto
credential-stealing packages (data-harvester, defi-tools, py-base58, solidity-dev,
eth-agent, jupiter-sdk, metemask-sdk sharing VirusTotal hash 4dd018d8; plus
proxy-check-i, pipspeed, fast-dotenv; OSV MAL-2026-10100/10191 through
MAL-2026-10197/10213/10215),
and the July 13-14 2026 npm/PyPI batch: 343 new npm packages across 15 campaigns
(dep-confusion MFE/internal-tools cluster, chai-as-*/fastify-bundler extension,
nodemon-* extension, polymarket-* extension, type-* extension, node-proc/fs
cluster, @gleamkit/@dervix socket.io typosquats, markable-table family,
getd-* dep-confusion, inflated-version dep-confusion batches, the
nottuff/abuden/ratelimitsucks/ishowfeet/speed/sixseven/imillegal/timmytuffknuckles/
backupsitetuff npm worm cluster, random-words any-version companion packages,
tipsen/antsrctest cluster, @gt-test-exp/profiler-exp-* cluster, and miscellaneous
individual packages; OSV MAL-2026-5393 through MAL-2026-10522), and 2 new PyPI
packages (turbocalcng OSV MAL-2026-10441, browser-use-headless OSV MAL-2026-10484),
and the July 14 2026 batch: @asyncapi maintainer-account compromise
(4 packages: @asyncapi/generator, @asyncapi/specs, @asyncapi/generator-components,
@asyncapi/generator-helpers; MAL-2025-190636/190643/190656/190657), the
@public-for-cdao dep-confusion cluster (6 packages at 99.99.99; MAL-2026-10599
through 10604), the crypto/DeFi npm credential-stealer cluster (14 packages:
@tabrex/bs58, @velkov/isows, @wrenfield/abitype, @wrenfield/viem, @web3-helpers/core,
eth-dev, abi-encode, ethereum-lib-utils, solana-key-utils, eth-wallet-helpers,
base58-utils, chain-sdk-js, chain-devkit, crypto-validate-lib; MAL-2026-10523/10524/
10529/10549/10552/10571/10572/10586/10591/10606/10608/10611/10613/10531/10580),
the Vite scope typosquat cluster (5 packages: @vite-mcp/vite-type, @vite-pro/vite-ui,
@vite-ts/vite-ui, @vitets/vite-ts, @vite-js/vui; MAL-2026-10525/10526/10527/10528/
10619), the developer-toolkit typosquat cluster (10 packages: chalkdev, chalkdevx,
cheeriobox, dayjscore, momenntjs, nodeaxois, openaiwrapper, stripedev, twiliobox,
yargsplus; MAL-2026-10583 through 10594), the akshajrawat DI-token/utility cluster
(14 any-version packages; MAL-2026-10554/10555/10558 through 10570), the @cw-ui/
micro-ui-loader dep-confusion (3 any-version packages; MAL-2026-10556/10557/10564),
the @public-for-cdao dep-confusion (6 packages), chai-as-act/hardened/structured
and nodemon-plint chai/nodemon extensions (MAL-2026-10595/10607/10621/10622),
five older-ID packages updated July 14 (class-weaver, @rockawayx/utils,
unified-ui-components-library, class-synth, @resolvx/core; MAL-2026-4521/5462/
5648/5730/5798), and ~35 miscellaneous npm packages (fluterjs, motion-pull,
n8n-nodes-social-facebook, neon-postgres, skrill/*, postcss-*, viteplugiin,
bimi-maker, ethers-core, harpoon-package, smb-*-uikit, monitoring-service*,
@sqlite-clone/nodesql, @sqlite-group/sql-creator, and others;
MAL-2026-10530 through MAL-2026-10623), plus 6 new PyPI packages (pokee-data-utils,
tennacity, proxy-check-ii, cosmos-cuda, cosmos-gradio, tronwe;
MAL-2026-10547/10576/10610/10617/10618/10624), the CanisterWorm @emilgroup
npm publisher-account compromise July 15 2026 (27 packages across the
@emilgroup scope — insurance, billing, claims, customer, and partner SDKs —
injected with a reverse-shell/credential-exfiltration backdoor; socket.dev +
JFrog primary sources; OSV MAL-2026-2031 through 2077), the gulp-jscrambler /
jscrambler-metro-plugin maintainer-account compromise July 15 2026
(OSV MAL-2026-10673/10674), the @bcs-mi-ui dep-confusion cluster July 15 2026
(OSV MAL-2026-10645/10646/10647), the @pimy-b2cweb dep-confusion cluster
July 15 2026 (OSV MAL-2026-10655/10656), the @sauruslord/* / zaldy-baileys /
ssweb-wp WhatsApp Baileys typosquat cluster July 15 2026
(OSV MAL-2026-10657 through 10663), the @fhkry/baileys-v2 and @fhkry/x-baileys
additional packages July 15 2026 (OSV MAL-2026-10664/10665), and the July 15-16
2026 miscellaneous npm/PyPI batch (~90 packages including ldpbootstrap-jquery
PowerShell dropper, nativescript-swisspost-* dep-confusion, log-guru / pylogora
Mythic/Poseidon C2 beacons, fflask Flask typosquat, and many smaller campaigns;
OSV MAL-2026-4789/4803/5460/5461/5515/5566/5575/5579/5580/5704/5727/5741/
5752/5790/5792/5793/5889/5890/5972/5980/6302/6325/6326/6365/6475/10091/
10550/10551/10625 through 10692),
and the July 18 2026 npm/PyPI batch: n8n-nodes-api-finder / n8n-nodes-devops-utils /
n8n-nodes-final-mile / n8n-nodes-probe malicious n8n community node cluster
(OSV MAL-2026-10774/10775/10776/10777), relativity-pdfjs-dist dep-confusion/typosquat
targeting pdfjs-dist / Relativity (OSV MAL-2026-10778), and mlflow-ui PyPI
MLflow impersonation (OSV MAL-2026-10779), the July 20 2026 npm batch
(vybscan-testbed-inert-postinstall / vybscan-testbed-obfuscated-postinstall
scanner-testbed malware GHSA-cwcf-rmgg-qg9w / GHSA-43r2-4jr2-rhjf;
@car_loans/dealerships-approval dep-confusion GHSA-p8xg-5qpp-p289;
@gocortexio/npmgremlinbox-* cluster of 80 security-simulation packages
MAL-2026-10783 through MAL-2026-10862; version updates for jscrambler 8.17.0,
svgson-lite 1.0.8, rollup-plugin-polyfill-handler 1.0.1, @vite-js/ui 7.15.10),
the Telegram bot / pyrogram stealer cluster (Oct 2025 – Feb 2026;
25 PyPI typosquats of pyrogram/telebot/requests exfiltrating session files;
OSV MAL-2025-191874 through MAL-2025-193011 and MAL-2026-42/96/236/237/325/326/
468/470/623/930/931/934/935/937), and the July 20 2026 PyPI batch
(telebot-bot-run, kimichat, kimitalk, nemopush, vantrala, neroteam-v1,
paperclip-ai; OSV MAL-2026-10863 through MAL-2026-10869).

Note: a large batch of packages initially flagged from the May 27 2026
bulk OSV disclosures were subsequently withdrawn as false positives by the
ossf/malicious-packages project (PRs #1276/#1278) — including the
fastapi / strawberry-graphql / notebook-intelligence PyPI reports, the
@tailwind-core and @onerjs npm typosquat clusters, the Baileys/WhatsApp,
Claude Code/openclaw, and local-mcp/lokal-mcp campaigns, and the bulk
edison-tools/heims/openirf/ranno PyPI batch. Those entries have been
removed. Only packages with an active (non-withdrawn) OSV MAL record, or
independent authoritative corroboration, are retained.

Author:    Jascha Wanger / Tarnover, LLC
Date:      2026-07-21
License:   MIT
Usage:     check_compromised_packages.py [path]   (defaults to cwd)
Exit code: 0 clean, 1 hit(s) found, 2 error
"""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Iterable

# ---------------------------------------------------------------------------
# Known-malicious version data. Update as advisories evolve.
#
# Data model: package name -> set of malicious version strings. An *empty
# set* is the wildcard convention: any installed version of that package is
# treated as malicious. Use it for pure-malware typosquats (where OSV's
# `affected.ranges` is `>=0`) so we still catch republished versions after
# npm/PyPI takedowns leave only a `0.0.1-security` placeholder.
# ---------------------------------------------------------------------------

# PyPI: package name (lowercased) -> set of malicious versions
PYPI_BAD: dict[str, set[str]] = {
    "durabletask": {"1.4.1", "1.4.2", "1.4.3"},
    "mistralai": {"2.4.6"},
    "guardrails-ai": {"0.10.1"},
    # PyTorch Lightning maintainer compromise (April 30 2026)
    # GHSA-w37p-236h-pfx3 / CVE-2026-44484
    "pytorch-lightning": {"2.6.2", "2.6.3"},
    # lightning: same campaign (2026-04-compr-lightning) and same maintainer compromise as
    # pytorch-lightning above; `lightning` is the renamed unified package published by
    # Lightning AI alongside `pytorch-lightning`. Both packages had versions 2.6.2 and 2.6.3
    # removed from PyPI after the attack. Specific versions only (no >=0 range in OSV record).
    # OSV MAL-2026-3201 (kam193); confirmed by Aikido aikido.dev/blog/pytorch-lightning-pypi-compromise-mini-shai-hulud
    # and Socket socket.dev/blog/lightning-pypi-package-compromised
    "lightning": {"2.6.2", "2.6.3"},
    # xinference maintainer-account compromise (April 22 2026) — 600k-download PyPI AI-inference framework
    # Three consecutive malicious versions published after account takeover; heavily obfuscated
    # base64 payload steals AWS/GCP/K8s/SSH/env credentials on import.
    # JFrog research.jfrog.com/post/xinference-compromise/
    # Mend.io mend.io/blog/malicious-xinference-pypi-teampcp-part-4/
    # OX Security ox.security/blog/xinference-allegedly-hacked-by-teampcp-malicious-package-in-pypi/
    "xinference": {"2.6.0", "2.6.1", "2.6.2"},
    # dYdX supply-chain attack (January 27 2026) — maintainer credential compromise
    # PYSEC-2026-1; Socket + TheHackerNews + Rescana + CyberPress
    "dydx-v4-client": {"1.1.5.post1"},
    # TeamPCP / Trivy CI credential-steal cascade (March 2026)
    # litellm: GHSA-5mg7-485q-xm76 (Datadog, Snyk, Sonatype, Wiz, Endor Labs, Truesec)
    "litellm": {"1.82.7", "1.82.8"},
    # telnyx: GHSA-955r-262c-33jc (Akamai, Help Net Security, Mend, Hexastrike)
    "telnyx": {"4.87.1", "4.87.2"},
    # elementary-data GitHub Actions script-injection (April 24 2026)
    # StepSecurity, Snyk, Bleeping Computer, CyberSecurityNews, Chainguard
    "elementary-data": {"0.23.3"},
    # libhmac crypto-stealer typosquat (May 26 2026)
    # Impersonates a legitimate HMAC library; exfiltrates credentials.
    # OSV MAL-2026-4194.
    "libhmac": {"0.3.0", "0.8.28.0", "0.8.28.1", "1.1.0"},
    # TrapDoor crypto-stealer campaign (May 22 2026) — fully malicious typosquats
    # OSV MAL-2026-4259, 4260, 4261, 4262, 4271, 4272, 4273
    "cryptowallet-safety": {"0.1.0"},
    "defi-risk-scanner": {"0.1.0"},
    "eth-security-auditor": {"0.1.0"},
    "solidity-build-guard": {"0.1.0"},
    "data-pipeline-check": {"0.1.0", "0.1.1"},
    "env-loader-cli": {"0.1.0", "0.1.1"},
    "git-config-sync": {"0.1.0", "0.1.1"},
    "quatres": {"3.0.1"},
    # Roblox/robase PyPI typosquat cluster (May 29 2026)
    # 52 packages impersonating Roblox API / database helper libs.
    # All confirmed by individual OSV MAL-2026-* records (active, not withdrawn).
    "api-analysis": {"0.0.8"},
    "api-feature": {"0.0.8"},
    "bloxy-api": {"3.4.0"},
    "core-roblox-utils": {"2.4.0"},
    "database-roblox": {"0.0.1"},
    "databaselooks": {"0.0.4"},
    "databasenaps": {"0.0.4", "0.0.5"},
    "databaseroboat": {"0.0.1", "0.0.2"},
    "databaseroboats": {"0.0.3", "0.0.4"},
    "databaserobooms": {"0.0.4"},
    "databaserotacos": {"0.0.4"},
    "databasesupalake": {"1.2.0"},
    "databasesupasafe": {"1.0.0", "1.2.0"},
    "databasetapes": {"0.0.4"},
    "databasetrace": {"0.0.5", "0.0.6", "0.0.7"},
    "pycolorlib001": {"0.0.1"},
    "pycolorlib3": {"0.0.4", "0.0.5"},
    "quicksolving": {"2.3.0"},
    "quicktestybesty": {"2.3.0"},
    "rblx-api": {"2.6.0"},
    "rblx-http": {"2.4.0"},
    "rblx-https": {"2.4.0"},
    "rblx-studio-api": {"2.6.0", "2.7.0", "2.8.0"},
    "ro-db": {"2.4.0"},
    "robase": {"2.1.0", "2.2.0"},
    "robase-api": {"2.4.0", "2.6.0"},
    "robase-apis": {"2.4.0"},
    "robase-app": {"2.1.0", "3.4.0"},
    "robase-dnb": {"2.4.0"},
    "robase-fallback": {"2.2.0", "2.4.0"},
    "robase-fast-install": {"2.3.0"},
    "robase-gui": {"2.3.0"},
    "robase-gui-api": {"2.3.0"},
    "robase-help": {"0.0.9"},
    "robase-install": {"2.1.0"},
    "robase-installer": {"2.2.0"},
    "robase-library-quick-install": {"2.3.0", "2.4.0", "2.5.0"},
    "robase-quick-install": {"2.6.0"},
    "robase-setup": {"2.0.0", "2.1.0", "2.2.0", "2.3.0"},
    "robase-start": {"2.4.0"},
    "robase-ui": {"2.3.0"},
    "robase-utils": {"2.3.0"},
    "roboat-addition": {"0.0.1"},
    "roboat-additions": {"0.0.1"},
    "roboat-utilities": {"2.1.0"},
    "roboat-utils": {
        "1.0.0", "2.1.0", "2.2.0", "2.3.0", "2.4.0", "2.5.0",
        "2.6.0", "2.7.0", "2.8.0", "2.9.0", "3.0.0",
    },
    "roboats-addition": {"0.0.1"},
    "rogiant": {"2.4.0"},
    "rogiant-install": {"2.5.0"},
    "rogiant-quick-install": {"2.4.0"},
    "rosolver": {"0.0.1"},
    "rostilesolver": {"2.4.0"},
    # modulebuild3240234t PyPI Roblox infostealer (May 29 2026)
    # Exfiltrates Roblox session data and credentials on import.
    # OSV MAL-2026-5029 (active, confirmed by kam193 / bad-packages.kam193.eu)
    "modulebuild3240234t": {"1.0.0", "1.0.1", "2.0.0", "3.0.0"},
    # polymarket-data PyPI crypto/credentials infostealer (May 30 2026)
    # Exfiltrates cryptocurrency-related data and API keys; establishes persistence.
    # Likely a typosquat of polymarket-data-fetcher. Specific malicious versions only.
    # OSV MAL-2026-5086 (active, confirmed by kam193 / bad-packages.kam193.eu)
    "polymarket-data": {"2.0.0", "2.0.1"},
    # crypto-helper / cryptolock / obfuscation PyPI install-time malware batch (May 30–31 2026)
    # All three tamper with security settings and download + execute a malicious executable
    # during pip install. Detected by kam193 / bad-packages.kam193.eu.
    # OSV MAL-2026-5088 (crypto-helper), MAL-2026-5089 (cryptolock), MAL-2026-5100 (obfuscation)
    # obfuscation: part of same 2026-05-cryptolock campaign; VirusTotal confirms setup.py backdoor
    # with IOC URLs pointing to seIfrighteous/x GitHub releases and tmpfiles.org executables.
    "crypto-helper": {"1.0.0"},
    "cryptolock": {"1.0.0", "1.0.1"},
    "obfuscation": {"3.23.0", "3.23.2", "3.23.3"},
    # discord-ban / discord-massban PyPI browser-credential infostealers (May 30–31 2026)
    # Both steal credentials, credit cards, and browsing history from web browsers.
    # Part of the same 2026-05-discord-ban campaign; detected by kam193 / bad-packages.kam193.eu.
    # OSV MAL-2026-5091 (discord-ban), MAL-2026-5099 (discord-massban)
    "discord-ban": {"1.0.0", "1.0.1", "1.0.2"},
    "discord-massban": {"0.1.0"},
    # neuralforge-ml PyPI env-variable exfiltrator (May 30 2026)
    # Stub package imitating a real ML library; version 0.9.9 adds obfuscated
    # exfiltration of environment variables. Detected by kam193 / bad-packages.kam193.eu.
    # OSV MAL-2026-5090
    "neuralforge-ml": {"0.9.9"},
    # h4xupdate / hell-cipher PyPI malware batch (May 31 2026)
    # h4xupdate: remote-control tool taking orders from a hardcoded Telegram bot;
    # impersonates a legitimate company. OSV MAL-2026-5093
    # hell-cipher: tampers with security settings during install and downloads + executes
    # a malicious executable. OSV MAL-2026-5094
    "h4xupdate": {"0.0.1"},
    "hell-cipher": {"1.0.1"},
    # cscc-glass-house PyPI cloud-credential exfiltrator (May 31 2026)
    # Exfiltrates credentials from cloud environments to a hardcoded location;
    # analyst notes suggest possible CTF origin but intent is clearly malicious.
    # OSV MAL-2026-5096 / https://bad-packages.kam193.eu/pypi/package/cscc-glass-house
    "cscc-glass-house": {"1.0.1", "1.0.2", "1.0.3", "1.0.4"},
    # redteam-qxz7-utils PyPI malware (June 1 2026)
    # Malicious code detected by kam193 / bad-packages.kam193.eu; single version published.
    # OSV MAL-2026-5120
    "redteam-qxz7-utils": {"1.0.0"},
    # imgmatrix-analysis PyPI remote-command executor (June 1 2026)
    # Executes remote commands during import; 10 versions published before takedown.
    # Detected by kam193 / bad-packages.kam193.eu.
    # OSV MAL-2026-5123
    "imgmatrix-analysis": {
        "0.1.0", "0.1.1", "0.1.2", "0.1.3", "0.1.4",
        "0.1.5", "0.1.6", "0.1.7", "0.1.8", "0.1.9",
    },
    # parsimonius PyPI RAT (June 2 2026)
    # Typosquat of the legitimate parsimonious PEG-parser library; all published
    # versions are clones of the real package with an injected RAT that takes orders
    # via a hardcoded Telegram bot and exfiltrates environment variables. The payload
    # is geo-filtered to skip systems whose timezone or geolocation suggests Russia.
    # Detected by kam193 / bad-packages.kam193.eu.
    # OSV MAL-2026-5151
    "parsimonius": {
        "0.10.0", "0.11.0", "0.11.1", "0.11.2", "0.11.3",
        "0.11.4", "0.11.5", "0.11.6", "0.12.0",
    },
    # quant-backtest-helpers / bt-signal-utils PyPI env-variable / cloud-token exfiltrator campaign (June 2 2026)
    # During import, exfiltrates environment variables and cloud tokens to a hardcoded
    # ngrok endpoint (disrupt-evasive-sterility.ngrok-free.app). Targets quantitative
    # finance / backtesting developers with cloud credentials in their environment.
    # Detected by kam193 / bad-packages.kam193.eu.
    # OSV MAL-2026-5152
    "quant-backtest-helpers": {"1.0.1"},
    # OSV MAL-2026-5160 — same campaign (2026-06-quant-backtest-helpers)
    "bt-signal-utils": {"1.0.0", "1.0.1"},
    # jules-test-utils PyPI host-info exfiltrator (June 2 2026)
    # Single-purpose recon package: installing or importing the module exfiltrates basic
    # information about the host. No other functionality. Detected by kam193.
    # OSV MAL-2026-5167 / https://bad-packages.kam193.eu/pypi/package/jules-test-utils
    "jules-test-utils": {"0.1.0"},
    # spaysrbdata / spaysdata PyPI Roblox-cookie infostealer campaign (June 2 2026)
    # Both packages exfiltrate Roblox session cookies from the victim machine.
    # Same campaign (2026-06-spaysrbdata); reported by kam193.
    # OSV MAL-2026-5170 / https://bad-packages.kam193.eu/pypi/package/spaysrbdata
    "spaysrbdata": {"0.1.0", "0.2.0", "0.3.0", "0.4.0", "0.5.0"},
    # OSV MAL-2026-5171 / https://bad-packages.kam193.eu/pypi/package/spaysdata
    "spaysdata": {"0.1.0", "0.2.0", "0.3.0", "0.4.0", "0.4.2", "0.4.4", "0.4.5"},
    # spadata PyPI Roblox-cookie infostealer (June 3 2026)
    # Same campaign (2026-06-spaysrbdata); exfiltrates Roblox session cookies.
    # OSV MAL-2026-5173 / https://bad-packages.kam193.eu/pypi/package/spadata
    "spadata": {"0.1.0", "0.1.1"},
    # internal-tracker PyPI host-info exfiltrator (June 3 2026)
    # Overrides setup.py install command to exfiltrate basic host info (IP, username) on install.
    # OSV MAL-2026-5176 / https://bad-packages.kam193.eu/pypi/package/internal-tracker
    "internal-tracker": {"0.0.1", "0.0.2", "0.0.5"},
    # fia-signals PyPI host-info exfiltrator (June 3 2026)
    # Overrides setup.py install command to exfiltrate basic host data (IP, username)
    # during installation; no other functionality. Detected by kam193.
    # OSV MAL-2026-5177 / https://bad-packages.kam193.eu/pypi/package/fia-signals
    "fia-signals": {"0.1.0", "0.1.3"},
    # tronlab / tronlabpy3 PyPI Tron/TRX private-key exfiltrators (June 3 2026)
    # Impersonate Tron blockchain tooling; designed for crypto private-key exfiltration,
    # sending stolen data to hardcoded mockapi.io / ngrok endpoints. Part of the
    # 2025-04-tronix campaign tracked by kam193.
    # OSV MAL-2026-5178 / https://bad-packages.kam193.eu/pypi/package/tronlab
    "tronlab": {"0.0.1"},
    # OSV MAL-2026-5181 / https://bad-packages.kam193.eu/pypi/package/tronlabpy3
    "tronlabpy3": {"0.0.1"},
    # hpe-glcp-automation-lib PyPI host-info exfiltrator (June 4 2026)
    # Overrides setup.py install command to exfiltrate basic host data (IP, username)
    # during installation; no other functionality. Impersonates an HPE GLCP automation
    # library. Detected by kam193 / bad-packages.kam193.eu.
    # OSV MAL-2026-5183
    "hpe-glcp-automation-lib": {"2.2160.0"},
    # sf-silly-goose-requests PyPI TruffleHog-based secret exfiltrator (June 4 2026)
    # Uses TruffleHog to scan the victim's environment for secrets, then exfiltrates
    # discovered credentials to a hardcoded endpoint (13.219.230.105:80/beacon).
    # Detected by kam193 / bad-packages.kam193.eu.
    # OSV MAL-2026-5184
    "sf-silly-goose-requests": {"0.1.0", "0.2.0"},
    # goodoldtoulas / goodoltoulas PyPI install-time droppers (June 5 2026)
    # Both overrides setup.py install command to download and execute a remote Windows
    # executable during pip install. Classified PROBABLY_PENTEST by kam193; active
    # OSV records, single version each published before takedown.
    # OSV MAL-2026-5271 / https://bad-packages.kam193.eu/pypi/package/goodoldtoulas
    "goodoldtoulas": {"0.1.0"},
    # OSV MAL-2026-5272 / https://bad-packages.kam193.eu/pypi/package/goodoltoulas
    "goodoltoulas": {"0.1.0"},
    # anthropy PyPI reverse-shell infostealer (June 5 2026)
    # On import the package starts a reverse shell. Categorized MALICIOUS (clearly
    # malicious intent) by kam193. Six consecutive versions published before takedown.
    # OSV MAL-2026-5273 / https://bad-packages.kam193.eu/pypi/package/anthropy
    "anthropy": {"0.0.1", "0.0.2", "0.0.3", "0.0.4", "0.0.5", "0.0.6"},
    # clip-logger PyPI clipboard-stealing crypto campaign (June 7 2026)
    # Both packages periodically monitor the clipboard for content matching patterns
    # consistent with cryptocurrency secret phrases (BIP-39 mnemonics), then
    # exfiltrate any match to a hardcoded remote endpoint. Early versions of
    # clip-logger documented this behaviour explicitly in the README.
    # Targeted data are likely cryptocurrency recovery phrases / private keys.
    # Detected and reported by kam193 / bad-packages.kam193.eu.
    # OSV MAL-2026-5293 (clip-logger), MAL-2026-5292 (bittensor-burn-watch)
    "clip-logger": {
        "1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4",
        "1.1.0", "1.1.1", "1.1.2",
    },
    "bittensor-burn-watch": {
        "1.2.0", "1.2.2", "1.2.3", "1.2.4", "1.2.5", "1.2.6", "1.2.7",
        "1.2.9", "1.2.10", "1.2.11", "1.2.12",
        "1.3.0", "1.3.1", "1.3.2", "1.3.3", "1.3.4",
    },
    # Woodpecker PyPI infostealer campaign (June 6 2026)
    # Twelve legitimate scientific / systems packages had specific versions compromised.
    # Each ships a heavily obfuscated JavaScript payload executed via Bun runtime on
    # Python startup. The payload collects API keys, PyPI/npm/GitHub credentials,
    # cryptocurrency wallet keystores, and password-manager data, then exfiltrates
    # via GitHub. It also attempts persistence and self-propagation by republishing
    # infected copies using stolen registry credentials. Described by kam193 as
    # related to the Mini Shai Hulud worm campaign.
    # Primary source: OSV (kam193/bad-packages.eu); exact versions only (no >=0 range).
    # OSV MAL-2026-5274 (dynamo-release)
    "dynamo-release": {"1.5.4"},
    # OSV MAL-2026-5275 / https://bad-packages.kam193.eu/pypi/package/napari-ufish
    "napari-ufish": {"0.0.2", "0.0.3"},
    # OSV MAL-2026-5276 / https://bad-packages.kam193.eu/pypi/campaign/2026-06-compr-woodpecker
    "nucbox": {"0.1.2", "0.1.3"},
    # OSV MAL-2026-5277
    "pantheon-toolsets": {"0.5.5", "0.5.6"},
    # OSV MAL-2026-5278
    "spateo-release": {"1.1.2"},
    # OSV MAL-2026-5279
    "uprobe": {"0.1.3", "0.1.4"},
    # Six additional Woodpecker packages confirmed June 6 2026 (same campaign)
    # OSV MAL-2026-5280
    "bramin": {"0.0.3", "0.0.4"},
    # OSV MAL-2026-5281
    "executor-http": {"0.1.3", "0.1.4"},
    # OSV MAL-2026-5282
    "mrbios": {"0.1.1", "0.1.2"},
    # OSV MAL-2026-5283
    "okite": {"0.0.7", "0.0.8"},
    # OSV MAL-2026-5284
    "synago": {"0.1.1", "0.1.2"},
    # OSV MAL-2026-5285
    "ufish": {"0.1.2", "0.1.3"},
    # Two additional Woodpecker campaign packages confirmed June 7 2026 (same campaign)
    # cmd2func: versions 0.2.2 and 0.2.3 were compromised with the same obfuscated
    #   Bun-runtime JS infostealer payload as the rest of the Woodpecker cluster.
    #   OSV MAL-2026-5290 / https://bad-packages.kam193.eu/pypi/campaign/2026-06-compr-woodpecker
    "cmd2func": {"0.2.2", "0.2.3"},
    # magique-ai: versions 0.4.4 and 0.4.5 were compromised with the same Woodpecker payload.
    #   OSV MAL-2026-5294 / https://bad-packages.kam193.eu/pypi/campaign/2026-06-compr-woodpecker
    "magique-ai": {"0.4.4", "0.4.5"},
    # Four additional Woodpecker campaign packages confirmed June 7 2026 (same campaign)
    # OSV MAL-2026-5295 / https://bad-packages.kam193.eu/pypi/campaign/2026-06-compr-woodpecker
    "coolbox": {"0.4.1", "0.4.2"},
    # OSV MAL-2026-5296
    "magique": {"0.6.8", "0.6.9"},
    # OSV MAL-2026-5298
    "executor-engine": {"0.3.4", "0.3.5"},
    # OSV MAL-2026-5299
    "pantheon-agents": {"0.6.1", "0.6.2"},
    # Woodpecker PyPI infostealer campaign continuation (June 8–9 2026)
    # Same campaign actor; additional legitimate Python packages compromised
    # with the Bun-runtime JS credential-exfiltration payload targeting API
    # keys, registry credentials, crypto wallet keystores, and password-manager
    # data, then exfiltrates via GitHub.
    # OSV MAL-2026-5300 (funcdesc), 5301 (mflux-streamlit), 5302 (nhmpy),
    # 5303 (rlask), 5304 (rsquests), 5305 (tlask), 5313 (dreamgen),
    # 5319 (mem8), 5321 (orchestr8-platform), 5345 (dstill)
    "funcdesc": {"0.2.2", "0.2.3"},
    "mflux-streamlit": {"0.0.3", "0.0.4"},
    "nhmpy": {"2.4.6", "2.4.7"},
    "rlask": {"3.1.3", "3.1.4", "3.1.5", "3.1.6", "3.1.7"},
    "rsquests": {"2.34.2", "2.34.3"},
    "tlask": {"3.1.3", "3.1.4"},
    "dreamgen": {"1.8.1"},
    "mem8": {"6.0.1"},
    "orchestr8-platform": {"3.3.2"},
    "dstill": {"0.3.0"},
    # Bioinformatics supply-chain compromise (June 8–9 2026)
    # Six legitimate phenotype-analysis and bioinformatics packages compromised
    # with a malicious payload using the same attacker technique as the
    # Woodpecker campaign. All published as specific versions before takedown.
    # OSV MAL-2026-5314 (embiggen), 5315 (ensmallen), 5316 (gpsea),
    # 5322 (phenopacket-store-toolkit), 5323 (ppkt2synergy), 5324 (pyphetools)
    "embiggen": {"0.11.97"},
    "ensmallen": {"0.8.101"},
    "gpsea": {"0.9.14"},
    "phenopacket-store-toolkit": {"0.1.7"},
    "ppkt2synergy": {"0.1.1"},
    "pyphetools": {"0.9.120"},
    # MCP-namespace PyPI typosquat cluster (June 8–9 2026)
    # Five packages impersonating popular ML libraries with an "-mcp" or
    # "-mcp-server" suffix; they silently exfiltrate environment variables
    # and credentials on import. Detected by kam193 / bad-packages.kam193.eu.
    # OSV MAL-2026-5317 (instructor-mcp), 5318 (langchain-core-mcp),
    # 5320 (openai-mcp), 5325 (ray-mcp-server), 5326 (tiktoken-mcp)
    "instructor-mcp": {"1.15.2", "1.15.3"},
    "langchain-core-mcp": {"1.4.2", "1.4.3"},
    "openai-mcp": {"2.41.1", "2.41.2"},
    "ray-mcp-server": {"0.2.1"},
    "tiktoken-mcp": {"0.13.1", "0.13.2"},
    # Solana ecosystem PyPI typosquat cluster (June 9 2026)
    # Four packages masquerading as official Solana Python SDK tooling; each
    # publishes version 1.0.0 with an install-time credential/wallet exfiltrator.
    # OSV MAL-2026-5336 (solana-cli-py), 5337 (solana-web3),
    # 5338 (solana-web3-py), 5339 (spl-token-py)
    "solana-cli-py": {"1.0.0"},
    "solana-web3": {"1.0.0"},
    "solana-web3-py": {"1.0.0"},
    "spl-token-py": {"1.0.0"},
    # Bittensor/crypto clipboard-stealer extension (June 8–27 2026)
    # Related to the clip-logger / bittensor-burn-watch campaign already tracked.
    # Multiple packages continuously published exfiltrating clipboard and env data,
    # targeting BIP-39 mnemonics, crypto wallet seeds, and Bittensor keys.
    # OSV MAL-2026-5311 (bittensor-burn-monitor), 5312 (bt-burn-watch),
    # 5329 (spaysdatarbx), 5330 (bittensor-burn-alert), 5331 (bittensor-burn),
    # 5334 (spaysrbx), 5457 (tao-subnet-metrics), 5489 (bittensor-emission-tracker),
    # 5680 (bittensor-burn-message), 5681 (trongap), 5683 (trongapy)
    "bt-burn-watch": {"1.4.0"},
    "bittensor-burn-monitor": {
        "1.5.0", "1.5.3", "1.5.5",
        "1.6.0", "1.6.3", "1.6.5",
        "1.7.0",
    },
    "spaysdatarbx": {"0.1.3", "0.1.5"},
    "bittensor-burn-alert": {"1.7.3", "1.7.4", "1.7.5"},
    "bittensor-burn": {"1.8.0", "1.8.1"},
    "spaysrbx": {"0.3.0"},
    "tao-subnet-metrics": {"1.0.1"},
    "bittensor-emission-tracker": {"1.0.1"},
    "bittensor-burn-message": {"1.0.1"},
    "trongap": {"0.0.1"},
    "trongapy": {"0.0.1"},
    # easyaillm LLM-utility PyPI typosquat cluster (June 18–23 2026)
    # Ten look-alike packages mimicking popular LLM utilities exfiltrating
    # environment variables and API keys on import. Linked by shared
    # version-numbering scheme (2.x series) and identical payload structure.
    # OSV MAL-2026-5756 (easyaillm), 5765 (easyaillm2), 5766 (easyllmai),
    # 5769 (ezllmgen), 5770 (llmgenerator), 5771 (llamagenerator),
    # 5773 (generatellm), 5776 (fastgptmini), 5795 (gptminifast), 5796 (llmfree)
    "easyaillm": {"2.0.15", "2.0.16"},
    "easyaillm2": {"2.0.16", "2.0.17", "2.0.18", "2.0.67", "2.0.68"},
    "easyllmai": {"2.1", "2.21"},
    "ezllmgen": {"2.21"},
    "llmgenerator": {"2.21"},
    "llamagenerator": {"2.22"},
    "generatellm": {"2.21", "2.22", "2.23"},
    "fastgptmini": {"2.21", "2.22", "2.23", "2.24", "2.25", "2.26"},
    "gptminifast": {"2.21"},
    "llmfree": {"2.21"},
    # Dep-confusion PyPI batches (June 8–27 2026)
    # Packages published at inflated version numbers targeting private CI
    # pipelines; no legitimate public release history at these versions.
    # OSV MAL-2026-5333 (nerfstudio-gs), 5519 (requests-toolbelt-plus),
    # 5532 (icinga), 5868 (datacamp-light)
    "nerfstudio-gs": {"99.0.0", "99.0.1", "99.0.2", "99.0.3"},
    "requests-toolbelt-plus": {"99.9.9", "99.9.10", "100.0.0"},
    "icinga": {"99.1.0", "99.2.0"},
    "datacamp-light": {"99.0.0"},
    # Malicious install-time infostealer / credential-grabber batch (June 27–28 2026)
    # discord-token-generator: token-harvesting tool with C2 exfiltration.
    # fsociety-tools: reverse-shell / credential-stealer named after Mr. Robot persona.
    # tdata-grabber: Telegram session-data exfiltrator targeting .tdata directories.
    # skillspector: env-var and credential exfiltrator using split versioning (0.0.x / 2.3.x).
    # pkg-fallback: generic name dep-confusion dropper, any version.
    # OSV MAL-2026-6549 (discord-token-generator), MAL-2026-6558 (fsociety-tools),
    # MAL-2026-6560 (tdata-grabber), MAL-2026-6561 (skillspector), MAL-2026-6557 (pkg-fallback)
    "discord-token-generator": {"1.0.0", "1.0.1", "1.0.2", "1.0.3"},
    "fsociety-tools": {"1.0.0", "1.0.1", "1.0.2"},
    "tdata-grabber": {"1.0.0"},
    "skillspector": {"0.0.1", "0.0.2", "0.0.3", "0.0.4", "2.3.7", "2.3.8", "2.3.9", "2.3.10"},
    "pkg-fallback": set(),
    # Miscellaneous PyPI malware batch (June 29 2026)
    # sqligen: SQL-helper package with obfuscated credential-exfiltration postinstall;
    #   any version is malicious (ranges: introduced 0). OSV MAL-2026-6515.
    # inlifegram: Instagram-API wrapper with data-exfiltration payload;
    #   any version is malicious (ranges: introduced 0). OSV MAL-2026-6516.
    # pdf-converter-pro: PDF conversion tool with malicious postinstall dropper;
    #   any version is malicious (ranges: introduced 0). OSV MAL-2026-6541.
    # django-bkvision: Django vision module with malicious install-time payload;
    #   only version 1.2.0 was published. OSV MAL-2026-6593.
    "sqligen": set(),
    "inlifegram": set(),
    "pdf-converter-pro": set(),
    "django-bkvision": {"1.2.0"},
    # twrap-tool PyPI malware (July 1 2026)
    # Install-time credential-exfiltration dropper; single version published before takedown.
    # OSV MAL-2026-6711.
    "twrap-tool": {"1.0.0"},
    # starlette-healthcheck PyPI malware (July 1 2026)
    # Typosquat of starlette-healthcheck ASGI extension; three consecutive malicious versions.
    # OSV MAL-2026-6724.
    "starlette-healthcheck": {"1.2.0", "1.3.0", "1.3.1"},
    # dt-validator PyPI remote-code-executor (July 2 2026)
    # Contains a function to execute remote code; single version 0.3.0 published before takedown.
    # Detected by kam193 / bad-packages.kam193.eu.
    # OSV MAL-2026-6728
    "dt-validator": {"0.3.0"},
    # Unreal Engine / Epic Games dep-confusion PyPI cluster (July 2 2026)
    # Four packages published at version 99999.0.0 impersonating Unreal Engine and Epic
    # Games internal Python tooling; installing or importing exfiltrates host information.
    # All detected by kam193 / bad-packages.kam193.eu. No >=0 range in OSV records — pin version.
    # OSV MAL-2026-6733 (epic-build-scripts), MAL-2026-6734 (horde-python-client),
    # MAL-2026-6735 (ue-python-tools), MAL-2026-6736 (unreal-mladapter)
    "epic-build-scripts": {"99999.0.0"},
    "horde-python-client": {"99999.0.0"},
    "ue-python-tools": {"99999.0.0"},
    "unreal-mladapter": {"99999.0.0"},
    # haproxy-config-client / ipa-user-collector PyPI downloader campaign (July 4 2026)
    # Both packages use obfuscated install-time code to download a malicious executable
    # (VirusTotal hash d47a2d1b96df84b10263a99866b865421b334448432d1b447b82c76253bcbe86).
    # Detected by kam193 / bad-packages.kam193.eu.
    # OSV MAL-2026-6748 (haproxy-config-client), MAL-2026-6749 (ipa-user-collector)
    "haproxy-config-client": {"8.5.3"},
    "ipa-user-collector": {"8.5.3"},
    # procwire PyPI campaign (July 4 2026)
    # Multi-package campaign sharing a common VirusTotal-confirmed dropper payload.
    # procwire: the trigger package; 4 malicious versions published. OSV MAL-2026-6750.
    # bytekit: same campaign; 2 malicious versions. OSV MAL-2026-6751.
    # confighub: depends on malicious procwire; 2 versions. OSV MAL-2026-6752.
    # schemavault: same campaign payload; 2 malicious versions. OSV MAL-2026-6753.
    # All detected by kam193 / bad-packages.kam193.eu.
    "procwire": {"5.2.3", "5.2.5", "5.2.6", "5.2.7"},
    "bytekit": {"3.4.1", "3.4.2"},
    "confighub": {"7.0.1", "7.0.2"},
    "schemavault": {"4.1.0", "4.1.1"},
    # yt-api-dlp PyPI crypto-stealer typosquat (July 4 2026)
    # Impersonates a YouTube downloader / yt-dlp wrapper; install-time payload exfiltrates
    # data to a Polygon blockchain smart contract address and VirusTotal-confirmed C2.
    # References a malicious GitHub commit (DreyCode2/youtube-downloader).
    # OSV MAL-2026-6754.
    "yt-api-dlp": {"0.1.0", "0.1.1"},
    # httpprobe PyPI malware (July 4 2026)
    # Single version published before takedown; malicious code detected by kam193.
    # OSV MAL-2026-6758 / https://bad-packages.kam193.eu/pypi/package/httpprobe
    "httpprobe": {"1.0.0"},
    # urlllib321 PyPI typosquat (July 5 2026)
    # Typosquat of the widely-used urllib3 library (urlllib321 vs urllib3);
    # two versions published with malicious code; detected by kam193.
    # OSV MAL-2026-6759 / https://bad-packages.kam193.eu/pypi/package/urlllib321
    "urlllib321": {"2.7.0", "2.7.1"},
    # Paysafe financial API credential-stealer cluster (July 7-8 2026)
    # Four packages impersonating Paysafe payment-processing API clients;
    # each exfiltrates credentials on import. OSV MAL-2026-6926 (paysafe-api),
    # MAL-2026-6927 (paysafe-kyc), MAL-2026-6928 (paysafe-payments),
    # MAL-2026-6929 (paysafe-sdk)
    "paysafe-api": {"1.0.0"},
    "paysafe-kyc": {"1.0.0"},
    "paysafe-payments": {"1.0.0"},
    "paysafe-sdk": {"1.0.0"},
    # jsonschema typosquat cluster (July 7-8 2026)
    # Two packages impersonating jsonschema with inflated version numbers.
    # OSV MAL-2026-6945 (jsonschemavalidation), MAL-2026-6970 (jsonschemavalid)
    "jsonschemavalidation": {"4.26.0"},
    "jsonschemavalid": {"4.26.0"},
    # PyQt6 dark-theme typosquat (July 7-8 2026, OSV MAL-2026-6960)
    "pyqt6darktheme": {"0.1.0"},
    # Waymo dep-confusion (July 7-8 2026, OSV MAL-2026-6961)
    # High-version shadow package targeting Waymo's internal CI.
    "waymo-waymax": {"99.0.0"},
    # Tron/TRX private-key exfiltrator cluster (July 7-8 2026)
    # Four new packages extending the tronlab / tronlabpy3 campaign (June 3 2026);
    # all exfiltrate TRX wallet private keys to mockapi.io/ngrok endpoints.
    # OSV MAL-2026-6971 (tronhap), MAL-2026-6974 (tronhapy),
    # MAL-2026-6983 (tronpak), MAL-2026-7025 (tronsev)
    "tronhap": {"0.0.1"},
    "tronhapy": {"0.0.1"},
    "tronpak": {"0.0.1"},
    "tronsev": {"0.0.1"},
    # py-slugify typosquat (July 7-8 2026, OSV MAL-2026-6976)
    # Impersonates the legitimate python-slugify package.
    "py-slugify": {"0.8.2"},
    # Miscellaneous PyPI malware batch (July 7-8 2026)
    # OSV MAL-2026-6975 (oxntime), MAL-2026-6977 (rarcore),
    # MAL-2026-6978 (manin), MAL-2026-6979 (turbod),
    # MAL-2026-7006 (manik), MAL-2026-7007 (manom),
    # MAL-2026-7015 (turbom), MAL-2026-7023 (dbzy-tools)
    "oxntime": {"0.0.1", "0.0.1.post1", "0.0.2", "0.0.3"},
    "rarcore": {"0.1.1", "0.1.2"},
    "manin": {"0.0.1", "0.1.0", "0.1.1"},
    "turbod": {
        "1.0.0", "1.0.1", "1.0.2", "1.0.3",
        "1.0.4", "1.0.5", "1.0.6", "1.0.7",
    },
    "manik": {"1.2.1"},
    "manom": {"1.2.2"},
    "turbom": {"1.0.0", "1.0.1"},
    "dbzy-tools": {"1.0.1"},
    # moonbit-* PyPI malware cluster (July 9 2026)
    # Three packages impersonating MoonBit language tooling; all contain
    # malicious code per a linked wechat-editor-studio PR diff.
    # Detected by kam193 / bad-packages.kam193.eu.
    # OSV MAL-2026-2945 (moonbit-locale-compat), MAL-2026-2946 (moonbit-metrics-validator),
    # MAL-2026-2947 (moonbit-schema-utils)
    "moonbit-locale-compat": {"0.2.1", "0.2.3", "0.2.4"},
    "moonbit-metrics-validator": {"1.0.0"},
    "moonbit-schema-utils": {"1.1.0", "1.1.1"},
    # playwrightr PyPI malware (July 9 2026)
    # Typosquat of the Playwright browser-automation library; malicious payload
    # confirmed by Triage (tria.ge) and VirusTotal hash analysis.
    # OSV MAL-2026-10020.
    "playwrightr": {"1.0.0", "1.0.1"},
    # telegramlite / telegram-lite-grabber PyPI credential-stealer campaign (July 9 2026)
    # telegramlite: installs a Telegram session grabber; two malicious versions.
    # telegram-lite-grabber: single-version companion package in the same campaign.
    # Detected by kam193 / bad-packages.kam193.eu.
    # OSV MAL-2026-5531 (telegramlite), MAL-2026-6051 (telegram-lite-grabber)
    "telegramlite": {"1.0.0", "1.0.1"},
    "telegram-lite-grabber": {"1.0.0"},
    # d0rk3r PyPI malware (July 9 2026)
    # Five published versions with malicious code; detected by kam193.
    # OSV MAL-2026-6246.
    "d0rk3r": {"1.0.0", "1.0.2", "1.0.3", "1.0.4", "1.0.5"},
    # nagios-xi PyPI dep-confusion (July 9 2026)
    # Two high-version packages targeting Nagios XI internal Python tooling.
    # Detected by kam193 / bad-packages.kam193.eu.
    # OSV MAL-2026-5698.
    "nagios-xi": {"19.4.0", "19.5.0"},
    # security-alerts-sdk PyPI malware (July 9 2026)
    # Four malicious versions; detected by kam193 / bad-packages.kam193.eu.
    # OSV MAL-2026-6327.
    "security-alerts-sdk": {"1.0.0", "1.0.1", "1.0.2", "1.0.3"},
    # sufiagent / pwn-control / web3-py-checksum PyPI malware batch (July 9 2026)
    # sufiagent: three versions with malicious payload. OSV MAL-2026-3370.
    # pwn-control: single version; detected by kam193. OSV MAL-2026-3248.
    # web3-py-checksum: two versions impersonating web3 checksum utilities. OSV MAL-2026-3411.
    "sufiagent": {"1.0.0", "1.0.1", "1.0.2"},
    "pwn-control": {"1.0"},
    "web3-py-checksum": {"1.0", "1.1"},
    # DeFi/crypto credential-stealing PyPI campaign (July 12 2026)
    # data-harvester, defi-tools, py-base58, and solidity-dev share the same
    # VirusTotal-confirmed dropper payload (hash 4dd018d84f2f9c35caed7a2c684cff2c1ea3af3a113cceb078a0788eefb93f66).
    # eth-agent, jupiter-sdk, and metemask-sdk are additional packages in the
    # same campaign targeting DeFi/crypto developers; all exfiltrate credentials
    # and API keys on import. Detected by kam193 / bad-packages.kam193.eu.
    # OSV MAL-2026-10191 (data-harvester), MAL-2026-10192 (defi-tools),
    # MAL-2026-10193 (py-base58), MAL-2026-10194 (solidity-dev),
    # MAL-2026-10195 (eth-agent), MAL-2026-10196 (jupiter-sdk),
    # MAL-2026-10197 (metemask-sdk)
    "data-harvester": {"0.3.1"},
    "defi-tools": {"0.8.0"},
    "py-base58": {"2.1.3", "2.1.4"},
    "solidity-dev": {"1.3.0"},
    "eth-agent": {"1.0.0", "1.0.1"},
    "jupiter-sdk": {"0.1.0", "0.1.1"},
    "metemask-sdk": {"1.2.0", "1.2.1"},
    # proxy-check-i PyPI malware (July 9–12 2026)
    # Two malicious versions published; detected by kam193 / bad-packages.kam193.eu.
    # OSV MAL-2026-10100
    "proxy-check-i": {"0.1.0", "0.1.1"},
    # pipspeed PyPI malware (July 12–13 2026)
    # Single malicious version; detected by kam193 / bad-packages.kam193.eu.
    # OSV MAL-2026-10213
    "pipspeed": {"0.1.0"},
    # fast-dotenv PyPI malware (July 12 2026)
    # dotenv-wrapper with malicious install-time payload; references
    # gist.github.com/opensource-crypto C2 infrastructure.
    # OSV MAL-2026-10215
    "fast-dotenv": {"1.0.0"},
    # turbocalcng PyPI malware (July 14 2026)
    # Credential-exfiltrating calculator tool typosquat; two published versions.
    # OSV MAL-2026-10441
    "turbocalcng": {"0.1.0", "0.2.0"},
    # browser-use-headless PyPI malware (July 13 2026)
    # Headless browser wrapper with malicious postinstall payload.
    # OSV MAL-2026-10484
    "browser-use-headless": {"0.1.4"},
    # pokee-data-utils PyPI malware (July 14 2026)
    # Single malicious version detected by OpenSSF Package Analysis.
    # OSV MAL-2026-10547
    "pokee-data-utils": {"1.0.1"},
    # tennacity PyPI malware (July 14 2026)
    # Three malicious versions; detected by OpenSSF Package Analysis.
    # OSV MAL-2026-10576
    "tennacity": {"1.0.0", "1.2.0", "1.2.2"},
    # proxy-check-ii PyPI malware (July 14 2026)
    # Single malicious version; companion to proxy-check-i (MAL-2026-10100).
    # OSV MAL-2026-10610
    "proxy-check-ii": {"0.1.0"},
    # cosmos-cuda / cosmos-gradio PyPI dep-confusion cluster (July 14 2026)
    # Two packages published at inflated version 9999.x targeting Cosmos/AI CI
    # pipelines; contain credential-exfiltration payloads. Detected by OpenSSF.
    # OSV MAL-2026-10617 (cosmos-cuda), MAL-2026-10618 (cosmos-gradio)
    "cosmos-cuda": {"9999.0.0", "9999.0.1"},
    "cosmos-gradio": {"9999.0.0", "9999.0.1"},
    # tronwe PyPI Tron private-key exfiltrator (July 14 2026)
    # Extension of the tronlab/tronlabpy3/tronhap/tronhapy/tronpak/tronsev campaign
    # (June 3 – July 8 2026); exfiltrates TRX wallet private keys to a hardcoded
    # mockapi.io / ngrok endpoint. Single version published before takedown.
    # OSV MAL-2026-10624
    "tronwe": {"0.0.1"},

    # July 15 2026 PyPI malware batch: Flask typosquat, C2 beacons, binary droppers,
    # and credential-exfiltration packages across diverse ecosystems.
    # fflask: Flask typosquat infostealer (MAL-2025-923; GHSA record)
    "fflask": {"3.1.8.dev0", "3.1.9.dev0", "3.2.0.dev0"},
    # qlinforge: Downloads opaque Linux binary from attacker IP (MAL-2026-10091)
    "qlinforge": {"0.3.2"},
    # data-proxy-for-test: Impersonates legitimate package, credential exfil (MAL-2026-10642)
    "data-proxy-for-test": {"0.1.1"},
    # ethereum-input-decorder: Typosquat of ethereum-input-decoder, payload on import (MAL-2026-10643)
    "ethereum-input-decorder": {"1.2.2", "1.2.4"},
    # proxy-checker-j: Bundles and runs rogue sshd binary (MAL-2026-10644)
    "proxy-checker-j": {"0.1.0"},
    # northstart-sdk: Executes attacker-controlled code on import (MAL-2026-10672)
    "northstart-sdk": {"0.1.0", "0.2.0", "0.2.1", "0.2.2"},
    # xyq-drama-skill: Downloads opaque binary from Volcano Engine tos-cn-beijing (MAL-2026-10681)
    "xyq-drama-skill": {"0.1.0", "0.2.0", "0.3.0"},
    # trongridweb: Tron / TRX private-key exfiltrator (MAL-2026-10685)
    "trongridweb": {"0.0.1"},
    # log-guru / pylogora: Mythic/Poseidon C2 framework beacon, same C2 domain (MAL-2026-10688/10689)
    "log-guru": {"0.7.8"},
    "pylogora": {"0.7.8"},
    # qwen-asr-pvt: Pulls in malicious transitive dep transformers4576 (MAL-2026-10690)
    "qwen-asr-pvt": {"0.0.6"},

    # July 16 2026 PyPI malware batch: Discord-themed remote-execution droppers,
    # AI-agent C2 beacons, Airflow/captcha/encoder typosquats, and credential exfiltrators.
    # discord-telemetry: downloads and executes remote binary on install (MAL-2026-10701)
    "discord-telemetry": {"0.1.0", "0.1.1", "0.1.2", "0.1.3", "0.1.4", "0.1.5"},
    # discordia-telemetria: same remote-execution dropper campaign as discord-telemetry (MAL-2026-10702)
    "discordia-telemetria": {"0.1.1", "0.1.2"},
    # a3s-code: loads attacker-controlled native binary on first import (MAL-2026-10753)
    "a3s-code": {"5.2.8", "5.3.3"},
    # airflow-provider-spirit: Airflow provider typosquat; exfiltrates env/creds at runtime (MAL-2026-10754)
    "airflow-provider-spirit": {"0.0.1"},
    # captcha-solve-api: downloads and executes remote payload under guise of CAPTCHA client (MAL-2026-10755)
    "captcha-solve-api": {"0.0.1"},
    # darkglitch: persistent WebSocket C2 beacon (MAL-2026-10756)
    "darkglitch": {"1.2.0"},
    # dde-common: advertises as 'base types and interfaces'; exfiltrates environment on import (MAL-2026-10757)
    "dde-common": {"0.0.1"},
    # mfq-private-encoder: fetches and executes remote payload via guise of a source encoder (MAL-2026-10758)
    "mfq-private-encoder": {"1.0.0"},
    # ryry-cli: long-lived WebSocket agent beaconing to hardcoded attacker endpoint (MAL-2026-10759)
    "ryry-cli": {"6.26", "6.28"},
    # abseil-py: typosquat of absl-py (Google Abseil); exfiltrates host info on import/install (MAL-2026-10760)
    "abseil-py": {"0.1.0"},

    # Tron/TRX private-key typosquats impersonating TronGrid developer APIs (July 17–18 2026)
    "trongridev": {"0.0.1"},    # MAL-2026-10768 GHSA-hx6g-6877-qvg8
    "trongridme": {"0.0.1"},    # MAL-2026-10771 GHSA-4fhx-73c8-xxhv
    # govpkg: generic malware with remote-execution payload (July 17–18 2026)
    "govpkg": {"0.1.0", "0.2.0"},   # MAL-2026-10770
    # mlflow-ui: PyPI typosquat / impersonation of mlflow (July 18 2026)
    "mlflow-ui": {"2.7.1", "2.7.2", "2.7.3"},   # MAL-2026-10779
    # data-parser-utils: generic data-exfiltration malware (July 19 2026)
    "data-parser-utils": {"2.4.1"},              # MAL-2026-10780

    # Telegram bot / pyrogram stealer cluster (Oct 2025 – Feb 2026)
    # Typosquats of pyrogram, telethon, telebot, requests, and colorama;
    # exfiltrate Discord tokens or Telegram session files via bot callbacks.
    # Active OSV records confirmed non-withdrawn in bulk export (July 20 2026).
    "speed-testing-nt": {"0.2"},           # MAL-2025-191874
    "speed-testing-vps": {"0.2"},          # MAL-2025-191875
    "speedd-testing-bot": {"0.2"},         # MAL-2025-191876
    "rendom": {"0.2"},                     # MAL-2025-192323
    "telebot-bot": {"0.2"},                # MAL-2025-192942
    "telegrem": {"0.2"},                   # MAL-2025-192943
    "pyrogrem": {"0.2"},                   # MAL-2025-192991
    "aiogrem": {"0.2"},                    # MAL-2025-193007
    "telegreph": {"0.2", "0.3"},           # MAL-2025-193008
    "pyrogrqm": {"0.3"},                   # MAL-2025-193010
    "requeses": {"1.0.0"},                 # MAL-2025-193011
    "graponater": {"1.0.0"},               # MAL-2026-236
    "formater": {"1.0.0", "1.0.1"},        # MAL-2026-237
    "marshel": {"0.3"},                    # MAL-2026-325
    "urlssser": {"0.1", "0.2"},            # MAL-2026-326
    "pyrogrom": {"0.3"},                   # MAL-2026-42
    "urlsser": {"0.2"},                    # MAL-2026-468
    "urlsssser": {"0.2"},                  # MAL-2026-470
    "marshl": {"0.3"},                     # MAL-2026-623
    "telebot-info": {"0.3", "0.4"},        # MAL-2026-930
    "telebot-infe": {"0.3"},               # MAL-2026-931
    "telebot-infoe": {"0.3"},              # MAL-2026-934
    "telebot-infoo": {"0.3"},              # MAL-2026-935
    "telebot-infee": {"0.3"},              # MAL-2026-937
    "pycolorom": {"1.0.1"},                # MAL-2026-96

    # PyPI malware batch (July 20 2026)
    # Diverse cluster: Kimi AI impostors, generic droppers, and multi-version
    # infostealers. All confirmed active in OSV bulk export (no withdrawn field).
    "telebot-bot-run": {"0.3", "0.4", "0.5"},          # MAL-2026-10863
    "kimichat": {"0.1.0", "0.1.1"},                    # MAL-2026-10864
    "kimitalk": {"0.1.0", "0.1.1", "0.1.2"},           # MAL-2026-10865
    "nemopush": {"0.1.0", "0.1.1", "0.1.2", "0.1.3"},  # MAL-2026-10866
    "vantrala": {"0.1.1"},                             # MAL-2026-10867
    "neroteam-v1": {                                   # MAL-2026-10868
        "1.0.0", "1.0.1", "1.0.2", "1.0.3",
        "1.0.4", "1.0.5", "1.0.6", "1.0.7",
    },
    "paperclip-ai": {"0.1.0", "0.1.1"},                # MAL-2026-10869
}

# npm: exact package name -> set of malicious versions.
# @tanstack/* list per GHSA-g7cv-rxg3-hmpx (TanStack supply-chain compromise).
NPM_BAD: dict[str, set[str]] = {
    "@tanstack/arktype-adapter": {"1.166.12", "1.166.15"},
    "@tanstack/eslint-plugin-router": {"1.161.9", "1.161.12"},
    "@tanstack/eslint-plugin-start": {"0.0.4", "0.0.7"},
    "@tanstack/history": {"1.161.9", "1.161.12"},
    "@tanstack/nitro-v2-vite-plugin": {"1.154.12", "1.154.15"},
    "@tanstack/react-router": {"1.169.5", "1.169.8"},
    "@tanstack/react-router-devtools": {"1.166.16", "1.166.19"},
    "@tanstack/react-router-ssr-query": {"1.166.15", "1.166.18"},
    "@tanstack/react-start": {"1.167.68", "1.167.71"},
    "@tanstack/react-start-client": {"1.166.51", "1.166.54"},
    "@tanstack/react-start-rsc": {"0.0.47", "0.0.50"},
    "@tanstack/react-start-server": {"1.166.55", "1.166.58"},
    "@tanstack/router-cli": {"1.166.46", "1.166.49"},
    "@tanstack/router-core": {"1.169.5", "1.169.8"},
    "@tanstack/router-devtools": {"1.166.16", "1.166.19"},
    "@tanstack/router-devtools-core": {"1.167.6", "1.167.9"},
    "@tanstack/router-generator": {"1.166.45", "1.166.48"},
    "@tanstack/router-plugin": {"1.167.38", "1.167.41"},
    "@tanstack/router-ssr-query-core": {"1.168.3", "1.168.6"},
    "@tanstack/router-utils": {"1.161.11", "1.161.14"},
    "@tanstack/router-vite-plugin": {"1.166.53", "1.166.56"},
    "@tanstack/solid-router": {"1.169.5", "1.169.8"},
    "@tanstack/solid-router-devtools": {"1.166.16", "1.166.19", "1.167.0"},
    "@tanstack/solid-router-ssr-query": {"1.166.15", "1.166.18"},
    "@tanstack/solid-start": {"1.167.65", "1.167.68"},
    "@tanstack/solid-start-client": {"1.166.50", "1.166.53"},
    "@tanstack/solid-start-server": {"1.166.54", "1.166.57"},
    "@tanstack/start-client-core": {"1.168.5", "1.168.8"},
    "@tanstack/start-fn-stubs": {"1.161.9", "1.161.12"},
    "@tanstack/start-plugin-core": {"1.169.23", "1.169.26"},
    "@tanstack/start-server-core": {"1.167.33", "1.167.36"},
    "@tanstack/start-static-server-functions": {"1.166.44", "1.166.47"},
    "@tanstack/start-storage-context": {"1.166.38", "1.166.41", "1.167.4"},
    "@tanstack/valibot-adapter": {"1.166.12", "1.166.15"},
    "@tanstack/virtual-file-routes": {"1.161.10", "1.161.13"},
    "@tanstack/vue-router": {"1.169.5", "1.169.8"},
    "@tanstack/vue-router-devtools": {"1.166.16", "1.166.19"},
    "@tanstack/vue-router-ssr-query": {"1.166.15", "1.166.18"},
    "@tanstack/vue-start": {"1.167.61", "1.167.64"},
    "@tanstack/vue-start-client": {"1.166.46", "1.166.49"},
    "@tanstack/vue-start-server": {"1.166.50", "1.166.53"},
    "@tanstack/zod-adapter": {"1.166.12", "1.166.15"},
    # April 2026 @cap-js / mbt wave
    "@cap-js/sqlite": {"2.2.2"},
    "@cap-js/postgres": {"2.2.2"},
    "@cap-js/db-service": {"2.10.1"},
    "mbt": {"1.2.48"},
    # @mistralai (May 2026 wave)
    # Caveat: per Corgea research, the @mistralai/* and @uipath/* payloads
    # contain a bug that renders the malware non-functional. These versions
    # should still be treated as compromised (remove and rotate credentials),
    # but the realised impact differs from the working @tanstack/* payloads.
    "@mistralai/mistralai": {"2.2.2", "2.2.3", "2.2.4"},
    "@mistralai/mistralai-gcp": {"1.7.1", "1.7.2", "1.7.3"},
    "@mistralai/mistralai-azure": {"1.7.1", "1.7.2", "1.7.3"},
    # @opensearch-project (May 2026 wave)
    "@opensearch-project/opensearch": {"3.5.3", "3.6.2", "3.7.0", "3.8.0"},
    # @uipath (May 2026 wave, 66 packages)
    "@uipath/access-policy-sdk": {"0.3.1"},
    "@uipath/access-policy-tool": {"0.3.1"},
    "@uipath/admin-tool": {"0.1.1"},
    "@uipath/agent-sdk": {"1.0.2"},
    "@uipath/agent-tool": {"1.0.1"},
    "@uipath/agent.sdk": {"0.0.18"},
    "@uipath/aops-policy-tool": {"0.3.1"},
    "@uipath/ap-chat": {"1.5.7"},
    "@uipath/api-workflow-tool": {"1.0.1"},
    "@uipath/apollo-core": {"5.9.2"},
    "@uipath/apollo-react": {"4.24.5"},
    "@uipath/apollo-wind": {"2.16.2"},
    "@uipath/auth": {"1.0.1"},
    "@uipath/case-tool": {"1.0.1"},
    "@uipath/cli": {"1.0.1"},
    "@uipath/codedagent-tool": {"1.0.1"},
    "@uipath/codedagents-tool": {"0.1.12"},
    "@uipath/codedapp-tool": {"1.0.1"},
    "@uipath/common": {"1.0.1"},
    "@uipath/context-grounding-tool": {"0.1.1"},
    "@uipath/data-fabric-tool": {"1.0.2"},
    "@uipath/docsai-tool": {"1.0.1"},
    "@uipath/filesystem": {"1.0.1"},
    "@uipath/flow-tool": {"1.0.2"},
    "@uipath/functions-tool": {"1.0.1"},
    "@uipath/gov-tool": {"0.3.1"},
    "@uipath/identity-tool": {"0.1.1"},
    "@uipath/insights-sdk": {"1.0.1"},
    "@uipath/insights-tool": {"1.0.1"},
    "@uipath/integrationservice-sdk": {"1.0.2"},
    "@uipath/integrationservice-tool": {"1.0.2"},
    "@uipath/llmgw-tool": {"1.0.1"},
    "@uipath/maestro-sdk": {"1.0.1"},
    "@uipath/maestro-tool": {"1.0.1"},
    "@uipath/orchestrator-tool": {"1.0.1"},
    "@uipath/packager-tool-apiworkflow": {"0.0.19"},
    "@uipath/packager-tool-bpmn": {"0.0.9"},
    "@uipath/packager-tool-case": {"0.0.9"},
    "@uipath/packager-tool-connector": {"0.0.19"},
    "@uipath/packager-tool-flow": {"0.0.19"},
    "@uipath/packager-tool-functions": {"0.1.1"},
    "@uipath/packager-tool-webapp": {"1.0.6"},
    "@uipath/packager-tool-workflowcompiler": {"0.0.16"},
    "@uipath/packager-tool-workflowcompiler-browser": {"0.0.34"},
    "@uipath/platform-tool": {"1.0.1"},
    "@uipath/project-packager": {"1.1.16"},
    "@uipath/resource-tool": {"1.0.1"},
    "@uipath/resourcecatalog-tool": {"0.1.1"},
    "@uipath/resources-tool": {"0.1.11"},
    "@uipath/robot": {"1.3.4"},
    "@uipath/rpa-legacy-tool": {"1.0.1"},
    "@uipath/rpa-tool": {"0.9.5"},
    "@uipath/solution-packager": {"0.0.35"},
    "@uipath/solution-tool": {"1.0.1"},
    "@uipath/solutionpackager-sdk": {"1.0.11"},
    "@uipath/solutionpackager-tool-core": {"0.0.34"},
    "@uipath/tasks-tool": {"1.0.1"},
    "@uipath/telemetry": {"0.0.7"},
    "@uipath/test-manager-tool": {"1.0.2"},
    "@uipath/tool-workflowcompiler": {"0.0.12"},
    "@uipath/traces-tool": {"1.0.1"},
    "@uipath/ui-widgets-multi-file-upload": {"1.0.1"},
    "@uipath/uipath-python-bridge": {"1.0.1"},
    "@uipath/vertical-solutions-tool": {"1.0.1"},
    "@uipath/vss": {"0.1.6"},
    "@uipath/widget.sdk": {"1.2.3"},
    # September 8 2025 Qix phishing attack — chalk / debug / color ecosystem
    # A single npm maintainer (Qix-) was phished via a fake npmjs.help 2FA-reset
    # email; attacker published malicious versions of 19 widely-used packages
    # within 16 minutes of account takeover. Malicious code is a browser-based
    # interceptor that silently rewrites crypto-wallet addresses in fetch/XHR
    # and window.ethereum payloads. Versions were live for ~2.5 hours before
    # the maintainer revoked access and re-published clean versions.
    # Collectively these packages see >2 billion weekly npm downloads.
    # Each entry has an individual GHSA/CVE record; versions confirmed as exact
    # pins by maintainer postmortems and multiple independent vendor writeups
    # (StepSecurity, Upwind, Wiz, Bleeping Computer, Checkmarx, OX Security).
    "chalk": {"5.6.1"},            # GHSA-2v46-p5h4-248w
    "debug": {"4.4.2"},            # GHSA-4x49-vf9v-38px / CVE-2025-59144
    "color": {"5.0.1"},            # GHSA-qrmh-qg46-72pp / CVE-2025-59143
    "color-name": {"2.0.1"},       # GHSA-5fvm-p68v-5wmh / CVE-2025-59145
    "color-convert": {"3.1.1"},    # GHSA-pxx3-g568-hxr4 / CVE-2025-59162
    "color-string": {"2.1.1"},     # GHSA-286p-vc9p-p5qv
    "error-ex": {"1.3.3"},         # GHSA-6jp5-hh4c-8c5h / CVE-2025-59330
    "ansi-regex": {"6.2.1"},       # GHSA-jvhh-2m83-6w29
    "strip-ansi": {"7.1.1"},       # GHSA-vfjc-p7x3-q864
    "ansi-styles": {"6.2.2"},      # GHSA-p5rr-crjh-x7gr
    "wrap-ansi": {"9.0.1"},        # GHSA-2rv4-jp6r-xgq7
    "backslash": {"0.2.1"},        # GHSA-53mq-f4w3-f7qv
    "is-arrayish": {"0.3.3"},      # GHSA-frh7-2f84-v9mw / CVE-2025-59331
    "simple-swizzle": {"0.2.3"},   # GHSA-9g9j-rggx-7fmg / CVE-2025-59141
    "supports-color": {"10.2.1"},  # GHSA-pj3j-3w3f-j752
    "slice-ansi": {"7.1.1"},       # GHSA-9xjj-cmqc-578p
    # StepSecurity + Bleeping Computer + Checkmarx + OX Security all confirm
    # the same version list for has-ansi, chalk-template, and supports-hyperlinks:
    "has-ansi": {"6.0.1"},
    "chalk-template": {"1.1.1"},
    "supports-hyperlinks": {"4.1.1"},
    # September 15 2025 Shai-Hulud worm — @ctrl/tinycolor and ngx-bootstrap wave
    # A separate account takeover (different maintainer) using an identical
    # postinstall bundle.js that harvests npm/GitHub tokens and cloud credentials,
    # then self-propagates by republishing infected versions using stolen credentials.
    # The campaign ultimately spread to 194 packages (582 compromised versions),
    # though only the original entry points are pinned here.
    # @ctrl/tinycolor: OSV MAL-2025-47141; Snyk + Endor Labs (independent sources)
    # ngx-bootstrap: GHSA-6m4g-vm7c-f8w6 / OSV MAL-2025-47197;
    #               Snyk blog + valor-software/ngx-bootstrap#6776 (maintainer issue)
    "@ctrl/tinycolor": {"4.1.1", "4.1.2"},
    "ngx-bootstrap": {"18.1.4", "19.0.3", "19.0.4",
                       "20.0.3", "20.0.4", "20.0.5", "20.0.6"},
    # dYdX supply-chain attack (January 27 2026) — maintainer credential compromise
    # Socket + TheHackerNews + Rescana + CyberPress agree on all four versions
    "@dydxprotocol/v4-client-js": {"3.4.1", "1.22.1", "1.15.2", "1.0.31"},
    # axios maintainer-account takeover (March 31 2026) — Sapphire Sleet / DPRK
    # OSV MAL-2026-2307 / GHSA-fw8c-xr5c-95f9 (axios)
    # OSV MAL-2026-2306 / GHSA-2x9r-6wxq-hrr7 (plain-crypto-js phantom dep)
    "axios": {"0.30.4", "1.14.1"},
    "plain-crypto-js": {"4.2.0", "4.2.1"},
    # @bitwarden/cli typosquat (April 22 2026) — TeamPCP / Checkmarx breach
    # OSV MAL-2026-3020 / GHSA-g98r-qjhg-4fmr
    "@bitwarden/cli": {"2026.4.0"},
    # node-ipc maintainer-account takeover (May 14 2026)
    # OSV MAL-2026-3744 / GHSA-g7cv-rxg3-hmpx / CVE-2026-45321
    "node-ipc": {"9.1.6", "9.2.3", "12.0.1"},
    # Additional Mini Shai-Hulud packages (May 2026 wave)
    # OSV MAL-2026-3448, MAL-2026-3456, MAL-2026-3444, MAL-2026-3515, MAL-2026-3458
    "@squawk/mcp": {"0.9.1", "0.9.2", "0.9.3", "0.9.4", "0.9.5"},
    "@squawk/weather": {"0.5.6", "0.5.7", "0.5.8", "0.5.9", "0.5.10"},
    "@squawk/flightplan": {"0.5.2", "0.5.3", "0.5.4", "0.5.5", "0.5.6"},
    "@tallyui/connector-medusa": {"1.0.1", "1.0.2", "1.0.3"},
    "@tallyui/connector-vendure": {"1.0.1", "1.0.2", "1.0.3"},
    # intercom-client maintainer-credential compromise (April 30 2026) — Shai-Hulud campaign
    # GHSA-54pg-9963-v8vg; confirmed by StepSecurity, Socket, Netskope, OX Security, Upwind
    "intercom-client": {"7.0.4"},
    # CanisterSprawl / TeamPCP npm self-propagating worm (April 8–22 2026)
    # Self-spreading credential stealer using ICP-canister exfiltration; compromised Namastex Labs
    # developer tools. Postinstall hook harvests cloud creds, SSH keys, npm tokens, then republishes
    # infected versions using stolen tokens. Covers @fairwords scope (April 8) and Namastex packages
    # (April 21–22). All version ranges confirmed by two+ independent vendors.
    # pgserve: StepSecurity stepsecurity.io/blog/pgserve-compromised-on-npm-malicious-versions-harvest-credentials
    #          Socket socket.dev/blog/namastex-npm-packages-compromised-canisterworm
    #          Maintainer issue github.com/namastexlabs/pgserve/issues/25
    # @automagik/genie: Socket; THN thehackernews.com/2026/04/self-propagating-supply-chain-worm.html
    #                   InfoWorld infoworld.com/article/4162198/malicious-pgserve-automagik-developer-tools-found-in-npm-registry.html
    # @fairwords/*: SafeDep safedep.io/malicious-fairwords-npm-credential-worm/; Socket (same campaign)
    # @openwebconcept/*: Socket (same campaign); THN; The Register
    "pgserve": {"1.1.11", "1.1.12", "1.1.13"},
    "@automagik/genie": {
        "4.260421.33", "4.260421.34", "4.260421.35", "4.260421.36",
        "4.260421.37", "4.260421.38", "4.260421.39", "4.260421.40",
    },
    "@fairwords/websocket": {"1.0.38", "1.0.39"},
    "@fairwords/loopback-connector-es": {"1.4.3", "1.4.4"},
    "@openwebconcept/theme-owc": {"1.0.1", "1.0.2", "1.0.3"},
    "@openwebconcept/design-tokens": {"1.0.1", "1.0.2", "1.0.3"},
    # @velora-dex/sdk registry-only supply-chain compromise (April 7 2026)
    # Malicious build published directly to npm without matching GitHub commit; injects a Go RAT
    # (minirat) + macOS launchctl persistence into dist/index.js on import (no postinstall hook).
    # Legitimate SDK; pin to <=9.4.0 and rotate all credentials.
    # StepSecurity stepsecurity.io/blog/velora-dex-sdk-compromised-on-npm-malicious-version-drops-macos-backdoor-via-launchctl-persistence
    # SafeDep safedep.io/malicious-velora-dex-sdk-npm-compromised-rat/
    "@velora-dex/sdk": {"9.4.1"},
    # @antv / atool mass wave (May 19 2026) — 317 npm packages, 631 versions
    # Per safedep.io and ossf/malicious-packages. High-impact subset only;
    # the rest of the @antv/ scope is covered by NPM_SUSPECT_SCOPES below.
    # OSV MAL-2026-3973, MAL-2026-3982, MAL-2026-4033, MAL-2026-4077,
    # MAL-2026-3839, MAL-2026-4083, MAL-2026-4153, MAL-2026-4132, MAL-2026-4156,
    # MAL-2026-3862 (@antv/color-util)
    "@antv/g2": {"5.5.8", "5.6.8"},
    "@antv/g6": {"5.2.1", "5.3.1"},
    "@antv/l7": {"2.26.10", "2.27.10"},
    "@antv/s2": {"2.8.1", "2.9.1"},
    "@antv/x6": {"3.2.7", "3.3.7"},
    "@antv/scale": {"0.6.2", "0.7.2"},
    # @antv/color-util: both specific versions (2.1.6, 2.2.6) and SEMVER >=0 range in OSV;
    # per SKILLS.md the combination means the whole package is malicious — use empty-set wildcard.
    # OSV MAL-2026-3862 / GHSA-rh6v-hwr4-6jcp (ghsa-malware + amazon-inspector + google-open-source-security)
    "@antv/color-util": set(),
    "size-sensor": {"1.0.4", "1.1.4", "1.2.4"},
    "echarts-for-react": {"3.0.7", "3.1.7", "3.2.7"},
    "timeago.js": {"4.1.2", "4.2.2"},
    # TrapDoor crypto-stealer campaign (May 22 2026) — pure-malware typosquats
    # OSV records flag the entire package (`affected.ranges` is `>=0`); use
    # the empty-set wildcard so we catch any republished versions.
    # OSV MAL-2026-4202..4208, 4218..4220, 4250, 4275..4284
    "async-pipeline-builder": set(),
    "build-scripts-utils": set(),
    "chain-key-validator": set(),
    "crypto-credential-scanner": set(),
    "defi-env-auditor": set(),
    "defi-threat-scanner": set(),
    "deployment-key-auditor": set(),
    "dev-env-bootstrapper": set(),
    "eth-wallet-sentinel": set(),
    "llm-context-compressor": set(),
    "mnemonic-safety-check": set(),
    "model-switch-router": set(),
    "node-setup-helpers": set(),
    "project-init-tools": set(),
    "prompt-engineering-toolkit": set(),
    "solidity-deploy-guard": set(),
    "token-usage-tracker": set(),
    "wallet-backup-verifier": set(),
    "wallet-security-checker": set(),
    "web3-secrets-detector": set(),
    "workspace-config-loader": set(),
    # Multi-cluster npm typosquat wave (May 25 2026) — 25 packages, all fully malicious.
    # GitHub Advisory Database confirmed affected.ranges >=0 for every entry; use the
    # empty-set wildcard. The batch breaks into five sub-clusters published the same day:
    #   ts-* family:        GHSA-jp5r-76w9-2rvh, GHSA-66j8-7w8q-vvf5, GHSA-xqpr-hv2v-6pfj,
    #                       GHSA-qgfv-9wmq-m4f7, GHSA-f6hr-rvf9-ch6p, GHSA-vxrv-934h-xj6q
    #   @gbrlxvii/* scope:  GHSA-pvrm-mpcj-2mcp, GHSA-362c-qm74-42gg, GHSA-59j3-wvx3-w9hx
    #   auth0-* cluster:    GHSA-4xqv-4874-rxx6, GHSA-g8jx-g4j9-hh3w, GHSA-cwjp-2mq2-6xp6,
    #                       GHSA-xm89-4mqj-hfrq, GHSA-c8ph-73mc-f5p8, GHSA-jfp3-8vwj-7g9v
    #   webservices.rest*:  GHSA-2qjx-pgq9-vx24, GHSA-v62r-4vqp-f32g
    #   vite-plugin-env-*:  GHSA-7v58-43rg-wjwq, GHSA-2rh6-x7fc-2fr4
    #   miscellaneous:      GHSA-fc78-r45j-m7f5, GHSA-6pxr-857g-mr97, GHSA-qcrh-87jf-mm39,
    #                       GHSA-w6gc-fhv9-53hq, GHSA-rj44-v8w3-c5q5, GHSA-gqvh-j8hx-425w
    "ts-stream-compose": set(),
    "ts-result-pipe": set(),
    "ts-typeguard-utils": set(),
    "ts-config-mapper": set(),
    "ts-iter-utils": set(),
    "ts-schema-config": set(),
    "@gbrlxvii/ts-project-lint": set(),
    "@gbrlxvii/ts-form-utils": set(),
    "@gbrlxvii/ts-env-validator": set(),
    "auth0-aspnetcore-utils": set(),
    "auth0-internal-collector": set(),
    "auth0-android-helper-utils": set(),
    "auth0-net-sdk-utils": set(),
    "auth0-sample-dus-utils": set(),
    "auth0-common-telemetry": set(),
    "webservices.rest": set(),
    "webservices.rest-utils": set(),
    "vite-plugin-env-compat-1.5": set(),
    "vite-plugin-env-compat-plus": set(),
    "fivem-monitor": set(),
    "jules-standard": set(),
    "internallib_v95": set(),
    "chai-as-redeploy": set(),
    "expo-config-plugin-typescript": set(),
    "unique-string-64": set(),
    # toskypi npm RAT/infostealer campaign (May 25 2026)
    # Multi-platform infostealer + RAT disguised as terminal/logger utilities.
    # Postinstall hook establishes persistence on Windows/macOS/Linux;
    # steals crypto wallets, browsers, SSH keys, cloud creds. Second-stage
    # payload fetched from HuggingFace repo; C2: ws://195.201.194.107:8010.
    # OSV MAL-2026-4345 (eo-terminal), MAL-2026-4346 (logger-draft)
    # ossf/malicious-packages PR #1270 (merged 2026-05-26); SafeDep discovery
    "eo-terminal": set(),
    "logger-draft": set(),
    # CLOB IPFS dropper campaign (May 26 2026)
    # Four typosquats targeting DeFi / Central-Limit-Order-Book API developers.
    # Postinstall hook fetches a Windows executable via IPFS CID, installs it
    # with registry persistence, and beacons to C2 at 45.8.22.112:2026.
    # OSV MAL-2026-4347 (@devcarron/clob), MAL-2026-4348 (api-rs-node),
    # MAL-2026-4349 (clob.api), MAL-2026-4350 (clobprice.api)
    # ossf/malicious-packages PR #1271 (merged 2026-05-26); SafeDep discovery
    "@devcarron/clob": set(),
    "api-rs-node": set(),
    "clob.api": set(),
    "clobprice.api": set(),
    # DPRK-linked js-logger-pack / terminal-logger-utils cluster (April–May 2026)
    # js-logger-pack: fake npm logger with 23 malicious versions (2026-04-01 to
    # 2026-04-15); downloads MicrosoftSystem64 binary from HuggingFace Lordplay/
    # system-releases and exfiltrates via WebSocket; OSV MAL-2026-2827.
    # terminal-logger-utils: multi-stage dropper + RAT targeting Telegram sessions,
    # SSH keys, crypto wallets, cloud credentials; postinstall hook, HuggingFace
    # second-stage; three dependent packages trigger it on install.
    # Sources: OSV MAL-2026-2827; JFrog research.jfrog.com/post/hugging-face-exfil/;
    #          OX Security ox.security/blog/north-korean-npm-infostealer-rat/;
    #          SafeDep safedep.io/malicious-js-logger-pack-npm-stealer/;
    #          CybersecurityNews cybersecuritynews.com/malicious-npm-package-turns-hugging-face/
    "js-logger-pack": set(),
    "terminal-logger-utils": set(),
    "pretty-logger-utils": set(),
    "ts-logger-pack": set(),
    "pinno-loggers": set(),
    # DevTap user0001 typosquat cluster (April–May 2026) — six pure-malware packages
    # Single throwaway publisher (user0001 / tanvisoul9@gmail.com); all six share identical
    # postinstall payloads. Payloads include: SSH-key backdoor via Supabase bucket, Windows
    # HKCU persistence + Node.js RAT with microphone/screenshot/browser-history theft,
    # and full remote-access shell. OSV confirmed affected.ranges >=0 for all; use empty-set
    # wildcard.
    # SafeDep (per-package blogs: safedep.io/malicious-npm-node-env-resolve-rat/,
    #          safedep.io/malicious-dom-utils-lite-npm-ssh-backdoor/)
    # Xygeni xygeni.io/blog/devtap-npm-typosquatting-attack-2/ (covers all six packages)
    "centralogger": set(),
    "connector-agent": set(),
    "dom-utils-lite": set(),
    "node-env-resolve": set(),
    "node-fetch-lite": set(),
    "node-gyp-runtime": set(),
    # Leaked Shai-Hulud / deadcode09284814 npm cluster (May 26 2026)
    # Four packages published by npm user deadcode09284814 containing different
    # payloads: chalk-tempalte carries a working Shai-Hulud worm clone with its
    # own C2; axois-utils delivers Phantom Bot (Golang DDoS botnet with HTTP/TCP/
    # UDP flood and persistence on Windows + Linux); @deadcode09284814/axios-util
    # and color-style-utils siphon SSH keys, env vars, cloud credentials, and
    # crypto wallet data. "Any version" confirmed for all four.
    # Sources: Bleeping Computer bleepingcomputer.com/news/security/leaked-shai-hulud-malware-fuels-new-npm-infostealer-campaign/ (2026-05-26);
    #          OX Security ox.security/blog/new-actors-deploy-shai-hulud-clones-teampcp-copycats-are-here/;
    #          SecurityWeek securityweek.com/first-shai-hulud-worm-clones-emerge/;
    #          The Hacker News thehackernews.com/2026/05/four-malicious-npm-packages-deliver.html
    "chalk-tempalte": set(),
    "@deadcode09284814/axios-util": set(),
    "axois-utils": set(),
    "color-style-utils": set(),
    # Nx build-system supply-chain compromise (May 27 2026)
    # Malicious versions injected into the @nx/* monorepo-build ecosystem.
    # OSV MAL-2025-41436 (@nx/devkit), MAL-2025-41437 (@nx/enterprise-cloud),
    # MAL-2025-41438 (@nx/eslint), MAL-2025-41439 (@nx/js),
    # MAL-2025-41440 (@nx/key), MAL-2025-41441 (@nx/node),
    # MAL-2025-41442 (@nx/workspace), MAL-2025-41443 (nx)
    "@nx/devkit": {"20.9.0", "21.5.0"},
    "@nx/enterprise-cloud": {"3.2.0"},
    "@nx/eslint": {"21.5.0"},
    "@nx/js": {"20.9.0", "21.5.0"},
    "@nx/node": {"20.9.0", "21.5.0"},
    "@nx/workspace": {"20.9.0", "21.5.0"},
    "nx": {"20.9.0", "20.10.0", "20.11.0", "20.12.0",
            "21.5.0", "21.6.0", "21.7.0", "21.8.0"},
    # @limebike/* dependency-confusion campaign (May 27 2026)
    # High-version (85.x) packages published to the @limebike scope to
    # override Lime's internal packages in CI. OSV affected.ranges is >=0
    # for every entry — use the empty-set wildcard.
    # OSV MAL-2026-4187 (@limebike/frontend-core-api),
    # MAL-2026-4188 (@limebike/supreme),
    # MAL-2026-4189 (@limebike/supreme-data-grid),
    # MAL-2026-4190 (@limebike/supreme-date-pickers)
    "@limebike/frontend-core-api": set(),
    "@limebike/supreme": set(),
    "@limebike/supreme-data-grid": set(),
    "@limebike/supreme-date-pickers": set(),
    # msc-terminal npm infostealer (May 27 2026)
    # Pure-malware any-version package; OSV affected.ranges is >=0.
    # OSV MAL-2026-4823.
    "msc-terminal": set(),
    # polymarket-clob-client compromise (May 26 2026)
    # Specific malicious version of the official Polymarket CLOB npm client.
    # OSV MAL-2026-4643.
    "polymarket-clob-client": {"2.1.1"},
    # Dependency-confusion 99.x campaign (May 27 2026)
    # High-version packages published to the public registry to shadow private
    # internal packages in CI pipelines. OSV MAL-2026-4424, 4543, 4830, 4831, 4832
    "@remitee-money-transfer/rmt-base": {
        "99.99.99", "99.99.100", "99.99.102", "99.99.104",
    },
    "customerdigital-ui-containers-lib": set(),  # >=0 wildcard (OSV MAL-2026-4543)
    "editorial-code": {"99.0.1"},
    "editorial-mse-authentication-ui": {"99.0.1"},
    "mse-authentication": {"99.0.1"},
    # Any-version wildcards — May 27 2026 pure-malware packages
    # OSV affected.ranges is >=0 for each; use empty-set wildcard.
    # OSV MAL-2026-2491, 4344, 4356, 4512, 4523, 4670, 4807, 4833
    "@not-nemo/crypto-tracker": set(),
    "bulletproof-json": set(),
    "chai-as-repaired": set(),
    "claude-channel-imessage": set(),
    "shop-minis": set(),
    "skills-detector": set(),
    "testing-on-npmjs": set(),
    "verify-mycommand": set(),
    "@luke-101141/nobody": {"1.0.1"},
    "wallet-agent-ai-radix": {"1.0.0"},
    # May 26 2026 pure-malware typosquat batch — 17 packages, all fully malicious.
    # GHSA affected.ranges is >= 0 for every entry; use the empty-set wildcard.
    # Clusters: Web3/DeFi impersonators (web3-prices, web3.prc, int-node, @izumiswap/sdk),
    # JSON-utility typosquats (jsonlogbundler, fastjsonlog, jsonbson), Solidity/Hardhat
    # dev-tool impersonators (solidity-coverage-plus, hardhat-gas-analytics), document-
    # library typosquats (pdf-lib-enhanced, xlsx-enhanced), and miscellaneous malware
    # (corelia, license-checker-plus, lynx-keeper, lynx-keeper-cli, zest-product,
    # tailwind-style-typography).
    # GHSA-g3vg-qhhh-pfv7 (web3-prices), GHSA-r4j3-79hx-xpr6 (web3.prc),
    # GHSA-r4ww-65gv-rhv8 (int-node), GHSA-q782-j24w-vv68 (@izumiswap/sdk),
    # GHSA-hhf2-gfcc-vw45 (jsonlogbundler), GHSA-82gw-34fc-qfwj (fastjsonlog),
    # GHSA-44rg-m26f-r36f (jsonbson), GHSA-fg63-2vqh-93xf (corelia),
    # GHSA-9qcm-qgjc-h848 (pdf-lib-enhanced), GHSA-j5gx-8qjw-gp5q (xlsx-enhanced),
    # GHSA-j3fh-3pm4-rw5h (solidity-coverage-plus), GHSA-73xx-w222-rg6v (license-checker-plus),
    # GHSA-7pxc-2jp3-w7c8 (hardhat-gas-analytics), GHSA-x7hr-g7qr-7j7p (lynx-keeper),
    # GHSA-3p5r-gmr8-v7mr (lynx-keeper-cli), GHSA-qm6m-33hv-fvwv (zest-product),
    # GHSA-pv74-wmjg-4gp8 (tailwind-style-typography)
    "@izumiswap/sdk": set(),
    "corelia": set(),
    "fastjsonlog": set(),
    "hardhat-gas-analytics": set(),
    "int-node": set(),
    "jsonbson": set(),
    "jsonlogbundler": set(),
    "license-checker-plus": set(),
    "lynx-keeper": set(),
    "lynx-keeper-cli": set(),
    "pdf-lib-enhanced": set(),
    "solidity-coverage-plus": set(),
    "tailwind-style-typography": set(),
    "web3-prices": set(),
    "web3.prc": set(),
    "xlsx-enhanced": set(),
    "zest-product": set(),
    # Moika Tech out-of-band dependency confusion campaign (May 28 2026)
    # Attacker (npm user 'pik-libs') published 164 private internal packages
    # belonging to a Russian bank / cloud platform at inflated version 99.99.99,
    # exploiting npm's default highest-version resolution to hijack internal CI.
    # All five scopes are company-internal; any version on the public npm registry
    # is malicious. OSV ingestion pending; confirmed in ossf/malicious-packages
    # PR #1279 (merged 2026-05-28, authors KunalSin9h + calebbrown; references
    # SafeDep Moika Tech dependency confusion report).
    # @car-loans scope (19 packages)
    "@car-loans/applicaion-aff": set(),
    "@car-loans/application-aff": set(),
    "@car-loans/close-flow-module": set(),
    "@car-loans/deal-aff": set(),
    "@car-loans/deal": set(),
    "@car-loans/desktop-car-loans-application": set(),
    "@car-loans/feature-toggles-module": set(),
    "@car-loans/general-analytics": set(),
    "@car-loans/general-feature-toggles": set(),
    "@car-loans/gus": set(),
    "@car-loans/mobile-car-loans-application": set(),
    "@car-loans/online-scoring-aff": set(),
    "@car-loans/online-sign-aff": set(),
    "@car-loans/referrer-module": set(),
    "@car-loans/restore": set(),
    "@car-loans/safe-storage-module": set(),
    "@car-loans/save": set(),
    "@car-loans/show-car-year-module": set(),
    "@car-loans/wait-task-props": set(),
    # @cloudplatform-single-spa scope (122 packages)
    "@cloudplatform-single-spa/administration": set(),
    "@cloudplatform-single-spa/advanced": set(),
    "@cloudplatform-single-spa/agreements": set(),
    "@cloudplatform-single-spa/aifactory-notebooks": set(),
    "@cloudplatform-single-spa/airflow": set(),
    "@cloudplatform-single-spa/anti-ddos": set(),
    "@cloudplatform-single-spa/arenadata-db": set(),
    "@cloudplatform-single-spa/audit-log": set(),
    "@cloudplatform-single-spa/bare-metal-servers": set(),
    "@cloudplatform-single-spa/base-static-page": set(),
    "@cloudplatform-single-spa/billing": set(),
    "@cloudplatform-single-spa/business-solutions": set(),
    "@cloudplatform-single-spa/certificate-manager": set(),
    "@cloudplatform-single-spa/clickhouse": set(),
    "@cloudplatform-single-spa/cloud-dns": set(),
    "@cloudplatform-single-spa/cloudia": set(),
    "@cloudplatform-single-spa/cnapp-ui": set(),
    "@cloudplatform-single-spa/container-registry": set(),
    "@cloudplatform-single-spa/corax": set(),
    "@cloudplatform-single-spa/cp-api-gw": set(),
    "@cloudplatform-single-spa/datagrid": set(),
    "@cloudplatform-single-spa/dataplatform-bi": set(),
    "@cloudplatform-single-spa/dataplatform-cloudberry": set(),
    "@cloudplatform-single-spa/dataplatform-clusters": set(),
    "@cloudplatform-single-spa/dataplatform-connections": set(),
    "@cloudplatform-single-spa/dataplatform-flink": set(),
    "@cloudplatform-single-spa/dataplatform-metastore": set(),
    "@cloudplatform-single-spa/dataplatform-nessie": set(),
    "@cloudplatform-single-spa/dataplatform-spark": set(),
    "@cloudplatform-single-spa/dataplatform-trino": set(),
    "@cloudplatform-single-spa/dataplatform": set(),
    "@cloudplatform-single-spa/disks": set(),
    "@cloudplatform-single-spa/dns": set(),
    "@cloudplatform-single-spa/document-db": set(),
    "@cloudplatform-single-spa/edge-manager": set(),
    "@cloudplatform-single-spa/employees": set(),
    "@cloudplatform-single-spa/enterprise": set(),
    "@cloudplatform-single-spa/event-bus": set(),
    "@cloudplatform-single-spa/evocs": set(),
    "@cloudplatform-single-spa/evolution": set(),
    "@cloudplatform-single-spa/floating-ips": set(),
    "@cloudplatform-single-spa/iam": set(),
    "@cloudplatform-single-spa/installations": set(),
    "@cloudplatform-single-spa/key-manager": set(),
    "@cloudplatform-single-spa/logaas": set(),
    "@cloudplatform-single-spa/magic-bridge": set(),
    "@cloudplatform-single-spa/magic-router": set(),
    "@cloudplatform-single-spa/managed-identities": set(),
    "@cloudplatform-single-spa/marketplace-apps": set(),
    "@cloudplatform-single-spa/marketplace-gigachat": set(),
    "@cloudplatform-single-spa/marketplace-main": set(),
    "@cloudplatform-single-spa/ml-ai-agents-agent-system": set(),
    "@cloudplatform-single-spa/ml-ai-agents-agent": set(),
    "@cloudplatform-single-spa/ml-ai-agents-evo-claw": set(),
    "@cloudplatform-single-spa/ml-ai-agents-ide": set(),
    "@cloudplatform-single-spa/ml-ai-agents-marketplace": set(),
    "@cloudplatform-single-spa/ml-ai-agents-mcp-server": set(),
    "@cloudplatform-single-spa/ml-ai-agents-system-prompt": set(),
    "@cloudplatform-single-spa/ml-ai-agents-trigger": set(),
    "@cloudplatform-single-spa/ml-finetuning": set(),
    "@cloudplatform-single-spa/ml-foundation-models": set(),
    "@cloudplatform-single-spa/ml-inference-comfy-run": set(),
    "@cloudplatform-single-spa/ml-inference-docker-run": set(),
    "@cloudplatform-single-spa/ml-inference-marketplace": set(),
    "@cloudplatform-single-spa/ml-inference-model-run": set(),
    "@cloudplatform-single-spa/ml-inference-router": set(),
    "@cloudplatform-single-spa/ml-inference": set(),
    "@cloudplatform-single-spa/ml-rag": set(),
    "@cloudplatform-single-spa/mlspace-access-request": set(),
    "@cloudplatform-single-spa/monaas-ui": set(),
    "@cloudplatform-single-spa/monitoring": set(),
    "@cloudplatform-single-spa/notification-gateway": set(),
    "@cloudplatform-single-spa/observability": set(),
    "@cloudplatform-single-spa/onboarding": set(),
    "@cloudplatform-single-spa/opensearch": set(),
    "@cloudplatform-single-spa/paas-kafka": set(),
    "@cloudplatform-single-spa/paas-redis": set(),
    "@cloudplatform-single-spa/pangolin": set(),
    "@cloudplatform-single-spa/postgre": set(),
    "@cloudplatform-single-spa/profile": set(),
    "@cloudplatform-single-spa/rabbitmq": set(),
    "@cloudplatform-single-spa/redirect": set(),
    "@cloudplatform-single-spa/resource-manager": set(),
    "@cloudplatform-single-spa/search": set(),
    "@cloudplatform-single-spa/secret-manager": set(),
    "@cloudplatform-single-spa/security-groups": set(),
    "@cloudplatform-single-spa/self-service": set(),
    "@cloudplatform-single-spa/serverless-containers": set(),
    "@cloudplatform-single-spa/smk": set(),
    "@cloudplatform-single-spa/solutions": set(),
    "@cloudplatform-single-spa/ssh-keys": set(),
    "@cloudplatform-single-spa/static-page": set(),
    "@cloudplatform-single-spa/subnets": set(),
    "@cloudplatform-single-spa/support": set(),
    "@cloudplatform-single-spa/svp-agent-backup": set(),
    "@cloudplatform-single-spa/svp-anti-affinity": set(),
    "@cloudplatform-single-spa/svp-baas": set(),
    "@cloudplatform-single-spa/svp-bare-metal-servers": set(),
    "@cloudplatform-single-spa/svp-draas": set(),
    "@cloudplatform-single-spa/svp-gateways": set(),
    "@cloudplatform-single-spa/svp-gitaas": set(),
    "@cloudplatform-single-spa/svp-images": set(),
    "@cloudplatform-single-spa/svp-interfaces": set(),
    "@cloudplatform-single-spa/svp-lbaas": set(),
    "@cloudplatform-single-spa/svp-managed-kubernetes": set(),
    "@cloudplatform-single-spa/svp-pipeline": set(),
    "@cloudplatform-single-spa/svp-s3-storage": set(),
    "@cloudplatform-single-spa/svp-tags": set(),
    "@cloudplatform-single-spa/svp-tasks": set(),
    "@cloudplatform-single-spa/svp-vdi": set(),
    "@cloudplatform-single-spa/svp-vm-migration": set(),
    "@cloudplatform-single-spa/timescale-db": set(),
    "@cloudplatform-single-spa/vcenter-manager": set(),
    "@cloudplatform-single-spa/vcenter-virtual-machines": set(),
    "@cloudplatform-single-spa/vdi": set(),
    "@cloudplatform-single-spa/virtual-ip": set(),
    "@cloudplatform-single-spa/virtual-machines": set(),
    "@cloudplatform-single-spa/vmmanager": set(),
    "@cloudplatform-single-spa/vmware-draas": set(),
    "@cloudplatform-single-spa/vpc-endpoint": set(),
    "@cloudplatform-single-spa/vpc": set(),
    "@cloudplatform-single-spa/vpn": set(),
    # @debit-ib scope (2 packages)
    "@debit-ib/desktop-debit-ib-additional-card-form": set(),
    "@debit-ib/mobile-debit-ib-additional-card-form": set(),
    # @fb-deposit scope (4 packages)
    "@fb-deposit/form-deposit-auth": set(),
    "@fb-deposit/form-deposit-calc": set(),
    "@fb-deposit/form-deposit": set(),
    "@fb-deposit/form-savings-account": set(),
    # @mlspace scope (17 packages)
    "@mlspace/allocations": set(),
    "@mlspace/connectors": set(),
    "@mlspace/docker-registry": set(),
    "@mlspace/dtransfer-history": set(),
    "@mlspace/dtransfer": set(),
    "@mlspace/env-gitlab": set(),
    "@mlspace/env-jobs": set(),
    "@mlspace/env-jupyter-server": set(),
    "@mlspace/experiments-monitoring": set(),
    "@mlspace/experiments": set(),
    "@mlspace/file-manager": set(),
    "@mlspace/inference-build": set(),
    "@mlspace/inference-deploy": set(),
    "@mlspace/model-monitoring": set(),
    "@mlspace/model-registry": set(),
    "@mlspace/profile": set(),
    "@mlspace/shared-storage": set(),
    # vpmdhaj OpenSearch/CI typosquat cluster (May 28, 2026)
    # A single threat actor (alias vpmdhaj, a39155771@gmail.com) published 14
    # malicious packages within a four-hour window, typosquatting OpenSearch,
    # ElasticSearch, DevOps, and environment-config libraries. All packages spoof
    # the upstream opensearch-project repository metadata in package.json to appear
    # legitimate. Postinstall stager deploys a ~195 KB Bun-compiled second-stage
    # payload that harvests AWS credentials, HashiCorp Vault tokens, and CI/CD
    # pipeline secrets. Packages were removed from the registry; no prior legitimate
    # versions exist — use the empty-set wildcard.
    # Microsoft Threat Intelligence (primary disclosure, versions enumerated):
    #   microsoft.com/en-us/security/blog/2026/05/28/typosquatted-npm-packages-used-steal-cloud-ci-cd-secrets/
    # GBHackers (independent corroboration):
    #   gbhackers.com/typosquatted-npm-packages/
    "@vpmdhaj/devops-tools": set(),
    "@vpmdhaj/elastic-helper": set(),
    "@vpmdhaj/opensearch-setup": set(),
    "@vpmdhaj/search-setup": set(),
    "app-config-utility": set(),
    "elastic-opensearch-helper": set(),
    "env-config-manager": set(),
    "opensearch-config-utility": set(),
    "opensearch-security-scanner": set(),
    "opensearch-setup": set(),
    "opensearch-setup-tool": set(),
    "search-cluster-setup": set(),
    "search-engine-setup": set(),
    "vpmdhaj-opensearch-setup": set(),
    # oob-moika-tech dependency-confusion + Roblox-adjacent npm cluster (May 29 2026)
    # Internal-package-name dependency-confusion (@databus-service-ui, @service-suppliers,
    # @service-user-notifications, @polka-ui, @pulse-web-platform-core, @loans) plus nemo-reporter.
    # All confirmed by individual OSV MAL-2026-* records (active, not withdrawn).
    "@databus-service-ui/scroll-up-content": set(),
    "@databus-service-ui/ui-event": set(),
    "@loans/vehicles-api": set(),
    "@polka-ui/config": {"9.9.11"},
    "@polka-ui/loader": set(),
    "@polka-ui/reco": set(),
    "@polka-ui/recoc": set(),
    "@pulse-web-platform-core/scripts-loader": set(),
    "@service-suppliers/fetch-suppliers-watcher-saga": set(),
    "@service-suppliers/fetch_suppliers_action_saga": set(),
    "@service-suppliers/reset_country_list": set(),
    "@service-suppliers/select-supplier-watcher-saga": set(),
    "@service-suppliers/set_selected_supplier": set(),
    "@service-suppliers/set_suppliers_data": set(),
    "@service-suppliers/set_suppliers_loading_start": set(),
    "@service-suppliers/set_suppliers_loading_stop": set(),
    "@service-suppliers/suppliers": set(),
    "@service-user-notifications/set_notifications_not_removable": set(),
    "nemo-reporter": {"1.8.3"},
    # oob-moika-tech Wave 2 npm dependency-confusion cluster (May 29 2026)
    # Same actor (npm user t-in-one, nath.dr4k3@gmail.com) and C2 (oob.moika.tech) as May 28
    # Moika Tech wave. Targets the @t-in-one scope (attacker's own npm username) with 15 packages
    # impersonating private Angular DI token packages, plus two external-scope targets
    # (@capibar.chat/ui-kit and @sber-ecom-core/sberpay-widget). All 17 packages have
    # OSV affected.ranges >=0 — use empty-set wildcard.
    # OSV MAL-2026-3337 (@t-in-one/save_application_hid_to_storage, first discovery),
    # MAL-2026-5031 (@capibar.chat/ui-kit), MAL-2026-5032 (@sber-ecom-core/sberpay-widget),
    # MAL-2026-5033–5046 (remaining @t-in-one/* packages)
    # Primary source: SafeDep safedep.io/oob-moika-tech-dependency-confusion-campaign/
    "@capibar.chat/ui-kit": set(),
    "@sber-ecom-core/sberpay-widget": set(),
    "@t-in-one/add_app_middleware_token": set(),
    "@t-in-one/add_application": set(),
    "@t-in-one/add_application_service_token": set(),
    "@t-in-one/add_application_tid": set(),
    "@t-in-one/application_id_storage_key_token": set(),
    "@t-in-one/form_product_token": set(),
    "@t-in-one/get_application_hid": set(),
    "@t-in-one/only_difference_payload": set(),
    "@t-in-one/prefill_bundle_data_token": set(),
    "@t-in-one/prefill_credit_data_token": set(),
    "@t-in-one/prefill_transformers_data_token": set(),
    "@t-in-one/restore_application_hid_from_storage": set(),
    "@t-in-one/safe_local_storage_token": set(),
    "@t-in-one/save_application_hid_to_storage": set(),
    "@t-in-one/send_add_application": set(),
    # oob-moika-tech Wave 3 / EMCD-impersonation npm dep-confusion cluster (June 2 2026)
    # Attacker registered the @emcd-vue npm scope to impersonate EMCD (emcd.io), a legitimate
    # Russian cryptocurrency exchange and mining pool, distributing packages posing as internal
    # Vue.js front-end tooling. SEMVER >=0 range in all three OSV records; use empty-set wildcard.
    # Same C2 infrastructure (oob.moika.tech) and discovery source as May 28–29 oob-moika-tech waves.
    # OSV MAL-2026-5163 (@emcd-vue/auth), MAL-2026-5164 (@emcd-vue/b2b-pay-form),
    # MAL-2026-5165 (@emcd-vue/loans)
    # Source: safedep.io/oob-moika-tech-dependency-confusion-campaign/
    "@emcd-vue/auth": set(),
    "@emcd-vue/b2b-pay-form": set(),
    "@emcd-vue/loans": set(),
    # Mixed npm malware batch (May 29 2026)
    # buffer-util-extend: decodes and executes base64 payload on require/import.
    #   OSV MAL-2026-2920 / GHSA-g44v-3gq3-j8p6 (Amazon Inspector primary discovery)
    # hellowornd: generic credential stealer, any-version wildcard.
    #   OSV MAL-2026-4839 / GHSA-4f9q-ffgq-5w82
    # tiny-naturalsort: any-version wildcard.
    #   OSV MAL-2026-5030 / GHSA-mqp5-9r9w-8hg4
    # @neon-i18n/core-ui: dependency-confusion package at inflated version 99.99.99.
    #   OSV MAL-2026-5027 (OpenSSF Package Analysis)
    # sorenson-webfonts: dependency-confusion package at inflated version 99.9.1.
    #   OSV MAL-2026-5028 (OpenSSF Package Analysis)
    "buffer-util-extend": set(),
    "hellowornd": set(),
    "tiny-naturalsort": set(),
    "@neon-i18n/core-ui": {"99.99.99"},
    "sorenson-webfonts": {"99.9.1"},
    # puppeteer maintainer-account compromise (May 29 2026)
    # A single malicious version published to the official puppeteer package
    # (Google's headless Chrome library, 25M+ weekly downloads). Any computer
    # with this version installed should be considered fully compromised.
    # OSV MAL-2026-5077 / GHSA-8r2f-2qg4-cv9v
    "puppeteer": {"25.0.1"},
    # Mini Shai-Hulud wave additional packages (May 2026)
    # @beproduct/nestjs-auth: every published version is infected;
    #   same Shai-Hulud postinstall bundle as @tanstack/* packages.
    #   OSV MAL-2026-3433 / GHSA-cqpw-mfqj-f2j7 (Aikido + StepSecurity)
    # @tallyui/storage-sqlite: three malicious versions in same campaign.
    #   OSV MAL-2026-3604 (Socket + Aikido + StepSecurity)
    "@beproduct/nestjs-auth": {
        "0.1.2", "0.1.3", "0.1.4", "0.1.5", "0.1.6", "0.1.7", "0.1.8",
        "0.1.9", "0.1.10", "0.1.11", "0.1.12", "0.1.13", "0.1.14",
        "0.1.15", "0.1.16", "0.1.17", "0.1.18", "0.1.19",
    },
    "@tallyui/storage-sqlite": {"0.2.1", "0.2.2", "0.2.3"},
    # @antv / atool wave supplemental packages (May 19 2026)
    # Non-@antv-scope packages compromised in the same 317-package campaign.
    # Compromised versions follow the same +1-minor pattern as the @antv/* entries.
    # Sources: safedep.io/mini-shai-hulud-strikes-again-314-npm-packages-compromised/;
    #          socket.dev/blog/antv-packages-compromised
    # OSV MAL-2026-4123 (@lint-md/cli), MAL-2026-4124 (@lint-md/core),
    # MAL-2026-4125 (@lint-md/parser), MAL-2026-4128 (ast-plugin),
    # MAL-2026-4131 (canvas-nest.js), MAL-2026-4134 (fixed-round),
    # MAL-2026-4137 (jest-date-mock), MAL-2026-4140 (jest-less-loader),
    # MAL-2026-4143 (limit-size), MAL-2026-4148 (miz), MAL-2026-4149 (onfire.js),
    # MAL-2026-4151 (relationship.js), MAL-2026-4154 (slice.js),
    # MAL-2026-4158 (word-width), MAL-2026-4159 (xmorse)
    "@lint-md/cli": {"2.1.0", "2.2.0"},
    "@lint-md/core": {"2.1.0", "2.2.0"},
    "@lint-md/parser": {"0.1.14", "0.2.14"},
    "ast-plugin": {"0.1.7", "0.2.7"},
    "canvas-nest.js": {"2.1.4", "2.2.4"},
    "fixed-round": {"1.1.2", "1.2.2"},
    "jest-date-mock": {"1.0.11", "1.1.11", "1.2.11"},
    "jest-less-loader": {"0.3.0", "0.4.0"},
    "limit-size": {"0.2.4", "0.3.4"},
    "miz": {"1.1.1", "1.2.1"},
    "onfire.js": {"2.1.1", "2.2.1"},
    "relationship.js": {"1.3.9", "1.4.9"},
    "slice.js": {"1.2.1", "1.3.1"},
    "word-width": {"1.1.1", "1.2.1"},
    "xmorse": {"1.1.0", "1.2.0"},
    # Multi-campaign dependency confusion batch (May 29–30 2026)
    # Multiple independent actors published high-version packages to public npm
    # to shadow private internal packages in CI. All have OSV affected.ranges >=0;
    # use empty-set wildcard.
    #
    # @clearpool dependency confusion (GHSA-fr5f-hf7f-p9w9 + siblings)
    # OSV MAL-2026-3056..3058
    "@clearpool/comms": set(),
    "@clearpool/streaming": set(),
    "@clearpool/table": set(),
    # Axis Communications dependency confusion
    # OSV MAL-2026-3075..3078
    "axis-abc-search-account": set(),
    "axis-abc-search-address": set(),
    "axis-notification": set(),
    # BreezeAI dependency confusion
    # OSV MAL-2026-3183, 3184, 3292, 3293
    "@breezeai-frontend/cargo-ui": set(),
    "@breezeai-frontend/tailwind-config": set(),
    "@breezeai-frontend/i18n-config": set(),
    "@breeze-ai/ui-library": set(),
    # Ally Financial dependency confusion (GHSA-2892-cpv4-xqr4 + siblings)
    # OSV MAL-2026-3289, 3290, 3295, 3296, 3298, 3299, 3301
    "@allybank/ally-sdk": set(),
    "@allyfinancial/allyfinancial-api": set(),
    "ally-antivirus": set(),
    "ally-badges": set(),
    "ally-ccapi": set(),
    "ally-eagw-identity": set(),
    "ally-json-threat-protect": set(),
    # Citigroup ICG dependency confusion (GHSA-gw7h-mv77-3wv8 + sibling)
    # OSV MAL-2026-3807, 3808
    "@citi-icg-158830/elemental-ui-react": set(),
    "@citi-icg-158830/icgds-react-css": set(),
    # ApexOmni / ApexPro crypto exchange API typosquats (GHSA-m6v2-w5cf-f85x + siblings)
    # OSV MAL-2026-3233, 3234, 3818, 3819
    "apexomni": set(),
    "apexpro": set(),
    "apexomni-node": set(),
    "apexpro-node": set(),
    # cplace software dependency confusion (GHSA-fmm7-x566-j93x + siblings)
    # OSV MAL-2026-3427, 5047, 5048
    "@cplace-workflow-fe/cf-workflow": set(),
    "@cplace-paw-fe/cf-training-extended": set(),
    "@cplace-project-planning-fe/cf-project-planning": set(),
    # RSI Community dependency confusion (GHSA-j83r-w4f8-v7m9 + sibling)
    # OSV MAL-2026-3414, 5050
    "@rsi-community/hub-schema": set(),
    "@rsi-community/hub-client-app": set(),
    # @lir-portal dependency confusion (GHSA-pvc4-pwx8-4c4g)
    # OSV MAL-2026-5049
    "@lir-portal/web-components": set(),
    # @tc-core dependency confusion
    # OSV MAL-2026-5051
    "@tc-core/provider-service": set(),
    # TimelyCare dependency confusion (GHSA-h3x2-x2gh-2hcm + siblings)
    # OSV MAL-2026-5052..5055
    "@timelycare/api": set(),
    "@timelycare/common": set(),
    "@timelycare/config-service": set(),
    "@timelycare/core": set(),
    # @trp-individual-investor-adv-disc dependency confusion
    # OSV MAL-2026-5056
    "@trp-individual-investor-adv-disc/adv-shared": set(),
    # Miscellaneous dependency-confusion and pure-malware packages (May 29–30 2026)
    # OSV MAL-2023-1274 (proton-pack, GHSA-gj36-855r-fpmf)
    # OSV MAL-2026-2909 (tailwind-typography-cssstyle)
    # OSV MAL-2026-2926 (material-ui-plugin-cache-endpoint)
    # OSV MAL-2026-3241 (nextjs-chat-with-ai-service)
    # OSV MAL-2026-3304 (apcyber-test-package)
    # OSV MAL-2026-3326 (paychex-common-vendor-lib)
    # OSV MAL-2026-3363 (mrdaa-frontend)
    # OSV MAL-2026-3645 (dit-envv), MAL-2026-3646 (erslove)
    # OSV MAL-2026-3745 (deepl-sync, GHSA-qvrg-265v-cqvc)
    # OSV MAL-2026-4254 (reactive-cdk-app), MAL-2026-4274 (power-apps)
    # OSV MAL-2026-4548 (dds-js-idl-types), MAL-2026-4612 (mmt-static)
    # OSV MAL-2026-4644 (power-platform-playwright-toolkit)
    # OSV MAL-2026-5057 (appkit-react-utils), MAL-2026-5058 (argpras)
    # OSV MAL-2026-5062 (codex-devcontainer-install, GHSA-frcf-f9wx-gq64)
    # OSV MAL-2026-5063 (customerdigital-service-lib, GHSA-9vx3-fc8v-7w96)
    # OSV MAL-2026-5071 (gcp-api-enabler), MAL-2026-5073 (midoss)
    # OSV MAL-2026-5074 (one-view-chat-ui-module), MAL-2026-5075 (ota_web_admin)
    # OSV MAL-2026-5076 (private-next-instrumentation-client, GHSA-cx3x-gvpc-g35w)
    # OSV MAL-2026-5078 (raven-i18n-react), MAL-2026-5079 (react-svg-animator)
    "proton-pack": set(),
    "tailwind-typography-cssstyle": set(),
    "material-ui-plugin-cache-endpoint": set(),
    "nextjs-chat-with-ai-service": set(),
    "apcyber-test-package": set(),
    "paychex-common-vendor-lib": set(),
    "mrdaa-frontend": set(),
    "dit-envv": set(),
    "erslove": set(),
    "deepl-sync": set(),
    "reactive-cdk-app": set(),
    "power-apps": set(),
    "dds-js-idl-types": set(),
    "mmt-static": set(),
    "power-platform-playwright-toolkit": set(),
    "appkit-react-utils": set(),
    "argpras": set(),
    "codex-devcontainer-install": set(),
    "customerdigital-service-lib": set(),
    "gcp-api-enabler": set(),
    "midoss": set(),
    "one-view-chat-ui-module": set(),
    "ota_web_admin": set(),
    "private-next-instrumentation-client": set(),
    "raven-i18n-react": set(),
    "react-svg-animator": set(),
    # ethers.js / EVM toolchain typosquat cluster (May 29–30 2026)
    # Pure-malware typosquats targeting Ethereum/EVM developers by impersonating
    # ethers.js sub-modules, Foundry, Hardhat, and viem toolchain packages.
    # All have OSV affected.ranges >=0; use empty-set wildcard.
    # OSV MAL-2026-3760 (ethers-abstract-signer, GHSA-2f7m-g9qw-8288)
    # OSV MAL-2026-3761 (ethers-signing-key)
    # OSV MAL-2026-5064 (ethers-contract, GHSA-gxfh-j6jv-hc58)
    # OSV MAL-2026-5065 (ethers-errors), MAL-2026-5066 (ethers-hash)
    # OSV MAL-2026-5067 (ethers-hdnode)
    # OSV MAL-2026-5068 (evmchain-cli), MAL-2026-5069 (evmchain-config)
    # OSV MAL-2026-5070 (foundry-config), MAL-2026-5072 (hardhat-evmchain)
    # OSV MAL-2026-5084 (viem-multichain), MAL-2026-5085 (web3-config-loader)
    "ethers-abstract-signer": set(),
    "ethers-signing-key": set(),
    "ethers-contract": set(),
    "ethers-errors": set(),
    "ethers-hash": set(),
    "ethers-hdnode": set(),
    "evmchain-cli": set(),
    "evmchain-config": set(),
    "foundry-config": set(),
    "hardhat-evmchain": set(),
    "viem-multichain": set(),
    "web3-config-loader": set(),
    # chai testing-library typosquat cluster (May 29–30 2026)
    # Fake Chai extensions; any installed version is malicious.
    # OSV MAL-2026-4513 (chai-as-tuned, GHSA-2f37-mh3q-7394)
    # OSV MAL-2026-5059 (chai-bundle, GHSA-q36r-56hw-2r46)
    # OSV MAL-2026-5060 (chai-extensions-extras), MAL-2026-5061 (chai-use-test)
    "chai-as-tuned": set(),
    "chai-bundle": set(),
    "chai-extensions-extras": set(),
    "chai-use-test": set(),
    # Tailwind CSS plugin typosquat cluster (May 29–30 2026)
    # Fake Tailwind CSS plugins; any installed version is malicious.
    # OSV MAL-2026-2909 (tailwind-typography-cssstyle — already listed above)
    # OSV MAL-2026-5080 (tailwind-clamps-line, GHSA-29g5-vw2p-x29p)
    # OSV MAL-2026-5081 (tailwind-effect), MAL-2026-5082 (tailwind-smooth-slider)
    # OSV MAL-2026-5083 (tailwindcss-basic-animation)
    "tailwind-clamps-line": set(),
    "tailwind-effect": set(),
    "tailwind-smooth-slider": set(),
    "tailwindcss-basic-animation": set(),
    # zod-to-js Zod-ecosystem typosquat (May 29 2026)
    # Impersonates a Zod-to-JS bridge library; two specific malicious versions.
    # OSV MAL-2026-4740 / GHSA-8cm2-vv7w-4c27
    "zod-to-js": {"13.4.3", "13.4.4"},
    # buffer-utilities npm malware (May 30 2026)
    # Communicates with a domain associated with malicious activity and executes
    # commands associated with malicious behavior; detected by OpenSSF Package Analysis.
    # Only one version published before takedown; pin it (no >=0 range in OSV record).
    # OSV MAL-2026-5087
    "buffer-utilities": {"1.0.0"},
    # retail-location-strategy-frontend npm malware (May 30 2026)
    # Communicates with a domain associated with malicious activity; detected by
    # OpenSSF Package Analysis. Two specific versions published; no >=0 range.
    # OSV MAL-2026-5092
    "retail-location-strategy-frontend": {"1.1.1", "1.1.2"},
    # @challenger6/vm-pattern-library npm malware (May 31 2026)
    # Communicates with a domain associated with malicious activity; detected by
    # OpenSSF Package Analysis. Single version published; no >=0 range.
    # OSV MAL-2026-5095
    "@challenger6/vm-pattern-library": {"99.0.0"},
    # cms-storehub npm malware (May 31 2026)
    # Communicates with a domain associated with malicious activity; detected by
    # OpenSSF Package Analysis. Single version published; no >=0 range.
    # OSV MAL-2026-5097
    "cms-storehub": {"1.3.6"},
    # js-shared-modules npm malware (May 31 2026)
    # Communicates with a domain associated with malicious activity; detected by
    # OpenSSF Package Analysis. Single version published; no >=0 range.
    # OSV MAL-2026-5098
    "js-shared-modules": {"1.11.7"},
    # CMS-dropper typosquat cluster (June 1 2026)
    # to-cms: postinstall downloads https://meet-fr.com/ChromeSetup.exe on install.
    # cms-github / cms-helpgit / shopifyto-cms: GHSA full-compromise packages in the
    # same CMS typosquat family; any installed version is treated as fully compromised.
    # OSV MAL-2026-4693 / GHSA-789x-j439-qx3f (to-cms)
    # OSV MAL-2026-5107 / GHSA-3r39-h7xh-jg85 (cms-github)
    # OSV MAL-2026-5108 / GHSA-hjw8-jc8q-mvwj (cms-helpgit)
    # OSV MAL-2026-5109 / GHSA-92q8-c63v-g77x (shopifyto-cms)
    "to-cms": set(),
    "cms-github": set(),
    "cms-helpgit": set(),
    "shopifyto-cms": set(),
    # Amazon Inspector postinstall-exfiltration batch (June 1 2026)
    # collected-forms-embed-js: postinstall hook performs recon + credential exfiltration.
    # audit-logsss: postinstall runs id/whoami/hostname, fetches public IP from external API.
    # chainix: presents as a pino-compatible logger; contains malicious postinstall payload.
    # OSV MAL-2026-4175 / GHSA-9j37-8wjm-pcxq (collected-forms-embed-js)
    # OSV MAL-2026-4487 / GHSA-gcq4-52q3-v4fm (audit-logsss)
    # OSV MAL-2026-4817 / GHSA-mrx8-p3w9-5cfm (chainix)
    "collected-forms-embed-js": set(),
    "audit-logsss": set(),
    "chainix": set(),
    # Chai typosquat cluster extension (June 1 2026)
    # Extends the existing chai-as-* / chai-bundle typosquat family.
    # OSV MAL-2026-5106 / GHSA-85px-g4cg-g2g3
    "chai-as-minted": set(),
    # AWS/CLI typosquats (June 1 2026)
    # @antoncallahan/aws-user-helper: AWS credential-helper typosquat; GHSA full-compromise.
    # @tmecontinue/cli: CLI tool impersonation package; GHSA full-compromise.
    # OSV MAL-2026-5101 / GHSA-v2cq-j5gf-pf5g (@antoncallahan/aws-user-helper)
    # OSV MAL-2026-5105 / GHSA-jq5f-g7j2-8f9g (@tmecontinue/cli)
    "@antoncallahan/aws-user-helper": set(),
    "@tmecontinue/cli": set(),
    # GHSA full-compromise test-scope packages (June 1 2026)
    # Garbage-scoped names consistent with security-research pipeline test submissions;
    # included because active OSV MAL records pass the evidence threshold.
    # OSV MAL-2026-5102 / GHSA-p4gj-2hmg-hj4f (@ewfewfewf/testhackerrr)
    # OSV MAL-2026-5103 / GHSA-rrrc-gchv-j329 (@osamdefeirrighs/testhackfrrferrr)
    # OSV MAL-2026-5104 / GHSA-xjcm-hjvm-fmhp (@pcldpvkoewpogw/testhacker)
    "@ewfewfewf/testhackerrr": set(),
    "@osamdefeirrighs/testhackfrrferrr": set(),
    "@pcldpvkoewpogw/testhacker": set(),
    # @redhat-cloud-services scope account compromise (June 1–2 2026)
    # Red Hat Cloud Services npm scope; malicious versions follow the +0.0.1-patch
    # pattern seen in prior maintainer-account-takeover waves. Additional packages
    # and supplemental versions published across June 1–2.
    # OSV MAL-2026-5111 / GHSA-942v-f47r-w9c3 (chrome)
    # OSV MAL-2026-5112 / GHSA-c3mv-fjj4-2542 (eslint-config-redhat-cloud-services)
    # OSV MAL-2026-5113 / GHSA-mrgj-mcjh-5mf2 (frontend-components)
    # OSV MAL-2026-5114 / GHSA-cxfw-p322-rfrv (frontend-components-config-utilities; updated: 4.11.3, 4.11.5)
    # OSV MAL-2026-5115 / GHSA-mj98-cgm5-6xrr (quickstarts-client)
    # OSV MAL-2026-5116 / GHSA-2p99-xvqh-j893 (rbac-client; updated: 9.0.4, 9.0.6)
    # OSV MAL-2026-5117 / GHSA-c4gm-6fh3-76v9 (rule-components)
    # OSV MAL-2026-5118 / GHSA-9wp8-557p-2hvf (topological-inventory-client; updated: 3.0.11, 3.0.13)
    # OSV MAL-2026-5119 / GHSA-8xj2-9c64-m64h (types)
    # OSV MAL-2026-5125 / GHSA-28hc-2275-h287 (entitlements-client)
    # OSV MAL-2026-5126 / GHSA-h43w-g623-gfmv (frontend-components-config)
    # OSV MAL-2026-5127 / GHSA-4rjr-7qhx-vjwg (frontend-components-remediations)
    # OSV MAL-2026-5128 / GHSA-wgvx-w8g7-vh4h (frontend-components-testing)
    # OSV MAL-2026-5129 / GHSA-vgm5-jmvr-cjgf (hcc-feo-mcp)
    # OSV MAL-2026-5130 / GHSA-8x4g-q845-wpfc (integrations-client)
    # OSV MAL-2026-5131 / GHSA-vp9c-9mjm-2f7w (sources-client)
    # OSV MAL-2026-5133 (compliance-client)
    # OSV MAL-2026-5134 (config-manager-client)
    # OSV MAL-2026-5135 (frontend-components-advisor-components)
    # OSV MAL-2026-5136 (frontend-components-notifications)
    # OSV MAL-2026-5137 (frontend-components-translations)
    # OSV MAL-2026-5138 (frontend-components-utilities)
    # OSV MAL-2026-5139 (hcc-kessel-mcp)
    # OSV MAL-2026-5140 (hcc-pf-mcp)
    # OSV MAL-2026-5141 (host-inventory-client)
    # OSV MAL-2026-5142 (insights-client)
    # OSV MAL-2026-5143 (javascript-clients-shared)
    # OSV MAL-2026-5144 (notifications-client)
    # OSV MAL-2026-5145 (patch-client)
    # OSV MAL-2026-5146 (remediations-client)
    # OSV MAL-2026-5147 (tsc-transform-imports)
    # OSV MAL-2026-5148 (vulnerabilities-client)
    "@redhat-cloud-services/chrome": {"2.3.1", "2.3.2", "2.3.4"},
    "@redhat-cloud-services/compliance-client": {"4.0.3", "4.0.4", "4.0.6"},
    "@redhat-cloud-services/config-manager-client": {"5.0.4", "5.0.5", "5.0.7"},
    "@redhat-cloud-services/entitlements-client": {"4.0.11", "4.0.12", "4.0.14"},
    "@redhat-cloud-services/eslint-config-redhat-cloud-services": {"3.2.1", "3.2.2", "3.2.4"},
    "@redhat-cloud-services/frontend-components": {"7.7.2", "7.7.3", "7.7.5"},
    "@redhat-cloud-services/frontend-components-advisor-components": {"3.8.2", "3.8.4", "3.8.6"},
    "@redhat-cloud-services/frontend-components-config": {"6.11.3", "6.11.4", "6.11.6"},
    "@redhat-cloud-services/frontend-components-config-utilities": {"4.11.2", "4.11.3", "4.11.5"},
    "@redhat-cloud-services/frontend-components-notifications": {"6.9.2", "6.9.3", "6.9.5"},
    "@redhat-cloud-services/frontend-components-remediations": {"4.9.2", "4.9.3", "4.9.5"},
    "@redhat-cloud-services/frontend-components-testing": {"1.2.1", "1.2.2", "1.2.4"},
    "@redhat-cloud-services/frontend-components-translations": {"4.4.1", "4.4.2", "4.4.4"},
    "@redhat-cloud-services/frontend-components-utilities": {"7.4.1", "7.4.2", "7.4.4"},
    "@redhat-cloud-services/hcc-feo-mcp": {"0.3.1", "0.3.2", "0.3.4"},
    "@redhat-cloud-services/hcc-kessel-mcp": {"0.3.1", "0.3.2", "0.3.4"},
    "@redhat-cloud-services/hcc-pf-mcp": {"0.6.1", "0.6.2", "0.6.4"},
    "@redhat-cloud-services/host-inventory-client": {"5.0.3", "5.0.4", "5.0.6"},
    "@redhat-cloud-services/insights-client": {"4.0.4", "4.0.5", "4.0.7"},
    "@redhat-cloud-services/integrations-client": {"6.0.4", "6.0.5", "6.0.7"},
    "@redhat-cloud-services/javascript-clients-shared": {"2.0.8", "2.0.9", "2.0.11"},
    "@redhat-cloud-services/notifications-client": {"6.1.4", "6.1.5", "6.1.7"},
    "@redhat-cloud-services/patch-client": {"4.0.4", "4.0.5", "4.0.7"},
    "@redhat-cloud-services/quickstarts-client": {"4.0.11", "4.0.12", "4.0.14"},
    "@redhat-cloud-services/rbac-client": {"9.0.3", "9.0.4", "9.0.6"},
    "@redhat-cloud-services/remediations-client": {"4.0.4", "4.0.5", "4.0.7"},
    "@redhat-cloud-services/rule-components": {"4.7.2", "4.7.3", "4.7.5"},
    "@redhat-cloud-services/sources-client": {"3.0.10", "3.0.11", "3.0.13"},
    "@redhat-cloud-services/topological-inventory-client": {"3.0.10", "3.0.11", "3.0.13"},
    "@redhat-cloud-services/tsc-transform-imports": {"1.2.2", "1.2.4", "1.2.6"},
    "@redhat-cloud-services/types": {"3.6.1", "3.6.2", "3.6.4"},
    "@redhat-cloud-services/vulnerabilities-client": {"2.1.8", "2.1.9", "2.1.11"},
    # loading-session npm package compromise (June 1 2026)
    # Session-management package with malicious code injected; OSV reports both
    # specific versions and a >=0 range — per convention, entire package is malicious.
    # OSV MAL-2026-4600 / GHSA-7vwr-8v2c-gjvr
    "loading-session": set(),
    # jingmeideshishi npm throwaway malware (June 1 2026)
    # Gibberish-name pure-malware package; OSV confirmed any-version malicious.
    # OSV MAL-2026-5110 / GHSA-pc3j-w4f9-94hj
    "jingmeideshishi": set(),
    # Amazon Inspector npm malware batch (June 1 2026)
    # xarc-webpack-cli: preinstall hook with malicious payload; typosquat of @xarc/webpack-cli.
    # json-to-simple-graphql-schema: contains poc.js script with malicious code.
    # motion-tool: masquerades as pino logger; any-version malicious.
    # randomlogs: main module carries malicious code across multiple versions.
    # All four have OSV affected.ranges >=0 (any-version); use empty-set wildcard.
    # OSV MAL-2026-4352 / GHSA-2xcr-5qfc-fq54 (xarc-webpack-cli)
    # OSV MAL-2026-4590 / GHSA-2qqv-9mw5-52q2 (json-to-simple-graphql-schema)
    # OSV MAL-2026-4615 / GHSA-hw79-5457-g9c3 (motion-tool)
    # OSV MAL-2026-4657 / GHSA-6x8j-5cx8-5qv6 (randomlogs)
    "xarc-webpack-cli": set(),
    "json-to-simple-graphql-schema": set(),
    "motion-tool": set(),
    "randomlogs": set(),
    # Dependency-confusion 9999.x batch (June 1 2026)
    # nepsnowplow: targets Snowplow Analytics internal CI; high-version shadow package.
    # picnic-react-mise-en-place: targets Picnic internal React packages in CI.
    # Detected by OpenSSF Package Analysis; specific malicious version pinned (no >=0 range).
    # OSV MAL-2026-5121 (nepsnowplow), MAL-2026-5122 (picnic-react-mise-en-place)
    "nepsnowplow": {"9999.0.0"},
    "picnic-react-mise-en-place": {"9999.0.0"},
    # @chat-template/auth GHSA full-compromise (June 1 2026)
    # Any installed version is malicious; OSV affected.ranges >=0.
    # OSV MAL-2026-5124 / GHSA-5jx8-qv7v-hv32
    "@chat-template/auth": set(),
    # rookie-security-test-pkg npm malware (June 1 2026)
    # Communicates with a domain associated with malicious activity and executes
    # commands associated with malicious behavior; detected by OpenSSF Package Analysis.
    # Single version published; specific version pinned (no >=0 range in OSV record).
    # OSV MAL-2026-5132
    "rookie-security-test-pkg": {"1.0.0"},
    # Dependency-confusion 99.x batch (June 2 2026)
    # @aonunited/angular: high-version (99.0.1) shadow package targeting AON United's
    #   internal Angular component library in CI; detected by OpenSSF Package Analysis
    #   communicating with a domain associated with malicious activity.
    #   OSV MAL-2026-5150
    # @att-ebiz/abs-components-bc: high-version (99.9.1) shadow package targeting AT&T
    #   eBusiness ABS Components BC library in CI; same detection pattern.
    #   OSV MAL-2026-5153
    "@aonunited/angular": {"99.0.1"},
    "@att-ebiz/abs-components-bc": {"99.9.1"},
    # Scandinavian telecom dep-confusion npm cluster (June 2 2026)
    # Actor debating0166 published four packages to the public registry using inflated version
    # numbers (99.0.x) to override private packages used by Telenor SE, Ownit, Customer 360
    # (C360), and TSE Digital. No prior legitimate versions exist; SEMVER >=0 range in all four
    # OSV records — use empty-set wildcard.
    # OSV MAL-2026-5154 (@customer-threesixty/assets), MAL-2026-5155 (@ownit/core),
    # MAL-2026-5156 (@telenor-se/core), MAL-2026-5157 (@tse-digital/core)
    "@customer-threesixty/assets": set(),
    "@ownit/core": set(),
    "@telenor-se/core": set(),
    "@tse-digital/core": set(),
    # Dep-confusion 99.x npm batch (June 2 2026)
    # Three packages detected by OpenSSF Package Analysis communicating with domains
    # associated with malicious activity and executing malicious commands.
    # page-info-service and po-ops-local-dev use version 99.9.1 (high-version shadow pattern).
    # sourceflow-tracker uses version 99.91.9; same detection pattern.
    # OSV MAL-2026-5158 (page-info-service), MAL-2026-5159 (po-ops-local-dev),
    # MAL-2026-5166 (sourceflow-tracker)
    "page-info-service": {"99.9.1"},
    "po-ops-local-dev": {"99.9.1"},
    "sourceflow-tracker": {"99.91.9"},
    # vg-interaction-model dep-confusion (June 2 2026; updated June 3 2026)
    # Detected by OpenSSF Package Analysis executing malicious commands; high-version shadow
    # packages (40.0.1, 40.0.4) typical of dep-confusion attacks. Both versions communicate
    # with a domain associated with malicious activity and execute malicious commands.
    # OSV MAL-2026-5168
    "vg-interaction-model": {"40.0.1", "40.0.4"},
    # chai-parse Chai typosquat (June 2 2026)
    # GHSA-confirmed any-version malware: "Any computer that has this package installed or
    # running should be considered fully compromised." OSV affected.ranges >=0 — use
    # the empty-set wildcard so any re-uploaded version is caught.
    # OSV MAL-2026-5169
    "chai-parse": set(),
    # fundraiserserv npm malware (June 3 2026)
    # Detected by OpenSSF Package Analysis communicating with a domain associated with
    # malicious activity. Single malicious version pinned (no >=0 range in OSV record).
    # OSV MAL-2026-5172
    "fundraiserserv": {"1.0.0"},
    # nodemon-pack / webpack-json npm typosquats (June 3 2026)
    # Full-compromise typosquats (of nodemon and webpack); GHSA flags any installed
    # version as fully malicious. SEMVER >=0 range in OSV — use empty-set wildcard.
    # OSV MAL-2026-5174 / GHSA-pqxq-jw84-3x8f (nodemon-pack)
    # OSV MAL-2026-5175 / GHSA-69hx-wrc9-h5wq (webpack-json)
    "nodemon-pack": set(),
    "webpack-json": set(),
    # chai-midpatch / nodemon-webpatch npm full-compromise typosquats (June 3 2026)
    # Both carry SEMVER >=0 range: "Any computer that has this package installed or
    # running should be considered fully compromised." chai-midpatch continues the
    # Chai-typosquat campaign (cf. chai-parse); nodemon-webpatch continues the
    # nodemon-typosquat wave (cf. nodemon-pack).
    # OSV MAL-2026-5179 / GHSA-qq87-jvv3-6c7r (chai-midpatch)
    # OSV MAL-2026-5180 / GHSA-q398-93fh-ghmj (nodemon-webpatch)
    "chai-midpatch": set(),
    "nodemon-webpatch": set(),
    # brave-search-mcp-server npm malware (June 3 2026)
    # Communicates with a domain associated with malicious activity and executes
    # commands associated with malicious behavior; detected by OpenSSF Package
    # Analysis. Single version published; specific version pinned (no >=0 range).
    # OSV MAL-2026-5182
    "brave-search-mcp-server": {"1.0.0"},
    # June 4 2026 npm full-compromise batch (ghsa-malware source)
    # Three packages reported via GitHub Advisory Database automated malware detection.
    # All three carry SEMVER >=0 range ("any installed version fully compromised");
    # no specific versions enumerated by the reporters.
    # @jagreehal/workflow: obscure workflow-automation package; SEMVER >=0.
    #   OSV MAL-2026-5185 / GHSA-6w7v-23mf-65g3
    "@jagreehal/workflow": set(),
    # autotel-terminal: terminal-utility package; SEMVER >=0.
    #   OSV MAL-2026-5186 / GHSA-cw9v-v9rh-r449
    "autotel-terminal": set(),
    # supabase (npm): the official Supabase CLI. Advisory was filed on June 4 2026
    # (the same day version 2.105.0 was published from the supabase/cli GitHub Actions
    # pipeline). GHSA source, single reporter, SEMVER >=0 — no specific compromised
    # version enumerated. Gate: active OSV MAL record, not withdrawn.
    # OSV MAL-2026-5187 / GHSA-x96m-c5fj-q75c
    "supabase": set(),
    # IronWorm supply-chain campaign (June 4 2026) — WeaveDB / Arweave ecosystem
    # A Rust-compiled 976 KB ELF x86-64 binary (sha256
    # 36abd242ddaa27f0160c539377a0e92cf781c1695137850acc87e3892b436d36) is shipped
    # inside npm tarballs and executed automatically via preinstall hooks on
    # `npm install`. The binary harvests developer credentials: cloud provider keys,
    # SSH key material, npm auth tokens, and crypto wallet keystores, then exfiltrates
    # them over HTTP. Targets the WeaveDB decentralised-database ecosystem and related
    # Arweave / blockchain developer tooling. JFrog calls it "Shai-Hulud's rustier
    # cousin"; OX Security confirmed the campaign independently with identical version lists.
    # Two independent vendor writeups agree on the full version list:
    #   OX Security ox.security/blog/ironworm-supply-chain-malware-hits-npm/
    #   JFrog       research.jfrog.com/post/iron-worm-shai-hulud-rustier-cousin/
    # OSV MAL-2026-4476 (ai3), 4480 (aonote), 4482 (arnext), 4483 (arnext-arkb),
    # 4486 (atomic-notes), 4538 (create-arnext-app), 4544 (cwao), 4545 (cwao-tools),
    # 4546 (cwao-units), 4566 (fpjson-lang), 4613 (monade), 4663 (roidjs),
    # 4689 (test-ajs), 4690 (test-weavedb-sdk), 4691 (testnpmnmp), 4711 (wao),
    # 4712 (warp-contracts-plugin-deploy-test), 4713 (wdb-cli), 4714 (wdb-sdk),
    # 4715 (weavedb-base), 4716 (weavedb-client), 4717 (weavedb-console),
    # 4718 (weavedb-exm-sdk), 4719 (weavedb-exm-sdk-web), 4720 (weavedb-lite),
    # 4721 (weavedb-node-client), 4722 (weavedb-offchain), 4723 (weavedb-sdk),
    # 4724 (weavedb-sdk-base), 4725 (weavedb-sdk-node), 4726 (weavedb-tools),
    # 4727 (weavedb-warp-contracts-plugin-deploy), 4739 (zkjson),
    # 5189 (arjson), 5190 (hbsig), 5191 (wdb-core), 5192 (weavedb-contracts)
    "ai3": {"0.3.5"},
    "aonote": {"0.11.1"},
    "arnext": {"0.1.5"},
    "arnext-arkb": {"0.0.2"},
    "atomic-notes": {"0.5.3"},
    "create-arnext-app": {"0.0.10"},
    "cwao": {"0.5.6"},
    "cwao-tools": {"0.3.1"},
    "cwao-units": {"0.8.3"},
    "fpjson-lang": {"0.1.7"},
    "monade": {"0.0.7"},
    "roidjs": {"0.1.7"},
    "test-ajs": {"0.1.19"},
    "test-weavedb-sdk": {"1.1.1"},
    "testnpmnmp": {"1.0.21"},
    "wao": {"0.41.2", "0.41.3", "0.41.4"},
    "warp-contracts-plugin-deploy-test": {"3.0.1"},
    "wdb-cli": {"0.1.1"},
    "wdb-sdk": {"0.1.2"},
    "weavedb-base": {"0.45.3"},
    "weavedb-client": {"0.45.3"},
    "weavedb-console": {"0.2.1"},
    "weavedb-exm-sdk": {"0.7.4"},
    "weavedb-exm-sdk-web": {"0.7.4"},
    "weavedb-lite": {"0.1.1"},
    "weavedb-node-client": {"0.45.3"},
    "weavedb-offchain": {"0.45.4"},
    "weavedb-sdk": {"0.45.3"},
    "weavedb-sdk-base": {"0.21.1"},
    "weavedb-sdk-node": {"0.45.3"},
    "weavedb-tools": {"0.45.3"},
    "weavedb-warp-contracts-plugin-deploy": {"1.0.11"},
    "zkjson": {"0.8.5"},
    "arjson": {"0.1.4"},
    "hbsig": {"0.3.2"},
    "wdb-core": {"0.1.2"},
    "weavedb-contracts": {"0.45.2"},
    # hello244a npm malware (June 4 2026)
    # Communicates with a domain associated with malicious activity and executes
    # commands associated with malicious behavior; detected by OpenSSF Package Analysis.
    # OSV MAL-2026-5188
    "hello244a": {"1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4"},
    # IronWorm supplemental packages (June 5 2026)
    # Additional npm packages in the IronWorm campaign carrying the same Rust-compiled
    # x86-64 ELF preinstall dropper that exfiltrates cloud keys, SSH material, npm tokens,
    # and crypto wallet keystores. These impersonate widely-used JavaScript utility libraries
    # (js-yaml, crypto-js, Microsoft Application Insights, Supabase client, etc.).
    # Two independent vendors confirm the same package list and campaign attribution:
    #   OX Security ox.security/blog/ironworm-supply-chain-malware-hits-npm/
    #   JFrog       research.jfrog.com/post/iron-worm-shai-hulud-rustier-cousin/
    # auth-javascript:                   OSV MAL-2026-3648 (SEMVER >=0 — any version)
    # iceberg-javascript:                OSV MAL-2026-3649 (SEMVER >=0 — any version)
    # microsoft-applicationinsights-common: OSV MAL-2026-3650 (SEMVER >=0 — any version)
    # ms-graph-types:                    OSV MAL-2026-3651 (SEMVER >=0 — any version)
    # supabase-javascript:               OSV MAL-2026-3652 (SEMVER >=0 — any version)
    # crypto-javascri:                   OSV MAL-2026-3508 (15 specific versions; no >=0 range)
    # crypto-javascript:                 OSV MAL-2026-4542 (5 specific versions; no >=0 range)
    # javascript-yaml:                   OSV MAL-2026-5193 (1 specific version; no >=0 range)
    # yaml-javascript:                   OSV MAL-2026-5194 (1 specific version; no >=0 range)
    "auth-javascript": set(),
    "iceberg-javascript": set(),
    "microsoft-applicationinsights-common": set(),
    "ms-graph-types": set(),
    "supabase-javascript": set(),
    "crypto-javascri": {
        "1.0.1", "1.2.1", "1.2.6", "1.2.8", "1.2.10", "1.2.11", "1.2.12",
        "1.3.6", "1.3.7", "1.4.1", "1.4.2", "1.4.3", "1.4.4", "1.4.5", "3.0.1",
    },
    "crypto-javascript": {"4.2.5", "4.2.10", "4.3.1", "4.3.4", "4.3.6"},
    "javascript-yaml": {"4.1.2"},
    "yaml-javascript": {"4.1.2"},
    # binding.gyp npm worm campaign (June 5 2026) — multiple publisher accounts compromised
    # A worm-style attack exploiting binding.gyp (native Node.js build files) to spread
    # across packages during npm install. Initial discovery: ai-sdk-ollama. The worm
    # spread to packages from many independent publishers: autotel, awaitly,
    # executable-stories, node-env-resolver, @ethlete, @forjacms, @vapi-ai, and others.
    # These are legitimate packages where specific versions were infected; pin exact
    # versions (not empty-set wildcards). Two independent sources agree on version lists:
    #   StepSecurity stepsecurity.io/blog/binding-gyp-npm-supply-chain-attack-spreads-like-worm
    #   Endor Labs   endorlabs.com/learn/malicious-payload-in-ai-sdk-ollama-npm-package
    #   OSV MAL-2026-5195 through MAL-2026-5267
    # ai-sdk-ollama — initial discovery (OSV MAL-2026-5210)
    "ai-sdk-ollama": {"0.13.1", "1.1.1", "2.2.1", "3.8.5"},
    # @contaazul/n8n-nodes-contaazul (OSV MAL-2026-5195)
    "@contaazul/n8n-nodes-contaazul": {"0.3.26"},
    # @ethlete Angular component library scope — account compromise
    # OSV MAL-2026-5196 (@ethlete/cdk), 5197 (cli), 5198 (components),
    # 5199 (contentful), 5200 (core), 5201 (dsp), 5202 (query), 5203 (theming), 5204 (types)
    "@ethlete/cdk": {"4.71.2"},
    "@ethlete/cli": {"2.0.1"},
    "@ethlete/components": {"3.3.1"},
    "@ethlete/contentful": {"3.9.1"},
    "@ethlete/core": {"4.31.1"},
    "@ethlete/dsp": {"0.3.1"},
    "@ethlete/query": {"5.43.2"},
    "@ethlete/theming": {"2.7.1"},
    "@ethlete/types": {"1.11.4"},
    # @forjacms CMS scope compromise
    # OSV MAL-2026-5205 (analytics), 5206 (client), 5207 (sections), 5208 (sections-react)
    "@forjacms/analytics": {"1.8.4", "1.8.5"},
    "@forjacms/client": {"1.8.4", "1.8.5"},
    "@forjacms/sections": {"1.8.4", "1.8.5"},
    "@forjacms/sections-react": {"1.8.4", "1.8.5"},
    # @vapi-ai voice API SDK compromise (OSV MAL-2026-5209)
    "@vapi-ai/server-sdk": {"0.11.1", "0.11.2", "1.2.1", "1.2.2"},
    # autotel OpenTelemetry wrapper ecosystem
    # OSV MAL-2026-5211 (autotel), 5212 (adapters), 5213 (audit), 5214 (aws),
    # 5215 (backends), 5216 (cli), 5217 (cloudflare), 5218 (devtools), 5219 (drizzle),
    # 5220 (edge), 5221 (eventcatalog), 5222 (hono), 5223 (mcp), 5224 (mcp-instrumentation),
    # 5225 (mongoose), 5226 (pact), 5227 (playwright), 5228 (plugins), 5229 (sentry),
    # 5230 (subscribers), 5231 (tanstack), 5232 (vitest), 5233 (web)
    "autotel": {"2.26.4", "3.4.3"},
    "autotel-adapters": {"0.3.5"},
    "autotel-audit": {"0.1.15"},
    "autotel-aws": {"0.13.10"},
    "autotel-backends": {"2.12.26"},
    "autotel-cli": {"0.8.14"},
    "autotel-cloudflare": {"2.18.16"},
    "autotel-devtools": {"0.1.1", "1.0.4", "2.1.1", "3.0.2", "4.0.1", "5.1.1", "6.1.2", "6.2.0"},
    "autotel-drizzle": {"0.0.27"},
    "autotel-edge": {"3.16.13"},
    "autotel-eventcatalog": {"1.0.1", "2.0.1", "3.0.1", "4.0.2", "5.0.1"},
    "autotel-hono": {"0.4.26"},
    "autotel-mcp": {
        "0.1.14", "2.0.1", "3.0.1", "4.0.1", "5.0.1", "6.0.1", "7.0.1", "8.0.1",
        "9.0.1", "10.0.1", "11.0.1", "13.0.1", "14.0.1", "15.0.2", "16.0.1",
        "17.0.2", "18.0.1", "19.0.1", "20.0.1", "21.1.1", "22.0.1", "23.0.1",
        "24.0.1", "25.0.1", "26.0.2", "27.0.1", "28.0.3", "29.0.1",
    },
    "autotel-mcp-instrumentation": {
        "29.0.2", "30.0.5", "31.0.1", "32.0.1", "33.0.2", "34.0.1",
    },
    "autotel-mongoose": {"0.0.3", "1.0.2", "2.0.5", "3.0.1", "4.0.1", "5.0.2", "6.0.1"},
    "autotel-pact": {"0.2.2", "1.0.3"},
    "autotel-playwright": {"0.4.32"},
    "autotel-plugins": {"0.19.26"},
    "autotel-sentry": {"0.5.13"},
    "autotel-subscribers": {
        "4.1.1", "5.0.1", "6.0.1", "7.0.1", "8.0.1", "9.0.1", "10.0.1", "11.0.1",
        "12.0.1", "13.0.1", "14.1.1", "15.0.1", "16.0.2", "17.0.1", "18.0.3",
        "19.0.1", "20.0.1", "21.0.1", "22.0.2", "23.0.2", "24.0.1", "25.0.1",
        "26.0.1", "27.0.2", "28.0.2", "29.0.6", "30.0.4", "31.1.4",
    },
    "autotel-tanstack": {"1.13.27"},
    "autotel-vitest": {"0.4.26"},
    "autotel-web": {"1.12.2"},
    # awaitly async library ecosystem
    # OSV MAL-2026-5234 (awaitly), 5235 (analyze), 5236 (libsql),
    # 5237 (mongo), 5238 (postgres), 5239 (visualizer)
    "awaitly": {"1.33.3"},
    "awaitly-analyze": {"0.24.2", "1.1.1", "2.0.1", "3.0.1", "4.0.1", "5.0.1", "6.0.1", "7.0.1", "8.0.1"},
    "awaitly-libsql": {
        "0.1.1", "1.0.1", "2.0.1", "3.0.1", "4.0.1", "5.0.1", "6.0.1", "7.0.1",
        "8.0.1", "9.0.1", "10.0.1", "11.0.1", "12.0.1", "13.0.1", "14.0.1",
        "15.0.1", "16.0.1", "17.0.1", "18.1.1", "19.0.1", "20.0.1", "21.0.1", "22.0.1",
    },
    "awaitly-mongo": {
        "0.1.1", "1.0.1", "2.0.1", "3.0.1", "4.0.1", "5.0.1", "6.0.1", "7.0.1",
        "8.0.1", "9.1.1", "10.0.1", "11.0.1", "12.0.1", "13.0.1", "14.0.1",
        "15.0.1", "16.0.1", "17.0.1", "18.0.1", "19.1.1", "20.0.1", "21.0.1",
        "22.0.1", "23.0.1",
    },
    "awaitly-postgres": {
        "0.1.1", "1.0.1", "2.0.1", "3.0.2", "4.0.1", "5.0.1", "6.0.1", "7.0.1",
        "8.0.1", "9.0.1", "10.0.1", "11.0.1", "12.0.1", "13.0.1", "14.0.1",
        "15.0.1", "16.0.1", "17.0.1", "18.0.1", "19.1.1", "20.0.1", "21.0.1",
        "22.0.1", "23.0.1",
    },
    "awaitly-visualizer": {
        "1.0.1", "2.0.2", "3.0.1", "4.0.1", "5.0.1", "6.0.1", "7.0.1", "8.0.1",
        "9.0.1", "10.0.1", "11.0.1", "12.0.1", "13.0.1", "14.0.1", "15.0.1",
        "16.0.1", "17.0.1", "18.1.1", "19.0.1", "20.0.2", "21.0.1", "22.0.2",
    },
    # executable-stories testing framework + awaitly eslint ecosystem
    # OSV MAL-2026-5246 (eslint-plugin-awaitly), 5247 (eslint-plugin-executable-stories-jest),
    # 5248 (eslint-plugin-executable-stories-playwright), 5249 (eslint-plugin-executable-stories-vitest),
    # 5250 (executable-stories-cypress), 5251 (demo), 5252 (formatters), 5253 (init),
    # 5254 (jest), 5255 (mcp), 5256 (playwright), 5257 (react), 5258 (vitest)
    "eslint-plugin-awaitly": {"0.17.1", "1.0.1"},
    "eslint-plugin-executable-stories-jest": {"1.2.1", "2.1.8"},
    "eslint-plugin-executable-stories-playwright": {"1.2.1", "2.1.8"},
    "eslint-plugin-executable-stories-vitest": {"1.2.1", "2.1.8"},
    "executable-stories-cypress": {"3.1.1", "4.0.1", "5.0.1", "6.1.1", "7.0.3", "8.3.2"},
    "executable-stories-demo": {"0.1.11"},
    "executable-stories-formatters": {"0.11.2"},
    "executable-stories-init": {"0.1.2"},
    "executable-stories-jest": {"3.1.1", "4.0.1", "5.0.1", "6.1.1", "7.0.3", "8.3.2"},
    "executable-stories-mcp": {"0.3.3"},
    "executable-stories-playwright": {"3.1.1", "4.0.1", "5.0.1", "6.1.1", "7.0.3", "8.4.3"},
    "executable-stories-react": {"0.1.7"},
    "executable-stories-vitest": {"2.0.1", "3.1.1", "4.0.1", "5.0.1", "6.1.1", "7.0.3", "8.3.3"},
    # node-env-resolver environment variable library ecosystem
    # OSV MAL-2026-5262 (node-env-resolver), 5263 (aws), 5264 (dotenvx), 5265 (nextjs), 5266 (vite)
    "node-env-resolver": {"6.5.1"},
    "node-env-resolver-aws": {"9.1.2", "10.0.1", "11.0.1", "12.0.1"},
    "node-env-resolver-dotenvx": {"1.0.1", "2.0.1"},
    "node-env-resolver-nextjs": {"7.4.2"},
    "node-env-resolver-vite": {"2.4.2"},
    # Cloudflare Workers deployment tools
    # OSV MAL-2026-5240 (create-cf-token), 5241 (create-wrangler-deploy), 5267 (wrangler-deploy)
    "create-cf-token": {"1.1.2", "1.1.3"},
    "create-wrangler-deploy": {"0.1.1"},
    "wrangler-deploy": {"1.5.5"},
    # Miscellaneous packages from the binding.gyp worm campaign
    # OSV MAL-2026-5242 (creditcard.js), 5243 (dbmux), 5244 (discord-search),
    # 5245 (effect-analyzer), 5259 (github-archiver), 5260 (mountly), 5261 (mountly-tailwind)
    "creditcard.js": {"2.1.8", "3.0.60"},
    "dbmux": {"1.0.5"},
    "discord-search": {"0.1.1", "0.1.2"},
    "effect-analyzer": {"0.3.1"},
    "github-archiver": {"1.5.4", "1.5.5"},
    "mountly": {"0.2.2"},
    "mountly-tailwind": {"0.1.3"},
    # ulid-os npm full-compromise typosquat (June 5 2026)
    # GHSA-confirmed any-version malware: "Any computer that has this package installed or
    # running should be considered fully compromised." OSV affected.ranges >=0 — use
    # the empty-set wildcard so any re-uploaded version is caught.
    # OSV MAL-2026-5268 / GHSA-fxhm-35h8-7jc7
    "ulid-os": set(),
    # utils-mf npm WhatsApp-bot + data-exfiltration + silent self-updater (June 5 2026)
    # Ships a 15.7 MB obfuscator.io blob padded with invisible Unicode whitespace to
    # conceal its contents.  On require() it: (1) opens a WhatsApp socket that prompts
    # on stdin for a pairing-code phone number and persists credential state in ./sessions/;
    # (2) runs a 30-second setInterval that PUTs accumulated chat/contact/env state to the
    # attacker's GitHub and GitLab repos; (3) fetches the latest tarball from the npm
    # registry and silently overwrites node_modules/utils-mf/ at runtime to enable
    # remote payload updates without a reinstall.  First published May 21 2026; GHSA alias
    # confirmed June 5 2026 by amazon-inspector.  No >=0 range in OSV — pin exact versions.
    # OSV MAL-2026-4699 / GHSA-4c54-hwv9-c5xm
    "utils-mf": {
        "11.2.4", "11.2.5", "11.2.6", "11.4.1",
        "11.9.8", "11.9.9", "12.0.1", "12.0.2", "12.1.0", "12.1.1",
    },
    # react-ui-polyfills remote-eval backdoor (June 5 2026)
    # Advertises itself as React polyfills / UI compatibility helpers but ships no React
    # or polyfill code.  The exported getPlugin() function fetches JSON from a mutable
    # jsonkeeper.com paste URL and passes the returned .cookie field directly to eval(),
    # executing attacker-controlled JavaScript in the consumer's process.  First published
    # May 26 2026; GHSA alias confirmed June 5 2026.  OSV has both specific versions (1.0.0,
    # 1.2.7) and a >=0 SEMVER range — per convention the whole package is malicious; use
    # the empty-set wildcard.
    # OSV MAL-2026-4784 / GHSA-v7mj-pmr3-7x4p
    "react-ui-polyfills": set(),
    # June 5 2026 GHSA full-compromise npm pair
    # glyphr: GHSA-confirmed any-version; CWE-506 embedded malicious code.
    #   OSV MAL-2026-5269 / GHSA-c988-j68q-h8h4
    # reactvora: GHSA-confirmed any-version; CWE-506 embedded malicious code.
    #   OSV MAL-2026-5270 / GHSA-x4gw-cjrp-c89f
    "glyphr": set(),
    "reactvora": set(),
    # Dep-confusion 99.x npm batch (June 6 2026)
    # Four packages published at version 99.0.0 detected by OpenSSF Package Analysis
    # communicating with a domain associated with malicious activity. High-version
    # shadow pattern typical of dependency-confusion attacks targeting private CI pipelines.
    # OSV MAL-2026-5286 (encrypted-archive), MAL-2026-5287 (uhd-setup),
    # MAL-2026-5288 (uisp-connector), MAL-2026-5289 (unifi-portal)
    "encrypted-archive": {"99.0.0"},
    "uhd-setup": {"99.0.0"},
    "uisp-connector": {"99.0.0"},
    "unifi-portal": {"99.0.0"},
    # sequoia-engineering npm malware (June 7 2026)
    # Communicates with a domain associated with malicious activity;
    # detected by OpenSSF Package Analysis. Single version published.
    # OSV MAL-2026-5291
    "sequoia-engineering": {"2.2.2"},
    # consumerweb-authflow npm malware (June 7 2026)
    # Communicates with a domain associated with malicious activity;
    # detected by OpenSSF Package Analysis. Two versions published.
    # OSV MAL-2026-5297
    "consumerweb-authflow": {"4.1.1", "4.1.3"},
    # @langgraphjs/toolkit npm any-version wildcard (MAL-2026-2509)
    # Pure-malware typosquat of LangGraph's JavaScript toolkit; OSV record
    # contains SEMVER >=0 range (any-version) plus specific versions 1.2.10/1.2.11.
    # Per convention the entire package is treated as malicious.
    "@langgraphjs/toolkit": set(),
    # @listings/energy-labels + @zimmo/last_search dep-confusion (June 8 2026)
    # Both packages published at high version 99.0.x; no legitimate public history.
    # OSV MAL-2026-5327 (@listings/energy-labels), 5328 (@zimmo/last_search)
    "@listings/energy-labels": {"99.0.0", "99.0.1"},
    "@zimmo/last_search": {"99.0.0", "99.0.1"},
    # @bancolonbia/menu-filter-widget-web dep-confusion (June 8 2026)
    # Published at version 0.0.1 with malicious payload; targets BanColombia
    # internal CI. OSV MAL-2026-5344.
    "@bancolonbia/menu-filter-widget-web": {"0.0.1"},
    # @demica/* dep-confusion cluster (June 8 2026)
    # Three packages targeting Demica trade-finance internal CI; published at
    # inflated 99.99.x versions. OSV MAL-2026-5349/5350/5351.
    "@demica/core": {"99.99.99", "99.99.100"},
    "@demica/resources": {"99.99.100"},
    "@demica/shared": {"99.99.100"},
    # @doaction/* dep-confusion cluster (June 8 2026)
    # Fifteen packages targeting internal DoAction/banking CI infrastructure.
    # Published at high versions (9.9.9 / 99.99.99); some with no specific
    # versions recorded (OSV >=0 range). OSV MAL-2026-5369 through 5383.
    "@doaction/auth": {"99.99.99"},
    "@doaction/eventemitter": {"9.9.9"},
    "@doaction/example": set(),
    "@doaction/examples": {"99.99.99"},
    "@doaction/http": {"9.9.9", "99.99.99"},
    "@doaction/mapstore": {"9.9.9", "99.99.99"},
    "@doaction/pay": {"9.9.9", "99.99.99"},
    "@doaction/rrweb-sdk": {"9.9.9", "99.99.99"},
    "@doaction/shared": {"9.9.9", "99.99.99"},
    "@doaction/signalhub": {"9.9.9"},
    "@doaction/storage": {"9.9.9", "99.99.99"},
    "@doaction/sudo-prompt": set(),
    "@doaction/systeminformation": {"9.9.9"},
    "@doaction/types": {"9.9.9", "99.99.99"},
    "@doaction/wasm-loader": {"9.9.9", "99.99.99"},
    # @0xlr/* dep-confusion cluster (June 8 2026)
    # Seven packages targeting a startup's internal CI; all published at 999.0.0.
    # OSV MAL-2026-5385 through 5391.
    "@0xlr/clerk-auth": {"999.0.0"},
    "@0xlr/prisma-client-js": {"999.0.0"},
    "@0xlr/sentry-web": {"999.0.0"},
    "@0xlr/stripe-checkout-js": {"999.0.0"},
    "@0xlr/stripe-frontend": {"999.0.0"},
    "@0xlr/supabase-db": {"999.0.0"},
    "@0xlr/vercel-analytics": {"999.0.0"},
    # @klapp-* / @easy-entry / @shell-* dep-confusion cluster (June 8 2026)
    # Twelve packages targeting Klapp banking-app and related internal pipelines;
    # published at 99.x versions. OSV MAL-2026-5408 through 5417, 5428/5429.
    "@easy-entry/landing-routes": {"99.9.5"},
    "@easy-entry/outside-registration-fop-navigator": {"99.9.5"},
    "@easy-entry/routes": {"99.9.5"},
    "@klapp-about/routes": {"99.0.0", "99.0.1", "99.0.2"},
    "@klapp-kyc/routes": {"99.0.0", "99.0.1"},
    "@klapp-login-platform/native-sdk": {"99.0.0", "99.0.2"},
    "@klapp-login-platform/oidc": {"99.0.0", "99.0.2"},
    "@klapp-login-platform/routes": {"99.0.0", "99.0.2"},
    "@klapp-otp/routes": {"99.0.0", "99.0.1"},
    "@klapp-sca/routes": {"99.0.0", "99.0.1"},
    "@shell-cabinet/routes": {"99.9.5"},
    "@shell-landing/routes": {"99.9.5"},
    # @nstrlabs/* dep-confusion cluster (June 8 2026)
    # Six packages targeting NstrLabs internal CI; published at 99.0.x.
    # OSV MAL-2026-5418 through 5423.
    "@nstrlabs/api-client": {"99.0.0", "99.0.1"},
    "@nstrlabs/auth": {"99.0.0", "99.0.1"},
    "@nstrlabs/ixel": {"99.0.0", "99.0.1"},
    "@nstrlabs/sdk": {"99.0.0", "99.0.1"},
    "@nstrlabs/shared-components": {"99.0.0", "99.0.1"},
    "@nstrlabs/utils": {"99.0.0", "99.0.1"},
    # @oplus/* dep-confusion cluster (June 8 2026)
    # Three packages targeting OnePlus/OPPO internal obus SDK pipeline;
    # published at 99.99.99. OSV MAL-2026-5424/5425/5426.
    "@oplus/obus-core": {"99.99.99"},
    "@oplus/obus-web-sdk": {"99.99.99"},
    "@oplus/obus-web-sdk-plugin-recovery": {"99.99.99"},
    # @orion-design-system/* dep-confusion cluster (June 11 2026)
    # Three packages targeting Orion design-system internal CI; published at
    # inflated 9999.x versions. OSV MAL-2026-5522/5523/5524.
    "@orion-design-system/components": {"9999.0.0", "9999.0.1", "9999.0.2", "9999.0.3"},
    "@orion-design-system/foundation": {
        "9999.0.0", "9999.0.1", "9999.0.2", "9999.0.3", "9999.0.4",
    },
    "@orion-design-system/store": {"9999.0.0", "9999.0.1", "9999.0.2"},
    # @solana-labs/* npm typosquat cluster (June 8–22 2026)
    # Six packages impersonating official @solana-labs tooling; each publishes
    # multiple versions carrying a credential/wallet exfiltrator payload.
    # Note: the legitimate @solana-labs/web3.js uses the exact name with a
    # period — these all use alternate spellings or names. The real package is
    # published by Anza and is not in this list.
    # OSV MAL-2026-5362 (etherjs), 5363 (web3-js), 5525 (web3.js),
    # 5786 (ancor), 5787 (spl-toke), 5788 (web3js)
    "@solana-labs/etherjs": {
        "1.0.0", "1.0.5", "1.0.6", "1.0.7", "1.0.8", "1.0.10",
    },
    "@solana-labs/web3-js": {
        "1.0.0", "1.0.5", "1.0.6", "1.0.7", "1.0.8", "1.0.10",
    },
    "@solana-labs/web3.js": {
        "1.0.0", "1.0.6", "1.0.7", "1.0.8", "1.0.10", "1.98.112",
    },
    "@solana-labs/ancor": {
        "1.0.0", "1.0.1", "1.0.7", "1.0.8", "1.0.9", "1.0.11",
    },
    "@solana-labs/spl-toke": {
        "1.0.0", "1.0.5", "1.0.6", "1.0.7", "1.0.8", "1.0.10",
    },
    "@solana-labs/web3js": {
        "1.0.0", "1.0.5", "1.0.6", "1.0.7", "1.0.8", "1.0.10",
    },
    # @403name/* npm typosquat cluster (June 12 2026)
    # Three packages impersonating popular native-build and crypto tooling;
    # each publishes versions 1.0.0 and 1.0.1 with malicious payloads.
    # OSV MAL-2026-5547 (electron-buidler), 5548 (ether-js), 5549 (fsevent)
    "@403name/electron-buidler": {"1.0.0", "1.0.1"},
    "@403name/ether-js": {"1.0.0", "1.0.1"},
    "@403name/fsevent": {"1.0.0", "1.0.1"},
    # @onum-releases/* dep-confusion cluster (June 22 2026)
    # Six packages impersonating NstrLabs (@nstrlabs) internal packages under a
    # new attacker scope; published at versions 1.0.1 through 1.0.3.
    # OSV MAL-2026-6122 through 6127.
    "@onum-releases/api-client": {"1.0.1", "1.0.2", "1.0.3"},
    "@onum-releases/auth": {"1.0.1", "1.0.2", "1.0.3"},
    "@onum-releases/ixel": {"1.0.1", "1.0.2", "1.0.3"},
    "@onum-releases/sdk": {"1.0.1", "1.0.2", "1.0.3"},
    "@onum-releases/shared-components": {"1.0.1", "1.0.2", "1.0.3"},
    "@onum-releases/utils": {"1.0.1", "1.0.2"},
    # @mastra/* npm scope compromise (June 20–27 2026)
    # 89 packages across the @mastra namespace were compromised; the attacker
    # published specific malicious versions of the Mastra AI agent framework
    # injecting a credential-exfiltration payload. The @mastra scope is also
    # added to NPM_SUSPECT_SCOPES to catch any additional undisclosed packages.
    # OSV MAL-2026-5939 through 5964, 5996 through 6057, 6072 through 6074.
    "@mastra/ai-sdk": {"1.4.6"},
    "@mastra/auth": {"1.0.3"},
    "@mastra/braintrust": {"1.1.4"},
    "@mastra/clickhouse": {"1.10.1"},
    "@mastra/datadog": {"1.2.5"},
    "@mastra/duckdb": {"1.4.3"},
    "@mastra/dynamodb": {"1.0.9"},
    "@mastra/editor": {"0.11.3"},
    "@mastra/evals": {"1.3.1"},
    "@mastra/fastembed": {"1.1.3"},
    "@mastra/fastify": {"1.3.31"},
    "@mastra/hono": {"1.4.26"},
    "@mastra/inngest": {"1.5.2"},
    "@mastra/langfuse": {"1.3.6"},
    "@mastra/langsmith": {"1.2.4"},
    "@mastra/libsql": {"1.13.1"},
    "@mastra/mcp": {"1.10.1"},
    "@mastra/mcp-docs-server": {"1.1.47"},
    "@mastra/mongodb": {"1.9.3"},
    "@mastra/otel-bridge": {"1.2.3"},
    "@mastra/pg": {"1.13.1"},
    "@mastra/posthog": {"1.0.29"},
    "@mastra/rag": {"2.2.2"},
    "@mastra/s3": {"0.5.3"},
    "@mastra/schema-compat": {"1.2.12"},
    "@mastra/sentry": {"1.1.4"},
    "@mastra/agent-browser": {"0.3.2"},
    "@mastra/agent-builder": {"1.0.42"},
    "@mastra/arize": {"1.2.3"},
    "@mastra/auth-auth0": {"1.0.2"},
    "@mastra/auth-better-auth": {"1.0.4"},
    "@mastra/auth-clerk": {"1.0.3"},
    "@mastra/auth-supabase": {"1.0.2"},
    "@mastra/auth-workos": {"1.5.3"},
    "@mastra/blaxel": {"0.4.2"},
    "@mastra/chroma": {"1.0.2"},
    "@mastra/claude": {"1.0.3"},
    "@mastra/client-js": {"1.24.1"},
    "@mastra/cloudflare": {"1.4.2"},
    "@mastra/cloudflare-d1": {"1.0.7"},
    "@mastra/convex": {"1.2.2"},
    "@mastra/core": {"1.42.1"},
    "@mastra/couchbase": {"1.0.4"},
    "@mastra/cursor": {"0.2.1"},
    "@mastra/daytona": {"0.4.2"},
    "@mastra/deployer": {"1.42.1"},
    "@mastra/deployer-cloudflare": {"1.1.44"},
    "@mastra/deployer-netlify": {"1.1.20"},
    "@mastra/deployer-vercel": {"1.1.38"},
    "@mastra/docker": {"0.3.1"},
    "@mastra/dsql": {"1.0.3"},
    "@mastra/e2b": {"0.3.4"},
    "@mastra/express": {"1.3.31"},
    "@mastra/gcs": {"0.2.3"},
    "@mastra/google-cloud-pubsub": {"1.0.6"},
    "@mastra/koa": {"1.5.14"},
    "@mastra/longmemeval": {"1.0.50"},
    "@mastra/mcp-registry-registry": {"1.0.2"},
    "@mastra/memory": {"1.20.4"},
    "@mastra/mssql": {"1.3.2"},
    "@mastra/nestjs": {"0.1.15"},
    "@mastra/otel-exporter": {"1.2.3"},
    "@mastra/pinecone": {"1.0.2"},
    "@mastra/playground-ui": {"33.0.1"},
    "@mastra/qdrant": {"1.0.3"},
    "@mastra/s3vectors": {"1.0.7"},
    "@mastra/server": {"2.1.1"},
    "@mastra/stagehand": {"0.2.5"},
    "@mastra/tavily": {"1.0.3"},
    "@mastra/temporal": {"0.1.14"},
    "@mastra/turbopuffer": {"1.0.3"},
    "@mastra/upstash": {"1.1.3"},
    "@mastra/vectorize": {"1.0.3"},
    "@mastra/voice-aws-nova-sonic": {"0.1.4"},
    "@mastra/voice-deepgram": {"0.12.2"},
    "@mastra/voice-elevenlabs": {"0.12.2"},
    "@mastra/voice-google": {"0.12.3"},
    "@mastra/voice-google-gemini-live": {"0.12.2"},
    "@mastra/voice-openai": {"0.12.3"},
    "@mastra/voice-openai-realtime": {"0.12.6"},
    "@mastra/github-signals": {"0.1.2"},
    "@mastra/mem0": {"0.1.14"},
    "@mastra/node-audio": {"0.1.8"},
    "@mastra/node-speaker": {"0.1.1"},
    "@mastra/react": {"1.0.1"},
    "@mastra/voice-playai": {"0.12.2"},
    "@mastra/loggers": {"1.1.3"},
    "@mastra/observability": {"1.14.2"},
    "@mastra/redis": {"1.1.3"},
    # Gartner gx-npm dep-confusion cluster (June 25 2026)
    # Three internal Gartner npm packages published at 99.99.99 via dependency confusion;
    # no legitimate public release history. GHSA-hhw7-23r7-qwj7 / GHSA-wcmr-4783-pq3p /
    # GHSA-5jpv-9x2f-72jj. OSV MAL-2026-6466, MAL-2026-6480, MAL-2026-6481.
    "gx-npm-feature-flags": set(),
    "gx-npm-lib": set(),
    "gx-npm-ui": set(),
    # @vpms/design-system dep-confusion (June 25 2026)
    # Private-scope package published at inflated versions (0.1.3, 1.0.x, 1.1.2) via
    # dependency confusion. GHSA-43r2-9cx9-pv7f. OSV MAL-2026-6467.
    "@vpms/design-system": set(),
    # Crossmint wallets-sdk typosquat cluster (June 25–27 2026)
    # crossmint-wallets-sdk: flat typosquat of the legitimate @crossmint/wallets-sdk.
    # @epsteinlovekids483/crossmint-wallets-sdk-pentest: attacker-controlled scope
    # with multiple pentest-labeled versions impersonating Crossmint.
    # GHSA-7rfm-v32j-2583, GHSA-x7jg-w433-8q2r. OSV MAL-2026-6545, MAL-2026-6522.
    "crossmint-wallets-sdk": set(),
    "@epsteinlovekids483/crossmint-wallets-sdk-pentest": set(),
    # ts-einkle / ts-ankle cluster (June 26–27 2026)
    # Three related typosquat packages with credential-exfiltration payloads.
    # GHSA-mjcv-m7fg-mg8j (ts-einkle), GHSA-8cxx-rp6g-mcr9 (ts-einkle-slot),
    # GHSA-992p-988h-h55j (ts-ankle). OSV MAL-2026-6524, MAL-2026-6525, MAL-2026-6548.
    "ts-einkle": set(),
    "ts-einkle-slot": set(),
    "ts-ankle": set(),
    # react-dynammic-table-component typosquat (June 26 2026)
    # Version 1.2.7 only; typosquat of react-dynamic-table-component with injected
    # postinstall payload. OSV MAL-2026-6534.
    "react-dynammic-table-component": {"1.2.7"},
    # Miscellaneous malware batch (June 27–29 2026)
    # claude-cup: pure-malware typosquat impersonating Claude CLI tooling.
    # chai-as-persisted: Chai test-framework plugin typosquat with infostealer payload.
    # ryan-pdf-js: dep-confusion dropper at 99.9.1.
    # @k18n/creatormarketplace-admin-language: dep-confusion at 99.0.0.
    # anthropic-internal-tools: fake Anthropic internal package, credential exfiltrator.
    # livekit-agents: npm typosquat of @livekit/agents with malicious postinstall.
    # lc-chatbot: chatbot malware package, version 0.9.0-rc.0.
    # react-editable-calendar: malicious React calendar component.
    # polymarket-clob-math: Polymarket CLOB typosquat with crypto-stealer payload.
    # OSV MAL-2026-5789 (claude-cup), MAL-2026-6544 (chai-as-persisted),
    # MAL-2026-6546 (ryan-pdf-js), MAL-2026-6550 (@k18n/creatormarketplace-admin-language),
    # MAL-2026-6551 (anthropic-internal-tools), MAL-2026-6555 (livekit-agents),
    # MAL-2026-6559 (lc-chatbot), MAL-2026-6547 (react-editable-calendar),
    # MAL-2026-6556 (polymarket-clob-math).
    "claude-cup": set(),
    "chai-as-persisted": set(),
    "ryan-pdf-js": set(),
    "@k18n/creatormarketplace-admin-language": set(),
    "anthropic-internal-tools": set(),
    "livekit-agents": set(),
    "lc-chatbot": {"0.9.0-rc.0"},
    "react-editable-calendar": set(),
    "polymarket-clob-math": set(),
    # insomnia m4gester test-malware cluster (June 28 2026)
    # Three packages under the "m4gester" identity published as Insomnia plugin/util
    # stubs with credential-exfiltration postinstall scripts.
    # OSV MAL-2026-6552 (insomnia-plugin-poc-m4gester),
    # MAL-2026-6553 (insomnia-plugin-poc-m4gester2),
    # MAL-2026-6554 (insomnia-test-util-m4gester).
    "insomnia-plugin-poc-m4gester": set(),
    "insomnia-plugin-poc-m4gester2": set(),
    "insomnia-test-util-m4gester": set(),
    # AI/LLM toolkit impersonation campaign (June 29–30 2026)
    # Packages impersonating popular AI SDK toolkits with postinstall credential-exfiltration
    # payloads. All are pure-malware typosquats with no legitimate use.
    # anthropic-toolkit: fake Anthropic developer toolkit; 21 specific versions published.
    #   OSV MAL-2026-6673.
    # ai-sdk-helpers: fake AI SDK helper library; any version is malicious
    #   (ranges: introduced 0). OSV MAL-2026-5565.
    # ollama-helpers: fake Ollama integration library; any version is malicious.
    #   OSV MAL-2026-6581.
    # openai-agents-helpers: fake OpenAI Agents SDK helper; any version is malicious.
    #   OSV MAL-2026-6582.
    "anthropic-toolkit": {
        "0.1.0", "0.1.1", "0.2.0", "0.2.1", "0.3.0", "0.3.1", "0.4.0", "0.4.1",
        "0.5.0", "0.5.1", "0.6.0", "0.7.0", "0.8.0", "0.9.0", "1.0.0", "1.0.1",
        "1.1.0", "1.1.1", "1.2.0", "1.2.1", "1.3.0",
    },
    "ai-sdk-helpers": set(),
    "ollama-helpers": set(),
    "openai-agents-helpers": set(),
    # ts-einkle/ts-ankle TypeScript runtime exploit cluster (June 29 2026)
    # Packages mimicking TypeScript utility libraries with postinstall exfiltration.
    # All have SEMVER ranges: introduced 0 (any version is malicious).
    # OSV MAL-2026-6524 (ts-einkle), MAL-2026-6525 (ts-einkle-slot), MAL-2026-6548 (ts-ankle).
    "ts-einkle": set(),
    "ts-einkle-slot": set(),
    "ts-ankle": set(),
    # @thone33 attacker-scope credential injector (June 29 2026)
    # Two packages published under the @thone33 scope with postinstall analytics/core
    # facades hiding credential-exfiltration payloads.
    # OSV MAL-2026-6563 (@thone33/analytics-injector), MAL-2026-6564 (@thone33/core-utils).
    "@thone33/analytics-injector": set(),
    "@thone33/core-utils": set(),
    # @epic-common/observability-node backdoor (June 29 2026)
    # Dependency-confusion or typosquat targeting the Epic Games common library scope.
    # OSV MAL-2026-6562.
    "@epic-common/observability-node": set(),
    # Targeted dep-confusion packages (June 29 2026)
    # Company-specific packages published at inflated version numbers (99.x / 9999.x)
    # to hijack internal dependency resolution in CI/CD pipelines.
    # All have SEMVER ranges: introduced 0 and are pure-malware with no legitimate releases.
    # OSV MAL-2026-2822 (ing-web-v5), MAL-2026-2846 (eslint-plugin-totara),
    # MAL-2026-2855 (react-resource-router-next), MAL-2026-2856 (@ataslkit/profilecard),
    # MAL-2026-2857 (@shoobx/types), MAL-2026-2858 (@source-row/source-container),
    # MAL-2026-2952 (@settle-sea/supporting-documents), MAL-2026-2956 (@serasa/core),
    # MAL-2026-2978 (@oec-settlement/react-router),
    # MAL-2026-4171 (@mc-xp/mc-monolith-js-src-package),
    # MAL-2026-4172 (@piewasm/pie-web-npm-package),
    # MAL-2026-4256 (@citi-icg-171632/citicms-repo-component),
    # MAL-2026-4257 (@cloudways-lab/unified-design-system),
    # MAL-2026-4389 (@flipbit2-bb/test-auth-state),
    # MAL-2026-4425 (@riskine-frontend/design-elements),
    # MAL-2026-4432 (@sec-loans-ui/utils), MAL-2026-4826 (wm-mapper),
    # MAL-2026-4827 (unleash-js),
    # MAL-2026-5431 (@webd-infra/query-designer-domain),
    # MAL-2026-5432 (@webda-features/dashboard), MAL-2026-5433 (@webda-infra/search),
    # MAL-2026-5453 (tivo-codelib-a), MAL-2026-5454 (ui-ng-components),
    # MAL-2026-5455 (uipath-sugar-sell), MAL-2026-5456 (via-city-tools-m-particle).
    "ing-web-v5": set(),
    "eslint-plugin-totara": set(),
    "react-resource-router-next": set(),
    "@ataslkit/profilecard": set(),
    "@shoobx/types": set(),
    "@source-row/source-container": set(),
    "@settle-sea/supporting-documents": set(),
    "@serasa/core": set(),
    "@oec-settlement/react-router": set(),
    "@mc-xp/mc-monolith-js-src-package": set(),
    "@piewasm/pie-web-npm-package": set(),
    "@citi-icg-171632/citicms-repo-component": set(),
    "@cloudways-lab/unified-design-system": set(),
    "@flipbit2-bb/test-auth-state": set(),
    "@riskine-frontend/design-elements": set(),
    "@sec-loans-ui/utils": set(),
    "wm-mapper": set(),
    "unleash-js": set(),
    "@webd-infra/query-designer-domain": set(),
    "@webda-features/dashboard": set(),
    "@webda-infra/search": set(),
    "tivo-codelib-a": set(),
    "ui-ng-components": set(),
    "uipath-sugar-sell": set(),
    "via-city-tools-m-particle": set(),
    # Gartner GX dependency-confusion cluster (June 29 2026)
    # Three packages mirroring internal Gartner GX npm packages at 99.99.99.
    # OSV MAL-2026-6466 (gx-npm-feature-flags), MAL-2026-6480 (gx-npm-lib),
    # MAL-2026-6481 (gx-npm-ui). Related to @gartnerx/gx-npm-messenger-util (see below).
    "gx-npm-feature-flags": set(),
    "gx-npm-lib": set(),
    "gx-npm-ui": set(),
    # Large dep-confusion wave (June 29 2026)
    # 79 packages published across diverse scopes and namespaces, all with
    # SEMVER ranges: introduced 0 (any version is malicious), targeting companies
    # ranging from Deel to Postman to Rakuten. Detected by OpenSSF Package Analysis.
    # OSV MAL-2026-6594 through MAL-2026-6672.
    "vkzmn": set(),
    "@digitalcnzz/commonmodule": set(),
    "@digitalcnzz/embedded-sdk": set(),
    "@longzy/react-native-polyfill": set(),
    "@sailing-package/core": set(),
    "@alerts/components": set(),
    "@anna-money/anna-web-lib": set(),
    "@appsource/utils": set(),
    "@bapiweb-ux/bapi-header": set(),
    "@bc-workspace/utils": set(),
    "@bodata/angular-client": set(),
    "@bscom/styling": set(),
    "@concerns/i18n": set(),
    "@content-editor/common": set(),
    "@contenteditor-shared/content-editor-common": set(),
    "@contentprod-authoring/block-manager": set(),
    "@cseo-hr/trpweb-shared": set(),
    "@cxp-shared/string-utilities": set(),
    "@ddh-libs/analytics": set(),
    "@deel-core/client-payroll-onboarding-types": set(),
    "@deel-ui/animation": set(),
    "@digitalpharmacist/http-error-util": set(),
    "@druidsoft/botframework-directlinejs": set(),
    "@e50/utils": set(),
    "@experian-shared/services": set(),
    "@fed-sofia/jetify": set(),
    "@finantix/webcomponents": set(),
    "@flipbit2-bb/scope-test": set(),
    "@gallup/pc-utils": set(),
    "@gartnerx/gx-npm-messenger-util": set(),
    "@gm-rvg/root-config": set(),
    "@grappi/automations": set(),
    "@hg-aka-prml/tapas-common": set(),
    "@huobi-ui/activity-components": set(),
    "@img-hls/vtt.js": set(),
    "@lexisnexisrisk/insider-threat-platform": set(),
    "@live-backstage-im/communication-chat": set(),
    "@mcconnect/mcc-common-lib": set(),
    "@meego-progressive/cdk": set(),
    "@ms-ows/logging": set(),
    "@multformats/multiaddr": set(),
    "@orbis-lr-sdk/orbis-lr-sdk": set(),
    "@partner-apps/ui": set(),
    "@planetlabs/admin-ng": set(),
    "@postidigital-feature/oneaccount-orgadmin-front": set(),
    "@postman-app-monolith/renderer": set(),
    "@rakuten-rewards/messaging-sdk": set(),
    "@rakuten-rewards/messaging-sdk-js": set(),
    "@react-thee/rapier": set(),
    "@reference-web/pmp-i18n": set(),
    "@report-portal/service-ui": set(),
    "@rmlibrary/formatting": set(),
    "@sentryx-libraries/auth-interceptor": set(),
    "@services-lib/application-http-client": set(),
    "@shopbop/api-models": set(),
    "@sixt-payment/form-react": set(),
    "@sumoinc/trashpanda": set(),
    "@tbe-ui/ides": set(),
    "@webda-infra-ui/static-images": set(),
    "alpine-csp": set(),
    "app-hotmart-blog-headless": set(),
    "auth-state-service": set(),
    "authmatrix": set(),
    "authsessionbridge": set(),
    "bundrix": set(),
    "cdocs-data": set(),
    "cdocs-markdoc": set(),
    "clx-cookieparser": set(),
    "cmp-api-stub": set(),
    "gel-bootstrap": set(),
    "hrb-cas-auth-js": set(),
    "ltididp1": set(),
    "magwien.sys": set(),
    "player-core-ui": set(),
    "player-theming": set(),
    "pvd3": set(),
    "rc-icon": set(),
    "wac-atl-context": set(),
    "ulid-xyz": set(),
    # Miscellaneous npm malware batch (June 29 2026)
    # Individual packages with varying payloads (infostealers, env-var exfiltrators,
    # dep-confusion droppers, crypto-math typosquats). All have active OSV MAL records
    # with no withdrawal. All entries are wildcard (any version malicious) unless noted.
    # OSV MAL-2026-3312 (path-internal-util), MAL-2026-4580 (http-uploader-dev),
    # MAL-2026-4792 (react-json-chalk), MAL-2026-5487 (tailwind-form),
    # MAL-2026-5488 (react-pinojs), MAL-2026-5734 (node-denv),
    # MAL-2026-5908 (chain-chai-test), MAL-2026-5934 (ssr-auth-sync),
    # MAL-2026-6066 (quirky-token), MAL-2026-6068 (swift-parse-stream),
    # MAL-2026-6087 (uol-simple-api-futebol), MAL-2026-6098 (stackus),
    # MAL-2026-6141 (clx-cookie-signature), MAL-2026-6229 (routecraft),
    # MAL-2026-6337 (hunsterx-package), MAL-2026-6369 (hardhat-test-log),
    # MAL-2026-6445 (base58-core), MAL-2026-6467 (@vpms/design-system),
    # MAL-2026-6486 (unsafe-malicious-package), MAL-2026-6487 (velocityfix),
    # MAL-2026-6501 (wellnpm), MAL-2026-6531 (@appupdate/cdn-sync),
    # MAL-2026-6532 (chai-as-assured), MAL-2026-6545 (crossmint-wallets-sdk),
    # MAL-2026-6565 (@uisp/utils), MAL-2026-6566 (date-uuid),
    # MAL-2026-6567 (eslint-commit-parser), MAL-2026-6568 (express-mocha-test),
    # MAL-2026-6569 (longzy-basic-ui), MAL-2026-6570 (pkg-fallback npm),
    # MAL-2026-6571 (react-wp-viewer), MAL-2026-6572 (rebrandly-domains-digger),
    # MAL-2026-6573 (rebrandly-domains-search-client), MAL-2026-6574 (yandex-geobase),
    # MAL-2026-6575 (@ibrahim1337/baksen), MAL-2026-6576 (checkmarx-claude-cache),
    # MAL-2026-6577 (int_sezzle_sfra), MAL-2026-6578 (layerd-unit-codec-parser),
    # MAL-2026-6579 (lessload), MAL-2026-6580 (loadutils),
    # MAL-2026-6583 (pino-debugging), MAL-2026-6584 (poly-kelly),
    # MAL-2026-6585 (stake-math), MAL-2026-6586 (yastatic-s3),
    # MAL-2026-6587 (clob-client-math), MAL-2026-6588 (endpointmap),
    # MAL-2026-6589 (envfile-sync), MAL-2026-6590 (envfile-sync-cli),
    # MAL-2026-6591 (ledgerflow-deploy-utils), MAL-2026-6592 (maplibre-gl-vue3).
    "path-internal-util": set(),
    "http-uploader-dev": set(),
    "react-json-chalk": set(),
    "tailwind-form": set(),
    "react-pinojs": set(),
    "node-denv": set(),
    "chain-chai-test": set(),
    "ssr-auth-sync": set(),
    "quirky-token": set(),
    "swift-parse-stream": set(),
    "uol-simple-api-futebol": set(),
    "stackus": set(),
    "clx-cookie-signature": set(),
    "routecraft": set(),
    "hunsterx-package": set(),
    "hardhat-test-log": set(),
    "base58-core": set(),
    "@vpms/design-system": set(),
    "unsafe-malicious-package": set(),
    "velocityfix": set(),
    "wellnpm": set(),
    "@appupdate/cdn-sync": set(),
    "chai-as-assured": set(),
    "crossmint-wallets-sdk": set(),
    "@uisp/utils": set(),
    "date-uuid": set(),
    "eslint-commit-parser": set(),
    "express-mocha-test": set(),
    "longzy-basic-ui": set(),
    "pkg-fallback": set(),
    "react-wp-viewer": set(),
    "rebrandly-domains-digger": set(),
    "rebrandly-domains-search-client": set(),
    "yandex-geobase": set(),
    "@ibrahim1337/baksen": set(),
    "checkmarx-claude-cache": set(),
    "int_sezzle_sfra": set(),
    "layerd-unit-codec-parser": set(),
    "lessload": set(),
    "loadutils": set(),
    "pino-debugging": set(),
    "poly-kelly": set(),
    "stake-math": set(),
    "yastatic-s3": set(),
    "clob-client-math": set(),
    "endpointmap": set(),
    "envfile-sync": set(),
    "envfile-sync-cli": set(),
    "ledgerflow-deploy-utils": set(),
    "maplibre-gl-vue3": set(),
    # Polymarket ecosystem typosquat cluster (June 30 – July 1 2026)
    # Five packages impersonating Polymarket trading tools and risk management utilities;
    # postinstall payloads exfiltrate API keys, crypto wallet data, and environment variables.
    # OSV MAL-2026-6691 (polymarket-clob-maths), MAL-2026-6692 (polymarket-trading-developer-tools),
    # MAL-2026-6712 (polymarket-risk-manager), MAL-2026-6713 (polymarket-toolkit),
    # MAL-2026-6714 (polymarket-trading-developer-tool).
    "polymarket-clob-maths": set(),
    "polymarket-trading-developer-tools": set(),
    "polymarket-risk-manager": {"3.5.2"},
    "polymarket-toolkit": {"1.4.9"},
    "polymarket-trading-developer-tool": {"0.1.1"},
    # TypeScript / ESLint / CLOB typosquat cluster (June 30 – July 1 2026)
    # Six packages impersonating TypeScript build utilities, ESLint helpers, and CLOB math
    # libraries; OSV affected.ranges >=0 for all-version entries.
    # OSV MAL-2026-6677 / GHSA-vjgf-xg3j-g9c5 (ts-lint-builders-v2.1),
    # MAL-2026-6678 / GHSA-8mpj-272v-jhv7 (ts-linting-builder),
    # MAL-2026-6695 (ts-bn-proto), MAL-2026-6720 (ts-elinter),
    # MAL-2026-6721 (ts-eslint-helper), MAL-2026-6719 (ts-clob-math-v2).
    "ts-lint-builders-v2.1": set(),
    "ts-linting-builder": set(),
    "ts-bn-proto": set(),
    "ts-elinter": {"3.3.9"},
    "ts-eslint-helper": {"4.0.3", "4.0.4", "4.0.5"},
    "ts-clob-math-v2": {"2.0.1"},
    # Frontend framework typosquats (June 30 – July 1 2026)
    # Six packages impersonating popular frontend libraries (date-fns, svgson, vega-lite,
    # vue-demi, electron, svg tooling) with credential-exfiltration postinstall payloads.
    # OSV MAL-2026-6722 (date-fns-lite), MAL-2026-6707 (svgson-lite),
    # MAL-2026-6709 (vega-lite-next), MAL-2026-6702 (vue-demi-fix),
    # MAL-2026-6723 (electron-orbit), MAL-2026-6715 (svgcraft-core).
    "date-fns-lite": {
        "1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4", "1.0.5", "1.0.6",
        "1.0.7", "1.0.8", "1.0.9", "1.0.10", "1.0.11", "1.0.12",
    },
    "svgson-lite": {
        "1.0.0", "1.0.1", "1.0.2", "1.0.4", "1.0.5", "1.0.6", "1.0.7",
        "1.0.8",
    },
    "vega-lite-next": {"19.2.1"},
    "vue-demi-fix": {"10.0.3", "10.0.4", "10.0.5"},
    "electron-orbit": {
        "1.0.3", "1.0.4", "1.0.5", "1.0.6", "1.0.7", "1.0.8", "1.0.9",
        "1.0.10", "1.0.11", "1.0.12", "1.0.13", "1.0.14", "1.0.15", "1.0.16",
        "1.0.18", "1.0.20", "1.0.21", "1.0.22", "1.0.23", "1.0.24", "1.0.25",
        "1.0.26", "1.0.27", "1.0.28", "1.0.29", "1.0.30", "1.0.31", "1.0.32",
        "1.0.33", "1.0.34", "1.0.36",
    },
    "svgcraft-core": {"1.0.1", "1.0.2", "1.0.3", "1.0.4", "1.0.5", "1.0.6"},
    # Hardhat / Solidity ecosystem typosquats (June 30 – July 1 2026)
    # Two packages impersonating Hardhat build tools with credential-exfiltration postinstall.
    # OSV MAL-2026-6705 (hardhat-compile-ethers), MAL-2026-6706 (hardhat-plugin-solidity).
    "hardhat-compile-ethers": {
        "0.0.1", "0.4.0", "0.4.2", "0.4.3", "0.4.4", "0.4.5", "0.4.6",
        "0.4.7", "0.4.8", "0.4.9", "0.4.10", "0.4.11", "0.4.12",
    },
    "hardhat-plugin-solidity": {"1.0.0", "1.1.0", "2.0.0", "2.3.1"},
    # GHSA full-compromise batch (June 30 – July 1 2026)
    # 16 packages with SEMVER >=0 range: "Any computer that has this package installed or
    # running should be considered fully compromised." All use empty-set wildcard.
    # OSV MAL-2026-6675 / GHSA-xm5w-w96q-42f3 (rs-biginteger),
    # MAL-2026-6676 / GHSA-m8cr-hv9p-pg3f (terminal-prettier),
    # MAL-2026-6679 / GHSA-x676-qqgj-qfgg (agent-starter-pack),
    # MAL-2026-6680 / GHSA-gwv3-x257-r43c (brock-loader),
    # MAL-2026-6681 / GHSA-gh2m-x2qr-m2cm (brock-react-alerts),
    # MAL-2026-6682 / GHSA-j28m-58xp-3wgh (confluent-kafka-javascript),
    # MAL-2026-6683 / GHSA-fc4r-p4fh-6h4p (nbmolviz-js),
    # MAL-2026-6684 / GHSA-6g2x-2f5c-wp9w (postcss-property-rollup),
    # MAL-2026-6685 / GHSA-x8q6-66jr-wmp3 (quoting),
    # MAL-2026-6686 / GHSA-5rc3-r829-w347 (setup-cicd),
    # MAL-2026-6687 / GHSA-5r42-357x-f2mx (procwire),
    # MAL-2026-6688 (console-fmt-cli), MAL-2026-6689 (decimal-format-core),
    # MAL-2026-6690 (log-taker1), MAL-2026-6693 (thirdwb), MAL-2026-6694 (thirdwebb).
    "rs-biginteger": set(),
    "terminal-prettier": set(),
    "agent-starter-pack": set(),
    "brock-loader": set(),
    "brock-react-alerts": set(),
    "confluent-kafka-javascript": set(),
    "nbmolviz-js": set(),
    "postcss-property-rollup": set(),
    "quoting": set(),
    "setup-cicd": set(),
    "procwire": set(),
    "console-fmt-cli": set(),
    "decimal-format-core": set(),
    "log-taker1": set(),
    "thirdwb": set(),
    "thirdwebb": set(),
    # Miscellaneous npm malware batch (June 30 – July 1 2026)
    # Individual packages with varying payloads. OSV records active, not withdrawn.
    # OSV MAL-2026-3509 (pp-react-v5), MAL-2026-6346 (triage-bot),
    # MAL-2026-6405 (sypoi1), MAL-2026-6701 (ripshakti), MAL-2026-6674 (ripshakti1),
    # MAL-2026-6699 (ecto-corsair-flag-7kq3mz), MAL-2026-6700 (module-index-cache),
    # MAL-2026-6708 (zyncmap), MAL-2026-6710 (vitest-agent),
    # MAL-2026-6704 (base65-85x), MAL-2026-6716 (test-pkg-pnpm),
    # MAL-2026-6717 (test-pkg-x0), MAL-2026-6718 (test-pkg-yarn).
    "pp-react-v5": set(),
    "triage-bot": {"1.0.1", "1.0.2"},
    "sypoi1": {"1.0.0", "1.0.1"},
    "ripshakti": {"80.0.0"},
    "ripshakti1": {"81.0.0"},
    "ecto-corsair-flag-7kq3mz": {"1.0.0", "1.0.1", "1.0.2"},
    "module-index-cache": {"1.0.0", "1.0.1", "1.0.2"},
    "zyncmap": {"0.0.0", "0.0.1"},
    "vitest-agent": {"1.0.5", "1.0.6"},
    "base65-85x": {"5.0.1"},
    "test-pkg-pnpm": {"1.0.1", "1.0.4"},
    "test-pkg-x0": {"1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4"},
    "test-pkg-yarn": {"1.0.0", "1.0.1", "1.0.2"},
    # Dependency-confusion packages (June 30 – July 1 2026)
    # High-version shadow packages targeting private CI pipelines.
    # OSV MAL-2026-6696 (@businessapp-microsites/apis),
    # MAL-2026-6697 (@sudoughnym/enviro-demo),
    # MAL-2026-6703 (@andes-tools/colors),
    # MAL-2026-6698 (cursed-modules).
    "@businessapp-microsites/apis": {"9999.0.0", "9999.0.1"},
    "@sudoughnym/enviro-demo": {"99.99.99"},
    "@andes-tools/colors": {"999.0.0"},
    "cursed-modules": {
        "1.0.1", "1.0.4", "1.0.5", "1.0.6", "1.0.7", "2.0.0",
        "999.0.0", "999.0.1", "999.0.2", "999.0.3", "999.0.4", "999.0.5",
        "999.0.6", "999.0.7", "999.0.8", "999.0.9", "999.1.0", "999.1.1", "999.1.2",
    },
    # tailwind-typography-stylecss Tailwind CSS typosquat (July 2 2026)
    # Impersonates tailwind-typography CSS plugin; SEMVER >=0 range — entire package malicious.
    # OSV MAL-2026-4681 / GHSA-p258-w6jm-c6ff
    "tailwind-typography-stylecss": set(),
    # SQL/SQLite fake npm package cluster (July 2–3 2026)
    # Three packages impersonating SQL access and SQLite tooling; each ships a
    # postinstall credential-exfiltration payload. SEMVER >=0 range — entire packages malicious.
    # OSV MAL-2026-5394 / GHSA-qpx3-6fx4-259q (@sql-access/nodesql)
    # OSV MAL-2026-5395 / GHSA-9f9w-wg5j-m53j (@sql-trigger/nodesql)
    # OSV MAL-2026-5396 / GHSA-9w2p-6gjc-vrqv (@sqlite-node/createsql)
    "@sql-access/nodesql": set(),
    "@sql-trigger/nodesql": set(),
    "@sqlite-node/createsql": set(),
    # Miscellaneous npm malware (July 2–3 2026)
    # All five carry a postinstall hook or import-time payload exfiltrating credentials.
    # SEMVER >=0 range in OSV records — entire packages are malicious.
    # OSV MAL-2026-5604 / GHSA-wg39-m2jm-wxhp (cache-section-helper)
    # OSV MAL-2026-6142 / GHSA-w7hw-9wmw-hj5w (db-connector-log)
    # OSV MAL-2026-6209 / GHSA-c3r7-wcqm-j4v8 (@antoncarlos1/nodelamp)
    # OSV MAL-2026-6495 / GHSA-p6ch-cw7w-ff5c (animatecss-postcss-plugin)
    # OSV MAL-2026-6538 / GHSA-j49r-84jx-vq3m (db-plog)
    "cache-section-helper": set(),
    "db-connector-log": set(),
    "@antoncarlos1/nodelamp": set(),
    "animatecss-postcss-plugin": set(),
    "db-plog": set(),
    # GHSA-confirmed npm malware batch (July 2 2026)
    # @modhamanish/rn-mm-template: only version 1.1.3 enumerated, no >=0 range — pin it.
    #   OSV MAL-2026-6725 / GHSA-7v96-p295-826q
    # db-convertor: SEMVER >=0 range, no specific versions — wildcard.
    #   OSV MAL-2026-6726 / GHSA-p467-3jcx-48q5
    # tailwind-animates: SEMVER >=0 range, no specific versions — wildcard.
    #   OSV MAL-2026-6727 / GHSA-3cr6-gpr8-pjfm
    "@modhamanish/rn-mm-template": {"1.1.3"},
    "db-convertor": set(),
    "tailwind-animates": set(),
    # Unreal Engine / Epic Games dep-confusion npm cluster (July 2 2026)
    # Five packages published at version 99999.0.0 to shadow private UE/Epic packages in CI/CD.
    # Detected by OpenSSF Package Analysis. No >=0 range in OSV records — pin version.
    # OSV MAL-2026-6729 (robomerge), MAL-2026-6730 (ue-automation-scripts),
    # MAL-2026-6731 (ue-jenkins-buildkite), MAL-2026-6732 (unreal-horde-dashboard),
    # MAL-2026-6737 (epic-internal-tools)
    "robomerge": {"99999.0.0"},
    "ue-automation-scripts": {"99999.0.0"},
    "ue-jenkins-buildkite": {"99999.0.0"},
    "unreal-horde-dashboard": {"99999.0.0"},
    "epic-internal-tools": {"99999.0.0"},
    # GHSA any-version malware cluster (July 3 2026)
    # Ten packages confirmed fully malicious by GHSA automated detection;
    # all have SEMVER >=0 range with no specific versions.
    # OSV MAL-2026-6738 / GHSA-3mg6-vg6x-m62v (@jacobtan/decode-sdk)
    # OSV MAL-2026-6739 / GHSA-37qp-frv4-562v (@lodash-en/lodash-en)
    # OSV MAL-2026-6740 / GHSA-gv37-287r-g9vx (decode-sdks)
    # OSV MAL-2026-6741 / GHSA-558p-3gxf-hm84 (@node-cloud/create)
    # OSV MAL-2026-6742 / GHSA-j23f-jg9h-gjmc (alder_morrgan)
    # OSV MAL-2026-6743 / GHSA-wj6w-3grq-735j (api-node-utils)
    # OSV MAL-2026-6744 / GHSA-3w2r-9f5g-prj8 (api-ts-utils)
    # OSV MAL-2026-6745 / GHSA-mjvg-2r5j-mg76 (ts-node-utils)
    # OSV MAL-2026-6746 / GHSA-84mg-p866-528x (typescript-util-core)
    # OSV MAL-2026-6747 / GHSA-j69c-7q52-h87f (web-api-node)
    "@jacobtan/decode-sdk": set(),
    "@lodash-en/lodash-en": set(),
    "decode-sdks": set(),
    "@node-cloud/create": set(),
    "alder_morrgan": set(),
    "api-node-utils": set(),
    "api-ts-utils": set(),
    "ts-node-utils": set(),
    "typescript-util-core": set(),
    "web-api-node": set(),
    # vps-maintenance / paperclip2 npm malware cluster (July 4 2026)
    # Three packages from the same actor published in the same minute;
    # each carries a postinstall credential-exfiltration payload.
    # Detected by OpenSSF Package Analysis.
    # OSV MAL-2026-6755 (paperclip2), MAL-2026-6756 (vps-maintenance),
    # MAL-2026-6757 (vps-maintenance-paperclip-adapter)
    "paperclip2": {"1.0.0"},
    "vps-maintenance": {"0.1.0"},
    "vps-maintenance-paperclip-adapter": set(),  # MAL-2026-6757 (ranges >=0; all versions malicious)
    # @marketfront/* dep-confusion cluster (July 5 2026, Yandex Market internal scope)
    # 25 packages published to public npm to shadow private @marketfront packages.
    # All carry a postinstall exfiltration payload; no legitimate public use.
    # OSV MAL-2026-6763 through MAL-2026-6787.
    "@marketfront/actualordersnippetpopup": set(),
    "@marketfront/advertisingdevtool": set(),
    "@marketfront/bannerpopup": set(),
    "@marketfront/baobabtech": set(),
    "@marketfront/basemarkettemplate": set(),
    "@marketfront/blenderdevtool": set(),
    "@marketfront/captchaservice": set(),
    "@marketfront/changefilter": set(),
    "@marketfront/commonecommerce": set(),
    "@marketfront/customdealsfeed": set(),
    "@marketfront/designsystemdevtool": set(),
    "@marketfront/devtoolsloader": set(),
    "@marketfront/digitalherobannercarousel": set(),
    "@marketfront/dynamicpageparams": set(),
    "@marketfront/errorcounter": set(),
    "@marketfront/fashiononboardingpopup": set(),
    "@marketfront/fingerprint": set(),
    "@marketfront/footer": set(),
    "@marketfront/gotoauthpopup": set(),
    "@marketfront/header": set(),
    "@marketfront/infopopup": set(),
    "@marketfront/livestreampreviewpopup": set(),
    "@marketfront/madvpopup": set(),
    "@marketfront/mychatspreloader": set(),
    "@marketfront/navbar": set(),
    # @liquid-web / @self-sell / @team-event dep-confusion campaign (July 5 2026)
    # All published at version 1.2.9213 to shadow private registry packages.
    # OSV MAL-2025-47032, MAL-2025-47033, MAL-2025-47040,
    #     MAL-2025-47045, MAL-2025-47046, MAL-2025-47047,
    #     MAL-2025-47048, MAL-2025-47051.
    "@liquid-web/app-services": set(),
    "@liquid-web/common": set(),
    "@liquid-web/utils": set(),
    "@self-sell/guards": set(),
    "@self-sell/self-sell-amplitude-events": set(),
    "@self-sell/store": set(),
    "@team-event/models": set(),
    "@team-event/v2": set(),
    # @google_cloud/precise-date typosquat (July 5 2026)
    # Typosquats the legitimate @google-cloud/precise-date package.
    # OSV MAL-2025-47029; affected.ranges >= 0 (any version malicious).
    "@google_cloud/precise-date": set(),
    # @swiggy-private dep-confusion (2024, recently updated in OSV)
    # High-version dep-confusion packages targeting Swiggy internal registry.
    # OSV MAL-2024-12164, MAL-2024-12168.
    "@swiggy-private/aatm-nirbhar-build": {"8999999999999999.99999999.99999999999"},
    "@swiggy-private/js-utils": {
        "1.0.0", "1.0.1", "1.0.999999999",
        "999.999999.99999", "9999.9999.9999", "99999.9999.9999",
        "999999.999.99999", "9999999.99.9999", "99999999.10012.9999",
    },
    # Misc npm malware batch (July 5–6 2026)
    # OSV MAL-2026-6760 through MAL-2026-6762, MAL-2026-6788 through MAL-2026-6795.
    "@adobesign/as-dev-tools": {"99.9.9", "99.9.10"},
    "gen-ai-opt-in": {"99.0.2"},
    "node-pino": {"2.3.2"},
    "datefmt-helper": {"1.0.0", "1.0.1"},
    "@checkrhq/adjudication-api-client": {"0.0.2"},
    "debugcli": {"4.3.5", "4.3.9"},
    "npm-show-date-proof-strings": {"1.0.3"},
    "wsh4-nmp": {"1.0.0"},
    "neon-terminal": {"0.2.0", "0.3.0", "0.4.0", "0.5.0", "0.6.0", "0.7.0", "0.9.0"},
    "zod-pino434": {"1.0.127", "1.0.128"},
    "zod-pino444": {"1.0.128", "1.0.129"},
    # @antv/adjust malicious versions (July 5 2026, part of ongoing @antv wave)
    # OSV MAL-2026-3849; two specific malicious versions among otherwise-legitimate releases.
    "@antv/adjust": {"0.3.5", "0.4.5"},
    # July 6–7 2026 multi-campaign npm batch
    # Sources: OSV.dev bulk export (npm ecosystem), filtered MAL-* records
    # modified >= 2026-07-06, not withdrawn. Clusters below.
    #
    # Logger / chalk / prettier typosquat cluster
    # OSV MAL-2026-1259, MAL-2026-4640, MAL-2026-5710, MAL-2026-5900,
    # MAL-2026-5901, MAL-2026-5925, MAL-2026-5930, MAL-2026-6809–6817,
    # MAL-2026-6828–6831, MAL-2026-6833, MAL-2026-6848–6850, MAL-2026-6861–6863,
    # MAL-2026-6866–6868, MAL-2026-6878, MAL-2026-6883, MAL-2026-6893,
    # MAL-2026-6904, MAL-2026-6905
    "pino-sdk-v2": set(),
    "pino-formatter": {"1.1.12", "1.1.13"},
    "chalk-plus-ts": {"1.0.3"},
    "chai-as-decrypted": {"4.2.8"},
    "chai-as-polished": {"7.0.8"},
    "motion-lib": {"2.3.5"},
    "bubblestr": {"1.1.4"},
    "chalk-logger-prettier": {"1.0.1", "1.0.2", "1.0.3", "1.0.5", "1.0.7", "1.0.8"},
    "chalk-prettier": {"1.0.8", "1.0.9"},
    "chalks-logger": {"1.0.9", "1.1.0", "1.1.1", "1.1.2", "1.1.3"},
    "color-logger-console": {"3.1.8", "3.1.9"},
    "debug-glitzs": {"1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4"},
    "elevate-log": {"2.0.5"},
    "emojiprint-logger": {"1.1.0", "5.6.2"},
    "emojiprint-prettier": {"1.0.9"},
    "chalk-pro-logger": {"1.1.1", "1.1.2"},
    "chalki-pretty": {"1.0.0"},
    "color-cli-log": {"2.0.0", "2.1.0"},
    "custom-log-viewer": {"1.0.0"},
    "log-format-thread": {"1.0.0", "1.0.1"},
    "log-upgrade": {"7.1.0"},
    "logger-beauty": {"1.0.1", "1.0.2", "1.0.3", "1.1.0", "2.1.1"},
    "picocolor-logger": {"1.0.0", "1.0.1", "1.0.2"},
    "pino-pretty-logs": {"1.1.0", "2.0.0"},
    "pino-utils": {"1.3.6", "1.4.0"},
    "prettier-logger": {"0.1.4", "0.1.5", "0.1.6"},
    "pretty-pino-logger": {"1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4", "2.0.1", "2.0.2"},
    "pretty-pino-loggers": {"1.0.1"},
    "sleek-pretty": {"1.0.0"},
    "styled-text-logger": {"1.3.1"},
    "test-prettier": {"1.0.9"},
    "winston-js-express": {"1.0.0", "1.0.3", "1.0.4", "1.0.5", "1.0.6", "1.0.7", "1.1.1", "1.1.2"},
    "winston-prism": {"1.0.1"},
    #
    # Lint / ESLint / TypeScript build typosquat cluster
    # OSV MAL-2026-2528 (GHSA-g48w-hprp-f478), MAL-2026-2880 (GHSA-m374-prpv-rf26),
    # MAL-2026-2881 (GHSA-cv9f-3jc4-hxhv), MAL-2026-2883 (GHSA-rhr9-fqxc-vwqq),
    # MAL-2026-3774, MAL-2026-5994, MAL-2026-6187, MAL-2026-6819, MAL-2026-6835,
    # MAL-2026-6836, MAL-2026-6839, MAL-2026-6842–6847, MAL-2026-6858,
    # MAL-2026-6876, MAL-2026-6877, MAL-2026-6896, MAL-2026-6897
    "sjs-lint-build1": set(),
    "bjs-lint-builder": set(),
    "bjs-lint-builders": set(),
    "ts-lint-builds": set(),
    "ts-build-optimize": {"1.1.5", "1.1.6", "1.2.0", "1.2.1", "1.2.2"},
    "ts-webplug": {"3.0.5"},
    "eslint-helper": {"4.0.1", "4.0.2"},
    "es-lint-builders": {"1.0.0", "1.0.3", "1.0.4", "1.0.5"},
    "es-lint-entry": {"1.0.0"},
    "eslint-vite": {"1.0.0", "1.0.1", "1.0.2"},
    "hjs-lint-builders": {"1.0.4"},
    "lint-builders": {"1.0.0"},
    "lint-builds": {"1.0.0", "1.0.5"},
    "lint-nule": {"1.0.4"},
    "lint-nuler": {"1.0.4"},
    "lint-null": {"1.0.4"},
    "linter-entry": {"1.0.0"},
    "npm-eslint-helper": {"1.0.1"},
    "sjs-builder": {"1.0.4", "1.0.5"},
    "sjs-builders": {"1.0.4"},
    "ts-eslinter": {"1.0.0"},
    "ts-lint-builders": {"1.0.5"},
    #
    # BigInt / number typosquat cluster
    # OSV MAL-2026-2527 (GHSA-38ww-f26r-f8w7), MAL-2026-2879 (GHSA-jjf3-wfhw-qhx4),
    # MAL-2026-2882 (GHSA-65gr-98mv-9rj5), MAL-2026-3750, MAL-2026-6800–6806,
    # MAL-2026-6838, MAL-2026-6853, MAL-2026-6855, MAL-2026-6880, MAL-2026-6881,
    # MAL-2026-6895
    "sjs-biginteger": set(),
    "bjs-biginteger": set(),
    "cjs-biginteger": set(),
    "bigint.fs": {"5.0.5", "5.0.6"},
    "big-numer": {"5.0.5"},
    "big-numerate": {"5.0.3"},
    "big-numerator": {"5.0.3", "5.0.6"},
    "big256-ts": {"5.0.3", "5.0.4"},
    "bigint.os": {"5.0.5", "5.0.6", "5.0.7", "5.0.8"},
    "bn-eslint.js": {"8.0.5"},
    "bn-math": {"1.0.0", "1.0.1"},
    "hjs-biginteger": {"5.0.5"},
    "mjs-biginteger": {"5.0.5", "5.0.6"},
    "next-bignumber.js": {"1.0.0"},
    "st-biginteger": {"5.0.5"},
    "st-bigintr": {"5.0.5", "5.0.6"},
    "ts-bigtn": {"1.3.1", "1.3.2"},
    #
    # Chai testing typosquat cluster
    # OSV MAL-2026-2891 (GHSA-7cq2-px9f-cq3g), MAL-2026-5606, MAL-2026-6808,
    # MAL-2026-6827
    "chai-as-init": set(),
    "chai-dec": {"2.3.5"},
    "chai-guard": {"1.0.0", "1.2.3"},
    "chain-await-test": {"1.3.5"},
    #
    # Tailwind CSS typosquat cluster
    # OSV MAL-2026-5619, MAL-2026-6885–6892, MAL-2026-6899, MAL-2026-6903
    "tailwind-typography-plus": {"2.1.0"},
    "tailstyle-core": {"0.0.1"},
    "tailwind-fonttype-inter": {"2.3.2"},
    "tailwind-scroller": {"1.0.2"},
    "tailwindcss-animatecss-latest": {"2.1.0", "2.1.1"},
    "tailwindcss-fonttype-inter": {"2.3.1", "2.3.2"},
    "tailwindcss-fonttypo-inter": {"2.3.2"},
    "tailwindcss-framer-motion": {"1.1.3"},
    "tailwindcss-svg-helper": {"1.17.9", "1.18.0"},
    "twcompose-utils": {"0.7.6", "0.7.7"},
    "windrule-utils": {"0.0.1"},
    #
    # Ethereum / blockchain typosquat cluster
    # OSV MAL-2026-3029, MAL-2026-4779, MAL-2026-5705, MAL-2026-5706,
    # MAL-2026-6837, MAL-2026-6851, MAL-2026-6852, MAL-2026-6864, MAL-2026-6865,
    # MAL-2026-6879
    "eth-logger": {"4.3.20", "4.3.21"},
    "ether-bn.js": {"1.0.3", "1.1.1", "1.2.1", "1.3.1", "1.3.3", "1.3.4", "1.4.0", "1.4.1"},
    "theta-connector": {"1.0.0"},
    "theta-kit": {"1.0.0", "1.0.1", "1.0.2", "1.0.3"},
    "eth-tick": {"7.4.17", "7.4.18"},
    "metrica-chain": {"2.4.5"},
    "metrica-node": {"2.4.5"},
    "polymarket-onchain-plugin": {"2.1.3", "2.1.4", "2.1.5"},
    "polymarket-onchain-sdk": {"1.0.2", "1.0.3", "1.0.4"},
    "sol-sdk": {"2.3.18"},
    #
    # Express / Node.js utility typosquat cluster
    # OSV MAL-2026-2419 (GHSA-2847-rm77-74wh), MAL-2026-2350, MAL-2026-5577,
    # MAL-2026-5578, MAL-2026-5581, MAL-2026-6543 (GHSA-fh43-48vc-c9r9),
    # MAL-2026-6818, MAL-2026-6820, MAL-2026-6821, MAL-2026-6856
    "express-session-js": set(),
    "express-initial": set(),
    "dotenv-express": {"2.5.5", "17.4.2", "17.4.3", "17.4.4", "17.4.5", "17.4.6"},
    "env-axios": {"1.3.6"},
    "express-dotenv": {"1.3.5"},
    "express-guardrail": {"1.3.5", "1.4.1"},
    "node-env-detector": {"1.0.0", "1.0.1"},
    "web-pool": {"2.3.5"},
    "webpack-cache-clean": {"0.1.4"},
    "webpack-patch": {"1.1.7"},
    #
    # Miscellaneous npm malware batch (July 6–7 2026)
    # OSV MAL-2026-1483, MAL-2026-2526, MAL-2026-3775, MAL-2026-4501,
    # MAL-2026-4503, MAL-2026-4592, MAL-2026-4622, MAL-2026-4781,
    # MAL-2026-5569, MAL-2026-5713, MAL-2026-5743, MAL-2026-5936,
    # MAL-2026-5973, MAL-2026-6079, MAL-2026-6192, MAL-2026-6341,
    # MAL-2026-6457, MAL-2026-6476, MAL-2026-6484, MAL-2026-6499,
    # MAL-2026-6539, MAL-2026-6796–6799, MAL-2026-6807, MAL-2026-6812,
    # MAL-2026-6814, MAL-2026-6822–6826, MAL-2026-6832, MAL-2026-6834,
    # MAL-2026-6840, MAL-2026-6841, MAL-2026-6854, MAL-2026-6857,
    # MAL-2026-6859, MAL-2026-6860, MAL-2026-6869–6875, MAL-2026-6882,
    # MAL-2026-6884, MAL-2026-6894, MAL-2026-6898, MAL-2026-6900–6902,
    # MAL-2026-6906
    "@jaime9008/math-service": set(),
    "request-js-validator": {"1.0.2", "1.0.3", "1.0.4"},
    "btd-smart": {"1.0.2", "1.0.3"},
    "bytecore": {"5.3.1"},
    "jsontoken-extend": {
        "1.0.6", "1.0.7", "1.0.8", "1.0.9",
        "1.0.10", "1.0.11", "1.0.12", "1.0.13",
    },
    "normalize-path-seq": {"3.8.9"},
    "unique-id-64": {"1.0.0"},
    "js-crypto-promise": {"1.0.1"},
    "vite-plugin-compress-js": {"0.5.5", "0.5.6", "0.5.7"},
    "environment-gate": {"7.3.5", "7.3.6"},
    "set-proto-chain": {"1.0.3"},
    "nodepathbalance54": {"1.1.0"},
    "react-check-error": {"2.1.6", "2.1.7"},
    "subsearch": {"1.0.2", "1.0.3"},
    "typedecode": {"1.0.1", "1.0.2", "1.0.3"},
    "random-string-64": {"1.0.0", "1.0.1"},
    "mongoose-json-format": {"3.0.0", "3.0.1"},
    "db-query-log": {"1.0.1"},
    "internallib_v234": {"1.0.3", "1.0.4", "1.0.5", "1.0.6", "1.0.7"},
    "mongoose-lean-hooks": {"0.5.2", "0.5.3"},
    "argonflux": {"2.0.1"},
    "awesome-cli-logger": {"1.0.0", "1.2.0"},
    "bootstrap-utils": {"4.5.0"},
    "devkit-scripts": {"1.0.0", "1.0.3"},
    "fastnodemailer": {"8.0.2", "8.0.3", "8.0.4"},
    "graphpilot": {"0.1.0", "0.1.1", "0.1.2", "0.1.3", "0.1.4"},
    "grid-settings-align": {"14.1.1", "14.1.2"},
    "react-next-dom": {"1.1.7", "17.2.7", "17.2.8"},
    "rollup-plugin-polyfill-handler": {"1.0.0", "1.0.1"},  # MAL-2026-6826; added 1.0.1
    "competion": {"1.8.1", "1.8.2", "1.8.3", "1.8.4"},
    "df-vision": {
        "1.1.72", "1.1.73", "1.1.74", "1.1.75",
        "1.1.76", "1.1.77", "1.1.78", "1.1.79",
    },
    "js-unimode": {
        "1.1.3", "1.1.4", "1.1.5", "1.1.6",
        "1.1.7", "1.1.8", "1.1.9", "1.1.10",
    },
    "jsonupper": {"1.0.0"},
    "modulyn": {"1.0.1"},
    "npm-doc-dev": {
        "1.0.4", "1.0.5", "1.0.6", "1.0.7",
        "1.0.8", "1.0.9", "1.1.0", "1.1.1",
    },
    "older_morgan": {"1.0.1", "1.0.2"},
    "peptideenv": {
        "16.6.1", "16.6.2", "16.6.3",
        "16.6.4", "16.6.5", "16.6.6",
    },
    "react-native-template-my-starter": {"1.0.0"},
    "react-svg-render": {"1.0.2"},
    "renderctx": {"1.1.1"},
    "rma-utils": {"1.0.1"},
    "router-kit": {
        "1.3.0", "1.3.1", "1.3.2", "1.3.3", "1.3.4",
        "2.0.0", "2.0.1", "2.1.0",
    },
    "safe-validate": {"1.0.1", "1.0.2", "1.0.3", "1.0.4"},
    "secure-box": {"1.0.1", "1.0.2"},
    "stacknova": {"1.0.0"},
    "syncora": {"0.2.0"},
    "tracing-str": {"1.0.0", "1.0.2", "1.0.3", "1.0.4", "1.0.5", "2.0.3"},
    "ts-relayer-pub": {"1.0.0"},
    "txs-data": {"1.0.1"},
    "vite-plugin-svg-paths": {"1.1.5", "1.1.6", "1.1.7", "1.1.8", "1.1.9"},
    "wime-zle": {"1.1.4"},
    "xnder-sdk-js": {"0.1.0"},
    "tsliverhome": {"1.0.0", "1.1.1", "1.1.2", "1.1.3", "1.1.4", "1.1.5"},
    "classbreeze-utils": {"0.7.7", "0.7.8", "0.7.9", "0.7.10"},
    "vite-config-field": {"1.1.0", "1.1.1", "1.1.2", "1.1.3"},
    "cookie-ease": {
        "1.0.6", "1.0.7", "1.0.8", "1.0.9",
        "1.1.1", "1.1.2", "1.1.3", "1.1.5",
    },
    # Redis/IORedis fake-client cluster (modified July 7-8 2026)
    # Six packages impersonating ioredis and redis clients with postinstall
    # credential-exfiltration payloads. All have affected.ranges >=0 (any-version).
    # OSV MAL-2026-5675 (ioredis-orm), MAL-2026-5676 (ioredis-typed),
    # MAL-2026-5879 (ioredis-os), MAL-2026-5882 (redis-type-os),
    # MAL-2026-5883 (redis-xyz), MAL-2026-6944 (zredis-typed)
    "ioredis-orm": set(),
    "ioredis-typed": set(),
    "ioredis-os": set(),
    "redis-type-os": set(),
    "redis-xyz": set(),
    "zredis-typed": set(),
    # Large misc npm malware batch (modified July 7-8 2026)
    # Dozens of packages from independent campaigns with active OSV MAL-* records.
    # any-version wildcards (affected.ranges >=0):
    # OSV MAL-2026-5307 (classwind-utils), MAL-2026-5384 (enquriers),
    # MAL-2026-5491 (xnder-sdk), MAL-2026-5635 (routing-controls),
    # MAL-2026-5724 (warp-dependency), MAL-2026-5843 (chai-smart-assert),
    # MAL-2026-5845 (prettier_v1), MAL-2026-5853 (sp-api-dev-assistant-mcp-server),
    # MAL-2026-5873 (rbac-auth), MAL-2026-5888 (middleware-jwt),
    # MAL-2026-6113 (intquery), MAL-2026-6119 (parket-helper),
    # MAL-2026-6143 (node-vfs-polyfill), MAL-2026-6199 (ts-big-ecro),
    # MAL-2026-6204 (ts-ecro-helper), MAL-2026-6278 (ts-wross),
    # MAL-2026-6287 (poly-utils), MAL-2026-6288 (ts-numbering),
    # MAL-2026-6333 (mjs-eslint-service), MAL-2026-6335 (server-parket),
    # MAL-2026-6387 (multer-express), MAL-2026-6388 (rapidsearch),
    # MAL-2026-6404 (syco1), MAL-2026-6442 (easy-time-format),
    # MAL-2026-6506 (pump-laserstream-parser), MAL-2026-6508 (tw-style-utils),
    # MAL-2026-6517 (ai-node-agent), MAL-2026-6518 (ai-node-relay)
    "classwind-utils": set(),
    "enquriers": set(),
    "xnder-sdk": set(),
    "routing-controls": set(),
    "warp-dependency": set(),
    "chai-smart-assert": set(),
    "prettier_v1": set(),
    "sp-api-dev-assistant-mcp-server": set(),
    "rbac-auth": set(),
    "middleware-jwt": set(),
    "intquery": set(),
    "parket-helper": set(),
    "node-vfs-polyfill": set(),
    "ts-big-ecro": set(),
    "ts-ecro-helper": set(),
    "ts-wross": set(),
    "poly-utils": set(),
    "ts-numbering": set(),
    "mjs-eslint-service": set(),
    "server-parket": set(),
    "multer-express": set(),
    "rapidsearch": set(),
    "syco1": set(),
    "easy-time-format": set(),
    "pump-laserstream-parser": set(),
    "tw-style-utils": set(),
    "ai-node-agent": set(),
    "ai-node-relay": set(),
    # pinned-version packages in the misc batch:
    # OSV MAL-2026-5342 (kecak256), MAL-2026-5346 (cookie-parser-legacy),
    # MAL-2026-5629 (sass-formats), MAL-2026-5666 (downlynpm),
    # MAL-2026-5682 (coral-wraith), MAL-2026-5707 (ttspc-server-sample),
    # MAL-2026-5750 (mailconfirmer), MAL-2026-5791 (mddriver),
    # MAL-2026-5837 (postcss-minify-selector), MAL-2026-5851 (epm-service-module-v2),
    # MAL-2026-5931 (mci-sdk), MAL-2026-6075 (opt-archetype-check),
    # MAL-2026-6198 (new-ecro-1), MAL-2026-6210 (@apexcraft/nano-key),
    # MAL-2026-6271 (node-fetch-utils), MAL-2026-6273 (zod-pino),
    # MAL-2026-6396 (signup-embedder), MAL-2026-6542 (@osmura/treeify)
    "kecak256": {"1.0.0", "1.0.1", "1.0.2", "1.0.5"},
    "cookie-parser-legacy": {"1.5.1", "1.5.2", "1.5.3", "1.5.4"},
    "sass-formats": {"1.0.2", "1.0.4", "1.0.5"},
    "downlynpm": {"1.0.0", "1.0.1", "1.0.2"},
    "coral-wraith": {
        "1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4",
        "1.0.5", "1.0.6", "1.0.7", "1.0.8", "1.0.9",
        "1.0.10", "1.0.11", "1.0.12", "1.0.13", "1.0.14",
        "2.0.0", "2.0.1", "2.0.2", "2.0.3", "2.0.4",
        "3.0.0", "4.0.0", "5.0.1", "5.0.2", "5.0.3",
        "6.0.0", "7.0.0", "7.0.1", "7.0.2", "7.0.3",
        "8.0.0", "9.0.0", "10.0.0", "11.0.0", "12.0.0",
        "12.0.1", "13.0.0", "14.0.0", "15.0.0", "16.0.0",
        "17.0.0", "19.0.0", "19.0.1", "20.0.0", "21.0.0",
        "22.0.0",
    },
    "ttspc-server-sample": {
        "9.0.0", "9.0.1",
        "99.9.0", "99.9.1", "99.9.2", "99.9.3",
    },
    "mailconfirmer": {
        "3.2.34", "3.2.35", "3.2.36", "3.2.38", "3.2.39",
        "3.3.11", "3.3.12", "3.3.13", "3.3.15", "3.3.16",
        "3.3.17", "3.3.18", "3.3.19", "3.3.20", "3.3.21",
        "3.3.22", "3.3.23", "3.3.24", "3.3.25", "3.3.26",
        "3.3.27", "3.3.28", "3.3.29", "3.3.30", "3.3.31",
        "3.3.32", "3.3.34", "3.3.35", "3.3.36", "3.3.37",
        "3.3.38", "3.3.39", "3.3.41", "3.3.42", "3.3.43",
        "3.3.44", "3.3.45", "3.3.46", "3.3.47", "3.3.48",
        "3.3.51", "3.3.52", "3.3.53", "3.3.54", "3.3.55",
        "3.3.58",
    },
    "mddriver": {"1.8.1", "1.8.2", "1.8.3", "1.8.4", "1.8.5", "1.8.6"},
    "postcss-minify-selector": {
        "0.1.2", "0.1.3", "0.1.4", "0.1.5",
        "0.1.6", "0.1.7", "0.1.8", "0.1.9",
        "0.1.10", "0.1.11", "2.0.1", "2.0.2",
    },
    "epm-service-module-v2": {"1.0.1", "1.0.2", "1.0.3"},
    "mci-sdk": {"1.2.8", "1.2.9", "1.2.10", "1.2.11"},
    "opt-archetype-check": {"9.9.0", "9.9.1", "9.99.4"},
    "new-ecro-1": {"0.1.9", "0.2.9", "0.3.9"},
    "@apexcraft/nano-key": {
        "1.2.4", "1.2.5",
        "1.3.2", "1.3.3", "1.3.4", "1.3.5", "1.3.6", "1.3.7", "1.3.8",
    },
    "node-fetch-utils": {
        "1.2.1", "1.2.2", "1.2.3", "1.2.4",
        "1.2.5", "1.2.6", "1.2.7", "1.3.0",
    },
    "zod-pino": {
        "1.0.122", "1.0.123", "1.0.124",
        "1.0.125", "1.0.126", "1.0.127",
    },
    "signup-embedder": {"99.99.99", "99.99.99-poc2", "99.99.99-poc3"},
    "@osmura/treeify": {"1.1.0", "1.1.2", "1.1.3"},
    # SQLite fake-client cluster (July 7-8 2026)
    # Four packages impersonating SQL/SQLite tooling (extends the July 2-3 wave:
    # @sql-access/nodesql, @sql-trigger/nodesql, @sqlite-node/createsql).
    # All have affected.ranges >=0; any version is malicious.
    # OSV MAL-2026-6914 (@sqlite-access/nodesql), MAL-2026-6915 (@sqlite-list/createsql),
    # MAL-2026-6916 (@sqlite-list/schema-generator), MAL-2026-6917 (@sqlite-list/sql-creator)
    "@sqlite-access/nodesql": set(),
    "@sqlite-list/createsql": set(),
    "@sqlite-list/schema-generator": set(),
    "@sqlite-list/sql-creator": set(),
    # WHS4 actor cluster (July 7-8 2026, extends wsh4-nmp already tracked)
    # Six packages from the same actor (whs4/wsh4 naming variants) with postinstall
    # credential-exfiltration payloads; all have affected.ranges >=0.
    # OSV MAL-2026-6946 (@whs4/whs4_npm), MAL-2026-6950 (whs4_nmp),
    # MAL-2026-6951 (whs4_npm), MAL-2026-6952 (whs4_npm_test),
    # MAL-2026-6953 (whs4_pnm), MAL-2026-6954 (wsh4_npm)
    "@whs4/whs4_npm": set(),
    "whs4_nmp": set(),
    "whs4_npm": set(),
    "whs4_npm_test": set(),
    "whs4_pnm": set(),
    "wsh4_npm": set(),
    # Paperclip/VPS extension cluster (July 7-8 2026)
    # Extends the July 4 vps-maintenance cluster (paperclip2, vps-maintenance,
    # vps-maintenance-paperclip-adapter already tracked).
    # OSV MAL-2026-6947 (paperclip-host-utils), MAL-2026-6948 (runtimedev-link),
    # MAL-2026-6949 (vps-adapter-core), MAL-2026-6981 (paperclip-adapter-helpers),
    # MAL-2026-7014 (vps-new-manager)
    "paperclip-host-utils": set(),
    "runtimedev-link": set(),
    "vps-adapter-core": set(),
    "paperclip-adapter-helpers": set(),  # MAL-2026-6981 (ranges >=0; all versions malicious)
    "vps-new-manager": {"0.1.4"},
    # Base58 / Solana credential-exfiltrator cluster (July 7-8 2026)
    # Four packages impersonating Base58 / Solana encoding utilities;
    # all have affected.ranges >=0 (any version is malicious).
    # OSV MAL-2026-6918 (base58-cli), MAL-2026-6920 (crypto-base58),
    # MAL-2026-6924 (solana-address-codec), MAL-2026-6925 (typescript-base58)
    "base58-cli": set(),
    "crypto-base58": set(),
    "solana-address-codec": set(),
    "typescript-base58": set(),
    # Chai typosquat extension cluster (July 7-8 2026)
    # Extends the ongoing Chai-typosquat campaign.
    # OSV MAL-2026-6907 (chai-spycore), MAL-2026-6919 (chai-chain-dom),
    # MAL-2026-6931 (chai-sdk), MAL-2026-7008 (chai-as-const),
    # MAL-2026-6994 (chai-presentation), MAL-2026-6995 (chai-redirection)
    "chai-spycore": set(),
    "chai-chain-dom": set(),
    "chai-sdk": set(),
    "chai-as-const": {"1.4.5"},
    "chai-presentation": {"0.0.1"},
    "chai-redirection": {"0.0.1"},
    # Express middleware extension cluster (July 7-8 2026)
    # Three packages impersonating Express.js middleware with postinstall payloads.
    # OSV MAL-2026-6908 (express-deflect), MAL-2026-6909 (express-firegate),
    # MAL-2026-7012 (express-mongo-limit)
    "express-deflect": set(),
    "express-firegate": set(),
    "express-mongo-limit": {"2.0.2", "2.0.6"},
    # AI / MCP tooling impersonation (July 7-8 2026)
    # OSV MAL-2026-6922 (mcp-server-pg) — has affected.ranges >=0 (any-version)
    "mcp-server-pg": set(),
    # Nuxt / dependency-confusion cluster (July 7-8 2026)
    # Four packages impersonating Nuxt internals at version 99.0.3 to shadow
    # private CI registry packages; all have affected.ranges >=0.
    # OSV MAL-2026-6934 (load-nuxt), MAL-2026-6935 (load-nuxt-dev),
    # MAL-2026-6937 (nuxt-fonts-devtools), MAL-2026-6933 (hook-augmenting-module)
    "load-nuxt": set(),
    "load-nuxt-dev": set(),
    "nuxt-fonts-devtools": set(),
    "hook-augmenting-module": set(),
    # Luminary Cloud internal dep-confusion (July 7-8 2026)
    # Two packages at 9999.0.x targeting Luminary Cloud internal CI.
    # OSV MAL-2026-6986 (@luminarycloudinternal/frodo),
    # MAL-2026-6987 (@luminarycloudinternal/lcvis-st)
    "@luminarycloudinternal/frodo": {"9999.0.1", "9999.0.2"},
    "@luminarycloudinternal/lcvis-st": {"9999.0.1", "9999.0.2"},
    # Notable individual malicious packages (July 7-8 2026)
    # OSV MAL-2026-6973 (gitlens), MAL-2026-6941 (shopify-internel),
    # MAL-2026-6982 (paysafe-cards), MAL-2026-6962 (gas-log),
    # MAL-2026-6938 (pinokio-redis), MAL-2026-6939 (polytrade),
    # MAL-2026-6943 (tx-guard-snap), MAL-2026-6932 (evm-typechain),
    # MAL-2026-6969 (vite-json-pwa)
    "gitlens": {"9.4.0"},
    "shopify-internel": set(),
    "paysafe-cards": {"1.0.0"},
    "gas-log": set(),
    "pinokio-redis": set(),
    "polytrade": set(),
    "tx-guard-snap": set(),
    "evm-typechain": set(),
    "vite-json-pwa": set(),
    # Miscellaneous dep-confusion / standalone npm malware batch (July 7-8 2026)
    # any-version wildcards: annotator-harvardx, nodemon-node, ts-await, karem-dp,
    # na-rony, nam-os-a-man (all have affected.ranges >=0)
    # OSV MAL-2026-6910 (zluri-ad-connector), MAL-2026-6911 (@higherlogic/ocfe),
    # MAL-2026-6930 (annotator-harvardx), MAL-2026-6955 (hello244b),
    # MAL-2026-6956 (rio-design-tokens), MAL-2026-6957 (nodemon-node),
    # MAL-2026-6958 (ts-await), MAL-2026-6963 (karem-dp),
    # MAL-2026-6964 (na-rony), MAL-2026-6967 (nam-os-a-man),
    # MAL-2026-6989 (ag-charts-test), MAL-2026-6990 (ai-gen-ai-opt-in),
    # MAL-2026-6993 (bytefaas-sdk), MAL-2026-6997 (goofy-sdk),
    # MAL-2026-7000 (pipo-sdk), MAL-2026-7005 (visa-cli-tools),
    # MAL-2026-7009 (configration), MAL-2026-7010 (crypto-promiser),
    # MAL-2026-7011 (events-alias), MAL-2026-7016 (@vraksha/gh-helper),
    # MAL-2026-7017 (logger-daemon-regex), MAL-2026-7019 (npm-rce-poc),
    # MAL-2026-7020 (react-v17), MAL-2026-7021 (@vite-js/ui),
    # MAL-2026-7022 (tslint-conf), MAL-2026-7024 (none123s),
    # MAL-2026-7026 (tailwind-core)
    "zluri-ad-connector": {"9.9.9"},
    "@higherlogic/ocfe": {"99.9.1"},
    "annotator-harvardx": set(),
    "hello244b": {"1.0.0"},
    "rio-design-tokens": {"99.99.100"},
    "nodemon-node": set(),
    "ts-await": set(),
    "karem-dp": set(),
    "na-rony": set(),
    "nam-os-a-man": set(),
    "ag-charts-test": {"99.9.1"},
    "ai-gen-ai-opt-in": {"99.0.0"},
    "bytefaas-sdk": {"9999.0.0"},
    "goofy-sdk": {"9999.0.0"},
    "pipo-sdk": {"9999.0.0"},
    "visa-cli-tools": {"99.9.1"},
    "configration": {"2.3.5"},
    "crypto-promiser": {"1.0.1", "1.0.2"},
    "events-alias": {"15.0.1"},
    "@vraksha/gh-helper": {"1.0.0"},
    "logger-daemon-regex": {"1.0.124"},
    "npm-rce-poc": {"1.0.13"},
    "react-v17": {"20.0.1"},
    "@vite-js/ui": {"7.15.10", "7.15.16"},  # MAL-2026-7021; added 7.15.10
    "tslint-conf": {"7.2.1"},
    "none123s": set(),  # MAL-2026-7024 (ranges >=0; all versions malicious)
    "tailwind-core": {"0.0.0", "4.3.0", "4.3.1", "4.3.2"},
    # @wagni_bot/* DeFi/crypto SDK typosquat cluster (July 9 2026)
    # Sixteen packages under the attacker-controlled @wagni_bot npm scope,
    # impersonating popular DeFi/Web3 SDKs (Binance, BSC, Ethereum, Hyperliquid,
    # Jupiter, Meteora, OpenSea, Orca, Polygon, Polymarket, PumpFun, Solana).
    # Each package steals crypto-wallet keys and sends them to attacker-controlled C2.
    # OSV MAL-2026-10022 through MAL-2026-10037.
    "@wagni_bot/binance-sdk": {"1.0.0", "1.2.0"},
    "@wagni_bot/bsc-sdk": {"1.0.0", "1.1.0", "1.1.1", "1.1.3", "1.1.4", "1.1.5", "1.2.0"},
    "@wagni_bot/eth-agent": {"1.0.0", "1.1.0", "1.1.1", "1.1.3", "1.1.4", "1.1.5", "1.2.0"},
    "@wagni_bot/ethereum-wallet": {"1.0.0", "1.2.0"},
    "@wagni_bot/hyperliquid-sdk": {"1.0.0", "1.1.0", "1.1.1", "1.1.3", "1.1.4", "1.1.5", "1.2.0"},
    "@wagni_bot/jupiter-sdk": {"1.0.0", "1.2.0"},
    "@wagni_bot/metemask-sdk": {"1.0.0", "1.1.0", "1.1.1", "1.1.3", "1.1.4", "1.1.5", "1.2.0"},
    "@wagni_bot/meteora-sdk": {"1.0.0", "1.2.0"},
    "@wagni_bot/opensea-sdk": {"1.0.0", "1.1.0", "1.1.1", "1.1.3", "1.1.4", "1.1.5", "1.2.0"},
    "@wagni_bot/orca-sdk": {"1.0.0", "1.2.0"},
    "@wagni_bot/polygon-sdk": {"1.0.0", "1.1.0", "1.1.1", "1.1.3", "1.1.4", "1.1.5", "1.2.0"},
    "@wagni_bot/polymarket-sdk": {"1.0.0", "1.1.0", "1.1.1", "1.1.3", "1.1.4", "1.1.5", "1.2.0"},
    "@wagni_bot/pumpfun-sdk": {"1.0.0", "1.2.0"},
    "@wagni_bot/solana-sdk": {"1.0.0", "1.2.0"},
    "@wagni_bot/web3-agent": {"1.0.0", "1.1.0", "1.1.1", "1.1.3", "1.1.4", "1.1.5"},
    "@wagni_bot/web3-toolkit": {"1.0.0", "1.2.0"},
    # paysafe-* npm credential-stealer cluster (July 10 2026)
    # Eight packages impersonating Paysafe payment-processing SDK components;
    # each package exfiltrates API credentials and environment variables on install.
    # Companion to the PyPI paysafe-* cluster (MAL-2026-6926 through 6929).
    # OSV MAL-2026-10166 (paysafe-api), MAL-2026-10167 (paysafe-checkout),
    # MAL-2026-10168 (paysafe-fraud), MAL-2026-10169 (paysafe-js),
    # MAL-2026-10170 (paysafe-kyc), MAL-2026-10171 (paysafe-node),
    # MAL-2026-10172 (paysafe-payments), MAL-2026-10173 (paysafe-vault)
    "paysafe-api": {"1.0.0"},
    "paysafe-checkout": {"1.0.0"},
    "paysafe-fraud": {"1.0.0"},
    "paysafe-js": {"1.0.0"},
    "paysafe-kyc": {"1.0.0"},
    "paysafe-node": {"1.0.0"},
    "paysafe-payments": {"1.0.0"},
    "paysafe-vault": {"1.0.0"},
    # notify-* npm malware cluster (July 10 2026)
    # Seven packages mimicking notification-utility libraries; each publishes
    # one or more versions with a malicious postinstall payload.
    # Detected by OpenSSF Package Analysis.
    # OSV MAL-2026-10152 (notifier-funcs), MAL-2026-10153 (notifier-log),
    # MAL-2026-10154 (notify-dist), MAL-2026-10155 (notify-funcs),
    # MAL-2026-10156 (notify-logs), MAL-2026-10157 (notify-theme),
    # MAL-2026-10158 (notify-utilities)
    "notifier-funcs": {"1.3.4"},
    "notifier-log": {"1.3.5"},
    "notify-dist": {"1.3.7"},
    "notify-funcs": {"1.3.5", "1.3.6"},
    "notify-logs": {"1.3.5"},
    "notify-theme": {"1.3.5", "1.3.6", "1.3.7"},
    "notify-utilities": {"1.3.5"},
    # type-* npm malware cluster (July 10 2026)
    # Five packages mimicking TypeScript/lint utility types with malicious payloads.
    # type-slint has an affected.ranges >=0 (any-version wildcard); others are pinned.
    # OSV MAL-2026-10077 (type-slint / GHSA-634c-4fgc-67w9),
    # MAL-2026-10130 (type-plint / GHSA-8mhh-r4mc-2293),
    # MAL-2026-10137 (type-elint / GHSA-v69h-23wr-hjg4),
    # MAL-2026-10164 (type-async), MAL-2026-10174 (type-atob)
    "type-slint": set(),
    "type-plint": {"3.3.7"},
    "type-elint": {"3.3.7"},
    "type-async": {"3.3.7"},
    "type-atob": {"3.3.7"},
    # sidecar-mcp npm malware (July 10 2026)
    # Four malicious versions of a package impersonating an MCP sidecar utility.
    # OSV MAL-2026-10161.
    "sidecar-mcp": {"1.0.0", "1.0.1", "1.0.2", "1.0.4"},
    # @injectivelabs/sdk-ts maintainer-account compromise (July 10 2026)
    # Single compromised version of the legitimate Injective Labs TypeScript SDK;
    # version 1.20.21 contains a malicious payload injected after account takeover.
    # OSV MAL-2026-10165.
    "@injectivelabs/sdk-ts": {"1.20.21"},
    # @bcryptln/becryptjs bcrypt typosquat (July 10 2026)
    # Typosquat of bcryptjs; three malicious versions exfiltrate credentials.
    # OSV MAL-2026-10162.
    "@bcryptln/becryptjs": {"3.0.8", "3.0.10", "3.0.11"},
    # stella-ai-cli / stella-coder npm AI-tool malware (July 10 2026)
    # Two packages masquerading as AI coding assistants; malicious payloads
    # confirmed by OpenSSF Package Analysis.
    # OSV MAL-2026-10133 (stella-ai-cli), MAL-2026-10134 (stella-coder)
    "stella-ai-cli": {"2.0.0", "3.0.1"},
    "stella-coder": {"4.0.0", "5.0.0", "5.0.1", "5.1.0", "5.1.1", "5.1.2"},
    # chai-as / chain-chai new typosquat batch (July 9-10 2026)
    # Continuation of the chai-as / chain-chai campaign; packages mimic
    # chai assertion plugins with malicious postinstall payloads.
    # chai-defender and chai-as-refined have affected.ranges >=0 (any-version).
    # OSV MAL-2026-10039 through MAL-2026-10056, MAL-2026-10175,
    # MAL-2026-2339 (chai-as-chains), MAL-2026-2641 (chai-as-refined),
    # MAL-2026-10082 (chain-async-dom), MAL-2026-10055/10056 (chain-chai-*)
    "chai-as-align": {"7.1.0"},
    "chai-as-balanced": {"2.2.3"},
    "chai-as-buffered": {"3.7.24"},
    "chai-as-disarmed": {"3.2.3"},
    "chai-as-modified": {"6.0.4"},
    "chai-as-serialized": {"7.0.8"},
    "chai-as-sharpened": {"7.0.9"},
    "chai-as-smart": {"2.3.5"},
    "chai-as-staged": {"6.0.4"},
    "chai-as-thread": {"7.0.8"},
    "chai-await-dom": {"1.3.7"},
    "chai-defender": set(),
    "chai-deflect": {"1.1.5", "1.1.6"},
    "chai-promised-test": {"1.3.5"},
    "chai-secure": {"1.2.3", "1.2.5"},
    "chai-smart": {"2.3.5"},
    "chai-as-chains": {"1.2.4", "1.2.7", "1.2.8"},
    "chai-as-doc": {"2.3.5"},
    "chai-as-refined": set(),
    "chain-async-dom": {"1.3.6"},
    "chain-chai-async": {"1.3.5"},
    "chain-chai-await": {"1.3.5", "1.3.6", "1.3.7"},
    # nodemon-gulp / nodemon-patch / nodemon-slint npm malware (July 10 2026)
    # Three packages mimicking nodemon, all with affected.ranges >=0 (any-version).
    # OSV MAL-2026-10065 (nodemon-gulp), MAL-2026-10110 (nodemon-patch),
    # MAL-2026-10117 (nodemon-slint)
    "nodemon-gulp": set(),
    "nodemon-patch": set(),
    "nodemon-slint": set(),
    # polymarket-* new typosquat batch (July 9-10 2026)
    # Additional packages targeting Polymarket traders; several have affected.ranges >=0.
    # polymarket-apis, polymarket-kelly-stake-math, polymarket-trader-apis,
    # polymarket-gamma-apis, polygon-gama-apis, polygon-gamma-apis: any-version (set()).
    # polymarket-kelly-math, polymarket-kelly-maths, polymarket-kit: exact versions.
    # OSV MAL-2026-10067 through MAL-2026-10072, MAL-2026-10147/10148/10149.
    "polymarket-apis": set(),
    "polymarket-kelly-math": {"3.5.2"},
    "polymarket-kelly-maths": {"3.5.3"},
    "polymarket-kelly-stake-math": set(),
    "polymarket-kit": {"2.4.1"},
    "polymarket-trader-apis": set(),
    "polymarket-gamma-apis": set(),
    "polygon-gama-apis": set(),
    "polygon-gamma-apis": set(),
    # July 11–12 2026 npm batch: auth/vault typosquats, dep-confusion packages,
    # jscrambler maintainer-account compromise, and misc single-version malware.
    # auth-next-gen: pure-malware auth-library typosquat; SEMVER >=0 (any-version);
    #   three versions captured before takedown (1.6.29, 1.7.2, 1.7.11).
    #   OSV MAL-2026-10180 / GHSA-8qpp-8j53-4wh7.
    "auth-next-gen": set(),
    # authvaultx: pure-malware vault/auth typosquat; SEMVER >=0 (any-version); no
    #   specific versions captured before takedown.
    #   OSV MAL-2026-10185 / GHSA-frr6-2jc6-6fhr.
    "authvaultx": set(),
    # awesome-ts-jest: typosquat of ts-jest; single malicious version 29.4.12 published
    #   with credential-exfiltration payload. OSV MAL-2026-10188.
    "awesome-ts-jest": {"29.4.12"},
    # client-cookies-agent: dep-confusion 99.x package; three high-version publications
    #   targeting internal pipelines. OSV MAL-2026-10019.
    "client-cookies-agent": {"99.9.5", "99.9.6", "99.9.7"},
    # google-caja-bower: dep-confusion package targeting Google Caja / Bower CI;
    #   seven high-version publications (20.x / 999.x / 1000.x). OSV MAL-2026-10186.
    "google-caja-bower": {
        "20.20.20", "999.20.20", "999.99.20", "999.999.20",
        "1000.80.20", "1000.800.20", "1000.801.20",
    },
    # jscrambler: maintainer-account compromise of the legitimate JS obfuscator tool.
    #   Versions 8.14.0, 8.16.0, 8.18.0, 8.20.0 inject a cross-platform native binary
    #   that harvests BIP-39 crypto-wallet seeds and browser sessions (Chromium/BoringSSL
    #   TLS internals present in payload). Amazon Inspector analysis confirmed the hidden
    #   executable; CHANGELOG has no entries past 8.13.0.
    #   OSV MAL-2026-10187.
    "jscrambler": {"8.14.0", "8.16.0", "8.17.0", "8.18.0", "8.20.0"},
    # tinymask-js: single-version malicious npm package; detected by OpenSSF/ossf.
    #   OSV MAL-2026-10189.
    "tinymask-js": {"1.0.2"},
    # tinyparrot: single-version malicious npm package; detected by OpenSSF/ossf.
    #   OSV MAL-2026-10190.
    "tinyparrot": {"0.4.1"},
    # July 12–13 2026 npm batch: mixed malware, dep-confusion, and framework typosquats
    # fastify-addone: Fastify plugin typosquat; two consecutive malicious versions
    #   published before takedown. OSV MAL-2026-10098.
    "fastify-addone": {"5.1.0", "5.1.1"},
    # polymarket-kelly-math-stake: extends the ongoing Polymarket ecosystem typosquat
    #   campaign (see July 1 batch); single malicious version. OSV MAL-2026-10199.
    "polymarket-kelly-math-stake": {"3.6.2"},
    # api-changelly: crypto exchange API typosquat at inflated version 19.2.11.
    #   OSV MAL-2026-10200.
    "api-changelly": {"19.2.11"},
    # chain-await-dom: single-version malware; detected by OpenSSF/ossf. OSV MAL-2026-10202.
    "chain-await-dom": {"1.3.4"},
    # giantswarm: dep-confusion at inflated version 22.0.1 targeting Giant Swarm CI.
    #   OSV MAL-2026-10203.
    "giantswarm": {"22.0.1"},
    # gptcore: AI/GPT-toolkit typosquat; three consecutive malicious versions.
    #   OSV MAL-2026-10204.
    "gptcore": {"4.0.6", "4.0.7", "4.0.8"},
    # library-explorer: dep-confusion at inflated version 25.2.1. OSV MAL-2026-10205.
    "library-explorer": {"25.2.1"},
    # nullrift: single-version malware; detected by OpenSSF/ossf. OSV MAL-2026-10206.
    "nullrift": {"1.0.0"},
    # react-dom-v17: typosquat of react-dom; single malicious version. OSV MAL-2026-10207.
    "react-dom-v17": {"15.0.1"},
    # @meziizana/frontend-logger: dep-confusion at inflated version 10.0.0.
    #   OSV MAL-2026-10208.
    "@meziizana/frontend-logger": {"10.0.0"},
    # auto-debug-tool: three malicious versions with credential-exfiltration payload.
    #   OSV MAL-2026-10209.
    "auto-debug-tool": {"1.0.0", "1.0.2", "1.0.3"},
    # mcp-notes-server-poc-praetorian: MCP server with malicious code; single version.
    #   OSV MAL-2026-10210.
    "mcp-notes-server-poc-praetorian": {"0.1.0"},
    # react-next-vite: React/Vite framework typosquat; single malicious version.
    #   OSV MAL-2026-10211.
    "react-next-vite": {"1.2.9"},
    # vuln-package: dep-confusion at inflated 99.x versions; four versions.
    #   OSV MAL-2026-10212.
    "vuln-package": {"99.9.9", "99.9.10", "99.9.11", "99.9.14"},
    # babel-preset-lib-client: Babel preset typosquat; three consecutive malicious versions.
    #   OSV MAL-2026-10214.
    "babel-preset-lib-client": {"4.9.9", "4.9.10", "4.9.11"},
    # polylabel-web-lib: dep-confusion at inflated version 99.9.1. OSV MAL-2026-10198.
    "polylabel-web-lib": {"99.9.1"},
    # bugexploit: dep-confusion at inflated version 99.9.9. OSV MAL-2026-10201.
    "bugexploit": {"99.9.9"},
    # node-sysmetrics: single-version npm malware (GHSA-w2wx-f2m6-332m).
    #   OSV MAL-2026-10216.
    "node-sysmetrics": {"1.0.0"},
    # dotnet-runtime-base: two-version npm malware (GHSA-9gr8-wg29-9wvv).
    #   OSV MAL-2026-10217.
    "dotnet-runtime-base": {"1.0.4", "1.0.5"},
    # pure-folder-three: Three.js-adjacent typosquat; five versions (GHSA-9w58-3cgj-jw7v).
    #   OSV MAL-2026-10218.
    "pure-folder-three": {"0.5.0", "0.6.0", "0.7.0", "0.7.1", "0.7.3"},

    # July 13-14 2026 dep-confusion / MFE internal-tools cluster
    # Dozens of packages published at inflated or date-formatted version numbers
    # targeting internal CI/CD pipelines of various organizations.
    # OSV IDs: MAL-2026-10221 through MAL-2026-10237, MAL-2026-10517 through MAL-2026-10522
    "@flex-ng/error-component": {"2.1.0"},  # MAL-2026-10221
    "@flex-ng/filter-pipe": {"1.1.0"},  # MAL-2026-10222
    "@flex-ng/header-component": {"0.1.0"},  # MAL-2026-10223
    "@idms-corp/auth-ui": {"0.0.0", "1.0.0"},  # MAL-2026-10224
    "@logdna-web/shared": {"13.19.37"},  # MAL-2026-10225
    "@logdna-web/styles": {"0.8.40"},  # MAL-2026-10226
    "box-react-uix": {"18.6.91"},  # MAL-2026-10227
    "chat-adapter-zoom": {"12.1.31"},  # MAL-2026-10228
    "enbd-react-error-boundry": {"6.0.0"},  # MAL-2026-10229
    "enbd-react-lib": {"8.0.0"},  # MAL-2026-10230
    "enbd-react-logger": {"4.0.0"},  # MAL-2026-10231
    "salesforce-vscode-slds": {"2026.7.11"},  # MAL-2026-10232
    "sams-sr-sdk-h5": {"7.0.0"},  # MAL-2026-10233
    "slds-lsp-client": {"2026.7.11"},  # MAL-2026-10234
    "tme-error": {"2.8.42"},  # MAL-2026-10235
    "tme-xca": {"3.0.0"},  # MAL-2026-10236
    "tme-xca-react": set(),  # MAL-2026-10237
    "@tqm-mfe/main": {"5.4.7"},  # MAL-2026-10517
    "@flcik/flick.js": set(),  # MAL-2026-10521
    "flick-test-app": set(),  # MAL-2026-10522

    # chai-as-* / fastify-bundler typosquat extension (July 13-14 2026)
    # Continuation of the existing chai-as-*/chain-chai typosquat campaign;
    # fastify-bundler is a Fastify plugin typosquat in the same wave.
    # OSV MAL-2026-10219/10504/10518/10519/10426/10520
    "chai-as-precision": {"7.0.6"},  # MAL-2026-10219
    "chai-as-auth": {"2.3.5"},  # MAL-2026-10518
    "chai-as-sets": {"3.1.3"},  # MAL-2026-10519
    "chai-as-verified": {"7.1.5"},  # MAL-2026-10504
    "chai-log": {"1.1.0"},  # MAL-2026-10426
    "fastify-bundler": {"1.4.13"},  # MAL-2026-10520

    # nodemon-* typosquat extension (July 13 2026)
    # Additional packages in the ongoing nodemon-*/type-* typosquat campaign;
    # each mimics nodemon tooling with credential-exfiltration payloads.
    # OSV MAL-2026-10014/10454/10468/10507/10508/10513/10514/10515
    "nodemon-sudo": {"3.1.16"},  # MAL-2026-10014
    "nodemon-delog": {"3.1.13"},  # MAL-2026-10507
    "nodemon-elint": {"3.1.13"},  # MAL-2026-10508
    "nodemon-web": {"3.1.13"},  # MAL-2026-10515
    "nodemon-async": set(),  # MAL-2026-10454
    "nodemon-sync": set(),  # MAL-2026-10468
    "nodemon-client": set(),  # MAL-2026-10513
    "nodemon-eslint": set(),  # MAL-2026-10514

    # polymarket-* typosquat extension (July 13 2026)
    # Additional packages in the Polymarket ecosystem typosquat campaign;
    # further Kelly-criterion and MCP-server impersonation packages.
    # OSV MAL-2026-10466/10467/10481/10485/10516
    "polymarket-mcp-v2": {"2.1.6"},  # MAL-2026-10481
    "polymarket-stake-kelly-math": {"3.8.2"},  # MAL-2026-10467
    "polymarket-math-stake-kelly": {"3.7.2"},  # MAL-2026-10466
    "polymarket-stake-kelly-math-check": {"3.5.2"},  # MAL-2026-10485
    "polymarket-bot-logger": {"1.0.1"},  # MAL-2026-10516

    # type-* typosquat extension (July 13 2026)
    # Additional packages in the type-* typosquat campaign targeting TypeScript tooling.
    # OSV MAL-2026-10440/10510/10511/10512
    "type-context": {"3.2.11", "3.2.7", "3.2.8", "3.2.9"},  # MAL-2026-10440
    "type-astr": {"3.2.3"},  # MAL-2026-10510
    "type-swap": {"3.1.3"},  # MAL-2026-10511
    "type-unique": {"3.1.3"},  # MAL-2026-10512

    # node-proc/fs/sysmon infostealer cluster (July 13 2026)
    # A cluster of fake Node.js system-metrics / filesystem utilities;
    # each runs a credential-exfiltration payload on install. Same actor
    # as the broader nodemon-* typosquat wave.
    # OSV MAL-2026-10420/10445/10463/10464/10465/10479/10480/10506
    "node-procmetrics": {"1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4", "1.0.5", "1.0.6", "1.0.7", "1.0.8", "1.0.9"},  # MAL-2026-10445
    "node-procmetrics-data": {"1.0.1"},  # MAL-2026-10464
    "node-fsagent": {"1.0.0", "1.0.4", "1.0.8", "1.1.1", "1.1.2", "1.1.3", "1.2.0", "1.2.1", "1.2.2"},  # MAL-2026-10506
    "node-fsmetrics-native": {"1.0.0"},  # MAL-2026-10480
    "node-fsmetrics-data": {"1.0.0", "1.0.1"},  # MAL-2026-10479
    "node-sysmon-native": {"1.0.0", "1.0.1", "1.0.2"},  # MAL-2026-10465
    "node-path-addon": {"1.0.8"},  # MAL-2026-10463
    "path-addon-extend": {"1.0.10", "1.0.7", "1.0.8"},  # MAL-2026-10420

    # @gleamkit / @dervix socket.io/ws typosquat cluster (July 13 2026)
    # Both scopes impersonate socket.io, engine.io, and ws packages;
    # any version is malicious for the engine.io/socket.io look-alikes.
    # OSV MAL-2026-6306/6496/10402/10474/10475/10476/10477
    "@gleamkit/ws": {"8.21.3"},  # MAL-2026-10402
    "@gleamkit/probe": {"0.0.1"},  # MAL-2026-6306
    "@gleamkit/engine.io": set(),  # MAL-2026-10476
    "@gleamkit/socket.io": set(),  # MAL-2026-10477
    "@dervix/ws": {"8.21.3", "8.21.4", "8.21.7"},  # MAL-2026-6496
    "@dervix/engine.io": set(),  # MAL-2026-10474
    "@dervix/socket.io": set(),  # MAL-2026-10475

    # markable-table family (July 13 2026)
    # Four packages impersonating markdown-table rendering utilities;
    # exact versions published before takedown.
    # OSV MAL-2026-10444/10446/10447/10452
    "markable-table": {"3.1.2", "3.1.3", "3.1.4", "3.1.5", "3.1.6", "3.1.7", "3.1.8"},  # MAL-2026-10444
    "markdown-editable-table": {"2.4.2", "2.4.3", "2.4.4"},  # MAL-2026-10452
    "react-markable-table": {"2.4.10"},  # MAL-2026-10446
    "remarkable-table": {"2.4.11"},  # MAL-2026-10447

    # getd-* dep-confusion cluster (July 13 2026)
    # Ten packages impersonating internal tooling of getd.io; all published
    # at version 0.0.1 with malicious postinstall code.
    # OSV MAL-2026-5465 through MAL-2026-5474
    "getd-content-management": {"0.0.1"},  # MAL-2026-5465
    "getd-eslint-rules": {"0.0.1"},  # MAL-2026-5466
    "getd-handler-api": {"0.0.1"},  # MAL-2026-5467
    "getd-pantallas-cliente": {"0.0.1"},  # MAL-2026-5468
    "getd-transactional-web": {"0.0.1"},  # MAL-2026-5469
    "getd-typescript-eslint-rules": {"0.0.1"},  # MAL-2026-5470
    "getd-ui-library": {"0.0.1"},  # MAL-2026-5471
    "getd-web-corporativa": {"0.0.1"},  # MAL-2026-5472
    "gethandler-api": {"0.0.1"},  # MAL-2026-5473
    "getui-library": {"0.0.1"},  # MAL-2026-5474

    # Dep-confusion inflated-version batches (July 13-14 2026)
    # Packages published at abnormally high / date-formatted version numbers
    # targeting internal CI/CD pipelines of various organizations.
    # OSV MAL-2025-6695 / MAL-2026-5393/5399/5517/10401/10415/10416/10419/10421/10422/10443/10458/10459/10498/10509
    "firefly-utilities-helper": {"99.9.0", "99.9.1"},  # MAL-2026-5517
    "test_adminet": {"99.9.9"},  # MAL-2026-10509
    "home-sections-web-ui": {"99.9.9"},  # MAL-2026-10443
    "kuaishou": {"99.9.10", "99.9.9"},  # MAL-2026-10416
    "portway": {"99.9.1"},  # MAL-2026-10421
    "sso-users-detection": {"99.9.1"},  # MAL-2026-10422
    "notifications-broadcast": {"99.9.1"},  # MAL-2026-10419
    "frontend-regulations": {"99.9.1"},  # MAL-2026-10415
    "compliancepolicyserv": {"9.9.11"},  # MAL-2026-10458
    "connectedmerchantsserv": {"9.9.11"},  # MAL-2026-10459
    "eslint-angular-react": {"110.0.1"},  # MAL-2026-10498
    "@espn-ping/react-dmed-oauth": {"666.0.0"},  # MAL-2026-10401
    "@sflyinc-knapsack/shutterfly-react": {"999.0.0"},  # MAL-2026-5393
    "kraken-ui": {"999.0.0"},  # MAL-2026-5399
    "amdocs-core-package": {"11.11.11"},  # MAL-2025-6695

    # nottuff/abuden/ratelimitsucks/ishowfeet/speed/sixseven/imillegal/
    # timmytuffknuckles/backupsitetuff npm worm cluster (July 13 2026)
    # A single prolific actor flooded npm with 127-package throwaway
    # malware cluster, all sharing versions 1.1.7 / 1.7.7 / 2.0.0 and a
    # postinstall credential-exfiltration payload. OSV IDs cover MAL-2026-5914
    # through MAL-2026-10390 (not all sequential).
    "nottuff1": {"1.1.7", "1.7.7", "2.0.0"},
    "nottuff2": {"1.1.7", "1.7.7", "2.0.0"},
    "nottuff3": {"1.1.7", "1.7.7", "2.0.0"},
    "nottuff4": {"1.1.7", "1.7.7", "2.0.0"},
    "nottuff5": {"1.1.7", "1.7.7", "2.0.0"},
    "nottuff6": {"1.1.7", "1.7.7", "2.0.0"},
    "nottuff7": {"1.1.7", "1.7.7", "2.0.0"},
    "nottuff8": {"1.1.7", "1.7.7", "2.0.0"},
    "nottuff9": {"1.1.7", "1.7.7", "2.0.0"},
    "nottuff10": {"1.1.7", "1.7.7", "2.0.0"},
    "nottuff11": {"1.1.7", "1.7.7", "2.0.0"},
    "nottuff12": {"1.1.7", "1.7.7", "2.0.0"},
    "nottuff13": {"1.1.7", "1.7.7", "2.0.0"},
    "nottuff14": {"1.1.7", "1.7.7", "2.0.0"},
    "nottuff15": {"1.1.7", "1.7.7", "2.0.0"},
    "nottuff16": {"1.1.7", "1.7.7", "2.0.0"},
    "nottuff17": {"1.1.7", "1.7.7", "2.0.0"},
    "nottuff18": {"1.1.7", "1.7.7", "2.0.0"},
    "nottuff19": {"1.1.7", "1.7.7", "2.0.0"},
    "nottuff20": {"1.1.7", "1.7.7", "2.0.0"},
    "nottuff21": {"1.1.7", "1.7.7", "2.0.0"},
    "nottuff22": {"1.1.7", "1.7.7", "2.0.0"},
    "nottuff23": {"1.1.7", "1.7.7", "2.0.0"},
    "nottuff24": {"1.1.7", "1.7.7", "2.0.0"},
    "nottuff25": {"1.1.7", "1.7.7", "2.0.0"},
    "nottuff26": {"1.1.7", "1.7.7", "2.0.0"},
    "nottuff27": {"1.1.7", "1.7.7"},
    "nottuff28": {"1.1.7", "1.7.7", "2.0.0"},
    "nottuff29": {"1.1.7", "1.7.7", "2.0.0"},
    "nottuff30": {"1.1.7", "1.7.7", "2.0.0"},
    "abuden1": {"1.1.7", "1.7.7", "2.0.0"},
    "abuden2": {"1.1.7", "1.7.7", "2.0.0"},
    "abuden3": {"1.1.7", "1.7.7", "2.0.0"},
    "abuden4": {"1.1.7", "1.7.7", "2.0.0"},
    "abuden5": {"1.1.7", "1.7.7", "2.0.0"},
    "abuden21": {"1.1.7", "1.7.7", "2.0.0"},
    "abuden22": {"1.1.7", "1.7.7", "2.0.0"},
    "abuden23": {"1.1.7", "1.7.7", "2.0.0"},
    "abuden24": {"1.1.7", "1.7.7", "2.0.0"},
    "abuden25": {"1.1.7", "1.7.7", "2.0.0"},
    "abuden26": {"1.1.7", "1.7.7", "2.0.0"},
    "abuden27": {"1.1.7", "1.7.7", "2.0.0"},
    "abuden28": {"1.1.7", "1.7.7", "2.0.0"},
    "abuden29": {"1.1.7", "1.7.7", "2.0.0"},
    "abuden210": {"1.1.7", "1.7.7", "2.0.0"},
    "abuden211": {"1.1.7", "1.7.7", "2.0.0"},
    "abuden212": {"1.1.7", "1.7.7", "2.0.0"},
    "abuden213": {"1.1.7", "1.7.7", "2.0.0"},
    "abuden214": {"1.1.7", "1.7.7", "2.0.0"},
    "abuden215": {"1.1.7", "1.7.7", "2.0.0"},
    "abuden216": {"1.1.7", "1.7.7", "2.0.0"},
    "abuden217": {"1.1.7", "1.7.7", "2.0.0"},
    "abuden218": {"1.1.7", "1.7.7", "2.0.0"},
    "abuden219": {"1.1.7", "1.7.7", "2.0.0"},
    "abuden220": {"1.1.7", "1.7.7", "2.0.0"},
    "abuden221": {"1.1.7", "1.7.7", "2.0.0"},
    "abuden222": {"1.1.7", "1.7.7", "2.0.0"},
    "abuden223": {"1.1.7", "1.7.7", "2.0.0"},
    "abuden224": {"1.1.7", "1.7.7", "2.0.0"},
    "abuden225": {"1.1.7", "1.7.7", "2.0.0"},
    "abuden226": {"1.1.7", "1.7.7", "2.0.0"},
    "abuden227": {"1.1.7", "1.7.7", "2.0.0"},
    "abuden228": {"1.1.7", "1.7.7", "2.0.0"},
    "abuden229": {"1.1.7", "1.7.7", "2.0.0"},
    "abuden230": {"1.1.7", "1.7.7", "2.0.0"},
    "ratelimitsucks": {"1.1.7", "1.7.7", "2.0.0"},
    "ratelimitsucks1": {"1.1.3", "1.1.7", "2.0.0"},
    "ratelimitsucks2": {"1.1.4", "1.1.7", "1.7.7", "2.0.0"},
    "ratelimitsucks3": {"1.1.5", "1.1.7", "2.0.0"},
    "ratelimitsucks4": {"1.1.6", "1.1.7", "2.0.0"},
    "ratelimitsucks5": {"1.1.7", "1.7.7", "2.0.0"},
    "ratelimitsucks6": {"1.1.7", "1.7.7", "2.0.0"},
    "ratelimitsucks9": {"1.1.7", "2.0.0"},
    "ratelimitsucks10": {"1.1.7", "1.7.7", "2.0.0"},
    "ishowfeet1": {"1.1.7", "1.7.7", "2.0.0"},
    "ishowfeet2": {"1.1.7", "1.7.7", "2.0.0"},
    "ishowfeet3": {"1.1.7", "1.7.7", "2.0.0"},
    "ishowfeet4": {"1.1.7", "1.7.7", "2.0.0"},
    "ishowfeet5": {"1.1.7", "1.7.7", "2.0.0"},
    "ishowfeet6": {"1.1.7", "1.7.7", "2.0.0"},
    "ishowfeet7": {"1.1.7", "1.7.7", "2.0.0"},
    "ishowfeet8": {"1.1.7", "1.7.7", "2.0.0"},
    "ishowfeet9": {"1.1.7", "1.7.7", "2.0.0"},
    "ishowfeet10": {"1.1.7", "1.7.7", "2.0.0"},
    "ishowfeet11": {"1.1.7", "1.7.7", "2.0.0"},
    "ishowfeet12": {"1.1.7", "1.7.7", "2.0.0"},
    "ishowfeet13": {"1.1.7", "1.7.7", "2.0.0"},
    "ishowfeet14": {"1.1.7", "1.7.7", "2.0.0"},
    "ishowfeet15": {"1.1.7", "1.7.7", "2.0.0"},
    "ishowfeet16": {"1.1.7", "1.7.7", "2.0.0"},
    "ishowfeet17": {"1.1.7", "1.7.7", "2.0.0"},
    "ishowfeet18": {"1.1.7", "1.7.7", "2.0.0"},
    "ishowfeet19": {"1.1.7", "1.7.7", "2.0.0"},
    "ishowfeet20": {"1.1.7", "1.7.7", "2.0.0"},
    "speed1": {"1.1.7", "2.0.0"},
    "speed2": {"1.1.7", "2.0.0"},
    "speed3": {"1.1.7", "2.0.0"},
    "speed4": {"1.1.7", "2.0.0"},
    "speed5": {"1.1.7", "2.0.0"},
    "sixseven1": {"1.1.7", "1.7.7", "2.0.0"},
    "sixseven2": {"1.1.7", "1.7.7", "2.0.0"},
    "sixseven3": {"1.1.7", "1.7.7", "2.0.0"},
    "sixseven4": {"1.1.7", "1.7.7", "2.0.0"},
    "sixseven5": {"1.1.7", "1.7.7", "2.0.0"},
    "sixseven6": {"1.1.7", "1.7.7", "2.0.0"},
    "sixseven7": {"1.7.7"},
    "sixseven8": {"1.7.7"},
    "sixseven9": {"1.7.7"},
    "sixseven10": {"1.7.7"},
    "imillegal1": {"1.1.7", "1.7.7", "2.0.0"},
    "imillegal2": {"1.1.7", "1.7.7", "2.0.0"},
    "imillegal3": {"1.1.7", "1.7.7", "2.0.0"},
    "imillegal4": {"1.1.7", "1.7.7", "2.0.0"},
    "imillegal5": {"1.1.7", "1.7.7", "2.0.0"},
    "timmytuffknuckles3": {"1.1.7"},
    "timmytuffknuckles6": {"1.1.7"},
    "timmytuffknuckles9": {"1.1.7"},
    "backupsitetuff3": {"1.1.7", "2.0.0"},
    "backupsitetuff6": {"1.1.7", "2.0.0"},
    "backupsitetuff9": {"1.1.7", "2.0.0"},
    "backupsitetuff10": {"1.1.7", "2.0.0"},
    "backup1-gg": {"2.0.0"},
    "backup2-asd": {"2.0.0"},
    "backup3-ff": {"2.0.0"},
    "backup4-gasp": {"2.0.0"},
    "backup5-updated": {"2.0.0"},
    "backupgenuine-updated": {"2.0.0"},

    # Random-words any-version packages (same actor; July 13 2026)
    # Companion packages to the nottuff/abuden/ratelimitsucks cluster;
    # published at ANY version with identical malicious postinstall payload.
    # OSV MAL-2026-10220/10282/10284/10295-10305/10331-10335/10361-10364/10386-10387/10394-10396/10430
    "acidic": set(),  # MAL-2026-10282
    "apps-gpt": set(),  # MAL-2026-10284
    "bismillahitidakimas": set(),  # MAL-2026-10295
    "bomboclatwallahi": set(),  # MAL-2026-10296
    "captainindia": set(),  # MAL-2026-10297
    "changiairportpromax": set(),  # MAL-2026-10298
    "crazynut": set(),  # MAL-2026-10299
    "dogfood-search": set(),  # MAL-2026-10300
    "fflc-updated": set(),  # MAL-2026-10301
    "gpapp": set(),  # MAL-2026-10302
    "gpapps": set(),  # MAL-2026-10303
    "howmanygreatbritain": set(),  # MAL-2026-10304
    "ilovefemboys": set(),  # MAL-2026-10305
    "kirkland": set(),  # MAL-2026-10331
    "lowkeybored": set(),  # MAL-2026-10332
    "lowkirkuenly": set(),  # MAL-2026-10333
    "midnightrush": set(),  # MAL-2026-10334
    "miguelphonk": set(),  # MAL-2026-10335
    "omglucidesotuff": set(),  # MAL-2026-10361
    "omgyesyesyes": set(),  # MAL-2026-10362
    "openai-apps": set(),  # MAL-2026-10363
    "pasirianspirit": set(),  # MAL-2026-10364
    "testdonotredeemit": set(),  # MAL-2026-10386
    "thebigyahu": set(),  # MAL-2026-10387
    "vibewise": set(),  # MAL-2026-10394
    "vibewise-cli": set(),  # MAL-2026-10395
    "whatsadmaidk": set(),  # MAL-2026-10396
    "@jplopezy/connectivity-test-do-not-install": set(),  # MAL-2026-10220
    "prettier-plugin-base": set(),  # MAL-2026-10430

    # tipsen / antsrctest single-version malware cluster (July 13 2026)
    # Small throwaway cluster; likely researcher or red-team exploration.
    # OSV MAL-2026-10038/10074/10075/10283/10391/10392/10393
    "antsrcsrctest": {"1.0.0"},  # MAL-2026-10038
    "testis-pack": {"1.0.0"},  # MAL-2026-10074
    "testudo-pack": {"1.0.0"},  # MAL-2026-10075
    "tipsen-last": {"1.0.0"},  # MAL-2026-10391
    "tipsen-last-pls": {"1.0.0"},  # MAL-2026-10392
    "tipsen-poc-again": {"1.0.0"},  # MAL-2026-10393
    "another-poc-by-tipsen": {"1.0.0"},  # MAL-2026-10283

    # @gt-test-exp/profiler-exp-* any-version malware cluster (July 13 2026)
    # Fourteen packages in the @gt-test-exp scope; all published with
    # malicious payload and flagged by OpenSSF. OSV MAL-2026-10238 through 10250.
    "@gt-test-exp/profiler-exp-00000001": set(),  # MAL-2026-10238
    "@gt-test-exp/profiler-exp-00000002": set(),  # MAL-2026-10239
    "@gt-test-exp/profiler-exp-00000003": set(),  # MAL-2026-10240
    "@gt-test-exp/profiler-exp-00000004": set(),  # MAL-2026-10241
    "@gt-test-exp/profiler-exp-00000005": set(),  # MAL-2026-10242
    "@gt-test-exp/profiler-exp-00000006": set(),  # MAL-2026-10243
    "@gt-test-exp/profiler-exp-00000008": set(),  # MAL-2026-10244
    "@gt-test-exp/profiler-exp-00000009": set(),  # MAL-2026-10245
    "@gt-test-exp/profiler-exp-00000010": set(),  # MAL-2026-10246
    "@gt-test-exp/profiler-exp-00000011": set(),  # MAL-2026-10247
    "@gt-test-exp/profiler-exp-00000012": set(),  # MAL-2026-10248
    "@gt-test-exp/profiler-exp-00000013": set(),  # MAL-2026-10249
    "@gt-test-exp/profiler-exp-00000014": set(),  # MAL-2026-10250

    # Miscellaneous npm malware batch (July 13-14 2026)
    # Includes dep-confusion targets, credential-exfiltration stubs, and
    # postinstall droppers across diverse topics. OSV MAL-2026-10062 through
    # MAL-2026-10522 (selected IDs; see per-entry comments for exact IDs).
    "es6-codify": {"1.0.0", "1.0.1", "1.1.0", "1.2.0", "1.3.0", "1.4.0", "2.0.0", "2.1.0", "2.2.0"},  # MAL-2026-10062
    "execfences": {"5.0.2", "5.0.3", "5.0.4", "5.0.5", "5.0.6", "5.1.0", "5.1.1"},  # MAL-2026-10118
    "eth-react-redirection": {"1.0.0", "1.0.1", "1.0.2"},  # MAL-2026-10127
    "marked-prettier": {"1.0.4", "1.0.5"},  # MAL-2026-10143
    "mdb-vite": {"1.5.2"},  # MAL-2026-10144
    "tokenization-util": {"0.1.0", "0.2.0", "1.1.0"},  # MAL-2026-6440
    "bs58-86": {"6.0.1", "6.0.2"},  # MAL-2026-6448
    "loading-sessions": {"6.13.2"},  # MAL-2026-10471
    "@torbeck/heap": {"4.3.10", "4.3.11", "4.3.14"},  # MAL-2026-10405
    "@torbeck/priority-queue": {"6.3.6", "6.3.7", "6.3.9"},  # MAL-2026-10472
    "claude-team-tracker": {"1.2.0", "1.2.1", "1.2.2"},  # MAL-2026-10473
    "@kl-starfish/test-01": {"2.0.0"},  # MAL-2026-10097
    "@car_loans/dealerships-approval": {"7.1.5"},  # MAL-2026-10397
    "@db-tools/main-app": {"2026.6.30"},  # MAL-2026-10398
    "@equansservices/codex": {"1.0.1"},  # MAL-2026-10399
    "@equansservices/tool": {"1.0.2"},  # MAL-2026-10400
    "@iana-rzms/bff-sdk": {"1.0.0"},  # MAL-2026-10403
    "@ica-gaming/slot-engine": {"1.1.0"},  # MAL-2026-10404
    "async-chain-dom": {"1.3.5"},  # MAL-2026-10406
    "awesome-terminal": {"1.0.3"},  # MAL-2026-10407
    "chain-js-utils": {"2.1.1"},  # MAL-2026-10408
    "cold-debug-elevator": {"1.0.1", "1.0.3", "1.0.4"},  # MAL-2026-10409
    "cookie-phase": {"2.3.5"},  # MAL-2026-10410
    "cookie-sign": {"2.3.5"},  # MAL-2026-10411
    "env-stream": {"1.0.1", "1.0.2"},  # MAL-2026-10412
    "eth-base": {"1.0.0"},  # MAL-2026-10413
    "express-request-engine": {"3.6.3"},  # MAL-2026-10414
    "minigptcore": {"4.0.8"},  # MAL-2026-10417
    "note-utilities": {"2.1.2"},  # MAL-2026-10418
    "supertokens-web": {"1.16.0"},  # MAL-2026-10423
    "terminal-mascot": {"3.5.2"},  # MAL-2026-10424
    "trinity-scheme": {"20.0.0"},  # MAL-2026-10425
    "svg-fetcher": {"2.4.1"},  # MAL-2026-10427
    "sysb1": {"1.0.0"},  # MAL-2026-10428
    "@nsub/nitxe": {"1.0.1"},  # MAL-2026-10429
    "@tailwind-ts/eslint-plugin": {"0.1.0", "0.2.0", "0.3.0"},  # MAL-2026-10431
    "animated-css-kit": {"1.0.1"},  # MAL-2026-10432
    "chain-guardian": {"1.1.0"},  # MAL-2026-10433
    "env-fast": {"1.0.0"},  # MAL-2026-10434
    "fetchcraft": {"1.0.0", "1.0.1"},  # MAL-2026-10435
    "jest-formatter": {"1.0.0"},  # MAL-2026-10436
    "jsonfb": {"1.1.0", "1.1.0-beta.1", "1.1.0-beta.2"},  # MAL-2026-10437
    "netspeedutil": {"1.0.13"},  # MAL-2026-10438
    "react-hot-svg": {"1.1.4", "1.1.5"},  # MAL-2026-10439
    "@oliviamcdaniel12/safer-buffer": {"2.2.0", "2.2.1"},  # MAL-2026-10442
    "@sqlite-group/schema-generator": {"1.0.2"},  # MAL-2026-10448
    "auth-gen-next": {"1.7.13"},  # MAL-2026-10449
    "font-hub": {"1.5.2"},  # MAL-2026-10450
    "gifuct": {"2.1.2"},  # MAL-2026-10451
    "router-processor": {"1.5.2"},  # MAL-2026-10453
    "@origindev/ethaccount": {"1.0.0", "1.0.1"},  # MAL-2026-10455
    "@spzhongwin/skill-logger-plugin": {"1.0.10", "1.0.5", "1.0.7"},  # MAL-2026-10456
    "cktool-core": {"1.0.0", "1.0.1", "1.0.2"},  # MAL-2026-10457
    "datavaultx": {"1.7.1"},  # MAL-2026-10460
    "gptlite": {"4.0.8"},  # MAL-2026-10461
    "hehehee": {"1.0.9"},  # MAL-2026-10462
    "@sheltr_/agent": {"1.0.2"},  # MAL-2026-10469
    "@uw010010/vite-tree": {"3.4.2", "3.4.3", "3.6.1"},  # MAL-2026-10470
    "@sqlite-panel/createsql": {"1.0.0"},  # MAL-2026-10490
    "assertcoreutils": {"2.3.2", "2.3.3"},  # MAL-2026-10491
    "font-huge": {"2.5.3"},  # MAL-2026-10492
    "insomnia-plugin-poc-m4gester-run": {"1.0.0"},  # MAL-2026-10493
    "@quickcall/krew": {"0.1.7"},  # MAL-2026-10494
    "@quukk/opencode-clawmessenger": {"1.1.10"},  # MAL-2026-10495
    "bubblestring": {"1.1.4"},  # MAL-2026-10496
    "ddok-modal": {"1.0.0"},  # MAL-2026-10497
    "eth-lib-utils": {"5.2.3", "5.2.4", "5.2.5"},  # MAL-2026-10499
    "express-bunker": {"6.1.0"},  # MAL-2026-10500
    "filewisee": {"0.1.0", "0.1.1"},  # MAL-2026-10501
    "gamified-trading-system": {"3.1.0", "3.6.2"},  # MAL-2026-10502
    "n8n-nodes-rce-poc": {"1.0.0"},  # MAL-2026-10503
    "express-ini": {"12.1.10"},  # MAL-2026-10505
    "@omniwatch-wick/cli": {"0.1.2"},  # MAL-2026-10486
    "@outsmartly/metaobjects": {"0.3.3-rc.1"},  # MAL-2026-10487
    "permcarmserver": {"1.0.0"},  # MAL-2026-10488
    "permcserver": {"1.0.0", "1.0.1", "1.0.3"},  # MAL-2026-10489
    "react-icons-svgo": {"1.0.0", "1.5.3", "1.5.4"},  # MAL-2026-10482
    "route-processor": {"3.1.5"},  # MAL-2026-10483
    "@sectest429/hello-npm-world": {"1.0.3"},  # MAL-2026-10478

    # @asyncapi maintainer-account compromise (July 2026)
    # Four packages in the @asyncapi scope had specific versions injected with
    # a malicious payload following an account takeover. These are legitimate
    # open-source AsyncAPI tooling packages with broad ecosystem adoption;
    # only the listed versions are compromised.
    # OSV MAL-2025-190636 (@asyncapi/generator)
    "@asyncapi/generator": {"2.8.5", "2.8.6", "3.3.1"},
    # OSV MAL-2025-190643 (@asyncapi/specs)
    "@asyncapi/specs": {"6.8.2", "6.8.3", "6.9.1", "6.10.1", "6.11.2", "6.11.2-alpha.1"},
    # OSV MAL-2025-190656 (@asyncapi/generator-components)
    "@asyncapi/generator-components": {"0.3.2", "0.3.3", "0.7.1"},
    # OSV MAL-2025-190657 (@asyncapi/generator-helpers)
    "@asyncapi/generator-helpers": {"0.2.1", "0.2.2", "1.1.1"},

    # @public-for-cdao dep-confusion cluster (July 14 2026)
    # Six packages impersonating Coinbase/CDAO internal tooling at version
    # 99.99.99 to hijack CI dependency resolution. All detected by OpenSSF.
    # OSV MAL-2026-10599 through MAL-2026-10604
    "@public-for-cdao/abi": {"99.99.99"},      # MAL-2026-10599
    "@public-for-cdao/api": {"99.99.99"},      # MAL-2026-10600
    "@public-for-cdao/common": {"99.99.99"},   # MAL-2026-10601
    "@public-for-cdao/config": {"99.99.99"},   # MAL-2026-10602
    "@public-for-cdao/token": {"99.99.99"},    # MAL-2026-10603
    "@public-for-cdao/types": {"99.99.99"},    # MAL-2026-10604

    # Crypto/DeFi npm credential-stealer cluster (July 14 2026)
    # Fourteen packages impersonating web3/DeFi utilities (bs58, viem, abitype,
    # ethers helpers, Solana key utilities, etc.); each exfiltrates wallet keys
    # and credentials on import. Versions pinned per OSV affected.versions.
    # OSV MAL-2026-10523 (@tabrex/bs58)
    "@tabrex/bs58": {"6.0.3"},
    # OSV MAL-2026-10524 (@velkov/isows)
    "@velkov/isows": {"1.0.10"},
    # OSV MAL-2026-10529 (@wrenfield/abitype)
    "@wrenfield/abitype": {"1.2.6", "1.2.7"},
    # OSV MAL-2026-10571 (@wrenfield/viem)
    "@wrenfield/viem": {"2.53.4"},
    # OSV MAL-2026-10611 (@web3-helpers/core)
    "@web3-helpers/core": {"1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4", "1.0.5", "1.0.6"},
    # OSV MAL-2026-10549 (abi-encode)
    "abi-encode": {"1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4"},
    # OSV MAL-2026-10552 (eth-dev)
    "eth-dev": {"1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4"},
    # OSV MAL-2026-10572 (eth-wallet-helpers)
    "eth-wallet-helpers": {"1.0.0", "1.0.1", "1.0.2", "1.0.3"},
    # OSV MAL-2026-10580 (ethers-core)
    "ethers-core": {"6.13.7"},
    # OSV MAL-2026-10613 (ethereum-lib-utils)
    "ethereum-lib-utils": {"1.3.7"},
    # OSV MAL-2026-10591 (solana-key-utils)
    "solana-key-utils": {"1.0.1", "1.0.2", "1.0.3"},
    # OSV MAL-2026-10606 (base58-utils)
    "base58-utils": {"1.0.0", "1.0.1", "1.0.3", "1.0.4", "1.0.5"},
    # OSV MAL-2026-10608 (chain-sdk-js)
    "chain-sdk-js": {"1.0.2", "1.0.3", "1.0.4", "1.0.5"},
    # OSV MAL-2026-10531 (chain-devkit)
    "chain-devkit": {"1.0.0"},
    # OSV MAL-2026-10586 (crypto-validate-lib)
    "crypto-validate-lib": {"1.0.1", "1.0.2", "1.0.3"},

    # Vite scope typosquat cluster (July 14 2026)
    # Five packages under attacker-controlled scopes mimicking the Vite build
    # tool; each publishes a single version with a credential-exfiltration
    # postinstall payload. OSV MAL-2026-10525 through MAL-2026-10528, MAL-2026-10619
    "@vite-mcp/vite-type": {"6.44.1"},   # MAL-2026-10525
    "@vite-pro/vite-ui": {"2.5.10"},     # MAL-2026-10526
    "@vite-ts/vite-ui": {"6.44.1"},      # MAL-2026-10527
    "@vitets/vite-ts": {"1.5.10"},       # MAL-2026-10528
    "@vite-js/vui": {"7.14.16"},         # MAL-2026-10619

    # Developer-toolkit typosquat cluster (July 14 2026)
    # Ten packages impersonating popular Node.js utilities by appending "dev",
    # "box", "core", "plus", or "wrapper" to well-known package names (chalk,
    # dayjs, cheerio, moment, axios, stripe, twilio, yargs, openai).
    # Each publishes a single version with a malicious postinstall payload.
    # OSV MAL-2026-10583 through MAL-2026-10594
    "chalkdev": {"1.0.0"},       # MAL-2026-10583
    "chalkdevx": {"2.0.0"},      # MAL-2026-10584
    "cheeriobox": {"1.0.0"},     # MAL-2026-10585
    "dayjscore": {"1.0.0"},      # MAL-2026-10587
    "momenntjs": {"1.0.0"},      # MAL-2026-10588
    "nodeaxois": {"1.0.0"},      # MAL-2026-10589
    "openaiwrapper": {"1.0.0"},  # MAL-2026-10590
    "stripedev": {"1.0.0"},      # MAL-2026-10592
    "twiliobox": {"1.0.0"},      # MAL-2026-10593
    "yargsplus": {"1.0.0"},      # MAL-2026-10594

    # chai-as-* / nodemon-plint extension batch (July 14 2026)
    # Three new chai-as-* malware packages (chai-as-act, chai-as-hardened,
    # chai-as-structured) extending the ongoing chai-as-* typosquat campaign
    # already tracked above, plus nodemon-plint (any-version wildcard).
    # OSV MAL-2026-10607 (chai-as-act), MAL-2026-10621 (chai-as-hardened),
    # MAL-2026-10622 (chai-as-structured), MAL-2026-10595 (nodemon-plint)
    "chai-as-act": {"1.0.2"},         # MAL-2026-10607
    "chai-as-hardened": {"7.0.9"},    # MAL-2026-10621
    "chai-as-structured": {"7.0.5"},  # MAL-2026-10622
    "nodemon-plint": set(),           # MAL-2026-10595

    # akshajrawat DI-token / utility malware cluster (July 14 2026)
    # Fourteen any-version packages under attacker account akshajrawat and
    # associated scopes (@akshajrawat/*, @codex2005/*); includes generic
    # UI-utility names used as DI token packages to shadow internal tooling.
    # OSV MAL-2026-10554 through MAL-2026-10570
    "@akshajrawat/plugin-repo-cli": set(),  # MAL-2026-10554
    "@codex2005/logger-core": set(),        # MAL-2026-10555
    "akshajrawat.utils": set(),             # MAL-2026-10558
    "avatar-forge": set(),                  # MAL-2026-10559
    "clipboard-drop": set(),                # MAL-2026-10560
    "dom-weave": set(),                     # MAL-2026-10561
    "duration-kit": set(),                  # MAL-2026-10562
    "humanize-kit": set(),                  # MAL-2026-10563
    "relative-time-live": set(),            # MAL-2026-10565
    "sight-bind": set(),                    # MAL-2026-10566
    "string-morph": set(),                  # MAL-2026-10567
    "sync-logger": set(),                   # MAL-2026-10568
    "temp-cloak": set(),                    # MAL-2026-10569
    "valid-scope": set(),                   # MAL-2026-10570

    # @cw-ui / micro-ui-loader dep-confusion cluster (July 14 2026)
    # Three any-version packages impersonating a corporate UI component
    # library; both scoped and unscoped variants published to shadow
    # private packages in internal CI. OSV MAL-2026-10556/10557/10564
    "@cw-ui/asio-neon-themes": set(),   # MAL-2026-10556
    "@cw-ui/micro-ui-loader": set(),    # MAL-2026-10557
    "micro-ui-loader": set(),           # MAL-2026-10564

    # SQLite-namespace fake packages (July 14 2026)
    # Two any-version packages under attacker-created @sqlite-clone and
    # @sqlite-group scopes shadowing earlier @sqlite-group/schema-generator
    # (already tracked above). OSV MAL-2026-10577/10578
    "@sqlite-clone/nodesql": set(),      # MAL-2026-10577
    "@sqlite-group/sql-creator": set(),  # MAL-2026-10578

    # Older-ID packages updated July 14 2026
    # Five packages whose OSV MAL records were first filed earlier but modified
    # on 2026-07-14 (first appearance in our floor date); all have >=0 ranges.
    "class-weaver": set(),                  # MAL-2026-4521
    "@rockawayx/utils": set(),              # MAL-2026-5462
    "unified-ui-components-library": set(), # MAL-2026-5648
    "class-synth": set(),                   # MAL-2026-5730
    "@resolvx/core": set(),                 # MAL-2026-5798

    # Miscellaneous npm malware batch July 14 2026
    # Diverse set of packages detected by OpenSSF Package Analysis on July 14 2026;
    # each carries a credential-exfiltration or postinstall dropper payload.
    # @ayunlove/bails  MAL-2026-10596  monitoring-service  MAL-2026-10597
    # monitoring-service-util  MAL-2026-10598  smb-common-uikit  MAL-2026-10615
    # smb-portal-uikit  MAL-2026-10616
    "@ayunlove/bails": set(),         # MAL-2026-10596
    "monitoring-service": set(),      # MAL-2026-10597
    "monitoring-service-util": set(), # MAL-2026-10598
    "smb-common-uikit": {"15.2.0"},   # MAL-2026-10615
    "smb-portal-uikit": {"18.1.1"},   # MAL-2026-10616
    # home-mp-commons (dep-confusion 999.x), process-status-widget (dep-confusion 99.x)
    "home-mp-commons": {"999.0.1", "999.0.3"},  # MAL-2026-10553
    "process-status-widget": {"99.9.1"},         # MAL-2026-10581
    # cbr-internal-utils, lusha-iam-widgets, utils-style-engine — internal-tooling shadows
    "cbr-internal-utils": {"2.2.2"},    # MAL-2026-10530
    "lusha-iam-widgets": {"1.5.2"},     # MAL-2026-10533
    "utils-style-engine": {"10.2.4"},   # MAL-2026-10609
    # motion-pull, @amedit/vercel-builder-probe — any-version wildcards
    "motion-pull": set(),                      # MAL-2026-10534
    "@amedit/vercel-builder-probe": set(),      # MAL-2026-10548
    # fluterjs, my-empty-package, n8n-nodes-social-facebook — throwaway single-version malware
    "fluterjs": {"1.0.0"},                 # MAL-2026-10532
    "my-empty-package": {"1.0.0"},         # MAL-2026-10535
    "n8n-nodes-social-facebook": {"0.1.96"},  # MAL-2026-10536
    # neon-postgres, neteller, skrill cluster — payment/infra API typosquats
    "neon-postgres": {"3.5.0", "3.5.1"},   # MAL-2026-10537
    "neteller": {"1.0.0"},                  # MAL-2026-10538
    "skrill": {"1.0.0"},                    # MAL-2026-10542
    "skrill-payments": {"1.0.0"},           # MAL-2026-10543
    "skrill-sdk": {"1.0.0"},                # MAL-2026-10544
    # postcss-animatecss, postcss-processor-utils, postcss-selector-minify — PostCSS typosquats
    "postcss-animatecss": {"1.0.1", "1.0.2"},  # MAL-2026-10539
    "postcss-processor-utils": {"1.0.2"},       # MAL-2026-10540
    "postcss-selector-minify": {"2.0.0"},       # MAL-2026-10614
    # proxy-seller-mcp, vite-plugin-model, viteplugiin, vite-plugin-config-paths
    "proxy-seller-mcp": {"0.1.7"},          # MAL-2026-10541
    "vite-plugin-model": {"1.0.0"},         # MAL-2026-10545
    "viteplugiin": {"1.0.28"},              # MAL-2026-10546
    "vite-plugin-config-paths": {"1.4.2"},  # MAL-2026-10574
    # bimi-maker, async-mutex-v2, ahooks-3.7.8, assertion-utils-js
    "bimi-maker": {"8.2.4"},                # MAL-2026-10579
    "async-mutex-v2": {"2.1.0"},            # MAL-2026-10582
    "ahooks-3.7.8": {"13.1.1"},             # MAL-2026-10620
    "assertion-utils-js": {"2.4.3"},        # MAL-2026-10612
    # @radivi-ui/react-dialog, harpoon-package, web-pop, http-ws-listener
    "@radivi-ui/react-dialog": {"1.1.3", "1.1.4"},  # MAL-2026-10605
    "harpoon-package": {"1.0.0", "1.1.0", "1.2.0"}, # MAL-2026-10573
    "web-pop": {"2.3.5"},                   # MAL-2026-10575
    "http-ws-listener": {"1.0.5"},          # MAL-2026-10623

    # CanisterWorm @emilgroup npm publisher-account compromise (July 15 2026)
    # A malicious actor hijacked the npm publisher account for the @emilgroup scope
    # and injected a backdoor payload into 27 insurance/fintech SDK packages published
    # under that scope. The compromised versions carry a reverse-shell/credential-
    # exfiltration payload; uncompromised versions exist at other version numbers.
    # Sources: https://socket.dev/blog/canisterworm-npm-publisher-compromise-deploys-backdoor-across-29-packages
    #          https://research.jfrog.com/post/canister-worm/
    # OSV MAL-2026-2031 through 2077
    "@emilgroup/account-sdk": {"1.41.1", "1.41.2"},                    # MAL-2026-2031
    "@emilgroup/account-sdk-node": {"1.40.1", "1.40.2"},               # MAL-2026-2032
    "@emilgroup/accounting-sdk": {"1.27.1", "1.27.2", "1.27.3"},       # MAL-2026-2033
    "@emilgroup/accounting-sdk-node": {"1.26.1", "1.26.2"},            # MAL-2026-2034
    "@emilgroup/auth-sdk": {"1.25.1", "1.25.2"},                       # MAL-2026-2036
    "@emilgroup/billing-sdk": {"1.56.1", "1.56.2"},                    # MAL-2026-2038
    "@emilgroup/billing-sdk-node": {"1.57.1", "1.57.2"},               # MAL-2026-2039
    "@emilgroup/claim-sdk": {"1.41.1", "1.41.2"},                      # MAL-2026-2041
    "@emilgroup/claim-sdk-node": {"1.39.1", "1.39.2"},                 # MAL-2026-2042
    "@emilgroup/customer-sdk": {"1.54.1", "1.54.2", "1.54.3", "1.54.4", "1.54.5"},  # MAL-2026-2044
    "@emilgroup/customer-sdk-node": {"1.55.1", "1.55.2"},              # MAL-2026-2045
    "@emilgroup/document-sdk": {"1.45.1", "1.45.2"},                   # MAL-2026-2046
    "@emilgroup/document-sdk-node": {
        "1.43.1", "1.43.2", "1.43.3", "1.43.4", "1.43.5", "1.43.6"
    },                                                                   # MAL-2026-2075
    "@emilgroup/gdv-sdk": {"2.6.1", "2.6.2"},                          # MAL-2026-2048
    "@emilgroup/gdv-sdk-node": {"2.6.1", "2.6.2", "2.6.3"},            # MAL-2026-2049
    "@emilgroup/insurance-sdk": {
        "1.97.1", "1.97.2", "1.97.3", "1.97.4", "1.97.6"
    },                                                                   # MAL-2026-2050
    "@emilgroup/insurance-sdk-node": {"1.95.1", "1.95.2"},             # MAL-2026-2051
    "@emilgroup/notification-sdk-node": {"1.4.1", "1.4.2"},            # MAL-2026-2052
    "@emilgroup/partner-portal-sdk": {"1.1.1", "1.1.2", "1.1.3"},      # MAL-2026-2053
    "@emilgroup/partner-portal-sdk-node": {"1.1.1", "1.1.2"},          # MAL-2026-2054
    "@emilgroup/partner-sdk-node": {"1.19.1", "1.19.2"},               # MAL-2026-2055
    "@emilgroup/payment-sdk": {"1.15.1", "1.15.2"},                    # MAL-2026-2056
    "@emilgroup/payment-sdk-node": {"1.23.1", "1.23.2"},               # MAL-2026-2057
    "@emilgroup/public-api-sdk": {"1.33.1", "1.33.2"},                 # MAL-2026-2058
    "@emilgroup/public-api-sdk-node": {"1.35.1", "1.35.2"},            # MAL-2026-2077
    "@emilgroup/tenant-sdk": {"1.34.1", "1.34.2"},                     # MAL-2026-2060
    "@emilgroup/tenant-sdk-node": {"1.33.1", "1.33.2"},                # MAL-2026-2061

    # gulp-jscrambler / jscrambler-metro-plugin maintainer-account compromise (July 15 2026)
    # Specific versions of two legitimate JSScrambler npm packages were injected
    # with a malicious payload following a publisher-account takeover.
    # OSV MAL-2026-10673 (GHSA-2cjx-v4hm-f5gf), MAL-2026-10674 (GHSA-v442-7fpg-636g)
    "gulp-jscrambler": {"8.6.2"},           # MAL-2026-10673
    "jscrambler-metro-plugin": {"9.0.2"},   # MAL-2026-10674

    # @bcs-mi-ui dep-confusion cluster (July 15 2026)
    # Three packages under the @bcs-mi-ui scope published at any version to shadow
    # internal corporate packages; all flagged as fully-compromised by GHSA.
    # OSV MAL-2026-10645 (GHSA-4ppp-p4x6-p4w5), MAL-2026-10646, MAL-2026-10647
    "@bcs-mi-ui/message": set(),            # MAL-2026-10645
    "@bcs-mi-ui/message-block": set(),      # MAL-2026-10646
    "@bcs-mi-ui/test1243npmpacket76": set(), # MAL-2026-10647

    # @pimy-b2cweb dep-confusion cluster (July 15 2026)
    # Two packages published at inflated version 99.99.99 to shadow internal
    # @pimy-b2cweb packages in CI pipelines. Detected by OpenSSF Package Analysis.
    # OSV MAL-2026-10655, MAL-2026-10656
    "@pimy-b2cweb/apiclient-b2cweb-r2": {"99.99.99"},  # MAL-2026-10655
    "@pimy-b2cweb/frontend-lib": {"99.99.99"},          # MAL-2026-10656

    # @sauruslord / zaldy-baileys / ssweb-wp WhatsApp Baileys typosquat cluster (July 15 2026)
    # Multiple packages impersonating the Baileys WhatsApp Web API library;
    # each silently performs unauthorized newsletter actions / exfiltrates credentials
    # on every WebSocket connection. Same actor as the existing @fhkry/baileys entry.
    # OSV MAL-2026-10657 (GHSA-gq5v-w47h-r596), MAL-2026-10658, MAL-2026-10659,
    #     MAL-2026-10660, MAL-2026-10661, MAL-2026-10662, MAL-2026-10663
    "@sauruslord/baileys": set(),                           # MAL-2026-10657
    "@sauruslord/eslint-config": set(),                     # MAL-2026-10658
    "@sauruslord/libsignal": {"2.0.2"},                     # MAL-2026-10659
    "saurus-assets": set(),                                 # MAL-2026-10660
    "sauruslord-baileys": {"3.0.0", "3.0.1", "3.0.2"},     # MAL-2026-10661
    "ssweb-wp": {"1.0.0"},                                  # MAL-2026-10662
    "zaldy-baileys": set(),                                 # MAL-2026-10663

    # @fhkry/* additional packages (July 15 2026)
    # Extension of the @fhkry/baileys entry (MAL-2026-4803) already tracked above;
    # two more forks published by the same actor.
    # OSV MAL-2026-10664, MAL-2026-10665
    "@fhkry/baileys-v2": set(),                                           # MAL-2026-10664
    "@fhkry/x-baileys": {"1.0.0", "1.1.0", "1.2.0", "1.3.0", "1.4.0",
                         "1.5.0", "1.6.0", "1.7.0"},                     # MAL-2026-10665

    # chai-as-byte extension (July 15 2026)
    # Another entry in the ongoing chai-as-* typosquat campaign.
    # OSV MAL-2026-10630
    "chai-as-byte": {"3.1.5", "3.1.6"},  # MAL-2026-10630

    # @ebay/ui-core-react maintainer-account compromise (updated July 15 2026)
    # Multiple specific versions of the legitimate eBay UI component library
    # were found to contain malicious code (GHSA-536f-jp4m-fgrw).
    # OSV MAL-2024-1006
    "@ebay/ui-core-react": {"6.2.5", "9.6.4", "9.6.5", "9.6.6", "9.7.0", "9.8.0", "9.8.1"},

    # ggk-happy CLI typosquat (updated July 15 2026)
    # Impersonates the slopus/happy CLI; includes postinstall credential-exfiltration
    # payload. Published 12 versions before takedown. OSV MAL-2026-4789
    "ggk-happy": {
        "1.0.9", "1.2.0", "1.2.12", "1.2.20", "1.2.22", "1.2.24",
        "1.2.28", "1.2.30", "1.2.32", "1.2.33", "1.2.34", "1.2.43"
    },

    # fhirproxy / fhirproxy-utils malicious loader cluster (updated July 15 2026)
    # fhirproxy@90.0.0 is a thin loader that pulls and executes fhirproxy-utils,
    # which carries the actual credential-exfiltration payload.
    # OSV MAL-2026-5460 (GHSA-g7wh-3cfq-x8m2), MAL-2026-5461
    "fhirproxy": {"90.0.0"},    # MAL-2026-5460
    "fhirproxy-utils": {"1.0.8"},  # MAL-2026-5461

    # fastify-addon Fastify typosquat (updated July 15 2026)
    # Typosquat of the legitimate fastify-plugin package; single version with
    # credential-exfiltration payload. OSV MAL-2026-5566 (GHSA-3237-pr3f-cm2g)
    "fastify-addon": {"5.1.0"},  # MAL-2026-5566

    # webpack-cache-* postinstall malware cluster (updated July 15 2026)
    # Two packages with obfuscated remote-code-execution postinstall loaders.
    # OSV MAL-2026-5579 (GHSA-2p34-5qgm-wr3f), MAL-2026-5580 (GHSA-x29m-589q-wmg6)
    "webpack-cache-cycle": {"0.1.4"},  # MAL-2026-5579
    "webpack-cache-reset": {"0.1.4"},  # MAL-2026-5580

    # yelp-react-component-chaos dep-confusion (updated July 15 2026)
    # Preinstall script collects hostname/username/network info and env var names
    # matching TOKEN/SECRET/KEY patterns; exfiltrates to attacker server.
    # OSV MAL-2026-5515 (GHSA-3chg-w9g2-778v)
    "yelp-react-component-chaos": {"8.14.5"},  # MAL-2026-5515

    # testzapier dep-confusion (updated July 15 2026)
    # OSV MAL-2026-5575
    "testzapier": {"1.0.0", "1.0.1"},  # MAL-2026-5575

    # vite-config-optimizer Vite typosquat (updated July 15 2026)
    # Postinstall hook spawns detached process with credential-exfiltration payload.
    # OSV MAL-2026-5727 (GHSA-5rwj-cgwr-q954)
    "vite-config-optimizer": {"1.1.4"},  # MAL-2026-5727

    # @achuthvp/postinstall-poc (updated July 15 2026)
    # Despite "poc" in the name, confirmed malware: runs system commands and
    # POSTs results to attacker server on npm install. OSV MAL-2026-5741 (GHSA-rpc3-vhwp-44cv)
    "@achuthvp/postinstall-poc": {"1.0.0", "1.0.1", "1.0.2", "1.0.3"},  # MAL-2026-5741

    # patientdocuments dep-confusion / wget exfiltration (updated July 15 2026)
    # Preinstall script runs wget to exfiltrate username, cwd, and network info
    # to an attacker-controlled Cloudflare Worker. OSV MAL-2026-5752 (GHSA-28q9-vg2f-r5m7)
    "patientdocuments": {"75.0.0"},  # MAL-2026-5752

    # ldpbootstrap-jquery Windows PowerShell dropper (updated July 15 2026)
    # Ships and executes an obfuscated PowerShell payload as part of documented usage.
    # 14 versions published before takedown. OSV MAL-2026-5790
    "ldpbootstrap-jquery": {
        "1.0.0", "1.0.2", "1.0.3", "1.0.4", "1.0.5", "1.0.6", "1.0.7",
        "1.0.9", "1.0.10", "1.0.11", "1.0.13", "1.0.14", "1.0.15", "1.0.16"
    },

    # nativescript-swisspost-* dep-confusion cluster (updated July 15 2026)
    # Two packages impersonating SwissPost NativeScript plugins; preinstall hook
    # exfiltrates project-root env vars to attacker server.
    # OSV MAL-2026-5792 (GHSA-vcxp-rm4v-qh5h), MAL-2026-5793
    "nativescript-swisspost-imagepicker": {"52.31.0"},               # MAL-2026-5792
    "nativescript-swisspost-pcc-creative-editor": {"54.16.3"},       # MAL-2026-5793

    # @dsft/ft-* dep-confusion cluster (updated July 15 2026)
    # Preinstall hook in each package reads INIT_CWD and exfiltrates project-root
    # files to attacker server. OSV MAL-2026-5889 (GHSA-5g88-35hm-8xr7), MAL-2026-5890
    "@dsft/ft-element": {"2.5.9"},  # MAL-2026-5889
    "@dsft/ft-utils": {"1.5.8"},    # MAL-2026-5890

    # canary-ci-test dep-confusion (updated July 15 2026)
    # OSV MAL-2026-5972
    "canary-ci-test": {"1.0.0"},  # MAL-2026-5972

    # gpu-accelerator multi-version malware (updated July 15 2026)
    # OSV MAL-2026-5980
    "gpu-accelerator": {"1.4.2", "1.4.3", "1.4.4", "1.4.5", "1.4.6", "1.4.7"},  # MAL-2026-5980

    # hashd-edu postinstall exfiltrator (updated July 15 2026)
    # OSV MAL-2026-6302
    "hashd-edu": {"1.0.0", "1.0.1", "1.0.2", "1.0.4", "1.0.5"},  # MAL-2026-6302

    # web3-eth-util / web3-eth-utils Ethereum typosquat cluster (updated July 15 2026)
    # Both packages impersonate @ethereumjs/util / ethereumjs-util; README is copied
    # verbatim from upstream but postinstall exfiltrates wallet keys.
    # OSV MAL-2026-6325 (GHSA-g69q-p7f8-4jp3), MAL-2026-6326
    "web3-eth-util": {"6.2.8"},   # MAL-2026-6325
    "web3-eth-utils": {"6.2.8"},  # MAL-2026-6326

    # assertcore multi-version credential-exfiltrator (updated July 15 2026)
    # OSV MAL-2026-6365
    "assertcore": {"3.1.7"},  # MAL-2026-6365

    # textshape-css any-version malware (updated July 15 2026)
    # OSV MAL-2026-6475
    "textshape-css": {"1.0.0"},  # MAL-2026-6475

    # @magda/semantic-indexer-sdk (updated July 15 2026)
    # OSV MAL-2025-47009 (GHSA-r2gq-mhfx-9mh3)
    "@magda/semantic-indexer-sdk": {"6.1.0-alpha.0"},  # MAL-2025-47009

    # rhynpm malware (updated July 15 2026)
    # OSV MAL-2025-32206 (GHSA-5jr8-4283-75xm)
    "rhynpm": {"1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4"},  # MAL-2025-32206

    # July 15-16 2026 miscellaneous npm malware batch
    # Diverse packages detected by OpenSSF Package Analysis, Amazon Inspector,
    # and GHSA malware reports; each carries credential-exfiltration or postinstall
    # dropper payloads.
    "better-tailwindcss": {"4.6.3"},                    # MAL-2026-10550
    "elsisi-cli": {"9.9.9"},                             # MAL-2026-10551
    "@leviosa86com/leviosa86-test": {
        "4.999.0", "5.999.0", "6.0.0", "6.2.1"
    },                                                   # MAL-2026-10625
    "leviosa86-test": {"4.999.0"},                       # MAL-2026-10636
    "@react-case/option": {"1.0.0"},                     # MAL-2026-10626
    "@sqlite-frame/nodesql": {"1.0.2", "1.0.3"},         # MAL-2026-10627
    "ai-explain": {"0.3.4"},                             # MAL-2026-10628
    "ai-pro-sdk": {"2.0.1", "2.0.2", "2.0.3", "2.0.4"},  # MAL-2026-10629
    "core-dotenv": {"1.4.1"},                            # MAL-2026-10631
    "cppt-common": {"13.1.1"},                           # MAL-2026-10632
    "creditgauge": {"1.0.0"},                            # MAL-2026-10633
    "estore-client": {"5.0.0"},                          # MAL-2026-10634
    "gmail-changer": {"2.0.2"},                          # MAL-2026-10635
    "mc-reg": {"1.0.3", "1.0.4"},                        # MAL-2026-10637
    "monogrok": {"1.0.30", "1.0.33"},                    # MAL-2026-10638
    "ogensec-sdk": {"1.1.1", "1.2.1"},                   # MAL-2026-10639
    "polygon-toolkit-validation": {"1.0.9", "1.1.0"},   # MAL-2026-10640
    "polygon-toolkit-validator": {"1.1.2"},              # MAL-2026-10641
    "@hkyyy/portal-widget-helper-0601": {"1.0.0"},       # MAL-2026-10648
    "@saladin0x1/js-shared-modules": set(),              # MAL-2026-10649
    "install-skia": {"1.0.0"},                           # MAL-2026-10650
    "iwsdk": {"22.0.0"},                                 # MAL-2026-10651
    "json-bigint-extend": set(),                         # MAL-2026-10652
    "webpack-session-cache": {"0.1.4"},                  # MAL-2026-10653
    "@debile/require-dir": {"1.9.1", "1.9.2"},           # MAL-2026-10654
    "crypto-hasher": {"3.1.2", "3.1.3"},                 # MAL-2026-10666
    "true": {"0.0.1", "0.0.2", "0.0.3", "0.0.4"},       # MAL-2026-10667
    "chain-as-log": {"3.0.1"},                           # MAL-2026-10668
    "dbconnectify": {"1.0.1"},                           # MAL-2026-10669
    "eslintcmd": {"0.2.0"},                              # MAL-2026-10670
    "spytrack": {"1.1.0"},                               # MAL-2026-10671
    "ac-raf-emitter": {"3.0.1"},                         # MAL-2026-10675
    "commonjs-assert": {"1.0.3"},                        # MAL-2026-10676
    "deployowl": {"2.1.0"},                              # MAL-2026-10677
    "ls-env-config": {"1.0.5"},                          # MAL-2026-10678
    "rakibox": {"2.0.0"},                                # MAL-2026-10679
    "syncgrove": {"1.4.0"},                              # MAL-2026-10680
    "code-formatter-setup": {"1.0.0"},                   # MAL-2026-10682
    "formatters.ts": {"14.2.1"},                         # MAL-2026-10683
    "react-hook-scripts": {"5.4.2"},                     # MAL-2026-10684
    "@ddh-libraries/analytics": {"99.0.0"},              # MAL-2026-10686
    "selparsecss-selector": {
        "1.0.0", "1.1.0", "2.0.0", "2.1.0"
    },                                                   # MAL-2026-10687
    "friendly-greeter-demo": {
        "1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4",
        "1.0.6", "1.0.9", "1.0.10", "1.0.11", "1.0.13", "1.0.14"
    },                                                   # MAL-2026-5704
    "internallib_v907": set(),                           # MAL-2026-10691
    "nyt-cms": set(),                                    # MAL-2026-10692

    # July 16–17 2026 npm malware batch: AI-agent C2 cluster, dep-confusion wave
    # (@across-toolkit/*, @hibachi-xyz/* at 99.x), prominent typosquats (astro 7.1.0,
    # nordpass, @equans-services/codex → @openai/codex), and miscellaneous infostealers.
    # OSV MAL-2026-10693 through MAL-2026-10761 plus MAL-2025-6694, MAL-2026-5777/5885/6966.

    # any-version P2P/MCP and WebSocket C2 (introduced: 0 in OSV ranges)
    "claude-token-tracker-mcp": set(),                   # MAL-2026-10693
    "vor8zakon": set(),                                  # MAL-2026-10694
    "ai-p2p": set(),                                     # MAL-2026-10695
    "loader1": set(),                                    # MAL-2026-10696
    "websight-p2p": set(),                               # MAL-2026-10697
    "websight2-p2p": set(),                              # MAL-2026-10698
    "field-plus": set(),                                 # MAL-2026-5777
    "wordpad-text-ui": set(),                            # MAL-2026-5885
    "na-rony-test-karem": set(),                         # MAL-2026-6966
    "my-tailwind-gutenberg-block": set(),                # MAL-2026-10761

    # @across-toolkit dep-confusion (Across Protocol; 99.x versions, July 16 2026)
    "@across-toolkit/eslint-config": {"99.0.0", "99.0.1"},      # MAL-2026-10703
    "@across-toolkit/typescript-config": {"99.0.0", "99.0.1"},  # MAL-2026-10704

    # @hibachi-xyz dep-confusion cluster (5 packages at 99.0.0, July 16 2026)
    # env exfiltration on require(); exact versions pinned; scope also added to suspect list
    "@hibachi-xyz/common": {"99.0.0"},                   # MAL-2026-10712
    "@hibachi-xyz/config": {"99.0.0"},                   # MAL-2026-10713
    "@hibachi-xyz/sdk": {"99.0.0"},                      # MAL-2026-10714
    "@hibachi-xyz/types": {"99.0.0"},                    # MAL-2026-10715
    "@hibachi-xyz/ui": {"99.0.0"},                       # MAL-2026-10716

    # AI-agent / remote-access-tool C2 cluster (July 16 2026)
    # All open outbound WebSocket / PTY tunnels to attacker-controlled infrastructure.
    "@agent-link/agent": {"0.1.269"},                    # MAL-2026-10705
    "@agentvox/host": {"0.1.5"},                         # MAL-2026-10706
    "@ai-support-agent/cli": {"0.3.2-beta.1"},           # MAL-2026-10707
    "@aicommander/agent": {"1.0.34"},                    # MAL-2026-10708
    "@cyberrant-rantai/rantai": {"1.0.15"},              # MAL-2026-10709
    "@equans-services/codex": {"1.0.0"},                 # MAL-2026-10710 (@openai/codex typosquat)
    "@funny-booth/agent-core": {                         # MAL-2026-10711
        "0.1.1", "0.1.2", "0.1.3", "0.1.4", "0.1.5", "0.1.6",
    },
    "@onescience/onecode": {                             # MAL-2026-10717
        "1.14.50-202607161038", "1.14.50-202607161139", "1.14.50-202607161710",
    },
    "@sciagent/cli": {"1.0.68", "1.0.69"},               # MAL-2026-10718
    "@thepayulink/server": {"2.0.0"},                    # MAL-2026-10719
    "@vibelet/cli": {"1.2.154"},                         # MAL-2026-10720
    "@whalent/agent": {"0.3.231"},                       # MAL-2026-10721
    "@whalent/agent-core": {                             # MAL-2026-10722
        "0.3.230", "0.3.231", "0.3.232", "0.3.233",
    },
    "@yeaft/webchat-agent": {"1.0.171"},                 # MAL-2026-10723
    "@yuandc/aica": {"0.1.1", "0.1.4"},                  # MAL-2026-10724
    "agentto": {"0.5.36"},                               # MAL-2026-10725
    "bvm-core": {"1.1.42", "1.1.43"},                   # MAL-2026-10728
    "channel-worker": {"2.5.39"},                        # MAL-2026-10729
    "codeam-cli": {"2.61.1", "2.61.3"},                  # MAL-2026-10730
    "http-req-lite": {"1.0.0"},                          # MAL-2026-10699
    "isite": {"2026.7.2"},                               # MAL-2026-10735
    "memtry-cli": {"1.0.4"},                             # MAL-2026-10736
    "netcontrol-agent": {"1.0.5"},                       # MAL-2026-10741
    "patchwork-os": {                                    # MAL-2026-10744
        "1.1.0-beta.3.canary.414", "1.1.0-beta.3.canary.415",
        "1.1.0-beta.3.canary.416", "1.1.0-beta.3.canary.417",
    },
    "phantomx-tool-client": {"1.0.8"},                   # MAL-2026-10745
    "sakuraai": {"0.0.11"},                              # MAL-2026-10746
    "sensorium-mcp": {"3.0.95"},                         # MAL-2026-10747
    "vanexa-agent": {"1.1.9", "1.1.10"},                 # MAL-2026-10751

    # Prominent typosquats and supply-chain impersonation (July 16–17 2026)
    "astro": {"7.1.0"},                                  # MAL-2026-10726 (Astro framework typosquat)
    "nordpass": {"1.0.0", "1.0.2", "1.0.4"},            # MAL-2026-10743 (NordPass password mgr typosquat)
    "axios-test-one": {"1.19.0"},                        # MAL-2026-10727 (axios typosquat)
    "idlive-document-capture-web": {"14.2.1"},           # MAL-2026-10733 (idlive-document-capture typosquat)
    "telemetry-metrics": {"0.2.1"},                      # MAL-2026-10750 (@telemetry-sdk typosquat)
    "amdocs-auth-package": {"99.1.0", "114.2.1", "115.2.1"},  # MAL-2025-6694 (dep-confusion)

    # dep-confusion inflated-version packages (July 16 2026)
    "infrastructure-common": {"99.9.9"},                 # MAL-2026-10734
    "myreviews-core": {"99.0.0"},                        # MAL-2026-10740

    # generic malware / infostealers (July 16–17 2026)
    "px8my": {                                           # MAL-2026-10104 (browser extension stealer, 34 versions)
        "1.0.13", "1.0.22", "1.0.23", "1.0.24", "1.0.25",
        "1.0.26", "1.0.27", "1.0.28", "1.0.29", "1.0.30",
        "1.0.31", "1.0.32", "1.0.33", "1.0.34", "1.0.35",
        "1.0.36", "1.0.37", "1.0.38", "1.0.39", "1.0.40",
        "1.0.41", "1.0.42", "1.0.43", "1.0.44", "1.0.45",
        "1.0.46", "1.0.47", "1.0.48", "1.0.49", "1.0.50",
        "1.0.51", "1.0.52", "1.0.53", "1.0.54",
    },
    "theta-sdk-js": {"1.2.14", "1.2.15", "1.2.16", "1.2.17"},  # MAL-2026-10135 (decrypt.js credential stealer)
    "time-format-kit": {"1.0.0", "1.0.1", "1.0.2"},     # MAL-2026-10700
    "date-utils-light": {"1.0.1"},                       # MAL-2026-10731
    "hehehe": {"2.0.1", "2.0.2"},                        # MAL-2026-10732
    "mmagrt": {"0.1.10"},                                # MAL-2026-10737
    "mui-option": {"1.0.0"},                             # MAL-2026-10738
    "mw-server-util": {"2.0.0", "2.0.1"},               # MAL-2026-10739
    "node-as-api": {"2.1.6"},                            # MAL-2026-10742
    "string-formatter-pro": {"1.0.0", "1.0.1"},          # MAL-2026-10748
    "sync-grove": {"1.0.0", "1.0.1", "1.0.2"},           # MAL-2026-10749
    "xxdxa": {                                           # MAL-2026-10752
        "1.0.1", "1.0.2", "1.0.3", "1.0.4", "1.0.5", "1.0.7",
    },

    # syft-acp dep-confusion cluster (July 16–18 2026)
    # Four packages in the syft-acp-* namespace shadow Anchore Syft ACP internal components.
    # OSV affected.ranges >= 0 with no fixed event; any version is malicious.
    "syft-acp-atoms": set(),    # MAL-2026-10764 GHSA-j5f4-f3f3-634h
    "syft-acp-core": set(),     # MAL-2026-10765 GHSA-289v-6j56-44w8
    "syft-acp-uikit": set(),    # MAL-2026-10766 GHSA-rvgp-458h-wjc3
    "syft-acp-util": set(),     # MAL-2026-10767
    # @edgecommons dep-confusion (July 16–18 2026); scope in NPM_SUSPECT_SCOPES
    "@edgecommons/edgecommons": set(),      # MAL-2026-10762 GHSA-8p39-h6xv-p2g9
    "@edgecommons/streamlog-node": set(),   # MAL-2026-10763 GHSA-4rqf-6883-f59f
    # axios typosquats — OSV ranges >= 0 (July 17 2026)
    "axios-native": set(),      # MAL-2026-10772 GHSA-9j78-5mc3-56h7
    "telemetry-axios": set(),   # MAL-2026-10773 GHSA-89mf-39r2-ff96
    # anthropic-claude-latest: fake Anthropic SDK typosquat — OSV ranges >= 0 (first published June 25 2026)
    "anthropic-claude-latest": set(),   # MAL-2026-6415 GHSA-j588-p757-86r9
    # scan-only: pure-malware package — OSV ranges >= 0 (first published June 17 2026)
    "scan-only": set(),         # MAL-2026-6067 GHSA-72g3-g9xj-wxp6
    # easyway2: generic malware, exact-version pins (July 17–18 2026)
    "easyway2": {"1.0.3", "1.0.7"},    # MAL-2026-10769 GHSA-68c2-54w2-m326
    # malicious n8n community node cluster (July 18 2026)
    # Four packages mimic legitimate n8n automation platform community nodes;
    # each embeds a malicious payload (credential/env exfiltration or remote exec).
    "n8n-nodes-api-finder": {"1.0.0"},     # MAL-2026-10774
    "n8n-nodes-devops-utils": {"1.0.7"},   # MAL-2026-10775
    "n8n-nodes-final-mile": {"1.0.5"},     # MAL-2026-10776
    "n8n-nodes-probe": {"1.0.6"},          # MAL-2026-10777
    # relativity-pdfjs-dist: dep-confusion/typosquat of pdfjs-dist targeting Relativity (July 18 2026)
    "relativity-pdfjs-dist": {"5.8.2", "99.9.9"},  # MAL-2026-10778

    # npm malware batch (July 8–20 2026)
    # Miscellaneous malicious packages confirmed active, no prior grouping.
    # uac-package: 14-version credential-stealer; GHSA-7cmm-649r-p3q2
    "uac-package": {
        "1.1.0", "1.1.1", "1.1.2", "1.1.3",
        "1.2.1", "1.3.0",
        "1.4.0", "1.4.1", "1.4.3", "1.4.4", "1.4.5", "1.4.6", "1.4.7", "1.4.8",
    },                                               # MAL-2026-10138 GHSA-7cmm-649r-p3q2
    # next-locomotive-init: malware disguised as a Next.js scaffold helper; GHSA-v4q3-jmq9-q449
    "next-locomotive-init": {"1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4"},  # MAL-2026-7013 GHSA-v4q3-jmq9-q449
    # luludawang-kit: malicious package; ranges >= 0, any version is malicious; GHSA-vgv8-886r-fvp5
    "luludawang-kit": set(),                         # MAL-2026-6999 GHSA-vgv8-886r-fvp5
    # chart-animation-helper: malicious package; ranges >= 0, any version is malicious; GHSA-8vgc-wrpv-6v7h
    "chart-animation-helper": set(),                 # MAL-2026-10781 GHSA-8vgc-wrpv-6v7h
    # dependency_confusions: dep-confusion attack package (version 99.9.9)
    "dependency_confusions": {"99.9.9"},             # MAL-2026-10085

    # npm malware batch (July 20 2026)
    # vybscan-testbed-* packages contain deliberate malicious postinstall code
    # used by the Vybscan scanner self-test suite; any version is malicious.
    "vybscan-testbed-inert-postinstall": set(),      # MAL-2026-10078 GHSA-cwcf-rmgg-qg9w
    "vybscan-testbed-obfuscated-postinstall": set(), # MAL-2026-10079 GHSA-43r2-4jr2-rhjf
    # @car_loans/dealerships-approval: dep-confusion using underscore scope
    # (distinct from @car-loans/ hyphen scope in NPM_SUSPECT_SCOPES).
    "@car_loans/dealerships-approval": set(),        # MAL-2026-10397 GHSA-p8xg-5qpp-p289
    # zoom-widget-xss-poc-paresh: named as an XSS PoC but confirmed by GHSA as
    # carrying deliberate malicious postinstall code; ranges >= 0, any version.
    "zoom-widget-xss-poc-paresh": set(),             # MAL-2026-10782
    # @gocortexio/npmgremlinbox-* cluster: 80 packages explicitly simulating
    # malicious behaviors (C2 beacon, credential harvesting, license typosquats).
    # All carry OSV ranges >= 0 (MAL-2026-10783 through MAL-2026-10862).
    # Scope covered by @gocortexio/ in NPM_SUSPECT_SCOPES; a representative set:
    "@gocortexio/npmgremlinbox-base": set(),                          # MAL-2026-10792
    "@gocortexio/npmgremlinbox-malware-c2-beacon": set(),             # MAL-2026-10832
    "@gocortexio/npmgremlinbox-malware-code-obfuscation": set(),      # MAL-2026-10833
    "@gocortexio/npmgremlinbox-malware-credential-harvesting": set(), # MAL-2026-10834
    "@gocortexio/npmgremlinbox-malware-cryptomining-indicators": set(), # MAL-2026-10835
    "@gocortexio/npmgremlinbox-malware-install-execution": set(),     # MAL-2026-10836
    "@gocortexio/npmgremlinbox-malware-network-indicators": set(),    # MAL-2026-10837
    "@gocortexio/npmgremlinbox-typosquat-axios": set(),               # MAL-2026-10852
    "@gocortexio/npmgremlinbox-typosquat-chalk": set(),               # MAL-2026-10853
    "@gocortexio/npmgremlinbox-typosquat-commander": set(),           # MAL-2026-10854
    "@gocortexio/npmgremlinbox-typosquat-express": set(),             # MAL-2026-10855
    "@gocortexio/npmgremlinbox-typosquat-lodash": set(),              # MAL-2026-10856
    "@gocortexio/npmgremlinbox-typosquat-moment": set(),              # MAL-2026-10857
    "@gocortexio/npmgremlinbox-typosquat-react": set(),               # MAL-2026-10858
    "@gocortexio/npmgremlinbox-typosquat-webpack": set(),             # MAL-2026-10859
}

# npm scopes hit in this campaign. Exact versions are pinned above; any
# additional package in these scopes still triggers a manual-review warning
# in case the advisory expands.
NPM_SUSPECT_SCOPES = (
    "@mistralai/", "@uipath/", "@opensearch-project/", "@antv/",
    # Moika Tech dependency confusion scopes (May 28 2026)
    "@car-loans/", "@cloudplatform-single-spa/",
    "@debit-ib/", "@fb-deposit/", "@mlspace/",
    # vpmdhaj typosquat cluster (May 28 2026) — entire scope is malicious
    "@vpmdhaj/",
    # oob-moika-tech Wave 2 (May 29 2026) — attacker's own npm username scope
    "@t-in-one/",
    # Red Hat Cloud Services account compromise (June 1 2026)
    "@redhat-cloud-services/",
    # @mastra scope compromise (June 20–27 2026) — 89 packages, exact versions
    # pinned above; scope entry catches any undisclosed additional packages
    "@mastra/",
    # @marketfront dep-confusion (July 5 2026) — 25 packages pinned above;
    # scope entry catches any undisclosed additional @marketfront packages
    "@marketfront/",
    # @liquid-web / @self-sell / @team-event dep-confusion (July 5 2026)
    "@liquid-web/", "@self-sell/", "@team-event/",
    # @swiggy-private dep-confusion (2024, OSV updated July 2026)
    "@swiggy-private/",
    # @checkrhq dep-confusion batch (July 6 2026)
    "@checkrhq/",
    # @wagni_bot DeFi/crypto SDK typosquat scope (July 9 2026)
    # Entire attacker-controlled scope; exact versions pinned above
    "@wagni_bot/",
    # @across-toolkit dep-confusion (July 16 2026) — 2 packages pinned above;
    # scope entry catches any undisclosed additional @across-toolkit packages
    "@across-toolkit/",
    # @hibachi-xyz dep-confusion (July 16 2026) — 5 packages at 99.0.0 pinned above;
    # scope entry catches any undisclosed additional @hibachi-xyz packages
    "@hibachi-xyz/",
    # @edgecommons dep-confusion (July 16–18 2026) — 2 packages pinned above;
    # scope entry catches any undisclosed additional @edgecommons packages
    "@edgecommons/",
    # @gocortexio scope (July 20 2026) — 80 npmgremlinbox-* packages with
    # active OSV MAL-2026-10783 through MAL-2026-10862; representative entries
    # pinned above in NPM_BAD; scope catches the remainder
    "@gocortexio/",
)

# crates.io: exact crate name -> set of malicious versions.
# All entries below are RustSec advisories tagged `categories = ["malicious"]`
# with `[versions] patched = []` — i.e. the package was removed from the
# registry and any installed version is malicious. Use the empty-set
# wildcard so re-uploads under different versions are still caught.
# Sources: rustsec/advisory-db, OSV crates.io ecosystem.
CRATES_BAD: dict[str, set[str]] = {
    # rustdecimal typosquat of rust_decimal (Mar 2022, GHSA-7pwq-f4pq-78gm)
    "rustdecimal": set(),
    # amaperf typosquat cluster (Aug 2023, Veracode/Phylum disclosure)
    "xrvrv": set(),
    "oncecell": set(),
    "serd": set(),
    "lazystatic": set(),
    "if-cfg": set(),
    "envlogger": set(),
    "postgress": set(),
    "littest": set(),
    "windowsservice": set(),
    "lfest-main": set(),
    "lasso-rs": set(),
    "monero-api": set(),
    "monero-rpc-rs": set(),
    "postgresderive": set(),
    "tauri-win-rt-notification": set(),
    "win-crypto": set(),
    "windows-service-rs": set(),
    "tauri-winrt-notifications": set(),
    "win-base64-rs": set(),
    "tiny-server": set(),
    "openvpn-plugin-rs": set(),
    "registry-win": set(),
    "win_run_rs": set(),
    "libusb1-main": set(),
    "winx-rs": set(),
    "hann-rs-service": set(),
    "bit-flags": set(),
    "acceptxmr-rs": set(),
    # Polymarket credential-stealer typosquat campaign (Feb 2026)
    "polymarket-clients-sdk": set(),
    "polymarket-client-sdks": set(),
    "polymarkets-client-sdk": set(),
    "polymarkets-rs-clob-client": set(),
    "clob-sdk": set(),
    "rpc-check": set(),
    # timeapi.io impersonation campaign (Mar 2026, Socket disclosure)
    "time_calibrator": set(),
    "time_calibrators": set(),
    "dnp3times": set(),
    "time-sync": set(),
    "chrono_anchor": set(),
    "tracing-check": set(),
    "tracings": set(),
    "tracing_checks": set(),
    "tracing-ethers": set(),
    # TrapDoor crates.io build.rs dropper cluster (May 22–26 2026) — Sui / Move developers
    # build.rs locates Sui, Solana, and Aptos wallet keystores, XOR-encrypts them
    # with hardcoded key "cargo-build-helper-2026", exfiltrates to GitHub Gists
    # (attacker account: ddjidd564). All six were removed from crates.io.
    # Sources: socket.dev/blog/trapdoor-crypto-stealer-npm-pypi-crates (primary);
    #          theblock.co/post/402458/ (independent corroboration);
    #          socradar.io/blog/trapdoor-npm-pypi-cratesio-secrets-ai-tooling/;
    #          cybersecuritynews.com/supply-chain-trapdoor-malware/
    "move-analyzer-build": set(),
    "move-compiler-tools": set(),
    "move-project-builder": set(),
    "sui-framework-helpers": set(),
    "sui-move-build-helper": set(),
    "sui-sdk-build-utils": set(),
    # build.rs droppers / .env exfiltration (2025-2026)
    "uniswap-utils": set(),
    "sha-rust": set(),
    "evm-units": set(),
    "finch-rust": set(),
    "finch-rst": set(),
    "sha-rst": set(),
    "finch_cli_rust": set(),
    "rands": set(),
    "replit_ruspty": set(),
    "tree-sitter-pkl": set(),
    "custom-req-on-workers": set(),
    "statsrelay-protobuf": set(),
    "jfrog_quotes": set(),
    "sophosfirewall-python": set(),
    "logtrace": set(),
    "pretty-changelog-logger": set(),
    "microsoftsystem64": set(),
    "safe-agent-rs": set(),
    "mysten-metrics": set(),
    "sui-execution-cut": set(),
    # crates.io dep-confusion batch (April 2026, ingested ossf/malicious-packages May 31 2026)
    # High-version (99.x) packages published to the public registry to hijack internal CI
    # dependency resolution. All detected by OpenSSF Package Analysis as communicating with
    # domains associated with malicious activity and executing malicious commands.
    # OSV MAL-2026-3101 (amzn-consolas-client), MAL-2026-3102 (semantic-search-client),
    # MAL-2026-3103 (amzn-codewhisperer-streaming-client),
    # MAL-2026-3126 (lsh), MAL-2026-3129 (supertag)
    "amzn-consolas-client": {"99.0.1"},
    "amzn-codewhisperer-streaming-client": {"99.0.1"},
    "semantic-search-client": {"99.0.1"},
    "lsh": {"99.0.1", "99.1.0"},
    "supertag": {"99.1.1"},
    # exploration remote-execute dropper (June 2 2026)
    # A method within the crate attempted to download and execute a payload from
    # a remote site; 1 version published ~1 hour before removal. Any version is
    # malicious (ranges: introduced 0.0.0-0, patched = []).
    # RUSTSEC-2026-0155; reported by Socket Threat Research Team.
    "exploration": set(),
    # logflux Rust-job-application dropper (June 3 2026)
    # Attempted to download and run a malicious payload; 1 version published
    # 2026-04-26 (~1 month before removal); no actual usage. Part of a campaign
    # targeting Rust job applicants via take-home assignments with malicious deps.
    # RUSTSEC-2026-0171; reported by Paweł Bis.
    "logflux": set(),
    # proton-pfff Proton AG dep-confusion (July 7-8 2026, OSV MAL-2026-6959)
    # Single high-version (99.99.5) crate published to crates.io to shadow Proton AG's
    # internal crate and hijack its CI dependency resolution.
    "proton-pfff": {"99.99.5"},
}

SKIP_DIRS = {"node_modules", ".venv", "venv", ".git",
             "dist", "build", "__pycache__", ".tox", ".mypy_cache",
             "target"}

PYPI_FILENAMES = {"Pipfile", "Pipfile.lock", "poetry.lock",
                  "pyproject.toml", "setup.py"}
NPM_FILENAMES = {"package.json", "package-lock.json",
                 "yarn.lock", "pnpm-lock.yaml"}
CRATES_FILENAMES = {"Cargo.toml", "Cargo.lock"}

REQ_TXT_RE = re.compile(r"^requirements.*\.txt$")


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

def parse_requirements_txt(path: Path) -> Iterable[tuple[str, str | None]]:
    for raw in path.read_text(errors="ignore").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        m = re.match(r"([A-Za-z0-9_.\-]+)\s*={2,3}\s*([A-Za-z0-9_.\-+]+)", line)
        if m:
            yield m.group(1).lower(), m.group(2)
        else:
            m = re.match(r"([A-Za-z0-9_.\-]+)", line)
            if m:
                yield m.group(1).lower(), None


def parse_pyproject_toml(path: Path) -> Iterable[tuple[str, str | None]]:
    text = path.read_text(errors="ignore")
    # poetry-style:  pkg = "==1.2.3"  or  pkg = "1.2.3"
    for m in re.finditer(
        r'^\s*([A-Za-z0-9_.\-]+)\s*=\s*"={0,2}\s*([A-Za-z0-9_.\-+]+)"',
        text, re.MULTILINE,
    ):
        yield m.group(1).lower(), m.group(2)
    # PEP 621 dependency strings:  "pkg==1.2.3"
    for m in re.finditer(
        r'"([A-Za-z0-9_.\-]+)\s*==\s*([A-Za-z0-9_.\-+]+)"',
        text,
    ):
        yield m.group(1).lower(), m.group(2)


def parse_package_json(path: Path) -> Iterable[tuple[str, str]]:
    try:
        data = json.loads(path.read_text(errors="ignore"))
    except Exception:
        return
    for section in ("dependencies", "devDependencies",
                    "peerDependencies", "optionalDependencies"):
        for name, spec in (data.get(section) or {}).items():
            # Strip leading range operators; bare version stays intact.
            ver = re.sub(r"^[\^~>=<]*\s*", "", str(spec)).strip()
            ver = ver.split(" ")[0]
            yield name, ver


def parse_package_lock(path: Path) -> Iterable[tuple[str, str]]:
    try:
        data = json.loads(path.read_text(errors="ignore"))
    except Exception:
        return
    # npm v2/v3 lockfile: flat "packages" map keyed by node_modules path.
    for key, entry in (data.get("packages") or {}).items():
        if not key:
            continue
        idx = key.rfind("node_modules/")
        if idx == -1:
            continue
        name = key[idx + len("node_modules/"):]
        version = entry.get("version")
        if name and version:
            yield name, version
    # npm v1 fallback.
    def walk(deps):
        for name, entry in (deps or {}).items():
            v = entry.get("version")
            if v:
                yield name, v
            yield from walk(entry.get("dependencies"))
    yield from walk(data.get("dependencies"))


YARN_BLOCK_RE = re.compile(
    r'^"?((?:@[^/\s"]+/)?[^@\s",]+)@[^\n]*?:\n'
    r'(?:[^\n]*\n)*?\s+version\s+"([^"]+)"',
    re.MULTILINE,
)


def parse_yarn_lock(path: Path) -> Iterable[tuple[str, str]]:
    for m in YARN_BLOCK_RE.finditer(path.read_text(errors="ignore")):
        yield m.group(1), m.group(2)


PNPM_ENTRY_RE = re.compile(
    r"(?:^|\s)'?/?((?:@[^/@\s']+/)?[A-Za-z0-9._\-]+)@(\d[^\s'():]*)"
)


def parse_pnpm_lock(path: Path) -> Iterable[tuple[str, str]]:
    for m in PNPM_ENTRY_RE.finditer(path.read_text(errors="ignore")):
        yield m.group(1), m.group(2)


# Cargo.lock: each [[package]] block holds name/version/source. Only entries
# sourced from the crates.io registry are reported; path/git dependencies
# can't be matched against a crates.io name list.
CARGO_LOCK_NAME_RE = re.compile(r'^\s*name\s*=\s*"([^"]+)"', re.MULTILINE)
CARGO_LOCK_VERSION_RE = re.compile(r'^\s*version\s*=\s*"([^"]+)"', re.MULTILINE)


def parse_cargo_lock(path: Path) -> Iterable[tuple[str, str]]:
    text = path.read_text(errors="ignore")
    for block in text.split("[[package]]")[1:]:
        if 'source = "registry+' not in block:
            continue
        name_m = CARGO_LOCK_NAME_RE.search(block)
        ver_m = CARGO_LOCK_VERSION_RE.search(block)
        if name_m and ver_m:
            yield name_m.group(1), ver_m.group(1)


# Cargo.toml: dependency tables can appear as
#   [dependencies]                 → inline `pkg = "1.2"` or `pkg = { version = "1.2", ... }`
#   [dev-dependencies]              → same
#   [build-dependencies]            → same
#   [target.'cfg(unix)'.dependencies] → same
#   [dependencies.pkg]              → version on its own line in the table body
# Workspace tables ([workspace.dependencies]) follow the same shape.
CARGO_SECTION_HEADER_RE = re.compile(r"^\[([^\]]+)\]\s*$", re.MULTILINE)
CARGO_INLINE_DEP_RE = re.compile(
    r'^\s*([A-Za-z0-9_\-]+)\s*=\s*"([^"]+)"\s*$', re.MULTILINE
)
CARGO_TABLE_DEP_RE = re.compile(
    r'^\s*([A-Za-z0-9_\-]+)\s*=\s*\{([^}]*)\}\s*$', re.MULTILINE
)
CARGO_TABLE_VERSION_RE = re.compile(r'version\s*=\s*"([^"]+)"')


def _is_cargo_dep_section(section: str) -> bool:
    """True for [dependencies], [dev-dependencies], [build-dependencies],
    workspace variants, and target-prefixed variants. Returns False for
    [dependencies.pkg] style (handled separately)."""
    s = section.strip()
    tail = s.rsplit(".", 1)[-1]
    return tail in {"dependencies", "dev-dependencies", "build-dependencies"}


def _cargo_subtable_dep_name(section: str) -> str | None:
    """For [dependencies.pkg] / [workspace.dependencies.pkg] /
    [target.X.dev-dependencies.pkg], return `pkg`. Otherwise None."""
    parts = section.strip().split(".")
    if len(parts) < 2:
        return None
    if parts[-2] in {"dependencies", "dev-dependencies", "build-dependencies"}:
        return parts[-1]
    return None


def parse_cargo_toml(path: Path) -> Iterable[tuple[str, str | None]]:
    text = path.read_text(errors="ignore")
    # Split text into (section_header, body) pairs.
    headers = list(CARGO_SECTION_HEADER_RE.finditer(text))
    for i, m in enumerate(headers):
        section = m.group(1)
        body_start = m.end()
        body_end = headers[i + 1].start() if i + 1 < len(headers) else len(text)
        body = text[body_start:body_end]

        sub_dep = _cargo_subtable_dep_name(section)
        if sub_dep:
            ver_m = CARGO_TABLE_VERSION_RE.search(body)
            yield sub_dep, ver_m.group(1) if ver_m else None
            continue

        if not _is_cargo_dep_section(section):
            continue

        for line_m in CARGO_INLINE_DEP_RE.finditer(body):
            yield line_m.group(1), line_m.group(2)
        for line_m in CARGO_TABLE_DEP_RE.finditer(body):
            inner = line_m.group(2)
            ver_m = CARGO_TABLE_VERSION_RE.search(inner)
            yield line_m.group(1), ver_m.group(1) if ver_m else None


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

def find_manifests(root: Path) -> list[Path]:
    out: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        name = path.name
        if (name in PYPI_FILENAMES or name in NPM_FILENAMES
                or name in CRATES_FILENAMES or REQ_TXT_RE.match(name)):
            out.append(path)
    return out


def parse_manifest(path: Path) -> tuple[list[tuple[str, str | None]], str]:
    """Return (pairs, ecosystem) for the given manifest path.
    Ecosystem is one of: "npm", "pypi", "crates", or "" if unknown."""
    name = path.name
    if name == "package.json":
        return list(parse_package_json(path)), "npm"
    if name == "package-lock.json":
        return list(parse_package_lock(path)), "npm"
    if name == "yarn.lock":
        return list(parse_yarn_lock(path)), "npm"
    if name == "pnpm-lock.yaml":
        return list(parse_pnpm_lock(path)), "npm"
    if name == "pyproject.toml":
        return list(parse_pyproject_toml(path)), "pypi"
    if name in {"Pipfile", "Pipfile.lock", "poetry.lock", "setup.py"} or REQ_TXT_RE.match(name):
        return list(parse_requirements_txt(path)), "pypi"
    if name == "Cargo.toml":
        return list(parse_cargo_toml(path)), "crates"
    if name == "Cargo.lock":
        return list(parse_cargo_lock(path)), "crates"
    return [], ""


def scan(root: Path):
    hits: list[tuple[Path, str, str, str]] = []
    suspects: list[tuple[Path, str, str, str]] = []

    for path in find_manifests(root):
        try:
            pairs, ecosystem = parse_manifest(path)
        except Exception as exc:
            print(f"warn: failed to parse {path}: {exc}", file=sys.stderr)
            continue

        for pkg, version in pairs:
            if ecosystem == "npm":
                bad = NPM_BAD.get(pkg)
                # Empty set is the wildcard: any version of this package is
                # malicious (pure-malware typosquats; see PYPI_BAD docstring).
                if bad is not None and (not bad or version in bad):
                    hits.append((path, pkg, version or "?", "npm"))
                elif any(pkg.startswith(s) for s in NPM_SUSPECT_SCOPES):
                    suspects.append((path, pkg, version or "?", "npm-scope"))
            elif ecosystem == "pypi":
                bad = PYPI_BAD.get(pkg.lower())
                if bad is not None and (not bad or (version and version in bad)):
                    hits.append((path, pkg, version or "?", "pypi"))
            elif ecosystem == "crates":
                bad = CRATES_BAD.get(pkg)
                if bad is not None and (not bad or (version and version in bad)):
                    hits.append((path, pkg, version or "?", "crates.io"))

    return hits, suspects


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check a repo for known-malicious npm/PyPI/crates.io package versions.",
        epilog="Author: Jascha Wanger / Tarnover, LLC",
    )
    parser.add_argument("path", nargs="?", default=".",
                        help="repo root to scan (default: current dir)")
    args = parser.parse_args()

    root = Path(args.path).resolve()
    if not root.exists():
        print(f"error: {root} does not exist", file=sys.stderr)
        return 2

    hits, suspects = scan(root)

    if hits:
        print(f"FOUND {len(hits)} MALICIOUS PACKAGE VERSION(S):")
        for path, pkg, ver, eco in hits:
            print(f"  [{eco}] {pkg}@{ver}  ({path.relative_to(root)})")

    if suspects:
        if hits:
            print()
        print(f"{len(suspects)} package(s) in advisory-affected scopes "
              "(verify versions manually):")
        # Dedupe by (pkg, version, file).
        seen = set()
        for path, pkg, ver, _ in suspects:
            key = (str(path), pkg, ver)
            if key in seen:
                continue
            seen.add(key)
            print(f"  {pkg}@{ver}  ({path.relative_to(root)})")

    if not hits and not suspects:
        print("No known-malicious packages detected.")

    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
