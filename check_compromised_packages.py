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
paperclip-ai; OSV MAL-2026-10863 through MAL-2026-10869), the July 22–25 2026
npm/PyPI multi-campaign wave (~283 packages; MAL-2026-10872 through
MAL-2026-11067), and the July 26–27 2026 npm/PyPI malware batch
(random-ua-generator PyPI keylogger, clerk-next-fix-auth-protection npm
Clerk.js impersonator, whs4_deu/whs4_eud/wsh4_edu npm malware cluster;
OSV MAL-2026-11068 through MAL-2026-11072), and the July 27–28 2026
npm/PyPI malware wave (49 npm packages across 11 campaigns:
thirdweb/RainbowKit/log-taker/polymarket typosquat extension,
ts-escrow/escro TypeScript typosquats, @sqlite-frame/@sqlite-tag
SQLite malware cluster, @thone33 scope extension, WhatsApp/Baileys/
kalipto/fazz credential cluster, @my_name_is_khn express-security
cluster, express-self-destruct/timer cluster, edu-npm postinstall
exfiltrators, txs-* SDK cluster, @heartlandone-private/@ceeferenderer
dep-confusion, and misc malware; OSV MAL-2026-2406/2407/5529/5550–5555/
5623/5624/5712/5723/5772/5922/6097/6319/6320/6338–6340/6342–6345/6439/
11073–11093); plus cfgzen PyPI native-module infostealer 7 versions
(OSV MAL-2026-11094), and the July 28–29 2026 npm/PyPI malware wave
(~60 new packages across 10 campaigns: PayPal/internal dep-confusion
cluster extension — filifecycleserv-paypal/crm-reportinsightserv-paypal/
identityauthorizationserv/riskunifiedgatewayserv/stargateproxyserv/
xo-twofa (OSV MAL-2025-190499/MAL-2026-11095–11105); @array-util/
dep-confusion (@array-util/nodepull/subsearch; OSV MAL-2026-6084/11095);
@vaultflow/ dep-confusion (@vaultflow/create-flow/update-flow; OSV
MAL-2026-11096/11097); motion/tailwind CSS typosquats (motion-forge-css/
tailwind-motionkit; OSV MAL-2026-11101/11104); @immobiliarelabs/
backstage-plugin-gitlab binding.gyp worm (7 versions; OSV MAL-2026-6526);
app-*/api-*-sdk postinstall cluster (6 packages at 2.1.6; OSV MAL-2026-
11124–11129); streak-*/lib-streak-math cluster (4 packages; OSV
MAL-2026-11141/11148–11150); xerohub-discord-voice v2/v3 (OSV
MAL-2026-11154/11155); generic helper/util malware (9 packages; OSV
MAL-2026-11106–11151); miscellaneous malware (23 packages including
@crbrc/xbt, json-schema-inspector, nemo-jaws, syspo, rollup-packages-
polyfill-core, @apexfnd/apex and others; OSV MAL-2026-2785/6406/10115/
10160/11099/11120–11159); vtranalytic PyPI Telegram-bot RAT (OSV
MAL-2026-11156); and 3 entry updates: fundraiserserv upgraded to
any-version wildcard (OSV MAL-2026-5172 SEMVER >=0 range), and
@daylightqc/date-fmt-lite version 1.1.2 added (OSV MAL-2026-11041)),
and the August 3–4 2026 npm/PyPI malware batch (simple-date-formatter-util-5/
simple-date-formatter-new-1 typosquat cluster extension, @types-beta/sdk
4-version infostealer, tailwind-anim tailwind typosquat, accounts-final-form/
accounts-loading-state/beaver-ui-date-range-picker/beaver-ui-grid/beaver-ui-header/
beaver-ui-items-with-more/beaver-ui-layout UI-component impersonation cluster,
bigops-chat-messages/internallib_v524/internallib_v568/lifestyle-test-utils misc
pure-malware npm packages; instalogin1234 PyPI credential-stealer;
OSV MAL-2026-11499 through MAL-2026-11514),
and the Aug 4–5 2026 keyv/cache-manager npm account compromise (attacker
injected malicious payloads into cache-manager 7.2.10, keyv 6.0.0, all 19
@keyv/* packages at 6.0.0, 4 @cacheable/* packages, and many other scopes
including @servicetitan/* 141 packages, @onereach/* 78 packages, @or-sdk/*
74 packages, @ornikar/* 42 packages, @qlik/* 28 packages, @nebula.js/* 22
packages, @umacloud/* 8 packages, and dozens of non-scoped packages; total
562 npm entries; OSV MAL-2026-11523 through MAL-2026-12079),
and the @zzzgenesis00/* crypto-wallet stealer scope (14 npm packages impersonating
bip39, ethers, solana-web3, hdkey, xrp-lib etc.; OSV MAL-2026-11515/11529–11534/
11994/12030–12031/12055–12058), and the Aug 4–5 2026 miscellaneous npm/PyPI batch
(Tinkoff dep-confusion, bigops/beaver-ui/streak continuation, sextant-cli,
nagix cluster, crypto hardware wallet fakes, cors-version/tailwind-anime wildcards,
4 PyPI crypto/AI-SDK typosquats; OSV MAL-2026-11192/11516–11550/11962–11999/
12026–12079),
and the Aug 5–6 2026 multi-campaign npm/PyPI batch: the @wethenorth12/
crypto-wallet-drainer scope (23 packages impersonating BIP39/Ethereum/Solana/
NEAR/TRON SDKs; OSV MAL-2026-12085 through MAL-2026-12107), the @zzzcrypto/
companion scope (5 packages; OSV MAL-2026-13211 through MAL-2026-13215), the
@cryptosrvc and @shiftmarkets exchange SDK typosquat pair (6 packages duplicating
shift-exchange/no-brainer-sdk at .9.9 versions; OSV MAL-2026-12315/12316/12317/
12329/12508/12509), the @zahlen checkout-flow malware pair (OSV MAL-2026-12332/
12333), the @copilot-mcp/apex MCP impersonator (13 versions; OSV MAL-2026-12314),
standalone crypto typosquats bip32-js/bip39-generator/bitcoinjs-wallet/ethers-lib/
ethers-signer/uniswap-sdk-v4/viem-toolkit/wagmi-react/web3-utils-crypto (OSV MAL-
2026-12109/12111/13257/13258/13343/13354/12490/12495/12498), akamai sensor
typosquats akamai-sensorv1/v2/v3/akamaijs-sensor (OSV MAL-2026-12139/12337/
13216/13217), async-mutex typosquats (OSV MAL-2026-12339/12513/12514), tailwind
scrollbar typosquats (OSV MAL-2026-12116/12224), alipclutch-baileys WhatsApp
typosquat (OSV MAL-2026-12108), anthropic-setup malware (OSV MAL-2026-12510),
aws-sdk-v4 typosquat (OSV MAL-2026-13218), streak-calc-math/metrics continuation
(OSV MAL-2026-12114/12115/12311), simple-date-formatter-* continuation 12 packages
(OSV MAL-2026-12194 through MAL-2026-12206), and the PyPI crypto-wallet-drainer
cluster bip39-py/bitcoinlib-py/crypto-trading-toolkit/crypto-wallet-sdk/defi-sdk-py/
eth-account-wallet/gcli-control/mnemonic-py/numpyp/solana-sniper-bot/uncrypt
(OSV MAL-2026-12080/12081/12082/12083/12502/12503/13361/13362/13372/13373/13380),
and the Aug 5–7 2026 multi-campaign npm/PyPI batch: the Tinkoff/T-Bank / BigOps /
DevPlatform dep-confusion continuation (229 additional fake internal packages across
tinkoff-*, bigops-*, beaver-ui-*, bnpl-*, dolyame-boxy-*, devplatform-*, statist-*,
pfa-*, pfp-*, sme-*, tramvai-*, twork-*, and related tooling; OSV MAL-2026-12145
through MAL-2026-13379), the @ccfly/setup-* CI tool typosquat cluster (4 packages
impersonating @actions/setup-* tooling for macOS/Linux; OSV MAL-2026-12084/12313/
13417/13418), the "common" dep-confusion scope cluster (@hoteldev, @nasddatax,
@nasdtickets, @rentwise, @vboxdev, @afasinatickets; OSV MAL-2026-12318/12323/12324/
12328/12330/13387), the @activepieces scope compromise (4 Google integration pieces:
piece-google-bigquery, piece-google-contacts, piece-google-forms, piece-base44; OSV
MAL-2026-13394/13395/13396/13408), the AI/LLM-tool malware cluster (19 packages
impersonating Claude, GPT, LLM, agent-hub, and AI-tooling names: @guangnao/claude-cli,
@cliphijack/santaclaude, remote-claude-daemon, llm-interceptor, wormgpt-cli,
gpt-terminal-cli, @agenthub-ai/agent, @addai/*, @vanexalabs-ai/vanexa-agent,
@agent-link/agent, @ai-support-agent/cli, and others; OSV MAL-2026-10705/10707/12312/
13209/13355/13363/13364/13370/13397–13400/13409–13411/13413/13419/13420), the
WhatsApp/Baileys typosquat extension (@xsat10/baileys-xsat, diezyyasha-baileys,
@diezyyasha/libsignal-node, santana-baileys, diezyclutch-baileys, ynastore-baileys,
@prototypevip/baileys, shadowx-fca; OSV MAL-2026-13390/13443/13456/13457/13470/
13474/13480/13482), the payment gateway malware cluster (simplipayng,
@simplipayng/checkout, @voxepay/checkout, @zahlen/checkout, ach-detail,
wallet-monitor-snap; OSV MAL-2026-12334/12437/13388/13389/13391/13393), the Svelte
ecosystem typosquat cluster (svelte-mapped-metrics, svelte-mapping-core,
svelte-visual-map; OSV MAL-2026-13383/13384/13477), the Sui blockchain malware
extension (sui-graphql-client, sui-migration-audit-cli; OSV MAL-2026-13475/13476),
the CLOB/polymarket cluster extension (poly-provider-api, polyclob-api, tick-forge;
OSV MAL-2026-13381/13382/13385), the streak-cache-map/streak-map-cache cluster
extension (OSV MAL-2026-13403/13459), the @united-airlines-org/atmos-design-system
dep-confusion (OSV MAL-2026-13435), the @cats-cdf dep-confusion cluster
(@cats-cdf/authentication, @cats-cdf/browser-metrics-meter, cdf-tag-commander-helper;
OSV MAL-2026-13478/13479/13481), the commonweb/consumerweb/merchantweb dep-confusion
extension (commonweb-flow, commonweb-balance, consumerweb-creditcollection,
merchantweb-lang-cookie-reset; OSV MAL-2025-6894/MAL-2026-13439/13441/13449), the
tailwindcss-form-components Tailwind typosquat (OSV MAL-2026-12223), and ~63
miscellaneous npm malware packages (delivery-ci-*, @lizhao1/memorax-code-internal,
electrode-ota-ui-app, new-native-tools-linux-x64-gnu, @cy4dev/cydemo-bg-color,
crypto-checkout-api, dbk-ui-forms, and others; OSV MAL-2026-12320/12368/12402/12504/
12666/12669/12680–12688/13360/13392/13401–13416/13421–13471/13483–13485), and the
AlphaLend DeFi PyPI typosquat cluster (alphalend-abi, alphalend-layouts; OSV
MAL-2026-13472/13473), decapod-common PyPI malware (OSV MAL-2026-13386), and
xayoub-xctxteam PyPI throwaway (OSV MAL-2026-13426),
and the Aug 7–8 2026 Dolyame / SME-RKO Russian banking dep-confusion cluster
(131 npm packages targeting Dolyame BNPL and SME-RKO finance internal tooling
at high-version 35.x.x; OSV MAL-2026-13494 through MAL-2026-13663),
and the Aug 7–8 2026 miscellaneous npm malware batch (40 packages: rdfxvela/
rdfxvela-build/velabuild typosquat cluster with introduced:0 range, hardhat-set/
hardhat-cap Hardhat typosquats, forge-gas-diff/gas-diff-core EVM tools, @depup/*
package-update impersonators, @nestjs-passport/jwt NestJS typosquat, @coralxyz/anchor
Solana Anchor impersonator, @vertexa/prisma-fetch-engine Prisma fake, mangomind-agent/
aclade-agent/agenthub-ai AI-agent infostealers, @rbxst/services + @rbx-ts/services
Roblox typosquats, streak-kit-map/streak-map-kit/map-streak-kit cluster,
localization-fixer/modern-localization cluster, titan-exchange-shared-permissions
dep-confusion 99.9.9, transform-es2015-unicode-regex Babel typosquat,
tailwindcss-motion-advanced Tailwind typosquat, @decido/backend-core,
@catamania/front-components, and misc; OSV MAL-2026-13491 through MAL-2026-13664),
and the Aug 7–8 2026 PyPI typosquat batch (8 packages: fastapii/flasq/idnna/
pydanticc web-framework typosquats, fast-hashes/speed-hashes hash-lib fakes,
cdktn-provider-azurerm CDKTF typosquat, atlas-internal dep-confusion;
OSV MAL-2026-13486/13487/13488/13489/13490/13606/13607/13619), and the
Aug 11–12 2026 npm/PyPI malware batch (44 new packages + 2 version updates:
DeFi/Ethereum protocol typosquat cluster (@aerodrome-finance/contracts+slipstream,
@openzeppelin-4+5/contracts, ethereum-vault-connector), base-x/base65/bs58
typosquat cluster (9 packages), dep-confusion/postinstall-canary batch (6),
Svelte/vim/kit extension + Sui blockchain (4), GHSA full-compromise wildcards
(5), miscellaneous (8: tilaver-mfa, newtun, @nzeros/codebreak, safe-local-env-loader,
zeal-rq-hooks, whs4_ued, dakumangalsingh_virus + 1 more); PyPI DeFi/Telegram SDK
typosquats (dlmm, dlmm-sdk, euler-sdk, morpho-sdk, joule-btp-extension,
joule-sbx-poc, telebot-pro); whs4_deu/whs4_eud updated to include 1.0.0;
OSV MAL-2026-10925/11070/11071/13728–13769), and the Aug 15 2026 npm batch
(depcruise-baseline/fmt/wrap-stream-in-html dep-confusion, HackerOne/Twilio
build-probe packages, Akamai sensor extension, misc malware;
OSV MAL-2026-14052 through MAL-2026-14068), and the August 16 2026 batch:
snavbox npm multi-protocol proxy/remote-management trojan (OSV MAL-2025-49362;
any-version wildcard), kb-ai PyPI dependency-confusion install-time exfiltrator
(OSV MAL-2026-14069; versions 0.1.0/0.1.1), and the August 24 2026 sweep:
sm-* dep-confusion cluster (8 packages: sm-admin, sm-apikey-model, sm-billing-form,
sm-cart, sm-checkout, sm-oauth, sm-payment, sm-session; OSV MAL-2026-14393–14400),
dext-crate-* malware cluster (dext-crate-check/image/video; MAL-2026-14406–14408),
*-dim-* UI typosquat extension (7 packages extending the Aug 23 dim-kit pair;
MAL-2026-14416/14417/14429–14431/14441/14442), dep-confusion 999.x batch (amundi-compare,
fund-calculator, @temptation.js/utils, dpg-media-7ehemel, @gsas/gsas-sdk, web-advertising,
@elc-online/up-analytics; MAL-2026-14390/14391/14410/14411/14420/14440/14443),
@medisend dep-confusion 4 packages (MAL-2026-14421–14424), MCP server malware pair
(livemcp, mcp-real-chrome; MAL-2026-14413/14414), manticore/PayPal 9.4.3 cluster
(manticore-log, paypal-business-sdk, ppb-manticore; MAL-2026-14433/14435/14437),
Tinkoff/devplatform + sme-* continuation (5 packages; MAL-2026-12208/12440/12441/12730/12763),
Tailwind animation typosquats (MAL-2026-12219/12220), older OSV records refreshed Aug 24
(MAL-2026-4164/4818/5574/6497/10107), misc mixed batch 19 npm packages, and
multyproccess/msrcpoc PyPI (MAL-2026-14401/14444).

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
Date:      2026-08-16
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

    # PyPI malware batch (July 22-24 2026)
    # num2words (MAL-2025-6794 / GHSA-jxr6-qrxx-2ph2 / PYSEC-2025-72): legitimate
    # number-to-words library; versions 0.5.15-0.5.16 contained malicious payload.
    "num2words": {"0.5.15", "0.5.16"},                  # MAL-2025-6794 GHSA-jxr6-qrxx-2ph2
    # pycryptoshuffle: crypto-themed infostealer; 6 versions published before takedown.
    "pycryptoshuffle": {
        "1.0.6", "1.0.7", "1.0.8", "1.0.9", "1.1.0", "1.1.1",
    },                                                   # MAL-2026-7458
    # trongrider / trongridmy: Tron ecosystem typosquats (cluster also includes
    # trongridme MAL-2026-10771 and trongridev MAL-2026-10768, tracked above).
    "trongrider": {"0.0.1"},                             # MAL-2026-10929
    "trongridmy": {"0.0.1"},                             # MAL-2026-10930
    # defi-kit / roles-royce: DeFi-themed credential stealers; both at 2.1.1.
    "defi-kit": {"2.1.1"},                               # MAL-2026-10926
    "roles-royce": {"2.1.0", "2.1.1"},                      # MAL-2026-10927
    # Tinkoff/DWH dep-confusion cluster: high-version packages (0.0.1, 8.5.x)
    # targeting internal Tinkoff and data-warehouse packages.
    "dwh-kafka-client": {"0.0.1"},                       # MAL-2026-10915
    "python-devplatform-client": {"0.0.1", "8.5.3", "8.5.4"},   # MAL-2026-10916
    "tinkoff-cloud-apis-internal": {"0.0.1", "8.5.3", "8.5.4"}, # MAL-2026-10917
    "ml-core-airflow-auth": {"0.0.1"},                   # MAL-2026-10919
    # GitHub-autoname cluster: random-name packages used as install-time malware droppers.
    "automatic-octo-invention": {"0.1.0", "0.1.1", "0.1.2", "0.1.3"},  # MAL-2026-10918
    "fluffy-octo-broccoli": {"0.1.0"},                   # MAL-2026-10973
    "reimagined-broccoli": {"0.1.0"},                    # MAL-2026-10978
    "animated-octo-spoon": {"0.1.0", "0.1.1"},           # MAL-2026-10985
    # ibreak / shark-e2e-bnsneo: install-time malware droppers.
    "ibreak": {"0.1.2", "0.1.3", "0.1.4"},              # MAL-2026-10909
    "shark-e2e-bnsneo": {"0.2.9", "0.2.10", "0.3.1"},   # MAL-2026-10912
    # torch-musa: PyTorch MUSA extension impostor.
    "torch-musa": {"0.0.0", "1.0.0"},                   # MAL-2026-10993
    # govapkg: typosquat of govpkg (MAL-2026-10770, tracked above).
    "govapkg": {"0.1.0"},                               # MAL-2026-11031
    # rasterkit / rasterkit-demo: raster-graphics library impostor with payload.
    "rasterkit": {"1.0.0", "1.0.2", "1.0.4"},           # MAL-2026-10974
    "rasterkit-demo": {"0.1.0"},                         # MAL-2026-10975
    # colorstack / comp-colors / lebinfmt: color/formatter utility malware.
    "colorstack": {"0.1.0", "0.1.1"},                   # MAL-2026-10976
    "comp-colors": {"0.1.5"},                            # MAL-2026-10986
    "lebinfmt": {"1.0.0"},                               # MAL-2026-10977
    # make-helper / dev-helper-bg: generic helper package malware cluster.
    "make-helper": {"0.1.0", "0.1.1"},                  # MAL-2026-10991
    "dev-helper-bg": {"0.1.3", "0.1.4", "0.1.6", "0.1.7"},  # MAL-2026-10992
    # mrmustard legitimate-package compromise — July 25 2026
    # XanaduAI/MrMustard#656; OSV MAL-2026-11049
    "mrmustard": {"0.7.4"},                              # MAL-2026-11049
    # discordnv: Discord token / Roblox cookie stealer — July 25 2026
    # OSV MAL-2026-11050 / bad-packages.kam193.eu
    "discordnv": {"0.8.0"},                              # MAL-2026-11050
    # trongridy: Tron private key exfiltrator — July 25 2026
    # OSV MAL-2026-11051 / bad-packages.kam193.eu
    "trongridy": {"0.0.1"},                              # MAL-2026-11051
    # intel-cicd-repo-infrastructure: host info exfiltrator — July 25 2026
    # OSV MAL-2026-11046 / bad-packages.kam193.eu
    "intel-cicd-repo-infrastructure": {"0.0.0", "1.0.0"},   # MAL-2026-11046
    # karpatkey / karpatkit dep-confusion credential exfiltrators — July 25 2026
    # OSV MAL-2026-11047 / MAL-2026-11048 / bad-packages.kam193.eu
    "karpatkey": {"2.1.1"},                              # MAL-2026-11047
    "karpatkit": {"2.1.0", "2.1.1"},                     # MAL-2026-11048
    # blessclient: host-info exfiltrator impersonating Netflix BLESS SSH tool — July 25 2026
    # Overrides install command to exfiltrate IP/username; OSV MAL-2026-11067
    "blessclient": {"0.0.1", "0.0.2"},                   # MAL-2026-11067
    # random-ua-generator: keylogger / environment exfiltrator — July 26 2026
    # Starts a keylogger on import and exfiltrates data; source: bad-packages.kam193.eu
    # OSV MAL-2026-11068
    "random-ua-generator": {"0.0.1"},                    # MAL-2026-11068
    # cfgzen: native-module infostealer (downloads encrypted blob, decrypts to executable) — July 27 2026
    # PTH file embedded since 1.0.6 triggers malicious code at import; VirusTotal confirmed.
    # OSV MAL-2026-11094; source: bad-packages.kam193.eu
    "cfgzen": {"1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4", "1.0.5", "1.0.6"},  # MAL-2026-11094
    # vtranalytic: Telegram-bot RAT disguised as VPS control system (July 28 2026)
    # Polling loop executes remote shell commands; walks filesystem for .py/.json/.conf/.env
    # SSH keys and credentials exfiltrated via api.telegram.org sendDocument.
    # OSV MAL-2026-11156; Amazon Inspector detection.
    "vtranalytic": {"9.0.1"},                               # MAL-2026-11156
    # ml-* dep-confusion cluster — July 30 2026
    # OSV MAL-2026-11199 / MAL-2026-11200 / MAL-2026-11201 / MAL-2026-11202
    "ml-data-shared": {"12.0.1", "16.0.1"},                 # MAL-2026-11199
    "ml-fdbk-shared": {"1.0.0", "2.3.1"},                   # MAL-2026-11200
    "ml-nps-shared": {"6.0.3", "8.2.3"},                    # MAL-2026-11201
    "ml-shared": {"6.3.0", "8.8.0"},                        # MAL-2026-11202
    # phabricator-client dep-confusion / ai-perf-toolkit / mcp-search-server — July 30 2026
    # OSV MAL-2026-11195 / MAL-2026-11197 / MAL-2026-11198
    "phabricator-client": {"99.0.0", "99.0.1", "99.0.2", "99.0.3", "99.0.4"},  # MAL-2026-11195
    "ai-perf-toolkit": {"2.4.2"},                           # MAL-2026-11197
    "mcp-search-server": {"1.0.0", "2.0.0", "2.0.1"},      # MAL-2026-11198
    # August 1 2026 PyPI malware wave
    # -----------------------------------------------------------------------
    # AI-named credential-stealer cluster — August 1 2026
    # OSV MAL-2026-11414 / MAL-2026-11415 / MAL-2026-11416 / MAL-2026-11417
    # OSV MAL-2026-11418 / MAL-2026-11419
    # Source: @L0Psec disclosure; bad-packages.kam193.eu
    "aiassistcore": {"0.1.2"},                                    # MAL-2026-11414
    "aichannel": {"0.1.2"},                                       # MAL-2026-11415
    "ailaunchkit": {"0.1.2"},                                     # MAL-2026-11416
    "aiprepkit": {"0.1.2"},                                       # MAL-2026-11417
    "catalogai": {"0.1.2"},                                       # MAL-2026-11418
    "cognikit": {"0.1.2"},                                        # MAL-2026-11419
    # ASDK dep-confusion cluster — August 1 2026
    # OSV MAL-2026-11421 / MAL-2026-11422 / MAL-2026-11423
    "asdk-plugin-ai-platform": {"0.0.1", "9999.0.0"},            # MAL-2026-11421
    "asdk-plugin-alphagen": {"0.0.1", "9999.0.0"},               # MAL-2026-11422
    "asdk-plugin-legacy": {"0.0.1", "9999.0.0"},                 # MAL-2026-11423
    # reguestsc — requests typosquat (August 1 2026)
    # OSV MAL-2026-11413; VirusTotal confirmed (db86ed61afec83acb523e8b00558ee7641b2ddc388d542dc0ff2922625da013f)
    "reguestsc": {"2.34.2"},                                      # MAL-2026-11413
    # telerape — Telegram-leveraging RAT (August 1 2026)
    # OSV MAL-2026-11424
    "telerape": {"0.0.0.dev0", "1.0.0", "1.0.1"},               # MAL-2026-11424
    # walmart-genai-trace — dep-confusion (August 1 2026)
    # OSV MAL-2026-11420
    "walmart-genai-trace": {"99.0.0"},                            # MAL-2026-11420
    # NVIDIA dep-confusion cluster — August 1 2026
    # OSV MAL-2026-11425 / MAL-2026-11426; source: kam193
    # Versions 99999.x used to supersede internal packages; exfiltrates host data on install
    "nvtorch-oot-nightly": {"99999.0.0", "99999.0.1"},           # MAL-2026-11425
    "trtllm-subdir-test": {"99999.0.0", "99999.0.1"},            # MAL-2026-11426
    # PyPI malware batch — August 2–3 2026
    # OSV MAL-2026-11428 (wacve-utils), MAL-2026-11429 (trongriden); source: kam193
    # Install-time infostealers; no legitimate prior use
    "wacve-utils": {"1.0.7"},                                     # MAL-2026-11428
    "trongriden": {"0.0.1"},                                      # MAL-2026-11429
    # instalogin1234 — PyPI credential-stealer (August 3 2026)
    # OSV MAL-2026-11503; install-time infostealer targeting Instagram credentials
    "instalogin1234": {"0.0.1"},                                  # MAL-2026-11503
    # Aug 4–5 2026 PyPI crypto / AI-SDK typosquat batch
    # Coldcard hardware wallet fake, LaunchDarkly AI SDK impersonator, and two
    # Bitcoin PSBT helper fakes that steal credentials on install.
    # OSV MAL-2026-11516, 11519–11521;
    # refs: bad-packages.kam193.eu/pypi/package/coldcard-helpers, pypi.org/project/psbt-utils/1.0.0/
    "coldcard-helpers": {"1.4.2"},                                # MAL-2026-11516
    "launchdarkly-ai-server-sdk": {"1.0.1", "1.9.9"},            # MAL-2026-11519
    "psbt-helpers": {"1.0.0"},                                    # MAL-2026-11521
    "psbt-utils": {"1.0.0"},                                      # MAL-2026-11520
    # PyPI crypto-wallet-drainer cluster Aug 5 2026
    # Multiple packages impersonating BIP39/BIP32 mnemonic tools, Ethereum account helpers,
    # Solana sniper bots, and DeFi SDKs; all exfiltrate private keys / mnemonics at install.
    # gcli-control and numpyp are CI/numpy typosquats in the same wave.
    # OSV MAL-2026-12080/12081/12082/12083/12502/12503/13361/13362/13372/13373/13380
    "bip39-py": {"1.0.6"},                                        # MAL-2026-12080
    "bitcoinlib-py": {"0.9.0"},                                   # MAL-2026-12081
    "crypto-trading-toolkit": {"3.2.0"},                          # MAL-2026-12082
    "crypto-wallet-sdk": {"1.8.3"},                               # MAL-2026-12083
    "defi-sdk-py": {"2.5.1"},                                     # MAL-2026-13361
    "eth-account-wallet": {"0.11.2"},                             # MAL-2026-13372
    "gcli-control": {"0.5.0", "0.11.1", "0.12.2", "0.12.4"},    # MAL-2026-12502
    "mnemonic-py": {"0.21"},                                      # MAL-2026-13362
    "numpyp": {"0.7.7"},                                          # MAL-2026-12503
    "solana-sniper-bot": {"1.4.2"},                               # MAL-2026-13373
    "uncrypt": {"0.1.0", "0.1.1", "0.1.2"},                     # MAL-2026-13380
    # AlphaLend DeFi protocol PyPI typosquat cluster Aug 6 2026
    # Two packages impersonating AlphaLend DeFi protocol Python libraries.
    # OSV MAL-2026-13472/13473
    "alphalend-abi": {"1.0.0", "1.0.1", "1.1.0"},  # MAL-2026-13472
    "alphalend-layouts": {"4.0.0", "4.0.1", "4.0.2", "4.1.0"},  # MAL-2026-13473
    # decapod-common PyPI typosquat Aug 6 2026 (3 versions)
    # OSV MAL-2026-13386
    "decapod-common": {"0.0.0", "1.2.dev1", "1.2.dev2"},  # MAL-2026-13386
    # xayoub-xctxteam PyPI throwaway malware Aug 6 2026 (3 versions)
    # OSV MAL-2026-13426
    "xayoub-xctxteam": {"0.1.0", "0.1.1", "0.1.2"},  # MAL-2026-13426
    # Aug 7–8 2026 PyPI typosquat batch (8 packages)
    # fastapii/flasq/idnna/pydanticc are pure web-framework name typosquats
    # (fastapi, flask, idna, pydantic); fast-hashes/speed-hashes are hash-lib
    # fakes; cdktn-provider-azurerm is a CDKTF azurerm provider impersonator;
    # atlas-internal is a dep-confusion package. All detected by Amazon Inspector.
    # OSV MAL-2026-13486/13487/13488/13489/13490/13606/13607/13619
    "atlas-internal": {"1.8.1"},                                # MAL-2026-13619
    "cdktn-provider-azurerm": {"17.0.0"},                       # MAL-2026-13606
    "fast-hashes": {"0.1.0"},                                   # MAL-2026-13490
    "fastapii": {"0.1.1", "0.1.2", "0.2.0", "0.3.0"},         # MAL-2026-13486
    "flasq": {"0.1.1", "0.1.2", "0.2.0", "0.3.0"},            # MAL-2026-13487
    "idnna": {"0.1.1", "0.1.2", "0.2.0", "0.3.0"},            # MAL-2026-13488
    "pydanticc": {"0.1.1", "0.1.2", "0.2.0", "0.3.0"},        # MAL-2026-13489
    "speed-hashes": {"0.1.0"},                                  # MAL-2026-13607
    # riakcs PyPI install-time exfiltrator Aug 8 2026
    # Overwrites setup.py install command to exfiltrate basic host info (IP, username)
    # on install. Categorised PROBABLY_PENTEST by ossf/malicious-packages.
    # OSV MAL-2026-13665
    "riakcs": {"0.0.1", "0.5.0"},                              # MAL-2026-13665
    # Aug 9–10 2026 PyPI malware batch (2 packages)
    # cubesat-upstream-driver: supply-chain malware detected by OpenSSF Package Analysis.
    # kotanku: supply-chain malware detected by OpenSSF Package Analysis.
    # OSV MAL-2026-13666/13667
    "cubesat-upstream-driver": {"1.0.1"},  # MAL-2026-13666
    "kotanku": {"0.1.0"},  # MAL-2026-13667
    # Aug 10–11 2026 PyPI malware batch (9 packages)
    # Crypto infostealers: btcflip, btcflx, kotoraka 0.1.0 each — exfiltrate
    # credentials/wallets; detected by Amazon Inspector + kam193 (Kamil Mańkowski).
    # bigtime 0.1.0, chaintest 0.1.0: misc malware (kam193).
    # pytablute 1.0.3: spellchecker-disguised RAT (refs: helixguard.ai / Aikido blog).
    # neutrl-contracts/neutrl-core/plp-contract 2.0.0–2.0.2: crypto-contract toolkit
    # infostealers attributed to mhoonumabaamercy-hub (C2 in config.py).
    # OSV MAL-2026-13681/13682/13683/13685/13686/13709/13710/13711/13712
    "btcflip": {"0.1.0"},  # MAL-2026-13681
    "btcflx": {"0.1.0"},  # MAL-2026-13682
    "kotoraka": {"0.1.0"},  # MAL-2026-13683
    "pytablute": {"1.0.3"},  # MAL-2026-13685
    "chaintest": {"0.1.0"},  # MAL-2026-13686
    "neutrl-contracts": {"2.0.0", "2.0.1", "2.0.2"},  # MAL-2026-13709
    "neutrl-core": {"2.0.0", "2.0.1", "2.0.2"},  # MAL-2026-13710
    "plp-contract": {"2.0.0", "2.0.1", "2.0.2"},  # MAL-2026-13711
    "bigtime": {"0.1.0"},  # MAL-2026-13712

    # Aug 11 2026 PyPI DeFi/Telegram SDK typosquat batch (7 packages)
    # DeFi protocol SDK typosquats impersonating Meteora DLMM, Euler Finance,
    # Morpho Protocol, and Joule Finance (BTP); install-time credential/env
    # exfiltrators detected by Amazon Inspector + kam193 (Kamil Mańkowski).
    # telebot-pro 2.3.7–2.3.8: pyTelegramBotAPI typosquat; starts a reporting
    # thread on bot initialization to exfiltrate bot tokens and user data.
    # OSV MAL-2026-13728/13729/13730/13731/13732/13756/13757
    "dlmm": {"1.0.0"},  # MAL-2026-13728
    "dlmm-sdk": {"1.0.0"},  # MAL-2026-13729
    "euler-sdk": {"1.0.0"},  # MAL-2026-13730
    "morpho-sdk": {"1.0.0"},  # MAL-2026-13731
    "joule-btp-extension": {"0.1.0", "0.1.1", "0.1.3", "0.1.4", "0.1.6"},  # MAL-2026-13732
    "joule-sbx-poc": {"0.1.0"},  # MAL-2026-13756
    "telebot-pro": {"2.3.7", "2.3.8"},  # MAL-2026-13757
    # August 16 2026 PyPI malware — dependency-confusion demonstrator with system exfiltration
    # kb-ai overrides the install command in setup.py to execute malicious code at install time,
    # exfiltrating basic host info (IP address, username). Detected by Kamil Mańkowski (kam193).
    # OSV MAL-2026-14069; campaign: GENERIC-standard-pypi-install-pentest.
    "kb-ai": {"0.1.0", "0.1.1"},                                    # MAL-2026-14069
    # socks5901 PyPI credential-harvesting malware (Aug 17 2026)
    # OSV MAL-2026-14100
    "socks5901": {"1.0.0"},                                          # MAL-2026-14100
    # Aug 18-19 2026 PyPI malware sweep
    # httpz-requests: typosquat of 'requests'; 33 versions active on PyPI exfiltrating credentials
    # OSV MAL-2026-14130
    "httpz-requests": {"1.8.0", "1.9.0", "1.10.0", "1.11.0", "1.12.0", "1.13.0",
                       "1.14.0", "1.15.0", "1.16.0", "1.17.0", "1.18.0", "1.19.0",
                       "1.20.0", "1.21.0", "1.21.1", "1.21.2", "1.21.3", "1.21.4",
                       "1.21.5", "1.21.6", "1.21.7", "1.21.8", "1.21.9", "1.21.10",
                       "1.21.11", "1.21.12", "1.21.13", "1.21.14", "1.21.15",
                       "1.21.16", "1.21.17", "1.21.18", "1.21.19",
                       "1.21.20"},                                   # MAL-2026-14130
    # infogram-bot: impersonates Infogram (data-viz SaaS) with malicious bot integration
    # OSV MAL-2026-14131
    "infogram-bot": {"1.0.0", "1.2.0", "1.2.1", "1.3.0", "1.4.0",
                     "1.5.0", "1.6.0", "1.6.1", "1.7.0", "1.8.0",
                     "1.9.0"},                                       # MAL-2026-14131
    # deepface-weight / deepface-weights: typosquats of deepface (face-recognition library)
    # install-time credential exfiltration; OSV MAL-2026-14132 / MAL-2026-14158
    "deepface-weights": {"0.1.0", "0.1.1", "0.1.2"},                # MAL-2026-14132
    "deepface-weight": {"0.1.4"},                                    # MAL-2026-14158
    # reqcrypt: typosquat of 'requests' with crypto-style naming; OSV MAL-2026-14133
    "reqcrypt": {"0.1.0"},                                           # MAL-2026-14133
    # reqcrypt-dev: companion to reqcrypt; same malicious dropper, dev variant (Aug 19 2026)
    # OSV MAL-2026-14274
    "reqcrypt-dev": {"0.1.0"},                                       # MAL-2026-14274
    # rc4-secure / libasync: infostealer packages (Aug 19–20 2026)
    # OSV MAL-2026-14306, MAL-2026-14308
    "rc4-secure": {"1.0.0"},                                         # MAL-2026-14306
    "libasync": {"1.0.0"},                                           # MAL-2026-14308
    # reqcrypts: further variant of the reqcrypt infostealer cluster (Aug 21 2026)
    # Contains hidden backdoor; 4 versions published before takedown.
    # OSV MAL-2026-14341
    "reqcrypts": {"0.1.0", "0.1.1", "0.1.2", "0.1.3"},             # MAL-2026-14341
    # boto4 ELF dropper / scrambleeer TCP reverse shell / requests-crypt exfiltrator (Aug 21 2026)
    # boto4: typosquat of boto3; setup.py base64-decodes and executes a ~17 MB Linux ELF.
    # scrambleeer: advertises numeric shuffler, opens TCP socket to bax.h4x.tv:6363 on import.
    # requests-crypt: wraps HTTP client to exfiltrate JSON responses to attacker server.
    # OSV MAL-2026-14349, MAL-2026-14350, MAL-2026-14351
    "boto4": {"1.0.0", "1.0.2"},                                    # MAL-2026-14349
    "scrambleeer": {"0.1.0", "0.1.1"},                              # MAL-2026-14350
    "requests-crypt": {"0.1.0"},                                    # MAL-2026-14351
    # scrambleeeer TCP reverse shell (Aug 23 2026; distinct from scrambleeer above)
    # Advertises a numeric-shuffling utility; opens reverse shell on import.
    # OSV MAL-2026-14358
    "scrambleeeer": {"0.1.0"},                                      # MAL-2026-14358
    # Aug 23 2026: MLflow OpenTelemetry instrumentor typosquat
    # Impersonates a legitimate OTEL instrumentor for MLflow.
    # OSV MAL-2026-14384
    "mlflow-otel-instrumentor": {"1.1.0"},                          # MAL-2026-14384
    # Aug 23 2026: cryptgraphy typosquat of `cryptography`
    # OSV MAL-2026-14388
    "cryptgraphy": {"1.0.0"},                                       # MAL-2026-14388
    # Aug 23 2026: envprovision PyPI malware (3 versions)
    # OSV MAL-2026-14389
    "envprovision": {"1.2.0", "1.3.0", "1.4.0"},                    # MAL-2026-14389
    # Aug 24 2026: multyproccess PyPI multiprocessing typosquat (4 versions)
    # OSV MAL-2026-14401
    "multyproccess": {"2.32.3", "2.32.4", "2.32.5", "2.32.6"},     # MAL-2026-14401
    # Aug 24 2026: msrcpoc PyPI dep-confusion POC (99.1.9)
    # OSV MAL-2026-14444
    "msrcpoc": {"99.1.9"},                                           # MAL-2026-14444
    # ─── Aug 25–27 2026: mixed PyPI malware batch (8 packages) ──────────────────
    # Diverse stealers, RCE probes, and typosquats, each confirmed by an
    # individual OSV MAL-2026-14xxx record.
    # OSV MAL-2026-14488, MAL-2026-14516, MAL-2026-14522, MAL-2026-14523,
    # MAL-2026-14524, MAL-2026-14525, MAL-2026-14542, MAL-2026-14545
    "0xfighter3": {"0.1"},                                           # MAL-2026-14525
    "bigquery-agent-analytics-tracing": {"0.0.0", "0.0.1"},         # MAL-2026-14524
    "minecraft-ytreceiver": {"0.1.0", "0.2.0", "0.3.0",
                              "0.4.0", "0.5.0"},                     # MAL-2026-14516
    "pybitjs": {"0.1.0"},                                            # MAL-2026-14545
    "python-walletlibr-v": {"0.7.9"},                                # MAL-2026-14488
    "rce-test": {"0.1"},                                             # MAL-2026-14523
    "syntaxerror-package-12345": {"0.1"},                            # MAL-2026-14522
    "trongridet": {"0.0.1"},                                         # MAL-2026-14542
    # ─── Aug 27-28 2026: misc PyPI malware batch (8 packages) ───────────────────
    # Mixed PyPI malware: mathkitlite/sap-quarterly-report/ekx-report-utils/decoris
    # typosquats, and flyteplugins-* dep-confusion impersonating Flyte plugin packages.
    # OSV MAL-2026-14552, MAL-2026-14554, MAL-2026-14555, MAL-2026-14556,
    # MAL-2026-14581, MAL-2026-14582, MAL-2026-14583, MAL-2026-14584
    "decoris": {"0.3.0", "0.3.3"},                                   # MAL-2026-14554
    "ekx-report-utils": {"0.1.0", "0.2.0", "0.3.0", "0.4.0"},       # MAL-2026-14555
    "flyteplugins-agento11y": {"2.6.10"},                             # MAL-2026-14581
    "flyteplugins-echo": {"2.6.10"},                                  # MAL-2026-14582
    "flyteplugins-nsight": {"2.6.10"},                                # MAL-2026-14583
    "flyteplugins-redis": {"2.6.10"},                                 # MAL-2026-14584
    "mathkitlite": {"0.1.0"},                                         # MAL-2026-14552
    "sap-quarterly-report": {"1.0.0"},                                # MAL-2026-14556
    # ─── Aug 28 2026: YAML-utility / game typosquat PyPI batch ──────────────────
    "pygame-renderkit": {"1.2.0"},           # MAL-2026-14587 — pygame typosquat
    "yaml-report-formatter": {"0.1.0", "0.2.0", "0.3.0"},  # MAL-2026-14588
    "yamlformat-tools": {"0.1.0"},           # MAL-2026-14589 — yaml cluster
    "yamlformatter-utils": {"1.0.0"},        # MAL-2026-14590 — yaml cluster
    "calcboxlite": {"1.0"},                  # MAL-2026-15488 — calculator utility typosquat
    # ─── Aug 29 2026: Flask utility typosquat ────────────────────────────────────
    "flask-header-guard": {"1.0.0"},        # MAL-2026-15566 — Flask plugin typosquat
    # ─── Sep 1 2026: server-check exfiltrator + Minecraft receiver ───────────────
    # pyservercheck: fake server diagnostics library with postinstall exfil payload.
    # OSV MAL-2026-15603
    "pyservercheck": {"0.1.0", "0.1.1"},    # MAL-2026-15603
    # ─── Aug 30 2026: Streamlit malware + Tron private-key stealers ──────────────
    # auth-app-streamlit exfiltrates credentials from Streamlit deployments.
    # trongridor / tronlinker target Tron blockchain users for private-key theft.
    # OSV MAL-2026-15577, MAL-2026-15578, MAL-2026-15588
    "auth-app-streamlit": {"2.1.1"},  # MAL-2026-15577
    "trongridor": {"0.0.1"},          # MAL-2026-15578 — Tron private-key stealer
    "tronlinker": {"0.0.1"},          # MAL-2026-15588 — Tron private-key stealer
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
    "fundraiserserv": set(),  # any version — OSV SEMVER >=0 range (updated Jul 28 2026)
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
    "permcarmserver": set(),       # MAL-2026-10488 (range >=0)
    "permcserver": set(),          # MAL-2026-10489 (range >=0; versions 1.0.0-1.0.4 published)
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

    # npm multi-campaign wave (July 22-24 2026)
    # 244 packages from OSV bulk export (modified >= 2026-07-22), all with active
    # MAL-* records (no withdrawn field). Organized by named sub-cluster below.

    # Solana typosquat cluster (July 22-24 2026)
    # Fourteen packages impersonating @solana/web3.js, @solana/spl-token, and
    # related Solana ecosystem libraries with install-time credential-exfiltration payloads.
    # OSV MAL-2026-5559/5560/5573/5787/5788/10898-10904.
    "@solana-labs/web3js": {
        "1.0.0", "1.0.2", "1.0.3", "1.0.4", "1.0.5", "1.0.6", "1.0.7", "1.0.8", "1.0.10",
        "1.98.103", "1.98.105", "1.98.107", "1.98.108", "1.98.109",
        "1.98.110", "1.98.111", "1.98.112",
    },                                                              # MAL-2026-5788
    "@solana-labs/spl-toke": {
        "1.0.0", "1.0.2", "1.0.3", "1.0.4", "1.0.5", "1.0.6", "1.0.7", "1.0.8", "1.0.10",
        "1.98.103", "1.98.105", "1.98.107", "1.98.108", "1.98.109",
        "1.98.110", "1.98.111", "1.98.112",
    },                                                              # MAL-2026-5787
    "solana-web3-community": {
        "1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4", "1.0.5",
    },                                                              # MAL-2026-5560
    "solana-rpc-client": {"1.0.0"},                                # MAL-2026-10898
    "solana-web3-fixed": {"1.0.0"},                                # MAL-2026-10899
    "solana-web3-fork": {"1.0.0"},                                 # MAL-2026-10900
    "solana-web3-lts": {"1.0.0"},                                  # MAL-2026-10901
    "solana-web3-patched": {"1.0.0"},                              # MAL-2026-10902
    "solana-web3-stable": {"1.0.0"},                               # MAL-2026-10903
    "solana-web3-v1": {"1.0.0"},                                   # MAL-2026-10904
    "solana-dev-tools": {"1.0.0"},                                 # MAL-2026-5559
    "solana-rpc-pool": {"1.0.0"},                                  # MAL-2026-5573
    "solana-js-client": {"1.0.0"},                                 # MAL-2026-5860
    "solana-mev-bot": {"1.0.0"},                                   # MAL-2026-5861

    # n8n malicious nodes cluster (July 22-24 2026)
    # Seven malicious n8n community nodes with port-scanner, net-utils, and
    # postinstall-exec payloads. OSV MAL-2026-10997 through MAL-2026-11006.
    "n8n-nodes-http-probe": {"1.0.0", "1.0.1", "1.0.2"},          # MAL-2026-10997
    "n8n-nodes-port-scanner": {"1.0.0", "1.0.1", "1.0.2"},        # MAL-2026-10998
    "n8n-nodes-task-runner": {
        "1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4",
        "1.0.5", "1.0.6", "1.0.7", "1.0.8", "1.0.9", "1.0.16",
    },                                                              # MAL-2026-10999
    "n8n-nodes-net-utils": {"1.0.0", "1.0.1", "1.0.2"},           # MAL-2026-11003
    "n8n-nodes-pwn": {"1.0.0", "1.0.5", "1.0.6", "1.0.7", "1.0.8"},  # MAL-2026-11004
    "n8n-nodes-quick-utils": {"1.0.0", "1.0.1", "1.0.2"},         # MAL-2026-11005
    "n8n-nodes-utils-helper": {"1.0.0", "1.0.1", "1.0.2"},        # MAL-2026-11006

    # @dxcl dep-confusion 99.99.99 cluster (July 22-24 2026)
    # Eight packages shadowing an internal @dxcl fintech scope at 99.99.99.
    # OSV MAL-2026-10872 through MAL-2026-10879.
    "@dxcl/account-js": {"99.99.99"},                              # MAL-2026-10872
    "@dxcl/customer-js": {"99.99.99"},                             # MAL-2026-10873
    "@dxcl/fund-js": {"99.99.99"},                                 # MAL-2026-10874
    "@dxcl/http-common-js": {"99.99.99"},                          # MAL-2026-10875
    "@dxcl/indicators-js": {"99.99.99"},                           # MAL-2026-10876
    "@dxcl/log-function-js": {"99.99.99"},                         # MAL-2026-10877
    "@dxcl/transaction-js": {"99.99.99"},                          # MAL-2026-10878
    "@dxcl/user-js": {"99.99.99"},                                 # MAL-2026-10879

    # @public-for-cdao dep-confusion 99.99.99 cluster (July 22-24 2026)
    # Eight packages targeting an internal @public-for-cdao scope at 99.99.99.
    # OSV MAL-2026-10882 through MAL-2026-10889.
    "@public-for-cdao/backend": {"99.99.99"},                      # MAL-2026-10882
    "@public-for-cdao/bot": {"99.99.99"},                          # MAL-2026-10883
    "@public-for-cdao/contracts": {"99.99.99"},                    # MAL-2026-10884
    "@public-for-cdao/core": {"99.99.99"},                         # MAL-2026-10885
    "@public-for-cdao/deploy": {"99.99.99"},                       # MAL-2026-10886
    "@public-for-cdao/sdk": {"99.99.99"},                          # MAL-2026-10887
    "@public-for-cdao/signer": {"99.99.99"},                       # MAL-2026-10888
    "@public-for-cdao/utils": {"99.99.99"},                        # MAL-2026-10889

    # Twilio dep-confusion cluster (July 22-24 2026)
    # Eight packages impersonating internal Twilio packages; any-version malicious.
    # OSV MAL-2026-10931 through MAL-2026-10938.
    "org-twilio-phone-numbers-utils": set(),                       # MAL-2026-10931
    "twilio-assets": set(),                                        # MAL-2026-10932
    "twilio-deploy": set(),                                        # MAL-2026-10933
    "twilio-internal": set(),                                      # MAL-2026-10934
    "twilio-platform-async-data-fetch": set(),                     # MAL-2026-10935
    "twilio-platform-request": set(),                              # MAL-2026-10936
    "twilio-serverless": set(),                                    # MAL-2026-10937
    "twiliointernal-messaging-toolbox": set(),                     # MAL-2026-10938

    # iphouse/markscan/akrai typosquat cluster (July 22-24 2026)
    # Nineteen packages in a coordinated cluster impersonating crypto scanning and
    # IP-intelligence tools; credential-exfiltration payloads; any-version malicious.
    # OSV MAL-2026-10946 through MAL-2026-10964.
    "@akrai/core": set(),                                          # MAL-2026-10946
    "@akrai/report": set(),                                        # MAL-2026-10947
    "@akrai/report_new": set(),                                    # MAL-2026-10948
    "@iphouse/api": set(),                                         # MAL-2026-10949
    "@iphouse/core": set(),                                        # MAL-2026-10950
    "@markscan/api": set(),                                        # MAL-2026-10951
    "@markscan/core": set(),                                       # MAL-2026-10952
    "@markscan/reports": set(),                                    # MAL-2026-10953
    "@markscan/utils": set(),                                      # MAL-2026-10954
    "akrai-report": set(),                                         # MAL-2026-10955
    "akrai-report-new": set(),                                     # MAL-2026-10956
    "iphouse": set(),                                              # MAL-2026-10957
    "iphouse-api": set(),                                          # MAL-2026-10958
    "iphouse-core": set(),                                         # MAL-2026-10959
    "markscan": set(),                                             # MAL-2026-10960
    "markscan-api": set(),                                         # MAL-2026-10961
    "markscan-core": set(),                                        # MAL-2026-10962
    "markscan-reports": set(),                                     # MAL-2026-10963
    "markscan-utils": set(),                                       # MAL-2026-10964

    # react-tabulix malware cluster (July 22-24 2026)
    # Five packages in a fake React table component library with malicious payloads.
    # OSV MAL-2026-10987/10988/10989/11015/11040.
    "react-tabulix-extended": {"0.1.7"},                           # MAL-2026-11040
    "react-tabulix-virtual": {"0.1.1"},                            # MAL-2026-10989
    "react-tabulix-core": set(),                                   # MAL-2026-10987 GHSA-5w4q-8fc9-88f4
    "react-tabulix-ui": set(),                                     # MAL-2026-10988 GHSA-5jr9-f9w4-93v3
    "react-tabulix-query": set(),                                  # MAL-2026-11015 GHSA-4rrq-g9w7-39c3

    # hemi-protocol 999.0.0 dep-confusion cluster (July 22-24 2026)
    # Seven packages targeting the Hemi protocol's internal build system at 999.0.0.
    # OSV MAL-2026-5778/5779/5781/5782/5783/5784/5785.
    "hemi-earn-actions": {"999.0.0"},                              # MAL-2026-5778
    "hemi-supply-cron": {"999.0.0"},                               # MAL-2026-5779
    "portal-backend": {"999.0.0"},                                 # MAL-2026-5781
    "token-prices-cron": {"999.0.0"},                              # MAL-2026-5782
    "vault-strategies": {"999.0.0"},                               # MAL-2026-5783
    "vaults-monitor-cron": {"999.0.0"},                            # MAL-2026-5784
    "ve-hemi-rewards": {"999.0.0"},                                # MAL-2026-5785

    # commonweb 99.9.1 dep-confusion cluster (July 22-24 2026)
    # Seven packages targeting an internal consumer-web monorepo at 99.9.1.
    # OSV MAL-2026-10965 through MAL-2026-10971.
    "requestor-util": {"99.9.1"},                                  # MAL-2026-10965
    "commonweb-card": {"99.9.1"},                                  # MAL-2026-10966
    "commonweb-moneymovement": {"99.9.1"},                         # MAL-2026-10967
    "commonweb-rewards": {"99.9.1"},                               # MAL-2026-10968
    "commonweb-wallet": {"99.9.1"},                                # MAL-2026-10969
    "consumerweb-calurls": {"99.9.1"},                             # MAL-2026-10970
    "cxpw-offers": {"99.9.1"},                                     # MAL-2026-10971

    # DeFi/crypto protocol impostors — any-version (July 22-24 2026)
    # OSV MAL-2026-10941/10942/10943/10944/10945.
    "aftermath-finance": set(),                                    # MAL-2026-10941
    "aftermath-sui": set(),                                        # MAL-2026-10942
    "aftermathfi": set(),                                          # MAL-2026-10943
    "zer0onetencent": set(),                                       # MAL-2026-10944
    "zer0onetencent2": set(),                                      # MAL-2026-10945

    # AWS CDK dep-confusion cluster (July 22-24 2026)
    # Six packages impersonating internal AWS CDK constructs; any-version malicious.
    # OSV MAL-2026-10920/10921/10922/10923/10924/10928.
    "alb-lambda-cdk": set(),                                       # MAL-2026-10920 GHSA-crmc-3m53-3crf
    "iot-kfh-s3": set(),                                           # MAL-2026-10921 GHSA-qg52-c79f-3q5c
    "lambda-cloudwatch-cdk": set(),                                # MAL-2026-10922 GHSA-m74r-g438-3r92
    "lwc-slds-lbc": set(),                                         # MAL-2026-10923 GHSA-xm8f-w286-57x5
    "s3-lambda-dynamodb-cdk": set(),                               # MAL-2026-10924 GHSA-6xqw-c34f-9275
    "upjsma": set(),                                               # MAL-2026-10928 GHSA-9g67-fm87-8p6v

    # Streak/svelte/calendar typosquat cluster (July 22-24 2026)
    # Eight packages impersonating streak-tracking and Svelte utility libraries.
    # OSV MAL-2026-10980/10981/10982/10983/11035/11036/11037/11038.
    "streak-calendar": set(),                                      # MAL-2026-10981 GHSA-2p69-mmpj-h84r
    "streak-daycount": set(),                                      # MAL-2026-10982 GHSA-2v57-6hmf-hpfj
    "svelte-streaks": set(),                                       # MAL-2026-10983 GHSA-8vq2-5c69-fm3w
    "nolby": set(),                                                # MAL-2026-10980 GHSA-x724-q7wp-wx6q
    "streak-bucket-lib": set(),                                    # MAL-2026-11035 GHSA-rg2p-8587-wx3w
    "streak-lib-math": set(),                                      # MAL-2026-11036 GHSA-c7rv-9j9g-pqh2
    "svelte-goal-streak": set(),                                   # MAL-2026-11037 GHSA-jw9g-wvg5-7rjg
    "svelte-streak-metrics": set(),                                # MAL-2026-11038 GHSA-fc4x-xfq3-5f35

    # Chai plugin typosquat cluster (July 22-24 2026)
    # Eleven malicious packages mimicking chai assertion plugins.
    # OSV MAL-2026-2743/2887/4168/5699/5843/5901/5903/5908/10939/10940/11032.
    "chai-as-elevated": set(),                                     # MAL-2026-2887 GHSA-p5jq-3963-9qmx
    "chai-as-vec": set(),                                          # MAL-2026-4168 GHSA-g2hx-wqmp-2fhg
    "chai-use-chain": set(),                                       # MAL-2026-2743 GHSA-77gr-x9m6-cm8g
    "chai-web3-testkit": set(),                                    # MAL-2026-5699 GHSA-j8qr-4p5h-mwqj
    "chai-smart-assert": set(),                                    # MAL-2026-5843 GHSA-897c-qgxj-rv65
    "chai-as-polished": {"7.0.8"},                                 # MAL-2026-5901 GHSA-jpr9-h23w-g7gg
    "chai-guid": {"1.1.5"},                                        # MAL-2026-5903
    "chain-chai-test": set(),                                      # MAL-2026-5908 GHSA-6626-c428-r9qf
    "chai-as-reddit": set(),                                       # MAL-2026-10939 GHSA-vc32-h28h-pmhm
    "chai-leaf": set(),                                            # MAL-2026-10940 GHSA-m3c7-2j38-rjh7
    "chai-as-stringify": set(),                                    # MAL-2026-11032 GHSA-vh7h-h87g-qv6x

    # Ethers/Web3/crypto typosquat cluster (July 22-24 2026)
    # Fifteen packages impersonating popular Web3 libraries with credential theft.
    # OSV MAL-2026-4553/4554/5494/5495/5496/5497/5498/5501/5651/5652/11023/11025/11026/11033/11034.
    "ethers-wallet-package": set(),                                # MAL-2026-4553 GHSA-7pvf-g7jg-rxpj
    "ethers-wallet-packages": set(),                               # MAL-2026-4554 GHSA-gm49-5q33-vf6f
    "@meme-sdk/trade": set(),                                      # MAL-2026-5494 GHSA-4c2m-9v9c-75xv
    "@solana-launchpad/sdk": set(),                                # MAL-2026-5495 GHSA-364r-rq62-6gx5
    "@validate-ethereum-address/core": set(),                      # MAL-2026-5496 GHSA-c29q-842f-rcjc
    "@validate-sdk/v2": set(),                                     # MAL-2026-5497 GHSA-vqg9-785x-8j39
    "@validator-sdk/pubkey": set(),                                # MAL-2026-5498 GHSA-w9ch-gj3p-2cj9
    "ethers-jss": set(),                                           # MAL-2026-5501 GHSA-xh65-7qcm-493w
    "ozonex-sdk": set(),                                           # MAL-2026-5651 GHSA-v2hc-cmv5-999p
    "theta-sdk": set(),                                            # MAL-2026-5652 GHSA-x7m6-5hw9-gj7f
    "bs58-88": set(),                                              # MAL-2026-11023 GHSA-qj7h-vp7h-8v85
    "da-sc-sdk": set(),                                            # MAL-2026-11025 GHSA-vxfh-w38r-2g54
    "ethers-packge": set(),                                        # MAL-2026-11026 GHSA-67vw-rvv3-mh93
    "eth-codergen": set(),                                         # MAL-2026-11033 GHSA-87w3-vjw9-8h4w
    "eth-slint": set(),                                            # MAL-2026-11034 GHSA-xp97-c4c4-7928

    # Generic invented-name malware cluster (July 22-24 2026)
    # Random-name pure-malware packages with GHSA records.
    # OSV MAL-2026-10984/11008/11009/11010/11014/11016/11017/11018/11019/11039.
    "veskra": set(),                                               # MAL-2026-10984 GHSA-pr2p-6xpw-q8vw
    "caldryn": set(),                                              # MAL-2026-11008 GHSA-h9c8-8wq8-r6q2
    "calmora": set(),                                              # MAL-2026-11009 GHSA-7wwx-476f-c8gm
    "calvora": set(),                                              # MAL-2026-11010 GHSA-jwm3-4ffq-hr73
    "kijai": set(),                                                # MAL-2026-11014 GHSA-5mgj-24pj-pj6f
    "vantora": set(),                                              # MAL-2026-11016 GHSA-4fm5-fwqx-8r39
    "vectormark": set(),                                           # MAL-2026-11017 GHSA-g48p-2cr5-5hm2
    "veldora": set(),                                              # MAL-2026-11018 GHSA-wxrm-vmq9-jp23
    "veskr": set(),                                                # MAL-2026-11019 GHSA-77c3-35xp-6chp
    "yuinpm": set(),                                               # MAL-2026-11039 GHSA-vpgm-qmgp-w4h4

    # encrypt-string typosquat cluster (July 22-24 2026)
    # OSV MAL-2026-11011/11012/11013.
    "encrypt-string-ttak": set(),                                  # MAL-2026-11011 GHSA-mpgp-492w-x7xj
    "encryptstringadmin": set(),                                   # MAL-2026-11012 GHSA-x92w-56m5-jchf
    "encryptstringadmincore": set(),                               # MAL-2026-11013 GHSA-hgfq-c4x3-jx2r

    # Misc Web3/DeFi typosquats — any-version (July 22-24 2026)
    "comos-sdk": set(),                                            # MAL-2026-5405 GHSA-xr7v-2mxc-cw5x
    "graphbase-js": set(),                                         # MAL-2026-5502 GHSA-29w9-hfv4-jjxh
    "anaylze-json": set(),                                         # MAL-2026-5505 GHSA-wjgw-rm6m-wgr3
    "argoncrypt": set(),                                           # MAL-2026-5506 GHSA-h3m2-g8jh-9p37
    "@bcryptln/bcryptjs": set(),                                   # MAL-2026-11021 GHSA-qw92-vxcv-397r
    "aio-commerce-lib-app": set(),                                 # MAL-2026-11022 GHSA-897j-xx2q-x2h9
    "create-kumo-project": set(),                                  # MAL-2026-11024 GHSA-7jg3-v58m-2f3p
    "fs-extra-core": set(),                                        # MAL-2026-11027 GHSA-f246-8cf4-26v7
    "helix-deploy": set(),                                         # MAL-2026-11028 GHSA-fhpm-cq57-j289
    "lychee-norm-cache": set(),                                    # MAL-2026-11029 GHSA-pj38-6jj4-4x3p
    "vitest-axios": set(),                                         # MAL-2026-11030 GHSA-6v5g-7h35-h33q
    "nw-demo-utils": set(),                                        # MAL-2026-5511 GHSA-q849-7xxq-hh4g
    "ts-vitest": set(),                                            # MAL-2026-10990

    # @su-doughnym dep-confusion cluster (July 22-24 2026)
    # Four packages impersonating an internal @su-doughnym scope.
    # OSV MAL-2026-6407/6408/6409/6410.
    "@su-doughnym/hubspot-loginui-poc": set(),                     # MAL-2026-6407 GHSA-jgj9-pm28-4m94
    "@su-doughnym/loginui": set(),                                 # MAL-2026-6408 GHSA-3rvq-gwcv-295m
    "@su-doughnym/metrics-js": set(),                              # MAL-2026-6409 GHSA-wj6x-p526-mv2w
    "@su-doughnym/react-dlb": set(),                               # MAL-2026-6410 GHSA-3g2q-cw4h-3g67

    # Large enterprise frontend dep-confusion batch (July 22-24 2026)
    # 50+ packages targeting named enterprise orgs; all any-version malicious.
    # OSV MAL-2026-4186/4440/4460/4463/4464/4465/5437/5438/5446/5451/5655/5658
    # /5662/5663/5664/5665/5667/5668/5670/5671/5693/5696/5697/5700/5701/5793
    # /6599/6600/6601/6605/6606/6607/6608/6609/6611/6613/6614/6615/6616/6617
    # /6618/6619/6620/6622/6624/6625/6626/6627/6628/6629/6630/6632/6633/6634
    # /6635/6636/6640/6641/6652.
    "@deel-core/client-payroll-onboarding-types": set(),           # MAL-2026-6613 GHSA-v8wg-p2qh-9q7g
    "@deel-ui/animation": set(),                                   # MAL-2026-6614 GHSA-9rwq-pr4x-fhqg
    "@rakuten-rewards/messaging-sdk": set(),                       # MAL-2026-6640 GHSA-fjrr-hfh2-c44q
    "@rakuten-rewards/messaging-sdk-js": set(),                    # MAL-2026-6641 GHSA-9hcr-h425-gc22
    "@anna-money/anna-web-lib": set(),                             # MAL-2026-6600 GHSA-f2cq-vvgf-2rrx
    "@alerts/components": set(),                                   # MAL-2026-6599 GHSA-m86f-3q43-wmpg
    "@appsource/utils": set(),                                     # MAL-2026-6601 GHSA-28xf-wrjx-23mj
    "@bscom/styling": set(),                                       # MAL-2026-6605 GHSA-29c6-c7cm-r8ch
    "@concerns/i18n": set(),                                       # MAL-2026-6606 GHSA-rp2m-w359-5cqp
    "@content-editor/common": set(),                               # MAL-2026-6607 GHSA-wwc7-v7xr-q4pc
    "@contenteditor-shared/content-editor-common": set(),          # MAL-2026-6608 GHSA-3v59-3pc3-p6qm
    "@contentprod-authoring/block-manager": set(),                 # MAL-2026-6609 GHSA-cpfg-m96g-j4j9
    "@cxp-shared/string-utilities": set(),                         # MAL-2026-6611 GHSA-fmg2-rq45-rc5r
    "@digitalpharmacist/http-error-util": set(),                   # MAL-2026-6615 GHSA-jw9w-w49g-cx4h
    "@druidsoft/botframework-directlinejs": set(),                  # MAL-2026-6616 GHSA-h76h-pchq-6m2g
    "@e50/utils": set(),                                           # MAL-2026-6617 GHSA-w945-prph-8545
    "@experian-shared/services": set(),                            # MAL-2026-6618 GHSA-vhf7-5xf6-3fwr
    "@fed-sofia/jetify": set(),                                    # MAL-2026-6619 GHSA-59mp-5h6w-4mpp
    "@finantix/webcomponents": set(),                              # MAL-2026-6620 GHSA-hf7q-222g-654m
    "@gallup/pc-utils": set(),                                     # MAL-2026-6622 GHSA-8f5r-5xw2-f3r4
    "@gm-rvg/root-config": set(),                                  # MAL-2026-6624 GHSA-9crf-2vxq-9j4r
    "@grappi/automations": set(),                                  # MAL-2026-6625 GHSA-85ph-rvjg-3hmr
    "@hg-aka-prml/tapas-common": set(),                            # MAL-2026-6626 GHSA-cmr6-9388-xg9g
    "@huobi-ui/activity-components": set(),                        # MAL-2026-6627 GHSA-h7hg-5749-jc66
    "@img-hls/vtt.js": set(),                                      # MAL-2026-6628 GHSA-7752-87g2-6jgf
    "@lexisnexisrisk/insider-threat-platform": set(),              # MAL-2026-6629 GHSA-q77j-rhqv-28m6
    "@live-backstage-im/communication-chat": set(),                # MAL-2026-6630 GHSA-h887-mrmh-2fjr
    "@meego-progressive/cdk": set(),                               # MAL-2026-6632 GHSA-f7vv-5p73-c4rr
    "@ms-ows/logging": set(),                                      # MAL-2026-6633 GHSA-46wp-9qm3-2vv4
    "@multformats/multiaddr": set(),                               # MAL-2026-6634 GHSA-92ch-4pr4-pmgj
    "@orbis-lr-sdk/orbis-lr-sdk": set(),                           # MAL-2026-6635 GHSA-8w2w-98mc-3qqc
    "@partner-apps/ui": set(),                                     # MAL-2026-6636 GHSA-5vf9-5xgw-84rw
    "@webda-infra-ui/static-images": set(),                        # MAL-2026-6652 GHSA-pp6c-f2ph-gxmm
    "@doctolib-apps/native-personalized-services": set(),          # MAL-2026-4186 GHSA-hgpx-hj7x-3cx9
    "@serviceshub/x-web-core": set(),                              # MAL-2026-4440 GHSA-xjvj-r6v9-q99q
    "@trackking/core": set(),                                      # MAL-2026-4460 GHSA-2qqx-q4v2-495g
    "@vivaux/telemetry": set(),                                    # MAL-2026-4463 GHSA-hq2r-xw8m-v4q8
    "@vtmn-play/react": set(),                                     # MAL-2026-4464 GHSA-vpcv-xpqm-w228
    "@web-3d-tool/sdk": set(),                                     # MAL-2026-4465 GHSA-qmfq-m796-v557
    "@hatcha-captcha/core": set(),                                 # MAL-2026-5655 GHSA-2v2g-hp62-vhwj
    "@marketplace-shared/components": set(),                       # MAL-2026-5658 GHSA-5cx4-3w47-xm4h
    "@snowsight/debug-tooling": set(),                             # MAL-2026-5662 GHSA-c33m-qf7q-vg8q
    "@tenforce/toolbox-fontmap": set(),                            # MAL-2026-5663 GHSA-4pgr-qgvj-c2wh
    "@tribe-digital/shopify-starter-theme": set(),                 # MAL-2026-5664 GHSA-6cc8-4vwg-c56v
    "@visma-net-platform/module-navigator": set(),                 # MAL-2026-5665 GHSA-r344-wgf5-fqf4
    "commons-ui-styles": set(),                                    # MAL-2026-5437 GHSA-3w2q-76fx-mcgj
    "corporate-front-vue": set(),                                  # MAL-2026-5438 GHSA-j2pq-r63w-52j5
    "housecall-ui": set(),                                         # MAL-2026-5446 GHSA-h2mj-mwm8-g9qp
    "privacy-sdk": set(),                                          # MAL-2026-5451 GHSA-wrgr-9636-hfmh
    "experian-analytics-components": set(),                        # MAL-2026-5667 GHSA-wg43-49xc-v68q
    "fed-callnative": set(),                                       # MAL-2026-5668 GHSA-hwp4-g2h4-2v7r
    "pui-diagnostics": set(),                                      # MAL-2026-5670 GHSA-96f9-39p2-gjwm
    "sitecore-mm-component-style": set(),                          # MAL-2026-5671 GHSA-mp9q-fvp5-ww2c
    "sea-bound-siren": set(),                                      # MAL-2026-5693 GHSA-cp5x-35vp-rj7j
    "voyager-web": set(),                                          # MAL-2026-5696 GHSA-3vr9-xc7m-h6qx
    "web-model-bridge": set(),                                     # MAL-2026-5697 GHSA-69cw-2vc8-9jm7
    "transportator": set(),                                        # MAL-2026-5700 GHSA-6wwm-jx4f-p4xq
    "vite-react-toolkit": set(),                                   # MAL-2026-5701 GHSA-4vwq-cp5w-hx5g
    "nativescript-swisspost-pcc-creative-editor": set(),           # MAL-2026-5793 GHSA-h5g9-q449-jr2c
    "simple-auth-basic": set(),                                    # MAL-2026-2905 GHSA-4v3c-c5pj-m2qq
    "swplayer-react-sl": set(),                                    # MAL-2026-2906 GHSA-959p-q4g9-cc8r
    "modern-events": set(),                                        # MAL-2026-2914 GHSA-wwr2-883g-52c2
    "path-extend": set(),                                          # MAL-2026-2929 GHSA-qvmc-2hcj-8h4f
    "ccl-component-resources": set(),                              # MAL-2024-1959 GHSA-892p-5g9m-p64x
    "launch-darkly-js": set(),                                     # MAL-2026-1050 GHSA-g8jj-44f9-c9rv
    "dgxeon-soket": set(),                                         # MAL-2026-1074 GHSA-838q-63vp-c27h
    "workspace-lint": set(),                                       # MAL-2026-10112 GHSA-2667-2whh-v3mf
    "workspace-scripts": set(),                                    # MAL-2026-10113 GHSA-pcrx-c762-59jm
    "motiondnb": set(),                                            # MAL-2026-10145 GHSA-278r-46x5-pfjm
    "ng-search-api": set(),                                        # MAL-2026-10146 GHSA-rgrc-mmg8-pgrr
    "mvn-runtime": set(),                                          # MAL-2026-1202 GHSA-5937-7cj9-h84g
    "ng-vzbootstrap": set(),                                       # MAL-2026-1100 GHSA-25jj-4j8c-cgrq
    "rnx-align-deps": set(),                                       # MAL-2026-6940 GHSA-q28c-5m68-92hm
    "vscode-test-web": set(),                                      # MAL-2026-6361 GHSA-vxwh-gqjr-fxcw
    "kdrive-utils": set(),                                         # MAL-2026-6295 GHSA-v9x6-7mvw-mf22
    "hs-locale-management": set(),                                 # MAL-2026-6394 GHSA-rv32-4gr2-5g7w
    "signup-embedder": set(),                                      # MAL-2026-6396 GHSA-8j4q-hx83-pfq9
    "data-fetching-client": set(),                                 # MAL-2026-6411 GHSA-j99m-jc5r-9w58
    "nabisco": set(),                                              # MAL-2026-6412 GHSA-m97m-v5gv-jm47
    "two-factor-prompt-lib": set(),                                # MAL-2026-6414 GHSA-94jg-r3hx-4v8v
    "xrblocks-remote-control": set(),                              # MAL-2026-6530 GHSA-24xr-qqmw-jvvf
    "rbac-auth": set(),                                            # MAL-2026-5873 GHSA-vhxh-pphh-cjmr
    "pampipes": set(),                                             # MAL-2026-5872 GHSA-j43p-473c-2jjx
    "hot-validation-sdk": set(),                                   # MAL-2026-5870 GHSA-86rx-hcgg-q42r
    "fabric-graphics": set(),                                      # MAL-2026-5869 GHSA-p7vq-w45x-hmmj
    "terminal-structured-logger": set(),                           # MAL-2026-5867 GHSA-9ggp-5rq8-jmff
    "terminal-pretty-logger": set(),                               # MAL-2026-5866 GHSA-2266-qhvj-h8r5
    "vemos-sdk": set(),                                            # MAL-2026-5855 GHSA-xfv6-m3cj-53m7
    "vite-enhancer-config": set(),                                 # MAL-2026-5850 GHSA-gmwm-6xjg-8wxr
    "slow-surf": set(),                                            # MAL-2026-5848 GHSA-4qxq-82wv-jq32
    "reading-cookies": set(),                                      # MAL-2026-5847 GHSA-mf62-v96j-mg7g
    "prettier_v2": set(),                                          # MAL-2026-5846 GHSA-cmfj-34j9-8w66
    "browserslist-db-sync": set(),                                 # MAL-2026-5842 GHSA-mfw9-5hqc-vc53
    "index-ulid": set(),                                           # MAL-2026-5827 GHSA-95pm-8vrw-2wrp
    "base65-85x": set(),                                           # MAL-2026-6704 GHSA-mv5w-mcrv-wmx9
    "vue-demi-fix": set(),                                         # MAL-2026-6702 GHSA-p53q-mf26-4h26
    "procwire": set(),                                             # MAL-2026-6687 GHSA-5r42-357x-f2mx
    "terminal-prettier": set(),                                    # MAL-2026-6676 GHSA-m8cr-hv9p-pg3f
    "wac-atl-context": set(),                                      # MAL-2026-6671 GHSA-hx4g-w4gr-x32f
    "pvd3": set(),                                                 # MAL-2026-6669 GHSA-4m95-g5w6-4x4w
    "cmp-api-stub": set(),                                         # MAL-2026-6662 GHSA-q9xg-g7r9-mqrx
    "clx-cookieparser": set(),                                     # MAL-2026-6661 GHSA-jpg2-3r22-63v7
    "bundrix": set(),                                              # MAL-2026-6658 GHSA-vrw9-m2mj-2fp9
    "app-hotmart-blog-headless": set(),                            # MAL-2026-6654 GHSA-vq57-p4j4-v553
    "clx-cookie-signature": set(),                                 # MAL-2026-6141 GHSA-vwwm-x6xj-cfmf
    "ratelimitsucks": set(),                                       # MAL-2026-6135 GHSA-x94f-fgw2-crm2
    "routecraft": set(),                                           # MAL-2026-6229 GHSA-mw8m-x3ph-h3x7
    "endpointmap": set(),                                          # MAL-2026-6588 GHSA-p3qr-5g48-8w89

    # Pinned-version npm malware packages (July 22-24 2026)
    # Packages with exact known-malicious versions; pin these.
    "analysis-chart": {
        "2.0.8", "2.0.9", "2.0.10", "2.0.11", "2.0.12", "2.0.13", "2.0.14",
        "2.0.15", "2.0.16", "2.0.17", "2.0.18", "2.0.19", "2.0.20", "2.0.21",
        "2.0.22", "2.0.23", "2.0.24", "2.0.25", "2.0.26", "2.0.27", "2.0.28",
    },                                                              # MAL-2026-10890 GHSA-2h56-6c2c-2475
    "@apexfdn/apex": {
        "1.0.1", "1.0.2", "1.0.3", "1.0.4", "1.0.5", "1.0.6", "1.0.7", "1.0.8",
        "1.0.9", "1.0.10", "1.0.11", "1.0.12", "1.0.13", "1.0.14", "1.0.15", "1.0.16",
        "1.0.17", "1.0.18", "1.0.19", "1.0.20", "1.0.21", "1.0.22", "1.0.23", "1.0.24",
        "1.0.25", "1.0.26", "1.0.27", "1.0.28", "1.0.29", "1.0.30", "1.0.31", "1.0.32",
    },                                                              # MAL-2026-10979 GHSA-w63r-vpcf-2wwf
    "svgcraft-core": {
        "1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4", "1.0.5", "1.0.6", "1.0.7",
    },                                                              # MAL-2026-6715 GHSA-j9vc-q728-qcx4
    "date-fns-lite": {
        "1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4", "1.0.5", "1.0.6",
        "1.0.7", "1.0.8", "1.0.9", "1.0.10", "1.0.11", "1.0.12",
    },                                                              # MAL-2026-6722
    "vega-lite-next": {"19.2.1"},                                  # MAL-2026-6709
    "ts-eslinter": {"1.0.0"},                                      # MAL-2026-6896 GHSA-h269-vrf6-9f75
    "pino-slite": {"4.1.12", "4.1.16"},                            # MAL-2026-6078
    "params-valid-js": {"1.0.0", "1.0.1", "1.0.3"},               # MAL-2026-5988
    "req-parmas-valid": {"1.0.2"},                                 # MAL-2026-5991
    "requests-middleware": {"1.0.2"},                              # MAL-2026-6096
    "electron-internal-utils": {"1.0.0"},                          # MAL-2026-6186
    "ts-bn-lint-helper": {"3.1.19"},                               # MAL-2026-6318
    "hyperpure": {"1.0.0"},                                        # MAL-2026-6370
    "macos-ci-utils": {"1.0.0", "1.0.1"},                          # MAL-2026-6378
    "path-addon": {
        "1.0.2", "1.0.3", "1.0.4", "1.0.5", "1.0.6", "1.0.7",
    },                                                              # MAL-2026-3311
    "date-format-utils-xz": {"1.0.3", "1.0.4"},                   # MAL-2026-11001
    "signzy-field-level-encrypter": {"12.9.12", "12.9.13"},        # MAL-2026-10972
    "airbnb-airlock": {"99.0.0"},                                  # MAL-2026-6293
    "myebaynode": {"99.0.0"},                                      # MAL-2026-6296
    "@outmarket/utils": {"9.9.9", "9.9.10", "9.9.11"},            # MAL-2026-6292
    "@atlaskit-internal_.smart-card/hover-card": {"99.0.0"},       # MAL-2026-10870
    "@azure-lab-services/ml-ts": {"99.0.0"},                       # MAL-2026-10871
    "crosswalker": {"1.0.0", "1.0.1", "18.2.1"},                  # MAL-2024-2031
    "oauth-connect": {"0.1.1", "2.0.1"},                           # MAL-2024-2779
    "@uwr/colors": {"1.3.6"},                                      # MAL-2026-10179
    "consumerweb": {"2200.4.2"},                                   # MAL-2026-10181
    "fkext-browser-min": {"1.0.14"},                               # MAL-2026-10183
    "conversionvaluemanager": {"3.0.0"},                           # MAL-2026-10084
    "bytecraft": {"1.5.0", "2.0.0"},                               # MAL-2026-10891
    "flow-eslint-oxidized": {"0.0.1", "74.2.1"},                   # MAL-2026-10896
    "@irys-solutions/odesa-main": {"1.0.0"},                       # MAL-2026-10881
    "hardhat-gas-tracker": {"1.0.1"},                              # MAL-2026-11020
    "app-data-ist": {"2.1.6"},                                     # MAL-2026-10994
    "habingeer": {"2.1.6"},                                        # MAL-2026-10995
    "application-util": {"2.1.6"},                                 # MAL-2026-11000
    "habinger": {"2.1.6"},                                         # MAL-2026-11002
    "web3-terminal": {"2.1.6"},                                    # MAL-2026-11007
    # CodeLake Research install-time droppers — July 25 2026
    # OSV MAL-2026-11042 / MAL-2026-11043 / MAL-2026-11044
    "faust-cont": {"1.0.0"},                                       # MAL-2026-11042
    "supplyhub": {"1.0.2"},                                        # MAL-2026-11043
    "tailwind-gutenberg-block-zero": {"1.0.0"},                    # MAL-2026-11044
    # @daylightqc/date-fmt-lite: malicious domain C2 — July 25 2026
    # OSV MAL-2026-11041 / OpenSSF detection
    "@daylightqc/date-fmt-lite": {"1.0.0", "1.0.1", "1.1.1", "1.1.2"},  # MAL-2026-11041 (1.1.2 added Jul 28)
    # subapp-pkg-util: dep-confusion high-version — July 25 2026
    # OSV MAL-2026-11045
    "subapp-pkg-util": {"99.0.1"},                                 # MAL-2026-11045
    # app-data-layer / app-data-lts / app-node-layer: full-compromise wildcards — July 25 2026
    # GHSA-346c-3w9c-8pmh / GHSA-c6xr-m3x3-23fm / GHSA-4xc7-2jx9-rp5j
    "app-data-layer": set(),                                       # MAL-2026-11052 GHSA-346c-3w9c-8pmh
    "app-data-lts": set(),                                         # MAL-2026-11053 GHSA-c6xr-m3x3-23fm
    "app-node-layer": set(),                                       # MAL-2026-11054 GHSA-4xc7-2jx9-rp5j
    # PayPal / f0 dep-confusion cluster (July 25 2026) — internal PayPal service names
    # published at v28.0.0 (dep-confusion probe); all communicate with malicious C2 domain
    # OSV MAL-2026-11055 through MAL-2026-11063; MAL-2023-1491 / MAL-2023-8293 updated with 28.0.0 variant
    "fundraiserservicepp": {"1.5.0"},                              # MAL-2026-11055
    "gpaas-paypal": {"28.0.0"},                                    # MAL-2026-11056
    "merchantprefsservice-paypal": {"28.0.0"},                     # MAL-2026-11057
    "payoutsvettingserv-paypal": {"28.0.0"},                       # MAL-2026-11058
    "pp-react-ui5": {"28.0.0"},                                    # MAL-2026-11059
    "f0-form-manipulator": {"28.0.0"},                             # MAL-2026-11060
    "identityscimapiserv": {"28.0.0"},                             # MAL-2026-11061
    "preferenceslifecycle-paypal": {"28.0.0"},                     # MAL-2026-11062
    "xo-member-components": {"28.0.0"},                            # MAL-2026-11063
    "f0-data-constructor": {"1.0.0", "28.0.0"},                    # MAL-2023-1491 (28.0.0 added Jul 25)
    "f0-fpti-tracking-manager": {"5.6.8", "28.0.0"},               # MAL-2023-8293 (28.0.0 added Jul 25)
    # Misc npm malware — July 25 2026
    # OSV MAL-2026-11064 / MAL-2026-11065 / MAL-2026-11066
    "page-navigation": {"1.0.1"},                                  # MAL-2026-11064
    "swiper_angular": {"5.9999.0"},                                # MAL-2026-11065
    "@ks-radar/radar": {"22.0.0"},                                 # MAL-2026-11066
    # Misc npm malware — July 26-27 2026
    # clerk-next-fix-auth-protection: Clerk.js auth-library impersonator, suspicious high
    # versions (8.8.8, 7.7.7); detected by OpenSSF Package Analysis. OSV MAL-2026-11069
    # whs4_deu / whs4_eud / wsh4_edu: malware cluster (similar naming pattern),
    # all detected by OpenSSF Package Analysis. OSV MAL-2026-11070/11071/11072
    "clerk-next-fix-auth-protection": {"8.8.8", "7.7.7"},        # MAL-2026-11069
    "whs4_deu": {"1.0.0", "1.0.1"},                               # MAL-2026-11070
    "whs4_eud": {"1.0.0", "1.0.1"},                               # MAL-2026-11071
    "wsh4_edu": {"1.0.0"},                                        # MAL-2026-11072
    # thirdweb/RainbowKit/log-taker typosquat extension — July 27 2026
    # Same typosquat campaign as thirdwb/thirdwebb (July 1 batch); additional variants
    # and RainbowKit/log-taker look-alike packages. All SEMVER >=0 ranges.
    # OSV MAL-2026-6338/6339/6340/6342/6343/6344/6345/6439
    "log-taker": set(),                                            # MAL-2026-6338
    "rainbokit": set(),                                            # MAL-2026-6339
    "rainbownkit": set(),                                          # MAL-2026-6340
    "therdweb": set(),                                             # MAL-2026-6342
    "thidweb": set(),                                              # MAL-2026-6343
    "thirdwebjs": set(),                                           # MAL-2026-6344
    "thurdweb": set(),                                             # MAL-2026-6345
    "polymarket-stake-maths": set(),                               # MAL-2026-6439
    # ts-escrow / ts-escro TypeScript escrow typosquats — July 27 2026
    # OSV MAL-2026-6319/6320
    "ts-escro": set(),                                             # MAL-2026-6319
    "ts-escrow": set(),                                            # MAL-2026-6320
    # @sqlite-frame / @sqlite-tag sqlite-related malware cluster — July 27 2026
    # New packages in same family as @sqlite-clone/nodesql and @sqlite-group/sql-creator.
    # OSV MAL-2026-11075/11076/11077
    "@sqlite-frame/createsql": set(),                              # MAL-2026-11075
    "@sqlite-tag/schema-generator": set(),                         # MAL-2026-11076
    "@sqlite-tag/sql-creator": set(),                              # MAL-2026-11077
    # @thone33 scope extension — July 27 2026
    # New package in same attacker scope as @thone33/analytics-injector and @thone33/core-utils.
    # OSV MAL-2026-11078 GHSA-vxmg-ff8j-2552
    "@thone33/react-helpers": set(),                               # MAL-2026-11078
    # WhatsApp/Baileys/kalipto/fazz credential-exfiltration cluster — July 27 2026
    # Packages impersonating the WhatsApp Baileys library and social-media utilities;
    # exfiltrate credentials and session data. OSV MAL-2026-5922/6097/11073/11079-11081/11085-11088
    "@fazzcode/baileys": set(),                                    # MAL-2026-11073
    "@vinnxcode/libsignal-node": set(),                            # MAL-2026-11079
    "@vinnxcode/xbailsync": set(),                                 # MAL-2026-11080
    "amanexzyra-baileys": set(),                                   # MAL-2026-11081
    "sixbails": set(),                                             # MAL-2026-11088
    "fazzanime": set(),                                            # MAL-2026-11085
    "fazzgram": set(),                                             # MAL-2026-11086
    "kalipto-runtime": set(),                                      # MAL-2026-11087
    "@kalipto/local": set(),                                       # MAL-2026-5922
    "roblox-api-client": set(),                                    # MAL-2026-6097
    # @my_name_is_khn express-security-tool cluster — July 27 2026
    # Four versioned malicious Express "security" packages by the same actor.
    # OSV MAL-2026-5550/5551/5552/11074
    "@my_name_is_khn/express-security-tool": set(),                # MAL-2026-5550
    "@my_name_is_khn/express-security-tool-v1": set(),             # MAL-2026-5551
    "@my_name_is_khn/express-security-tool-v2": set(),             # MAL-2026-11074
    "@my_name_is_khn/express-security-tool-v3": set(),             # MAL-2026-5552
    # express-self-destruct / express-timer malware cluster — July 27 2026
    # Packages publishing under "self-destruct" and "timer" Express middleware names;
    # all OSV SEMVER >=0. OSV MAL-2026-5553/5554/5555/11084
    "express-self-destruct": set(),                                # MAL-2026-5553
    "express-self-destruct1": set(),                               # MAL-2026-11084
    "express-self-destruct2": set(),                               # MAL-2026-5554
    "express-timer": set(),                                        # MAL-2026-5555
    # edu-npm / demo-probe postinstall exfiltrators — July 27 2026
    # Packages with "edu" and "demo" names that run malicious postinstall scripts
    # exfiltrating environment data. OSV MAL-2026-5623/5624/5723/5772/11082/11083
    "edu-npm-dependency-chain-demo": set(),                        # MAL-2026-5623
    "edu-npm-postinstall-demo2": set(),                            # MAL-2026-5624
    "edu-npm-helper-alpha": set(),                                 # MAL-2026-11082
    "edu-npm-helper-beta": set(),                                  # MAL-2026-11083
    "@ci-lifecycle-test/postinstall-ping": set(),                  # MAL-2026-5723
    "npx-whoami-demo": set(),                                      # MAL-2026-5772
    # txs-* transaction SDK malware cluster — July 27 2026
    # Four packages impersonating a transaction SDK; SEMVER >=0 ranges.
    # OSV MAL-2026-11089/11090/11091/11092
    "txs-builder": set(),                                          # MAL-2026-11089
    "txs-random-lib": set(),                                       # MAL-2026-11090
    "txs-runner-lib": set(),                                       # MAL-2026-11091
    "txs-sdk-lib": set(),                                          # MAL-2026-11092
    # @heartlandone-private dep-confusion — July 27 2026
    # Dep-confusion probe targeting Heartland One's private FontAwesome Pro registry.
    # OSV MAL-2026-11093; version 6.3.3 pinned (no >=0 range, dep-confusion probe only).
    "@heartlandone-private/fontawesome-pro": {"6.3.3"},            # MAL-2026-11093
    # @ceeferenderer dep-confusion cluster — July 27 2026
    # Two packages at 99.9.9 targeting Ceef/Erenderer internal SDKs.
    # OSV MAL-2026-2406/2407 GHSA-mw7m-6vvq-q69p / GHSA-3v4h-w4g3-h6r2; SafeDep primary source.
    "@ceeferenderer/fe-renderer-sdk": set(),                       # MAL-2026-2406
    "@ceeferenderer/itg-renderer-sdk": set(),                      # MAL-2026-2407
    # Misc npm malware — July 27 2026
    # ap3-components-ui: dep-confusion probe at 9.999.0; SEMVER >=0 range. OSV MAL-2026-10150
    # llama-tokenizer: LLM-tool typosquat at 1.2.2; SEMVER >=0 range. OSV MAL-2026-10163
    # v018-axios-cdntest: axios CDN test malware; 4 versions, SEMVER >=0. OSV MAL-2026-5529
    # jextic-eclib: miscellaneous malware at 1.0.0. OSV MAL-2026-5712
    "ap3-components-ui": set(),                                    # MAL-2026-10150
    "llama-tokenizer": set(),                                      # MAL-2026-10163
    "v018-axios-cdntest": set(),                                   # MAL-2026-5529
    "jextic-eclib": set(),                                         # MAL-2026-5712
    # -----------------------------------------------------------------------
    # July 28 2026 npm/PyPI malware wave (~60 new packages across 10 campaigns)
    # -----------------------------------------------------------------------
    # PayPal/internal dep-confusion cluster extension — July 27-28 2026
    # Targets PayPal internal service names with dep-confusion probes; GHSA/OSV
    # confirmed malicious payloads communicating with external C2.
    # OSV MAL-2025-190499 / MAL-2026-11095-11105
    "filifecycleserv-paypal": {"3.0.0"},                          # MAL-2025-190499
    "crm-reportinsightserv-paypal": set(),                         # MAL-2026-11098
    "identityauthorizationserv": set(),                            # MAL-2026-11100
    "riskunifiedgatewayserv": set(),                               # MAL-2026-11102
    "stargateproxyserv": set(),                                    # MAL-2026-11103
    "xo-twofa": set(),                                             # MAL-2026-11105
    # @array-util/ dep-confusion cluster — June-July 28 2026
    # Ships a single obfuscated JS file phoning home; targets private @array-util scope.
    # OSV MAL-2026-6084 / MAL-2026-11095
    "@array-util/nodepull": {"1.0.0", "1.1.0", "1.1.1"},         # MAL-2026-6084
    "@array-util/subsearch": set(),                                # MAL-2026-11095
    # @vaultflow/ dep-confusion cluster — July 28 2026
    # OSV MAL-2026-11096 / MAL-2026-11097; GHSA any-computer-fully-compromised warning.
    "@vaultflow/create-flow": set(),                               # MAL-2026-11096
    "@vaultflow/update-flow": set(),                               # MAL-2026-11097
    # motion-forge-css / tailwind-motionkit CSS framework typosquats — July 28 2026
    # Impersonate CSS animation / Tailwind utility packages; SEMVER >=0 range.
    # OSV MAL-2026-11101 / MAL-2026-11104
    "motion-forge-css": set(),                                     # MAL-2026-11101
    "tailwind-motionkit": set(),                                   # MAL-2026-11104
    # @immobiliarelabs/backstage-plugin-gitlab: binding.gyp worm (June 26 - July 28 2026)
    # Legitimate Backstage GitLab plugin; 7 specific versions infected by the binding.gyp
    # worm campaign (June 5 2026). Pin exact versions — this is a legitimate package.
    # OSV MAL-2026-6526; Amazon Inspector detection.
    "@immobiliarelabs/backstage-plugin-gitlab": {
        "1.0.1", "2.1.2", "3.0.3", "4.0.2", "5.2.1", "6.13.1", "7.0.2",
    },                                                             # MAL-2026-6526
    # app-*-layer / api-*-sdk postinstall exfiltrator cluster — July 28 2026
    # Six packages sharing the same 2.1.6 version and malicious postinstall hook
    # pattern; extension of app-node-layer / app-data-layer (July 25 2026) campaign.
    # OSV MAL-2026-11124/11125/11126/11127/11128/11129
    "api-node-sdk": {"2.1.6"},                                    # MAL-2026-11124
    "api-rust-sdk": {"2.1.6"},                                    # MAL-2026-11125
    "app-sim-layer": {"2.1.6"},                                   # MAL-2026-11126
    "app-sima-layer": {"2.1.6"},                                  # MAL-2026-11127
    "app-soda-layer": {"2.1.6"},                                  # MAL-2026-11128
    "app-svm-layer": {"2.1.6"},                                   # MAL-2026-11129
    # streak-*/lib-streak-math postinstall credential cluster — July 28 2026
    # Packages presenting as "streak tracking" / math utilities; run malicious postinstall
    # scripts. All at 1.0.0. OSV MAL-2026-11141/11148/11149/11150
    "lib-streak-math": {"1.0.0"},                                 # MAL-2026-11141
    "streak-core-lib": {"1.0.0"},                                 # MAL-2026-11148
    "streak-core-math": {"1.0.0"},                                # MAL-2026-11149
    "streak-daily-lib": {"1.0.0"},                                # MAL-2026-11150
    # xerohub-discord-voice malware cluster — July 28 2026
    # Packages impersonating a Discord voice library; OSV MAL-2026-11154/11155
    "xerohub-discord-voice-v2": {"1.8.0"},                       # MAL-2026-11154
    "xerohub-discord-voice-v3": {"3.0.0", "3.0.2", "3.0.3"},    # MAL-2026-11155
    # Generic helper/utility malware cluster — July 28 2026
    # Amazon Inspector detections: packages advertising as array/JSON/date/string utilities
    # but running malicious postinstall scripts or phoning home.
    # OSV MAL-2026-11106/11107/11108/11118/11119/11130/11142/11147/11151
    "date-sanitize-helper": {"1.0.0"},                            # MAL-2026-11106
    "num-format-helper": {"1.0.0"},                               # MAL-2026-11107
    "string-format-kit": {"1.0.2"},                               # MAL-2026-11108
    "array-sort-helper": {"1.0.0"},                               # MAL-2026-11118
    "json-to-table-util": {"1.0.0"},                              # MAL-2026-11119
    "array-node-utils": {"1.0.9"},                                # MAL-2026-11130
    "node-array-plus": {"1.0.9"},                                 # MAL-2026-11142
    "simple-probe-utils": {"1.0.1"},                              # MAL-2026-11147
    "text-line-parser": {"1.0.0"},                                # MAL-2026-11151
    # Miscellaneous npm malware — July 28 2026
    # Mixture of typosquats, dep-confusion probes, and standalone malware packages
    # detected by Amazon Inspector and OpenSSF Package Analysis.
    # OSV MAL-2026-2785 / MAL-2025-190499 / MAL-2026-6406 / MAL-2026-10115 / MAL-2026-10160
    # / MAL-2026-11120-11145 / MAL-2026-11152-11159
    "nemo-jaws": {"3.99.99", "99.99.9"},                         # MAL-2026-2785
    "syspo": {"1.0.0", "1.0.1"},                                 # MAL-2026-6406
    "fmt-date-lite": {"1.0.0"},                                   # MAL-2026-10115
    "rollup-packages-polyfill-core": {"0.13.7", "0.13.8", "0.14.1"},  # MAL-2026-10160
    "@ai_/autoprefixers": {"1.2.0"},                              # MAL-2026-11120
    "@apexfnd/apex": {"1.0.0", "1.0.1"},                         # MAL-2026-11121
    "@crbrc/xbt": {
        "1.1.0", "1.1.1", "1.1.2", "1.1.3", "1.1.4", "1.2.1",
    },                                                             # MAL-2026-11122
    "@yancyyu/agentcli": {                                       # MAL-2026-11123
        "1.9.25", "1.9.26", "1.9.27", "1.9.28", "1.9.29", "1.9.30",
        "1.9.32", "1.9.33", "1.9.35", "1.9.36", "1.9.40", "1.9.42",
        "1.9.43", "1.9.44", "1.9.48", "1.9.50", "1.9.52", "1.9.53",
        "1.9.58", "1.9.61", "1.9.66", "1.9.67", "1.9.71", "1.9.77",
        "1.9.78", "1.9.79", "1.9.80",
    },
    "basic-vite": {"1.0.0"},                                      # MAL-2026-11131
    "bianira-ui": {"1.27.0"},                                     # MAL-2026-11132
    "chain-analyze": {"1.0.2"},                                   # MAL-2026-11133
    "color-convert-helper": {"1.0.0"},                            # MAL-2026-11134
    "ethers-secure": {"1.0.0"},                                   # MAL-2026-11135
    "fluid-type-ui": {"2.0.8"},                                   # MAL-2026-11136
    "jobber-app-template-react": {"1.0.1"},                      # MAL-2026-11137
    "json-schema-inspector": {"1.1.4", "1.1.5", "1.1.6", "1.1.7"},  # MAL-2026-11138
    "kordyn": {"0.9.16", "0.9.18"},                              # MAL-2026-11139
    "korvica": {"1.0.0"},                                         # MAL-2026-11140
    "parallely": {"10.0.3"},                                      # MAL-2026-11143
    "react-puller": {"1.0.0"},                                    # MAL-2026-11144
    "rollup-runtime-core-polyfills": {"0.0.1"},                  # MAL-2026-11145
    "sigchain-js": {"1.0.1"},                                     # MAL-2026-11146
    "demo-awesome-date-parser-test": {
        "0.0.1", "0.0.2", "0.0.3", "0.0.4", "0.0.5", "0.0.6", "0.0.7",
    },                                                             # MAL-2026-11099
    "tidal-embed-player": {"1.0.1"},                             # MAL-2026-11152
    "triage_bot_using_sdkv3": {"2.0.1"},                         # MAL-2026-11153
    "blots": {"2.1.0"},                                           # MAL-2026-11158
    "toll_free": {"1.0.1"},                                       # MAL-2026-11159
    "@mypwn/hawkeye": {"99.0.0"},                                 # MAL-2026-11157
    # July 29 2026 npm malware wave (11 packages)
    # -----------------------------------------------------------------------
    # @joyfill account compromise — July 29 2026
    # Specific beta/RC versions of legitimate @joyfill UI packages published
    # with malicious payloads. Pin exact compromised versions only.
    # OSV MAL-2026-11160 (GHSA-x4p3-wjxx-m4x5) / MAL-2026-11161 (GHSA-887f-rwr9-wp54)
    "@joyfill/components": {"4.0.0-rc24-2773-beta.4"},            # MAL-2026-11160
    "@joyfill/layouts": {"0.1.2-2773.beta.0"},                    # MAL-2026-11161
    # aone-* typosquat cluster — July 29 2026
    # Pure-malware packages (SEMVER range >=0); any installed version is malicious.
    # OSV MAL-2026-11162 / MAL-2026-11163 / MAL-2026-11164
    "aone-kit": set(),                                             # MAL-2026-11162
    "aone-kit-cli": set(),                                         # MAL-2026-11163
    "aone-sandbox": set(),                                         # MAL-2026-11164
    # config/utility typosquat cluster — July 29 2026
    # Pure-malware packages impersonating config-fetcher / parser / lib utilities.
    # OSV MAL-2026-11165 / MAL-2026-11166 / MAL-2026-11167 / MAL-2026-11168 / MAL-2026-11169
    "cloud-config-fetcher": set(),                                 # MAL-2026-11165
    "lib-mtop": set(),                                             # MAL-2026-11166
    "local-config-parser": set(),                                  # MAL-2026-11167
    "postcss-motion-utils": set(),                                 # MAL-2026-11168
    "smart-config-manager": set(),                                 # MAL-2026-11169
    # @finxsecdemo/utils security-demo malware — July 29 2026
    # OSV MAL-2026-11170
    "@finxsecdemo/utils": {"1.0.2"},                              # MAL-2026-11170
    # July 30 2026 npm malware wave (35 packages)
    # -----------------------------------------------------------------------
    # Older OSV IDs freshly confirmed active (modified >= 2026-07-30):
    # chakll / date-fns-2 / neon-poly-utls pure-malware typosquats.
    # OSV MAL-2025-1210 / MAL-2025-6086 / MAL-2026-10089
    "chakll": set(),                                               # MAL-2025-1210
    "date-fns-2": set(),                                           # MAL-2025-6086
    "neon-poly-utls": set(),                                       # MAL-2026-10089
    # Polymarket-impersonating typosquat cluster (July 30 2026)
    # Pure-malware packages; OSV ranges show introduced:"0" on all.
    # OSV MAL-2026-3770 / MAL-2026-3771 / MAL-2026-6368 / MAL-2026-6437 /
    # MAL-2026-6438 / MAL-2026-6469 / MAL-2026-6490 / MAL-2026-6502
    "prisma-callback": set(),                                      # MAL-2026-3770
    "request-logger-canary": set(),                                # MAL-2026-3771
    "decimal-format-utils": set(),                                 # MAL-2026-6368
    "logfmt-core": set(),                                          # MAL-2026-6437
    "polymarket-stake-math": set(),                                # MAL-2026-6438
    "ts-precision": set(),                                         # MAL-2026-6469
    "data-parser-utils": set(),                                    # MAL-2026-6490
    "js-client-node": set(),                                       # MAL-2026-6502
    # @ai-agent-node typosquat cluster — July 30 2026
    # OSV MAL-2026-11171 / MAL-2026-11172 / MAL-2026-11173
    "@ai-agent-node/agent-node": set(),                            # MAL-2026-11171
    "@ai-agent-node/createnode": set(),                            # MAL-2026-11172
    "@ai-agent-node/nodesql": set(),                               # MAL-2026-11173
    # @ai-plus typosquat cluster — July 30 2026
    # OSV MAL-2026-11174 / MAL-2026-11175
    "@ai-plus/de-agent": set(),                                    # MAL-2026-11174
    "@ai-plus/de-agent-sdk": set(),                                # MAL-2026-11175
    # baileys WhatsApp-client typosquat cluster — July 30 2026
    # @bowozzz: wildcard (OSV range introduced:0); @zannstore: explicit versions only.
    # OSV MAL-2026-11176 / MAL-2026-11179
    "@bowozzz/baileys": set(),                                     # MAL-2026-11176
    "@zannstore/baileys": {                                        # MAL-2026-11179
        "2.4.4", "2.4.3", "2.4.2", "2.4.1", "2.4.0",
        "2.3.9", "2.3.7", "2.3.6", "2.3.5", "2.3.4",
        "2.3.3", "2.3.2", "2.3.1", "2.3.0",
        "2.2.8", "2.2.7", "2.2.6",
    },
    # @peptide-unit typosquat cluster — July 30 2026
    # OSV MAL-2026-11177 / MAL-2026-11178
    "@peptide-unit/js-unimode": set(),                             # MAL-2026-11177
    "@peptide-unit/peptide-modify": set(),                         # MAL-2026-11178
    # aone-cloud-cli — extension of aone-* cluster (July 30 2026)
    # OSV MAL-2026-11180
    "aone-cloud-cli": set(),                                       # MAL-2026-11180
    # Misc typosquat/malware cluster — July 30 2026
    # OSV MAL-2026-11181 through MAL-2026-11194
    "chain-manager": set(),                                        # MAL-2026-11181
    "colder-cli": set(),                                           # MAL-2026-11182
    "def-open-client": set(),                                      # MAL-2026-11183
    "feedback-ai-sdk": set(),                                      # MAL-2026-11184
    "flight-compare-analyzer": set(),                              # MAL-2026-11185
    "lwp-web-client": set(),                                       # MAL-2026-11186
    "lzd-unified-station-sdk": set(),                              # MAL-2026-11187
    "open-worker-cli": set(),                                      # MAL-2026-11188
    "uniapi-bridge": set(),                                        # MAL-2026-11190
    "zer0code": {"0.2.0"},                                         # MAL-2026-11191
    "litespeed-cache": set(),                                      # MAL-2026-11193
    "n8n-nodes-trust-me-im-totally-safe": set(),                   # MAL-2026-11194
    # @wbnr/design dep-confusion — July 30 2026
    # Version 99.3.0 published to internal package name; OSV MAL-2026-11196
    "@wbnr/design": {"99.3.0"},                                    # MAL-2026-11196
    # July 31 2026 npm malware wave (30 packages)
    # -----------------------------------------------------------------------
    # @dexwilt/node-fetch — node-fetch typosquat (July 31 2026)
    # OSV MAL-2026-11203
    "@dexwilt/node-fetch": {"2.7.3"},                              # MAL-2026-11203
    # nano-perf / redis-type-xyz typosquats — July 31 2026
    # OSV MAL-2026-11204 / MAL-2026-11205
    "nano-perf": {"2.2.0"},                                        # MAL-2026-11204
    "redis-type-xyz": {"1.10.6"},                                  # MAL-2026-11205
    # @dotconf-pro/* typosquat cluster — July 31 2026
    # OSV MAL-2026-11208 / MAL-2026-11209
    "@dotconf-pro/dotconf-pro": set(),                             # MAL-2026-11208
    "@dotconf-pro/dotenv": set(),                                  # MAL-2026-11209
    # @ethers-sdk/* crypto typosquat cluster — July 31 2026
    # OSV MAL-2026-11210 / MAL-2026-11211
    "@ethers-sdk/ethers": set(),                                   # MAL-2026-11210
    "@ethers-sdk/wallet": set(),                                   # MAL-2026-11211
    # @goodjavascript/dotenv — dotenv typosquat (July 31 2026)
    # OSV MAL-2026-11212
    "@goodjavascript/dotenv": set(),                               # MAL-2026-11212
    # @grua/* typosquat cluster — July 31 2026
    # OSV MAL-2026-11213 / MAL-2026-11214
    "@grua/core": set(),                                           # MAL-2026-11213
    "@grua/icons": set(),                                          # MAL-2026-11214
    # @meteora-sdk/core — Meteora DEX crypto typosquat (July 31 2026)
    # OSV MAL-2026-11215
    "@meteora-sdk/core": set(),                                    # MAL-2026-11215
    # @node-console-log/log — console-log typosquat (July 31 2026)
    # OSV MAL-2026-11216
    "@node-console-log/log": set(),                                # MAL-2026-11216
    # @nordea-web/* dep-confusion — July 31 2026
    # Impersonates legitimate @nordea-web packages from Nordea Bank.
    # OSV MAL-2026-11217 / MAL-2026-11218
    "@nordea-web/core": set(),                                     # MAL-2026-11217
    "@nordea-web/ui": set(),                                       # MAL-2026-11218
    # @patternfly-4/* dep-confusion cluster — July 31 2026
    # Impersonates Red Hat PatternFly design-system packages.
    # OSV MAL-2026-11219 / MAL-2026-11220 / MAL-2026-11221 / MAL-2026-11222
    "@patternfly-4/quickstarts": set(),                            # MAL-2026-11219
    "@patternfly-4/react-core": set(),                             # MAL-2026-11220
    "@patternfly-4/react-table": set(),                            # MAL-2026-11221
    "@patternfly-4/react-tokens": set(),                           # MAL-2026-11222
    # @pumpdot-fun/* crypto typosquat cluster — July 31 2026
    # OSV MAL-2026-11223 / MAL-2026-11224
    "@pumpdot-fun/pump-sdk": set(),                                # MAL-2026-11223
    "@pumpdot-fun/pump-swap-sdk": set(),                           # MAL-2026-11224
    # @relforce-dev/console-log — console-log typosquat (July 31 2026)
    # OSV MAL-2026-11225
    "@relforce-dev/console-log": set(),                            # MAL-2026-11225
    # @santieich/homebridge-midea-lan — homebridge plugin typosquat (July 31 2026)
    # OSV MAL-2026-11226
    "@santieich/homebridge-midea-lan": set(),                      # MAL-2026-11226
    # Solana crypto typosquat cluster — July 31 2026
    # OSV MAL-2026-11227 / MAL-2026-11228
    "@solana-sdk/web3.js": set(),                                  # MAL-2026-11227
    "@solana-utils/common": set(),                                  # MAL-2026-11228
    # @sourav_chanduka/* typosquat cluster — July 31 2026
    # OSV MAL-2026-11229 / MAL-2026-11230 / MAL-2026-11231
    "@sourav_chanduka/core": set(),                                # MAL-2026-11229
    "@sourav_chanduka/core-no-ngrok": set(),                       # MAL-2026-11230
    "@sourav_chanduka/oidc-client": set(),                         # MAL-2026-11231
    # @spectraltest/loglevel — loglevel typosquat (July 31 2026)
    # OSV MAL-2026-11232
    "@spectraltest/loglevel": set(),                               # MAL-2026-11232
    # @web3-util/common / @web3utils/common crypto typosquats — July 31 2026
    # OSV MAL-2026-11233 / MAL-2026-11234
    "@web3-util/common": set(),                                    # MAL-2026-11233
    "@web3utils/common": set(),                                    # MAL-2026-11234
    # create-backend-scaffold supply-chain compromise — July 31 2026
    # All published versions contain malicious payload; OSV MAL-2026-11270
    "create-backend-scaffold": {                                   # MAL-2026-11270
        "1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4",
        "1.0.5", "1.1.0", "1.1.1", "1.1.2",
    },
    # August 1 2026 npm malware wave (180 packages — typosquats, crypto stealers, misc malware)
    # -----------------------------------------------------------------------
    # ethers/web3 crypto typosquat cluster — August 1 2026
    # OSV MAL-2026-11293 / MAL-2026-11294 / MAL-2026-11295 / MAL-2026-11296
    # OSV MAL-2026-11297 / MAL-2026-11298 / MAL-2026-11299 / MAL-2026-11300 / MAL-2026-11301
    "eth.json": set(),                                            # MAL-2026-11293
    "ethe": set(),                                                # MAL-2026-11294
    "ethe.json": set(),                                           # MAL-2026-11295
    "ethers-io-ethers": set(),                                    # MAL-2026-11296
    "ethers-v6": set(),                                           # MAL-2026-11297
    "ethers.json": set(),                                         # MAL-2026-11298
    "ethers.jsonn": set(),                                        # MAL-2026-11299
    "ethersss": set(),                                            # MAL-2026-11300
    "etwl": set(),                                                # MAL-2026-11301
    # crypto-encoding library typosquats — August 1 2026
    # OSV MAL-2026-11246 / MAL-2026-11247 / MAL-2026-11249 / MAL-2026-11250
    # OSV MAL-2026-11371 / MAL-2026-11372
    "base-x-ts": set(),                                           # MAL-2026-11246
    "base58-ts": set(),                                           # MAL-2026-11247
    "bn.js-4": set(),                                             # MAL-2026-11249
    "bn.js-5": set(),                                             # MAL-2026-11250
    "rlp-master": set(),                                          # MAL-2026-11371
    "rlp.git": set(),                                             # MAL-2026-11372
    # Uniswap / Raydium DEX typosquats — August 1 2026
    # OSV MAL-2026-11363 / MAL-2026-11407
    "raydiums": set(),                                            # MAL-2026-11363
    "uniswapintefrace": set(),                                    # MAL-2026-11407
    # express.js typosquat cluster — August 1 2026
    # OSV MAL-2026-11288 / MAL-2026-11302 / MAL-2026-11303 / MAL-2026-11304
    # OSV MAL-2026-11305 / MAL-2026-11306 / MAL-2026-11307 / MAL-2026-11308
    "ekspress": set(),                                            # MAL-2026-11288
    "expres.js": set(),                                           # MAL-2026-11302
    "express-bubble": set(),                                      # MAL-2026-11303
    "express-sequelize-wrapper": set(),                           # MAL-2026-11304
    "express-test-dependency": set(),                             # MAL-2026-11305
    "express-wrapper": set(),                                     # MAL-2026-11306
    "express.ja": set(),                                          # MAL-2026-11307
    "express.jd": set(),                                          # MAL-2026-11308
    # react.js typosquat cluster — August 1 2026
    # OSV MAL-2026-11322 / MAL-2026-11364 / MAL-2026-11365 / MAL-2026-11366
    # OSV MAL-2026-11367 / MAL-2026-11368 / MAL-2026-11369 / MAL-2026-11370
    "installreact": set(),                                        # MAL-2026-11322
    "reac.js": set(),                                             # MAL-2026-11364
    "react-ag-grid": set(),                                       # MAL-2026-11365
    "react-fast-refresh-helper": set(),                           # MAL-2026-11366
    "react.j": set(),                                             # MAL-2026-11367
    "react.ja": set(),                                            # MAL-2026-11368
    "react.jd": set(),                                            # MAL-2026-11369
    "reakt.js": set(),                                            # MAL-2026-11370
    # socket.io typosquat cluster — August 1 2026
    # OSV MAL-2026-11376 / MAL-2026-11381 / MAL-2026-11382 / MAL-2026-11383
    "scketio": set(),                                             # MAL-2026-11376
    "soccketio": set(),                                           # MAL-2026-11381
    "socketi": set(),                                             # MAL-2026-11382
    "socktio": set(),                                             # MAL-2026-11383
    # chalk typosquat cluster — August 1 2026
    # OSV MAL-2026-11255 / MAL-2026-11256 / MAL-2026-11257 / MAL-2026-11258
    "chalk-butons": set(),                                        # MAL-2026-11255
    "chalk-button": set(),                                        # MAL-2026-11256
    "chalk-buttons": set(),                                       # MAL-2026-11257
    "chalk-helper": set(),                                        # MAL-2026-11258
    # fs-extra / node-fs typosquat cluster — August 1 2026
    # OSV MAL-2026-11312 / MAL-2026-11313 / MAL-2026-11339 / MAL-2026-11340
    "fs-extra-master": set(),                                     # MAL-2026-11312
    "fsextrra": set(),                                            # MAL-2026-11313
    "node-fetch-core": set(),                                     # MAL-2026-11339
    "node-fs-extra-master": set(),                                # MAL-2026-11340
    # discord fake package cluster — August 1 2026
    # OSV MAL-2026-11277 / MAL-2026-11278 / MAL-2026-11279 / MAL-2026-11280
    "discord-csr": set(),                                         # MAL-2026-11277
    "discord-ms": set(),                                          # MAL-2026-11278
    "discord-rsc": set(),                                         # MAL-2026-11279
    "discord-starter": set(),                                     # MAL-2026-11280
    # lodash / winston / logform typosquats — August 1 2026
    # OSV MAL-2026-11327 / MAL-2026-11328 / MAL-2026-11341
    "lodash-ex": set(),                                           # MAL-2026-11327
    "logform-core": set(),                                        # MAL-2026-11328
    "node-logger-winston": set(),                                 # MAL-2026-11341
    # ncc typosquat cluster — August 1 2026
    # OSV MAL-2026-11336 / MAL-2026-11337 / MAL-2026-11338
    "ncc-fonts": set(),                                           # MAL-2026-11336
    "ncc-hyperapp": set(),                                        # MAL-2026-11337
    "ncc-web": set(),                                             # MAL-2026-11338
    # clo-adspect click-fraud / redirect cluster — August 1 2026
    # OSV MAL-2026-11206 / MAL-2026-11239 / MAL-2026-11259 / MAL-2026-11260
    # OSV MAL-2026-11261 / MAL-2026-11262 / MAL-2026-11263
    "1apijs": set(),                                              # MAL-2026-11206
    "apijsclo": set(),                                            # MAL-2026-11239
    "clo-adspect": set(),                                         # MAL-2026-11259
    "clo2": set(),                                                # MAL-2026-11260
    "clo321": set(),                                              # MAL-2026-11261
    "clo321-server": set(),                                       # MAL-2026-11262
    "clotest": set(),                                             # MAL-2026-11263
    # tailwind typosquat cluster — August 1 2026
    # OSV MAL-2026-11393 / MAL-2026-11394
    "tailwindcssss": set(),                                       # MAL-2026-11393
    "tailwindcsssss": set(),                                      # MAL-2026-11394
    # pullingpackage* exfiltrator cluster — August 1 2026
    # OSV MAL-2026-11350 – MAL-2026-11360
    "pulleeelll": set(),                                          # MAL-2026-11350
    "pullingpackage": set(),                                      # MAL-2026-11351
    "pullingpackaged": set(),                                     # MAL-2026-11352
    "pullingpackagee": set(),                                     # MAL-2026-11353
    "pullingpackageee": set(),                                    # MAL-2026-11354
    "pullingpackageeee": set(),                                   # MAL-2026-11355
    "pullingpackageeeeeee": set(),                                # MAL-2026-11356
    "pullingpackageeeeeeee": set(),                               # MAL-2026-11357
    "pullingpackageeeeeeeee": set(),                              # MAL-2026-11358
    "pullingpackageeeeeeeeee": set(),                             # MAL-2026-11359
    "pullingpackageeeeeeeeeee": set(),                            # MAL-2026-11360
    # streak-metrics / svelte-streak malware cluster — August 1 2026
    # OSV MAL-2026-11387 / MAL-2026-11388 / MAL-2026-11390 / MAL-2026-11391
    "streak-metrics-core": set(),                                 # MAL-2026-11387
    "streak-metrics-math": set(),                                 # MAL-2026-11388
    "svelte-metric-map": set(),                                   # MAL-2026-11390
    "svelte-streak-metric": set(),                                # MAL-2026-11391
    # spectral typosquat cluster — August 1 2026
    # OSV MAL-2026-11384 / MAL-2026-11385
    "spectral-corsair": set(),                                    # MAL-2026-11384
    "spectral-wraith": set(),                                     # MAL-2026-11385
    # axios typosquat cluster (maalxios / malxios) — August 1 2026
    # OSV MAL-2026-11329 / MAL-2026-11330
    "maalxios": set(),                                            # MAL-2026-11329
    "malxios": set(),                                             # MAL-2026-11330
    # mongoose typosquat cluster — August 1 2026
    # OSV MAL-2026-11333 / MAL-2026-11334
    "mongostose": set(),                                          # MAL-2026-11333
    "moontose": set(),                                            # MAL-2026-11334
    # bluebird typosquat — August 1 2026
    # OSV MAL-2026-11248
    "blbird": set(),                                              # MAL-2026-11248
    # ag-grid typosquat — August 1 2026
    # OSV MAL-2026-11235
    "ag-grid-boost": set(),                                       # MAL-2026-11235
    # passport typosquats — August 1 2026
    # OSV MAL-2026-11344 / MAL-2026-11345
    "passsport1": set(),                                          # MAL-2026-11344
    "passtpor": set(),                                            # MAL-2026-11345
    # puppeteer typosquat — August 1 2026
    # OSV MAL-2026-11361
    "puppetewebr": set(),                                         # MAL-2026-11361
    # dotenv typosquats — August 1 2026
    # OSV MAL-2026-11281 / MAL-2026-11282
    "dotenv-core": set(),                                         # MAL-2026-11281
    "dotex-plugin": set(),                                        # MAL-2026-11282
    # @404c3s4r test-malware package — August 1 2026
    # OSV MAL-2026-11207
    "@404c3s4r/testxxx": set(),                                   # MAL-2026-11207
    # @sie-ppr-web-checkout dep-confusion — OSV MAL-2026-2865
    "@sie-ppr-web-checkout/app": set(),                           # MAL-2026-2865
    # Miscellaneous malware — August 1 2026
    # OSV MAL-2026-11236 through MAL-2026-11412 (various)
    "android-web-logger": set(),                                  # MAL-2026-11236
    "api-gateway-lambda-router": set(),                           # MAL-2026-11237
    "apihost": set(),                                             # MAL-2026-11238
    "aruda": set(),                                               # MAL-2026-11240
    "asdsafsadad": set(),                                         # MAL-2026-11241
    "asdsafsafdasdsaasdasda": set(),                              # MAL-2026-11242
    "aven_shared": set(),                                         # MAL-2026-11243
    "bajkvahzv8allnltvr7x4s5hdxkjvyji": set(),                   # MAL-2026-11244
    "baofdadbybmqeefeeginweoamxlphrjq": set(),                   # MAL-2026-11245
    "broccoli-watcher-siphon": set(),                             # MAL-2026-11251
    "build-time-metrics": set(),                                  # MAL-2026-11252
    "cancelling": set(),                                          # MAL-2026-11253
    "canvas-to": set(),                                           # MAL-2026-11254
    "cmd-auth": set(),                                            # MAL-2026-11264
    "cocktail-lib": set(),                                        # MAL-2026-11265
    "columns_changed": set(),                                     # MAL-2026-11266
    "compose-logger-stand": set(),                                # MAL-2026-11267
    "confetti-rebuilds": set(),                                   # MAL-2026-11268
    "consumerweb-risk": set(),                                    # MAL-2026-11269
    "cross-sell": set(),                                          # MAL-2026-11271
    "curse-dependent": set(),                                     # MAL-2026-11272
    "d3-bbox": set(),                                             # MAL-2026-11273
    "dash-merge": set(),                                          # MAL-2026-11274
    "datdbs": set(),                                              # MAL-2026-11275
    "decline": set(),                                             # MAL-2026-11276
    "dsilva-react-module-seed": set(),                            # MAL-2026-11283
    "dwa-tridion-webapp": set(),                                  # MAL-2026-11284
    "easycommons": set(),                                         # MAL-2026-11285
    "easyinstaller": set(),                                       # MAL-2026-11286
    "ecto-logger": set(),                                         # MAL-2026-11287
    "ember-cli-deploy-derploy": set(),                            # MAL-2026-11289
    "ember-cli-deploy-secrets": set(),                            # MAL-2026-11290
    "ember-livereload-indicator": set(),                          # MAL-2026-11291
    "equiviewer": set(),                                          # MAL-2026-11292
    "famshot": set(),                                             # MAL-2026-11309
    "fcogvspgigatanzcydfyvgtjhvxibyau": set(),                   # MAL-2026-11310
    "files-bucket-server": set(),                                 # MAL-2026-11311
    "fwf": set(),                                                 # MAL-2026-11314
    "gatorhelper": set(),                                         # MAL-2026-11315
    "hjw-nasa-lib": set(),                                        # MAL-2026-11316
    "host-inspector-module": set(),                               # MAL-2026-11317
    "ideascloud": set(),                                          # MAL-2026-11318
    "impv": set(),                                                # MAL-2026-11319
    "imut-set": set(),                                            # MAL-2026-11320
    "inkalabs": set(),                                            # MAL-2026-11321
    "isix": set(),                                                # MAL-2026-11323
    "js-focus-within": set(),                                     # MAL-2026-11324
    "kajl": set(),                                                # MAL-2026-11325
    "live-reload-on-error": set(),                                # MAL-2026-11326
    "merg-descripters": set(),                                    # MAL-2026-11331
    "model-data-cache-service": set(),                            # MAL-2026-11332
    "n158": set(),                                                # MAL-2026-11335
    "npum": set(),                                                # MAL-2026-11342
    "page_colors": set(),                                         # MAL-2026-11343
    "payu-node": set(),                                           # MAL-2026-11346
    "pjm-dls": set(),                                             # MAL-2026-11347
    "pretierr": set(),                                            # MAL-2026-11348
    "pretty-log-cli": set(),                                      # MAL-2026-11349
    "qserver": set(),                                             # MAL-2026-11362
    "rph-validator": set(),                                       # MAL-2026-11373
    "rshell": set(),                                              # MAL-2026-11374
    "rumjs": set(),                                               # MAL-2026-11375
    "scol": set(),                                                # MAL-2026-11377
    "shnc": set(),                                                # MAL-2026-11378
    "shsk": set(),                                                # MAL-2026-11379
    "slowest-build-nodes": set(),                                 # MAL-2026-11380
    "srgb-linear": set(),                                         # MAL-2026-11386
    "sunpro-3dmodel-renderer": set(),                             # MAL-2026-11389
    "switchpaymentsapiserv-paypal": set(),                        # MAL-2026-11392
    "termly-namespace": set(),                                    # MAL-2026-11395
    "test-wastu": set(),                                          # MAL-2026-11396
    "testsetset": set(),                                          # MAL-2026-11397
    "testtwix": set(),                                            # MAL-2026-11398
    "tgnode": set(),                                              # MAL-2026-11399
    "thedata": set(),                                             # MAL-2026-11400
    "thoughtgear": set(),                                         # MAL-2026-11401
    "time-to-reload": set(),                                      # MAL-2026-11402
    "tsetnpmackage": set(),                                       # MAL-2026-11403
    "ttest333": set(),                                            # MAL-2026-11404
    "ttest3333": set(),                                           # MAL-2026-11405
    "unified-help-center-alpha": set(),                           # MAL-2026-11406
    "vcse": set(),                                                # MAL-2026-11408
    "wastu": set(),                                               # MAL-2026-11409
    "wistia_namespace": set(),                                    # MAL-2026-11410
    "xp-node-logger": set(),                                      # MAL-2026-11411
    "zcas": set(),                                                # MAL-2026-11412
    # pp-react-worldready — PayPal/worldready typosquat — August 1 2026
    # OSV MAL-2026-11427; communicates with malicious domain
    "pp-react-worldready": {"1.0.0"},                            # MAL-2026-11427
    # August 2–3 2026 dep-confusion cluster — 22 scoped packages targeting
    # corporate npm registries; all have `introduced: 0` / no fixed version
    # (entire package is malicious); OSV MAL-2026-11431 through MAL-2026-11452
    "@0xlr/dep-confusion-poc": set(),                            # MAL-2026-11431
    "@0xlr/question-types": set(),                               # MAL-2026-11432
    "@0xlr/test-callback": set(),                                # MAL-2026-11433
    "@cr-invested-ui-components/chart": set(),                   # MAL-2026-11435
    "@finance-ui/finance-view": set(),                           # MAL-2026-11436
    "@finance-ui/snackbar-ifpe": set(),                          # MAL-2026-11437
    "@fuji-web-components/maps": set(),                          # MAL-2026-11438
    "@global-theme/context": set(),                              # MAL-2026-11439
    "@meli-testing/jest-react": set(),                           # MAL-2026-11440
    "@moxfive-llc/common": set(),                                # MAL-2026-11441
    "@mp-op-ss-front-lib/tracks": set(),                         # MAL-2026-11442
    "@mplay-core-lib/utilities": set(),                          # MAL-2026-11443
    "@mplay-frontend-ui/link": set(),                            # MAL-2026-11444
    "@nordic-dev/linting-tools": set(),                          # MAL-2026-11445
    "@one-chat/react": set(),                                    # MAL-2026-11446
    "@peptide-packets/js-unimode": set(),                        # MAL-2026-11447
    "@peptide-packets/peptide-modify": set(),                    # MAL-2026-11448
    "@sof-assistant-fe-lib/vertical-faqs": set(),                # MAL-2026-11449
    "@spending-behavior-ui/cashflow-widget": set(),              # MAL-2026-11450
    "@spending-behavior-ui/widget-insights": set(),              # MAL-2026-11451
    "@sw-commons-components/message-upsell": set(),              # MAL-2026-11452
    # August 2 2026 misc pure-malware typosquats — `introduced: 0` wildcard
    # OSV MAL-2026-11430, 11461, 11473, 11478–11479, 11483–11485, 11487–11497
    "list-issue-predecessor-dependencies-block": {"99.0.0"},     # MAL-2026-11430
    "eth-bridge": set(),                                         # MAL-2026-11461
    "metrics-ui": set(),                                         # MAL-2026-11473
    "rollup-plugin-polyfill-helper": set(),                      # MAL-2026-11478
    "rollup-plugin-polyfill-hold": set(),                        # MAL-2026-11479
    "simple-date-formatter-util": set(),                         # MAL-2026-11483
    "simple-date-formatter-util-1": {"1.0.0"},                  # MAL-2026-11484
    "simple-date-formatter-util-2": set(),                       # MAL-2026-11485
    "tailwindcss-anim": set(),                                   # MAL-2026-11487
    "test-dev-boot": set(),                                      # MAL-2026-11488
    "test-dev-dispatch": set(),                                  # MAL-2026-11489
    "test-dev-exec": set(),                                      # MAL-2026-11490
    "test-dev-host": set(),                                      # MAL-2026-11491
    "test-dev-link": set(),                                      # MAL-2026-11492
    "test-dev-store": set(),                                      # MAL-2026-11493
    "test-dev-sync": set(),                                      # MAL-2026-11494
    "test-dev-watch": set(),                                     # MAL-2026-11495
    "vite-config-svg": set(),                                    # MAL-2026-11496
    "vite-tsconfig-svg": set(),                                  # MAL-2026-11497
    # August 2 2026 MCP-toolkit typosquat cluster — 13 fake MCP server packages
    # OSV MAL-2026-11458, 11464, 11466, 11469–11472, 11475, 11477, 11480–11482, 11486
    "chaos-mcp": {"1.0.0"},                                      # MAL-2026-11458
    "gtm-mcp-auth": {"1.0.0"},                                   # MAL-2026-11464
    "hit-mcp": {"1.0.0"},                                        # MAL-2026-11466
    "iwomm-mcp": {"1.0.0"},                                      # MAL-2026-11469
    "kip-mcp-http": {"1.0.0"},                                   # MAL-2026-11470
    "maximumsats-mcp": {"1.0.0"},                                # MAL-2026-11471
    "mcp-server-boilerplate": {"1.0.0"},                         # MAL-2026-11472
    "pm-claude-skills-mcp": {"1.0.0"},                           # MAL-2026-11475
    "refbase-mcp": {"1.0.0"},                                    # MAL-2026-11477
    "routerbase-mcp": {"1.0.0"},                                 # MAL-2026-11480
    "sap-mcp-config": {"1.0.0"},                                 # MAL-2026-11481
    "sap-mcp-facilitator": {"1.0.0"},                            # MAL-2026-11482
    "smart-npv-mcp": {"1.0.0"},                                  # MAL-2026-11486
    # August 2 2026 miscellaneous malware batch — specific pinned versions
    # OSV MAL-2026-11434, 11453–11457, 11459–11460, 11462–11463, 11465, 11467–11468,
    #      11474, 11476, 11498
    "@404c3s4r/lodash": {"9.0.0"},                               # MAL-2026-11434
    "@custombots/custombot": {"1.0.0"},                          # MAL-2026-11498
    "adpanel-core": {"1.0.0"},                                   # MAL-2026-11453
    "ai-backup-script": {"0.0.2", "1.0.0", "1.0.2"},            # MAL-2026-11454
    "allurectl": {"1.0.0"},                                      # MAL-2026-11455
    "attio-discover": {"1.0.0"},                                 # MAL-2026-11456
    "capacitor-assets": {"1.0.0"},                               # MAL-2026-11457
    "community-published": {"1.0.0"},                            # MAL-2026-11459
    "create-remotion": {"0.0.2", "0.0.3"},                       # MAL-2026-11460
    "fast-csv-helper": {"1.0.0"},                                # MAL-2026-11462
    "goldenflow-js": {"1.0.0"},                                  # MAL-2026-11463
    "hazmat-cfr": {"1.0.0"},                                     # MAL-2026-11465
    "iac-scanner": {"0.0.2", "1.0.0"},                           # MAL-2026-11467
    "install-native-host": {"1.0.0"},                            # MAL-2026-11468
    "paraglide-js": {"1.0.1"},                                   # MAL-2026-11474
    "polyprompt": {"1.0.0"},                                     # MAL-2026-11476
    # Older packages confirmed / updated August 2 2026
    # Amazon Inspector source; install-time infostealers; whole package malicious
    # OSV MAL-2026-5729 (houzidawang806), MAL-2026-5731 (houzidawang807),
    #     MAL-2026-5732 (houzidawang808), MAL-2026-6482 (kelly-stake)
    "houzidawang806": set(),                                     # MAL-2026-5729
    "houzidawang807": set(),                                     # MAL-2026-5731
    "houzidawang808": set(),                                     # MAL-2026-5732
    "kelly-stake": set(),                                        # MAL-2026-6482
    # html-to-gutenberg — compromised versions confirmed August 2 2026
    # OSV MAL-2026-6359; specific malicious versions only
    "html-to-gutenberg": {"4.2.11", "4.2.14"},                   # MAL-2026-6359
    # August 3 2026 simple-date-formatter typosquat cluster (continued)
    # Additional variants beyond MAL-2026-11483/11484/11485 added August 2
    # OSV MAL-2026-11501 (simple-date-formatter-util-5), MAL-2026-11502 (simple-date-formatter-new-1)
    "simple-date-formatter-util-5": {"1.0.0"},                   # MAL-2026-11501
    "simple-date-formatter-new-1": {"1.0.0"},                    # MAL-2026-11502
    # August 3 2026 miscellaneous npm malware
    # @types-beta/sdk (MAL-2026-11499): four versions exfiltrate data on install
    # tailwind-anim (MAL-2026-11500): tailwind-anim typosquat, any version malicious
    "@types-beta/sdk": {"0.1.0", "0.1.1", "0.1.2", "0.1.3"},   # MAL-2026-11499
    "tailwind-anim": set(),                                       # MAL-2026-11500
    # August 3–4 2026 pure-malware npm batch — accounts/beaver-ui/misc cluster
    # accounts-* are form/state management impersonators; beaver-ui-* impersonate
    # a UI component library; internallib_v524/v568 are dep-confusion packages;
    # bigops-chat-messages and lifestyle-test-utils are standalone throwaway malware.
    # All have SEMVER ranges `introduced: 0` (any version is malicious).
    # OSV MAL-2026-11504 through MAL-2026-11514
    "accounts-final-form": set(),                                 # MAL-2026-11504
    "accounts-loading-state": set(),                              # MAL-2026-11505
    "beaver-ui-date-range-picker": set(),                         # MAL-2026-11506
    "beaver-ui-grid": set(),                                      # MAL-2026-11507
    "beaver-ui-header": set(),                                    # MAL-2026-11508
    "beaver-ui-items-with-more": set(),                           # MAL-2026-11509
    "beaver-ui-layout": set(),                                    # MAL-2026-11510
    "bigops-chat-messages": set(),                                # MAL-2026-11511
    "internallib_v524": set(),                                    # MAL-2026-11512
    "internallib_v568": set(),                                    # MAL-2026-11513
    "lifestyle-test-utils": set(),                                # MAL-2026-11514

    # keyv/cache-manager npm account compromise Aug 4–5 2026 — attacker gained access
    # to the keyv and cacheable maintainer accounts and injected credential-exfiltration
    # payloads into new releases of popular cache-manager / keyv / @keyv/* / @cacheable/*
    # packages (cache-manager 15M+ weekly downloads, keyv 10M+). The same campaign also
    # compromised maintainer accounts across many companies, publishing malicious versions
    # of @servicetitan/*, @onereach/*, @or-sdk/*, @ornikar/*, @qlik/*, @nebula.js/*,
    # and many other private/semi-private scopes. OSV MAL-2026-11523 through MAL-2026-12079;
    # sources: socket.dev/blog/popular-npm-packages-in-the-keyv-and-cacheable-namespaces-
    # compromised-in-active-supply-chain; aikido.dev/blog/keyv-and-friends-compromised-in-
    # npm-supply-chain-attack; safedep.io/keyv-npm-supply-chain-compromise/
    # Core keyv / cacheable ecosystem — compromised at specific versions (pin exact versions)
    "cache-manager": {"7.2.10"},  # MAL-2026-11523
    "keyv": {"6.0.0"},  # MAL-2026-11524
    "cacheable": {"2.5.1"},  # MAL-2026-11963
    "cacheable-request": {"13.0.20"},  # MAL-2026-11964
    "file-entry-cache": {"11.1.6"},  # MAL-2026-11970
    "flat-cache": {"6.1.24"},  # MAL-2026-11971
    # @cacheable/* scope — full namespace compromised alongside cache-manager
    "@cacheable/memory": {"2.2.1"},  # MAL-2026-11558
    "@cacheable/net": {"2.1.1"},  # MAL-2026-11559
    "@cacheable/node-cache": {"3.1.2"},  # MAL-2026-11560
    "@cacheable/utils": {"2.5.1"},  # MAL-2026-11561
    # @keyv/* scope — full v6.0.0 release of entire namespace is malicious
    "@keyv/bigmap": {"6.0.0"},  # MAL-2026-12007
    "@keyv/cloudflare-kv": {"6.0.0"},  # MAL-2026-12008
    "@keyv/compress-brotli": {"6.0.0"},  # MAL-2026-12009
    "@keyv/compress-gzip": {"6.0.0"},  # MAL-2026-12010
    "@keyv/compress-lz4": {"6.0.0"},  # MAL-2026-12011
    "@keyv/dynamo": {"6.0.0"},  # MAL-2026-12012
    "@keyv/encrypt-node": {"6.0.0"},  # MAL-2026-12013
    "@keyv/encrypt-web": {"6.0.0"},  # MAL-2026-12014
    "@keyv/etcd": {"6.0.0"},  # MAL-2026-12015
    "@keyv/memcache": {"6.0.0"},  # MAL-2026-12016
    "@keyv/mongo": {"6.0.0"},  # MAL-2026-12017
    "@keyv/mysql": {"6.0.0"},  # MAL-2026-12018
    "@keyv/postgres": {"6.0.0"},  # MAL-2026-12019
    "@keyv/redis": {"6.0.0"},  # MAL-2026-12020
    "@keyv/serialize-msgpackr": {"6.0.0"},  # MAL-2026-12021
    "@keyv/serialize-superjson": {"6.0.0"},  # MAL-2026-12022
    "@keyv/sqlite": {"6.0.0"},  # MAL-2026-12023
    "@keyv/test-suite": {"6.0.0"},  # MAL-2026-12024
    "@keyv/valkey": {"6.0.0"},  # MAL-2026-12025
    # Other packages compromised in the keyv/cacheable campaign (non-scoped)
    "babel-plugin-linaria-css-to-undefined": {"0.3.1", "0.3.10", "0.3.11", "0.3.12", "0.3.13", "0.3.14", "0.3.15", "0.3.16", "0.3.17", "0.3.2", "0.3.3", "0.3.4", "0.3.5", "0.3.6", "0.3.7", "0.3.8", "0.3.9"},  # MAL-2026-11962
    "conv-context-next": {"1.0.1", "1.0.10", "1.0.2", "1.0.3", "1.0.4", "1.0.5", "1.0.6", "1.0.7", "1.0.8", "1.0.9"},  # MAL-2026-11965
    "ecto": {"5.0.1"},  # MAL-2026-11966
    "editable-contracts": {"0.0.12", "0.0.13", "0.0.14", "0.0.15", "0.0.16", "0.0.17", "0.0.18", "0.0.19", "0.0.20", "0.0.21", "0.0.22", "0.0.23", "0.0.24", "0.0.25", "0.0.26", "0.0.27"},  # MAL-2026-11967
    "eslint-plugin-folder-schema": {"1.0.10", "1.0.11", "1.0.12", "1.0.13", "1.0.14", "1.0.15", "1.0.16", "1.0.17", "1.0.18", "1.0.19", "1.0.20", "1.0.21", "1.0.6", "1.0.7", "1.0.8", "1.0.9"},  # MAL-2026-11968
    "example-js-project": {"1.0.10", "1.0.11", "1.0.2", "1.0.3", "1.0.4", "1.0.5", "1.0.6", "1.0.7", "1.0.8", "1.0.9"},  # MAL-2026-11969
    "folder-lint": {"1.0.10", "1.0.11", "1.0.12", "1.0.13", "1.0.14", "1.0.15", "1.0.16", "1.0.17", "1.0.18", "1.0.19", "1.0.20", "1.0.21", "1.0.6", "1.0.7", "1.0.8", "1.0.9"},  # MAL-2026-11972
    "frontend-orb": {"4.4.1", "4.4.10", "4.4.11", "4.4.12", "4.4.13", "4.4.14", "4.4.15", "4.4.16", "4.4.17", "4.4.18", "4.4.2", "4.4.3", "4.4.4", "4.4.5", "4.4.6", "4.4.7", "4.4.8", "4.4.9"},  # MAL-2026-11973
    "hamus.js": {"0.4.1"},  # MAL-2026-11974
    "http-metrics-middleware": {"2.2.2"},  # MAL-2026-11975
    "native-frontend-orb": {"1.1.10", "1.1.11", "1.1.12", "1.1.13", "1.1.14", "1.1.15", "1.1.16", "1.1.17", "1.1.18", "1.1.19", "1.1.4", "1.1.5", "1.1.6", "1.1.7", "1.1.8", "1.1.9"},  # MAL-2026-11976
    "picasso-plugin-hammer": {"2.11.6"},  # MAL-2026-11977
    "picasso-plugin-q": {"2.11.6"},  # MAL-2026-11978
    "picasso.js": {"2.11.6"},  # MAL-2026-11979
    "pob-test-package-in-monorepo": {"5.2.1", "5.2.10", "5.2.11", "5.2.12", "5.2.13", "5.2.14", "5.2.15", "5.2.16", "5.2.2", "5.2.3", "5.2.4", "5.2.5", "5.2.6", "5.2.7", "5.2.8", "5.2.9"},  # MAL-2026-11980
    "pob-test-typescript-package-in-monorepo": {"4.2.1", "4.2.10", "4.2.11", "4.2.12", "4.2.13", "4.2.14", "4.2.15", "4.2.16", "4.2.17", "4.2.2", "4.2.3", "4.2.4", "4.2.5", "4.2.6", "4.2.7", "4.2.8", "4.2.9"},  # MAL-2026-11981
    "qlik-chart-modules": {"1.1.1"},  # MAL-2026-11982
    "qlik-modifiers": {"0.10.1"},  # MAL-2026-11983
    "qlik-object-conversion": {"0.17.2"},  # MAL-2026-11984
    "rwc-client": {"0.29.10", "0.29.11", "0.29.12", "0.29.13", "0.29.14", "0.29.15", "0.29.16", "0.29.17", "0.29.18", "0.29.19"},  # MAL-2026-11985
    "server-hemera-mongo": {"0.0.12"},  # MAL-2026-11986
    "sn-listbox": {"0.3.3"},  # MAL-2026-11987
    "tslint-folder-schema": {"1.0.10", "1.0.11", "1.0.12", "1.0.13", "1.0.14", "1.0.15", "1.0.16", "1.0.17", "1.0.18", "1.0.19", "1.0.20", "1.0.21", "1.0.6", "1.0.7", "1.0.8", "1.0.9"},  # MAL-2026-11988
    "umadev": {"1.0.74"},  # MAL-2026-11989
    "verdaccio-okta-oauth": {"38.1.1", "38.1.10", "38.1.11", "38.1.12", "38.1.13", "38.1.14", "38.1.15", "38.1.16", "38.1.2", "38.1.3", "38.1.4", "38.1.5", "38.1.6", "38.1.7", "38.1.8", "38.1.9"},  # MAL-2026-11990
    "verdaccio-tarball-local-storage": {"38.1.1", "38.1.10", "38.1.11", "38.1.12", "38.1.13", "38.1.14", "38.1.15", "38.1.16", "38.1.2", "38.1.3", "38.1.4", "38.1.5", "38.1.6", "38.1.7", "38.1.8", "38.1.9"},  # MAL-2026-11991
    "workbench-browser-server": {"0.0.2"},  # MAL-2026-11992
    # @adminide-stack/* — compromised in the keyv/cacheable campaign
    "@adminide-stack/clock-tik-browser": {"12.0.24"},  # MAL-2026-11551
    "@adminide-stack/yantra-mobile": {"12.0.33"},  # MAL-2026-11552
    # @arv-bedrock/* — compromised in the keyv/cacheable campaign
    "@arv-bedrock/auth": {"1.1.7", "1.1.8"},  # MAL-2026-11553
    "@arv-bedrock/auth-admin": {"1.0.2", "1.0.3"},  # MAL-2026-11554
    "@arv-bedrock/auth-sso": {"1.6.1", "1.6.2"},  # MAL-2026-11555
    "@arv-bedrock/auth-sso-backend": {"1.7.1", "1.7.2"},  # MAL-2026-11556
    "@arv-bedrock/logger": {"1.7.1", "1.7.2"},  # MAL-2026-11557
    # @deliveroo/* — compromised in the keyv/cacheable campaign
    "@deliveroo/determinator": {"0.2.1"},  # MAL-2026-11562
    "@deliveroo/reevent": {"1.0.1"},  # MAL-2026-11563
    # @hubsync/* — compromised in the keyv/cacheable campaign
    "@hubsync/web-sdk-react": {"6.3.10", "6.3.11", "6.3.12", "6.3.13", "6.3.14", "6.3.15", "6.3.16", "6.3.17", "6.3.18", "6.3.19", "6.3.20", "6.3.21", "6.3.22", "6.3.23", "6.3.24", "6.3.25", "6.3.26", "6.3.27", "6.3.28", "6.3.29", "6.3.30", "6.3.31", "6.3.32", "6.3.33", "6.3.7", "6.3.8", "6.3.9"},  # MAL-2026-11564
    # @picsart/* — compromised in the keyv/cacheable campaign
    "@picsart/ai-sdk": {"3.32.2"},  # MAL-2026-11781
    "@picsart/gen-ai": {"2.55.11"},  # MAL-2026-11782
    # @thiennq/* — compromised in the keyv/cacheable campaign
    "@thiennq/docs-viewer": {"1.6.2", "1.6.3", "1.6.4"},  # MAL-2026-11952
    # @workbench-stack/* — compromised in the keyv/cacheable campaign
    "@workbench-stack/core": {"3.9.8"},  # MAL-2026-11961
    # @umacloud/* — 8 packages compromised in the keyv/cacheable campaign
    "@umacloud/cli-darwin-arm64": {"1.0.74"},  # MAL-2026-11953
    "@umacloud/cli-darwin-x64": {"1.0.74"},  # MAL-2026-11954
    "@umacloud/cli-linux-arm64": {"1.0.74"},  # MAL-2026-11955
    "@umacloud/cli-linux-musl-arm64": {"1.0.74"},  # MAL-2026-11956
    "@umacloud/cli-linux-musl-x64": {"1.0.74"},  # MAL-2026-11957
    "@umacloud/cli-linux-x64": {"1.0.74"},  # MAL-2026-11958
    "@umacloud/cli-win32-x64": {"1.0.74"},  # MAL-2026-11959
    "@umacloud/knowledge": {"1.0.74"},  # MAL-2026-11960
    # @nebula.js/* — Qlik visualization framework (22 packages) compromised
    "@nebula.js/cli": {"7.1.2"},  # MAL-2026-11565
    "@nebula.js/cli-build": {"7.1.2"},  # MAL-2026-11566
    "@nebula.js/cli-sense": {"7.1.2"},  # MAL-2026-11567
    "@nebula.js/cli-serve": {"7.1.2"},  # MAL-2026-11568
    "@nebula.js/locale": {"0.6.2"},  # MAL-2026-11569
    "@nebula.js/nucleus": {"0.5.1"},  # MAL-2026-11570
    "@nebula.js/sn-action-button": {"2.3.1"},  # MAL-2026-11571
    "@nebula.js/sn-animator": {"2.13.1"},  # MAL-2026-11572
    "@nebula.js/sn-distributionplot": {"1.0.7"},  # MAL-2026-11573
    "@nebula.js/sn-layout-container": {"4.4.1"},  # MAL-2026-11574
    "@nebula.js/sn-line-chart": {"2.7.1"},  # MAL-2026-11575
    "@nebula.js/sn-listbox": {"0.19.3"},  # MAL-2026-11576
    "@nebula.js/sn-map": {"0.12.7"},  # MAL-2026-11577
    "@nebula.js/sn-nav-menu": {"0.14.2"},  # MAL-2026-11578
    "@nebula.js/sn-org-chart": {"1.7.1"},  # MAL-2026-11579
    "@nebula.js/sn-shape": {"1.5.1"},  # MAL-2026-11580
    "@nebula.js/sn-slider": {"0.20.1"},  # MAL-2026-11581
    "@nebula.js/sn-tabbed-container": {"2.4.1"},  # MAL-2026-11582
    "@nebula.js/snapshooter": {"0.6.1"},  # MAL-2026-11583
    "@nebula.js/stardust": {"7.1.2"},  # MAL-2026-11584
    "@nebula.js/test-utils": {"0.6.1"},  # MAL-2026-11585
    "@nebula.js/theme": {"0.6.1"},  # MAL-2026-11586
    # picasso.js / qlik-* non-scoped packages compromised in the same campaign
    "picasso-plugin-hammer": {"2.11.6"},  # MAL-2026-11977
    "picasso-plugin-q": {"2.11.6"},  # MAL-2026-11978
    "picasso.js": {"2.11.6"},  # MAL-2026-11979
    "qlik-chart-modules": {"1.1.1"},  # MAL-2026-11982
    "qlik-modifiers": {"0.10.1"},  # MAL-2026-11983
    "qlik-object-conversion": {"0.17.2"},  # MAL-2026-11984
    "sn-listbox": {"0.3.3"},  # MAL-2026-11987
    # @qlik/* — Qlik Analytics scope (28 packages) compromised
    "@qlik/api": {"2.14.2"},  # MAL-2026-11783
    "@qlik/browserslist-config": {"3.0.2"},  # MAL-2026-11784
    "@qlik/carbon-core": {"2.1.1"},  # MAL-2026-11785
    "@qlik/carboncopy": {"1.1.6"},  # MAL-2026-11786
    "@qlik/design-tokens": {"1.3.13"},  # MAL-2026-11787
    "@qlik/dts-bundler": {"2.0.3"},  # MAL-2026-11788
    "@qlik/embed-react": {"2.5.3"},  # MAL-2026-11789
    "@qlik/embed-runtime": {"1.6.4"},  # MAL-2026-11790
    "@qlik/embed-svelte": {"1.1.4"},  # MAL-2026-11791
    "@qlik/embed-web-components": {"1.7.3"},  # MAL-2026-11792
    "@qlik/eslint-config": {"2.0.20"},  # MAL-2026-11793
    "@qlik/eslint-config-base": {"0.1.1"},  # MAL-2026-11794
    "@qlik/eslint-config-react": {"0.1.1"},  # MAL-2026-11795
    "@qlik/eslint-config-svelte": {"0.1.1"},  # MAL-2026-11796
    "@qlik/eslint-config-vue": {"0.1.1"},  # MAL-2026-11797
    "@qlik/nebula-table-utils": {"2.6.9"},  # MAL-2026-11798
    "@qlik/oxfmt-config": {"0.1.6"},  # MAL-2026-11799
    "@qlik/oxlint-config": {"0.7.2"},  # MAL-2026-11800
    "@qlik/prettier-config": {"1.0.3"},  # MAL-2026-11801
    "@qlik/react-native-simple-grid": {"1.5.5"},  # MAL-2026-11802
    "@qlik/runtime-module-loader": {"1.5.1"},  # MAL-2026-11803
    "@qlik/sdk": {"0.28.1"},  # MAL-2026-11804
    "@qlik/sprout-design-docs": {"1.0.2"},  # MAL-2026-11805
    "@qlik/sprout-gesture": {"0.0.13"},  # MAL-2026-11806
    "@qlik/sprout-icons": {"0.12.3"},  # MAL-2026-11807
    "@qlik/sprout-react": {"6.45.3"},  # MAL-2026-11808
    "@qlik/sprout-react-table": {"0.16.7"},  # MAL-2026-11809
    "@qlik/tsconfig": {"1.0.3"},  # MAL-2026-11810
    # @ornikar/* — Ornikar internal packages dep-confusion (42 packages)
    "@ornikar/apollo-link-timeout": {"1.4.10", "1.4.11", "1.4.2", "1.4.3", "1.4.4", "1.4.5", "1.4.6", "1.4.7", "1.4.8", "1.4.9"},  # MAL-2026-11739
    "@ornikar/babel-preset-base": {"6.0.10", "6.0.11", "6.0.12", "6.0.13", "6.0.14", "6.0.3", "6.0.4", "6.0.5", "6.0.6", "6.0.7", "6.0.8", "6.0.9"},  # MAL-2026-11740
    "@ornikar/babel-preset-kitt-universal": {"8.0.10", "8.0.11", "8.0.12", "8.0.3", "8.0.4", "8.0.5", "8.0.6", "8.0.7", "8.0.8", "8.0.9"},  # MAL-2026-11741
    "@ornikar/babel-preset-react": {"6.1.10", "6.1.11", "6.1.12", "6.1.13", "6.1.14", "6.1.4", "6.1.5", "6.1.6", "6.1.7", "6.1.8", "6.1.9"},  # MAL-2026-11742
    "@ornikar/browserslist-config": {"8.0.10", "8.0.11", "8.0.3", "8.0.4", "8.0.5", "8.0.6", "8.0.7", "8.0.8", "8.0.9"},  # MAL-2026-11743
    "@ornikar/commitlint-config": {"8.3.10", "8.3.11", "8.3.12", "8.3.2", "8.3.3", "8.3.4", "8.3.5", "8.3.6", "8.3.7", "8.3.8", "8.3.9"},  # MAL-2026-11744
    "@ornikar/eslint-config": {"24.0.1", "24.0.10", "24.0.11", "24.0.12", "24.0.2", "24.0.3", "24.0.4", "24.0.5", "24.0.6", "24.0.7", "24.0.8", "24.0.9"},  # MAL-2026-11745
    "@ornikar/eslint-config-babel": {"24.0.1", "24.0.10", "24.0.11", "24.0.12", "24.0.2", "24.0.3", "24.0.4", "24.0.5", "24.0.6", "24.0.7", "24.0.8", "24.0.9"},  # MAL-2026-11746
    "@ornikar/eslint-config-babel-use": {"13.2.1", "13.2.10", "13.2.11", "13.2.12", "13.2.2", "13.2.3", "13.2.4", "13.2.5", "13.2.6", "13.2.7", "13.2.8", "13.2.9"},  # MAL-2026-11747
    "@ornikar/eslint-config-formatjs": {"24.0.1", "24.0.10", "24.0.2", "24.0.3", "24.0.4", "24.0.5", "24.0.6", "24.0.7", "24.0.8", "24.0.9"},  # MAL-2026-11748
    "@ornikar/eslint-config-node": {"12.2.1", "12.2.10", "12.2.2", "12.2.3", "12.2.4", "12.2.5", "12.2.6", "12.2.7", "12.2.8", "12.2.9"},  # MAL-2026-11749
    "@ornikar/eslint-config-react": {"24.0.1", "24.0.10", "24.0.11", "24.0.2", "24.0.3", "24.0.4", "24.0.5", "24.0.6", "24.0.7", "24.0.8", "24.0.9"},  # MAL-2026-11750
    "@ornikar/eslint-config-typescript": {"24.0.1", "24.0.10", "24.0.2", "24.0.3", "24.0.4", "24.0.5", "24.0.6", "24.0.7", "24.0.8", "24.0.9"},  # MAL-2026-11751
    "@ornikar/eslint-config-typescript-nestjs": {"24.0.1", "24.0.10", "24.0.11", "24.0.2", "24.0.3", "24.0.4", "24.0.5", "24.0.6", "24.0.7", "24.0.8", "24.0.9"},  # MAL-2026-11752
    "@ornikar/eslint-config-typescript-react": {"24.0.1", "24.0.10", "24.0.11", "24.0.2", "24.0.3", "24.0.4", "24.0.5", "24.0.6", "24.0.7", "24.0.8", "24.0.9"},  # MAL-2026-11753
    "@ornikar/eslint-plugin-neverthrow": {"1.3.1", "1.3.10", "1.3.11", "1.3.12", "1.3.2", "1.3.3", "1.3.4", "1.3.5", "1.3.6", "1.3.7", "1.3.8", "1.3.9"},  # MAL-2026-11754
    "@ornikar/eslint-plugin-ornikar": {"24.0.1", "24.0.10", "24.0.11", "24.0.2", "24.0.3", "24.0.4", "24.0.5", "24.0.6", "24.0.7", "24.0.8", "24.0.9"},  # MAL-2026-11755
    "@ornikar/graphql-config": {"1.1.1", "1.1.10", "1.1.11", "1.1.2", "1.1.3", "1.1.4", "1.1.5", "1.1.6", "1.1.7", "1.1.8", "1.1.9"},  # MAL-2026-11756
    "@ornikar/intl-config": {"10.0.2", "10.0.3", "10.0.4", "10.0.5", "10.0.6", "10.0.7", "10.0.8", "10.0.9"},  # MAL-2026-11757
    "@ornikar/jest-config": {"13.0.10", "13.0.11", "13.0.12", "13.0.13", "13.0.3", "13.0.4", "13.0.5", "13.0.6", "13.0.7", "13.0.8", "13.0.9"},  # MAL-2026-11758
    "@ornikar/jest-config-react": {"18.0.10", "18.0.11", "18.0.2", "18.0.3", "18.0.4", "18.0.5", "18.0.6", "18.0.7", "18.0.8", "18.0.9"},  # MAL-2026-11759
    "@ornikar/jest-config-react-native": {"17.0.10", "17.0.11", "17.0.12", "17.0.2", "17.0.3", "17.0.4", "17.0.5", "17.0.6", "17.0.7", "17.0.8", "17.0.9"},  # MAL-2026-11760
    "@ornikar/jest-config-react-native-web": {"12.0.10", "12.0.11", "12.0.12", "12.0.13", "12.0.3", "12.0.4", "12.0.5", "12.0.6", "12.0.7", "12.0.8", "12.0.9"},  # MAL-2026-11761
    "@ornikar/kitt2": {"1.0.1", "1.0.10", "1.0.11", "1.0.2", "1.0.3", "1.0.4", "1.0.5", "1.0.6", "1.0.7", "1.0.8", "1.0.9"},  # MAL-2026-11762
    "@ornikar/lerna-config": {"11.0.1", "11.0.10", "11.0.11", "11.0.2", "11.0.3", "11.0.4", "11.0.5", "11.0.6", "11.0.7", "11.0.8", "11.0.9"},  # MAL-2026-11763
    "@ornikar/monorepo-config": {"14.3.10", "14.3.11", "14.3.12", "14.3.13", "14.3.2", "14.3.3", "14.3.4", "14.3.5", "14.3.6", "14.3.7", "14.3.8", "14.3.9"},  # MAL-2026-11764
    "@ornikar/postcss-config": {"9.1.10", "9.1.11", "9.1.12", "9.1.2", "9.1.3", "9.1.4", "9.1.5", "9.1.6", "9.1.7", "9.1.8", "9.1.9"},  # MAL-2026-11765
    "@ornikar/prettier-config": {"9.0.10", "9.0.11", "9.0.3", "9.0.4", "9.0.5", "9.0.6", "9.0.7", "9.0.8", "9.0.9"},  # MAL-2026-11766
    "@ornikar/prismic-components": {"0.0.10", "0.0.11", "0.0.12", "0.0.2", "0.0.3", "0.0.4", "0.0.5", "0.0.6", "0.0.7", "0.0.8", "0.0.9"},  # MAL-2026-11767
    "@ornikar/react-modern-calendar-datepicker": {"3.2.1", "3.2.10", "3.2.11", "3.2.2", "3.2.3", "3.2.4", "3.2.5", "3.2.6", "3.2.7", "3.2.8", "3.2.9"},  # MAL-2026-11768
    "@ornikar/react-native-svg-transformer": {"1.0.10", "1.0.11", "1.0.12", "1.0.6", "1.0.7", "1.0.8", "1.0.9"},  # MAL-2026-11769
    "@ornikar/renovate-config": {"9.0.10", "9.0.11", "9.0.12", "9.0.13", "9.0.2", "9.0.3", "9.0.4", "9.0.5", "9.0.6", "9.0.7", "9.0.8", "9.0.9"},  # MAL-2026-11770
    "@ornikar/repo-config": {"15.3.10", "15.3.11", "15.3.12", "15.3.13", "15.3.3", "15.3.4", "15.3.5", "15.3.6", "15.3.7", "15.3.8", "15.3.9"},  # MAL-2026-11771
    "@ornikar/repo-config-react": {"13.0.10", "13.0.11", "13.0.12", "13.0.13", "13.0.14", "13.0.15", "13.0.16", "13.0.17", "13.0.18", "13.0.19", "13.0.8", "13.0.9"},  # MAL-2026-11772
    "@ornikar/repo-config-react-legacy-css": {"15.1.10", "15.1.11", "15.1.12", "15.1.13", "15.1.2", "15.1.3", "15.1.4", "15.1.5", "15.1.6", "15.1.7", "15.1.8", "15.1.9"},  # MAL-2026-11773
    "@ornikar/rollup-config": {"11.1.10", "11.1.11", "11.1.12", "11.1.13", "11.1.2", "11.1.3", "11.1.4", "11.1.5", "11.1.6", "11.1.7", "11.1.8", "11.1.9"},  # MAL-2026-11774
    "@ornikar/rollup-plugin-postcss": {"2.0.10", "2.0.11", "2.0.12", "2.0.13", "2.0.14", "2.0.15", "2.0.5", "2.0.6", "2.0.7", "2.0.8", "2.0.9"},  # MAL-2026-11775
    "@ornikar/slate-react-fork": {"1.0.1", "1.0.10", "1.0.11", "1.0.2", "1.0.3", "1.0.4", "1.0.5", "1.0.6", "1.0.7", "1.0.8", "1.0.9"},  # MAL-2026-11776
    "@ornikar/storybook-config": {"12.1.10", "12.1.2", "12.1.3", "12.1.4", "12.1.5", "12.1.6", "12.1.7", "12.1.8", "12.1.9"},  # MAL-2026-11777
    "@ornikar/stylelint-config": {"14.0.10", "14.0.11", "14.0.12", "14.0.13", "14.0.3", "14.0.4", "14.0.5", "14.0.6", "14.0.7", "14.0.8", "14.0.9"},  # MAL-2026-11778
    "@ornikar/typed-css-modules-loader": {"0.8.10", "0.8.11", "0.8.12", "0.8.2", "0.8.3", "0.8.4", "0.8.5", "0.8.6", "0.8.7", "0.8.8", "0.8.9"},  # MAL-2026-11779
    "@ornikar/webpack-config": {"12.0.10", "12.0.11", "12.0.12", "12.0.2", "12.0.3", "12.0.4", "12.0.5", "12.0.6", "12.0.7", "12.0.8", "12.0.9"},  # MAL-2026-11780
    # @or-sdk/* — OneReach.ai SDK packages compromised (74 packages)
    "@or-sdk/account-settings": {"1.3.6", "1.3.7", "1.3.8"},  # MAL-2026-11665
    "@or-sdk/accounts": {"2.3.5", "2.3.6", "2.3.7"},  # MAL-2026-11666
    "@or-sdk/adapters": {"0.3.6", "0.3.7", "0.3.8"},  # MAL-2026-11667
    "@or-sdk/agents": {"4.21.3", "4.21.4", "4.21.5"},  # MAL-2026-11668
    "@or-sdk/api-tokens": {"1.4.2", "1.4.3", "1.4.4"},  # MAL-2026-11669
    "@or-sdk/api-tokens-lambda": {"1.4.2", "1.4.3", "1.4.4"},  # MAL-2026-11670
    "@or-sdk/apps": {"1.2.6", "1.2.7", "1.2.8"},  # MAL-2026-11671
    "@or-sdk/auth": {"0.38.1", "0.38.2", "0.38.3"},  # MAL-2026-11672
    "@or-sdk/authorizer": {"0.26.7", "0.26.8", "0.26.9"},  # MAL-2026-11673
    "@or-sdk/base": {"0.44.4", "0.44.5", "0.44.6"},  # MAL-2026-11674
    "@or-sdk/billing": {"27.2.1", "27.2.2", "27.2.3"},  # MAL-2026-11675
    "@or-sdk/billing-internal": {"27.2.1", "27.2.2", "27.2.3"},  # MAL-2026-11676
    "@or-sdk/bot-templates": {"2.2.5", "2.2.6", "2.2.7"},  # MAL-2026-11677
    "@or-sdk/bots": {"1.7.1", "1.7.2", "1.7.3"},  # MAL-2026-11678
    "@or-sdk/card-templates": {"2.2.5", "2.2.6", "2.2.7"},  # MAL-2026-11679
    "@or-sdk/cards": {"1.2.5", "1.2.6", "1.2.7"},  # MAL-2026-11680
    "@or-sdk/ccp": {"10.15.4", "10.15.5", "10.15.6"},  # MAL-2026-11681
    "@or-sdk/chat": {"0.3.1", "0.3.2", "0.3.3"},  # MAL-2026-11682
    "@or-sdk/contacts": {"4.7.5", "4.7.6", "4.7.7"},  # MAL-2026-11683
    "@or-sdk/content-request": {"0.2.6", "0.2.7", "0.2.8"},  # MAL-2026-11684
    "@or-sdk/data-hub": {"0.26.5", "0.26.6", "0.26.7"},  # MAL-2026-11685
    "@or-sdk/data-hub-svc": {"2.3.5", "2.3.6", "2.3.7"},  # MAL-2026-11686
    "@or-sdk/deployer": {"1.7.5", "1.7.6", "1.7.7"},  # MAL-2026-11687
    "@or-sdk/deployments": {"2.1.5", "2.1.6", "2.1.7"},  # MAL-2026-11688
    "@or-sdk/discovery": {"1.12.1", "1.12.2", "1.12.3"},  # MAL-2026-11689
    "@or-sdk/druid": {"1.4.7", "1.4.8", "1.4.9"},  # MAL-2026-11690
    "@or-sdk/event-manager": {"1.1.5", "1.1.6", "1.1.7"},  # MAL-2026-11691
    "@or-sdk/files": {"3.11.6", "3.11.7", "3.11.8"},  # MAL-2026-11692
    "@or-sdk/files-sync-node": {"0.1.10", "0.1.8", "0.1.9"},  # MAL-2026-11693
    "@or-sdk/flow-templates": {"2.1.5", "2.1.6", "2.1.7"},  # MAL-2026-11694
    "@or-sdk/flows": {"2.7.10", "2.7.8", "2.7.9"},  # MAL-2026-11695
    "@or-sdk/graph": {"1.10.5", "1.10.6", "1.10.7"},  # MAL-2026-11696
    "@or-sdk/hitl": {"0.41.1", "0.41.2", "0.41.3"},  # MAL-2026-11697
    "@or-sdk/identifiers": {"0.27.6", "0.27.7", "0.27.8"},  # MAL-2026-11698
    "@or-sdk/idw": {"9.0.4", "9.0.5", "9.0.6"},  # MAL-2026-11699
    "@or-sdk/idw-public": {"1.6.6", "1.6.7", "1.6.8"},  # MAL-2026-11700
    "@or-sdk/idw-skill": {"1.4.1", "1.4.2", "1.4.3"},  # MAL-2026-11701
    "@or-sdk/invitations": {"1.4.10", "1.4.8", "1.4.9"},  # MAL-2026-11702
    "@or-sdk/key-value-storage": {"0.28.6", "0.28.7", "0.28.8"},  # MAL-2026-11703
    "@or-sdk/keys": {"1.2.6", "1.2.7", "1.2.8"},  # MAL-2026-11704
    "@or-sdk/knowledge-models": {"0.25.5", "0.25.6", "0.25.7"},  # MAL-2026-11705
    "@or-sdk/library": {"0.5.6", "0.5.7", "0.5.8"},  # MAL-2026-11706
    "@or-sdk/library-categories": {"0.2.6", "0.2.7", "0.2.8"},  # MAL-2026-11707
    "@or-sdk/library-source": {"0.4.5", "0.4.6", "0.4.7"},  # MAL-2026-11708
    "@or-sdk/library-types-v1": {"9.0.1", "9.0.2", "9.0.3"},  # MAL-2026-11709
    "@or-sdk/library-types-v2": {"9.0.1", "9.0.2", "9.0.3"},  # MAL-2026-11710
    "@or-sdk/lookup": {"1.25.1", "1.25.2", "1.25.3"},  # MAL-2026-11711
    "@or-sdk/markdowner": {"0.5.1", "0.5.2", "0.5.3"},  # MAL-2026-11712
    "@or-sdk/mcp-tools": {"0.5.2", "0.5.3", "0.5.4"},  # MAL-2026-11713
    "@or-sdk/notifications": {"1.7.5", "1.7.6", "1.7.7"},  # MAL-2026-11714
    "@or-sdk/password": {"1.3.6", "1.3.7", "1.3.8"},  # MAL-2026-11715
    "@or-sdk/payments": {"3.2.5", "3.2.6", "3.2.7"},  # MAL-2026-11716
    "@or-sdk/permissions": {"2.8.1", "2.8.2", "2.8.3"},  # MAL-2026-11717
    "@or-sdk/permissions-cli": {"1.4.1", "1.4.2", "1.4.3"},  # MAL-2026-11718
    "@or-sdk/permissions-lambda": {"2.5.1", "2.5.2", "2.5.3"},  # MAL-2026-11719
    "@or-sdk/pgsql": {"1.5.1", "1.5.2", "1.5.3"},  # MAL-2026-11720
    "@or-sdk/providers": {"0.3.6", "0.3.7", "0.3.8"},  # MAL-2026-11721
    "@or-sdk/qna": {"3.4.2", "3.4.3", "3.4.4"},  # MAL-2026-11722
    "@or-sdk/queue-manager": {"1.4.6", "1.4.7", "1.4.8"},  # MAL-2026-11723
    "@or-sdk/sdk-api": {"0.29.2", "0.29.3", "0.29.4"},  # MAL-2026-11724
    "@or-sdk/settings": {"0.25.6", "0.25.7", "0.25.8"},  # MAL-2026-11725
    "@or-sdk/sku-builder": {"2.5.1", "2.5.2", "2.5.3"},  # MAL-2026-11726
    "@or-sdk/source": {"2.1.5", "2.1.6", "2.1.7"},  # MAL-2026-11727
    "@or-sdk/source-api": {"1.1.1", "1.1.2", "1.1.3"},  # MAL-2026-11728
    "@or-sdk/step-templates": {"2.2.5", "2.2.6", "2.2.7"},  # MAL-2026-11729
    "@or-sdk/store": {"2.1.5", "2.1.6", "2.1.7"},  # MAL-2026-11730
    "@or-sdk/tables": {"0.28.5", "0.28.6", "0.28.7"},  # MAL-2026-11731
    "@or-sdk/tags": {"1.1.5", "1.1.6", "1.1.7"},  # MAL-2026-11732
    "@or-sdk/tickets": {"1.9.5", "1.9.6", "1.9.7"},  # MAL-2026-11733
    "@or-sdk/transcripts": {"1.2.5", "1.2.6", "1.2.7"},  # MAL-2026-11734
    "@or-sdk/users": {"3.8.1", "3.8.2", "3.8.3"},  # MAL-2026-11735
    "@or-sdk/view-templates": {"2.2.5", "2.2.6", "2.2.7"},  # MAL-2026-11736
    "@or-sdk/views": {"3.1.5", "3.1.6", "3.1.7"},  # MAL-2026-11737
    "@or-sdk/web-search": {"0.6.1", "0.6.2", "0.6.3"},  # MAL-2026-11738
    # @onereach/* — OneReach.ai platform packages compromised (78 packages)
    "@onereach/authorizer-helper": {"0.0.11", "0.0.12", "0.0.13"},  # MAL-2026-11587
    "@onereach/bandwidth-steps-voice-bxml": {"0.1.1", "0.1.2", "0.1.3"},  # MAL-2026-11588
    "@onereach/billing-dto": {"27.2.1", "27.2.2", "27.2.3"},  # MAL-2026-11589
    "@onereach/billing-shared": {"27.2.1", "27.2.2", "27.2.3"},  # MAL-2026-11590
    "@onereach/cb-schema-translator": {"1.3.1", "1.3.2", "1.3.3"},  # MAL-2026-11591
    "@onereach/channel-transformer": {"0.0.66", "0.0.67", "0.0.68"},  # MAL-2026-11592
    "@onereach/channel-transformers": {"0.0.5", "0.0.6", "0.0.7"},  # MAL-2026-11593
    "@onereach/ckeditor5-build-classic": {"30.0.1", "30.0.2", "30.0.3"},  # MAL-2026-11594
    "@onereach/condition-builder": {"1.0.10", "1.0.8", "1.0.9"},  # MAL-2026-11595
    "@onereach/content-builder": {"0.0.18", "0.0.19", "0.0.20"},  # MAL-2026-11596
    "@onereach/content-builder-template-compiler": {"0.0.3", "0.0.4", "0.0.5"},  # MAL-2026-11597
    "@onereach/expression-components": {"9.1.1", "9.1.2", "9.1.3"},  # MAL-2026-11598
    "@onereach/font-icons": {"27.0.2", "27.0.3", "27.0.4"},  # MAL-2026-11599
    "@onereach/get-version-data": {"3.1.2", "3.1.3", "3.1.4"},  # MAL-2026-11600
    "@onereach/idw-apps": {"0.1.3", "0.1.4", "0.1.5"},  # MAL-2026-11601
    "@onereach/idw-contracts": {"0.1.2", "0.1.3", "0.1.4"},  # MAL-2026-11602
    "@onereach/idw-init-account-resources": {"1.0.1", "1.0.2", "1.0.3"},  # MAL-2026-11603
    "@onereach/idw-sdk": {"0.1.2", "0.1.3", "0.1.4"},  # MAL-2026-11604
    "@onereach/idw-ui-components": {"0.1.2", "0.1.3", "0.1.4"},  # MAL-2026-11605
    "@onereach/lambda-invocation": {"1.2.1", "1.2.2", "1.2.3"},  # MAL-2026-11606
    "@onereach/messengers-infobip-sdk": {"0.1.1", "0.1.2", "0.1.3"},  # MAL-2026-11607
    "@onereach/or-browser": {"0.0.48", "0.0.49", "0.0.50"},  # MAL-2026-11608
    "@onereach/or-browser-next": {"0.0.11", "0.0.12", "0.0.13"},  # MAL-2026-11609
    "@onereach/or-content-builder-renderer": {"0.0.2", "0.0.3", "0.0.4"},  # MAL-2026-11610
    "@onereach/or-file-uploader-next": {"0.0.10", "0.0.8", "0.0.9"},  # MAL-2026-11611
    "@onereach/or-pro": {"1.13.1", "1.13.2", "1.13.3"},  # MAL-2026-11612
    "@onereach/or-sdk-agent-cli": {"0.0.6", "0.0.7", "0.0.8"},  # MAL-2026-11613
    "@onereach/orest-cli": {"2.4.1", "2.4.2", "2.4.3"},  # MAL-2026-11614
    "@onereach/orest-input-cli": {"1.18.1", "1.18.2", "1.18.3"},  # MAL-2026-11615
    "@onereach/orest-jest-presets": {"0.0.3", "0.0.4", "0.0.5"},  # MAL-2026-11616
    "@onereach/orest-vue-demi-vue2": {"0.0.4", "0.0.5", "0.0.6"},  # MAL-2026-11617
    "@onereach/orest-vue-demi-vue3": {"0.0.4", "0.0.5", "0.0.6"},  # MAL-2026-11618
    "@onereach/orest-vue3": {"0.0.4", "0.0.5", "0.0.6"},  # MAL-2026-11619
    "@onereach/phonenumber-interpreter": {"0.0.18", "0.0.19", "0.0.20"},  # MAL-2026-11620
    "@onereach/pnpm-audit-junit": {"1.0.3", "1.0.4", "1.0.5"},  # MAL-2026-11621
    "@onereach/postcss-scoped-selector": {"1.2.1", "1.2.2", "1.2.3"},  # MAL-2026-11622
    "@onereach/regex-helper": {"0.5.16", "0.5.17", "0.5.18"},  # MAL-2026-11623
    "@onereach/regular-expressions": {"0.5.23", "0.5.24", "0.5.25"},  # MAL-2026-11624
    "@onereach/regular-expressions-test": {"0.0.4", "0.0.5", "0.0.6"},  # MAL-2026-11625
    "@onereach/rwc-client": {"6.4.7", "6.4.8", "6.4.9"},  # MAL-2026-11626
    "@onereach/salesforce-miaw-client": {"0.0.3", "0.0.4", "0.0.5"},  # MAL-2026-11627
    "@onereach/si-a-button": {"0.0.3", "0.0.4", "0.0.5"},  # MAL-2026-11628
    "@onereach/si-alert": {"0.4.11", "0.4.12", "0.4.13"},  # MAL-2026-11629
    "@onereach/si-checkbox": {"0.6.5", "0.6.6", "0.6.7"},  # MAL-2026-11630
    "@onereach/si-checkbox-group": {"0.3.5", "0.3.6", "0.3.7"},  # MAL-2026-11631
    "@onereach/si-code": {"0.6.4", "0.6.5", "0.6.6"},  # MAL-2026-11632
    "@onereach/si-collapsible-group": {"0.6.4", "0.6.5", "0.6.6"},  # MAL-2026-11633
    "@onereach/si-copyable-text": {"0.4.11", "0.4.12", "0.4.13"},  # MAL-2026-11634
    "@onereach/si-datepicker": {"0.4.5", "0.4.6", "0.4.7"},  # MAL-2026-11635
    "@onereach/si-divider": {"0.4.11", "0.4.12", "0.4.13"},  # MAL-2026-11636
    "@onereach/si-dropdown-advanced": {"0.4.5", "0.4.6", "0.4.7"},  # MAL-2026-11637
    "@onereach/si-dropdown-simple": {"0.4.5", "0.4.6", "0.4.7"},  # MAL-2026-11638
    "@onereach/si-header": {"0.4.11", "0.4.12", "0.4.13", "0.4.14"},  # MAL-2026-11639
    "@onereach/si-list": {"0.7.4", "0.7.5", "0.7.6"},  # MAL-2026-11640
    "@onereach/si-merge-tag-input": {"0.4.5", "0.4.6", "0.4.7"},  # MAL-2026-11641
    "@onereach/si-radio-group": {"0.3.5", "0.3.6", "0.3.7"},  # MAL-2026-11642
    "@onereach/si-root": {"0.9.4", "0.9.5", "0.9.6"},  # MAL-2026-11643
    "@onereach/si-select": {"0.1.3", "0.1.4", "0.1.5"},  # MAL-2026-11644
    "@onereach/si-step-chooser": {"0.4.4", "0.4.5", "0.4.6"},  # MAL-2026-11645
    "@onereach/si-switch": {"0.4.5", "0.4.6", "0.4.7"},  # MAL-2026-11646
    "@onereach/si-text-message": {"0.4.5", "0.4.6", "0.4.7"},  # MAL-2026-11647
    "@onereach/si-textinput": {"0.5.5", "0.5.6", "0.5.7"},  # MAL-2026-11648
    "@onereach/si-validated-timestring-input": {"0.3.5", "0.3.6", "0.3.7"},  # MAL-2026-11649
    "@onereach/slack-helpers": {"1.0.3", "1.0.4", "1.0.5"},  # MAL-2026-11650
    "@onereach/ssml-editor": {"2.0.12", "2.0.13", "2.0.14"},  # MAL-2026-11651
    "@onereach/step-components": {"0.1.37", "0.1.38", "0.1.39"},  # MAL-2026-11652
    "@onereach/step-conversation": {"1.0.41", "1.0.42", "1.0.43"},  # MAL-2026-11653
    "@onereach/step-run-snowflake-query": {"0.1.1", "0.1.2", "0.1.3"},  # MAL-2026-11654
    "@onereach/step-voice": {"7.0.32", "7.0.33", "7.0.34"},  # MAL-2026-11655
    "@onereach/styles": {"27.0.2", "27.0.3", "27.0.4"},  # MAL-2026-11656
    "@onereach/time-interpreter": {"1.0.30", "1.0.31", "1.0.32"},  # MAL-2026-11657
    "@onereach/ts-memoize": {"1.0.2", "1.0.3", "1.0.4"},  # MAL-2026-11658
    "@onereach/types-contacts-api": {"9.0.10", "9.0.8", "9.0.9"},  # MAL-2026-11659
    "@onereach/ui-components": {"27.0.2", "27.0.3", "27.0.4"},  # MAL-2026-11660
    "@onereach/ui-components-common": {"27.0.2", "27.0.3", "27.0.4"},  # MAL-2026-11661
    "@onereach/ui-components-vue2": {"27.0.2", "27.0.3", "27.0.4"},  # MAL-2026-11662
    "@onereach/v-event-calendar": {"0.1.22", "0.1.23", "0.1.24"},  # MAL-2026-11663
    "@onereach/webform": {"0.3.13", "0.3.14", "0.3.15"},  # MAL-2026-11664
    # @servicetitan/* — ServiceTitan internal packages compromised (141 packages)
    "@servicetitan/acquisition-functions": {"5.22.1", "5.22.2", "5.22.3", "5.22.4", "5.22.5", "5.22.6", "5.22.7"},  # MAL-2026-11811
    "@servicetitan/admin-layout": {"2.4.3", "2.4.4", "2.4.5", "2.4.6", "2.4.7", "2.4.8", "2.4.9"},  # MAL-2026-11812
    "@servicetitan/admin-sql-table": {"1.0.14", "1.0.15", "1.0.16", "1.0.17", "1.0.18", "1.0.19", "1.0.20"},  # MAL-2026-11813
    "@servicetitan/ajax-handlers": {"38.1.1", "38.1.2", "38.1.3", "38.1.4", "38.1.5", "38.1.6", "38.1.7"},  # MAL-2026-11814
    "@servicetitan/anvil-css-utilities": {"14.5.10", "14.5.4", "14.5.5", "14.5.6", "14.5.7", "14.5.8", "14.5.9"},  # MAL-2026-11815
    "@servicetitan/anvil-fonts": {"14.5.10", "14.5.4", "14.5.5", "14.5.6", "14.5.7", "14.5.8", "14.5.9"},  # MAL-2026-11816
    "@servicetitan/anvil-icon": {"0.5.1", "0.5.2", "0.5.3", "0.5.4", "0.5.5", "0.5.6", "0.5.7"},  # MAL-2026-11817
    "@servicetitan/anvil-icons": {"14.5.10", "14.5.4", "14.5.5", "14.5.6", "14.5.7", "14.5.8", "14.5.9"},  # MAL-2026-11818
    "@servicetitan/anvil-react": {"0.11.3", "0.11.4", "0.11.5", "0.11.6", "0.11.7", "0.11.8", "0.11.9"},  # MAL-2026-11819
    "@servicetitan/anvil-themes": {"14.5.10", "14.5.4", "14.5.5", "14.5.6", "14.5.7", "14.5.8", "14.5.9"},  # MAL-2026-11820
    "@servicetitan/anvil-token": {"0.4.1", "0.4.2", "0.4.3", "0.4.4", "0.4.5", "0.4.6", "0.4.7"},  # MAL-2026-11821
    "@servicetitan/anvil2": {"3.9.1", "3.9.2", "3.9.3", "3.9.4", "3.9.5", "3.9.6", "3.9.7"},  # MAL-2026-11822
    "@servicetitan/anvil2-codemods": {"0.11.2", "0.11.3", "0.11.4", "0.11.5", "0.11.6", "0.11.7", "0.11.8"},  # MAL-2026-11823
    "@servicetitan/anvil2-ext-atlas": {"4.0.2", "4.0.3", "4.0.4", "4.0.5", "4.0.6", "4.0.7", "4.0.8"},  # MAL-2026-11824
    "@servicetitan/anvil2-ext-charts": {"0.2.10", "0.2.4", "0.2.5", "0.2.6", "0.2.7", "0.2.8", "0.2.9"},  # MAL-2026-11825
    "@servicetitan/anvil2-ext-common": {"0.7.1", "0.7.2", "0.7.3", "0.7.4", "0.7.5", "0.7.6", "0.7.7"},  # MAL-2026-11826
    "@servicetitan/anvil2-ext-mwv": {"0.0.10", "0.0.11", "0.0.5", "0.0.6", "0.0.7", "0.0.8", "0.0.9"},  # MAL-2026-11827
    "@servicetitan/anvil2-illustrations": {"1.0.2", "1.0.3", "1.0.4", "1.0.5", "1.0.6", "1.0.7", "1.0.8"},  # MAL-2026-11828
    "@servicetitan/anvil2-mcp": {"0.0.10", "0.0.11", "0.0.12", "0.0.13", "0.0.14", "0.0.15", "0.0.9"},  # MAL-2026-11829
    "@servicetitan/assist-ui": {"2.1.1", "2.1.2", "2.1.3", "2.1.4", "2.1.5", "2.1.6", "2.1.7"},  # MAL-2026-11830
    "@servicetitan/assist-utils": {"1.1.2", "1.1.3", "1.1.4", "1.1.5", "1.1.6", "1.1.7", "1.1.8"},  # MAL-2026-11831
    "@servicetitan/carto-charts-core": {"0.0.2", "0.0.3", "0.0.4", "0.0.5", "0.0.6", "0.0.7", "0.0.8"},  # MAL-2026-11832
    "@servicetitan/carto-charts-react": {"0.0.2", "0.0.3", "0.0.4", "0.0.5", "0.0.6", "0.0.7", "0.0.8"},  # MAL-2026-11833
    "@servicetitan/carto-charts-rn": {"0.0.2", "0.0.3", "0.0.4", "0.0.5", "0.0.6", "0.0.7", "0.0.8"},  # MAL-2026-11834
    "@servicetitan/carto-react-kit": {"0.8.10", "0.8.4", "0.8.5", "0.8.6", "0.8.7", "0.8.8", "0.8.9"},  # MAL-2026-11835
    "@servicetitan/carto-rn-kit": {"0.0.10", "0.0.11", "0.0.12", "0.0.13", "0.0.14", "0.0.15", "0.0.16"},  # MAL-2026-11836
    "@servicetitan/carto-tokens": {"0.3.1", "0.3.2", "0.3.3", "0.3.4", "0.3.5", "0.3.6", "0.3.7"},  # MAL-2026-11837
    "@servicetitan/component-usage": {"28.5.1", "28.5.2", "28.5.3", "28.5.4", "28.5.5", "28.5.6", "28.5.7"},  # MAL-2026-11838
    "@servicetitan/confirm": {"41.3.1", "41.3.2", "41.3.3", "41.3.4", "41.3.5", "41.3.6", "41.3.7"},  # MAL-2026-11839
    "@servicetitan/confirm-navigation": {"41.3.1", "41.3.2", "41.3.3", "41.3.4", "41.3.5", "41.3.6", "41.3.7"},  # MAL-2026-11840
    "@servicetitan/contentful": {"0.0.3", "0.0.4", "0.0.5", "0.0.6", "0.0.7", "0.0.8", "0.0.9"},  # MAL-2026-11841
    "@servicetitan/contentful-proxy": {"1.1.12", "1.1.13", "1.1.14", "1.1.15", "1.1.16", "1.1.17", "1.1.18"},  # MAL-2026-11842
    "@servicetitan/cp-api": {"1.115.1", "1.115.2", "1.115.3", "1.115.4", "1.115.5", "1.115.6", "1.115.7"},  # MAL-2026-11843
    "@servicetitan/cp-mfe": {"1.115.1", "1.115.2", "1.115.3", "1.115.4", "1.115.5", "1.115.6", "1.115.7"},  # MAL-2026-11844
    "@servicetitan/cp-mfe-dev": {"1.115.1", "1.115.2", "1.115.3", "1.115.4", "1.115.5", "1.115.6", "1.115.7"},  # MAL-2026-11845
    "@servicetitan/cp-react-hooks": {"1.115.1", "1.115.2", "1.115.3", "1.115.4", "1.115.5", "1.115.6", "1.115.7"},  # MAL-2026-11846
    "@servicetitan/cp-ui": {"1.115.1", "1.115.2", "1.115.3", "1.115.4", "1.115.5", "1.115.6", "1.115.7"},  # MAL-2026-11847
    "@servicetitan/culture": {"41.3.1", "41.3.2", "41.3.3", "41.3.4", "41.3.5", "41.3.6", "41.3.7"},  # MAL-2026-11848
    "@servicetitan/data-query": {"41.3.1", "41.3.2", "41.3.3", "41.3.4", "41.3.5", "41.3.6", "41.3.7"},  # MAL-2026-11849
    "@servicetitan/datadog-rum": {"38.1.1", "38.1.2", "38.1.3", "38.1.4", "38.1.5", "38.1.6", "38.1.7"},  # MAL-2026-11850
    "@servicetitan/datetime-utils": {"41.3.1", "41.3.2", "41.3.3", "41.3.4", "41.3.5", "41.3.6", "41.3.7"},  # MAL-2026-11851
    "@servicetitan/design-system": {"14.5.10", "14.5.4", "14.5.5", "14.5.6", "14.5.7", "14.5.8", "14.5.9"},  # MAL-2026-11852
    "@servicetitan/docs-anvil-uikit-contrib": {"41.3.1", "41.3.2", "41.3.3", "41.3.4", "41.3.5", "41.3.6", "41.3.7"},  # MAL-2026-11853
    "@servicetitan/docs-uikit": {"38.1.1", "38.1.2", "38.1.3", "38.1.4", "38.1.5", "38.1.6", "38.1.7"},  # MAL-2026-11854
    "@servicetitan/document-title": {"2.4.1", "2.4.2", "2.4.3", "2.4.4", "2.4.5", "2.4.6", "2.4.7"},  # MAL-2026-11855
    "@servicetitan/dte-pdf-editor": {"1.76.1", "1.76.2", "1.76.3", "1.76.4", "1.76.5", "1.76.6", "1.76.7"},  # MAL-2026-11856
    "@servicetitan/dte-unlayer": {"0.150.1", "0.150.2", "0.150.3", "0.150.4", "0.150.5", "0.150.6", "0.150.7"},  # MAL-2026-11857
    "@servicetitan/eh-module-communication": {"0.2.1", "0.2.2", "0.2.3", "0.2.4", "0.2.5", "0.2.6", "0.2.7"},  # MAL-2026-11858
    "@servicetitan/error-boundary": {"38.1.1", "38.1.2", "38.1.3", "38.1.4", "38.1.5", "38.1.6", "38.1.7"},  # MAL-2026-11859
    "@servicetitan/eslint-config": {"38.1.1", "38.1.2", "38.1.3", "38.1.4", "38.1.5", "38.1.6", "38.1.7"},  # MAL-2026-11860
    "@servicetitan/eslint-plugin": {"38.1.1", "38.1.2", "38.1.3", "38.1.4", "38.1.5", "38.1.6", "38.1.7"},  # MAL-2026-11861
    "@servicetitan/eslint-plugin-decorators-declare": {"12.8.15", "12.8.16", "12.8.17", "12.8.18", "12.8.19", "12.8.20", "12.8.21"},  # MAL-2026-11862
    "@servicetitan/eslint-plugin-folder-schema": {"38.1.1", "38.1.2", "38.1.3", "38.1.4", "38.1.5", "38.1.6", "38.1.7"},  # MAL-2026-11863
    "@servicetitan/eslint-plugin-mobx-6": {"12.8.15", "12.8.16", "12.8.17", "12.8.18", "12.8.19", "12.8.20"},  # MAL-2026-11864
    "@servicetitan/eslint-plugin-processors-stub": {"12.8.15", "12.8.16", "12.8.17", "12.8.18", "12.8.19", "12.8.20", "12.8.21"},  # MAL-2026-11865
    "@servicetitan/examples": {"1.2.10", "1.2.11", "1.2.5", "1.2.6", "1.2.7", "1.2.8", "1.2.9"},  # MAL-2026-11866
    "@servicetitan/feature-spotlight": {"3.9.1", "3.9.2", "3.9.3", "3.9.4", "3.9.5", "3.9.6", "3.9.7"},  # MAL-2026-11867
    "@servicetitan/folder-lint": {"38.1.1", "38.1.2", "38.1.3", "38.1.4", "38.1.5", "38.1.6", "38.1.7"},  # MAL-2026-11868
    "@servicetitan/forge": {"0.5.1", "0.5.2", "0.5.3", "0.5.4", "0.5.5", "0.5.6", "0.5.7"},  # MAL-2026-11869
    "@servicetitan/form": {"41.3.1", "41.3.2", "41.3.3", "41.3.4", "41.3.5", "41.3.6", "41.3.7"},  # MAL-2026-11870
    "@servicetitan/form-state": {"41.3.1", "41.3.2", "41.3.3", "41.3.4", "41.3.5", "41.3.6", "41.3.7"},  # MAL-2026-11871
    "@servicetitan/grid": {"0.0.63", "0.0.64", "0.0.65", "0.0.66", "0.0.67", "0.0.68", "0.0.69"},  # MAL-2026-11872
    "@servicetitan/hammer-icon": {"1.2.1", "1.2.2", "1.2.3", "1.2.4", "1.2.5", "1.2.6", "1.2.7"},  # MAL-2026-11873
    "@servicetitan/hammer-react": {"1.42.2", "1.42.3", "1.42.4", "1.42.5", "1.42.6", "1.42.7", "1.42.8"},  # MAL-2026-11874
    "@servicetitan/hammer-token": {"3.1.1", "3.1.2", "3.1.3", "3.1.4", "3.1.5", "3.1.6", "3.1.7"},  # MAL-2026-11875
    "@servicetitan/hash-browser-router": {"38.1.1", "38.1.2", "38.1.3", "38.1.4", "38.1.5", "38.1.6", "38.1.7"},  # MAL-2026-11876
    "@servicetitan/help-center": {"1.0.10", "1.0.11", "1.0.12", "1.0.13", "1.0.14", "1.0.8", "1.0.9"},  # MAL-2026-11877
    "@servicetitan/html-sketchapp": {"4.2.10", "4.2.11", "4.2.12", "4.2.13", "4.2.14", "4.2.8", "4.2.9"},  # MAL-2026-11878
    "@servicetitan/install": {"38.1.1", "38.1.2", "38.1.3", "38.1.4", "38.1.5", "38.1.6", "38.1.7"},  # MAL-2026-11879
    "@servicetitan/intl": {"7.2.1", "7.2.2", "7.2.3", "7.2.4", "7.2.5", "7.2.6", "7.2.7"},  # MAL-2026-11880
    "@servicetitan/json-render-react": {"0.4.10", "0.4.11", "0.4.12", "0.4.6", "0.4.7", "0.4.8", "0.4.9"},  # MAL-2026-11881
    "@servicetitan/kendo-theme": {"0.0.27", "0.0.28", "0.0.29", "0.0.30", "0.0.31", "0.0.32", "0.0.33"},  # MAL-2026-11882
    "@servicetitan/ko-bridge": {"38.1.1", "38.1.2", "38.1.3", "38.1.4", "38.1.5", "38.1.6", "38.1.7"},  # MAL-2026-11883
    "@servicetitan/launchdarkly-service": {"38.1.1", "38.1.2", "38.1.3", "38.1.4", "38.1.5", "38.1.6", "38.1.7"},  # MAL-2026-11884
    "@servicetitan/lazy-module": {"38.1.1", "38.1.2", "38.1.3", "38.1.4", "38.1.5", "38.1.6", "38.1.7"},  # MAL-2026-11885
    "@servicetitan/ld-type-generator": {"0.2.1", "0.2.2", "0.2.3", "0.2.4", "0.2.5", "0.2.6", "0.2.7"},  # MAL-2026-11886
    "@servicetitan/line-item-editor": {"1.5.1", "1.5.2", "1.5.3", "1.5.4", "1.5.5", "1.5.6", "1.5.7"},  # MAL-2026-11887
    "@servicetitan/link-item": {"41.3.1", "41.3.2", "41.3.3", "41.3.4", "41.3.5", "41.3.6", "41.3.7"},  # MAL-2026-11888
    "@servicetitan/log-service": {"38.1.1", "38.1.2", "38.1.3", "38.1.4", "38.1.5", "38.1.6", "38.1.7"},  # MAL-2026-11889
    "@servicetitan/marketing-direct-mail-components": {"20.1.1", "20.1.2", "20.1.3", "20.1.4", "20.1.5", "20.1.6", "20.1.7"},  # MAL-2026-11890
    "@servicetitan/marketing-email-components": {"20.2.3", "20.2.4", "20.2.5", "20.2.6", "20.2.7", "20.2.8", "20.2.9"},  # MAL-2026-11891
    "@servicetitan/marketing-form": {"0.1.2", "0.1.3", "0.1.4", "0.1.5", "0.1.6", "0.1.7", "0.1.8"},  # MAL-2026-11892
    "@servicetitan/marketing-global-route": {"1.14.1", "1.14.2", "1.14.3", "1.14.4", "1.14.5", "1.14.6", "1.14.7"},  # MAL-2026-11893
    "@servicetitan/marketing-integration-widgets": {"1.0.40", "1.0.41", "1.0.42", "1.0.43", "1.0.44", "1.0.45", "1.0.46"},  # MAL-2026-11894
    "@servicetitan/marketing-route": {"1.2.1", "1.2.2", "1.2.3", "1.2.4", "1.2.5", "1.2.6", "1.2.7"},  # MAL-2026-11895
    "@servicetitan/marketing-ui": {"9.3.1", "9.3.2", "9.3.3", "9.3.4", "9.3.5", "9.3.6", "9.3.7"},  # MAL-2026-11896
    "@servicetitan/marketing-widgets": {"1.0.1", "1.0.2", "1.0.3", "1.0.4", "1.0.5", "1.0.6", "1.0.7"},  # MAL-2026-11897
    "@servicetitan/measure-sheet-data": {"2.6.1", "2.6.2", "2.6.3", "2.6.4", "2.6.5", "2.6.6", "2.6.7"},  # MAL-2026-11898
    "@servicetitan/mfe-quick-actions": {"0.5.49", "0.5.50", "0.5.51", "0.5.52", "0.5.53", "0.5.54", "0.5.55"},  # MAL-2026-11899
    "@servicetitan/micro-frontend": {"0.0.10", "0.0.4", "0.0.5", "0.0.6", "0.0.7", "0.0.8", "0.0.9"},  # MAL-2026-11900
    "@servicetitan/microfront": {"0.0.2", "0.0.3", "0.0.4", "0.0.5", "0.0.6", "0.0.7", "0.0.8"},  # MAL-2026-11901
    "@servicetitan/microfront-auth": {"0.0.10", "0.0.11", "0.0.5", "0.0.6", "0.0.7", "0.0.8", "0.0.9"},  # MAL-2026-11902
    "@servicetitan/microfront-tests": {"0.0.11", "0.0.12", "0.0.13", "0.0.14", "0.0.15", "0.0.16", "0.0.17"},  # MAL-2026-11903
    "@servicetitan/microfront-utils": {"1.4.1", "1.4.2", "1.4.3", "1.4.4", "1.4.5", "1.4.6", "1.4.7"},  # MAL-2026-11904
    "@servicetitan/modularpayments-webfields": {"1.0.53", "1.0.54", "1.0.55", "1.0.56", "1.0.57", "1.0.58", "1.0.59"},  # MAL-2026-11905
    "@servicetitan/moneyout-api-client": {"1.29.1", "1.29.2", "1.29.3", "1.29.4", "1.29.5", "1.29.6", "1.29.7"},  # MAL-2026-11906
    "@servicetitan/mpa-components": {"2.5.1", "2.5.2", "2.5.3", "2.5.4", "2.5.5", "2.5.6", "2.5.7"},  # MAL-2026-11907
    "@servicetitan/navigation": {"14.1.1", "14.1.2", "14.1.3", "14.1.4", "14.1.5", "14.1.6", "14.1.7"},  # MAL-2026-11908
    "@servicetitan/notifications": {"41.3.1", "41.3.2", "41.3.3", "41.3.4", "41.3.5", "41.3.6", "41.3.7"},  # MAL-2026-11909
    "@servicetitan/onboarding-ui": {"18.5.1", "18.5.2", "18.5.3", "18.5.4", "18.5.5", "18.5.6", "18.5.7"},  # MAL-2026-11910
    "@servicetitan/quick-actions": {"1.15.2", "1.15.3", "1.15.4", "1.15.5", "1.15.6", "1.15.7", "1.15.8"},  # MAL-2026-11911
    "@servicetitan/react-hooks": {"7.7.1", "7.7.2", "7.7.3", "7.7.4", "7.7.5", "7.7.6", "7.7.7"},  # MAL-2026-11912
    "@servicetitan/react-ioc": {"38.1.1", "38.1.2", "38.1.3", "38.1.4", "38.1.5", "38.1.6", "38.1.7"},  # MAL-2026-11913
    "@servicetitan/responsive": {"6.1.1", "6.1.2", "6.1.3", "6.1.4", "6.1.5", "6.1.6", "6.1.7"},  # MAL-2026-11914
    "@servicetitan/restrict-imports": {"38.1.1", "38.1.2", "38.1.3", "38.1.4", "38.1.5", "38.1.6", "38.1.7"},  # MAL-2026-11915
    "@servicetitan/schema-comparison": {"0.1.3", "0.1.4", "0.1.5", "0.1.6", "0.1.7", "0.1.8", "0.1.9"},  # MAL-2026-11916
    "@servicetitan/skeleton": {"9.2.10", "9.2.4", "9.2.5", "9.2.6", "9.2.7", "9.2.8", "9.2.9"},  # MAL-2026-11917
    "@servicetitan/standalone-core-feature-gates": {"1.11.10", "1.11.4", "1.11.5", "1.11.6", "1.11.7", "1.11.8", "1.11.9"},  # MAL-2026-11918
    "@servicetitan/standalone-feature-flags": {"2.3.2", "2.3.3", "2.3.4", "2.3.5", "2.3.6", "2.3.7", "2.3.8"},  # MAL-2026-11919
    "@servicetitan/standalone-root": {"1.11.3", "1.11.4", "1.11.5", "1.11.6", "1.11.7", "1.11.8", "1.11.9"},  # MAL-2026-11920
    "@servicetitan/standalone-tm-api": {"1.1.1", "1.1.2", "1.1.3", "1.1.4", "1.1.5", "1.1.6", "1.1.7"},  # MAL-2026-11921
    "@servicetitan/standalone-ui": {"2.2.10", "2.2.4", "2.2.5", "2.2.6", "2.2.7", "2.2.8", "2.2.9"},  # MAL-2026-11922
    "@servicetitan/startup": {"38.1.1", "38.1.2", "38.1.3", "38.1.4", "38.1.5", "38.1.6", "38.1.7"},  # MAL-2026-11923
    "@servicetitan/startup-jest": {"2.2.1", "2.2.2", "2.2.3", "2.2.4", "2.2.5", "2.2.6", "2.2.7"},  # MAL-2026-11924
    "@servicetitan/startup-mfe-compat": {"0.5.1", "0.5.2", "0.5.3", "0.5.4", "0.5.5", "0.5.6", "0.5.7"},  # MAL-2026-11925
    "@servicetitan/startup-utils": {"38.1.1", "38.1.2", "38.1.3", "38.1.4", "38.1.5", "38.1.6", "38.1.7"},  # MAL-2026-11926
    "@servicetitan/stylelint-config": {"38.1.1", "38.1.2", "38.1.3", "38.1.4", "38.1.5", "38.1.6", "38.1.7"},  # MAL-2026-11927
    "@servicetitan/suppress-warnings": {"34.0.1", "34.1.0", "34.2.0", "34.2.1", "34.3.0", "34.3.0-beta.0", "34.3.0-beta.1", "34.3.0-beta.2", "35.0.0", "35.1.0", "35.2.0", "35.3.0", "36.0.0", "36.1.0", "36.1.1", "36.1.1-beta.1", "36.2.0", "36.3.0", "36.3.1", "36.4.0", "37.0.0", "37.0.1", "37.0.2", "38.0.0", "38.1.0", "38.1.1", "38.1.2", "38.1.3", "38.1.4", "38.1.5", "38.1.6", "38.1.7"},  # MAL-2026-11928
    "@servicetitan/table": {"41.3.1", "41.3.2", "41.3.3", "41.3.4", "41.3.5", "41.3.6", "41.3.7"},  # MAL-2026-11929
    "@servicetitan/tanstack-query-mobx": {"6.2.1", "6.2.2", "6.2.3", "6.2.4", "6.2.5", "6.2.6", "6.2.7"},  # MAL-2026-11930
    "@servicetitan/temporal-lite": {"3.4.1", "3.4.2", "3.4.3", "3.4.4", "3.4.5", "3.4.6", "3.4.7"},  # MAL-2026-11931
    "@servicetitan/testing-library": {"6.6.1", "6.6.2", "6.6.3", "6.6.4", "6.6.5", "6.6.6", "6.6.7"},  # MAL-2026-11932
    "@servicetitan/thoughtspot-theme": {"1.7.1", "1.7.2", "1.7.3", "1.7.4", "1.7.5", "1.7.6", "1.7.7"},  # MAL-2026-11933
    "@servicetitan/time-zones": {"3.8.1", "3.8.2", "3.8.3", "3.8.4", "3.8.5", "3.8.6", "3.8.7"},  # MAL-2026-11934
    "@servicetitan/titan-chat-ui": {"7.1.3", "7.1.4", "7.1.5", "7.1.6", "7.1.7", "7.1.8", "7.1.9"},  # MAL-2026-11935
    "@servicetitan/titan-chat-ui-anvil2": {"9.0.1", "9.0.2", "9.0.3", "9.0.4", "9.0.5", "9.0.6", "9.0.7"},  # MAL-2026-11936
    "@servicetitan/titan-chat-ui-common": {"9.0.1", "9.0.2", "9.0.3", "9.0.4", "9.0.5", "9.0.6", "9.0.7"},  # MAL-2026-11937
    "@servicetitan/titan-chat-ui-cypress": {"2.1.3", "2.1.4", "2.1.5", "2.1.6", "2.1.7", "2.1.8", "2.1.9"},  # MAL-2026-11938
    "@servicetitan/titan-chatbot-api": {"9.0.1", "9.0.2", "9.0.3", "9.0.4", "9.0.5", "9.0.6", "9.0.7"},  # MAL-2026-11939
    "@servicetitan/titan-chatbot-client": {"2.1.3", "2.1.4", "2.1.5", "2.1.6", "2.1.7", "2.1.8", "2.1.9"},  # MAL-2026-11940
    "@servicetitan/titan-chatbot-ui": {"7.1.3", "7.1.4", "7.1.5", "7.1.6", "7.1.7", "7.1.8", "7.1.9"},  # MAL-2026-11941
    "@servicetitan/titan-chatbot-ui-anvil2": {"9.0.1", "9.0.2", "9.0.3", "9.0.4", "9.0.5", "9.0.6", "9.0.7"},  # MAL-2026-11942
    "@servicetitan/titan-chatbot-ui-cypress": {"9.0.1", "9.0.2", "9.0.3", "9.0.4", "9.0.5", "9.0.6", "9.0.7"},  # MAL-2026-11943
    "@servicetitan/tokens": {"12.9.1", "12.9.2", "12.9.3", "12.9.4", "12.9.5", "12.9.6", "12.9.7"},  # MAL-2026-11944
    "@servicetitan/toolbelt-shared-registry": {"1.14.1", "1.14.2", "1.14.3", "1.14.4", "1.14.5", "1.14.6", "1.14.7"},  # MAL-2026-11945
    "@servicetitan/uikit-docs": {"22.11.1", "22.11.2", "22.11.3", "22.11.4", "22.11.5", "22.11.6", "22.11.7"},  # MAL-2026-11946
    "@servicetitan/unit-tests": {"0.0.2", "0.0.3", "0.0.4", "0.0.5", "0.0.6", "0.0.7", "0.0.8"},  # MAL-2026-11947
    "@servicetitan/va-mfe-loader": {"1.1.1", "1.1.2", "1.1.3", "1.1.4", "1.1.5", "1.1.6", "1.1.7"},  # MAL-2026-11948
    "@servicetitan/web-components": {"38.1.1", "38.1.2", "38.1.3", "38.1.4", "38.1.5", "38.1.6", "38.1.7"},  # MAL-2026-11949
    "@servicetitan/widget-platform": {"5.6.1", "5.6.2", "5.6.3", "5.6.4", "5.6.5", "5.6.6", "5.6.7"},  # MAL-2026-11950
    "@servicetitan/widget-platform-monolith": {"5.6.1", "5.6.2", "5.6.3", "5.6.4", "5.6.5", "5.6.6", "5.6.7"},  # MAL-2026-11951
    # @zzzgenesis00/* crypto-wallet key-stealer scope Aug 4–5 2026 (14 packages)
    # Attacker-controlled scope publishing fake impersonators of popular crypto/Web3 libraries
    # (bip39, ethers, solana-web3, hdkey, xrp-lib, etc.) that exfiltrate wallet keys and
    # mnemonics. All packages are new publishes with no legitimate history.
    # OSV MAL-2026-11515, 11529–11534, 11994, 12030–12031, 12055–12058
    "@zzzgenesis00/bip39-generator": {"3.1.2"},  # MAL-2026-11515
    "@zzzgenesis00/bip39-mnemonic": {"2.3.1"},  # MAL-2026-12030
    "@zzzgenesis00/crypto-config": {"2.0.1"},  # MAL-2026-11529
    "@zzzgenesis00/docker-api-client": {"2.0.2"},  # MAL-2026-12055
    "@zzzgenesis00/etherjs": {"6.15.0"},  # MAL-2026-11530
    "@zzzgenesis00/ethers-wallet": {"6.13.5"},  # MAL-2026-12031
    "@zzzgenesis00/hdkey-wallet": {"2.1.0"},  # MAL-2026-11531
    "@zzzgenesis00/mnemonic-to-key": {"1.2.0"},  # MAL-2026-12056
    "@zzzgenesis00/playwrite": {"1.48.0"},  # MAL-2026-12057
    "@zzzgenesis00/solana-wallet-adapter": {"0.18.0"},  # MAL-2026-11532
    "@zzzgenesis00/solana-web3": {"2.1.0"},  # MAL-2026-11533
    "@zzzgenesis00/spl-token-utils": {"1.4.2"},  # MAL-2026-12058
    "@zzzgenesis00/web3-provider-engine": {"16.0.5"},  # MAL-2026-11994
    "@zzzgenesis00/xrp-lib": {"2.14.0"},  # MAL-2026-11534
    # @jsimplify/* — misc malware Aug 4–5 2026
    "@jsimplify/errno": set(),  # MAL-2026-12006
    # @ks-openclaw/* — misc malware Aug 4–5 2026
    "@ks-openclaw/kim": {"99.0.0", "99.0.1"},  # MAL-2026-11528
    # @tuluax/* — misc malware Aug 4–5 2026
    "@tuluax/errb": {"3.0.1"},  # MAL-2026-11993
    # beaver-ui-* continuation — additional fake UI component packages Aug 4–5 2026
    # Extends the beaver-ui cluster from MAL-2026-11506/11507/11508/11509/11510
    # OSV MAL-2026-11522, 12034, 12060
    "beaver-ui-card-large": {"12.4.3", "9.6.2", "9.6.3", "9.6.4", "9.6.5"},  # MAL-2026-12060
    "beaver-ui-form": {"34.9.1"},  # MAL-2026-11522
    "beaver-ui-form-modal": {"12.7.6", "34.6.3"},  # MAL-2026-12034
    # bigops-* continuation — additional fake bigops dep-confusion packages Aug 4–5 2026
    # Extends bigops-chat-messages from MAL-2026-11511; versions at 35.x
    # OSV MAL-2026-11535, 12035–12038, 12061
    "bigops-auth-utils": {"35.4.5"},  # MAL-2026-12035
    "bigops-backend": {"35.8.3"},  # MAL-2026-11535
    "bigops-chat-tmsg": {"35.8.5"},  # MAL-2026-12036
    "bigops-create-manifest": {"35.2.4"},  # MAL-2026-12037
    "bigops-customer": {"35.1.1"},  # MAL-2026-12038
    "bigops-eslint": {"35.9.5"},  # MAL-2026-12061
    # Tinkoff/T-Bank dep-confusion cluster Aug 4–5 2026
    # Private packages of Tinkoff (Russian neobank) published to public npm at version 20.x,
    # targeting internal CI/CD dependency resolution. OSV MAL-2026-11549–11550, 12041–12042,
    # 12044–12046, 12048–12053, 12063, 12069–12077, 12079
    "checkout-create-pos-order-am": {"20.9.5"},  # MAL-2026-12063
    "eacq-payform-core": {"20.3.6"},  # MAL-2026-11538
    "nxify-unic": {"20.3.2"},  # MAL-2026-12069
    "platform-ui-codemods": {"20.6.7"},  # MAL-2026-12041
    "platform-ui-island": {"20.5.9"},  # MAL-2026-12042
    "shopping-shared-atom-mobile-cart-counter": {"20.6.6"},  # MAL-2026-12070
    "sotqa-test": {"20.3.8"},  # MAL-2026-12071
    "specials-mvno-client": {"20.9.8"},  # MAL-2026-12044
    "specials-obid-webpack": {"20.5.4"},  # MAL-2026-12072
    "sso-tramvai-module-context-auth": {"20.4.5"},  # MAL-2026-12073
    "statist-browser-typed-client-hra.workplacer.events": {"20.9.1"},  # MAL-2026-12045
    "statist-browser-typed-client-nfs.grocery.mobile.events": {"20.3.3"},  # MAL-2026-12074
    "statist-browser-typed-client-test.jumpwork.circuitbreaker": {"20.8.2"},  # MAL-2026-12046
    "tinkoff-boxy-desktop-features-banner": {"20.2.4"},  # MAL-2026-12048
    "tinkoff-boxy-mobile-vivid-heading": {"20.7.5"},  # MAL-2026-12075
    "tinkoff-cache-path": {"20.8.3"},  # MAL-2026-12076
    "tinkoff-component-infopanel": {"20.8.3"},  # MAL-2026-12049
    "tinkoff-statist-browser-typed-client-sme.compliance.web.events": {"20.4.4"},  # MAL-2026-12077
    "tinkoff-statist-browser-typed-client-sme.reporting.reporting": {"20.5.4"},  # MAL-2026-12050
    "tinkoff-terminal-kit-carousel": {"20.6.3"},  # MAL-2026-11549
    "tinkoff-ui-action": {"20.5.7"},  # MAL-2026-12051
    "tramvai-tinkoff-module-legacy-popup": {"20.4.9"},  # MAL-2026-12052
    "tui-react-mobile-styles": {"20.8.7"},  # MAL-2026-12053
    "volna-boxy-di-test": {"20.3.8"},  # MAL-2026-12079
    # streak-* dep-confusion cluster Aug 4–5 2026 (8 packages targeting Streak CRM)
    # OSV MAL-2026-11527–11548, 11999–12003, 12047
    "streak-day-utils": {"1.0.0"},  # MAL-2026-12047
    "streak-map-metrics": {"1.0.0"},  # MAL-2026-11999
    "streak-math-abz": {"1.0.0"},  # MAL-2026-11548
    "streak-math-metrics": {"1.0.0"},  # MAL-2026-12000
    "streak-metricazbd": {"1.0.0"},  # MAL-2026-12001
    "streak-metricsaz": {"1.0.0"},  # MAL-2026-11527
    "streak-metricsazb": {"1.0.0"},  # MAL-2026-12002
    "streak-test-mathcore": {"1.0.0"},  # MAL-2026-12003
    # sextant-cli dep-confusion cluster Aug 4–5 2026 (4 platform binaries)
    # OSV MAL-2026-11997, 12028–12029, 12043
    "sextant-cli-darwin-amd64": {"0.0.1-rc34"},  # MAL-2026-12028
    "sextant-cli-darwin-arm64": {"0.0.1-rc24"},  # MAL-2026-11997
    "sextant-cli-linux-amd64": {"0.0.1-rc26", "0.0.1-rc32", "0.0.1-rc34"},  # MAL-2026-12029
    "sextant-cli-linux-arm64": {"0.0.1-rc11", "0.0.1-rc12", "0.0.1-rc25", "0.0.1-rc29"},  # MAL-2026-12043
    # simple-date-formatter-* continuation — additional fake util packages Aug 4–5 2026
    # Extends cluster from MAL-2026-11483/11484/11485/11501/11502; OSV MAL-2026-11543–11547, 11998
    "simple-date-formatter-new-5": {"1.0.0"},  # MAL-2026-11543
    "simple-date-formatter-util-10": {"1.0.0"},  # MAL-2026-11544
    "simple-date-formatter-util-15": {"1.0.0"},  # MAL-2026-11545
    "simple-date-formatter-util-6": {"1.0.0"},  # MAL-2026-11546
    "simple-date-formatter-util-7": {"1.0.0"},  # MAL-2026-11998
    "simple-date-formatter-util-9": {"1.0.0"},  # MAL-2026-11547
    # nagix-* cluster Aug 4–5 2026 (nagix-node, nagix-nodejs, nagixjs)
    # OSV MAL-2026-11525–11526, 11541
    "nagix-node": {"2.1.6"},  # MAL-2026-11525
    "nagix-nodejs": {"2.1.6"},  # MAL-2026-11526
    "nagixjs": {"2.1.6"},  # MAL-2026-11541
    # Crypto hardware wallet fake npm packages Aug 5 2026
    # Fake impersonators of hardware wallet utility libraries (Coldcard/HWI/Ledger/Trezor);
    # OSV MAL-2026-12064, 12067–12068, 12078
    "ckcc-protocol": {"1.0.0"},  # MAL-2026-12064
    "hwi-lib": {"1.0.0", "1.0.1"},  # MAL-2026-12067
    "ledger-lib": {"1.0.0"},  # MAL-2026-12068
    "trezor-lib": {"1.0.0"},  # MAL-2026-12078
    # Miscellaneous npm malware Aug 4–5 2026 (no cluster pattern)
    # OSV MAL-2026-11192, 11517–11518, 11536–11539, 11542, 11993–11998, 12032–12033,
    #      12039–12040, 12054, 12059, 12061–12062, 12065–12066
    "add-two-numbers-x7q9m": {"1.0.0"},  # MAL-2026-12032
    "aedes_clusters": {"1.0.1"},  # MAL-2026-12033
    "approval-guardian": {"1.0.1", "1.0.6"},  # MAL-2026-11995
    "bcore-bravo-eslint-config": {"12.5.7", "9.5.6", "9.5.7", "9.5.8", "9.5.9"},  # MAL-2026-12059
    "boardwalk-js-tests": {"1.1.1"},  # MAL-2026-12062
    "cors-version": set(),  # MAL-2026-12026
    "data-format-helper": {"1.0.0", "1.0.1"},  # MAL-2026-12039
    "discord-vibegrations-api-helpers": {"1.0.0"},  # MAL-2026-11536
    "discord-vibegrations-api-natives": {"1.0.5"},  # MAL-2026-11537
    "emulative": {"1.0.1"},  # MAL-2026-11996
    "entropyeasybots": {"2.0.2"},  # MAL-2026-11539
    "exnesss": {"0.0.1"},  # MAL-2026-11518
    "forge-extended": {"1.0.1"},  # MAL-2026-12040
    "greatcall-customers-commandapi": {"99.0.0"},  # MAL-2026-12065
    "hubert-application-get-document-preview-am": {"20.4.6"},  # MAL-2026-11540
    "hubert-appointment-v2-task-create-am": {"20.4.4"},  # MAL-2026-12066
    "internallib_v688": set(),  # MAL-2026-11517
    "osinthell": {"1.0.1", "1.0.5", "1.6.6", "1.6.9", "1.9.1", "1.9.5"},  # MAL-2026-11542
    "tailwind-anime": set(),  # MAL-2026-12027
    "test2221": {"2.2.4"},  # MAL-2026-11192
    "twork-data-services-aggregator-api-v2-data-view-company-company-profile-mf-data-transformer": {"20.5.3"},  # MAL-2026-11550
    "uibabai": {"5.7.5"},  # MAL-2026-12054
    "vitest-preview-pro": set(),  # MAL-2026-12004 (SEMVER introduced:0 — any-version wildcard)
    "webdev-conf": {"5.0.0"},  # MAL-2026-12005

    # @wethenorth12 crypto-wallet-drainer campaign Aug 5 2026
    # Attacker-controlled scope publishing fake Web3/DeFi SDK impersonators designed to
    # exfiltrate private keys, mnemonics, and wallet credentials. 23 packages across
    # BIP39, Ethereum, Solana, NEAR, TRON, XRP ecosystems; also includes infra packages
    # (docker-api-client, env-loader, playwrite) as delivery vectors.
    # OSV MAL-2026-12085 through MAL-2026-12107
    "@wethenorth12/bip39-generator": {"3.1.2"},       # MAL-2026-12085
    "@wethenorth12/bip39-mnemonic": {"2.3.1"},         # MAL-2026-12086
    "@wethenorth12/bitcoin-lib": {"6.1.7"},             # MAL-2026-12087
    "@wethenorth12/bitcoinjs-wallet": {"5.4.2"},        # MAL-2026-12088
    "@wethenorth12/crypto-config": {"2.0.1"},           # MAL-2026-12089
    "@wethenorth12/docker-api-client": {"2.0.2"},       # MAL-2026-12090
    "@wethenorth12/env-loader": {"4.2.0"},              # MAL-2026-12091
    "@wethenorth12/etherjs": {"6.15.0", "6.15.1", "6.15.2", "6.15.3", "6.15.4"},  # MAL-2026-12092
    "@wethenorth12/ethers-signer": {"3.2.1"},           # MAL-2026-12093
    "@wethenorth12/ethers-wallet": {"6.13.5"},          # MAL-2026-12094
    "@wethenorth12/hd-key-generator": {"1.6.3"},        # MAL-2026-12095
    "@wethenorth12/hdkey-wallet": {"2.1.0"},            # MAL-2026-12096
    "@wethenorth12/mnemonic-to-key": {"1.2.0"},         # MAL-2026-12097
    "@wethenorth12/near-api": {"3.0.1"},                # MAL-2026-12098
    "@wethenorth12/playwrite": {"1.48.0"},              # MAL-2026-12099
    "@wethenorth12/solana-spl-token": {"0.4.0"},        # MAL-2026-12100
    "@wethenorth12/solana-wallet-adapter": {"0.18.0"},  # MAL-2026-12101
    "@wethenorth12/solana-web3": {"2.1.0"},             # MAL-2026-12102
    "@wethenorth12/spl-token-utils": {"1.4.2"},         # MAL-2026-12103
    "@wethenorth12/test-fresh": {"1.0.0"},              # MAL-2026-12104
    "@wethenorth12/tronweb3": {"5.3.2"},                # MAL-2026-12105
    "@wethenorth12/web3-provider-engine": {"16.0.5"},   # MAL-2026-12106
    "@wethenorth12/web3-utils-crypto": {"1.10.4"},      # MAL-2026-12107

    # @zzzcrypto crypto-stealer scope Aug 5 2026
    # Companion scope to @wethenorth12; 5 packages mirroring the same BTC/ETH/Solana/XRP
    # fake-SDK credential-theft pattern. OSV MAL-2026-13211 through MAL-2026-13215
    "@zzzcrypto/bitcoin-lib": {"6.1.7"},       # MAL-2026-13211
    "@zzzcrypto/etherjs": {"6.15.4"},          # MAL-2026-13212
    "@zzzcrypto/playwrite": {"1.48.0"},        # MAL-2026-13213
    "@zzzcrypto/solana-spl-token": {"0.4.0"},  # MAL-2026-13214
    "@zzzcrypto/xrp-lib": {"2.14.0"},          # MAL-2026-13215

    # @cryptosrvc / @shiftmarkets exchange SDK typosquat pair Aug 5 2026
    # Two scopes publishing identical fake "shift-exchange" and "no-brainer-sdk" packages,
    # impersonating legitimate ShiftMarkets crypto exchange SDKs. Versions bump at .9.9
    # (1.9.9, 2.9.9, 3.9.9) signal dependency confusion intent.
    # OSV MAL-2026-12315/12316/12317/12329/12508/12509
    "@cryptosrvc/no-brainer-sdk": {"1.0.18"},                        # MAL-2026-12315
    "@cryptosrvc/shift-exchange-root": {"1.9.9", "2.9.9", "3.9.9"}, # MAL-2026-12316
    "@cryptosrvc/shift-sdk-v4": {"1.0.77"},                          # MAL-2026-12317
    "@shiftmarkets/no-brainer-sdk": {"1.0.18"},                      # MAL-2026-12508
    "@shiftmarkets/shift-exchange-root": {"1.9.9", "2.9.9", "3.9.9"}, # MAL-2026-12509
    "@shiftmarkets/shift-sdk-v4": {"1.0.77"},                        # MAL-2026-12329

    # @zahlen checkout-flow malware pair Aug 5–6 2026
    # Two packages impersonating a payment/checkout flow library.
    # OSV MAL-2026-12332/12333
    "@zahlen/checkout-angular": {"0.1.4"},  # MAL-2026-12332
    "@zahlen/checkout-react": {"0.1.1"},    # MAL-2026-12333

    # @copilot-mcp/apex MCP server impersonator Aug 5 2026
    # Impersonates a GitHub Copilot MCP (Model Context Protocol) server extension.
    # 13 versions published; OSV MAL-2026-12314
    "@copilot-mcp/apex": {"1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4", "1.0.5",
                          "1.0.6", "1.0.7", "1.0.8", "1.0.16", "1.0.17", "1.0.21",
                          "1.0.22"},  # MAL-2026-12314

    # Standalone crypto-wallet-drainer typosquats Aug 5 2026
    # Bare (un-scoped) versions of the same fake Web3 SDK packages as @wethenorth12/
    # and related scopes. All are pure-malware impersonators with no legitimate
    # prior history. OSV MAL-2026-12109/12111/13257/13258/13343/13354/12490/12495/12498
    "bip32-js": {"1.0.0", "1.0.1", "1.0.2"},                    # MAL-2026-12109
    "bip39-generator": {"3.1.2"},                                # MAL-2026-13257
    "bitcoinjs-wallet": {"5.4.2"},                               # MAL-2026-13258
    "ethers-lib": {"1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4"}, # MAL-2026-12111
    "ethers-signer": {"3.2.1"},                                  # MAL-2026-13343
    "uniswap-sdk-v4": {"1.0.0"},                                 # MAL-2026-12490
    "viem-toolkit": {"1.0.0"},                                   # MAL-2026-12495
    "wagmi-react": {"1.0.0"},                                    # MAL-2026-12498
    "web3-utils-crypto": {"1.10.4"},                             # MAL-2026-13354

    # akamai sensor typosquats Aug 5 2026
    # Four packages impersonating Akamai bot-detection sensor scripts.
    # OSV MAL-2026-12139/12337/13216/13217
    "akamai-sensorv1": {"1.0.0"},   # MAL-2026-13216
    "akamai-sensorv2": {"1.0.0"},   # MAL-2026-13217
    "akamai-sensorv3": {"1.0.0"},   # MAL-2026-12139
    "akamaijs-sensor": {"2.0.0", "3.0.0"},   # MAL-2026-12337

    # async-mutex typosquats Aug 5–6 2026
    # Three packages typosquatting the popular `async-mutex` concurrency library.
    # async-mutex-lock uses ranges: introduced 0 (any version malicious).
    # OSV MAL-2026-12339/12513/12514
    "async-mutex-hook": {"2.1.0"},  # MAL-2026-12339
    "async-mutex-lock": set(),      # MAL-2026-12513
    "async-mutex-v3": {"3.1.0"},    # MAL-2026-12514

    # tailwind scrollbar typosquats Aug 6 2026
    # Two packages impersonating the popular `tailwindcss-scrollbar-hide` / `tailwind-scrollbar`
    # utility plugins. Both have ranges: introduced 0 (entire history is malicious).
    # OSV MAL-2026-12116/12224
    "tailwind-hide-scrollbar": set(),      # MAL-2026-12116
    "tailwindcss-scrollbar-hide": set(),   # MAL-2026-12224

    # alipclutch-baileys WhatsApp bot credential typosquat Aug 5 2026
    # Typosquats the legitimate @whiskeysockets/baileys WhatsApp library;
    # 5 versions exfiltrate WhatsApp session credentials. OSV MAL-2026-12108
    "alipclutch-baileys": {"8.6.58", "8.6.59", "8.6.60", "8.6.75", "8.6.77"},  # MAL-2026-12108

    # anthropic-setup malware Aug 5 2026
    # Impersonates an Anthropic SDK setup helper; single version 1.0.1.
    # OSV MAL-2026-12510
    "anthropic-setup": {"1.0.1"},  # MAL-2026-12510

    # aws-sdk-v4 AWS SDK typosquat Aug 5 2026
    # Impersonates the AWS SDK v3 under a fake "v4" name; single version 3.650.0
    # (mirrors the real @aws-sdk/* version numbering). OSV MAL-2026-13218
    "aws-sdk-v4": {"3.650.0"},  # MAL-2026-13218

    # streak-* postinstall credential cluster continuation Aug 5–6 2026
    # Three more packages extending the existing streak-math / streak-metrics cluster.
    # streak-calc-metrics and streak-math-calc have ranges: introduced 0 (any version).
    # OSV MAL-2026-12114/12115/12311
    "streak-calc-math": {"1.0.0"},   # MAL-2026-12114
    "streak-calc-metrics": set(),    # MAL-2026-12311
    "streak-math-calc": set(),       # MAL-2026-12115

    # simple-date-formatter-* typosquat cluster continuation Aug 5 2026
    # Extends the existing simple-date-formatter-* dep-confusion cluster (new-5/util-6
    # through util-10 already tracked). 12 additional variants at version 1.0.0.
    # OSV MAL-2026-12194 through MAL-2026-12206
    "simple-date-formatter-new-2": {"1.0.0"},   # MAL-2026-12194
    "simple-date-formatter-new-3": {"1.0.0"},   # MAL-2026-12195
    "simple-date-formatter-new-4": {"1.0.0"},   # MAL-2026-12196
    "simple-date-formatter-new-6": {"1.0.0"},   # MAL-2026-12197
    "simple-date-formatter-new-7": {"1.0.0"},   # MAL-2026-12198
    "simple-date-formatter-new-8": {"1.0.0"},   # MAL-2026-12199
    "simple-date-formatter-util-8": {"1.0.0"},  # MAL-2026-12206
    "simple-date-formatter-util-11": {"1.0.0"}, # MAL-2026-12200
    "simple-date-formatter-util-12": {"1.0.0"}, # MAL-2026-12201
    "simple-date-formatter-util-13": {"1.0.0"}, # MAL-2026-12202
    "simple-date-formatter-util-14": {"1.0.0"}, # MAL-2026-12203
    "simple-date-formatter-util-16": {"1.0.0"}, # MAL-2026-12204

# Tinkoff/T-Bank / BigOps / DevPlatform dep-confusion continuation Aug 5–7 2026
    # 229 additional fake internal npm packages across the Tinkoff ecosystem
    # (tinkoff-*, bigops-*, beaver-ui-*, bnpl-*, dolyame-boxy-*, devplatform-*, statist-*,
    # pfa-*, pfp-*, sme-*, tramvai-*, twork-*, eventea-*, tcb-web-*, and related tooling).
    # All have ranges: introduced 0 (pure dep-confusion malware, no legitimate versions).
    # OSV MAL-2026-12145 through MAL-2026-13379
    "beaver-ui-form-object": set(),  # MAL-2026-12145
    "beaver-ui-hooks": set(),  # MAL-2026-12146
    "beaver-ui-list": set(),  # MAL-2026-12817
    "beaver-ui-multi-select-with-all": set(),  # MAL-2026-12818
    "beaver-ui-object-card": set(),  # MAL-2026-12819
    "beaver-ui-pagination": set(),  # MAL-2026-12820
    "beaver-ui-popover-card": set(),  # MAL-2026-12821
    "beaver-ui-search-dropdown": set(),  # MAL-2026-12822
    "beaver-ui-side-navigation": set(),  # MAL-2026-12823
    "beaver-ui-smart-filter": set(),  # MAL-2026-12824
    "beaver-ui-split-view": set(),  # MAL-2026-12825
    "beaver-ui-storybook-addon-code-description": set(),  # MAL-2026-12826
    "beaver-ui-subheader": set(),  # MAL-2026-12827
    "beaver-ui-table": set(),  # MAL-2026-12828
    "bi-core-bi-core-core": set(),  # MAL-2026-12829
    "bigops-activity-headers-interceptor": set(),  # MAL-2026-12830
    "bigops-alerts-widget": set(),  # MAL-2026-12831
    "bigops-api": set(),  # MAL-2026-12832
    "bigops-api-customer": set(),  # MAL-2026-12833
    "bigops-api-mobile": set(),  # MAL-2026-12148
    "bigops-auth": set(),  # MAL-2026-12149
    "bigops-status-selection": set(),  # MAL-2026-13251
    "bigops-storio": set(),  # MAL-2026-13252
    "bigops-storio-ngrx": set(),  # MAL-2026-13253
    "bigops-storio-ngrx-component-store": set(),  # MAL-2026-13254
    "bigops-storio-schematics": set(),  # MAL-2026-13255
    "bigops-storio-store-adapter": set(),  # MAL-2026-13256
    "bigops-stylelint": set(),  # MAL-2026-12834
    "bigops-tasks": set(),  # MAL-2026-12835
    "bigops-tasks-client": set(),  # MAL-2026-12836
    "bigops-tcrm-auth": set(),  # MAL-2026-12837
    "bigops-tcrm-identity-auth": set(),  # MAL-2026-12838
    "bigops-telephony": set(),  # MAL-2026-12840
    "bigops-telephony-client": set(),  # MAL-2026-12841
    "bigops-telephony-ui": set(),  # MAL-2026-12842
    "bigops-telephony-ui-adapter": set(),  # MAL-2026-12843
    "bigops-timeline-ui": set(),  # MAL-2026-12845
    "bigops-tinkoff-telephony-mock": set(),  # MAL-2026-12847
    "bigops-tslint": set(),  # MAL-2026-12848
    "bigops-ui-kit": set(),  # MAL-2026-12849
    "bigops-ui-kit-styles": set(),  # MAL-2026-12850
    "bigops-ui-themes": set(),  # MAL-2026-12851
    "bigops-videocalls": set(),  # MAL-2026-12854
    "bigops-voximplant": set(),  # MAL-2026-12172
    "bigops-watchdog-worker": set(),  # MAL-2026-12856
    "bigops-watermark": set(),  # MAL-2026-12857
    "bigops-web-analytics": set(),  # MAL-2026-12858
    "blocks-sahred-atom-mobile-app-bar-action": set(),  # MAL-2026-12859
    "bnpl-api": set(),  # MAL-2026-12860
    "bnpl-blocks-analytics": set(),  # MAL-2026-12861
    "bnpl-blocks-atom-bnpl-action-card": set(),  # MAL-2026-12862
    "bnpl-blocks-atom-bnpl-anchor-menu": set(),  # MAL-2026-12863
    "bnpl-blocks-atom-bnpl-badge": set(),  # MAL-2026-12864
    "bnpl-blocks-atom-bnpl-base-popup": set(),  # MAL-2026-12865
    "bnpl-blocks-atom-bnpl-breadcrumbs": set(),  # MAL-2026-12866
    "bnpl-blocks-atom-bnpl-button": set(),  # MAL-2026-12867
    "bnpl-blocks-atom-bnpl-card": set(),  # MAL-2026-12868
    "bnpl-blocks-atom-bnpl-dangerously-html": set(),  # MAL-2026-12870
    "bnpl-blocks-atom-bnpl-dolyame-button": set(),  # MAL-2026-12871
    "bnpl-blocks-atom-bnpl-dropdown": set(),  # MAL-2026-12872
    "bnpl-blocks-atom-bnpl-email-form": set(),  # MAL-2026-12873
    "bnpl-blocks-atom-bnpl-fade-overflow": set(),  # MAL-2026-12874
    "bnpl-blocks-atom-bnpl-feedback": set(),  # MAL-2026-12875
    "bnpl-blocks-atom-bnpl-image": set(),  # MAL-2026-12876
    "bnpl-blocks-atom-bnpl-image-popup": set(),  # MAL-2026-12877
    "bnpl-blocks-atom-bnpl-info-card": set(),  # MAL-2026-12878
    "bnpl-blocks-atom-bnpl-integrations-breadcrumbs": set(),  # MAL-2026-12879
    "bnpl-blocks-atom-bnpl-link-avatar": set(),  # MAL-2026-12880
    "bnpl-blocks-atom-bnpl-navigation-arrow": set(),  # MAL-2026-12881
    "bnpl-blocks-atom-bnpl-news-card": set(),  # MAL-2026-12882
    "boxy-fixture-allure": set(),  # MAL-2026-12342
    "cardsmobile-collection": set(),  # MAL-2026-12346
    "deposits-overnight": set(),  # MAL-2026-12361
    "devplatform-api-v2-resource-mock": set(),  # MAL-2026-12695
    "devplatform-auth-client": set(),  # MAL-2026-12698
    "devplatform-cli-plugin-lint": set(),  # MAL-2026-12702
    "devplatform-data-table": set(),  # MAL-2026-12708
    "devplatform-http-client": set(),  # MAL-2026-12712
    "devplatform-humanize-network-error": set(),  # MAL-2026-12713
    "devplatform-i18n": set(),  # MAL-2026-12714
    "devplatform-jscodeshift-utils": set(),  # MAL-2026-12719
    "devplatform-npm-versions-checker": set(),  # MAL-2026-12721
    "devplatform-nx-husky": set(),  # MAL-2026-12724
    "devplatform-nx-react": set(),  # MAL-2026-12726
    "devplatform-nx-stylelint": set(),  # MAL-2026-12728
    "devplatform-po-declaration-generator": set(),  # MAL-2026-12731
    "devplatform-react-form": set(),  # MAL-2026-12735
    "devplatform-react-micro-frontend": set(),  # MAL-2026-12737
    "devplatform-react-rest-client": set(),  # MAL-2026-12740
    "devplatform-react-sentry": set(),  # MAL-2026-12742
    "devplatform-react-utils": set(),  # MAL-2026-12743
    "devplatform-rest-client": set(),  # MAL-2026-12744
    "devplatform-select-fields": set(),  # MAL-2026-12751
    "devplatform-spa-cli": set(),  # MAL-2026-12755
    "devplatform-spa-plugin-devtools": set(),  # MAL-2026-12764
    "devplatform-spa-plugin-error-boundary": set(),  # MAL-2026-12766
    "devplatform-spa-plugin-history": set(),  # MAL-2026-12767
    "devplatform-spa-plugin-i18next": set(),  # MAL-2026-12768
    "devplatform-spa-plugin-location": set(),  # MAL-2026-12770
    "devplatform-spa-plugin-root-sentry": set(),  # MAL-2026-12776
    "devplatform-spa-plugin-router": set(),  # MAL-2026-12777
    "devplatform-spa-plugin-s3-router": set(),  # MAL-2026-13261
    "devplatform-spa-plugin-suspense": set(),  # MAL-2026-12781
    "devplatform-sre-devplatform-sre-core": set(),  # MAL-2026-13264
    "devplatform-table": set(),  # MAL-2026-13266
    "devplatform-ui-kit": set(),  # MAL-2026-13269
    "devplatform-vite-plugin-external": set(),  # MAL-2026-13272
    "devplatform-vite-plugin-gle": set(),  # MAL-2026-13273
    "dlp-dlp-core": set(),  # MAL-2026-13278
    "dolyame-boxy-atom-bnpl-badge": set(),  # MAL-2026-13282
    "dolyame-boxy-atom-bnpl-button": set(),  # MAL-2026-13283
    "dolyame-boxy-atom-bnpl-card": set(),  # MAL-2026-13284
    "dolyame-boxy-atom-bnpl-dangerously-html": set(),  # MAL-2026-13285
    "dolyame-boxy-atom-bnpl-dolyame-button": set(),  # MAL-2026-13286
    "dolyame-boxy-atom-bnpl-email-form": set(),  # MAL-2026-12363
    "dolyame-boxy-atom-bnpl-image-card": set(),  # MAL-2026-13287
    "dolyame-boxy-atom-bnpl-info-card": set(),  # MAL-2026-13288
    "dolyame-boxy-atom-bnpl-popup": set(),  # MAL-2026-13289
    "dolyame-boxy-atom-bnpl-text": set(),  # MAL-2026-13291
    "dolyame-boxy-atom-desktop-bnpl-container": set(),  # MAL-2026-13293
    "dolyame-boxy-atom-desktop-bnpl-dangerously-html": set(),  # MAL-2026-13294
    "dolyame-boxy-atom-desktop-bnpl-highlighted-text": set(),  # MAL-2026-13295
    "dolyame-boxy-atom-desktop-bnpl-text": set(),  # MAL-2026-13296
    "dolyame-boxy-atom-icon-loader": set(),  # MAL-2026-13297
    "dolyame-boxy-desktop-bnpl-button-set": set(),  # MAL-2026-13300
    "dolyame-boxy-desktop-bnpl-card-gallery": set(),  # MAL-2026-13301
    "dolyame-boxy-desktop-bnpl-footer": set(),  # MAL-2026-13303
    "dolyame-boxy-desktop-bnpl-header": set(),  # MAL-2026-13304
    "dolyame-boxy-desktop-bnpl-hero-title": set(),  # MAL-2026-13305
    "dolyame-boxy-desktop-bnpl-image-plus-text": set(),  # MAL-2026-13306
    "dolyame-boxy-desktop-bnpl-picture-gallery": set(),  # MAL-2026-13307
    "dolyame-boxy-desktop-bnpl-popup": set(),  # MAL-2026-13308
    "dolyame-boxy-desktop-bnpl-text-block": set(),  # MAL-2026-13309
    "dolyame-boxy-desktop-bnpl-title": set(),  # MAL-2026-13310
    "dolyame-boxy-fonts": set(),  # MAL-2026-13311
    "dolyame-boxy-independent-bnpl-breadcrumbs": set(),  # MAL-2026-13312
    "dolyame-boxy-independent-bnpl-button": set(),  # MAL-2026-13313
    "dolyame-boxy-independent-bnpl-cards": set(),  # MAL-2026-13314
    "dolyame-boxy-independent-bnpl-code-text": set(),  # MAL-2026-13315
    "dolyame-boxy-independent-bnpl-features": set(),  # MAL-2026-13317
    "dolyame-boxy-independent-bnpl-info-slider": set(),  # MAL-2026-13318
    "dolyame-boxy-independent-bnpl-items": set(),  # MAL-2026-13319
    "dolyame-boxy-independent-bnpl-main-banner": set(),  # MAL-2026-13320
    "dolyame-boxy-independent-bnpl-mobile-application": set(),  # MAL-2026-13321
    "dolyame-boxy-independent-bnpl-navigation": set(),  # MAL-2026-13322
    "dolyame-boxy-independent-bnpl-open-api": set(),  # MAL-2026-12366
    "dolyame-boxy-independent-bnpl-origination": set(),  # MAL-2026-13323
    "dolyame-boxy-independent-bnpl-partners": set(),  # MAL-2026-13324
    "dolyame-boxy-independent-bnpl-picture-gallery": set(),  # MAL-2026-13325
    "dolyame-boxy-independent-bnpl-preset-container": set(),  # MAL-2026-13326
    "dolyame-boxy-independent-bnpl-scheme": set(),  # MAL-2026-13327
    "dolyame-boxy-independent-bnpl-search": set(),  # MAL-2026-13328
    "eslint-plugin-vitest-ts": set(),  # MAL-2026-12370
    "eventea-diag": set(),  # MAL-2026-12373
    "eventea-router": set(),  # MAL-2026-12374
    "evo-web-base-analytics-data": set(),  # MAL-2026-12375
    "fb-hr-sites--boxified-form-meetup-subcribe": set(),  # MAL-2026-12381
    "fry-page-maker-types": set(),  # MAL-2026-12385
    "hubert-react-query": set(),  # MAL-2026-12181
    "peter-desktop-peter-big-column": set(),  # MAL-2026-12184
    "pfa-autotests-reporter": set(),  # MAL-2026-12185
    "pfa-prettier-config": set(),  # MAL-2026-12407
    "pfp-block-independent-iframe": set(),  # MAL-2026-12408
    "pfp-block-mobile-past-meetup-list": set(),  # MAL-2026-12409
    "pfp-block-mobile-vacancy-description": set(),  # MAL-2026-12411
    "pfp-forms-mobile-sme-group-tiles": set(),  # MAL-2026-12413
    "pfp-forms-sme-registration-ooo": set(),  # MAL-2026-12187
    "pfp-integration-mobile-heading": set(),  # MAL-2026-12188
    "scandoc-scandoc-core": set(),  # MAL-2026-12191
    "sme-auth-core": set(),  # MAL-2026-12207
    "sme-crm-services-sme-crm-services-core": set(),  # MAL-2026-12438
    "sme-foundation-frame-manager": set(),  # MAL-2026-12439
    "sso-tramvai-lib-roles": set(),  # MAL-2026-12442
    "statist-browser-typed-client-automlplatform.nlppl.searchy": set(),  # MAL-2026-12443
    "statist-browser-typed-client-coretech.web.metrics": set(),  # MAL-2026-12444
    "statist-browser-typed-client-ddp.mentat.ui.web": set(),  # MAL-2026-12209
    "statist-browser-typed-client-eventea.projects.pfpacquiring": set(),  # MAL-2026-12445
    "statist-browser-typed-client-investing.product.loginandauthorization": set(),  # MAL-2026-12210
    "statist-browser-typed-client-itsa.digitalinterview.events": set(),  # MAL-2026-12446
    "statist-browser-typed-client-mb.product.mclaccount": set(),  # MAL-2026-12447
    "statist-browser-typed-client-mb.product.payments": set(),  # MAL-2026-12212
    "statist-browser-typed-client-mb.product.sme.cards": set(),  # MAL-2026-12213
    "statist-browser-typed-client-risktech.uwfrontantifraud.events": set(),  # MAL-2026-12450
    "statist-browser-typed-client-rubliq.platform.keycloak": set(),  # MAL-2026-12451
    "statist-browser-typed-client-sme.platform.mobile.voip.common.events": set(),  # MAL-2026-12452
    "statist-browser-typed-client-sme.rko.finance.web": set(),  # MAL-2026-12453
    "statist-browser-typed-client-sme.rko.tariffs.web": set(),  # MAL-2026-13379
    "statist-browser-typed-client-social.shorts.editor": set(),  # MAL-2026-12454
    "statist-statist-core": set(),  # MAL-2026-12456
    "sui-migration-audit-rules": set(),  # MAL-2026-12472
    "tcb-web-header": set(),  # MAL-2026-12476
    "tcb-web-images": set(),  # MAL-2026-12477
    "tinkoff-boxy-desktop-mgm-product-filter": set(),  # MAL-2026-12229
    "tinkoff-boxy-desktop-two-panel-right-image": set(),  # MAL-2026-12230
    "tinkoff-boxy-gitlab-labels": set(),  # MAL-2026-12232
    "tinkoff-codeceptjs-storyshots": set(),  # MAL-2026-12236
    "tinkoff-codeceptjs-storyshots-alpha": set(),  # MAL-2026-12237
    "tinkoff-component-limits": set(),  # MAL-2026-12238
    "tinkoff-fb-app-frame-page-height-dippy": set(),  # MAL-2026-12240
    "tinkoff-fb-fieldset-car-reference-kasko": set(),  # MAL-2026-12241
    "tinkoff-pfp-atom-desktop-carousel": set(),  # MAL-2026-12245
    "tinkoff-pfp-block-desktop-tabs": set(),  # MAL-2026-12247
    "tinkoff-pfp-block-mobile-advert-footer": set(),  # MAL-2026-12248
    "tinkoff-pfpa-tools": set(),  # MAL-2026-12251
    "tinkoff-statist-browser-typed-client-cardsmobile.events.promotest": set(),  # MAL-2026-12255
    "tinkoff-statist-browser-typed-client-coretech.statist.mobile.ci": set(),  # MAL-2026-12256
    "tinkoff-statist-browser-typed-client-eventea.projects.finhealthwebmicroblocks": set(),  # MAL-2026-12259
    "tinkoff-statist-browser-typed-client-itsa.candy.selfservicesupport.frontend.events": set(),  # MAL-2026-12263
    "tinkoff-statist-browser-typed-client-itsa.corporatemessenger.clientv1.web.events": set(),  # MAL-2026-12264
    "tinkoff-statist-browser-typed-client-jumptaxi.feature.contacts": set(),  # MAL-2026-12265
    "tinkoff-statist-browser-typed-client-sme.rko.origsmartphonepaytb.common.mobile.events": set(),  # MAL-2026-12275
    "tinkoff-statist-browser-typed-client-sme.users.origination.web": set(),  # MAL-2026-12277
    "tinkoff-statist-web-typed-client-test.golden.retriever": set(),  # MAL-2026-12279
    "tinkoff-test-app-child-app": set(),  # MAL-2026-12282
    "tinkoff-volna-zustate": set(),  # MAL-2026-12284
    "tramvai-module-feature-toggle": set(),  # MAL-2026-12285
    "trapp-check-logs": set(),  # MAL-2026-12286
    "trapp-configuration": set(),  # MAL-2026-12485
    "travel-core-typings-reducers": set(),  # MAL-2026-12486
    "ts-toolkit-plus": set(),  # MAL-2026-12812
    "tt-help-cli-ycl": {"1.4.57", "1.4.58", "1.4.59", "1.4.60", "1.4.61", "1.4.62", "1.4.63", "1.4.64", "1.4.65", "1.4.66", "1.4.67", "1.4.68", "1.4.69", "1.4.70", "1.4.71", "1.4.72", "1.4.73", "1.4.74"},  # MAL-2026-12488
    "tui-react-tooltip": set(),  # MAL-2026-12489
    "twork-data-services-product-design-data": set(),  # MAL-2026-12296
    "twork-data-services-proxy-b2b-crm-api-v1-partners-companies-info": set(),  # MAL-2026-12297
    "twork-data-services-sme-agent-company-relation": set(),  # MAL-2026-12301
    "twork-products-taiga2-products-investment": set(),  # MAL-2026-12305
    "utility-kit-ts": set(),  # MAL-2026-12493
    "vvvedernikov-test-another-test": set(),  # MAL-2026-12308
    "wallet-analytics": set(),  # MAL-2026-12499

    # @ccfly/setup-* CI tool typosquat cluster Aug 5–7 2026
    # Four packages impersonating CI setup tools (@actions/setup-* pattern) for macOS/Linux.
    # OSV MAL-2026-12084/12313/13417/13418
    "@ccfly/setup-darwin-arm64": {"0.1.10", "0.1.13", "0.1.14", "0.1.2", "0.1.20", "0.1.5", "0.1.7", "0.1.8", "0.1.9"},  # MAL-2026-12084
    "@ccfly/setup-darwin-x64": {"0.1.0", "0.1.1", "0.1.13", "0.1.14", "0.1.15", "0.1.16", "0.1.3", "0.1.6", "0.1.7", "0.1.8", "0.1.9"},  # MAL-2026-12313
    "@ccfly/setup-linux-arm64": {"0.1.0"},  # MAL-2026-13417
    "@ccfly/setup-linux-x64": {"0.1.0", "0.1.1", "0.1.10", "0.1.14", "0.1.17", "0.1.19", "0.1.2", "0.1.3", "0.1.4", "0.1.9"},  # MAL-2026-13418

    # "common" dep-confusion scope cluster Aug 5–6 2026
    # Six packages targeting internal dep-confusion: @hoteldev, @nasddatax, @nasdtickets,
    # @rentwise, @vboxdev, @afasinatickets — each publishing a "common" internal module.
    # OSV MAL-2026-12318/12323/12324/12328/12330/13387
    "@afasinatickets/common": set(),  # MAL-2026-13387
    "@hoteldev/common": set(),  # MAL-2026-12318
    "@nasddatax/common": set(),  # MAL-2026-12323
    "@nasdtickets/common": set(),  # MAL-2026-12324
    "@rentwise/common": set(),  # MAL-2026-12328
    "@vboxdev/common": set(),  # MAL-2026-12330

    # @activepieces scope compromise Aug 6 2026
    # Four Google integration "piece" packages in the Activepieces no-code automation
    # platform were compromised: piece-google-bigquery, piece-google-contacts,
    # piece-google-forms, and piece-base44. Specific malicious versions only.
    # OSV MAL-2026-13394/13395/13396/13408
    "@activepieces/piece-base44": {"0.1.7"},  # MAL-2026-13408
    "@activepieces/piece-google-bigquery": {"0.0.5", "0.0.6"},  # MAL-2026-13394
    "@activepieces/piece-google-contacts": {"0.4.7", "0.4.8"},  # MAL-2026-13395
    "@activepieces/piece-google-forms": {"0.5.5", "0.5.6", "0.5.7"},  # MAL-2026-13396

    # AI/LLM-tool malware cluster Aug 5–7 2026
    # 19 packages impersonating Claude, GPT, LLM, agent-hub, and AI-tooling names.
    # Includes @guangnao/claude-cli, @cliphijack/santaclaude, remote-claude-daemon,
    # llm-interceptor, wormgpt-cli, gpt-terminal-cli, @agenthub-ai/agent, @addai/*,
    # @vanexalabs-ai/vanexa-agent, @agent-link/agent, @ai-support-agent/cli, and others.
    # OSV MAL-2026-10705/10707/12312/13209/13355/13363/13364/13370/13397–13400/13409–13411/13413/13419/13420
    "@addai/ainode": {"0.3.0", "0.3.1"},  # MAL-2026-13409
    "@addai/entity-runtime": {"0.2.45", "0.2.46", "0.2.47", "0.2.48", "0.2.49", "0.2.50", "0.2.51", "0.2.52", "0.2.53", "0.2.55", "0.2.56", "0.2.58"},  # MAL-2026-13410
    "@addai/node": {"0.11.0", "0.11.1", "0.11.2", "0.4.0", "0.5.0", "0.7.0", "0.8.0", "0.8.1", "0.8.2", "0.9.0"},  # MAL-2026-13411
    "@agenthub-ai/agent": {"0.1.0", "0.1.1", "0.1.2", "0.1.3", "0.10.1", "0.12.2", "0.14.1", "0.14.2", "0.2.0", "0.2.1", "0.3.0", "0.4.0", "0.5.0", "0.5.1", "0.6.0", "0.6.1", "0.6.2", "0.8.0", "0.8.1", "0.8.2", "0.8.3", "0.8.4", "0.8.5", "0.8.6", "0.8.7", "0.9.0", "0.9.1", "0.9.2", "0.9.3", "0.9.4", "0.9.5"},  # MAL-2026-12312
    "@astralcore/aura-wb": {"1.0.0", "1.0.1", "1.0.4"},  # MAL-2026-13413
    "@astralcore/sl-aura": {"1.0.0", "1.0.1", "1.0.4", "1.0.5", "1.0.6"},  # MAL-2026-13355
    "@cliphijack/santaclaude": {"1.0.100", "1.0.102", "1.0.103", "1.0.104", "1.0.106", "1.0.107", "1.0.108"},  # MAL-2026-13363
    "@guangnao/claude-cli": {"1.0.12", "1.0.13", "1.0.5"},  # MAL-2026-13209
    "@holocronlab/botruntime-runtime": {"2.1.15", "2.2.5", "2.2.7", "2.4.2", "2.5.0", "2.5.4", "2.6.0", "2.6.1", "2.6.3", "2.6.4", "2.9.7"},  # MAL-2026-13419
    "@ikbal_fadilah_vanexa01/vanexa-agent": {"1.1.51", "1.1.52", "1.1.53", "1.1.54", "1.1.55", "1.1.56", "1.1.57", "1.1.58", "1.1.59", "1.2.0", "1.3.10", "1.3.12", "1.3.14", "1.3.15", "1.3.17", "1.3.19", "1.3.21", "1.3.23", "1.3.27", "1.3.28", "1.3.29", "1.3.3", "1.3.31", "1.3.32", "1.3.34", "1.3.35", "1.3.37", "1.3.4", "1.3.40", "1.3.44", "1.3.45", "1.3.6", "1.3.7", "1.3.8", "1.3.9"},  # MAL-2026-13364
    "@innocarpe/deepseek-build": {"1.0.0"},  # MAL-2026-13420
    "@vanexalabs-ai/vanexa-agent": {"1.3.50", "1.3.51", "1.3.52", "1.3.53", "1.3.54", "1.3.55", "1.3.56", "1.3.57", "1.3.59", "1.3.60", "1.3.61", "1.3.62"},  # MAL-2026-13397
    "@xiaohhhh1/canvas-agent": {"0.4.4"},  # MAL-2026-13398
    "agenthub-multiagent-mcp": {"1.57.0"},  # MAL-2026-13399
    "agenttunnels": {"0.1.11", "0.1.12", "0.1.5", "0.1.6", "0.1.9"},  # MAL-2026-13400
    "gpt-terminal-cli": {"1.0.0"},  # MAL-2026-13447
    "llm-interceptor": {"0.3.0", "0.3.1", "0.3.3", "0.3.4", "0.3.8", "0.4.0", "0.4.1"},  # MAL-2026-13370
    "remote-claude-daemon": {"0.3.0", "0.3.4", "0.3.5", "0.3.6", "0.3.7", "0.3.8", "0.3.9", "0.4.2", "0.4.6", "0.4.7", "0.5.0", "0.5.2", "0.5.4", "0.5.5", "0.5.7", "0.5.9", "0.6.0", "0.6.1", "0.6.2", "0.6.6"},  # MAL-2026-13455
    "wormgpt-cli": {"1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4", "1.0.5", "1.0.6", "1.0.7", "1.0.8"},  # MAL-2026-13466

    # WhatsApp/Baileys typosquat extension Aug 6–7 2026
    # Eight packages extending the ongoing Baileys-based WhatsApp credential-stealing
    # campaign: @xsat10/baileys-xsat, diezyyasha-baileys (wildcard), @diezyyasha/libsignal-node,
    # santana-baileys, diezyclutch-baileys, ynastore-baileys, @prototypevip/baileys, shadowx-fca.
    # OSV MAL-2026-13390/13443/13456/13457/13470/13474/13480/13482
    "@diezyyasha/libsignal-node": set(),  # MAL-2026-13474
    "@prototypevip/baileys": {"0.0.3"},  # MAL-2026-13480
    "@xsat10/baileys-xsat": {"2.0.0"},  # MAL-2026-13390
    "diezyclutch-baileys": {"8.6.78"},  # MAL-2026-13482
    "diezyyasha-baileys": set(),  # MAL-2026-13443
    "santana-baileys": {"2.0.2", "2.0.3", "2.0.4"},  # MAL-2026-13456
    "shadowx-fca": {"10.0.0", "10.1.0"},  # MAL-2026-13457
    "ynastore-baileys": {"1.0.21"},  # MAL-2026-13470

    # Payment gateway malware cluster Aug 5–6 2026
    # Six packages targeting payment / fintech: simplipayng, @simplipayng/checkout,
    # @voxepay/checkout, @zahlen/checkout (extension of existing @zahlen entries),
    # ach-detail, wallet-monitor-snap.
    # OSV MAL-2026-12334/12437/13388/13389/13391/13393
    "@simplipayng/checkout": set(),  # MAL-2026-13388
    "@voxepay/checkout": set(),  # MAL-2026-13389
    "@zahlen/checkout": set(),  # MAL-2026-13391
    "ach-detail": {"99.0.1", "99.0.2"},  # MAL-2026-12334
    "simplipayng": set(),  # MAL-2026-12437
    "wallet-monitor-snap": {"1.0.2", "1.0.4"},  # MAL-2026-13393

    # Svelte ecosystem typosquat cluster Aug 6–7 2026
    # Three packages impersonating Svelte mapping/visualization libraries:
    # svelte-mapped-metrics, svelte-mapping-core, svelte-visual-map.
    # All have ranges: introduced 0. OSV MAL-2026-13383/13384/13477
    "svelte-mapped-metrics": set(),  # MAL-2026-13383
    "svelte-mapping-core": set(),  # MAL-2026-13384
    "svelte-visual-map": set(),  # MAL-2026-13477

    # Sui blockchain malware extension Aug 6–7 2026
    # Two additional Sui-ecosystem packages (sui-graphql-client, sui-migration-audit-cli)
    # extending the existing sui-migration-audit-rules entry from Aug 5–6 2026.
    # Both have ranges: introduced 0. OSV MAL-2026-13475/13476
    "sui-graphql-client": set(),  # MAL-2026-13475
    "sui-migration-audit-cli": set(),  # MAL-2026-13476

    # CLOB/polymarket typosquat extension Aug 6 2026
    # Three packages extending the existing polymarket/CLOB cluster:
    # poly-provider-api, polyclob-api, tick-forge. All wildcard.
    # OSV MAL-2026-13381/13382/13385
    "poly-provider-api": set(),  # MAL-2026-13381
    "polyclob-api": set(),  # MAL-2026-13382
    "tick-forge": set(),  # MAL-2026-13385

    # streak-cache-map / streak-map-cache Aug 6–7 2026 (streak cluster extension)
    # OSV MAL-2026-13403/13459
    "streak-cache-map": set(),  # MAL-2026-13403
    "streak-map-cache": {"1.0.0"},  # MAL-2026-13459

    # tailwindcss-form-components Aug 5 2026 — Tailwind CSS form plugin typosquat (wildcard)
    # OSV MAL-2026-12223
    "tailwindcss-form-components": set(),  # MAL-2026-12223

    # @united-airlines-org/atmos-design-system dep-confusion Aug 6–7 2026 (wildcard)
    # OSV MAL-2026-13435
    "@united-airlines-org/atmos-design-system": set(),  # MAL-2026-13435

    # @cats-cdf dep-confusion cluster Aug 7 2026
    # Three packages targeting a French CDF bank internal tooling:
    # @cats-cdf/authentication, @cats-cdf/browser-metrics-meter, cdf-tag-commander-helper.
    # OSV MAL-2026-13478/13479/13481
    "@cats-cdf/authentication": {"2.17.1", "3.1.1"},  # MAL-2026-13478
    "@cats-cdf/browser-metrics-meter": {"2.0.0", "3.1.1"},  # MAL-2026-13479
    "cdf-tag-commander-helper": {"3.1.1", "3.6.2"},  # MAL-2026-13481

    # commonweb/consumerweb/merchantweb dep-confusion extension Aug 6 2026
    # Four packages extending the Tinkoff commonweb/consumerweb/merchantweb dep-confusion cluster.
    # OSV MAL-2025-6894/MAL-2026-13439/13441/13449
    "commonweb-balance": {"99.9.1"},  # MAL-2026-13439
    "commonweb-flow": {"1.0.0", "10.11.0", "10.12.0", "10.13.0", "10.14.0", "10.15.0", "5.8.999", "5.999.999", "6.0.999", "6.999.999", "7.1.999", "7.2.999", "7.3.999", "7.999.999", "99.99.99"},  # MAL-2025-6894
    "consumerweb-creditcollection": {"99.9.1"},  # MAL-2026-13441
    "merchantweb-lang-cookie-reset": {"99.99.99"},  # MAL-2026-13449

    # Miscellaneous npm malware Aug 5–7 2026 (no cluster pattern)
    # 63 packages: assorted malware, typosquats, and dep-confusion not fitting a named cluster.
    # OSV MAL-2026-12320/12368/12402/12504/12666/12669/12680–12688/13360/13392/13401/13402
    #      13404/13405/13406/13407/13412/13414/13415/13416/13421–13425/13427–13434/13436–13448
    #      13450–13454/13458/13460–13462/13463–13469/13471/13483–13485
    "9remote": {"2.1.1", "2.1.14", "2.1.16", "2.1.20", "2.1.21", "2.1.5", "2.1.6", "2.1.9", "2.2.5", "2.2.6"},  # MAL-2026-13406
    "@0l00000l/auth": {"1.1.3", "1.1.4"},  # MAL-2026-13407
    "@apicity/meta": {"0.8.0", "0.8.1", "0.8.2", "0.8.3", "0.8.4", "0.8.5", "0.8.6"},  # MAL-2026-13412
    "@atom8n/inspector": {"0.17.32"},  # MAL-2026-13414
    "@aubea/mars": {"1.0.0", "1.1.0", "1.2.0", "1.2.10", "1.2.11", "1.2.12", "1.2.2", "1.2.3", "1.2.4", "1.2.6", "1.2.7", "1.2.8", "1.2.9"},  # MAL-2026-13415
    "@avi892nash/aegis-grid-runner": {"0.3.3"},  # MAL-2026-13429
    "@bananacool467/ui-tools": {"0.1.0-beta", "0.1.1-beta", "0.1.2-beta", "0.1.3-beta", "0.1.4-beta", "0.1.5-beta", "0.1.6-beta", "0.1.7-beta"},  # MAL-2026-13416
    "@ch4acko3/frontal-lobe": {"0.1.12", "0.1.12-preview.2", "0.1.14"},  # MAL-2026-13430
    "@cy4dev/cydemo-bg-color": {"4.0.0", "5.0.0", "6.0.0", "7.0.0"},  # MAL-2026-12504
    "@itsreduxtm/unpkg-xss-test": {"1.0.5", "1.0.9"},  # MAL-2026-13431
    "@junyoung-kim/reins": {"0.1.6", "0.1.7"},  # MAL-2026-13432
    "@ks-video/kwai-player-web": {"9.1.2"},  # MAL-2026-13433
    "@leejungkiin/awkit": {"3.3.1", "3.3.2", "3.3.3", "3.3.4", "3.3.5", "3.3.8", "3.3.9", "3.4.0", "3.4.1", "3.4.2", "3.4.3", "3.4.4", "3.4.5", "3.4.6", "3.4.7", "3.4.8", "3.5.0", "3.5.10", "3.5.5", "3.5.6", "3.5.7", "3.5.8", "3.5.9", "3.6.0", "3.6.1", "3.6.2"},  # MAL-2026-13427
    "@lizhao1/memorax-code-internal": {"0.1.0", "0.1.1", "0.1.2", "0.1.3"},  # MAL-2026-12320
    "@love-moon/conductor-cli": {"0.7.4", "0.7.5", "0.7.6", "0.8.0"},  # MAL-2026-13428
    "@lyxa.ai/core": {"1.0.129", "1.0.13", "1.0.144-test", "1.0.145-debug", "1.0.16", "1.0.162-test", "1.0.201", "1.0.206", "1.0.23", "1.0.281", "1.0.333", "1.0.37", "1.0.386", "1.0.56", "1.0.79", "1.0.8-debug-1", "1.1.36", "1.1.47", "1.2.24", "1.2.43"},  # MAL-2026-13434
    "@trackunit/iris-app-sdk-vite": {"1.2.10-alpha-d785aff3531.0"},  # MAL-2026-13421
    "@wbnr/frontend-shared": {"99.0.0", "99.0.1"},  # MAL-2026-13436
    "aitable-workflow-server": {"9.9.9"},  # MAL-2026-13437
    "beautiful-ui-monitoring": {"1.0.8"},  # MAL-2026-13422
    "cewe-npm-cops": {"99.9.9"},  # MAL-2026-13438
    "connect-contingency": {"99.9.1"},  # MAL-2026-13440
    "content-common": {"99.9.9"},  # MAL-2026-13442
    "crypto-checkout-api": set(),  # MAL-2026-12666
    "dbk-ui-forms": {"99.0.0", "99.0.1"},  # MAL-2026-12669
    "delivery-ci-sage": set(),  # MAL-2026-12680
    "delivery-ci-storybook": set(),  # MAL-2026-12681
    "delivery-ci-update-gitlab": set(),  # MAL-2026-12685
    "delivery-ci-upgrade-from": set(),  # MAL-2026-12687
    "dpdgroup-css": {"2.0.1"},  # MAL-2026-13444
    "electrode-ota-ui-app": {"99.0.0", "99.0.1"},  # MAL-2026-12368
    "elephant-tusk-runner": {"1.0.0", "1.0.1"},  # MAL-2026-13445
    "express-chai": {"3.7.9"},  # MAL-2026-13446
    "fetchrtds": {"1.1.0"},  # MAL-2026-13423
    "golaaa": {"1.0.0"},  # MAL-2026-13392
    "helmet-pro": {"10.0.4"},  # MAL-2026-13401
    "internallib_v514": {"1.0.0"},  # MAL-2026-13483
    "jagproject": {"28.1.0", "28.2.0", "28.3.0", "28.7.0"},  # MAL-2026-13402
    "lib-frontsga": {"9.999.999"},  # MAL-2026-13448
    "merge-grid-stats": {"1.0.0", "1.0.1", "1.1.0", "1.2.0", "1.3.0", "1.4.0", "1.5.0"},  # MAL-2026-13484
    "move-bcs-codec": {"1.0.0", "1.0.1", "1.0.2"},  # MAL-2026-13450
    "new-native-tools-linux-x64-gnu": {"3.1.40-as2-9923-378-1785154830", "3.1.40-as2-9962-369-1784812980", "3.1.40-browser-release-151-359-1784544869", "3.1.40-browser-release-151-362-1784553070", "3.1.40-browser-release-151-363-1784553412", "3.1.40-browser-release-151-365-1784638523", "3.1.40-browser-release-151-368-1784717346", "3.1.40-browser-release-151-371-1784887043", "3.1.40-browser-release-151-373-1784890024", "3.1.40-browser-release-151-375-1784897296", "3.1.40-browser-release-151-380-1785161758", "3.1.40-chrom-381-new-browser-icons-367-1784657143", "3.1.40-chrom-381-new-browser-icons-377-1785143176", "3.1.40-chrom-468-delete-windows-32-bit-358-1784544836", "3.1.40-chrom-553-fix-undeletable-import-cookies-355-1784226602", "3.1.40-chrom-553-fix-undeletable-import-cookies-360-1784545605", "3.1.41-as2-9980-test-400-1785776624", "3.1.41-browser-release-151-389-1785423950", "3.1.41-browser-release-151-upd-native-tools-397-1785772979", "3.1.41-browser-release-151-upd-native-tools-398-1785774129", "3.1.41-chrom-381-new-browser-icons-391-1785747283", "3.1.41-origin-chrom-468-delete-windows-32-bit-changelog-fix-408-1785838091", "3.1.41-origin-chrom-468-delete-windows-32-bit-changelog-fix-409-1785839050", "3.1.41-v2026.217.1-native-tools-392-1785759657", "3.1.42", "3.1.42-as2-9980-419-1785846283", "3.1.42-origin-chrom-468-delete-windows-32-bit-changelog-fix-410-1785839786", "3.1.42-origin-chrom-468-delete-windows-32-bit-changelog-fix-411-1785839911", "3.1.42-origin-chrom-468-delete-windows-32-bit-changelog-fix-412-1785840430", "3.1.42-origin-chrom-468-delete-windows-32-bit-changelog-fix-415-1785842368", "3.1.42-origin-chrom-468-delete-windows-32-bit-changelog-fix-416-1785842977", "3.1.43", "3.1.43-as2-9980-424-1785851759", "3.1.44-as2-9980-433-1786011509"},  # MAL-2026-12402
    "nms-dashboard-js": {"9.9.11"},  # MAL-2026-13451
    "opencode-optimised-toolings": {"3.4.0", "4.0.0", "4.0.1"},  # MAL-2026-13452
    "pilgrimage-portal-client": {"99.0.0"},  # MAL-2026-13453
    "poc-ch4rlygr": {"1.1.0", "1.2.0", "1.3.0", "1.4.0", "1.5.0", "1.6.0"},  # MAL-2026-13454
    "squeez": {"1.38.0", "1.40.0", "1.42.1", "1.44.1"},  # MAL-2026-13458
    "stretchshop": {"0.7.5"},  # MAL-2026-13460
    "supersig": {"1.0.5"},  # MAL-2026-13461
    "tailwindcss-hide-scrollbar": {"2.5.3", "2.5.4"},  # MAL-2026-13424
    "trimprompt": {"1.0.35", "1.0.42", "1.0.46", "1.0.47", "1.0.48", "1.0.49"},  # MAL-2026-13462
    "tsihealth-client": set(),  # MAL-2026-13404 (upgraded to SEMVER >=0; any version)
    "typst-resume-cli": {"1.0.2", "1.0.3"},  # MAL-2026-13425
    "uzair-rajput-new": {"1.0.1", "1.1.0", "1.2.0", "1.3.0"},  # MAL-2026-13360
    "vite-plugin-cleaner": {"4.1.3"},  # MAL-2026-13463
    "vite-svg-parse": set(),  # MAL-2026-13464 (upgraded to SEMVER >=0; any version)
    "vite-vue-path-map": {"1.0.0", "1.0.1", "1.0.2"},  # MAL-2026-13465
    "vitest-preview-pro-all": {"10.0.3"},  # MAL-2026-13405
    "weight2loss": {"1.0.5"},  # MAL-2026-13485
    "wos-library-ui": {"99.0.0"},  # MAL-2026-13467
    "xdaxx": {"1.0.1"},  # MAL-2026-13468
    "xxdxax": {"1.0.0", "1.0.1"},  # MAL-2026-13469
    "zyr-agent": {"1.5.7", "1.6.2"},  # MAL-2026-13471

    # Dolyame / SME-RKO Russian banking dep-confusion cluster (Aug 7–8 2026)
    # 131 packages targeting Dolyame BNPL service and SME-RKO (small/medium
    # enterprise current-account finance) internal npm tooling. High-version
    # (35.x.x) packages published to the public registry to hijack internal CI
    # dependency resolution. All detected by Amazon Inspector / OpenSSF.
    # OSV MAL-2026-13494 through MAL-2026-13663 (see individual # comments).
    "beaver-ui-popover-marker": {"35.5.8"},  # MAL-2026-13523
    "bigops-abstract-entity-data": {"35.1.7"},  # MAL-2026-13524
    "bigops-security": {"35.8.8"},  # MAL-2026-13525
    "bigops-shared-product-design": {"35.9.3"},  # MAL-2026-13526
    "bigops-telephony-mock": {"35.7.2"},  # MAL-2026-13494
    "bnpl-blocks-atom-bnpl-checkbox": {"35.6.1"},  # MAL-2026-13527
    "bnpl-blocks-atom-bnpl-faq-item": {"35.8.2"},  # MAL-2026-13528
    "bnpl-blocks-atom-bnpl-image-card": {"35.6.1"},  # MAL-2026-13529
    "bnpl-blocks-atom-bnpl-loader": {"35.1.2"},  # MAL-2026-13530
    "damir-cbr-dawdntrnssbf": {"35.8.1"},  # MAL-2026-13531
    "ded-pwa-bnpl-forms-test-demo": {"35.7.8"},  # MAL-2026-13532
    "ded-pwa-c-boxy": {"35.9.1"},  # MAL-2026-13533
    "ded-pwa-c-boxy-di": {"35.2.2"},  # MAL-2026-13534
    "ded-pwa-c-cms": {"35.9.9"},  # MAL-2026-13496
    "ded-pwa-c-mapping": {"35.8.7"},  # MAL-2026-13535
    "ded-pwa-c-micro": {"35.8.3"},  # MAL-2026-13536
    "ded-pwa-c-page-maker-props": {"35.7.7"},  # MAL-2026-13497
    "ded-pwa-ded-pwa-core": {"35.6.3"},  # MAL-2026-13498
    "ded-pwa-test-pub-pkg": {"35.8.4"},  # MAL-2026-13537
    "delivery-ci-cli": {"35.3.5"},  # MAL-2026-13538
    "delivery-ci-codeceptjs": {"35.1.7"},  # MAL-2026-13539
    "delivery-ci-codeceptjs-fork": {"35.4.5"},  # MAL-2026-13499
    "delivery-ci-core": {"35.3.7"},  # MAL-2026-13540
    "delivery-ci-documentation": {"35.3.7"},  # MAL-2026-13541
    "delivery-ci-dpat": {"35.1.5"},  # MAL-2026-13500
    "delivery-ci-jira": {"35.5.2"},  # MAL-2026-13542
    "delivery-ci-jira-rnd": {"35.5.4"},  # MAL-2026-13501
    "devplatform-api-v1-resources": {"35.4.7"},  # MAL-2026-13543
    "devplatform-eslint-config": {"35.8.9"},  # MAL-2026-13544
    "devplatform-react-mcp": {"35.5.6"},  # MAL-2026-13502
    "devplatform-spa-errors": {"35.5.7"},  # MAL-2026-13545
    "devplatform-spa-plugin-feature-toggle": {"35.7.4"},  # MAL-2026-13546
    "devplatform-spa-plugin-remote-module": {"35.9.6"},  # MAL-2026-13547
    "devplatform-stylelint-config": {"35.7.4"},  # MAL-2026-13548
    "distributorblock": {"35.8.1"},  # MAL-2026-13503
    "dolyame-boxy-atom-bnpl-navigation-arrow": {"35.6.5"},  # MAL-2026-13550
    "dolyame-boxy-independent-bnpl-faq": {"35.8.7"},  # MAL-2026-13551
    "dolyame-boxy-independent-bnpl-main-title": {"35.5.6"},  # MAL-2026-13552
    "dolyame-boxy-independent-bnpl-product-grid": {"35.9.2"},  # MAL-2026-13553
    "dolyame-ui-attachfile": {"35.8.1"},  # MAL-2026-13504
    "dolyame-ui-buttonstore": {"35.8.1"},  # MAL-2026-13554
    "dolyame-ui-cardlogo": {"35.8.1"},  # MAL-2026-13555
    "dolyame-ui-carouselline": {"35.8.1"},  # MAL-2026-13556
    "dolyame-ui-checkablegroup": {"35.8.1"},  # MAL-2026-13557
    "dolyame-ui-clickoutsidehoc": {"35.8.1"},  # MAL-2026-13558
    "dolyame-ui-collapseblock": {"35.8.1"},  # MAL-2026-13559
    "dolyame-ui-contenteditable": {"35.8.1"},  # MAL-2026-13560
    "dolyame-ui-contextmenu": {"35.8.1"},  # MAL-2026-13561
    "dolyame-ui-contextmenusearchable": {"35.8.1"},  # MAL-2026-13562
    "dolyame-ui-controlgroup": {"35.8.1"},  # MAL-2026-13563
    "dolyame-ui-dataqa": {"35.8.1"},  # MAL-2026-13564
    "dolyame-ui-datatable": {"35.8.1"},  # MAL-2026-13565
    "dolyame-ui-deprecatepropshoc": {"35.8.1"},  # MAL-2026-13566
    "dolyame-ui-draghoc": {"35.8.1"},  # MAL-2026-13567
    "dolyame-ui-eventoutside": {"35.8.1"},  # MAL-2026-13568
    "dolyame-ui-flatcorners": {"35.8.1"},  # MAL-2026-13569
    "dolyame-ui-focusstatehoc": {"35.8.1"},  # MAL-2026-13570
    "dolyame-ui-generateid": {"35.8.1"},  # MAL-2026-13571
    "dolyame-ui-iconloaderhoc": {"35.8.1"},  # MAL-2026-13505
    "dolyame-ui-iconspack": {"35.8.1"},  # MAL-2026-13572
    "dolyame-ui-inlineedit": {"35.8.1"},  # MAL-2026-13573
    "dolyame-ui-inputautocomplete": {"35.8.1"},  # MAL-2026-13574
    "dolyame-ui-inputbox": {"35.8.1"},  # MAL-2026-13506
    "dolyame-ui-inputcard": {"35.8.1"},  # MAL-2026-13575
    "dolyame-ui-inputcolor": {"35.8.1"},  # MAL-2026-13507
    "dolyame-ui-inputcount": {"35.8.1"},  # MAL-2026-13576
    "dolyame-ui-inputdate": {"35.8.1"},  # MAL-2026-13577
    "dolyame-ui-inputfio": {"35.8.1"},  # MAL-2026-13578
    "dolyame-ui-inputmoney": {"35.8.1"},  # MAL-2026-13579
    "dolyame-ui-inputpassword": {"35.8.1"},  # MAL-2026-13508
    "dolyame-ui-inputphone": {"35.8.1"},  # MAL-2026-13580
    "dolyame-ui-inputrange": {"35.8.1"},  # MAL-2026-13581
    "dolyame-ui-inputsearch": {"35.8.1"},  # MAL-2026-13582
    "dolyame-ui-inputsearchtagged": {"35.8.1"},  # MAL-2026-13583
    "dolyame-ui-inputsecure": {"35.8.1"},  # MAL-2026-13584
    "dolyame-ui-inputtag": {"35.8.1"},  # MAL-2026-13585
    "dolyame-ui-inputtime": {"35.8.1"},  # MAL-2026-13586
    "dolyame-ui-inputtools": {"35.8.1"},  # MAL-2026-13587
    "dolyame-ui-lazyrender": {"35.8.1"},  # MAL-2026-13509
    "dolyame-ui-mediainfohoc": {"35.8.1"},  # MAL-2026-13588
    "dolyame-ui-memoizeweak": {"35.8.1"},  # MAL-2026-13589
    "dolyame-ui-noindex": {"35.8.1"},  # MAL-2026-13590
    "dolyame-ui-overridestyles": {"35.8.1"},  # MAL-2026-13591
    "dolyame-ui-pageheader": {"35.8.1"},  # MAL-2026-13592
    "dolyame-ui-popupcarousel": {"35.8.1"},  # MAL-2026-13593
    "dolyame-ui-postcssconfig": {"35.8.1"},  # MAL-2026-13594
    "dolyame-ui-postcsscustomproperties": {"35.8.1"},  # MAL-2026-13595
    "dolyame-ui-progresscircle": {"35.8.1"},  # MAL-2026-13510
    "dolyame-ui-progressline": {"35.8.1"},  # MAL-2026-13596
    "dolyame-ui-scrollblock": {"35.8.1"},  # MAL-2026-13597
    "dolyame-ui-selectaccount": {"35.8.1"},  # MAL-2026-13598
    "dolyame-ui-sortablelist": {"35.8.1"},  # MAL-2026-13599
    "dolyame-ui-stateutils": {"35.8.1"},  # MAL-2026-13511
    "dolyame-ui-tableinline": {"35.8.1"},  # MAL-2026-13600
    "dolyame-ui-tablemobile": {"35.8.1"},  # MAL-2026-13601
    "dolyame-ui-tabsblock": {"35.8.1"},  # MAL-2026-13512
    "dolyame-ui-tabslayout": {"35.8.1"},  # MAL-2026-13602
    "eacq-cdk": {"35.8.1"},  # MAL-2026-13513
    "eacq-core": {"35.8.1"},  # MAL-2026-13514
    "eacq-dialog": {"35.8.1"},  # MAL-2026-13515
    "platform-ui-colors": {"35.8.1"},  # MAL-2026-13603
    "sme-rko-finance-front-operations-domain": {"35.8.1"},  # MAL-2026-13634
    "sme-rko-finance-front-operations-fee": {"35.8.1"},  # MAL-2026-13635
    "sme-rko-finance-front-operations-feed-impl": {"35.8.1"},  # MAL-2026-13636
    "sme-rko-finance-front-operations-feed-models": {"35.8.1"},  # MAL-2026-13637
    "sme-rko-finance-front-operations-holding-domain": {"35.8.1"},  # MAL-2026-13638
    "sme-rko-finance-front-operations-income": {"35.8.1"},  # MAL-2026-13639
    "sme-rko-finance-front-operations-notifications-impl": {"35.8.1"},  # MAL-2026-13640
    "sme-rko-finance-front-operations-notifications-models": {"35.8.1"},  # MAL-2026-13641
    "sme-rko-finance-front-operations-other": {"35.8.1"},  # MAL-2026-13642
    "sme-rko-finance-front-operations-overnight": {"35.8.1"},  # MAL-2026-13643
    "sme-rko-finance-front-operations-pegasus": {"35.8.1"},  # MAL-2026-13644
    "sme-rko-finance-front-operations-penalty": {"35.8.1"},  # MAL-2026-13645
    "sme-rko-finance-front-operations-providers": {"35.8.1"},  # MAL-2026-13646
    "sme-rko-finance-front-operations-shared": {"35.8.1"},  # MAL-2026-13647
    "sme-rko-finance-front-operations-special-payments": {"35.8.1"},  # MAL-2026-13648
    "sme-rko-finance-front-operations-tax": {"35.8.1"},  # MAL-2026-13649
    "sme-rko-finance-front-operations-widget-domain": {"35.8.1"},  # MAL-2026-13650
    "sme-rko-finance-front-operations-widget-impl": {"35.8.1"},  # MAL-2026-13651
    "sme-rko-finance-front-operations-widget-models": {"35.8.1"},  # MAL-2026-13652
    "sme-rko-finance-front-payment-registers-operations-domain": {"35.8.1"},  # MAL-2026-13653
    "sme-rko-finance-front-payments-allowed-tariffs-filter": {"35.8.1"},  # MAL-2026-13654
    "sme-rko-finance-front-payments-classic-payment-actions-operations-repeat-impl": {"35.8.1"},  # MAL-2026-13655
    "sme-rko-finance-front-payments-classic-payment-actions-operations-repeat-models": {"35.8.1"},  # MAL-2026-13656
    "sme-rko-finance-front-payments-currency-payment-actions-operations-repeat-impl": {"35.8.1"},  # MAL-2026-13657
    "sme-rko-finance-front-payments-currency-payment-actions-operations-repeat-models": {"35.8.1"},  # MAL-2026-13658
    "sme-rko-finance-front-payments-currency-payment-domain": {"35.8.1"},  # MAL-2026-13659
    "sme-rko-finance-front-payments-domain": {"35.8.1"},  # MAL-2026-13660
    "sme-rko-finance-front-payments-feed-adapter": {"35.8.1"},  # MAL-2026-13661
    "sme-rko-finance-front-payments-feed-display-list": {"35.8.1"},  # MAL-2026-13662
    "sme-rko-finance-front-payments-feed-display-list-impl": {"35.8.1"},  # MAL-2026-13663

    # Miscellaneous npm malware Aug 7–8 2026 (40 packages)
    # Assorted typosquats, dep-confusion, and infostealers. Includes the
    # rdfxvela/velabuild typosquat cluster (introduced:0 SEMVER range → any-version
    # wildcard), Hardhat/EVM tool fakes, @depup/* package-update impersonators,
    # AI-agent infostealers, Roblox/Solana/NestJS/Prisma typosquats, and misc.
    # All detected by Amazon Inspector.
    # OSV MAL-2026-13491/13492/13493/13495/13516–13522/13549/13604/13605/13608–13618/
    #      13620–13633/13664
    "@aster110/cc2wechat": {"5.1.0"},  # MAL-2026-13520
    "@catamania/front-components": {"1.0.5"},  # MAL-2026-13620
    "@coralxyz/anchor": {"0.30.2"},  # MAL-2026-13629
    "@decido/backend-core": {"4.1.1", "4.1.12", "4.1.18", "4.1.19"},  # MAL-2026-13621
    "@depup/astro": {"7.1.3-depup.2", "7.2.0-depup.0"},  # MAL-2026-13622
    "@depup/aws-sdk__credential-provider-process": {"3.972.59-depup.0", "3.972.62-depup.0", "3.972.63-depup.0", "3.972.66-depup.0"},  # MAL-2026-13623
    "@depup/memfs": {"4.67.0-depup.0"},  # MAL-2026-13624
    "@depup/nuxt": {"4.5.0-depup.0"},  # MAL-2026-13625
    "@mrbenty8jf1p9y5/oidc-bind-canary": {"0.0.3"},  # MAL-2026-13626
    "@nestjs-passport/jwt": {"1.0.4", "1.0.7"},  # MAL-2026-13627
    "@rbx-ts/services": {"1.6.0"},  # MAL-2026-13630
    "@rbxst/services": {"1.0.756"},  # MAL-2026-13521
    "@vertexa/prisma-fetch-engine": {"7.8.0", "7.8.1", "7.8.2", "7.8.3", "7.8.4", "7.8.5"},  # MAL-2026-13608
    "aclade-agent": {"1.0.1", "1.0.2", "1.0.4", "1.0.5", "1.0.6"},  # MAL-2026-13614
    "agenthub-ai": {"0.20.1", "0.20.2", "0.20.3", "0.20.4"},  # MAL-2026-13615
    "base-ui-cli": {"1.1.47"},  # MAL-2026-13522
    "big-tss": {"5.0.5"},  # MAL-2026-13613
    "blekit": {"0.1.0", "0.2.0", "0.3.0", "0.3.1", "0.3.2", "1.0.0", "1.1.0", "1.2.0", "1.2.1"},  # MAL-2026-13495
    "dojo-rn-interview": {"1.0.1"},  # MAL-2026-13549
    "f-termx": {"1.2.6"},  # MAL-2026-13610
    "forge-gas-diff": {"1.0.0", "1.0.1"},  # MAL-2026-13516
    "gas-diff-core": {"1.0.0"},  # MAL-2026-13517
    "hardhat-cap": {"2.21.1"},  # MAL-2026-13616
    "hardhat-set": {"2.21.0"},  # MAL-2026-13609
    "localization-fixer": {"1.0.1", "1.1.1"},  # MAL-2026-13631
    "mangomind-agent": {"0.1.0", "0.1.1", "0.1.2", "0.1.3", "0.1.4", "0.1.5", "0.1.6", "0.1.7", "0.1.8", "0.1.9", "0.2.0", "0.2.1"},  # MAL-2026-13611
    "map-streak-kit": {"1.0.0"},  # MAL-2026-13632
    "modern-localization": {"1.1.1", "1.2.1"},  # MAL-2026-13633
    "postcss-theme-provider": {"1.0.2"},  # MAL-2026-13518
    "rdfxvela": set(),  # MAL-2026-13491 (SEMVER introduced:0 — any-version wildcard)
    "rdfxvela-build": set(),  # MAL-2026-13492 (SEMVER introduced:0)
    "streak-kit-map": {"1.0.0"},  # MAL-2026-13519
    "streak-map-kit": {"1.0.0"},  # MAL-2026-13628
    "tailwindcss-motion-advanced": {"1.0.1"},  # MAL-2026-13604
    "titan-exchange-shared-permissions": {"99.9.9"},  # MAL-2026-13664
    "transform-es2015-unicode-regex": {"6.24.1"},  # MAL-2026-13612
    "ts-utility-plus": {"1.3.2"},  # MAL-2026-13617
    "velabuild": set(),  # MAL-2026-13493 (SEMVER introduced:0)
    "w-screenctl": {"1.0.4", "1.0.6", "1.0.7"},  # MAL-2026-13618
    "yakuza0": {"2.23.40", "2.23.40-beta.3"},  # MAL-2026-13605

    # Miscellaneous npm malware Aug 9–10 2026 (14 packages)
    # Tinkoff/Dolyame extended packages (6): bnpl-blocks-desktop-bnpl-anchor-title
    # extends the Dolyame BNPL dep-confusion family (SEMVER introduced:0 wildcard);
    # statist-browser-typed-client-eventea.projects.{pwafamily,pwahelp,pwainsurance,
    # pwakasko,tdeal,tdevice} extend the Tinkoff statist analytics dep-confusion wave.
    # Svelte ecosystem typosquat cluster (4): svelte-cache-kit, svelte-kit-cache,
    # svelte-map-visual, svelte-streak-kit — all SEMVER introduced:0 wildcards.
    # Miscellaneous (4): @lambda-platform/lambda-vue, specials-resources-server,
    # test-noexist-xyz-99 (wildcard), and the @lambda-platform entry (pinned version).
    # OSV MAL-2026-12912/13668/13669/13670/13671/13672/13673/13674/13675/
    #      13676/13677/13678/13679/13680
    "@lambda-platform/lambda-vue": {"3.3.24"},  # MAL-2026-13668
    "bnpl-blocks-desktop-bnpl-anchor-title": set(),  # MAL-2026-12912 (SEMVER introduced:0)
    "specials-resources-server": set(),  # MAL-2026-13669 (SEMVER introduced:0)
    "statist-browser-typed-client-eventea.projects.pwafamily": set(),  # MAL-2026-13670
    "statist-browser-typed-client-eventea.projects.pwahelp": set(),  # MAL-2026-13671
    "statist-browser-typed-client-eventea.projects.pwainsurance": set(),  # MAL-2026-13672
    "statist-browser-typed-client-eventea.projects.pwakasko": set(),  # MAL-2026-13673
    "statist-browser-typed-client-eventea.projects.tdeal": set(),  # MAL-2026-13674
    "statist-browser-typed-client-eventea.projects.tdevice": set(),  # MAL-2026-13675
    "svelte-cache-kit": set(),  # MAL-2026-13676 (SEMVER introduced:0)
    "svelte-kit-cache": set(),  # MAL-2026-13677 (SEMVER introduced:0)
    "svelte-map-visual": set(),  # MAL-2026-13678 (SEMVER introduced:0)
    "svelte-streak-kit": set(),  # MAL-2026-13679 (SEMVER introduced:0)
    "test-noexist-xyz-99": set(),  # MAL-2026-13680 (SEMVER introduced:0)

    # Aug 10–11 2026 npm malware batch (40 packages across 8 clusters)
    #
    # Chai typosquat cluster (8): packages impersonating chai testing framework or
    # chai plugins, detected by Amazon Inspector; exact versions pinned.
    # OSV MAL-2026-13692/13699/13700/13701/13702/13703/13704
    "chai-jsonss": {"3.7.7"},  # MAL-2026-13692
    "chai-as-bench": {"7.0.3"},  # MAL-2026-13699
    "chai-as-deployer": {"2.3.5", "2.3.6"},  # MAL-2026-13700
    "chai-as-format": {"2.3.5"},  # MAL-2026-13701
    "chai-as-map": {"2.3.5"},  # MAL-2026-13702
    "chai-as-promised-plus": {"6.1.3"},  # MAL-2026-13703
    "chai-tracker": {"1.1.0", "1.1.1", "1.1.2", "1.1.3", "1.2.1"},  # MAL-2026-13704
    #
    # Fake SQLite namespace cluster (6): attacker-controlled scopes
    # @sqlite-labs, @sqlite-prime, @sqlite-table publishing SQLite-themed packages;
    # SEMVER introduced:0 wildcards (pure malware); source: GitHub Advisory Database.
    # GHSA-qwqp-6xhg-jhhv/86f7-qh62-pq7c/v49c-g99c-qvf9/f348-mwv9-7p8h/
    # f86c-mf53-7934/4hxf-37q3-vfxh; OSV MAL-2026-13713/13714/13715/13716/13717/13718
    "@sqlite-labs/createsql": set(),  # MAL-2026-13713
    "@sqlite-labs/nodesql": set(),  # MAL-2026-13714
    "@sqlite-prime/createsql": set(),  # MAL-2026-13715
    "@sqlite-prime/nodesql": set(),  # MAL-2026-13716
    "@sqlite-table/schema-generator": set(),  # MAL-2026-13717
    "@sqlite-table/sql-creator": set(),  # MAL-2026-13718
    #
    # Ethereum/crypto toolkit typosquats (4): eth-library-toolkit and eth-library-utils
    # are SEMVER wildcard packages mimicking Ethereum utility libs (GHSA-mqxc-259c-25w3,
    # GHSA-rp49-3975-7q6c); cryptostock and polymarket-stake-mathss are pinned-version
    # crypto-targeting malware (Amazon Inspector).
    # OSV MAL-2026-13693/13707/13720/13721
    "cryptostock": {"1.0.0", "1.0.1"},  # MAL-2026-13693
    "polymarket-stake-mathss": {"3.5.2"},  # MAL-2026-13707
    "eth-library-toolkit": set(),  # MAL-2026-13720 (SEMVER introduced:0)
    "eth-library-utils": set(),  # MAL-2026-13721 (SEMVER introduced:0)
    #
    # PostCSS impersonator cluster (2): SEMVER wildcard packages masquerading as
    # PostCSS plugins; source: Amazon Inspector + GitHub Advisory Database.
    # GHSA-f5h9-q436-8chv / GHSA-44hx-h55m-c65w; OSV MAL-2026-12417/13696
    "post-css-transfer": set(),  # MAL-2026-12417 (SEMVER introduced:0)
    "postcss-initial-provider": set(),  # MAL-2026-13696 (SEMVER introduced:0)
    #
    # commonjs-assertion (1): extends the commonjs-assert family (MAL-2026-10676
    # already tracked); SEMVER wildcard; GHSA-mfjj-4625-mpvr; OSV MAL-2026-13719
    "commonjs-assertion": set(),  # MAL-2026-13719 (SEMVER introduced:0)
    #
    # Additional svelte/streak/map cluster (3): extends the Aug 9–10 2026
    # svelte ecosystem typosquat cluster; all SEMVER introduced:0 wildcards.
    # OSV MAL-2026-13724/13726/13727
    "kit-map-streak": set(),  # MAL-2026-13724 (SEMVER introduced:0)
    "svelte-kit-streak": set(),  # MAL-2026-13726 (SEMVER introduced:0)
    "tailwind-elements-ui": set(),  # MAL-2026-13727 (SEMVER introduced:0)
    #
    # hex-encode-utils (1): SEMVER wildcard trojan masquerading as hex encode/decode
    # utility; published by devr* npm account; detected by Amazon Inspector + SafeDep.
    # OSV MAL-2026-13695
    "hex-encode-utils": set(),  # MAL-2026-13695 (SEMVER introduced:0)
    #
    # Miscellaneous Aug 10–11 2026 npm malware (14 packages)
    # Roblox/Discord impersonators: @rblxts/services (Roblox service typosquat,
    # Amazon Inspector; MAL-2026-13691) and xerohub-discord-voice (Discord bot
    # credential stealer, Amazon Inspector; MAL-2026-13708).
    # @noobaihome/* AMIS widget impersonators (Amazon Inspector; MAL-2026-13689/13690).
    # env-local 18.4.2: dotenv-style env loader malware (Amazon Inspector; MAL-2026-13694).
    # iconova-react: React icon lib typosquat, wildcard (Amazon Inspector; MAL-2026-13705).
    # neverthrow-js 2.0.0: neverthrow library impersonator (Amazon Inspector; MAL-2026-13706).
    # runtimekit: runtime SDK typosquat, wildcard (Amazon Inspector; MAL-2026-6477).
    # @ssgw/icon 9.999.999: icon library dep-confusion (OpenSSF PA; MAL-2026-13684).
    # tokocrytodev 1.0.0: crypto typosquat (Amazon Inspector; MAL-2026-13687).
    # @kuperka/chainguard-sdk: Chainguard SDK impersonator (Amazon Inspector; MAL-2026-13688).
    # simple-date-formatter-new-9/10: extends the simple-date-formatter-new-* cluster
    # (Amazon Inspector; MAL-2026-13697/13698).
    # fsbrowse 0.2.28, godot-kit, spoint 0.1.695–0.1.700: misc malware
    # (GHSA-pvvh-h7rh-2c7g / GHSA-j7m9-r9h4-rfw8 / GHSA-72h3-pwwh-68cx).
    # OSV MAL-2026-13684/13687/13688/13689/13690/13691/13694/13697/13698/
    #      13705/13706/13722/13723/13725; MAL-2026-6477
    "@rblxts/services": {"1.6.0", "1.6.2"},  # MAL-2026-13691
    "@noobaihome/amis-simple-area-widget": {"1.0.0"},  # MAL-2026-13689
    "@noobaihome/amis-uni-area-widget": {"1.0.0", "1.0.1", "1.0.2", "1.0.4", "1.0.5", "1.0.6", "1.0.7", "1.0.8", "1.0.10", "1.0.11"},  # MAL-2026-13690
    "@ssgw/icon": {"9.999.999"},  # MAL-2026-13684
    "@kuperka/chainguard-sdk": {"1.0.1", "1.0.2"},  # MAL-2026-13688
    "env-local": {"18.4.2"},  # MAL-2026-13694
    "iconova-react": set(),  # MAL-2026-13705 (SEMVER introduced:0)
    "neverthrow-js": {"2.0.0"},  # MAL-2026-13706
    "runtimekit": set(),  # MAL-2026-6477 (SEMVER introduced:0)
    "simple-date-formatter-new-9": {"1.0.0"},  # MAL-2026-13698
    "simple-date-formatter-new-10": {"1.0.0"},  # MAL-2026-13697
    "tokocrytodev": {"1.0.0"},  # MAL-2026-13687
    "xerohub-discord-voice": {"1.0.0", "1.0.1"},  # MAL-2026-13708
    "fsbrowse": {"0.2.28"},  # MAL-2026-13722 (GHSA-pvvh-h7rh-2c7g)
    "godot-kit": {"1.0.1786316795"},  # MAL-2026-13723 (GHSA-j7m9-r9h4-rfw8)
    "spoint": {"0.1.695", "0.1.696", "0.1.697", "0.1.698", "0.1.699", "0.1.700"},  # MAL-2026-13725 (GHSA-72h3-pwwh-68cx)

    # Aug 11–12 2026 npm malware batch (37 packages across 6 clusters)
    #
    # DeFi/Ethereum protocol typosquat cluster (5): packages impersonating Aerodrome Finance
    # (Base L2 DEX contracts/Slipstream), OpenZeppelin contracts v4/v5, and Euler Labs EVC;
    # all detected by Amazon Inspector; exact versions pinned.
    # OSV MAL-2026-13734/13735/13737/13738/13739
    "@aerodrome-finance/contracts": {"1.0.0", "1.1.0", "1.1.1"},  # MAL-2026-13734
    "@aerodrome-finance/slipstream": {"1.0.0", "1.1.0", "1.1.1"},  # MAL-2026-13735
    "@openzeppelin-4/contracts": {"1.0.0", "1.0.1"},  # MAL-2026-13737
    "@openzeppelin-5/contracts": {"1.0.0", "1.0.1"},  # MAL-2026-13738
    "ethereum-vault-connector": {"1.0.0", "1.1.0", "1.1.1"},  # MAL-2026-13739
    #
    # base-x / base65 / bs58 typosquat cluster (9): name-lookalikes of the widely-used
    # base-x encoder and bs58 library; all ship obfuscated payloads or embedded ELF binaries.
    # base65-{11,12,13}x carry SEMVER introduced:0 (wildcards); base65-{15,33,77}x are pinned.
    # bs58-1{1,2,3} are GHSA-confirmed full-compromise wildcards.
    # GHSA-39c6-h85q-hpcw / GHSA-mw39-7442-3p8m / GHSA-x9c8-g63x-mh7q / GHSA-72pr-qcvq-fgpg
    # OSV MAL-2026-13745/13746/13747/13748/13749/13750/13758/13759/13760
    "base65-11x": set(),  # MAL-2026-13745 (SEMVER introduced:0, GHSA-39c6-h85q-hpcw)
    "base65-12x": set(),  # MAL-2026-13746 (SEMVER introduced:0)
    "base65-13x": set(),  # MAL-2026-13747 (SEMVER introduced:0)
    "base65-15x": {"5.0.2"},  # MAL-2026-13748
    "base65-33x": {"5.0.2"},  # MAL-2026-13749
    "base65-77x": {"5.0.2"},  # MAL-2026-13750
    "bs58-11": set(),  # MAL-2026-13758 (GHSA-mw39-7442-3p8m)
    "bs58-12": set(),  # MAL-2026-13759 (GHSA-x9c8-g63x-mh7q)
    "bs58-13": set(),  # MAL-2026-13760 (GHSA-72pr-qcvq-fgpg)
    #
    # dep-confusion / postinstall-canary batch Aug 11–12 2026 (6 packages):
    # classic 99.x / 9.999.x dep-confusion versions; postinstall hooks collect
    # hostname/username/cwd and exfiltrate to attacker C2.
    # GHSA-6xhq-px35-hhv9 / GHSA-g62q-mq3x-765x
    # OSV MAL-2026-13744/13751/13752/13753/13754/13755
    "@dgn-src-click-to-pay-org/srcdcfreleasecert": {"999.0.1"},  # MAL-2026-13744
    "bjm-low-code-components": {"99.0.0"},  # MAL-2026-13751
    "chapters-core": {"9.999.999"},  # MAL-2026-13752
    "dcfarguscert": {"999.0.1"},  # MAL-2026-13753
    "dependencyfsdsfdsfg": set(),  # MAL-2026-13754 (SEMVER introduced:0, GHSA-6xhq-px35-hhv9)
    "ghazaly": set(),  # MAL-2026-13755 (SEMVER introduced:0, GHSA-g62q-mq3x-765x)
    #
    # Svelte/vim/kit cluster extension + Sui blockchain typosquats (4 packages):
    # kit-vim-map and svelte-vim-kit extend the Svelte/streak/map cluster (fake
    # calendar/streak libs shipping Linux ELF binaries; GHSA-mj69-vr76-h2mq /
    # GHSA-rvh4-87p7-h5pm). sui-bcs-codec and sui-gql-client extend the Sui
    # blockchain SDK typosquat cluster from Aug 6–7 2026.
    # OSV MAL-2026-13740/13767/13768/13769
    "kit-vim-map": set(),  # MAL-2026-13740 (SEMVER introduced:0, GHSA-mj69-vr76-h2mq)
    "sui-bcs-codec": set(),  # MAL-2026-13767 (SEMVER introduced:0)
    "sui-gql-client": set(),  # MAL-2026-13768 (SEMVER introduced:0)
    "svelte-vim-kit": set(),  # MAL-2026-13769 (GHSA-rvh4-87p7-h5pm)
    #
    # GHSA full-compromise wildcards Aug 12 2026 (5 packages):
    # developer-dashboard, fetch-runtime, internallib_v164, lines-columns,
    # node-internal-svg-loader — all confirmed "full compromise" by the GitHub
    # Advisory Database (ghsa-malware source); any installed version is malicious.
    # GHSA-vf74-54mr-mp44 / GHSA-3hqj-592v-g33j / GHSA-3qvf-g7pq-m3m3 /
    # GHSA-572q-x4v9-m474 / GHSA-9rgf-6m2p-q73f
    # OSV MAL-2026-13762/13763/13764/13765/13766
    "developer-dashboard": set(),  # MAL-2026-13762 (GHSA-vf74-54mr-mp44)
    "fetch-runtime": set(),  # MAL-2026-13763 (GHSA-3hqj-592v-g33j)
    "internallib_v164": set(),  # MAL-2026-13764 (GHSA-3qvf-g7pq-m3m3)
    "lines-columns": set(),  # MAL-2026-13765 (GHSA-572q-x4v9-m474)
    "node-internal-svg-loader": set(),  # MAL-2026-13766 (GHSA-9rgf-6m2p-q73f)
    #
    # Miscellaneous npm malware Aug 11–12 2026 (8 packages):
    # tilaver-mfa: heavily obfuscated custom-VM MFA SDK malware, SEMVER introduced:0
    # (Amazon Inspector; GHSA-4j5x-wjw6-qvq5). newtun 1.0.0–1.0.27: CLI tool that opens
    # a plaintext WebSocket for data exfiltration; all versions malicious by design
    # (Amazon Inspector). @nzeros/codebreak 1.3.0: declares native/solver.c as a binary
    # payload (Amazon Inspector). safe-local-env-loader 1.0.0: env-loader typosquat
    # (Amazon Inspector). zeal-rq-hooks 0.0.0: imports canary.js at require-time
    # (Amazon Inspector). whs4_ued 1.0.0: postinstall exfiltrator; extends the
    # whs4_deu/whs4_eud cluster (Amazon Inspector). dakumangalsingh_virus: all versions
    # confirmed full compromise (GHSA-ppp3-vpgx-2v73).
    # OSV MAL-2026-10925/13733/13736/13741/13742/13743/13761
    "tilaver-mfa": set(),  # MAL-2026-10925 (SEMVER introduced:0, GHSA-4j5x-wjw6-qvq5)
    "newtun": {"1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.8", "1.0.11", "1.0.12", "1.0.13", "1.0.14", "1.0.15", "1.0.16", "1.0.17", "1.0.18", "1.0.19", "1.0.20", "1.0.21", "1.0.22", "1.0.23", "1.0.24", "1.0.25", "1.0.26", "1.0.27"},  # MAL-2026-13733
    "@nzeros/codebreak": {"1.3.0"},  # MAL-2026-13736
    "safe-local-env-loader": {"1.0.0"},  # MAL-2026-13741
    "zeal-rq-hooks": {"0.0.0"},  # MAL-2026-13742
    "whs4_ued": {"1.0.0"},  # MAL-2026-13743 (extends whs4_deu/whs4_eud cluster)
    "dakumangalsingh_virus": {"1.0.0", "1.2.0", "1.3.0"},  # MAL-2026-13761 (GHSA-ppp3-vpgx-2v73)

    "boring-vault": set(),                    # MAL-2026-13771
    "camelot-ammv2-core": set(),              # MAL-2026-13772
    "camelot-ammv2-periphery": set(),         # MAL-2026-13773
    "permit2": set(),                         # MAL-2026-13775
    "upshift-config": set(),                  # MAL-2026-13776
    "upshift-finance": set(),                 # MAL-2026-13777
    "augustdigital-sdk": set(),               # MAL-2026-13774
    # Aug 12 2026 — @telekom-ods/react-ui-kit dep-confusion
    # OSV MAL-2026-13770
    "@telekom-ods/react-ui-kit": {"2.6.0", "2.6.9"},  # MAL-2026-13770
    # Aug 12 2026 — @bikli publisher-account npm cluster (6 packages)
    # Attacker-controlled @bikli scope + standalone packages; all any-version malware.
    # OSV MAL-2026-13778/13779/13782/13786/13787/13788 (GHSA-jrmr-j9fg-c874, GHSA-cc5p-hf7h-rrjh,
    # GHSA-6fpw-43qx-wxvf, GHSA-pcfp-4v4q-w735, GHSA-f5c6-4rpr-wjhp, GHSA-3qxv-77j4-mg7c)
    "@bikli/bikli": set(),     # MAL-2026-13778
    "@bikli/cli": set(),       # MAL-2026-13779
    "airdzticket": set(),      # MAL-2026-13782
    "biklimaster": set(),      # MAL-2026-13786
    "biklirouter": set(),      # MAL-2026-13787
    "bikliwrapper": set(),     # MAL-2026-13788
    # Aug 12 2026 — @noxzacode npm cluster (3 packages)
    # Attacker-controlled scope publishing fake eslint-config and libsignal-node packages.
    # OSV MAL-2026-13780/13781/13831 (GHSA-7x8x-h24p-92f4, GHSA-7p3j-35rp-g3v5,
    # GHSA-rch8-8p8v-23j7)
    "@noxzacode/eslint-config": set(),   # MAL-2026-13780
    "@noxzacode/libsignal-node": set(),  # MAL-2026-13781
    "noxleys": set(),                    # MAL-2026-13831
    "sui-gql": set(),         # MAL-2026-13926
    "kit-map-vim": set(),    # MAL-2026-13915
    "svelte-kit-vim": set(), # MAL-2026-13927
    # Aug 12 2026 — @years17–20 n8n malicious-community-node campaign (78 packages)
    # Four attacker-controlled scopes (@years17/@years18/@years19/@years20) publishing
    # fake n8n workflow-automation community nodes; all at version 1.0.0 except
    # @years17/n8n-nodes-helper-utils (7 versions) and @years17/n8n-nodes-utils-helper (2 versions).
    # OSV MAL-2026-13847 through MAL-2026-13919
    "@years17/n8n-nodes-helper-utils": {
        "1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4", "1.0.5", "1.0.6",
    },  # MAL-2026-13869
    "@years17/n8n-nodes-utils-helper": {"1.0.0", "1.0.1"},  # MAL-2026-13870
    "@years17/n8n-nodes-utils-helper-b": {"1.0.0"},  # MAL-2026-13871
    "@years17/n8n-nodes-utils-helper-c": {"1.0.0"},  # MAL-2026-13872
    "@years17/n8n-nodes-utils-helper-d": {"1.0.0"},  # MAL-2026-13873
    "@years17/n8n-nodes-utils-helper-e": {"1.0.0"},  # MAL-2026-13874
    "@years17/n8n-nodes-utils-helper-f": {"1.0.0"},  # MAL-2026-13875
    "@years17/n8n-nodes-utils-helper-g": {"1.0.0"},  # MAL-2026-13876
    "@years17/n8n-nodes-utils-helper-h": {"1.0.0"},  # MAL-2026-13877
    "@years17/n8n-nodes-utils-helper-i": {"1.0.0"},  # MAL-2026-13878
    "@years18/n8n-nodes-utils-helper-a": {"1.0.0"},  # MAL-2026-13847
    "@years18/n8n-nodes-utils-helper-b": {"1.0.0"},  # MAL-2026-13848
    "@years18/n8n-nodes-utils-helper-c": {"1.0.0"},  # MAL-2026-13849
    "@years18/n8n-nodes-utils-helper-d": {"1.0.0"},  # MAL-2026-13850
    "@years18/n8n-nodes-utils-helper-e": {"1.0.0"},  # MAL-2026-13851
    "@years18/n8n-nodes-utils-helper-f": {"1.0.0"},  # MAL-2026-13852
    "@years18/n8n-nodes-utils-helper-g": {"1.0.0"},  # MAL-2026-13853
    "@years18/n8n-nodes-utils-helper-j": {"1.0.0"},  # MAL-2026-13854
    "@years18/n8n-nodes-utils-helper-k": {"1.0.0"},  # MAL-2026-13855
    "@years18/n8n-nodes-utils-helper-l": {"1.0.0"},  # MAL-2026-13856
    "@years18/n8n-nodes-utils-helper-m": {"1.0.0"},  # MAL-2026-13857
    "@years18/n8n-nodes-utils-helper-n": {"1.0.0"},  # MAL-2026-13858
    "@years18/n8n-nodes-utils-helper-o": {"1.0.0"},  # MAL-2026-13859
    "@years18/n8n-nodes-utils-helper-p": {"1.0.0"},  # MAL-2026-13860
    "@years18/n8n-nodes-utils-helper-q": {"1.0.0"},  # MAL-2026-13861
    "@years18/n8n-nodes-utils-helper-r": {"1.0.0"},  # MAL-2026-13862
    "@years18/n8n-nodes-utils-helper-s": {"1.0.0"},  # MAL-2026-13863
    "@years18/n8n-nodes-utils-helper-t": {"1.0.0"},  # MAL-2026-13864
    "@years18/n8n-nodes-utils-helper-u": {"1.0.0"},  # MAL-2026-13865
    "@years18/n8n-nodes-utils-helper-v": {"1.0.0"},  # MAL-2026-13866
    "@years18/n8n-nodes-utils-helper-w": {"1.0.0"},  # MAL-2026-13867
    "@years18/n8n-nodes-utils-helper-x": {"1.0.0"},  # MAL-2026-13868
    "@years18/n8n-nodes-utils-helper-y": {"1.0.0"},  # MAL-2026-13883
    "@years19/n8n-nodes-utils-helper-a": {"1.0.0"},  # MAL-2026-13884
    "@years19/n8n-nodes-utils-helper-b": {"1.0.0"},  # MAL-2026-13885
    "@years19/n8n-nodes-utils-helper-c": {"1.0.0"},  # MAL-2026-13886
    "@years19/n8n-nodes-utils-helper-d": {"1.0.0"},  # MAL-2026-13887
    "@years19/n8n-nodes-utils-helper-e": {"1.0.0"},  # MAL-2026-13888
    "@years19/n8n-nodes-utils-helper-f": {"1.0.0"},  # MAL-2026-13889
    "@years19/n8n-nodes-utils-helper-g": {"1.0.0"},  # MAL-2026-13890
    "@years19/n8n-nodes-utils-helper-h": {"1.0.0"},  # MAL-2026-13891
    "@years19/n8n-nodes-utils-helper-i": {"1.0.0"},  # MAL-2026-13892
    "@years19/n8n-nodes-utils-helper-j": {"1.0.0"},  # MAL-2026-13893
    "@years19/n8n-nodes-utils-helper-k": {"1.0.0"},  # MAL-2026-13894
    "@years19/n8n-nodes-utils-helper-l": {"1.0.0"},  # MAL-2026-13895
    "@years19/n8n-nodes-utils-helper-m": {"1.0.0"},  # MAL-2026-13896
    "@years19/n8n-nodes-utils-helper-n": {"1.0.0"},  # MAL-2026-13897
    "@years19/n8n-nodes-utils-helper-o": {"1.0.0"},  # MAL-2026-13898
    "@years19/n8n-nodes-utils-helper-p": {"1.0.0"},  # MAL-2026-13899
    "@years19/n8n-nodes-utils-helper-q": {"1.0.0"},  # MAL-2026-13900
    "@years19/n8n-nodes-utils-helper-r": {"1.0.0"},  # MAL-2026-13901
    "@years19/n8n-nodes-utils-helper-s": {"1.0.0"},  # MAL-2026-13902
    "@years19/n8n-nodes-utils-helper-t": {"1.0.0"},  # MAL-2026-13903
    "@years19/n8n-nodes-utils-helper-u": {"1.0.0"},  # MAL-2026-13904
    "@years19/n8n-nodes-utils-helper-v": {"1.0.0"},  # MAL-2026-13905
    "@years19/n8n-nodes-utils-helper-w": {"1.0.0"},  # MAL-2026-13906
    "@years19/n8n-nodes-utils-helper-x": {"1.0.0"},  # MAL-2026-13907
    "@years19/n8n-nodes-utils-helper-y": {"1.0.0"},  # MAL-2026-13908
    "@years20/n8n-nodes-utils-helper-a": {"1.0.0"},  # MAL-2026-13909
    "@years20/n8n-nodes-utils-helper-b": {"1.0.0"},  # MAL-2026-13910
    "@years20/n8n-nodes-utils-helper-c": {"1.0.0"},  # MAL-2026-13911
    "@years20/n8n-nodes-utils-helper-d": {"1.0.0"},  # MAL-2026-13912
    "@years20/n8n-nodes-utils-helper-e": {"1.0.0"},  # MAL-2026-13913
    "@years20/n8n-nodes-utils-helper-f": {"1.0.0"},  # MAL-2026-13914
    "@years20/n8n-nodes-utils-helper-g": {"1.0.0"},  # MAL-2026-13916
    "@years20/n8n-nodes-utils-helper-h": {"1.0.0"},  # MAL-2026-13917
    "@years20/n8n-nodes-utils-helper-i": {"1.0.0"},  # MAL-2026-13918
    "@years20/n8n-nodes-utils-helper-j": {"1.0.0"},  # MAL-2026-13919
    # Aug 12 2026 — @assetshop/verify-cli dep-confusion pair
    # OSV MAL-2026-13881/13882
    "@assetshop/verify-cli": {"99.0.0", "99.0.1"},  # MAL-2026-13881
    "verify-cli": {"99.0.0"},                        # MAL-2026-13882
    "internallib_v392": set(),        # MAL-2026-13924 GHSA-j9qq-rx28-vcjh
    "internallib_v756": set(),        # MAL-2026-13928 GHSA-933g-5588-v5hp
    "bcs-compact": set(),             # MAL-2026-13925 GHSA-xr26-x39h-746w
    "mcp-util-helpers": {"1.0.0"},    # MAL-2026-13880
    "bb-twl-k7x2": {"1.0.0", "1.0.1"},  # MAL-2026-13920
    "envpack-conf": {"1.0.1"},        # MAL-2026-13921
    "passkeys-react": {"1.0.1"},      # MAL-2026-13922
    "tailwind-form-templates": {"0.7.4"},  # MAL-2026-13923
    "dakumangalsingh": {"1.0.0", "1.0.1", "1.1.0"},          # MAL-2026-13879
    # Aug 12 2026 — throwaway/junk npm malware cluster (~55 packages)
    # GHSA-backed entries covering a spray of short-lived throwaway packages
    # published by multiple actors; all confirmed active (SEMVER >=0 range).
    # Includes country-themed stubs (china_airlines, egair0810, egypt0811),
    # mobi-* telecom fakes, random-string junk, and nation-themed identifiers.
    # OSV MAL-2026-13783 through MAL-2026-13846 (selected)
    "bcnfjndwbkf2": set(),     # MAL-2026-13783 GHSA-7cv8-7v66-c3mh
    "bgncvhferucfds": set(),   # MAL-2026-13784 GHSA-p783-m8pp-74w8
    "bgzxcuite2": set(),       # MAL-2026-13785 GHSA-35pm-fj6m-m6v6
    "bmgki3g6fh3": set(),      # MAL-2026-13789 GHSA-wm4g-m94m-47vj
    "bvdfhdfvnk3": set(),      # MAL-2026-13790 GHSA-cp2x-vxp4-762f
    "china_airlines": set(),   # MAL-2026-13791 GHSA-6gv6-cwww-6793
    "chmjdsidwlf5": set(),     # MAL-2026-13792 GHSA-cgrq-g6cw-53vg
    "cjdfswifuem3": set(),     # MAL-2026-13793 GHSA-w32m-789q-9hgh
    "clxofwfjskaz7": set(),    # MAL-2026-13794 GHSA-j89c-cv6h-xxq6
    "csbcldfvivwfgd4": set(),  # MAL-2026-13795 GHSA-5pjw-x44v-j286
    "cvbmxiowkwqla6": set(),   # MAL-2026-13796 GHSA-mgr2-2cf3-5j8q
    "cvbniydplwe3": set(),     # MAL-2026-13797 GHSA-x9wp-p3fp-f3rm
    "cvjwyinkpas": set(),      # MAL-2026-13798 GHSA-5g9r-vh85-2p2v
    "cvmbxcjiasdg": set(),     # MAL-2026-13799 GHSA-cvfr-666p-q22g
    "cvvkshuelwiu": set(),     # MAL-2026-13800 GHSA-9m4j-9m44-ff75
    "cxcbdjxcmncvfg2": set(),  # MAL-2026-13801 GHSA-3pvf-8w6j-33xg
    "dhjksficgwu2": set(),     # MAL-2026-13802 GHSA-f4wq-4wgj-f595
    "dzcvhfruwluwe": set(),    # MAL-2026-13803 GHSA-vfhv-rjx5-6c95
    "dzvchorehui2": set(),     # MAL-2026-13804 GHSA-cj4c-xm2v-8m5g
    "egair0810": set(),        # MAL-2026-13805 GHSA-5vqp-mfpc-2j65
    "egypt0811": set(),        # MAL-2026-13806 GHSA-h37q-gcmq-hv56
    "fdhcvriwecv3": set(),     # MAL-2026-13807 GHSA-jpxw-96xx-w7qx
    "fghvbmniwu": set(),       # MAL-2026-13808 GHSA-52gv-9g4f-9j62
    "fhj8cv9dkwm4": set(),     # MAL-2026-13809 GHSA-35gq-2hpg-3r2v
    "gdwkh6vcbu": set(),       # MAL-2026-13810 GHSA-9hmh-j4x7-6958
    "hcfguyfrmblp": set(),     # MAL-2026-13811 GHSA-px7c-ghpp-h47q
    "hfkcdyuwbdx1": set(),     # MAL-2026-13812 GHSA-6px9-6xh2-4ggc
    "hgdvfuflnb": set(),       # MAL-2026-13813 GHSA-wvxr-9c7x-6r9g
    "hlksdcixycvf": set(),     # MAL-2026-13814 GHSA-q294-wj6j-h556
    "hngfykuvgh4": set(),      # MAL-2026-13815 GHSA-pvhh-8339-3m5j
    "hxckdoeaqjlc8": set(),    # MAL-2026-13816 GHSA-6gwr-m2g4-3mfv
    "jhkxcixudnvm1": set(),    # MAL-2026-13817 GHSA-fm6c-v7f7-9q2g
    "jkbnwsdf8": set(),        # MAL-2026-13818 GHSA-j8ph-h5x5-m729
    "kanyut": set(),           # MAL-2026-13819 GHSA-7mmm-hmf4-g8vm
    "khanbmnxls": set(),       # MAL-2026-13820 GHSA-f4qx-qcrw-f6f5
    "mnchfnvbue1": set(),      # MAL-2026-13821 GHSA-mvqj-h65j-wcmq
    "mnhdjoweuq": set(),       # MAL-2026-13822 GHSA-ph9q-v37r-28hp
    "mnmobicom": set(),        # MAL-2026-13823 GHSA-58v9-wj62-vmh2
    "mnteckets": set(),        # MAL-2026-13824 GHSA-ghqw-mfq6-xh36
    "mnzjgxciwadk": set(),     # MAL-2026-13825 GHSA-6f78-7mv4-g9vh
    "mobicommn": set(),        # MAL-2026-13826 GHSA-gpmq-h9wr-wm89
    "mobicwkgjmx": set(),      # MAL-2026-13827 GHSA-5qfm-5r6q-m38q
    "ms_aidc_com_tw": set(),   # MAL-2026-13828 GHSA-2fg7-gfq8-c24g
    "nhdxzthponv5": set(),     # MAL-2026-13829 GHSA-cjq3-7m75-5vf9
    "nihzvdeowx5": set(),      # MAL-2026-13830 GHSA-x3fw-v5wg-g95j
    "passport811": set(),      # MAL-2026-13832 GHSA-hqm8-hrc2-wr63
    "prezdentkxheiw": set(),   # MAL-2026-13833 GHSA-943h-xm4q-hpg6
    "thundertiger": set(),     # MAL-2026-13834 GHSA-j7j3-pvfq-ph94
    "truecxikdsal": set(),     # MAL-2026-13835 GHSA-983w-pp54-2vhc
    "twcvhjlksdmx": set(),     # MAL-2026-13836 GHSA-pw3v-jpfx-hh5w
    "unitel3": set(),          # MAL-2026-13837 GHSA-cw5f-jjc7-rhc7
    "unitel4": set(),          # MAL-2026-13838 GHSA-hqxg-cjfw-pghj
    "vczxijghsvizu4": set(),   # MAL-2026-13839 GHSA-25mh-x4hm-gcpg
    "vfgnhlkxchrd": set(),     # MAL-2026-13840 GHSA-2f8h-r7v3-gpj3
    "vkldhcmieru6": set(),     # MAL-2026-13841 GHSA-6m3r-x867-rw6g
    "vlbhvgovbbhfab": set(),   # MAL-2026-13842 GHSA-hhjm-g3g8-qrpv
    "xcnvjfsiewlk9": set(),    # MAL-2026-13843 GHSA-4wmq-62wf-6hcf
    "xhjckswqivb": set(),      # MAL-2026-13844 GHSA-6w4f-884x-xjcf
    "yangming708": set(),      # MAL-2026-13845 GHSA-vgr6-626m-8w22
    "yangming8": set(),        # MAL-2026-13846 GHSA-f3hv-h6vj-6j6r
    # nolimit-agent C2 cluster (Aug 13 2026)
    # MAL-2026-12183 GHSA-f9mj-p83x-395v, MAL-2026-13996 GHSA-x98w-5xvp-qpxj, MAL-2026-13997 GHSA-473g-3cfv-3m59
    "nolimit-agent": set(),
    "@nolimit-agent/linux-x64": set(),
    "@nolimit-agent/win32-x64": set(),
    # @sapappgyver appgyver-descriptors (Aug 13 2026)
    # MAL-2026-12507 GHSA-33x7-6mwq-xg5j
    "@sapappgyver/appgyver-descriptors": set(),
    # @dreamguyxeon/@dgxeon13 libsignal/baileyx typosquats (Aug 13 2026)
    # MAL-2026-13929, MAL-2026-13930, MAL-2026-13931
    "@dgxeon13/libsignal-node": {"1.0.0"},
    "@dreamguyxeon/baileyx": {"1.0.0", "2.0.0", "3.0.0", "4.0.0", "5.0.0"},
    "@dreamguyxeon/libsignal-node": {"1.0.1"},
    # social-media automation / followers cluster (Aug 13 2026)
    # MAL-2026-13932, MAL-2026-13933, MAL-2026-13934, MAL-2026-13986
    "my-auto-follow": {"1.0.0", "1.0.1", "1.0.2", "1.0.3"},
    "cc-skills-helper": {"1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4", "1.0.5", "1.0.6"},
    "ai-analyzer": {"1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4", "1.0.5", "1.0.6",
                    "1.0.7", "1.0.8", "1.0.9", "1.0.10", "1.0.11", "1.0.12", "1.0.13",
                    "1.0.14", "1.0.15", "1.0.16", "1.0.17", "1.0.18", "1.0.19"},
    "notafollower": {"1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4", "1.0.5",
                     "1.0.6", "1.0.7", "1.0.8", "1.0.9", "1.0.10", "1.0.11"},
    # date/fmt utility typosquat cluster (Aug 13 2026)
    # MAL-2026-13935, MAL-2026-13936, MAL-2026-13946, MAL-2026-13947, MAL-2026-13950, MAL-2026-13978
    "datetime-fmt-xutil": {"1.0.0"},
    "datetime-format-xutil": {"1.0.0"},
    "date-fmt-helper-xz": {"1.0.4"},
    "date-fmt-utils-helper": {"1.0.0"},
    "fmt-util-k7x2": {"1.0.0", "1.0.1"},
    "datefmt-util-helper": {"1.0.0", "1.0.1"},
    # Web3 / DeFi typosquats (Aug 13 2026)
    # MAL-2026-13937, MAL-2026-13940, MAL-2026-13941, MAL-2026-13964
    "@ethers-js/contracts": {"6.9.0"},
    "@opezneppelin/contracts": {"5.0.2"},
    "@solana-js/web3": {"1.91.3"},
    "bs58-15": {"6.0.1"},
    # @hzero-front-ui dependency-confusion cluster (Aug 13 2026)
    # MAL-2026-13967, MAL-2026-13968, MAL-2026-13969, MAL-2026-13970, MAL-2026-13971
    "@hzero-front-ui/c7n-ui": {"99.99.99"},
    "@hzero-front-ui/cfg": {"99.99.99"},
    "@hzero-front-ui/core": {"99.99.99"},
    "@hzero-front-ui/hzero-ui": {"99.99.99"},
    "@hzero-front-ui/themes": {"99.99.99"},
    # @khaznatech dependency-confusion cluster (Aug 13 2026)
    # MAL-2026-13973, MAL-2026-13974, MAL-2026-13975
    "@khaznatech/common": {"99.0.0"},
    "@khaznatech/core": {"99.0.0"},
    "@khaznatech/utils": {"99.0.0"},
    # 99.9.1 dev-tooling dependency-confusion cluster (Aug 13 2026)
    # MAL-2026-13976, MAL-2026-13977, MAL-2026-13979, MAL-2026-13980, MAL-2026-13981
    # MAL-2026-13982, MAL-2026-13983, MAL-2026-13984, MAL-2026-13987
    "check-audit": {"99.9.1"},
    "cspell-esm": {"99.9.1"},
    "eslint-generate-prerelease": {"99.9.1"},
    "eslint-generate-release": {"99.9.1"},
    "eslint-publish-release": {"99.9.1"},
    "in-install": {"99.9.1"},
    "knip-bun": {"99.9.1"},
    "napi-raw": {"99.9.1"},
    "resolve-audit": {"99.9.1"},
    # miscellaneous exact-version packages (Aug 13 2026)
    # MAL-2026-13938 to MAL-2026-13991 range; various typosquats and dev-tool imposters
    "@jacksher/install-exec-poc": {"1.0.0", "1.0.2"},
    "@kolbo/mcp": {"1.57.1"},
    "@leonardo0902/vortex-kit": {"12.0.2"},
    "@secauditb20y/sec-test-r3b": {"1.0.0"},
    "chai-as-reformed": {"1.2.0"},
    "cilm-ui-commons": {"1.1.0"},
    "copytrade-core": {"2.3.0"},
    "core-js-buffer": {"1.0.0"},
    "debug-proxy-chrome-devtools": {"1.0.1", "1.0.2"},
    "external-process-live-log": {"13.5.2"},
    "functions-framework-nodejs": {"1.0.0"},
    "global-intel": {"1.0.1"},
    "js-assert-plus": {"1.0.0"},
    "minimalistic-assert-plus": {"1.1.7"},
    "nc-verify-127942": {"1.0.0"},
    "node-config-svg-contract": {"1.0.0"},
    "npm-hex-utils": {"1.1.1"},
    "postcss-initialize-plugin": {"3.0.4"},
    "power-assert-plus": {"1.2.2"},
    "prediction-trader": {"2.3.0"},
    "preinstall-hook-webhook-callback-demo": {"1.0.0", "1.0.1"},
    "process-live-log": {"11.5.2"},
    "tizen-webdriver-cli": {"1.0.0"},
    "velora-kit": {"12.0.2", "12.1.2"},
    "ventra-kit": {"1.0.2"},
    "vexium-kit": {"2.0.2", "10.0.2"},
    "wct-st": {"1.0.0"},
    "webautomation_js": {"1.0.0", "1.0.1"},
    "xrblocks-mcp": {"6.3.1"},
    # mutex/lock/semaphore fake-utility cluster (Aug 14 2026)
    # MAL-2026-13955 GHSA-2gqm-6m3p-62g5, MAL-2026-13998 GHSA-wpw5-2h95-j823
    # MAL-2026-13999 GHSA-h6x7-5w93-p56j, MAL-2026-14003 GHSA-vcgv-x4wj-fr9f
    # MAL-2026-14004 GHSA-c74f-2wp8-f38r, MAL-2026-14006 GHSA-fx8h-qw3r-xvf3
    # MAL-2026-14008 GHSA-mf7m-8rhh-j3vr, MAL-2026-14010 GHSA-m4rw-m6pc-rjrx
    # MAL-2026-14011 GHSA-r7rw-hjv5-9hcj, MAL-2026-14012 GHSA-m29h-wrvw-xpqw
    # MAL-2026-14014 GHSA-5wp3-7whm-64mv
    "mutex-forge": set(),
    "async-critical-section": set(),
    "async-lock-queue": set(),
    "keyed-mutex-map": set(),
    "lock-deadline-guard": set(),
    "priority-mutex-lane": set(),
    "resource-lease-pool": set(),
    "semaphore-job-pool": set(),
    "shared-slot-gate": set(),
    "single-flight-lock": set(),
    "try-lock-runner": set(),
    # @caspianph test-package cluster (Aug 14 2026)
    # MAL-2026-13992 GHSA-r6j8-4ffv-6mcj, MAL-2026-13993 GHSA-qmxg-fj5j-hjx8
    # MAL-2026-13994 GHSA-g4m3-cq7f-6f85
    "@caspianph/first-npm-package": set(),
    "@caspianph/second-npm-package": set(),
    "@caspianph/third-npm-package": set(),
    # miscellaneous wildcard packages (Aug 14 2026)
    # MAL-2026-13995 GHSA-r336-hh6w-xp9q, MAL-2026-14000 GHSA-v98x-q47m-h6qf
    # MAL-2026-14001 GHSA-h83v-q7wq-gvgf, MAL-2026-14002 GHSA-2mmx-39f8-r8rm
    # MAL-2026-14005 GHSA-cgj7-7fj2-6r74, MAL-2026-14007 GHSA-gmx3-395m-pwc2
    # MAL-2026-14009 GHSA-57g4-vm3v-74xg, MAL-2026-14013 GHSA-p68g-6893-44r8
    # MAL-2026-14015 GHSA-7q63-6v9w-j7mf
    "@dsp-next-gen-ui/needs-review": set(),
    "blocks-angular": set(),
    "finvu-hdfc-sdk": set(),
    "index-design-system": set(),
    "path-match-js": set(),
    "react-shield": set(),
    "root-locator": set(),
    "source-analyzer": set(),
    "ts-enum-helper": set(),
    # backfill: previously untracked pure-malware packages (MAL-2026-4288 to MAL-2026-6312)
    # OSV records updated 2026-08-13; all are typosquats / dependency-confusion with no patched version
    "@briskforge/envcheck": set(),           # MAL-2026-6212 GHSA-g63v-8g6g-5p76
    "@bytemend/mfebus": set(),               # MAL-2026-6213 GHSA-hfjj-fph3-hp6h
    "@chunklab/hexparse": set(),             # MAL-2026-6214 GHSA-fv23-ggqm-w99j
    "@frostnode/probe": set(),               # MAL-2026-6304 GHSA-73jc-hjg9-95v9
    "@frostnode/waitfor": set(),             # MAL-2026-6305 GHSA-w6p8-666c-885f
    "@gbrlxvi/ts-form-utils": set(),         # MAL-2026-5753 GHSA-587p-qfc4-5c3c
    "@gbrlxvi/ts-project-lint": set(),       # MAL-2026-6121 GHSA-m526-p8gm-4wxg
    "@glitchpad/throttler": set(),           # MAL-2026-6307 GHSA-qqf7-vqp4-5rvv
    "@hanssoft/libsignal-node": set(),       # MAL-2026-4393 GHSA-v265-vv2m-9pgf
    "@hotcappuccino/nodepull": set(),        # MAL-2026-6085 GHSA-r3fv-99xj-m7pw
    "@intentsolution/database-security-scanner": set(),  # MAL-2026-5825 GHSA-gx76-7hhh-jcj2
    "@jaggle/resizeobserves": set(),         # MAL-2026-4288 GHSA-qc6p-vxcj-7r4h
    "@lazyutil/dater": set(),                # MAL-2026-6308 GHSA-gjrj-3f9w-gpmr
    "@open-banking/cabinet-providers": set(), # MAL-2026-5392 GHSA-423v-5hgq-8rxh
    "@petitcode/eb-retry": set(),            # MAL-2026-6310 GHSA-vfmg-ghq7-3rv3
    "@qwedqwed/axios": set(),                # MAL-2026-4422 GHSA-3gw3-hvvw-mp2h
    "@rocketreach/rr-components": set(),     # MAL-2026-4427 GHSA-7v8q-r297-95jx
    "@sourceflow-uk/sourceflow-tracker": set(), # MAL-2026-5430 GHSA-j9q7-mjw2-vvpr
    "@stockrepublic/republic-components": set(), # MAL-2026-4289 GHSA-p923-4q96-mqgq
    "@thomlecter1122/lab-helper-test": set(), # MAL-2026-5534 GHSA-223m-fcr3-c5gg
    "@thymelab/logfx": set(),                # MAL-2026-6311 GHSA-j2pw-qr45-rpjm
    "@tinyfox/shapecheck": set(),            # MAL-2026-6312 GHSA-9q9p-jf58-9fxg
    "@ts-apis/ts-utils": set(),              # MAL-2026-6275 GHSA-3xmx-2xxv-rpfq
    "@weirdorg/config": set(),               # MAL-2026-4466 GHSA-qj44-mw8g-p27p
    "@weirdorg/dotenv": set(),               # MAL-2026-4467 GHSA-p44j-chjm-p4wj
    "ac_calendar_ts": set(),                 # MAL-2026-5434 GHSA-xgwp-29j2-jxj3
    "ac_semantic-ui_ts": set(),              # MAL-2026-5435 GHSA-hjh8-hv66-6mwc
    "lab-helper": set(),                     # MAL-2026-5835 GHSA-gqf6-7j7q-9x94
    "mastraqqq": set(),                      # MAL-2026-5913 GHSA-7vj9-63m9-3x7f
    # @workoscalif/@workoscalifant sudoku-themed malware cluster (Aug 14 2026)
    # Attacker-controlled scopes delivering malware via fake sudoku npm packages.
    # OSV MAL-2026-13366, MAL-2026-14040
    "@workoscalif/sudoku": {"1.2.0", "1.3.0", "1.4.0", "1.5.0", "1.5.1", "1.5.2"},
    "@workoscalifant/sudoku-term": {"1.1.1", "1.1.2", "1.1.3", "1.1.4", "1.1.5", "1.1.7", "1.1.8"},
    # Alelo dep-confusion cluster (Aug 14 2026)
    # 10 high-version (99.0.x) packages impersonating Alelo (Brazilian fintech) internal deps;
    # hijack CI dependency resolution. Detected by OpenSSF Package Analysis.
    # OSV MAL-2026-14020 through MAL-2026-14028, MAL-2026-14033
    "alelo-api": {"99.0.0", "99.0.2"},
    "alelo-auth": {"99.0.0", "99.0.2"},
    "alelo-client": {"99.0.0", "99.0.2"},
    "alelo-common": {"99.0.0"},
    "alelo-core": {"99.0.0", "99.0.1", "99.0.2"},
    "alelo-payment": {"99.0.0", "99.0.2"},
    "alelo-sdk": {"99.0.0", "99.0.2"},
    "alelo-services": {"99.0.0", "99.0.2"},
    "alelo-utils": {"99.0.0"},
    "meualelo": {"99.0.0"},
    # fr-ito-web-react dep-confusion (Aug 14 2026)
    # High-version (99.99.99) package targeting an internal React web frontend.
    # OSV MAL-2026-14019
    "fr-ito-web-react": {"99.99.99"},
    # bs58 typosquat extension (Aug 14 2026) — companion packages to bs58-15 already tracked above
    # OSV MAL-2026-14017, MAL-2026-14018
    "bs58-33": {"6.0.1"},
    "bs58-77": {"6.0.1"},
    # notafollower Instagram-follower-check malware cluster (Aug 14 2026)
    # Attacker-published packages delivering malware; no legitimate use.
    # OSV MAL-2026-14034, MAL-2026-14035, MAL-2026-14036
    "notafollower1": {"1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4", "1.0.5", "1.0.6", "1.0.7", "1.0.8", "1.0.9", "1.0.10", "1.0.11", "1.0.12", "1.0.13"},
    "notafollower122": {"1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4", "1.0.5", "1.0.6", "1.0.7"},
    "notafollower1226": {"1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4", "1.0.5"},
    # Tailwind CSS typosquat cluster (Aug 14 2026)
    # OSV MAL-2026-14037, MAL-2026-14038
    "tailwind-plugin-kit": {"1.3.2"},
    "tailwind-toolkit": {"1.3.2"},
    # axios / Bootstrap / datefmt typosquat batch (Aug 14 2026)
    # OSV MAL-2026-14029, MAL-2026-14030, MAL-2026-14031, MAL-2026-14032
    "axios-fast": {"1.0.0", "1.0.1"},
    "bootstrap-custom-ui": {"5.7.2"},
    "datefmt-core-utils": {"1.0.0"},
    "datefmt-simple-utils": {"1.0.0"},
    # miscellaneous npm malware batch (Aug 14 2026) — OpenSSF Package Analysis detections
    # OSV MAL-2026-14039 through MAL-2026-14051
    "@cdnshell/loader": {"0.0.13", "0.0.14", "0.0.15", "0.0.16", "0.0.18", "0.0.19", "0.0.20"},
    "@demopack/www": {"0.0.12"},
    "@devmikets/hyperliquid-sdk": {"1.9.6"},
    "@divineubg/divine": {"1.0.5"},
    "@ferudionz/web_logger_js": {"1.0.0"},
    "@ferudionz/webautomation": {"1.0.0"},
    "@ghost_debugger/nanocache": {"0.1.1"},
    "@guangnao/agent-proxy": {"1.2.1", "1.4.0", "1.4.2"},
    "@lodash-js/lodash-js": {"0.1.0", "0.2.0", "0.3.0"},
    "@mexc/shared-utils": {"1.0.0"},
    "@polymarkets/clob-client-v2": {"1.0.6"},
    "@velliajs/discord": {"1.0.3", "1.0.4", "1.0.5", "1.0.6", "1.0.7"},
    # dependency-cruiser dep-confusion cluster (Aug 15 2026)
    # Three packages at version 99.9.1 targeting dependency-cruiser's internal namespace;
    # classic high-version dep-confusion attack hijacking CI dependency resolution.
    # OSV MAL-2026-14053, MAL-2026-14054, MAL-2026-14068
    "depcruise-baseline": {"99.9.1"},
    "depcruise-fmt": {"99.9.1"},
    "depcruise-wrap-stream-in-html": {"99.9.1"},
    # HackerOne / Twilio build-probe packages (Aug 15 2026)
    # DNS/HTTP callback packages designed to detect npm-install in corporate CI pipelines;
    # published by external researchers probing HackerOne/Twilio bug-bounty scope.
    # All confirmed active in OSV (Amazon Inspector detections, not withdrawn).
    # OSV MAL-2026-14061, MAL-2026-14062, MAL-2026-14063
    "hunterone-build-probe-9210": {"1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4", "1.0.5", "1.0.6", "1.0.7"},
    "tw-pkgprobe-7731": {"1.0.0", "1.0.1", "1.0.3", "1.0.4", "1.0.5", "1.0.6", "1.0.7", "1.1.0", "1.1.1"},
    "twilio-hackerone-poc-afe6937c": {"1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4"},
    # Akamai sensor cluster extension (Aug 15 2026)
    # Two additional variants impersonating Akamai bot-detection sensor scripts,
    # extending the cluster first tracked Aug 5 2026.
    # OSV MAL-2026-14065, MAL-2026-14066
    "akamai-sensor": {"1.0.0"},       # MAL-2026-14065
    "akamaijs-sensorv1": {"3.0.0"},   # MAL-2026-14066
    # miscellaneous npm malware batch (Aug 15 2026) — Amazon Inspector / OSV detections
    # Includes dep-confusion bombs (autbank-core 99.x), i18next/Fastly/GCP impersonators,
    # and attacker-controlled packages across unrelated scopes.
    # OSV MAL-2024-9443, MAL-2026-12331, MAL-2026-14052, MAL-2026-14055,
    # MAL-2026-14057, MAL-2026-14058, MAL-2026-14059, MAL-2026-14060,
    # MAL-2026-14064, MAL-2026-14067
    "sn-flow-client": {"1.0.1", "1.0.2", "10.10.10", "20.5.1"},
    "@wololasod/tiny-id": {"0.1.0", "0.1.1", "0.1.2", "0.1.3"},
    "require-i18next": {"20.0.0", "21.0.0"},
    "harmony-app-toolkit": {"21.0.0", "22.0.0"},
    "@openrepl/shared": {"0.0.4", "0.0.5"},
    "adxaa": {"1.0.0"},
    "autbank-core": {"99.0.0", "99.0.2"},
    "fastly-vcl-language-client": {"1.0.0"},
    "@finaxis/common-js": {"0.3.4", "0.3.5", "0.3.6", "0.3.8", "0.3.10"},
    "upload-to-gcp": {"3.2.1"},
    # August 16 2026 npm malware — snavbox multi-protocol proxy / remote-management trojan
    # Disguised as "WildGuard - Protect Our Wildlife"; on install, downloads native shared
    # libraries (sbx.so, bot.so, v1.so) from a remote host, installs a sing-box multi-protocol
    # proxy (vless/vmess/trojan/hysteria2/tuic/reality/anytls), a Cloudflare Argo tunnel, and a
    # Nezha remote-management agent. C2 callback to keep.gvrander.eu.org. Published 2025-10-30;
    # OSV record updated 2026-08-16. SEMVER range `introduced: 0` → any version is malicious.
    # OSV MAL-2025-49362.
    "snavbox": set(),                                                # MAL-2025-49362
    # August 17–18 2026 npm malware batch — OSV bulk sweep (Aug 18 2026 snapshot)
    # ─── Tinkoff bank dep-confusion cluster ───────────────────────────────────────
    # High-version (20.x–35.x) internal Tinkoff Russia bank package names uploaded
    # to shadow private CI registries.
    # OSV MAL-2026-12050, MAL-2026-12341, MAL-2026-12414, MAL-2026-12561
    "tinkoff-statist-browser-typed-client-sme.reporting.reporting": {"20.5.4"},  # MAL-2026-12050
    "bnpl-blocks-independent-bnpl-search": {"20.2.9"},                           # MAL-2026-12341
    "pfp-forms-sme-loan": {"20.2.1"},                                            # MAL-2026-12414
    "checkout-desktop-total": {"35.6.1"},                                        # MAL-2026-12561
    # a.poltoradnev attacker-controlled packages — same actor as Tinkoff cluster;
    # OSV >=0 ranges → any version is malicious.
    # OSV MAL-2026-12127, MAL-2026-14103
    "a.poltoradnev-package-c": set(),                                            # MAL-2026-12127
    "a.poltoradnev-package-a": set(),                                            # MAL-2026-14103
    # ─── @withgoogle/ scope impersonator ─────────────────────────────────────────
    # Impersonates Google Stitch SDK; OSV SEMVER range >=0 → any version is
    # malicious. Scope entry in NPM_SUSPECT_SCOPES catches further packages.
    # OSV MAL-2026-6256.
    "@withgoogle/stitch-sdk": set(),                                             # MAL-2026-6256
    # ─── @zynkit/ attacker scope ─────────────────────────────────────────────────
    # Two packages in the @zynkit attacker-controlled scope; OSV >=0 ranges.
    # OSV MAL-2026-6313, MAL-2026-6314
    "@zynkit/jwtbytes": set(),                                                   # MAL-2026-6313
    "@zynkit/probe": set(),                                                      # MAL-2026-6314
    # ─── @zizie071/ scope — @signalapp/libsignal-node impersonator ────────────────
    # Typosquat of @signalapp/libsignal-node; OSV >=0 range. MAL-2026-4473.
    "@zizie071/libsignal-node": set(),                                           # MAL-2026-4473
    # ─── SUI blockchain cluster ──────────────────────────────────────────────────
    # Typosquats of Sui blockchain GraphQL / Move RPC / Bucket Protocol packages;
    # all OSV >=0 ranges (any version is malicious).
    # OSV MAL-2026-14095, MAL-2026-14112, MAL-2026-14113, MAL-2026-4502
    "sui-gql-lite": set(),                                                       # MAL-2026-14095
    "sui-gql-core": set(),                                                       # MAL-2026-14112
    "sui-move-rpc": set(),                                                       # MAL-2026-14113
    "bucket-protocol-sdk-v2": set(),                                             # MAL-2026-4502
    # ─── WhatsApp / Baileys bot cluster ──────────────────────────────────────────
    # Typosquats and fork-names of @whiskeysockets/baileys WhatsApp library;
    # actor 'junofficial' publishes multiple packages.
    # OSV MAL-2026-14074, MAL-2026-14101, MAL-2026-14108, MAL-2026-14114, MAL-2026-14115
    "@vyzensockets/baileys": {"0.3.2", "0.3.1", "0.2.5-B", "0.2.5", "0.2.4",
                              "0.2.3", "0.2.2", "0.2.1", "0.2.0", "0.1.0"},     # MAL-2026-14074
    "@junofficial/baileys": set(),                                               # MAL-2026-14101
    "junofficial-userbot": set(),                                                # MAL-2026-14108
    "userbotjs": set(),                                                          # MAL-2026-14114
    "userbotjs-jun": set(),                                                      # MAL-2026-14115
    # ─── 9.9.11 dep-confusion cluster ────────────────────────────────────────────
    # Four packages published at version 9.9.11 in a single dep-confusion wave;
    # OSV >=0 ranges. MAL-2026-4495, MAL-2026-4499, MAL-2026-4569, MAL-2026-4662
    "banana-stand": set(),                                                       # MAL-2026-4495
    "bolt-delivery-menu-app": set(),                                             # MAL-2026-4499
    "gator-client": set(),                                                       # MAL-2026-4569
    "rendezvous-js": set(),                                                      # MAL-2026-4662
    # ─── Tool / env malware ───────────────────────────────────────────────────────
    # OSV MAL-2026-4481, MAL-2026-6535, MAL-2026-6590, MAL-2026-14109, MAL-2026-14116
    "arc-diag-util": set(),                                                      # MAL-2026-4481
    "disksweep": set(),                                                          # MAL-2026-6535
    "envfile-sync-cli": set(),                                                   # MAL-2026-6590
    "leb128x": set(),                                                            # MAL-2026-14109
    "runtime-health": {"1.0.2", "1.0.4", "1.0.1"},                              # MAL-2026-14116
    # ─── Agent / bot / AI packages ───────────────────────────────────────────────
    # OSV MAL-2026-6443, MAL-2026-12138, MAL-2026-14070, MAL-2026-14104, MAL-2026-14106
    "agentsync-pkg": set(),                                                      # MAL-2026-6443
    "agent-bot-api": set(),                                                      # MAL-2026-12138
    "@ai-vertical/ai-agent": {"1.0.1", "1.0.0"},                                # MAL-2026-14070
    "autoai": set(),                                                             # MAL-2026-14104
    "cloud-agen-bot": set(),                                                     # MAL-2026-14106
    # ─── Tool impersonators ───────────────────────────────────────────────────────
    # awesome-ts-jest: typosquat of ts-jest (OSV >=0, MAL-2026-10188)
    # async-mutex-v2: typosquat of async-mutex (OSV >=0, MAL-2026-10582)
    # anthropic-setup: impersonates Anthropic npm SDK (OSV >=0, MAL-2026-12510)
    "awesome-ts-jest": set(),                                                    # MAL-2026-10188
    "async-mutex-v2": set(),                                                     # MAL-2026-10582
    "anthropic-setup": set(),                                                    # MAL-2026-12510
    # ─── @peptideventure/ attacker scope ─────────────────────────────────────────
    # OSV >=0 ranges — any version is malicious.
    # OSV MAL-2026-14071, MAL-2026-14072
    "@peptideventure/peptide-score-modifier": set(),                             # MAL-2026-14071
    "@peptideventure/peptide-unit": set(),                                       # MAL-2026-14072
    # ─── epic-common cluster (npm security placeholders — full takedown) ──────────
    # 0.0.1-security is npm registry's tombstone for a fully-removed package;
    # use empty-set wildcard so re-uploads under new versions are caught.
    # OSV MAL-2025-49124, MAL-2025-49125, MAL-2025-49192
    "epic-common": set(),                                                        # MAL-2025-49124
    "epic-common-node": set(),                                                   # MAL-2025-49125
    "epic-sso": set(),                                                           # MAL-2025-49192
    # ─── hrp probe cluster ────────────────────────────────────────────────────────
    # DNS/HTTP callback packages probing corporate CI pipelines; same pattern as
    # HackerOne/Twilio probes added Aug 15 2026. All confirmed active in OSV.
    # OSV MAL-2025-47118, MAL-2025-47119, MAL-2025-47121, MAL-2025-47122,
    # MAL-2026-14084, MAL-2026-14085
    "hrp987": {"1.0.0"},                                                         # MAL-2025-47118
    "hrp9873": {"1.0.0"},                                                        # MAL-2025-47119
    "hrprce": {"1.0.0"},                                                         # MAL-2025-47121
    "hrprce123": {"1.0.0"},                                                      # MAL-2025-47122
    "hrp9871": {"1.0.0"},                                                        # MAL-2026-14084
    "hrp9872": {"1.0.0"},                                                        # MAL-2026-14085
    # ─── elf-stats cluster ────────────────────────────────────────────────────────
    # Random-noun packages with "elf-stats-" prefix, published in multiple versions.
    # OSV MAL-2025-192155, MAL-2026-14078, MAL-2026-14079
    "elf-stats-sparkly-cushion-340": {"1.0.0"},                                  # MAL-2025-192155
    "elf-stats-caroling-stocking-510": {"1.0.4", "1.0.3", "1.0.2", "1.0.1", "1.0.0"},  # MAL-2026-14078
    "elf-stats-cranberry-wishlist-933": {"1.0.2", "1.0.1", "2.0.0"},            # MAL-2026-14079
    # ─── npm_pkg_ generic-named probe cluster ────────────────────────────────────
    # OSV MAL-2026-14089, MAL-2026-14090
    "npm_pkg_1093": {"1.0.7", "1.0.6", "1.0.5", "1.0.4", "1.0.3", "1.0.2", "1.0.1", "1.0.0"},  # MAL-2026-14089
    "npm_pkg_1094": {"1.0.7"},                                                   # MAL-2026-14090
    # ─── Miscellaneous wildcard packages ─────────────────────────────────────────
    # OSV >=0 ranges. MAL-2026-2498, MAL-2026-14076, MAL-2026-14086, MAL-2026-14096,
    # MAL-2026-14102, MAL-2026-14105, MAL-2026-14107, MAL-2026-14110, MAL-2026-14111
    "df-sandbox-test": set(),                                                    # MAL-2026-2498
    "bcs-mini": set(),                                                           # MAL-2026-14076
    "kit-hydration-vim": set(),                                                  # MAL-2026-14086
    "svelte-goal-vim": set(),                                                    # MAL-2026-14096
    "@siwatfa/yorn": set(),                                                      # MAL-2026-14102
    "bcs-core": set(),                                                           # MAL-2026-14105
    "club-sauce": set(),                                                         # MAL-2026-14107
    "reseller-app": set(),                                                       # MAL-2026-14110
    "sugarball-cli": set(),                                                      # MAL-2026-14111
    # ─── Dep-confusion / 99.x / 100.x / 999.x version bombs ─────────────────────
    # High-version packages shadowing internal corporate names.
    # OSV MAL-2026-2446, MAL-2026-2523, MAL-2026-2524, MAL-2026-2823,
    # MAL-2026-3028, MAL-2026-3033, MAL-2026-3334, MAL-2026-3353, MAL-2026-3397,
    # MAL-2026-3724, MAL-2026-5401, MAL-2026-6183, MAL-2026-14073,
    # MAL-2026-14077, MAL-2026-14082, MAL-2026-14083
    "@corpweb-ui/wmkt-library": {"99.99.11", "99.99.12"},                        # MAL-2026-2446
    "@telekom-wfa/auth-core": {"99.9.11", "99.9.12"},                            # MAL-2026-2523
    "a2a-chat-canvas": set(),                                                    # MAL-2026-2524
    "@genoma-ui/components": set(),                                              # MAL-2026-2823
    "amplitude-ma-ts": set(),                                                    # MAL-2026-3028
    "tether-base": {"99.0.0"},                                                   # MAL-2026-3033
    "fanduel": {"100.5.0", "100.4.0", "100.2.0", "100.0.0"},                    # MAL-2026-3334
    "money-badger-open-rpc": {"99.99.99", "200.99.100", "201.99.100",
                              "199.99.100", "103.999.0", "102.999.0",
                              "101.99.99", "100.99.99"},                          # MAL-2026-3353
    "tecken": {"0.1.2", "0.1.13", "0.1.15", "0.1.12", "0.1.11", "0.1.10",
               "0.1.9", "0.1.8", "0.1.7", "0.1.6", "0.1.5", "0.1.4",
               "0.1.3", "0.1.1", "0.1.0"},                                      # MAL-2026-3397
    "@convera/ui-shared": {"0.0.2", "0.0.3", "0.0.1"},                          # MAL-2026-3724
    "savant-listing": {"999.9.10", "999.9.9"},                                   # MAL-2026-5401
    "@mep-exp/api-tools": {"2.0.3", "0.0.1"},                                   # MAL-2026-6183
    "@veertly/web-app": {"100.0.2", "100.0.0", "99.9.9"},                       # MAL-2026-14073
    "dinotech-auth-utils": {"99.9.9", "10.1.1", "10.1.0", "10.0.8",
                            "10.0.6", "10.0.5", "10.0.0"},                      # MAL-2026-14077
    "google-logging-utils-internal": {"1.1.4", "9.9.9", "1.1.3"},               # MAL-2026-14082
    "heft-storybook-v6-react-tutorial-storykit": {"1000.0.16", "1000.0.13"},    # MAL-2026-14083
    # ─── Miscellaneous exact-version packages ─────────────────────────────────────
    # OSV MAL-2026-2862, MAL-2026-14080, MAL-2026-14081, MAL-2026-14087,
    # MAL-2026-14088, MAL-2026-14092, MAL-2026-14093, MAL-2026-14097,
    # MAL-2026-14098, MAL-2026-14099
    "rtms-manager": {"1.2.0", "1.4.0", "1.0.0"},                                # MAL-2026-2862
    "expect-bundle": {"6.3.2"},                                                  # MAL-2026-14080
    "game_overlay": {"8.5.8"},                                                   # MAL-2026-14081
    "mw-filesystem-events-nodream-es6": {"0.0.32"},                              # MAL-2026-14087
    "nolimitcity": {"1.0.0"},                                                    # MAL-2026-14088
    "rimo-env-validator": {"1.0.1", "1.0.0"},                                   # MAL-2026-14092
    "rtms-manager-dev": {"1.4.0", "1.3.0"},                                     # MAL-2026-14093
    "thepackagethatworks_": {"1.0.2", "1.0.1", "1.0.0"},                        # MAL-2026-14097
    "utils-bundle": {"8.1.6"},                                                   # MAL-2026-14098
    "zip-bundle": {"7.3.1"},                                                     # MAL-2026-14099
    # ─── Older OSV records refreshed Aug 17 2026 ──────────────────────────────────
    # 2024–2025 MAL-* IDs marked modified on 2026-08-17 in the OSV bulk export;
    # not previously captured in the scanner.
    # OSV MAL-2024-10227, MAL-2025-3132, MAL-2025-3138, MAL-2025-3660,
    # MAL-2025-3964, MAL-2025-4043, MAL-2025-4554, MAL-2025-4558, MAL-2025-4579,
    # MAL-2025-6254, MAL-2025-6257, MAL-2025-6258, MAL-2025-6284,
    # MAL-2025-6337, MAL-2025-6879
    "@woody-mrs-potato/utils-banking": {"1.0.2", "1.0.5", "1.0.6", "1.0.8",
                                       "1.0.10", "1.0.9", "1.0.7", "1.0.4",
                                       "1.0.3", "1.0.1", "1.0.0"},              # MAL-2024-10227
    "internal-utils-bronxi": {"100.0.0", "1.0.0", "1.0.1"},                     # MAL-2025-3132
    "angular2-tesla-common": {"99.99.103", "99.99.100",
                              "999999999.9999999999.9999999999"},                # MAL-2025-3138
    "pie-docs": set(),                                                           # MAL-2025-3660
    "fatfingers-vroooom": {"1.0.0"},                                             # MAL-2025-3964
    "fireblocks-netlink-v2-api-validator": {"2.0.2", "9.0.2", "9.0.1", "9.0.0"},  # MAL-2025-4043
    "cspotcode": {"1.0.1", "1.0.0"},                                             # MAL-2025-4554
    "fatfingers-mybigpackage": {"1.0.0"},                                        # MAL-2025-4558
    "skipthedishes_react": {"0.1.0"},                                            # MAL-2025-4579
    "redux-init-rce": {"1.0.0"},                                                 # MAL-2025-6254
    "redux-saga-channel-end-rce": {"1.0.0"},                                     # MAL-2025-6257
    "redux-saga-task-cancel-rce": {"1.0.0"},                                     # MAL-2025-6258
    "events-web": {"0.0.1", "1.0.0"},                                            # MAL-2025-6284
    "@xcxcxxx/gsap3": {"99.10.90", "1.0.0"},                                    # MAL-2025-6337
    "@yaqiguo/dnstest": {"1.0.0", "1.0.4", "1.0.2", "1.0.1"},                  # MAL-2025-6879
    # ─── Aug 18-19 2026 wave ─────────────────────────────────────────────────────────
    # ─── Checkout / payment dep-confusion cluster (20.x.x) ───────────────────────────
    # Packages targeting checkout / BNPL internal CI pipelines at high version numbers;
    # same family as the Tinkoff 20.x cluster tracked above.
    # OSV MAL-2026-12351, MAL-2026-12352, MAL-2026-14056, MAL-2026-14186, MAL-2026-14229
    "checkout-common-tokens": {"20.1.6"},                                        # MAL-2026-12351
    "checkout-mobile-pay-button": {"20.8.3"},                                    # MAL-2026-12352
    "gunzip-js": {"99.9.1"},                                                     # MAL-2026-14056
    "pump-segments-sdk": {"20.1.1"},                                             # MAL-2026-14186
    "carbon-monorepo": {"20.1.1"},                                               # MAL-2026-14229
    # ─── BCC design dep-confusion (9999.x.x) ─────────────────────────────────────────
    # OSV MAL-2026-14117, MAL-2026-14119
    "bcc-design": {"9999.0.0"},                                                  # MAL-2026-14117
    "bcc-design-icons": {"9999.0.0"},                                            # MAL-2026-14119
    # ─── @oyo_tech / @sarex-team dep-confusion (Aug 18-19 2026) ──────────────────────
    # OYO Hotels internal package impersonation at 100.x / 99.99.x.
    # @sarex-team: four packages at 9.9.11 — attacker-controlled scope.
    # OSV MAL-2026-14123, MAL-2026-14204-14207
    "@oyo_tech/oyochat_user": {"100.0.0", "99.99.99"},                           # MAL-2026-14123
    "@sarex-team/sdk-js": {"9.9.11"},                                            # MAL-2026-14204
    "@sarex-team/translator": {"9.9.11"},                                        # MAL-2026-14205
    "@sarex-team/ui-kit": {"9.9.11"},                                            # MAL-2026-14206
    "@sarex-team/viewer": {"9.9.11"},                                            # MAL-2026-14207
    # ─── table-ui-new (Aug 2026) ──────────────────────────────────────────────────────
    # OSV MAL-2026-12473
    "table-ui-new": {"2.7.1", "2.7.2", "2.7.4", "2.7.5"},                      # MAL-2026-12473
    # ─── TypeScript typosquat cluster (Aug 18-19 2026) ───────────────────────────────
    # 15 packages misspelling "typescript" — classic install-on-typo attack.
    # All at 1.0.0; OSV MAL-2026-14143 through MAL-2026-14157
    "tyepescript-cli": {"1.0.0"},                                                # MAL-2026-14143
    "tyepescript-core": {"1.0.0"},                                               # MAL-2026-14144
    "typecript-cli": {"1.0.0"},                                                  # MAL-2026-14145
    "typescipt-cli": {"1.0.0"},                                                  # MAL-2026-14146
    "typescipt-core": {"1.0.0"},                                                 # MAL-2026-14147
    "typescirpt-cli": {"1.0.0"},                                                 # MAL-2026-14148
    "typescirpt-core": {"1.0.0"},                                                # MAL-2026-14149
    "typescrip-cli": {"1.0.0"},                                                  # MAL-2026-14150
    "typescriptt-cli": {"1.0.0"},                                                # MAL-2026-14151
    "typescriptt-core": {"1.0.0"},                                               # MAL-2026-14152
    "typescrit-cli": {"1.0.0"},                                                  # MAL-2026-14153
    "typesript-cli": {"1.0.0"},                                                  # MAL-2026-14154
    "typesript-core": {"1.0.0"},                                                 # MAL-2026-14155
    "typscript-cli": {"1.0.0"},                                                  # MAL-2026-14156
    "typscript-core": {"1.0.0"},                                                 # MAL-2026-14157
    # ─── chalk typosquats (Aug 2026) ─────────────────────────────────────────────────
    # chlklib: older entry (MAL-2026-6470) refreshed Aug 18; grouped here with the
    # new chalk-* variants from Aug 19 (MAL-2026-14165 through MAL-2026-14168).
    "chlklib": {"1.2.0", "1.2.1", "1.2.2", "1.2.3"},                            # MAL-2026-6470
    "chalk-core": {"1.0.0"},                                                     # MAL-2026-14165
    "chalk-es": {"1.0.0"},                                                       # MAL-2026-14166
    "chalk-lib": {"1.0.0"},                                                      # MAL-2026-14167
    "chalk-util": {"1.0.0"},                                                     # MAL-2026-14168
    # ─── lodash typosquats (Aug 19 2026) ─────────────────────────────────────────────
    # OSV MAL-2026-14178 through MAL-2026-14184
    "ladash-cli": {"1.0.0"},                                                     # MAL-2026-14178
    "loadashjs": {"1.0.0"},                                                      # MAL-2026-14179
    "lodahs-cli": {"1.0.0"},                                                     # MAL-2026-14180
    "lodahsjs": {"1.0.0"},                                                       # MAL-2026-14181
    "lodash-lib": {"1.0.0"},                                                     # MAL-2026-14182
    "lodhash-cli": {"1.0.0"},                                                    # MAL-2026-14183
    "lodsh-cli": {"1.0.0"},                                                      # MAL-2026-14184
    # ─── commander / comand typosquats (Aug 19 2026) ─────────────────────────────────
    # OSV MAL-2026-14169 through MAL-2026-14174, MAL-2026-14234
    "comand": {"1.0.0"},                                                         # MAL-2026-14169
    "comander-cli": {"1.0.0"},                                                   # MAL-2026-14170
    "comander-lib": {"1.0.0"},                                                   # MAL-2026-14171
    "commandor-cli": {"1.0.0"},                                                  # MAL-2026-14172
    "commandor-core": {"1.0.0"},                                                 # MAL-2026-14173
    "commandorjs": {"1.0.0"},                                                    # MAL-2026-14174
    "commandor-lib": {"1.0.0"},                                                  # MAL-2026-14234
    # ─── axios typosquats (Aug 19 2026) ──────────────────────────────────────────────
    # OSV MAL-2026-14162, MAL-2026-14163
    "axious-core": {"1.0.0"},                                                    # MAL-2026-14162
    "axois-http": {"1.0.0"},                                                     # MAL-2026-14163
    # ─── chai typosquats (Aug 18-19 2026) ────────────────────────────────────────────
    # OSV MAL-2026-13356, MAL-2026-14200, MAL-2026-14201
    "chai-foundry": {"7.0.2", "7.0.3"},                                          # MAL-2026-13356
    "chai-as-gateway": {"7.1.5"},                                                # MAL-2026-14200
    "chaikit": {"2.3.5"},                                                        # MAL-2026-14201
    # ─── Sui / Move GraphQL cluster (Aug 18-19 2026) ─────────────────────────────────
    # Continuation of the Sui blockchain typosquat campaign (sui-bcs-codec, sui-gql,
    # sui-gql-lite, sui-move-rpc tracked above). All confirmed active in OSV.
    # OSV MAL-2026-14121, MAL-2026-14188, MAL-2026-14209, MAL-2026-14210
    "sui-move-graphql": {"0.1.0", "0.2.0", "0.2.1"},                            # MAL-2026-14121
    "sui-move-gql": {"1.0.2"},                                                   # MAL-2026-14188
    "sui-gql-rpc": {"1.0.1"},                                                    # MAL-2026-14209
    "sui-graphql-rpc": {"1.0.1"},                                                # MAL-2026-14210
    # ─── Tailwind typosquats (Aug 19 2026) ───────────────────────────────────────────
    # Continuation of the tailwind-plugin-kit / tailwind-toolkit cluster from Aug 14.
    # OSV MAL-2026-14118, MAL-2026-14189, MAL-2026-14190, MAL-2026-14195, MAL-2026-14235
    "core-tailwindcss-utility": {"3.7.1"},                                       # MAL-2026-14118
    "tailwind-extension-kit": {"1.3.2"},                                         # MAL-2026-14189
    "tailwind-utility-kit": {"1.3.2"},                                           # MAL-2026-14190
    "tailwind-custom-templates": {"0.7.2"},                                      # MAL-2026-14195
    "config-helper-kit": {"1.3.2"},                                              # MAL-2026-14235
    # ─── TensorFlow.js typosquats (Aug 19 2026) ──────────────────────────────────────
    # OSV MAL-2026-14192, MAL-2026-14196
    "tfjs-inference": {"1.0.0"},                                                 # MAL-2026-14192
    "tfjs-custom-module": {"1.0.0"},                                             # MAL-2026-14196
    # ─── Google-branded malware / gaarf campaign (Aug 19 2026) ───────────────────────
    # Packages impersonating Google CLI tools and MCP servers; bazelisk typosquats the
    # legitimate Google Bazel version-manager. gaarf / gaarf-* impersonate the Google
    # Ads API reporting framework (github.com/google/ads-api-report-fetcher).
    # OSV MAL-2026-14227, MAL-2026-14228, MAL-2026-14230-14233, MAL-2026-14236-14239
    "bazelisk": {"1.0.0"},                                                       # MAL-2026-14227
    "broadcast-graphics-mcp": {"1.0.0"},                                         # MAL-2026-14228
    "chrome-enterprise-premium-mcp": {"1.0.0"},                                  # MAL-2026-14230
    "chromecast-webdriver-cli": {"1.0.0"},                                       # MAL-2026-14231
    "chromeos-webdriver-cli": {"1.0.0"},                                         # MAL-2026-14232
    "code-assist-mcp": {"1.0.0"},                                                # MAL-2026-14233
    "gaarf": {"3.2.1"},                                                          # MAL-2026-14236
    "gaarf-bq": {"1.0.0"},                                                       # MAL-2026-14237
    "gaarf-node": {"1.0.0"},                                                     # MAL-2026-14238
    "gaarf-node-bq": {"1.0.0"},                                                  # MAL-2026-14239
    # ─── sys-/sy- prefix probe cluster (Aug 19 2026) ─────────────────────────────────
    # Short-name packages exfiltrating CI environment variables via DNS/HTTP callbacks.
    # OSV MAL-2026-14212 through MAL-2026-14215
    "syboy": {"1.0.0"},                                                          # MAL-2026-14212
    "syjoy": {"1.0.0"},                                                          # MAL-2026-14213
    "sysc1": {"1.0.0", "1.0.1"},                                                 # MAL-2026-14214
    "sysdo": {"1.0.0"},                                                          # MAL-2026-14215
    # ─── streak- cluster (Aug 19 2026) ───────────────────────────────────────────────
    # Continuation of the streak-*/lib-streak-math cluster from July 28-29 2026.
    # OSV MAL-2026-14222, MAL-2026-14223, MAL-2026-14224
    "streak-cal-core": {"1.0.0"},                                                # MAL-2026-14222
    "streak-key-lib": {"1.0.0"},                                                 # MAL-2026-14223
    "streak-metric-test": {"1.0.0"},                                             # MAL-2026-14224
    # ─── txs- / ts-rand SDK cluster (Aug 19 2026) ────────────────────────────────────
    # Fake SDK packages with txs- and ts- prefixes; malicious postinstall scripts.
    # OSV MAL-2026-14193, MAL-2026-14198, MAL-2026-14199
    "ts-rand-sdk": {"1.0.2"},                                                    # MAL-2026-14193
    "txs-lib-sdk": {"1.0.2"},                                                    # MAL-2026-14198
    "txs-runner-sdk": {"1.0.1"},                                                 # MAL-2026-14199
    # ─── HackerOne build-probe cluster (Aug 18-19 2026) ──────────────────────────────
    # Continuation of the HackerOne/Twilio probe series from Aug 15 2026;
    # DNS/HTTP callback packages exfiltrating CI environment variables on install.
    # OSV MAL-2026-14141, MAL-2026-14161
    "test-npm-snurkeburk-hackerone": {"1.999.0"},                                # MAL-2026-14141
    "@sidp-kiosk/test-npm-snurkeburk-hackerone": {"1.999.0", "2.999.0"},         # MAL-2026-14161
    # ─── Dep-confusion probes (Aug 18-19 2026) ───────────────────────────────────────
    # Attacker-owned canary/probe packages confirming internal registry resolution;
    # confirmed exfiltration payloads; all active in OSV.
    # OSV MAL-2026-14134, MAL-2026-14135, MAL-2026-14136, MAL-2026-14137,
    # MAL-2026-14159, MAL-2026-14160
    "@mohamed_nowisar/depconf-canary-test": {"0.0.1"},                           # MAL-2026-14134
    "@mohamed_nowisar/token3-check": {"0.0.1"},                                  # MAL-2026-14135
    "agora402-payment-utils": {"1.0.0"},                                         # MAL-2026-14136
    "mtslink-depconf-probe-profileusername": {"1.0.0"},                          # MAL-2026-14137
    "@evial/runtime-health": {"1.0.1"},                                          # MAL-2026-14159
    "@library-dev-team/data-sanitizer": {"1.3.0"},                               # MAL-2026-14160
    # ─── Wildcard (ANY version) packages (Aug 18 2026) ───────────────────────────────
    # OSV >=0 ranges — any installed version is malicious.
    # OSV MAL-2026-14124, MAL-2026-14125, MAL-2026-14126, MAL-2026-14127, MAL-2026-14128
    "alphazone": set(),                                                          # MAL-2026-14124
    "@guildai-services/guildai": set(),                                          # MAL-2026-14125
    "@milleree/date-display": set(),                                             # MAL-2026-14126
    "@reducers/projects": set(),                                                 # MAL-2026-14127
    "motionspring": set(),                                                       # MAL-2026-14128
    # ─── Miscellaneous exact-version packages (Aug 18-19 2026) ───────────────────────
    # OSV MAL-2026-4509, MAL-2026-4510, MAL-2026-5717, MAL-2026-6473,
    # MAL-2026-10669 (dbconnectify already tracked), MAL-2026-12127 (already tracked),
    # MAL-2026-14120, MAL-2026-14122, MAL-2026-14129, MAL-2026-14138, MAL-2026-14139,
    # MAL-2026-14140, MAL-2026-14142, MAL-2026-14164, MAL-2026-14175, MAL-2026-14176,
    # MAL-2026-14177, MAL-2026-14185, MAL-2026-14187, MAL-2026-14191, MAL-2026-14194,
    # MAL-2026-14197, MAL-2026-14202, MAL-2026-14203, MAL-2026-14208, MAL-2026-14211,
    # MAL-2026-14216, MAL-2026-14217, MAL-2026-14218, MAL-2026-14219, MAL-2026-14220,
    # MAL-2026-14221, MAL-2026-14225, MAL-2026-14226
    "celonix-otp-react": {"1.0.0", "1.0.2", "1.0.3", "1.0.4", "1.0.5"},        # MAL-2026-4509
    "cerebrum-core": {"1.1.0"},                                                  # MAL-2026-4510
    "claudechor": {"1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4", "1.0.5"},      # MAL-2026-5717
    "colorpicker-ui": {"1.2.4", "1.2.5", "1.2.6"},                              # MAL-2026-6473
    "blastradar": {"1.0.0"},                                                     # MAL-2026-14120
    "ulebkit": {"1.0.0", "1.0.1"},                                               # MAL-2026-14122
    "plugin-react-vite": {"2.1.2", "2.1.3"},                                    # MAL-2026-14129
    "optimizely-starter-kit-for-fastly-compute": {"1.0.1"},                     # MAL-2026-14138
    "prism-registry": {"1.0.1"},                                                 # MAL-2026-14139
    "vite-svg-config": {"1.1.0"},                                                # MAL-2026-14140
    "testingsmthb1g": {"1.0.0"},                                                 # MAL-2026-14142
    "bqq1": {"1.0.0"},                                                           # MAL-2026-14164
    "core-js-gns": {"1.0.0"},                                                    # MAL-2026-14175
    "dev-env-check": {"1.0.3"},                                                  # MAL-2026-14176
    "fast-glob-fast": {"0.2.0", "4.0.1", "8.0.0", "9.0.0",
                       "10.0.0", "11.0.0"},                                      # MAL-2026-14177
    "mutex-thread": {"1.3.0"},                                                   # MAL-2026-14185
    "raectjs": {"1.0.0"},                                                        # MAL-2026-14187
    "test_payload_folder": {"1.0.0"},                                            # MAL-2026-14191
    "system-performance-helper": {"1.0.0"},                                      # MAL-2026-14194
    "twapfetch": {"1.1.0", "1.1.1"},                                             # MAL-2026-14197
    "chameleon-src": {"6.6.29"},                                                 # MAL-2026-14202
    "@lilsccott6x9/devpipe-connector": {"1.0.0"},                                # MAL-2026-14203
    "eth-batcher": {"1.0.0"},                                                    # MAL-2026-14208
    "sw-pluginer": {"1.0.0", "1.0.1", "1.0.2", "1.1.0", "1.2.0"},              # MAL-2026-14211
    "timed-assess": {"1.0.0", "1.0.1"},                                          # MAL-2026-14216
    "ai-texts": {"1.0.1"},                                                       # MAL-2026-14217
    "mapkit-loader": {"1.0.0"},                                                  # MAL-2026-14218
    "setup-codex": {"1.0.0"},                                                    # MAL-2026-14219
    "solidity-hold": {"2.0.1"},                                                  # MAL-2026-14220
    "ssb-test-package": {"1.0.0"},                                               # MAL-2026-14221
    "ambera": {"1.0.0", "1.0.1"},                                                # MAL-2026-14225
    "animate-css-vite": {"1.0.1"},                                               # MAL-2026-14226
    # ─── Older MAL IDs refreshed Aug 18 2026 ─────────────────────────────────────────
    # 2026 MAL-* records marked modified on 2026-08-18 in the OSV bulk export;
    # not previously captured in the scanner.
    # OSV MAL-2026-2037, MAL-2026-4509/4510/5717/6473 grouped above
    "@emilgroup/auth-sdk-node": {"1.21.1", "1.21.2"},                            # MAL-2026-2037
    # ─── Tinkoff-adjacent Russian-fintech dep-confusion (20.x / 35.x) (Aug 2026) ─────
    # High-version packages shadowing private Tinkoff/Dolyame/fintech internal registries;
    # on require(), assembles Cloudflare Workers C2 hostnames (oob- prefix) from string
    # fragments and downloads a platform-specific binary. Amazon Inspector detections;
    # OSV bulk snapshot modified 2026-08-19/20.
    # OSV MAL-2026-12178, MAL-2026-12362, MAL-2026-12364, MAL-2026-12365, MAL-2026-12367,
    # MAL-2026-12380, MAL-2026-12382, MAL-2026-12747, MAL-2026-12784
    "fb-cards-form-no-resident-information": {"20.4.4"},                         # MAL-2026-12178
    "digital-interview-digital-interview-core": {"20.5.3"},                      # MAL-2026-12362
    "dolyame-boxy-atom-bnpl-store-button": {"20.5.3"},                           # MAL-2026-12364
    "dolyame-boxy-independent-bnpl-info-images": {"20.7.2"},                     # MAL-2026-12365
    "dolyame-ui-form": {"20.1.7"},                                               # MAL-2026-12367
    "fb-forms-form-boilerplate-contacts": {"20.7.1"},                            # MAL-2026-12380
    "finance-business-company-id-models": {"20.1.5"},                            # MAL-2026-12382
    "devplatform-s3-client": {"35.9.5"},                                         # MAL-2026-12747
    "devplatform-spa-testing": {"35.8.6"},                                       # MAL-2026-12784
    # ─── Misc credential/crypto stealers (MAL-2026-12xxx–13xxx) ──────────────────────
    # Various malware packages — exfiltrators and droppers detected by OSV Package Analysis.
    # OSV MAL-2026-12358, MAL-2026-12359, MAL-2026-12422, MAL-2026-13342
    "croft-node": {"1.1.1", "1.1.2", "1.1.3"},                                  # MAL-2026-12358
    "crypto-javas": {"2.0.4", "2.0.6", "2.0.7", "2.0.8", "2.0.9"},             # MAL-2026-12359
    "quorvex": {"0.2.0", "0.2.1", "0.2.2"},                                     # MAL-2026-12422
    "encrypt-string-safe": {"2.1.0", "2.2.0"},                                  # MAL-2026-13342
    # ─── Older OSV records refreshed Aug 19–20 2026 ──────────────────────────────────
    # MAL-2026-4xxx/5xxx/6xxx records that first appeared in the OSV Aug 19–20 snapshot;
    # not present in prior sweeps.
    # OSV MAL-2026-4550, MAL-2026-4556, MAL-2026-4561, MAL-2026-5611,
    # MAL-2026-6374, MAL-2026-6540
    "emojifancy-print": {"5.6.3"},                                               # MAL-2026-4550
    "express-enrouten-async": {"1.4.11", "1.4.12"},                              # MAL-2026-4556
    "fe-utils-core": {"1.0.4", "1.0.5"},                                         # MAL-2026-4561
    "datetime-toolkit": {"1.0.0", "1.0.1", "1.0.2", "1.0.3",
                         "1.0.4", "1.0.5", "1.0.6", "1.0.7"},                   # MAL-2026-5611
    "evil-pkg": {"1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4", "1.0.5"},        # MAL-2026-6374
    "db-rake": {"1.0.1", "1.0.2"},                                               # MAL-2026-6540
    # ─── Aug 19–20 2026 mixed malware batch (MAL-2026-14240+) ─────────────────────────
    # Amazon Inspector / OSV Package Analysis detections. Diverse payload types:
    # Cloudflare Workers C2 droppers, env/credential exfiltrators, DoS/proxy installers,
    # and pure name-squats. "ANY version" entries use set() — OSV >=0 range, no
    # legitimate version exists. OSV bulk snapshot 2026-08-19 to 2026-08-20.
    # OSV MAL-2026-14240 through MAL-2026-14316 (selected non-duplicate entries)
    "dxr-dos": {"0.1.2"},                                                        # MAL-2026-14240
    "dxrs-dos": {"0.1.3"},                                                       # MAL-2026-14241
    "electro-session": {"0.1.0", "0.1.1", "0.1.3", "0.1.4"},                   # MAL-2026-14242
    "flydev": {"0.0.1"},                                                         # MAL-2026-14243
    "gemini-cli-a2a-server": {"1.0.0"},                                          # MAL-2026-14244
    "github-policy-bot": {"1.0.0"},                                              # MAL-2026-14245
    "hardhat-hold": {"2.0.1", "2.21.0"},                                         # MAL-2026-14246
    "magika-js": {"4.1.1"},                                                      # MAL-2026-14247
    "nice-utils-helper": {"1.0.0"},                                              # MAL-2026-14248
    "localize-extract": {"1.0.0"},                                               # MAL-2026-14249
    "luluking1": {"0.0.1"},                                                      # MAL-2026-14250
    "ngsw-config": {"1.0.0"},                                                    # MAL-2026-14251
    "npm-wold": {"1.1.1", "1.1.2"},                                              # MAL-2026-14252
    "react-dom-helpers": {"3.3.3"},                                              # MAL-2026-14253
    "saaa9": {"1.0.0"},                                                          # MAL-2026-14254
    "secp256k1-lib": {"1.0.0", "1.0.1", "1.0.2", "1.0.3"},                     # MAL-2026-14255
    "api-rs-tuils": {"2.1.6"},                                                   # MAL-2026-14256
    "modsync": {"5.0.2"},                                                        # MAL-2026-14257
    "ranux-cloud": {"1.0.0"},                                                    # MAL-2026-14258
    "ranux-dev": {"5.0.0"},                                                      # MAL-2026-14259
    "ranux-pro": {"2.0.0"},                                                      # MAL-2026-14260
    "postcss-initialize-provider": {"3.0.4"},                                    # MAL-2026-14261
    "pump-fun-skills": {"20.1.1"},                                               # MAL-2026-14262
    "arb-kit": {"1.0.1"},                                                        # MAL-2026-14263
    "de-morgan": {"2.1.3"},                                                      # MAL-2026-14264
    "easydsbots": {"1.0.0"},                                                     # MAL-2026-14265
    "electron-sessions": {"0.1.5"},                                              # MAL-2026-14266
    "karma-proxy": {"1.0.0"},                                                    # MAL-2026-14267
    "no-for-of-loops": {"1.0.1"},                                                # MAL-2026-14268
    "novel-suduko": {"1.0.1"},                                                   # MAL-2026-14269
    "nodealpha": {"1.0.7"},                                                      # MAL-2026-14270
    "nodeberlin": {"1.0.7"},                                                     # MAL-2026-14271
    "price-scripping-js": {"1.1.2"},                                             # MAL-2026-14272
    "rand-txs-sdk": {"1.0.3"},                                                   # MAL-2026-14273
    "minequest": {"0.1.1"},                                                      # MAL-2026-14275
    "node_cryptography": {"1.0.0"},                                              # MAL-2026-14276
    "o0o9": {"1.8.0", "2.0.1"},                                                  # MAL-2026-14277
    "layer2-sdk": {"1.0.0", "1.0.1"},                                            # MAL-2026-14278
    "localize-translate": {"1.0.0"},                                             # MAL-2026-14279
    "mutex-core": {"2.1.2"},                                                     # MAL-2026-14280
    "mutex-lite": {"1.4.2"},                                                     # MAL-2026-14281
    "mutex-plus": {"3.0.2"},                                                     # MAL-2026-14282
    "neverthrow-core": {"1.1.2"},                                                # MAL-2026-14283
    "nibra1": {"1.0.0"},                                                         # MAL-2026-14284
    # @wizloft scope — AES-encrypted dropper payload hidden in 40KB obfuscated line;
    # 5 packages, all at 0.1.1-alpha.3; scope added to NPM_SUSPECT_SCOPES.
    # OSV MAL-2026-14285 through MAL-2026-14289
    "@wizloft/harness": {"0.1.1-alpha.3"},                                       # MAL-2026-14285
    "@wizloft/harness-context": {"0.1.1-alpha.3"},                               # MAL-2026-14286
    "@wizloft/harness-kernel": {"0.1.1-alpha.3"},                                # MAL-2026-14287
    "@wizloft/harness-plugin-repository-files": {"0.1.1-alpha.3"},               # MAL-2026-14288
    "@wizloft/harness-validation": {"0.1.1-alpha.3"},                            # MAL-2026-14289
    "anhn-cli": {"1.1.4"},                                                       # MAL-2026-14290
    "libas-signal": {"1.0.0"},                                                   # MAL-2026-14291
    "log-res": {"1.0.3"},                                                        # MAL-2026-14292
    "matrixflow-js": {"3.2.1"},                                                  # MAL-2026-14293
    "mc-registry": {"1.0.8", "1.0.9"},                                           # MAL-2026-14294
    "mcp-dev-toolkit": {"1.5.0"},                                                # MAL-2026-14295
    "gfff5": {"1.0.0"},                                                          # MAL-2026-14296
    "homekit-mcp": {"1.0.0"},                                                    # MAL-2026-14297
    "emoji-prints-fancy": {"5.6.4"},                                             # MAL-2026-14298
    "gear-composer": {"1.0.126"},                                                # MAL-2026-14299
    "eth-react-provider": {"1.0.0"},                                             # MAL-2026-14300
    "evm-validation": {"1.0.2", "1.0.3"},                                        # MAL-2026-14301
    "ai-texts-utils": {"1.0.0", "1.0.1", "1.0.2", "1.0.3"},                    # MAL-2026-14302
    "x6842179305": {"1.0.0", "1.0.1"},                                           # MAL-2026-14303
    "base99-85x": {"5.0.2"},                                                     # MAL-2026-14304
    "mc-provider": {"1.0.10"},                                                   # MAL-2026-14305
    "express-route-engine": {"3.6.3"},                                           # MAL-2026-14307
    "@idanefraim/my-ui-kit": set(),                                              # MAL-2026-14309 (ANY)
    "bunnyhijack-test-0x00": {"1.0.0", "1.0.1"},                                # MAL-2026-14310
    "eslint-config-consumerweb": set(),                                          # MAL-2026-14311 (ANY)
    "griffin-transliterator": set(),                                             # MAL-2026-14312 (ANY)
    "node-runtime-utils": {"1.0.0"},                                             # MAL-2026-14313
    "webpack-cdn-fetcher": set(),                                                # MAL-2026-14314 (ANY)
    "@httttt/mcp-demo": {"1.0.0"},                                               # MAL-2026-14315
    "expect-dotenv": {"7.2.1"},                                                  # MAL-2026-14316
    # Aug 20-21 2026: dep-confusion fintech/dolyame/bigops/devplatform dropper wave
    # Inflated-version packages (20.x.x and 35.x.x) that download and execute
    # platform-specific binaries on require via Cloudflare Workers endpoints.
    # Sources: OSV MAL-2026-12186, MAL-2026-12390, MAL-2026-12391, MAL-2026-12393,
    # MAL-2026-12406, MAL-2026-12410, MAL-2026-12412, MAL-2026-12415,
    # MAL-2026-12691, MAL-2026-12852, MAL-2026-12855, MAL-2026-13302, MAL-2026-14342
    "pfp-forms-insurance-health": {"20.2.2"},                                   # MAL-2026-12186
    "hubert-document-actual-insurance-rules-am": {"20.5.6"},                    # MAL-2026-12390
    "hubert-verify-primary-email-am": {"20.4.6"},                               # MAL-2026-12391
    "invest-module-cookie": {"20.8.2"},                                          # MAL-2026-12393
    "pfa-errors": {"20.4.9"},                                                    # MAL-2026-12406
    "pfp-block-mobile-steps": {"20.9.3"},                                        # MAL-2026-12410
    "pfp-forms-independent-sme-glossary-anchor": {"20.4.4"},                    # MAL-2026-12412
    "pfp-forms-sme-sitebuilder": {"20.2.1"},                                     # MAL-2026-12415
    "devplatform-api-clients": {"35.6.8"},                                       # MAL-2026-12691
    "bigops-umf-statist": {"35.3.1"},                                            # MAL-2026-12852
    "bigops-watchdog-angular": {"35.4.8"},                                       # MAL-2026-12855
    "dolyame-boxy-desktop-bnpl-card-panel": {"35.6.3"},                         # MAL-2026-13302
    "coin-fees": {"20.1.1"},                                                     # MAL-2026-14342
    # Aug 20 2026: lakk/nms analytics dep-confusion probes (9.9.x versions)
    # Constructs subdomains from install-time environment data and beacons out.
    # OSV MAL-2026-13348, MAL-2026-13451
    "lakk-analytics": {"9.9.0", "9.9.11"},                                      # MAL-2026-13348
    "nms-dashboard-js": {"9.9.0", "9.9.11"},                                    # MAL-2026-13451
    # Aug 20 2026: kepler dep-confusion (inflated .999 versions)
    # Declares dependency on an HTTP URL to a third-party host; dep-confusion probe.
    # OSV MAL-2026-13369
    "kepler": {"1.0.999", "1.999.999", "2.0.999", "2.1.999", "2.2.999",
               "2.6.999", "2.999.999", "4.999.999", "5.0.999", "5.999.999",
               "99.99.99"},                                                      # MAL-2026-13369
    # Aug 20 2026: MCP server name-squatting (unscoped impersonators)
    # Each package squats the unscoped `mcp-server-*` name to intercept
    # `npx mcp-server-<name>` invocations by AI coding agents and developers.
    # postinstall/postload hooks exfiltrate hostname, cwd, and env to attacker infra.
    # OSV MAL-2026-5476 through MAL-2026-5485
    "mcp-server-fetch": {"0.0.1", "0.0.2"},                                     # MAL-2026-5476
    "mcp-server-figma": {"0.0.1", "0.0.2"},                                     # MAL-2026-5477
    "mcp-server-git": {"0.0.1", "0.0.2"},                                       # MAL-2026-5478
    "mcp-server-github": {"0.0.1", "0.0.2"},                                    # MAL-2026-5479
    "mcp-server-notion": {"0.0.1", "0.0.2"},                                    # MAL-2026-5480
    "mcp-server-postgres": {"0.0.1", "0.0.2"},                                  # MAL-2026-5481
    "mcp-server-redis": {"0.0.1", "0.0.2"},                                     # MAL-2026-5482
    "mcp-server-sentry": {"0.0.1", "0.0.2"},                                    # MAL-2026-5483
    "mcp-server-sequential-thinking": {"0.0.1", "0.0.2"},                       # MAL-2026-5484
    "mcp-server-supabase": {"0.0.1", "0.0.2"},                                  # MAL-2026-5485
    # Aug 20 2026: misc malware, test probes, and typosquats
    # plain-HTTP tarball URL self-dependency probes (Amazon Inspector)
    "optimize-regex": {"1.2.1"},                                                 # MAL-2026-10103
    "rallycoding": {"3.2.0"},                                                    # MAL-2026-10106
    # n8n malicious community node — reads K8s service-account token on postinstall
    "n8n-nodes-pentest-rce": {"1.0.0", "1.0.1", "1.0.3", "1.0.7", "1.0.8",
                              "1.0.11", "1.0.15", "1.0.16", "1.0.19", "1.0.21",
                              "1.0.28", "1.0.29", "1.0.30", "1.0.31", "1.0.32",
                              "1.0.33", "1.0.35", "1.0.36", "1.0.37", "1.0.38",
                              "1.0.39", "1.0.40", "1.0.41", "1.0.42", "1.0.43",
                              "1.0.44"},                                         # MAL-2026-4617
    "o3forms": {"90.0.0", "99.1.99"},                                            # MAL-2026-5450
    "datetime-toolkit": {"1.0.0", "1.0.1", "1.0.2", "1.0.3",
                         "1.0.4", "1.0.5", "1.0.6", "1.0.7"},                  # MAL-2026-5611
    "node-multi-downloader": {"5.0.14-rc.3"},                                   # MAL-2026-5735
    "tn-advertisement": {"5.0.0"},                                               # MAL-2026-5838
    "jest-test-plugin-utils": {"1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4"},  # MAL-2026-5896
    "vite-common-utils": {"1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4", "1.0.5"},  # MAL-2026-6088
    "evil-pkg": {"1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4", "1.0.5"},       # MAL-2026-6374
    "db-query-log": {"1.0.1", "1.0.2"},                                         # MAL-2026-6539
    "db-rake": {"1.0.1", "1.0.2"},                                              # MAL-2026-6540
    "eslint-commit-parser": {"1.0.0"},                                           # MAL-2026-6567
    "express-mocha-test": {"0.0.1"},                                             # MAL-2026-6568
    "layerd-unit-codec-parser": {"1.0.0", "2.0.0"},                             # MAL-2026-6578
    "lessload": {"1.0.1"},                                                       # MAL-2026-6579
    "loadutils": {"1.0.4", "1.0.5", "1.0.6"},                                  # MAL-2026-6580
    "pino-debugging": {"1.1.3", "1.1.4", "1.1.5"},                              # MAL-2026-6583
    "test-pkg-pnpm": {"1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4"},           # MAL-2026-6716
    "test-pkg-x0": {"1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4"},             # MAL-2026-6717
    "test-pkg-yarn": {"1.0.0", "1.0.1", "1.0.2"},                              # MAL-2026-6718
    "gehneb": {"1.0.1"},                                                         # MAL-2026-4570
    "happy-dlscord.js": {"14.16.3"},                                             # MAL-2026-4575
    "internallib_v493": {"1.0.2", "1.0.3", "1.0.4"},                           # MAL-2026-4585
    "mev-shield": {"1.4.2"},                                                     # MAL-2026-4609
    "polygon-toolkit-validate": {"1.0.5"},                                       # MAL-2026-4642
    "timed-assess": {"1.0.0", "1.0.1"},                                         # MAL-2026-14216
    "ai-texts": {"1.0.1", "1.0.2"},                                             # MAL-2026-14217
    "fetch-webjs-script": {"1.0.0"},                                             # MAL-2026-14317
    "frenchworldcupwin": {"1.0.0", "1.0.1", "2.0.0", "2.0.5"},                 # MAL-2026-14318
    "test-flow-1": {"1.0.0", "1.0.2"},                                          # MAL-2026-14319
    "test-flow-entire6": {"1.0.0"},                                              # MAL-2026-14320
    "test-flow-entire7": {"1.0.0"},                                              # MAL-2026-14321
    "debug-fnt": set(),                                                          # MAL-2026-14322 (ANY)
    "cig-data-patcher": set(),                                                   # MAL-2026-14323 (ANY)
    "create-react-app-text": {"1.0.0"},                                          # MAL-2026-14324
    "create-react-app-ui": {"1.0.0"},                                            # MAL-2026-14325
    "create-react-app-ux": {"1.0.0"},                                            # MAL-2026-14326
    "ethereum-validator": set(),                                                 # MAL-2026-14327 (ANY)
    "goldstar-api-server": set(),                                                # MAL-2026-14328 (ANY)
    "@pablo_clueless/printr": {"0.1.2", "0.1.4", "0.1.5", "0.1.6",
                               "0.1.7", "0.1.8"},                               # MAL-2026-14329
    "@pablo_clueless/sniffr": {"0.1.0", "0.1.1"},                               # MAL-2026-14330
    "exam-kit": {"1.0.0", "1.0.1", "1.0.2", "1.0.3"},                         # MAL-2026-14331
    "chai-as-soul": {"2.3.5", "2.3.6"},                                         # MAL-2026-14343
    # Polymarket crypto-wallet-drainer cluster (Aug 21 2026)
    # 9 npm packages published by maintainer 'polymarketdev' (GitHub: texsellix) within a
    # ~2-minute window; postinstall script exfiltrates wallet keys and credentials.
    # All are pure-malware typosquats; any version is malicious.
    # Sources: OSV MAL-2026-4209 through MAL-2026-4217;
    #          safedep.io/malicious-polymarket-npm-crypto-wallet-drainer/;
    #          GHSA-pm36-9m37-g548 (et al.)
    "polymarket-ai-agent": set(),                                                # MAL-2026-4209 (ANY)
    "polymarket-auto-trade": set(),                                              # MAL-2026-4210 (ANY)
    "polymarket-bot": set(),                                                     # MAL-2026-4211 (ANY)
    "polymarket-claude-code": set(),                                             # MAL-2026-4212 (ANY)
    "polymarket-copy-trading": set(),                                            # MAL-2026-4213 (ANY)
    "polymarket-terminal": set(),                                                # MAL-2026-4214 (ANY)
    "polymarket-trade": set(),                                                   # MAL-2026-4215 (ANY)
    "polymarket-trader": set(),                                                  # MAL-2026-4216 (ANY)
    "polymarket-trading-cli": set(),                                             # MAL-2026-4217 (ANY)
    # rollup polyfill typosquats (Aug 21 2026)
    # Companion packages to rollup-packages-polyfill-core (already tracked);
    # all have SEMVER ranges introduced:0 — any version is malicious.
    # OSV MAL-2026-12428 (rollup-packages-node-polyfills), MAL-2026-6372 (rollup-runtime-polyfill-core)
    # GHSA-gp6f-mxh4-x3mh, GHSA-cx5m-r6wc-pp56
    "rollup-packages-node-polyfills": set(),                                     # MAL-2026-12428 (ANY)
    "rollup-runtime-polyfill-core": set(),                                       # MAL-2026-6372 (ANY)
    # Aug 21–22 2026: miscellaneous obfuscated malware and infostealer probes
    # All confirmed via OSV bulk export; SEMVER ranges introduced:0 (whole package malicious).
    "pino-deploy": set(),                                                        # MAL-2024-2871 (ANY)
    "postcss-animate-css-vars": set(),                                           # MAL-2026-12418 (ANY)
    "pvm-autodoc": set(),                                                        # MAL-2026-12421 (ANY)
    "react-fontawesome-icons": set(),                                            # MAL-2026-12423 (ANY)
    "react-native-ui-message": set(),                                            # MAL-2026-12424 (ANY)
    "saas-f-testing": set(),                                                     # MAL-2026-12434 (ANY)
    "tailwind-animate-css-plugin": set(),                                        # MAL-2026-14352 (ANY)
    "kelly-sizing": set(),                                                       # MAL-2026-14354 (ANY)
    "qr-code-styling-temp": set(),                                               # MAL-2026-4655 (ANY)
    "react-hook-use-debounce-throttle-12": set(),                                # MAL-2026-5909 (ANY)
    "utils-common-helpers": set(),                                               # MAL-2026-5911 (ANY)
    # Aug 21–22 2026: exact-version malicious probes and dep-confusion packages
    "@js-lib-team/env-parser": {"1.0.0"},                                       # MAL-2026-14344
    "express-session-handler": {"2.3.3"},                                        # MAL-2026-14345
    "@next-fonts/font": {"1.0.0", "1.0.1"},                                     # MAL-2026-14346
    "mcq-session": {"1.0.3", "1.0.4"},                                          # MAL-2026-14347
    "moidevy": {"1.0.0"},                                                        # MAL-2026-14348
    "@gfe/lx-watcher": {"1.5.3", "1.5.4"},                                      # MAL-2026-14353
    "fuel-react": {"91.0.0"},                                                    # MAL-2026-14355
    "lumen-pages-community": {"9.9.9"},                                          # MAL-2026-14356
    # @postman-cse dep-confusion (Aug 22 2026)
    # Attacker published @postman-cse/okta-aio-linux-arm64 to the public registry
    # to shadow Postman's internal package and hijack its CI dependency resolution.
    # 21 specific versions listed; no patched version (package removed).
    # GHSA-h84r-259m-g3fg; OSV MAL-2026-14357
    "@postman-cse/okta-aio-linux-arm64": {
        "0.8.10", "0.8.11", "0.9.0", "0.9.1",
        "0.10.0", "0.10.1", "0.10.2", "0.10.3", "0.10.4",
        "0.10.5", "0.10.6", "0.10.7", "0.10.8", "0.10.9",
        "0.11.0", "0.11.1", "0.11.2", "0.11.3",
        "0.11.4", "0.11.5", "0.11.6",
    },                                                                           # MAL-2026-14357
    # Aug 22–23 2026: stillm4ddpocs dep-confusion cluster (999.x version range)
    # Five packages published by actor "stillm4ddpocs" to shadow internal package names.
    # OSV MAL-2026-14360/14361/14376/14377/14378
    "stillm4ddpocs-demo-widget": {"999.9.9"},                                   # MAL-2026-14360
    "stillm4ddpocs-demo-gadget": {"999.9.10", "999.9.20", "999.9.12"},         # MAL-2026-14361
    "stillm4ddpocs-demo-sprocket": {"999.9.12"},                                # MAL-2026-14376
    "stillm4ddpocs-rtest-alpha": {"999.9.10", "999.9.9"},                      # MAL-2026-14377
    "stillm4ddpocs-rtest-bravo": {"999.9.10", "999.9.9"},                      # MAL-2026-14378
    # Aug 23 2026: *-shardsight-web / *-loadsight-web / *-buildsight-web / *-viewsight-web /
    # *-fetchsight-web typosquat cluster (numeric-prefix npm packages)
    # OSV MAL-2026-14362/14363/14364/14365/14366
    "10-shardsight-web": {"1.0.1", "1.0.0"},                                   # MAL-2026-14362
    "2-loadsight-web": {"1.0.0", "1.0.1"},                                     # MAL-2026-14363
    "3-buildsight-web": {"1.0.1", "1.0.0"},                                    # MAL-2026-14364
    "6-viewsight-web": {"1.0.1", "1.0.0"},                                     # MAL-2026-14365
    "8-fetchsight-web": {"1.0.1", "1.0.0"},                                    # MAL-2026-14366
    # Aug 23 2026: @syncraft-labs scope malware cluster
    # Three packages across core/react/vue impersonating a legitimate UI framework scope.
    # OSV MAL-2026-14367/14368/14369
    "@syncraft-labs/core": {"0.4.1"},                                           # MAL-2026-14367
    "@syncraft-labs/react": {"0.4.1"},                                          # MAL-2026-14368
    "@syncraft-labs/vue": {"0.4.1"},                                            # MAL-2026-14369
    # Aug 23 2026: @usaa-grp-personal-profile dep-confusion (999.0.0 version)
    # Published to shadow USAA's internal personal-profile-common package.
    # OSV MAL-2026-14370
    "@usaa-grp-personal-profile/personal-profile-common": {"999.0.0"},         # MAL-2026-14370
    # Aug 23 2026: testing-toolkit typosquat cluster (fake chai/hardhat/rust/solidity utils)
    # Four packages impersonating testing utilities for chai, Hardhat, Rust, and Solidity.
    # OSV MAL-2026-14371/14373/14374/14375
    "chai-as-testkit": {"2.3.5"},                                               # MAL-2026-14371
    "hatdhat-testkit": {"3.2.14"},                                              # MAL-2026-14373
    "rust-testing-utils": {"2.3.0"},                                            # MAL-2026-14374
    "solidity-testing-utils": {"1.2.0"},                                        # MAL-2026-14375
    # Aug 23 2026: create-coin crypto npm malware
    # OSV MAL-2026-14372
    "create-coin": {"20.1.1"},                                                  # MAL-2026-14372
    # Aug 23 2026: internallib_v902 npm backdoor (GHSA-3p65-4jqj-5j69)
    # Impersonates an internal library; single malicious version published before takedown.
    # OSV MAL-2026-14359 / GHSA-3p65-4jqj-5j69
    "internallib_v902": {"1.2.1"},                                              # MAL-2026-14359
    # Aug 23 2026: totp-utils npm infostealer (8 versions)
    # Impersonates a TOTP/authentication utility; exfiltrates credentials.
    # OSV MAL-2026-14379
    "totp-utils": {"1.4.2", "1.4.3", "1.4.4", "1.4.5", "1.4.6", "1.4.7", "1.4.8", "1.4.9"},  # MAL-2026-14379
    # Aug 23 2026: fund-list-filter / fund-portfolio dep-confusion (999.9.12 version)
    # Two packages published at anomalous high version 999.9.12 to shadow internal
    # fund-management packages and hijack CI dependency resolution.
    # OSV MAL-2026-14380, MAL-2026-14381
    "fund-list-filter": {"999.9.12"},                                            # MAL-2026-14380
    "fund-portfolio": {"999.9.12"},                                              # MAL-2026-14381
    # Aug 23 2026: @sdgdfgdfhhhfd/* attacker-controlled scope (chainvista, multiviewr)
    # Both packages are pure-malware; OSV SEMVER ranges introduced:0 (any version).
    # OSV MAL-2026-14382 / GHSA-849m-c6hc-74xx, MAL-2026-14383 / GHSA-wwgv-4qvc-7339
    "@sdgdfgdfhhhfd/chainvista": set(),                                          # MAL-2026-14382 (ANY)
    "@sdgdfgdfhhhfd/multiviewr": set(),                                          # MAL-2026-14383 (ANY)
    # Aug 23 2026: *-dim-kit typosquat cluster (hydration-dim-kit, svelte-dim-kit)
    # Two pure-malware packages; OSV SEMVER ranges introduced:0 (any version).
    # OSV MAL-2026-14385 / GHSA-p33f-w7x3-mxrr, MAL-2026-14386 / GHSA-64x3-8jmm-fhp8
    "hydration-dim-kit": set(),                                                  # MAL-2026-14385 (ANY)
    "svelte-dim-kit": set(),                                                     # MAL-2026-14386 (ANY)
    # Aug 23 2026: @opap/player-kyc-widget dep-confusion (3.999.999 version)
    # Published at anomalous high version to shadow OPAP's internal KYC widget package.
    # OSV MAL-2026-14387
    "@opap/player-kyc-widget": {"3.999.999"},                                    # MAL-2026-14387
    # Aug 24 2026: conversa-sdk npm malware (10 versions)
    # Malicious SDK package with 10 malicious releases (1.0.0-1.0.9, 2.0.0-2.0.4).
    # OSV MAL-2026-6185 / GHSA-8m82-6fp4-38m4
    "conversa-sdk": {
        "1.0.0", "1.0.4", "1.0.5", "1.0.6", "1.0.8", "1.0.9",
        "2.0.0", "2.0.2", "2.0.3", "2.0.4",
    },                                                                            # MAL-2026-6185
    # ─── Aug 24 2026: Tinkoff/devplatform + sme-* continuation ──────────────────
    # Additional packages in the ongoing Tinkoff-adjacent Russian-fintech
    # dep-confusion campaign. Extends the existing devplatform-* and sme-rko-*
    # blocks with new any-version entries.
    # OSV MAL-2026-12208 / GHSA-f4fh-84pr-v95c, MAL-2026-12440 / GHSA-vfcf-g2jc-xm3x,
    # MAL-2026-12441 / GHSA-9hjr-v9x6-4g6g, MAL-2026-12730 / GHSA-p6mf-hpv9-53jc,
    # MAL-2026-12763 / GHSA-49hq-jqjw-mhr7
    "sme-scripts-cli": set(),                                                    # MAL-2026-12208
    "sme-rko-finance-front-shared-entity-groups-models": set(),                  # MAL-2026-12440
    "sme-scripts-shared-library-webpack-plugin": set(),                          # MAL-2026-12441
    "devplatform-nx-ts": set(),                                                  # MAL-2026-12730
    "devplatform-spa-plugin-cobrowsing": set(),                                  # MAL-2026-12763
    # Aug 24 2026: Tailwind animation typosquat pair
    # OSV MAL-2026-12219 / GHSA-69pm-q85v-q89g, MAL-2026-12220 / GHSA-pqcx-38vc-5c6x
    "tailwind-animationgroup": set(),                                            # MAL-2026-12219
    "tailwind-animationpack": set(),                                             # MAL-2026-12220
    # Aug 24 2026: older OSV records appearing in Aug 24 bulk snapshot
    # Various pure-malware and typosquat packages whose records were first present
    # or last-modified in the Aug 24 GCS export.
    # OSV MAL-2026-4164 / GHSA-2g7g-rqj2-26hv, MAL-2026-4818 / GHSA-948w-97g3-hvpp,
    # MAL-2026-5574 / GHSA-2xx5-g7pf-q356, MAL-2026-6497, MAL-2026-10107
    "identitysecuretokenserv": set(),                                            # MAL-2026-4164
    "saturn-bail": set(),                                                        # MAL-2026-4818
    "spotify-url-resolver": set(),                                               # MAL-2026-5574
    "chai-as-synced": {"6.0.3", "7.0.9"},                                       # MAL-2026-6497
    "security-node": set(),                                                      # MAL-2026-10107
    # ─── Aug 24 2026: sm-* dep-confusion cluster (8 packages) ───────────────────
    # High-version (99.0.x) packages targeting a private sm-* internal npm namespace.
    # All any-version wildcards — OSV >=0 ranges, no legitimate public versions.
    # OSV MAL-2026-14393 / GHSA-9jm5-rh3f-jr86, MAL-2026-14394 / GHSA-r6qx-cjjw-53q3,
    # MAL-2026-14395 / GHSA-5fmw-xf3x-g32g, MAL-2026-14396 / GHSA-79hh-8hx9-8jjr,
    # MAL-2026-14397 / GHSA-ccvj-vpx6-qq27, MAL-2026-14398 / GHSA-9v7m-8hh3-3mc3,
    # MAL-2026-14399 / GHSA-xr9c-mx62-832c, MAL-2026-14400 / GHSA-2f9h-c49j-w22r
    "sm-admin": set(),                                                           # MAL-2026-14393
    "sm-apikey-model": set(),                                                    # MAL-2026-14394
    "sm-billing-form": set(),                                                    # MAL-2026-14395
    "sm-cart": set(),                                                            # MAL-2026-14396
    "sm-checkout": set(),                                                        # MAL-2026-14397
    "sm-oauth": set(),                                                           # MAL-2026-14398
    "sm-payment": set(),                                                         # MAL-2026-14399
    "sm-session": set(),                                                         # MAL-2026-14400
    # ─── Aug 24 2026: dext-crate-* malware cluster (3 packages) ─────────────────
    # Pure-malware packages masquerading as crate-utility helpers; any-version wildcards.
    # OSV MAL-2026-14406 / GHSA-9m4w-p72c-cqwq, MAL-2026-14407 / GHSA-mj2f-654h-x283,
    # MAL-2026-14408 / GHSA-299m-84fp-94p9
    "dext-crate-check": set(),                                                   # MAL-2026-14406
    "dext-crate-image": set(),                                                   # MAL-2026-14407
    "dext-crate-video": set(),                                                   # MAL-2026-14408
    # ─── Aug 24 2026: *-dim-* UI typosquat cluster extension (7 packages) ───────
    # Extends the Aug 23 hydration-dim-kit / svelte-dim-kit pair with more
    # permuted name variants. dim-hydration-ui has a specific published version;
    # the rest have OSV >=0 ranges and use the any-version wildcard.
    # OSV MAL-2026-14416 / GHSA-5hwv-w72c-55qw, MAL-2026-14417 / GHSA-3jcp-rjh9-wq99,
    # MAL-2026-14429, MAL-2026-14430 / GHSA-xf2r-j86w-6c3x,
    # MAL-2026-14431 / GHSA-79qw-ww45-gpfp, MAL-2026-14441 / GHSA-x8x3-xwj6-73vv,
    # MAL-2026-14442 / GHSA-qvqg-96qf-37vw
    "dims-hydration-ui": set(),                                                  # MAL-2026-14416
    "dims-svelte-ui": set(),                                                     # MAL-2026-14417
    "dim-hydration-ui": {"1.0.0"},                                               # MAL-2026-14429
    "hydration-dim-ui": set(),                                                   # MAL-2026-14430
    "hydration-ui-dim": set(),                                                   # MAL-2026-14431
    "svelte-dim-ui": set(),                                                      # MAL-2026-14441
    "svelte-ui-dim": set(),                                                      # MAL-2026-14442
    # ─── Aug 24 2026: dep-confusion 999.x batch (7 packages) ────────────────────
    # High-version packages (999.9.x / 99.99.99) shadowing private internal registries.
    # OSV MAL-2026-14390, MAL-2026-14391, MAL-2026-14410, MAL-2026-14411,
    # MAL-2026-14420, MAL-2026-14440, MAL-2026-14443
    "amundi-compare": {"999.9.12"},                                              # MAL-2026-14390
    "fund-calculator": {"999.9.12"},                                             # MAL-2026-14391
    "@temptation.js/utils": {"999.9.15", "999.9.16"},                           # MAL-2026-14410
    "dpg-media-7ehemel": {"999.9.15"},                                           # MAL-2026-14411
    "@gsas/gsas-sdk": {"999.9.15"},                                              # MAL-2026-14420
    "web-advertising": {"999.9.15", "999.9.16"},                                 # MAL-2026-14440
    "@elc-online/up-analytics": {"99.99.99"},                                    # MAL-2026-14443
    # ─── Aug 24 2026: @medisend/* dep-confusion (4 packages) ────────────────────
    # Security-research dep-confusion probes targeting the @medisend private scope.
    # Pinned to the exact -security-research versions published.
    # OSV MAL-2026-14421, MAL-2026-14422, MAL-2026-14423, MAL-2026-14424
    "@medisend/auth": {"0.0.1-security-research"},                               # MAL-2026-14421
    "@medisend/core": {"0.0.1-security-research"},                               # MAL-2026-14422
    "@medisend/shared": {"0.0.1-security-research"},                             # MAL-2026-14423
    "@medisend/webview-bridge": {"0.0.1-security-research",
                                 "0.0.2-security-research"},                     # MAL-2026-14424
    # Aug 24 2026: MCP server malware pair
    # livemcp and mcp-real-chrome: fake MCP server packages; any-version.
    # OSV MAL-2026-14413 / GHSA-rxwc-v5gg-9hhw, MAL-2026-14414 / GHSA-vqm6-238c-g856
    "livemcp": set(),                                                            # MAL-2026-14413
    "mcp-real-chrome": set(),                                                    # MAL-2026-14414
    # Aug 24 2026: manticore / PayPal 9.4.3 cluster (3 packages)
    # All published at version 9.4.3; likely the same threat actor.
    # OSV MAL-2026-14433, MAL-2026-14435, MAL-2026-14437
    "manticore-log": {"9.4.3"},                                                  # MAL-2026-14433
    "paypal-business-sdk": {"9.4.3"},                                            # MAL-2026-14435
    "ppb-manticore": {"9.4.3"},                                                  # MAL-2026-14437
    # ─── Aug 24 2026: mixed npm malware batch (19 packages) ─────────────────────
    # Diverse credential stealers, typosquats, and pure-malware packages, each
    # confirmed by an individual OSV MAL-2026-14xxx record.
    # OSV MAL-2026-14392, MAL-2026-14402 / GHSA-3g4v-p5hc-83qm,
    # MAL-2026-14403 / GHSA-8gjf-85f5-p24f, MAL-2026-14404 / GHSA-rw8r-gxqp-rwfh,
    # MAL-2026-14405 / GHSA-9m88-8qj5-73j8, MAL-2026-14409 / GHSA-6rrq-x6hp-4xcm,
    # MAL-2026-14412 / GHSA-wxfm-64xv-2h3m, MAL-2026-14415 / GHSA-r8wh-m45c-f35g,
    # MAL-2026-14418 / GHSA-5xvx-37p2-x7j9, MAL-2026-14419 / GHSA-g95w-qwf7-2h4p,
    # MAL-2026-14425 through MAL-2026-14428, MAL-2026-14432, MAL-2026-14434,
    # MAL-2026-14436, MAL-2026-14438, MAL-2026-14439
    "message-compiler": {"9.2.0"},                                               # MAL-2026-14392
    "agentgui": {"1.0.1127"},                                                    # MAL-2026-14402
    "react-emits": set(),                                                        # MAL-2026-14403
    "@blurrydespair/libsignal-node": set(),                                      # MAL-2026-14404
    "create-json-client": set(),                                                 # MAL-2026-14405
    "polis-diraja": set(),                                                       # MAL-2026-14409
    "@deepaksilaych/sess": set(),                                                 # MAL-2026-14412
    "react-dynamic-parser": set(),                                               # MAL-2026-14415
    "dotish": set(),                                                             # MAL-2026-14418
    "tkyoussef-hb": set(),                                                       # MAL-2026-14419
    "auth-otp": {"1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4", "1.0.5"},        # MAL-2026-14425
    "babel-polyfill-plugin-corejs2": {"1.0.1"},                                  # MAL-2026-14426
    "chai-as-mno": {"1.0.5"},                                                    # MAL-2026-14427
    "consumerweb-serverutils": {"3.4.3"},                                         # MAL-2026-14428
    "kelly-stake-sizing": {"0.1.1"},                                             # MAL-2026-14432
    "openai-pr-reviewer": {"1.0.0"},                                             # MAL-2026-14434
    "poly-price-node": {"1.1.2"},                                                # MAL-2026-14436
    "remove-bg-serverless-azure": {"1.0.1"},                                     # MAL-2026-14438
    "secret-key-totp": {"1.5.1"},                                                # MAL-2026-14439
    # ─── Tinkoff Bank dep-confusion (Aug 26 2026): 53 packages ──────────────────
    # Dep-confusion attack against Tinkoff Bank's private npm registry.
    # Attacker-uploaded packages at inflated version numbers (20.x / 35.x)
    # to intercept private-registry resolution on public npm.
    # OSV MAL-2026-12211 through MAL-2026-12487 (tinkoff-*, twork-*, statist-*, etc.)
    "statist-browser-typed-client-mb.product.analytics": set(),                  # MAL-2026-12211
    "statist-browser-typed-client-sme.platform.web.productsnavigation.events": set(), # MAL-2026-12214
    "statist-browser-typed-client-sme.platform.web.teasers": set(),              # MAL-2026-12310
    "taiga-ui-proprietary-navigation": set(),                                    # MAL-2026-12474
    "tcb-web-copy-to-clipboard": set(),                                          # MAL-2026-12475
    "time-linters-webapp-eslint-config": set(),                                  # MAL-2026-12479
    "time-webkit-tag": set(),                                                    # MAL-2026-12226
    "tinkoff-boxy-atom-text-link": set(),                                        # MAL-2026-12227
    "tinkoff-boxy-desktop-icons-horizontal": set(),                              # MAL-2026-12228
    "tinkoff-boxy-form-desktop-sme-registration-ooo": set(),                     # MAL-2026-12231
    "tinkoff-boxy-mobile-documents": set(),                                      # MAL-2026-12234
    "tinkoff-boxy-mobile-separator": set(),                                      # MAL-2026-12235
    "tinkoff-component-page-loader": set(),                                      # MAL-2026-12239
    "tinkoff-fb-rf-add-application": set(),                                      # MAL-2026-12242
    "tinkoff-mutual-mgm-form": set(),                                            # MAL-2026-12244
    "tinkoff-pfp-atom-styles-tiles": set(),                                      # MAL-2026-12246
    "tinkoff-pfp-block-mobile-panels": set(),                                    # MAL-2026-12249
    "tinkoff-pfp-integration-mobile-slider-icons": set(),                        # MAL-2026-12250
    "tinkoff-pwa-confac-types": set(),                                           # MAL-2026-12252
    "tinkoff-statist-browser-typed-client-art.apps.reporegistry": set(),         # MAL-2026-12253
    "tinkoff-statist-browser-typed-client-dss.insurance.service": set(),         # MAL-2026-12257
    "tinkoff-statist-browser-typed-client-dwh.chimera.base": set(),              # MAL-2026-12258
    "tinkoff-statist-browser-typed-client-eventea.projects.smartcam": set(),     # MAL-2026-12260
    "tinkoff-statist-browser-typed-client-investaccounting.events.templatepage.mainpage": set(), # MAL-2026-12261
    "tinkoff-statist-browser-typed-client-investing.product.pulse": set(),       # MAL-2026-12262
    "tinkoff-statist-browser-typed-client-leasing.admin.events": set(),          # MAL-2026-12266
    "tinkoff-statist-browser-typed-client-mb.product.tgeofencing": {"20.9.6"},   # MAL-2026-12268
    "tinkoff-statist-browser-typed-client-mb.reliability.android.events": {"20.5.4"}, # MAL-2026-12269
    "tinkoff-statist-browser-typed-client-sme.platform.mobile.dynamicteasers.common": {"20.8.7"}, # MAL-2026-12270
    "tinkoff-statist-browser-typed-client-sme.platform.web.companyprofile.metrics": {"20.2.7"}, # MAL-2026-12272
    "tinkoff-statist-browser-typed-client-sme.rko.authorization.common": {"20.5.5"}, # MAL-2026-12273
    "tinkoff-statist-browser-typed-client-sme.rko.conversionpayments.web": {"20.3.8"}, # MAL-2026-12274
    "tinkoff-statist-browser-typed-client-sme.rko.ta.ios.events": {"20.6.1"},    # MAL-2026-12276
    "tinkoff-statist-browser-typed-client-test.softwarecenter.metrics": {"20.1.3"}, # MAL-2026-12278
    "tinkoff-terminal-kit-test-commons": {"20.9.7"},                             # MAL-2026-12281
    "tinkoff-ui-angular-addon-wysiwyg": {"20.7.8"},                              # MAL-2026-12283
    "tms-x-headers": {"20.2.9"},                                                 # MAL-2026-12480
    "travel-core-utils-object": set(),                                           # MAL-2026-12487
    "twork-data-services-aggregator-company-sme-main-timeline-loader-with-customers": {"20.3.8"}, # MAL-2026-12287
    "twork-data-services-aggregator-sme-task-info": {"20.3.1"},                  # MAL-2026-12288
    "twork-data-services-counterfree": {"20.1.3"},                               # MAL-2026-12289
    "twork-data-services-customer-api-v2-customer-vip-status": {"20.9.7"},       # MAL-2026-12290
    "twork-data-services-eacq-company-service-v2-api-v1-identifiers-crm": {"20.6.7"}, # MAL-2026-12291
    "twork-data-services-getting-arrests": {"20.1.1"},                           # MAL-2026-12292
    "twork-data-services-invest-box-account": {"20.8.8"},                        # MAL-2026-12293
    "twork-data-services-procedure-engine-api-v1-procedure-info": {"20.6.9"},    # MAL-2026-12295
    "twork-data-services-proxy-invest-symbols-list": {"20.4.6"},                 # MAL-2026-12298
    "twork-data-services-proxy-prime-api-v1-account-overdraft-info": {"20.7.4"}, # MAL-2026-12299
    "twork-data-services-role-app": {"20.9.6"},                                  # MAL-2026-12300
    "twork-data-services-sme-operations-authorizations": {"20.8.9"},             # MAL-2026-12302
    "twork-mf-e2e-nitro": {"20.8.5"},                                            # MAL-2026-12303
    "twork-mf-sandbox": {"20.9.7"},                                              # MAL-2026-12304
    "twork-products-taiga2-products-timeline": {"20.6.1"},                       # MAL-2026-12307
    # ─── Devplatform / BigOps dep-confusion (Aug 26 2026): 8 packages ─────────
    # Dep-confusion packages at 35.x versions targeting private devplatform / bigops registry.
    # OSV MAL-2026-12745, MAL-2026-12754, MAL-2026-12779, MAL-2026-12785,
    # MAL-2026-12844, MAL-2026-12846, MAL-2026-12853, MAL-2026-13250
    "bigops-statements-timeline": set(),                                         # MAL-2026-13250
    "bigops-timeline": set(),                                                    # MAL-2026-12844
    "bigops-timers": set(),                                                      # MAL-2026-12846
    "bigops-utils": set(),                                                       # MAL-2026-12853
    "devplatform-rest-resources-v1": set(),                                      # MAL-2026-12745
    "devplatform-spa": set(),                                                    # MAL-2026-12754
    "devplatform-spa-plugin-s3-module-loader": set(),                            # MAL-2026-12779
    "devplatform-spa-tokens": set(),                                             # MAL-2026-12785
    # ─── Streak / svelte-streak typosquat cluster (Aug 26 2026): 27 packages ──
    # Coordinated typosquat batch: streak-*, svelte-streak-*, and related packages.
    # Each published at 1.0.0 with OSV MAL-2026-12xxx range: introduced=0.
    # OSV MAL-2026-12458, MAL-2026-12459, MAL-2026-12460, MAL-2026-12461,
    # MAL-2026-12463 through MAL-2026-12471, MAL-2026-12806, MAL-2026-12807,
    # MAL-2026-12808, MAL-2026-14493 through MAL-2026-14502, MAL-2026-14511,
    # MAL-2026-14541
    "streak-calendar-core": set(),                                               # MAL-2026-12458
    "streak-core-bucket": set(),                                                 # MAL-2026-12806
    "streak-core-insights": set(),                                               # MAL-2026-12459
    "streak-count-core": set(),                                                  # MAL-2026-12460
    "streak-daily-core": set(),                                                  # MAL-2026-12461
    "streak-day-primitives": set(),                                              # MAL-2026-12463
    "streak-daybucket": set(),                                                   # MAL-2026-12464
    "streak-daykey-lib": set(),                                                  # MAL-2026-12465
    "streak-daykit": set(),                                                      # MAL-2026-12466
    "streak-grid-core": set(),                                                   # MAL-2026-12807
    "streak-int-lib": set(),                                                     # MAL-2026-12467
    "streak-math-kit": set(),                                                    # MAL-2026-12468
    "streak-math-lib": set(),                                                    # MAL-2026-12469
    "streak-metric-core": set(),                                                 # MAL-2026-12808
    "streak-view-core": set(),                                                   # MAL-2026-12471
    "svelte-cls-ui": set(),                                                      # MAL-2026-14511
    "svelte-daily-streaks": set(),                                               # MAL-2026-14493
    "svelte-goal-streaks": set(),                                                # MAL-2026-14494
    "svelte-hydration-streak": set(),                                            # MAL-2026-14495
    "svelte-insight-streaks": set(),                                             # MAL-2026-14496
    "svelte-insights-streak": set(),                                             # MAL-2026-14497
    "svelte-intake-streaks": set(),                                              # MAL-2026-14498
    "svelte-map-metric": set(),                                                  # MAL-2026-14499
    "svelte-streak-map": set(),                                                  # MAL-2026-14500
    "svelte-streak-panel": set(),                                                # MAL-2026-14501
    "svelte-streak-tracker": set(),                                              # MAL-2026-14502
    "svelte-vli-ui": set(),                                                      # MAL-2026-14541
    # ─── Student/desmos npm malware cluster (Aug 25–26 2026): 25 packages ──────
    # Coordinated batch of student-named malware packages. Each has an active OSV
    # MAL-2026-14xxx record; all published at 1.0.0 with introduced=0 range.
    # OSV MAL-2026-14446 through MAL-2026-14470 (25 records)
    "classhomework": set(),                                                      # MAL-2026-14446
    "classlesson": set(),                                                        # MAL-2026-14447
    "classroomhomework": set(),                                                  # MAL-2026-14448
    "classroomlesson": set(),                                                    # MAL-2026-14449
    "classroomwork": set(),                                                      # MAL-2026-14450
    "classwork": set(),                                                          # MAL-2026-14451
    "desmosclasswork": set(),                                                    # MAL-2026-14452
    "desmoshomework": set(),                                                     # MAL-2026-14453
    "desmosisfire": set(),                                                       # MAL-2026-14454
    "desmosistuff": set(),                                                       # MAL-2026-14455
    "desmosmathwork": set(),                                                     # MAL-2026-14456
    "desmosschoolwork": set(),                                                   # MAL-2026-14457
    "desmoswork": set(),                                                         # MAL-2026-14458
    "iamhungryrn": set(),                                                        # MAL-2026-14459
    "ilovedesmos": set(),                                                        # MAL-2026-14460
    "iwantaburger": set(),                                                       # MAL-2026-14461
    "pleasedoyourhomework": set(),                                               # MAL-2026-14462
    "schoolhomework": set(),                                                     # MAL-2026-14463
    "schoollesson": set(),                                                       # MAL-2026-14464
    "schoolwork": set(),                                                         # MAL-2026-14465
    "sonsonsahur": set(),                                                        # MAL-2026-14466
    "superdupertest111": set(),                                                  # MAL-2026-14467
    "tungtunggod": set(),                                                        # MAL-2026-14468
    "tungtungisgoated": set(),                                                   # MAL-2026-14469
    "whatsgoodlookingbabycreed": set(),                                          # MAL-2026-14470
    # ─── Hydration UI / svelte-UI cluster (Aug 25–26 2026): 5 packages ─────────
    # OSV MAL-2026-14489, MAL-2026-14506, MAL-2026-14517, MAL-2026-14518,
    # MAL-2026-14535
    "dim-svelte-ui": set(),                                                      # MAL-2026-14506
    "hydration-cls-ui": set(),                                                   # MAL-2026-14489
    "hydration-ui-cls": set(),                                                   # MAL-2026-14517
    "hydration-vli-ui": set(),                                                   # MAL-2026-14535
    "svelte-ui-cls": set(),                                                      # MAL-2026-14518
    # ─── WhatsApp Baileys malware cluster (Aug 26–27 2026): 4 packages ──────────
    # Malicious Baileys (WhatsApp API) wrappers — attacker-controlled scopes.
    # OSV MAL-2026-14527, MAL-2026-14528, MAL-2026-14529, MAL-2026-14540
    "@fongsidev/scraper": set(),                                                 # MAL-2026-14527
    "@lordmega/baileys": set(),                                                  # MAL-2026-14540
    "baileys-inmemory-store": set(),                                             # MAL-2026-14528
    "baileys-mbuilder": set(),                                                   # MAL-2026-14529
    # ─── Vue plugin typosquats (2026): 2 packages ─────────────────────────────
    # vue-template-compiler-plugin and vue-compiler-sfc-plugin impersonate
    # official Vue plugins.
    # OSV MAL-2026-3777, MAL-2026-4707
    "vue-compiler-sfc-plugin": set(),                                            # MAL-2026-4707
    "vue-template-compiler-plugin": set(),                                       # MAL-2026-3777
    # ─── Vite plugin malware cluster (Aug 25–26 2026): 5 packages ───────────────
    # Fake Vite build-tool plugins; multiple versions published per package.
    # OSV MAL-2026-5714, MAL-2026-14479, MAL-2026-14480, MAL-2026-14481,
    # MAL-2026-14482
    "vite-plugin-bug-tracker": {"1.0.0", "1.1.0"},                               # MAL-2026-14479
    "vite-plugin-image-analysis": {"1.0.0", "1.1.0", "1.1.2"},                  # MAL-2026-14480
    "vite-plugin-image-tracker": {"1.0.0", "1.1.0"},                             # MAL-2026-14481
    "vite-plugin-images-analysis": {"1.0.0"},                                    # MAL-2026-14482
    "vite-plugin-logo": set(),                                                   # MAL-2026-5714
    # ─── Self-sign certificate malware (Aug 27 2026): 2 packages ────────────────
    # self-certificates and self-sign: credential/cert stealers with many versions.
    # OSV MAL-2026-14543, MAL-2026-14544
    "self-certificates": set(),                                                  # MAL-2026-14543
    "self-sign": set(),                                                          # MAL-2026-14544
    # ─── Ecobee API typosquats (Aug 25 2026): 3 packages ─────────────────────────
    # ecobee-api, ecobee-home, ecobee2: fake Ecobee home-automation SDK packages.
    # OSV MAL-2026-14474, MAL-2026-14475, MAL-2026-14476
    "ecobee-api": {"0.0.2"},                                                     # MAL-2026-14474
    "ecobee-home": {"0.0.2"},                                                    # MAL-2026-14475
    "ecobee2": {"0.0.2"},                                                        # MAL-2026-14476
    # ─── Spotify URL typosquats (Aug 25–26 2026): 3 packages ─────────────────────
    # Typosquats on the legitimate spotify-url-info package (3.4.2).
    # OSV MAL-2026-14487, MAL-2026-14492, MAL-2026-14538
    "spotify-url-infos": {"3.4.2"},                                              # MAL-2026-14492
    "spotify-url-resolovela": {"3.4.2"},                                         # MAL-2026-14487
    "spotify-url-resolvers": {"3.4.2"},                                          # MAL-2026-14538
    # ─── Chai testing framework typosquats (Aug 25–26 2026): 3 packages ─────────
    # chai-as-otc, chai-as-org, chai-plus: typosquats on chai assertion library.
    # OSV MAL-2026-14491, MAL-2026-14532, MAL-2026-14533
    "chai-as-org": {"1.0.5"},                                                    # MAL-2026-14532
    "chai-as-otc": {"1.0.5"},                                                    # MAL-2026-14491
    "chai-plus": set(),                                                          # MAL-2026-14533
    # ─── WM internal dep-confusion (Aug 26 2026): 3 packages ─────────────────────
    # wm-eslint-fe, wm-lib-env-provider, wm-idp-sdk: dep-confusion probes
    # against a WM private npm scope.
    # OSV MAL-2026-4808, MAL-2026-14514, MAL-2026-14515
    "wm-eslint-fe": set(),                                                       # MAL-2026-14514
    "wm-idp-sdk": set(),                                                         # MAL-2026-4808
    "wm-lib-env-provider": set(),                                                # MAL-2026-14515
    # ─── Aug 25–27 2026: mixed npm malware batch (48 packages) ────────────────────
    # Diverse credential stealers, dep-confusion probes, and pure-malware packages,
    # each confirmed by an individual OSV MAL-2026-14xxx / MAL-2025-xxxx record.
    # OSV MAL-2025-6727, MAL-2026-1383, MAL-2026-2828, MAL-2026-2830,
    # MAL-2026-3030, MAL-2026-4677, MAL-2026-5884, MAL-2026-5935,
    # MAL-2026-6223, MAL-2026-6224, MAL-2026-6358, MAL-2026-10136,
    # MAL-2026-12221, MAL-2026-14445, MAL-2026-14471 through MAL-2026-14486,
    # MAL-2026-14490, MAL-2026-14503 through MAL-2026-14510, MAL-2026-14512,
    # MAL-2026-14513, MAL-2026-14519 through MAL-2026-14521, MAL-2026-14526,
    # MAL-2026-14530, MAL-2026-14531, MAL-2026-14534, MAL-2026-14536,
    # MAL-2026-14537, MAL-2026-14539, MAL-2026-14546 through MAL-2026-14550
    "@immuta/pxl-components": {"99.99.0", "99.99.1"},                            # MAL-2026-1383
    "analytics-v2": {"4.0.0"},                                                   # MAL-2026-14531
    "array-shuffler-utils-99": set(),                                            # MAL-2026-14519
    "cat-embed-i18n-res": {"1.0.0"},                                             # MAL-2026-14471
    "commonjs-code-token": {"1.0.0", "1.0.1"},                                   # MAL-2026-14534
    "cscasereadserv-paypal": {"3.4.3"},                                          # MAL-2026-14472
    "css-import-order": {"1.1.0"},                                               # MAL-2026-14473
    "digitalexp-style-module-l9": {"99.0.0"},                                    # MAL-2026-14445
    "dumb-binding-gyp-package": set(),                                           # MAL-2026-14546
    "express-security-policy": set(),                                            # MAL-2026-2828
    "fetch-page-assets": {"1.2.9", "1.2.13", "1.2.14"},                          # MAL-2026-6358
    "fivem-tool-helper": set(),                                                  # MAL-2026-14520
    "fivem-tool-helper-v2": set(),                                               # MAL-2026-14521
    "foldmap": set(),                                                            # MAL-2026-14507
    "grandfather_of_the_desert": set(),                                          # MAL-2026-14547
    "hexdrift": set(),                                                           # MAL-2026-14508
    "hyperion-react-native-testapp": {"1.0.0"},                                  # MAL-2025-6727
    "infomedia": set(),                                                          # MAL-2026-14530
    "js-soul": {"1.0.4"},                                                        # MAL-2026-14477
    "mham-js": {"1.0.4"},                                                        # MAL-2026-14478
    "mjs-eslint": set(),                                                         # MAL-2026-6223
    "mkb-manager": set(),                                                        # MAL-2026-14490
    "model-poc-suhail": set(),                                                   # MAL-2026-3030
    "modules-newline": {"0.0.6"},                                                # MAL-2026-14483
    "mt-ts-serverless-starter": {"1.0.1"},                                       # MAL-2026-14536
    "new-eslint": set(),                                                         # MAL-2026-6224
    "octopus-action": {"1.0.1"},                                                 # MAL-2026-14537
    "omniauth-recharge-rails-example": {"1.0.0"},                                # MAL-2026-14526
    "r4wk-book": set(),                                                          # MAL-2026-14509
    "react-remove-properties": {"6.14.1"},                                       # MAL-2026-14484
    "renovate-config-doctolib": set(),                                           # MAL-2026-2830
    "secretkey-2fa": {"1.0.0", "1.0.1"},                                         # MAL-2026-14485
    "shai_hulululud": set(),                                                     # MAL-2026-14548
    "snapbuf": set(),                                                            # MAL-2026-14510
    "spf-analytics": {"1.0.0"},                                                  # MAL-2026-14486
    "swift-optimizer": set(),                                                    # MAL-2026-4677
    "tailwind-custom-forms": set(),                                              # MAL-2026-12221
    "tailwind-scrollbar-hider": set(),                                           # MAL-2026-14512
    "text-crate-check": set(),                                                   # MAL-2026-14503
    "the_tax_free_cashier_is_at_9f": set(),                                      # MAL-2026-14549
    "transform-es2015-sticky-regex": set(),                                      # MAL-2026-10136
    "tset_racie": set(),                                                         # MAL-2026-14550
    "tw-theme-kit": set(),                                                       # MAL-2026-5935
    "typedoc-xyz": set(),                                                        # MAL-2026-14513
    "video-crate-check": set(),                                                  # MAL-2026-14504
    "voice-crate-check": set(),                                                  # MAL-2026-14505
    "vortnode": set(),                                                           # MAL-2026-5884
    "zenntechinc-cli": {"1.6.4", "1.6.6"},                                       # MAL-2026-14539
    # ─── @hd-team dep-confusion cluster (Aug 27 2026): 8 packages ───────────────
    # Eight private-scope packages published to the public npm registry as
    # dep-confusion probes targeting a company using @hd-team/* internally.
    # OSV MAL-2026-14569, MAL-2026-14570, MAL-2026-14571, MAL-2026-14572,
    # MAL-2026-14573, MAL-2026-14574, MAL-2026-14575, MAL-2026-14576
    "@hd-team/app-dnpkg-beta": set(),                                 # MAL-2026-14569
    "@hd-team/app-dnpkg-eight": set(),                                # MAL-2026-14570
    "@hd-team/app-dnpkg-prod": set(),                                 # MAL-2026-14571
    "@hd-team/app-dnpkg-ten": set(),                                  # MAL-2026-14572
    "@hd-team/app-dnpkg-test": set(),                                 # MAL-2026-14573
    "@hd-team/app-dnpkg-three": set(),                                # MAL-2026-14574
    "@hd-team/app-impkg-prod": set(),                                 # MAL-2026-14575
    "@hd-team/app-impkg-test": set(),                                 # MAL-2026-14576
    # ─── Aug 27-28 2026: mixed npm malware batch (24 packages) ──────────────────
    # Diverse credential stealers, dep-confusion probes, typosquats, and pure-malware.
    # OSV MAL-2026-14551, MAL-2026-14553, MAL-2026-14557, MAL-2026-14558,
    # MAL-2026-14559, MAL-2026-14560, MAL-2026-14561, MAL-2026-14562,
    # MAL-2026-14563, MAL-2026-14564, MAL-2026-14565, MAL-2026-14566,
    # MAL-2026-14567, MAL-2026-14568, MAL-2026-14577, MAL-2026-14578,
    # MAL-2026-14579, MAL-2026-14580, MAL-2026-14585
    "@cortana-md/engine": set(),                                      # MAL-2026-14553
    "@postman-cse/okta-aio-darwin-arm64": {"0.11.6"},                 # MAL-2026-14580
    "@znan/wabot": {"0.0.87", "0.0.88", "0.0.89", "0.0.90",
                    "0.0.93", "0.0.94", "0.0.95", "0.0.96",
                    "0.0.97", "0.0.98", "0.0.99", "0.0.101",
                    "0.0.102", "0.0.103", "0.0.104", "0.0.105",
                    "0.0.106", "0.1.0-rc.0", "0.1.0-rc.1",
                    "0.1.0-beta.0", "0.2.0-beta.0", "0.2.0-beta.3",
                    "0.2.0-beta.4", "0.2.0-beta.5", "0.2.0-beta.6",
                    "0.2.0-beta.7", "0.2.0-beta.8", "0.2.1",
                    "0.2.2-beta.0", "0.2.2-beta.1", "0.2.2-beta.2",
                    "0.2.2-beta.3"},                                   # MAL-2026-14585
    "bnotify-web-sdk": set(),                                         # MAL-2026-14551
    "charclass": set(),                                               # MAL-2026-14557
    "deepjoin": set(),                                                # MAL-2026-14558
    "hydration-ui-dlx": set(),                                        # MAL-2026-14577
    "imo-allowlist-xss-poc": set(),                                   # MAL-2026-14559
    "inspectstack": set(),                                            # MAL-2026-14560
    "module-relpath": set(),                                          # MAL-2026-14561
    "morglog": set(),                                                  # MAL-2026-14562
    "pushgitquickx": {"1.0.0", "1.0.4", "1.0.5", "1.0.6",
                      "1.0.7", "1.0.8", "1.0.9", "1.0.10",
                      "1.0.11", "1.0.12", "1.0.13", "1.0.14",
                      "1.0.15", "1.0.16", "1.0.17"},                  # MAL-2026-14578
    "rn-push-provisioning": set(),                                    # MAL-2026-14563
    "sigcheck": set(),                                                # MAL-2026-14564
    "stackpaths": set(),                                              # MAL-2026-14565
    "svelte-ui-dlx": set(),                                           # MAL-2026-14579
    "tailwindcss-3d-animate": set(),                                  # MAL-2026-14567
    "tailwindcss-form-styles": {"0.5.15"},                            # MAL-2026-14568
    "veloq": set(),                                                   # MAL-2026-14566
    # ─── 3layerdipstack obfuscated dep-confusion cluster (Aug 28 2026) ────────
    # 407 packages using randomised suffix names to probe for private internal
    # modules. All carry an introduced:0 range (pure-malware, no legitimate use).
    # OSV MAL-2026-14592 .. MAL-2026-14998
    "3layerdipstack04tdo": set(),  # MAL-2026-14592
    "3layerdipstack0dsxsc": set(),  # MAL-2026-14593
    "3layerdipstack0e2jp": set(),  # MAL-2026-14594
    "3layerdipstack0ighvf": set(),  # MAL-2026-14595
    "3layerdipstack0y4arx": set(),  # MAL-2026-14596
    "3layerdipstack18hkx": set(),  # MAL-2026-14597
    "3layerdipstack1a4xg": set(),  # MAL-2026-14598
    "3layerdipstack1ccrm9": set(),  # MAL-2026-14599
    "3layerdipstack1eognp": set(),  # MAL-2026-14600
    "3layerdipstack1ew1w": set(),  # MAL-2026-14601
    "3layerdipstack1g5cxo": set(),  # MAL-2026-14602
    "3layerdipstack1igc1l": set(),  # MAL-2026-14603
    "3layerdipstack1lb2r": set(),  # MAL-2026-14604
    "3layerdipstack1lkqg9": set(),  # MAL-2026-14605
    "3layerdipstack1nz8o": set(),  # MAL-2026-14606
    "3layerdipstack1qjbr": set(),  # MAL-2026-14607
    "3layerdipstack1ykdgn": set(),  # MAL-2026-14608
    "3layerdipstack2cyinb": set(),  # MAL-2026-14609
    "3layerdipstack2pdlo4": set(),  # MAL-2026-14610
    "3layerdipstack2u8fh": set(),  # MAL-2026-14611
    "3layerdipstack2ya7xz": set(),  # MAL-2026-14612
    "3layerdipstack3h0mt": set(),  # MAL-2026-14613
    "3layerdipstack3hsru3": set(),  # MAL-2026-14614
    "3layerdipstack3i8km": set(),  # MAL-2026-14615
    "3layerdipstack3jen8": set(),  # MAL-2026-14616
    "3layerdipstack3psj0": set(),  # MAL-2026-14617
    "3layerdipstack3vept": set(),  # MAL-2026-14618
    "3layerdipstack4dhmdb": set(),  # MAL-2026-14619
    "3layerdipstack4dhts": set(),  # MAL-2026-14620
    "3layerdipstack4ebgmu": set(),  # MAL-2026-14621
    "3layerdipstack4hg6p": set(),  # MAL-2026-14622
    "3layerdipstack4ib1jd": set(),  # MAL-2026-14623
    "3layerdipstack4iivta": set(),  # MAL-2026-14624
    "3layerdipstack4ilqnj": set(),  # MAL-2026-14625
    "3layerdipstack4pstwd": set(),  # MAL-2026-14626
    "3layerdipstack4wsms0": set(),  # MAL-2026-14627
    "3layerdipstack5a7otk": set(),  # MAL-2026-14628
    "3layerdipstack5aycu": set(),  # MAL-2026-14629
    "3layerdipstack5cwu1": set(),  # MAL-2026-14630
    "3layerdipstack5dfkei": set(),  # MAL-2026-14631
    "3layerdipstack5eariu": set(),  # MAL-2026-14632
    "3layerdipstack5f0nl": set(),  # MAL-2026-14633
    "3layerdipstack5f9qf": set(),  # MAL-2026-14634
    "3layerdipstack5hkzmg": set(),  # MAL-2026-14635
    "3layerdipstack5nigd": set(),  # MAL-2026-14636
    "3layerdipstack5r1sh": set(),  # MAL-2026-14637
    "3layerdipstack5tuhr5": set(),  # MAL-2026-14638
    "3layerdipstack5vnbm": set(),  # MAL-2026-14639
    "3layerdipstack5vpco": set(),  # MAL-2026-14640
    "3layerdipstack5zhcdq": set(),  # MAL-2026-14641
    "3layerdipstack6ih5ru": set(),  # MAL-2026-14642
    "3layerdipstack6jqkjs": set(),  # MAL-2026-14643
    "3layerdipstack6kyra": set(),  # MAL-2026-14644
    "3layerdipstack6mpbze": set(),  # MAL-2026-14645
    "3layerdipstack6wih1": set(),  # MAL-2026-14646
    "3layerdipstack6wovmj": set(),  # MAL-2026-14647
    "3layerdipstack71tlcd": set(),  # MAL-2026-14648
    "3layerdipstack74ooau": set(),  # MAL-2026-14649
    "3layerdipstack75faj": set(),  # MAL-2026-14650
    "3layerdipstack7atotw": set(),  # MAL-2026-14651
    "3layerdipstack7cgotb": set(),  # MAL-2026-14652
    "3layerdipstack7d0vc": set(),  # MAL-2026-14653
    "3layerdipstack7eu4ry": set(),  # MAL-2026-14654
    "3layerdipstack7ezqzp": set(),  # MAL-2026-14655
    "3layerdipstack7ke6fz": set(),  # MAL-2026-14656
    "3layerdipstack7lknl": set(),  # MAL-2026-14657
    "3layerdipstack7u3sgs": set(),  # MAL-2026-14658
    "3layerdipstack7wbw9m": set(),  # MAL-2026-14659
    "3layerdipstack7zgtws": set(),  # MAL-2026-14660
    "3layerdipstack89dtg": set(),  # MAL-2026-14661
    "3layerdipstack8b4dts": set(),  # MAL-2026-14662
    "3layerdipstack8e0an": set(),  # MAL-2026-14663
    "3layerdipstack8lj8gm": set(),  # MAL-2026-14664
    "3layerdipstack8nvcr": set(),  # MAL-2026-14665
    "3layerdipstack8v1vs": set(),  # MAL-2026-14666
    "3layerdipstack8xhwdm": set(),  # MAL-2026-14667
    "3layerdipstack8yfoyr": set(),  # MAL-2026-14668
    "3layerdipstack8zg7y": set(),  # MAL-2026-14669
    "3layerdipstack97rmzr": set(),  # MAL-2026-14670
    "3layerdipstack9ai4f": set(),  # MAL-2026-14671
    "3layerdipstack9b0cq": set(),  # MAL-2026-14672
    "3layerdipstack9d7ow": set(),  # MAL-2026-14673
    "3layerdipstack9gdxi6": set(),  # MAL-2026-14674
    "3layerdipstack9j4ke": set(),  # MAL-2026-14675
    "3layerdipstack9ma2d": set(),  # MAL-2026-14676
    "3layerdipstack9nawzv": set(),  # MAL-2026-14677
    "3layerdipstack9riv6": set(),  # MAL-2026-14678
    "3layerdipstack9thbs": set(),  # MAL-2026-14679
    "3layerdipstack9u8ge": set(),  # MAL-2026-14680
    "3layerdipstack9umaj": set(),  # MAL-2026-14681
    "3layerdipstack9umzt": set(),  # MAL-2026-14682
    "3layerdipstack9vcxi9": set(),  # MAL-2026-14683
    "3layerdipstacka1fnr": set(),  # MAL-2026-14684
    "3layerdipstackaac4df": set(),  # MAL-2026-14685
    "3layerdipstackaawov4": set(),  # MAL-2026-14686
    "3layerdipstackaho91u": set(),  # MAL-2026-14687
    "3layerdipstackaudu38": set(),  # MAL-2026-14688
    "3layerdipstackay9drz": set(),  # MAL-2026-14689
    "3layerdipstackb0eeq": set(),  # MAL-2026-14690
    "3layerdipstackb1ojqr": set(),  # MAL-2026-14691
    "3layerdipstackb68qiv": set(),  # MAL-2026-14692
    "3layerdipstackba1nq3": set(),  # MAL-2026-14693
    "3layerdipstackba23j": set(),  # MAL-2026-14694
    "3layerdipstackbgh33k": set(),  # MAL-2026-14695
    "3layerdipstackbn5wu": set(),  # MAL-2026-14696
    "3layerdipstackbn8wg": set(),  # MAL-2026-14697
    "3layerdipstackbndk47": set(),  # MAL-2026-14698
    "3layerdipstackbopqb8": set(),  # MAL-2026-14699
    "3layerdipstackbxw4k": set(),  # MAL-2026-14700
    "3layerdipstackbz1nv9": set(),  # MAL-2026-14701
    "3layerdipstackc6c5kn": set(),  # MAL-2026-14702
    "3layerdipstackcaujb": set(),  # MAL-2026-14703
    "3layerdipstackcbatl4": set(),  # MAL-2026-14704
    "3layerdipstackcfbla": set(),  # MAL-2026-14705
    "3layerdipstackcfu35": set(),  # MAL-2026-14706
    "3layerdipstackch7e5": set(),  # MAL-2026-14707
    "3layerdipstackchk77": set(),  # MAL-2026-14708
    "3layerdipstackcjddnb": set(),  # MAL-2026-14709
    "3layerdipstackckdy9": set(),  # MAL-2026-14710
    "3layerdipstackcnxrzk": set(),  # MAL-2026-14711
    "3layerdipstackcrikda": set(),  # MAL-2026-14712
    "3layerdipstackcstjn": set(),  # MAL-2026-14713
    "3layerdipstackctn2v": set(),  # MAL-2026-14714
    "3layerdipstackcvi67o": set(),  # MAL-2026-14715
    "3layerdipstackcyqc7o": set(),  # MAL-2026-14716
    "3layerdipstackd3cxf7": set(),  # MAL-2026-14717
    "3layerdipstackd4npj": set(),  # MAL-2026-14718
    "3layerdipstackd80ved": set(),  # MAL-2026-14719
    "3layerdipstackd8ze8": set(),  # MAL-2026-14720
    "3layerdipstackdanp80": set(),  # MAL-2026-14721
    "3layerdipstackdb90s": set(),  # MAL-2026-14722
    "3layerdipstackdci73": set(),  # MAL-2026-14723
    "3layerdipstackdcw7ib": set(),  # MAL-2026-14724
    "3layerdipstackdflm1d": set(),  # MAL-2026-14725
    "3layerdipstackdfw3wg": set(),  # MAL-2026-14726
    "3layerdipstackdit9j": set(),  # MAL-2026-14727
    "3layerdipstackdnbulr": set(),  # MAL-2026-14728
    "3layerdipstackds3oln": set(),  # MAL-2026-14729
    "3layerdipstackds5wll": set(),  # MAL-2026-14730
    "3layerdipstackdsc6gn": set(),  # MAL-2026-14731
    "3layerdipstackdwrofj": set(),  # MAL-2026-14732
    "3layerdipstacke2eppx": set(),  # MAL-2026-14733
    "3layerdipstackea57kt": set(),  # MAL-2026-14734
    "3layerdipstackebunld": set(),  # MAL-2026-14735
    "3layerdipstackedh67n": set(),  # MAL-2026-14736
    "3layerdipstackedqpy": set(),  # MAL-2026-14737
    "3layerdipstackeflbpd": set(),  # MAL-2026-14738
    "3layerdipstackefwqm": set(),  # MAL-2026-14739
    "3layerdipstackelcuhp": set(),  # MAL-2026-14740
    "3layerdipstackenjw1i": set(),  # MAL-2026-14741
    "3layerdipstackepcy6k": set(),  # MAL-2026-14742
    "3layerdipstackesp1lb": set(),  # MAL-2026-14743
    "3layerdipstackesxum": set(),  # MAL-2026-14744
    "3layerdipstackev4sn5": set(),  # MAL-2026-14745
    "3layerdipstackewhns5": set(),  # MAL-2026-14746
    "3layerdipstackf0lda9": set(),  # MAL-2026-14747
    "3layerdipstackf9oik": set(),  # MAL-2026-14748
    "3layerdipstackfdgka0": set(),  # MAL-2026-14749
    "3layerdipstackfhcuh": set(),  # MAL-2026-14750
    "3layerdipstackfkqbp4": set(),  # MAL-2026-14751
    "3layerdipstackfl4v8": set(),  # MAL-2026-14752
    "3layerdipstackfm45yj": set(),  # MAL-2026-14753
    "3layerdipstackfoajna": set(),  # MAL-2026-14754
    "3layerdipstackfooret": set(),  # MAL-2026-14755
    "3layerdipstackfourm4": set(),  # MAL-2026-14756
    "3layerdipstackfp5dp": set(),  # MAL-2026-14757
    "3layerdipstackfqxcmc": set(),  # MAL-2026-14758
    "3layerdipstackftd8b": set(),  # MAL-2026-14759
    "3layerdipstackfywqmz": set(),  # MAL-2026-14760
    "3layerdipstackfzx88": set(),  # MAL-2026-14761
    "3layerdipstackg4okgs": set(),  # MAL-2026-14762
    "3layerdipstackgbmd1c": set(),  # MAL-2026-14763
    "3layerdipstackgbshj": set(),  # MAL-2026-14764
    "3layerdipstackgcno4": set(),  # MAL-2026-14765
    "3layerdipstackggjd8x": set(),  # MAL-2026-14766
    "3layerdipstackgqt6yc": set(),  # MAL-2026-14767
    "3layerdipstackgrzn5z": set(),  # MAL-2026-14768
    "3layerdipstackgyrw9d": set(),  # MAL-2026-14769
    "3layerdipstackh5ax7": set(),  # MAL-2026-14770
    "3layerdipstackhcymwm": set(),  # MAL-2026-14771
    "3layerdipstackhi9md": set(),  # MAL-2026-14772
    "3layerdipstackhivao": set(),  # MAL-2026-14773
    "3layerdipstackhr3ocw": set(),  # MAL-2026-14774
    "3layerdipstackhyazlk": set(),  # MAL-2026-14775
    "3layerdipstackhykud": set(),  # MAL-2026-14776
    "3layerdipstackic0c5r": set(),  # MAL-2026-14777
    "3layerdipstackicrmv": set(),  # MAL-2026-14778
    "3layerdipstackidjlc": set(),  # MAL-2026-14779
    "3layerdipstackieh8c": set(),  # MAL-2026-14780
    "3layerdipstackihi1o9": set(),  # MAL-2026-14781
    "3layerdipstackiud1lz": set(),  # MAL-2026-14782
    "3layerdipstackj0xnu": set(),  # MAL-2026-14783
    "3layerdipstackj3eh2": set(),  # MAL-2026-14784
    "3layerdipstackjac6a": set(),  # MAL-2026-14785
    "3layerdipstackjdbrp": set(),  # MAL-2026-14786
    "3layerdipstackjfp5u": set(),  # MAL-2026-14787
    "3layerdipstackjgfism": set(),  # MAL-2026-14788
    "3layerdipstackjj1l0": set(),  # MAL-2026-14789
    "3layerdipstackjnh4m1": set(),  # MAL-2026-14790
    "3layerdipstackjsuvtk": set(),  # MAL-2026-14791
    "3layerdipstackjw2t3": set(),  # MAL-2026-14792
    "3layerdipstackjx20az": set(),  # MAL-2026-14793
    "3layerdipstackjxbse8": set(),  # MAL-2026-14794
    "3layerdipstackk5ewlo": set(),  # MAL-2026-14795
    "3layerdipstackk83nm": set(),  # MAL-2026-14796
    "3layerdipstackkaw1i8": set(),  # MAL-2026-14797
    "3layerdipstackkdz8gp": set(),  # MAL-2026-14798
    "3layerdipstackkege4f": set(),  # MAL-2026-14799
    "3layerdipstackkg0gfy": set(),  # MAL-2026-14800
    "3layerdipstackkirw0e": set(),  # MAL-2026-14801
    "3layerdipstackkl17i": set(),  # MAL-2026-14802
    "3layerdipstackklb52": set(),  # MAL-2026-14803
    "3layerdipstackkpfva6": set(),  # MAL-2026-14804
    "3layerdipstackkrgcjq": set(),  # MAL-2026-14805
    "3layerdipstackkx7y2": set(),  # MAL-2026-14806
    "3layerdipstackkxrxle": set(),  # MAL-2026-14807
    "3layerdipstackkysrek": set(),  # MAL-2026-14808
    "3layerdipstackkzelo0": set(),  # MAL-2026-14809
    "3layerdipstackl21ibf": set(),  # MAL-2026-14810
    "3layerdipstackl3dhz": set(),  # MAL-2026-14811
    "3layerdipstackl3yyy": set(),  # MAL-2026-14812
    "3layerdipstackl52afz": set(),  # MAL-2026-14813
    "3layerdipstackl7gab": set(),  # MAL-2026-14814
    "3layerdipstackl88spb": set(),  # MAL-2026-14815
    "3layerdipstacklabm6": set(),  # MAL-2026-14816
    "3layerdipstacklbpy50": set(),  # MAL-2026-14817
    "3layerdipstacklbxr4c": set(),  # MAL-2026-14818
    "3layerdipstacklc7lgg": set(),  # MAL-2026-14819
    "3layerdipstacklgszmx": set(),  # MAL-2026-14820
    "3layerdipstackljpzly": set(),  # MAL-2026-14821
    "3layerdipstacklrswmw": set(),  # MAL-2026-14822
    "3layerdipstacklskknx": set(),  # MAL-2026-14823
    "3layerdipstacklzflp": set(),  # MAL-2026-14824
    "3layerdipstackm1j2h": set(),  # MAL-2026-14825
    "3layerdipstackm6i9v": set(),  # MAL-2026-14826
    "3layerdipstackm7mock": set(),  # MAL-2026-14827
    "3layerdipstackm7yxnp": set(),  # MAL-2026-14828
    "3layerdipstackmi10b": set(),  # MAL-2026-14829
    "3layerdipstackmiputn": set(),  # MAL-2026-14830
    "3layerdipstackmjdc98": set(),  # MAL-2026-14831
    "3layerdipstackmjm6e": set(),  # MAL-2026-14832
    "3layerdipstackmk7pb": set(),  # MAL-2026-14833
    "3layerdipstackmn51k": set(),  # MAL-2026-14834
    "3layerdipstackmokfkh": set(),  # MAL-2026-14835
    "3layerdipstackmplv5": set(),  # MAL-2026-14836
    "3layerdipstackmu4bxx": set(),  # MAL-2026-14837
    "3layerdipstackn2nce": set(),  # MAL-2026-14838
    "3layerdipstackn71eil": set(),  # MAL-2026-14839
    "3layerdipstackn7fk1": set(),  # MAL-2026-14840
    "3layerdipstackn7sxtp": set(),  # MAL-2026-14841
    "3layerdipstackn9ng1d": set(),  # MAL-2026-14842
    "3layerdipstacknk2da": set(),  # MAL-2026-14843
    "3layerdipstacknk99g": set(),  # MAL-2026-14844
    "3layerdipstacknlxzr": set(),  # MAL-2026-14845
    "3layerdipstacknqbfz": set(),  # MAL-2026-14846
    "3layerdipstacknqxij": set(),  # MAL-2026-14847
    "3layerdipstacknstgz": set(),  # MAL-2026-14848
    "3layerdipstacknuabm": set(),  # MAL-2026-14849
    "3layerdipstacknwgnpw": set(),  # MAL-2026-14850
    "3layerdipstacko89fkl": set(),  # MAL-2026-14851
    "3layerdipstacko8li9w": set(),  # MAL-2026-14852
    "3layerdipstackoa1cxf": set(),  # MAL-2026-14853
    "3layerdipstackobk93q": set(),  # MAL-2026-14854
    "3layerdipstackodswc": set(),  # MAL-2026-14855
    "3layerdipstackog84a": set(),  # MAL-2026-14856
    "3layerdipstackogwk1": set(),  # MAL-2026-14857
    "3layerdipstackoi4dda": set(),  # MAL-2026-14858
    "3layerdipstackoj4nf9": set(),  # MAL-2026-14859
    "3layerdipstackolosqh": set(),  # MAL-2026-14860
    "3layerdipstackoms1fe": set(),  # MAL-2026-14861
    "3layerdipstackoo1jd": set(),  # MAL-2026-14862
    "3layerdipstackoo3m1u": set(),  # MAL-2026-14863
    "3layerdipstackopdmf": set(),  # MAL-2026-14864
    "3layerdipstackoue8uj": set(),  # MAL-2026-14865
    "3layerdipstackp4yyc": set(),  # MAL-2026-14866
    "3layerdipstackp5nvj": set(),  # MAL-2026-14867
    "3layerdipstackp6m8ir": set(),  # MAL-2026-14868
    "3layerdipstackp92wd": set(),  # MAL-2026-14869
    "3layerdipstackp9bua": set(),  # MAL-2026-14870
    "3layerdipstackpbkfvo": set(),  # MAL-2026-14871
    "3layerdipstackpcv17m": set(),  # MAL-2026-14872
    "3layerdipstackpd83be": set(),  # MAL-2026-14873
    "3layerdipstackpfnj1": set(),  # MAL-2026-14874
    "3layerdipstackplila": set(),  # MAL-2026-14875
    "3layerdipstackplnt8o": set(),  # MAL-2026-14876
    "3layerdipstackpmrxi4": set(),  # MAL-2026-14877
    "3layerdipstackpmw72s": set(),  # MAL-2026-14878
    "3layerdipstackposh4n": set(),  # MAL-2026-14879
    "3layerdipstackpsq4vf": set(),  # MAL-2026-14880
    "3layerdipstackpvsk6r": set(),  # MAL-2026-14881
    "3layerdipstackpyqy5": set(),  # MAL-2026-14882
    "3layerdipstackq06zyy": set(),  # MAL-2026-14883
    "3layerdipstackq0lwcc": set(),  # MAL-2026-14884
    "3layerdipstackq4ek0f": set(),  # MAL-2026-14885
    "3layerdipstackq6h8eq": set(),  # MAL-2026-14886
    "3layerdipstackqb6ww": set(),  # MAL-2026-14887
    "3layerdipstackqbqwn": set(),  # MAL-2026-14888
    "3layerdipstackqcvl6h": set(),  # MAL-2026-14889
    "3layerdipstackqi4id": set(),  # MAL-2026-14890
    "3layerdipstackqjq77e": set(),  # MAL-2026-14891
    "3layerdipstackqokw95": set(),  # MAL-2026-14892
    "3layerdipstackqpma84": set(),  # MAL-2026-14893
    "3layerdipstackqqd7f": set(),  # MAL-2026-14894
    "3layerdipstackqszzc": set(),  # MAL-2026-14895
    "3layerdipstackqyhks": set(),  # MAL-2026-14896
    "3layerdipstackr4geh2": set(),  # MAL-2026-14897
    "3layerdipstackr5ga2v": set(),  # MAL-2026-14898
    "3layerdipstackr7ib9k": set(),  # MAL-2026-14899
    "3layerdipstackr8xy1r": set(),  # MAL-2026-14900
    "3layerdipstackra0nf": set(),  # MAL-2026-14901
    "3layerdipstackrbupl": set(),  # MAL-2026-14902
    "3layerdipstackrc44f": set(),  # MAL-2026-14903
    "3layerdipstackrce3qw": set(),  # MAL-2026-14904
    "3layerdipstackrcuf3": set(),  # MAL-2026-14905
    "3layerdipstackrh52pp": set(),  # MAL-2026-14906
    "3layerdipstackric51a": set(),  # MAL-2026-14907
    "3layerdipstackrkxyr1": set(),  # MAL-2026-14908
    "3layerdipstackru7mfn": set(),  # MAL-2026-14909
    "3layerdipstackrvc9k": set(),  # MAL-2026-14910
    "3layerdipstackrygm3": set(),  # MAL-2026-14911
    "3layerdipstackryyay3": set(),  # MAL-2026-14912
    "3layerdipstacks0fpdw": set(),  # MAL-2026-14913
    "3layerdipstacks42lb": set(),  # MAL-2026-14914
    "3layerdipstacks4wje": set(),  # MAL-2026-14915
    "3layerdipstacks8qqq": set(),  # MAL-2026-14916
    "3layerdipstacksgs6k": set(),  # MAL-2026-14917
    "3layerdipstacksh21o": set(),  # MAL-2026-14918
    "3layerdipstacksihvvg": set(),  # MAL-2026-14919
    "3layerdipstacksla5p": set(),  # MAL-2026-14920
    "3layerdipstacksn9ze": set(),  # MAL-2026-14921
    "3layerdipstacksokbgx": set(),  # MAL-2026-14922
    "3layerdipstacksu99cs": set(),  # MAL-2026-14923
    "3layerdipstacksz3ee": set(),  # MAL-2026-14924
    "3layerdipstackt3wr5f": set(),  # MAL-2026-14925
    "3layerdipstackta7o8u": set(),  # MAL-2026-14926
    "3layerdipstacktc0tq7": set(),  # MAL-2026-14927
    "3layerdipstacktclg9": set(),  # MAL-2026-14928
    "3layerdipstacktfieac": set(),  # MAL-2026-14929
    "3layerdipstacktfp41b": set(),  # MAL-2026-14930
    "3layerdipstackthgojd": set(),  # MAL-2026-14931
    "3layerdipstacktlt5o": set(),  # MAL-2026-14932
    "3layerdipstacktm8xp5": set(),  # MAL-2026-14933
    "3layerdipstacktmo3tu": set(),  # MAL-2026-14934
    "3layerdipstackttd2o": set(),  # MAL-2026-14935
    "3layerdipstackttt4c": set(),  # MAL-2026-14936
    "3layerdipstacku03hgo": set(),  # MAL-2026-14937
    "3layerdipstacku0rsp": set(),  # MAL-2026-14938
    "3layerdipstacku2axz": set(),  # MAL-2026-14939
    "3layerdipstackuayqn": set(),  # MAL-2026-14940
    "3layerdipstackub7lk": set(),  # MAL-2026-14941
    "3layerdipstackubntx": set(),  # MAL-2026-14942
    "3layerdipstackudibkf": set(),  # MAL-2026-14943
    "3layerdipstackuew4bh": set(),  # MAL-2026-14944
    "3layerdipstackujb8p": set(),  # MAL-2026-14945
    "3layerdipstackujfdgm": set(),  # MAL-2026-14946
    "3layerdipstackujt40": set(),  # MAL-2026-14947
    "3layerdipstackuldhl": set(),  # MAL-2026-14948
    "3layerdipstackulgnp8": set(),  # MAL-2026-14949
    "3layerdipstackunyzh": set(),  # MAL-2026-14950
    "3layerdipstackuo78n": set(),  # MAL-2026-14951
    "3layerdipstackuu02ly": set(),  # MAL-2026-14952
    "3layerdipstackuyb1e": set(),  # MAL-2026-14953
    "3layerdipstackuyd45d": set(),  # MAL-2026-14954
    "3layerdipstackv4z5q": set(),  # MAL-2026-14955
    "3layerdipstackvaovrs": set(),  # MAL-2026-14956
    "3layerdipstackvb5y6": set(),  # MAL-2026-14957
    "3layerdipstackvcdkrp": set(),  # MAL-2026-14958
    "3layerdipstackvd6za6": set(),  # MAL-2026-14959
    "3layerdipstackvdy7nf": set(),  # MAL-2026-14960
    "3layerdipstackvhbhs6": set(),  # MAL-2026-14961
    "3layerdipstackvkl1hd": set(),  # MAL-2026-14962
    "3layerdipstackvld3fr": set(),  # MAL-2026-14963
    "3layerdipstackvm4qaj": set(),  # MAL-2026-14964
    "3layerdipstackvnmth1": set(),  # MAL-2026-14965
    "3layerdipstackvo9oet": set(),  # MAL-2026-14966
    "3layerdipstackvtd7og": set(),  # MAL-2026-14967
    "3layerdipstackvtid3m": set(),  # MAL-2026-14968
    "3layerdipstackw1ma2": set(),  # MAL-2026-14969
    "3layerdipstackw2pt3": set(),  # MAL-2026-14970
    "3layerdipstackwc0qja": set(),  # MAL-2026-14971
    "3layerdipstackwexso": set(),  # MAL-2026-14972
    "3layerdipstackwm7sa": set(),  # MAL-2026-14973
    "3layerdipstackwqo67k": set(),  # MAL-2026-14974
    "3layerdipstackwu6ij": set(),  # MAL-2026-14975
    "3layerdipstackwudpnc": set(),  # MAL-2026-14976
    "3layerdipstackx1zi8p": set(),  # MAL-2026-14977
    "3layerdipstackx26ujd": set(),  # MAL-2026-14978
    "3layerdipstackx4y4fx": set(),  # MAL-2026-14979
    "3layerdipstackx70bgg": set(),  # MAL-2026-14980
    "3layerdipstackxav9q": set(),  # MAL-2026-14981
    "3layerdipstackxdv18": set(),  # MAL-2026-14982
    "3layerdipstackxlmq6": set(),  # MAL-2026-14983
    "3layerdipstackxms0j": set(),  # MAL-2026-14984
    "3layerdipstacky2fxy": set(),  # MAL-2026-14985
    "3layerdipstackybqdp4": set(),  # MAL-2026-14986
    "3layerdipstackyhk67g": set(),  # MAL-2026-14987
    "3layerdipstackykas5": set(),  # MAL-2026-14988
    "3layerdipstackykuowv": set(),  # MAL-2026-14989
    "3layerdipstackyq24q": set(),  # MAL-2026-14990
    "3layerdipstackyqrxdf": set(),  # MAL-2026-14991
    "3layerdipstackyt68w": set(),  # MAL-2026-14992
    "3layerdipstackytruq6": set(),  # MAL-2026-14993
    "3layerdipstackz54iek": set(),  # MAL-2026-14994
    "3layerdipstackzhe5k": set(),  # MAL-2026-14995
    "3layerdipstackzhnxi": set(),  # MAL-2026-14996
    "3layerdipstackzpi9o": set(),  # MAL-2026-14997
    "3layerdipstackzz0n4": set(),  # MAL-2026-14998
    # ─── classlink-* dep-confusion/impersonation cluster (Aug 28 2026) ─────────
    # 188 packages mimicking ClassLink ed-tech. All wildcard.
    # OSV MAL-2026-15002 .. MAL-2026-15189
    "classlink-05aivir0": set(),  # MAL-2026-15002
    "classlink-0cxdj3vn": set(),  # MAL-2026-15003
    "classlink-0e3uievl": set(),  # MAL-2026-15004
    "classlink-0oci59kq": set(),  # MAL-2026-15005
    "classlink-0wihdhrz": set(),  # MAL-2026-15006
    "classlink-0xcszcdo": set(),  # MAL-2026-15007
    "classlink-0xj51osu": set(),  # MAL-2026-15008
    "classlink-1avoqu4p": set(),  # MAL-2026-15009
    "classlink-1sbqnhys": set(),  # MAL-2026-15010
    "classlink-1u8eeq4p": set(),  # MAL-2026-15011
    "classlink-1xclw9bj": set(),  # MAL-2026-15012
    "classlink-2ls71exe": set(),  # MAL-2026-15013
    "classlink-2n5caofp": set(),  # MAL-2026-15014
    "classlink-2t1af7jn": set(),  # MAL-2026-15015
    "classlink-2t2ozsy0": set(),  # MAL-2026-15016
    "classlink-31ci3vtf": set(),  # MAL-2026-15017
    "classlink-321ouwqc": set(),  # MAL-2026-15018
    "classlink-3k14cslj": set(),  # MAL-2026-15019
    "classlink-4cnowpix": set(),  # MAL-2026-15020
    "classlink-4d2zvwhb": set(),  # MAL-2026-15021
    "classlink-4mjgbs9i": set(),  # MAL-2026-15022
    "classlink-5bhzaaq2": set(),  # MAL-2026-15023
    "classlink-5ciuoj5g": set(),  # MAL-2026-15024
    "classlink-5fkxmizt": set(),  # MAL-2026-15025
    "classlink-5gz93nzs": set(),  # MAL-2026-15026
    "classlink-5kz6s5ta": set(),  # MAL-2026-15027
    "classlink-5tdruito": set(),  # MAL-2026-15028
    "classlink-5tvmx8a6": set(),  # MAL-2026-15029
    "classlink-5ymxe9bn": set(),  # MAL-2026-15030
    "classlink-62yk5hyp": set(),  # MAL-2026-15031
    "classlink-66crblus": set(),  # MAL-2026-15032
    "classlink-6c4gq8pl": set(),  # MAL-2026-15033
    "classlink-6d5qzkyc": set(),  # MAL-2026-15034
    "classlink-6tjmt4am": set(),  # MAL-2026-15035
    "classlink-775iocrc": set(),  # MAL-2026-15036
    "classlink-7bnzowrp": set(),  # MAL-2026-15037
    "classlink-7yk1dxxn": set(),  # MAL-2026-15038
    "classlink-8bkqsit1": set(),  # MAL-2026-15039
    "classlink-8ockomn3": set(),  # MAL-2026-15040
    "classlink-9nxfp7hx": set(),  # MAL-2026-15041
    "classlink-9uqnil1j": set(),  # MAL-2026-15042
    "classlink-a68gv8mp": set(),  # MAL-2026-15043
    "classlink-aki07yws": set(),  # MAL-2026-15044
    "classlink-aki2aftl": set(),  # MAL-2026-15045
    "classlink-b2mpnr66": set(),  # MAL-2026-15046
    "classlink-b3kc8x9d": set(),  # MAL-2026-15047
    "classlink-bae1zj6h": set(),  # MAL-2026-15048
    "classlink-bi8xv3ye": set(),  # MAL-2026-15049
    "classlink-bjd009ch": set(),  # MAL-2026-15050
    "classlink-bxzjfapu": set(),  # MAL-2026-15051
    "classlink-c78zjnbn": set(),  # MAL-2026-15052
    "classlink-c9euh9gz": set(),  # MAL-2026-15053
    "classlink-c9l8m7yz": set(),  # MAL-2026-15054
    "classlink-chtm9stv": set(),  # MAL-2026-15055
    "classlink-co3ghhbr": set(),  # MAL-2026-15056
    "classlink-cpecvdw5": set(),  # MAL-2026-15057
    "classlink-cqofn6z6": set(),  # MAL-2026-15058
    "classlink-csh3v6cf": set(),  # MAL-2026-15059
    "classlink-csowy37o": set(),  # MAL-2026-15060
    "classlink-cwhcq8dv": set(),  # MAL-2026-15061
    "classlink-cx3wum2m": set(),  # MAL-2026-15062
    "classlink-d29uplpm": set(),  # MAL-2026-15063
    "classlink-d6dllzf9": set(),  # MAL-2026-15064
    "classlink-d7x3eua6": set(),  # MAL-2026-15065
    "classlink-dg6t1awu": set(),  # MAL-2026-15066
    "classlink-djhde9mb": set(),  # MAL-2026-15067
    "classlink-dskw2g17": set(),  # MAL-2026-15068
    "classlink-ejybc15w": set(),  # MAL-2026-15069
    "classlink-ekumpokt": set(),  # MAL-2026-15070
    "classlink-ewfmy87w": set(),  # MAL-2026-15071
    "classlink-eznqjohp": set(),  # MAL-2026-15072
    "classlink-f5r03nln": set(),  # MAL-2026-15073
    "classlink-fp7poyii": set(),  # MAL-2026-15074
    "classlink-fr0zh2sv": set(),  # MAL-2026-15075
    "classlink-fy6wub00": set(),  # MAL-2026-15076
    "classlink-gd7tr7i7": set(),  # MAL-2026-15077
    "classlink-gvxxr7vn": set(),  # MAL-2026-15078
    "classlink-h08wpi0d": set(),  # MAL-2026-15079
    "classlink-h6e4w4ws": set(),  # MAL-2026-15080
    "classlink-h7lrg5jc": set(),  # MAL-2026-15081
    "classlink-hb1qmq9m": set(),  # MAL-2026-15082
    "classlink-hceirb4w": set(),  # MAL-2026-15083
    "classlink-hilvoxs4": set(),  # MAL-2026-15084
    "classlink-hl9uycka": set(),  # MAL-2026-15085
    "classlink-hpxf23yu": set(),  # MAL-2026-15086
    "classlink-i1otx27d": set(),  # MAL-2026-15087
    "classlink-i6ftjcf7": set(),  # MAL-2026-15088
    "classlink-i6i0xjcn": set(),  # MAL-2026-15089
    "classlink-i9ht4ftz": set(),  # MAL-2026-15090
    "classlink-icth7fnc": set(),  # MAL-2026-15091
    "classlink-idih6eh4": set(),  # MAL-2026-15092
    "classlink-ikbkatut": set(),  # MAL-2026-15093
    "classlink-ilhmof2m": set(),  # MAL-2026-15094
    "classlink-ioteg9wb": set(),  # MAL-2026-15095
    "classlink-ivfqk4dz": set(),  # MAL-2026-15096
    "classlink-j9vld79j": set(),  # MAL-2026-15097
    "classlink-jkakj9fh": set(),  # MAL-2026-15098
    "classlink-jp62vjo9": set(),  # MAL-2026-15099
    "classlink-k0tfm3o8": set(),  # MAL-2026-15100
    "classlink-k2zddcsu": set(),  # MAL-2026-15101
    "classlink-k4nakbnt": set(),  # MAL-2026-15102
    "classlink-kfovigbh": set(),  # MAL-2026-15103
    "classlink-kr1dsssk": set(),  # MAL-2026-15104
    "classlink-kr6i9ei3": set(),  # MAL-2026-15105
    "classlink-ksqo5rn6": set(),  # MAL-2026-15106
    "classlink-lbh9r8oq": set(),  # MAL-2026-15107
    "classlink-lflju095": set(),  # MAL-2026-15108
    "classlink-lipiec7v": set(),  # MAL-2026-15109
    "classlink-m3zzm8wb": set(),  # MAL-2026-15110
    "classlink-m7k74jsv": set(),  # MAL-2026-15111
    "classlink-mdtv2lhz": set(),  # MAL-2026-15112
    "classlink-mgsmua9q": set(),  # MAL-2026-15113
    "classlink-mikkkqox": set(),  # MAL-2026-15114
    "classlink-miudxzw9": set(),  # MAL-2026-15115
    "classlink-mwnbufxp": set(),  # MAL-2026-15116
    "classlink-nvrzsxgt": set(),  # MAL-2026-15117
    "classlink-oizqqihf": set(),  # MAL-2026-15118
    "classlink-ojxguxoq": set(),  # MAL-2026-15119
    "classlink-otcbsfdv": set(),  # MAL-2026-15120
    "classlink-ptiyrjb5": set(),  # MAL-2026-15121
    "classlink-pv0kxucy": set(),  # MAL-2026-15122
    "classlink-q2byg0v7": set(),  # MAL-2026-15123
    "classlink-qejnkyc6": set(),  # MAL-2026-15124
    "classlink-qeyyxkvk": set(),  # MAL-2026-15125
    "classlink-qfa5rsns": set(),  # MAL-2026-15126
    "classlink-qk0jdy82": set(),  # MAL-2026-15127
    "classlink-qph1z5ql": set(),  # MAL-2026-15128
    "classlink-qq62iaxh": set(),  # MAL-2026-15129
    "classlink-qrvgupip": set(),  # MAL-2026-15130
    "classlink-qu12nxtj": set(),  # MAL-2026-15131
    "classlink-qxwl5yxv": set(),  # MAL-2026-15132
    "classlink-qz9wfc7a": set(),  # MAL-2026-15133
    "classlink-r6iheodx": set(),  # MAL-2026-15134
    "classlink-r8folkn0": set(),  # MAL-2026-15135
    "classlink-rfaxqc0e": set(),  # MAL-2026-15136
    "classlink-rikzs2gv": set(),  # MAL-2026-15137
    "classlink-rlofqkrd": set(),  # MAL-2026-15138
    "classlink-rloj3ls4": set(),  # MAL-2026-15139
    "classlink-s6pridbx": set(),  # MAL-2026-15140
    "classlink-skdmdyhc": set(),  # MAL-2026-15141
    "classlink-sliybcp6": set(),  # MAL-2026-15142
    "classlink-sowghg1a": set(),  # MAL-2026-15143
    "classlink-t347plks": set(),  # MAL-2026-15144
    "classlink-t5p3uu1o": set(),  # MAL-2026-15145
    "classlink-tbq8gn8g": set(),  # MAL-2026-15146
    "classlink-tl646sho": set(),  # MAL-2026-15147
    "classlink-tw13ax4f": set(),  # MAL-2026-15148
    "classlink-tzib0ls7": set(),  # MAL-2026-15149
    "classlink-u1vqpl5z": set(),  # MAL-2026-15150
    "classlink-u2n0gqft": set(),  # MAL-2026-15151
    "classlink-u5hbagi9": set(),  # MAL-2026-15152
    "classlink-un5tiosp": set(),  # MAL-2026-15153
    "classlink-uudsbhsk": set(),  # MAL-2026-15154
    "classlink-uzimt3ve": set(),  # MAL-2026-15155
    "classlink-v56d6aoz": set(),  # MAL-2026-15156
    "classlink-vax4rqs7": set(),  # MAL-2026-15157
    "classlink-vfw41du0": set(),  # MAL-2026-15158
    "classlink-vhnhn5w0": set(),  # MAL-2026-15159
    "classlink-vmc7lcol": set(),  # MAL-2026-15160
    "classlink-vulrfg00": set(),  # MAL-2026-15161
    "classlink-vvp2o5z5": set(),  # MAL-2026-15162
    "classlink-vzhe1ult": set(),  # MAL-2026-15163
    "classlink-w17ma4im": set(),  # MAL-2026-15164
    "classlink-w1k2id3o": set(),  # MAL-2026-15165
    "classlink-w2aoc2w4": set(),  # MAL-2026-15166
    "classlink-w64ufvz0": set(),  # MAL-2026-15167
    "classlink-wdy28px7": set(),  # MAL-2026-15168
    "classlink-wktpjm2c": set(),  # MAL-2026-15169
    "classlink-wmjbe2so": set(),  # MAL-2026-15170
    "classlink-wvr5eoop": set(),  # MAL-2026-15171
    "classlink-x8inh2p5": set(),  # MAL-2026-15172
    "classlink-x9ht6k0r": set(),  # MAL-2026-15173
    "classlink-xfzjn3nt": set(),  # MAL-2026-15174
    "classlink-xjpjh7dw": set(),  # MAL-2026-15175
    "classlink-xkyruh8p": set(),  # MAL-2026-15176
    "classlink-xx8vtk2p": set(),  # MAL-2026-15177
    "classlink-xzg0d4g6": set(),  # MAL-2026-15178
    "classlink-y9cjgg19": set(),  # MAL-2026-15179
    "classlink-ye9hv1rp": set(),  # MAL-2026-15180
    "classlink-yeyuc75j": set(),  # MAL-2026-15181
    "classlink-yiqm3f92": set(),  # MAL-2026-15182
    "classlink-yo9y3rsf": set(),  # MAL-2026-15183
    "classlink-yqzh7rhx": set(),  # MAL-2026-15184
    "classlink-yxtuscfu": set(),  # MAL-2026-15185
    "classlink-z1owf3wo": set(),  # MAL-2026-15186
    "classlink-zgfuyabx": set(),  # MAL-2026-15187
    "classlink-zjrua8lg": set(),  # MAL-2026-15188
    "classlink-zwfxjs6w": set(),  # MAL-2026-15189
    # ─── desmos-graphing-* typosquat cluster (Aug 28 2026) ──────────────────────
    # 69 packages impersonating the Desmos graphing calculator JS library.
    # OSV MAL-2026-15190 .. MAL-2026-15258
    "desmos-graphing-0uw2z1ux": set(),  # MAL-2026-15190
    "desmos-graphing-1ocr3byl": set(),  # MAL-2026-15191
    "desmos-graphing-1yozr7ui": set(),  # MAL-2026-15192
    "desmos-graphing-24xpfja3": set(),  # MAL-2026-15193
    "desmos-graphing-2gmv774y": set(),  # MAL-2026-15194
    "desmos-graphing-31ajc1r0": set(),  # MAL-2026-15195
    "desmos-graphing-3ab6ghzv": set(),  # MAL-2026-15196
    "desmos-graphing-3sp71tdg": set(),  # MAL-2026-15197
    "desmos-graphing-3zydr56h": set(),  # MAL-2026-15198
    "desmos-graphing-4ctk1sud": set(),  # MAL-2026-15199
    "desmos-graphing-4qeytcit": set(),  # MAL-2026-15200
    "desmos-graphing-53uzgn30": set(),  # MAL-2026-15201
    "desmos-graphing-604nkzg5": set(),  # MAL-2026-15202
    "desmos-graphing-6qcpuz5a": set(),  # MAL-2026-15203
    "desmos-graphing-7l7x3nnm": set(),  # MAL-2026-15204
    "desmos-graphing-900fv2np": set(),  # MAL-2026-15205
    "desmos-graphing-9k03wszi": set(),  # MAL-2026-15206
    "desmos-graphing-9w6qhtr4": set(),  # MAL-2026-15207
    "desmos-graphing-9xaocjv2": set(),  # MAL-2026-15208
    "desmos-graphing-9yn0tiwq": set(),  # MAL-2026-15209
    "desmos-graphing-a4jd3pt5": set(),  # MAL-2026-15210
    "desmos-graphing-abi6w1hy": set(),  # MAL-2026-15211
    "desmos-graphing-b3cpqprr": set(),  # MAL-2026-15212
    "desmos-graphing-czo3yc51": set(),  # MAL-2026-15213
    "desmos-graphing-d2xe9mki": set(),  # MAL-2026-15214
    "desmos-graphing-dkkvj828": set(),  # MAL-2026-15215
    "desmos-graphing-ewtz5c63": set(),  # MAL-2026-15216
    "desmos-graphing-fgm5m2nw": set(),  # MAL-2026-15217
    "desmos-graphing-fmb6dd87": set(),  # MAL-2026-15218
    "desmos-graphing-fzdcyprv": set(),  # MAL-2026-15219
    "desmos-graphing-gv9cg140": set(),  # MAL-2026-15220
    "desmos-graphing-hl4k7wwb": set(),  # MAL-2026-15221
    "desmos-graphing-hufuztqe": set(),  # MAL-2026-15222
    "desmos-graphing-hycgbxao": set(),  # MAL-2026-15223
    "desmos-graphing-imo7mjh4": set(),  # MAL-2026-15224
    "desmos-graphing-j990vgop": set(),  # MAL-2026-15225
    "desmos-graphing-k3itlw7s": set(),  # MAL-2026-15226
    "desmos-graphing-kkzww3k1": set(),  # MAL-2026-15227
    "desmos-graphing-krktmhwo": set(),  # MAL-2026-15228
    "desmos-graphing-l5lxfme2": set(),  # MAL-2026-15229
    "desmos-graphing-l5t17nyz": set(),  # MAL-2026-15230
    "desmos-graphing-lxtc2yo8": set(),  # MAL-2026-15231
    "desmos-graphing-m3pf2jmu": set(),  # MAL-2026-15232
    "desmos-graphing-mh7e6p9s": set(),  # MAL-2026-15233
    "desmos-graphing-n4e8jp1j": set(),  # MAL-2026-15234
    "desmos-graphing-o15wcfen": set(),  # MAL-2026-15235
    "desmos-graphing-o9a1phdu": set(),  # MAL-2026-15236
    "desmos-graphing-pjl185sb": set(),  # MAL-2026-15237
    "desmos-graphing-pmvpzutq": set(),  # MAL-2026-15238
    "desmos-graphing-q31vb5mk": set(),  # MAL-2026-15239
    "desmos-graphing-qqmn0bic": set(),  # MAL-2026-15240
    "desmos-graphing-r4opzxol": set(),  # MAL-2026-15241
    "desmos-graphing-tmb49zcp": set(),  # MAL-2026-15242
    "desmos-graphing-ucnf033l": set(),  # MAL-2026-15243
    "desmos-graphing-upran64i": set(),  # MAL-2026-15244
    "desmos-graphing-v01eezwb": set(),  # MAL-2026-15245
    "desmos-graphing-vgq4y2qo": set(),  # MAL-2026-15246
    "desmos-graphing-vxtbz5de": set(),  # MAL-2026-15247
    "desmos-graphing-w7am2h4f": set(),  # MAL-2026-15248
    "desmos-graphing-xfd8ozbr": set(),  # MAL-2026-15249
    "desmos-graphing-xodr0yt2": set(),  # MAL-2026-15250
    "desmos-graphing-xs937ohf": set(),  # MAL-2026-15251
    "desmos-graphing-xsts58sz": set(),  # MAL-2026-15252
    "desmos-graphing-xuxzyx1y": set(),  # MAL-2026-15253
    "desmos-graphing-y1aqhk2u": set(),  # MAL-2026-15254
    "desmos-graphing-z0ky26le": set(),  # MAL-2026-15255
    "desmos-graphing-z79m5krq": set(),  # MAL-2026-15256
    "desmos-graphing-zlkxgzq0": set(),  # MAL-2026-15257
    "desmos-graphing-zqf21nqg": set(),  # MAL-2026-15258
    # ─── secure-test-browser-* dep-confusion cluster (Aug 28 2026) ──────────────
    # 215 packages mimicking secure browser / lockdown testing software scopes.
    # OSV MAL-2026-15260 .. MAL-2026-15474
    "secure-test-browser-03suqyfr": set(),  # MAL-2026-15260
    "secure-test-browser-0qyw2qfc": set(),  # MAL-2026-15261
    "secure-test-browser-12x7arc7": set(),  # MAL-2026-15262
    "secure-test-browser-14vzjjd9": set(),  # MAL-2026-15263
    "secure-test-browser-1pe78gsn": set(),  # MAL-2026-15264
    "secure-test-browser-1uomcu7q": set(),  # MAL-2026-15265
    "secure-test-browser-1yjarnvk": set(),  # MAL-2026-15266
    "secure-test-browser-21qgniz4": set(),  # MAL-2026-15267
    "secure-test-browser-232piklt": set(),  # MAL-2026-15268
    "secure-test-browser-24u4swst": set(),  # MAL-2026-15269
    "secure-test-browser-2agi8qru": set(),  # MAL-2026-15270
    "secure-test-browser-2amz9mh0": set(),  # MAL-2026-15271
    "secure-test-browser-2bt2axnr": set(),  # MAL-2026-15272
    "secure-test-browser-2edtawwr": set(),  # MAL-2026-15273
    "secure-test-browser-2o7y1f6z": set(),  # MAL-2026-15274
    "secure-test-browser-2qj2ykc2": set(),  # MAL-2026-15275
    "secure-test-browser-2r4fku8u": set(),  # MAL-2026-15276
    "secure-test-browser-359hvy0n": set(),  # MAL-2026-15277
    "secure-test-browser-3a1zujw0": set(),  # MAL-2026-15278
    "secure-test-browser-3bpg8lyh": set(),  # MAL-2026-15279
    "secure-test-browser-3kcnc7ob": set(),  # MAL-2026-15280
    "secure-test-browser-3nr8zugm": set(),  # MAL-2026-15281
    "secure-test-browser-3z3nxhmf": set(),  # MAL-2026-15282
    "secure-test-browser-3zgjufzb": set(),  # MAL-2026-15283
    "secure-test-browser-4eirlssh": set(),  # MAL-2026-15284
    "secure-test-browser-4h6ifluo": set(),  # MAL-2026-15285
    "secure-test-browser-4kquugfg": set(),  # MAL-2026-15286
    "secure-test-browser-4np1hfmm": set(),  # MAL-2026-15287
    "secure-test-browser-569xk6xr": set(),  # MAL-2026-15288
    "secure-test-browser-5debzirt": set(),  # MAL-2026-15289
    "secure-test-browser-5pst58e3": set(),  # MAL-2026-15290
    "secure-test-browser-5rybpaky": set(),  # MAL-2026-15291
    "secure-test-browser-6k7x6cae": set(),  # MAL-2026-15292
    "secure-test-browser-6ms5icgf": set(),  # MAL-2026-15293
    "secure-test-browser-6ofl6ajg": set(),  # MAL-2026-15294
    "secure-test-browser-6p3j19kb": set(),  # MAL-2026-15295
    "secure-test-browser-73oqds2r": set(),  # MAL-2026-15296
    "secure-test-browser-7djh0xc5": set(),  # MAL-2026-15297
    "secure-test-browser-7lp0evnc": set(),  # MAL-2026-15298
    "secure-test-browser-7s217blm": set(),  # MAL-2026-15299
    "secure-test-browser-7sktckna": set(),  # MAL-2026-15300
    "secure-test-browser-7v1llls8": set(),  # MAL-2026-15301
    "secure-test-browser-8juo05de": set(),  # MAL-2026-15302
    "secure-test-browser-8uhdfxxx": set(),  # MAL-2026-15303
    "secure-test-browser-95spzg4v": set(),  # MAL-2026-15304
    "secure-test-browser-9btl0kji": set(),  # MAL-2026-15305
    "secure-test-browser-9clb03cp": set(),  # MAL-2026-15306
    "secure-test-browser-9yod5p2o": set(),  # MAL-2026-15307
    "secure-test-browser-a2fosa7t": set(),  # MAL-2026-15308
    "secure-test-browser-a510xpj1": set(),  # MAL-2026-15309
    "secure-test-browser-agjzldze": set(),  # MAL-2026-15310
    "secure-test-browser-ajsfon9k": set(),  # MAL-2026-15311
    "secure-test-browser-ak37sb04": set(),  # MAL-2026-15312
    "secure-test-browser-ameyqv97": set(),  # MAL-2026-15313
    "secure-test-browser-avybg7z5": set(),  # MAL-2026-15314
    "secure-test-browser-aycygv9y": set(),  # MAL-2026-15315
    "secure-test-browser-bgsjanbj": set(),  # MAL-2026-15316
    "secure-test-browser-bph71q7u": set(),  # MAL-2026-15317
    "secure-test-browser-bv6h8voq": set(),  # MAL-2026-15318
    "secure-test-browser-c2df2vbx": set(),  # MAL-2026-15319
    "secure-test-browser-c5iac3qm": set(),  # MAL-2026-15320
    "secure-test-browser-c9b32eoo": set(),  # MAL-2026-15321
    "secure-test-browser-cezm8gko": set(),  # MAL-2026-15322
    "secure-test-browser-cnsorczp": set(),  # MAL-2026-15323
    "secure-test-browser-cqkfx0ip": set(),  # MAL-2026-15324
    "secure-test-browser-cxtwmz33": set(),  # MAL-2026-15325
    "secure-test-browser-cxu66pgp": set(),  # MAL-2026-15326
    "secure-test-browser-d2gc9pv0": set(),  # MAL-2026-15327
    "secure-test-browser-d75nv86j": set(),  # MAL-2026-15328
    "secure-test-browser-demni4rs": set(),  # MAL-2026-15329
    "secure-test-browser-df9e7gu5": set(),  # MAL-2026-15330
    "secure-test-browser-dixty5xk": set(),  # MAL-2026-15331
    "secure-test-browser-e96lialz": set(),  # MAL-2026-15332
    "secure-test-browser-eeaoqmwm": set(),  # MAL-2026-15333
    "secure-test-browser-egronan3": set(),  # MAL-2026-15334
    "secure-test-browser-emsn23qs": set(),  # MAL-2026-15335
    "secure-test-browser-ennvvg1y": set(),  # MAL-2026-15336
    "secure-test-browser-eudlabdg": set(),  # MAL-2026-15337
    "secure-test-browser-evbdrbjc": set(),  # MAL-2026-15338
    "secure-test-browser-ezbajpcd": set(),  # MAL-2026-15339
    "secure-test-browser-f0dzh835": set(),  # MAL-2026-15340
    "secure-test-browser-fb1mhg79": set(),  # MAL-2026-15341
    "secure-test-browser-fl9ivf6p": set(),  # MAL-2026-15342
    "secure-test-browser-fmbp7grs": set(),  # MAL-2026-15343
    "secure-test-browser-fndndxw5": set(),  # MAL-2026-15344
    "secure-test-browser-fnv4nx5h": set(),  # MAL-2026-15345
    "secure-test-browser-folaacmo": set(),  # MAL-2026-15346
    "secure-test-browser-g3ptxefk": set(),  # MAL-2026-15347
    "secure-test-browser-garuibak": set(),  # MAL-2026-15348
    "secure-test-browser-gbzem94w": set(),  # MAL-2026-15349
    "secure-test-browser-gcaoki0c": set(),  # MAL-2026-15350
    "secure-test-browser-ggbh6tng": set(),  # MAL-2026-15351
    "secure-test-browser-gth8e4pu": set(),  # MAL-2026-15352
    "secure-test-browser-h3vxp8o4": set(),  # MAL-2026-15353
    "secure-test-browser-hgqmatd7": set(),  # MAL-2026-15354
    "secure-test-browser-hu55z8cs": set(),  # MAL-2026-15355
    "secure-test-browser-hxytxlf0": set(),  # MAL-2026-15356
    "secure-test-browser-hy4udrjc": set(),  # MAL-2026-15357
    "secure-test-browser-hyowq23e": set(),  # MAL-2026-15358
    "secure-test-browser-i1f7ingl": set(),  # MAL-2026-15359
    "secure-test-browser-ifgfdw9m": set(),  # MAL-2026-15360
    "secure-test-browser-ig1r2teb": set(),  # MAL-2026-15361
    "secure-test-browser-inakf617": set(),  # MAL-2026-15362
    "secure-test-browser-iny4wirp": set(),  # MAL-2026-15363
    "secure-test-browser-ipq1kljp": set(),  # MAL-2026-15364
    "secure-test-browser-iy9s690g": set(),  # MAL-2026-15365
    "secure-test-browser-izxyw11l": set(),  # MAL-2026-15366
    "secure-test-browser-j60bbhhk": set(),  # MAL-2026-15367
    "secure-test-browser-j8hvv68h": set(),  # MAL-2026-15368
    "secure-test-browser-jau0u06f": set(),  # MAL-2026-15369
    "secure-test-browser-jiyi62e9": set(),  # MAL-2026-15370
    "secure-test-browser-jo8mjqxy": set(),  # MAL-2026-15371
    "secure-test-browser-jxcnispl": set(),  # MAL-2026-15372
    "secure-test-browser-k866lkga": set(),  # MAL-2026-15373
    "secure-test-browser-kdfmv2fs": set(),  # MAL-2026-15374
    "secure-test-browser-kec5c73l": set(),  # MAL-2026-15375
    "secure-test-browser-khflxpz7": set(),  # MAL-2026-15376
    "secure-test-browser-knr23kp7": set(),  # MAL-2026-15377
    "secure-test-browser-kp4pxm1b": set(),  # MAL-2026-15378
    "secure-test-browser-l5js3w12": set(),  # MAL-2026-15379
    "secure-test-browser-l78cgbss": set(),  # MAL-2026-15380
    "secure-test-browser-l8clykly": set(),  # MAL-2026-15381
    "secure-test-browser-l8ruvmc8": set(),  # MAL-2026-15382
    "secure-test-browser-lb0mxh9x": set(),  # MAL-2026-15383
    "secure-test-browser-lhf0jvj4": set(),  # MAL-2026-15384
    "secure-test-browser-ljzgz4nz": set(),  # MAL-2026-15385
    "secure-test-browser-lqc3kubo": set(),  # MAL-2026-15386
    "secure-test-browser-lu4lkn26": set(),  # MAL-2026-15387
    "secure-test-browser-lyoqpvaa": set(),  # MAL-2026-15388
    "secure-test-browser-m3g9i71p": set(),  # MAL-2026-15389
    "secure-test-browser-mcpdx7d2": set(),  # MAL-2026-15390
    "secure-test-browser-mevcta3b": set(),  # MAL-2026-15391
    "secure-test-browser-mg7243ns": set(),  # MAL-2026-15392
    "secure-test-browser-mulk8a4f": set(),  # MAL-2026-15393
    "secure-test-browser-n115xjja": set(),  # MAL-2026-15394
    "secure-test-browser-njhgckg2": set(),  # MAL-2026-15395
    "secure-test-browser-nqhmg3dh": set(),  # MAL-2026-15396
    "secure-test-browser-nu4lhvyb": set(),  # MAL-2026-15397
    "secure-test-browser-nuoqdbij": set(),  # MAL-2026-15398
    "secure-test-browser-nve3ll3e": set(),  # MAL-2026-15399
    "secure-test-browser-nxottb5j": set(),  # MAL-2026-15400
    "secure-test-browser-nyiv1der": set(),  # MAL-2026-15401
    "secure-test-browser-o5kevayg": set(),  # MAL-2026-15402
    "secure-test-browser-o6h9f5zo": set(),  # MAL-2026-15403
    "secure-test-browser-o87p0cmc": set(),  # MAL-2026-15404
    "secure-test-browser-ob8ovb9g": set(),  # MAL-2026-15405
    "secure-test-browser-opnxdwiy": set(),  # MAL-2026-15406
    "secure-test-browser-ouqvph7x": set(),  # MAL-2026-15407
    "secure-test-browser-p8ocawid": set(),  # MAL-2026-15408
    "secure-test-browser-p9cmgd4z": set(),  # MAL-2026-15409
    "secure-test-browser-pdsbchpf": set(),  # MAL-2026-15410
    "secure-test-browser-puq5o3yn": set(),  # MAL-2026-15411
    "secure-test-browser-pw5nxdep": set(),  # MAL-2026-15412
    "secure-test-browser-q0mgniqs": set(),  # MAL-2026-15413
    "secure-test-browser-q73s2nfh": set(),  # MAL-2026-15414
    "secure-test-browser-qq9c659k": set(),  # MAL-2026-15415
    "secure-test-browser-r270knja": set(),  # MAL-2026-15416
    "secure-test-browser-rccbxvt8": set(),  # MAL-2026-15417
    "secure-test-browser-rgoovozu": set(),  # MAL-2026-15418
    "secure-test-browser-rk9zd7ax": set(),  # MAL-2026-15419
    "secure-test-browser-rkt8e6l7": set(),  # MAL-2026-15420
    "secure-test-browser-rnvmkpow": set(),  # MAL-2026-15421
    "secure-test-browser-rryi25y4": set(),  # MAL-2026-15422
    "secure-test-browser-rwlrhorb": set(),  # MAL-2026-15423
    "secure-test-browser-s55u3gg6": set(),  # MAL-2026-15424
    "secure-test-browser-s78uli7l": set(),  # MAL-2026-15425
    "secure-test-browser-sbfd7kfx": set(),  # MAL-2026-15426
    "secure-test-browser-sq08t0fx": set(),  # MAL-2026-15427
    "secure-test-browser-srukyz7a": set(),  # MAL-2026-15428
    "secure-test-browser-t2i4qcoi": set(),  # MAL-2026-15429
    "secure-test-browser-t7a9jtay": set(),  # MAL-2026-15430
    "secure-test-browser-tiig2hex": set(),  # MAL-2026-15431
    "secure-test-browser-tln381c3": set(),  # MAL-2026-15432
    "secure-test-browser-tvzkbkqw": set(),  # MAL-2026-15433
    "secure-test-browser-ude9srx4": set(),  # MAL-2026-15434
    "secure-test-browser-uhdrf7v4": set(),  # MAL-2026-15435
    "secure-test-browser-ui1d892v": set(),  # MAL-2026-15436
    "secure-test-browser-ujmcmke5": set(),  # MAL-2026-15437
    "secure-test-browser-umhcq9s5": set(),  # MAL-2026-15438
    "secure-test-browser-uoi8lnoc": set(),  # MAL-2026-15439
    "secure-test-browser-us4fh8cc": set(),  # MAL-2026-15440
    "secure-test-browser-uwydfkra": set(),  # MAL-2026-15441
    "secure-test-browser-v1ll4zdk": set(),  # MAL-2026-15442
    "secure-test-browser-vd16ucb8": set(),  # MAL-2026-15443
    "secure-test-browser-vf21r2kh": set(),  # MAL-2026-15444
    "secure-test-browser-vixx0js1": set(),  # MAL-2026-15445
    "secure-test-browser-w3hnz5rz": set(),  # MAL-2026-15446
    "secure-test-browser-wctt1ocx": set(),  # MAL-2026-15447
    "secure-test-browser-wrbb4ntb": set(),  # MAL-2026-15448
    "secure-test-browser-x1a67wby": set(),  # MAL-2026-15449
    "secure-test-browser-x2k6m2im": set(),  # MAL-2026-15450
    "secure-test-browser-xcx2boj2": set(),  # MAL-2026-15451
    "secure-test-browser-xnhyannw": set(),  # MAL-2026-15452
    "secure-test-browser-xob8el1r": set(),  # MAL-2026-15453
    "secure-test-browser-xteou3v8": set(),  # MAL-2026-15454
    "secure-test-browser-xynt39lg": set(),  # MAL-2026-15455
    "secure-test-browser-y4yd7ndu": set(),  # MAL-2026-15456
    "secure-test-browser-y6f58a5o": set(),  # MAL-2026-15457
    "secure-test-browser-y76q2hho": set(),  # MAL-2026-15458
    "secure-test-browser-y85jryx0": set(),  # MAL-2026-15459
    "secure-test-browser-yp88o07w": set(),  # MAL-2026-15460
    "secure-test-browser-ypovha9r": set(),  # MAL-2026-15461
    "secure-test-browser-yyh15o1o": set(),  # MAL-2026-15462
    "secure-test-browser-z2j7z8ae": set(),  # MAL-2026-15463
    "secure-test-browser-z5stq4b0": set(),  # MAL-2026-15464
    "secure-test-browser-z6d4ruii": set(),  # MAL-2026-15465
    "secure-test-browser-z7dg2pww": set(),  # MAL-2026-15466
    "secure-test-browser-z7qi6ys2": set(),  # MAL-2026-15467
    "secure-test-browser-zbkz03dn": set(),  # MAL-2026-15468
    "secure-test-browser-zmhkw0mg": set(),  # MAL-2026-15469
    "secure-test-browser-znrlknt8": set(),  # MAL-2026-15470
    "secure-test-browser-zufp4hzx": set(),  # MAL-2026-15471
    "secure-test-browser-zvl6tsad": set(),  # MAL-2026-15472
    "secure-test-browser-zystijl5": set(),  # MAL-2026-15473
    "secure-test-browser-zyyxnta9": set(),  # MAL-2026-15474
    # ─── waxed-slightly-weathered-cut-copper-stairs-* Minecraft-theme cluster ──
    # 13 packages with Minecraft block-name style names; pure-malware typosquats.
    # OSV MAL-2026-15475 .. MAL-2026-15487
    "waxed-slightly-weathered-cut-copper-stairs-3xt74ldh": set(),  # MAL-2026-15475
    "waxed-slightly-weathered-cut-copper-stairs-7m6xp6w6": set(),  # MAL-2026-15476
    "waxed-slightly-weathered-cut-copper-stairs-ah9dirwo": set(),  # MAL-2026-15477
    "waxed-slightly-weathered-cut-copper-stairs-at3x6r0d": set(),  # MAL-2026-15478
    "waxed-slightly-weathered-cut-copper-stairs-cg2nzejt": set(),  # MAL-2026-15479
    "waxed-slightly-weathered-cut-copper-stairs-e7jj8nht": set(),  # MAL-2026-15480
    "waxed-slightly-weathered-cut-copper-stairs-f90oqwwm": set(),  # MAL-2026-15481
    "waxed-slightly-weathered-cut-copper-stairs-kg8byhpv": set(),  # MAL-2026-15482
    "waxed-slightly-weathered-cut-copper-stairs-q0j9jdqv": set(),  # MAL-2026-15483
    "waxed-slightly-weathered-cut-copper-stairs-rsq09wdf": set(),  # MAL-2026-15484
    "waxed-slightly-weathered-cut-copper-stairs-t8vrii0t": set(),  # MAL-2026-15485
    "waxed-slightly-weathered-cut-copper-stairs-tyhez6rf": set(),  # MAL-2026-15486
    "waxed-slightly-weathered-cut-copper-stairs-vxn9jfje": set(),  # MAL-2026-15487
    # ─── Aug 28 2026: misc pure-malware typosquats and credential stealers ──────
    "abcdefghijklnmopqrstuvwxyz": set(),  # MAL-2026-14999
    "bluebook-testing": set(),            # MAL-2026-15000
    "chilly-mountain": set(),             # MAL-2026-15001
    "estudiar-matematicas": set(),        # MAL-2026-15259
    "borsh-lite": set(),                  # MAL-2026-15489 — Web3/Solana Borsh codec typosquat
    "clmm-fee-audit": set(),              # MAL-2026-15490 — DeFi CLMM audit tool typosquat
    "eip712-lite": set(),                 # MAL-2026-15491 — EIP-712 signing typosquat (>=0 range)
    "mfa-js": set(),                      # MAL-2026-15492 — MFA library typosquat (>=0 range)
    "ozturk-mfa": set(),                  # MAL-2026-15493 — MFA utility typosquat
    "@fleetbo/svro": {"0.0.5", "0.0.6", "0.0.7", "0.0.9", "0.0.10", "0.0.11", "0.0.12", "0.0.13", "0.0.14", "0.0.15", "0.0.16", "0.0.17", "0.0.19", "0.0.20", "0.0.21", "0.0.22", "0.0.23", "0.0.24", "0.0.26", "0.0.27", "0.0.29", "0.0.30", "0.0.31", "0.0.32", "0.0.33", "0.0.34", "0.0.35", "0.0.37", "0.0.38", "0.0.39", "0.0.40", "0.0.42"},  # MAL-2026-14586
    "cacao1": {"9.9.9"},                  # MAL-2026-14591 — dep-confusion probe
    "@7nohe/openapi-react-query-codegen": {"0.0.0-365d4eb738d3146583431948d3ba6e27a32556be", "0.0.0-ec7876d6c917dad516ba69bbfafc948b834bf0ab", "0.5.4", "0.5.5", "1.6.3", "1.6.4", "2.2.1", "2.2.2", "3.0.3", "3.0.4"},  # MAL-2026-15494
    "@testrelic/playwright-analytics": {"2.13.0"},  # MAL-2026-15565
    # ─── grafeno-* dep-confusion cluster (Aug 28–29 2026): 13 packages ────────────
    # Attacker published packages impersonating Grafeno's private Brazilian
    # fintech API/SDK suite. OSV MAL-2026-15501..15522, MAL-2026-15571..15573
    "grafeno-api": {"1.0.0", "1.0.1"},      # MAL-2026-15501
    "grafeno-auth": {"1.0.0"},               # MAL-2026-15502
    "grafeno-billing": {"1.0.0"},            # MAL-2026-15571
    "grafeno-client": {"1.0.0"},             # MAL-2026-15503
    "grafeno-config": {"1.0.0"},             # MAL-2026-15504
    "grafeno-core": {"1.0.0", "1.0.1"},      # MAL-2026-15505
    "grafeno-logger": {"1.0.0", "1.0.1"},    # MAL-2026-15506
    "grafeno-payments": {"1.0.0"},           # MAL-2026-15572
    "grafeno-pix": {"1.0.0", "1.0.1"},       # MAL-2026-15507
    "grafeno-sdk": {"1.0.0", "1.0.1"},       # MAL-2026-15508
    "grafeno-utils": {"1.0.0"},               # MAL-2026-15509
    "grafeno-webhook": {"1.0.0"},            # MAL-2026-15573
    "grafeno-actions": {"999.0.0"},          # MAL-2026-15596
    "spc-grafeno": {"1.0.0"},                 # MAL-2026-15522
    # ─── dep-confusion 45.0.0 / 55.0.0 / 30.0.0 batch (Aug 28 2026): 30 pkgs ──
    # Internal-tool names published at inflated version numbers; classic dependency
    # confusion probes targeting Alibaba, Intuit, Atlassian, Ring, Mintel, etc.
    # OSV MAL-2026-15495..15546
    "alimama-minisite": {"45.0.0"},  # MAL-2026-15495
    "amplitude-experiment": {"55.0.0"},  # MAL-2026-15496
    "amplitude-react-native": {"45.0.0"},  # MAL-2026-15525
    "amplitude-session-replay": {"45.0.0"},  # MAL-2026-15497
    "analytics-web-client": {"30.0.0"},  # MAL-2026-15526
    "aura-instrumentation": {"45.0.0"},  # MAL-2026-15527
    "aws-blog": {"45.0.0", "45.0.1", "45.0.2"},  # MAL-2026-15498
    "axis-datagrid": {"45.0.0"},  # MAL-2026-15528
    "bui-react-10themes": {"45.0.0"},  # MAL-2026-15529
    "calcite-web": {"45.0.0"},  # MAL-2026-15499
    "confluence-create-content": {"30.0.0"},  # MAL-2026-15530
    "confluence-editor": {"30.0.0"},  # MAL-2026-15531
    "confluence-rest": {"30.0.0"},  # MAL-2026-15532
    "data-value": {"45.0.0"},  # MAL-2026-15533
    "firestore-lite": {"45.0.0"},  # MAL-2026-15534
    "framework-zero": {"45.0.0"},  # MAL-2026-15500
    "gridster-coords": {"45.0.0"},  # MAL-2026-15535
    "integration-amplitude": {"45.0.0"},  # MAL-2026-15510
    "intuit-authz": {"55.0.0"},  # MAL-2026-15511
    "ir-annuities-client-authentication-module": {"30.0.0"},  # MAL-2026-15536
    "jira-projects-backbone": {"45.0.0"},  # MAL-2026-15537
    "jsb-adapter": {"45.0.0"},  # MAL-2026-15512
    "katal-logger": {"45.0.0"},  # MAL-2026-15513
    "librastandardlib": {"45.0.0"},  # MAL-2026-15538
    "loading-performance-instrumentation": {"45.0.0"},  # MAL-2026-15539
    "mintel-taskbar": {"45.0.0"},  # MAL-2026-15514
    "mkt-ui-library": {"45.0.0"},  # MAL-2026-15540
    "npm-extension": {"45.0.0"},  # MAL-2026-15515
    "nx-app": {"9999.0.0-security-test"},  # MAL-2026-15516
    "oit-lib-oracle-util": {"45.0.0"},  # MAL-2026-15541
    "one-intuit-help-system-utils": {"45.0.0"},  # MAL-2026-15517
    "paper-password-input": {"45.0.0"},  # MAL-2026-15542
    "payments-ui-services": {"45.0.0"},  # MAL-2026-15518
    "prm-bundles": {"45.0.0"},  # MAL-2026-15543
    "qbo-ui-services": {"45.0.0"},  # MAL-2026-15519
    "ring-device-settings-library": {"30.0.0", "45.0.0"},  # MAL-2026-15520
    "search-reservation": {"55.0.0"},  # MAL-2026-15521
    "sentrykit": {"30.0.0"},  # MAL-2026-15544
    "sycm-vendors": {"55.0.0"},  # MAL-2026-15523
    "tabbables": {"45.0.0"},  # MAL-2026-15524
    "ux-metrics-client-interaction-subscriber": {"45.0.0"},  # MAL-2026-15545
    "vui-gateway": {"45.0.0"},  # MAL-2026-15546
    # ─── MFA-token stealer + misc npm malware batch (Aug 28 2026) ───────────────
    # 2FA/MFA secret-stealing packages and diverse credential-exfiltration tools.
    # OSV MAL-2026-15547..15564
    "2fa-secretkey": {"1.0.1", "1.0.2", "1.0.3", "1.0.4", "1.0.5", "1.0.6", "1.0.7"},  # MAL-2026-15547
    "2fasecretkey": {"1.1.2", "1.1.3", "1.1.4"},  # MAL-2026-15548
    "ckeditor5-ckbox": {"5.0.0"},  # MAL-2026-15549
    "common-array-token": {"1.0.0"},  # MAL-2026-15550
    "date-fns-sync": {"1.0.0"},  # MAL-2026-15551
    "discord-mfa": {"3.0.0", "3.0.1"},  # MAL-2026-15552
    "es6-migrator": {"1.0.1"},  # MAL-2026-15553
    "eth-pino": {"2.0.3"},  # MAL-2026-15554
    "js-array-tokens": {"1.0.2"},  # MAL-2026-15555
    "js-tokens-array": {"1.0.0", "1.1.1"},  # MAL-2026-15556
    "mfacord": {"1.0.2", "1.0.3"},  # MAL-2026-15557
    "mfakit": {"1.4.0"},  # MAL-2026-15558
    "secretkey2fa": {"1.0.1"},  # MAL-2026-15559
    "supersignaturenature": {"1.0.5", "1.0.6"},  # MAL-2026-15560
    "techportal": {"4.0.10"},  # MAL-2026-15561
    "test-in-one": {"1.0.0"},  # MAL-2026-15562
    "vitest-chalk-pro": {"10.0.7"},  # MAL-2026-15563
    "vs-modules": {"1.2.2"},  # MAL-2026-15564
    # ─── misc npm typosquat/malware batch (Aug 29 2026) ──────────────────────────
    # Four new packages with ranges: introduced 0 (any version malicious).
    # OSV MAL-2026-15567..15570
    "htps-provider": set(),           # MAL-2026-15567, GHSA-gcqr-3vw3-7fqm
    "manager-thedate": set(),         # MAL-2026-15568, GHSA-3rww-v3p8-fw9p
    "nuvyra-marketplace-sdk": set(),  # MAL-2026-15569, GHSA-rq2p-956p-32h6
    "node-net-pool": set(),           # MAL-2026-15570, GHSA-vm9g-mp9v-6q5p
    # ─── Autobahn/DB dep-confusion probes (Aug 30 2026) ──────────────────────────
    # Two packages impersonating Deutsche Bank's internal autobahn tooling at
    # implausibly high version numbers — classic dep-confusion probes.
    # OSV MAL-2026-15589, MAL-2026-15590
    "autobahn-electron-probe": {"99.99.1"},                       # MAL-2026-15589
    "com.db.autobahn.notification-center-electron": {"88.88.2"},  # MAL-2026-15590
    # ─── Web3 / DeFi malicious tools (Aug 30 2026): 8 packages ──────────────────
    # Credential-exfiltrating packages targeting Web3/DeFi workflows:
    # Fuel Network SDK impostors, schema/verify tools for ethers & viem,
    # a random cre-setup dropper, and an npx OOB probe.
    # OSV MAL-2026-15591..15599 (excl. 15596 grafeno-actions, added above)
    "cre-setup": {"1.0.0"},           # MAL-2026-15591
    "fuels-core": {"1.0.0"},          # MAL-2026-15592 — Fuel Network SDK impostor
    "fuels-typegen": {"1.0.0"},       # MAL-2026-15593 — Fuel typegen impostor
    "generate-schema-ethers": {"1.0.0"},  # MAL-2026-15594
    "generate-schema-viem": {"1.0.0"},    # MAL-2026-15595
    "npx-oob-package": {"1.0.2"},         # MAL-2026-15597 — OOB exfil probe
    "verify-contract-ethers": {"1.0.0"},  # MAL-2026-15598
    "verify-contract-viem": {"1.0.0"},    # MAL-2026-15599
    # ─── misc npm malware batch (Aug 30–31 2026): 15 pure-malware typosquats ────
    # GHSA-sourced, all ranges: introduced 0 — any installed version is malicious.
    # Includes an @fidzzhost/baileys fake (targets WhatsApp bot devs), a
    # @lucideproxy/svg Lucide icon proxy, ESLint/Prettier and Redis tooling
    # typosquats, h-codex cluster, cloud-exfiltrator cluster, and misc.
    # OSV MAL-2026-15574..15576, MAL-2026-15579..15588, MAL-2026-15600..15602
    "gclassroom": set(),                  # MAL-2026-15574, GHSA-6c25-pq89-3m9w
    "opiumbest": set(),                   # MAL-2026-15575, GHSA-pwqr-5gcr-9rc4
    "quesoeducation": set(),              # MAL-2026-15576, GHSA-mm9m-8q5p-fxwx
    "@fidzzhost/baileys": set(),          # MAL-2026-15579, GHSA-vc2v-c8j2-qxg9
    "brat-codex": set(),                  # MAL-2026-15580, GHSA-63wg-22hx-h5q4
    "cloudfcrxz": set(),                  # MAL-2026-15581, GHSA-p375-pmrj-262v
    "cloufcrxz": set(),                   # MAL-2026-15582, GHSA-gxpc-36pf-vcrw
    "h2-codex": set(),                    # MAL-2026-15583, GHSA-8h78-gfj3-qrp2
    "h3-codex": set(),                    # MAL-2026-15584, GHSA-w6m7-6jhr-mfjc
    "h3client": set(),                    # MAL-2026-15585, GHSA-89vf-5xgx-fhq7
    "originaldevelopmentstelemetry": set(),  # MAL-2026-15586, GHSA-m8hq-jrvf-g8xm
    "real-browser-plus": set(),           # MAL-2026-15587, GHSA-ffvr-gx62-j45m
    "@lucideproxy/svg": set(),            # MAL-2026-15600, GHSA-6j97-93gg-j7r8
    "eslint-prettier-js": set(),          # MAL-2026-15601, GHSA-fp43-fcrg-6w93
    "redis-cookie-server": set(),         # MAL-2026-15602, GHSA-jgx3-v64x-v2w5
    # ─── Sep 1 2026: @yane88 scope — 19 packages, Windows-tool repackagers ────────
    # Attacker-controlled @yane88 scope publishing repackaged Windows binaries
    # (Listary, Reqable, ripgrep, workbuddy, JetBrains IDEs) that exfiltrate
    # credentials. All versions malicious (introduced: 0).
    # OSV MAL-2026-15649..15667
    "@yane88/hexhub-client": set(),      # MAL-2026-15649
    "@yane88/idea-2026.2": set(),        # MAL-2026-15650
    "@yane88/idea-2026.2-01": set(),     # MAL-2026-15651
    "@yane88/idea-2026.2-02": set(),     # MAL-2026-15652
    "@yane88/idea-2026.2-03": set(),     # MAL-2026-15653
    "@yane88/idea-2026.2-04": set(),     # MAL-2026-15654
    "@yane88/idea-2026.2-05": set(),     # MAL-2026-15655
    "@yane88/idea-2026.2-06": set(),     # MAL-2026-15656
    "@yane88/listary": set(),            # MAL-2026-15657
    "@yane88/listary-01": set(),         # MAL-2026-15658
    "@yane88/listary-02": set(),         # MAL-2026-15659
    "@yane88/ripgrep-win": set(),        # MAL-2026-15660
    "@yane88/term-reqable": set(),       # MAL-2026-15661
    "@yane88/term-reqable-01": set(),    # MAL-2026-15662
    "@yane88/term-reqable-02": set(),    # MAL-2026-15663
    "@yane88/workbuddy": set(),          # MAL-2026-15664
    "@yane88/workbuddy-01": set(),       # MAL-2026-15665
    "@yane88/workbuddy-02": set(),       # MAL-2026-15666
    "@yane88/workbuddy-03": set(),       # MAL-2026-15667
    # ─── Sep 1 2026: @baipiaodajun scope — 5 packages, SSH/proxy malware ──────────
    # Attacker-controlled scope publishing reverse-proxy and SSH-key harvesters.
    # All versions malicious. OSV MAL-2026-15639..15643
    "@baipiaodajun/mcbot": set(),           # MAL-2026-15639
    "@baipiaodajun/mcbots": set(),          # MAL-2026-15640
    "@baipiaodajun/npmsshx": set(),         # MAL-2026-15641
    "@baipiaodajun/podman_env": set(),      # MAL-2026-15642
    "@baipiaodajun/reverseproxy-fm": set(), # MAL-2026-15643
    # ─── Sep 1 2026: misc single-scope pure-malware entries ──────────────────────
    # @pipi596888/ccursor — cursor IDE impersonator. MAL-2026-15644
    "@pipi596888/ccursor": set(),
    # @fdr-mar/promos-types — attacker scope, all versions malicious. MAL-2026-15648
    "@fdr-mar/promos-types": set(),
    # @worrisome/reutil — attacker scope, all versions malicious. MAL-2026-15604
    "@worrisome/reutil": set(),
    # @testrelic/appium-analytics — fake Appium analytics node. MAL-2026-15647
    "@testrelic/appium-analytics": {"1.1.1-next.88"},
    # ─── Sep 1 2026: random-string cluster — 16 pure-malware typosquats ───────────
    # Cluster of obfuscated-name packages with no legitimate use; all carry
    # postinstall dropper payloads. OSV MAL-2026-15605..15620
    "m2fcsfyjkuxb": set(),    # MAL-2026-15605
    "m3fdfocdoewn": set(),    # MAL-2026-15606
    "mbxcnsuwgs1": set(),     # MAL-2026-15607
    "mjsdqwocvn": set(),      # MAL-2026-15608
    "mn2adskhweox": set(),    # MAL-2026-15609
    "mn3sadkoiewu": set(),    # MAL-2026-15610
    "mn4xcouzvhus": set(),    # MAL-2026-15611
    "mndsxcusiwlk1": set(),   # MAL-2026-15612
    "mobiwaefhxc3": set(),    # MAL-2026-15613
    "ndmfguyhoxc3": set(),    # MAL-2026-15614
    "ndmushdkeqe": set(),     # MAL-2026-15615
    "ndmxchdjxn2": set(),     # MAL-2026-15616
    "skxcmwuncbg2": set(),    # MAL-2026-15617
    "tesgfvbncsdbcv": set(),  # MAL-2026-15618
    "testdgdbcsd": set(),     # MAL-2026-15619
    "vxhjkseuiaqkb": set(),   # MAL-2026-15620
    # ─── Sep 1 2026: misc pure-malware typosquats ─────────────────────────────────
    # Assorted single-package pure-malware entries; all introduced: 0.
    "nitroping": set(),             # MAL-2025-191134 — data-exfil tool
    "acme-diagnostics": set(),      # MAL-2025-6396 — ACME typosquat
    "core_main": set(),             # MAL-2026-15668
    "kendo-angular-window": set(),  # MAL-2026-15669 — Kendo UI typosquat
    "kisama-js": set(),             # MAL-2026-15645
    "matrix-by-lmx": set(),        # MAL-2026-15670
    "pig-ui-first": set(),          # MAL-2026-15646
    "quartz-core": set(),           # MAL-2026-15671
    "randomunblockedwebsite": set(), # MAL-2026-15672
    "selfsigned-certificate": set(), # MAL-2026-15623
    # ─── Sep 1 2026: MFA campaign extensions (3 packages) ─────────────────────────
    # Additional packages from the same actor behind mfacord/mfakit/mfa-js.
    # OSV MAL-2026-15628..15630
    "mfa.io": {"1.0.0", "1.0.1"},     # MAL-2026-15628
    "mfaatest": {"1.0.0"},            # MAL-2026-15629
    "mfafix": {"1.1.0", "1.1.1"},     # MAL-2026-15630
    # ─── Sep 1 2026: grafeno/SPC campaign extensions (2 packages) ─────────────────
    # Two more SPC login packages tied to the grafeno dep-confusion campaign.
    # OSV MAL-2026-15622, MAL-2026-15633
    "spc_login": {"1.0.0"},          # MAL-2026-15622
    "spc-grafeno-login": {"1.0.0"},  # MAL-2026-15633
    # ─── Sep 1 2026: Fuel Network SDK impostors — fuels-forc (1 package) ──────────
    # Additional Fuel Network SDK impostor; companion to fuels-core/fuels-typegen.
    "fuels-forc": {"1.0.0"},         # MAL-2026-15626
    # ─── Sep 1 2026: misc versioned malware batch (9 packages) ───────────────────
    # Miscellaneous packages with pinned malicious versions from the Aug 31–Sep 1 sweep.
    "claude-channel-telegram": {"9.9.9"},                          # MAL-2026-15624 — implausible version probe
    "evilpostinstall": {"0.2.0", "0.6.0", "49.13.4074225", "4127000.0.1"},  # MAL-2026-15625
    "gas-monitor": {"1.1.0"},                                      # MAL-2026-15621
    "hyperliquid-composer": {"1.0.0"},                             # MAL-2026-15627
    "nextjsupdater": {"1.2.1"},                                    # MAL-2026-15631
    "node-request-utils": {"1.0.0"},                               # MAL-2026-15632
    "tailwind-minanimated": {"2.3.7"},                             # MAL-2026-15634
    "tailwind-modernanimation": {"2.3.8"},                         # MAL-2026-15635
    "tailwindcss-forms-style": {"0.1.2"},                          # MAL-2026-15636
    "test__123q1": {"3.2.4", "4.3.5"},                             # MAL-2026-15637
    "test__123q2": {"2.1.1"},                                      # MAL-2026-15638
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
    # @wethenorth12 crypto-wallet-drainer scope (Aug 5 2026) — 23 packages pinned above;
    # entire attacker-controlled scope; scope catches any undisclosed additional packages
    "@wethenorth12/",
    # @zzzcrypto crypto-stealer scope (Aug 5 2026) — 5 packages pinned above;
    # companion scope to @wethenorth12
    "@zzzcrypto/",
    # @cryptosrvc exchange SDK typosquat scope (Aug 5 2026) — 3 packages pinned above
    "@cryptosrvc/",
    # @shiftmarkets exchange SDK typosquat scope (Aug 5 2026) — 3 packages pinned above
    "@shiftmarkets/",
    # @zahlen checkout-flow malware scope (Aug 5–6 2026) — 2 packages pinned above
    "@zahlen/",
    # @copilot-mcp MCP server impersonator scope (Aug 5 2026) — 1 package pinned above
    "@copilot-mcp/",
    # @ai-agent-node scope (July 30 2026) — 3 packages pinned above;
    # scope catches any undisclosed additional @ai-agent-node packages
    "@ai-agent-node/",
    # @ai-plus scope (July 30 2026) — 2 packages pinned above
    "@ai-plus/",
    # @peptide-unit scope (July 30 2026) — 2 packages pinned above
    "@peptide-unit/",
    # @dotconf-pro scope (July 31 2026) — 2 packages pinned above
    "@dotconf-pro/",
    # @ethers-sdk scope (July 31 2026) — 2 crypto-targeting packages pinned above
    "@ethers-sdk/",
    # @grua scope (July 31 2026) — 2 packages pinned above
    "@grua/",
    # @nordea-web dep-confusion scope (July 31 2026) — 2 packages pinned above
    "@nordea-web/",
    # @patternfly-4 dep-confusion scope (July 31 2026) — 4 packages pinned above
    "@patternfly-4/",
    # @pumpdot-fun scope (July 31 2026) — 2 crypto packages pinned above
    "@pumpdot-fun/",
    # @sourav_chanduka scope (July 31 2026) — 3 packages pinned above
    "@sourav_chanduka/",
    # keyv/cacheable npm account compromise (Aug 4–5 2026) — large scopes with individual
    # packages pinned above in NPM_BAD; scope entries catch any additional unreported packages
    "@keyv/",           # 19 packages at 6.0.0 pinned above
    "@nebula.js/",      # 22 Qlik visualization packages pinned above
    "@onereach/",       # 78 OneReach.ai packages pinned above
    "@ornikar/",        # 42 Ornikar packages pinned above
    "@or-sdk/",         # 74 OneReach.ai SDK packages pinned above
    "@qlik/",           # 28 Qlik Analytics packages pinned above
    "@servicetitan/",   # 141 ServiceTitan packages pinned above
    "@umacloud/",       # 8 UmaCloud packages pinned above
    "@zzzgenesis00/",   # 14 crypto-wallet stealer packages pinned above
    # @bikli publisher-account scope (Aug 12 2026) — 5 packages pinned above;
    # entire attacker-controlled scope; scope catches any undisclosed additional packages
    "@bikli/",
    # @noxzacode scope (Aug 12 2026) — 2 packages pinned above
    "@noxzacode/",
    # @years17-20 n8n malicious-community-node scopes (Aug 12 2026) — 78 packages pinned above;
    # four attacker-controlled scopes publishing fake n8n workflow-automation nodes
    "@years17/",
    "@years18/",
    "@years19/",
    "@years20/",
    # fake @openzeppelin-4/5 scopes (Aug 12 2026) — 2 packages pinned above;
    # scope catches any further fake OpenZeppelin versions
    "@openzeppelin-4/",
    "@openzeppelin-5/",
    # @assetshop dep-confusion scope (Aug 12 2026) — 1 package pinned above
    "@assetshop/",
    # @hzero-front-ui dep-confusion scope (Aug 13 2026) — 5 packages pinned above
    "@hzero-front-ui/",
    # @khaznatech dep-confusion scope (Aug 13 2026) — 3 packages pinned above
    "@khaznatech/",
    # @workoscalif/@workoscalifant sudoku-themed malware scopes (Aug 14 2026) — attacker-controlled;
    # packages pinned above; scope entries catch any undisclosed additional packages
    "@workoscalif/",
    "@workoscalifant/",
    # @ferudionz malware scope (Aug 14 2026) — 2 packages pinned above
    "@ferudionz/",
    # Aug 17–18 2026 new attacker-controlled scopes
    # @withgoogle/ impersonates Google; @withgoogle/stitch-sdk pinned above
    "@withgoogle/",
    # @zynkit/ attacker scope — jwtbytes + probe pinned above
    "@zynkit/",
    # @junofficial/ WhatsApp/userbot actor scope — baileys + userbot packages pinned above
    "@junofficial/",
    # @peptideventure/ attacker scope — 2 packages pinned above
    "@peptideventure/",
    # @siwatfa/ attacker scope — yorn pinned above
    "@siwatfa/",
    # @zizie071/ attacker scope — libsignal-node impersonator pinned above
    "@zizie071/",
    # @ai-vertical/ attacker scope — ai-agent pinned above
    "@ai-vertical/",
    # @vyzensockets/ WhatsApp Baileys typosquat scope — baileys pinned above
    "@vyzensockets/",
    # Aug 18-19 2026 new attacker-controlled scopes
    # @sarex-team/ dep-confusion scope — sdk-js/translator/ui-kit/viewer pinned above
    "@sarex-team/",
    # @mohamed_nowisar/ dep-confusion probe scope — canary-test + token3-check pinned above
    "@mohamed_nowisar/",
    # @wizloft/ obfuscated-dropper scope (Aug 19 2026) — 5 harness packages pinned above;
    # scope catches any undisclosed additional @wizloft packages
    "@wizloft/",
    # @postman-cse dep-confusion scope (Aug 22 + Aug 28 2026) — okta-aio-linux-arm64 and
    # okta-aio-darwin-arm64 pinned above; scope catches any further @postman-cse packages
    "@postman-cse/",
    # Aug 26–27 2026 new attacker-controlled scopes
    # @fongsidev/ WhatsApp scraper/stealer scope — scraper pinned above
    "@fongsidev/",
    # @lordmega/ WhatsApp Baileys impersonator scope — baileys pinned above
    "@lordmega/",
    # @hd-team dep-confusion scope (Aug 27 2026) — 8 packages pinned above;
    # scope catches any undisclosed additional @hd-team packages
    "@hd-team/",
    # @yane88 Windows-tool repackager scope (Sep 1 2026) — 19 packages pinned above;
    # scope catches any undisclosed additional @yane88 packages
    "@yane88/",
    # @baipiaodajun SSH/proxy malware scope (Sep 1 2026) — 5 packages pinned above
    "@baipiaodajun/",
    # @pipi596888 attacker scope (Sep 1 2026) — ccursor pinned above
    "@pipi596888/",
    # @fdr-mar attacker scope (Sep 1 2026) — promos-types pinned above
    "@fdr-mar/",
    # @worrisome attacker scope (Sep 1 2026) — reutil pinned above
    "@worrisome/",
    # @testrelic fake Appium scope (Sep 1 2026) — appium-analytics pinned above
    "@testrelic/",
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
    # Aug 20-21 2026: droundy account compromise + coordinated build-time payload campaign
    # Attacker compromised the 'droundy' (David Roundy) crates.io maintainer account and
    # published malicious versions of three popular legitimate crates (arrayref, internment,
    # append-only-vec) adding a dependency on the malicious dropper crate proc-macro1
    # (typosquat of proc-macro2). Pure-malware support crates (aovine, arone, aronenao,
    # proc-macro-en, tinymember) were also published as part of the same campaign.
    # Sources: OSV MAL-2026-14332 through MAL-2026-14340
    # Legitimate crates with poisoned specific versions — pin exactly:
    "arrayref": {"0.3.10"},                                                      # MAL-2026-14336
    "internment": {"0.8.7"},                                                     # MAL-2026-14337
    "append-only-vec": {"0.1.9"},                                                # MAL-2026-14333
    # Pure-malware crates (any version is malicious):
    "proc-macro1": set(),                                                        # MAL-2026-14338 (ANY)
    "proc-macro-en": set(),                                                      # MAL-2026-14339 (ANY)
    "aovine": set(),                                                             # MAL-2026-14332 (ANY)
    "arone": set(),                                                              # MAL-2026-14334 (ANY)
    "aronenao": set(),                                                           # MAL-2026-14335 (ANY)
    "tinymember": set(),                                                         # MAL-2026-14340 (ANY)
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
