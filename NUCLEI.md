# Nuclei & Web Scanning: Practical Reference & Cheat Sheet

A working reference for nuclei and the broader web reconnaissance toolchain. Nuclei is the current standard for templated vulnerability scanning fast, community-maintained, and the closest thing the industry has to a shared language for "check for this specific thing." This doc covers nuclei itself, the supporting tools you'll run alongside it (httpx, katana, subfinder, ffuf, etc.), target-specific workflows, and honest notes on what nuclei is and isn't good for.

---

## Table of Contents

1. [What Nuclei Actually Is](#what-nuclei-actually-is)
2. [The Web Recon Toolchain](#the-web-recon-toolchain)
3. [Nuclei Core Usage](#nuclei-core-usage)
4. [Template System](#template-system)
5. [Target-Specific Workflows](#target-specific-workflows)
   - [External Attack Surface](#external-attack-surface)
   - [Single Web Application](#single-web-application)
   - [API Endpoints](#api-endpoints)
   - [Internal Web Services](#internal-web-services)
   - [CMS Targets](#cms-targets)
   - [Cloud & SaaS](#cloud--saas)
   - [IoT Web Interfaces](#iot-web-interfaces)
6. [Writing Custom Templates](#writing-custom-templates)
7. [Cheat Sheet](#cheat-sheet)
8. [Supporting Tools Cheat Sheet](#supporting-tools-cheat-sheet)
9. [Practical Notes](#practical-notes)

---

## What Nuclei Actually Is

Nuclei is a Go-based scanner that runs YAML templates describing specific checks "send this request, look for this in the response, report it as this severity." The value isn't the scanner itself (it's a fairly simple HTTP client with matchers) but the **template repository**: `projectdiscovery/nuclei-templates` on GitHub, which at any given moment contains several thousand community-maintained checks covering CVEs, misconfigurations, exposed panels, default credentials, tech detection, and more.

Key mental model: nuclei is **pattern-matching at scale**. It's the best tool in the world for "does this known issue exist on any of these 10,000 hosts" and the worst tool in the world for "find the novel vulnerability in this one application." It replaces the `http-vuln-*` and `http-enum` parts of nmap NSE entirely, does them faster, and has orders of magnitude more coverage but it doesn't crawl, doesn't understand application state, and doesn't do anything dynamic. It sends templates and matches responses.

Where nuclei fits in the pipeline: **after** discovery (you need URLs/hosts) and **alongside** manual testing (it finds known issues, you find the unknowns). A typical flow is `subfinder → httpx → katana → nuclei` with manual Burp work layered on top.

---

## The Web Recon Toolchain

Nuclei is part of the ProjectDiscovery ecosystem. These tools are designed to pipe into each other and share output formats:

| Tool | Role |
|---|---|
| `subfinder` | Passive subdomain enumeration |
| `dnsx` | DNS resolution + record queries |
| `naabu` | Fast TCP port scanner (nmap-lite in Go) |
| `httpx` | HTTP probe / tech detection / screenshot |
| `katana` | Headless web crawler |
| `nuclei` | Template-based vuln scanning |
| `notify` | Pipe findings to Slack/Discord/Telegram |
| `interactsh` | OOB interaction server (for blind injection detection) |
| `uncover` | Query Shodan/Censys/Fofa from CLI |
| `cdncheck` | Identify CDN-hosted targets |
| `tlsx` | TLS inspection |

Non-PD tools you'll use alongside:

| Tool | Role |
|---|---|
| `amass` | Active + passive subdomain enum (more thorough, slower) |
| `ffuf` | Directory/parameter fuzzing |
| `feroxbuster` | Recursive content discovery |
| `gobuster` | Alternative content/subdomain brute |
| `gau` / `waybackurls` | Historical URLs from Wayback/CommonCrawl |
| `gf` | Pattern-based URL filtering |
| `qsreplace` | Query string manipulation for fuzz lists |
| `hakrawler` | Alternative crawler |
| `gospider` | Another crawler (JS-aware) |
| `waymore` | Aggressive historical URL mining |
| `arjun` | HTTP parameter discovery |
| `paramspider` | Parameter mining from Wayback |

The canonical external recon pipeline:
```bash
subfinder -d example.com -all -silent \
  | dnsx -silent -a -resp \
  | httpx -silent -title -tech-detect -status-code \
  | tee live_hosts.txt
```

---

## Nuclei Core Usage

### Installation & Updates

```bash
# Install (Go)
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Update binary and templates
nuclei -update
nuclei -update-templates

# Template location (default)
ls ~/.local/nuclei-templates/
```

Templates update frequently. Always `nuclei -ut` before a serious scan the delta between last week's templates and today's might include the check you need.

### Basic Invocation

```bash
# Single target, all templates
nuclei -u https://example.com

# List of targets
nuclei -l targets.txt

# Pipe from httpx
httpx -l hosts.txt -silent | nuclei

# Specific severity only
nuclei -l targets.txt -severity critical,high

# Specific tags
nuclei -l targets.txt -tags cve,oast

# Specific template or directory
nuclei -l targets.txt -t http/cves/2023/
nuclei -l targets.txt -t http/cves/2023/CVE-2023-1234.yaml

# Exclude noisy templates
nuclei -l targets.txt -etags fuzz,dos,intrusive

# Rate limiting
nuclei -l targets.txt -rl 150 -c 25 -bs 25
```

### Output Formats

```bash
# JSON lines (for parsing)
nuclei -l targets.txt -jsonl -o results.jsonl

# Markdown export (great for reports)
nuclei -l targets.txt -me ./report/

# SARIF (for GitHub code scanning integration)
nuclei -l targets.txt -sarif-export results.sarif

# Silent mode (findings only, no banner/progress)
nuclei -l targets.txt -silent

# Only show matched lines
nuclei -l targets.txt -nc -silent    # no color, silent
```

### OOB / Interactsh

For blind vulnerabilities (blind SSRF, blind XXE, blind RCE, log4shell-style callbacks), nuclei integrates with interactsh a public OOB server that catches DNS/HTTP callbacks:

```bash
# Use default public interactsh server
nuclei -l targets.txt -tags oast

# Use your own interactsh server (recommended for real engagements)
nuclei -l targets.txt -tags oast -iserver https://your-interactsh.example.com

# Self-host interactsh
interactsh-server -domain your-interactsh.example.com
```

Self-hosting interactsh is the right move for serious engagements the public server is shared, results can leak, and some targets will block requests to the public interactsh domains.

---

## Template System

Templates live under category directories:

```
~/.local/nuclei-templates/
├── http/
│   ├── cves/          # CVE-specific checks (by year)
│   ├── cnvd/          # Chinese CNVD advisories
│   ├── default-logins/ # Default credential checks
│   ├── exposures/     # Exposed config, tokens, files
│   ├── exposed-panels/ # Admin panels
│   ├── fuzzing/       # Fuzzing templates
│   ├── iot/           # IoT-specific
│   ├── misconfiguration/ # General misconfigs
│   ├── miscellaneous/
│   ├── takeovers/     # Subdomain takeover
│   ├── technologies/  # Tech fingerprinting
│   ├── token-spray/   # Token validation
│   ├── vulnerabilities/ # Non-CVE vulns
│   └── ...
├── dns/               # DNS checks
├── file/              # File content matching (for local scanning)
├── network/           # Raw TCP/network protocols
├── ssl/               # TLS checks
├── workflows/         # Multi-step template chains
├── headless/          # Browser-based templates
└── code/              # Code execution templates
```

### Key Tags

Templates are tagged for selection. The most useful:

| Tag | What it selects |
|---|---|
| `cve` | All CVE-backed templates |
| `cve2023`, `cve2024` | CVEs by year |
| `oast` | Templates using OOB (interactsh) |
| `tech` | Technology fingerprinting |
| `panel` | Exposed admin panels |
| `exposure` | Exposed files/config/tokens |
| `misconfig` | Misconfigurations |
| `default-login` | Default credential checks |
| `takeover` | Subdomain takeover checks |
| `rce` | Remote code execution |
| `sqli` | SQL injection |
| `xss` | Cross-site scripting |
| `lfi` | Local file inclusion |
| `ssrf` | Server-side request forgery |
| `injection` | Various injection classes |
| `auth-bypass` | Authentication bypasses |
| `intrusive` | Potentially dangerous / noisy |
| `dos` | Denial of service (don't run on prod) |
| `fuzz` | Fuzzing-based checks (slower, noisier) |
| `wordpress`, `drupal`, `joomla` | CMS-specific |
| `k8s`, `docker`, `aws`, `gcp`, `azure` | Cloud/container |

### Selection Examples

```bash
# CVEs from last two years only, high+critical
nuclei -l targets.txt -tags cve2024,cve2025 -severity high,critical

# Everything except potentially destructive
nuclei -l targets.txt -etags intrusive,dos,fuzz

# Just tech fingerprinting (safe, fast, informative)
nuclei -l targets.txt -tags tech -silent

# Exposed panels + default logins (classic initial access)
nuclei -l targets.txt -tags panel,default-login

# Specific vulnerability class across all templates
nuclei -l targets.txt -tags ssrf,rce -severity critical

# Author filter (e.g. templates by pdteam)
nuclei -l targets.txt -author pdteam

# Combine inclusion + exclusion + severity + rate
nuclei -l targets.txt \
  -tags cve,panel,exposure \
  -etags intrusive,dos \
  -severity medium,high,critical \
  -rl 100 -c 25 \
  -jsonl -o findings.jsonl
```

---

## Target-Specific Workflows

### External Attack Surface

Use case: you have a domain and want to find everything exposed.

```bash
# 1. Passive subdomain enumeration
subfinder -d example.com -all -silent -o subs.txt

# 2. Resolve and find live hosts
dnsx -l subs.txt -silent -a -resp -o resolved.txt

# 3. Probe HTTP(S) services, capture tech and titles
cat subs.txt | httpx -silent \
  -title -tech-detect -status-code -web-server -favicon -jarm \
  -o http_live.txt

# 4. Subdomain takeover check (cheap, always worth running)
nuclei -l subs.txt -tags takeover -severity high,critical

# 5. Tech fingerprinting pass
nuclei -l http_live.txt -tags tech -silent -jsonl -o tech.jsonl

# 6. CVE + exposure pass (the real work)
nuclei -l http_live.txt \
  -tags cve,exposure,misconfig,panel,default-login \
  -etags intrusive,dos \
  -severity medium,high,critical \
  -rl 150 -c 25 \
  -jsonl -o findings.jsonl \
  -me ./report

# 7. Specific high-value checks
nuclei -l http_live.txt -tags log4j,spring4shell,confluence,exchange
```

### Single Web Application

Use case: one target, deeper investigation.

```bash
TARGET=https://app.example.com

# 1. Tech fingerprint
nuclei -u $TARGET -tags tech

# 2. Crawl to find endpoints
katana -u $TARGET -d 3 -jc -kf all -silent -o urls.txt

# 3. Historical URLs (often finds forgotten endpoints)
echo $TARGET | waybackurls >> urls.txt
echo $TARGET | gau >> urls.txt
sort -u urls.txt -o urls.txt

# 4. Probe which historical URLs are still live
httpx -l urls.txt -silent -mc 200,301,302,401,403 -o live_urls.txt

# 5. Run nuclei against crawled URLs
nuclei -l live_urls.txt \
  -tags cve,exposure,misconfig \
  -severity medium,high,critical

# 6. Directory brute-force for unlinked content
ffuf -u $TARGET/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt \
  -mc 200,301,302,401,403 \
  -recursion -recursion-depth 2 \
  -o ffuf.json -of json

# 7. Parameter discovery on interesting endpoints
arjun -u $TARGET/api/user -m GET,POST

# 8. Targeted fuzzing templates
nuclei -u $TARGET -tags fuzz -severity high,critical
```

### API Endpoints

Use case: REST/GraphQL APIs, often discovered from JS analysis or OpenAPI specs.

```bash
# GraphQL-specific
nuclei -u https://api.example.com/graphql -tags graphql

# Swagger / OpenAPI discovery
nuclei -u https://api.example.com -tags swagger,openapi,exposure

# JWT / token issues
nuclei -l api_endpoints.txt -tags jwt,token

# API-specific CVEs and misconfigs
nuclei -l api_endpoints.txt -tags api,cve,misconfig

# If you have an OpenAPI spec, feed it to nuclei's OpenAPI mode
nuclei -im openapi -l openapi.json -u https://api.example.com
```

Nuclei has limited support for OpenAPI/Swagger-driven scanning it can consume a spec file and generate requests against documented endpoints. This is genuinely useful when specs exist, but most real APIs don't publish them and you're stuck discovering endpoints via crawling and JS analysis.

### Internal Web Services

Use case: internal pentests, intranets, admin panels on non-standard ports.

```bash
# 1. Find internal HTTP services on common + high ports
naabu -host 10.0.0.0/24 \
  -p 80,443,3000,5000,7000,8000-8100,8443,8888,9000,9090,9200,9443,15672 \
  -silent \
  | httpx -silent -title -tech-detect -status-code -o internal_web.txt

# 2. Focus on panels and default logins the internal goldmine
nuclei -l internal_web.txt \
  -tags panel,default-login,exposure \
  -etags intrusive,dos

# 3. Internal-specific tech (Jenkins, GitLab, Jira, Confluence, etc.)
nuclei -l internal_web.txt \
  -tags jenkins,gitlab,jira,confluence,nexus,artifactory,grafana,kibana,prometheus \
  -severity medium,high,critical

# 4. Elasticsearch / Kibana / Prometheus unauth
nuclei -l internal_web.txt -tags elasticsearch,kibana,prometheus

# 5. Spring/Java stack leaks (actuator is hugely common internally)
nuclei -l internal_web.txt -tags springboot,actuator
```

Internal networks are where nuclei shines hardest. Exposed Jenkins script consoles, default-cred Grafana, unauth Kubernetes dashboards, Spring Boot actuator with `/env` disclosing credentials, and exposed Prometheus `/metrics` showing internal service topology all of these are one-template checks that land with high reliability on internal engagements.

### CMS Targets

```bash
# WordPress
nuclei -u https://wp.example.com -tags wordpress
# Deep plugin/theme enumeration (complement with wpscan)
wpscan --url https://wp.example.com --enumerate ap,at,u --api-token $WPSCAN_TOKEN

# Drupal
nuclei -u https://drupal.example.com -tags drupal

# Joomla
nuclei -u https://joomla.example.com -tags joomla

# Magento
nuclei -u https://magento.example.com -tags magento

# SharePoint
nuclei -u https://sharepoint.example.com -tags sharepoint
```

For WordPress specifically, `wpscan` remains more thorough than nuclei run both. Nuclei is faster and catches recent CVEs; wpscan does authenticated scans, user enumeration, and integrates with the WPVulnDB for plugin-level CVEs.

### Cloud & SaaS

```bash
# AWS-specific (S3 buckets, IAM misconfigs, exposed metadata)
nuclei -l targets.txt -tags aws,s3

# Exposed cloud credentials in responses/files
nuclei -l targets.txt -tags exposure,token

# Kubernetes dashboards, kubelet APIs, etcd
nuclei -l targets.txt -tags k8s,kubernetes

# Docker registry, daemon
nuclei -l targets.txt -tags docker

# CI/CD exposures (Jenkins, GitLab runners, TeamCity)
nuclei -l targets.txt -tags ci,cd,jenkins,gitlab,teamcity

# Common SaaS auth bypass / takeover
nuclei -l targets.txt -tags saas,takeover
```

### IoT Web Interfaces

```bash
# Generic IoT templates
nuclei -l iot_http.txt -tags iot

# Vendor-specific (coverage varies Dahua/Hikvision/D-Link/Netgear are well-covered)
nuclei -l iot_http.txt -tags dahua,hikvision,dlink,netgear,tplink

# Router-specific
nuclei -l iot_http.txt -tags router

# IP camera specific
nuclei -l iot_http.txt -tags camera

# Rate-limit hard IoT devices die under load
nuclei -l iot_http.txt -tags iot -rl 20 -c 5 -timeout 15
```

The `iot` tag is uneven some templates are well-tested, others reference CVEs from obscure advisories that barely work. Expect false positives and verify findings manually before reporting.

---

## Writing Custom Templates

When you find an issue that isn't covered, write a template. The format is YAML and the learning curve is a few hours. Example of a simple check:

```yaml
id: example-exposed-config
info:
  name: Example Exposed Configuration File
  author: you
  severity: high
  description: Detects exposed config.json with credentials
  tags: exposure,config

http:
  - method: GET
    path:
      - "{{BaseURL}}/config.json"
      - "{{BaseURL}}/api/config.json"

    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200

      - type: word
        part: body
        words:
          - "api_key"
          - "secret"
        condition: or

      - type: word
        part: header
        words:
          - "application/json"
```

Core concepts:

- **`id`** is the filename-safe identifier
- **`info`** block holds metadata (name, author, severity, tags, description, reference, classification)
- **`http`** is the request section; also available: `dns`, `tcp`, `ssl`, `file`, `headless`, `code`, `workflow`
- **`{{BaseURL}}`** is the target URL; other variables include `{{Hostname}}`, `{{Host}}`, `{{Port}}`, `{{Path}}`
- **`matchers`** define pass/fail conditions: `status`, `word`, `regex`, `binary`, `dsl`, `xpath`
- **`matchers-condition`** `and` (all must match) or `or` (any match)
- **`extractors`** pull data out of responses (`regex`, `kval`, `xpath`, `json`, `dsl`) for use in reporting or chaining
- **`payloads`** for fuzzing lists of values to substitute into `{{variable}}` markers
- **`stop-at-first-match`** to short-circuit
- **`req-condition: true`** to reference earlier requests in multi-step templates

Test a template with:
```bash
nuclei -u https://target.example.com -t ./my-template.yaml -debug
```

The `-debug` flag shows the full request and response, which is essential for getting matchers right. Once working, add to a private template directory and reference it with `-t /path/to/custom-templates/`.

For complex templates (multi-step auth, chaining responses, DSL expressions), the documentation at `docs.projectdiscovery.io/templates` is the authoritative reference. Reading existing templates in the public repo is the fastest way to learn `http/cves/2023/` has hundreds of real examples.

---

## Cheat Sheet

### Input / Targets

| Flag | Purpose |
|---|---|
| `-u, -target` | Single target URL/host |
| `-l, -list` | File of targets |
| `-eh, -exclude-hosts` | Exclude hosts file |
| `-resume` | Resume from previous scan |
| `-sa, -scan-all-ips` | Scan all IPs for a host (multi-A-record) |
| `-iv, -ip-version` | `4`, `6`, or both |
| `-im, -input-mode` | `list`, `burp`, `jsonl`, `yaml`, `openapi`, `swagger` |

### Template Selection

| Flag | Purpose |
|---|---|
| `-t, -templates` | Template file/dir |
| `-turl, -template-url` | Load templates from URL |
| `-w, -workflows` | Run workflow file |
| `-nt, -new-templates` | Only templates added in latest release |
| `-ntv, -new-templates-version` | Templates from specific version |
| `-as, -automatic-scan` | Auto-select templates based on tech detection |
| `-tags` | Include tags |
| `-etags, -exclude-tags` | Exclude tags |
| `-itags, -include-tags` | Force-include (override exclusions) |
| `-id, -template-id` | Run by template ID |
| `-eid, -exclude-id` | Exclude by template ID |
| `-it, -include-templates` | Force-include template files |
| `-et, -exclude-templates` | Exclude template files |
| `-s, -severity` | `info`, `low`, `medium`, `high`, `critical`, `unknown` |
| `-es, -exclude-severity` | Exclude by severity |
| `-pt, -type` | Protocol type: `http`, `dns`, `tcp`, `ssl`, `file`, etc. |
| `-ept, -exclude-type` | Exclude protocol type |
| `-a, -author` | By author |

### Output

| Flag | Purpose |
|---|---|
| `-o, -output` | Text output file |
| `-j, -jsonl` | JSONL output |
| `-sarif-export` | SARIF output |
| `-me, -markdown-export` | Markdown report directory |
| `-store-resp` | Store full requests/responses |
| `-store-resp-dir` | Directory for stored responses |
| `-silent` | Only show findings |
| `-nc, -no-color` | Disable color |
| `-v, -verbose` | Verbose |
| `-debug` | Full request/response logging |
| `-debug-req` | Log requests only |
| `-debug-resp` | Log responses only |
| `-stats` | Show progress stats |
| `-si, -stats-interval` | Stats interval (seconds) |

### Rate / Performance

| Flag | Purpose |
|---|---|
| `-rl, -rate-limit` | Requests per second (global) |
| `-rlm, -rate-limit-minute` | Requests per minute |
| `-c, -concurrency` | Parallel templates (default 25) |
| `-bs, -bulk-size` | Parallel hosts per template (default 25) |
| `-hbs, -headless-bulk-size` | Headless parallelism |
| `-timeout` | Request timeout in seconds |
| `-retries` | Number of retries |
| `-mhe, -max-host-error` | Max errors per host before skipping |
| `-nmhe, -no-mhe` | Disable host error skip |

### Headers / Auth / Proxy

| Flag | Purpose |
|---|---|
| `-H, -header` | Custom header (repeatable) |
| `-V, -var` | Custom variable (for templates) |
| `-r, -resolvers` | Custom DNS resolvers |
| `-sr, -system-resolvers` | Use system DNS |
| `-p, -proxy` | Proxy URL (e.g. `http://127.0.0.1:8080`) |
| `-pi, -proxy-internal` | Proxy internal requests too |
| `-sni` | Custom TLS SNI |
| `-ztls` | Use zcrypto TLS (more permissive) |
| `-lfa, -allow-local-file-access` | Allow file:// (dangerous) |

### Interactsh / OOB

| Flag | Purpose |
|---|---|
| `-iserver, -interactsh-server` | Custom interactsh URL |
| `-itoken, -interactsh-token` | Auth token |
| `-interactions-cache-size` | Cache size |
| `-interactions-eviction` | Eviction timeout |
| `-interactions-poll-duration` | Poll frequency |
| `-interactions-cooldown-period` | Cooldown |
| `-ni, -no-interactsh` | Disable OOB entirely |

### Update / Config

| Flag | Purpose |
|---|---|
| `-ut, -update-templates` | Update template repo |
| `-un, -update` | Update nuclei binary |
| `-duc, -disable-update-check` | Disable update check |
| `-config` | Custom config file |
| `-tc, -template-config` | Template-specific config |
| `-rc, -report-config` | Reporting config (Jira, GitHub, etc.) |

### Reporting Integrations

Nuclei has built-in reporters for pushing findings to external systems. Configure in a YAML file passed via `-rc`:

```yaml
# report-config.yaml
github:
  owner: your-org
  repository: findings-repo
  token: ghp_xxx

slack:
  webhook-url: https://hooks.slack.com/...

jira:
  cloud: true
  url: https://org.atlassian.net
  account-id: xxx
  email: xxx
  token: xxx
  project-name: SEC
  issue-type: Bug
```

---

## Supporting Tools Cheat Sheet

### httpx

```bash
# Basic probe
httpx -l hosts.txt -silent

# Rich output
httpx -l hosts.txt -silent \
  -title -tech-detect -status-code -web-server \
  -content-length -ip -cname -cdn -favicon -jarm

# Screenshot every live host
httpx -l hosts.txt -ss -srd ./screenshots/

# Filter by status, match content, follow redirects
httpx -l hosts.txt -mc 200,401,403 -fr -timeout 10

# Match specific tech or string
httpx -l hosts.txt -ms "admin panel" -silent

# Detect specific tech
httpx -l hosts.txt -td -ms "WordPress"
```

### katana (crawler)

```bash
# Basic crawl
katana -u https://example.com -d 3 -silent

# JS-aware crawl (parses JS for URLs)
katana -u https://example.com -d 3 -jc -silent

# Headless mode (real browser)
katana -u https://example.com -d 3 -hl -silent

# Crawl from list, output format control
katana -list urls.txt -d 2 -kf all -f qurl -silent -o crawled.txt

# Scope control
katana -u https://example.com -cs "example.com" -silent
```

### subfinder

```bash
# Basic (passive sources only)
subfinder -d example.com -silent

# All sources including slower ones
subfinder -d example.com -all -silent

# Multiple domains
subfinder -dL domains.txt -silent -o all_subs.txt

# Recursive
subfinder -d example.com -recursive -silent
```

API keys for premium sources live in `~/.config/subfinder/provider-config.yaml` Censys, Shodan, SecurityTrails, VirusTotal keys make a massive difference in coverage.

### ffuf

```bash
# Directory brute
ffuf -u https://example.com/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt \
  -mc 200,301,302,401,403

# Recursive
ffuf -u https://example.com/FUZZ -w wordlist.txt -recursion -recursion-depth 2

# Parameter fuzzing (GET)
ffuf -u "https://example.com/api?FUZZ=test" \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -fs 1234   # filter out size 1234 (baseline response)

# Parameter fuzzing (POST body)
ffuf -u https://example.com/api -X POST \
  -d "FUZZ=test" -w params.txt -mc 200 -fc 404

# Virtual host fuzzing
ffuf -u https://example.com -H "Host: FUZZ.example.com" \
  -w subs.txt -fs 1234

# Filter by response characteristics
ffuf -u https://example.com/FUZZ -w wordlist.txt \
  -mc all -fs 0 -fl 1 -fw 10 -fr "not found"
  # mc=match code, fs=filter size, fl=filter lines, fw=filter words, fr=filter regex
```

### Other useful one-liners

```bash
# Historical URLs for attack surface
echo "example.com" | gau --subs | tee gau.txt

# Extract interesting URLs with gf patterns
cat gau.txt | gf xss > potential_xss.txt
cat gau.txt | gf sqli > potential_sqli.txt
cat gau.txt | gf ssrf > potential_ssrf.txt

# Replace all query values with payload (for fuzzing)
cat urls.txt | qsreplace '"><script>alert(1)</script>' > xss_tests.txt

# Parameter discovery
arjun -u https://example.com/api/endpoint -m GET,POST --stable
```

---

## Practical Notes

**Nuclei is pattern-matching, not understanding.** Every template check is "send this, look for that" there's no semantic understanding of the application. This means nuclei will miss any vulnerability that requires application state, authentication flow awareness, business logic understanding, or novel attack patterns. It will also produce false positives when a response happens to match a matcher by coincidence. Treat nuclei findings as leads requiring verification, not as final confirmations.

**Template freshness matters more than anything else.** The delta between a scan with last month's templates and today's templates can include the exact check you need. Run `nuclei -ut` before every serious scan. For continuous monitoring setups, automate the update `nuclei -ut && nuclei -l targets.txt ...` is the right shape for cron.

**Severity is advisory, not authoritative.** Template severity is set by the author and varies in quality. An `info`-severity template might be a high-value finding in context (e.g., a tech fingerprint revealing an end-of-life product); a `critical`-severity template might be a noisy false positive. Don't filter on severity alone for final reporting review findings in context.

**False positive rate varies dramatically by tag.** The `cve` tag tends to be well-maintained because CVEs get attention. The `exposure` and `misconfig` tags are noisier because they rely on fuzzy heuristics (file contents, error messages). The `takeover` tag is almost always accurate when it fires. The `tech` tag is informational and reliable. When triaging, weight tags by their typical precision.

**OAST templates require correct interactsh setup.** If your scan isn't getting OOB callbacks on known-vulnerable targets, check: (1) the interactsh server is actually reachable from the target, (2) egress DNS/HTTP isn't blocked on the target side, (3) you're not hitting the public interactsh rate limits, (4) the target's network isn't running a DNS firewall that blocks interactsh domains. For real engagements, self-host with a domain and wildcard DNS that doesn't look like "interactsh."

**Rate limiting is necessary but tricky.** Nuclei defaults (`-c 25 -bs 25 -rl 150`) are fine for external internet targets behind CDNs but will overwhelm small targets. For internal networks with fragile services, drop to `-c 10 -bs 10 -rl 50`. For IoT, drop further to `-c 5 -bs 5 -rl 20`. For external scans against hosts without WAF protection, consider scaling down not because the target will crash, but because you'll trip rate-based IDS on the network path. WAFs will absolutely rate-limit and blackhole you at defaults.

**Headless templates are slow and fragile.** The `-hl` mode launches Chromium via chromedp for templates that need a real browser (DOM XSS, JS-heavy SPAs). It works but consumes significant memory and CPU, and the templates themselves are more prone to breakage when sites change. Only enable headless mode when you specifically need those templates.

**Authenticated scanning is possible but clunky.** Nuclei supports custom headers (`-H "Authorization: Bearer xxx"`) and cookies, which is enough for static-token auth. For session-based auth, you need to either keep a valid session cookie fresh manually or write a pre-request template. For OAuth flows, MFA, or anything dynamic, nuclei is the wrong tool use Burp Scanner or write a custom scanner that handles the auth state.

**Nuclei is not a crawler.** It takes URLs as input and sends template requests against those URLs. If you point it at `https://example.com`, it only tests the root. For thorough coverage, crawl with katana first, pipe the URLs into nuclei. This is the most common mistake people make with nuclei running it against a bare domain and assuming it found everything.

**Combine with Burp for real web app testing.** Proxy nuclei through Burp (`-p http://127.0.0.1:8080`) to capture all requests/responses in Burp's history, then review them manually. This gives you nuclei's template coverage plus Burp's manual review workflow in one pass. Useful for engagements where you want nuclei's speed but also want to eyeball interesting responses.

**Compared to commercial scanners.** Nuclei is narrower than Burp Scanner, Invicti, or Qualys WAS in terms of smart crawling and dynamic testing it won't auto-authenticate, won't track state, won't mutate parameters intelligently. It's broader in terms of raw check coverage (thousands of templates vs. hundreds of built-in checks) and vastly faster. Commercial scanners win on single-app depth; nuclei wins on breadth, speed, and keeping pace with new CVEs. Best outcome is running both.

**Compared to nmap NSE.** Nuclei replaces `http-*` NSE scripts entirely and does the job better faster, more coverage, easier to update. Nmap still wins for service detection, OS fingerprinting, non-HTTP protocol checks, and anything requiring raw packet control. On real engagements, nmap does discovery and service detection, nuclei does HTTP-layer vuln checking. They don't overlap functionally; they chain.

**Writing templates is the multiplier.** The biggest difference between "runs nuclei" and "gets value from nuclei" is the willingness to write custom templates for findings that aren't covered. Every engagement reveals at least one pattern you'll see again. Turn it into a template. After a year of doing this, you'll have a private template library that catches things nobody else's scans will.

**Watch out for template deprecation and renaming.** The upstream template repo occasionally reorganizes templates move between directories, tags get renamed, deprecated templates are removed. If your pipeline pins specific template paths, it will break. Use tags and IDs instead of paths where possible, and version-pin the template repo for reproducible scans: `nuclei -ut -tv 9.8.1`.

**Legal and scope considerations.** Nuclei sends a lot of requests fast, many of which look indistinguishable from attack traffic. On anything you don't own, confirm scope in writing before running it, exclude clearly out-of-scope hosts (`-eh`), and keep logs. Templates tagged `intrusive`, `dos`, and `fuzz` have a real chance of affecting service stability exclude them on production targets unless you've explicitly negotiated authorization for destructive testing. The default template set doesn't include these, but it's worth double-checking when you add tags.

**Don't neglect the boring outputs.** Tech fingerprinting and `info`-severity findings often matter more than critical-tagged ones. A clean `tech`-only scan showing every framework, language, and server version across the attack surface is one of the most useful artifacts you can produce on an engagement it feeds every subsequent decision about where to look deeper. Run `nuclei -tags tech -silent -jsonl` as part of every workflow and keep the output as engagement baseline.