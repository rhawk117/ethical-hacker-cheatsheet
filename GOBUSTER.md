# Gobuster: Practical Reference & Cheat Sheet

A working reference for gobuster — the Go-based brute-forcing tool for content discovery, DNS enumeration, virtual host discovery, and a handful of other niche modes. Gobuster is narrower in scope than nuclei or nmap: it does one thing (send requests from a wordlist and filter responses) and does it fast. This doc covers every mode, wordlist selection, tuning, workflows by target type, and honest notes on when to reach for gobuster vs. the alternatives (ffuf, feroxbuster, dirsearch, wfuzz).

---

## Table of Contents

1. [What Gobuster Is](#what-gobuster-is)
2. [Modes Overview](#modes-overview)
3. [Wordlists: The Real Determinant](#wordlists-the-real-determinant)
4. [Dir Mode — Content Discovery](#dir-mode--content-discovery)
5. [DNS Mode — Subdomain Enumeration](#dns-mode--subdomain-enumeration)
6. [Vhost Mode — Virtual Host Discovery](#vhost-mode--virtual-host-discovery)
7. [Fuzz Mode — Generic Fuzzing](#fuzz-mode--generic-fuzzing)
8. [S3 Mode — Bucket Enumeration](#s3-mode--bucket-enumeration)
9. [GCS Mode — Google Cloud Storage](#gcs-mode--google-cloud-storage)
10. [TFTP Mode](#tftp-mode)
11. [Target-Specific Workflows](#target-specific-workflows)
12. [Cheat Sheet](#cheat-sheet)
13. [Gobuster vs Alternatives](#gobuster-vs-alternatives)
14. [Practical Notes](#practical-notes)

---

## What Gobuster Is

Gobuster is a brute-forcer. You give it a target and a wordlist, it sends a request per word, filters responses, and prints matches. That's the whole thing. It's written in Go so it's fast and single-binary, it handles TLS cleanly, and it has clean output. What it **doesn't** have: recursion (by default), response-content matching beyond status code and size, parameter fuzzing, multi-stage logic, or any of the flexibility ffuf offers. It's a sharp, narrow tool.

Mental model: gobuster is **wordlist-driven enumeration**. The quality of your findings is directly proportional to the quality of your wordlist. Using gobuster with `common.txt` gets you what everyone else gets. Using it with a tuned, target-specific wordlist gets you things other people miss. The tool is the easy part; wordlist selection is the work.

Where it fits: early in a web engagement, after you've identified live HTTP services but before you've started manual exploration. Gobuster's job is to hand you the directory structure so you know where to look. For subdomain enum, it's a reasonable option alongside `subfinder` and `amass` (though for passive enum `subfinder` is better; gobuster's DNS mode is active brute-force).

---

## Modes Overview

Gobuster commands are subcommand-structured: `gobuster <mode> <flags>`.

| Mode | Purpose |
|---|---|
| `dir` | Directory/file brute-force against HTTP(S) |
| `dns` | Subdomain brute-force via DNS |
| `vhost` | Virtual host discovery via Host header |
| `fuzz` | Generic `FUZZ`-keyword replacement |
| `s3` | AWS S3 bucket name enumeration |
| `gcs` | Google Cloud Storage bucket enumeration |
| `tftp` | TFTP file discovery |
| `version` | Print version |
| `help` | Help text |

Each mode has its own flag set but shares common concerns (wordlist, threading, output).

---

## Wordlists: The Real Determinant

Gobuster ships with no wordlists. You need SecLists and a few others. If you haven't already:

```bash
sudo git clone https://github.com/danielmiessler/SecLists.git /usr/share/seclists
```

The relevant directories within SecLists:

```
/usr/share/seclists/Discovery/
├── Web-Content/           # Directory/file brute-force lists
├── DNS/                   # Subdomain wordlists
├── Variables/             # Parameter names
└── Infrastructure/        # Port/protocol lists
```

### Recommended Lists by Mode

**Dir mode — web content**

| List | Size | Use case |
|---|---|---|
| `Discovery/Web-Content/common.txt` | ~4.7k | Quick first pass |
| `Discovery/Web-Content/raft-small-directories.txt` | ~20k | Directories, reasonable runtime |
| `Discovery/Web-Content/raft-medium-directories.txt` | ~46k | Thorough directory sweep |
| `Discovery/Web-Content/raft-large-directories.txt` | ~88k | Aggressive, when you have time |
| `Discovery/Web-Content/raft-small-files.txt` | ~11k | Files, small list |
| `Discovery/Web-Content/raft-medium-files.txt` | ~18k | Files, medium |
| `Discovery/Web-Content/raft-large-files.txt` | ~37k | Files, large |
| `Discovery/Web-Content/directory-list-2.3-medium.txt` | ~220k | The classic "big list" |
| `Discovery/Web-Content/directory-list-2.3-small.txt` | ~88k | Smaller variant |
| `Discovery/Web-Content/big.txt` | ~20k | General-purpose |
| `Discovery/Web-Content/quickhits.txt` | ~2.4k | Fast high-value paths |
| `Discovery/Web-Content/api/` | varies | API-specific paths |

**Tech-specific lists** (much higher signal than generic lists when tech is known):

```
Discovery/Web-Content/CMS/          # WordPress, Drupal, Joomla, Magento
Discovery/Web-Content/Web-Servers/  # Apache, Nginx, IIS
Discovery/Web-Content/Frameworks/   # Laravel, Django, Rails, Spring
Discovery/Web-Content/tomcat.txt
Discovery/Web-Content/jboss.txt
Discovery/Web-Content/websphere.txt
Discovery/Web-Content/weblogic.txt
Discovery/Web-Content/spring-boot.txt
```

**DNS mode — subdomains**

| List | Size | Use case |
|---|---|---|
| `Discovery/DNS/subdomains-top1million-5000.txt` | 5k | Quick pass |
| `Discovery/DNS/subdomains-top1million-20000.txt` | 20k | Balanced |
| `Discovery/DNS/subdomains-top1million-110000.txt` | 110k | Thorough |
| `Discovery/DNS/n0kovo_subdomains/n0kovo_subdomains_huge.txt` | 3M+ | Maximum coverage |
| `Discovery/DNS/bitquark-subdomains-top100000.txt` | 100k | Alternative source |
| `Discovery/DNS/dns-Jhaddix.txt` | ~9k | Curated, high-quality |

**Extensions for dir mode** (`-x` flag):

- Generic: `php,html,txt,bak,old,zip,tar.gz`
- PHP stack: `php,phtml,php3,php4,php5,php7,phar,inc`
- ASP.NET: `asp,aspx,ashx,asmx,axd,config`
- Java: `jsp,do,action,jspx,war`
- Config/backup: `bak,old,backup,orig,save,swp,conf,config,yml,yaml,json,xml,env`
- Archives: `zip,tar,tar.gz,tgz,rar,7z,gz`

### Building Tuned Wordlists

Generic wordlists are the baseline. For real engagement value, build target-specific ones by scraping:

```bash
# Scrape words from the target site itself
cewl https://target.example.com -d 3 -w scraped.txt

# Extract words from JS files after crawling
cat urls.txt | grep '\.js$' | xargs -I{} curl -s {} \
  | grep -oE '[a-zA-Z][a-zA-Z0-9_-]{3,}' \
  | sort -u > js_words.txt

# Historical paths from Wayback (often finds deleted endpoints)
echo "target.example.com" | waybackurls \
  | unfurl paths \
  | sed 's|^/||' \
  | sort -u > wayback_paths.txt

# Combine tuned list
cat raft-small-directories.txt scraped.txt js_words.txt wayback_paths.txt \
  | sort -u > target_tuned.txt
```

The wayback + js_words combination is underrated — it finds endpoints that exist in the current codebase but aren't linked from any page, and endpoints that existed historically but are still deployed.

---

## Dir Mode — Content Discovery

The most-used mode. Brute-forces paths against an HTTP(S) target.

### Basic Usage

```bash
gobuster dir \
  -u https://target.example.com \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
```

### Common Invocations

```bash
# With extensions
gobuster dir \
  -u https://target.example.com \
  -w wordlist.txt \
  -x php,html,txt,bak

# Tune for speed + quiet output
gobuster dir \
  -u https://target.example.com \
  -w wordlist.txt \
  -t 50 \
  -q --no-error \
  -o results.txt

# Filter by status codes (default is 200,204,301,302,307,401,403)
gobuster dir \
  -u https://target.example.com \
  -w wordlist.txt \
  -s "200,204,301,302,307,401,403,405,500"

# Alternative: blacklist codes instead
gobuster dir \
  -u https://target.example.com \
  -w wordlist.txt \
  -b "404,503"

# Filter responses by size (hide known 404 page size)
gobuster dir \
  -u https://target.example.com \
  -w wordlist.txt \
  --exclude-length 1234

# Custom headers (auth, API keys, host spoofing)
gobuster dir \
  -u https://target.example.com \
  -w wordlist.txt \
  -H "Authorization: Bearer eyJ..." \
  -H "X-Forwarded-For: 127.0.0.1"

# Cookie-based auth
gobuster dir \
  -u https://target.example.com \
  -w wordlist.txt \
  -c "session=abc123; csrftoken=xyz"

# Basic auth
gobuster dir \
  -u https://target.example.com \
  -w wordlist.txt \
  -U admin -P password

# Custom user agent (bypass naive UA blocking)
gobuster dir \
  -u https://target.example.com \
  -w wordlist.txt \
  -a "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# Random user agents from a list (rotate per request)
gobuster dir \
  -u https://target.example.com \
  -w wordlist.txt \
  --random-agent

# Follow redirects (off by default — usually leave off)
gobuster dir \
  -u https://target.example.com \
  -w wordlist.txt \
  -r

# Skip TLS verification (self-signed, misconfigured certs)
gobuster dir \
  -u https://target.example.com \
  -w wordlist.txt \
  -k

# Discover backup files for found paths
gobuster dir \
  -u https://target.example.com \
  -w wordlist.txt \
  -d  # returns full response body hash for comparison

# Add extensions from a file (huge ext list)
gobuster dir \
  -u https://target.example.com \
  -w wordlist.txt \
  -X extensions.txt
```

### Status Code Reference

Default dir mode considers these as "found":

| Code | Meaning | Usually means |
|---|---|---|
| 200 | OK | Resource exists |
| 204 | No Content | Resource exists but empty response |
| 301 | Moved Permanently | Redirect — check Location header |
| 302 | Found | Redirect — check Location header |
| 307 | Temporary Redirect | Redirect |
| 401 | Unauthorized | Auth required — **interesting** |
| 403 | Forbidden | Exists but access denied — **very interesting** |

Worth adding manually:

| Code | Why |
|---|---|
| 405 | Method not allowed — endpoint exists, wrong verb |
| 500 | Server error — often reveals existence + stack traces |
| 502/503 | Backend alive but misconfigured |

### Gobuster Lacks Recursion

Gobuster `dir` mode does **not** recurse into discovered directories. This is the single most important limitation to understand. If gobuster finds `/admin/`, it won't automatically enumerate inside `/admin/`. You have two options:

**Manual recursion:**
```bash
# First pass
gobuster dir -u https://target.example.com -w wordlist.txt -o pass1.txt

# Extract directories and scan each
grep "Status: 301" pass1.txt | awk '{print $1}' | while read dir; do
  gobuster dir -u "https://target.example.com$dir" -w wordlist.txt \
    -o "pass2_$(echo $dir | tr '/' '_').txt"
done
```

**Use feroxbuster instead**, which does recursion natively:
```bash
feroxbuster -u https://target.example.com -w wordlist.txt -d 3
```

Honestly, for content discovery with recursion, feroxbuster is the better tool. Gobuster is cleaner for single-level enumeration and for piping into other tools.

---

## DNS Mode — Subdomain Enumeration

Active subdomain brute-force via DNS resolution.

### Basic Usage

```bash
gobuster dns \
  -d example.com \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
```

### Common Invocations

```bash
# Show IPs of discovered subdomains
gobuster dns \
  -d example.com \
  -w wordlist.txt \
  -i

# Custom resolver (avoid ISP DNS which may rate-limit)
gobuster dns \
  -d example.com \
  -w wordlist.txt \
  -r 8.8.8.8

# Multiple resolvers (round-robin for speed)
gobuster dns \
  -d example.com \
  -w wordlist.txt \
  -r 8.8.8.8,1.1.1.1,9.9.9.9

# Show CNAME records
gobuster dns \
  -d example.com \
  -w wordlist.txt \
  -c

# Threads + timeout tuning
gobuster dns \
  -d example.com \
  -w wordlist.txt \
  -t 100 \
  --timeout 3s

# Wildcard handling — gobuster detects wildcards automatically
# and refuses to proceed unless you allow:
gobuster dns \
  -d example.com \
  -w wordlist.txt \
  --wildcard
```

### When to Use DNS Mode vs Alternatives

Gobuster DNS mode is **active brute-force** — it sends thousands of DNS queries directly and makes noise with whatever resolver you use. For initial subdomain enumeration, **passive sources are always better**: `subfinder -all -d example.com` hits ~30 sources (Censys, Shodan, crt.sh, VirusTotal, etc.) and returns subdomains discovered via other means without sending a single query to the target's authoritative DNS.

Use gobuster DNS mode when:
- Passive sources are exhausted and you want to find unpublished subdomains
- The target has internal-only subdomains that won't appear in public sources
- You're doing targeted guessing based on naming conventions (`dev-app1`, `staging-app1`, etc.)
- You need a list-based sweep of a fixed naming pattern

Don't use it as your first move. `subfinder -all` first, gobuster DNS second for gap-filling.

---

## Vhost Mode — Virtual Host Discovery

Discovers virtual hosts sharing the same IP by brute-forcing the `Host` header.

### Basic Usage

```bash
gobuster vhost \
  -u https://target.example.com \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  --append-domain
```

### Key Flags

```bash
# --append-domain: append the base domain to each wordlist entry
# Without it, the wordlist must contain full hostnames.
# With it, "dev" becomes "dev.example.com"
gobuster vhost -u https://example.com -w subs.txt --append-domain

# Exclude by response length (filters out default vhost responses)
gobuster vhost \
  -u https://target.example.com \
  -w wordlist.txt \
  --append-domain \
  --exclude-length 1234

# Exclude by length range
gobuster vhost \
  -u https://target.example.com \
  -w wordlist.txt \
  --append-domain \
  --exclude-length 1200-1300

# Show status codes (default hides them)
gobuster vhost \
  -u https://target.example.com \
  -w wordlist.txt \
  --append-domain \
  --show-status
```

### How Vhost Discovery Works

When multiple sites share an IP (shared hosting, CDN, reverse proxies), the server uses the `Host` header to decide which site to serve. Gobuster vhost mode sends `Host: candidate.example.com` for each candidate and looks for responses that differ from the default. Findings usually mean:

- A virtual host configured on the server that isn't in public DNS (internal/staging/dev sites)
- A legacy vhost still configured after DNS changed
- A misconfigured backend reachable by direct Host header

**Critical:** vhost discovery requires finding responses that differ from the baseline. If the default vhost and the discovered vhost return identical responses, gobuster won't flag it. Set `--exclude-length` to the baseline response size for clean results, or use ffuf with more sophisticated filters.

---

## Fuzz Mode — Generic Fuzzing

Replaces `FUZZ` keyword in the URL with wordlist entries. Similar to ffuf but less flexible.

### Basic Usage

```bash
gobuster fuzz \
  -u "https://target.example.com/FUZZ" \
  -w wordlist.txt
```

### Use Cases

```bash
# Fuzz path segments
gobuster fuzz \
  -u "https://target.example.com/api/FUZZ/users" \
  -w endpoints.txt

# Fuzz parameter values
gobuster fuzz \
  -u "https://target.example.com/page?id=FUZZ" \
  -w values.txt \
  --exclude-length 1234

# Fuzz headers
gobuster fuzz \
  -u "https://target.example.com/" \
  -H "X-Original-URL: FUZZ" \
  -w paths.txt

# Filter by status
gobuster fuzz \
  -u "https://target.example.com/FUZZ" \
  -w wordlist.txt \
  -b "404,403"
```

Honestly, if you're reaching for fuzz mode, ffuf does this better with more filter options, multi-position fuzzing, and clearer syntax. Gobuster fuzz exists for completeness; ffuf should be your default for generic fuzzing.

---

## S3 Mode — Bucket Enumeration

Brute-forces AWS S3 bucket names and checks for public access.

### Basic Usage

```bash
gobuster s3 \
  -w /usr/share/seclists/Discovery/Web-Content/s3/s3-buckets.txt
```

### Common Invocations

```bash
# Basic enumeration
gobuster s3 -w bucket_names.txt

# Show bucket contents for readable buckets
gobuster s3 -w bucket_names.txt -i

# Limit max keys shown per bucket
gobuster s3 -w bucket_names.txt -i -m 10

# Threads
gobuster s3 -w bucket_names.txt -t 50
```

### Building Target-Specific Bucket Wordlists

Generic S3 wordlists find generic buckets. For a specific company, mutate the company name:

```bash
COMPANY=acme
for prefix in "" "dev-" "prod-" "staging-" "test-" "backup-" "assets-" \
              "logs-" "data-" "files-" "media-" "www-" "cdn-"; do
  for suffix in "" "-dev" "-prod" "-staging" "-backup" "-assets" "-data" \
                "-files" "-logs" "-old" "-bak" "-2022" "-2023" "-2024"; do
    echo "${prefix}${COMPANY}${suffix}"
  done
done > ${COMPANY}_buckets.txt

gobuster s3 -w ${COMPANY}_buckets.txt -i
```

For more comprehensive bucket mutation, use a dedicated tool like `s3scanner` or `cloud_enum` — they cover AWS, Azure, and GCP in one pass with better mutation logic.

---

## GCS Mode — Google Cloud Storage

Same idea as S3 mode but for GCS buckets.

```bash
gobuster gcs \
  -w bucket_names.txt \
  -i
```

The usage is nearly identical to S3 mode. GCS bucket namespace is global (same as S3), so target-specific mutations work the same way.

---

## TFTP Mode

Brute-forces TFTP filenames. TFTP is UDP-based, has no auth or directory listing, so you have to guess filenames. Still relevant against network gear (routers, switches, VoIP phones) that store configs on TFTP servers.

```bash
gobuster tftp \
  -s tftp.example.com:69 \
  -w /usr/share/seclists/Discovery/Infrastructure/TFTP.fuzz.txt
```

Useful wordlists:
- `running-config`, `startup-config`
- `SEP<MAC>.cnf.xml` for Cisco phones
- `router-confg`, `switch-confg`
- `backup.cfg`, `config.bin`, `firmware.bin`

Honest take: TFTP mode is a niche use case. If you're already in a position to talk to a TFTP server, you probably know what you're looking for.

---

## Target-Specific Workflows

### External Web Application

```bash
TARGET=https://target.example.com

# 1. Quick first pass for low-hanging fruit
gobuster dir -u $TARGET \
  -w /usr/share/seclists/Discovery/Web-Content/quickhits.txt \
  -t 50 -q -o quickhits_results.txt

# 2. Main content discovery
gobuster dir -u $TARGET \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -x php,html,txt,bak,old,zip \
  -t 50 -q -o dir_results.txt

# 3. File-focused pass
gobuster dir -u $TARGET \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt \
  -t 50 -q -o files_results.txt

# 4. Backup/config hunt
gobuster dir -u $TARGET \
  -w /usr/share/seclists/Discovery/Web-Content/Common-DB-Backups.txt \
  -t 30 -q -o backups.txt

# 5. Manual recursion into discovered directories
grep -E "Status: (301|302)" dir_results.txt | awk '{print $1}' \
  | while read d; do
      gobuster dir -u "$TARGET$d" -w raft-small-directories.txt \
        -t 50 -q -o "recurse_${d//\//_}.txt"
    done
```

### Subdomain Enumeration (Hybrid Approach)

```bash
DOMAIN=example.com

# 1. Passive first (always)
subfinder -d $DOMAIN -all -silent -o passive_subs.txt

# 2. Active brute with gobuster to fill gaps
gobuster dns -d $DOMAIN \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
  -r 1.1.1.1,8.8.8.8 \
  -t 100 \
  -o active_subs.txt

# 3. Merge, resolve, probe
cat passive_subs.txt active_subs.txt | sort -u \
  | dnsx -silent -a -resp \
  | httpx -silent -title -tech-detect \
  > all_live.txt
```

### Tech-Targeted Enumeration

Once you know the backend, use tech-specific wordlists:

```bash
# Identified as Tomcat
gobuster dir -u https://target.example.com \
  -w /usr/share/seclists/Discovery/Web-Content/tomcat.txt \
  -x jsp,do

# Spring Boot — actuator hunting
gobuster dir -u https://target.example.com \
  -w /usr/share/seclists/Discovery/Web-Content/spring-boot.txt

# WordPress
gobuster dir -u https://target.example.com \
  -w /usr/share/seclists/Discovery/Web-Content/CMS/wordpress.fuzz.txt

# API endpoint discovery
gobuster dir -u https://api.target.example.com \
  -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
  -s "200,201,204,301,302,307,401,403,405"
```

### Internal Network Web Service

```bash
# After finding internal web services via naabu/nmap
for host in $(cat internal_web.txt); do
  gobuster dir -u "http://$host" \
    -w /usr/share/seclists/Discovery/Web-Content/common.txt \
    -t 30 -q -k --no-error \
    -o "internal_${host//[:.\/]/_}.txt" \
    --timeout 10s
done

# Focus on the classics: admin panels, Spring Boot actuator, Jenkins, etc.
for host in $(cat internal_web.txt); do
  gobuster dir -u "http://$host" \
    -w /usr/share/seclists/Discovery/Web-Content/AdminPagesDirb.txt \
    -t 30 -q -k --no-error
done
```

### Cloud Bucket Hunt

```bash
COMPANY=acme

# Build mutation list
cat > mutations.sh <<'EOF'
#!/bin/bash
COMPANY=$1
prefixes=("" "dev-" "prod-" "stage-" "test-" "qa-" "uat-" "backup-" "backups-"
          "old-" "new-" "assets-" "static-" "cdn-" "media-" "files-" "data-"
          "logs-" "log-" "db-" "database-" "config-" "secret-" "secrets-"
          "internal-" "private-" "public-" "www-" "web-")
suffixes=("" "-dev" "-prod" "-stage" "-test" "-qa" "-uat" "-backup" "-backups"
          "-old" "-new" "-assets" "-static" "-cdn" "-media" "-files" "-data"
          "-logs" "-log" "-db" "-2021" "-2022" "-2023" "-2024" "-2025"
          "-internal" "-private" "-public" "-www" "-web" "-bak")
for p in "${prefixes[@]}"; do
  for s in "${suffixes[@]}"; do
    echo "${p}${COMPANY}${s}"
  done
done | sort -u
EOF
chmod +x mutations.sh
./mutations.sh $COMPANY > ${COMPANY}_mutations.txt

# Run S3 + GCS in parallel
gobuster s3 -w ${COMPANY}_mutations.txt -i -t 50 -o s3_results.txt &
gobuster gcs -w ${COMPANY}_mutations.txt -i -t 50 -o gcs_results.txt &
wait
```

---

## Cheat Sheet

### Global Flags (All Modes)

| Flag | Purpose |
|---|---|
| `-w, --wordlist` | Path to wordlist (required) |
| `-t, --threads` | Concurrent threads (default 10) |
| `-o, --output` | Output file |
| `-q, --quiet` | Quiet mode (no banner, minimal output) |
| `-v, --verbose` | Verbose output |
| `-z, --no-progress` | Hide progress bar |
| `--no-color` | Disable color |
| `--no-error` | Suppress error messages |
| `--delay` | Delay between requests (e.g. `100ms`, `1s`) |
| `--debug` | Debug output |
| `-p, --pattern` | Pattern file for word mutation |
| `--discover-backup` | Check for common backup extensions on found paths |

### Dir Mode Flags

| Flag | Purpose |
|---|---|
| `-u, --url` | Target URL (required) |
| `-x, --extensions` | Extensions list (e.g. `php,html,txt`) |
| `-X, --extensions-file` | Extensions from file |
| `-s, --status-codes` | Positive status codes |
| `-b, --status-codes-blacklist` | Negative status codes |
| `--exclude-length` | Exclude by response length (single/range/list) |
| `-c, --cookies` | Cookies string |
| `-H, --headers` | Custom header (repeatable) |
| `-a, --useragent` | Custom User-Agent |
| `--random-agent` | Random User-Agent per request |
| `-U, --username` | Basic auth username |
| `-P, --password` | Basic auth password |
| `-k, --no-tls-validation` | Skip TLS cert validation |
| `-r, --follow-redirect` | Follow redirects |
| `--timeout` | Request timeout (e.g. `10s`) |
| `--retry` | Retry on timeout |
| `--retry-attempts` | Number of retries |
| `-m, --method` | HTTP method (default GET) |
| `--proxy` | Proxy URL |
| `-n, --no-status` | Hide status codes |
| `-d, --discover-backup` | Discover backup files for hits |
| `-e, --expanded` | Expanded URL output |
| `-f, --add-slash` | Append `/` to each word |

### DNS Mode Flags

| Flag | Purpose |
|---|---|
| `-d, --domain` | Target domain (required) |
| `-r, --resolver` | Custom resolver(s) |
| `-i, --show-ips` | Show resolved IPs |
| `-c, --show-cname` | Show CNAME records |
| `--wildcard` | Allow scanning despite wildcard DNS |
| `--timeout` | DNS query timeout |
| `--no-fqdn` | Don't append FQDN |

### Vhost Mode Flags

| Flag | Purpose |
|---|---|
| `-u, --url` | Target URL (required) |
| `--append-domain` | Append base domain to wordlist entries |
| `--exclude-length` | Exclude by response length |
| `-c, --cookies` | Cookies |
| `-H, --headers` | Custom headers |
| `-k, --no-tls-validation` | Skip TLS validation |
| `-r, --follow-redirect` | Follow redirects |
| `-m, --method` | HTTP method |
| `--domain` | Override domain for appending |

### S3/GCS Mode Flags

| Flag | Purpose |
|---|---|
| `-w` | Bucket name wordlist |
| `-i, --show-files` | Show files in readable buckets |
| `-m, --maxfiles` | Max files to list per bucket |

### Exit Codes

Gobuster returns non-zero on error. Useful for scripting:
```bash
if gobuster dir -u $TARGET -w $WORDLIST -o $OUT 2>/dev/null; then
  echo "Scan completed"
else
  echo "Scan failed or interrupted"
fi
```

---

## Gobuster vs Alternatives

Honest comparison against the other commonly-used tools in this space.

### gobuster vs ffuf

**ffuf wins for:**
- Flexibility: multiple FUZZ positions, parameter fuzzing, body fuzzing, header fuzzing
- Response filtering: filter by status, size, words, lines, regex, time — all simultaneously
- Recursion (with `-recursion`)
- Better output formats (JSON, CSV, HTML, markdown)
- More active development and community

**gobuster wins for:**
- Clean, predictable output (better for piping)
- Simpler CLI for simple tasks
- Better DNS mode (ffuf doesn't really do DNS)
- Dedicated S3/GCS/TFTP modes

**Verdict:** ffuf is the more capable tool for content discovery and fuzzing. Gobuster is cleaner when you want simple directory enumeration with clean output, and its non-HTTP modes (DNS, S3, GCS) have no direct ffuf equivalent. Most serious testers use ffuf as the primary tool and gobuster for specific modes.

### gobuster vs feroxbuster

**feroxbuster wins for:**
- Native recursion (the big one)
- Faster in most benchmarks
- Better collision detection
- Auto-filtering based on wildcard responses
- Pausable/resumable scans

**gobuster wins for:**
- Simpler output (easier to pipe)
- Multi-mode (DNS, S3, etc.)

**Verdict:** For recursive content discovery, feroxbuster is clearly better. Gobuster dir mode without recursion is a limitation that's hard to justify when feroxbuster exists.

### gobuster vs dirsearch

**dirsearch wins for:**
- Built-in smart wildcard handling
- Dynamic extension substitution (`%EXT%` in wordlist)
- Better default wordlist
- Auto-recursion

**gobuster wins for:**
- Speed (Go vs Python)
- Cleaner output for piping

**Verdict:** dirsearch has smarter defaults and better UX; gobuster is faster. For someone who likes Python tooling and wants something that "just works" on first run, dirsearch is easier. For someone building a scripted pipeline, gobuster's speed and output cleanliness win.

### gobuster vs wfuzz

wfuzz is older, more flexible, and much slower. It's still relevant for niche fuzzing scenarios (multi-position fuzzing with encoders, complex payload generation) but ffuf has largely replaced it. Don't reach for wfuzz unless you have a specific reason.

### When to Actually Use Gobuster

Despite the above, gobuster still has its place:

1. **Quick single-level content sweeps** where you want clean output
2. **DNS brute-forcing** as a complement to passive enumeration
3. **Vhost discovery** when you need it without ffuf's flag complexity
4. **S3/GCS enumeration** as a quick check without installing cloud-specific tools
5. **Scripted pipelines** where gobuster's deterministic output format is easier to parse than ffuf's
6. **CTFs and HTB** where it's the "default expected tool" and the targets are small enough that speed/recursion don't matter

For real engagements with modern web applications, ffuf (for fuzzing) + feroxbuster (for recursive content discovery) + subfinder (for subdomains) is a more capable toolkit than gobuster alone. But gobuster remains fine for quick, simple tasks.

---

## Practical Notes

**Wildcard responses are the #1 cause of garbage output.** Many servers return 200 for every URL (soft 404s), or return the same page with a different status code for everything. Gobuster detects some wildcards automatically in DNS mode, but dir mode will happily report 10,000 "findings" if the target returns 200 for every path. Always establish a baseline: `curl -s https://target/definitely-does-not-exist-$(date +%s)` and note the response size/status, then use `--exclude-length` to filter it out. If the soft-404 response varies in size (dynamic content), use ffuf with `-fr` regex filtering or feroxbuster with its auto-filter.

**Thread count matters more than you think.** Default 10 threads is conservative. Against a beefy CDN-backed target, `-t 50` is fine. Against a small internal service or an IoT device, 10 is already too many and you'll crash things. Against a WAF'd target, anything above `-t 5` with `--delay 200ms` will get you rate-limited and blackholed within seconds. Start conservative and scale up, not the other way around.

**TLS issues are a common silent failure mode.** Internal services with self-signed certs will silently fail without `-k`. If gobuster reports "connection refused" or "TLS error" on a target you know is up, add `-k`. For targets with expired or mismatched certs behind TLS-intercepting proxies, this is doubly important.

**The `--exclude-length` flag accepts ranges.** `--exclude-length 1200-1400` excludes any response between 1200 and 1400 bytes. Useful when the 404 page has slightly variable content (timestamps, request IDs in the body) that makes the length fluctuate.

**Output to file early, always.** Gobuster scans can take hours on big wordlists. If your terminal dies, your SSH session drops, or you hit Ctrl+C by accident without `-o`, the results are gone. Always use `-o` from the start, and consider wrapping in `tmux` or `screen` for long scans.

**Don't point gobuster at the apex when the app is on a subpath.** If the application is served at `https://target/app/`, scanning `https://target/` with a directory wordlist will mostly return 404s and miss everything important. Point it at the actual application root. This sounds obvious but it's a common mistake when the target has `/api/`, `/admin/`, or similar subpaths housing the real application.

**Scanning behind auth is finicky.** Cookie-based auth works with `-c "sessionid=xyz"` but sessions expire mid-scan, causing the rest of the run to hit login redirects and produce false 302s. For long scans against authenticated areas, you need to either (a) use a long-lived session, (b) script session refresh, or (c) scan through Burp with session handling rules active. For the proxy approach: `--proxy http://127.0.0.1:8080` and let Burp handle auth.

**WAFs see gobuster immediately.** Cloudflare, Akamai, AWS WAF, and Imperva all have detection for high-rate directory brute-forcing and flag it as "directory enumeration" within the first few dozen requests. Once flagged, you'll start seeing 403s or 429s from the WAF instead of the origin, and every subsequent result is garbage. Either (a) scan very slowly with `--delay 1s -t 3` and hope to stay under the threshold, (b) accept detection and scan fast to get what you can before being blocked, or (c) scan from disposable infrastructure. For serious WAF evasion, the right move is not gobuster at all — use Burp's Content Discovery module which integrates with your existing session and handles some evasion, or do targeted manual enumeration.

**Gobuster does not understand the application.** It sends requests and matches on status/size. It won't notice that `/admin/` redirects to `/login/` and therefore probably exists. It won't notice that `/api/v1/users/1` returns different content than `/api/v1/users/999999`. It won't chain findings. Treat gobuster output as raw data requiring human interpretation, not as a finished enumeration.

**Build tuned wordlists as you work.** Every engagement reveals organization-specific naming conventions (`acme-api-v2`, `acme_admin_portal`, etc.). When you find a pattern, add variations to a custom wordlist and rerun. The second pass with a tuned list usually finds things the generic lists missed. Save these per-engagement lists; over time you'll accumulate a personal wordlist collection that outperforms anything shipped with SecLists for the kinds of targets you work on regularly.

**Don't forget discovered paths from other tools.** If katana, gau, or waybackurls found `/legacy/old-api/v1/users` on the target, add `legacy`, `old-api`, `v1`, and `users` to your gobuster wordlist. Historical recon data feeds gobuster's brute-force — the combination is much more effective than either alone.

**For CTFs specifically:** gobuster with `common.txt` or `raft-small-directories.txt` + `-x php,html,txt,bak` is the default first move on any web box and usually finds what you need. CTF targets are small, wildcard detection isn't an issue, and the tooling convention favors gobuster. For real-world targets, most of this advice doesn't apply — the environment is too different.

**Legal reminder:** brute-forcing directories generates a lot of traffic that looks exactly like an attack (because it is one, technically). On anything you don't own, have written scope and keep the wordlist reasonable. Running `directory-list-2.3-medium.txt` (220k entries) against a target produces 220k log entries in their access logs and will absolutely trigger investigation. Be deliberate about wordlist size and scope.