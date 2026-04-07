# Nmap Templates, Cheat Sheet, and Practical Notes

A working reference covering staged scan templates for common target classes (IoT, web servers, routers, iPhones, Windows, macOS, Linux), an options cheat sheet, and honest notes on what actually works against modern detection.

All templates assume you've set `TARGET=<ip-or-cidr>` and are running as root. `db_nmap` (Metasploit) accepts the same syntax, just remember that **nmap only accepts one `-p` flag**, so TCP and UDP ports must be combined as `-p T:...,U:...` rather than `-pT:... -pU:...`.

---

## Table of Contents

1. [IoT Devices](#iot-devices)
2. [Web Servers](#web-servers)
3. [Routers / Network Gear](#routers--network-gear)
4. [iPhones / iOS](#iphones--ios)
5. [Windows Endpoints](#windows-endpoints)
6. [macOS / MacBooks](#macos--macbooks)
7. [Linux Devices](#linux-devices)
8. [Options Cheat Sheet](#options-cheat-sheet)
9. [NSE Reference](#nse-reference)
10. [Practical Reality of Evasion](#practical-reality-of-evasion)

---

## IoT Devices

**Target notes.** IoT gear is fragile. Cheap MCUs run minimal TCP/IP stacks that crash under aggressive timing or unusual flag combinations you can brick a smart bulb or knock an IP camera offline with `-T4` and a parallel port count above 100. Most interesting IoT services live on UDP (mDNS, SSDP, CoAP, SNMP) and are missed entirely by TCP-only sweeps. Expect to see vendor-specific high ports (Dahua 37777, Hikvision 8000, Realtek 9999, UPnP dynamic 49152+), and expect MQTT brokers, TR-069 CWMP endpoints, and unauthenticated HTTP admin panels. The Mosquitto-on-the-internet pattern remains depressingly common on consumer gateways.

**Stage 1   Initial Probe**
```bash
nmap -sS -Pn -T2 --max-retries 1 --min-rate 50 --max-rate 150 \
  -p 22,23,53,80,443,554,1883,5000,5353,8080,8443,8883,9999,49152 \
  -f --data-length 24 -g 53 \
  -oA iot_stage1 $TARGET
```

**Stage 2   Extensive Enumeration**
```bash
nmap -sS -sU -Pn -T2 --max-retries 2 \
  -p T:21,22,23,80,443,554,1883,5000,5683,7547,8080,8443,8883,9999,37777,49152-49157,U:53,67,123,161,1900,5353,5683 \
  -sV --version-intensity 4 \
  -f --data-length 24 -D RND:5 \
  -oA iot_stage2 $TARGET
```

**Stage 3   Vulnerability & Metadata**
```bash
nmap -sS -sU -Pn -T2 \
  -p T:23,80,443,554,1883,7547,8883,37777,49152,U:161,1900,5353,5683 \
  -sV -O --osscan-limit \
  --script "(default or discovery or vuln) and not (brute or dos or intrusive)" \
  --script "upnp-info,broadcast-upnp-info,mqtt-subscribe,coap-resources,rtsp-url-brute,snmp-info,snmp-sysdescr,ssl-cert,ssl-enum-ciphers,http-default-accounts,http-title,realtek-backdoor" \
  --script-args "mqtt-subscribe.topic=#" \
  -oA iot_stage3 $TARGET
```

The MQTT `#` wildcard subscribes to every topic on the broker   devastating against unauthenticated brokers, which is exactly the misconfig you find on consumer gateways. Excludes brute and dos categories because IoT crashes.

---

## Web Servers

**Target notes.** Web servers can take punishment, so timing goes up. Focus shifts to virtual hosts, TLS posture, HTTP methods, exposed admin panels, and CMS fingerprinting. Modern WAFs (Cloudflare, Akamai, AWS WAF) will detect nmap NSE scripts and rate-limit or blackhole your IP within seconds. The right answer against WAF-protected targets is to do reconnaissance via Censys/Shodan first (they've already scanned the host from their own infrastructure) and then send a small number of targeted probes from disposable infrastructure. Nmap is mostly useful here for service detection on origin servers you've found out-of-band, and for the deep TLS audit scripts.

**Stage 1   Initial Probe**
```bash
nmap -sS -Pn -T3 --min-rate 300 \
  -p 80,443,8000,8008,8080,8081,8443,8888,9000,9090,9443 \
  -g 443 --data-length 16 \
  -oA web_stage1 $TARGET
```

**Stage 2   Extensive Enumeration**
```bash
nmap -sS -Pn -T3 --max-retries 2 \
  -p 80,280,443,591,593,832,981,1010,1311,2082,2087,2095,2096,2480,3000,3128,3333,4243,4567,4711,4712,4993,5000,5104,5108,5800,6543,7000,7396,7474,8000,8001,8008,8014,8042,8069,8080-8090,8181,8222,8243,8280,8281,8333,8443,8500,8834,8880,8888,8983,9000,9043,9060,9080,9090,9091,9200,9443,9800,9981,12443,16080,18091,18092,20720,28017 \
  -sV --version-intensity 7 \
  -D RND:8 --data-length 32 \
  -oA web_stage2 $TARGET
```

Includes Tomcat, JBoss, Jenkins, Elasticsearch, CouchDB, Mongo admin, cPanel, Plesk.

**Stage 3   Vulnerability & Metadata**
```bash
nmap -sS -Pn -T3 -p 80,443,8000,8080,8443,8888,9200 \
  -sV -sC \
  --script "http-enum,http-headers,http-methods,http-title,http-server-header,http-robots.txt,http-sitemap-generator,http-security-headers,http-cors,http-cookie-flags,http-trace,http-shellshock,http-slowloris-check,http-vuln-*,http-wordpress-enum,http-wordpress-users,http-drupal-enum,http-git,http-config-backup,http-backup-finder,http-php-version,http-default-accounts,http-auth-finder,ssl-cert,ssl-enum-ciphers,ssl-heartbleed,ssl-poodle,ssl-ccs-injection,ssl-dh-params,tls-alpn,tls-nextprotoneg,http-jsonp-detection,http-open-redirect" \
  --script-args "http.useragent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36,http-methods.test-all" \
  -oA web_stage3 $TARGET
```

The custom UA defeats lazy User-Agent blocking. `http-enum` alone hits hundreds of common paths and will absolutely show up on any WAF dashboard.

---

## Routers / Network Gear

**Target notes.** Routers usually expose management on multiple protocols (SSH, Telnet, HTTP/S admin, SNMP, NETCONF, TR-069, vendor APIs). SNMP with default community strings (`public`, `private`, `cisco`) is still everywhere on consumer and SMB gear, and it's the highest-yield finding when present `snmp-interfaces` and `snmp-netstat` will hand you the routing table and connection list for free. Be careful with core routers: scanning can trip control-plane policing and generate alerts faster than against endpoints. Vendor backdoors (Cisco Smart Install on 4786, Netgear on 32764, various Realtek bugs) are still in the wild on unpatched gear.

**Stage 1  Initial Probe**
```bash
nmap -sS -Pn -T2 --max-retries 1 --min-rate 100 \
  -p 22,23,53,80,179,443,830,2000,4786,5060,7547,8080,8291,8443 \
  -f -g 53 --data-length 24 \
  -oA router_stage1 $TARGET
```

**Stage 2   Extensive Enumeration**
```bash
nmap -sS -sU -Pn -T2 --max-retries 2 \
  -p T:22,23,53,80,88,179,443,514,515,623,636,830,1080,1723,2000,2601,2604,3128,3389,4786,5060,5353,6666,7547,8000,8080,8181,8291,8443,8728,8729,9100,10000,32764,U:53,67,68,69,123,161,162,500,514,520,623,1701,1900,4500,5060 \
  -sV --version-intensity 6 \
  -O --osscan-guess \
  -f -D RND:6 -g 53 \
  -oA router_stage2 $TARGET
```

Adds IPMI (623), routing daemons (Quagga/FRR 2601/2604), IKE/IPsec, RIP, syslog, TFTP, the Netgear backdoor (32764), Mikrotik API.

**Stage 3   Vulnerability & Metadata**
```bash
nmap -sS -sU -Pn -T2 \
  -p T:22,23,80,443,161,4786,7547,8291,U:161,623,500 \
  -sV -O \
  --script "snmp-info,snmp-sysdescr,snmp-interfaces,snmp-netstat,snmp-processes,snmp-brute,snmp-hh3c-logins,ssh2-enum-algos,ssh-auth-methods,ssh-hostkey,telnet-encryption,http-default-accounts,http-auth-finder,http-title,http-vuln-cve2014-3704,ssl-cert,ike-version,ipmi-version,ipmi-cipher-zero,tftp-enum,cisco-siet,mikrotik-routeros-brute" \
  --script-args "snmpcommunity=public,snmp-brute.communitiesdb=/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt" \
  -oA router_stage3 $TARGET
```

`ipmi-cipher-zero` finds the IPMI 2.0 auth bypass still present on a startling amount of server BMCs and out-of-band management cards.

---

## iPhones / iOS

**Target notes.** iOS is the hardest consumer target to fingerprint with nmap. Lockdown mode and the default firewall drop almost everything. Most useful info comes from mDNS/Bonjour, AirDrop/AirPlay, and the handful of ports Apple opens for continuity features. Don't expect OS detection to work Apple's stack and aggressive filtering defeat it. The single most reliable iOS indicator is TCP 62078 (`lockdownd`, the iTunes/usbmuxd sync service). Honest take: passive sniffing on the broadcast domain (mDNS, SSDP, DHCP) tells you more about iPhones than any active scan ever will, because iOS broadcasts device name and advertised services on a regular cadence.

**Stage 1   Initial Probe**
```bash
nmap -sS -Pn -T2 --max-retries 1 --min-rate 50 \
  -p 62078,5353,7000,49152,3689,5223,8009,5000 \
  -f -g 5353 --data-length 24 \
  -oA ios_stage1 $TARGET
```

**Stage 2   Extensive Enumeration**
```bash
nmap -sS -sU -Pn -T2 --max-retries 2 \
  -p T:62078,5353,7000,7100,49152-49160,3689,5223,8009,5000,U:5353,5298,1900,137 \
  -sV --version-intensity 3 \
  -f --data-length 24 -D RND:4 \
  -oA ios_stage2 $TARGET
```

**Stage 3   Metadata & Service Discovery**
```bash
# Pass A: mDNS / Bonjour discovery (broadcast)
nmap -sU -Pn -T2 -p 5353 \
  --script "dns-service-discovery,broadcast-dns-service-discovery,broadcast-bonjour" \
  -oA ios_stage3_mdns $TARGET

# Pass B: targeted service banners
nmap -sS -Pn -T2 -p 62078,7000,3689,5223,8009 \
  -sV --script "banner,ssl-cert,ssl-enum-ciphers,daap-get-library,airplay-info" \
  -oA ios_stage3_svc $TARGET
```

There's no real "vuln scan" stage for iOS over the network   the attack surface is too small. Anything interesting comes from the lockdownd banner, the TLS cert on 7000, or the device name leaked via mDNS.

---

## Windows Endpoints

**Target notes.** Windows is the richest nmap target on a typical network   SMB, RPC, NetBIOS, WinRM, RDP, and AD services all leak useful metadata. EDR (Defender for Endpoint, CrowdStrike, SentinelOne) will see you immediately on managed endpoints regardless of timing flags. On internal pentests, assume detection and optimize for information yield rather than stealth. The highest-value unauth info leaks are `smb-os-discovery` (returns exact build, domain, FQDN, system time) and `rdp-ntlm-info` / `http-ntlm-info` (returns hostname, domain, DNS   Microsoft has never fixed this). EternalBlue (`ms17-010`) is still found on internal networks more often than it should be.

**Stage 1   Initial Probe**
```bash
nmap -sS -Pn -T3 --min-rate 200 \
  -p 135,139,445,3389,5040,5357,5985,5986,47001,49152-49157 \
  -g 88 --data-length 16 \
  -oA win_stage1 $TARGET
```

**Stage 2   Extensive Enumeration**
```bash
nmap -sS -sU -Pn -T3 --max-retries 2 \
  -p T:21,22,53,80,88,135,139,389,443,445,464,593,636,1433,2179,3268,3269,3389,5040,5357,5722,5985,5986,8080,9389,47001,49152-49157,U:53,67,88,123,137,138,389,464,500,1900,4500,5353,5355 \
  -sV --version-intensity 7 \
  -O --osscan-guess \
  -D RND:5 --data-length 32 \
  -oA win_stage2 $TARGET
```

**Stage 3   Vulnerability & Metadata**
```bash
nmap -sS -Pn -T3 -p 88,135,139,389,445,3389,5985 \
  -sV -O \
  --script "smb-os-discovery,smb-security-mode,smb2-security-mode,smb2-time,smb2-capabilities,smb-enum-shares,smb-enum-sessions,smb-enum-users,smb-enum-domains,smb-enum-groups,smb-enum-services,smb-protocols,smb-vuln-ms17-010,smb-vuln-cve-2017-7494,smb-double-pulsar-backdoor,msrpc-enum,rdp-enum-encryption,rdp-ntlm-info,rdp-vuln-ms12-020,ldap-rootdse,ldap-search,krb5-enum-users,nbstat,http-ntlm-info,ssl-cert" \
  --script-args "krb5-enum-users.realm='CONTOSO.LOCAL',ldap.username='',smbdomain=WORKGROUP" \
  -oA win_stage3 $TARGET
```

For domain controllers specifically, add `--script "ldap-search,dns-srv-enum"` and target ports 88/389/636/3268.

---

## macOS / MacBooks

**Target notes.** macOS sits between iOS (locked) and Linux (open). The built-in firewall is application-aware and off by default, so visible attack surface depends entirely on what the user has enabled (Screen Sharing, File Sharing, Remote Login, AirDrop, AirPlay Receiver, content caching). Bonjour is always chatty and gives up an unreasonable amount of identifying info   device model, macOS version, sometimes username. Apple replaced AFP with SMB years ago but legacy AFP (548) still appears. TCP 62078 may show up on Macs that have ever synced an iPhone (lockdownd).

**Stage 1   Initial Probe**
```bash
nmap -sS -Pn -T3 --min-rate 150 \
  -p 22,88,445,548,631,5000,5353,5900,7000,49152,62078 \
  -g 5353 --data-length 16 \
  -oA mac_stage1 $TARGET
```

**Stage 2   Extensive Enumeration**
```bash
nmap -sS -sU -Pn -T3 --max-retries 2 \
  -p T:22,80,88,111,443,445,515,548,631,3283,3689,4488,5000,5009,5222,5223,5269,5298,5353,5900,5988,6942,7000,8021,8080,8443,49152-49156,62078,U:53,67,88,111,123,137,138,514,5353,5355 \
  -sV --version-intensity 6 \
  -O --osscan-guess \
  -D RND:4 --data-length 24 \
  -oA mac_stage2 $TARGET
```

**Stage 3   Metadata & Vulnerability**
```bash
nmap -sS -sU -Pn -T3 -p T:22,445,548,631,5900,7000,U:5353 \
  -sV -O \
  --script "ssh2-enum-algos,ssh-auth-methods,ssh-hostkey,smb-os-discovery,smb2-security-mode,smb-protocols,afp-serverinfo,afp-showmount,cups-info,cups-queue-info,vnc-info,realvnc-auth-bypass,dns-service-discovery,airplay-info,ssl-cert,banner" \
  -oA mac_stage3 $TARGET
```

`afp-serverinfo` returns the model identifier (e.g. `MacBookPro18,3`), macOS version, and machine signature. `dns-service-discovery` over mDNS pulls advertised services with rich metadata.

---

## Linux Devices

**Target notes.** Linux is the most variable target class   a hardened server has nothing but SSH, a desktop might have CUPS/Avahi/SSH and a dev server on 8000, a NAS has SMB/NFS/AFP plus a half-dozen web admin panels, a Kubernetes node has the kubelet API and etcd. The high-value findings are almost always misconfigured services bound to all interfaces with default or no auth: unauthenticated Redis (6379), MongoDB (27017), Elasticsearch (9200), Docker daemon (2375   instant root), exposed `.git` directories, NFSv3 with `no_root_squash`, and rsync modules without auth. NTP `monlist` and DNS open recursors are the classic amplification checks.

**Stage 1   Initial Probe**
```bash
nmap -sS -Pn -T3 --min-rate 200 \
  -p 22,25,53,80,111,443,631,2049,3306,5432,5353,5900,6000,8000,8080 \
  -g 53 --data-length 16 \
  -oA linux_stage1 $TARGET
```

**Stage 2   Extensive Enumeration**
```bash
nmap -sS -sU -Pn -T3 --max-retries 2 \
  -p T:21,22,23,25,53,69,79,80,88,110,111,113,119,123,135,139,143,161,179,389,443,445,465,514,515,587,631,636,873,902,993,995,1080,1194,1433,1521,2049,2181,2375,2376,3000,3128,3268,3306,3389,4369,5000,5060,5222,5269,5353,5432,5601,5672,5900,5984,5985,6000,6379,6443,6660-6669,7001,8000,8008,8080,8081,8086,8088,8089,8333,8443,8500,8888,9000,9042,9092,9200,9300,9418,9999,10000,11211,15672,25565,27017,27018,27019,28017,50000,50070,U:53,67,68,69,111,123,137,138,161,500,514,520,623,1900,2049,4500,5353 \
  -sV --version-intensity 7 \
  -O --osscan-guess \
  -D RND:5 --data-length 32 \
  -oA linux_stage2 $TARGET
```

**Stage 3   Vulnerability & Metadata**
```bash
nmap -sS -sU -Pn -T3 \
  -p T:22,25,80,111,139,443,445,873,2049,2375,3306,5432,6379,8080,9200,11211,27017,U:53,123,161,2049 \
  -sV -O \
  --script "ssh2-enum-algos,ssh-auth-methods,ssh-hostkey,smtp-commands,smtp-open-relay,smtp-enum-users,rpcinfo,nfs-ls,nfs-showmount,nfs-statfs,smb-os-discovery,smb-enum-shares,smb-protocols,rsync-list-modules,docker-version,mysql-info,mysql-empty-password,mysql-users,ms-sql-info,pgsql-brute,redis-info,mongodb-info,mongodb-databases,memcached-info,elasticsearch,http-elasticsearch-head,couchdb-databases,couchdb-stats,http-title,http-headers,http-methods,http-enum,http-vuln-*,ssl-cert,ssl-enum-ciphers,ssl-heartbleed,snmp-info,ntp-info,ntp-monlist,dns-recursion,dns-cache-snoop" \
  --script-args "mongodb-databases.bypassauth=true" \
  -oA linux_stage3 $TARGET
```

---

## Options Cheat Sheet

### Host Discovery

| Flag | Purpose | When to use |
|---|---|---|
| `-sn` | Ping sweep, no port scan | Initial network inventory |
| `-Pn` | Skip discovery, treat all as up | Targets blocking ICMP; cloud hosts; CTFs |
| `-PS<ports>` | TCP SYN discovery probe | When ICMP filtered; `-PS443,80` reliable |
| `-PA<ports>` | TCP ACK discovery probe | Bypassing stateless firewalls |
| `-PU<ports>` | UDP discovery probe | Targets with UDP-only services |
| `-PE` / `-PP` / `-PM` | ICMP echo / timestamp / netmask | Timestamp sometimes passes filters |
| `-PR` | ARP ping (LAN only) | Always default on local segments |
| `-n` | No DNS resolution | Speed; OPSEC (no PTR queries) |
| `-R` | Force reverse DNS on all | Inventory work where hostnames matter |

### Scan Types

| Flag | Name | Notes |
|---|---|---|
| `-sS` | TCP SYN (half-open) | Default as root; fast, low log footprint |
| `-sT` | TCP connect | Required when unprivileged or via proxy/pivot |
| `-sU` | UDP scan | Slow but essential; pair with `--top-ports 100` |
| `-sA` | TCP ACK | Maps firewall rules; doesn't determine open/closed |
| `-sW` | TCP window | Niche, legacy stack quirk |
| `-sM` | TCP Maimon | Historical |
| `-sN` / `-sF` / `-sX` | Null / FIN / Xmas | Bypasses some stateless filters; fails on Windows |
| `-sY` | SCTP INIT | Telecom/signaling networks |
| `-sZ` | SCTP COOKIE-ECHO | Stealthier SCTP variant |
| `-sO` | IP protocol scan | Fingerprints routers/VPN concentrators |
| `-sI <zombie>` | Idle scan | True blind scan via third party |
| `--scanflags <flags>` | Custom TCP flags | IDS rule testing, evasion experiments |

### Port Specification

| Flag | Meaning |
|---|---|
| `-p 22,80,443` | Specific ports |
| `-p 1-65535` or `-p-` | All ports |
| `-p T:80,443,U:53` | TCP and UDP combined (single `-p` flag only) |
| `-F` | Fast scan (top 100 ports) |
| `--top-ports <N>` | Top N most common ports |
| `-r` | Sequential (don't randomize) |
| `--port-ratio <0-1>` | Ports more common than ratio |

### Service / Version / OS Detection

| Flag | Effect |
|---|---|
| `-sV` | Service version detection |
| `--version-intensity 0-9` | Probe aggression (default 7) |
| `--version-light` | Intensity 2 |
| `--version-all` | Intensity 9 |
| `-O` | OS fingerprinting |
| `--osscan-limit` | Only fingerprint promising hosts |
| `--osscan-guess` | Aggressive matching when uncertain |
| `-A` | Aggressive: `-sV -O -sC --traceroute` |
| `-sC` | Run default NSE scripts |

### Timing

| Flag | Profile | Use case |
|---|---|---|
| `-T0` | Paranoid | IDS evasion, very slow |
| `-T1` | Sneaky | IDS evasion, slow |
| `-T2` | Polite | Fragile targets (IoT, OT) |
| `-T3` | Normal | Default |
| `-T4` | Aggressive | Reliable LANs |
| `-T5` | Insane | Fast LANs, accuracy loss |
| `--min-rate <pps>` | Floor packet rate | Predictable for large scans |
| `--max-rate <pps>` | Ceiling packet rate | Avoid saturating links |
| `--max-retries <N>` | Probe retry count | Lower = faster, less accurate |
| `--host-timeout <time>` | Give up on slow hosts | `30m`, `1h` |
| `--scan-delay <time>` | Wait between probes | `--scan-delay 1s` for IDS evasion |

### Evasion (see practicality notes below)

| Flag | Purpose | Actually works? |
|---|---|---|
| `-f` / `--mtu <n>` | Fragment packets | Rarely; modern firewalls reassemble |
| `-D <decoys>` | Decoy source IPs | Only against humans reading logs |
| `-S <ip>` | Spoof source IP | Requires return path control |
| `-g <port>` / `--source-port <port>` | Spoof source port | Against misconfigured stateless ACLs only |
| `--data-length <n>` | Pad packets | Defeats some old size-based sigs |
| `--badsum` | Bad checksums | Reveals inline inspection |
| `--ttl <n>` | Custom TTL | Niche |
| `--ip-options <opts>` | IP options | Niche |
| `--randomize-hosts` | Shuffle target order | Mild help against rate triggers |
| `--spoof-mac <mac>` | Spoof MAC (LAN) | Useful on L2 segments |
| `-e <iface>` | Specify interface | Multi-NIC hosts, pivoting |

### Output

| Flag | Format |
|---|---|
| `-oN <file>` | Normal (human-readable) |
| `-oX <file>` | XML (parseable) |
| `-oG <file>` | Grepable |
| `-oA <basename>` | All three formats |
| `-oS` | Script kiddie (joke output) |
| `-v` / `-vv` | Verbosity |
| `-d` / `-dd` | Debug |
| `--reason` | Show why each port classified that way |
| `--open` | Show only open ports |
| `--packet-trace` | Print every packet sent/received |
| `--stats-every <time>` | Periodic progress |
| `--resume <file>` | Resume aborted scan |

### Misc

| Flag | Meaning |
|---|---|
| `-iL <file>` | Read targets from file |
| `-iR <n>` | N random targets (use `0` for forever) |
| `--exclude <hosts>` | Exclude from target list |
| `--excludefile <file>` | Exclude from file |
| `-6` | IPv6 |
| `--send-eth` / `--send-ip` | Force ethernet/raw IP |
| `--privileged` / `--unprivileged` | Override privilege detection |
| `-V` | Version info |
| `-h` | Help |

---

## NSE Reference

**Categories:** `auth`, `broadcast`, `brute`, `default`, `discovery`, `dos`, `exploit`, `external`, `fuzzer`, `intrusive`, `malware`, `safe`, `version`, `vuln`.

**Common selectors:**
```bash
--script default                          # same as -sC
--script vuln                             # all vuln-category scripts
--script "default or safe"                # boolean expressions
--script "http-* and not brute"           # wildcards + exclusion
--script "not (dos or brute)"             # exclude dangerous categories
--script smb-enum-shares,smb-enum-users   # explicit list
--script-args "user=admin,pass=admin"     # script arguments
--script-args-file args.txt               # arguments from file
--script-help <name>                      # docs for a script
--script-trace                            # debug NSE execution
--script-updatedb                         # rebuild script database
```

**High-value scripts worth knowing by name:**

- **Discovery:** `dns-service-discovery`, `broadcast-bonjour`, `broadcast-upnp-info`, `nbstat`, `snmp-sysdescr`, `rpcinfo`
- **TLS:** `ssl-cert`, `ssl-enum-ciphers`, `ssl-heartbleed`, `ssl-poodle`, `ssl-ccs-injection`, `ssl-dh-params`
- **SMB:** `smb-os-discovery`, `smb-enum-shares`, `smb-enum-users`, `smb-vuln-ms17-010`, `smb2-security-mode`
- **HTTP:** `http-enum`, `http-title`, `http-methods`, `http-headers`, `http-default-accounts`, `http-git`, `http-ntlm-info`
- **Database:** `mysql-info`, `mysql-empty-password`, `mongodb-databases`, `redis-info`, `pgsql-brute`, `ms-sql-info`
- **NFS / RPC:** `nfs-showmount`, `nfs-ls`, `rpcinfo`
- **Routing / mgmt:** `snmp-interfaces`, `snmp-netstat`, `snmp-brute`, `ipmi-cipher-zero`, `cisco-siet`
- **Auth:** `ssh-auth-methods`, `ssh-hostkey`, `ssh2-enum-algos`, `krb5-enum-users`

---

## Practical Reality of Evasion

The honest version, since the cheat sheet above lists evasion flags that mostly don't work the way folklore says they do.

### Why most nmap "evasion" doesn't defeat modern detection

Modern detection isn't signature-based the way 2005-era IDS was. Suricata, Zeek, Corelight, and the EDR/NDR vendors detect scanning **behaviorally**: a single source touching N destinations or N ports inside a time window, regardless of packet shape. Fragmenting, decoy-spraying, padding, and source-port spoofing don't change the connection graph   and the connection graph is what gets you caught.

- **Fragmentation (`-f`, `--mtu`)**: every modern stateful firewall and IDS reassembles before inspection. Hasn't been a real evasion technique since around 2008.
- **Decoys (`-D`)**: only fool humans reading raw logs. Any SIEM correlating NetFlow, EDR telemetry, or DHCP leases trivially identifies the real source because decoys don't generate return traffic and timing correlation gives them up.
- **Slow timing (`-T0`, `-T1`)**: helps against rate-based triggers, useless against threshold-based ones. If the rule is "any source touching >50 unique destinations in 24 hours," scanning slowly means getting caught at hour 23 instead of minute 5   and giving the SOC more time to act on the early hits.
- **Source port spoofing (`-g 53`, `-g 88`)**: defeats one specific class of misconfiguration   stateless ACLs that whitelist "trusted" source ports. Stateful firewalls (i.e., all of them since the early 2000s) don't care. Still occasionally useful against ancient gear and lazy cloud security group configs.
- **Idle scan (`-sI`)**: genuinely works against the *target's* logs because packets really come from the zombie. But finding a usable zombie with predictable IP IDs on the modern internet is hard, the scan is very slow, and any network-position telemetry between you and the zombie still sees you.

### What experienced operators actually do

**Don't scan from the attack host.** Recon happens from disposable infrastructure: throwaway VPS, residential proxies, compromised third parties, cloud functions in unexpected regions. The attack host stays clean. If a recon node burns, spin up another.

**Passive recon first, and it's almost always enough.** Censys, Shodan, BinaryEdge, FOFA, ZoomEye, Netlas, certificate transparency aggregators (crt.sh), Amass passive mode, SecurityTrails, DNSDumpster   they've already scanned the internet from their own infrastructure. You can build a complete external service inventory without sending a packet. By the time you actually need to touch a target, you know what you're aiming at and send three packets instead of three thousand.

**Scan small and targeted.** Real tradecraft isn't `nmap -p- -A`. It's "Shodan tells me 203.0.113.45 has nginx 1.18 on 443   let me hit just that port with just the checks I need." Low-volume targeted probes against specific ports look like background internet noise and are statistically invisible unless they trip a specific tripwire.

**Use protocols that look legitimate.** Full TCP connects to web ports (look like any other client), `openssl s_client` for certs, `curl` with a real UA, `dig` for DNS. The fingerprint that flags "nmap" is the *combination* of weird flags + many destinations + short window. Strip all three and you're indistinguishable from a curious user.

**Use better tools for specific jobs.** `masscan` and `zmap` for internet-scale discovery from infrastructure built for it. `naabu` for fast TCP discovery. `httpx` for web service ID. `nuclei` for templated vuln checks. `rustscan` as a fast frontend feeding nmap. Custom Go/Python sending exactly the packets you need. Nmap stays in the toolbox for service version detection and NSE   there's nothing better   but it's used surgically after broad recon is done elsewhere.

**Internal pentests: accept detection, optimize for speed.** Once inside, EDR will see you. The honest workflow is: get in, scan fast and loud to map the environment before someone responds, pivot, assume each foothold has a finite lifetime. Internal "stealth" usually means "scan from a host the SOC won't look at" (a printer, a forgotten dev box, an IoT device) rather than "make nmap quiet." Living-off-the-land replaces nmap entirely   `nltest`, `net view`, PowerShell AD cmdlets, BloodHound collectors   all of which generate traffic the SOC sees from real admins constantly.

**Abuse trusted positions.** The most reliable evasion is not being seen as an outsider. Scans from inside a VPN, a managed device, a CI/CD runner, or a cloud account with legitimate access blend in because the baseline already includes scanner-shaped traffic from those sources (vuln scanners, asset management, config drift checkers all generate nmap-shaped patterns on a schedule).

### What still occasionally works against weak targets

- **Source port 53 / 88 / 443 against misconfigured cloud security groups.** AWS SGs are stateful, but plenty of on-prem firewalls and appliance-based cloud setups have stateless rules.
- **Scanning from "trusted" cloud ranges (AWS, GCP, Azure).** Targets can't blanket-ban AWS without breaking real customers, so reputation filters are weaker.
- **IPv6.** Many orgs have IPv6 enabled by default on endpoints with zero IPv6 monitoring. Dual-stack hosts often have a free pass on the v6 side. Use `-6`.
- **Fragmentation against truly ancient inline IDS** and some ICS/SCADA inspection appliances that don't get updated.
- **Slow scans against networks with no SIEM correlation** (logs go to a file nobody reads). Most small businesses fall here.

### The mental model shift

Detection isn't a property of your packets, it's more of a property of the relationship between your behavior vs a  defender's baseline. Although Nmap evasion flags try to manipulate packet properties, modern detection will ignores packet properties and looks at relationships. The only real evasion is to (a) make your behavior match the baseline, (b) move your behavior to a vantage point where the baseline isn't observed, or (c) accept detection and outpace response.

Stage 1 is almost always "ask someone who already scanned" (Shodan/Censys). Stage 2 is "small targeted probes from disposable infrastructure." Nmap shows up in stage 3 or 4, against a tiny target list, doing the version detection and NSE scripting nothing else does as well.

### Useful exercise

Stand up Suricata with the ET Open ruleset and Zeek alongside it on a small network, then run every nmap "stealth" combination you can think of against a host on that network. Almost all of them generate alerts, and the few that don't still show clearly in Zeek's `conn.log` connection graph. It turns the abstract argument above into a very concrete one and is one of the more clarifying afternoons you can spend on this topic.

---

## General Workflow Reminders

- Always use `-oA` on real engagements. XML output feeds `nmap-parse-output`, Metasploit `db_import`, custom parsers.
- Add `--reason` when triaging false positives   tells you *why* nmap classified each port the way it did.
- Use `--stats-every 30s` on long scans to stay sane (lol)
- When pivoting through SOCKS or Meterpreter, you're stuck with `-sT` and lose most evasion options.
- For unknown subnets, the highest-yield first move on Windows is `smb-os-discovery` + `rdp-ntlm-info` against likely Windows ports   it gives you AD domain and hostname faster than anything else.
- For weird embedded gear, run `tcpdump` in parallel with the scan. Half the value is in unexpected responses, banner leaks, and mDNS chatter that nmap doesn't surface but the pcap shows clearly.
- `vuln`-category scripts are mostly old (CVEs from 2014–2017). Worth running for low hanging fruit but don't mistake "no vuln hits" for "not vulnerable." Pair with version output and manual CVE lookup.
- `db_nmap` quirk: nmap accepts only one `-p` flag. Combine TCP and UDP as `-p T:...,U:...` not `-pT:... -pU:...`.
