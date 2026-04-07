# Metasploit Auxiliary Modules: Target-Specific Reference & Cheat Sheet

A working reference for `auxiliary/` modules organized by target class, mirroring the nmap template structure. Auxiliary modules cover scanners, fuzzers, sniffers, spoofers, DoS, and admin helpers — everything in Metasploit that isn't a full exploit or post module. Paths are given without the `auxiliary/` prefix.

All examples assume you're in `msfconsole` with a workspace set (`workspace -a engagement1`) so results go into the database for later `hosts`, `services`, `vulns`, and `creds` queries.

---

## Table of Contents

1. [How Auxiliary Modules Work](#how-auxiliary-modules-work)
2. [IoT Devices](#iot-devices)
3. [Web Servers](#web-servers)
4. [Routers / Network Gear](#routers--network-gear)
5. [iPhones / iOS](#iphones--ios)
6. [Windows Endpoints](#windows-endpoints)
7. [macOS / MacBooks](#macos--macbooks)
8. [Linux Devices](#linux-devices)
9. [Cheat Sheet](#cheat-sheet)
10. [Practical Notes](#practical-notes)

---

## How Auxiliary Modules Work

Auxiliary modules live under `auxiliary/` and are grouped by function:

- `scanner/` — port, service, and vuln scanners (the bulk of what you'll use)
- `admin/` — authenticated admin actions, exploit-adjacent helpers
- `fuzzers/` — protocol fuzzers
- `sniffer/` — passive capture modules
- `spoof/` — LLMNR/NBNS/mDNS/ARP spoofing
- `dos/` — denial of service (rarely what you want)
- `gather/` — OSINT and info collection
- `analyze/` — password cracking helpers
- `server/` — rogue servers (capture creds, serve payloads, etc.)
- `client/` — client-side helpers
- `vsploit/` — traffic generators for testing IDS

Core workflow:
```
use auxiliary/scanner/smb/smb_version
show options
set RHOSTS 10.0.0.0/24
set THREADS 32
run
```

`RHOSTS` accepts CIDR, ranges (`10.0.0.1-50`), `file:targets.txt`, and workspace queries (`hosts -R` populates it from the db). `run` and `exploit` are interchangeable for auxiliary. Background with `run -j`. Everything writes to the database automatically when a workspace is active — `creds`, `services`, `notes`, `loot` all populate without extra effort.

---

## IoT Devices

**Target notes.** Metasploit's IoT coverage is thinner than its Windows coverage, but the modules that exist are high-value because IoT gear ships with known default creds and long-unpatched CVEs. Focus on MQTT enumeration, UPnP/SSDP discovery, SNMP with default communities, and vendor-specific modules (Dahua, Hikvision, D-Link, Netgear). Many IoT scanners are noisy — run them slowly with low `THREADS` to avoid crashing cheap stacks.

### Discovery & Enumeration

| Module | Purpose |
|---|---|
| `scanner/upnp/ssdp_msearch` | SSDP M-SEARCH discovery, enumerates UPnP devices |
| `scanner/sip/options` | SIP OPTIONS sweep, finds VoIP/SIP IoT devices |
| `scanner/snmp/snmp_enum` | Full SNMP enumeration with default community |
| `scanner/snmp/snmp_login` | SNMP community string brute-force |
| `scanner/mdns/query` | mDNS service query |
| `scanner/natpmp/natpmp_external_address` | NAT-PMP external addr disclosure |
| `scanner/rdp/rdp_scanner` | RDP discovery (some IoT panels) |

### MQTT

| Module | Purpose |
|---|---|
| `scanner/mqtt/connect` | Test MQTT broker connection (anon + auth) |

Metasploit's native MQTT coverage is limited — pair with `mosquitto_sub -h <host> -t '#' -v` for topic enumeration, which is the real gold.

### Vendor-Specific

| Module | Purpose |
|---|---|
| `scanner/misc/dlink_dir_300_615_info_disclosure` | D-Link info leak |
| `scanner/http/dlink_dir_session_cgi_http_login` | D-Link login bypass check |
| `scanner/http/dlink_user_agent_backdoor` | D-Link UA-triggered backdoor |
| `scanner/http/dahua_dvr_auth_bypass` | Dahua DVR unauth info leak |
| `scanner/http/hikvision_cve_2021_36260_rce_check` | Hikvision RCE check |
| `scanner/http/netgear_enum` | Netgear device enumeration |
| `scanner/http/wemo_apcagent_probe` | Belkin WeMo discovery |
| `admin/http/foreman_openstack_satellite_priv_esc` | Satellite/Foreman priv esc |

### Common IoT Workflow

```
workspace -a iot_engagement
use auxiliary/scanner/upnp/ssdp_msearch
set RHOSTS 10.0.0.0/24
set THREADS 16
run

use auxiliary/scanner/snmp/snmp_login
set RHOSTS 10.0.0.0/24
set PASS_FILE /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt
set THREADS 16
run

use auxiliary/scanner/snmp/snmp_enum
set RHOSTS file:hosts_with_snmp.txt
run

use auxiliary/scanner/mqtt/connect
set RHOSTS 10.0.0.0/24
set RPORT 1883
run
```

---

## Web Servers

**Target notes.** This is where Metasploit's auxiliary modules are densest. HTTP scanners cover everything from generic fingerprinting and directory brute-forcing to CMS-specific enumeration, version detection, and hundreds of CVE checks. Most `scanner/http/*_version` modules are unauth-safe and fast. Vuln-check modules (usually suffixed `_check` or matching a CVE number) verify exploitability without actually popping the host. Pair with `nuclei` and `httpx` — Metasploit's web scanners are comprehensive but slow compared to the Go-based alternatives, so use MSF when you want the findings auto-ingested into the database and correlated with creds/sessions.

### Generic HTTP

| Module | Purpose |
|---|---|
| `scanner/http/http_version` | Server header / version fingerprinting |
| `scanner/http/title` | HTTP title enumeration |
| `scanner/http/dir_scanner` | Directory brute-force |
| `scanner/http/files_dir` | Common filename brute-force |
| `scanner/http/brute_dirs` | Directory brute-force (alternate) |
| `scanner/http/http_header` | Header enumeration |
| `scanner/http/options` | HTTP OPTIONS method enumeration |
| `scanner/http/trace` | TRACE method check |
| `scanner/http/webdav_scanner` | WebDAV detection |
| `scanner/http/robots_txt` | robots.txt enumeration |
| `scanner/http/http_put` | HTTP PUT method test |
| `scanner/http/ssl` | SSL/TLS info |
| `scanner/http/ssl_version` | SSL version / cipher enumeration |
| `scanner/http/cert` | Certificate enumeration |
| `scanner/http/open_proxy` | Open proxy detection |
| `scanner/http/enum_wayback` | Wayback machine URL enumeration (passive!) |

### CMS-Specific

| Module | Purpose |
|---|---|
| `scanner/http/wordpress_scanner` | WordPress detection |
| `scanner/http/wordpress_login_enum` | WP login brute-force |
| `scanner/http/wordpress_xmlrpc_login` | WP XML-RPC brute-force |
| `scanner/http/wp_login_brute` | Alternate WP brute |
| `scanner/http/wp_themes_active` | Active theme enumeration |
| `scanner/http/wp_plugins_fpd` | Plugin full-path disclosure |
| `scanner/http/joomla_version` | Joomla version detection |
| `scanner/http/joomla_plugins` | Joomla plugin enumeration |
| `scanner/http/drupal_views_user_enum` | Drupal user enumeration |

### Application Servers

| Module | Purpose |
|---|---|
| `scanner/http/tomcat_mgr_login` | Tomcat manager brute-force |
| `scanner/http/tomcat_enum` | Tomcat user enumeration |
| `scanner/http/jboss_vulnscan` | JBoss vuln scanner |
| `scanner/http/jboss_status` | JBoss status page info leak |
| `scanner/http/glassfish_login` | GlassFish admin brute-force |
| `scanner/http/jenkins_enum` | Jenkins enumeration |
| `scanner/http/jenkins_command` | Jenkins script console check |
| `scanner/http/coldfusion_version` | ColdFusion version |
| `scanner/http/coldfusion_locale_traversal` | CF directory traversal |

### High-Value Vuln Checks

| Module | CVE |
|---|---|
| `scanner/http/apache_mod_cgi_bash_env` | Shellshock (CVE-2014-6271) |
| `scanner/http/struts2_code_exec_check` | Struts2 RCE |
| `scanner/http/struts_code_exec_exception_delegator` | Struts CVE-2017-5638 check |
| `scanner/http/log4shell_scanner` | Log4Shell (CVE-2021-44228) |
| `scanner/http/confluence_webwork_ognl_injection` | Confluence OGNL |
| `scanner/http/exchange_proxylogon` | Exchange ProxyLogon |
| `scanner/http/exchange_proxyshell` | Exchange ProxyShell |
| `scanner/http/gitlab_user_enum` | GitLab user enumeration |

### Common Web Workflow

```
workspace -a web_engagement
use auxiliary/scanner/http/http_version
set RHOSTS file:web_targets.txt
set RPORT 443
set SSL true
set THREADS 32
run

use auxiliary/scanner/http/dir_scanner
set RHOSTS file:web_targets.txt
set DICTIONARY /usr/share/seclists/Discovery/Web-Content/common.txt
set THREADS 16
run

use auxiliary/scanner/http/wordpress_scanner
set RHOSTS file:wp_targets.txt
run

services -p 443 -R        # auto-populate RHOSTS from db
use auxiliary/scanner/http/log4shell_scanner
run
```

---

## Routers / Network Gear

**Target notes.** Router coverage in MSF is good for SNMP, SSH brute-force, and vendor-specific CVEs. SNMP with default communities remains the highest-yield finding on consumer and SMB gear — `snmp_enum` will hand you the full routing table, ARP cache, interface list, and sometimes the config. Cisco Smart Install (port 4786) and the various Mikrotik RouterOS issues are still encountered in the wild. Be careful on production gear: some of these modules can trigger control-plane alarms or, for older Cisco gear, cause a reload.

### SNMP (Highest Yield)

| Module | Purpose |
|---|---|
| `scanner/snmp/snmp_enum` | Full SNMP walk, system info, interfaces, routes |
| `scanner/snmp/snmp_login` | Community string brute-force |
| `scanner/snmp/snmp_enumshares` | Windows shares via SNMP |
| `scanner/snmp/snmp_enumusers` | User enumeration via SNMP |
| `scanner/snmp/snmp_set` | SNMP write test |
| `scanner/snmp/cisco_config_tftp` | Pull Cisco config via SNMP+TFTP |
| `scanner/snmp/cisco_upload_file` | Upload to Cisco via SNMP |
| `scanner/snmp/arris_dg950` | Arris DG950 info leak |

### Cisco

| Module | Purpose |
|---|---|
| `scanner/telnet/telnet_login` | Telnet brute-force (still works on old gear) |
| `scanner/ssh/ssh_login` | SSH brute-force |
| `scanner/http/cisco_ios_auth_bypass` | IOS HTTP auth bypass |
| `scanner/http/cisco_device_manager` | Cisco device manager info |
| `scanner/http/cisco_ironport_enum` | IronPort enumeration |
| `scanner/misc/cisco_smart_install` | Smart Install (CVE-2018-0171) check |
| `admin/cisco/cisco_secure_acs_bypass` | ACS bypass |
| `admin/cisco/cisco_asa_extrabacon` | ASA EXTRABACON (Shadow Brokers) |

### Mikrotik

| Module | Purpose |
|---|---|
| `scanner/mikrotik/mikrotik_api_login` | RouterOS API brute-force (port 8728) |
| `scanner/http/mikrotik_http_login` | WebFig login brute-force |
| `admin/http/mikrotik_file_read` | CVE-2018-14847 file read (WinBox) |

### Other Vendors

| Module | Purpose |
|---|---|
| `scanner/http/netgear_enum` | Netgear model/firmware enum |
| `admin/http/netgear_soap_password_extractor` | Netgear password extraction |
| `scanner/http/dlink_dir_300_615_info_disclosure` | D-Link info leak |
| `admin/http/dlink_dir_300_600_exec_noauth` | D-Link unauth exec |
| `scanner/http/linksys_wrt54gl_exec_noauth` | Linksys unauth exec |

### Common Router Workflow

```
workspace -a router_engagement
use auxiliary/scanner/snmp/snmp_login
set RHOSTS 10.0.0.0/24
set PASS_FILE /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt
set THREADS 16
run

use auxiliary/scanner/snmp/snmp_enum
set RHOSTS file:snmp_hosts.txt
run
# Check loot/ for extracted info

use auxiliary/scanner/ssh/ssh_login
set RHOSTS file:router_ssh.txt
set USER_FILE /usr/share/metasploit-framework/data/wordlists/unix_users.txt
set PASS_FILE /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt
set STOP_ON_SUCCESS true
set THREADS 8
run

use auxiliary/scanner/misc/cisco_smart_install
set RHOSTS file:cisco_hosts.txt
run
```

---

## iPhones / iOS

**Target notes.** There are essentially no iOS-specific auxiliary modules in Metasploit, and this reflects reality — iOS network-side attack surface is tiny and Apple patches fast. What MSF *can* do against iOS devices is generic discovery: mDNS scanning to find advertised services, SSDP, and banner grabs against any Bonjour-advertised HTTP endpoints (AirPlay, AirDrop helpers). The useful work against iOS is almost always passive: sniffing mDNS/Bonjour, capturing DHCP, and monitoring what the device broadcasts. For anything beyond that you're outside MSF's sweet spot.

### What Actually Applies

| Module | Purpose |
|---|---|
| `scanner/mdns/query` | Query mDNS services |
| `scanner/upnp/ssdp_msearch` | SSDP discovery |
| `scanner/http/http_version` | Banner grab on AirPlay port 7000 |
| `scanner/http/cert` | TLS cert on 7000, 62078 |
| `sniffer/psnuffle` | Passive credential sniffing |
| `server/capture/*` | Rogue service capture (see Windows section) |

### Common iOS Workflow

```
workspace -a ios_engagement
use auxiliary/scanner/mdns/query
set RHOSTS 10.0.0.0/24
run

use auxiliary/scanner/upnp/ssdp_msearch
set RHOSTS 10.0.0.0/24
run

# That's really about it for native MSF coverage.
# Supplement with: tcpdump -i en0 'port 5353 or port 1900'
```

Honest recommendation: for iOS recon, skip MSF entirely and run `avahi-browse -art` or `dns-sd -B _services._dns-sd._udp` instead. You'll get far more useful output.

---

## Windows Endpoints

**Target notes.** This is MSF's strongest area by a wide margin. SMB, RPC, NetBIOS, and AD enumeration modules cover every angle, and the spoofing modules (LLMNR/NBNS/mDNS) are the foundation of internal network attacks alongside Responder. The highest-value modules are `smb_version` (fast OS/build fingerprinting), `smb_enumshares` (unauth share listing when guest is enabled), `smb_login` (credential validation at scale — the number one way to find misused local admin passwords), and the `ms17_010` checker. For AD environments, `kerberos/` modules cover user enumeration, AS-REP roasting, and kerberoasting. LLMNR/NBNS poisoning via `spoof/` + `server/capture/` is the classic internal-network cred capture chain.

### SMB / Windows Core

| Module | Purpose |
|---|---|
| `scanner/smb/smb_version` | SMB version + OS + domain fingerprint |
| `scanner/smb/smb_enumshares` | Share enumeration |
| `scanner/smb/smb_enumusers` | User enumeration via RPC |
| `scanner/smb/smb_enumusers_domain` | Domain user enumeration |
| `scanner/smb/smb_login` | Credential validation / password spray |
| `scanner/smb/smb_lookupsid` | SID lookup / RID cycling |
| `scanner/smb/pipe_auditor` | Named pipe enumeration |
| `scanner/smb/pipe_dcerpc_auditor` | DCERPC pipe enumeration |
| `scanner/smb/smb_ms17_010` | EternalBlue vuln check |
| `scanner/smb/smb2` | SMB2 capability detection |
| `scanner/smb/psexec_loggedin_users` | Logged-in user enum (auth) |
| `admin/smb/psexec_ntdsgrab` | NTDS.dit extraction (auth) |
| `admin/smb/ms17_010_command` | MS17-010 command exec |

### NetBIOS / DCERPC / RPC

| Module | Purpose |
|---|---|
| `scanner/netbios/nbname` | NetBIOS name service query |
| `scanner/dcerpc/endpoint_mapper` | RPC endpoint enumeration |
| `scanner/dcerpc/hidden` | Hidden RPC service discovery |
| `scanner/dcerpc/management` | DCE/RPC management info |
| `scanner/dcerpc/tcp_dcerpc_auditor` | TCP RPC auditor |

### RDP

| Module | Purpose |
|---|---|
| `scanner/rdp/rdp_scanner` | RDP detection |
| `scanner/rdp/cve_2019_0708_bluekeep` | BlueKeep check |
| `scanner/rdp/ms12_020_check` | MS12-020 check |

### WinRM

| Module | Purpose |
|---|---|
| `scanner/winrm/winrm_auth_methods` | Enumerate WinRM auth methods |
| `scanner/winrm/winrm_login` | WinRM brute-force |
| `scanner/winrm/winrm_cmd` | Command exec (auth) |
| `scanner/winrm/winrm_wql` | WQL query (auth) |

### Active Directory / Kerberos

| Module | Purpose |
|---|---|
| `scanner/ldap/ldap_login` | LDAP bind brute-force |
| `gather/ldap_query` | LDAP query runner |
| `gather/ldap_hashdump` | Dump hashes from LDAP (auth) |
| `scanner/kerberos/kerberos_login` | Kerberos pre-auth brute |
| `gather/kerberos_enumusers` | Kerberos user enumeration |
| `admin/kerberos/get_ticket` | AS-REP / TGS-REP roasting |
| `admin/kerberos/ms14_068_kerberos_checksum` | MS14-068 check |
| `admin/kerberos/forge_ticket` | Golden/silver ticket forging |

### Poisoning / Capture (Internal LAN)

| Module | Purpose |
|---|---|
| `spoof/llmnr/llmnr_response` | LLMNR poisoning |
| `spoof/nbns/nbns_response` | NBT-NS poisoning |
| `spoof/mdns/mdns_response` | mDNS poisoning |
| `server/capture/smb` | Rogue SMB server, captures NetNTLM |
| `server/capture/http_ntlm` | Rogue HTTP server with NTLM auth |
| `server/capture/ftp` | Rogue FTP server |
| `server/capture/printjob_capture` | Rogue print server |

The canonical internal-LAN cred capture chain: run `spoof/llmnr/llmnr_response` + `spoof/nbns/nbns_response` + `server/capture/smb` concurrently as backgrounded jobs. Hashes flow into the database, then pipe to `hashcat -m 5600`.

### Common Windows Workflow

```
workspace -a win_engagement
use auxiliary/scanner/smb/smb_version
set RHOSTS 10.0.0.0/24
set THREADS 32
run

hosts -R                           # populate RHOSTS from db
use auxiliary/scanner/smb/smb_enumshares
run

use auxiliary/scanner/smb/smb_ms17_010
run

# Credential validation / password spray
use auxiliary/scanner/smb/smb_login
set RHOSTS file:win_hosts.txt
set SMBUser administrator
set PASS_FILE spray.txt
set THREADS 4                      # careful - lockouts
set VERBOSE false
run

# Internal LAN poisoning (run each as a job)
use auxiliary/spoof/llmnr/llmnr_response
set INTERFACE eth0
set SPOOFIP 10.0.0.50
run -j

use auxiliary/spoof/nbns/nbns_response
set INTERFACE eth0
set SPOOFIP 10.0.0.50
run -j

use auxiliary/server/capture/smb
set JOHNPWFILE /tmp/hashes.txt
run -j

jobs                               # verify all running
creds                              # check captures
```

---

## macOS / MacBooks

**Target notes.** Like iOS, MSF's macOS-specific auxiliary coverage is thin. macOS uses SMB for file sharing (same as Windows, so Windows SMB modules apply), Bonjour/mDNS for service discovery, AFP for legacy file sharing, VNC for screen sharing, and SSH for remote login. The Windows SMB modules work fine against macOS SMB and will identify the host as macOS in `smb_version` output. AFP modules are sparse but exist. Most macOS recon in MSF is just running the generic modules (SMB, SSH, VNC, mDNS) against macOS hosts.

### Applicable Modules

| Module | Purpose |
|---|---|
| `scanner/smb/smb_version` | Works against macOS SMB, identifies as macOS |
| `scanner/smb/smb_enumshares` | macOS File Sharing shares |
| `scanner/afp/afp_server_info` | AFP server info (legacy File Sharing) |
| `scanner/afp/afp_login` | AFP brute-force |
| `scanner/ssh/ssh_version` | SSH banner (Remote Login) |
| `scanner/ssh/ssh_login` | SSH brute-force |
| `scanner/ssh/ssh_enumusers` | SSH user enum (timing-based) |
| `scanner/vnc/vnc_none_auth` | VNC no-auth check (Screen Sharing) |
| `scanner/vnc/vnc_login` | VNC brute-force |
| `scanner/mdns/query` | Bonjour enumeration |
| `scanner/http/http_version` | AirPlay banner (port 7000) |
| `scanner/printer/printer_version_info` | CUPS printer info |

### Common macOS Workflow

```
workspace -a mac_engagement
use auxiliary/scanner/smb/smb_version
set RHOSTS 10.0.0.0/24
run

use auxiliary/scanner/afp/afp_server_info
set RHOSTS 10.0.0.0/24
run

use auxiliary/scanner/vnc/vnc_none_auth
set RHOSTS 10.0.0.0/24
run

use auxiliary/scanner/ssh/ssh_version
set RHOSTS 10.0.0.0/24
run

use auxiliary/scanner/mdns/query
set RHOSTS 10.0.0.0/24
run
```

---

## Linux Devices

**Target notes.** Linux coverage in MSF is broad because "Linux" covers so many services. The highest-yield modules are the database scanners (MySQL, Postgres, Mongo, Redis — finding unauth or default-cred databases is a regular occurrence), NFS enumeration, rsync module listing, and SSH user enum / login. Docker daemon detection on 2375 is a one-shot win when found. SMTP open relay and user enum modules are still relevant. The SSH modules are useful for credential spraying but watch for fail2ban and lockouts.

### SSH

| Module | Purpose |
|---|---|
| `scanner/ssh/ssh_version` | SSH banner enumeration |
| `scanner/ssh/ssh_login` | SSH brute-force |
| `scanner/ssh/ssh_login_pubkey` | SSH key-based login |
| `scanner/ssh/ssh_enumusers` | Timing-based user enumeration |
| `scanner/ssh/ssh_identify_pubkeys` | Identify pubkey auth methods |
| `scanner/ssh/libssh_auth_bypass` | CVE-2018-10933 check |

### Databases

| Module | Purpose |
|---|---|
| `scanner/mysql/mysql_version` | MySQL version |
| `scanner/mysql/mysql_login` | MySQL brute-force |
| `scanner/mysql/mysql_hashdump` | Hash dump (auth) |
| `scanner/mysql/mysql_schemadump` | Schema dump (auth) |
| `admin/mysql/mysql_enum` | Full MySQL enumeration |
| `scanner/postgres/postgres_version` | Postgres version |
| `scanner/postgres/postgres_login` | Postgres brute-force |
| `scanner/postgres/postgres_dbname_flag_injection` | Postgres injection check |
| `admin/postgres/postgres_readfile` | Read file via Postgres (auth) |
| `scanner/mongodb/mongodb_login` | MongoDB login (try anon first) |
| `scanner/redis/redis_server` | Redis info (anon) |
| `scanner/redis/redis_login` | Redis AUTH brute-force |
| `scanner/redis/file_upload` | Redis file write for RCE |
| `scanner/oracle/oracle_login` | Oracle TNS brute-force |
| `scanner/oracle/sid_brute` | Oracle SID enumeration |
| `scanner/mssql/mssql_ping` | MSSQL discovery |
| `scanner/mssql/mssql_login` | MSSQL brute-force |
| `admin/mssql/mssql_enum` | MSSQL enumeration (auth) |
| `admin/mssql/mssql_exec` | xp_cmdshell exec (auth) |
| `scanner/couchdb/couchdb_enum` | CouchDB database enumeration |
| `scanner/couchdb/couchdb_login` | CouchDB brute-force |

### File Services

| Module | Purpose |
|---|---|
| `scanner/nfs/nfsmount` | NFS showmount + export listing |
| `scanner/rsync/modules_list` | rsync module enumeration |
| `scanner/ftp/ftp_version` | FTP banner |
| `scanner/ftp/ftp_login` | FTP brute-force |
| `scanner/ftp/anonymous` | Anonymous FTP check |
| `scanner/tftp/tftpbrute` | TFTP file brute-force |

### Services

| Module | Purpose |
|---|---|
| `scanner/smtp/smtp_version` | SMTP banner |
| `scanner/smtp/smtp_enum` | SMTP user enumeration (VRFY/EXPN/RCPT) |
| `scanner/smtp/smtp_relay` | Open relay check |
| `scanner/smtp/smtp_ntlm_domain` | NTLM domain leak |
| `scanner/pop3/pop3_version` | POP3 banner |
| `scanner/imap/imap_version` | IMAP banner |
| `scanner/telnet/telnet_login` | Telnet brute-force |
| `scanner/telnet/telnet_version` | Telnet banner |
| `scanner/memcached/memcached_amp` | Memcached amplification check |
| `scanner/elasticsearch/indices_enum` | Elasticsearch index enum |
| `scanner/x11/open_x11` | Unauth X11 check |
| `scanner/vnc/vnc_none_auth` | VNC no-auth check |
| `scanner/portmap/portmap_amp` | Portmap amplification check |
| `scanner/ntp/ntp_monlist` | NTP monlist amplification |
| `scanner/dns/dns_amp` | DNS amplification check |

### Docker / Kubernetes

| Module | Purpose |
|---|---|
| `scanner/http/docker_version` | Docker API version detection |
| `scanner/http/kubernetes_enum` | Kubernetes API enum |

### Common Linux Workflow

```
workspace -a linux_engagement
use auxiliary/scanner/ssh/ssh_version
set RHOSTS 10.0.0.0/24
run

use auxiliary/scanner/redis/redis_server
set RHOSTS 10.0.0.0/24
run

use auxiliary/scanner/mongodb/mongodb_login
set RHOSTS 10.0.0.0/24
run
# Try anon by default

use auxiliary/scanner/nfs/nfsmount
set RHOSTS 10.0.0.0/24
run

use auxiliary/scanner/rsync/modules_list
set RHOSTS 10.0.0.0/24
run

use auxiliary/scanner/http/docker_version
set RHOSTS 10.0.0.0/24
set RPORT 2375
run

use auxiliary/scanner/smtp/smtp_enum
set RHOSTS file:smtp_hosts.txt
set USER_FILE /usr/share/seclists/Usernames/Names/names.txt
run
```

---

## Cheat Sheet

### Core Navigation

| Command | Purpose |
|---|---|
| `search <term>` | Search all modules |
| `search type:auxiliary name:smb` | Filtered search |
| `search cve:2021` | By CVE year |
| `search platform:linux` | By platform |
| `info` | Module docs (current module) |
| `info <module>` | Docs for any module |
| `use <module>` | Load module |
| `use <number>` | Load by search index |
| `back` | Exit current module |
| `show options` | Module options |
| `show advanced` | Advanced options (often useful) |
| `show actions` | Module actions (some auxiliary have sub-actions) |
| `show missing` | Only unset required options |
| `reload` | Reload current module from disk |
| `reload_all` | Reload all modules |

### Setting Options

| Command | Purpose |
|---|---|
| `set RHOSTS 10.0.0.0/24` | Set option |
| `setg RHOSTS 10.0.0.0/24` | Set globally (persists across modules) |
| `unset RHOSTS` | Unset |
| `unsetg RHOSTS` | Unset global |
| `save` | Save datastore to `~/.msf4/config` |
| `set RHOSTS file:targets.txt` | Load from file |
| `set RHOSTS cidr:/24:10.0.0.0` | CIDR shorthand |
| `set RHOSTS file:hosts.txt cidr:/24:10.0.0.0` | Combine sources |

### Running

| Command | Purpose |
|---|---|
| `run` / `exploit` | Execute module |
| `run -j` | Background as job |
| `run -z` | No session interaction |
| `jobs` | List running jobs |
| `jobs -K` | Kill all jobs |
| `jobs -k <id>` | Kill specific job |
| `sessions` | List sessions |
| `sessions -i <id>` | Interact |

### Workspace / Database

| Command | Purpose |
|---|---|
| `db_status` | Database connection status |
| `workspace` | List workspaces |
| `workspace -a <name>` | Add workspace |
| `workspace <name>` | Switch workspace |
| `workspace -d <name>` | Delete workspace |
| `db_nmap <args>` | Run nmap, auto-import results |
| `db_import <file>` | Import scan results |
| `db_export -f xml out.xml` | Export workspace |
| `hosts` | List discovered hosts |
| `hosts -R` | Auto-populate RHOSTS |
| `hosts -d <ip>` | Delete host |
| `services` | List discovered services |
| `services -p 445` | Filter by port |
| `services -s smb -R` | Filter + populate RHOSTS |
| `services -c name,info` | Columns to display |
| `vulns` | List vulnerabilities |
| `notes` | List notes (rich metadata) |
| `creds` | List captured credentials |
| `creds -t password` | Filter creds by type |
| `loot` | List looted files |
| `analyze` | Suggest modules based on db |

### RHOSTS / RPORT Patterns

```
set RHOSTS 10.0.0.1                      # single
set RHOSTS 10.0.0.1,10.0.0.5             # list
set RHOSTS 10.0.0.1-50                   # range
set RHOSTS 10.0.0.0/24                   # CIDR
set RHOSTS file:targets.txt              # from file
set RHOSTS https://example.com           # URL (resolves)
hosts -R                                 # from db
services -p 445 -R                       # from db by service
```

### Common Module Options

| Option | Purpose |
|---|---|
| `RHOSTS` | Target host(s) |
| `RPORT` | Target port |
| `LHOST` | Local host (for callbacks) |
| `LPORT` | Local port |
| `THREADS` | Parallelism (scanners) |
| `USER_FILE` | Username wordlist |
| `PASS_FILE` | Password wordlist |
| `USERPASS_FILE` | Combined `user pass` wordlist |
| `STOP_ON_SUCCESS` | Stop on first valid cred |
| `BRUTEFORCE_SPEED` | 0-5, controls login attempt speed |
| `VERBOSE` | Per-attempt output |
| `SSL` | Use SSL/TLS |
| `PROXIES` | Route through proxy chain |
| `ConnectTimeout` | Network timeout |
| `RPORT_RANGE` | Port range (some scanners) |

### Useful Global Settings

```
setg LHOST 10.0.0.50
setg RHOSTS 10.0.0.0/24
setg THREADS 16
setg VERBOSE false
save
```

### Resource Scripts

```
# file: recon.rc
workspace -a engagement1
db_nmap -sS -sV -p 22,80,443,445 10.0.0.0/24
use auxiliary/scanner/smb/smb_version
hosts -R
run
use auxiliary/scanner/ssh/ssh_version
hosts -R
run
```

Run with: `msfconsole -r recon.rc` or from inside msf: `resource recon.rc`.

### Output / Logging

| Command | Purpose |
|---|---|
| `spool /tmp/msf.log` | Log all output to file |
| `spool off` | Stop logging |
| `makerc /tmp/history.rc` | Save command history as resource script |
| `set ConsoleLogging true` | Persistent console log |
| `set LogLevel 3` | Verbose logging |

### Credential Management

```
creds                                      # list all
creds -u administrator                     # by user
creds -t ntlm                              # by type (password, ntlm, hash, ssh_key)
creds -s smb                               # by service
creds -R                                   # populate RHOSTS with hosts that have creds
creds -o creds.csv                         # export CSV
```

Pipe NTLM hashes straight to hashcat:
```
creds -t ntlm -o /tmp/hashes.csv
awk -F, '{print $5}' /tmp/hashes.csv | hashcat -m 5600 - wordlist.txt
```

---

## Practical Notes

**When to use MSF auxiliary vs dedicated tools.** MSF auxiliary scanners are rarely the fastest option. `nuclei` beats MSF for web vuln checks, `masscan`/`naabu` beats it for port discovery, `crackmapexec`/`netexec` beats it for SMB enumeration and credential spraying, `kerbrute` beats it for Kerberos user enum. The reason to use MSF anyway is the database — when a scanner auto-populates `hosts`, `services`, `creds`, and `vulns` into a workspace, correlation across modules becomes trivial and you can run `hosts -R` to pivot findings from one module into another without shell scripting. For engagements longer than a few hours, the database payoff justifies the slower scanners. For quick one-shot recon, use the Go-based alternatives.

**`db_nmap` is the right way to combine nmap speed with MSF database integration.** Everything nmap discovers lands in `hosts` and `services` automatically, and subsequent auxiliary modules can use `hosts -R` / `services -R` to target them. This is the single biggest reason to run nmap from inside msfconsole rather than standalone.

**Credential validation modules (`*_login`) are dual-purpose.** They're brute-force tools but also credential *validators* — given a known cred, you can run `smb_login` with that one cred against a whole /24 to find every host it works on. This is how you find reused local admin passwords and domain creds with broad access. Set `PASS_FILE` to a file containing just the one known password and `USER_FILE` to one known user, and the module becomes a validation sweep instead of a brute force. `crackmapexec` does this better, but MSF's version auto-populates the creds table with valid hits linked to hosts.

**Lockout awareness.** `smb_login`, `ssh_login`, and the AD brute-force modules will trigger account lockout policies fast if you're not careful. Set `BRUTEFORCE_SPEED` low (2 or 3), set `THREADS` low (2-4), and always test with a throwaway username first to see what the lockout threshold looks like. On AD engagements, check the actual domain password policy before spraying — `crackmapexec smb <dc> --pass-pol` gives it to you. Never hit the same user more than N-2 times per lockout window.

**Spoofing modules need correct `INTERFACE` and `SPOOFIP`.** LLMNR/NBNS/mDNS poisoning requires Metasploit to know which interface to listen on and what IP to return as the "answer" (usually your own IP or a rogue SMB server's IP). Running these without setting both correctly is the most common reason the cred capture chain silently fails. Verify with a test lookup from a target host: `ping nonexistentname` should resolve to your spoof IP within a few seconds if everything is wired up.

**Auxiliary modules can crash things.** Unlike exploits, auxiliary modules are generally safe, but the fuzzers, DoS modules, and some of the older vuln-check modules have been known to crash services. Read `info <module>` before running anything against production. Anything in `auxiliary/dos/` is obviously destructive; some of the `scanner/sip/*` and `scanner/snmp/*` modules can overwhelm small devices; some of the older router scanners reference exploits that crash old firmware on execution of the check itself.

**Workspace discipline saves hours.** Separate workspaces per engagement, per subnet, or per phase. Dumping everything into `default` and then trying to untangle it afterward is miserable. `workspace -a <name>` at the start of every session, and use `db_export` regularly for backups since the MSF database can and does get corrupted on ungraceful shutdowns.

**Resource scripts for repeatable recon.** Anything you find yourself running more than twice, put in a `.rc` file. Staged recon runs (discovery → service scan → vuln check → credential spray) work especially well as resource scripts because each stage can query the database from the previous stage.

**`search` is underused.** `search cve:2023 type:auxiliary platform:linux` finds every 2023 CVE auxiliary module for Linux. `search path:snmp` finds everything under `auxiliary/scanner/snmp/`. `search author:zerosum0x0` finds modules by a specific author (useful when following up on public research). Learn the filter syntax — it's in `help search`.

**Pair with external tooling via stdout/stdin.** MSF output isn't great for piping, but `-q -x` lets you run headless:
```
msfconsole -q -x "use auxiliary/scanner/smb/smb_version; set RHOSTS file:hosts.txt; run; exit"
```
This is the right shape for automation and CI integration when you don't need the interactive database.

**Finally: read module source.** Everything auxiliary lives under `/usr/share/metasploit-framework/modules/auxiliary/` (or the Ruby gem path on non-Kali installs). The source is Ruby and mostly readable, and understanding what a module actually sends on the wire is the difference between running it blindly and knowing whether its findings are reliable. Many modules have subtle assumptions (default ports, expected banner formats, hardcoded timeouts) that only become obvious when you read the code.