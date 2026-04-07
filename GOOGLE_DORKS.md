# Google Dork

Google dorking is the use of advanced search operators to refine search engine results into highly targeted queries. For security research and the initial recon phase, it serves as a validation technique for identifying low hanging fruit such as publicly exposed files, administrative portals, debug interfaces, outdated software, leaked credentials, and other indicators of misconfiguration or neglect. Rather than relying on broad keyword searches, dorking narrows results through carefully combined operators such as site:, inurl:, intitle:, and file-type filters, allowing researchers to uncover assets and artifacts that would otherwise remain buried in ordinary search results. When applied ethically and within scope, it is a valuable method for exposure discovery, asset inventory, and responsible disclosure workflows.

Some of the dorks I've listed here are HIGHLY specific and are not commonly known which will lead you to vulnerable servers that were likely never meant to be indexed by a search engine. If you stumble upon anything particularly vulnerable, (_if you go through this list long enough you will_), it is your duty to ethically disclose your findings and to stay within the bounds of the law.


## Scoring rubric

| Score | Meaning |
|---|---|
| 10 | Very high signal. Often exposes directly sensitive data, admin access, debug interfaces, or obviously neglected infrastructure. |
| 8-9 | Strong signal. Usually finds real exposure or serious misconfiguration, but with more false positives or narrower applicability. |
| 6-7 | Moderate signal. Useful for triage or legacy hunting, but noisier or more contextual. |
| 4-5 | Weak-to-moderate signal. Can still be useful, but often needs validation and cross-checking. |
| 1-3 | Low signal. Mostly historical curiosity, broad hygiene checks, or very noisy heuristics. |

## Notes

- Scores below rate **defensive exposure-finding value**, not exploitability.
- High scores usually mean the result is worth triaging quickly.
- Very broad patterns can be useful, but their score may be lower if they produce a lot of noise.

---

## Outdated Server Software Signatures

| Dork | Score | Clear description |
|---|---:|---|
| `"Apache/1.3" intitle:"Index of"` | 9 | Finds directory listings on hosts still advertising Apache 1.3, which is extremely old and strongly suggests abandoned or unmaintained infrastructure. |
| `"Apache/2.0" intitle:"Index of"` | 8 | Finds open listings on Apache 2.0-era systems. Strong neglect signal, though less catastrophic than 1.3. |
| `"Apache/2.2" "Server at"` | 7 | Finds pages where Apache 2.2 is still exposed in footer/banner text. Good legacy signal, but noisier than directory-listing patterns. |
| `"Microsoft-IIS/5.0" intitle:"Under Construction"` | 9 | Finds very old IIS 5.0-era pages, often untouched Windows 2000-era systems or ancient mirrored content. |
| `"Microsoft-IIS/6.0"` | 8 | Finds IIS 6.0-era infrastructure, usually tied to badly aged Windows Server 2003-era stacks. |
| `"PHP/4." "Server at"` | 9 | Finds pages openly disclosing PHP 4.x in server output or error text. Very strong sign of neglected PHP infrastructure. |
| `"PHP/5.2" OR "PHP/5.3" "Server at"` | 8 | Finds ancient PHP 5 branches still exposed. Strong indicator of insecure legacy web apps or forgotten backends. |
| `"Powered by Apache Tomcat/4" OR "Tomcat/5"` | 8 | Finds legacy Tomcat deployments, which often come with outdated app stacks, weak defaults, or forgotten management consoles. |
| `"Server: nginx/0."` | 7 | Finds pre-1.0 nginx references. Useful for identifying antique reverse proxies or web stacks, though some references may be cached or copied. |

---

## Default / Placeholder Pages Still Live

| Dork | Score | Clear description |
|---|---:|---|
| `intitle:"Apache2 Ubuntu Default Page" "It works"` | 7 | Finds stock Ubuntu Apache default pages left exposed, usually meaning the server was never fully configured. |
| `intitle:"Test Page for the Apache HTTP Server"` | 7 | Finds the standard Red Hat/CentOS Apache test page, often indicating a host was stood up and then neglected. |
| `intitle:"Welcome to nginx!" "If you see this page"` | 7 | Finds default nginx landing pages. Good sign of unfinished setup, placeholder vhosts, or abandoned staging hosts. |
| `intitle:"IIS Windows Server" "Internet Information Services"` | 7 | Finds default IIS pages. Useful for identifying Windows web servers that were never hardened or finished. |
| `intitle:"It works!" "This is the default web page"` | 6 | Finds generic default web pages. Useful, but noisier because many environments reuse default messaging. |
| `intitle:"Plesk" "default page"` | 7 | Finds Plesk-managed sites still showing placeholder content, often revealing neglected hosting tenants or forgotten domains. |
| `intitle:"cPanel" "Default Web Site Page"` | 7 | Finds cPanel-managed placeholder pages, which often indicate unclaimed or abandoned web roots. |
| `"This is a Parallels default page"` | 7 | Finds Parallels/Plesk placeholder pages left in production. Strong neglect signal for hosted environments. |

---

## Legacy


### Internet Archaeology

| Dork | Score | Clear description |
|---|---:|---|
| `"© 1999" OR "© 2000" OR "© 2001" inurl:html` | 4 | Finds pages with very old copyright footers. Useful as a weak neglect heuristic, but easy to false-positive on abandoned templates. |
| `"Last modified" "1998" OR "1999" OR "2000" intitle:"Index of"` | 7 | Finds directory listings serving files with 20+ year old timestamps, a stronger sign of stale content than a footer alone. |
| `"Powered by FrontPage" OR "Microsoft FrontPage"` | 7 | Finds FrontPage-era sites, which often correlate with obsolete publishing workflows and long-abandoned content. |
| `"Created with Dreamweaver" OR "generator" "Dreamweaver 4"` | 5 | Finds old Dreamweaver-era artifacts. Useful for legacy site hunting, but not always a current exposure indicator. |
| `"best viewed in Netscape" OR "best viewed in 800x600"` | 4 | Finds very old web design relics. More of a legacy-content clue than a strong security finding on its own. |
| `"best viewed in Internet Explorer"` | 4 | Finds old IE-era pages. Similar value to other legacy-content heuristics: interesting, but not high-confidence exposure by itself. |
| `"This site is under construction" +counter` | 5 | Finds classic placeholder pages with hit counters, often tied to abandoned small-business or personal hosting. |

---

### CMS Installs

| Dork | Score | Clear description |
|---|---:|---|
| `"Powered by Joomla! 1.0" OR "Joomla! 1.5"` | 8 | Finds very old Joomla installs that strongly suggest unsupported CMS exposure. |
| `"Powered by WordPress" "Version 2." OR "Version 3."` | 7 | Finds very old WordPress deployments. High-value for triage, though version strings are not always current or accurate. |
| `"Powered by phpBB" "2.0"` | 8 | Finds phpBB 2-era forums, which are usually abandoned or dangerously old. |
| `"Powered by vBulletin" "Version 3."` | 7 | Finds old vBulletin installs, often neglected forums with weak operational hygiene. |
| `inurl:"/mambo/" "Mambo" intitle:"Welcome"` | 8 | Finds Mambo CMS relics, a strong signal for abandoned or museum-piece PHP environments. |
| `"Powered by Drupal" "Drupal 5" OR "Drupal 6"` | 8 | Finds EOL Drupal installs. Strong signal for unmaintained CMS exposure. |
| `"Powered by MovableType" OR "Movable Type 3"` | 7 | Finds legacy blog platforms that often linger unpatched and unmanaged. |

---

### Infrastructure & Services

| Dork | Score | Clear description |
|---|---:|---|
| `intitle:"Index of" "www.conf" OR "httpd.conf"` | 9 | Finds exposed web-server configuration files or directories. High signal because config files often reveal internals and credentials. |
| `intitle:"Index of" inurl:"/old" OR inurl:"/archive" OR inurl:"/legacy"` | 6 | Finds explicitly archived or legacy paths still being served. Useful for forgotten content discovery, but broad. |
| `inurl:"/cgi-bin/" "Index of" "test-cgi"` | 8 | Finds exposed CGI-bin paths and default test scripts, often on old or embedded servers. |
| `intitle:"Webmin" inurl:":10000"` | 8 | Finds Webmin admin interfaces, which are highly sensitive if public. |
| `intitle:"phpinfo()" "PHP Version 4" OR "PHP Version 5.2"` | 9 | Finds exposed phpinfo pages on ancient PHP versions, which leak extensive environment details. |
| `inurl:"/mrtg/" "MRTG Index Page"` | 7 | Finds old MRTG monitoring pages, often revealing infrastructure naming and network structure. |
| `inurl:"/nagios/" intitle:"Nagios"` | 8 | Finds exposed Nagios dashboards with operational detail about monitored systems. |
| `inurl:"/cacti/" intitle:"Login to Cacti"` | 8 | Finds Cacti login panels, which are sensitive and often neglected. |
| `inurl:"/munin/" intitle:"Munin"` | 7 | Finds Munin monitoring instances exposing graphs and node names. |

---

### Expired SSL / Security Indicators

| Dork | Score | Clear description |
|---|---:|---|
| `"ssl_error" OR "certificate has expired"` | 5 | Finds government pages visibly failing TLS. Useful for hygiene checks, though indexed error pages can be stale. |
| `inurl:"http://" "login" -inurl:"https://"` | 8 | Finds login surfaces still served over plain HTTP. High-value security hygiene finding if real. |

---

## Open Directory Listings, Info Leaks

| Dork | Score | Clear description |
|---|---:|---|
| `intitle:"Index of /" site:example.com` | 7 | Finds standard Apache-style directory listings on a scoped target. Useful, broad baseline for owned assets. |
| `intitle:"Index of" "Parent Directory"` | 7 | Finds generic open directory listings across many servers. Strong baseline pattern, but noisy without scoping. |
| `intitle:"Index of" "Apache" "Server at"` | 7 | Finds Apache-style directory listings where footer text may also reveal a server banner/version. |
| `intitle:"Index of /" +.htaccess` | 9 | Finds listings exposing `.htaccess`, which can leak rewrite rules, auth directives, and path structure. |
| `intitle:"Index of /" +.env` | 10 | Finds listings exposing `.env` files, often containing credentials, keys, and secret configuration. |
| `intitle:"Index of /" "backup" site:example.com` | 8 | Finds backup directories under your target that may contain archives or historical site copies. |
| `intitle:"Index of /" +passwd` | 9 | Finds password-related files in directory listings, often indicating direct secret exposure. |
| `intitle:"Index of /" +.git` | 10 | Finds exposed Git repositories, which can often be cloned or mined for source and secrets. |
| `intitle:"Index of" ".sql"` | 10 | Finds database dumps in open listings. Very high-value exposure signal. |
| `intitle:"Apache Status" "Server Version"` | 9 | Finds Apache mod_status pages, which can leak request activity, clients, and server versioning. |
| `inurl:"/server-status" "Apache"` | 9 | Directly targets Apache status endpoints. High-value operational leak if exposed. |
| `inurl:"/server-info" "Apache Server Information"` | 10 | Finds Apache mod_info pages, which can reveal modules, config details, and server internals. |

---

## Admin Portals

| Dork | Score | Clear description |
|---|---:|---|
| `inurl:"/admin" site:example.com` | 5 | Broad way to find admin paths on owned assets. Useful but noisy because many apps use `/admin`. |
| `inurl:"/administrator" intitle:"login"` | 6 | Finds administrator login panels, often Joomla or custom admin interfaces. |
| `inurl:"/wp-admin" OR inurl:"/wp-login" site:example.com` | 6 | Finds WordPress admin surfaces on owned assets. Useful inventory query, but not automatically a problem. |
| `intitle:"Login" inurl:"/admin" "Apache"` | 5 | Finds Apache-hosted admin login pages. Broad and noisy, but sometimes useful for triage. |
| `inurl:"/phpmyadmin" site:example.com` | 8 | Finds phpMyAdmin instances, which are sensitive and often should not be public. |
| `inurl:"/cpanel" OR inurl:":2082" OR inurl:":2083"` | 7 | Finds cPanel login portals and hosting-control interfaces. |
| `inurl:"/manager/html" intitle:"Tomcat"` | 9 | Finds Tomcat manager interfaces, which are high-sensitivity management surfaces. |
| `inurl:"/webdav" intitle:"Index of"` | 8 | Finds exposed WebDAV directories, which may allow browsing or unintended file access. |
| `intitle:"Kibana" "Discover" "Dashboard"` | 9 | Finds exposed Kibana dashboards that may reveal logs, indices, and internal data. |
| `intitle:"Grafana" inurl:"/login" "Welcome to Grafana"` | 8 | Finds Grafana login portals, often forgotten or default-configured. |
| `intitle:"Jenkins" "Dashboard" inurl:"/manage"` | 9 | Finds Jenkins management surfaces, which are highly sensitive in CI/CD environments. |
| `intitle:"Portainer" inurl:"/#!/init/admin"` | 10 | Finds Portainer initial setup state, often meaning first-user admin registration is still open. |
| `intitle:"RabbitMQ Management" inurl:":15672"` | 9 | Finds RabbitMQ management consoles exposing broker operations and queue details. |
| `intitle:"Flower" "Celery" inurl:":5555"` | 9 | Finds Celery Flower dashboards, which often expose task metadata and worker state. |
| `intitle:"Elasticsearch" "cluster_name" "status"` | 10 | Finds raw Elasticsearch cluster info endpoints. Very high signal. |
| `inurl:"/_cat/indices" "health" "status" "index"` | 10 | Finds open Elasticsearch cat APIs, which reveal index inventory and data scale. |
| `intitle:"MinIO Console" inurl:"/login"` | 8 | Finds MinIO object-storage consoles. High-value management surface. |
| `intitle:"Traefik" "Dashboard" inurl:"/dashboard"` | 9 | Finds Traefik reverse-proxy dashboards exposing routes and backend topology. |
| `intitle:"Argo CD" inurl:"/login"` | 8 | Finds Argo CD dashboards, which are highly sensitive in deployment pipelines. |
| `intitle:"Consul" "Services" "Nodes" inurl:"/ui"` | 9 | Finds exposed Consul UIs revealing service inventory and cluster nodes. |
| `intitle:"Vault" inurl:"/ui/vault/auth"` | 8 | Finds Vault login pages. Important inventory signal, though not automatically exploitable. |
| `inurl:"staging." OR inurl:"dev." OR inurl:"test." intitle:"Login"` | 8 | Finds staging or test subdomains with login portals left indexed. |
| `inurl:"uat." OR inurl:"qa." intitle:"Dashboard"` | 8 | Finds QA/UAT dashboards left public. |
| `site:*.internal.* -inurl:www` | 6 | Finds accidentally indexed internal-style subdomains. Useful but broad. |
| `inurl:"debug" "mode" "true" intitle:"Login"` | 7 | Finds pages suggesting debug mode is enabled in sensitive contexts. |
| `inurl:":8080" OR inurl:":3000" OR inurl:":8443" intitle:"Login"` | 7 | Finds likely dev or non-standard admin surfaces exposed on common alternate ports. |
| `inurl:"/adminer.php" "Login" "SQLite" OR "MySQL"` | 9 | Finds Adminer database management tools left exposed. |
| `inurl:"/phppgadmin/" intitle:"phpPgAdmin"` | 9 | Finds phpPgAdmin interfaces left public. |
| `inurl:"/mailhog/" OR inurl:":8025" "MailHog"` | 9 | Finds MailHog developer mail catchers exposing internal email flows. |
| `inurl:"/rediscommander" OR intitle:"Redis Commander"` | 9 | Finds Redis Commander web UIs exposing cache/session data and server info. |

---

## Data Exposure

### Secrets, Keys, Cloud Storage & Config Files

| Dork | Score | Clear description |
|---|---:|---|
| `intitle:"Index of" ".env" "DB_PASSWORD"` | 10 | Finds `.env` files in directory listings with obvious database credentials. Extremely high signal. |
| `filetype:env "MAIL_PASSWORD" OR "AWS_SECRET"` | 10 | Finds indexed environment files containing mail or cloud secrets. |
| `filetype:yml "password:" "database:" -github` | 9 | Finds YAML config files with hardcoded credentials, excluding common GitHub noise. |
| `filetype:ini "[database]" "password ="` | 9 | Finds INI-style configuration files exposing database credentials. |
| `filetype:conf "server {" "listen" "root"` | 7 | Finds exposed nginx or similar server config snippets. Good operational leak signal, but not always secret-bearing. |
| `filetype:properties "jdbc.password" OR "db.password"` | 10 | Finds Java `.properties` files with database passwords. |
| `filetype:xml "connectionString" "password"` | 9 | Finds XML config files, often .NET-style, with connection strings and embedded secrets. |
| `intitle:"Index of" "wp-config.php.bak" OR "wp-config.php.old"` | 10 | Finds WordPress config backups in web roots, often containing database credentials and salts. |
| `filetype:log "password" "failed" OR "authentication"` | 8 | Finds log files that may capture credentials, auth failures, or usernames. |
| `intitle:"Index of" ".docker-compose.yml"` | 8 | Finds Docker Compose files that reveal topology, service names, ports, and sometimes secrets. |
| `filetype:json "client_secret" "client_id" "auth_uri"` | 10 | Finds exposed OAuth credential files, commonly Google client secrets. |
| `filetype:json "aws_access_key_id" "aws_secret_access_key"` | 10 | Finds exposed AWS credential files. Extremely high-value leak pattern. |
| `filetype:pem "BEGIN RSA PRIVATE KEY"` | 10 | Finds exposed PEM private keys. Critical finding. |
| `filetype:ppk "PuTTY-User-Key-File"` | 10 | Finds exposed PuTTY private key files. Critical if real. |
| `filetype:ovpn "remote" "auth-user-pass"` | 9 | Finds OpenVPN configs that may reveal infrastructure and possibly credentials. |
| `filetype:rdp "full address" "username"` | 8 | Finds RDP connection files that reveal hostnames, usernames, and targeting info. |
| `"bucket_name" "aws_secret" filetype:json OR filetype:yml` | 9 | Finds cloud config files exposing S3 or similar storage details with secrets. |
| `site:s3.amazonaws.com filetype:sql` | 10 | Finds SQL dumps in public S3 buckets. Very high-value exposure pattern. |
| `site:blob.core.windows.net filetype:sql OR filetype:bak` | 10 | Finds database dumps or backups in public Azure blob storage. |
| `site:storage.googleapis.com filetype:csv "email" "password"` | 10 | Finds public GCS objects containing credential-like CSV data. |
| `intitle:"Index of" "/.git/config"` | 10 | Finds exposed Git metadata that can often lead to full repository recovery. |
| `intitle:"Index of" "/.svn/entries"` | 9 | Finds exposed Subversion metadata, often enough to reconstruct source history. |
| `intitle:"Index of" "/node_modules/" "package.json"` | 7 | Finds node_modules being served, revealing dependency tree and likely weak app hygiene. |
| `filetype:sh "#!/bin/bash" "password" OR "token" OR "secret"` | 9 | Finds shell scripts with embedded credentials or API tokens. |
| `filetype:py "password" "mysql.connector" OR "psycopg2"` | 9 | Finds Python code with hardcoded DB credentials. |
| `inurl:"/swagger-ui.html" OR inurl:"/swagger/" "Swagger UI"` | 8 | Finds exposed Swagger UI documentation interfaces. |
| `inurl:"/graphql" "query" "mutation" intitle:"GraphiQL"` | 9 | Finds exposed GraphiQL interfaces allowing direct API exploration and mutation testing. |
| `inurl:"/api-docs" "openapi" OR "swagger"` | 8 | Finds raw or generated API documentation endpoints. |
| `intitle:"Index of" "id_rsa" OR "id_ed25519"` | 10 | Finds SSH private keys in open directories. Critical exposure. |
| `filetype:tf "aws_secret_access_key" OR "password"` | 10 | Finds Terraform files with embedded secrets. |
| `filetype:tfstate "aws_access_key_id"` | 10 | Finds Terraform state files, which frequently contain credentials and sensitive infrastructure data. |

---

### Database Dumps & Backups

| Dork | Score | Clear description |
|---|---:|---|
| `intitle:"Index of" "database.sql" OR "dump.sql" OR "db.sql"` | 10 | Finds exposed SQL dumps in open listings. |
| `intitle:"Index of" ".sql.gz" OR ".sql.bz2" OR ".sql.zip"` | 10 | Finds compressed database backups left in public directories. |
| `intitle:"Index of" "backup" ".tar.gz" OR ".zip" "2024" OR "2025"` | 9 | Finds recent backup archives that may contain full site or server snapshots. |
| `filetype:sql "INSERT INTO" "users" "password"` | 10 | Finds raw SQL containing user table inserts and password fields. |
| `filetype:sql "CREATE TABLE" "credit_card" OR "ssn" OR "social_security"` | 10 | Finds schema dumps exposing highly sensitive table structures. |
| `intitle:"Index of" ".mdb" OR ".accdb"` | 8 | Finds exposed Access database files. Often legacy, but still sensitive. |
| `intitle:"Index of" "*.sqlite" OR "*.db"` | 9 | Finds exposed SQLite or generic DB files. |
| `intitle:"Index of" "mongodump" OR "mongorestore"` | 8 | Finds MongoDB backup directories or artifacts. |

---

## IoT, SCADA & Embedded Devices

| Dork | Score | Clear description |
|---|---:|---|
| `intitle:"webcamXP 5" OR intitle:"webcam 7"` | 8 | Finds webcam management panels on old camera software. |
| `inurl:"/view/view.shtml" "Network Camera"` | 8 | Finds Axis-style or similar network camera viewer endpoints. |
| `intitle:"Live View / - AXIS"` | 9 | Finds Axis live camera views, often directly exposing feeds. |
| `inurl:"/cgi-bin/viewer/video.jpg"` | 8 | Finds direct camera image endpoints, commonly on embedded devices. |
| `intitle:"HP LaserJet" inurl:":9100" OR inurl:"/hp/device"` | 7 | Finds printer web interfaces and management pages. |
| `intitle:"PrinterLogic" OR intitle:"RICOH" "Web Image Monitor"` | 7 | Finds enterprise printer administration portals. |
| `intitle:"RouterOS" "mikrotik" inurl:"/webfig"` | 9 | Finds MikroTik RouterOS web administration surfaces. |
| `intitle:"Ubiquiti" "airOS" inurl:"/login"` | 8 | Finds Ubiquiti device management interfaces. |
| `intitle:"PRTG Network Monitor" "Login"` | 8 | Finds PRTG monitoring interfaces exposing network monitoring infrastructure. |
| `"Powered by CODESYS" OR intitle:"CODESYS" "WebVisu"` | 10 | Finds PLC or industrial control web visualizations. Very sensitive operational exposure. |

---


### Documents

| Dork | Score | Clear description |
|---|---:|---|
| `filetype:xls "confidential" "internal use only"` | 8 | Finds indexed spreadsheets explicitly marked confidential. |
| `filetype:pdf "internal" "not for distribution" site:*.com` | 7 | Finds PDFs marked as internal or restricted. |
| `filetype:csv "email" "phone" "address" -site:github.com` | 8 | Finds CSV files likely containing PII. |
| `filetype:doc "private" "salary" OR "compensation"` | 9 | Finds Word docs with salary or compensation data. |
| `intitle:"Index of" "financial" ".xls" OR ".xlsx"` | 9 | Finds financial spreadsheets in open listings. |
| `filetype:eml "password" OR "credentials"` | 9 | Finds email files containing likely credential discussions or secrets. |
| `filetype:ica "Address=" "InitialProgram="` | 7 | Finds Citrix ICA files revealing internal app server names and launch targets. |

---

## Developer Artifacts / Negligence

### Error Pages Leaking Internals

| Dork | Score | Clear description |
|---|---:|---|
| `"Fatal error: Uncaught" "Stack trace" filetype:php` | 8 | Finds PHP stack traces that reveal filesystem paths and code structure. |
| `"Traceback (most recent call last)" "File" site:*.com` | 7 | Finds Python tracebacks on production sites, often revealing app internals. |
| `"ORA-" "TNS:" "Error" site:*.gov` | 7 | Finds Oracle errors leaking connection or backend details. |
| `"MySQL" "server version" "syntax" "near"` | 7 | Finds MySQL errors that may reveal versioning and query structure. |
| `"SQLSTATE" "PDOException" "in /var/www"` | 8 | Finds PHP PDO exceptions exposing server paths and application structure. |
| `"Django" "DEBUG = True" "Traceback"` | 10 | Finds Django debug pages explicitly showing production debug mode. |
| `"Laravel" "Whoops" "stack trace" "env"` | 10 | Finds Laravel debug pages leaking stack traces and possibly environment values. |
| `intitle:"Application Error" "Heroku"` | 5 | Finds crashed or abandoned Heroku apps. Useful triage, but not always a sensitive leak. |
| `"Spring Boot" "Whitelabel Error Page" "status=500"` | 7 | Finds Spring Boot default error pages, which often indicate poor production hardening. |

---

### Task Queue & Worker Dashboards

| Dork | Score | Clear description |
|---|---:|---|
| `intitle:"Flower" "Active" "Processed" "Failed" inurl:":5555/tasks"` | 9 | Finds Flower task list views exposing task state and execution metadata. |
| `intitle:"Flower" "broker" "celery" inurl:"/api/workers"` | 9 | Finds Flower API endpoints leaking worker metadata. |
| `intitle:"Flower" inurl:"/dashboard" "Uptime" "Pool"` | 9 | Finds Flower dashboards with worker and concurrency state. |
| `inurl:":5555/api/tasks" "uuid" "state" "args"` | 10 | Finds raw Flower task APIs exposing arguments and task metadata. |
| `intitle:"RQ Dashboard" "Queues" "Workers" "Jobs"` | 8 | Finds Python RQ dashboards exposing queue and worker state. |
| `intitle:"Dramatiq" "Dashboard" "actors" "messages"` | 8 | Finds Dramatiq task dashboards. |
| `intitle:"Huey" "task" "queue" "result"` | 7 | Finds Huey task queue dashboards or monitoring. |
| `intitle:"bull" "Dashboard" "Completed" "Failed" inurl:"/queues"` | 8 | Finds Bull/BullMQ dashboards exposing Node queue state. |
| `intitle:"Arena" "Bull" "Queues" inurl:"/arena"` | 8 | Finds Bull Arena dashboards. |
| `intitle:"Sidekiq" "Dashboard" "Busy" "Enqueued" "Retries"` | 9 | Finds Sidekiq dashboards exposing live queue operations. |
| `intitle:"Hangfire" "Dashboard" "Succeeded" "Processing"` | 8 | Finds Hangfire job dashboards exposing .NET background jobs. |
| `intitle:"Asynq" "Dashboard" "Queues" "Servers"` | 8 | Finds Asynq task dashboards for Go services. |

---

### Cache & Session Store Interfaces

| Dork | Score | Clear description |
|---|---:|---|
| `intitle:"Redis Commander" "Connection" "dbsize" inurl:":8081"` | 9 | Finds Redis Commander with visible DB stats and connection info. |
| `intitle:"RedisInsight" inurl:"/redis-stack/browser"` | 9 | Finds RedisInsight browser interfaces. |
| `intitle:"phpRedisAdmin" "Redis" "keys" "info"` | 9 | Finds phpRedisAdmin panels exposing Redis metadata and key access. |
| `intitle:"Memcached" "stats" "curr_items" "bytes"` | 8 | Finds Memcached stats pages exposing cache usage. |
| `intitle:"Hazelcast" "Management Center" "Cluster"` | 8 | Finds Hazelcast management consoles exposing cluster state. |

---

### Message Broker & Event Stream Panels

| Dork | Score | Clear description |
|---|---:|---|
| `intitle:"RabbitMQ Management" "Queues" "Connections" inurl:":15672/#/queues"` | 9 | Finds RabbitMQ queue views with live message counts and connections. |
| `intitle:"RabbitMQ" "Exchanges" "Bindings" inurl:"/api/overview"` | 10 | Finds RabbitMQ API overviews exposing broker internals and topology. |
| `intitle:"Kafka UI" "Topics" "Brokers" "Consumers"` | 8 | Finds Kafka UI dashboards exposing broker and topic state. |
| `intitle:"Kafdrop" "Broker List" "Topic List"` | 8 | Finds Kafdrop Kafka browsers. |
| `intitle:"AKHQ" "Topics" "Consumer Groups" "Schema Registry"` | 8 | Finds AKHQ management surfaces for Kafka environments. |
| `intitle:"Kafka Manager" "Cluster" "Brokers" "Topics"` | 8 | Finds Kafka Manager dashboards. |
| `intitle:"Redpanda Console" "Topics" "Brokers"` | 8 | Finds Redpanda management consoles. |
| `intitle:"NATS" "Monitoring" "connz" "routez" inurl:":8222"` | 9 | Finds NATS monitoring endpoints exposing connection and routing data. |

---

### Python Framework Debug Pages

| Dork | Score | Clear description |
|---|---:|---|
| `"Django" "Settings" "INSTALLED_APPS" "DATABASES" intitle:"Settings"` | 10 | Finds Django settings dumps exposing installed apps and database config. |
| `intitle:"DisallowedHost" "Invalid HTTP_HOST header" "Django"` | 6 | Finds Django ALLOWED_HOSTS errors. Useful as a debug signal, but lower impact than full debug output. |
| `"Django" "You're seeing this error because you have DEBUG = True"` | 10 | Finds Django debug mode explicitly enabled in production. |
| `intitle:"Page not found" "Django tried these URL patterns" "urlpatterns"` | 9 | Finds Django 404 debug pages leaking route patterns. |
| `"Django" "OperationalError" "no such table" OR "relation" "does not exist"` | 7 | Finds Django migration or DB errors that leak schema clues. |
| `intitle:"TemplateDoesNotExist" "Django" "Template-loader postmortem"` | 9 | Finds detailed Django template debug pages exposing search paths and filesystem layout. |
| `intitle:"DatabaseError" "Django" "LINE" "SELECT" "FROM"` | 8 | Finds Django SQL errors leaking raw query details. |
| `"Flask" "Debugger" "Traceback" "Console Locked" inurl:"?__debugger__"` | 10 | Finds Werkzeug/Flask debugger pages, a very high-value debug exposure. |
| `"Flask" "Werkzeug" "The debugger caught an exception" "Traceback"` | 9 | Finds Flask debug exception pages exposing stack traces and internal paths. |
| `"Werkzeug Debugger" "CONSOLE" "interact" inurl:"__debugger__"` | 10 | Finds the Werkzeug interactive debugger surface directly. |
| `intitle:"Starlette" "Traceback" "ASGI" "scope"` | 8 | Finds Starlette/FastAPI tracebacks with app internals. |
| `"FastAPI" "Internal Server Error" "traceback" "File"` | 7 | Finds FastAPI error traces leaking file paths and code context. |
| `inurl:"/docs" intitle:"FastAPI" "Swagger UI" "openapi.json"` | 8 | Finds FastAPI auto-generated docs exposed in production. |
| `inurl:"/redoc" intitle:"ReDoc" "API" site:*.com` | 7 | Finds ReDoc endpoints on production sites. Good inventory signal, somewhat noisier than `/docs`. |

---

### PHP Framework Debug Pages

| Dork | Score | Clear description |
|---|---:|---|
| `"Laravel" "Whoops!" "Stack Trace" "Environment Variables"` | 10 | Finds Laravel debug pages leaking stack traces and environment variables. |
| `"Laravel" "APP_KEY" "DB_PASSWORD" "Whoops"` | 10 | Finds Laravel debug pages explicitly leaking sensitive env values. |
| `intitle:"Ignition" "Laravel" "Solution" "Stack trace"` | 9 | Finds Laravel Ignition debug pages exposing remediation suggestions and stack data. |
| `"Symfony" "Exception" "Stack Trace" "kernel.debug" "true"` | 9 | Finds Symfony debug mode in production. |
| `inurl:"/_profiler" "Symfony Profiler" "Request" "Performance"` | 9 | Finds Symfony profiler routes exposing request details and performance data. |
| `inurl:"/_wdt/" "Symfony" "sf-toolbar"` | 8 | Finds Symfony web debug toolbar routes. |
| `"Yii" "CHttpException" "Stack Trace" "REQUEST_URI"` | 8 | Finds Yii debug traces exposing paths and request context. |
| `"CodeIgniter" "A PHP Error was encountered" "Filename:" "Line Number:"` | 8 | Finds CodeIgniter verbose error pages. |
| `"CakePHP" "Error" "Stack Trace" "ROOT" "APP"` | 8 | Finds CakePHP debug output exposing filesystem layout. |

---

### Ruby / Rails & Node Debug Pages

| Dork | Score | Clear description |
|---|---:|---|
| `"Rails" "Action Controller: Exception caught" "ActiveRecord"` | 8 | Finds Rails exception pages with database and stack details. |
| `intitle:"Action Controller: Exception" "Rails.root:" "Application Trace"` | 9 | Finds Rails debug pages leaking app root paths and traces. |
| `"BetterErrors" "Rails" "REPL" "Local Variables"` | 10 | Finds BetterErrors interactive debug pages, which are extremely sensitive. |
| `"Rails" "RoutingError" "No route matches" "routes.rb"` | 8 | Finds Rails routing debug pages leaking route structure. |
| `"Puma" "Error" "Lowlevel" "status" inurl:":9293"` | 6 | Finds Puma status/error surfaces. Useful, but less severe than full debug tooling. |
| `"Express" "ReferenceError" "at Object" "node_modules"` | 7 | Finds Express.js error traces exposing stack details and module paths. |
| `"Next.js" "Internal Server Error" "Server Error" "pages/"` | 6 | Finds Next.js server-side errors leaking file structure. |
| `"Nuxt" "NuxtServerError" "server" "statusCode"` | 6 | Finds Nuxt server errors with internal routing or rendering details. |

---

### Java / .NET Debug & Management

| Dork | Score | Clear description |
|---|---:|---|
| `"Spring Boot" "Whitelabel Error" "status=500" "trace="` | 9 | Finds Spring Boot error pages with full stack trace output. |
| `inurl:"/actuator" "beans" "health" "env" "mappings"` | 9 | Finds exposed Spring Boot Actuator index pages. |
| `inurl:"/actuator/env" "spring.datasource.password"` | 10 | Finds Actuator environment dumps leaking datasource credentials. |
| `inurl:"/actuator/heapdump"` | 10 | Finds heap dump endpoints, which are extremely sensitive. |
| `inurl:"/actuator/mappings" "requestMappings" "dispatcherServlets"` | 9 | Finds endpoints exposing full Spring MVC route maps. |
| `inurl:"/actuator/configprops" "spring.datasource"` | 10 | Finds Actuator config properties exposing resolved secrets or internal config. |
| `inurl:"/jolokia/" "listMBeans" OR "read" "java.lang"` | 9 | Finds Jolokia JMX bridges exposing live JVM internals. |
| `inurl:"/elmah.axd" "Error Log" "ASP.NET"` | 9 | Finds ELMAH error logs on .NET apps. |
| `"YSOD" "Server Error in" "Application" "Stack Trace" ".aspx"` | 8 | Finds ASP.NET Yellow Screen of Death error pages. |
| `inurl:"/Elmah" "All Errors" "Detail" "text/xml"` | 9 | Finds ELMAH error listings or feeds. |
| `"Struts Problem Report" "Stacktraces" "struts.devMode"` | 9 | Finds Apache Struts dev mode exposures. |

---

### Debug Toolbars & Profilers Left On


| Dork | Score | Clear description |
|---|---:|---|
| `"djdt" "DjDebugToolbarHandle" OR inurl:"__debug__/render_panel"` | 9 | Finds Django Debug Toolbar assets or panels. |
| `inurl:"/__debug__/" "SQL" "Templates" "Cache" "Signals"` | 9 | Finds Django Debug Toolbar panel routes exposing internals. |
| `inurl:"/_debugbar" "Queries" "Route" "Session" "Request"` | 9 | Finds Laravel Debugbar interfaces exposing request, query, and session data. |
| `inurl:"/telescope" intitle:"Laravel Telescope" "Requests" "Exceptions"` | 10 | Finds Laravel Telescope dashboards exposing request, exception, query, and job data. |
| `inurl:"/horizon" intitle:"Laravel Horizon" "Jobs" "Failed"` | 9 | Finds Laravel Horizon queue dashboards. |
| `inurl:"/silk/" intitle:"Silk" "Requests" "Profiling" "Django"` | 9 | Finds Django Silk profiling dashboards. |
| `inurl:"/ray" intitle:"Ray" "Laravel" "Requests"` | 7 | Finds Spatie Ray-related web surfaces. Useful, but less standard than bigger debug suites. |
| `inurl:"/__clockwork/" OR inurl:"/clockwork/app"` | 8 | Finds Clockwork profiler interfaces on PHP apps. |
| `inurl:"/xhprof" "XHProf" "Overall Summary" "Incl. Wall Time"` | 9 | Finds XHProf profiling pages leaking callgraph and performance details. |
| `inurl:"/debug/pprof/" "Profile" "Heap" "Goroutine"` | 10 | Finds Go pprof endpoints exposing heap, goroutines, and profiling data. |
| `inurl:"/debug/vars" "cmdline" "memstats" "goroutines"` | 9 | Finds Go expvar endpoints leaking runtime stats. |
| `inurl:"/metrics" "go_gc_duration" "process_resident_memory"` | 8 | Finds Prometheus metrics pages for Go services. |
| `inurl:"/metrics" "python_info" "process_start_time"` | 8 | Finds Prometheus metrics pages for Python services. |

---

### Exposed API Documentation

| Dork | Score | Clear description |
|---|---:|---|
| `inurl:"/swagger-ui/" "Authorize" "Try it out" -github.com` | 8 | Finds live Swagger UI deployments with interactive request capability. |
| `inurl:"/swagger/v1/swagger.json" "paths" "components"` | 9 | Finds raw OpenAPI spec JSON exposing full API structure. |
| `inurl:"/graphql" intitle:"GraphiQL" "Explorer" "Query"` | 9 | Finds GraphiQL IDEs exposing schema exploration and query execution. |
| `inurl:"/graphql/playground" OR inurl:"/playground" "GraphQL Playground"` | 9 | Finds GraphQL Playground IDEs. |
| `inurl:"/altair" intitle:"Altair" "GraphQL"` | 8 | Finds Altair GraphQL client interfaces. |
| `inurl:"/api/v1" "swagger" "schemas" "endpoints" intitle:"API"` | 7 | Finds generic API docs or versioned endpoint docs. |
| `inurl:"/dredd" OR inurl:"/stoplight" "API" "endpoints"` | 7 | Finds API testing or documentation tools left exposed. |

---

## Exposed Services

### Elasticsearch — Deep Internals

| Dork | Score | Clear description |
|---|---:|---|
| `inurl:"/_cat/indices" "health" "pri" "docs.count"` | 10 | Finds Elasticsearch index inventory with doc counts and sizes. |
| `inurl:"/_cat/nodes" "heap.percent" "ram.percent" "master"` | 10 | Finds node hardware and heap details, revealing cluster topology. |
| `inurl:"/_cat/shards" "prirep" "store" "node"` | 10 | Finds shard allocation maps showing where data lives. |
| `inurl:"/_cat/allocation" "shards" "disk.used" "disk.avail"` | 9 | Finds disk allocation and capacity data per node. |
| `inurl:"/_cluster/health" "cluster_name" "number_of_nodes"` | 9 | Finds cluster health endpoints exposing cluster identity and node count. |
| `inurl:"/_cluster/settings" "persistent" "transient"` | 10 | Finds live cluster settings, sometimes including snapshot or repository details. |
| `inurl:"/_cluster/state" "metadata" "indices"` | 10 | Finds full cluster state dumps with metadata and mappings. |
| `inurl:"/_nodes" "transport_address" "jvm" "os" "process"` | 10 | Finds per-node OS, JVM, and process details. |
| `inurl:"/_nodes/stats" "indices" "jvm" "thread_pool"` | 10 | Finds detailed performance and runtime stats for every node. |
| `inurl:"/_mapping" "properties" "type" "keyword" OR "text"` | 10 | Finds index mappings that reveal full schema structure. |
| `inurl:"/_aliases" "index" "alias"` | 8 | Finds alias configuration and index naming patterns. |
| `inurl:"/_search" "hits" "total" "_source" "_index"` | 10 | Finds open search endpoints returning actual document content. |
| `inurl:"/_snapshot" "type" "s3" OR "fs" "settings"` | 10 | Finds snapshot repository config revealing storage backends and sometimes credential-adjacent details. |
| `inurl:"/_template" "index_patterns" "mappings"` | 9 | Finds index templates describing how new data is structured. |
| `inurl:"/_ingest/pipeline" "description" "processors"` | 9 | Finds ingest pipelines revealing data transformation logic. |
| `inurl:"/_security" "roles" "users" inurl:":9200"` | 10 | Finds exposed security configuration endpoints. |
| `inurl:"/_tasks" "action" "running_time_in_nanos" "node"` | 8 | Finds task endpoints exposing ongoing operations and node activity. |
| `inurl:"/_render/template" "source" "params"` | 8 | Finds template rendering endpoints that reveal query logic. |
| `inurl:":9200" "name" "cluster_name" "version" "lucene_version"` | 9 | Finds root Elasticsearch banners on open clusters. |

---

### Redis — Exposed Interfaces

| Dork | Score | Clear description |
|---|---:|---|
| `intitle:"Redis Commander" "dbsize" "connected_clients" "used_memory"` | 9 | Finds Redis Commander showing live cache stats and connected-client data. |
| `intitle:"Redis Commander" inurl:"/apiv2/server/info"` | 10 | Finds Redis Commander API endpoints leaking full INFO output. |
| `intitle:"RedisInsight" "Databases" "Add Redis database"` | 9 | Finds RedisInsight interfaces that may allow browsing or adding Redis connections. |
| `intitle:"phpRedisAdmin" "INFO" "Server" "redis_version"` | 9 | Finds phpRedisAdmin showing raw server info. |
| `intitle:"phpRedisAdmin" "keys" "KEYS *" "TTL"` | 10 | Finds Redis key-browsing interfaces exposing actual key data paths. |
| `intitle:"Redis Stat" "dbsize" "used_memory_human"` | 8 | Finds Redis monitoring pages exposing memory and database stats. |
| `intitle:"Medis" "Redis" "Connection" "Terminal"` | 10 | Finds Redis web clients with terminal-style access. |
| `inurl:"/redis-stack/browser" "Keys" "Search"` | 10 | Finds Redis Stack browser interfaces allowing key enumeration. |
| `intitle:"Webdis" "commands" "info" "keys" inurl:":7379"` | 10 | Finds Webdis HTTP-to-Redis gateways exposing raw command capability. |
| `inurl:"/redis/info" "redis_version" "connected_clients" "used_memory"` | 8 | Finds custom Redis info endpoints exposing server internals. |

---

### Apache — Internal Status & Misconfiguration

| Dork | Score | Clear description |
|---|---:|---|
| `inurl:"/server-status" "Apache Server Status" "Total accesses" "CPU Usage"` | 10 | Finds full Apache mod_status output with request and client details. |
| `inurl:"/server-status?auto" "Total Accesses" "BusyWorkers"` | 10 | Finds machine-readable status endpoints that are easy to scrape at scale. |
| `inurl:"/server-info" "Server Settings" "Module Name" "Content handlers"` | 10 | Finds Apache mod_info pages exposing modules and config directives. |
| `inurl:"/balancer-manager" "LoadBalancer" "Worker URL" "Route"` | 9 | Finds balancer-manager pages revealing backend topology. |
| `inurl:"/balancer-manager" "Enable Balancer Manager" "httpd.conf"` | 8 | Finds balancer-manager pages with config hints or exposed controls. |
| `intitle:"Apache Tomcat" inurl:"/manager/html" "List Applications"` | 10 | Finds Tomcat Manager with application management capability. |
| `intitle:"Apache Tomcat" inurl:"/host-manager/html" "Add Virtual Host"` | 10 | Finds Tomcat Host Manager with virtual-host management capability. |
| `inurl:"/status" "Apache" "mod_jk" "worker" "Type" "Host"` | 8 | Finds mod_jk status pages revealing backend worker mappings. |
| `inurl:"/jkmanager" "worker" "ajp13" "host" "port"` | 9 | Finds JK Manager pages exposing AJP connector and backend details. |
| `intitle:"Index of" "/.htpasswd" OR "/.htaccess"` | 10 | Finds browsable Apache auth files or access-control artifacts. |
| `intitle:"Index of" "/conf/" "httpd.conf" OR "apache2.conf"` | 10 | Finds Apache config files in served directories. |
| `intitle:"Index of" "/etc/apache2/" OR "/etc/httpd/"` | 10 | Finds entire Apache config directories exposed. |
| `inurl:"/icons/" "Apache" intitle:"Index of" "README"` | 6 | Finds default `/icons/` alias exposure, a weak but useful default-config clue. |
| `inurl:"/cgi-bin/printenv" "DOCUMENT_ROOT" "SERVER_SOFTWARE"` | 10 | Finds printenv CGI pages leaking environment variables and server internals. |
| `inurl:"/cgi-bin/test-cgi" "SERVER_SOFTWARE" "REMOTE_ADDR"` | 9 | Finds default test CGI scripts exposing request and server details. |

---

### SSH — Indexed Artifacts That Should Never Exist on the Web

| Dork | Score | Clear description |
|---|---:|---|
| `intitle:"Index of" "id_rsa" "id_rsa.pub"` | 10 | Finds SSH keypairs in open directories. Critical exposure. |
| `intitle:"Index of" "id_ed25519" "id_ed25519.pub"` | 10 | Finds Ed25519 keypairs exposed on the web. |
| `intitle:"Index of" "id_ecdsa"` | 10 | Finds ECDSA private keys exposed in open listings. |
| `intitle:"Index of" "authorized_keys"` | 9 | Finds authorized_keys files, revealing which public keys have access. |
| `intitle:"Index of" "known_hosts" "ssh-rsa" OR "ssh-ed25519"` | 8 | Finds known_hosts files mapping internal hostnames and fingerprints. |
| `intitle:"Index of" "ssh_host_" "key"` | 10 | Finds SSH host keys, which are extremely sensitive operationally. |
| `intitle:"Index of" ".ssh/" "config"` | 10 | Finds entire `.ssh` directories containing configs, keys, and host mappings. |
| `filetype:pub "ssh-rsa" OR "ssh-ed25519" "root@" OR "admin@"` | 6 | Finds public keys with useful username hints. Lower impact than private key exposure. |
| `intitle:"Index of" "sshd_config"` | 8 | Finds SSHD config files exposing auth methods, ports, and policy choices. |
| `intitle:"Shell In A Box" "Shell In A Box" inurl:":4200"` | 9 | Finds web-based shell frontends exposing SSH-like terminal access. |
| `intitle:"Wetty" "Terminal" inurl:"/wetty"` | 9 | Finds Wetty browser-based terminal interfaces. |
| `intitle:"GateOne" "Terminal" "SSH"` | 9 | Finds Gate One web SSH terminals. |
| `intitle:"WebSSH" "Hostname" "Username" "Password"` | 8 | Finds WebSSH login forms and terminal frontends. |
| `intitle:"Guacamole" inurl:"/guacamole" "Login"` | 8 | Finds Apache Guacamole gateways for clientless remote access. |

---

### Telnet

| Dork | Score | Clear description |
|---|---:|---|
| `intitle:"BusyBox" "httpd" "telnetd" inurl:"/cgi-bin"` | 9 | Finds embedded BusyBox devices with telnet and CGI-based administration. |
| `"Telnet" "port 23" "login:" inurl:"/cgi-bin/"` | 8 | Finds CGI wrappers exposing telnet login prompts. |
| `intitle:"Telnet" "Terminal" inurl:":8023"` | 8 | Finds web-based telnet terminals on alternate ports. |
| `intitle:"MikroTik" "RouterOS" "telnet" inurl:"/webfig"` | 7 | Finds MikroTik interfaces where telnet may be enabled or referenced. |
| `"telnet" "console" "Serial" intitle:"Terminal Server"` | 8 | Finds terminal servers bridging serial/telnet into web interfaces. |
| `intitle:"Lantronix" "Telnet" "Configuration"` | 8 | Finds Lantronix serial-to-IP management portals. |
| `intitle:"Digi" "Connect" "Telnet" "Configuration" "Network"` | 8 | Finds Digi serial/telnet gateways. |
| `intitle:"ser2net" "configuration" "connection"` | 7 | Finds ser2net serial-over-network configuration surfaces. |

---

## Web Framework Internals — Zero Reason to Be Public

### Django

| Dork | Score | Clear description |
|---|---:|---|
| `inurl:"/__debug__/sql_select/" "Executed SQL"` | 10 | Finds Django Debug Toolbar SQL panels exposing executed queries and parameters. |
| `inurl:"/__debug__/sql_explain/" "EXPLAIN"` | 9 | Finds SQL EXPLAIN panels revealing query plans and schema hints. |
| `inurl:"/__debug__/template_source/" "Template source"` | 10 | Finds debug toolbar template-source panels exposing actual template code. |
| `inurl:"/__debug__/sql_profile/" "profiling"` | 9 | Finds SQL profiling endpoints. |
| `inurl:"/admin/doc/" "Documentation" "Models" "Views" "Tags" "Django"` | 7 | Finds Django admindocs, which can reveal models and view structure. |
| `inurl:"/silk/requests/" "Path" "Time" "Num. Queries" "Django"` | 9 | Finds Django Silk request profilers. |
| `inurl:"/silk/sql/" "Query" "Time Taken" "Num. Queries"` | 9 | Finds Silk SQL profiler views with query details. |
| `inurl:"/silk/profiling/" "Function" "Time" "Calls"` | 9 | Finds Silk cProfile or function-level profiler output. |

### Laravel

| Dork | Score | Clear description |
|---|---:|---|
| `inurl:"/telescope/requests" "Method" "URI" "Status" "Duration"` | 10 | Finds Telescope request logs exposing HTTP activity. |
| `inurl:"/telescope/exceptions" "Class" "File" "Line" "Occurred"` | 10 | Finds Telescope exception logs with file and line details. |
| `inurl:"/telescope/queries" "Connection" "Duration" "Slow"` | 10 | Finds Telescope query logs exposing SQL activity. |
| `inurl:"/telescope/mail" "Mailable" "To" "Subject"` | 10 | Finds Telescope mail logs exposing outbound email data. |
| `inurl:"/telescope/dumps" "Dump" "HtmlDumper"` | 9 | Finds dump output from production debug logging. |
| `inurl:"/telescope/redis" "Command" "Duration"` | 10 | Finds Telescope Redis logs exposing cache/session operations. |
| `inurl:"/telescope/schedule" "Command" "Expression" "Cron"` | 9 | Finds scheduler logs revealing cron jobs and command cadence. |
| `inurl:"/horizon/api/stats" "wait" "throughput" "runtime"` | 9 | Finds Horizon stats APIs exposing queue metrics. |
| `inurl:"/_debugbar/open" "queries" "request" "session"` | 10 | Finds Laravel Debugbar open endpoints with rich request dumps. |
| `inurl:"/_ignition/health-check" "can_execute_commands"` | 10 | Finds Ignition health checks indicating dangerous debug exposure. |
| `inurl:"/_ignition/execute-solution" "solution" "parameters"` | 10 | Finds the Ignition solution executor endpoint, which is exceptionally sensitive. |

### Spring Boot

| Dork | Score | Clear description |
|---|---:|---|
| `inurl:"/actuator/env" "spring.datasource" "password" "jdbc"` | 10 | Finds Spring Actuator env dumps with datasource details. |
| `inurl:"/actuator/heapdump" "application/octet-stream"` | 10 | Finds downloadable heap dumps. |
| `inurl:"/actuator/configprops" "spring.mail.password" OR "spring.redis"` | 10 | Finds resolved config properties exposing secrets or internal config. |
| `inurl:"/actuator/beans" "scope" "type" "dependencies"` | 9 | Finds full Spring bean graphs. |
| `inurl:"/actuator/threaddump" "threadName" "stackTrace" "RUNNABLE"` | 9 | Finds thread dumps with runtime execution state. |
| `inurl:"/actuator/loggers" "configuredLevel" "effectiveLevel"` | 8 | Finds logger configuration endpoints. |
| `inurl:"/actuator/scheduledtasks" "cron" "fixedRate"` | 8 | Finds scheduled task listings. |
| `inurl:"/actuator/flyway" "installedOn" "script" "checksum"` | 9 | Finds Flyway migration history. |
| `inurl:"/actuator/liquibase" "changeSet" "author"` | 9 | Finds Liquibase migration history. |
| `inurl:"/actuator/prometheus" "jvm_memory" "http_server_requests"` | 8 | Finds Prometheus-formatted app metrics. |
| `inurl:"/actuator/sessions" "sessionId" "creationTime"` | 10 | Finds session-management endpoints leaking active sessions. |
| `inurl:"/actuator/caches" "cacheManager" "target"` | 8 | Finds Actuator cache endpoints exposing cache structure. |
| `inurl:"/jolokia/read" "java.lang:type=Runtime" "ClassPath"` | 9 | Finds Jolokia runtime reads exposing classpath and runtime info. |
| `inurl:"/jolokia/exec" "java.lang:type=Runtime"` | 10 | Finds Jolokia exec surfaces capable of dangerous MBean invocation. |

### Rails

| Dork | Score | Clear description |
|---|---:|---|
| `"Rails" "Action Controller" "Application Trace" "Framework Trace" "Full Trace"` | 8 | Finds Rails exception pages with full trace views. |
| `inurl:"/rails/info/properties" "Rails version" "Ruby version" "Application root"` | 9 | Finds Rails info properties showing versions and filesystem paths. |
| `inurl:"/rails/info/routes" "Helper" "HTTP Verb" "Path" "Controller#Action"` | 9 | Finds full Rails route listings. |
| `inurl:"/rails/mailers" "Mailer" "Action" "Preview"` | 8 | Finds ActionMailer previews exposing email content and templates. |
| `inurl:"/letter_opener" "Inbox" "Subject" "From" "To"` | 9 | Finds LetterOpener dev mail inboxes. |
| `intitle:"Better Errors" "REPL" "local_variables" "instance_variables"` | 10 | Finds BetterErrors interactive REPL pages. |
| `inurl:"/sidekiq" "Busy" "Enqueued" "Retries" "Dead" "Processed"` | 9 | Finds Sidekiq dashboards exposing job operations. |
| `inurl:"/sidekiq/busy" "Worker" "JID" "Queue" "Arguments"` | 10 | Finds Sidekiq busy pages exposing job arguments. |

### Express / Node.js

| Dork | Score | Clear description |
|---|---:|---|
| `"Express" "stack" "node_modules" "at Layer.handle" "at Route.dispatch"` | 7 | Finds Express stack traces exposing route and middleware details. |
| `inurl:"/debug" "heapTotal" "heapUsed" "external" "rss" "node"` | 8 | Finds Node debug endpoints leaking memory/process stats. |
| `inurl:"/health" "uptime" "memoryUsage" "nodeVersion" "pid"` | 6 | Finds overly verbose health checks. Useful for inventory, but lower severity than full debug tools. |
| `inurl:"/status" "env" "NODE_ENV" "production" OR "development"` | 7 | Finds status endpoints revealing environment and runtime configuration. |
| `intitle:"Apollo Server" "GraphQL Playground" inurl:"/graphql"` | 9 | Finds Apollo GraphQL playgrounds exposing schema and mutation capability. |
| `inurl:"/bull-board" "Queues" "Active" "Completed" "Failed"` | 9 | Finds Bull Board queue dashboards for Node services. |

---

## Core IP-Only Targeting Patterns


| Dork | Score | Clear description |
|---|---:|---|
| `intitle:"Index of /" inurl:"10."` | 6 | Finds listings that appear to reference RFC1918-style `10.x` paths or proxied IP-only content. |
| `intitle:"Index of /" inurl:"192.168."` | 6 | Finds content with `192.168.x.x` style addressing visible in URLs. |
| `intitle:"Index of /" inurl:"172.16." OR inurl:"172.17." OR inurl:"172.18."` | 6 | Finds internal/Docker-style addressing leaking into indexed content. |
| `site:*.*.*.* intitle:"Index of"` | 7 | Broad IP-address site operator pattern for finding bare-IP directory listings. |
| `intitle:"Index of /" "Server at" inurl:":8080"` | 8 | Finds IP-based services on 8080 that expose directory listings. Strong dev/test signal. |
| `intitle:"Index of /" "Server at" inurl:":8443"` | 8 | Finds IP-based HTTPS-ish services on 8443 exposing listings. |
| `intitle:"Index of /" "Server at" inurl:":3000"` | 8 | Finds Node/Rails/dev-server style directory listings on 3000. |
| `intitle:"Index of /" "Server at" inurl:":9090"` | 8 | Finds Prometheus/Cockpit/misc services exposing listings on 9090. |

---

### Default Install Pages (Bare IP)

| Dork | Score | Clear description |
|---|---:|---|
| `intitle:"Apache2 Ubuntu Default Page" inurl:":80" -www -site:*.com -site:*.org -site:*.net` | 7 | Finds default Apache installs hosted directly on bare IPs. |
| `intitle:"Welcome to nginx!" inurl:":80" -www -site:*.com -site:*.org` | 7 | Finds default nginx pages on raw IPs. |
| `intitle:"Test Page for the Apache HTTP Server" -site:*.com -site:*.org -site:*.net -site:*.edu` | 7 | Finds default Apache test pages, biased toward non-branded bare-IP installs. |
| `intitle:"IIS Windows Server" -site:*.com -site:*.org -site:*.net` | 7 | Finds default IIS pages on bare IPs. |
| `intitle:"Apache Tomcat" "If you're seeing this" -site:*.com -site:*.org` | 8 | Finds Tomcat default pages on raw IPs, often with adjacent manager surfaces. |
| `intitle:"Welcome to CentOS" "Apache HTTP Server" -www` | 7 | Finds CentOS Apache default landing pages. |
| `intitle:"Fedora Test Page" "Fedora" "Apache" -www` | 7 | Finds Fedora Apache test pages on undeveloped hosts. |
| `intitle:"OpenResty" "Welcome to OpenResty" -site:*.com` | 7 | Finds default OpenResty pages on bare-IP services. |

---

### Management Panels (Bare IP)

| Dork | Score | Clear description |
|---|---:|---|
| `intitle:"Webmin" inurl:":10000" -site:*.com -site:*.org` | 9 | Finds Webmin on bare IPs, a highly sensitive full-server management surface. |
| `intitle:"Cockpit" "Log in" inurl:":9090" -site:*.com` | 8 | Finds Cockpit server dashboards on bare IPs. |
| `intitle:"Portainer" inurl:":9000" -site:*.com -site:*.org` | 9 | Finds Portainer Docker management on IP-only hosts. |
| `intitle:"Proxmox" "Virtual Environment" inurl:":8006" -site:*.com` | 10 | Finds Proxmox hypervisor management on raw IPs. |
| `intitle:"TrueNAS" "Log In" -site:*.com -site:*.org` | 8 | Finds TrueNAS storage admin on bare IPs. |
| `intitle:"Synology" "DiskStation" -site:*.com -site:*.org` | 8 | Finds Synology NAS admin portals on raw IPs. |
| `intitle:"QNAP" "QTS" "Login" -site:*.com -site:*.org` | 8 | Finds QNAP management portals. |
| `intitle:"pfSense" "Login" -site:*.com -site:*.org -site:*.net` | 9 | Finds pfSense firewall management on bare IPs. |
| `intitle:"OPNsense" "Login" -site:*.com -site:*.org` | 9 | Finds OPNsense firewall administration on raw IPs. |
| `intitle:"UniFi" "Network" "Login" -site:*.com -site:*.org` | 8 | Finds UniFi controller login portals on bare IPs. |
| `intitle:"iDRAC" "Login" -site:*.com -site:*.org` | 10 | Finds Dell iDRAC out-of-band management. Extremely sensitive. |
| `intitle:"iLO" "Integrated Lights-Out" -site:*.com -site:*.org` | 10 | Finds HP iLO management consoles. Extremely sensitive. |
| `intitle:"IPMI" "Login" -site:*.com -site:*.org` | 10 | Finds generic IPMI/BMC web interfaces. Extremely sensitive. |

---

### Database Interfaces (Bare IP)

| Dork | Score | Clear description |
|---|---:|---|
| `intitle:"phpMyAdmin" inurl:":8080" OR inurl:":8888" -site:*.com` | 9 | Finds phpMyAdmin on non-standard ports hosted directly on IPs. |
| `intitle:"phpPgAdmin" -site:*.com -site:*.org -site:*.net` | 9 | Finds phpPgAdmin instances on bare IPs. |
| `intitle:"Adminer" "Login" "System" "Server" "Username" -site:*.com` | 9 | Finds Adminer database-management interfaces on IP-only hosts. |
| `intitle:"Mongo Express" "Database" "Collections" -site:*.com` | 9 | Finds Mongo Express dashboards. |
| `intitle:"CouchDB" "Welcome" "couchdb" inurl:":5984"` | 9 | Finds CouchDB/Fauxton-style surfaces on raw IPs. |
| `intitle:"Redis Commander" -site:*.com -site:*.org` | 9 | Finds Redis Commander on bare IPs. |
| `inurl:":9200" "cluster_name" "version" "lucene_version" -site:*.com` | 10 | Finds Elasticsearch root endpoints on bare IPs. |
| `inurl:":15672" intitle:"RabbitMQ Management" -site:*.com` | 9 | Finds RabbitMQ management interfaces on bare IPs. |
| `intitle:"Kibana" "Discover" "Dashboard" -site:*.com -site:*.org` | 8 | Finds Kibana dashboards on bare IPs. |

---

### CI/CD & DevOps (Bare IP)

| Dork | Score | Clear description |
|---|---:|---|
| `intitle:"Jenkins" "Dashboard" inurl:":8080" -site:*.com -site:*.org` | 9 | Finds Jenkins dashboards on bare IPs. |
| `intitle:"GitLab" "Sign in" inurl:":8080" OR inurl:":443" -site:*.com` | 8 | Finds self-hosted GitLab on raw IPs. |
| `intitle:"Gitea" "Sign In" -site:*.com -site:*.org` | 8 | Finds Gitea instances on bare IPs. |
| `intitle:"Gogs" "Sign In" -site:*.com -site:*.org` | 8 | Finds Gogs instances on raw IPs. |
| `intitle:"Drone CI" "Welcome" OR "Repositories" -site:*.com` | 8 | Finds Drone CI interfaces on bare IPs. |
| `intitle:"Argo CD" "Login" -site:*.com -site:*.org` | 8 | Finds Argo CD dashboards on bare IPs. |
| `intitle:"SonarQube" "Projects" "Quality Gates" -site:*.com` | 8 | Finds SonarQube dashboards. |
| `intitle:"Nexus Repository Manager" "Sign in" -site:*.com` | 8 | Finds Nexus repository managers on IP-only hosts. |
| `intitle:"Harbor" "Sign In" "Registry" -site:*.com -site:*.org` | 8 | Finds Harbor container registry portals. |
| `intitle:"TeamCity" "Log in" -site:*.com -site:*.org` | 8 | Finds TeamCity build-server dashboards. |

---

### Monitoring & Observability (Bare IP)

| Dork | Score | Clear description |
|---|---:|---|
| `intitle:"Grafana" inurl:":3000/login" -site:*.com -site:*.org` | 8 | Finds Grafana login portals on bare IPs. |
| `intitle:"Prometheus" "Targets" "Configuration" inurl:":9090" -site:*.com` | 9 | Finds Prometheus targets/configuration pages on raw IPs. |
| `intitle:"AlertManager" "Alerts" "Silences" inurl:":9093" -site:*.com` | 8 | Finds AlertManager consoles on bare IPs. |
| `intitle:"Nagios" "Current Network Status" -site:*.com -site:*.org` | 8 | Finds Nagios dashboards with topology and host data. |
| `intitle:"Zabbix" "Sign in" -site:*.com -site:*.org -site:*.net` | 8 | Finds Zabbix monitoring interfaces on bare IPs. |
| `intitle:"Cacti" "Login" inurl:"/cacti" -site:*.com` | 8 | Finds Cacti monitoring portals. |
| `intitle:"LibreNMS" "Login" -site:*.com -site:*.org` | 8 | Finds LibreNMS monitoring dashboards. |
| `intitle:"Uptime Kuma" "Status" -site:*.com -site:*.org` | 7 | Finds Uptime Kuma status or management pages on raw IPs. |
| `intitle:"Netdata" "Dashboard" inurl:":19999" -site:*.com` | 9 | Finds Netdata dashboards exposing detailed real-time host metrics. |
| `intitle:"Graylog" "Search" "Streams" inurl:":9000" -site:*.com` | 8 | Finds Graylog log-management interfaces. |

---

### Routers, Switches & Network Gear (Bare IP)

| Dork | Score | Clear description |
|---|---:|---|
| `intitle:"RouterOS" inurl:"/webfig" -site:*.com` | 9 | Finds MikroTik RouterOS admin surfaces on raw IPs. |
| `intitle:"ZyXEL" "Login" -site:*.com -site:*.org` | 8 | Finds ZyXEL device administration portals. |
| `intitle:"TP-LINK" "Login" -site:*.com -site:*.org` | 8 | Finds TP-Link router web admin panels. |
| `intitle:"NETGEAR" "Login" OR "Firmware" -site:*.com` | 8 | Finds NETGEAR management portals. |
| `intitle:"ASUS" "Login" "Router" -site:*.com -site:*.asus.com` | 8 | Finds ASUS router management interfaces. |
| `intitle:"Fortinet" "FortiGate" "Login" -site:*.com -site:*.org` | 9 | Finds FortiGate firewall management pages on bare IPs. |
| `intitle:"SonicWall" "Login" -site:*.com -site:*.org` | 9 | Finds SonicWall firewall management portals. |
| `intitle:"Aruba" "Login" "Controller" -site:*.com -site:*.org` | 8 | Finds Aruba controller interfaces on bare IPs. |

---

### Cameras & Physical Security (Bare IP)

| Dork | Score | Clear description |
|---|---:|---|
| `intitle:"Live View / - AXIS" -site:*.com -site:*.org` | 9 | Finds Axis cameras directly on bare IPs, often exposing live views. |
| `inurl:"/view/viewer_index.shtml" -site:*.com` | 8 | Finds Axis or similar viewer pages on raw IPs. |
| `intitle:"Hikvision" "Login" -site:*.com -site:*.org` | 8 | Finds Hikvision camera/NVR login portals. |
| `intitle:"Dahua" "Login" -site:*.com -site:*.org` | 8 | Finds Dahua management portals. |
| `intitle:"Blue Iris" "Login" -site:*.com -site:*.org` | 8 | Finds Blue Iris NVR login pages. |
| `inurl:":37777" "Login" -site:*.com` | 8 | Finds Dahua-style services or related interfaces on their common port. |
| `intitle:"DVR" "Login" "admin" inurl:":8000" OR inurl:":8080" -site:*.com` | 8 | Finds DVR web interfaces on common alternate ports. |

---

## Pro Tips

### Deeper validation and scoping

| Tip | Description |
|---|---|
| Chain with TLDs | Appending `site:*.edu`, `site:*.gov`, or country TLDs narrows results toward institutional infrastructure, which often has different neglect patterns. |
| Wayback Machine cross-reference | Use archived snapshots to distinguish truly abandoned infrastructure from pages with stale footers but active maintenance. |
| Shodan/Censys complement | Search engines find indexed web content. Internet-wide search engines help verify open ports, banners, and TLS state. |
| `cache:` operator | Useful for intermittently unavailable or half-dead hosts whose indexed content remains in search cache. |
| Scope to owned assets | When validating your own estate, add `site:example.com` or similar scope to reduce noise and avoid dragging in unrelated hosts. |
| Combine operators | Combining `intitle:`, `inurl:`, and `site:` significantly improves precision and reduces junk results. |

### Wildcard IP-only exclusion pattern

```text
-site:*.com -site:*.org -site:*.net -site:*.edu -site:*.gov -site:*.io -site:*.co -site:*.dev -site:*.app -site:*.me -www
```

Use a reduced subset when needed because Google limits how many negations can be practical in a single query.
