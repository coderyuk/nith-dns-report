# DNS Security Assessment & Proof-of-Concept (PoC) Report

**Target Domain:** `nith.ac.in`  
**Authoritative Nameservers:**

- `name.nith.ac.in` (`14.139.56.2`) — Primary Nameserver
- `name1.nith.ac.in` (`14.139.56.3`) — On-Campus Secondary Nameserver
- `name2.nith.ac.in` (`117.251.114.194`) — Off-Campus Secondary Nameserver

**Assessment Date:** November 2, 2026  
**Scope:** Analysis of zone transfer captures (`name.txt`, `name1.txt`, `name2.txt`) and delegation path trace (`dig+trace.txt`).

---

## 1. Executive Summary & Vulnerability Matrix

An assessment of the DNS infrastructure for `nith.ac.in` uncovered **seven distinct vulnerabilities** ranging from High to Low severity. Most notably, the domain suffers from a classic **"Secured Primary, Exposed Secondaries"** misconfiguration alongside an **unlinked and unsigned DNSSEC deployment**. While the primary nameserver (`name.nith.ac.in`) restricts zone transfers, both secondary nameservers (`name1.nith.ac.in` and `name2.nith.ac.in`) allow any unauthenticated host on the internet to download the complete 86-record zone file over TCP port 53.

| ID          | Vulnerability Title                                             | Affected Component                      | Severity   | CVSS v3.1 | Status |
| :---------- | :-------------------------------------------------------------- | :-------------------------------------- | :--------- | :-------- | :----- |
| **VULN-01** | Unauthenticated Zone Transfer (AXFR) on Secondary Nameservers   | `name1.nith.ac.in`, `name2.nith.ac.in`  | **High**   | 7.5       | Open   |
| **VULN-02** | Broken DNSSEC Chain of Trust & Deprecated SHA-1 Cryptography    | `nith.ac.in` Zone / `.ac.in` Delegation | **High**   | 7.4       | Open   |
| **VULN-03** | Subdomain Takeover Vectors via External CNAME & A Records       | 16 Subdomains (Vercel, GitHub, Netlify) | **High**   | 8.2*      | Open   |
| **VULN-04** | Exposure of Internal Infrastructure (Missing Split-Horizon DNS) | `14.139.56.0/24` Subnet                 | **Medium** | 6.5       | Open   |
| **VULN-05** | Lack of Network Segmentation & Multi-Tier Host Co-Location      | `.3`, `.11`, `.17`, `.28` Hosts         | **Medium** | 6.1       | Open   |
| **VULN-06** | Permissive Email Authentication Policies (SPF SoftFail & DMARC) | Root `TXT` & `_dmarc.nith.ac.in`        | **Medium** | 5.3       | Open   |
| **VULN-07** | Inverted SOA Refresh and Retry Timers                           | `nith.ac.in` `SOA` Record               | **Low**    | N/A       | Open   |

_\*Note: VULN-03 carries a CVSS score of 8.2 if any of the third-party cloud slugs or external domains become unclaimed/expired._

---

## 2. Detailed Vulnerability Analysis & Proofs of Concept

### VULN-01: Unauthenticated Zone Transfer (AXFR) on Secondary Nameservers

- **Severity:** High (CVSS v3.1: 7.5 — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`)
- **CWE Classification:** CWE-284 (Improper Access Control) / CWE-200 (Exposure of Sensitive Information)

#### Proof-of-Concept (PoC)

Testing full zone transfers (`AXFR`) against all three authoritative nameservers reveals inconsistent Access Control Lists (ACLs):

**1. Querying Primary Nameserver (`name.nith.ac.in` — Properly Secured):**

```bash
dig @name.nith.ac.in nith.ac.in axfr
```

_Output (`name.txt`):_

```text
; <<>> DiG 9.20.29-1-Debian <<>> @name.nith.ac.in nith.ac.in axfr
; (1 server found)
;; global options: +cmd
; Transfer failed.
```

**2. Querying Secondary Nameservers (`name1.nith.ac.in` & `name2.nith.ac.in` — Vulnerable):**

```bash
dig @name1.nith.ac.in nith.ac.in axfr
dig @name2.nith.ac.in nith.ac.in axfr
```

_Output (`name1.txt` and `name2.txt`):_

```text
nith.ac.in.		8549	IN	SOA	name.nith.ac.in. akc.nith.ac.in. 2025110738 2800 3600 1604800 86400
... [84 records omitted for brevity] ...
;; Query time: 60 msec
;; SERVER: 14.139.56.3#53(name1.nith.ac.in) (TCP)
;; WHEN: Mon Nov 02 02:35:31 IST 2026
;; XFR size: 86 records (messages 1, bytes 3690)
```

#### Technical Explanation & Exploitation Scenario

The DNS administrator restricted `AXFR` on the primary server (`name.nith.ac.in`) to allow only the secondary servers to pull zone updates, but failed to disable outbound zone transfers on the secondary servers (`name1` and `name2`). Because secondary nameservers hold an identical copy of the authoritative zone, an attacker can query either secondary server over TCP port 53 to dump the entire zone file.

**How an Attacker Exploits This:**

1. **Stealth Reconnaissance:** Instead of running noisy DNS brute-force tools (such as `gobuster`, `ffuf`, or `amass`) that generate thousands of queries and alert Intrusion Detection Systems (IDS), the attacker sends a single TCP packet to `14.139.56.3` or `117.251.114.194` and receives 100% of the domain's records in 36–60 milliseconds.
2. **Target Prioritization:** The dump immediately reveals high-value internal targets (`dbserver`, `ldap`, `adserver`, `idp`, `dev`, `tempcse`) and third-party CNAME mappings.

#### Remediation

Update the DNS configuration (e.g., `/etc/bind/named.conf.options` or zone blocks in BIND9) across all servers:

```nginx
// On Primary (name.nith.ac.in - 14.139.56.2):
zone "nith.ac.in" {
    type master;
    file "/etc/bind/zones/db.nith.ac.in";
    // Restrict transfers strictly to secondary IPs + TSIG key
    allow-transfer { key "tsig-transfer-key"; };
};

// On Secondaries (name1.nith.ac.in & name2.nith.ac.in):
zone "nith.ac.in" {
    type slave;
    masters { 14.139.56.2 key "tsig-transfer-key"; };
    // Never allow downstream hosts to pull zone transfers from secondaries
    allow-transfer { none; };
};
```

---

### VULN-02: Unlinked, Unsigned DNSSEC Deployment with Deprecated SHA-1 Keys

- **Severity:** High (CVSS v3.1: 7.4 — `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N`)
- **CWE Classification:** CWE-327 (Use of a Broken or Risky Cryptographic Algorithm) / CWE-345 (Insufficient Verification of Data Authenticity)

#### Proof-of-Concept (PoC)

Combining evidence from the zone transfer files (`name1.txt`, `name2.txt`) and the delegation trace (`dig+trace.txt`) proves three distinct failures in the DNSSEC deployment:

**1. Deprecated Algorithm 7 (`RSASHA1-NSEC3-SHA1`) Public Keys Published in Zone:**

```text
nith.ac.in. 8549 IN DNSKEY 256 3 7 AwEAActyuMZHyZqdbp++Kl3bjuOmRRxjEV46EWWYiBTbgms08GfHlc08...
nith.ac.in. 8549 IN DNSKEY 257 3 7 AwEAAb/g9IumVnVblcBWXKHzf1YJ8qhxSv9iOUgcwjWiIib2VRO9+leW...
```

_(In the `DNSKEY` format `Flags Protocol Algorithm PublicKey`, the value `7` represents `RSASHA1-NSEC3-SHA1`)._

**2. Broken Parent Chain of Trust (Missing `DS` Record in `.ac.in`):**  
In `dig+trace.txt`, the `.in` registry returns `NSEC3` records proving that no `DS` (Delegation Signer) record exists for `nith.ac.in`:

```text
nith.ac.in. 900 IN NS name2.nith.ac.in.
nith.ac.in. 900 IN NS name.nith.ac.in.
nith.ac.in. 900 IN NS name1.nith.ac.in.
2A7AF8STCGBAKKGI81GG1GAFJ7VAES17.ac.in. 300 IN NSEC3 1 1 0 - 2NS1OVIN6LLQREBPEQD5IH2CV67F1C3D NS SOA RRSIG DNSKEY NSEC3PARAM
BNG6NA3S2670U6U318I93IU40JM51J80.ac.in. 300 IN NSEC3 1 1 0 - LFNDMA3S65R8PN6MEULOTDLFV34LNMI5 NS DS RRSIG
;; Received 535 bytes from 64.96.2.1#53(ns2.registry.in) in 56 ms
```

**3. Complete Absence of `RRSIG` Records in the Child Zone:**  
Out of all 86 records returned in `name1.txt` and `name2.txt`, there are **zero** `RRSIG` or `NSEC3` records signing the `nith.ac.in` resource records.

#### Technical Explanation & Exploitation Scenario

The domain administrators generated a Zone Signing Key (`256`) and a Key Signing Key (`257`) and pasted the `DNSKEY` records into the zone file, but never actually signed the zone or submitted a `DS` record to the `.ac.in` parent registry.

- **Spoofing / Cache Poisoning Vulnerability:** Because the parent `.ac.in` servers return `NSEC3` records proving an **Insecure Delegation**, recursive resolvers worldwide treat `nith.ac.in` as an unsigned domain and skip signature checks. An attacker on a local network (such as campus Wi-Fi or an ISP path) can execute **DNS Spoofing / Cache Poisoning** to redirect users visiting `grades.nith.ac.in` or `moodle.nith.ac.in` to a malicious IP without triggering DNSSEC validation errors.
- **Cryptographic Weakness:** Algorithm `7` (`RSASHA1-NSEC3-SHA1`) relies on SHA-1, which is vulnerable to practical collision attacks (SHAttered) and is formally deprecated by IETF RFC 8624 (`MUST NOT` be used for DNSSEC signing).
- **Catastrophic Outage Risk:** If an administrator uploads a `DS` record for these keys to the `.ac.in` registry without first signing the zone to generate `RRSIG` records, every DNSSEC-validating resolver globally (`8.8.8.8`, `1.1.1.1`, `9.9.9.9`) will immediately return `SERVFAIL` for all `*.nith.ac.in` queries, taking the entire college offline.

#### Remediation

1. Remove the legacy Algorithm `7` `DNSKEY` records.
2. Generate new keys using **Algorithm 13 (`ECDSAP256SHA256`)** via `dnssec-keygen -a ECDSAP256SHA256 -n ZONE nith.ac.in`.
3. Enable automated zone signing in BIND9 (`dnssec-policy default;` or `inline-signing yes;`) and verify that `RRSIG` records are returned via `dig @name.nith.ac.in nith.ac.in A +dnssec`.
4. Only after confirming valid `RRSIG` propagation across `name`, `name1`, and `name2`, publish the `DS` record in the `.ac.in` registry.

---

### VULN-03: Subdomain Takeover Vectors via External CNAME & A Records

- **Severity:** High (CVSS v3.1: 8.2 — `AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N`)
- **CWE Classification:** CWE-350 (Reliance on Reverse DNS Resolution for a Security-Critical Action) / Dangling DNS Records

#### Proof-of-Concept (PoC)

The zone transfer exposes **16 external `CNAME` records**, **1 external `A` record**, and **1 Vercel verification `TXT` record** pointing outside the institute's `14.139.56.0/24` subnet:

```text
; Vercel Cloud Deployments (11 Subdomains)
appteam.nith.ac.in.         8549 IN CNAME app-team-website.vercel.app.
esummit.nith.ac.in.         8549 IN CNAME esummit-2k26.vercel.app.
festhillffair.nith.ac.in.   8549 IN CNAME 4de7d8c1494eb157.vercel-dns-017.com.
festnimbus.nith.ac.in.      8549 IN CNAME nimbus2k25-tan.vercel.app.
hack.nith.ac.in.            8549 IN CNAME hack-5-0.vercel.app.
hacksecure.nith.ac.in.      8549 IN CNAME hack-6-0.vercel.app.
literacymission.nith.ac.in. 8549 IN CNAME literacy-mission.vercel.app.
mathed2025.nith.ac.in.      8549 IN CNAME mathed-2025.vercel.app.
robosoc.nith.ac.in.         8549 IN CNAME 41c27a39828c054f.vercel-dns-017.com.
sec.nith.ac.in.             8549 IN CNAME csec-website.vercel.app.
shield.nith.ac.in.          8549 IN CNAME shield-static-website.vercel.app.

; GitHub Pages & Netlify Deployments (4 Subdomains)
aidccsp24.nith.ac.in.       8549 IN CNAME spec-nith.github.io.
electrothon.nith.ac.in.     8549 IN CNAME spec-nith.github.io.
spec.nith.ac.in.            8549 IN CNAME spec-nith.github.io.
ecell.nith.ac.in.           8549 IN CNAME ecellnith.netlify.app.

; External Custom Domains & Third-Party IPs
hackonhills.nith.ac.in.     8549 IN CNAME hackonhills.com.
alumni.nith.ac.in.          8549 IN CNAME hs.vaave.co.
shikshamahakumbh.nith.ac.in. 8549 IN A    187.127.184.57

; Leftover Verification Token
_vercel.nith.ac.in.         8549 IN TXT   "vc-domain-verify=shield.nith.ac.in,fda37c89656275a1cab5"
```

#### Technical Explanation & Exploitation Scenario

Several subdomains point to time-bound student hackathons, fests, or academic conferences (`aidccsp24`, `mathed2025`, `festnimbus`, `hack-5-0`, `hackonhills.com`). Student clubs typically host these sites on personal Vercel, Netlify, or GitHub accounts.

**How an Attacker Exploits This:**

1. **Claiming Abandoned Cloud Slugs:** If a student organizer deletes `mathed-2025.vercel.app`, `hack-5-0.vercel.app`, or `ecellnith.netlify.app` from their personal account, or renames the `spec-nith` GitHub organization, the `CNAME` in `nith.ac.in` remains active. An attacker can register that exact project name on Vercel/Netlify/GitHub and bind the `*.nith.ac.in` custom domain.
2. **Expired External Domain Registration:** `hackonhills.nith.ac.in` points via `CNAME` to a commercial `.com` domain (`hackonhills.com.`). If the student club fails to renew `hackonhills.com`, an attacker can buy the domain for ~$10 and instantly control `hackonhills.nith.ac.in`.
3. **Post-Takeover Impact:** With control over a legitimate `*.nith.ac.in` subdomain and a valid Let's Encrypt TLS certificate, an attacker can harvest Single Sign-On (SSO) credentials, capture session cookies scoped to `.nith.ac.in`, or deliver malware under the trusted institutional domain name.

#### Remediation

- Immediately audit all 16 `CNAME` records and `187.127.184.57` (`shikshamahakumbh.nith.ac.in`) to verify whether any return HTTP `404` / `DEPLOYMENT_NOT_FOUND` errors.
- Delete stale DNS records for past events (`aidccsp24`, `mathed2025`, `festnimbus`, `mind2023`, `rttp2024`).
- Enforce a policy requiring all third-party cloud deployments to reside under an official, institution-owned Vercel/GitHub/Netlify organization.

---

### VULN-04: Exposure of Core Internal Infrastructure (Missing Split-Horizon DNS)

- **Severity:** Medium (CVSS v3.1: 6.5 — `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`)
- **CWE Classification:** CWE-668 (Exposure of Resource to Wrong Sphere)

#### Proof-of-Concept (PoC)

The public zone dump exposes critical backend servers, authentication directories, and staging environments mapped to routable public IPv4 addresses:

```text
dbserver.nith.ac.in.    8549 IN A 14.139.56.10  ; Database Server
dev.nith.ac.in.         8549 IN A 14.139.56.11  ; Development Environment
development.nith.ac.in. 8549 IN A 14.139.56.11  ; Development Environment
idp.nith.ac.in.         8549 IN A 14.139.56.13  ; Identity Provider (SSO)
deployment.nith.ac.in.  8549 IN A 14.139.56.17  ; CI/CD or Deployment Host
adserver.nith.ac.in.    8549 IN A 14.139.56.22  ; Active Directory Server
tempcse.nith.ac.in.     8549 IN A 14.139.56.28  ; Temporary CSE Server
ldap.nith.ac.in.        8549 IN A 14.139.56.30  ; LDAP Directory Server
```

#### Technical Explanation & Exploitation Scenario

In a hardened enterprise or university network, internal infrastructure (Database servers, LDAP/Active Directory controllers, and staging servers) should use private RFC 1918 IP addresses (`10.x.x.x`, `172.16.x.x`, or `192.168.x.x`) and resolve only on internal DNS resolvers via **Split-Horizon (Split-Brain) DNS**.

**How an Attacker Exploits This:**

- **Targeted Service Exploitation:** An attacker knows immediately that `14.139.56.10` is the primary database server (`dbserver`) and can probe ports `3306` (MySQL), `5432` (PostgreSQL), `1433` (MSSQL), or `27017` (MongoDB).
- **Identity Compromise:** Knowing `14.139.56.30` (`ldap`) and `14.139.56.22` (`adserver`) allows an attacker to test for anonymous LDAP binds (port `389`/`636`) to dump the entire faculty and student directory, or execute password-spraying attacks.
- **Staging Environment Compromise:** Servers like `dev.nith.ac.in`, `deployment.nith.ac.in`, and `tempcse.nith.ac.in` frequently run unpatched code, exposed `.git` directories, debug modes (e.g., Laravel Telescope/Debugbar, Django Debug), or default credentials.

#### Remediation

- Implement **Split-Horizon DNS** (using BIND `view` statements) so internal hosts (`dbserver`, `ldap`, `adserver`, `dev`, `development`, `deployment`, `tempcse`) are served only to internal campus subnets.
- Migrate backend servers from public `14.139.56.0/24` IPs to private internal VLANs accessible solely via a hardened campus VPN.

---

### VULN-05: Lack of Network Segmentation & Multi-Tier Host Co-Location

- **Severity:** Medium (CVSS v3.1: 6.1 — `AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N`)
- **CWE Classification:** CWE-653 (Improper Isolation or Compartmentalization)

#### Proof-of-Concept (PoC)

Correlating the `A` records by IP address across `name1.txt` and `name2.txt` demonstrates that critical administrative systems share the exact same IP addresses with development servers, temporary sites, and student club portals:

| Shared Public IP   | Co-Located Subdomains on Host                                                                                 | Security Tier Conflict                                                                                   |
| :----------------- | :------------------------------------------------------------------------------------------------------------ | :------------------------------------------------------------------------------------------------------- |
| **`14.139.56.3`**  | `name1` (Secondary DNS), `exams`, `complaints`, `ntr`, `rec`, `web`                                           | **Critical DNS + Exam Portal** sharing a host with general web apps.                                     |
| **`14.139.56.11`** | `dev`, `development`, `semreg` (Semester Registration), `recruitment`                                         | **Unstable Dev/Staging** sharing a host with **Production Registration & Hiring**.                       |
| **`14.139.56.15`** | `academic`, `grades`                                                                                          | Academic & Grading portals co-located.                                                                   |
| **`14.139.56.16`** | `moodle`, `pgadmissions`, `portfolios`, `supplementary`                                                       | E-learning, Admissions, and Student Portfolios on a single host.                                         |
| **`14.139.56.17`** | `deployment`, `gatepass`, `tpo` (Placement), `elsoc`, `gdg`, `iste`, `mun`, `prody`, `rttp2024`, `icgesi2026` | **Placement (`tpo`) & Campus Security (`gatepass`)** sharing a host with **7 Student Club/Event sites**. |
| **`14.139.56.28`** | `cms`, `eo`, `mind2023`, `tempcse`                                                                            | **Temporary/Legacy sites (`tempcse`, `mind2023`)** on the same host as `cms` and `eo`.                   |

#### Technical Explanation & Exploitation Scenario

When multiple applications share a single IP address (without strict hypervisor/container isolation or reverse-proxy backend separation), a vulnerability in the least secure application compromises the entire host.

**How an Attacker Exploits This:**

1. **Lateral Movement on `14.139.56.17`:** Student society websites (`elsoc`, `gdg`, `iste`, `mun`, `prody`) or old conference pages (`rttp2024`) are often built rapidly by students and left unmaintained. An attacker can exploit an arbitrary file upload or SQL injection flaw on a club website to get a web shell on `14.139.56.17`, and then pivot locally to compromise the **Training & Placement Office (`tpo.nith.ac.in`)** or **Campus Gatepass (`gatepass.nith.ac.in`)** databases.
2. **Dev-to-Prod Pivot on `14.139.56.11`:** An attacker compromises a work-in-progress script on `dev.nith.ac.in` (`14.139.56.11`) and uses local access on the same server to tamper with **Semester Registration (`semreg.nith.ac.in`)** or **Faculty Recruitment (`recruitment.nith.ac.in`)**.
3. **DNS Takeover via Web Exploit on `14.139.56.3`:** Compromising any web application on `14.139.56.3` (`complaints`, `web`, `rec`) places the attacker on the exact same machine running the authoritative DNS service (`name1.nith.ac.in`).

#### Remediation

- Dedicate `14.139.56.3` (`name1.nith.ac.in`) exclusively to DNS operations and move `exams`, `complaints`, `ntr`, `rec`, and `web` to a separate application server.
- Isolate `dev.nith.ac.in` and `development.nith.ac.in` on a non-production server completely separate from `semreg` and `recruitment`.
- Move student society websites (`elsoc`, `gdg`, `iste`, `mun`, `prody`) off the server hosting `tpo.nith.ac.in` and `gatepass.nith.ac.in`.

---

### VULN-06: Permissive Email Authentication Policies (SPF SoftFail & DMARC Quarantine)

- **Severity:** Medium (CVSS v3.1: 5.3 — `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N`)
- **CWE Classification:** CWE-290 (Authentication Bypass by Spoofing)

#### Proof-of-Concept (PoC)

Inspecting the `TXT` records in `name1.txt` and `name2.txt` shows the following email security configuration:

```text
nith.ac.in.        8549 IN TXT "v=spf1 include:_spf.google.com ~all"
_dmarc.nith.ac.in. 8549 IN TXT "v=DMARC1;p=quarantine;rua=mailto:cc-admin@nith.ac.in"
```

#### Technical Explanation & Exploitation Scenario

- **SPF SoftFail (`~all`):** The tilde (`~`) prefix instructs receiving mail servers to accept unauthorized emails claiming to come from `@nith.ac.in` and merely mark them as "SoftFail" rather than rejecting them outright (`-all`).
- **DMARC `p=quarantine` & Missing `sp=` Tag:** While `p=quarantine` directs unauthenticated emails to the recipient's spam folder, it does not block delivery (`p=reject`) and lacks an explicit subdomain policy (`sp=reject`).

**How an Attacker Exploits This:**
An attacker can use an external SMTP server to send spear-phishing emails forged to appear from `director@nith.ac.in`, `tpo@nith.ac.in`, or `admin@exams.nith.ac.in`. Depending on the target organization's spam filter sensitivity, messages marked with SPF SoftFail (`~all`) may still reach the recipient's inbox or junk folder, increasing the likelihood of successful credential harvesting or financial fraud.

#### Remediation

Once `cc-admin@nith.ac.in` confirms via DMARC aggregate reports that all legitimate institutional mail servers are covered by `_spf.google.com`, update the records to enforce strict rejection:

```text
nith.ac.in.        3600 IN TXT "v=spf1 include:_spf.google.com -all"
_dmarc.nith.ac.in. 3600 IN TXT "v=DMARC1; p=reject; sp=reject; pct=100; adkim=s; aspf=s; rua=mailto:cc-admin@nith.ac.in"
```

---

### VULN-07: Inverted SOA Refresh and Retry Timers

- **Severity:** Low / Informational (Operational Resilience)
- **Reference Standard:** IETF RFC 1912 Section 2.2

#### Proof-of-Concept (PoC)

The Start of Authority (`SOA`) record in `name1.txt` and `name2.txt` contains the following timing parameters:

```text
nith.ac.in. 8549 IN SOA name.nith.ac.in. akc.nith.ac.in. (
                        2025110738 ; Serial
                        2800       ; Refresh (46 minutes, 40 seconds)
                        3600       ; Retry   (60 minutes)
                        1604800    ; Expire  (18 days, 13 hours)
                        86400      ; Minimum / Negative Cache TTL (24 hours)
)
```

#### Technical Explanation & Impact

- **Refresh (`2800`s):** How often secondary servers (`name1`, `name2`) poll the primary server (`name`) to check if the SOA serial number has increased.
- **Retry (`3600`s):** How long a secondary server waits before trying again if a scheduled Refresh query to the primary server fails.

Per **RFC 1912**, the **Retry** value should always be _smaller_ than the **Refresh** value (typically $\frac{1}{4}$ to $\frac{1}{2}$ of the Refresh interval). Having a Retry timer (`3600`s) longer than the Refresh timer (`2800`s) causes unnecessary delays in zone convergence if a temporary network drop prevents `name1` or `name2` from contacting `name.nith.ac.in` during an emergency DNS update.

#### Remediation

Update the `SOA` record on `name.nith.ac.in` to RFC-compliant values (and increment the serial number):

```text
nith.ac.in. 3600 IN SOA name.nith.ac.in. akc.nith.ac.in. (
                        2026110201 ; Serial (YYYYMMDDNN)
                        3600       ; Refresh (1 hour)
                        900        ; Retry   (15 minutes)
                        1209600    ; Expire  (14 days)
                        3600       ; Minimum Negative Cache TTL (1 hour)
)
```

---

## 3. Prioritized Remediation Roadmap

1. **Immediate (0–24 Hours):** Disable public `AXFR` transfers on `name1.nith.ac.in` (`14.139.56.3`) and `name2.nith.ac.in` (`117.251.114.194`) by setting `allow-transfer { none; };` (**VULN-01**).
2. **Short-Term (1–7 Days):** Audit all 16 third-party `CNAME` records (`*.vercel.app`, `*.github.io`, `*.netlify.app`, `hackonhills.com`) and remove dangling or past-event records (**VULN-03**).
3. **Medium-Term (1–4 Weeks):** Re-key DNSSEC using Algorithm 13 (`ECDSAP256SHA256`), sign the zone (`RRSIG`), and link the `DS` record at the `.ac.in` registry (**VULN-02**); harden SPF (`-all`) and DMARC (`p=reject`) (**VULN-06**); and fix SOA timers (**VULN-07**).
4. **Long-Term (1–3 Months):** Implement Split-Horizon DNS to hide `dbserver`, `ldap`, `adserver`, and `dev` from public resolvers (**VULN-04**), and segregate student club and staging sites onto separate hosts away from `name1`, `exams`, `semreg`, and `tpo` (**VULN-05**).

