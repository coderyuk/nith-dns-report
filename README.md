# DNS Security Assessment & Disclosure Report (`nith.ac.in`)

> **Responsible Disclosure Notice:** This repository documents findings from a passive, non-intrusive DNS security assessment of `nith.ac.in`. No services were actively exploited, brute-forced, or disrupted. This material is shared strictly in good faith to assist the Computer Centre in hardening institutional infrastructure.

## Overview

An audit of the authoritative nameservers (`name`, `name1`, and `name2.nith.ac.in`) and parent delegation chain identified **7 configuration vulnerabilities** across DNS access controls, DNSSEC validation, external subdomain pointers, network segmentation, and email authentication.

- **Target Domain:** `nith.ac.in`
- **Scope:** Authoritative zone transfers (`AXFR`) and DNSSEC delegation path trace (`dig +trace`)
- **Overall Risk:** High (3 High, 3 Medium, 1 Low)

## Findings Summary

Full technical analyses, Proofs-of-Concept (PoCs), and BIND9/DNS configuration fixes are documented in [`dns_security_assessment_and_poc_report.md`](./dns_security_assessment_and_poc_report.md).

| ID          | Vulnerability                                                              | Affected Component                                       |  Severity  | Status |
| :---------- | :------------------------------------------------------------------------- | :------------------------------------------------------- | :--------: | :----: |
| **VULN-01** | Unauthenticated Zone Transfer (`AXFR`) on Secondary Nameservers            | `name1.nith.ac.in`, `name2.nith.ac.in`                   |  **High**  |  Open  |
| **VULN-02** | Broken DNSSEC Chain of Trust & Deprecated SHA-1 Keys (Alg 7)               | `nith.ac.in` / `.ac.in` Delegation                       |  **High**  |  Open  |
| **VULN-03** | Subdomain Takeover Vectors via External CNAME & A Records                  | 16 External Subdomains                                   |  **High**  |  Open  |
| **VULN-04** | Exposure of Internal Infrastructure (Missing Split-Horizon DNS)            | `14.139.56.0/24` (`dbserver`, `ldap`, `adserver`, `dev`) | **Medium** |  Open  |
| **VULN-05** | Multi-Tier Host Co-Location & Lack of Network Segmentation                 | `.3`, `.11`, `.17`, `.28` Hosts                          | **Medium** |  Open  |
| **VULN-06** | Permissive Email Authentication Policies (SPF `~all` & DMARC `quarantine`) | Root `TXT` & `_dmarc.nith.ac.in`                         | **Medium** |  Open  |
| **VULN-07** | Inverted SOA Refresh (`2800`s) and Retry (`3600`s) Timers                  | `nith.ac.in` `SOA` Record                                |  **Low**   |  Open  |

## Quickest High-Impact Fix

While the primary nameserver (`name.nith.ac.in`) properly blocks unauthorized zone transfers, both secondary nameservers (`name1` and `name2`) permit full unauthenticated `AXFR` dumps over TCP port 53. Adding `allow-transfer { none; };` to the zone configuration on both secondary servers immediately closes **VULN-01** and prevents external reconnaissance of the zone file.

See **Section 3 (Prioritized Remediation Roadmap)** in the [full report](./dns_security_assessment_and_poc_report.md#3-prioritized-remediation-roadmap) for short-, medium-, and long-term steps.

## Repository Structure

```text
.
├── README.md                                   # Executive overview and disclosure notice
├── dns_security_assessment_and_poc_report.md   # Complete assessment, PoCs, and remediation configs
├── name.txt                                    # AXFR test against name.nith.ac.in (Transfer failed)
├── name1.txt                                   # AXFR capture from name1.nith.ac.in (86 records)
├── name2.txt                                   # AXFR capture from name2.nith.ac.in (86 records)
└── dig+trace.txt                               # Delegation trace verifying missing DS / NSEC3 proofs
```

## Contact & Collaboration

This assessment was conducted responsibly under the supervision of the **Shield Society, NIT Hamirpur**.

If you need any clarification regarding these findings, assistance in implementing the recommended fixes, or re-testing after patches are applied, please reach out. The Shield Society is also available to work alongside the Computer Centre to proactively discover additional security issues and assist in remediating them across campus infrastructure.

- **Reporter:** `Yashraj Saini`
- **Email:** `25dec027@nith.ac.in`
- **GitHub:** `github.com/coderyuk`
- **Supervised By:** Shield Society, NIT Hamirpur (`shield.nith.ac.in`)
