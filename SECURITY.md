# Security Policy

## Scope of Compensating Controls

Project Aegis-Kernel (`kshield`) provides defense-in-depth compensating controls, module disarm configurations, Seccomp profiles, and cryptographic WORM auditing designed to mitigate kernel attack surfaces and Day-0 vulnerabilities during the vendor upstream patch gap.

While these controls are designed to minimize risk on live production infrastructure without reboots, no compensating control is a complete replacement for vendor-signed upstream kernel upgrades.

---

## Supported Releases & Maintenance

| Branch / Release | Supported          |
| :--------------- | :----------------- |
| `main`           | Yes                |
| Historical tags  | Limited            |

---

## Reporting Security Vulnerabilities

If you discover a flaw, bypass, privilege escalation loophole, or unintended denial-of-service vector within the compensating controls or tooling provided in this repository:

1. **Do NOT open a public GitHub issue.**
2. Report the vulnerability privately via **GitHub Private Vulnerability Reporting** (under the repository's Security tab).
3. Alternatively, notify the maintainers directly via email: `nemospecialis@gmail.com`.

### What to Provide:
* Detailed description of the bypass or failure mode.
* Affected kernel versions and container runtimes (e.g. Linux 6.8+, containerd v2.0+).
* A minimal reproduction script or shell transcript showing how the control was circumvented.
* Suggested remediations (e.g. improved Seccomp filter, additional module blacklists, or tighter sysctl parameters).

### Response SLA:
* **Acknowledgment:** Within **48 hours**.
* **Triage & Assessment:** Within **5 business days**.
* **Remediation & Attestation:** Once validated, a patched control will be released with appropriate security advisory credit.
