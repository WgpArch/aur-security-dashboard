# Threat Intelligence Log

## Active Monitoring Sources
- **Mailing Lists:** arch-security, aur-general, aur-dev
- **Research Labs:** Datadog Security Labs, Elastic Security Labs, Sandfly Security
- **Community:** AUR Issues Thread (BBS), r/archlinux, r/linuxsecurity
- **Package Security:** Socket.dev, Phylum, Snyk
- **Incident Reports:** The DFIR Report, MITRE ATT&CK Linux Matrix

## Technique Backlog
| Date | Source | Technique / IOC | Maps To Tab | Status | Notes |
|------|--------|-----------------|-------------|--------|-------|
| 2026-10-28 | Reddit / Atomic Arch | eBPF rootkit hiding processes/network | Tab 9 (Hardening) + Tab 6 (Process Hunter) | ✅ Implemented v1.1.8 | Added bpftool prog show audit |
| 2026-10-28 | Self-Diagnosis | Waybar polling causing thermal hunting | N/A (Ops) | ✅ Resolved | Raised interval 2s → 10s |

## How to Add New Entries
1. Read an article or spot a new attack pattern.
2. Identify the core technique (e.g., "hex-escape obfuscation in PKGBUILD").
3. Map it to a dashboard tab (or note if it needs a new feature).
4. Add a row above. When implemented, change status to ✅ and add version.
