# 🛡️ Arch Security Dashboard

[![Buy Me a Coffee](https://img.buymeacoffee.com/button-api/?text=Buy%20me%20a%20coffee&emoji=☕&slug=wgparch&button_colour=FFDD00&font_colour=000000&font_family=Cookie&outline_colour=000000&coffee_colour=ffffff)](https://www.buymeacoffee.com/wgparch)

A forensic-grade, local Security Information and Event Management (SIEM) dashboard built specifically for Arch Linux. 

Unlike traditional security scripts that just run and dump text, this tool provides a beautiful, interactive GTK4 GUI to monitor system integrity, hunt anomalies, and audit your security posture in real-time.

## ⚠️ Current Threat Landscape

The Arch User Repository (AUR) has recently experienced a notable increase in supply chain attacks, compromised maintainer accounts, and malicious package submissions. Most notably, the **"Atomic Arch"** campaign recently targeted over 1,500 AUR packages by hijacking orphaned repositories to inject rootkit-like malware (leveraging eBPF for persistence, process hiding, and credential harvesting).

**This dashboard is designed to provide immediate, local visibility and defense against these evolving, real-world threats.** 

By running entirely locally and auditing your system's AUR packages, SUID binaries, active network connections, and system integrity, it empowers you to verify your own system's security posture without relying on external, potentially compromised tools.

![Dashboard Screenshot](docs/screenshot-1.png)

## 🚀 Features

The dashboard is divided into 9 specialized forensic tabs:

### 🛡️ Pre-Install Security Gate (Tab 10)
Unlike standard package managers that install first and ask questions later, the AUR Security Dashboard includes a **Pre-Install PKGBUILD Checker**.
*   **Static Analysis:** Scans PKGBUILD scripts for malicious patterns (`curl | bash`, `eval`, `chmod 4755`) before you build them.
*   **Entropy Scoring:** Detects obfuscated payloads and high-entropy strings that hide inside "clean" looking scripts.
*   **Recursive Decoding:** Automatically decodes base64 and hex blobs to inspect the hidden payload underneath.
*   **Build-System Awareness:** Flags packages using Rust (`cargo`), CMake, or Go, alerting you to code that executes during the build process outside the PKGBUILD's direct control.

![Tab 10: PKGBUILD Checker](docs/screenshot-2.png)

##  Incident Response Manual

This tool is designed to be part of a professional forensic workflow. A comprehensive, step-by-step Incident Response Manual is included in the `docs/` directory, detailing exactly how to investigate, preserve evidence, and remediate threats found in each tab.

## ⚙️ Requirements

- Arch Linux (Not intended for Arch-based derivatives)
- Python 3.10+
- GTK4 (`python-gobject`)
- Standard Arch utilities (`pacman`, `systemctl`, `ss`, `journalctl`)

## 📦 Installation & Usage

```markdown
### Option 1: AUR Installation (Recommended)
The dashboard is officially available on the Arch User Repository (AUR). You can install and update it directly using your preferred AUR helper (e.g., `trizen`, `yay`, `paru`):
```bash
trizen -S aur-security-dashboard
# or
yay -S aur-security-dashboard

### Option 2: Manual Build & Install
For those who prefer to build from source and review the PKGBUILD:
```bash
git clone https://github.com/WgpArch/aur-security-dashboard.git
cd aur-security-dashboard
makepkg -si
```

### Option 3: Run Directly from Source
If you just want to test it without installing system-wide:
```bash
git clone https://github.com/WgpArch/aur-security-dashboard.git
cd aur-security-dashboard
python3 main.py
```

## 🛡️ Security & Verification

As a security tool, you should never blindly trust code downloaded from the internet. This project is designed with transparency in mind:

1. **No Compiled Binaries:** This dashboard is written entirely in plain-text Python. There are no hidden, pre-compiled executables. You can read the entire `main.py` source code to verify exactly what it does before running it.
2. **No Obfuscation:** The code is clean, well-commented, and uses standard library calls. There is no base64 encoding, eval tricks, or hidden network calls.
3. **Minimal Dependencies:** It relies only on standard Arch Linux utilities (`pacman`, `systemctl`, `ss`, `journalctl`) and `python-gobject` (GTK4). It does not require `pip install` of unvetted third-party Python packages.
4. **Local Execution:** All scanning and analysis happen 100% locally on your machine. **No data, logs, or system information is ever sent over the network.**

**Recommended First Step:** 
If you are cautious, we recommend reviewing the `main.py` file or running the dashboard inside a virtual machine or `systemd-nspawn` container for your first test run.

## 🤝 Contributing

Pull requests and issue reports are welcome. If you find a false positive or have a suggestion for a new security check, please open an issue.

##  License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

---
*Built for the Arch Linux community. Stay secure.*
