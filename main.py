#!/usr/bin/env python3
"""
AUR Security Dashboard
A forensic-grade, local SIEM dashboard for Arch Linux.

Maintainer: WgpArch
Purpose: Monitor system integrity, audit AUR packages, and hunt anomalies.
"""

# Suppress GTK4 deprecation warnings for FileChooserNative
import warnings
warnings.filterwarnings('ignore', category=DeprecationWarning, module='gi.repository.Gtk')

import sarif_output
import ctypes
import sys
import subprocess
import threading
import platform
import datetime
import os
import re
import json
import math 
import base64 

# --- Rust Performance Layer Integration ---
rust_scanner = None
try:
    import importlib.util
    lib_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "libaur_scan.so")
    if os.path.exists(lib_path):
        spec = importlib.util.spec_from_file_location("aur_scan", lib_path)
        if spec and spec.loader:
            rust_scanner = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(rust_scanner)
            print("✅ Rust scanner loaded successfully.")
except Exception as e:
    print(f"Note: Rust scanner not loaded ({e}). Using Python fallback.")

import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gtk, GLib, Adw, Gdk


def fetch_aur_packages():
    pkg_list = []
    try:
        # 1. Get normal AUR (Foreign) packages
        aur_res = subprocess.run(["pacman", "-Qm"], capture_output=True, text=True, check=True)
        for line in aur_res.stdout.strip().split("\n"):
            if line:
                name, version = line.split(" ", 1)
                pkg_list.append({"name": name, "version": version, "source": "AUR"})

        # 2. Get Chaotic AUR packages (The "X-Ray" check)
        chaotic_res = subprocess.run(["bash", "-c", "comm -12 <(pacman -Qq | sort) <(pacman -Sl chaotic-aur 2>/dev/null | awk '{print $2}' | sort)"], capture_output=True, text=True)
        for name in chaotic_res.stdout.strip().split("\n"):
            if name:
                ver_res = subprocess.run(["pacman", "-Q", name], capture_output=True, text=True)
                if ver_res.returncode == 0:
                    version = ver_res.stdout.strip().split(" ", 1)[1]
                    pkg_list.append({"name": name, "version": version, "source": "Chaotic"})


        
        return pkg_list
    except Exception:
        return []


CONFIG_DIR = os.path.expanduser("~/.config/aur-security-dashboard")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")
CACHE_DIR = os.path.join(CONFIG_DIR, "pkgbuild_cache")
os.makedirs(CACHE_DIR, exist_ok=True)

def get_pkgbuild_diff(pkg_name, new_content):
    cache_file = os.path.join(CACHE_DIR, f"{pkg_name}.PKGBUILD")
    if not os.path.exists(cache_file):
        with open(cache_file, 'w') as f: f.write(new_content)
        return "NEW_BASELINE", ""
    with open(cache_file, 'r') as f: old_content = f.read()
    if old_content == new_content: return "UNCHANGED", ""
    import difflib
    diff = list(difflib.unified_diff(old_content.splitlines(keepends=True), new_content.splitlines(keepends=True), fromfile="old", tofile="new", lineterm=""))
    with open(cache_file, 'w') as f: f.write(new_content)
    return "CHANGED", "".join(diff)

def send_notification(title, message, urgency="normal"):
    try: subprocess.run(["notify-send", "-u", urgency, "-a", "AUR Security Dashboard", title, message], check=False)
    except Exception: pass


def load_config():
    os.makedirs(CONFIG_DIR, exist_ok=True)
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
        except Exception:
            pass
    return {"export_path": os.path.expanduser("~/Documents/aur-security-dashboard")}


def save_config(config):
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=4)
    except Exception as e:
        print(f"Failed to save config: {e}")

# --- PKGBUILD Analysis Engine ---
def shannon_entropy(data):
    """Calculates randomness. High entropy = obfuscated/encoded payload."""
    if not data: return 0
    freq = {}
    for char in data:
        freq[char] = freq.get(char, 0) + 1
    entropy = 0
    for count in freq.values():
        p = count / len(data)
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy

# v1.1.5: .install post-install hook signatures
INSTALL_SIGNATURES = {
    "CRITICAL": [
        (r"(curl|wget)\s+[^|\n]*\|\s*(sudo\s+)?(ba)?sh", "Remote script piped into a shell in install hook"),
        (r"base64\s+(-d|--decode)\s*\|\s*(ba)?sh", "Base64 payload decoded and executed in install hook"),
        (r"authorized_keys", "SSH authorized_keys touched by install hook (backdoor access)"),
        (r"chmod\s+[^;\n]*[ug]\+s|chmod\s+[^;\n]*[24][0-7]{3}\b", "SUID/SGID bit planted by install hook"),
        (r"ld\.so\.preload", "LD_PRELOAD hijack (intercepts every binary on the system)"),
        (r"crontab|/etc/cron|/var/spool/cron", "Cron persistence installed by hook"),
        (r"chattr\s+\+i", "Immutable flag used to lock/hide malicious files"),
    ],
    "HIGH": [
        (r"\b(useradd|adduser)\b", "Install hook creates a user account"),
        (r"\b(usermod|groupadd)\b", "Install hook modifies users/groups (privilege grant?)"),
        (r"/etc/sudoers", "Install hook touches sudoers"),
        (r"\bsetcap\b", "Install hook assigns capability bits"),
        (r">>\s*/etc/(bashrc|profile|rc\.local)|/etc/profile\.d/", "Shell-startup persistence written by hook"),
        (r"systemctl\s+(enable|start)\s+[^ \n]+", "Install hook enables/starts a service"),
    ],
}
def is_memfd_process(pid):
    """Detect processes loaded via memfd_create() - common in fileless Linux attacks per Sandfly Intel"""
    try:
        exe_link = os.readlink(f"/proc/{pid}/exe")
        # memfd files appear as "/memfd:<name> (deleted)" in /proc/PID/exe
        if exe_link.startswith("/memfd:"):
            return True
        # Also check cmdline for memfd indicators in encrypted payload loaders
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            cmdline = f.read().decode("utf-8", errors="ignore")
            if "memfd" in cmdline.lower() and "deleted" in exe_link:
                return True
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        pass
    return False

def resolve_pkgbuild_vars(text):
    """Resolve common PKGBUILD variables for accurate static analysis.
    
    Handles: $pkgname, ${pkgver}, ${pkgrel}, $srcdir, $pkgdir, $startdir,
             ${source[@]}, ${md5sums[@]}, and nested ${var_${suffix}} patterns.
    Returns resolved text; undefined variables are left as-is to avoid false negatives.
    """
    # Default safe values for unassigned variables (mirrors makepkg behavior)
    defaults = {
        'pkgname': 'unknown',
        'pkgver': '0',
        'pkgrel': '1',
        'epoch': '',
        'srcdir': '/tmp/makepkg-src',
        'pkgdir': '/tmp/makepkg-pkg',
        'startdir': '.',
        'BUILDDIR': '/tmp/makepkg-build',
    }
    
    # Extract assigned variables from the PKGBUILD text itself
    assignments = {}
    for match in re.finditer(r'^([A-Za-z_][A-Za-z0-9_]*)=(.+)$', text, re.MULTILINE):
        key, val = match.group(1), match.group(2).strip().strip("'\"")
        assignments[key] = val
    
    # Merge with defaults (assigned vars take precedence)
    resolved = {**defaults, **assignments}
    
    # Resolve nested variable references iteratively (max 3 passes to prevent infinite loops)
    result = text
    for _ in range(3):
        new_result = re.sub(
            r'\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?(\[@\])?',
            lambda m: resolved.get(m.group(1), m.group(0)),
            result
        )
        if new_result == result:
            break
        result = new_result


def load_detection_catalog():
    """Load detection rules from detection_catalog.toml."""
    import tomllib
    catalog_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "detection_catalog.toml")
    
    if not os.path.exists(catalog_path):
        return [] 
        
    try:
        with open(catalog_path, "rb") as f:
            data = tomllib.load(f)
        
        rules = []
        for code, details in data.items():
            rules.append({
                "code": code,
                "name": details.get("name", "Unknown"),
                "severity": details.get("severity", "INFO"),
                "category": details.get("category", "General"),
                "cwe": details.get("cwe", "N/A"),
                "pattern": re.compile(details["pattern"]),
                "description": details.get("description", "")
            })
        return rules
    except Exception as e:
        print(f"Warning: Failed to load detection catalog: {e}")
        return []

def decode_obfuscated_strings(text):
    r"""Decode base64, hex escapes, and octal sequences in PKGBUILD text.

    Returns: tuple(original_text, decoded_text)
    - original_text: unmodified input (for baseline scanning)
    - decoded_text: with all detected obfuscation layers resolved

    Handles nested obfuscation (e.g., base64-encoded \xNN sequences).
    Skips decoding if no patterns detected (zero-cost for clean PKGBUILDs).
    Never raises exceptions on malformed input — returns original text as fallback.
    """
    import base64
    import re

    decoded = text
    
    # 1. Hex Escape Decoding (\xNN)
    try:
        def replace_hex(m):
            try: return chr(int(m.group(1), 16))
            except: return m.group(0)
        decoded = re.sub(r'\\x([0-9a-fA-F]{2})', replace_hex, decoded)
    except: pass

    # 2. Octal Escape Decoding (\NNN)
    try:
        def replace_oct(m):
            try: return chr(int(m.group(1), 8))
            except: return m.group(0)
        decoded = re.sub(r'\\([0-7]{3})', replace_oct, decoded)
    except: pass

    # 3. Base64 Decoding (looks for long alphanumeric strings)
    try:
        b64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
        def replace_b64(m):
            try: 
                val = base64.b64decode(m.group(0)).decode('utf-8', errors='ignore')
                return val if all(c.isprintable() or c.isspace() for c in val) else m.group(0)
            except: return m.group(0)
        decoded = re.sub(b64_pattern, replace_b64, decoded)
    except: pass

    return (text, decoded)

def is_typosquat(pkg_name):
    """Check if a package name is a potential typosquat of an official repo package."""
    import difflib
    
    # Cache official packages to avoid repeated pacman calls
    cache_file = os.path.expanduser("~/.cache/aur-security-dashboard/official_pkgs.txt")
    os.makedirs(os.path.dirname(cache_file), exist_ok=True)
    
    official_pkgs = []
    if os.path.exists(cache_file) and (time.time() - os.path.getmtime(cache_file)) < 604800: # 7 days
        with open(cache_file, 'r') as f:
            official_pkgs = [line.strip() for line in f if line.strip()]
    else:
        try:
            result = subprocess.run(['pacman', '-Sl', 'core', 'extra', 'multilib'], 
                                    capture_output=True, text=True, timeout=10)
            official_pkgs = [line.split()[1] for line in result.stdout.splitlines() if line]
            with open(cache_file, 'w') as f:
                f.write('\n'.join(official_pkgs))
        except:
            return False # Fail silently if pacman fails

    # Check for high similarity using SequenceMatcher
    for official in official_pkgs:
        if pkg_name == official:
            return False # It's an exact match, not a typosquat
        ratio = difflib.SequenceMatcher(None, pkg_name, official).ratio()
        if ratio > 0.85: # 85% similarity threshold
            return True
            
    return False

def analyze_pkgbuild_content(text, is_install=False):
    # --- Phase 1: De-obfuscation & Resolution ---
    resolved_text = resolve_pkgbuild_vars(text)
    original_decoded, decoded_text = decode_obfuscated_strings(resolved_text)

    findings = []
    verdict = "✅ LOOKS CLEAN"
    verdict_color = "#2ecc71"
    has_critical = False
    has_warning = False
    # --- Phase 1.5: Typosquatting Check ---
    pkg_name_match = re.search(r'^pkgname\s*=\s*[\'"]?([^\'"\s]+)', text, re.MULTILINE)
    if pkg_name_match:
        pkg_name = pkg_name_match.group(1)
        if is_typosquat(pkg_name):
            findings.append(("⚠️ WARNING", "Typosquat Risk", f"'{pkg_name}' is suspiciously similar to an official package.", "#f39c12"))
            has_warning = True
    # --- Phase 3: SARIF Report Generation ---
    import sarif_output
    import datetime
    
    pkg_name = "unknown"
    if pkg_name_match:
        pkg_name = pkg_name_match.group(1)
    
    # Ensure report directory exists
    report_dir = os.path.expanduser("~/.local/share/aur-security-dashboard/reports")
    os.makedirs(report_dir, exist_ok=True)
    
    # Generate and save SARIF file
    timestamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
    sarif_file = os.path.join(report_dir, f"{pkg_name}-{timestamp}.sarif")
    
    try:
        with open(sarif_file, 'w') as f:
            f.write(sarif_output.generate_sarif(findings, pkg_name))
    except Exception as e:
        print(f"Warning: Could not save SARIF report: {e}")

    # --- Phase 4: Final Verdict Logic ---
    if has_critical:
        verdict = "🔴 MALICIOUS PATTERNS DETECTED"
        verdict_color = "#e74c3c"
    elif has_warning:
        verdict = "⚠️ SUSPICIOUS ACTIVITY"
        verdict_color = "#f39c12"
        
    return verdict, verdict_color, findings

    # --- Phase 2: Scanning Loop ---
    # --- Phase 2: Scanning Loop ---
    texts_to_scan = [
        ("Original", text), 
        ("Resolved/Decoded", decoded_text)
    ]
    
    for source_name, scan_text in texts_to_scan:
        # 1. Provenance & Hygiene (Only run on 'Original' to avoid duplicate warnings)
        if source_name == "Original":
            if "sha256sums=('SKIP'" in scan_text or 'sha256sums=("SKIP"' in scan_text:
                is_pinned = bool(re.search(r"source=\([^)]*(#tag=|#commit=|\.git)", scan_text))
                if not is_pinned:
                    findings.append(("⚠️ WARNING", "Missing Checksums", "SKIP used without pinned git tag/commit.", "#f39c12"))
                    has_warning = True
            if ".install=" in scan_text:
                findings.append(("⚠️ WARNING", "Install Script", "Package uses a custom .install script (post-install hooks).", "#f39c12"))
                has_warning = True
            if re.search(r'source=\(.*git\+', scan_text) or re.search(r'source=\(.*\.git\b', scan_text):
                 findings.append(("ℹ️ INFO", "VCS Package", "Source is a live git repo. Code can change after this review.", "#3498db"))
def analyze_workflow_content(text):
    """Analyze GitHub Actions YAML for supply chain threats."""
    findings = []
    verdict = "✅ LOOKS CLEAN"
    verdict_color = "#2ecc71"
    has_critical = False
    has_warning = False

    # CI-001: Secret exfiltration via curl/wget pipe to shell
    if re.search(r'(curl|wget)\s+.*\|\s*(ba)?sh', text, re.IGNORECASE):
        findings.append(("🔴 CRITICAL", "[CI-001] Secret Exfiltration",
                        "Curl/wget piped to shell detected in workflow.", "#e74c3c"))
        has_critical = True

    # CI-002: Overly permissive GITHUB_TOKEN
    if re.search(r'permissions:\s*write-all', text, re.IGNORECASE):
        findings.append(("⚠️ WARNING", "[CI-002] Overly Permissive Token",
                        "GITHUB_TOKEN has write-all permissions.", "#f39c12"))
        has_warning = True

    # CI-003: Unpinned third-party actions
    if re.search(r'uses:\s+\S+@(?!sha256:)[a-zA-Z]', text):
        findings.append(("⚠️ WARNING", "[CI-003] Unpinned Action",
                        "Third-party action not pinned to SHA.", "#f39c12"))
        has_warning = True

    # CI-004: Hardcoded secrets (basic heuristic)
    hardcoded_patterns = [
        r'(?:password|passwd|pwd)\s*[:=]\s*[\'"][^$][^\'"]{8,}[\'"]',
        r'(?:api[_-]?key|apikey)\s*[:=]\s*[\'"][A-Za-z0-9]{20,}[\'"]',
        r'(?:token|secret)\s*[:=]\s*[\'"][A-Za-z0-9+/]{20,}={0,2}[\'"]',
    ]
    for pattern in hardcoded_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            findings.append(("🔴 CRITICAL", "[CI-004] Hardcoded Secret",
                            "Potential hardcoded credential found in workflow.", "#e74c3c"))
            has_critical = True
            break

    # CI-005: PR trigger with write access
    if re.search(r'on:\s*\n\s*pull_request', text, re.IGNORECASE) and \
       re.search(r'permissions:\s*write', text, re.IGNORECASE):
        findings.append(("⚠️ WARNING", "[CI-005] PR Trigger + Write Access",
                        "Workflow runs on PR with write permissions. Fork PRs can exfiltrate secrets.", "#f39c12"))
        has_warning = True

    # --- SARIF Report Generation ---
    import sarif_output
    import datetime
    import os

    report_dir = os.path.expanduser("~/.local/share/aur-security-dashboard/reports")
    os.makedirs(report_dir, exist_ok=True)

    timestamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
    sarif_file = os.path.join(report_dir, f"workflow-{timestamp}.sarif")

    try:
        with open(sarif_file, 'w') as f:
            f.write(sarif_output.generate_sarif(findings, "github-actions-workflow"))
    except Exception as e:
        print(f"Warning: Could not save workflow SARIF: {e}")

    # --- Final Verdict Logic ---
    if has_critical:
        verdict = "🔴 MALICIOUS WORKFLOW DETECTED"
        verdict_color = "#e74c3c"
    elif has_warning:
        verdict = "⚠️ SUSPICIOUS WORKFLOW"
        verdict_color = "#f39c12"

    return verdict, verdict_color, findings

        # 2. Build System Detection (Run on BOTH to catch obfuscated build calls)
    build_systems = []
    if "cargo " in scan_text or "cargo build" in scan_text: build_systems.append("Rust/Cargo")
    if "cmake " in scan_text or "cmake .." in scan_text: build_systems.append("CMake")
    if "ninja" in scan_text: build_systems.append("Ninja")
    if "meson " in scan_text: build_systems.append("Meson")
    if "go build" in scan_text: build_systems.append("Go")
    if "pip install" in scan_text or "python setup.py" in scan_text: build_systems.append("Python/Pip")
    # v1.1.4: Node.js supply chain detection
    if "npm install" in scan_text or "npm i " in scan_text: build_systems.append("Node/NPM")
    if "yarn install" in scan_text or "yarn add" in scan_text: build_systems.append("Node/Yarn")
    if "pnpm install" in scan_text or "pnpm add" in scan_text: build_systems.append("Node/PNPM")

    if build_systems:
            # Avoid duplicate build system findings
            if not any(f[1] == "Toolchain Detected" for f in findings):
                findings.append(("🔧 BUILD", "Toolchain Detected", f"{', '.join(build_systems)} executes code during build outside this tool's view.", "#3498db"))

        # 3. Red Flags (Critical)
    red_flags = [
        (r'curl\s+.*\|\s*(ba)?sh', "Pipes curl directly to shell"),
        (r'wget\s+.*\|\s*(ba)?sh', "Pipes wget directly to shell"),
        (r'eval\s+', "Uses eval()"),
        (r'base64\s+-d', "Decodes base64"),
        (r'chmod\s+[0-7]*4[0-7]*', "Sets SUID/SGID permissions"),
        (r'setcap\s+', "Sets Linux capabilities"),
        (r'/dev/shm/', "Writes to shared memory (/dev/shm)"),
        (r'~/.bashrc|~/.profile|~/.zshrc', "Modifies user shell profiles"),
        (r'/etc/systemd/', "Drops systemd service files"),
        (r'\\x[0-9a-fA-F]{2}.*\\x[0-9a-fA-F]{2}', "Hex-escape obfuscation detected"),
        (r'install\s+-m\s*4[0-7]{3}', "SUID bit planted via install command"),
        (r'source=\([^)]*http://[^)]*\)', "Insecure HTTP source URL (no TLS)"),
        (r'source=\([^)]*\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', "Raw IP address in source URL"),
        (r'source=\([^)]*(pastebin|gist\.github\.com|ghostbin)', "Source fetched from ephemeral paste site"),
    ]
    for pattern, desc in red_flags:
        if re.search(pattern, text):
            findings.append((" CRITICAL", "Red Flag", desc, "#e74c3c"))
            has_critical = True

    # 3.5. v1.1.1 Threat Intel Signatures (Supply Chain Attacks)
    threat_intel_signatures = {
        "CRITICAL": [
            (r"tailscale\s+up", "Tailscale tunnel initiation"),
            (r"ngrok\s+http", "Ngrok tunnel initiation"),
            (r"cloudflared\s+tunnel", "Cloudflare tunnel initiation"),
            (r">>\s*~\/\.ssh\/authorized_keys", "SSH key persistence injection"),
            (r"ssh-keygen\s+-t", "SSH key generation"),
            (r"useradd.*-G.*(wheel|sudo)", "User creation with sudo/wheel group"),
            (r"usermod.*-aG.*(wheel|sudo)", "User modification to add sudo/wheel group"),
            (r"echo\s+['\"].*['\"]\s*\|\s*chpasswd", "Hardcoded password injection via chpasswd"),
            (r"passwd\s+--stdin", "Hardcoded password injection via passwd --stdin"),
        ],
        "HIGH": [
            (r"sed\s+-i.*sshd_config", "SSHD configuration tampering"),
            (r"PasswordAuthentication\s+yes", "Enabling SSH password authentication"),
            (r"systemctl\s+enable\s+sshd", "Enabling SSHD service"),
            (r"systemctl\s+start\s+sshd", "Starting SSHD service"),
            (r"(npm|yarn|pnpm)\s+(install|i|add)\b(?!.*--frozen-lockfile)", "Node dependency install without frozen lockfile"),
        ]
    }

    for severity, patterns in threat_intel_signatures.items():
        for pattern, desc in patterns:
            if re.search(pattern, text):
                color = "#e74c3c" if severity == "CRITICAL" else "#f39c12"
                sev_label = f"⛔ {severity}" if severity == "CRITICAL" else f"⚠️ {severity}"
                findings.append((sev_label, "Threat Intel Match", desc, color))
                if severity == "CRITICAL":
                    has_critical = True
                else:
                    has_warning = True

    # 4. Network in build()
    if re.search(r'build\(\)\s*\{.*?(curl|wget|nc\s)', text, re.DOTALL):
        findings.append(("⛔ CRITICAL", "Network in build()", "Fetches external data during the build phase.", "#e74c3c"))
        has_critical = True

    # 5. Entropy Scoring (Obfuscation check)
    long_strings = re.findall(r'[A-Za-z0-9+/=]{60,}', text)
    for s in long_strings:
        if shannon_entropy(s) > 4.8: # High entropy threshold
            findings.append(("⚠️ WARNING", "High Entropy Blob", "Found a long, highly randomized string (possible encoded payload).", "#f39c12"))
            has_warning = True
            break 

    # 6. Recursive Decoding (Base64)
    b64_matches = re.findall(r'[A-Za-z0-9+/]{40,}={0,2}', text)
    for match in b64_matches:
        try:
            decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
            if len(decoded) > 10:
                for pattern, desc in red_flags:
                    if re.search(pattern, decoded):
                        findings.append(("⛔ CRITICAL", "Hidden in Base64", f"Decoded payload contains: {desc}", "#e74c3c"))
                        has_critical = True
        except Exception:
            pass
# 7. .install Hook Analysis (v1.1.5)
    if is_install:
        for severity, patterns in INSTALL_SIGNATURES.items():
            for pattern, desc in patterns:
                if re.search(pattern, text):
                    color = "#e74c3c" if severity == "CRITICAL" else "#f39c12"
                    sev_label = f"⛔ {severity}" if severity == "CRITICAL" else f"⚠️ {severity}"
                    findings.append((sev_label, "Install Hook Match", desc, color))
                    if severity == "CRITICAL":
                        has_critical = True
                    else:
                        has_warning = True

    if has_critical:
        verdict, verdict_color = "⛔ DO NOT INSTALL", "#e74c3c"

    if has_critical:
        verdict, verdict_color = "⛔ DO NOT INSTALL", "#e74c3c"
    elif has_warning:
        verdict, verdict_color = "⚠️ REVIEW MANUALLY", "#f39c12"

    return verdict, verdict_color, findings

    return verdict, verdict_color, findings

    return verdict, verdict_color, findings

# v1.1.5 wrapper for .install hooks
def analyze_install_content(text):
    return analyze_pkgbuild_content(text, is_install=True)

class SecurityApp(Adw.Application):
    def __init__(self, **kwargs):
        super().__init__(**kwargs, application_id="com.archhack.aursecurity")
        self.connect("activate", self.on_activate)

        # Inject dark theme CSS for feed buttons (GTK4)
        css_provider = Gtk.CssProvider()
        css_provider.load_from_data(b"""
            .feed-button {
                background-color: #1e1e2e;
                color: #cdd6f4;
                border: 1px solid #414868;
                border-radius: 6px;
                padding: 8px 16px;
                font-family: monospace;
            }
            .feed-button:hover {
                background-color: #313244;
            }
        """)
        display = Gdk.Display.get_default()
        if display:
            Gtk.StyleContext.add_provider_for_display(
                display,
                css_provider,
                Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
            )

    def on_activate(self, app):
        self.win = Gtk.ApplicationWindow(application=app)
        self.win.set_title("AUR Security Dashboard")
        self.win.set_default_size(1400, 800)
        self.win.set_size_request(1200, 700)

        main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        header = Adw.HeaderBar()
        header.set_show_end_title_buttons(True)
        main_box.append(header)

        self.stack = Gtk.Stack()
        self.stack.set_transition_type(Gtk.StackTransitionType.SLIDE_LEFT_RIGHT)
        self.stack.set_transition_duration(300)
        self.stack.set_margin_start(10)
        self.stack.set_margin_end(10)
        self.stack.set_margin_bottom(10)

        stack_switcher = Gtk.StackSwitcher()
        stack_switcher.set_stack(self.stack)
        switcher_scroll = Gtk.ScrolledWindow()
        switcher_scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.NEVER)
        switcher_scroll.set_hexpand(True)
        switcher_scroll.set_child(stack_switcher)

        # Create a vertical box to force the tabs down
        title_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        
        # Use a plain Box as a spacer (no text, no hover effects)
        spacer = Gtk.Box()
        spacer.set_size_request(-1, 22)
        title_box.append(spacer)
        
        title_box.append(switcher_scroll)

        header.set_title_widget(title_box)

        # Pin the horizontal scrollbar
        css_provider = Gtk.CssProvider()
        css = """
        scrollbar.horizontal,
        scrollbar.horizontal slider,
        scrollbar.horizontal slider:hover,
        scrollbar.horizontal slider:active,
        scrollbar.horizontal slider:hover:active {
            min-height: 2px;
        }
        """
        try:
            css_provider.load_from_data(css.encode(), -1)
        except TypeError:
            css_provider.load_from_data(css.encode())
        Gtk.StyleContext.add_provider_for_display(
            Gdk.Display.get_default(), css_provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)

        # Universal safe clear: ListBox now holds ONLY result rows
        def clear_listbox(lb):
            child = lb.get_first_child()
            while child:
                nxt = child.get_next_sibling()
                lb.remove(child)
                child = nxt

        def make_tab(title_label, button_label, tab_id, tab_name):
            box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
            box.set_spacing(10)
            hdr = Gtk.Label(label=title_label, xalign=0)
            hdr.set_margin_start(10)
            box.append(hdr)
            btn = Gtk.Button(label=button_label)
            btn.set_margin_start(10)
            btn.set_halign(Gtk.Align.START)
            box.append(btn)
            scrolled = Gtk.ScrolledWindow()
            scrolled.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
            scrolled.set_vexpand(True)
            scrolled.set_hexpand(True)
            lb = Gtk.ListBox()
            lb.set_selection_mode(Gtk.SelectionMode.NONE)
            scrolled.set_child(lb)
            box.append(scrolled)
            self.stack.add_titled(box, tab_id, tab_name)
            return lb, btn  
            

        # =========================================================================
        # WINDOW FINALIZATION & STARTUP SCANS
        # =========================================================================
        self.aur_listbox, self.aur_scan_btn = make_tab(
            "Installed AUR Packages:", "Rescan AUR Packages", "aur", "AUR Packages")

        def populate_aur(button=None):
            if button:
                button.set_sensitive(False)
                button.set_label("Scanning...")
            clear_listbox(self.aur_listbox)
            pkgs = fetch_aur_packages()
            if not pkgs:
                self.aur_listbox.append(Gtk.Label(label="No AUR packages found on this system.", margin_top=20))
            else:
                for pkg in pkgs:
                    row = Gtk.ListBoxRow()
                    row.set_margin_top(2)
                    row.set_margin_bottom(2)
                    row.set_margin_start(10)
                    row.set_margin_end(10)
                    row_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
                    badge = f" <span foreground='#9b59b6' size='small'>[Chaotic]</span>" if pkg.get("source") == "Chaotic" else ""
                    row_box.append(Gtk.Label(label=f"{pkg['name']}{badge}", xalign=0, hexpand=False, use_markup=True))
                    row_box.append(Gtk.Label(label=pkg["version"], xalign=1))
                    row.set_child(row_box)
                    self.aur_listbox.append(row)
        
        
        # --- GitHub Actions / CI/CD Scanner Tab ---
        self.workflow_listbox, self.workflow_scan_btn = make_tab(
            "GitHub Actions / CI/CD Security Audit:", 
            "📄 Scan Workflow YAML", 
            "workflow", 
            "CI/CD Audit"
        )
        

        def scan_workflow_file(button=None):
            if button:
                button.set_sensitive(False)
                button.set_label("Scanning...")
            
            clear_listbox(self.workflow_listbox)
            
        def scan_workflow_file(button=None):
            if button:
                button.set_sensitive(False)
                button.set_label("Scanning...")

            dialog = Gtk.FileChooserNative.new(
                title="Select GitHub Actions Workflow File",
                parent=self.get_active_window(),
                action=Gtk.FileChooserAction.OPEN,
                accept_label="Scan",
                cancel_label="Cancel"
            )

            yaml_filter = Gtk.FileFilter()
            yaml_filter.set_name("YAML Files (*.yml, *.yaml)")
            yaml_filter.add_pattern("*.yml")
            yaml_filter.add_pattern("*.yaml")
            dialog.add_filter(yaml_filter)

            def on_response(dialog, response):
                if response == Gtk.ResponseType.ACCEPT:
                    gfile = dialog.get_file()
                    file_path = gfile.get_path() if gfile else None
                    
                    if file_path:
                        try:
                            with open(file_path, 'r') as f:
                                workflow_text = f.read()

                            verdict, color, findings = analyze_workflow_content(workflow_text)

                            clear_listbox(self.workflow_listbox)

                            # Verdict row
                            v_row = Gtk.ListBoxRow()
                            v_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
                            v_box.set_margin_start(10)
                            v_box.set_margin_end(10)
                            v_box.set_margin_top(8)
                            v_box.set_margin_bottom(8)
                            v_box.append(Gtk.Label(label=f"<b>{verdict}</b>", use_markup=True, xalign=0))
                            v_row.set_child(v_box)
                            self.workflow_listbox.append(v_row)

                            # Finding rows
                            for severity, title, desc, _ in findings:
                                row = Gtk.ListBoxRow()
                                box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
                                box.set_margin_start(10)
                                box.set_margin_end(10)
                                box.set_margin_top(6)
                                box.set_margin_bottom(6)
                                box.append(Gtk.Label(label=f"{severity} — {title}", xalign=0))
                                box.append(Gtk.Label(label=desc, xalign=0, wrap=True))
                                row.set_child(box)
                                self.workflow_listbox.append(row)

                        except Exception as e:
                            err_row = Gtk.ListBoxRow()
                            err_row.set_child(Gtk.Label(label=f"Error: {e}", xalign=0, margin_start=10))
                            self.workflow_listbox.append(err_row)

                dialog.destroy()
                if button:
                    button.set_sensitive(True)
                    button.set_label("📄 Scan Workflow YAML")

            dialog.connect("response", on_response)
            dialog.show()
            
                    
                   
        self.workflow_scan_btn.connect("clicked", scan_workflow_file)

        self.aur_scan_btn.connect("clicked", populate_aur)

        # =========================================================================
        # TAB 2: NETWORK MONITOR
        # =========================================================================
        self.net_listbox, self.net_scan_btn = make_tab(
            "Active Network Connections:", "Rescan Network", "network", "Network")

        def populate_net(button=None):
            if button:
                button.set_sensitive(False)
                button.set_label("Scanning...")
            clear_listbox(self.net_listbox)
            try:
                import psutil
                connections = psutil.net_connections(kind="inet")
                if not connections:
                    self.net_listbox.append(Gtk.Label(label="No active network connections detected.", margin_top=20))
                else:
                    for conn in connections:
                        row = Gtk.ListBoxRow()
                        row.set_margin_top(2)
                        row.set_margin_bottom(2)
                        row.set_margin_start(10)
                        row.set_margin_end(10)
                        row_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
                        row_box.append(Gtk.Label(label=conn.type.name if hasattr(conn.type, "name") else str(conn.type), xalign=0, width_chars=8))
                        row_box.append(Gtk.Label(label=f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A", xalign=0, hexpand=False))
                        row_box.append(Gtk.Label(label=f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "LISTENING", xalign=1))
                        row.set_child(row_box)
                        self.net_listbox.append(row)
            except ImportError:
                self.net_listbox.append(Gtk.Label(label="Warning: 'psutil' module not installed.", margin_top=20))
            except Exception as e:
                self.net_listbox.append(Gtk.Label(label=f"Network scan error: {str(e)}", margin_top=20))
            if button:
                button.set_label("Rescan Network")
                button.set_sensitive(True)

        self.net_scan_btn.connect("clicked", populate_net)

        # =========================================================================
        # TAB 3: SYSTEM INTEGRITY
        # =========================================================================
        self.sys_listbox, self.sys_scan_btn = make_tab(
            "Critical File Integrity Check:", "Rescan Integrity", "system", "System Integrity")

        def populate_sys(button=None):
            if button:
                button.set_sensitive(False)
                button.set_label("Scanning...")
            clear_listbox(self.sys_listbox)
            critical_files = {"/usr/bin/bash": "bash", "/usr/bin/ls": "coreutils", "/usr/bin/pacman": "pacman", "/usr/bin/systemd": "systemd"}
            for filepath, pkg_name in critical_files.items():
                row = Gtk.ListBoxRow()
                row.set_margin_top(2)
                row.set_margin_bottom(2)
                row.set_margin_start(10)
                row.set_margin_end(10)
                row_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
                row_box.append(Gtk.Label(label=filepath, xalign=0, ellipsize=3))
                try:
                    pkg_result = subprocess.run(["pacman", "-Qk", pkg_name], capture_output=True, text=True, timeout=5)
                    status = "Intact" if pkg_result.returncode == 0 and "0 missing files" in pkg_result.stdout else "Check Failed"
                except Exception:
                    status = "Check Failed"
                row_box.append(Gtk.Label(label=status, xalign=1))
                row.set_child(row_box)
                self.sys_listbox.append(row)
            if button:
                button.set_label("Rescan Integrity")
                button.set_sensitive(True)

        self.sys_scan_btn.connect("clicked", populate_sys)

        # =========================================================================
        # TAB 4: SUID/SGID SCANNER
        # =========================================================================
        self.suid_listbox, self.suid_scan_btn = make_tab(
            "SUID/SGID Binary Scanner:", "Start SUID Scan", "suid", "SUID Scanner")

        safe_suid_binaries = {
            "/usr/bin/sudo", "/usr/bin/ping", "/usr/bin/passwd", "/usr/bin/su", "/usr/bin/mount", "/usr/bin/umount",
            "/usr/bin/newgrp", "/usr/bin/chsh", "/usr/bin/chfn", "/usr/bin/gpasswd", "/usr/bin/fusermount", "/usr/bin/fusermount3",
            "/usr/bin/pkexec", "/usr/bin/crontab", "/usr/bin/at", "/usr/bin/sudoedit", "/usr/lib/openssh/ssh-keysign",
            "/usr/lib/dbus-1.0/dbus-daemon-launch-helper", "/usr/lib/Xorg.wrap", "/usr/bin/Xorg.wrap", "/usr/bin/kmscon",
            "/usr/bin/ntfs-3g", "/usr/bin/expiry", "/usr/bin/chage", "/usr/lib/dbus-daemon-launch-helper",
            "/opt/vivaldi/vivaldi-sandbox", "/usr/lib/electron43/chrome-sandbox", "/usr/bin/ksu", "/usr/bin/unix_chkpwd",
            "/usr/lib/electron44/chrome-sandbox",  
            "/usr/bin/ksu", "/usr/bin/unix_chkpwd",
            "/usr/bin/wall", "/usr/bin/write", "/usr/lib/ssh/ssh-keysign",
            "/usr/bin/mount.cifs",
        }

        def populate_suid(button=None):
            if button:
                button.set_sensitive(False)
                button.set_label("Scanning...")

            def do_scan():
                try:
                    find_cmd = ["find", "/", "-not", "-path", "/proc/*", "-not", "-path", "/sys/*", "-not", "-path", "/dev/*", "-not", "-path", "/run/*", "-perm", "/6000", "-type", "f"]
                    scan_result = subprocess.run(find_cmd, capture_output=True, text=True, timeout=45)
                    files = [f.strip() for f in scan_result.stdout.split('\n') if f.strip()]
                except Exception:
                    files = None
                GLib.idle_add(fill_ui, files, button)

            def fill_ui(files, button):
                clear_listbox(self.suid_listbox)
                if files is None:
                    self.suid_listbox.append(Gtk.Label(label="Scan failed or timed out."))
                elif not files:
                    self.suid_listbox.append(Gtk.Label(label="No SUID/SGID files found."))
                else:
                    for filepath in sorted(files):
                        row = Gtk.ListBoxRow()
                        row.set_margin_top(2)
                        row.set_margin_bottom(2)
                        row.set_margin_start(10)
                        row.set_margin_end(10)
                        row_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
                        row_box.append(Gtk.Label(label=filepath, xalign=0, ellipsize=3))
                        status_markup = "<span foreground='#2ecc71'>Safe</span>" if filepath in safe_suid_binaries else "<span foreground='#e74c3c' weight='bold'>SUSPICIOUS</span>"
                        row_box.append(Gtk.Label(label=status_markup, xalign=1, use_markup=True, ellipsize=3, max_width_chars=30))
                        row.set_child(row_box)
                        self.suid_listbox.append(row)
                if button:
                    button.set_label("Rescan SUID")
                    button.set_sensitive(True)

            threading.Thread(target=do_scan, daemon=True).start()

        self.suid_scan_btn.connect("clicked", populate_suid)

        # =========================================================================
        # TAB 5: AUTH & BRUTE-FORCE MONITOR
        # =========================================================================
        self.auth_listbox, self.auth_scan_btn = make_tab(
            "Authentication & Brute-Force Monitor (Last 24h):", "Start Auth Scan", "auth", "Auth Monitor")

        def run_auth_scan(button):
            button.set_sensitive(False)
            button.set_label("Scanning...")
            clear_listbox(self.auth_listbox)

            def do_scan():
                results = []
                try:
                    log_result = subprocess.run(["journalctl", "--since", "24 hours ago", "-g", "Failed password|Invalid user|sudo:.*COMMAND|session opened", "--no-pager", "-q"], capture_output=True, text=True, timeout=10)
                    logs = log_result.stdout.strip().split('\n')
                    if not logs or (len(logs) == 1 and not logs[0].strip()):
                        results.append(("NO_EVENTS", "No authentication events in the last 24 hours.", "#2ecc71"))
                    else:
                        for log in logs[-50:]:
                            if not log.strip():
                                continue
                            parts = log.split(' ', 3)
                            time_str = f"{parts[0]} {parts[1]}" if len(parts) > 2 else "Unknown Time"
                            message = parts[3] if len(parts) > 3 else log
                            if "Failed" in message or "Invalid" in message:
                                color, event_type = "#e74c3c", "FAILED LOGIN"
                            elif "sudo" in message:
                                color, event_type = "#f39c12", "SUDO USAGE"
                            else:
                                color, event_type = "#2ecc71", "SUCCESS"
                            results.append((time_str, message, event_type, color))
                except Exception as e:
                    results.append(("Error", str(e), "ERROR", "#e74c3c"))
                GLib.idle_add(update_auth_ui, results, button)

            def update_auth_ui(results, button):
                for res in results:
                    row = Gtk.ListBoxRow()
                    row.set_margin_top(2)
                    row.set_margin_bottom(2)
                    row.set_margin_start(10)
                    row.set_margin_end(10)
                    if res[0] == "NO_EVENTS":
                        row.set_child(Gtk.Label(label=res[1], xalign=0, margin_top=20))
                    else:
                        row_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
                        row_box.append(Gtk.Label(label=res[0], xalign=0, margin_bottom=2))
                        row_box.append(Gtk.Label(label=f"<span foreground='{res[3]}' weight='bold'>[{res[2]}]</span> {res[1]}", xalign=0, use_markup=True, max_width_chars=80, wrap=True))
                        row.set_child(row_box)
                    self.auth_listbox.append(row)
                button.set_label("Rescan Auth Monitor")
                button.set_sensitive(True)

            threading.Thread(target=do_scan, daemon=True).start()

        self.auth_scan_btn.connect("clicked", run_auth_scan)

        # =========================================================================
        # TAB 6: ANOMALOUS PROCESS HUNTER
        # =========================================================================
        self.proc_listbox, self.proc_scan_btn = make_tab(
            "Anomalous Process Hunter:", "Start Process Scan", "processes", "Process Hunter")

        def run_proc_scan(button):
            button.set_sensitive(False)
            button.set_label("Scanning...")
            clear_listbox(self.proc_listbox)

            def do_scan():
                results = []
                try:
                    ps_result = subprocess.run(["ps", "aux", "--no-headers"], capture_output=True, text=True, timeout=5)
                    for proc in ps_result.stdout.strip().split('\n'):
                        if not proc.strip():
                            continue
                        parts = proc.split(None, 10)
                        if len(parts) < 11:
                            continue
                        user, pid = parts[0], parts[1]
                        command = parts[10]
                        if command.startswith("["):
                            continue
                        if any(x in command.lower() for x in ["/usr/lib/sddm/", "/opt/firefox", "betterbird", "thunderbird"]):
                            continue
                        threat_level, reason, color = None, "", ""
                        if "/tmp/" in command or command.startswith("./"):
                            threat_level, color, reason = "CRITICAL", "#e74c3c", "Running from /tmp"
                        elif "/dev/shm/" in command:
                            threat_level, color, reason = "CRITICAL", "#e74c3c", "Running from /dev/shm"
                        elif "/var/tmp/" in command:
                            threat_level, color, reason = "HIGH", "#e67e22", "Running from /var/tmp"
                        elif user == "root" and any(x in command for x in ["python", "bash", "/bin/sh"]) and "/usr/" not in command:
                            threat_level, color, reason = "MEDIUM", "#f39c12", "Root running script"
                                                                       # v1.1.6: Deleted binary hunter
                        # v1.1.10-patch1: memfd fileless loader detection (Sandfly Intel)
                        try:
                            exe_link = os.readlink(f"/proc/{pid}/exe")
                            if "(deleted)" in exe_link:
                                if is_memfd_process(pid):
                                    threat_level, color, reason = "CRITICAL", "#e74c3c", "memfd fileless loader detected (encrypted payload)"
                                else:
                                    threat_level, color, reason = "CRITICAL", "#e74c3c", "Binary deleted from disk (stealth malware)"
                        except Exception: pass
                        if threat_level:
                            results.append((pid, user, command, threat_level, reason, color))
                except Exception as e:
                    results.append(("Error", str(e), "ERROR", "Scan failed", "#e74c3c"))
                GLib.idle_add(update_proc_ui, results, button)

            def update_proc_ui(results, button):
                if not results:
                    row = Gtk.ListBoxRow()
                    row.set_margin_top(20)
                    row.set_child(Gtk.Label(label="✅ No anomalous processes detected. All clear!", xalign=0))
                    self.proc_listbox.append(row)
                else:
                    for pid, user, command, threat_level, reason, color in results:
                        row = Gtk.ListBoxRow()
                        row.set_margin_top(2)
                        row.set_margin_bottom(2)
                        row.set_margin_start(10)
                        row.set_margin_end(10)
                        row_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
                        row_box.append(Gtk.Label(label=f"<span foreground='{color}' weight='bold'>[{threat_level}]</span> PID: {pid} | User: {user}", xalign=0, use_markup=True))
                        row_box.append(Gtk.Label(label=f"<span foreground='#bdc3c7'>{command}</span>", xalign=0, use_markup=True, max_width_chars=80, wrap=True))
                        row_box.append(Gtk.Label(label=f"<span foreground='{color}' style='italic'>{reason}</span>", xalign=0, use_markup=True))
                        if threat_level == "CRITICAL": send_notification("CRITICAL Process", f"PID {pid}: {reason}", "critical")
                        row.set_child(row_box)
                        self.proc_listbox.append(row)
                button.set_label("Rescan Processes")
                button.set_sensitive(True)

            threading.Thread(target=do_scan, daemon=True).start()

        self.proc_scan_btn.connect("clicked", run_proc_scan)

        # =========================================================================
        # TAB 7: SYSTEMD SERVICE AUDITOR
        # =========================================================================
        self.systemd_listbox, self.svc_scan_btn = make_tab(
            "Systemd Service Auditor:", "Start Service Scan", "systemd", "Service Auditor")

        def run_svc_scan(button):
            button.set_sensitive(False)
            button.set_label("Scanning...")
            clear_listbox(self.systemd_listbox)

            def do_scan():
                results = []
                try:
                    svc_result = subprocess.run(["systemctl", "list-units", "--type=service", "--all", "--no-pager", "--no-legend"], capture_output=True, text=True, timeout=10)
                    services = svc_result.stdout.strip().split('\n')
                    for svc in services:
                        if not svc.strip():
                            continue
                        parts = svc.split()
                        if len(parts) < 4:
                            continue
                        service_name = parts[0]
                        active_state = parts[2]
                        if active_state == "failed" or "/home/" in svc:
                            threat_level = "FAILED" if active_state == "failed" else "SUSPICIOUS"
                            color = "#e74c3c" if active_state == "failed" else "#f39c12"
                            reason = "Service has failed" if active_state == "failed" else "Runs from /home"
                            results.append((service_name, active_state, threat_level, reason, color))
                except Exception as e:
                    results.append(("Error", str(e), "ERROR", "Scan failed", "#e74c3c"))
                GLib.idle_add(update_svc_ui, results, button)

            threading.Thread(target=do_scan, daemon=True).start()

        def update_svc_ui(results, button):
            if not results:
                row = Gtk.ListBoxRow()
                row.set_margin_top(40)
                row.set_margin_bottom(40)
                row.set_child(Gtk.Label(label="<span foreground='#2ecc71' weight='bold' size='x-large'>✅ All systemd services appear normal.</span>", xalign=0, use_markup=True))
                self.systemd_listbox.append(row)
            else:
                for name, state, level, reason, color in results:
                    row = Gtk.ListBoxRow()
                    row.set_margin_top(2)
                    row.set_margin_bottom(2)
                    row.set_margin_start(10)
                    row.set_margin_end(10)
                    row_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
                    row_box.append(Gtk.Label(label=f"<span foreground='{color}' weight='bold'>[{level}]</span> {name}", xalign=0, use_markup=True))
                    row.set_child(row_box)
                    self.systemd_listbox.append(row)
            button.set_label("Rescan Services")
            button.set_sensitive(True)

        self.svc_scan_btn.connect("clicked", run_svc_scan)

        # =========================================================================
        # TAB 8: DEEP CODE INSPECTOR
        # =========================================================================
        self.code_listbox, self.code_scan_btn = make_tab(
            "Deep Code Inspector (AUR PKGBUILD Scanner):", "Start Code Scan", "code", "Code Inspector")

        def run_code_scan(button):
            button.set_sensitive(False)
            button.set_label("Scanning...")
            clear_listbox(self.code_listbox)

            def do_scan():
                results = []
                try:
                    aur_result = subprocess.run(["pacman", "-Qm"], capture_output=True, text=True, timeout=5)
                    aur_packages = [line.split()[0] for line in aur_result.stdout.strip().split('\n') if line.strip()]
                    critical_patterns = [(r'\beval\b', "Uses eval()"), (r'base64\s+-d', "Decodes base64"), (r'\|\s*bash', "Pipes to bash")]
                    for pkg_name in aur_packages[:10]:
                        try:
                            fetch_result = subprocess.run(["curl", "-s", f"https://aur.archlinux.org/cgit/aur.git/plain/PKGBUILD?h={pkg_name}"], capture_output=True, text=True, timeout=5)
                            if fetch_result.returncode != 0 or "404" in fetch_result.stdout:
                                results.append((pkg_name, "[SKIPPED] Could not fetch", "#95a5a6"))
                                continue
                            content_pkg = fetch_result.stdout
                            threats = [desc for pattern, desc in critical_patterns if re.search(pattern, content_pkg)]
                            if threats:
                                results.append((pkg_name, f"[CRITICAL] {', '.join(threats)}", "#e74c3c"))
                            else:
                                results.append((pkg_name, "[CLEAN] No suspicious patterns", "#2ecc71"))
                        except Exception:
                            results.append((pkg_name, "[ERROR] Fetch failed", "#e74c3c"))
                except Exception as e:
                    results.append(("Error", str(e), "#e74c3c"))
                GLib.idle_add(update_code_ui, results, button)

            threading.Thread(target=do_scan, daemon=True).start()

        def update_code_ui(results, button):
            for pkg, status, color in results:
                row = Gtk.ListBoxRow()
                row.set_margin_top(2)
                row.set_margin_bottom(2)
                row.set_margin_start(10)
                row.set_margin_end(10)
                row_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
                row_box.append(Gtk.Label(label=pkg, xalign=0))
                row_box.append(Gtk.Label(label=f"<span foreground='{color}'>{status}</span>", xalign=0, use_markup=True, wrap=True))
                row.set_child(row_box)
                self.code_listbox.append(row)
            button.set_label("Rescan Code")
            button.set_sensitive(True)

        self.code_scan_btn.connect("clicked", run_code_scan)

        # =========================================================================
        # TAB 9: SYSTEM HARDENING POSTURE
        # =========================================================================
        self.hardening_listbox, self.hardening_scan_btn = make_tab(
            "System Hardening Posture (Kernel & MAC):", "Start Hardening Scan", "hardening", "Hardening Posture")

        def run_hardening_scan(button):
            button.set_sensitive(False)
            button.set_label("Scanning...")
            clear_listbox(self.hardening_listbox)

            def read_file(path):
                try:
                    with open(path, 'r') as f:
                        return f.read().strip()
                except Exception:
                    return None

            results = []
            lsm = read_file('/sys/kernel/security/lsm')
            mac_active = bool(lsm) and any(m in lsm for m in ['apparmor', 'selinux', 'tomoyo'])
            results.append(("MAC System", "Active" if mac_active else "Inactive", "#2ecc71" if mac_active else "#f39c12"))
            kptr = read_file('/proc/sys/kernel/kptr_restrict')
            results.append(("Kernel Pointer Restriction", "Hardened" if kptr == '2' else "Default", "#2ecc71" if kptr == '2' else "#f39c12"))
            ptrace = read_file('/proc/sys/kernel/yama/ptrace_scope')
            results.append(("ptrace Scope", "Hardened" if ptrace in ['2', '3'] else "Default", "#2ecc71" if ptrace in ['2', '3'] else "#f39c12"))
            bpf = read_file('/proc/sys/net/core/bpf_jit_harden')
            results.append(("BPF JIT Hardening", "Hardened" if bpf == '2' else "Default", "#2ecc71" if bpf == '2' else "#f39c12"))

            # v1.1.8: eBPF program audit (Atomic Arch rootkit closer)
            try:
                bpftool_res = subprocess.run(["sudo", "-n", "bpftool", "prog", "show"], capture_output=True, text=True, timeout=8)
                if bpftool_res.returncode != 0:
                    results.append(("eBPF Programs", "bpftool needs passwordless sudo — see note", "#3498db"))
                else:
                    progs = [l for l in bpftool_res.stdout.splitlines() if re.match(r'\s*\d+:', l)]
                    if not progs:
                        results.append(("eBPF Programs", "None loaded — kernel BPF surface clean", "#2ecc71"))
                    else:
                        names = ", ".join((re.search(r'name\s+(\S+)', l) or [None, "?"])[1] for l in progs[:8])
                        results.append(("eBPF Programs", f"{len(progs)} loaded — verify each is legitimate ({names})", "#f39c12"))
            except FileNotFoundError:
                results.append(("eBPF Programs", "bpftool not installed (pacman -S bpf)", "#3498db"))
            except Exception:
                results.append(("eBPF Programs", "Audit unavailable", "#3498db"))

            for name, status, color in results:
                row = Gtk.ListBoxRow()
                row.set_margin_top(5)
                row.set_margin_bottom(5)
                row.set_margin_start(10)
                row.set_margin_end(10)
                row.set_child(Gtk.Label(label=f"<span foreground='#bdc3c7'>{name}</span>  <span foreground='{color}' weight='bold'>[{status}]</span>", xalign=0, use_markup=True, wrap=True, max_width_chars=100))
                self.hardening_listbox.append(row)
            button.set_label("Rescan Hardening Posture")
            button.set_sensitive(True)

        self.hardening_scan_btn.connect("clicked", run_hardening_scan)
        
        # =========================================================================
        # TAB 10: PKGBUILD CHECKER
        # =========================================================================
        pkg_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        pkg_box.set_margin_start(10)
        pkg_box.set_margin_end(10)
        pkg_box.set_margin_top(10)
        
        pkg_header = Gtk.Label(label="Pre-Install PKGBUILD Security Gate", xalign=0)
        pkg_box.append(pkg_header)

        # Fetch row
        fetch_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        self.pkg_name_entry = Gtk.Entry(placeholder_text="Enter AUR package name to fetch...", hexpand=True)
        self.fetch_pkg_btn = Gtk.Button(label="Fetch from AUR")
        fetch_row.append(self.pkg_name_entry)
        fetch_row.append(self.fetch_pkg_btn)
        pkg_box.append(fetch_row)

        # Text view for pasting
        self.pkgbuild_textview = Gtk.TextView()
        self.pkgbuild_textview.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        self.pkgbuild_buffer = self.pkgbuild_textview.get_buffer()
        tv_scroll = Gtk.ScrolledWindow()
        tv_scroll.set_min_content_height(150)
        tv_scroll.set_max_content_height(150)
        tv_scroll.set_child(self.pkgbuild_textview)
        pkg_box.append(tv_scroll)

        # Analyze button
        self.analyze_pkg_btn = Gtk.Button(label="Analyze PKGBUILD")
        self.analyze_pkg_btn.set_halign(Gtk.Align.START)
        pkg_box.append(self.analyze_pkg_btn)

        # Results area
        self.pkg_results_listbox = Gtk.ListBox()
        self.pkg_results_listbox.set_selection_mode(Gtk.SelectionMode.NONE)
        res_scroll = Gtk.ScrolledWindow(vexpand=True)
        res_scroll.set_child(self.pkg_results_listbox)
        pkg_box.append(res_scroll)

        self.stack.add_titled(pkg_box, "pkgbuild", "PKGBUILD Checker")

        # --- Tab 10 Logic ---
        def fetch_pkg_clicked(btn):
            name = self.pkg_name_entry.get_text().strip()
            if not name: return
            btn.set_sensitive(False)
            btn.set_label("Fetching...")
            def do_fetch():
                try:
                    res = subprocess.run(["curl", "-s", f"https://aur.archlinux.org/cgit/aur.git/plain/PKGBUILD?h={name}"], capture_output=True, text=True, timeout=10)
                    text = res.stdout if res.returncode == 0 and "404" not in res.stdout and not res.stdout.lstrip().startswith("<") else f"# Error fetching {name} (enter only the package name, not a URL)"
                except Exception as e:
                    text = f"# Error: {e}"
                GLib.idle_add(update_textview, text, btn)
            threading.Thread(target=do_fetch, daemon=True).start()

        def update_textview(text, btn):
            self.pkgbuild_buffer.set_text(text)
            btn.set_label("Fetch from AUR")
            btn.set_sensitive(True)

        def analyze_pkg_clicked(btn):
            btn.set_sensitive(False)
            btn.set_label("Analyzing...")
            clear_listbox(self.pkg_results_listbox)
            
            start_iter = self.pkgbuild_buffer.get_start_iter()
            end_iter = self.pkgbuild_buffer.get_end_iter()
            text = self.pkgbuild_buffer.get_text(start_iter, end_iter, True)

            def do_analyze():
                verdict, color, findings = analyze_pkgbuild_content(text)
                GLib.idle_add(update_pkg_results, verdict, color, findings, btn)
            threading.Thread(target=do_analyze, daemon=True).start()

        def update_pkg_results(verdict, color, findings, btn):
            # Verdict Banner
            v_row = Gtk.ListBoxRow()
            v_row.set_margin_top(10)
            v_row.set_margin_bottom(10)
            v_label = Gtk.Label(label=f"<span size='x-large' weight='bold' foreground='{color}'>{verdict}</span>", xalign=0.5, use_markup=True)
            v_row.set_child(v_label)
            self.pkg_results_listbox.append(v_row)

            # Disclaimer
            d_row = Gtk.ListBoxRow()
            d_label = Gtk.Label(label="<span size='small' foreground='#7f8c8d' style='italic'>Note: Static analysis cannot defeat all obfuscation. 'Clean' means no known red flags.</span>", xalign=0.5, use_markup=True, wrap=True)
            d_row.set_child(d_label)
            self.pkg_results_listbox.append(d_row)

            # Findings
            for severity, title, desc, sev_color in findings:
                row = Gtk.ListBoxRow()
                row.set_margin_top(5)
                row.set_margin_bottom(5)
                row.set_margin_start(10)
                row.set_margin_end(10)
                row_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
                row_box.append(Gtk.Label(label=f"<span foreground='{sev_color}' weight='bold'>{severity} {title}</span>", xalign=0, use_markup=True))
                row_box.append(Gtk.Label(label=desc, xalign=0, wrap=True))
                row.set_child(row_box)
                self.pkg_results_listbox.append(row)
            
            if not findings:
                row = Gtk.ListBoxRow()
                row.set_child(Gtk.Label(label="No specific red flags, high-entropy blobs, or provenance warnings found.", xalign=0, margin_top=10))
                self.pkg_results_listbox.append(row)

            btn.set_label("Analyze PKGBUILD")
            btn.set_sensitive(True)

        self.fetch_pkg_btn.connect("clicked", fetch_pkg_clicked)
        self.analyze_pkg_btn.connect("clicked", analyze_pkg_clicked) 
        # =========================================================================
        # TAB 12: UPDATE DIFF
        # =========================================================================
        self.diff_listbox, self.diff_scan_btn = make_tab(
            "PKGBUILD Change Detector:", "Scan Installed for Changes", "diff", "Update Diff")

        def run_diff_scan(button):
            button.set_sensitive(False)
            button.set_label("Scanning...")
            clear_listbox(self.diff_listbox)
            def do_scan():
                results = []
                try:
                    aur_result = subprocess.run(["pacman", "-Qm"], capture_output=True, text=True, timeout=5)
                    aur_packages = [line.split()[0] for line in aur_result.stdout.strip().split('\n') if line.strip()]
                    for pkg_name in aur_packages:
                        try:
                            fetch_result = subprocess.run(["curl", "-s", f"https://aur.archlinux.org/cgit/aur.git/plain/PKGBUILD?h={pkg_name}"], capture_output=True, text=True, timeout=5)
                            if fetch_result.returncode != 0 or "404" in fetch_result.stdout:
                                results.append((pkg_name, "[SKIPPED]", "Could not fetch", "#95a5a6", ""))
                                continue
                            status, diff_text = get_pkgbuild_diff(pkg_name, fetch_result.stdout)
                            if status == "CHANGED":
                                results.append((pkg_name, "⛔ CHANGED", "Modified since last review", "#e74c3c", diff_text))
                                send_notification("PKGBUILD Changed!", f"{pkg_name} modified upstream.", "critical")
                            elif status == "NEW_BASELINE":
                                results.append((pkg_name, "ℹ️ NEW", "Baseline recorded", "#3498db", ""))
                            else:
                                results.append((pkg_name, "✅ UNCHANGED", "No changes", "#2ecc71", ""))
                        except Exception:
                            results.append((pkg_name, "[ERROR]", "Fetch failed", "#e74c3c", ""))
                except Exception as e:
                    results.append(("Error", "ERROR", str(e), "#e74c3c", ""))
                GLib.idle_add(update_diff_ui, results, button)
            threading.Thread(target=do_scan, daemon=True).start()

        def update_diff_ui(results, button):
            for pkg, status, desc, color, diff in results:
                row = Gtk.ListBoxRow()
                row.set_margin_top(5)
                row.set_margin_bottom(5)
                row.set_margin_start(10)
                row.set_margin_end(10)
                row_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)
                row_box.append(Gtk.Label(label=f"<span foreground='{color}' weight='bold'>{status}</span>  <b>{pkg}</b>  <span foreground='#bdc3c7'>{desc}</span>", xalign=0, use_markup=True))
                if diff:
                    diff_label = Gtk.Label(label=f"<span font_family='monospace' size='small'>{diff}</span>", xalign=0, use_markup=True, wrap=True, selectable=True)
                    diff_label.set_margin_start(20)
                    row_box.append(diff_label)
                row.set_child(row_box)
                self.diff_listbox.append(row)
            button.set_label("Rescan for Changes")
            button.set_sensitive(True)

        self.diff_scan_btn.connect("clicked", run_diff_scan)
        # =========================================================================
        # TAB 11: SETTINGS
        # =========================================================================
        settings_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        settings_box.set_spacing(15)
        settings_box.set_margin_top(20)
        settings_box.set_margin_start(20)
        settings_box.set_margin_end(20)

        export_label = Gtk.Label(label="Report Export Settings", xalign=0, margin_bottom=5)
        settings_box.append(export_label)

        path_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10, margin_bottom=10)
        path_entry = Gtk.Entry(placeholder_text="Enter export directory path...", hexpand=True)
        current_config = load_config()
        path_entry.set_text(current_config.get("export_path", ""))

        def save_path_clicked(b):
            new_path = path_entry.get_text().strip()
            if new_path:
                current_config["export_path"] = new_path
                save_config(current_config)
                print(f"Export path saved to: {new_path}")

        save_path_btn = Gtk.Button(label="Save Path")
        save_path_btn.connect("clicked", save_path_clicked)
        path_box.append(path_entry)
        path_box.append(save_path_btn)
        settings_box.append(path_box)

        actions_label = Gtk.Label(label="Quick Actions", xalign=0, margin_top=15, margin_bottom=10)
        settings_box.append(actions_label)

        actions_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10, margin_bottom=10)

        def refresh_all_clicked(b):
            self.aur_scan_btn.clicked()
            self.net_scan_btn.clicked()
            self.sys_scan_btn.clicked()
            self.suid_scan_btn.clicked()
            self.auth_scan_btn.clicked()
            self.proc_scan_btn.clicked()
            self.svc_scan_btn.clicked()
            self.code_scan_btn.clicked()
            self.hardening_scan_btn.clicked()
            print("Refresh All triggered!")

        def clear_all_clicked(b):
            for lb in [self.aur_listbox, self.net_listbox, self.sys_listbox, self.code_listbox,
                       self.auth_listbox, self.proc_listbox, self.systemd_listbox, self.sys_listbox,
                       self.suid_listbox, self.hardening_listbox, self.pkg_results_listbox]:
                clear_listbox(lb)
            print("All results cleared!")

        def export_report(btn):
            config = load_config()
            report_dir = os.path.expanduser(config.get("export_path", "~/Documents/aur-security-dashboard"))
            os.makedirs(report_dir, exist_ok=True)
            report_path = os.path.join(report_dir, 'security_report.txt')
            try:
                with open(report_path, 'w') as f:
                    f.write(f"AUR Security Dashboard Report\nGenerated: {datetime.datetime.now()}\nExported to: {report_path}\n")
                print(f"Report successfully exported to {report_path}")
            except Exception as e:
                print(f"Error exporting report: {e}")

        refresh_btn = Gtk.Button(label="Refresh All Tabs")
        refresh_btn.connect("clicked", refresh_all_clicked)

        clear_btn = Gtk.Button(label="Clear All Results")
        clear_btn.connect("clicked", clear_all_clicked)

        export_btn = Gtk.Button(label="Export Security Report")
        export_btn.connect("clicked", lambda btn: threading.Thread(target=export_report, args=(btn,), daemon=True).start())

        actions_row.append(refresh_btn)
        actions_row.append(clear_btn)
        actions_row.append(export_btn)
        settings_box.append(actions_row)

        # v1.1.9: Threat Intel Feeds Section
        intel_label = Gtk.Label(label="Threat Intel Feeds", xalign=0, margin_top=30, margin_bottom=10)
        settings_box.append(intel_label)

        intel_grid = Gtk.Grid()
        intel_grid.set_column_spacing(15)
        intel_grid.set_row_spacing(8)
        intel_grid.set_margin_start(10)
        
        feeds = [
            ("Arch Security List", "https://lists.archlinux.org/listinfo/arch-security"),
            ("AUR General List", "https://lists.archlinux.org/listinfo/aur-general"),
            ("AUR Dev List", "https://lists.archlinux.org/listinfo/aur-dev"),
            ("Datadog Sec Labs", "https://securitylabs.datadoghq.com/"),
            ("Elastic Sec Labs", "https://www.elastic.co/security-labs"),
            ("Sandfly Security", "https://sandflysecurity.com/blog/"),
            ("AUR Issues & Requests", "https://aur.archlinux.org/packages/?O=0&SeB=nd&K=&outdated=&SB=n&SO=a&PP=50&do_Search=Go"),
            ("Socket.dev", "https://socket.dev/"),
            ("The DFIR Report", "https://thedfirreport.com/"),
            ("MITRE ATT&CK Linux", "https://attack.mitre.org/matrices/enterprise/linux/")
        ]
        
        for i, (name, url) in enumerate(feeds):
            row = i // 2
            col = (i % 2) * 2
            
            btn = Gtk.Button(label=name)
            btn.set_halign(Gtk.Align.START)
            btn.connect("clicked", lambda b, u=url: subprocess.run(["xdg-open", u]))
            
            intel_grid.attach(btn, col, row, 1, 1)
            
            
            intel_grid.attach(btn, col, row, 1, 1)

        settings_box.append(intel_grid)

        info_label = Gtk.Label(label="System Information", xalign=0, margin_top=30, margin_bottom=10)
            
        settings_box.append(intel_grid)

        info_label = Gtk.Label(label="System Information", xalign=0, margin_top=30, margin_bottom=10)
        settings_box.append(info_label)

        info_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)  # ← Add this
        info_box.append(Gtk.Label(label=f"Hostname: {platform.node()}", xalign=0))
        info_box.append(Gtk.Label(label=f"Kernel: {platform.release()}", xalign=0))
        try:
          uptime_res = subprocess.run(["uptime", "-p"], capture_output=True, text=True)  
          info_box.append(Gtk.Label(label=f"Uptime: {uptime_res.stdout.strip().replace('up ', '')}", xalign=0)) 
        except Exception:  # ← same level as 'try'
          pass
          
        self.stack.add_titled(settings_box, "settings", "Settings") 
  

        # =========================================================================
        # WINDOW FINALIZATION & STARTUP SCANS
        # =========================================================================
        close_btn = Gtk.Button(label="✖", margin_end=20)
        close_btn.connect("clicked", lambda w: app.quit())

        top_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        top_box.append(Gtk.Box())
        top_box.append(close_btn)
        main_box.prepend(top_box)

        main_box.append(self.stack)
        self.win.set_child(main_box)
        self.win.present()

        # Auto-populate the light tabs at startup (SUID runs in background)
        populate_aur()
        populate_net()
        populate_sys()
        populate_suid()


def main():
    app = SecurityApp()
    app.run(sys.argv)


if __name__ == "__main__":
    main()
