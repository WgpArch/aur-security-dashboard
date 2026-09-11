#!/usr/bin/env python3
"""
AUR Security Dashboard
A forensic-grade, local SIEM dashboard for Arch Linux.

Maintainer: WgpArch
Purpose: Monitor system integrity, audit AUR packages, and hunt anomalies.
"""

import sys
import subprocess
import threading
import platform
import datetime
import os
import re
import json

import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gtk, GLib, Adw


def fetch_aur_packages():
    try:
        pacman_output = subprocess.run(["pacman", "-Qm"], capture_output=True, text=True, check=True)
        pkg_list = []
        for line in pacman_output.stdout.strip().split("\n"):
            if line:
                name, version = line.split(" ", 1)
                pkg_list.append({"name": name, "version": version})
        return pkg_list
    except Exception:
        return []


CONFIG_DIR = os.path.expanduser("~/.config/aur-security-dashboard")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")


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


class SecurityApp(Adw.Application):
    def __init__(self, **kwargs):
        super().__init__(**kwargs, application_id="com.archhack.aursecurity")
        self.connect("activate", self.on_activate)

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
        stack_switcher.set_margin_bottom(10)
        header.set_title_widget(stack_switcher)

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
        # TAB 1: AUR PACKAGES
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
                    row_box.append(Gtk.Label(label=pkg["name"], xalign=0, hexpand=False))
                    row_box.append(Gtk.Label(label=pkg["version"], xalign=1))
                    row.set_child(row_box)
                    self.aur_listbox.append(row)
            if button:
                button.set_label("Rescan AUR Packages")
                button.set_sensitive(True)

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
            "/usr/bin/wall", "/usr/bin/write", "/usr/lib/ssh/ssh-keysign"
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
        # TAB 10: SETTINGS
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
            for lb in [self.aur_listbox, self.net_listbox, self.sys_listbox, self.suid_listbox,
                       self.auth_listbox, self.proc_listbox, self.systemd_listbox, self.code_listbox,
                       self.hardening_listbox]:
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

        info_label = Gtk.Label(label="System Information", xalign=0, margin_top=20, margin_bottom=10)
        settings_box.append(info_label)

        info_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)
        info_box.append(Gtk.Label(label=f"Hostname: {platform.node()}", xalign=0))
        info_box.append(Gtk.Label(label=f"Kernel: {platform.release()}", xalign=0))
        try:
            uptime_res = subprocess.run(["uptime", "-p"], capture_output=True, text=True)
            info_box.append(Gtk.Label(label=f"Uptime: {uptime_res.stdout.strip().replace('up ', '')}", xalign=0))
        except Exception:
            pass
        settings_box.append(info_box)
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
