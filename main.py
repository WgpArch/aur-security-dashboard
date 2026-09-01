#!/usr/bin/env python3
import sys, subprocess, gi, threading
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gtk, GLib, Adw

def get_aur_packages():
    try:
        result = subprocess.run(["pacman", "-Qm"], capture_output=True, text=True, check=True)
        packages = []
        for line in result.stdout.strip().split("\n"):
            if line:
                name, version = line.split(" ", 1)
                packages.append({"name": name, "version": version})
        return packages
    except Exception:
        return []

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

        # TAB 1: AUR PACKAGES
        aur_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        aur_box.set_spacing(10)
        aur_box.set_vexpand(True)
        aur_box.set_hexpand(True)
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        scrolled.set_vexpand(True)
        scrolled.set_hexpand(True)
        listbox = Gtk.ListBox()
        listbox.set_selection_mode(Gtk.SelectionMode.NONE)
        aur_packages = get_aur_packages()
        if not aur_packages:
            label = Gtk.Label(label="No AUR packages found.")
            label.set_margin_top(20)
            listbox.append(label)
        else:
            for pkg in aur_packages:
                row = Gtk.ListBoxRow()
                row.set_margin_top(2)
                row.set_margin_bottom(2)
                row.set_margin_start(10)
                row.set_margin_end(10)
                row_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
                name_label = Gtk.Label(label=pkg["name"], xalign=0)
                name_label.set_hexpand(False)
                version_label = Gtk.Label(label=pkg["version"], xalign=1)
                row_box.append(name_label)
                row_box.append(version_label)
                row.set_child(row_box)
                listbox.append(row)
        scrolled.set_child(listbox)
        aur_box.append(scrolled)
        self.stack.add_titled(aur_box, "aur", "AUR Packages")

        # TAB 2: NETWORK MONITOR
        net_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        net_box.set_spacing(10)
        net_scrolled = Gtk.ScrolledWindow()
        net_scrolled.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        net_scrolled.set_vexpand(True)
        net_scrolled.set_hexpand(True)
        net_listbox = Gtk.ListBox()
        net_listbox.set_selection_mode(Gtk.SelectionMode.NONE)
        try:
            import psutil
            connections = psutil.net_connections(kind="inet")
            if not connections:
                label = Gtk.Label(label="No active network connections.")
                label.set_margin_top(20)
                net_listbox.append(label)
            else:
                for conn in connections:
                    row = Gtk.ListBoxRow()
                    row.set_margin_top(2)
                    row.set_margin_bottom(2)
                    row.set_margin_start(10)
                    row.set_margin_end(10)
                    row_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
                    proto_label = Gtk.Label(label=conn.type.name if hasattr(conn.type, "name") else str(conn.type), xalign=0)
                    proto_label.set_width_chars(8)
                    local_addr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
                    local_label = Gtk.Label(label=local_addr, xalign=0)
                    local_label.set_hexpand(False)
                    remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "LISTENING"
                    remote_label = Gtk.Label(label=remote_addr, xalign=1)
                    status_label = Gtk.Label(label=conn.status, xalign=1)
                    status_label.set_width_chars(12)
                    row_box.append(proto_label)
                    row_box.append(local_label)
                    row_box.append(remote_label)
                    row.set_child(row_box)
                    net_listbox.append(row)
        except ImportError:
            label = Gtk.Label(label="psutil not installed")
            label.set_margin_top(20)
            net_listbox.append(label)
        except Exception as e:
            label = Gtk.Label(label=f"Error: {str(e)}")
            label.set_margin_top(20)
            net_listbox.append(label)
        net_scrolled.set_child(net_listbox)
        net_box.append(net_scrolled)
        self.stack.add_titled(net_box, "network", "Network")

        # TAB 3: SYSTEM INTEGRITY
        sys_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        sys_box.set_spacing(10)
        sys_scrolled = Gtk.ScrolledWindow()
        sys_scrolled.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        sys_scrolled.set_vexpand(True)
        sys_scrolled.set_hexpand(True)
        sys_listbox = Gtk.ListBox()
        sys_listbox.set_selection_mode(Gtk.SelectionMode.NONE)
        # === SECTION 3: CRITICAL FILE INTEGRITY ===
        header_integrity = Gtk.Label(label="Critical File Integrity Check:")
        header_integrity.set_xalign(0)
        header_integrity.set_margin_bottom(5)
        sys_listbox.append(header_integrity)
        critical_files = {"/usr/bin/bash": "bash", "/usr/bin/ls": "coreutils", "/usr/bin/pacman": "pacman", "/usr/bin/systemd": "systemd"}
        for filepath, pkg_name in critical_files.items():
            row = Gtk.ListBoxRow()
            row.set_margin_top(2)
            row.set_margin_bottom(2)
            row.set_margin_start(10)
            row.set_margin_end(10)
            row_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
            file_label = Gtk.Label(label=filepath, xalign=0, ellipsize=3)  # Pango.EllipsizeMode.END
            pkg_result = subprocess.run(["pacman", "-Qk", pkg_name], capture_output=True, text=True, timeout=5)
            if pkg_result.returncode == 0 and "0 missing files" in pkg_result.stdout:
                status = " Intact"
            elif pkg_result.returncode != 0:
                status = " Modified/Missing"
            else:
                status = " Check Failed"
            status_label = Gtk.Label(label=status, xalign=1)
            row_box.append(file_label)
            row.set_child(row_box)
            sys_listbox.append(row)
        sys_scrolled.set_child(sys_listbox)
        sys_box.append(sys_scrolled)
        self.stack.add_titled(sys_box, "system", "System Integrity")


        # TAB 5: SUID/SGID SCANNER
        suid_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        suid_box.set_spacing(10)
        suid_scrolled = Gtk.ScrolledWindow()
        suid_scrolled.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        suid_scrolled.set_vexpand(True)
        suid_scrolled.set_hexpand(True)
        suid_listbox = Gtk.ListBox()
        suid_listbox.set_selection_mode(Gtk.SelectionMode.NONE)

        suid_header = Gtk.Label(label="SUID/SGID Binary Scanner:")
        suid_header.set_xalign(0)
        suid_header.set_margin_bottom(5)
        suid_listbox.append(suid_header)

        # Standard Arch Linux SUID/SGID whitelist
        safe_suid_binaries = {
            "/usr/bin/sudo", "/usr/bin/ping", "/usr/bin/passwd", "/usr/bin/su",
            "/usr/bin/mount", "/usr/bin/umount", "/usr/bin/newgrp", "/usr/bin/chsh",
            "/usr/bin/chfn", "/usr/bin/gpasswd", "/usr/bin/fusermount", "/usr/bin/fusermount3",
            "/usr/bin/pkexec", "/usr/bin/crontab", "/usr/bin/at", "/usr/bin/sudoedit",
            "/usr/lib/openssh/ssh-keysign", "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
            "/usr/lib/Xorg.wrap", "/usr/bin/Xorg.wrap", "/usr/bin/kmscon",
            "/usr/bin/ntfs-3g", "/usr/bin/expiry", "/usr/bin/chage",
            "/usr/lib/dbus-daemon-launch-helper",
            # Browser sandboxes
            "/opt/vivaldi/vivaldi-sandbox", "/usr/lib/electron43/chrome-sandbox",
            # Additional system binaries
            "/usr/bin/ksu", "/usr/bin/unix_chkpwd", "/usr/bin/wall", "/usr/bin/write",
            "/usr/lib/ssh/ssh-keysign"
        }

        try:
            # /6000 matches any file with SUID (4000) or SGID (2000) bits set
            result = subprocess.run(
                ["find", "/", "-not", "-path", "/proc/*", "-not", "-path", "/sys/*", "-not", "-path", "/dev/*", "-not", "-path", "/run/*", "-perm", "/6000", "-type", "f"],
                capture_output=True, text=True, timeout=45
            )
            suid_files = [f.strip() for f in result.stdout.split('\n') if f.strip()]
        except subprocess.TimeoutExpired:
            suid_files = []
            err_label = Gtk.Label(label="Scan timed out (took >15s). Try running as root for full scan.")
            suid_listbox.append(err_label)
        except Exception as e:
            suid_files = []
            err_label = Gtk.Label(label=f"Scan failed: {str(e)}")
            suid_listbox.append(err_label)

        if suid_files:
            for filepath in sorted(suid_files):
                row = Gtk.ListBoxRow()
                row.set_margin_top(2)
                row.set_margin_bottom(2)
                row.set_margin_start(10)
                row.set_margin_end(10)
                row_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)

                file_label = Gtk.Label(label=filepath, xalign=0, ellipsize=3)  # Pango.EllipsizeMode.END

                if filepath in safe_suid_binaries:
                    status_markup = "<span foreground='#2ecc71'>Safe</span>"
                else:
                    status_markup = "<span foreground='#e74c3c' weight='bold'>SUSPICIOUS</span>"

                status_label = Gtk.Label(label=status_markup, xalign=1, use_markup=True, ellipsize=3, max_width_chars=30)
                row_box.append(file_label)
                row.set_child(row_box)
                suid_listbox.append(row)
        elif not suid_files and "Scan timed out" not in locals() and "Scan failed" not in locals():
            no_label = Gtk.Label(label="No SUID/SGID files found.")
            suid_listbox.append(no_label)

        suid_scrolled.set_child(suid_listbox)
        suid_box.append(suid_scrolled)
        self.stack.add_titled(suid_box, "suid", "SUID Scanner")

                # TAB 6: AUTH & BRUTE-FORCE MONITOR
        auth_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        auth_box.set_spacing(10)
        auth_scrolled = Gtk.ScrolledWindow()
        auth_scrolled.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        auth_scrolled.set_vexpand(True)
        auth_scrolled.set_hexpand(True)
        auth_listbox = Gtk.ListBox()
        auth_listbox.set_selection_mode(Gtk.SelectionMode.NONE)

        auth_header = Gtk.Label(label="Authentication & Brute-Force Monitor (Last 24h):")
        auth_header.set_xalign(0)
        auth_header.set_margin_bottom(5)
        auth_listbox.append(auth_header)

        def run_auth_scan(button):
            button.set_sensitive(False)
            button.set_label("Scanning...")
            
            # Clear old results
            child = auth_listbox.get_first_child()
            while child:
                next_child = child.get_next_sibling()
                if child != auth_header:
                    auth_listbox.remove(child)
                child = next_child
                
            def do_scan():
                results = []
                try:
                    log_result = subprocess.run(["journalctl", "--since", "24 hours ago", "-g", "Failed password|Invalid user|sudo:.*COMMAND|session opened", "--no-pager", "-q"], capture_output=True, text=True, timeout=10)
                    logs = log_result.stdout.strip().split('\\n')
                    if not logs or (len(logs) == 1 and not logs[0].strip()):
                        results.append(("NO_EVENTS", "No authentication events in the last 24 hours.", "#2ecc71"))
                    else:
                        for log in logs[-50:]:
                            if not log.strip(): continue
                            parts = log.split(' ', 3)
                            time_str = f"{parts[0]} {parts[1]}" if len(parts) > 2 else "Unknown Time"
                            message = parts[3] if len(parts) > 3 else log
                            if "Failed" in message or "Invalid" in message: color, event_type = "#e74c3c", "FAILED LOGIN"
                            elif "sudo" in message: color, event_type = "#f39c12", "SUDO USAGE"
                            else: color, event_type = "#2ecc71", "SUCCESS"
                            results.append((time_str, message, event_type, color))
                except Exception as e:
                    results.append(("Error", str(e), "ERROR", "#e74c3c"))
                GLib.idle_add(update_auth_ui, results, button)

            def update_auth_ui(results, button):
                for res in results:
                    row = Gtk.ListBoxRow()
                    row.set_margin_top(2); row.set_margin_bottom(2); row.set_margin_start(10); row.set_margin_end(10)
                    if res[0] == "NO_EVENTS":
                        row.set_child(Gtk.Label(label=res[1], xalign=0, margin_top=20))
                    else:
                        row_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
                        row_box.append(Gtk.Label(label=res[0], xalign=0, margin_bottom=2))
                        msg_markup = f"<span foreground='{res[3]}' weight='bold'>[{res[2]}]</span> {res[1]}"
                        row_box.append(Gtk.Label(label=msg_markup, xalign=0, use_markup=True, max_width_chars=80, wrap=True))
                        row.set_child(row_box)
                    auth_listbox.append(row)
                button.set_label("Rescan Auth Monitor")
                button.set_sensitive(True)
                
            threading.Thread(target=do_scan, daemon=True).start()

        scan_btn = Gtk.Button(label="Start Auth Scan")
        scan_btn.connect("clicked", run_auth_scan)
        auth_listbox.append(scan_btn)
        auth_scrolled.set_child(auth_listbox)
        auth_box.append(auth_scrolled)
        self.stack.add_titled(auth_box, "auth", "Auth Monitor")

                # TAB 7: ANOMALOUS PROCESS HUNTER
        proc_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        proc_box.set_spacing(10)
        proc_scrolled = Gtk.ScrolledWindow()
        proc_scrolled.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        proc_scrolled.set_vexpand(True)
        proc_scrolled.set_hexpand(True)
        proc_listbox = Gtk.ListBox()
        proc_listbox.set_selection_mode(Gtk.SelectionMode.NONE)

        proc_header = Gtk.Label(label="Anomalous Process Hunter:")
        proc_header.set_xalign(0)
        proc_header.set_margin_bottom(5)
        proc_listbox.append(proc_header)

        def run_proc_scan(button):
            button.set_sensitive(False)
            button.set_label("Scanning...")
            
            # Clear old results
            child = proc_listbox.get_first_child()
            while child:
                next_child = child.get_next_sibling()
                if child != proc_header:
                    proc_listbox.remove(child)
                child = next_child
                
            def do_scan():
                results = []
                try:
                    result = subprocess.run(["ps", "aux", "--no-headers"], capture_output=True, text=True, timeout=5)
                    for proc in result.stdout.strip().split('\\n'):
                        if not proc.strip(): continue
                        parts = proc.split(None, 10)
                        if len(parts) < 11: continue
                        user, pid, cpu, mem, vsz, rss, tty, stat, start, time_cmd = parts[:10]
                        command = parts[10]
                        if command.startswith("["): continue
                        if any(x in command.lower() for x in ["/usr/lib/sddm/", "/opt/firefox", "betterbird", "thunderbird"]): continue
                        
                        threat_level, reason, color = None, "", ""
                        if "/tmp/" in command or command.startswith("./"): threat_level, color, reason = "CRITICAL", "#e74c3c", "Running from /tmp or current directory"
                        elif "/dev/shm/" in command: threat_level, color, reason = "CRITICAL", "#e74c3c", "Running from /dev/shm"
                        elif "/var/tmp/" in command: threat_level, color, reason = "HIGH", "#e67e22", "Running from /var/tmp"
                        elif user == "root" and any(x in command for x in ["python", "bash", "/bin/sh"]) and "/usr/" not in command:
                            threat_level, color, reason = "MEDIUM", "#f39c12", "Root running script from non-standard location"
                        
                        if threat_level: results.append((pid, user, command, threat_level, reason, color))
                except Exception as e:
                    results.append(("Error", "Error", str(e), "ERROR", "Scan failed", "#e74c3c"))
                GLib.idle_add(update_proc_ui, results, button)

            def update_proc_ui(results, button):
                if not results:
                    row = Gtk.ListBoxRow()
                    row.set_margin_top(20)
                    row.set_child(Gtk.Label(label="✅ No anomalous processes detected. All clear!", xalign=0))
                    proc_listbox.append(row)
                else:
                    for pid, user, command, threat_level, reason, color in results:
                        row = Gtk.ListBoxRow()
                        row.set_margin_top(2); row.set_margin_bottom(2); row.set_margin_start(10); row.set_margin_end(10)
                        row_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
                        row_box.append(Gtk.Label(label=f"<span foreground='{color}' weight='bold'>[{threat_level}]</span> PID: {pid} | User: {user}", xalign=0, use_markup=True))
                        row_box.append(Gtk.Label(label=f"<span foreground='#bdc3c7'>{command}</span>", xalign=0, use_markup=True, max_width_chars=80, wrap=True))
                        row_box.append(Gtk.Label(label=f"<span foreground='{color}' style='italic'>{reason}</span>", xalign=0, use_markup=True))
                        row.set_child(row_box)
                        proc_listbox.append(row)
                button.set_label("Rescan Processes")
                button.set_sensitive(True)
                
            threading.Thread(target=do_scan, daemon=True).start()

        scan_btn = Gtk.Button(label="Start Process Scan")
        scan_btn.connect("clicked", run_proc_scan)
        proc_listbox.append(scan_btn)
        proc_scrolled.set_child(proc_listbox)
        proc_box.append(proc_scrolled)
        self.stack.add_titled(proc_box, "processes", "Process Hunter")

                                # TAB 8: SYSTEMD SERVICE AUDITOR
        systemd_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        systemd_box.set_spacing(10)
        systemd_scrolled = Gtk.ScrolledWindow()
        systemd_scrolled.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        systemd_scrolled.set_vexpand(True)
        systemd_scrolled.set_hexpand(True)
        systemd_listbox = Gtk.ListBox()
        systemd_listbox.set_selection_mode(Gtk.SelectionMode.NONE)

        systemd_header = Gtk.Label(label="Systemd Service Auditor:")
        systemd_header.set_xalign(0)
        systemd_header.set_margin_bottom(5)
        systemd_listbox.append(systemd_header)

        def run_svc_scan(button):
            button.set_sensitive(False)
            button.set_label("Scanning...")
            
            def do_scan():
                results = []
                try:
                    result = subprocess.run(["systemctl", "list-units", "--type=service", "--all", "--no-pager", "--no-legend"], capture_output=True, text=True, timeout=10)
                    services = result.stdout.strip().split('\n')
                    suspicious_count = 0
                    for svc in services:
                        if not svc.strip(): continue
                        parts = svc.split()
                        if len(parts) < 4: continue
                        service_name = parts[0]; active_state = parts[2]
                        if active_state == "failed" or "/home/" in svc:
                            suspicious_count += 1
                            threat_level = "FAILED" if active_state == "failed" else "SUSPICIOUS"
                            color = "#e74c3c" if active_state == "failed" else "#f39c12"
                            reason = "Service has failed" if active_state == "failed" else "Runs from /home"
                            results.append((service_name, active_state, threat_level, reason, color))
                except Exception as e:
                    results.append(("Error", str(e), "ERROR", "Scan failed", "#e74c3c"))
                
                GLib.idle_add(update_svc_ui, results, button)

            threading.Thread(target=do_scan, daemon=True).start()

        def update_svc_ui(results, button):
            # Clear everything except header and button
            child = systemd_listbox.get_first_child()
            while child:
                next_child = child.get_next_sibling()
                if child != systemd_header and not isinstance(child, Gtk.Button):
                    systemd_listbox.remove(child)
                child = next_child
            
            # If no suspicious services found, show all-clear
            if not results:
                row = Gtk.ListBoxRow()
                row.set_margin_top(40)
                row.set_margin_bottom(40)
                safe_markup = "<span foreground='#2ecc71' weight='bold' size='x-large'>✅ All systemd services appear normal.</span>"
                safe_label = Gtk.Label(label=safe_markup, xalign=0, use_markup=True)
                row.set_child(safe_label)
                systemd_listbox.append(row)
            else:
                # Show suspicious services
                for name, state, level, reason, color in results:
                    row = Gtk.ListBoxRow()
                    row.set_margin_top(2); row.set_margin_bottom(2); row.set_margin_start(10); row.set_margin_end(10)
                    row_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
                    header_markup = f"<span foreground='{color}' weight='bold'>[{level}]</span> {name}"
                    header_label = Gtk.Label(label=header_markup, xalign=0, use_markup=True)
                    row_box.append(header_label)
                    row.set_child(row_box)
                    systemd_listbox.append(row)
            
            button.set_label("Rescan Services")
            button.set_sensitive(True)

        scan_btn = Gtk.Button(label="Start Service Scan")
        scan_btn.connect("clicked", run_svc_scan)
        systemd_listbox.append(scan_btn)
        systemd_scrolled.set_child(systemd_listbox)
        systemd_box.append(systemd_scrolled)
        self.stack.add_titled(systemd_box, "systemd", "Service Auditor")

# TAB 9: DEEP CODE INSPECTOR
        code_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        code_box.set_spacing(10)
        code_scrolled = Gtk.ScrolledWindow()
        code_scrolled.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        code_scrolled.set_vexpand(True)
        code_scrolled.set_hexpand(True)
        code_listbox = Gtk.ListBox()
        code_listbox.set_selection_mode(Gtk.SelectionMode.NONE)

        code_header = Gtk.Label(label="Deep Code Inspector (AUR PKGBUILD Scanner):")
        code_header.set_xalign(0)
        code_header.set_margin_bottom(5)
        code_listbox.append(code_header)

        def run_code_scan(button):
            button.set_sensitive(False)
            button.set_label("Scanning...")
            
            def do_scan():
                results = []
                import re
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
                        except:
                            results.append((pkg_name, "[ERROR] Fetch failed", "#e74c3c"))
                except Exception as e:
                    results.append(("Error", str(e), "#e74c3c"))
                
                GLib.idle_add(update_code_ui, results, button)

            threading.Thread(target=do_scan, daemon=True).start()

        def update_code_ui(results, button):
            child = code_listbox.get_first_child()
            while child:
                next_child = child.get_next_sibling()
                if child != code_header and not isinstance(child, Gtk.Button):
                    code_listbox.remove(child)
                child = next_child
                
            for pkg, status, color in results:
                row = Gtk.ListBoxRow()
                row.set_margin_top(2); row.set_margin_bottom(2); row.set_margin_start(10); row.set_margin_end(10)
                row_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
                
                pkg_label = Gtk.Label(label=pkg, xalign=0)
                row_box.append(pkg_label)
                
                status_markup = f"<span foreground='{color}'>{status}</span>"
                status_label = Gtk.Label(label=status_markup, xalign=0, use_markup=True)
                status_label.set_wrap(True)
                row_box.append(status_label)
                
                row.set_child(row_box)
                code_listbox.append(row)
                
            button.set_label("Rescan Code")
            button.set_sensitive(True)

        scan_btn = Gtk.Button(label="Start Code Scan")
        scan_btn.connect("clicked", run_code_scan)
        code_listbox.append(scan_btn)
        code_scrolled.set_child(code_listbox)
        code_box.append(code_scrolled)
        self.stack.add_titled(code_box, "code", "Code Inspector")

        

                                # TAB 10: SYSTEM HARDENING POSTURE
        hardening_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        hardening_box.set_spacing(10)
        hardening_scrolled = Gtk.ScrolledWindow()
        hardening_scrolled.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        hardening_scrolled.set_vexpand(True)
        hardening_scrolled.set_hexpand(True)
        hardening_listbox = Gtk.ListBox()
        hardening_listbox.set_selection_mode(Gtk.SelectionMode.NONE)

        hardening_header = Gtk.Label(label="System Hardening Posture (Kernel & MAC):")
        hardening_header.set_xalign(0)
        hardening_header.set_margin_bottom(10)
        hardening_listbox.append(hardening_header)

        def check_hardening():
            results = []
            def read_file(path):
                try:
                    with open(path, 'r') as f:
                        return f.read().strip()
                except:
                    return None
            
            lsm = read_file('/sys/kernel/security/lsm')
            if lsm and any(m in lsm for m in ['apparmor', 'selinux', 'tomoyo']):
                results.append(("MAC System", "Active", "#2ecc71"))
            else:
                results.append(("MAC System", "Inactive", "#f39c12"))
            
            kptr = read_file('/proc/sys/kernel/kptr_restrict')
            if kptr == '2': results.append(("Kernel Pointer Restriction", "Hardened", "#2ecc71"))
            elif kptr == '1': results.append(("Kernel Pointer Restriction", "Default", "#f39c12"))
            else: results.append(("Kernel Pointer Restriction", "Vulnerable", "#e74c3c"))
            
            ptrace = read_file('/proc/sys/kernel/yama/ptrace_scope')
            if ptrace in ['2', '3']: results.append(("ptrace Scope", "Hardened", "#2ecc71"))
            elif ptrace == '1': results.append(("ptrace Scope", "Default", "#f39c12"))
            else: results.append(("ptrace Scope", "Vulnerable", "#e74c3c"))
            
            bpf = read_file('/proc/sys/net/core/bpf_jit_harden')
            if bpf == '2': results.append(("BPF JIT Hardening", "Hardened", "#2ecc71"))
            elif bpf == '1': results.append(("BPF JIT Hardening", "Default", "#f39c12"))
            else: results.append(("BPF JIT Hardening", "Vulnerable", "#e74c3c"))
            
            return results

        def display_results(results):
            # Clear existing results (keep header and button)
            child = hardening_listbox.get_first_child()
            while child:
                next_child = child.get_next_sibling()
                if child != hardening_header and not isinstance(child, Gtk.Button):
                    hardening_listbox.remove(child)
                child = next_child
            
            # Add new results
            for name, status, color in results:
                row = Gtk.ListBoxRow()
                row.set_margin_top(5)
                row.set_margin_bottom(5)
                row.set_margin_start(10)
                row.set_margin_end(10)
                
                markup = f"<span foreground='#bdc3c7'>{name}</span>  <span foreground='{color}' weight='bold'>[{status}]</span>"
                label = Gtk.Label(label=markup, xalign=0, use_markup=True)
                label.set_wrap(True)
                label.set_max_width_chars(100)
                row.set_child(label)
                hardening_listbox.append(row)

        def run_scan(button):
            try:
                results = check_hardening()
                display_results(results)
                button.set_label("Rescan Hardening Posture")
            except Exception as e:
                err_row = Gtk.ListBoxRow()
                err_label = Gtk.Label(label=f"Error: {str(e)}", xalign=0)
                err_row.set_child(err_label)
                hardening_listbox.append(err_row)
                button.set_label("Rescan Hardening Posture")
            button.set_sensitive(True)

        scan_btn = Gtk.Button(label="Start Hardening Scan")
        scan_btn.connect("clicked", lambda btn: threading.Thread(target=run_scan, args=(btn,), daemon=True).start())
        hardening_listbox.append(scan_btn)
        
        hardening_scrolled.set_child(hardening_listbox)
        hardening_box.append(hardening_scrolled)
        self.stack.add_titled(hardening_box, "hardening", "Hardening Posture")


# TAB 4: SETTINGS
        settings_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        settings_box.set_spacing(15)
        settings_box.set_margin_top(20)
        settings_box.set_margin_start(20)
        settings_box.set_margin_end(20)

        actions_label = Gtk.Label(label="Quick Actions", xalign=0)
        actions_label.set_margin_bottom(10)
        settings_box.append(actions_label)

        actions_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        refresh_btn = Gtk.Button(label=" Refresh All Tabs")
        refresh_btn.connect("clicked", lambda w: print("Refresh All clicked!"))
        
        export_btn = Gtk.Button(label=" Export Security Report")
        def export_report(btn):
            import datetime
            import os
            report_dir = '/home/wgparch/Documents/aur-security-dashboard'
            os.makedirs(report_dir, exist_ok=True)
            report_path = os.path.join(report_dir, 'security_report.txt')
            with open(report_path, 'w') as f:
                f.write(f"AUR Security Dashboard Report\nGenerated: {datetime.datetime.now()}\n")
            print(f"Report exported to {report_path}")
        export_btn.connect("clicked", lambda btn: threading.Thread(target=export_report, args=(btn,), daemon=True).start())
        
        actions_row.append(refresh_btn)
        actions_row.append(export_btn)
        settings_box.append(actions_row)

        info_label = Gtk.Label(label="System Information", xalign=0)
        info_label.set_margin_top(20)
        info_label.set_margin_bottom(10)
        settings_box.append(info_label)

        import platform
        info_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)
        info_box.append(Gtk.Label(label=f"Hostname: {platform.node()}", xalign=0))
        info_box.append(Gtk.Label(label=f"Kernel: {platform.release()}", xalign=0))
        
        try:
            uptime_res = subprocess.run(["uptime", "-p"], capture_output=True, text=True)
            uptime = uptime_res.stdout.strip().replace("up ", "")
            info_box.append(Gtk.Label(label=f"Uptime: {uptime}", xalign=0))
        except Exception:
            pass
        
        settings_box.append(info_box)
        self.stack.add_titled(settings_box, "settings", "Settings")

        
        # Restore Close Button
        close_btn = Gtk.Button(label="✖")
        close_btn.set_margin_end(20)
        close_btn.connect("clicked", lambda w: app.quit())
        # Try to add to header bar if it exists, otherwise add to main box top
        if hasattr(self, 'header_bar'):
            self.header_bar.pack_end(close_btn)
        else:
            # Add to top of main_box
            top_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
            top_box.append(Gtk.Box()) # spacer
            top_box.append(close_btn)
            main_box.prepend(top_box)

        main_box.append(self.stack)

        self.win.set_child(main_box)

        self.win.present()


def main():
    app = SecurityApp()
    app.run(sys.argv)

if __name__ == "__main__":
    main()
