#!/usr/bin/env python3
"""PAM Bait Dashboard Integration Module."""
import json, os, subprocess, datetime
from pathlib import Path
from gi.repository import Gtk, GLib

LOG_DIR = Path("/var/lib/pam-bait/logs")
FIFO_PATH = Path("/var/lib/pam-bait/pam_bait.fifo")

def get_bait_status():
    """Get current PAM bait service status and recent triggers."""
    status = {"service": "unknown", "triggers_today": 0, "last_trigger": None}
    
    # Check systemd service state
    try:
        result = subprocess.run(
            ["systemctl", "is-active", "pam-bait.service"],
            capture_output=True, text=True, timeout=5
        )
        status["service"] = result.stdout.strip()
    except Exception:
        status["service"] = "error"
    
    # Count today's triggers from log file
    today_log = LOG_DIR / f"bait_{datetime.date.today()}.jsonl"
    if today_log.exists():
        try:
            with open(today_log, "r") as f:
                lines = [l for l in f if l.strip()]
                status["triggers_today"] = len(lines)
                if lines:
                    last = json.loads(lines[-1])
                    status["last_trigger"] = {
                        "user": last.get("user", "unknown"),
                        "service": last.get("service", "unknown"),
                        "time": last.get("timestamp", "").split("T")[1][:8]
                    }
        except Exception:
            pass
    
    return status

def create_pam_bait_tab(app):
    """Create and return the PAM Bait Monitor tab widget."""
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
    box.set_margin_start(10)
    box.set_margin_end(10)
    box.set_margin_top(10)
    box.set_margin_bottom(10)
    
    # Header
    header = Gtk.Label(label="PAM Bait Authentication Honeypot", xalign=0)
    header.set_attributes(Gtk.pango_attr_list_new())
    box.append(header)
    
    # Status grid
    grid = Gtk.Grid(column_spacing=15, row_spacing=8)
    grid.set_margin_top(10)
    
    labels = {
        "Service State": ("service_label", "#2ecc71" if get_bait_status()["service"] == "active" else "#e74c3c"),
        "Triggers Today": ("triggers_label", "#f39c12"),
        "Last Trigger": ("last_label", "#3498db"),
    }
    
    for i, (title, (id_suffix, color)) in enumerate(labels.items()):
        title_lbl = Gtk.Label(label=title, xalign=0)
        value_lbl = Gtk.Label(label="Loading...", xalign=0, use_markup=True)
        value_lbl.set_name(id_suffix)
        grid.attach(title_lbl, 0, i, 1, 1)
        grid.attach(value_lbl, 1, i, 1, 1)
    
    box.append(grid)
    
    # Action buttons
    btn_box = Gtk.Box(spacing=10, margin_top=20)
    
    def refresh_clicked(btn):
        status = get_bait_status()
        svc_lbl = grid.get_child_at(1, 0)
        trig_lbl = grid.get_child_at(1, 1)
        last_lbl = grid.get_child_at(1, 2)
        
        svc_color = "#2ecc71" if status["service"] == "active" else "#e74c3c"
        svc_lbl.set_markup(f'<span foreground="{svc_color}" weight="bold">{status["service"].upper()}</span>')
        trig_lbl.set_markup(f'<span foreground="#f39c12" weight="bold">{status["triggers_today"]}</span>')
        
        if status["last_trigger"]:
            lt = status["last_trigger"]
            last_lbl.set_markup(f'<span foreground="#3498db">{lt["user"]}@{lt["service"]} ({lt["time"]})</span>')
        else:
            last_lbl.set_markup('<span foreground="#7f8c8d">No triggers today</span>')
    
    refresh_btn = Gtk.Button(label="🔄 Refresh Status")
    refresh_btn.connect("clicked", refresh_clicked)
    btn_box.append(refresh_btn)
    
    def toggle_service(btn):
        status = get_bait_status()
        cmd = "stop" if status["service"] == "active" else "start"
        try:
            subprocess.run(["sudo", "systemctl", cmd, "pam-bait.service"], timeout=10)
            refresh_clicked(btn)
        except Exception as e:
            print(f"Service toggle failed: {e}")
    
    toggle_btn = Gtk.Button(label="⏯️ Toggle Service")
    toggle_btn.connect("clicked", toggle_service)
    btn_box.append(toggle_btn)
    
    box.append(btn_box)
    
    # Log viewer placeholder
    log_scroll = Gtk.ScrolledWindow(vexpand=True, margin_top=20)
    log_text = Gtk.TextView(margin_start=10, margin_end=10)
    log_text.set_editable(False)
    log_text.set_cursor_visible(False)
    log_scroll.set_child(log_text)
    box.append(log_scroll)
    
    # Initial load
    GLib.idle_add(refresh_clicked, refresh_btn)
    
    return box
