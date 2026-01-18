#!/usr/bin/env python3
"""
ShadowOS Threat Dashboard
Real-time visualization of security threats and module status.
"""

import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk, GLib, Gdk, Pango
import os
import time
import json
from datetime import datetime

SYSFS_BASE = "/sys/kernel/shadowos"


class ThreatLevel:
    """DEFCON-style threat levels."""
    LEVELS = [
        (1, "CRITICAL", "#ff0000", "Maximum threat - Under active attack"),
        (2, "SEVERE", "#ff6600", "High threat - Attack in progress"),
        (3, "ELEVATED", "#ffcc00", "Elevated threat - Suspicious activity"),
        (4, "GUARDED", "#00cc00", "Low threat - Minor anomalies"),
        (5, "NORMAL", "#00ff00", "Minimal threat - All clear"),
    ]


class ModuleStatusWidget(Gtk.Box):
    """Shows status of all ShadowOS modules."""
    
    def __init__(self):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        
        header = Gtk.Label()
        header.set_markup("<b>Module Status</b>")
        header.set_halign(Gtk.Align.START)
        self.pack_start(header, False, False, 0)
        
        self.grid = Gtk.Grid()
        self.grid.set_column_spacing(8)
        self.grid.set_row_spacing(2)
        self.pack_start(self.grid, False, False, 0)
        
        self.modules = [
            'av', 'cloak', 'panic', 'defcon', 'detect', 'frustrate',
            'phantom', 'decoy', 'shred', 'ram', 'memcrypt', 'deadman'
        ]
        self.status_labels = {}
        
        for i, mod in enumerate(self.modules):
            name_label = Gtk.Label(label=mod)
            name_label.set_halign(Gtk.Align.START)
            self.grid.attach(name_label, 0, i, 1, 1)
            
            status_label = Gtk.Label()
            status_label.set_halign(Gtk.Align.END)
            self.grid.attach(status_label, 1, i, 1, 1)
            self.status_labels[mod] = status_label
        
        self.refresh()
    
    def refresh(self):
        for mod, label in self.status_labels.items():
            path = os.path.join(SYSFS_BASE, mod, "enabled")
            try:
                with open(path, 'r') as f:
                    enabled = f.read().strip() == "1"
                if enabled:
                    label.set_markup("<span foreground='#00ff00'>● ON</span>")
                else:
                    label.set_markup("<span foreground='#888888'>○ off</span>")
            except:
                label.set_markup("<span foreground='#666666'>— N/A</span>")


class ThreatGauge(Gtk.DrawingArea):
    """Visual gauge showing current threat level."""
    
    def __init__(self):
        super().__init__()
        self.set_size_request(200, 60)
        self.level = 5  # Default: NORMAL
        self.connect("draw", self.on_draw)
    
    def set_level(self, level):
        self.level = max(1, min(5, level))
        self.queue_draw()
    
    def on_draw(self, widget, cr):
        width = widget.get_allocated_width()
        height = widget.get_allocated_height()
        
        # Background
        cr.set_source_rgb(0.1, 0.1, 0.1)
        cr.rectangle(0, 0, width, height)
        cr.fill()
        
        # Draw 5 segments
        segment_width = (width - 20) / 5
        for i in range(5):
            level = i + 1
            _, name, color, _ = ThreatLevel.LEVELS[i]
            
            # Parse color
            r = int(color[1:3], 16) / 255
            g = int(color[3:5], 16) / 255
            b = int(color[5:7], 16) / 255
            
            if level >= self.level:
                cr.set_source_rgb(r, g, b)
            else:
                cr.set_source_rgb(0.2, 0.2, 0.2)
            
            x = 10 + i * segment_width
            cr.rectangle(x, 10, segment_width - 4, height - 20)
            cr.fill()
        
        # Label
        _, name, _, desc = ThreatLevel.LEVELS[self.level - 1]
        cr.set_source_rgb(1, 1, 1)
        cr.select_font_face("Sans", 0, 1)  # Bold
        cr.set_font_size(12)
        cr.move_to(10, height - 5)
        cr.show_text(f"DEFCON {self.level}: {name}")
        
        return False


class AlertsWidget(Gtk.Box):
    """Shows recent security alerts."""
    
    def __init__(self):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        
        header = Gtk.Label()
        header.set_markup("<b>Recent Alerts</b>")
        header.set_halign(Gtk.Align.START)
        self.pack_start(header, False, False, 0)
        
        # Scrollable alert list
        scroll = Gtk.ScrolledWindow()
        scroll.set_size_request(-1, 150)
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        
        self.listbox = Gtk.ListBox()
        self.listbox.set_selection_mode(Gtk.SelectionMode.NONE)
        scroll.add(self.listbox)
        self.pack_start(scroll, True, True, 0)
        
        # Sample alerts (would come from shadow-alertd in real system)
        self.alerts = []
    
    def add_alert(self, severity, message, source_ip=None):
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        row = Gtk.ListBoxRow()
        box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        box.set_margin_start(4)
        box.set_margin_end(4)
        box.set_margin_top(2)
        box.set_margin_bottom(2)
        
        # Severity indicator
        colors = {'critical': '#ff0000', 'high': '#ff6600', 'medium': '#ffcc00', 'low': '#00cc00'}
        color = colors.get(severity, '#888888')
        sev_label = Gtk.Label()
        sev_label.set_markup(f"<span foreground='{color}'>●</span>")
        box.pack_start(sev_label, False, False, 0)
        
        # Time
        time_label = Gtk.Label(label=timestamp)
        time_label.get_style_context().add_class("dim-label")
        box.pack_start(time_label, False, False, 0)
        
        # Message
        msg_label = Gtk.Label(label=message)
        msg_label.set_ellipsize(Pango.EllipsizeMode.END)
        msg_label.set_halign(Gtk.Align.START)
        box.pack_start(msg_label, True, True, 0)
        
        # Source IP if available
        if source_ip:
            ip_label = Gtk.Label(label=source_ip)
            ip_label.get_style_context().add_class("dim-label")
            box.pack_end(ip_label, False, False, 0)
        
        row.add(box)
        self.listbox.prepend(row)
        row.show_all()
        
        # Keep only last 50 alerts
        children = self.listbox.get_children()
        if len(children) > 50:
            self.listbox.remove(children[-1])


class StatsWidget(Gtk.Box):
    """Shows key statistics."""
    
    def __init__(self):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        
        header = Gtk.Label()
        header.set_markup("<b>Statistics</b>")
        header.set_halign(Gtk.Align.START)
        self.pack_start(header, False, False, 0)
        
        self.stats_grid = Gtk.Grid()
        self.stats_grid.set_column_spacing(16)
        self.stats_grid.set_row_spacing(4)
        self.pack_start(self.stats_grid, False, False, 0)
        
        self.stat_labels = {}
        stats = [
            ("Scans Detected", "detect"),
            ("Attackers Tracked", "frustrate"),
            ("Tarpits Active", "phantom"),
            ("ARP Responses", "decoy"),
        ]
        
        for i, (label, mod) in enumerate(stats):
            name_lbl = Gtk.Label(label=label + ":")
            name_lbl.set_halign(Gtk.Align.START)
            self.stats_grid.attach(name_lbl, 0, i, 1, 1)
            
            val_lbl = Gtk.Label(label="0")
            val_lbl.set_halign(Gtk.Align.END)
            self.stats_grid.attach(val_lbl, 1, i, 1, 1)
            self.stat_labels[mod] = val_lbl
        
        self.refresh()
    
    def refresh(self):
        for mod, label in self.stat_labels.items():
            try:
                with open(os.path.join(SYSFS_BASE, mod, "stats"), 'r') as f:
                    stats = f.read()
                # Extract first number from stats
                for line in stats.split('\n'):
                    if ':' in line:
                        val = line.split(':')[-1].strip()
                        if val.isdigit():
                            label.set_text(val)
                            break
            except:
                label.set_text("—")


class ThreatDashboard(Gtk.Window):
    """Main dashboard window."""
    
    def __init__(self):
        super().__init__(title="ShadowOS Threat Dashboard")
        self.set_default_size(800, 600)
        self.set_border_width(12)
        
        # Dark theme
        settings = Gtk.Settings.get_default()
        settings.set_property("gtk-application-prefer-dark-theme", True)
        
        # Main layout
        main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self.add(main_box)
        
        # Header
        header_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        
        title = Gtk.Label()
        title.set_markup("<big><b>🛡️ ShadowOS Threat Dashboard</b></big>")
        header_box.pack_start(title, False, False, 0)
        
        # Refresh button
        refresh_btn = Gtk.Button(label="🔄 Refresh")
        refresh_btn.connect("clicked", self.on_refresh)
        header_box.pack_end(refresh_btn, False, False, 0)
        
        main_box.pack_start(header_box, False, False, 0)
        
        # Threat gauge
        self.threat_gauge = ThreatGauge()
        main_box.pack_start(self.threat_gauge, False, False, 0)
        
        # Main content area
        content_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        
        # Left column: Alerts
        left_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        left_box.set_hexpand(True)
        
        self.alerts_widget = AlertsWidget()
        left_box.pack_start(self.alerts_widget, True, True, 0)
        
        content_box.pack_start(left_box, True, True, 0)
        
        # Right column: Module status & stats
        right_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        right_box.set_size_request(250, -1)
        
        self.module_status = ModuleStatusWidget()
        right_box.pack_start(self.module_status, False, False, 0)
        
        right_box.pack_start(Gtk.Separator(), False, False, 4)
        
        self.stats_widget = StatsWidget()
        right_box.pack_start(self.stats_widget, False, False, 0)
        
        content_box.pack_start(right_box, False, False, 0)
        
        main_box.pack_start(content_box, True, True, 0)
        
        # Status bar
        self.status_bar = Gtk.Label()
        self.status_bar.set_halign(Gtk.Align.START)
        self.update_status()
        main_box.pack_start(self.status_bar, False, False, 0)
        
        # Auto-refresh every 5 seconds
        GLib.timeout_add_seconds(5, self.auto_refresh)
        
        # Add sample alerts for demo
        self.add_sample_alerts()
    
    def add_sample_alerts(self):
        """Add sample alerts for demonstration."""
        self.alerts_widget.add_alert("low", "Module shadow_av enabled", None)
        self.alerts_widget.add_alert("medium", "SYN scan detected", "192.168.1.100")
        self.alerts_widget.add_alert("high", "Multiple failed auth attempts", "10.0.0.50")
    
    def on_refresh(self, button):
        self.refresh_all()
    
    def auto_refresh(self):
        self.refresh_all()
        return True  # Continue timer
    
    def refresh_all(self):
        self.module_status.refresh()
        self.stats_widget.refresh()
        self.update_threat_level()
        self.update_status()
    
    def update_threat_level(self):
        """Read DEFCON level from sysfs."""
        try:
            with open(os.path.join(SYSFS_BASE, "defcon", "level"), 'r') as f:
                level = int(f.read().strip())
                self.threat_gauge.set_level(level)
        except:
            self.threat_gauge.set_level(5)  # Default to NORMAL
    
    def update_status(self):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.status_bar.set_text(f"Last updated: {timestamp}")


def main():
    dashboard = ThreatDashboard()
    dashboard.connect("destroy", Gtk.main_quit)
    dashboard.show_all()
    Gtk.main()


if __name__ == "__main__":
    main()
