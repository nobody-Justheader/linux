#!/usr/bin/env python3
"""
ShadowOS Control Center - Time Tab
Dead Man's Switch, Time-Locked Secrets
"""

import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk, GLib
import os

SYSFS_BASE = "/sys/kernel/shadowos"


class ModuleFrame(Gtk.Frame):
    """Base frame for module controls."""
    
    def __init__(self, title, module_name):
        super().__init__(label=title)
        self.module_name = module_name
        self.module_path = os.path.join(SYSFS_BASE, module_name)
        
        self.box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.box.set_margin_start(12)
        self.box.set_margin_end(12)
        self.box.set_margin_top(8)
        self.box.set_margin_bottom(8)
        
        self.add(self.box)
    
    @property
    def available(self):
        return os.path.exists(self.module_path)
    
    def read_attr(self, attr):
        try:
            with open(os.path.join(self.module_path, attr), "r") as f:
                return f.read().strip()
        except:
            return None
    
    def write_attr(self, attr, value):
        try:
            with open(os.path.join(self.module_path, attr), "w") as f:
                f.write(str(value))
            return True
        except Exception as e:
            print(f"Error writing to {self.module_name}/{attr}: {e}")
            return False


class DeadmanFrame(ModuleFrame):
    """Dead Man's Switch controls."""
    
    def __init__(self):
        super().__init__("💀 Dead Man's Switch", "deadman")
        
        # Armed toggle
        arm_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        arm_label = Gtk.Label(label="Armed:")
        arm_box.pack_start(arm_label, False, False, 0)
        
        self.armed_switch = Gtk.Switch()
        self.armed_switch.connect("state-set", self.on_arm_toggle)
        arm_box.pack_end(self.armed_switch, False, False, 0)
        
        self.status_label = Gtk.Label()
        arm_box.pack_start(self.status_label, True, True, 0)
        
        self.box.pack_start(arm_box, False, False, 0)
        self.box.pack_start(Gtk.Separator(), False, False, 4)
        
        # Interval setting
        interval_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        interval_label = Gtk.Label(label="Check-in interval:")
        interval_box.pack_start(interval_label, False, False, 0)
        
        self.interval_spin = Gtk.SpinButton.new_with_range(1, 168, 1)
        self.interval_spin.set_value(24)
        interval_box.pack_start(self.interval_spin, False, False, 0)
        
        hours_label = Gtk.Label(label="hours")
        interval_box.pack_start(hours_label, False, False, 0)
        
        self.box.pack_start(interval_box, False, False, 0)
        
        # Action selection
        action_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        action_label = Gtk.Label(label="Action on timeout:")
        action_box.pack_start(action_label, False, False, 0)
        
        self.action_combo = Gtk.ComboBoxText()
        self.action_combo.append_text("alert")
        self.action_combo.append_text("lock")
        self.action_combo.append_text("wipe")
        self.action_combo.set_active(0)
        self.action_combo.connect("changed", self.on_action_changed)
        action_box.pack_start(self.action_combo, False, False, 0)
        
        self.box.pack_start(action_box, False, False, 0)
        
        # Countdown display
        self.countdown_label = Gtk.Label()
        self.countdown_label.set_markup("<big>⏱️ --:--:--</big>")
        self.box.pack_start(self.countdown_label, False, False, 8)
        
        # Check-in button
        checkin_btn = Gtk.Button(label="✓ Check In Now")
        checkin_btn.get_style_context().add_class("suggested-action")
        checkin_btn.connect("clicked", self.on_checkin)
        self.box.pack_start(checkin_btn, False, False, 4)
        
        self.refresh_status()
        # Auto-refresh every 10 seconds
        GLib.timeout_add_seconds(10, self.refresh_status)
    
    def refresh_status(self):
        if not self.available:
            self.status_label.set_text("Module not loaded")
            return True
        
        status = self.read_attr("status") or ""
        
        # Parse status
        armed = "armed: yes" in status.lower()
        triggered = "triggered: yes" in status.lower()
        
        self.armed_switch.set_active(armed)
        
        if triggered:
            self.status_label.set_markup("<b>⚠️ TRIGGERED!</b>")
        elif armed:
            self.status_label.set_markup("🔴 Armed")
        else:
            self.status_label.set_markup("🟢 Disarmed")
        
        # Extract remaining time
        for line in status.split('\n'):
            if 'remaining' in line.lower():
                hours = line.split(':')[-1].strip()
                self.countdown_label.set_markup(f"<big>⏱️ {hours}h remaining</big>")
        
        return True  # Continue timer
    
    def on_arm_toggle(self, switch, state):
        self.write_attr("armed", "1" if state else "0")
        self.refresh_status()
        return False
    
    def on_action_changed(self, combo):
        action = combo.get_active_text()
        self.write_attr("action", action)
    
    def on_checkin(self, button):
        self.write_attr("checkin", "1")
        self.refresh_status()


class TimelockFrame(ModuleFrame):
    """Time-Locked Secrets controls."""
    
    def __init__(self):
        super().__init__("⏰ Time-Locked Secrets", "timelock")
        
        # Enable toggle
        enable_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        enable_label = Gtk.Label(label="Enabled:")
        enable_box.pack_start(enable_label, False, False, 0)
        
        self.enabled_switch = Gtk.Switch()
        self.enabled_switch.connect("state-set", self.on_enable_toggle)
        enable_box.pack_end(self.enabled_switch, False, False, 0)
        
        self.box.pack_start(enable_box, False, False, 0)
        self.box.pack_start(Gtk.Separator(), False, False, 4)
        
        # Current time display
        self.time_label = Gtk.Label()
        self.time_label.set_halign(Gtk.Align.START)
        self.box.pack_start(self.time_label, False, False, 0)
        
        # Add rule section
        add_label = Gtk.Label(label="Add access rule:")
        add_label.set_halign(Gtk.Align.START)
        self.box.pack_start(add_label, False, False, 4)
        
        rule_grid = Gtk.Grid()
        rule_grid.set_column_spacing(8)
        rule_grid.set_row_spacing(4)
        
        # Path entry
        rule_grid.attach(Gtk.Label(label="Path:"), 0, 0, 1, 1)
        self.path_entry = Gtk.Entry()
        self.path_entry.set_placeholder_text("/path/to/protect")
        rule_grid.attach(self.path_entry, 1, 0, 2, 1)
        
        # Hour range
        rule_grid.attach(Gtk.Label(label="Hours:"), 0, 1, 1, 1)
        self.start_hour = Gtk.SpinButton.new_with_range(0, 23, 1)
        self.start_hour.set_value(9)
        rule_grid.attach(self.start_hour, 1, 1, 1, 1)
        
        rule_grid.attach(Gtk.Label(label="to"), 2, 1, 1, 1)
        self.end_hour = Gtk.SpinButton.new_with_range(0, 23, 1)
        self.end_hour.set_value(17)
        rule_grid.attach(self.end_hour, 3, 1, 1, 1)
        
        # Days checkboxes
        days_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=4)
        self.day_checks = []
        for day in ['S', 'M', 'T', 'W', 'T', 'F', 'S']:
            cb = Gtk.CheckButton(label=day)
            if day in ['M', 'T', 'W', 'F']:  # Default weekdays
                cb.set_active(True)
            self.day_checks.append(cb)
            days_box.pack_start(cb, False, False, 0)
        
        rule_grid.attach(Gtk.Label(label="Days:"), 0, 2, 1, 1)
        rule_grid.attach(days_box, 1, 2, 3, 1)
        
        self.box.pack_start(rule_grid, False, False, 0)
        
        # Add button
        add_btn = Gtk.Button(label="➕ Add Rule")
        add_btn.connect("clicked", self.on_add_rule)
        self.box.pack_start(add_btn, False, False, 4)
        
        # Rules list
        self.rules_label = Gtk.Label()
        self.rules_label.set_halign(Gtk.Align.START)
        self.box.pack_start(self.rules_label, False, False, 4)
        
        self.refresh()
        GLib.timeout_add_seconds(60, self.refresh)
    
    def refresh(self):
        if not self.available:
            return True
        
        # Current time
        time_str = self.read_attr("current_time") or "Unknown"
        self.time_label.set_markup(f"<b>Current:</b> {time_str}")
        
        # Enabled state
        enabled = self.read_attr("enabled") == "1"
        self.enabled_switch.set_active(enabled)
        
        # Rules
        rules = self.read_attr("list") or "No rules"
        self.rules_label.set_text(rules[:200])  # Truncate
        
        return True
    
    def on_enable_toggle(self, switch, state):
        self.write_attr("enabled", "1" if state else "0")
        return False
    
    def on_add_rule(self, button):
        path = self.path_entry.get_text()
        if not path:
            return
        
        start = int(self.start_hour.get_value())
        end = int(self.end_hour.get_value())
        
        # Calculate days bitmask
        days = 0
        for i, cb in enumerate(self.day_checks):
            if cb.get_active():
                days |= (1 << i)
        
        rule = f"{path}:{start}-{end}:{days}"
        self.write_attr("add", rule)
        self.path_entry.set_text("")
        self.refresh()


class TimeTab(Gtk.Box):
    """Main Time tab container."""
    
    def __init__(self):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self.set_margin_start(16)
        self.set_margin_end(16)
        self.set_margin_top(16)
        self.set_margin_bottom(16)
        
        # Header
        header = Gtk.Label()
        header.set_markup("<big><b>⏰ Time-Based Security</b></big>")
        header.set_halign(Gtk.Align.START)
        self.pack_start(header, False, False, 0)
        
        desc = Gtk.Label(label="Dead man's switch and time-based access control")
        desc.set_halign(Gtk.Align.START)
        desc.get_style_context().add_class("dim-label")
        self.pack_start(desc, False, False, 0)
        
        self.pack_start(Gtk.Separator(), False, False, 8)
        
        # Module frames
        self.pack_start(DeadmanFrame(), False, False, 0)
        self.pack_start(TimelockFrame(), False, False, 0)


def get_tab():
    """Return the tab widget and label."""
    return TimeTab(), "⏰ Time"
