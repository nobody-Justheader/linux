#!/usr/bin/env python3
"""
ShadowOS Control Center - Defense Tab
Scan Detection, Protocol Chaos, Frustration Engine
"""

import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk
import os

SYSFS_BASE = "/sys/kernel/shadowos"


class ModuleFrame(Gtk.Frame):
    """A frame containing module controls with toggle switch."""
    
    def __init__(self, title, module_name):
        super().__init__(label=title)
        self.module_name = module_name
        self.module_path = os.path.join(SYSFS_BASE, module_name)
        
        self.box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.box.set_margin_start(12)
        self.box.set_margin_end(12)
        self.box.set_margin_top(8)
        self.box.set_margin_bottom(8)
        
        # Enable row
        enable_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        self.status_label = Gtk.Label()
        self.update_status()
        enable_box.pack_start(self.status_label, False, False, 0)
        
        self.switch = Gtk.Switch()
        self.switch.set_active(self.is_enabled())
        self.switch.connect("state-set", self.on_toggle)
        enable_box.pack_end(self.switch, False, False, 0)
        
        self.box.pack_start(enable_box, False, False, 0)
        self.add(self.box)
    
    @property
    def available(self):
        return os.path.exists(self.module_path)
    
    def is_enabled(self):
        try:
            with open(os.path.join(self.module_path, "enabled"), "r") as f:
                return f.read().strip() == "1"
        except:
            return False
    
    def set_enabled(self, value):
        try:
            with open(os.path.join(self.module_path, "enabled"), "w") as f:
                f.write("1" if value else "0")
        except Exception as e:
            print(f"Error setting {self.module_name} enabled: {e}")
    
    def update_status(self):
        if self.available:
            self.status_label.set_markup("● <b>Available</b>")
            self.status_label.get_style_context().add_class("success")
        else:
            self.status_label.set_markup("○ <i>Not loaded</i>")
            self.status_label.get_style_context().add_class("dim-label")
    
    def on_toggle(self, switch, state):
        self.set_enabled(state)
        return False


class ScanDetectionFrame(ModuleFrame):
    """Scan Detection controls with sensitivity and action options."""
    
    def __init__(self):
        super().__init__("🛡️ Scan Detection", "detect")
        
        # Separator
        self.box.pack_start(Gtk.Separator(), False, False, 4)
        
        # Sensitivity slider
        sens_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        sens_label = Gtk.Label(label="Sensitivity:")
        sens_box.pack_start(sens_label, False, False, 0)
        
        self.sensitivity = Gtk.Scale.new_with_range(Gtk.Orientation.HORIZONTAL, 1, 10, 1)
        self.sensitivity.set_value(5)
        self.sensitivity.set_hexpand(True)
        self.sensitivity.add_mark(1, Gtk.PositionType.BOTTOM, "Low")
        self.sensitivity.add_mark(5, Gtk.PositionType.BOTTOM, "Med")
        self.sensitivity.add_mark(10, Gtk.PositionType.BOTTOM, "High")
        sens_box.pack_start(self.sensitivity, True, True, 0)
        self.box.pack_start(sens_box, False, False, 0)
        
        # Action options
        action_label = Gtk.Label(label="Action on detection:")
        action_label.set_halign(Gtk.Align.START)
        self.box.pack_start(action_label, False, False, 0)
        
        self.action_alert = Gtk.RadioButton.new_with_label(None, "Alert Only")
        self.action_divert = Gtk.RadioButton.new_with_label_from_widget(
            self.action_alert, "Alert + Divert to Phantom"
        )
        self.action_block = Gtk.RadioButton.new_with_label_from_widget(
            self.action_alert, "Alert + Block"
        )
        self.action_divert.set_active(True)
        
        self.box.pack_start(self.action_alert, False, False, 0)
        self.box.pack_start(self.action_divert, False, False, 0)
        self.box.pack_start(self.action_block, False, False, 0)
        
        # Threshold settings
        thresh_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=5)
        thresh_box.pack_start(Gtk.Label(label="Threshold:"), False, False, 0)
        
        self.port_count = Gtk.SpinButton.new_with_range(1, 100, 1)
        self.port_count.set_value(5)
        thresh_box.pack_start(self.port_count, False, False, 0)
        
        thresh_box.pack_start(Gtk.Label(label="ports in"), False, False, 0)
        
        self.time_window = Gtk.SpinButton.new_with_range(1, 60, 1)
        self.time_window.set_value(10)
        thresh_box.pack_start(self.time_window, False, False, 0)
        
        thresh_box.pack_start(Gtk.Label(label="seconds"), False, False, 0)
        self.box.pack_start(thresh_box, False, False, 0)


class ProtocolChaosFrame(ModuleFrame):
    """Protocol Chaos controls with chaos options."""
    
    def __init__(self):
        super().__init__("🌀 Protocol Chaos", "chaos")
        
        # Separator
        self.box.pack_start(Gtk.Separator(), False, False, 4)
        
        # Chaos options
        self.ttl_check = Gtk.CheckButton(label="TTL Randomization")
        self.ttl_check.set_active(True)
        self.box.pack_start(self.ttl_check, False, False, 0)
        
        self.window_check = Gtk.CheckButton(label="Window Size Chaos")
        self.window_check.set_active(True)
        self.box.pack_start(self.window_check, False, False, 0)
        
        self.timestamp_check = Gtk.CheckButton(label="Timestamp Manipulation")
        self.timestamp_check.set_active(True)
        self.box.pack_start(self.timestamp_check, False, False, 0)
        
        self.tcp_opts_check = Gtk.CheckButton(label="TCP Options Chaos")
        self.box.pack_start(self.tcp_opts_check, False, False, 0)
        
        # Response jitter
        jitter_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        jitter_box.pack_start(Gtk.Label(label="Response Jitter:"), False, False, 0)
        
        self.jitter = Gtk.Scale.new_with_range(Gtk.Orientation.HORIZONTAL, 0, 1000, 50)
        self.jitter.set_value(250)
        self.jitter.set_hexpand(True)
        jitter_box.pack_start(self.jitter, True, True, 0)
        
        jitter_box.pack_start(Gtk.Label(label="ms"), False, False, 0)
        self.box.pack_start(jitter_box, False, False, 0)


class FrustrationFrame(ModuleFrame):
    """Frustration Engine controls."""
    
    def __init__(self):
        super().__init__("😤 Frustration Engine", "frustrate")
        
        # Separator
        self.box.pack_start(Gtk.Separator(), False, False, 4)
        
        # Frustration techniques
        self.slowdown_check = Gtk.CheckButton(label="Connection Slowdown")
        self.slowdown_check.set_active(True)
        self.box.pack_start(self.slowdown_check, False, False, 0)
        
        self.corrupt_check = Gtk.CheckButton(label="Response Corruption")
        self.box.pack_start(self.corrupt_check, False, False, 0)
        
        self.random_drop_check = Gtk.CheckButton(label="Random Packet Drops")
        self.box.pack_start(self.random_drop_check, False, False, 0)
        
        # Intensity
        intensity_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        intensity_box.pack_start(Gtk.Label(label="Intensity:"), False, False, 0)
        
        self.intensity = Gtk.Scale.new_with_range(Gtk.Orientation.HORIZONTAL, 1, 10, 1)
        self.intensity.set_value(5)
        self.intensity.set_hexpand(True)
        intensity_box.pack_start(self.intensity, True, True, 0)
        
        self.box.pack_start(intensity_box, False, False, 0)


class DefenseTab(Gtk.Box):
    """Defense tab containing scan detection, chaos, and frustration controls."""
    
    def __init__(self):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=15)
        self.set_margin_start(20)
        self.set_margin_end(20)
        self.set_margin_top(20)
        self.set_margin_bottom(20)
        
        # Title
        title = Gtk.Label()
        title.set_markup("<big><b>🛡️ ACTIVE DEFENSE</b></big>")
        title.set_halign(Gtk.Align.START)
        self.pack_start(title, False, False, 0)
        
        # Scrolled content
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        
        content_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=15)
        
        # Add module frames
        content_box.pack_start(ScanDetectionFrame(), False, False, 0)
        content_box.pack_start(ProtocolChaosFrame(), False, False, 0)
        content_box.pack_start(FrustrationFrame(), False, False, 0)
        
        scrolled.add(content_box)
        self.pack_start(scrolled, True, True, 0)
