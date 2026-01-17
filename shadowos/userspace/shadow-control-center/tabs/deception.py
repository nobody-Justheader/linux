#!/usr/bin/env python3
"""
ShadowOS Control Center - Deception Tab
Phantom Services, Identity Flux, Decoy Network, Infinite Depth
"""

import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk
import os

SYSFS_BASE = "/sys/kernel/shadowos"

BANNER_PROFILES = [
    "Corporate Server",
    "Home Router",
    "IoT Device",
    "Development Server",
    "Web Server",
    "Database Server",
]

OS_PROFILES = [
    ("Windows 10", "win10"),
    ("Windows Server 2019", "winserver"),
    ("Ubuntu 22.04", "ubuntu"),
    ("CentOS 7", "centos"),
    ("macOS Ventura", "macos"),
    ("FreeBSD 13", "freebsd"),
    ("Cisco IOS", "cisco"),
    ("HP Printer", "printer"),
]


class PhantomServicesFrame(Gtk.Frame):
    """Phantom Services configuration."""
    
    def __init__(self):
        super().__init__(label="👻 Phantom Services")
        self.module_path = os.path.join(SYSFS_BASE, "phantom")
        
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        box.set_margin_start(12)
        box.set_margin_end(12)
        box.set_margin_top(8)
        box.set_margin_bottom(8)
        
        # Status and toggle
        status_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        self.status_label = Gtk.Label()
        self.update_status()
        status_box.pack_start(self.status_label, False, False, 0)
        
        self.switch = Gtk.Switch()
        self.switch.set_active(self.is_enabled())
        self.switch.connect("state-set", self.on_toggle)
        status_box.pack_end(self.switch, False, False, 0)
        
        box.pack_start(status_box, False, False, 0)
        box.pack_start(Gtk.Separator(), False, False, 4)
        
        # Banner profile
        profile_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        profile_box.pack_start(Gtk.Label(label="Banner Profile:"), False, False, 0)
        
        self.profile_combo = Gtk.ComboBoxText()
        for profile in BANNER_PROFILES:
            self.profile_combo.append_text(profile)
        self.profile_combo.set_active(0)
        profile_box.pack_start(self.profile_combo, True, True, 0)
        
        box.pack_start(profile_box, False, False, 0)
        
        # Active ports list
        ports_label = Gtk.Label(label="Active Phantom Ports:")
        ports_label.set_halign(Gtk.Align.START)
        box.pack_start(ports_label, False, False, 0)
        
        ports_scroll = Gtk.ScrolledWindow()
        ports_scroll.set_min_content_height(100)
        
        self.ports_list = Gtk.ListBox()
        self.ports_list.set_selection_mode(Gtk.SelectionMode.NONE)
        
        # Default phantom ports
        default_ports = [
            ("22", "SSH-2.0-OpenSSH_8.9p1"),
            ("80", "Apache/2.4.52"),
            ("443", "(TLS tarpit)"),
            ("3389", "(RDP tarpit)"),
            ("445", "(SMB tarpit)"),
        ]
        
        for port, banner in default_ports:
            row = Gtk.ListBoxRow()
            hbox = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
            hbox.set_margin_start(5)
            hbox.set_margin_end(5)
            hbox.set_margin_top(3)
            hbox.set_margin_bottom(3)
            
            port_label = Gtk.Label(label=f":{port}")
            port_label.set_width_chars(6)
            hbox.pack_start(port_label, False, False, 0)
            
            banner_label = Gtk.Label(label=banner)
            banner_label.set_halign(Gtk.Align.START)
            hbox.pack_start(banner_label, True, True, 0)
            
            row.add(hbox)
            self.ports_list.add(row)
        
        ports_scroll.add(self.ports_list)
        box.pack_start(ports_scroll, False, False, 0)
        
        # Configure button
        config_btn = Gtk.Button(label="Configure Custom Ports...")
        box.pack_start(config_btn, False, False, 0)
        
        self.add(box)
    
    @property
    def available(self):
        return os.path.exists(self.module_path)
    
    def is_enabled(self):
        try:
            with open(os.path.join(self.module_path, "enabled"), "r") as f:
                return f.read().strip() == "1"
        except:
            return False
    
    def update_status(self):
        if self.available:
            self.status_label.set_markup("● <b>Active</b>")
        else:
            self.status_label.set_markup("○ <i>Not loaded</i>")
    
    def on_toggle(self, switch, state):
        try:
            with open(os.path.join(self.module_path, "enabled"), "w") as f:
                f.write("1" if state else "0")
        except:
            pass
        return False


class IdentityFluxFrame(Gtk.Frame):
    """Identity Flux controls."""
    
    def __init__(self):
        super().__init__(label="🎭 Identity Flux")
        self.module_path = os.path.join(SYSFS_BASE, "flux")
        
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        box.set_margin_start(12)
        box.set_margin_end(12)
        box.set_margin_top(8)
        box.set_margin_bottom(8)
        
        # Status and toggle
        status_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        self.status_label = Gtk.Label()
        self.update_status()
        status_box.pack_start(self.status_label, False, False, 0)
        
        self.switch = Gtk.Switch()
        self.switch.set_active(self.is_enabled())
        self.switch.connect("state-set", self.on_toggle)
        status_box.pack_end(self.switch, False, False, 0)
        
        box.pack_start(status_box, False, False, 0)
        box.pack_start(Gtk.Separator(), False, False, 4)
        
        # Mode selection
        mode_label = Gtk.Label(label="Mode:")
        mode_label.set_halign(Gtk.Align.START)
        box.pack_start(mode_label, False, False, 0)
        
        self.mode_random = Gtk.RadioButton.new_with_label(None, "Random per connection")
        self.mode_sticky = Gtk.RadioButton.new_with_label_from_widget(
            self.mode_random, "Sticky (same for session)"
        )
        self.mode_fixed = Gtk.RadioButton.new_with_label_from_widget(
            self.mode_random, "Fixed profile"
        )
        self.mode_sticky.set_active(True)
        
        box.pack_start(self.mode_random, False, False, 0)
        box.pack_start(self.mode_sticky, False, False, 0)
        box.pack_start(self.mode_fixed, False, False, 0)
        
        box.pack_start(Gtk.Separator(), False, False, 4)
        
        # Profile buttons
        profiles_label = Gtk.Label(label="OS Profiles:")
        profiles_label.set_halign(Gtk.Align.START)
        box.pack_start(profiles_label, False, False, 0)
        
        profile_flow = Gtk.FlowBox()
        profile_flow.set_selection_mode(Gtk.SelectionMode.SINGLE)
        profile_flow.set_max_children_per_line(4)
        profile_flow.set_min_children_per_line(2)
        
        for name, _ in OS_PROFILES:
            btn = Gtk.Button(label=name)
            profile_flow.add(btn)
        
        box.pack_start(profile_flow, False, False, 0)
        
        self.add(box)
    
    @property
    def available(self):
        return os.path.exists(self.module_path)
    
    def is_enabled(self):
        try:
            with open(os.path.join(self.module_path, "enabled"), "r") as f:
                return f.read().strip() == "1"
        except:
            return False
    
    def update_status(self):
        if self.available:
            self.status_label.set_markup("● <b>Active</b>")
        else:
            self.status_label.set_markup("○ <i>Not loaded</i>")
    
    def on_toggle(self, switch, state):
        try:
            with open(os.path.join(self.module_path, "enabled"), "w") as f:
                f.write("1" if state else "0")
        except:
            pass
        return False


class DecoyNetworkFrame(Gtk.Frame):
    """Decoy Network controls."""
    
    def __init__(self):
        super().__init__(label="🪤 Decoy Network")
        self.module_path = os.path.join(SYSFS_BASE, "decoy")
        
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        box.set_margin_start(12)
        box.set_margin_end(12)
        box.set_margin_top(8)
        box.set_margin_bottom(8)
        
        # Status and toggle
        status_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        status_label = Gtk.Label()
        if os.path.exists(self.module_path):
            status_label.set_markup("● <b>Available</b>")
        else:
            status_label.set_markup("○ <i>Not loaded</i>")
        status_box.pack_start(status_label, False, False, 0)
        
        switch = Gtk.Switch()
        status_box.pack_end(switch, False, False, 0)
        
        box.pack_start(status_box, False, False, 0)
        box.pack_start(Gtk.Separator(), False, False, 4)
        
        # Decoy count
        count_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        count_box.pack_start(Gtk.Label(label="Decoy Hosts:"), False, False, 0)
        
        self.decoy_count = Gtk.SpinButton.new_with_range(1, 50, 1)
        self.decoy_count.set_value(10)
        count_box.pack_start(self.decoy_count, False, False, 0)
        
        box.pack_start(count_box, False, False, 0)
        
        # Options
        self.respond_check = Gtk.CheckButton(label="Respond to ARP")
        self.respond_check.set_active(True)
        box.pack_start(self.respond_check, False, False, 0)
        
        self.services_check = Gtk.CheckButton(label="Fake services on decoys")
        self.services_check.set_active(True)
        box.pack_start(self.services_check, False, False, 0)
        
        self.add(box)


class InfiniteDepthFrame(Gtk.Frame):
    """Infinite Depth controls."""
    
    def __init__(self):
        super().__init__(label="∞ Infinite Depth")
        self.module_path = os.path.join(SYSFS_BASE, "infinite")
        
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        box.set_margin_start(12)
        box.set_margin_end(12)
        box.set_margin_top(8)
        box.set_margin_bottom(8)
        
        # Status and toggle
        status_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        status_label = Gtk.Label()
        if os.path.exists(self.module_path):
            status_label.set_markup("● <b>Available</b>")
        else:
            status_label.set_markup("○ <i>Not loaded</i>")
        status_box.pack_start(status_label, False, False, 0)
        
        switch = Gtk.Switch()
        status_box.pack_end(switch, False, False, 0)
        
        box.pack_start(status_box, False, False, 0)
        box.pack_start(Gtk.Separator(), False, False, 4)
        
        # Description
        desc = Gtk.Label(label="Generates infinite fake directory structures\nto trap and confuse attackers.")
        desc.set_line_wrap(True)
        desc.set_halign(Gtk.Align.START)
        box.pack_start(desc, False, False, 0)
        
        # Depth setting
        depth_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        depth_box.pack_start(Gtk.Label(label="Max Depth:"), False, False, 0)
        
        self.max_depth = Gtk.SpinButton.new_with_range(5, 100, 5)
        self.max_depth.set_value(50)
        depth_box.pack_start(self.max_depth, False, False, 0)
        
        box.pack_start(depth_box, False, False, 0)
        
        self.add(box)


class DeceptionTab(Gtk.Box):
    """Deception tab containing phantom, flux, decoy, and infinite depth controls."""
    
    def __init__(self):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=15)
        self.set_margin_start(20)
        self.set_margin_end(20)
        self.set_margin_top(20)
        self.set_margin_bottom(20)
        
        # Title
        title = Gtk.Label()
        title.set_markup("<big><b>🎭 NETWORK DECEPTION</b></big>")
        title.set_halign(Gtk.Align.START)
        self.pack_start(title, False, False, 0)
        
        # Scrolled content
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        
        content_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=15)
        
        # Add module frames
        content_box.pack_start(PhantomServicesFrame(), False, False, 0)
        content_box.pack_start(IdentityFluxFrame(), False, False, 0)
        content_box.pack_start(DecoyNetworkFrame(), False, False, 0)
        content_box.pack_start(InfiniteDepthFrame(), False, False, 0)
        
        scrolled.add(content_box)
        self.pack_start(scrolled, True, True, 0)
