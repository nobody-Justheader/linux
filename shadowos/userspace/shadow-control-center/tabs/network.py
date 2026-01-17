#!/usr/bin/env python3
"""
ShadowOS Control Center - Network Tab
DNS, Geo-Fencing, Fingerprinting, MTD, MAC, Injection, Promisc
"""

import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk
import os

SYSFS_BASE = "/sys/kernel/shadowos"


class ModuleRow(Gtk.ListBoxRow):
    """A simple module row with toggle switch."""
    
    def __init__(self, icon, name, module_name, description=""):
        super().__init__()
        self.module_name = module_name
        self.module_path = os.path.join(SYSFS_BASE, module_name)
        
        box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        box.set_margin_start(10)
        box.set_margin_end(10)
        box.set_margin_top(8)
        box.set_margin_bottom(8)
        
        # Icon
        icon_label = Gtk.Label(label=icon)
        icon_label.set_size_request(30, -1)
        box.pack_start(icon_label, False, False, 0)
        
        # Name and description
        text_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        
        name_label = Gtk.Label(label=name)
        name_label.set_halign(Gtk.Align.START)
        name_label.get_style_context().add_class("heading")
        text_box.pack_start(name_label, False, False, 0)
        
        if description:
            desc_label = Gtk.Label(label=description)
            desc_label.set_halign(Gtk.Align.START)
            desc_label.get_style_context().add_class("dim-label")
            text_box.pack_start(desc_label, False, False, 0)
        
        box.pack_start(text_box, True, True, 0)
        
        # Status/toggle
        if os.path.exists(self.module_path):
            self.switch = Gtk.Switch()
            self.switch.set_active(self.is_enabled())
            self.switch.connect("state-set", self.on_toggle)
            box.pack_end(self.switch, False, False, 0)
        else:
            status = Gtk.Label(label="Not loaded")
            status.get_style_context().add_class("dim-label")
            box.pack_end(status, False, False, 0)
        
        self.add(box)
    
    def is_enabled(self):
        try:
            with open(os.path.join(self.module_path, "enabled"), "r") as f:
                return f.read().strip() == "1"
        except:
            return False
    
    def on_toggle(self, switch, state):
        try:
            with open(os.path.join(self.module_path, "enabled"), "w") as f:
                f.write("1" if state else "0")
        except:
            pass
        return False


class DNSSinkholeFrame(Gtk.Frame):
    """DNS Sinkhole controls."""
    
    def __init__(self):
        super().__init__(label="🌐 DNS Sinkhole")
        self.module_path = os.path.join(SYSFS_BASE, "dns")
        
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
        
        # Block lists
        self.block_ads = Gtk.CheckButton(label="Block advertising domains")
        self.block_ads.set_active(True)
        box.pack_start(self.block_ads, False, False, 0)
        
        self.block_tracking = Gtk.CheckButton(label="Block tracking domains")
        self.block_tracking.set_active(True)
        box.pack_start(self.block_tracking, False, False, 0)
        
        self.block_malware = Gtk.CheckButton(label="Block malware domains")
        self.block_malware.set_active(True)
        box.pack_start(self.block_malware, False, False, 0)
        
        self.block_telemetry = Gtk.CheckButton(label="Block telemetry domains")
        self.block_telemetry.set_active(True)
        box.pack_start(self.block_telemetry, False, False, 0)
        
        # Custom blocklist
        custom_btn = Gtk.Button(label="Edit Custom Blocklist...")
        box.pack_start(custom_btn, False, False, 0)
        
        self.add(box)


class GeoFencingFrame(Gtk.Frame):
    """Geo-Fencing controls."""
    
    def __init__(self):
        super().__init__(label="🗺️ Geo-Fencing")
        self.module_path = os.path.join(SYSFS_BASE, "geo")
        
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
        
        # Mode
        mode_label = Gtk.Label(label="Mode:")
        mode_label.set_halign(Gtk.Align.START)
        box.pack_start(mode_label, False, False, 0)
        
        self.mode_allow = Gtk.RadioButton.new_with_label(None, "Allow only listed countries")
        self.mode_block = Gtk.RadioButton.new_with_label_from_widget(
            self.mode_allow, "Block listed countries"
        )
        box.pack_start(self.mode_allow, False, False, 0)
        box.pack_start(self.mode_block, False, False, 0)
        
        # Country list button
        countries_btn = Gtk.Button(label="Configure Countries...")
        box.pack_start(countries_btn, False, False, 0)
        
        self.add(box)


class NetworkTab(Gtk.Box):
    """Network tab with various network security modules."""
    
    def __init__(self):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=15)
        self.set_margin_start(20)
        self.set_margin_end(20)
        self.set_margin_top(20)
        self.set_margin_bottom(20)
        
        # Title
        title = Gtk.Label()
        title.set_markup("<big><b>📡 NETWORK SECURITY</b></big>")
        title.set_halign(Gtk.Align.START)
        self.pack_start(title, False, False, 0)
        
        # Scrolled content
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        
        content_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=15)
        
        # Full-featured frames
        content_box.pack_start(DNSSinkholeFrame(), False, False, 0)
        content_box.pack_start(GeoFencingFrame(), False, False, 0)
        
        # Simple module list
        simple_frame = Gtk.Frame(label="Additional Modules")
        listbox = Gtk.ListBox()
        listbox.set_selection_mode(Gtk.SelectionMode.NONE)
        
        modules = [
            ("🔍", "JA3/HASSH Fingerprinting", "fprint", "TLS/SSH client fingerprinting"),
            ("🎯", "Moving Target Defense", "mtd", "Dynamic network reconfiguration"),
            ("📡", "MAC Spoofing", "mac", "Interface MAC address management"),
            ("💉", "Packet Injection", "inject", "Raw packet injection capability"),
            ("🙈", "Promisc Hiding", "promisc", "Hide promiscuous mode from detection"),
        ]
        
        for icon, name, module, desc in modules:
            listbox.add(ModuleRow(icon, name, module, desc))
        
        simple_frame.add(listbox)
        content_box.pack_start(simple_frame, False, False, 0)
        
        scrolled.add(content_box)
        self.pack_start(scrolled, True, True, 0)
