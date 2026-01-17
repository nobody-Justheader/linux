#!/usr/bin/env python3
"""
ShadowOS Control Center - Offensive Tab
Packet Injection, Network Scanning, Exploitation Tools
"""

import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk
import os
import subprocess

SYSFS_BASE = "/sys/kernel/shadowos"


class ModuleFrame(Gtk.Frame):
    def __init__(self, title, module_name):
        super().__init__(label=title)
        self.module_name = module_name
        self.module_path = os.path.join(SYSFS_BASE, module_name)
        self.box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.box.set_margin_start(12)
        self.box.set_margin_end(12)
        self.box.set_margin_top(8)
        self.box.set_margin_bottom(8)
        
        enable_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        self.switch = Gtk.Switch()
        self.switch.connect("state-set", self.on_toggle)
        enable_box.pack_end(self.switch, False, False, 0)
        self.box.pack_start(enable_box, False, False, 0)
        self.add(self.box)
    
    def on_toggle(self, switch, state):
        try:
            with open(os.path.join(self.module_path, "enabled"), "w") as f:
                f.write("1" if state else "0")
        except:
            pass
        return False


class InjectFrame(ModuleFrame):
    def __init__(self):
        super().__init__("💉 Packet Injection", "inject")
        self.box.pack_start(Gtk.Separator(), False, False, 4)
        
        iface_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=5)
        iface_box.pack_start(Gtk.Label(label="Interface:"), False, False, 0)
        self.iface = Gtk.ComboBoxText()
        self.iface.append_text("eth0")
        self.iface.append_text("wlan0")
        self.iface.set_active(0)
        iface_box.pack_start(self.iface, True, True, 0)
        self.box.pack_start(iface_box, False, False, 0)
        
        self.raw_mode = Gtk.CheckButton(label="Raw Mode")
        self.box.pack_start(self.raw_mode, False, False, 0)


class ScanFrame(Gtk.Frame):
    def __init__(self):
        super().__init__(label="🔍 Network Scanning")
        self.box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.box.set_margin_start(12)
        self.box.set_margin_end(12)
        self.box.set_margin_top(8)
        self.box.set_margin_bottom(8)
        
        target_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=5)
        target_box.pack_start(Gtk.Label(label="Target:"), False, False, 0)
        self.target = Gtk.Entry()
        self.target.set_placeholder_text("192.168.1.0/24")
        target_box.pack_start(self.target, True, True, 0)
        self.box.pack_start(target_box, False, False, 0)
        
        self.scan_type = Gtk.ComboBoxText()
        self.scan_type.append_text("Quick Scan")
        self.scan_type.append_text("Full Port Scan")
        self.scan_type.append_text("Service Detection")
        self.scan_type.append_text("OS Detection")
        self.scan_type.set_active(0)
        self.box.pack_start(self.scan_type, False, False, 0)
        
        scan_btn = Gtk.Button(label="🚀 Start Scan")
        scan_btn.connect("clicked", self.on_scan)
        self.box.pack_start(scan_btn, False, False, 8)
        
        self.add(self.box)
    
    def on_scan(self, widget):
        target = self.target.get_text().strip()
        if target:
            subprocess.Popen(["shadow-scan", target])


class ExploitFrame(Gtk.Frame):
    def __init__(self):
        super().__init__(label="⚔️ Exploitation Tools")
        self.box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.box.set_margin_start(12)
        self.box.set_margin_end(12)
        self.box.set_margin_top(8)
        self.box.set_margin_bottom(8)
        
        msf_btn = Gtk.Button(label="Launch Metasploit")
        msf_btn.connect("clicked", lambda w: subprocess.Popen(["msfconsole"]))
        self.box.pack_start(msf_btn, False, False, 0)
        
        crack_btn = Gtk.Button(label="Launch Hashcat")
        crack_btn.connect("clicked", lambda w: subprocess.Popen(["hashcat", "--help"]))
        self.box.pack_start(crack_btn, False, False, 0)
        
        burp_btn = Gtk.Button(label="Launch Burp Suite")
        burp_btn.connect("clicked", lambda w: subprocess.Popen(["burpsuite"]))
        self.box.pack_start(burp_btn, False, False, 0)
        
        self.add(self.box)


class CredFrame(Gtk.Frame):
    def __init__(self):
        super().__init__(label="🔑 Credential Attacks")
        self.box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.box.set_margin_start(12)
        self.box.set_margin_end(12)
        self.box.set_margin_top(8)
        self.box.set_margin_bottom(8)
        
        target_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=5)
        target_box.pack_start(Gtk.Label(label="Target:"), False, False, 0)
        self.target = Gtk.Entry()
        self.target.set_placeholder_text("ssh://192.168.1.1")
        target_box.pack_start(self.target, True, True, 0)
        self.box.pack_start(target_box, False, False, 0)
        
        self.attack_type = Gtk.ComboBoxText()
        self.attack_type.append_text("Brute Force")
        self.attack_type.append_text("Dictionary")
        self.attack_type.append_text("Credential Spray")
        self.attack_type.set_active(1)
        self.box.pack_start(self.attack_type, False, False, 0)
        
        attack_btn = Gtk.Button(label="🔓 Start Attack")
        attack_btn.get_style_context().add_class("destructive-action")
        self.box.pack_start(attack_btn, False, False, 8)
        
        self.add(self.box)


class OffensiveTab(Gtk.Box):
    def __init__(self):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=15)
        self.set_margin_start(20)
        self.set_margin_end(20)
        self.set_margin_top(20)
        self.set_margin_bottom(20)
        
        # Warning banner
        warning = Gtk.Label()
        warning.set_markup("<span color='red'><b>⚠️ AUTHORIZED USE ONLY</b></span>")
        self.pack_start(warning, False, False, 0)
        
        title = Gtk.Label()
        title.set_markup("<big><b>⚔️ OFFENSIVE TOOLS</b></big>")
        title.set_halign(Gtk.Align.START)
        self.pack_start(title, False, False, 0)
        
        scrolled = Gtk.ScrolledWindow()
        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=15)
        content.pack_start(InjectFrame(), False, False, 0)
        content.pack_start(ScanFrame(), False, False, 0)
        content.pack_start(ExploitFrame(), False, False, 0)
        content.pack_start(CredFrame(), False, False, 0)
        scrolled.add(content)
        self.pack_start(scrolled, True, True, 0)
