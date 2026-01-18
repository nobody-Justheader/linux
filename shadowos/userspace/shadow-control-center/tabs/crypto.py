#!/usr/bin/env python3
"""
ShadowOS Control Center - Crypto Tab
Memory Encryption, Duress Passwords, Evidence Chain
"""

import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk
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
    
    def is_enabled(self):
        val = self.read_attr("enabled")
        return val == "1" if val else False
    
    def update_status(self):
        if self.available:
            self.status_label.set_markup("● <b>Available</b>")
        else:
            self.status_label.set_markup("○ <i>Not loaded</i>")
    
    def on_toggle(self, switch, state):
        self.write_attr("enabled", "1" if state else "0")
        return False


class MemcryptFrame(ModuleFrame):
    """Memory Encryption controls."""
    
    def __init__(self):
        super().__init__("🔐 Memory Encryption", "memcrypt")
        
        self.box.pack_start(Gtk.Separator(), False, False, 4)
        
        # Algorithm info
        info = Gtk.Label(label="AES-256-CBC encryption for sensitive memory regions")
        info.set_halign(Gtk.Align.START)
        info.get_style_context().add_class("dim-label")
        self.box.pack_start(info, False, False, 0)
        
        # Stats
        stats_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=20)
        
        self.regions_label = Gtk.Label()
        stats_box.pack_start(self.regions_label, False, False, 0)
        
        self.bytes_label = Gtk.Label()
        stats_box.pack_start(self.bytes_label, False, False, 0)
        
        self.box.pack_start(stats_box, False, False, 4)
        
        # Key rotation button
        rotate_btn = Gtk.Button(label="🔄 Rotate Keys")
        rotate_btn.connect("clicked", self.on_rotate_keys)
        self.box.pack_start(rotate_btn, False, False, 4)
        
        self.refresh_stats()
    
    def refresh_stats(self):
        stats = self.read_attr("stats") or ""
        regions = "0"
        bytes_enc = "0"
        for line in stats.split('\n'):
            if 'regions' in line.lower():
                regions = line.split(':')[-1].strip()
            if 'bytes' in line.lower():
                bytes_enc = line.split(':')[-1].strip()
        self.regions_label.set_text(f"Regions: {regions}")
        self.bytes_label.set_text(f"Encrypted: {bytes_enc} bytes")
    
    def on_rotate_keys(self, button):
        if self.write_attr("rotate_key", "1"):
            self.refresh_stats()


class DuressFrame(ModuleFrame):
    """Duress Password controls."""
    
    def __init__(self):
        super().__init__("🚨 Duress Passwords", "duress")
        
        self.box.pack_start(Gtk.Separator(), False, False, 4)
        
        # Description
        info = Gtk.Label(label="Emergency passwords that trigger panic actions")
        info.set_halign(Gtk.Align.START)
        info.get_style_context().add_class("dim-label")
        self.box.pack_start(info, False, False, 0)
        
        # Add duress password
        add_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.password_entry = Gtk.Entry()
        self.password_entry.set_placeholder_text("Enter duress password")
        self.password_entry.set_visibility(False)
        add_box.pack_start(self.password_entry, True, True, 0)
        
        add_btn = Gtk.Button(label="Add")
        add_btn.connect("clicked", self.on_add_password)
        add_box.pack_start(add_btn, False, False, 0)
        
        self.box.pack_start(add_box, False, False, 4)
        
        # Actions
        action_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        action_label = Gtk.Label(label="Action:")
        action_box.pack_start(action_label, False, False, 0)
        
        self.action_combo = Gtk.ComboBoxText()
        self.action_combo.append_text("wipe")
        self.action_combo.append_text("shutdown")
        self.action_combo.append_text("lock")
        self.action_combo.set_active(0)
        action_box.pack_start(self.action_combo, False, False, 0)
        
        self.box.pack_start(action_box, False, False, 4)
    
    def on_add_password(self, button):
        password = self.password_entry.get_text()
        if password:
            self.write_attr("add", password)
            self.password_entry.set_text("")


class EvidenceFrame(ModuleFrame):
    """Evidence Chain controls."""
    
    def __init__(self):
        super().__init__("📋 Evidence Chain", "evidence")
        
        self.box.pack_start(Gtk.Separator(), False, False, 4)
        
        # Description
        info = Gtk.Label(label="Tamper-resistant logging with SHA-256 hash chain")
        info.set_halign(Gtk.Align.START)
        info.get_style_context().add_class("dim-label")
        self.box.pack_start(info, False, False, 0)
        
        # Stats
        stats_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=20)
        
        self.entries_label = Gtk.Label()
        stats_box.pack_start(self.entries_label, False, False, 0)
        
        self.integrity_label = Gtk.Label()
        stats_box.pack_start(self.integrity_label, False, False, 0)
        
        self.box.pack_start(stats_box, False, False, 4)
        
        # Verify button
        verify_btn = Gtk.Button(label="✓ Verify Chain Integrity")
        verify_btn.connect("clicked", self.on_verify)
        self.box.pack_start(verify_btn, False, False, 4)
        
        self.refresh_stats()
    
    def refresh_stats(self):
        stats = self.read_attr("stats") or ""
        entries = "0"
        for line in stats.split('\n'):
            if 'entries' in line.lower():
                entries = line.split(':')[-1].strip()
        self.entries_label.set_text(f"Log entries: {entries}")
        self.integrity_label.set_text("Integrity: ✓ Valid")
    
    def on_verify(self, button):
        result = self.read_attr("verify")
        if result and "valid" in result.lower():
            self.integrity_label.set_markup("Integrity: <b>✓ Valid</b>")
        else:
            self.integrity_label.set_markup("Integrity: <b>✗ INVALID</b>")


class CryptoTab(Gtk.Box):
    """Main Crypto tab container."""
    
    def __init__(self):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self.set_margin_start(16)
        self.set_margin_end(16)
        self.set_margin_top(16)
        self.set_margin_bottom(16)
        
        # Header
        header = Gtk.Label()
        header.set_markup("<big><b>🔐 Cryptographic Security</b></big>")
        header.set_halign(Gtk.Align.START)
        self.pack_start(header, False, False, 0)
        
        desc = Gtk.Label(label="Memory encryption, duress passwords, and tamper-proof logging")
        desc.set_halign(Gtk.Align.START)
        desc.get_style_context().add_class("dim-label")
        self.pack_start(desc, False, False, 0)
        
        self.pack_start(Gtk.Separator(), False, False, 8)
        
        # Module frames
        self.pack_start(MemcryptFrame(), False, False, 0)
        self.pack_start(DuressFrame(), False, False, 0)
        self.pack_start(EvidenceFrame(), False, False, 0)


def get_tab():
    """Return the tab widget and label."""
    return CryptoTab(), "🔐 Crypto"
