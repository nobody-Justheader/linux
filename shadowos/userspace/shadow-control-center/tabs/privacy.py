#!/usr/bin/env python3
"""
ShadowOS Control Center - Privacy Tab
MAC Randomization, Identity Flux, Cloaking, Honeytokens
"""

import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk
import os

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


class MACFrame(ModuleFrame):
    def __init__(self):
        super().__init__("🔀 MAC Randomization", "mac")
        self.box.pack_start(Gtk.Separator(), False, False, 4)
        
        self.preserve_oui = Gtk.CheckButton(label="Preserve OUI")
        self.box.pack_start(self.preserve_oui, False, False, 0)
        
        rotate_btn = Gtk.Button(label="🔄 Rotate MAC Now")
        self.box.pack_start(rotate_btn, False, False, 8)


class IdentityFrame(ModuleFrame):
    def __init__(self):
        super().__init__("🎭 Identity Flux", "flux")
        self.box.pack_start(Gtk.Separator(), False, False, 4)
        
        self.mode = Gtk.ComboBoxText()
        self.mode.append_text("Random")
        self.mode.append_text("Sticky")
        self.mode.set_active(0)
        self.box.pack_start(self.mode, False, False, 0)


class CloakFrame(ModuleFrame):
    def __init__(self):
        super().__init__("👻 Process Cloaking", "cloak")
        self.box.pack_start(Gtk.Separator(), False, False, 4)
        
        self.pid_entry = Gtk.Entry()
        self.pid_entry.set_placeholder_text("PID to hide")
        self.box.pack_start(self.pid_entry, False, False, 0)


class HoneyFrame(ModuleFrame):
    def __init__(self):
        super().__init__("🍯 Honeytokens", "honey")
        self.box.pack_start(Gtk.Separator(), False, False, 4)
        
        self.path_entry = Gtk.Entry()
        self.path_entry.set_placeholder_text("Path to create")
        self.box.pack_start(self.path_entry, False, False, 0)


class PrivacyTab(Gtk.Box):
    def __init__(self):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=15)
        self.set_margin_start(20)
        self.set_margin_end(20)
        self.set_margin_top(20)
        self.set_margin_bottom(20)
        
        title = Gtk.Label()
        title.set_markup("<big><b>🔒 PRIVACY</b></big>")
        title.set_halign(Gtk.Align.START)
        self.pack_start(title, False, False, 0)
        
        scrolled = Gtk.ScrolledWindow()
        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=15)
        content.pack_start(MACFrame(), False, False, 0)
        content.pack_start(IdentityFrame(), False, False, 0)
        content.pack_start(CloakFrame(), False, False, 0)
        content.pack_start(HoneyFrame(), False, False, 0)
        scrolled.add(content)
        self.pack_start(scrolled, True, True, 0)
