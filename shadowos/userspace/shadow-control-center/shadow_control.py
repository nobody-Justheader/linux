#!/usr/bin/env python3
"""
ShadowOS Control Center
GTK 3.0 application for managing ShadowOS kernel modules.

Copyright (C) 2024 ShadowOS Project
"""

import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk, GLib, Gio
import os
import threading

# ShadowOS sysfs base path
SYSFS_BASE = "/sys/kernel/shadowos"

class ShadowModule:
    """Wrapper for a ShadowOS kernel module."""
    
    def __init__(self, name, display_name, icon):
        self.name = name
        self.display_name = display_name
        self.icon = icon
        self.path = os.path.join(SYSFS_BASE, name)
    
    @property
    def available(self):
        return os.path.exists(self.path)
    
    @property
    def enabled(self):
        try:
            with open(os.path.join(self.path, "enabled"), "r") as f:
                return f.read().strip() == "1"
        except:
            return False
    
    @enabled.setter
    def enabled(self, value):
        try:
            with open(os.path.join(self.path, "enabled"), "w") as f:
                f.write("1" if value else "0")
        except Exception as e:
            print(f"Error setting {self.name} enabled: {e}")
    
    def read_attr(self, attr):
        try:
            with open(os.path.join(self.path, attr), "r") as f:
                return f.read().strip()
        except:
            return ""
    
    def write_attr(self, attr, value):
        try:
            with open(os.path.join(self.path, attr), "w") as f:
                f.write(str(value))
            return True
        except:
            return False


# Module definitions
MODULES = {
    'defense': [
        ShadowModule('detect', 'Scan Detection', '🛡️'),
        ShadowModule('chaos', 'Protocol Chaos', '🌀'),
        ShadowModule('frustrate', 'Frustration Engine', '😤'),
    ],
    'deception': [
        ShadowModule('phantom', 'Phantom Services', '👻'),
        ShadowModule('flux', 'Identity Flux', '🎭'),
        ShadowModule('decoy', 'Decoy Network', '🪤'),
        ShadowModule('infinite', 'Infinite Depth', '∞'),
    ],
    'network': [
        ShadowModule('dns', 'DNS Sinkhole', '🌐'),
        ShadowModule('geo', 'Geo-Fencing', '🗺️'),
        ShadowModule('fprint', 'JA3/HASSH Fingerprinting', '🔍'),
        ShadowModule('mtd', 'Moving Target Defense', '🎯'),
        ShadowModule('mac', 'MAC Spoofing', '📡'),
        ShadowModule('inject', 'Packet Injection', '💉'),
        ShadowModule('promisc', 'Promisc Hiding', '🙈'),
    ],
    'hardware': [
        ShadowModule('usb', 'USB Firewall', '🔌'),
        ShadowModule('av', 'Camera/Mic Kill', '📷'),
    ],
    'storage': [
        ShadowModule('shred', 'Secure Shred', '🗑️'),
        ShadowModule('meta', 'Metadata Scrub', '🧹'),
    ],
    'antiforensics': [
        ShadowModule('ram', 'RAM Scrubbing', '💾'),
        ShadowModule('panic', 'Panic Button', '🚨'),
        ShadowModule('cloak', 'Process Cloaking', '🥷'),
        ShadowModule('honey', 'Honeytokens', '🍯'),
        ShadowModule('deadman', "Dead Man's Switch", '💀'),
        ShadowModule('timelock', 'Time-Lock', '⏰'),
    ],
}


class ModuleRow(Gtk.ListBoxRow):
    """A row displaying a module with toggle switch."""
    
    def __init__(self, module):
        super().__init__()
        self.module = module
        
        box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        box.set_margin_start(10)
        box.set_margin_end(10)
        box.set_margin_top(5)
        box.set_margin_bottom(5)
        
        # Icon
        icon_label = Gtk.Label(label=module.icon)
        icon_label.set_size_request(30, -1)
        box.pack_start(icon_label, False, False, 0)
        
        # Name
        name_label = Gtk.Label(label=module.display_name)
        name_label.set_halign(Gtk.Align.START)
        box.pack_start(name_label, True, True, 0)
        
        # Status
        if module.available:
            self.switch = Gtk.Switch()
            self.switch.set_active(module.enabled)
            self.switch.connect("state-set", self.on_toggle)
            box.pack_end(self.switch, False, False, 0)
        else:
            status = Gtk.Label(label="Not loaded")
            status.get_style_context().add_class("dim-label")
            box.pack_end(status, False, False, 0)
        
        self.add(box)
    
    def on_toggle(self, switch, state):
        self.module.enabled = state
        return False


class CategoryPage(Gtk.Box):
    """A page for a category of modules."""
    
    def __init__(self, category_name, modules):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        self.set_margin_start(20)
        self.set_margin_end(20)
        self.set_margin_top(20)
        self.set_margin_bottom(20)
        
        # Title
        title = Gtk.Label()
        title.set_markup(f"<big><b>{category_name.upper()}</b></big>")
        title.set_halign(Gtk.Align.START)
        self.pack_start(title, False, False, 0)
        
        # Module list
        listbox = Gtk.ListBox()
        listbox.set_selection_mode(Gtk.SelectionMode.NONE)
        listbox.get_style_context().add_class("boxed-list")
        
        for module in modules:
            row = ModuleRow(module)
            listbox.add(row)
        
        frame = Gtk.Frame()
        frame.add(listbox)
        self.pack_start(frame, False, False, 0)


class EmergencyPage(Gtk.Box):
    """Emergency controls page with dangerous actions."""
    
    def __init__(self):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=20)
        self.set_margin_start(20)
        self.set_margin_end(20)
        self.set_margin_top(20)
        self.set_margin_bottom(20)
        
        # Warning
        warning = Gtk.Label()
        warning.set_markup("<big><b>⚠️ EMERGENCY CONTROLS</b></big>\n<i>Use with extreme caution!</i>")
        warning.set_halign(Gtk.Align.CENTER)
        self.pack_start(warning, False, False, 0)
        
        # Quick actions
        button_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        button_box.set_halign(Gtk.Align.CENTER)
        
        ram_btn = Gtk.Button(label="🧹 Scrub RAM Now")
        ram_btn.connect("clicked", self.on_ram_scrub)
        button_box.pack_start(ram_btn, False, False, 0)
        
        mac_btn = Gtk.Button(label="🔀 Rotate All MACs")
        mac_btn.connect("clicked", self.on_rotate_macs)
        button_box.pack_start(mac_btn, False, False, 0)
        
        kill_btn = Gtk.Button(label="🔌 Kill Network")
        kill_btn.connect("clicked", self.on_kill_network)
        button_box.pack_start(kill_btn, False, False, 0)
        
        self.pack_start(button_box, False, False, 0)
        
        # Separator
        self.pack_start(Gtk.Separator(), False, False, 10)
        
        # Panic button
        panic_frame = Gtk.Frame()
        panic_frame.set_label("⚠️ Panic Wipe")
        panic_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        panic_box.set_margin_start(10)
        panic_box.set_margin_end(10)
        panic_box.set_margin_top(10)
        panic_box.set_margin_bottom(10)
        
        confirm_label = Gtk.Label(label="Type 'CONFIRM WIPE' to enable panic button:")
        panic_box.pack_start(confirm_label, False, False, 0)
        
        self.confirm_entry = Gtk.Entry()
        self.confirm_entry.set_placeholder_text("CONFIRM WIPE")
        panic_box.pack_start(self.confirm_entry, False, False, 0)
        
        self.panic_btn = Gtk.Button(label="🔴 TRIGGER EMERGENCY WIPE")
        self.panic_btn.set_sensitive(False)
        self.panic_btn.get_style_context().add_class("destructive-action")
        self.panic_btn.connect("clicked", self.on_panic)
        self.confirm_entry.connect("changed", self.on_confirm_changed)
        panic_box.pack_start(self.panic_btn, False, False, 0)
        
        panic_frame.add(panic_box)
        self.pack_start(panic_frame, False, False, 0)
    
    def on_confirm_changed(self, entry):
        self.panic_btn.set_sensitive(entry.get_text() == "CONFIRM WIPE")
    
    def on_ram_scrub(self, button):
        self.execute_action("ram", "scrub_now", "1")
    
    def on_rotate_macs(self, button):
        self.execute_action("mac", "rotate_all", "1")
    
    def on_kill_network(self, button):
        os.system("ip link set eth0 down 2>/dev/null")
    
    def on_panic(self, button):
        if self.confirm_entry.get_text() == "CONFIRM WIPE":
            self.execute_action("panic", "trigger", "CONFIRM")
    
    def execute_action(self, module, attr, value):
        path = os.path.join(SYSFS_BASE, module, attr)
        try:
            with open(path, "w") as f:
                f.write(value)
        except Exception as e:
            print(f"Error: {e}")


class MonitorPage(Gtk.Box):
    """Security monitoring page."""
    
    def __init__(self):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        self.set_margin_start(20)
        self.set_margin_end(20)
        self.set_margin_top(20)
        self.set_margin_bottom(20)
        
        # Title
        title = Gtk.Label()
        title.set_markup("<big><b>📊 SECURITY MONITOR</b></big>")
        title.set_halign(Gtk.Align.START)
        self.pack_start(title, False, False, 0)
        
        # Stats display
        self.stats_text = Gtk.TextView()
        self.stats_text.set_editable(False)
        self.stats_text.set_monospace(True)
        
        scroll = Gtk.ScrolledWindow()
        scroll.set_min_content_height(200)
        scroll.add(self.stats_text)
        self.pack_start(scroll, True, True, 0)
        
        # Refresh button
        refresh_btn = Gtk.Button(label="🔄 Refresh Stats")
        refresh_btn.connect("clicked", self.refresh_stats)
        self.pack_start(refresh_btn, False, False, 0)
        
        self.refresh_stats(None)
    
    def refresh_stats(self, button):
        stats = []
        
        for category, modules in MODULES.items():
            for module in modules:
                if module.available:
                    stat = module.read_attr("stats")
                    if stat:
                        stats.append(f"[{module.display_name}]")
                        stats.append(stat)
                        stats.append("")
        
        buffer = self.stats_text.get_buffer()
        buffer.set_text("\n".join(stats) if stats else "No statistics available")


class ShadowControlCenter(Gtk.Window):
    """Main application window."""
    
    def __init__(self):
        super().__init__(title="ShadowOS Control Center")
        self.set_default_size(800, 600)
        self.set_border_width(0)
        
        # Header bar
        header = Gtk.HeaderBar()
        header.set_show_close_button(True)
        header.set_title("ShadowOS Control Center")
        header.set_subtitle(self.get_status())
        self.set_titlebar(header)
        
        # Main stack
        stack = Gtk.Stack()
        stack.set_transition_type(Gtk.StackTransitionType.SLIDE_LEFT_RIGHT)
        
        # Add pages for each category
        for category, modules in MODULES.items():
            page = CategoryPage(category, modules)
            stack.add_titled(page, category, category.title())
        
        # Add emergency page
        emergency_page = EmergencyPage()
        stack.add_titled(emergency_page, "emergency", "🚨 Emergency")
        
        # Add monitor page
        monitor_page = MonitorPage()
        stack.add_titled(monitor_page, "monitor", "📊 Monitor")
        
        # Stack switcher
        switcher = Gtk.StackSwitcher()
        switcher.set_stack(stack)
        header.set_custom_title(switcher)
        
        self.add(stack)
    
    def get_status(self):
        if os.path.exists(SYSFS_BASE):
            return "🟢 Protected"
        return "🔴 Modules not loaded"


def main():
    # Premium Dark Theme (Cyberpunk/Security Style)
    css = b"""
    * {
        color: #e0e0e0;
    }
    
    window {
        background-color: #1a1b26;
    }
    
    headerbar {
        background-color: #24283b;
        border-bottom: 1px solid #414868;
        min-height: 48px;
    }
    
    headerbar entry,
    headerbar button {
        background-color: #414868;
        color: white;
        border: none;
        box-shadow: none;
    }
    
    label {
        color: #a9b1d6;
        font-family: 'Inter', 'Segoe UI', sans-serif;
    }
    
    button {
        background-color: #414868;
        color: #c0caf5;
        border: none;
        border-radius: 6px;
        padding: 8px 16px;
        font-weight: bold;
        transition: all 0.2s;
    }
    
    button:hover {
        background-color: #565f89;
        color: white;
        box-shadow: 0 0 10px rgba(86, 95, 137, 0.5);
    }
    
    button:active {
        background-color: #7aa2f7;
        color: #1a1b26;
    }
    
    switch {
        background-color: #24283b; 
        border: 1px solid #565f89;
    }
    
    switch:checked {
        background-color: #7aa2f7; 
        border-color: #7aa2f7;
    }
    
    switch slider {
        background-color: #a9b1d6;
    }
    
    .boxed-list {
        background-color: #24283b;
        border-radius: 8px;
        padding: 5px;
        border: 1px solid #414868;
    }
    
    row {
        padding: 10px;
        border-bottom: 1px solid #1a1b26;
    }
    
    row:last-child {
        border-bottom: none;
    }
    
    row:hover {
        background-color: #2f3549;
    }

    /* Status indicators */
    .dim-label {
        color: #565f89;
        font-size: 0.9em;
    }

    /* Emergency Controls */
    .destructive-action {
        background-color: #f7768e;
        color: #1a1b26;
    }
    
    .destructive-action:hover {
        background-color: #ff9e64;
    }
    
    frame {
        border: 1px solid #414868;
        border-radius: 8px;
    }
    
    frame border {
        border: none;
    }
    """
    css_provider = Gtk.CssProvider()
    css_provider.load_from_data(css)
    Gtk.StyleContext.add_provider_for_screen(
        Gdk.Screen.get_default() if 'Gdk' in dir() else None,
        css_provider,
        Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
    )
    
    # Force dark theme preference
    settings = Gtk.Settings.get_default()
    settings.set_property("gtk-application-prefer-dark-theme", True)
    settings.set_property("gtk-theme-name", "Adwaita-dark")
    
    win = ShadowControlCenter()
    win.connect("destroy", Gtk.main_quit)
    win.show_all()
    Gtk.main()


if __name__ == "__main__":
    main()
