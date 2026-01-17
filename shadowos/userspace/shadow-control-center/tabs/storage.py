#!/usr/bin/env python3
"""
ShadowOS Control Center - Storage Tab
Secure Shred, RAM Security, Metadata Scrubbing, Evidence Preservation
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


class SecureShredFrame(ModuleFrame):
    """Secure file deletion controls."""
    
    def __init__(self):
        super().__init__("🗑️ Secure Shred", "shred")
        
        # Separator
        self.box.pack_start(Gtk.Separator(), False, False, 4)
        
        # Overwrite passes
        pass_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        pass_box.pack_start(Gtk.Label(label="Overwrite Passes:"), False, False, 0)
        
        self.passes = Gtk.SpinButton.new_with_range(1, 35, 1)
        self.passes.set_value(3)
        pass_box.pack_start(self.passes, False, False, 0)
        
        self.box.pack_start(pass_box, False, False, 0)
        
        # Options
        self.zero_fill = Gtk.CheckButton(label="Final Zero Fill")
        self.zero_fill.set_active(True)
        self.box.pack_start(self.zero_fill, False, False, 0)
        
        self.random_name = Gtk.CheckButton(label="Randomize Filename Before Delete")
        self.random_name.set_active(True)
        self.box.pack_start(self.random_name, False, False, 0)
        
        self.verify = Gtk.CheckButton(label="Verify Overwrite")
        self.verify.set_active(False)
        self.box.pack_start(self.verify, False, False, 0)
        
        # Method selector
        method_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        method_box.pack_start(Gtk.Label(label="Method:"), False, False, 0)
        
        self.method = Gtk.ComboBoxText()
        self.method.append_text("Random Data")
        self.method.append_text("DoD 5220.22-M")
        self.method.append_text("Gutmann (35 pass)")
        self.method.set_active(0)
        method_box.pack_start(self.method, False, False, 0)
        
        self.box.pack_start(method_box, False, False, 0)


class RAMSecurityFrame(ModuleFrame):
    """RAM scrubbing and cold boot protection controls."""
    
    def __init__(self):
        super().__init__("💾 RAM Security", "ram")
        
        # Separator
        self.box.pack_start(Gtk.Separator(), False, False, 4)
        
        # Wipe options
        self.wipe_shutdown = Gtk.CheckButton(label="Wipe RAM on Shutdown")
        self.wipe_shutdown.set_active(True)
        self.box.pack_start(self.wipe_shutdown, False, False, 0)
        
        self.wipe_reboot = Gtk.CheckButton(label="Wipe RAM on Reboot")
        self.wipe_reboot.set_active(True)
        self.box.pack_start(self.wipe_reboot, False, False, 0)
        
        self.wipe_suspend = Gtk.CheckButton(label="Wipe RAM on Suspend")
        self.wipe_suspend.set_active(False)
        self.box.pack_start(self.wipe_suspend, False, False, 0)
        
        # Manual scrub button
        scrub_btn = Gtk.Button(label="🧹 Manual RAM Scrub (Free Memory)")
        scrub_btn.connect("clicked", self.on_scrub)
        self.box.pack_start(scrub_btn, False, False, 8)
        
        # RAM status
        status_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        status_box.pack_start(Gtk.Label(label="Last Scrub:"), False, False, 0)
        self.last_scrub = Gtk.Label(label="Never")
        status_box.pack_start(self.last_scrub, False, False, 0)
        self.box.pack_start(status_box, False, False, 0)
    
    def on_scrub(self, widget):
        try:
            with open(os.path.join(self.module_path, "scrub_now"), "w") as f:
                f.write("1")
            self.last_scrub.set_text("Just now")
        except Exception as e:
            print(f"Error scrubbing RAM: {e}")


class MetadataFrame(ModuleFrame):
    """Metadata scrubbing controls."""
    
    def __init__(self):
        super().__init__("📄 Metadata Scrubbing", "meta")
        
        # Separator
        self.box.pack_start(Gtk.Separator(), False, False, 4)
        
        # Scrub options
        self.scrub_exif = Gtk.CheckButton(label="Scrub EXIF Data (Images)")
        self.scrub_exif.set_active(True)
        self.box.pack_start(self.scrub_exif, False, False, 0)
        
        self.scrub_pdf = Gtk.CheckButton(label="Scrub PDF Metadata")
        self.scrub_pdf.set_active(True)
        self.box.pack_start(self.scrub_pdf, False, False, 0)
        
        self.scrub_office = Gtk.CheckButton(label="Scrub Office Documents")
        self.scrub_office.set_active(True)
        self.box.pack_start(self.scrub_office, False, False, 0)
        
        self.randomize_timestamps = Gtk.CheckButton(label="Randomize File Timestamps")
        self.randomize_timestamps.set_active(False)
        self.box.pack_start(self.randomize_timestamps, False, False, 0)
        
        # Auto-scrub on copy
        self.auto_scrub = Gtk.CheckButton(label="Auto-Scrub on File Copy (scopy)")
        self.auto_scrub.set_active(True)
        self.box.pack_start(self.auto_scrub, False, False, 0)


class EvidenceFrame(ModuleFrame):
    """Evidence preservation and forensic logging controls."""
    
    def __init__(self):
        super().__init__("🔒 Evidence Preservation", "evidence")
        
        # Separator
        self.box.pack_start(Gtk.Separator(), False, False, 4)
        
        # Log stats
        stats_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        stats_box.pack_start(Gtk.Label(label="Log Entries:"), False, False, 0)
        self.entry_count = Gtk.Label(label="0")
        stats_box.pack_start(self.entry_count, False, False, 0)
        self.box.pack_start(stats_box, False, False, 0)
        
        # Chain status
        chain_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        chain_box.pack_start(Gtk.Label(label="Chain Integrity:"), False, False, 0)
        self.chain_status = Gtk.Label()
        self.chain_status.set_markup("<span color='green'>✓ Valid</span>")
        chain_box.pack_start(self.chain_status, False, False, 0)
        self.box.pack_start(chain_box, False, False, 0)
        
        # Verify button
        verify_btn = Gtk.Button(label="🔍 Verify Chain Integrity")
        verify_btn.connect("clicked", self.on_verify)
        self.box.pack_start(verify_btn, False, False, 8)
        
        # Export button
        export_btn = Gtk.Button(label="📤 Export Evidence Log")
        export_btn.connect("clicked", self.on_export)
        self.box.pack_start(export_btn, False, False, 0)
        
        self.refresh_stats()
    
    def refresh_stats(self):
        try:
            with open(os.path.join(self.module_path, "count"), "r") as f:
                self.entry_count.set_text(f.read().strip())
        except:
            pass
    
    def on_verify(self, widget):
        try:
            with open(os.path.join(self.module_path, "verify"), "w") as f:
                f.write("1")
            # Check result
            with open(os.path.join(self.module_path, "stats"), "r") as f:
                stats = f.read()
                if "chain_valid: 1" in stats:
                    self.chain_status.set_markup("<span color='green'>✓ Valid</span>")
                else:
                    self.chain_status.set_markup("<span color='red'>✗ TAMPERED</span>")
        except Exception as e:
            print(f"Error verifying chain: {e}")
    
    def on_export(self, widget):
        dialog = Gtk.FileChooserDialog(
            title="Export Evidence Log",
            action=Gtk.FileChooserAction.SAVE
        )
        dialog.add_buttons(Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
                          Gtk.STOCK_SAVE, Gtk.ResponseType.OK)
        dialog.set_current_name("evidence_log.txt")
        
        if dialog.run() == Gtk.ResponseType.OK:
            filename = dialog.get_filename()
            try:
                with open(os.path.join(self.module_path, "latest"), "r") as f:
                    content = f.read()
                with open(filename, "w") as f:
                    f.write(content)
            except Exception as e:
                print(f"Error exporting: {e}")
        
        dialog.destroy()


class StorageTab(Gtk.Box):
    """Storage tab containing shred, RAM, metadata, and evidence controls."""
    
    def __init__(self):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=15)
        self.set_margin_start(20)
        self.set_margin_end(20)
        self.set_margin_top(20)
        self.set_margin_bottom(20)
        
        # Title
        title = Gtk.Label()
        title.set_markup("<big><b>💾 STORAGE SECURITY</b></big>")
        title.set_halign(Gtk.Align.START)
        self.pack_start(title, False, False, 0)
        
        # Scrolled content
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        
        content_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=15)
        
        # Add module frames
        content_box.pack_start(SecureShredFrame(), False, False, 0)
        content_box.pack_start(RAMSecurityFrame(), False, False, 0)
        content_box.pack_start(MetadataFrame(), False, False, 0)
        content_box.pack_start(EvidenceFrame(), False, False, 0)
        
        scrolled.add(content_box)
        self.pack_start(scrolled, True, True, 0)
