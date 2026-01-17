#!/usr/bin/env python3
"""
ShadowOS Control Center - Hardware Tab
USB Firewall, Camera/Mic Kill, Bluetooth, DMA Protection
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


class USBFirewallFrame(ModuleFrame):
    """USB Firewall controls with device class blocking."""
    
    def __init__(self):
        super().__init__("🔌 USB Firewall", "usb")
        
        # Separator
        self.box.pack_start(Gtk.Separator(), False, False, 4)
        
        # Block options
        self.block_storage = Gtk.CheckButton(label="Block Mass Storage")
        self.block_storage.set_active(True)
        self.block_storage.connect("toggled", self.on_storage_toggle)
        self.box.pack_start(self.block_storage, False, False, 0)
        
        self.block_hid = Gtk.CheckButton(label="Block New HID (BadUSB Protection)")
        self.block_hid.set_active(True)
        self.block_hid.connect("toggled", self.on_hid_toggle)
        self.box.pack_start(self.block_hid, False, False, 0)
        
        self.log_connections = Gtk.CheckButton(label="Log All Connections")
        self.log_connections.set_active(True)
        self.box.pack_start(self.log_connections, False, False, 0)
        
        # Whitelist entry
        whitelist_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=5)
        whitelist_box.pack_start(Gtk.Label(label="Whitelist (VID:PID):"), False, False, 0)
        self.whitelist_entry = Gtk.Entry()
        self.whitelist_entry.set_placeholder_text("e.g. 046d:c52b")
        whitelist_box.pack_start(self.whitelist_entry, True, True, 0)
        
        add_btn = Gtk.Button(label="Add")
        add_btn.connect("clicked", self.on_add_whitelist)
        whitelist_box.pack_start(add_btn, False, False, 0)
        
        self.box.pack_start(whitelist_box, False, False, 0)
    
    def on_storage_toggle(self, widget):
        try:
            with open(os.path.join(self.module_path, "block_storage"), "w") as f:
                f.write("1" if widget.get_active() else "0")
        except:
            pass
    
    def on_hid_toggle(self, widget):
        try:
            with open(os.path.join(self.module_path, "block_new_hid"), "w") as f:
                f.write("1" if widget.get_active() else "0")
        except:
            pass
    
    def on_add_whitelist(self, widget):
        vid_pid = self.whitelist_entry.get_text().strip()
        if vid_pid:
            try:
                with open(os.path.join(self.module_path, "whitelist"), "w") as f:
                    f.write(vid_pid)
                self.whitelist_entry.set_text("")
            except Exception as e:
                print(f"Error adding to whitelist: {e}")


class AudioVideoFrame(ModuleFrame):
    """Camera and Microphone kill switches."""
    
    def __init__(self):
        super().__init__("📷 Audio/Video Kill Switch", "av")
        
        # Separator
        self.box.pack_start(Gtk.Separator(), False, False, 4)
        
        # Individual kill switches
        camera_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        camera_box.pack_start(Gtk.Label(label="📷 Camera:"), False, False, 0)
        self.camera_switch = Gtk.Switch()
        self.camera_switch.set_active(False)  # Off = camera enabled
        self.camera_switch.connect("state-set", self.on_camera_toggle)
        camera_box.pack_end(self.camera_switch, False, False, 0)
        camera_box.pack_end(Gtk.Label(label="Kill"), False, False, 0)
        self.box.pack_start(camera_box, False, False, 0)
        
        mic_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        mic_box.pack_start(Gtk.Label(label="🎤 Microphone:"), False, False, 0)
        self.mic_switch = Gtk.Switch()
        self.mic_switch.set_active(False)
        self.mic_switch.connect("state-set", self.on_mic_toggle)
        mic_box.pack_end(self.mic_switch, False, False, 0)
        mic_box.pack_end(Gtk.Label(label="Kill"), False, False, 0)
        self.box.pack_start(mic_box, False, False, 0)
        
        # Kill All button
        kill_all_btn = Gtk.Button(label="🔇 KILL ALL (Camera + Mic)")
        kill_all_btn.get_style_context().add_class("destructive-action")
        kill_all_btn.connect("clicked", self.on_kill_all)
        self.box.pack_start(kill_all_btn, False, False, 8)
    
    def on_camera_toggle(self, switch, state):
        try:
            with open(os.path.join(self.module_path, "camera_kill"), "w") as f:
                f.write("1" if state else "0")
        except:
            pass
        return False
    
    def on_mic_toggle(self, switch, state):
        try:
            with open(os.path.join(self.module_path, "mic_kill"), "w") as f:
                f.write("1" if state else "0")
        except:
            pass
        return False
    
    def on_kill_all(self, widget):
        self.camera_switch.set_active(True)
        self.mic_switch.set_active(True)


class BluetoothFrame(ModuleFrame):
    """Bluetooth control and kill switch."""
    
    def __init__(self):
        super().__init__("📶 Bluetooth Control", "bluetooth")
        
        # Separator
        self.box.pack_start(Gtk.Separator(), False, False, 4)
        
        # Block all switch
        block_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        block_box.pack_start(Gtk.Label(label="Block All Connections:"), False, False, 0)
        self.block_switch = Gtk.Switch()
        self.block_switch.set_active(True)
        self.block_switch.connect("state-set", self.on_block_toggle)
        block_box.pack_end(self.block_switch, False, False, 0)
        self.box.pack_start(block_box, False, False, 0)
        
        # Kill button
        kill_btn = Gtk.Button(label="📶 KILL Bluetooth Radio")
        kill_btn.get_style_context().add_class("destructive-action")
        kill_btn.connect("clicked", self.on_kill)
        self.box.pack_start(kill_btn, False, False, 8)
    
    def on_block_toggle(self, switch, state):
        try:
            with open(os.path.join(self.module_path, "block_all"), "w") as f:
                f.write("1" if state else "0")
        except:
            pass
        return False
    
    def on_kill(self, widget):
        try:
            with open(os.path.join(self.module_path, "kill"), "w") as f:
                f.write("1")
        except:
            pass


class DMAProtectionFrame(ModuleFrame):
    """DMA Attack protection controls."""
    
    def __init__(self):
        super().__init__("⚡ DMA Attack Protection", "dma")
        
        # Separator
        self.box.pack_start(Gtk.Separator(), False, False, 4)
        
        # Block options
        self.block_thunderbolt = Gtk.CheckButton(label="Block Thunderbolt")
        self.block_thunderbolt.set_active(True)
        self.block_thunderbolt.connect("toggled", self.on_thunderbolt_toggle)
        self.box.pack_start(self.block_thunderbolt, False, False, 0)
        
        self.block_firewire = Gtk.CheckButton(label="Block FireWire")
        self.block_firewire.set_active(True)
        self.block_firewire.connect("toggled", self.on_firewire_toggle)
        self.box.pack_start(self.block_firewire, False, False, 0)
        
        self.block_pcie = Gtk.CheckButton(label="Block PCIe Hotplug")
        self.block_pcie.set_active(True)
        self.box.pack_start(self.block_pcie, False, False, 0)
        
        # IOMMU status
        iommu_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        iommu_box.pack_start(Gtk.Label(label="IOMMU Status:"), False, False, 0)
        self.iommu_label = Gtk.Label(label="Checking...")
        iommu_box.pack_start(self.iommu_label, False, False, 0)
        self.box.pack_start(iommu_box, False, False, 0)
        
        self.check_iommu()
    
    def check_iommu(self):
        try:
            with open("/sys/kernel/iommu_groups/0/type", "r") as f:
                self.iommu_label.set_markup("<b>✓ Enabled</b>")
        except:
            self.iommu_label.set_markup("<span color='red'>✗ Not Enabled</span>")
    
    def on_thunderbolt_toggle(self, widget):
        try:
            with open(os.path.join(self.module_path, "block_thunderbolt"), "w") as f:
                f.write("1" if widget.get_active() else "0")
        except:
            pass
    
    def on_firewire_toggle(self, widget):
        try:
            with open(os.path.join(self.module_path, "block_firewire"), "w") as f:
                f.write("1" if widget.get_active() else "0")
        except:
            pass


class HardwareTab(Gtk.Box):
    """Hardware tab containing USB, A/V, Bluetooth, and DMA controls."""
    
    def __init__(self):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=15)
        self.set_margin_start(20)
        self.set_margin_end(20)
        self.set_margin_top(20)
        self.set_margin_bottom(20)
        
        # Title
        title = Gtk.Label()
        title.set_markup("<big><b>🔌 HARDWARE CONTROL</b></big>")
        title.set_halign(Gtk.Align.START)
        self.pack_start(title, False, False, 0)
        
        # Scrolled content
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        
        content_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=15)
        
        # Add module frames
        content_box.pack_start(USBFirewallFrame(), False, False, 0)
        content_box.pack_start(AudioVideoFrame(), False, False, 0)
        content_box.pack_start(BluetoothFrame(), False, False, 0)
        content_box.pack_start(DMAProtectionFrame(), False, False, 0)
        
        scrolled.add(content_box)
        self.pack_start(scrolled, True, True, 0)
