#!/usr/bin/env python3
"""
ShadowOS Alert Daemon
- Listens on netlink for kernel alerts
- Displays desktop notifications
"""

import sys
import os
import socket
import struct
import threading
import time

try:
    import gi
    gi.require_version('Notify', '0.7')
    from gi.repository import Notify, GLib
except ImportError:
    print("Warning: gi.repository or Notify not found. Notifications disabled.")
    Notify = None

# Constants
NETLINK_GENERIC = 16
SHADOW_GENL_NAME = "shadowos"
SHADOW_MCGRP_NAME = "events"

class ShadowAlertd:
    def __init__(self):
        self.running = True
        self.sock = None
        if Notify:
            try:
                Notify.init("ShadowOS")
            except Exception as e:
                print(f"Failed to init Notify: {e}")
                
    def create_socket(self):
        try:
            # Create netlink socket
            self.sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_GENERIC)
            self.sock.bind((os.getpid(), 0))
            print("Netlink socket created")
            return True
        except Exception as e:
            print(f"Failed to create netlink socket: {e}")
            return False

    def listen(self):
        if not self.create_socket():
            return

        print("ShadowOS Alert Daemon Listening...")
        while self.running:
            try:
                data = self.sock.recv(4096)
                self.handle_msg(data)
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"Error receiving: {e}")
                time.sleep(1)

    def handle_msg(self, data):
        # Parse netlink message (Simplified for prototype)
        # Real implementation needs proper Genl parsing
        # For now we simulate alert reception
        print(f"Received {len(data)} bytes")
        
        # Trigger notification
        self.show_notification("Security Alert", "Suspicious activity detected")

    def show_notification(self, title, message):
        if not Notify:
            print(f"[ALERT] {title}: {message}")
            return
            
        try:
            notification = Notify.Notification.new(
                title,
                message,
                "security-high"
            )
            notification.show()
        except Exception as e:
            print(f"Failed to show notification: {e}")

if __name__ == "__main__":
    daemon = ShadowAlertd()
    daemon.listen()
