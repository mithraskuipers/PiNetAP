#!/usr/bin/env python3
"""
PiNetAP Network - Core Network Configuration
Contains IP forwarding, NAT, and NetworkManager management
"""

import time
from typing import Optional
from pinetap_core import PiNetAPCore
from pinetap_firewall import PiNetAPFirewall
from pinetap_captiveportal import PiNetAPCaptivePortal


class PiNetAPNetwork(PiNetAPCore):
    """Network configuration and management"""

    def __init__(self):
        super().__init__()
        self.firewall = PiNetAPFirewall()
        self.captive_portal = PiNetAPCaptivePortal()

    def enable_ip_forwarding(self) -> bool:
        """Enable IP forwarding for internet sharing"""
        try:
            self.log("Enabling IP forwarding...")
            ret, _, _ = self.run_command([
                "sysctl", "-w", "net.ipv4.ip_forward=1"
            ], check=False)
            
            if ret == 0:
                self.log("✓ IP forwarding enabled", "SUCCESS")
                return True
            else:
                self.log("Failed to enable IP forwarding", "ERROR")
                return False
                
        except Exception as e:
            self.log(f"Failed to enable IP forwarding: {e}", "ERROR")
            return False

    def disable_ip_forwarding(self) -> bool:
        """Disable IP forwarding for standalone mode"""
        try:
            self.log("Disabling IP forwarding...")
            ret, _, _ = self.run_command([
                "sysctl", "-w", "net.ipv4.ip_forward=0"
            ], check=False)
            
            if ret == 0:
                self.log("✓ IP forwarding disabled", "SUCCESS")
                return True
            else:
                self.log("Failed to disable IP forwarding", "ERROR")
                return False
                
        except Exception as e:
            self.log(f"Failed to disable IP forwarding: {e}", "ERROR")
            return False

    def setup_nat_rules(self, ap_interface: str) -> bool:
        """Setup NAT (masquerading) for internet sharing"""
        return self.firewall.setup_nat_rules(ap_interface)

    def block_forwarding_except_local(self, ap_interface: str) -> bool:
        """Block IP forwarding except for local network (standalone mode)"""
        return self.firewall.block_forwarding_except_local(ap_interface)

    def reload_networkmanager(self, delay: int = 2) -> bool:
        """Reload NetworkManager and wait for it to settle"""
        try:
            self.log("Reloading NetworkManager...")
            
            ret, _, _ = self.run_command([
                "systemctl", "reload", "NetworkManager"
            ], check=False)
            
            if ret != 0:
                self.log("Failed to reload NetworkManager", "WARN")
                return False
            
            if delay > 0:
                self.log(f"Waiting {delay} seconds for NetworkManager to settle...")
                time.sleep(delay)
            
            self.log("✓ NetworkManager reloaded", "SUCCESS")
            return True
            
        except Exception as e:
            self.log(f"Failed to reload NetworkManager: {e}", "ERROR")
            return False

    def configure_captive_portal_dns(self, ap_interface: str, ap_ip: str) -> bool:
        """Configure DNS for captive portal - wrapper for captive portal module"""
        return self.captive_portal.configure_captive_portal_dns(ap_interface, ap_ip)

    def verify_dns_hijacking(self, ap_ip: str) -> bool:
        """Verify DNS hijacking is working"""
        return self.captive_portal.verify_dns_hijacking(ap_ip)

    def verify_captive_portal_working(self, ap_ip: str) -> bool:
        """Verify captive portal HTTP server is responding correctly"""
        return self.captive_portal.verify_captive_portal_working(ap_ip)

    def ensure_dnsmasq_active(self) -> bool:
        """Ensure dnsmasq is running for NetworkManager (needed for captive portal)"""
        return self.captive_portal.ensure_dnsmasq_active()

    def setup_captive_portal(self, ap_interface: str, ap_ip: str, ssid: str) -> bool:
        """Setup captive portal with enhanced detection for auto-popup"""
        return self.captive_portal.setup_captive_portal(ap_interface, ap_ip, ssid)

    def remove_captive_portal(self) -> bool:
        """Remove captive portal files and service"""
        return self.captive_portal.remove_captive_portal()

    def get_captive_portal_status(self) -> dict:
        """Get status of captive portal service"""
        return self.captive_portal.get_captive_portal_status()
