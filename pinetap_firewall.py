#!/usr/bin/env python3
"""
PiNetAP Firewall - iptables and Firewall Management
Contains all iptables rules for NAT, forwarding, and captive portal interception
"""

from typing import Optional
from pathlib import Path
from pinetap_core import PiNetAPCore


class PiNetAPFirewall(PiNetAPCore):
    """Firewall and iptables management"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def setup_nat_rules(self, ap_interface: str, internet_interface: Optional[str] = None) -> bool:
        """Setup NAT (masquerading) for internet sharing
        
        Args:
            ap_interface: The AP interface (incoming traffic)
            internet_interface: The internet interface (outgoing traffic). If None, auto-detect.
        """
        try:
            # Auto-detect internet interface if not specified
            if not internet_interface:
                self.log("Auto-detecting internet interface...", "DEBUG")
                
                # Method 1: Try to find default route interface
                ret, stdout, _ = self.run_command(["ip", "route", "show", "default"], check=False)
                if ret == 0 and stdout:
                    self.log(f"Default route: {stdout.strip()}", "DEBUG")
                    # Parse: "default via 192.168.1.1 dev eth0 ..." or "default via ... dev wlan0 proto dhcp ..."
                    for word_idx, word in enumerate(stdout.split()):
                        if word == "dev" and word_idx + 1 < len(stdout.split()):
                            internet_interface = stdout.split()[word_idx + 1]
                            break
                
                # Method 2: If still not found, look for any interface with a default route that's not the AP
                if not internet_interface:
                    self.log("Trying alternative detection method...", "DEBUG")
                    ret, stdout, _ = self.run_command(["ip", "route"], check=False)
                    if ret == 0:
                        for line in stdout.split('\n'):
                            if 'default' in line and ap_interface not in line:
                                parts = line.split()
                                if 'dev' in parts:
                                    internet_interface = parts[parts.index('dev') + 1]
                                    break
                
                if internet_interface and internet_interface != ap_interface:
                    self.log(f"✓ Auto-detected internet interface: {internet_interface}", "SUCCESS")
                else:
                    self.log("Could not auto-detect internet interface", "WARN")
                    self.log("Will use generic NAT rules (may not work without explicit internet source)", "WARN")
                    
                    # Set up generic masquerading without specific interface
                    ret, _, _ = self.run_command([
                        "iptables", "-t", "nat", "-A", "POSTROUTING",
                        "-s", "192.168.0.0/16",
                        "!", "-d", "192.168.0.0/16",
                        "-j", "MASQUERADE"
                    ], check=False)
                    
                    if ret == 0:
                        self.log("✓ Generic NAT rules configured", "SUCCESS")
                        self.log("⚠️ If internet sharing doesn't work, specify --uplink-interface", "WARN")
                        return True
                    else:
                        self.log("Failed to setup NAT rules", "ERROR")
                        return False
            
            self.log(f"Setting up NAT: {ap_interface} (AP) → {internet_interface} (Internet)...")
            
            # CORRECT: Masquerade traffic going OUT through the internet interface
            ret, _, stderr = self.run_command([
                "iptables", "-t", "nat", "-A", "POSTROUTING",
                "-o", internet_interface,  # OUT through internet interface
                "-j", "MASQUERADE"
            ], check=False)
            
            if ret == 0:
                self.log(f"✓ NAT rules configured: traffic from AP will exit via {internet_interface}", "SUCCESS")
                
                # Verify the rule was added
                ret2, stdout2, _ = self.run_command([
                    "iptables", "-t", "nat", "-L", "POSTROUTING", "-n", "-v"
                ], check=False)
                if ret2 == 0 and internet_interface in stdout2:
                    self.log(f"✓ NAT rule verified in iptables", "DEBUG")
                
                return True
            else:
                self.log(f"Failed to setup NAT rules: {stderr}", "ERROR")
                return False
                
        except Exception as e:
            self.log(f"Failed to setup NAT: {e}", "ERROR")
            import traceback
            self.log(traceback.format_exc(), "DEBUG")
            return False

    def allow_forwarding(self, ap_interface: str, internet_interface: Optional[str] = None) -> bool:
        """Allow forwarding for internet sharing"""
        try:
            self.log(f"Setting up forwarding rules for internet sharing...", "DEBUG")
            
            # Flush FORWARD chain first for clean slate
            self.run_command([
                "iptables", "-F", "FORWARD"
            ], check=False)
            
            # Allow established connections
            self.run_command([
                "iptables", "-A", "FORWARD",
                "-m", "state", "--state", "RELATED,ESTABLISHED",
                "-j", "ACCEPT"
            ], check=False)
            
            # Allow traffic from AP interface
            self.run_command([
                "iptables", "-A", "FORWARD",
                "-i", ap_interface,
                "-j", "ACCEPT"
            ], check=False)
            
            # If we know the internet interface, allow traffic to it specifically
            if internet_interface:
                self.run_command([
                    "iptables", "-A", "FORWARD",
                    "-o", internet_interface,
                    "-j", "ACCEPT"
                ], check=False)
                self.log(f"✓ Forwarding enabled: {ap_interface} ↔ {internet_interface}", "SUCCESS")
            else:
                # Otherwise allow all forwarding
                self.run_command([
                    "iptables", "-P", "FORWARD", "ACCEPT"
                ], check=False)
                self.log(f"✓ Forwarding enabled: {ap_interface} ↔ all interfaces", "SUCCESS")
            
            return True
            
        except Exception as e:
            self.log(f"Failed to setup forwarding rules: {e}", "ERROR")
            return False

    def block_forwarding_except_local(self, ap_interface: str) -> bool:
        """Block IP forwarding except for local network (standalone mode)"""
        try:
            self.log(f"Blocking forwarding for {ap_interface} (standalone mode)...")
            
            # Flush FORWARD chain first
            self.run_command([
                "iptables", "-F", "FORWARD"
            ], check=False)
            
            # Allow local network traffic on the AP interface
            self.run_command([
                "iptables", "-A", "FORWARD",
                "-i", ap_interface,
                "-d", "192.168.0.0/16",
                "-j", "ACCEPT"
            ], check=False)
            
            self.run_command([
                "iptables", "-A", "FORWARD",
                "-o", ap_interface,
                "-s", "192.168.0.0/16",
                "-j", "ACCEPT"
            ], check=False)
            
            # Drop everything else (no internet forwarding)
            self.run_command([
                "iptables", "-A", "FORWARD",
                "-i", ap_interface,
                "-j", "DROP"
            ], check=False)
            
            self.log("✓ Firewall configured for standalone mode", "SUCCESS")
            return True
            
        except Exception as e:
            self.log(f"Failed to block forwarding: {e}", "ERROR")
            return False

    def setup_captive_portal_iptables(self, ap_interface: str, ap_ip: str, skip_http_redirect: bool = False) -> bool:
        """Setup iptables rules ONLY for the AP interface to intercept HTTP traffic
        
        Args:
            ap_interface: The AP interface
            ap_ip: The AP IP address
            skip_http_redirect: If True, don't redirect HTTP/HTTPS (for internet sharing mode)
        """
        try:
            if skip_http_redirect:
                self.log(f"Skipping HTTP redirect (internet sharing mode) for {ap_interface}", "INFO")
                return True
                
            self.log(f"Setting up HTTP/HTTPS interception for {ap_interface}...")
            
            ret, _, _ = self.run_command(["which", "iptables"], check=False)
            if ret != 0:
                self.log("iptables not found", "WARN")
                return False
            
            # CRITICAL: Flush existing NAT PREROUTING rules for clean slate
            self.log("Flushing NAT PREROUTING rules...")
            self.run_command([
                "iptables", "-t", "nat", "-F", "PREROUTING"
            ], check=False)
            
            # Rule 1: FIRST, allow direct access to portal IP (most important!)
            ret, _, _ = self.run_command([
                "iptables", "-t", "nat", "-A", "PREROUTING",
                "-i", ap_interface, 
                "-d", ap_ip,
                "-j", "ACCEPT"
            ], check=False)
            
            if ret == 0:
                self.log(f"✓ Rule 1: Direct portal access ({ap_ip}) allowed")
            
            # Rule 2: Redirect HTTP (port 80) to portal
            ret, _, stderr = self.run_command([
                "iptables", "-t", "nat", "-A", "PREROUTING",
                "-i", ap_interface, 
                "-p", "tcp", 
                "--dport", "80",
                "!", "-d", ap_ip,  # Don't redirect if already going to portal
                "-j", "DNAT", 
                "--to-destination", f"{ap_ip}:80"
            ], check=False)
            
            if ret == 0:
                self.log(f"✓ Rule 2: HTTP (80) redirect active → {ap_ip}:80")
            else:
                self.log(f"Failed to add HTTP redirect: {stderr}", "ERROR")
                return False
            
            # Rule 3: Redirect HTTPS (port 443) to portal (will show cert error)
            ret, _, _ = self.run_command([
                "iptables", "-t", "nat", "-A", "PREROUTING",
                "-i", ap_interface, 
                "-p", "tcp", 
                "--dport", "443",
                "!", "-d", ap_ip,
                "-j", "DNAT", 
                "--to-destination", f"{ap_ip}:80"
            ], check=False)
            
            if ret == 0:
                self.log(f"✓ Rule 3: HTTPS (443) redirect active → {ap_ip}:80")
            else:
                self.log(f"Warning: Could not redirect HTTPS", "WARN")
            
            # Allow INPUT to portal web server
            self.run_command([
                "iptables", "-A", "INPUT",
                "-i", ap_interface, 
                "-p", "tcp", 
                "--dport", "80",
                "-j", "ACCEPT"
            ], check=False)
            
            self.log("✓ HTTP interception configured", "SUCCESS")
            
            # Display current rules for verification
            self.log("\n📋 Current NAT PREROUTING rules:", "INFO")
            ret, stdout, _ = self.run_command([
                "iptables", "-t", "nat", "-L", "PREROUTING", "-n", "-v", "--line-numbers"
            ], check=False)
            
            if ret == 0:
                for line in stdout.split('\n')[:10]:  # First 10 lines
                    if ap_interface in line or ap_ip in line or "pkts" in line or "Chain" in line:
                        self.log(f"  {line}", "INFO")
            
            self.save_iptables_rules()
            return True
            
        except Exception as e:
            self.log(f"Failed to setup iptables: {e}", "ERROR")
            import traceback
            self.log(traceback.format_exc(), "ERROR")
            return False

    def remove_captive_portal_iptables(self) -> bool:
        """Remove captive portal iptables rules"""
        try:
            self.log("Removing captive portal iptables rules...")
            
            # Flush NAT PREROUTING rules
            ret, _, _ = self.run_command([
                "iptables", "-t", "nat", "-F", "PREROUTING"
            ], check=False)
            
            if ret == 0:
                self.log("✓ NAT PREROUTING rules flushed", "SUCCESS")
            
            # Flush NAT POSTROUTING rules
            self.run_command([
                "iptables", "-t", "nat", "-F", "POSTROUTING"
            ], check=False)
            
            # Flush INPUT chain rules related to captive portal
            self.run_command([
                "iptables", "-F", "INPUT"
            ], check=False)
            
            self.log("✓ Captive portal iptables rules removed", "SUCCESS")
            return True
            
        except Exception as e:
            self.log(f"Failed to remove iptables rules: {e}", "ERROR")
            return False

    def save_iptables_rules(self) -> bool:
        """Save iptables rules to persist across reboots"""
        try:
            ret, _, _ = self.run_command(["which", "iptables-save"], check=False)
            if ret != 0:
                return False
            
            rules_file = Path("/etc/pinetap/iptables-captive.rules")
            self.PINETAP_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            
            ret, stdout, _ = self.run_command(["iptables-save"], check=False)
            if ret == 0 and stdout:
                rules_file.write_text(stdout)
                self.log(f"Saved iptables rules to {rules_file}")
            
            return True
        except Exception as e:
            self.log(f"Failed to save iptables rules: {e}", "WARN")
            return False

    def restore_iptables_rules(self) -> bool:
        """Restore saved iptables rules"""
        try:
            rules_file = Path("/etc/pinetap/iptables-captive.rules")
            if not rules_file.exists():
                self.log("No saved iptables rules found", "WARN")
                return False
            
            ret, _, _ = self.run_command(["which", "iptables-restore"], check=False)
            if ret != 0:
                return False
            
            ret, _, _ = self.run_command([
                "iptables-restore", "<", str(rules_file)
            ], check=False)
            
            if ret == 0:
                self.log("✓ iptables rules restored", "SUCCESS")
                return True
            else:
                self.log("Failed to restore iptables rules", "ERROR")
                return False
                
        except Exception as e:
            self.log(f"Failed to restore iptables rules: {e}", "ERROR")
            return False
