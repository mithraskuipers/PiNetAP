"""
PiNetAP - Access Point Management
Core AP creation, configuration, and removal logic
"""

import time
import json
from typing import Optional, Tuple, List, Dict
from pathlib import Path

from pinetap_core import SecurityMode
from pinetap_network import PiNetAPNetwork
from pinetap_diagnostics import PiNetAPDiagnostics


class PiNetAPManager(PiNetAPDiagnostics):
    """Main PiNetAP class with AP management capabilities"""

    def save_original_system_state(self) -> bool:
        """Save current system state before making changes"""
        try:
            self.log("Saving original system state...")

            # Save current IP forwarding setting
            try:
                with open("/proc/sys/net/ipv4/ip_forward", "r") as f:
                    self._original_ip_forward = f.read().strip()
                self.log(f"Saved IP forwarding state: {self._original_ip_forward}")
            except Exception as e:
                self.log(f"Could not read IP forwarding state: {e}", "WARN")
                self._original_ip_forward = "0"  # Default to disabled

            # Save current iptables rules
            rules_file = Path("/etc/pinetap/iptables-original.rules")
            self.PINETAP_CONFIG_DIR.mkdir(parents=True, exist_ok=True)

            ret, stdout, _ = self.run_command(["iptables-save"], check=False)
            if ret == 0 and stdout:
                rules_file.write_text(stdout)
                self.log(f"Saved original iptables rules to {rules_file}")
            else:
                self.log("Could not save iptables rules", "WARN")

            self.log("✓ Original system state saved", "SUCCESS")
            return True

        except Exception as e:
            self.log(f"Failed to save system state: {e}", "WARN")
            return False

    def restore_original_system_state(self) -> bool:
        """Restore original system state (IP forwarding, firewall rules, etc.)"""
        try:
            self.log("Restoring original system state...")

            # Restore IP forwarding
            if hasattr(self, '_original_ip_forward'):
                self.log(f"Restoring IP forwarding to: {self._original_ip_forward}")
                ret, _, _ = self.run_command([
                    "sysctl", "-w", f"net.ipv4.ip_forward={self._original_ip_forward}"
                ], check=False)
                if ret == 0:
                    self.log("✓ IP forwarding restored", "SUCCESS")

            # Remove captive portal iptables rules
            self.firewall.remove_captive_portal_iptables()

            # Flush custom iptables rules (be careful not to break system)
            self.log("Cleaning up iptables rules...")

            # Remove NAT rules for AP interfaces
            self.run_command([
                "iptables", "-t", "nat", "-F", "PREROUTING"
            ], check=False)

            self.run_command([
                "iptables", "-t", "nat", "-F", "POSTROUTING"
            ], check=False)

            # Reload saved iptables if available
            rules_file = Path("/etc/pinetap/iptables-original.rules")
            if rules_file.exists():
                self.log(f"Restoring original iptables from {rules_file}")
                self.run_command([
                    "iptables-restore", str(rules_file)
                ], check=False)

            self.log("✓ Original system state restored", "SUCCESS")
            return True

        except Exception as e:
            self.log(f"Failed to restore system state: {e}", "WARN")
            return False

    def check_interface_available(self, interface: str, for_ap: bool = True,
                                 allow_reconnect: bool = False) -> Tuple[bool, str, Optional[str]]:
        """Check if interface is available for use"""
        interfaces = self.get_available_interfaces()

        if interface not in interfaces:
            return False, f"Interface {interface} not found", None

        if interfaces[interface]['type'] != 'wifi':
            if for_ap:
                return False, f"Interface {interface} is not a WiFi interface", None

        current_conn = self.get_interface_connection(interface)
        if current_conn and for_ap:
            if allow_reconnect:
                return True, f"Interface {interface} has existing connection: {current_conn} (will be replaced)", current_conn
            return False, f"Interface {interface} is already in use by connection: {current_conn}", current_conn

        return True, "Available", None

    def connect_to_uplink(self, uplink_ssid: str, uplink_password: Optional[str],
                         uplink_interface: str, autoconnect: bool = True) -> bool:
        self.log(f"Connecting to uplink network: {uplink_ssid} on {uplink_interface}")

        available, msg, existing_conn = self.check_interface_available(uplink_interface, for_ap=False, allow_reconnect=True)
        if not available and "already in use" not in msg:
            self.log(f"Uplink interface check: {msg}", "WARN")

        uplink_mac = self.get_interface_mac(uplink_interface)
        if uplink_mac:
            self.log(f"Binding uplink to MAC address: {uplink_mac}")

        conn_name = f"[PiNetAP] {uplink_ssid}-Uplink"

        if self.connection_exists(conn_name):
            self.log(f"Removing existing uplink connection: {conn_name}")
            self.delete_connection(conn_name)

        cmd = [
            "nmcli", "dev", "wifi", "connect", uplink_ssid,
            "ifname", uplink_interface
        ]

        if uplink_password:
            cmd.extend(["password", uplink_password])

        cmd.extend(["name", conn_name])

        ret, stdout, stderr = self.run_command(cmd, check=False)
        if ret != 0:
            self.log(f"Failed to connect to uplink: {stderr}", "ERROR")
            return False

        if uplink_mac:
            self.run_command([
                "nmcli", "con", "modify", conn_name,
                "wifi.mac-address", uplink_mac
            ], check=False)
            self.log(f"Bound uplink connection to MAC: {uplink_mac}")

        if autoconnect:
            self.log("Configuring uplink for autoconnect...")
            self.run_command([
                "nmcli", "con", "modify", conn_name,
                "connection.autoconnect", "yes",
                "connection.autoconnect-priority", "10"
            ], check=False)

        self.log(f"Connected to uplink network: {uplink_ssid}", "SUCCESS")
        return True

    def create_ap(
        self,
        ssid: str,
        password: Optional[str],
        ap_interface: str,
        ip_address: str,
        channel: int,
        mac_address: Optional[str],
        autoconnect: bool,
        con_name: Optional[str],
        share_internet: bool = True,
        internet_interface: Optional[str] = None,
        security_mode: SecurityMode = SecurityMode.WPA2_PSK,
        captive_portal: bool = False,
        portal_services: Optional[List[Dict]] = None,
        services_file: Optional[str] = None
    ) -> bool:
        available, msg, existing_conn = self.check_interface_available(ap_interface, for_ap=True, allow_reconnect=True)

        if not available and existing_conn:
            self.log(f"Interface {ap_interface} is currently used by connection: {existing_conn}", "WARN")
            self.log(f"Removing existing connection to free up the interface...")

            self.run_command(["nmcli", "con", "down", existing_conn], check=False)
            if not self.delete_connection(existing_conn):
                self.log(f"Failed to remove existing connection", "ERROR")
                return False

            time.sleep(2)
            self.log(f"Interface {ap_interface} is now available")
        elif not available:
            self.log(f"Cannot use {ap_interface}: {msg}", "ERROR")
            return False

        ap_mac = self.get_interface_mac(ap_interface)
        if not ap_mac:
            self.log(f"Warning: Could not determine MAC address for {ap_interface}", "WARN")
        else:
            self.log(f"AP Interface MAC address: {ap_mac}")

        if not con_name:
            con_name = f"[PiNetAP] {ssid}-AP"

        if self.connection_exists(con_name):
            self.log(f"Removing existing connection '{con_name}' to recreate it")
            self.delete_connection(con_name)

        self.log(f"Creating access point: {ssid} on {ap_interface}")
        self.log(f"⚠️ IMPORTANT: Connection will be bound to MAC {ap_mac}", "INFO")

        # Configure system settings based on internet sharing mode
        if share_internet:
            self.log("=" * 60, "INFO")
            self.log("CONFIGURING INTERNET SHARING", "INFO")
            self.log("=" * 60, "INFO")
            self.log(f"AP Interface: {ap_interface}", "INFO")
            self.log(f"Internet Interface: {internet_interface if internet_interface else 'Auto-detect'}", "INFO")
            
            self.enable_ip_forwarding()
            # CRITICAL: Use 'manual' instead of 'shared' to prevent NetworkManager from
            # creating its own dnsmasq that conflicts with our standalone dnsmasq
            ipv4_method = "manual"
            
            # Setup NAT rules
            if not self.setup_nat_rules(ap_interface, internet_interface):
                self.log("⚠️ NAT setup failed - internet sharing may not work!", "ERROR")
            
            # Setup FORWARD chain rules (CRITICAL!)
            if not self.allow_forwarding(ap_interface, internet_interface):
                self.log("⚠️ Forwarding setup failed - internet sharing may not work!", "ERROR")
            
            self.log("=" * 60, "INFO")
        else:
            # For standalone mode: disable forwarding and block forwarding
            self.disable_ip_forwarding()
            self.block_forwarding_except_local(ap_interface)
            # Use 'manual' method - standalone dnsmasq will provide DHCP
            ipv4_method = "manual"
            self.log("Configuring for standalone mode (no internet, local network only)", "INFO")

        cmd = [
            "nmcli", "con", "add",
            "type", "wifi",
            "ifname", ap_interface,
            "mode", "ap",
            "con-name", con_name,
            "ssid", ssid,
            "autoconnect", "yes" if autoconnect else "no"
        ]

        ret, _, stderr = self.run_command(cmd, check=False)
        if ret != 0:
            self.log(f"Failed to create connection: {stderr}", "ERROR")
            return False

        modifications = [
            (["wifi.band", "bg"], "Set band to 2.4GHz"),
            (["wifi.channel", str(channel)], f"Set channel to {channel}"),
            (["wifi.ssid", ssid], f"Explicitly set SSID to {ssid}"),
            (["ipv4.addresses", ip_address], f"Set IP to {ip_address}"),  # Set addresses FIRST
            (["ipv4.method", ipv4_method], f"Set IPv4 method to {ipv4_method}"),  # Then set method
            (["ipv6.method", "disabled"], "Disable IPv6"),
            (["wifi.hidden", "false"], "Ensure SSID is broadcast"),
        ]

        if ap_mac:
            modifications.append(
                (["wifi.mac-address", ap_mac], f"Bind to MAC {ap_mac}")
            )

        if autoconnect:
            modifications.append(
                (["connection.autoconnect-priority", "5"], "Set autoconnect priority")
            )

        if mac_address:
            modifications.append(
                (["wifi.cloned-mac-address", mac_address], f"Set cloned MAC to {mac_address}")
            )

        if security_mode == SecurityMode.OPEN:
            modifications.append(
                (["wifi-sec.key-mgmt", "none"], "Set open network")
            )
        elif security_mode == SecurityMode.WPA2_PSK:
            modifications.extend([
                (["wifi-sec.key-mgmt", "wpa-psk"], "Set WPA-PSK security"),
                (["wifi-sec.proto", "rsn"], "Set WPA2 protocol"),
                (["wifi-sec.pairwise", "ccmp"], "Set AES-CCMP encryption"),
                (["wifi-sec.group", "ccmp"], "Set group AES-CCMP"),
                (["wifi-sec.psk", password], "Set password"),
            ])
        elif security_mode == SecurityMode.WPA3_SAE:
            modifications.extend([
                (["wifi-sec.key-mgmt", "sae"], "Set WPA3-SAE security"),
                (["wifi-sec.psk", password], "Set password"),
            ])

        if not share_internet:
            modifications.extend([
                (["ipv4.route-metric", "9999"], "Set high route metric"),
                (["ipv4.never-default", "yes"], "Never make default route"),
                (["ipv4.may-fail", "no"], "Connection should succeed"),
            ])

        for args, description in modifications:
            cmd = ["nmcli", "con", "modify", con_name] + args
            ret, _, stderr = self.run_command(cmd, check=False)
            if ret != 0:
                self.log(f"Warning: {description} failed: {stderr}", "WARN")
            elif self.verbose:
                self.log(f"✓ {description}", "DEBUG")

        self.log("Ensuring interface is ready...")
        self.run_command(["nmcli", "device", "set", ap_interface, "managed", "yes"], check=False)
        time.sleep(1)

        self.log("Activating access point...")
        ret, stdout, stderr = self.run_command(
            ["nmcli", "con", "up", con_name],
            check=False
        )

        if ret != 0:
            self.log(f"Failed to activate AP: {stderr}", "ERROR")
            return False

        time.sleep(2)

        # Re-apply firewall rules after NetworkManager starts the connection
        # NetworkManager may clear/modify iptables rules, so we need to reapply them
        if share_internet:
            self.log("Re-applying firewall rules for internet sharing...", "DEBUG")
            # Re-enable IP forwarding (NetworkManager might have changed it)
            self.enable_ip_forwarding()
            # Re-apply NAT rules
            self.setup_nat_rules(ap_interface, internet_interface)
            # Re-apply FORWARD rules
            self.allow_forwarding(ap_interface, internet_interface)
            self.log("✓ Firewall rules re-applied after NetworkManager activation", "SUCCESS")
        else:
            self.log("Re-applying firewall rules to prevent internet sharing...")
            self.block_forwarding_except_local(ap_interface)

        ret, stdout, _ = self.run_command(["nmcli", "con", "show", "--active"], check=False)
        if ret == 0 and con_name in stdout:
            autoconnect_msg = " (will reconnect on reboot)" if autoconnect else ""
            sharing_msg = " with internet sharing" if share_internet else " (standalone, local only)"
            self.log(f"✓ Access point '{ssid}' created on {ap_interface}{sharing_msg}{autoconnect_msg}!", "SUCCESS")

            self.log("\nAP Configuration:", "INFO")
            self.log(f"  SSID: {ssid}", "INFO")
            self.log(f"  Interface: {ap_interface} (MAC: {ap_mac})", "INFO")
            self.log(f"  IP Address: {ip_address.split('/')[0]}", "INFO")
            self.log(f"  Channel: {channel}", "INFO")
            self.log(f"  Security: {security_mode.value}", "INFO")
            if not share_internet:
                self.log(f"  Mode: Standalone (no internet)", "INFO")
            else:
                self.log(f"  Mode: Internet Sharing Enabled", "INFO")

            self.save_managed_connection(con_name, ap_interface, ssid, security_mode.value, share_internet, captive_portal)

            # CRITICAL FIX: Setup captive portal AFTER AP is fully active
            if captive_portal:
                self.log("\n📱 Setting up captive portal...", "INFO")

                # Step 1: Setup portal web server and standalone DNS
                # NOTE: We no longer need to restart NetworkManager because we use standalone dnsmasq
                self.log("Step 1/2: Starting captive portal with standalone DNS...")
                if self.setup_captive_portal(
                    ip_address.split('/')[0], 
                    ssid, 
                    ap_interface, 
                    portal_services,
                    services_file=services_file,
                    share_internet=share_internet
                ):
                    self.log("✓ Captive portal web server active!", "SUCCESS")
                    
                    # Step 2: Verify standalone dnsmasq is running
                    self.log("Step 2/2: Verifying standalone dnsmasq...")
                    if not self.ensure_dnsmasq_active():
                        self.log("⚠️ Standalone dnsmasq may not be active", "WARN")
                        self.log("  Trying to restart it...", "INFO")
                        self.run_command(["systemctl", "restart", "pinetap-dnsmasq"], check=False)
                        time.sleep(2)
                        if not self.ensure_dnsmasq_active():
                            self.log("⚠️ Captive portal detection might not work properly", "WARN")
                            self.log("  Try: sudo systemctl restart pinetap-dnsmasq", "INFO")
                    
                    if services_file:
                        self.log("\n⚡ AUTO-RELOAD ENABLED", "SUCCESS")
                        self.log("=" * 60, "INFO")
                        # Get the actual path being monitored from metadata
                        metadata_file = Path("/var/www/pinetap-portal/portal_metadata.json")
                        monitored_path = services_file
                        if metadata_file.exists():
                            try:
                                metadata = json.loads(metadata_file.read_text())
                                monitored_path = metadata.get('services_file', services_file)
                            except Exception:
                                pass
                        
                        self.log(f"📄 Monitoring: {monitored_path}", "INFO")
                        self.log(f"📄 Edit this file to update portal instantly!", "INFO")
                        self.log(f"   Changes appear on next browser refresh - no restart needed", "INFO")
                        self.log("=" * 60, "INFO")

                    # CRITICAL: Verify everything is working
                    time.sleep(3)

                    # Test DNS hijacking
                    self.log("\n🧪 Verifying captive portal setup...", "INFO")
                    if self.verify_dns_hijacking(ip_address.split('/')[0]):
                        self.log("✓ DNS hijacking verified!", "SUCCESS")
                    else:
                        self.log("⚠️ DNS hijacking may not be working", "WARN")
                        self.log("  Test manually: nslookup google.com " + ip_address.split('/')[0], "INFO")

                    # Test portal HTTP responses
                    if self.verify_captive_portal_working(ip_address.split('/')[0]):
                        self.log("✓ Captive portal detection verified!", "SUCCESS")
                        self.log("\n📋 What happens next:", "INFO")
                        self.log("  • Android: Shows 'Sign in to network' notification", "INFO")
                        self.log("  • iPhone: Auto-opens Safari with portal page", "INFO")
                        self.log("  • Windows: Shows 'Action required' on network icon", "INFO")
                    else:
                        self.log("⚠️ Captive portal may not auto-trigger", "WARN")
                        self.log("  Check logs: sudo journalctl -u pinetap-portal -f", "INFO")
                else:
                    self.log("⚠️ Captive portal setup failed", "WARN")
                    self.log("  AP is working, but portal may not auto-open", "WARN")

            self.log("\n⏳ Waiting then verifying SSID broadcast...", "INFO")
            time.sleep(3)
            ret, stdout, _ = self.run_command(["iwlist", ap_interface, "scan"], check=False)
            if ret == 0 and ssid in stdout:
                self.log(f"✓ Verified: SSID '{ssid}' is being broadcast!", "SUCCESS")
            else:
                self.log(f"⚠️ Could not verify SSID broadcast", "WARN")

            return True
        else:
            self.log("Connection created but failed to activate", "ERROR")
            return False

    def remove_ap(self, con_name: str, restore_config: bool = True) -> bool:
        self.log(f"Removing access point: {con_name}")

        connections = self.load_managed_connections()
        was_standalone = False
        had_captive_portal = False
        if con_name in connections:
            was_standalone = not connections[con_name].get('share_internet', True)
            had_captive_portal = connections[con_name].get('captive_portal', False)

        ret, stdout, _ = self.run_command(["nmcli", "con", "show", "--active"], check=False)
        if ret == 0 and con_name in stdout:
            self.log(f"Disconnecting active connection: {con_name}")
            self.run_command(["nmcli", "con", "down", con_name], check=False)
            time.sleep(1)

        if not self.delete_connection(con_name):
            self.log(f"Connection {con_name} not found or failed to delete", "WARN")
        else:
            self.remove_managed_connection(con_name)

        if restore_config:
            remaining = self.load_managed_connections()
            if not remaining:
                self.log("Last PiNetAP connection removed, restoring system state...")

                if had_captive_portal or any(c.get('captive_portal', False) for c in connections.values()):
                    self.remove_captive_portal()

                self.restore_original_system_state()
                self.restore_nm_config()
                self.manage_dnsmasq_service("enable")
                self.reload_networkmanager()

                if self.PINETAP_CONFIG_DIR.exists():
                    try:
                        import shutil
                        shutil.rmtree(self.PINETAP_CONFIG_DIR)
                        self.log("Removed PiNetAP configuration directory")
                    except Exception as e:
                        self.log(f"Could not remove config directory: {e}", "WARN")
            else:
                self.log(f"{len(remaining)} connection(s) remaining", "INFO")

        self.log("Access point removed successfully!", "SUCCESS")
        return True

    def remove_all_managed_aps(self, restore_config: bool = True, force: bool = False) -> bool:
        """Remove all PiNetAP-managed connections"""
        connections = self.load_managed_connections()

        if not connections:
            self.log("No managed connections to remove", "INFO")
            return True

        print("\n" + "="*70)
        print("⚠️ UNINSTALL ALL PINETAP ACCESS POINTS")
        print("="*70)
        print(f"\nThe following {len(connections)} connection(s) will be removed:")
        for con_name, info in connections.items():
            ssid = info.get('ssid', 'N/A')
            interface = info.get('interface', 'N/A')
            mode = "Standalone" if not info.get('share_internet', True) else "Internet Sharing"
            print(f"  • {con_name}")
            print(f"    SSID: {ssid}, Interface: {interface}, Mode: {mode}")

        print("\nThe following will also be cleaned up:")
        print("  • Network configuration restored")
        print("  • IP forwarding restored")
        print("  • iptables rules removed")
        print("  • Captive portal removed (if enabled)")
        print("  • PiNetAP configuration directory removed")

        if not force:
            print("\n" + "-"*70)
            response = input("Continue with uninstall? [y/N]: ").strip().lower()
            if response not in ['y', 'yes']:
                print("Uninstall cancelled.")
                return False

        print("\n" + "="*70)
        print("REMOVING ACCESS POINTS...")
        print("="*70)

        success_count = 0
        for con_name in list(connections.keys()):
            print(f"\n[{success_count + 1}/{len(connections)}] Removing {con_name}...")

            ret, stdout, _ = self.run_command(["nmcli", "con", "show", "--active"], check=False)
            if ret == 0 and con_name in stdout:
                self.log(f"  Disconnecting active connection")
                self.run_command(["nmcli", "con", "down", con_name], check=False)
                time.sleep(1)

            if self.delete_connection(con_name):
                self.remove_managed_connection(con_name)
                success_count += 1
                print(f"  ✓ Removed")
            else:
                print(f"  ✗ Failed to remove")

        has_captive_portal = any(conn.get('captive_portal', False) for conn in connections.values())
        if has_captive_portal:
            print("\nRemoving captive portal...")
            self.remove_captive_portal()

        if restore_config:
            print("\nRestoring system configuration...")
            print("  • Restoring IP forwarding and firewall rules...")
            self.restore_original_system_state()
            print("  • Restoring NetworkManager configuration...")
            self.restore_nm_config()
            print("  • Re-enabling dnsmasq service...")
            self.manage_dnsmasq_service("enable")
            print("  • Reloading NetworkManager...")
            self.reload_networkmanager()

        if self.INTERFACE_CONFIG.exists():
            try:
                self.INTERFACE_CONFIG.unlink()
                print("  • Removed interface mapping")
            except Exception as e:
                self.log(f"Failed to remove interface mapping: {e}", "WARN")

        if self.PINETAP_CONFIG_DIR.exists():
            try:
                import shutil
                shutil.rmtree(self.PINETAP_CONFIG_DIR)
                print("  • Removed PiNetAP configuration directory")
            except Exception as e:
                self.log(f"Could not remove config directory: {e}", "WARN")

        print("\n" + "="*70)
        if success_count == len(connections):
            print(f"✅ Successfully removed all {success_count} connection(s)!")
        else:
            print(f"⚠️ Removed {success_count}/{len(connections)} connection(s)")
        print("="*70)

        return success_count == len(connections)