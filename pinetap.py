#!/usr/bin/env python3
"""
PiNetAP - Dual WiFi Access Point Manager for Raspberry Pi
Main CLI interface and AP management

Usage: sudo python pinetap.py [command] [options]
"""

import argparse
import sys
import time
import json
from typing import Optional, Tuple, List, Dict
from pathlib import Path

from pinetap_core import SecurityMode, TestStatus, TestResult
from pinetap_network import PiNetAPNetwork


class PiNetAP(PiNetAPNetwork):
    """Main PiNetAP class with AP management and diagnostics"""

    def list_interfaces(self, detailed: bool = False):
        interfaces = self.get_available_interfaces()
        
        if not interfaces:
            print("No network interfaces found.")
            return

        print("\n" + "="*80)
        print("AVAILABLE NETWORK INTERFACES")
        print("="*80)
        
        if detailed:
            print(f"{'Interface':<15} {'Type':<15} {'State':<20} {'MAC Address':<20}")
        else:
            print(f"{'Interface':<15} {'Type':<15} {'State':<20}")
        print("-"*80)

        wifi_count = 0
        eth_count = 0
        wifi_list = []
        eth_list = []

        for name, info in interfaces.items():
            mac = self.get_interface_mac(name) if detailed else None
            mac_display = mac if mac else "--"
            
            if detailed:
                print(f"{name:<15} {info['type']:<15} {info['state']:<20} {mac_display:<20}")
            else:
                print(f"{name:<15} {info['type']:<15} {info['state']:<20}")

            if info['type'] == 'wifi':
                wifi_count += 1
                wifi_list.append(name)
            elif info['type'] == 'ethernet':
                eth_count += 1
                eth_list.append(name)

        print("-"*80)
        print(f"\nSummary: {wifi_count} WiFi, {eth_count} Ethernet interface(s)")
        if wifi_list:
            print(f"WiFi interfaces: {', '.join(wifi_list)}")
        if eth_list:
            print(f"Ethernet interfaces: {', '.join(eth_list)}")

        mapping = self.load_interface_mapping()
        if mapping:
            print("\n" + "="*80)
            print("SAVED INTERFACE MAPPINGS (from previous installation)")
            print("="*80)
            for role, info in mapping.items():
                expected_iface = info['interface']
                expected_mac = info['mac']
                current_iface = self.get_interface_by_mac(expected_mac)
                
                if current_iface == expected_iface:
                    status = "✓ Same"
                elif current_iface:
                    status = f"⚠ Now: {current_iface}"
                else:
                    status = "✗ Not found"
                
                print(f"{role.upper():<10} {expected_iface:<15} {expected_mac:<20} {status}")

        print("\n" + "="*80)
        print("SETUP RECOMMENDATIONS")
        print("="*80)

        if wifi_count < 1:
            print("\n❌ No WiFi Setup Possible")
            print("   No WiFi interfaces detected!")
        elif wifi_count == 1:
            print("\n💡 Single WiFi Setup Options")
            print(f"   AP Interface: {wifi_list[0]} (for hotspot)")
            print("\n   Option 1: Standalone (No Internet) - Open Network")
            print(f"   sudo python pinetap.py install --ssid MyHotspot --security open \\")
            print(f"        --ap-interface {wifi_list[0]} --no-share --autoconnect")
            print("\n   Option 2: Standalone (No Internet) - Secured")
            print(f"   sudo python pinetap.py install --ssid MyHotspot --password Pass12345 \\")
            print(f"        --security wpa2-psk --ap-interface {wifi_list[0]} --no-share --autoconnect")
            if eth_count > 0:
                print(f"\n   Option 3: Internet via Ethernet")
                print(f"   sudo python pinetap.py install --ssid MyHotspot --password Pass12345 \\")
                print(f"        --security wpa2-psk --ap-interface {wifi_list[0]} --autoconnect")
        else:
            print("\n🎉 Dual WiFi Setup Available!")
            print(f"   sudo python pinetap.py install --ssid MyHotspot --password Pass12345 \\")
            print(f"        --security wpa2-psk --ap-interface {wifi_list[0]} \\")
            print(f"        --uplink-ssid HomeWiFi --uplink-password HomePass \\")
            print(f"        --uplink-interface {wifi_list[1]} --autoconnect")

        print("\n" + "="*80)
        print("💡 TIP: Interface names may change after reboot (USB adapters)")
        print("   PiNetAP uses MAC address binding to prevent issues.")
        print("="*80)

    def list_managed_connections(self):
        connections = self.load_managed_connections()
        
        if not connections:
            print("\nNo PiNetAP-managed connections found.")
            print("Use 'pinetap.py install' to create an access point.")
            return
        
        print("\n" + "="*80)
        print("PINETAP MANAGED ACCESS POINTS")
        print("="*80)
        print(f"{'Connection Name':<25} {'SSID':<20} {'Interface':<12} {'Status':<10}")
        print("-"*80)
        
        for con_name, info in connections.items():
            exists = self.connection_exists(con_name)
            status = "Active" if exists else "Deleted"
            
            ssid = info.get('ssid', 'N/A')
            interface = info.get('interface', 'N/A')
            
            print(f"{con_name:<25} {ssid:<20} {interface:<12} {status:<10}")
        
        print("-"*80)
        print(f"\nTotal: {len(connections)} managed connection(s)")
        print("\nTo remove: sudo pinetap.py uninstall --connection <CONNECTION_NAME>")
        print("To remove all: sudo pinetap.py uninstall --all")
        print("="*80)

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

        conn_name = f"{uplink_ssid}-Uplink"
        
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
        security_mode: SecurityMode = SecurityMode.WPA2_PSK,
        captive_portal: bool = False,
        portal_services: Optional[List[Dict]] = None
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
            con_name = f"{ssid}-AP"

        if self.connection_exists(con_name):
            self.log(f"Removing existing connection '{con_name}' to recreate it")
            self.delete_connection(con_name)

        self.log(f"Creating access point: {ssid} on {ap_interface}")
        self.log(f"⚠ IMPORTANT: Connection will be bound to MAC {ap_mac}", "INFO")

        if share_internet:
            self.enable_ip_forwarding()
            ipv4_method = "shared"
            self.log("Configuring for internet sharing (NAT enabled)", "INFO")
        else:
            self.disable_ip_forwarding()
            self.clear_iptables_nat_rules()
            ipv4_method = "shared"
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
            (["ipv4.method", ipv4_method], f"Set IPv4 method to {ipv4_method}"),
            (["ipv4.address", ip_address], f"Set IP to {ip_address}"),
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
        
        if not share_internet:
            self.log("Re-applying firewall rules to prevent internet sharing...")
            self.clear_iptables_nat_rules()
        
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
            
            if captive_portal:
                self.log("\n📱 Setting up captive portal...")
                self.configure_captive_portal_dns(ap_interface, ip_address.split('/')[0])
                self.reload_networkmanager(delay=2)
                
                if self.setup_captive_portal(ip_address.split('/')[0], ssid, ap_interface, portal_services):
                    self.log(f"✓ Captive portal active!", "SUCCESS")
                else:
                    self.log(f"⚠ Captive portal setup failed", "WARN")
            
            self.log("\n⏳ Waiting then verifying SSID broadcast...", "INFO")
            time.sleep(3)
            ret, stdout, _ = self.run_command(["iwlist", ap_interface, "scan"], check=False)
            if ret == 0 and ssid in stdout:
                self.log(f"✓ Verified: SSID '{ssid}' is being broadcast!", "SUCCESS")
            else:
                self.log(f"⚠ Could not verify SSID broadcast", "WARN")
            
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

        if was_standalone:
            self.remove_standalone_dhcp()

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
        print("⚠️  UNINSTALL ALL PINETAP ACCESS POINTS")
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
        
        has_standalone = any(not conn.get('share_internet', True) for conn in connections.values())
        
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
        
        if has_standalone:
            print("\nCleaning up standalone DHCP configuration...")
            self.remove_standalone_dhcp()
        
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
            print(f"⚠️  Removed {success_count}/{len(connections)} connection(s)")
        print("="*70)
        
        return success_count == len(connections)

    def diagnose_ap(self, con_name: Optional[str] = None):
        """Run comprehensive diagnostics on AP setup"""
        print("\n" + "="*70)
        print("ACCESS POINT DIAGNOSTICS")
        print("="*70)
        
        ret, stdout, _ = self.run_command(["nmcli", "con", "show"], check=False)
        ap_connections = []
        if ret == 0:
            for line in stdout.strip().split('\n')[1:]:
                parts = line.split()
                if len(parts) >= 3 and 'wifi' in line.lower():
                    ap_connections.append(parts[0])
        
        if not ap_connections:
            print("\n❌ No WiFi connections found")
            return
        
        print(f"\n📡 Found {len(ap_connections)} WiFi connection(s):")
        for conn in ap_connections:
            print(f"   - {conn}")
        
        target_conn = con_name if con_name else ap_connections[0]
        
        print(f"\n🔍 Diagnosing: {target_conn}")
        print("-"*70)
        
        ret, stdout, _ = self.run_command(["nmcli", "con", "show", target_conn], check=False)
        if ret != 0:
            print(f"❌ Cannot read connection '{target_conn}'")
            return
        
        config = {}
        for line in stdout.split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                config[key.strip()] = value.strip()
        
        print("\n📋 Configuration:")
        important_keys = [
            '802-11-wireless.mode', '802-11-wireless.ssid',
            '802-11-wireless.channel', '802-11-wireless.band',
            '802-11-wireless-security.key-mgmt',
            'ipv4.method', 'ipv4.addresses',
            'connection.autoconnect', 'GENERAL.DEVICES', 'GENERAL.STATE'
        ]
        
        for key in important_keys:
            if key in config and config[key] != '--':
                print(f"   {key}: {config[key]}")
        
        ret, stdout, _ = self.run_command(["nmcli", "con", "show", "--active"], check=False)
        is_active = ret == 0 and target_conn in stdout
        print(f"\n🔌 Connection Status: {'✓ ACTIVE' if is_active else '✗ INACTIVE'}")
        
        print("\n🌐 IP Forwarding:")
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "r") as f:
                value = f.read().strip()
            print(f"   {'✓ Enabled' if value == '1' else '✗ Disabled'}")
        except Exception:
            print("   ? Cannot check")
        
        print("\n" + "="*70)
        print("💡 TROUBLESHOOTING TIPS:")
        print("="*70)
        if not is_active:
            print("❌ Connection is not active!")
            print(f"   Try: sudo nmcli con up {target_conn}")
        print("\n🔧 Common fixes:")
        print("   1. Restart NetworkManager: sudo systemctl restart NetworkManager")
        print("   2. Check logs: journalctl -u NetworkManager -f")
        print("="*70)

    def fix_ap_issues(self, con_name: Optional[str] = None):
        """Attempt to fix common AP issues"""
        print("\n" + "="*70)
        print("AUTOMATIC AP ISSUE FIXER")
        print("="*70)
        
        issues_fixed = 0
        issues_found = 0
        
        print("\n[1/2] Checking NetworkManager...")
        if not self.check_networkmanager():
            issues_found += 1
            print("   ❌ Not running")
            print("   🔧 Attempting to start...")
            self.run_command(["systemctl", "start", "NetworkManager"], check=False)
            time.sleep(2)
            if self.check_networkmanager():
                print("   ✓ Started")
                issues_fixed += 1
        else:
            print("   ✓ Running")
        
        print("\n[2/2] Checking AP connection...")
        if not con_name:
            ret, stdout, _ = self.run_command(["nmcli", "con", "show"], check=False)
            for line in stdout.strip().split('\n')[1:]:
                if 'wifi' in line.lower():
                    con_name = line.split()[0]
                    break
        
        if con_name:
            ret, stdout, _ = self.run_command(["nmcli", "con", "show", "--active"], check=False)
            is_active = ret == 0 and con_name in stdout
            
            if not is_active:
                issues_found += 1
                print(f"   ❌ Not active")
                print("   🔧 Activating...")
                ret, _, _ = self.run_command(["nmcli", "con", "up", con_name], check=False)
                if ret == 0:
                    print("   ✓ Activated")
                    issues_fixed += 1
            else:
                print("   ✓ Active")
        
        print("\n" + "="*70)
        if issues_found == 0:
            print("✅ No issues found!")
        elif issues_fixed == issues_found:
            print(f"✅ All {issues_fixed} issue(s) fixed!")
        else:
            print(f"⚠️  Fixed {issues_fixed}/{issues_found} issue(s)")
        print("="*70)


def main():
    parser = argparse.ArgumentParser(
        description="PiNetAP - Dual WiFi Access Point Manager",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Show interfaces
  sudo python pinetap.py interfaces -d

  # Standalone AP (no internet) - Open
  sudo python pinetap.py install --ssid OfflineNet --security open \\
       --ap-interface wlan0 --no-share --autoconnect

  # Standalone AP (no internet) - Secured
  sudo python pinetap.py install --ssid SecureNet --password Pass12345 \\
       --security wpa2-psk --ap-interface wlan0 --no-share --autoconnect

  # With internet sharing
  sudo python pinetap.py install --ssid MyHotspot --password Pass12345 \\
       --security wpa2-psk --ap-interface wlan0 --autoconnect

  # With captive portal
  sudo python pinetap.py install --ssid MyServices --password Pass12345 \\
       --security wpa2-psk --ap-interface wlan0 --no-share --autoconnect \\
       --captive-portal

  # Remove AP
  sudo python pinetap.py uninstall --connection MyHotspot-AP

  # Remove all
  sudo python pinetap.py uninstall --all
"""
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    interfaces_parser = subparsers.add_parser("interfaces", help="List interfaces")
    interfaces_parser.add_argument("-d", "--detailed", action="store_true")

    subparsers.add_parser("managed", help="List managed connections")

    install_parser = subparsers.add_parser("install", help="Create AP")
    install_parser.add_argument("--ssid", required=True)
    install_parser.add_argument("--password")
    install_parser.add_argument("--security", choices=["open", "wpa2-psk", "wpa3-sae"], default="wpa2-psk")
    install_parser.add_argument("--ap-interface", required=True)
    install_parser.add_argument("--uplink-ssid")
    install_parser.add_argument("--uplink-password")
    install_parser.add_argument("--uplink-interface")
    install_parser.add_argument("--ip", default="192.168.4.1/24")
    install_parser.add_argument("--channel", type=int, default=3)
    install_parser.add_argument("--mac")
    install_parser.add_argument("--autoconnect", action="store_true")
    install_parser.add_argument("--connection")
    install_parser.add_argument("--no-share", action="store_true")
    install_parser.add_argument("--captive-portal", action="store_true")
    install_parser.add_argument("--portal-services", type=str)

    uninstall_parser = subparsers.add_parser("uninstall", help="Remove AP")
    uninstall_parser.add_argument("--connection")
    uninstall_parser.add_argument("--all", action="store_true")
    uninstall_parser.add_argument("--keep-config", action="store_true")
    uninstall_parser.add_argument("--force", action="store_true")

    subparsers.add_parser("list", help="List connections")

    diagnose_parser = subparsers.add_parser("diagnose", help="Diagnose AP")
    diagnose_parser.add_argument("--connection")
    
    fix_parser = subparsers.add_parser("fix", help="Fix AP issues")
    fix_parser.add_argument("--connection")

    parser.add_argument("-v", "--verbose", action="store_true")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    manager = PiNetAP(verbose=args.verbose)

    if args.command == "interfaces":
        manager.list_interfaces(detailed=getattr(args, 'detailed', False))
        return 0

    if args.command == "managed":
        manager.list_managed_connections()
        return 0

    if args.command in ["list", "diagnose"]:
        if args.command == "list":
            manager.list_connections()
        elif args.command == "diagnose":
            manager.diagnose_ap(args.connection if hasattr(args, 'connection') else None)
        return 0

    if not manager.check_root():
        manager.log("This command requires root. Run with sudo.", "ERROR")
        return 1

    if not manager.check_networkmanager():
        manager.log("NetworkManager is not running.", "ERROR")
        return 1

    if args.command == "fix":
        manager.fix_ap_issues(args.connection if hasattr(args, 'connection') else None)
        return 0

    if args.command == "install":
        security_mode = SecurityMode(args.security)
        
        is_valid, error_msg = manager.validate_password(args.password, security_mode)
        if not is_valid:
            manager.log(f"Password validation failed: {error_msg}", "ERROR")
            return 1

        if args.uplink_ssid:
            if not args.uplink_interface:
                manager.log("--uplink-interface required with --uplink-ssid", "ERROR")
                return 1

            success = manager.connect_to_uplink(
                args.uplink_ssid,
                args.uplink_password,
                args.uplink_interface,
                autoconnect=args.autoconnect
            )

            if not success:
                manager.log("Failed to connect to uplink", "WARN")

        manager.save_original_system_state()
        manager.backup_nm_config()
        manager.modify_nm_config(add_dnsmasq=True)
        manager.manage_dnsmasq_service("disable")
        manager.reload_networkmanager()

        portal_services = None
        if args.portal_services:
            try:
                with open(args.portal_services, 'r') as f:
                    portal_services = json.load(f)
                manager.log(f"Loaded {len(portal_services)} service(s)")
            except Exception as e:
                manager.log(f"Failed to load services: {e}", "WARN")

        success = manager.create_ap(
            ssid=args.ssid,
            password=args.password,
            ap_interface=args.ap_interface,
            ip_address=args.ip,
            channel=args.channel,
            mac_address=args.mac,
            autoconnect=args.autoconnect,
            con_name=args.connection,
            share_internet=not args.no_share,
            security_mode=security_mode,
            captive_portal=args.captive_portal,
            portal_services=portal_services
        )

        if success:
            manager.save_interface_mapping(
                ap_interface=args.ap_interface,
                uplink_interface=args.uplink_interface
            )

        return 0 if success else 1

    elif args.command == "uninstall":
        if args.all:
            success = manager.remove_all_managed_aps(
                restore_config=not args.keep_config,
                force=args.force
            )
        elif args.connection:
            success = manager.remove_ap(
                con_name=args.connection,
                restore_config=not args.keep_config
            )
        else:
            manager.log("Specify --connection or --all", "ERROR")
            return 1
        
        return 0 if success else 1

    return 0


if __name__ == "__main__":
    sys.exit(main())