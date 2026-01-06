#!/usr/bin/env python3
"""
PiNetAP - Dual WiFi Access Point Manager for Raspberry Pi
Create WiFi hotspots with internet sharing from WiFi/Ethernet uplinks

Fixed: Interface naming stability using MAC address binding
Enhanced: Security modes, password validation, easier uninstall
FIXED: --no-share now properly prevents internet sharing

Usage: sudo python pinetap.py [command] [options]
"""

import argparse
import subprocess
import sys
import os
import time
import re
import json
from typing import Optional, Tuple, Dict, List
from pathlib import Path
from enum import Enum

class TestStatus(Enum):
    PASS = "✓"
    FAIL = "✗"
    WARN = "⚠"
    SKIP = "○"

class SecurityMode(Enum):
    OPEN = "open"
    WPA2_PSK = "wpa2-psk"
    WPA3_SAE = "wpa3-sae"

class TestResult:
    def __init__(self, name: str, status: TestStatus, message: str = "", details: str = ""):
        self.name = name
        self.status = status
        self.message = message
        self.details = details

    def __str__(self):
        status_color = {
            TestStatus.PASS: "\033[92m",
            TestStatus.FAIL: "\033[91m",
            TestStatus.WARN: "\033[93m",
            TestStatus.SKIP: "\033[90m",
        }
        reset = "\033[0m"
        color = status_color.get(self.status, "")
        result = f"{color}{self.status.value} {self.name}{reset}"
        if self.message:
            result += f": {self.message}"
        return result

class PiNetAP:
    NM_CONFIG_PATH = Path("/etc/NetworkManager/NetworkManager.conf")
    NM_CONFIG_BACKUP = Path("/etc/NetworkManager/NetworkManager.conf.backup")
    PINETAP_CONFIG_DIR = Path("/etc/pinetap")
    INTERFACE_CONFIG = PINETAP_CONFIG_DIR / "interface_mapping.json"
    CONNECTIONS_CONFIG = PINETAP_CONFIG_DIR / "managed_connections.json"
    DNSMASQ_CONF_DIR = Path("/etc/NetworkManager/dnsmasq.d")
    AP_DNSMASQ_CONF = DNSMASQ_CONF_DIR / "pinetap-ap.conf"

    # Password requirements for different security modes
    PASSWORD_REQUIREMENTS = {
        SecurityMode.WPA2_PSK: {
            'min_length': 8,
            'max_length': 63,
            'description': 'WPA2-PSK requires 8-63 characters'
        },
        SecurityMode.WPA3_SAE: {
            'min_length': 8,
            'max_length': 63,
            'description': 'WPA3-SAE requires 8-63 characters'
        }
    }

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.test_results: List[TestResult] = []

    def log(self, message: str, level: str = "INFO"):
        prefix = f"[{level}]"
        print(f"{prefix} {message}")

    def run_command(self, cmd: list, check: bool = True, capture: bool = True) -> Tuple[int, str, str]:
        if self.verbose:
            self.log(f"Executing: {' '.join(cmd)}", "DEBUG")
        try:
            result = subprocess.run(
                cmd,
                check=check,
                capture_output=capture,
                text=True
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.CalledProcessError as e:
            return e.returncode, e.stdout if capture else "", e.stderr if capture else ""
        except Exception as e:
            self.log(f"Command execution failed: {e}", "ERROR")
            return 1, "", str(e)

    def check_root(self) -> bool:
        return os.geteuid() == 0

    def check_networkmanager(self) -> bool:
        ret, _, _ = self.run_command(["systemctl", "is-active", "NetworkManager"], check=False)
        return ret == 0

    def validate_password(self, password: Optional[str], security_mode: SecurityMode) -> Tuple[bool, str]:
        """
        Validate password based on security mode requirements
        Returns: (is_valid, error_message)
        """
        if security_mode == SecurityMode.OPEN:
            if password:
                return False, "Open network should not have a password. Remove --password or choose a different security mode."
            return True, ""
        
        if not password:
            return False, f"{security_mode.value} requires a password. Please provide --password."
        
        requirements = self.PASSWORD_REQUIREMENTS.get(security_mode)
        if not requirements:
            return True, ""  # No specific requirements
        
        min_len = requirements['min_length']
        max_len = requirements['max_length']
        
        if len(password) < min_len:
            return False, f"Password too short. {requirements['description']} (current length: {len(password)})"
        
        if len(password) > max_len:
            return False, f"Password too long. {requirements['description']} (current length: {len(password)})"
        
        return True, ""

    def save_managed_connection(self, con_name: str, ap_interface: str, ssid: str, 
                               security_mode: str, share_internet: bool):
        """Save information about managed connections for easy uninstall"""
        connections = self.load_managed_connections()
        
        connections[con_name] = {
            'ssid': ssid,
            'interface': ap_interface,
            'security_mode': security_mode,
            'share_internet': share_internet,
            'created': time.time(),
            'last_modified': time.time()
        }
        
        self.PINETAP_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        self.CONNECTIONS_CONFIG.write_text(json.dumps(connections, indent=2))
        self.log(f"Saved connection info for easier management")

    def load_managed_connections(self) -> Dict:
        """Load saved connection information"""
        if not self.CONNECTIONS_CONFIG.exists():
            return {}
        
        try:
            return json.loads(self.CONNECTIONS_CONFIG.read_text())
        except Exception as e:
            self.log(f"Failed to load connections config: {e}", "ERROR")
            return {}

    def remove_managed_connection(self, con_name: str):
        """Remove a connection from managed list"""
        connections = self.load_managed_connections()
        if con_name in connections:
            del connections[con_name]
            self.CONNECTIONS_CONFIG.write_text(json.dumps(connections, indent=2))

    def list_managed_connections(self):
        """List all PiNetAP-managed connections"""
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
            # Check if connection still exists
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

    def get_interface_mac(self, interface: str) -> Optional[str]:
        """Get MAC address for a given interface"""
        ret, stdout, _ = self.run_command(["nmcli", "device", "show", interface], check=False)
        if ret != 0:
            return None
        
        for line in stdout.split('\n'):
            if "GENERAL.HWADDR:" in line:
                parts = line.split(':', 1)
                if len(parts) == 2:
                    return parts[1].strip()
        return None

    def get_interface_by_mac(self, mac: str) -> Optional[str]:
        """Find interface name by MAC address"""
        interfaces = self.get_available_interfaces()
        
        for iface in interfaces:
            iface_mac = self.get_interface_mac(iface)
            if iface_mac and iface_mac.lower() == mac.lower():
                return iface
        
        return None

    def save_interface_mapping(self, ap_interface: str, uplink_interface: Optional[str] = None):
        """Save interface to MAC address mapping for persistent identification"""
        mapping = {}
        
        ap_mac = self.get_interface_mac(ap_interface)
        if ap_mac:
            mapping['ap'] = {
                'interface': ap_interface,
                'mac': ap_mac,
                'timestamp': time.time()
            }
            self.log(f"Saved AP interface mapping: {ap_interface} → {ap_mac}")
        
        if uplink_interface:
            uplink_mac = self.get_interface_mac(uplink_interface)
            if uplink_mac:
                mapping['uplink'] = {
                    'interface': uplink_interface,
                    'mac': uplink_mac,
                    'timestamp': time.time()
                }
                self.log(f"Saved uplink interface mapping: {uplink_interface} → {uplink_mac}")
        
        if mapping:
            self.PINETAP_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            self.INTERFACE_CONFIG.write_text(json.dumps(mapping, indent=2))
            self.log(f"Interface mapping saved to {self.INTERFACE_CONFIG}")

    def load_interface_mapping(self) -> Dict:
        """Load saved interface mappings"""
        if not self.INTERFACE_CONFIG.exists():
            return {}
        
        try:
            return json.loads(self.INTERFACE_CONFIG.read_text())
        except Exception as e:
            self.log(f"Failed to load interface mapping: {e}", "ERROR")
            return {}

    def verify_interface_consistency(self) -> bool:
        """Verify current interfaces match saved mappings"""
        mapping = self.load_interface_mapping()
        if not mapping:
            return True  # No mapping to verify
        
        all_consistent = True
        
        for role, info in mapping.items():
            expected_iface = info['interface']
            expected_mac = info['mac']
            
            current_mac = self.get_interface_mac(expected_iface)
            
            if current_mac and current_mac.lower() == expected_mac.lower():
                self.log(f"✓ {role.upper()} interface {expected_iface} consistent (MAC: {expected_mac})", "INFO")
            else:
                # Interface name changed, try to find by MAC
                actual_iface = self.get_interface_by_mac(expected_mac)
                if actual_iface:
                    self.log(
                        f"⚠ {role.upper()} interface name changed: {expected_iface} → {actual_iface} (MAC: {expected_mac})",
                        "WARN"
                    )
                    self.log(f"   This is normal after reboot with USB adapters", "INFO")
                    all_consistent = False
                else:
                    self.log(
                        f"✗ {role.upper()} interface {expected_iface} not found! Expected MAC: {expected_mac}",
                        "ERROR"
                    )
                    all_consistent = False
        
        return all_consistent

    def get_available_interfaces(self) -> Dict[str, Dict[str, str]]:
        ret, stdout, _ = self.run_command(["nmcli", "device", "status"], check=False)
        if ret != 0:
            return {}

        interfaces = {}
        for line in stdout.strip().split('\n')[1:]:
            parts = line.split()
            if len(parts) >= 3:
                name = parts[0]
                dev_type = parts[1]
                state = parts[2]
                interfaces[name] = {
                    "type": dev_type,
                    "state": state
                }
        return interfaces

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

        # Check for saved mappings
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
            print("   You need at least 1 WiFi interface for AP mode.")
        elif wifi_count == 1:
            print("\n💡 Single WiFi Setup Options")
            print(f"   AP Interface: {wifi_list[0]} (for hotspot)")
            print("\n   Option 1: Standalone (No Internet) - Open Network")
            print("   Perfect for: File sharing, local services, offline networks")
            print(f"   sudo pinetap.py install --ssid MyHotspot --security open \\")
            print(f"        --ap-interface {wifi_list[0]} --no-share --autoconnect")
            
            print("\n   Option 2: Standalone (No Internet) - Secured")
            print(f"   sudo pinetap.py install --ssid MyHotspot --password Pass12345 \\")
            print(f"        --security wpa2-psk --ap-interface {wifi_list[0]} --no-share --autoconnect")
            
            if eth_count > 0:
                print(f"\n   Option 3: Internet via Ethernet")
                print(f"   Uplink: {eth_list[0]} (for internet)")
                print(f"   sudo pinetap.py install --ssid MyHotspot --password Pass12345 \\")
                print(f"        --security wpa2-psk --ap-interface {wifi_list[0]} --autoconnect")
            else:
                print("\n   Note: No Ethernet detected. Standalone mode only.")
                print("   Connect clients to access local services on the Pi.")
        else:
            print("\n🎉 Dual WiFi Setup Available!")
            print(f"   AP Interface: {wifi_list[0]} (for hotspot)")
            print(f"   Uplink: {wifi_list[1]} (for internet)")
            if eth_count > 0:
                print(f"   Alternative: {eth_list[0]} (for internet)")
            
            print("\n   Option 1: Dual WiFi with Internet")
            print(f"   sudo pinetap.py install --ssid MyHotspot --password Pass12345 \\")
            print(f"        --security wpa2-psk --ap-interface {wifi_list[0]} \\")
            print(f"        --uplink-ssid HomeWiFi --uplink-password HomePass \\")
            print(f"        --uplink-interface {wifi_list[1]} --autoconnect")
            
            print("\n   Option 2: Standalone (No Internet)")
            print(f"   sudo pinetap.py install --ssid MyHotspot --password Pass12345 \\")
            print(f"        --security wpa2-psk --ap-interface {wifi_list[0]} --no-share --autoconnect")

        print("\n" + "="*80)
        print("💡 TIP: Interface names may change after reboot (USB adapters)")
        print("   PiNetAP uses MAC address binding to prevent issues.")
        print("   Use 'pinetap.py interfaces -d' to see MAC addresses.")
        print("="*80)

    def get_active_connections(self) -> List[str]:
        ret, stdout, _ = self.run_command(["nmcli", "con", "show", "--active"], check=False)
        if ret != 0:
            return []

        connections = []
        for line in stdout.strip().split('\n')[1:]:
            parts = line.split()
            if parts:
                connections.append(parts[0])
        return connections

    def get_interface_connection(self, interface: str) -> Optional[str]:
        ret, stdout, _ = self.run_command(["nmcli", "device", "show", interface], check=False)
        if ret != 0:
            return None

        for line in stdout.split('\n'):
            if "GENERAL.CONNECTION:" in line:
                parts = line.split(':', 1)
                if len(parts) == 2:
                    conn = parts[1].strip()
                    if conn and conn != "--":
                        return conn
        return None

    def check_interface_available(self, interface: str, for_ap: bool = True, 
                                 allow_reconnect: bool = False) -> Tuple[bool, str, Optional[str]]:
        """
        Check if interface is available for use.
        Returns: (is_available, message, existing_connection_name)
        """
        interfaces = self.get_available_interfaces()
        
        if interface not in interfaces:
            return False, f"Interface {interface} not found", None

        if interfaces[interface]['type'] != 'wifi':
            if for_ap:
                return False, f"Interface {interface} is not a WiFi interface (type: {interfaces[interface]['type']})", None

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

        # Get MAC address for binding
        uplink_mac = self.get_interface_mac(uplink_interface)
        if uplink_mac:
            self.log(f"Binding uplink to MAC address: {uplink_mac}")

        conn_name = f"{uplink_ssid}-Uplink"
        
        # Delete existing connection if it exists
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

        # Bind connection to MAC address
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

    def backup_nm_config(self) -> bool:
        if self.NM_CONFIG_PATH.exists() and not self.NM_CONFIG_BACKUP.exists():
            try:
                import shutil
                shutil.copy2(self.NM_CONFIG_PATH, self.NM_CONFIG_BACKUP)
                self.log(f"Backed up {self.NM_CONFIG_PATH}")
                return True
            except Exception as e:
                self.log(f"Failed to backup config: {e}", "ERROR")
                return False
        return True

    def restore_nm_config(self) -> bool:
        if self.NM_CONFIG_BACKUP.exists():
            try:
                import shutil
                shutil.copy2(self.NM_CONFIG_BACKUP, self.NM_CONFIG_PATH)
                self.NM_CONFIG_BACKUP.unlink()
                self.log(f"Restored {self.NM_CONFIG_PATH}")
                return True
            except Exception as e:
                self.log(f"Failed to restore config: {e}", "ERROR")
                return False
        return True

    def modify_nm_config(self, add_dnsmasq: bool = True) -> bool:
        try:
            content = self.NM_CONFIG_PATH.read_text() if self.NM_CONFIG_PATH.exists() else ""

            if add_dnsmasq:
                if "dns=dnsmasq" not in content:
                    if "[main]" in content:
                        content = content.replace("[main]", "[main]\ndns=dnsmasq")
                    else:
                        content = "[main]\ndns=dnsmasq\n\n" + content

            self.NM_CONFIG_PATH.write_text(content)
            self.log("Added dnsmasq to NetworkManager config")
            return True
        except Exception as e:
            self.log(f"Failed to modify NetworkManager config: {e}", "ERROR")
            return False

    def manage_dnsmasq_service(self, action: str) -> bool:
        if action == "disable":
            ret, _, _ = self.run_command(["systemctl", "list-unit-files", "dnsmasq.service"], check=False)
            if ret == 0:
                self.run_command(["systemctl", "stop", "dnsmasq"], check=False)
                self.run_command(["systemctl", "disable", "dnsmasq"], check=False)
                self.log("Disabled system dnsmasq service")
        elif action == "enable":
            ret, _, _ = self.run_command(["systemctl", "list-unit-files", "dnsmasq.service"], check=False)
            if ret == 0:
                self.run_command(["systemctl", "enable", "dnsmasq"], check=False)
                self.log("Re-enabled system dnsmasq service")
        return True

    def setup_standalone_dhcp(self, ap_interface: str, ip_address: str) -> bool:
        """
        Configure dnsmasq for DHCP in standalone mode (no internet sharing)
        This provides DHCP without NAT/routing
        """
        try:
            # Create dnsmasq config directory if it doesn't exist
            self.DNSMASQ_CONF_DIR.mkdir(parents=True, exist_ok=True)
            
            # Parse IP and subnet
            if '/' in ip_address:
                ip, prefix = ip_address.split('/')
                prefix = int(prefix)
            else:
                ip = ip_address
                prefix = 24
            
            # Calculate DHCP range (typically .10 to .250)
            ip_parts = ip.split('.')
            base_ip = '.'.join(ip_parts[:3])
            dhcp_start = f"{base_ip}.10"
            dhcp_end = f"{base_ip}.250"
            
            # Create dnsmasq config for this AP
            dnsmasq_config = f"""# PiNetAP standalone AP configuration
# Interface: {ap_interface}
# No internet routing - local network only

interface={ap_interface}
bind-interfaces
dhcp-range={dhcp_start},{dhcp_end},12h
dhcp-option=option:router,{ip}
dhcp-option=option:dns-server,{ip}

# Don't forward requests to upstream DNS for local-only network
no-resolv
# Provide a basic local DNS response
address=/#/{ip}
"""
            
            self.AP_DNSMASQ_CONF.write_text(dnsmasq_config)
            self.log(f"Created standalone DHCP config: {self.AP_DNSMASQ_CONF}")
            self.log(f"DHCP range: {dhcp_start} - {dhcp_end}")
            
            return True
            
        except Exception as e:
            self.log(f"Failed to setup standalone DHCP: {e}", "ERROR")
            return False

    def remove_standalone_dhcp(self) -> bool:
        """Remove standalone DHCP configuration"""
        try:
            if self.AP_DNSMASQ_CONF.exists():
                self.AP_DNSMASQ_CONF.unlink()
                self.log("Removed standalone DHCP configuration")
            return True
        except Exception as e:
            self.log(f"Failed to remove DHCP config: {e}", "WARN")
            return False

    def reload_networkmanager(self, delay: int = 2):
        self.log("Reloading NetworkManager configuration...")
        self.run_command(["systemctl", "reload", "NetworkManager"], check=False)
        time.sleep(delay)
        self.log("NetworkManager reloaded")

    def connection_exists(self, con_name: str) -> bool:
        ret, stdout, _ = self.run_command(
            ["nmcli", "con", "show", con_name],
            check=False
        )
        return ret == 0

    def delete_connection(self, con_name: str) -> bool:
        if self.connection_exists(con_name):
            ret, _, stderr = self.run_command(
                ["nmcli", "con", "delete", con_name],
                check=False
            )
            if ret == 0:
                self.log(f"Deleted existing connection: {con_name}")
                return True
            else:
                self.log(f"Failed to delete connection: {stderr}", "ERROR")
                return False
        return True

    def clear_iptables_nat_rules(self) -> bool:
        """Clear all NAT/MASQUERADE rules to prevent internet sharing"""
        try:
            # Flush NAT table
            self.run_command(["iptables", "-t", "nat", "-F"], check=False)
            self.log("Cleared iptables NAT rules")
            
            # Flush filter table FORWARD chain
            self.run_command(["iptables", "-F", "FORWARD"], check=False)
            self.log("Cleared iptables FORWARD rules")
            
            # Set FORWARD policy to DROP (no forwarding between interfaces)
            self.run_command(["iptables", "-P", "FORWARD", "DROP"], check=False)
            self.log("Set FORWARD policy to DROP")
            
            return True
        except Exception as e:
            self.log(f"Failed to clear iptables rules: {e}", "WARN")
            return False

    def disable_ip_forwarding(self) -> bool:
        """Disable IP forwarding to prevent internet sharing"""
        try:
            # Disable via sysctl (temporary)
            self.run_command(["sysctl", "-w", "net.ipv4.ip_forward=0"], check=False)
            
            # Make it persistent
            sysctl_conf = Path("/etc/sysctl.conf")
            if sysctl_conf.exists():
                content = sysctl_conf.read_text()
                if "net.ipv4.ip_forward=1" in content:
                    content = content.replace("net.ipv4.ip_forward=1", "net.ipv4.ip_forward=0")
                    sysctl_conf.write_text(content)
                elif "net.ipv4.ip_forward" not in content:
                    with sysctl_conf.open('a') as f:
                        f.write("\n# Disabled by PiNetAP for standalone mode\nnet.ipv4.ip_forward=0\n")
            
            self.log("IP forwarding disabled")
            return True
        except Exception as e:
            self.log(f"Failed to disable IP forwarding: {e}", "WARN")
            return False

    def enable_ip_forwarding(self) -> bool:
        """Enable IP forwarding for internet sharing"""
        try:
            # Enable via sysctl (temporary)
            self.run_command(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=False)
            
            # Make it persistent
            sysctl_conf = Path("/etc/sysctl.conf")
            if sysctl_conf.exists():
                content = sysctl_conf.read_text()
                if "net.ipv4.ip_forward=0" in content:
                    content = content.replace("net.ipv4.ip_forward=0", "net.ipv4.ip_forward=1")
                    sysctl_conf.write_text(content)
                elif "net.ipv4.ip_forward" not in content:
                    with sysctl_conf.open('a') as f:
                        f.write("\n# Enabled by PiNetAP for internet sharing\nnet.ipv4.ip_forward=1\n")
            
            self.log("IP forwarding enabled")
            return True
        except Exception as e:
            self.log(f"Failed to enable IP forwarding: {e}", "WARN")
            return False

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
        security_mode: SecurityMode = SecurityMode.WPA2_PSK
    ) -> bool:
        available, msg, existing_conn = self.check_interface_available(ap_interface, for_ap=True, allow_reconnect=True)
        
        # If interface is in use, offer to disconnect and recreate
        if not available and existing_conn:
            self.log(f"Interface {ap_interface} is currently used by connection: {existing_conn}", "WARN")
            self.log(f"Removing existing connection to free up the interface...")
            
            # Disconnect and remove the existing connection
            self.run_command(["nmcli", "con", "down", existing_conn], check=False)
            if not self.delete_connection(existing_conn):
                self.log(f"Failed to remove existing connection", "ERROR")
                return False
            
            # Wait for interface to become available
            time.sleep(2)
            self.log(f"Interface {ap_interface} is now available")
        elif not available:
            self.log(f"Cannot use {ap_interface}: {msg}", "ERROR")
            return False

        # Get MAC address for binding
        ap_mac = self.get_interface_mac(ap_interface)
        if not ap_mac:
            self.log(f"Warning: Could not determine MAC address for {ap_interface}", "WARN")
        else:
            self.log(f"AP Interface MAC address: {ap_mac}")

        if not con_name:
            con_name = f"{ssid}-AP"

        # Delete connection if it exists (might be a different interface)
        if self.connection_exists(con_name):
            self.log(f"Removing existing connection '{con_name}' to recreate it")
            self.delete_connection(con_name)

        self.log(f"Creating access point: {ssid} on {ap_interface}")
        self.log(f"⚠ IMPORTANT: Connection will be bound to MAC {ap_mac}", "INFO")
        self.log(f"   Interface name may change after reboot, but connection will follow the hardware", "INFO")

        # Configure IP forwarding and routing based on share_internet setting
        if share_internet:
            self.enable_ip_forwarding()
            ipv4_method = "shared"
            self.log("Configuring for internet sharing (NAT enabled)", "INFO")
        else:
            # For standalone mode: disable forwarding and clear any NAT rules
            self.disable_ip_forwarding()
            self.clear_iptables_nat_rules()
            
            # Use manual method to prevent NetworkManager from creating NAT rules
            ipv4_method = "manual"
            
            # Setup standalone DHCP configuration
            self.setup_standalone_dhcp(ap_interface, ip_address)
            self.log("Configuring for standalone mode (no internet, local DHCP only)", "INFO")
        
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
            (["wifi.hidden", "false"], "Ensure SSID is broadcast (not hidden)"),
        ]

        # Bind to MAC address for persistent interface identification
        if ap_mac:
            modifications.append(
                (["wifi.mac-address", ap_mac], f"Bind to MAC {ap_mac} (prevents interface name issues)")
            )

        if autoconnect:
            modifications.append(
                (["connection.autoconnect-priority", "5"], "Set autoconnect priority")
            )

        if mac_address:
            modifications.append(
                (["wifi.cloned-mac-address", mac_address], f"Set cloned MAC to {mac_address}")
            )

        # Configure security based on mode
        if security_mode == SecurityMode.OPEN:
            modifications.append(
                (["wifi-sec.key-mgmt", "none"], "Set open network (no security)")
            )
        elif security_mode == SecurityMode.WPA2_PSK:
            modifications.extend([
                (["wifi-sec.key-mgmt", "wpa-psk"], "Set WPA-PSK security"),
                (["wifi-sec.proto", "rsn"], "Set WPA2 protocol"),
                (["wifi-sec.pairwise", "ccmp"], "Set AES-CCMP encryption"),
                (["wifi-sec.group", "ccmp"], "Set group AES-CCMP encryption"),
                (["wifi-sec.psk", password], "Set password"),
            ])
        elif security_mode == SecurityMode.WPA3_SAE:
            modifications.extend([
                (["wifi-sec.key-mgmt", "sae"], "Set WPA3-SAE security"),
                (["wifi-sec.psk", password], "Set password"),
            ])

        # For standalone mode, ensure no internet routing and no default route
        if not share_internet:
            modifications.extend([
                (["ipv4.route-metric", "9999"], "Set very high route metric (low priority)"),
                (["ipv4.never-default", "yes"], "Never make this the default route"),
                (["ipv4.may-fail", "no"], "Connection should succeed even without gateway"),
            ])

        for args, description in modifications:
            cmd = ["nmcli", "con", "modify", con_name] + args
            ret, _, stderr = self.run_command(cmd, check=False)
            if ret != 0:
                self.log(f"Warning: {description} failed: {stderr}", "WARN")
            else:
                if self.verbose:
                    self.log(f"✓ {description}", "DEBUG")

        # Make sure interface is up and not in any weird state
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
            self.log("Checking interface state...", "DEBUG")
            
            # Try to get more diagnostic info
            ret2, stdout2, _ = self.run_command(["nmcli", "device", "status"], check=False)
            if ret2 == 0:
                self.log(f"Device status:\n{stdout2}", "DEBUG")
            
            # Try to check rfkill
            ret3, stdout3, _ = self.run_command(["rfkill", "list"], check=False)
            if ret3 == 0:
                self.log(f"RF Kill status:\n{stdout3}", "DEBUG")
                if "blocked" in stdout3.lower():
                    self.log("WARNING: WiFi may be blocked by rfkill!", "ERROR")
                    self.log("Try: sudo rfkill unblock wifi", "INFO")
            
            return False

        # For standalone mode, reload NetworkManager to apply dnsmasq config
        if not share_internet:
            self.log("Reloading NetworkManager to apply standalone DHCP config...")
            self.reload_networkmanager(delay=3)

        # Verify the connection is actually active
        time.sleep(2)
        ret, stdout, _ = self.run_command(["nmcli", "con", "show", "--active"], check=False)
        if ret == 0 and con_name in stdout:
            autoconnect_msg = " (will reconnect on reboot)" if autoconnect else ""
            sharing_msg = " with internet sharing" if share_internet else " (standalone, local network only)"
            self.log(f"✓ Access point '{ssid}' created successfully on {ap_interface}{sharing_msg}{autoconnect_msg}!", "SUCCESS")
            
            # Show connection info
            self.log("\nAP Configuration:", "INFO")
            self.log(f"  SSID: {ssid}", "INFO")
            self.log(f"  Interface: {ap_interface} (MAC: {ap_mac})", "INFO")
            self.log(f"  IP Address: {ip_address.split('/')[0]}", "INFO")
            self.log(f"  Channel: {channel}", "INFO")
            self.log(f"  Security: {security_mode.value}", "INFO")
            if not share_internet:
                self.log(f"  Mode: Standalone (clients can connect but won't have internet)", "INFO")
                self.log(f"  IP Forwarding: Disabled", "INFO")
                self.log(f"  NAT/Masquerading: Disabled", "INFO")
                self.log(f"  DHCP: Enabled (local network only)", "INFO")
            else:
                self.log(f"  Mode: Internet Sharing Enabled", "INFO")
                self.log(f"  IP Forwarding: Enabled", "INFO")
                self.log(f"  NAT/Masquerading: Enabled (via NetworkManager)", "INFO")
            
            # Save connection info for management
            self.save_managed_connection(con_name, ap_interface, ssid, security_mode.value, share_internet)
            
            # Verify SSID is being broadcast
            self.log("\n⏳ Waiting 3 seconds then verifying SSID broadcast...", "INFO")
            time.sleep(3)
            ret, stdout, _ = self.run_command(["iwlist", ap_interface, "scan"], check=False)
            if ret == 0 and ssid in stdout:
                self.log(f"✓ Verified: SSID '{ssid}' is being broadcast!", "SUCCESS")
            else:
                self.log(f"⚠ Warning: Could not verify SSID broadcast. Check with: sudo iwlist {ap_interface} scan | grep ESSID", "WARN")
                self.log(f"  The AP may still work - try connecting from your phone", "INFO")
            
            return True
        else:
            self.log("Connection created but failed to activate properly", "ERROR")
            return False

    def remove_ap(self, con_name: str, restore_config: bool = True) -> bool:
        self.log(f"Removing access point: {con_name}")

        # Check if this was a standalone AP
        connections = self.load_managed_connections()
        was_standalone = False
        if con_name in connections:
            was_standalone = not connections[con_name].get('share_internet', True)

        if not self.delete_connection(con_name):
            self.log(f"Connection {con_name} not found or failed to delete", "WARN")
        else:
            # Remove from managed connections
            self.remove_managed_connection(con_name)

        # Clean up standalone DHCP config if needed
        if was_standalone:
            self.remove_standalone_dhcp()

        if restore_config:
            self.restore_nm_config()
            self.manage_dnsmasq_service("enable")
            self.reload_networkmanager()

        self.log("Access point removed successfully!", "SUCCESS")
        return True

    def remove_all_managed_aps(self, restore_config: bool = True) -> bool:
        """Remove all PiNetAP-managed connections"""
        connections = self.load_managed_connections()
        
        if not connections:
            self.log("No managed connections to remove", "INFO")
            return True
        
        self.log(f"Removing {len(connections)} managed connection(s)...")
        
        # Check if any were standalone
        has_standalone = any(not conn.get('share_internet', True) for conn in connections.values())
        
        success_count = 0
        for con_name in list(connections.keys()):
            if self.delete_connection(con_name):
                self.remove_managed_connection(con_name)
                success_count += 1
        
        # Clean up standalone DHCP config if any standalone APs existed
        if has_standalone:
            self.remove_standalone_dhcp()
        
        if restore_config:
            self.restore_nm_config()
            self.manage_dnsmasq_service("enable")
            self.reload_networkmanager()
        
        # Clean up interface mapping if it exists
        if self.INTERFACE_CONFIG.exists():
            try:
                self.INTERFACE_CONFIG.unlink()
                self.log("Removed interface mapping configuration")
            except Exception as e:
                self.log(f"Failed to remove interface mapping: {e}", "WARN")
        
        self.log(f"Successfully removed {success_count}/{len(connections)} connection(s)!", "SUCCESS")
        return success_count == len(connections)

    def list_connections(self):
        ret, stdout, _ = self.run_command(["nmcli", "con", "show"], check=False)
        if ret == 0:
            print("\nNetworkManager Connections:")
            print(stdout)

    def fix_ap_issues(self, con_name: Optional[str] = None):
        """Attempt to automatically fix common AP issues"""
        print("\n" + "="*70)
        print("AUTOMATIC AP ISSUE FIXER")
        print("="*70)
        
        issues_fixed = 0
        issues_found = 0
        
        # Fix 1: Ensure NetworkManager is running
        print("\n[1/3] Checking NetworkManager status...")
        if not self.check_networkmanager():
            issues_found += 1
            print("   ❌ NetworkManager is not running")
            print("   🔧 Attempting to start...")
            ret, _, _ = self.run_command(["systemctl", "start", "NetworkManager"], check=False)
            if ret == 0:
                time.sleep(2)
                if self.check_networkmanager():
                    print("   ✓ NetworkManager started")
                    issues_fixed += 1
                else:
                    print("   ✗ Failed to start NetworkManager")
            else:
                print("   ✗ Failed to start NetworkManager")
        else:
            print("   ✓ NetworkManager is running")
        
        # Fix 2: Check connection status
        print("\n[2/3] Checking AP connection status...")
        if con_name:
            target_conn = con_name
        else:
            # Find first AP connection
            ret, stdout, _ = self.run_command(["nmcli", "con", "show"], check=False)
            ap_connections = []
            if ret == 0:
                for line in stdout.strip().split('\n')[1:]:
                    if 'wifi' in line.lower():
                        ap_connections.append(line.split()[0])
            
            if not ap_connections:
                print("   ⚠ No WiFi connections found")
                print("\n" + "="*70)
                print(f"Summary: {issues_fixed}/{issues_found} issues fixed")
                print("="*70)
                return
            
            target_conn = ap_connections[0]
        
        print(f"   Checking: {target_conn}")
        ret, stdout, _ = self.run_command(["nmcli", "con", "show", "--active"], check=False)
        is_active = ret == 0 and target_conn in stdout
        
        if not is_active:
            issues_found += 1
            print(f"   ❌ Connection '{target_conn}' is not active")
            print("   🔧 Attempting to activate...")
            ret, _, stderr = self.run_command(["nmcli", "con", "up", target_conn], check=False)
            if ret == 0:
                print(f"   ✓ Connection activated")
                issues_fixed += 1
            else:
                print(f"   ✗ Failed to activate: {stderr}")
        else:
            print(f"   ✓ Connection is active")
        
        # Fix 3: Restart NetworkManager if there were issues
        print("\n[3/3] Checking if restart needed...")
        if issues_found > issues_fixed:
            print("   ⚠ Some issues remain, restarting NetworkManager...")
            self.run_command(["systemctl", "restart", "NetworkManager"], check=False)
            time.sleep(3)
            print("   ✓ NetworkManager restarted")
            
            # Try to reactivate connection
            if con_name or target_conn:
                print(f"   🔧 Reactivating {target_conn}...")
                ret, _, _ = self.run_command(["nmcli", "con", "up", target_conn], check=False)
                if ret == 0:
                    print("   ✓ Connection reactivated")
                    issues_fixed += 1
        else:
            print("   ✓ No restart needed")
        
        # Summary
        print("\n" + "="*70)
        if issues_found == 0:
            print("✅ No issues found! AP should be working.")
        elif issues_fixed == issues_found:
            print(f"✅ All {issues_fixed} issue(s) fixed! AP should now be working.")
        else:
            print(f"⚠️  Fixed {issues_fixed}/{issues_found} issue(s). Some problems remain.")
        
        print("\n💡 Next steps:")
        print("   1. Check if AP is visible on your phone")
        print("   2. Run: sudo python pinetap.py diagnose")
        print("   3. Check logs: journalctl -u NetworkManager -f")
        print("="*70)

    def diagnose_ap(self, con_name: Optional[str] = None):
        """Run comprehensive diagnostics on AP setup"""
        print("\n" + "="*70)
        print("ACCESS POINT DIAGNOSTICS")
        print("="*70)
        
        # Check all AP connections
        ret, stdout, _ = self.run_command(["nmcli", "con", "show"], check=False)
        ap_connections = []
        if ret == 0:
            for line in stdout.strip().split('\n')[1:]:
                parts = line.split()
                if len(parts) >= 3 and 'wifi' in line.lower():
                    conn_name = parts[0]
                    ap_connections.append(conn_name)
        
        if not ap_connections:
            print("\n❌ No WiFi connections found")
            return
        
        print(f"\n📡 Found {len(ap_connections)} WiFi connection(s):")
        for conn in ap_connections:
            print(f"   - {conn}")
        
        # If specific connection requested, check it
        target_conn = con_name if con_name else ap_connections[0]
        
        print(f"\n🔍 Diagnosing: {target_conn}")
        print("-"*70)
        
        # Get detailed connection info
        ret, stdout, _ = self.run_command(["nmcli", "con", "show", target_conn], check=False)
        if ret != 0:
            print(f"❌ Cannot read connection '{target_conn}'")
            return
        
        # Parse important settings
        config = {}
        for line in stdout.split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                config[key.strip()] = value.strip()
        
        # Display critical settings
        print("\n📋 Configuration:")
        important_keys = [
            '802-11-wireless.mode',
            '802-11-wireless.ssid',
            '802-11-wireless.channel',
            '802-11-wireless.band',
            '802-11-wireless-security.key-mgmt',
            'ipv4.method',
            'ipv4.addresses',
            'connection.autoconnect',
            'GENERAL.DEVICES',
            'GENERAL.STATE'
        ]
        
        for key in important_keys:
            if key in config:
                value = config[key]
                if value and value != '--':
                    print(f"   {key}: {value}")
        
        # Check if connection is active
        ret, stdout, _ = self.run_command(["nmcli", "con", "show", "--active"], check=False)
        is_active = ret == 0 and target_conn in stdout
        
        print(f"\n🔌 Connection Status: {'✓ ACTIVE' if is_active else '✗ INACTIVE'}")
        
        # Check interface status
        if 'GENERAL.DEVICES' in config:
            iface = config['GENERAL.DEVICES']
            if iface and iface != '--':
                print(f"\n🖧  Interface Status: {iface}")
                ret, stdout, _ = self.run_command(["nmcli", "device", "show", iface], check=False)
                if ret == 0:
                    for line in stdout.split('\n'):
                        if any(x in line for x in ['GENERAL.STATE', 'GENERAL.IP4', 'IP4.ADDRESS']):
                            print(f"   {line.strip()}")
        
        # Check IP forwarding
        print("\n🌐 IP Forwarding:")
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "r") as f:
                value = f.read().strip()
            if value == "1":
                print("   ✓ Enabled (internet sharing active)")
            else:
                print("   ✗ Disabled (standalone mode - no internet)")
        except Exception:
            print("   ? Cannot check")
        
        # Check for NAT rules
        print("\n🔧 NAT/Masquerading Status:")
        ret, stdout, _ = self.run_command(["iptables", "-t", "nat", "-L", "-n"], check=False)
        if ret == 0:
            if "MASQUERADE" in stdout:
                print("   ✓ NAT rules present (internet sharing enabled)")
            else:
                print("   ✗ No NAT rules (standalone mode or not configured)")
        else:
            print("   ? Cannot check (requires root)")
        
        # Check rfkill
        print("\n📻 RF Kill Status:")
        ret, stdout, _ = self.run_command(["rfkill", "list"], check=False)
        if ret == 0:
            for line in stdout.split('\n'):
                if 'phy' in line.lower() or 'wireless' in line.lower() or 'blocked' in line.lower():
                    print(f"   {line}")
        else:
            print("   (rfkill not available)")
        
        # Check for dnsmasq process
        print("\n🌐 DHCP Service:")
        ret, stdout, _ = self.run_command(["ps", "aux"], check=False)
        if ret == 0:
            dnsmasq_found = False
            for line in stdout.split('\n'):
                if 'dnsmasq' in line and 'NetworkManager' in line:
                    dnsmasq_found = True
                    print(f"   ✓ dnsmasq running (via NetworkManager)")
                    break
            if not dnsmasq_found:
                print("   ⚠️  dnsmasq not detected")
        
        # Check for standalone DHCP config
        if self.AP_DNSMASQ_CONF.exists():
            print(f"   ✓ Standalone DHCP config exists: {self.AP_DNSMASQ_CONF}")
        
        # Check system journal for errors
        print("\n📝 Recent Logs:")
        ret, stdout, _ = self.run_command(
            ["journalctl", "-u", "NetworkManager", "-n", "20", "--no-pager"],
            check=False
        )
        if ret == 0:
            error_lines = [line for line in stdout.split('\n') if 'error' in line.lower() or 'fail' in line.lower()]
            if error_lines:
                print("   Recent errors found:")
                for line in error_lines[-5:]:  # Show last 5 errors
                    print(f"   {line}")
            else:
                print("   ✓ No recent errors")
        
        # Final recommendations
        print("\n" + "="*70)
        print("💡 TROUBLESHOOTING TIPS:")
        print("="*70)
        
        if not is_active:
            print("❌ Connection is not active!")
            print("   Try: sudo nmcli con up", target_conn)
        
        print("\n🔧 Common fixes:")
        print("   1. Restart NetworkManager: sudo systemctl restart NetworkManager")
        print("   2. Check interface: nmcli device status")
        print("   3. View full config: nmcli con show", target_conn)
        print("   4. Check logs: journalctl -u NetworkManager -f")
        
        print("\n📱 To test from your phone:")
        print("   1. Look for WiFi network in your phone's WiFi list")
        print("   2. If not visible, the AP might not be broadcasting")
        print("   3. Try recreating: sudo python pinetap.py install --ssid YourSSID ...")
        print("="*70)

    def test_root_privileges(self) -> TestResult:
        if self.check_root():
            return TestResult("Root Privileges", TestStatus.PASS, "Running as root")
        else:
            return TestResult("Root Privileges", TestStatus.FAIL, "Not running as root (required for installation)")

    def test_networkmanager_installed(self) -> TestResult:
        ret, _, _ = self.run_command(["which", "nmcli"], check=False)
        if ret == 0:
            return TestResult("NetworkManager Installed", TestStatus.PASS, "nmcli found")
        else:
            return TestResult("NetworkManager Installed", TestStatus.FAIL, "NetworkManager not installed")

    def test_networkmanager_running(self) -> TestResult:
        ret, stdout, _ = self.run_command(["systemctl", "is-active", "NetworkManager"], check=False)
        if ret == 0:
            return TestResult("NetworkManager Running", TestStatus.PASS, "Service is active")
        else:
            return TestResult("NetworkManager Running", TestStatus.FAIL, "Service is not running")

    def test_wifi_interface_exists(self, interface: str = "wlan0") -> TestResult:
        ret, stdout, _ = self.run_command(["nmcli", "device", "status"], check=False)
        if ret == 0 and interface in stdout:
            return TestResult(f"WiFi Interface ({interface})", TestStatus.PASS, "Interface exists")
        else:
            return TestResult(f"WiFi Interface ({interface})", TestStatus.FAIL, "Interface not found")

    def test_multiple_wifi_interfaces(self) -> TestResult:
        interfaces = self.get_available_interfaces()
        wifi_count = sum(1 for info in interfaces.values() if info['type'] == 'wifi')

        if wifi_count >= 2:
            return TestResult("Multiple WiFi Interfaces", TestStatus.PASS, 
                            f"{wifi_count} WiFi interfaces detected (dual WiFi setup possible)")
        elif wifi_count == 1:
            return TestResult("Multiple WiFi Interfaces", TestStatus.WARN, 
                            "Only 1 WiFi interface (use Ethernet for uplink)")
        else:
            return TestResult("Multiple WiFi Interfaces", TestStatus.FAIL, 
                            "No WiFi interfaces detected")

    def test_interface_consistency(self) -> TestResult:
        """Test if interface names match saved mappings"""
        mapping = self.load_interface_mapping()
        if not mapping:
            return TestResult("Interface Consistency", TestStatus.SKIP, 
                            "No saved mappings (normal on first run)")
        
        inconsistencies = []
        for role, info in mapping.items():
            expected_iface = info['interface']
            expected_mac = info['mac']
            current_iface = self.get_interface_by_mac(expected_mac)
            
            if not current_iface:
                inconsistencies.append(f"{role} ({expected_iface}/{expected_mac}) not found")
            elif current_iface != expected_iface:
                inconsistencies.append(f"{role}: {expected_iface}→{current_iface}")
        
        if not inconsistencies:
            return TestResult("Interface Consistency", TestStatus.PASS, 
                            "All interfaces match saved mappings")
        else:
            return TestResult("Interface Consistency", TestStatus.WARN, 
                            "; ".join(inconsistencies))

    def test_uplink_connectivity(self) -> TestResult:
        ret, stdout, _ = self.run_command(["nmcli", "networking", "connectivity", "check"], check=False)
        if ret == 0:
            connectivity = stdout.strip()
            if connectivity == "full":
                return TestResult("Uplink Connectivity", TestStatus.PASS, "Full internet connectivity")
            elif connectivity == "limited":
                return TestResult("Uplink Connectivity", TestStatus.WARN, "Limited connectivity")
            else:
                return TestResult("Uplink Connectivity", TestStatus.FAIL, f"No connectivity ({connectivity})")
        else:
            return TestResult("Uplink Connectivity", TestStatus.FAIL, "Cannot check connectivity")

    def test_dnsmasq_installed(self) -> TestResult:
        ret, _, _ = self.run_command(["which", "dnsmasq"], check=False)
        if ret == 0:
            return TestResult("dnsmasq Installed", TestStatus.PASS, "Package found")
        else:
            return TestResult("dnsmasq Installed", TestStatus.WARN, 
                            "Not installed (NetworkManager can use built-in DHCP)")

    def test_dnsmasq_service_status(self) -> TestResult:
        ret, stdout, _ = self.run_command(["systemctl", "is-enabled", "dnsmasq"], check=False)
        if ret != 0:
            return TestResult("dnsmasq Service", TestStatus.SKIP, "Service not available")

        is_enabled = stdout.strip() == "enabled"
        ret, _, _ = self.run_command(["systemctl", "is-active", "dnsmasq"], check=False)
        is_active = ret == 0

        if not is_enabled and not is_active:
            return TestResult("dnsmasq Service", TestStatus.PASS, "Disabled (correct for AP mode)")
        elif is_enabled or is_active:
            return TestResult("dnsmasq Service", TestStatus.WARN, "Enabled/running (should be disabled for AP)")
        else:
            return TestResult("dnsmasq Service", TestStatus.PASS, "Properly configured")

    def test_nm_config_backup_exists(self) -> TestResult:
        if self.NM_CONFIG_BACKUP.exists():
            return TestResult("Config Backup", TestStatus.PASS, f"Backup exists at {self.NM_CONFIG_BACKUP}")
        else:
            return TestResult("Config Backup", TestStatus.SKIP, "No backup found (normal if not installed yet)")

    def test_nm_config_dnsmasq(self) -> TestResult:
        if not self.NM_CONFIG_PATH.exists():
            return TestResult("NetworkManager dnsmasq Config", TestStatus.FAIL, "Config file not found")

        content = self.NM_CONFIG_PATH.read_text()
        if "dns=dnsmasq" in content:
            return TestResult("NetworkManager dnsmasq Config", TestStatus.PASS, 
                            "dnsmasq configured in NetworkManager")
        else:
            return TestResult("NetworkManager dnsmasq Config", TestStatus.SKIP, 
                            "dnsmasq not configured (will be set during installation)")

    def test_connection_exists(self, con_name: str) -> TestResult:
        if self.connection_exists(con_name):
            return TestResult(f"AP Connection ({con_name})", TestStatus.PASS, "Connection exists")
        else:
            return TestResult(f"AP Connection ({con_name})", TestStatus.FAIL, "Connection not found")

    def test_connection_active(self, con_name: str) -> TestResult:
        ret, stdout, _ = self.run_command(["nmcli", "con", "show", "--active"], check=False)
        if ret == 0 and con_name in stdout:
            return TestResult(f"AP Active ({con_name})", TestStatus.PASS, "Connection is active")
        else:
            return TestResult(f"AP Active ({con_name})", TestStatus.FAIL, "Connection is not active")

    def test_ap_interface_up(self, interface: str = "wlan0") -> TestResult:
        ret, stdout, _ = self.run_command(["nmcli", "device", "status"], check=False)
        if ret != 0:
            return TestResult(f"AP Interface Status ({interface})", TestStatus.FAIL, 
                            "Cannot query device status")

        for line in stdout.split('\n'):
            if interface in line:
                if "connected" in line.lower():
                    return TestResult(f"AP Interface Status ({interface})", TestStatus.PASS, 
                                    "Interface is connected")
                else:
                    return TestResult(f"AP Interface Status ({interface})", TestStatus.WARN, 
                                    f"Interface state: {line.strip()}")

        return TestResult(f"AP Interface Status ({interface})", TestStatus.FAIL, "Interface not found")

    def test_autoconnect_settings(self, con_name: str) -> TestResult:
        ret, stdout, _ = self.run_command(["nmcli", "con", "show", con_name], check=False)
        if ret != 0:
            return TestResult(f"Autoconnect Settings ({con_name})", TestStatus.FAIL, 
                            "Cannot read connection")

        autoconnect_enabled = False
        for line in stdout.split('\n'):
            if "connection.autoconnect:" in line and "yes" in line:
                autoconnect_enabled = True
                break

        if autoconnect_enabled:
            return TestResult(f"Autoconnect Settings ({con_name})", TestStatus.PASS, 
                            "Will reconnect on reboot")
        else:
            return TestResult(f"Autoconnect Settings ({con_name})", TestStatus.WARN, 
                            "Manual start required after reboot")

    def test_ap_configuration(self, con_name: str) -> TestResult:
        ret, stdout, _ = self.run_command(["nmcli", "con", "show", con_name], check=False)
        if ret != 0:
            return TestResult(f"AP Configuration ({con_name})", TestStatus.FAIL, 
                            "Cannot read connection details")

        checks = {
            "mode": False,
            "method": False,
            "address": False,
            "mac_binding": False
        }

        for line in stdout.split('\n'):
            if "802-11-wireless.mode:" in line and "ap" in line:
                checks["mode"] = True
            if "ipv4.method:" in line and ("shared" in line or "manual" in line):
                checks["method"] = True
            if "ipv4.addresses:" in line and len(line.strip()) > 20:
                checks["address"] = True
            if "802-11-wireless.mac-address:" in line and line.split(':')[-1].strip() != "--":
                checks["mac_binding"] = True

        failed = [k for k, v in checks.items() if not v]
        if not failed:
            return TestResult(f"AP Configuration ({con_name})", TestStatus.PASS, 
                            "All settings correct including MAC binding")
        else:
            return TestResult(f"AP Configuration ({con_name})", TestStatus.WARN, 
                            f"Missing/incorrect: {', '.join(failed)}")

    def test_dhcp_service(self, interface: str = "wlan0") -> TestResult:
        ret, stdout, _ = self.run_command(["ps", "aux"], check=False)
        if ret != 0:
            return TestResult("DHCP Service", TestStatus.FAIL, "Cannot check processes")

        if f"dnsmasq" in stdout and interface in stdout:
            return TestResult("DHCP Service", TestStatus.PASS, f"dnsmasq running for {interface}")
        else:
            return TestResult("DHCP Service", TestStatus.WARN, f"dnsmasq not detected for {interface}")

    def test_ip_forwarding(self) -> TestResult:
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "r") as f:
                value = f.read().strip()
            if value == "1":
                return TestResult("IP Forwarding", TestStatus.PASS, "Enabled (internet sharing on)")
            else:
                return TestResult("IP Forwarding", TestStatus.PASS, 
                                "Disabled (standalone/no-share mode)")
        except Exception as e:
            return TestResult("IP Forwarding", TestStatus.FAIL, f"Cannot check: {e}")

    def test_firewall_rules(self) -> TestResult:
        ret, stdout, _ = self.run_command(["iptables", "-t", "nat", "-L"], check=False)
        if ret != 0:
            return TestResult("Firewall Rules", TestStatus.SKIP, 
                            "Cannot check iptables (requires root)")

        if "MASQUERADE" in stdout or "POSTROUTING" in stdout:
            return TestResult("Firewall Rules", TestStatus.PASS, "NAT rules detected (internet sharing)")
        else:
            return TestResult("Firewall Rules", TestStatus.PASS, 
                            "No NAT rules (standalone mode or not configured)")

    def test_ap_visibility(self, ssid: str, timeout: int = 5) -> TestResult:
        self.log(f"Scanning for SSID '{ssid}' (this may take {timeout} seconds)...", "DEBUG")
        ret, stdout, _ = self.run_command(["nmcli", "device", "wifi", "list"], check=False)
        if ret != 0:
            return TestResult(f"AP Visibility ({ssid})", TestStatus.SKIP, 
                            "Cannot scan from AP interface")

        if ssid in stdout:
            return TestResult(f"AP Visibility ({ssid})", TestStatus.PASS, "SSID visible in scan")
        else:
            return TestResult(f"AP Visibility ({ssid})", TestStatus.WARN, 
                            "SSID not detected (may need external device to verify)")

    def run_test_suite(self, test_type: str = "all", con_name: Optional[str] = None, 
                       interface: str = "wlan0", ssid: Optional[str] = None) -> List[TestResult]:
        results = []

        if test_type in ["all", "prerequisites", "pre"]:
            self.log("=== Testing Prerequisites ===")
            results.append(self.test_root_privileges())
            results.append(self.test_networkmanager_installed())
            results.append(self.test_networkmanager_running())
            results.append(self.test_wifi_interface_exists(interface))
            results.append(self.test_multiple_wifi_interfaces())
            results.append(self.test_uplink_connectivity())
            results.append(self.test_dnsmasq_installed())
            results.append(self.test_interface_consistency())

        if test_type in ["all", "configuration", "config"]:
            self.log("=== Testing Configuration ===")
            results.append(self.test_dnsmasq_service_status())
            results.append(self.test_nm_config_backup_exists())
            results.append(self.test_nm_config_dnsmasq())

        if test_type in ["all", "connection", "conn"] and con_name:
            self.log(f"=== Testing AP Connection ({con_name}) ===")
            results.append(self.test_connection_exists(con_name))
            results.append(self.test_connection_active(con_name))
            results.append(self.test_autoconnect_settings(con_name))
            results.append(self.test_ap_interface_up(interface))
            results.append(self.test_ap_configuration(con_name))

        if test_type in ["all", "services", "svc"]:
            self.log("=== Testing Services ===")
            results.append(self.test_dhcp_service(interface))
            results.append(self.test_ip_forwarding())
            if self.check_root():
                results.append(self.test_firewall_rules())

        if test_type in ["all", "visibility", "vis"] and ssid:
            self.log("=== Testing AP Visibility ===")
            results.append(self.test_ap_visibility(ssid))

        return results

    def print_test_results(self, results: List[TestResult], summary: bool = True):
        print("\n" + "="*60)
        print("TEST RESULTS")
        print("="*60)

        for result in results:
            print(result)

        if summary:
            print("\n" + "-"*60)
            passed = sum(1 for r in results if r.status == TestStatus.PASS)
            failed = sum(1 for r in results if r.status == TestStatus.FAIL)
            warned = sum(1 for r in results if r.status == TestStatus.WARN)
            skipped = sum(1 for r in results if r.status == TestStatus.SKIP)
            total = len(results)

            print(f"Summary: {passed} passed, {failed} failed, {warned} warnings, {skipped} skipped ({total} total)")

            if failed > 0:
                print("\n⚠️ Some tests failed. Please review the issues above.")
                return False
            elif warned > 0:
                print("\n✓ All critical tests passed, but there are some warnings.")
                return True
            else:
                print("\n✓ All tests passed!")
                return True

        return True


def main():
    parser = argparse.ArgumentParser(
        description="PiNetAP - Dual WiFi Access Point Manager for Raspberry Pi (Enhanced - Fixed --no-share)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Show available network interfaces with MAC addresses
  sudo python pinetap.py interfaces -d

  # Standalone AP (single WiFi, no internet) - Open Network
  sudo python pinetap.py install --ssid OfflineNetwork --security open \\
       --ap-interface wlan0 --no-share --autoconnect

  # Standalone AP (single WiFi, no internet) - Secured
  sudo python pinetap.py install --ssid SecureOffline --password Pass12345 \\
       --security wpa2-psk --ap-interface wlan0 --no-share --autoconnect

  # Single WiFi + Ethernet setup (internet sharing)
  sudo python pinetap.py install --ssid MyHotspot --password Pass12345 \\
       --security wpa2-psk --ap-interface wlan0 --autoconnect

  # Dual WiFi setup (one for AP, one for uplink)
  sudo python pinetap.py install --ssid MyHotspot --password Pass12345 \\
       --security wpa2-psk --ap-interface wlan1 \\
       --uplink-ssid HomeWiFi --uplink-password HomePass \\
       --uplink-interface wlan0

  # WPA3-SAE security (most secure)
  sudo python pinetap.py install --ssid SecureAP --password Pass12345 \\
       --security wpa3-sae --ap-interface wlan0 --autoconnect

  # List all managed connections
  sudo python pinetap.py managed

  # Remove specific AP
  sudo python pinetap.py uninstall --connection MyHotspot-AP

  # Remove all managed APs
  sudo python pinetap.py uninstall --all

Note: 
  - Always use 'sudo' or run as root
  - Connections are bound to MAC addresses
  - Interface names (wlan0/wlan1) may change after reboot
  - Your AP will continue working regardless of name changes
  - Password requirements: WPA2/WPA3 require 8-63 characters
  - Open networks should not have a password
  - --no-share properly disables internet sharing (IP forwarding + NAT disabled)
"""
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Interfaces command
    interfaces_parser = subparsers.add_parser("interfaces", 
                                             help="List available network interfaces")
    interfaces_parser.add_argument("-d", "--detailed", action="store_true",
                                  help="Show detailed information including MAC addresses")

    # Managed command
    subparsers.add_parser("managed", help="List all PiNetAP-managed connections")

    # Install command
    install_parser = subparsers.add_parser("install", help="Create WiFi Access Point")
    install_parser.add_argument("--ssid", required=True, help="AP SSID (network name)")
    install_parser.add_argument("--password", help="AP WiFi password (required for WPA2/WPA3, omit for open)")
    install_parser.add_argument("--security", 
                               choices=["open", "wpa2-psk", "wpa3-sae"],
                               default="wpa2-psk",
                               help="Security mode (default: wpa2-psk)")
    install_parser.add_argument("--ap-interface", required=True, 
                               help="WiFi interface for AP (e.g., wlan0, wlan1)")
    install_parser.add_argument("--uplink-ssid", help="Uplink WiFi SSID to connect to")
    install_parser.add_argument("--uplink-password", help="Uplink WiFi password")
    install_parser.add_argument("--uplink-interface", 
                               help="Interface for uplink connection (e.g., wlan0, eth0)")
    install_parser.add_argument("--ip", default="192.168.4.1/24",
                               help="AP IP address and subnet (default: 192.168.4.1/24)")
    install_parser.add_argument("--channel", type=int, default=3,
                               help="WiFi channel (default: 3)")
    install_parser.add_argument("--mac", help="Custom cloned MAC address for AP")
    install_parser.add_argument("--autoconnect", action="store_true",
                               help="Enable autoconnect on boot")
    install_parser.add_argument("--connection", help="AP connection name (default: SSID-AP)")
    install_parser.add_argument("--no-share", action="store_true",
                               help="Don't share internet (standalone AP - disables NAT and IP forwarding)")
    install_parser.add_argument("--test", action="store_true",
                               help="Run tests after installation")

    # Uninstall command
    uninstall_parser = subparsers.add_parser("uninstall", help="Remove WiFi Access Point")
    uninstall_parser.add_argument("--connection", 
                                 help="Connection name to remove")
    uninstall_parser.add_argument("--all", action="store_true",
                                 help="Remove all PiNetAP-managed connections")
    uninstall_parser.add_argument("--keep-config", action="store_true",
                                 help="Keep NetworkManager configuration changes")

    # List command
    subparsers.add_parser("list", help="List all NetworkManager connections")

    # Status command
    status_parser = subparsers.add_parser("status", help="Show AP connection status")
    status_parser.add_argument("--connection", help="Connection name (optional)")

    # Diagnose command
    diagnose_parser = subparsers.add_parser("diagnose", help="Run comprehensive AP diagnostics")
    diagnose_parser.add_argument("--connection", help="Connection name (optional, uses first WiFi connection if not specified)")
    
    # Fix command
    fix_parser = subparsers.add_parser("fix", help="Attempt to fix common AP issues")
    fix_parser.add_argument("--connection", help="Connection name to fix (optional)")

    # Test command
    test_parser = subparsers.add_parser("test", help="Run diagnostic tests")
    test_parser.add_argument("--type", 
                            choices=["all", "prerequisites", "pre", "configuration", "config",
                                   "connection", "conn", "services", "svc", "visibility", "vis"],
                            default="all", help="Type of tests to run")
    test_parser.add_argument("--connection", help="Connection name (required for connection tests)")
    test_parser.add_argument("--ssid", help="SSID (required for visibility tests)")
    test_parser.add_argument("--interface", default="wlan0", 
                            help="WiFi interface (default: wlan0)")

    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    manager = PiNetAP(verbose=args.verbose)

    # Handle non-root commands
    if args.command == "interfaces":
        manager.list_interfaces(detailed=getattr(args, 'detailed', False))
        return 0

    if args.command == "managed":
        manager.list_managed_connections()
        return 0

    if args.command in ["list", "status", "test", "diagnose", "fix"]:
        if args.command == "list":
            manager.list_connections()
        elif args.command == "status":
            if hasattr(args, 'connection') and args.connection:
                ret, stdout, _ = manager.run_command(["nmcli", "con", "show", args.connection], check=False)
                if ret == 0:
                    print(f"\nStatus of '{args.connection}':")
                    print(stdout)
                else:
                    print(f"Connection '{args.connection}' not found")
            else:
                print("Please specify --connection")
                return 1
        elif args.command == "diagnose":
            manager.diagnose_ap(args.connection if hasattr(args, 'connection') else None)
        elif args.command == "fix":
            if not manager.check_root():
                manager.log("Fix command requires root privileges. Please run with sudo.", "ERROR")
                return 1
            manager.fix_ap_issues(args.connection if hasattr(args, 'connection') else None)
        elif args.command == "test":
            if args.type in ["services", "svc", "all"] and not manager.check_root():
                manager.log("Some tests require root privileges. Run with sudo for complete results.", "WARN")

            results = manager.run_test_suite(
                test_type=args.type,
                con_name=args.connection,
                interface=args.interface,
                ssid=args.ssid
            )
            success = manager.print_test_results(results)
            return 0 if success else 1

        return 0

    # Root-required commands
    if not manager.check_root():
        manager.log("This command requires root privileges. Please run with sudo.", "ERROR")
        return 1

    if not manager.check_networkmanager():
        manager.log("NetworkManager is not running. Please install and start NetworkManager.", "ERROR")
        return 1

    if args.command == "install":
        # Parse security mode
        security_mode = SecurityMode(args.security)
        
        # Validate password
        is_valid, error_msg = manager.validate_password(args.password, security_mode)
        if not is_valid:
            manager.log(f"Password validation failed: {error_msg}", "ERROR")
            return 1

        # Connect to uplink if specified
        if args.uplink_ssid:
            if not args.uplink_interface:
                manager.log("--uplink-interface is required when using --uplink-ssid", "ERROR")
                return 1

            success = manager.connect_to_uplink(
                args.uplink_ssid,
                args.uplink_password,
                args.uplink_interface,
                autoconnect=args.autoconnect
            )

            if not success:
                manager.log("Failed to connect to uplink. Continuing with AP creation...", "WARN")

        # Configure NetworkManager
        manager.backup_nm_config()
        manager.modify_nm_config(add_dnsmasq=True)
        manager.manage_dnsmasq_service("disable")
        manager.reload_networkmanager()

        # Create the AP
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
            security_mode=security_mode
        )

        if success:
            # Save interface mappings
            manager.save_interface_mapping(
                ap_interface=args.ap_interface,
                uplink_interface=args.uplink_interface
            )

            if args.autoconnect:
                manager.log("\n✓ Autoconnect enabled: AP will start automatically on reboot", "INFO")
                manager.log("  Connection is bound to MAC address - interface name changes won't affect it", "INFO")
            else:
                manager.log("\nAutoconnect disabled: Use 'nmcli con up CONNECTION-NAME' to start manually", "INFO")

        # Run tests if requested
        if success and args.test:
            manager.log("\n=== Running post-installation tests ===")
            time.sleep(2)

            con_name = args.connection if args.connection else f"{args.ssid}-AP"
            results = manager.run_test_suite(
                test_type="all",
                con_name=con_name,
                interface=args.ap_interface,
                ssid=args.ssid
            )
            manager.print_test_results(results)

        return 0 if success else 1

    elif args.command == "uninstall":
        if args.all:
            success = manager.remove_all_managed_aps(restore_config=not args.keep_config)
        elif args.connection:
            success = manager.remove_ap(
                con_name=args.connection,
                restore_config=not args.keep_config
            )
        else:
            manager.log("Please specify --connection or --all", "ERROR")
            return 1
        
        return 0 if success else 1

    return 0


if __name__ == "__main__":
    sys.exit(main())