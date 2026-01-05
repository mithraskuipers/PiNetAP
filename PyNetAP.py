#!/usr/bin/env python3
"""
PiNetAP - Dual WiFi Access Point Manager for Raspberry Pi
Create WiFi hotspots with internet sharing from WiFi/Ethernet uplinks
"""

import argparse
import subprocess
import sys
import os
import time
import re
from typing import Optional, Tuple, Dict, List
from pathlib import Path
from enum import Enum


class TestStatus(Enum):
    PASS = "✓"
    FAIL = "✗"
    WARN = "⚠"
    SKIP = "○"


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
        
        print("\n" + "="*70)
        print("AVAILABLE NETWORK INTERFACES")
        print("="*70)
        
        if detailed:
            print(f"{'Interface':<15} {'Type':<15} {'State':<20} {'Connection':<20}")
        else:
            print(f"{'Interface':<15} {'Type':<15} {'State':<20}")
        print("-"*70)
        
        wifi_count = 0
        eth_count = 0
        wifi_list = []
        eth_list = []
        
        for name, info in interfaces.items():
            connection = self.get_interface_connection(name) if detailed else None
            conn_display = connection if connection else "--"
            
            if detailed:
                print(f"{name:<15} {info['type']:<15} {info['state']:<20} {conn_display:<20}")
            else:
                print(f"{name:<15} {info['type']:<15} {info['state']:<20}")
            
            if info['type'] == 'wifi':
                wifi_count += 1
                wifi_list.append(name)
            elif info['type'] == 'ethernet':
                eth_count += 1
                eth_list.append(name)
        
        print("-"*70)
        print(f"\nSummary: {wifi_count} WiFi, {eth_count} Ethernet interface(s)")
        
        if wifi_list:
            print(f"WiFi interfaces: {', '.join(wifi_list)}")
        if eth_list:
            print(f"Ethernet interfaces: {', '.join(eth_list)}")
        
        print("\n" + "="*70)
        print("SETUP RECOMMENDATIONS")
        print("="*70)
        
        if wifi_count < 1:
            print("\n❌ No WiFi Setup Possible")
            print("   No WiFi interfaces detected!")
            print("   You need at least 1 WiFi interface for AP mode.")
        elif wifi_count == 1:
            print("\n💡 Single WiFi Setup Options")
            print(f"   AP Interface:  {wifi_list[0]} (for hotspot)")
            
            print("\n   Option 1: Standalone (No Internet)")
            print("   Perfect for: File sharing, local services, offline networks")
            print(f"   sudo pinetap.py install --ssid MyHotspot --password Pass123 \\")
            print(f"       --ap-interface {wifi_list[0]} --no-share --autoconnect")
            
            if eth_count > 0:
                print(f"\n   Option 2: Internet via Ethernet")
                print(f"   Uplink:        {eth_list[0]} (for internet)")
                print(f"   sudo pinetap.py install --ssid MyHotspot --password Pass123 \\")
                print(f"       --ap-interface {wifi_list[0]} --autoconnect")
            else:
                print("\n   Note: No Ethernet detected. Standalone mode only.")
                print("   Connect clients to access local services on the Pi.")
        else:
            print("\n🎉 Dual WiFi Setup Available!")
            print(f"   AP Interface:  {wifi_list[0]} (for hotspot)")
            print(f"   Uplink:        {wifi_list[1]} (for internet)")
            if eth_count > 0:
                print(f"   Alternative:   {eth_list[0]} (for internet)")
            
            print("\n   Option 1: Dual WiFi with Internet")
            print(f"   sudo pinetap.py install --ssid MyHotspot --password Pass123 \\")
            print(f"       --ap-interface {wifi_list[0]} \\")
            print(f"       --uplink-ssid HomeWiFi --uplink-password HomePass \\")
            print(f"       --uplink-interface {wifi_list[1]} --autoconnect")
            
            print("\n   Option 2: Standalone (No Internet)")
            print(f"   sudo pinetap.py install --ssid MyHotspot --password Pass123 \\")
            print(f"       --ap-interface {wifi_list[0]} --no-share --autoconnect")
        
        print("\n" + "="*70)
    
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
    
    def check_interface_available(self, interface: str, for_ap: bool = True) -> Tuple[bool, str]:
        interfaces = self.get_available_interfaces()
        
        if interface not in interfaces:
            return False, f"Interface {interface} not found"
        
        if interfaces[interface]['type'] != 'wifi':
            if for_ap:
                return False, f"Interface {interface} is not a WiFi interface (type: {interfaces[interface]['type']})"
        
        current_conn = self.get_interface_connection(interface)
        if current_conn and for_ap:
            return False, f"Interface {interface} is already in use by connection: {current_conn}"
        
        return True, "Available"
    
    def connect_to_uplink(self, uplink_ssid: str, uplink_password: Optional[str], 
                         uplink_interface: str, autoconnect: bool = True) -> bool:
        self.log(f"Connecting to uplink network: {uplink_ssid} on {uplink_interface}")
        
        available, msg = self.check_interface_available(uplink_interface, for_ap=False)
        if not available and "already in use" not in msg:
            self.log(f"Uplink interface check: {msg}", "WARN")
        
        conn_name = f"{uplink_ssid}-Uplink"
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
        share_internet: bool = True
    ) -> bool:
        available, msg = self.check_interface_available(ap_interface, for_ap=True)
        if not available:
            self.log(f"Cannot use {ap_interface}: {msg}", "ERROR")
            return False
        
        if not con_name:
            con_name = f"{ssid}-AP"
        
        self.delete_connection(con_name)
        
        self.log(f"Creating access point: {ssid} on {ap_interface}")
        
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
        
        ipv4_method = "shared" if share_internet else "manual"
        
        modifications = [
            (["wifi.band", "bg"], "Set band to 2.4GHz"),
            (["wifi.channel", str(channel)], f"Set channel to {channel}"),
            (["ipv4.method", ipv4_method, "ipv4.address", ip_address], f"Set IP to {ip_address}"),
            (["ipv6.method", "disabled"], "Disable IPv6"),
        ]
        
        if autoconnect:
            modifications.append(
                (["connection.autoconnect-priority", "5"], "Set autoconnect priority")
            )
        
        if mac_address:
            modifications.append(
                (["wifi.cloned-mac-address", mac_address], f"Set MAC to {mac_address}")
            )
        
        if password:
            modifications.extend([
                (["wifi-sec.key-mgmt", "wpa-psk"], "Set WPA-PSK security"),
                (["wifi-sec.psk", password], "Set password"),
            ])
        
        for args, description in modifications:
            cmd = ["nmcli", "con", "modify", con_name] + args
            ret, _, stderr = self.run_command(cmd, check=False)
            if ret != 0:
                self.log(f"Warning: {description} failed: {stderr}", "WARN")
        
        self.log("Activating access point...")
        ret, _, stderr = self.run_command(
            ["nmcli", "con", "up", con_name],
            check=False
        )
        
        if ret != 0:
            self.log(f"Failed to activate AP: {stderr}", "ERROR")
            return False
        
        autoconnect_msg = " (will reconnect on reboot)" if autoconnect else ""
        sharing_msg = " with internet sharing" if share_internet else " (standalone)"
        self.log(f"Access point '{ssid}' created successfully on {ap_interface}{sharing_msg}{autoconnect_msg}!", "SUCCESS")
        return True
    
    def remove_ap(self, con_name: str, restore_config: bool = True) -> bool:
        self.log(f"Removing access point: {con_name}")
        
        if not self.delete_connection(con_name):
            self.log(f"Connection {con_name} not found or failed to delete", "WARN")
        
        if restore_config:
            self.restore_nm_config()
            self.manage_dnsmasq_service("enable")
            self.reload_networkmanager()
        
        self.log("Access point removed successfully!", "SUCCESS")
        return True
    
    def list_connections(self):
        ret, stdout, _ = self.run_command(["nmcli", "con", "show"], check=False)
        if ret == 0:
            print("\nNetworkManager Connections:")
            print(stdout)
    
    def show_ap_status(self, con_name: str):
        ret, stdout, _ = self.run_command(["nmcli", "con", "show", con_name], check=False)
        if ret == 0:
            print(f"\nStatus of '{con_name}':")
            print(stdout)
        else:
            print(f"Connection '{con_name}' not found")
    
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
            return TestResult("dnsmasq Service", TestStatus.PASS, 
                            "Disabled (correct for AP mode)")
        elif is_enabled or is_active:
            return TestResult("dnsmasq Service", TestStatus.WARN, 
                            "Enabled/running (should be disabled for AP)")
        else:
            return TestResult("dnsmasq Service", TestStatus.PASS, "Properly configured")
    
    def test_nm_config_backup_exists(self) -> TestResult:
        if self.NM_CONFIG_BACKUP.exists():
            return TestResult("Config Backup", TestStatus.PASS, 
                            f"Backup exists at {self.NM_CONFIG_BACKUP}")
        else:
            return TestResult("Config Backup", TestStatus.SKIP, 
                            "No backup found (normal if not installed yet)")
    
    def test_nm_config_dnsmasq(self) -> TestResult:
        if not self.NM_CONFIG_PATH.exists():
            return TestResult("NetworkManager dnsmasq Config", TestStatus.FAIL, 
                            "Config file not found")
        
        content = self.NM_CONFIG_PATH.read_text()
        if "dns=dnsmasq" in content:
            return TestResult("NetworkManager dnsmasq Config", TestStatus.PASS, 
                            "dnsmasq configured in NetworkManager")
        else:
            return TestResult("NetworkManager dnsmasq Config", TestStatus.SKIP, 
                            "dnsmasq not configured (will be set during installation)")
    
    def test_connection_exists(self, con_name: str) -> TestResult:
        if self.connection_exists(con_name):
            return TestResult(f"AP Connection ({con_name})", TestStatus.PASS, 
                            "Connection exists")
        else:
            return TestResult(f"AP Connection ({con_name})", TestStatus.FAIL, 
                            "Connection not found")
    
    def test_connection_active(self, con_name: str) -> TestResult:
        ret, stdout, _ = self.run_command(["nmcli", "con", "show", "--active"], check=False)
        if ret == 0 and con_name in stdout:
            return TestResult(f"AP Active ({con_name})", TestStatus.PASS, 
                            "Connection is active")
        else:
            return TestResult(f"AP Active ({con_name})", TestStatus.FAIL, 
                            "Connection is not active")
    
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
        
        return TestResult(f"AP Interface Status ({interface})", TestStatus.FAIL, 
                        "Interface not found")
    
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
        ret, stdout, _ = self.run_command(["nmcli", "con", "show", con_name], check=False)
        if ret != 0:
            return TestResult(f"AP Configuration ({con_name})", TestStatus.FAIL, 
                            "Cannot read connection details")
        
        checks = {
            "mode": False,
            "method": False,
            "address": False
        }
        
        for line in stdout.split('\n'):
            if "802-11-wireless.mode:" in line and "ap" in line:
                checks["mode"] = True
            if "ipv4.method:" in line and ("shared" in line or "manual" in line):
                checks["method"] = True
            if "ipv4.addresses:" in line and len(line.strip()) > 20:
                checks["address"] = True
        
        failed = [k for k, v in checks.items() if not v]
        if not failed:
            return TestResult(f"AP Configuration ({con_name})", TestStatus.PASS, 
                            "All settings correct")
        else:
            return TestResult(f"AP Configuration ({con_name})", TestStatus.WARN, 
                            f"Missing/incorrect: {', '.join(failed)}")
    
    def test_dhcp_service(self, interface: str = "wlan0") -> TestResult:
        ret, stdout, _ = self.run_command(["ps", "aux"], check=False)
        if ret != 0:
            return TestResult("DHCP Service", TestStatus.FAIL, "Cannot check processes")
        
        if f"dnsmasq" in stdout and interface in stdout:
            return TestResult("DHCP Service", TestStatus.PASS, 
                            f"dnsmasq running for {interface}")
        else:
            return TestResult("DHCP Service", TestStatus.WARN, 
                            f"dnsmasq not detected for {interface}")
    
    def test_ip_forwarding(self) -> TestResult:
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "r") as f:
                value = f.read().strip()
                if value == "1":
                    return TestResult("IP Forwarding", TestStatus.PASS, "Enabled")
                else:
                    return TestResult("IP Forwarding", TestStatus.WARN, 
                                    "Disabled (may be needed for internet sharing)")
        except Exception as e:
            return TestResult("IP Forwarding", TestStatus.FAIL, f"Cannot check: {e}")
    
    def test_firewall_rules(self) -> TestResult:
        ret, stdout, _ = self.run_command(["iptables", "-t", "nat", "-L"], check=False)
        if ret != 0:
            return TestResult("Firewall Rules", TestStatus.SKIP, 
                            "Cannot check iptables (requires root)")
        
        if "MASQUERADE" in stdout or "POSTROUTING" in stdout:
            return TestResult("Firewall Rules", TestStatus.PASS, 
                            "NAT rules detected")
        else:
            return TestResult("Firewall Rules", TestStatus.WARN, 
                            "No NAT rules found (needed for internet sharing)")
    
    def test_ap_visibility(self, ssid: str, timeout: int = 5) -> TestResult:
        self.log(f"Scanning for SSID '{ssid}' (this may take {timeout} seconds)...", "DEBUG")
        
        ret, stdout, _ = self.run_command(["nmcli", "device", "wifi", "list"], check=False)
        
        if ret != 0:
            return TestResult(f"AP Visibility ({ssid})", TestStatus.SKIP, 
                            "Cannot scan from AP interface")
        
        if ssid in stdout:
            return TestResult(f"AP Visibility ({ssid})", TestStatus.PASS, 
                            "SSID visible in scan")
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
                print("\n⚠️  Some tests failed. Please review the issues above.")
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
        description="PiNetAP - Dual WiFi Access Point Manager for Raspberry Pi",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Show available network interfaces
  %(prog)s interfaces
  
  # Standalone AP (single WiFi, no internet)
  sudo %(prog)s install --ssid OfflineNetwork --password Pass123 \\
      --ap-interface wlan0 --no-share --autoconnect
  
  # Single WiFi + Ethernet setup (internet sharing)
  sudo %(prog)s install --ssid MyHotspot --password Pass123 \\
      --ap-interface wlan0 --autoconnect
  
  # Dual WiFi setup (one for AP, one for uplink)
  sudo %(prog)s install --ssid MyHotspot --password Pass123 \\
      --ap-interface wlan1 \\
      --uplink-ssid HomeWiFi --uplink-password HomePass \\
      --uplink-interface wlan0
  
  # Standalone AP (no internet sharing)
  sudo %(prog)s install --ssid LocalNetwork --password Pass123 \\
      --ap-interface wlan0 --no-share
  
  # Custom configuration
  sudo %(prog)s install --ssid CustomAP --password Pass123 \\
      --ap-interface wlan1 --ip 10.0.0.1/24 --channel 6
  
  # Remove AP
  sudo %(prog)s uninstall --connection MyHotspot-AP
  
  # List all connections
  %(prog)s list
  
  # Test setup
  %(prog)s test --type prerequisites
  sudo %(prog)s test --type all --connection MyHotspot-AP --ssid MyHotspot
  
  # Install with automatic testing
  sudo %(prog)s install --ssid TestAP --password Pass123 \\
      --ap-interface wlan0 --test
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    interfaces_parser = subparsers.add_parser("interfaces", help="List available network interfaces")
    interfaces_parser.add_argument("-d", "--detailed", action="store_true", 
                                  help="Show detailed information including current connections")
    
    install_parser = subparsers.add_parser("install", help="Create WiFi Access Point")
    install_parser.add_argument("--ssid", required=True, help="AP SSID (network name)")
    install_parser.add_argument("--password", help="AP WiFi password (omit for open network)")
    install_parser.add_argument("--ap-interface", required=True, help="WiFi interface for AP (e.g., wlan0, wlan1)")
    install_parser.add_argument("--uplink-ssid", help="Uplink WiFi SSID to connect to")
    install_parser.add_argument("--uplink-password", help="Uplink WiFi password")
    install_parser.add_argument("--uplink-interface", help="Interface for uplink connection (e.g., wlan0, eth0)")
    install_parser.add_argument("--ip", default="192.168.4.1/24", help="AP IP address and subnet (default: 192.168.4.1/24)")
    install_parser.add_argument("--channel", type=int, default=3, help="WiFi channel (default: 3)")
    install_parser.add_argument("--mac", help="Custom MAC address for AP")
    install_parser.add_argument("--autoconnect", action="store_true", help="Enable autoconnect on boot")
    install_parser.add_argument("--connection", help="AP connection name (default: SSID-AP)")
    install_parser.add_argument("--no-share", action="store_true", help="Don't share internet (standalone AP)")
    install_parser.add_argument("--test", action="store_true", help="Run tests after installation")
    
    uninstall_parser = subparsers.add_parser("uninstall", help="Remove WiFi Access Point")
    uninstall_parser.add_argument("--connection", required=True, help="Connection name to remove")
    uninstall_parser.add_argument("--keep-config", action="store_true", help="Keep NetworkManager configuration changes")
    
    subparsers.add_parser("list", help="List all NetworkManager connections")
    
    status_parser = subparsers.add_parser("status", help="Show AP connection status")
    status_parser.add_argument("--connection", required=True, help="Connection name")
    
    test_parser = subparsers.add_parser("test", help="Run diagnostic tests")
    test_parser.add_argument("--type", 
                            choices=["all", "prerequisites", "pre", "configuration", "config", 
                                    "connection", "conn", "services", "svc", "visibility", "vis"],
                            default="all",
                            help="Type of tests to run")
    test_parser.add_argument("--connection", help="Connection name (required for connection tests)")
    test_parser.add_argument("--ssid", help="SSID (required for visibility tests)")
    test_parser.add_argument("--interface", default="wlan0", help="WiFi interface (default: wlan0)")
    
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    manager = PiNetAP(verbose=args.verbose)
    
    if args.command == "interfaces":
        manager.list_interfaces(detailed=getattr(args, 'detailed', False))
        return 0
    
    if args.command in ["list", "status", "test"]:
        if args.command == "list":
            manager.list_connections()
        elif args.command == "status":
            manager.show_ap_status(args.connection)
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
    
    if not manager.check_root():
        manager.log("This command requires root privileges. Please run with sudo.", "ERROR")
        return 1
    
    if not manager.check_networkmanager():
        manager.log("NetworkManager is not running. Please install and start NetworkManager.", "ERROR")
        return 1
    
    if args.command == "install":
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
        
        manager.backup_nm_config()
        manager.modify_nm_config(add_dnsmasq=True)
        manager.manage_dnsmasq_service("disable")
        manager.reload_networkmanager()
        
        success = manager.create_ap(
            ssid=args.ssid,
            password=args.password,
            ap_interface=args.ap_interface,
            ip_address=args.ip,
            channel=args.channel,
            mac_address=args.mac,
            autoconnect=args.autoconnect,
            con_name=args.connection,
            share_internet=not args.no_share
        )
        
        if success:
            if args.autoconnect:
                manager.log("\nAutoconnect enabled: AP will start automatically on reboot", "INFO")
            else:
                manager.log("\nAutoconnect disabled: Use 'nmcli con up CONNECTION-NAME' to start manually", "INFO")
        
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
        success = manager.remove_ap(
            con_name=args.connection,
            restore_config=not args.keep_config
        )
        return 0 if success else 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())