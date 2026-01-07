#!/usr/bin/env python3
"""
PiNetAP Core - Core Classes and Configuration
Contains base classes, enums, and configuration management
"""

import subprocess
import os
import time
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


class PiNetAPCore:
    """Core configuration and utility methods for PiNetAP"""

    NM_CONFIG_PATH = Path("/etc/NetworkManager/NetworkManager.conf")
    NM_CONFIG_BACKUP = Path("/etc/NetworkManager/NetworkManager.conf.backup")
    PINETAP_CONFIG_DIR = Path("/etc/pinetap")
    INTERFACE_CONFIG = PINETAP_CONFIG_DIR / "interface_mapping.json"
    CONNECTIONS_CONFIG = PINETAP_CONFIG_DIR / "managed_connections.json"
    DNSMASQ_CONF_DIR = Path("/etc/NetworkManager/dnsmasq.d")
    AP_DNSMASQ_CONF = DNSMASQ_CONF_DIR / "pinetap-ap.conf"
    SYSTEM_STATE_CONFIG = PINETAP_CONFIG_DIR / "original_state.json"

    # Captive portal paths
    CAPTIVE_PORTAL_DIR = Path("/var/www/pinetap-portal")
    CAPTIVE_PORTAL_HTML = CAPTIVE_PORTAL_DIR / "index.html"
    CAPTIVE_PORTAL_SERVICE = Path("/etc/systemd/system/pinetap-portal.service")
    CAPTIVE_PORTAL_SCRIPT = PINETAP_CONFIG_DIR / "portal_server.py"

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
            return True, ""

        min_len = requirements['min_length']
        max_len = requirements['max_length']

        if len(password) < min_len:
            return False, f"Password too short. {requirements['description']} (current length: {len(password)})"

        if len(password) > max_len:
            return False, f"Password too long. {requirements['description']} (current length: {len(password)})"

        return True, ""

    # Connection Management
    def save_managed_connection(self, con_name: str, ap_interface: str, ssid: str,
                               security_mode: str, share_internet: bool, captive_portal: bool = False):
        """Save information about managed connections for easy uninstall"""
        connections = self.load_managed_connections()

        connections[con_name] = {
            'ssid': ssid,
            'interface': ap_interface,
            'security_mode': security_mode,
            'share_internet': share_internet,
            'captive_portal': captive_portal,
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

    # Interface Management
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
            return True

        all_consistent = True

        for role, info in mapping.items():
            expected_iface = info['interface']
            expected_mac = info['mac']

            current_mac = self.get_interface_mac(expected_iface)

            if current_mac and current_mac.lower() == expected_mac.lower():
                self.log(f"✓ {role.upper()} interface {expected_iface} consistent (MAC: {expected_mac})", "INFO")
            else:
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

    # NetworkManager Configuration
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
        """
        Modify NetworkManager config to use dnsmasq ONLY if needed.
        For standalone APs without captive portal, we DON'T need dnsmasq at all.
        NetworkManager's built-in DHCP (shared mode) handles everything.
        """
        try:
            if not add_dnsmasq:
                self.log("Skipping dnsmasq config (not needed)")
                return True
                
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

    def list_connections(self):
        ret, stdout, _ = self.run_command(["nmcli", "con", "show"], check=False)
        if ret == 0:
            print("\nNetworkManager Connections:")
            print(stdout)