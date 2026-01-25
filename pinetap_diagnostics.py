"""
PiNetAP - Diagnostics and Interface Management
Interface listing, diagnostics, and troubleshooting utilities
"""

import time
import json
from pathlib import Path
from typing import Optional

from pinetap_network import PiNetAPNetwork


class PiNetAPDiagnostics(PiNetAPNetwork):
    """Diagnostics and interface management utilities"""

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
            print("\n⛔ No WiFi Setup Possible")
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
            print("\n⛔ No WiFi connections found")
            return

        print(f"\n📡 Found {len(ap_connections)} WiFi connection(s):")
        for conn in ap_connections:
            print(f"   - {conn}")

        target_conn = con_name if con_name else ap_connections[0]

        print(f"\n🔍 Diagnosing: {target_conn}")
        print("-"*70)

        ret, stdout, _ = self.run_command(["nmcli", "con", "show", target_conn], check=False)
        if ret != 0:
            print(f"⛔ Cannot read connection '{target_conn}'")
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

        # Check for captive portal
        connections = self.load_managed_connections()
        has_captive = False
        ap_interface = None
        for conn, info in connections.items():
            if conn == target_conn:
                has_captive = info.get('captive_portal', False)
                ap_interface = info.get('interface')
                break

        if has_captive:
            print("\n📱 Captive Portal Diagnostics:")
            print("-"*70)

            # Check portal service
            ret, _, _ = self.run_command(["systemctl", "is-active", "pinetap-portal"], check=False)
            status = "✓ Running" if ret == 0 else "✗ Not Running"
            print(f"   Portal Service: {status}")

            if ret != 0:
                print("   Attempting to start portal...")
                self.run_command(["systemctl", "start", "pinetap-portal"], check=False)
                time.sleep(1)
                ret, _, _ = self.run_command(["systemctl", "is-active", "pinetap-portal"], check=False)
                if ret == 0:
                    print("   ✓ Portal started successfully")
                else:
                    print("   ✗ Failed to start portal")
                    print("\n   Check logs: sudo journalctl -u pinetap-portal -n 20")

            # Check if portal responds
            ret, stdout, _ = self.run_command([
                "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                "http://192.168.4.1/"
            ], check=False)

            if ret == 0:
                code = stdout.strip()
                if code == "200":
                    print(f"   Portal HTTP: ✓ Responding (HTTP {code})")
                else:
                    print(f"   Portal HTTP: ⚠️ Unexpected response (HTTP {code})")
            else:
                print(f"   Portal HTTP: ✗ Not responding")

            # Check for auto-reload feature
            services_file = Path("/var/www/pinetap-portal/services.json")
            if services_file.exists():
                print(f"   Auto-Reload: ✓ Enabled ({services_file})")
            else:
                # Check metadata for original file path
                metadata_file = Path("/var/www/pinetap-portal/portal_metadata.json")
                if metadata_file.exists():
                    try:
                        metadata = json.loads(metadata_file.read_text())
                        original_file = metadata.get('services_file')
                        if original_file and Path(original_file).exists():
                            print(f"   Auto-Reload: ✓ Enabled (monitoring: {original_file})")
                        else:
                            print(f"   Auto-Reload: ✗ Not configured")
                    except Exception:
                        print(f"   Auto-Reload: ✗ Not configured")
                else:
                    print(f"   Auto-Reload: ✗ Not configured")

            # Check DNS config
            if ap_interface:
                dns_conf = Path(f"/etc/NetworkManager/dnsmasq.d/pinetap-captive-{ap_interface}.conf")
                if dns_conf.exists():
                    print(f"   DNS Config: ✓ Found ({dns_conf})")
                else:
                    print(f"   DNS Config: ✗ Missing")

            # Check iptables rules
            ret, stdout, _ = self.run_command([
                "iptables", "-t", "nat", "-L", "PREROUTING", "-n"
            ], check=False)

            if ret == 0 and ap_interface and ap_interface in stdout:
                print(f"   iptables Rules: ✓ Found for {ap_interface}")
            else:
                print(f"   iptables Rules: ⚠️ May be missing")

            # Check NetworkManager dnsmasq
            ret, _, _ = self.run_command(["pgrep", "-f", "dnsmasq.*NetworkManager"], check=False)
            if ret == 0:
                print(f"   dnsmasq: ✓ Running for NetworkManager")
            else:
                print(f"   dnsmasq: ⚠️ Not running")

        print("\n" + "="*70)
        print("💡 TROUBLESHOOTING TIPS:")
        print("="*70)
        if not is_active:
            print("⛔ Connection is not active!")
            print(f"   Try: sudo nmcli con up {target_conn}")

        if has_captive:
            print("\n🔧 Captive Portal Tips:")
            print("   1. Restart portal: sudo systemctl restart pinetap-portal")
            print("   2. Check logs: sudo journalctl -u pinetap-portal -f")
            print("   3. Test DNS: nslookup google.com (from client device)")
            print("   4. Test HTTP: curl http://google.com (from client device)")
            print("   5. View iptables: sudo iptables -t nat -L PREROUTING -n -v")
            print("   6. Reload NetworkManager: sudo systemctl reload NetworkManager")
            
            services_file = Path("/var/www/pinetap-portal/services.json")
            if services_file.exists():
                print(f"   7. Update services: edit {services_file}")
                print("      Changes take effect on next page load (auto-reload enabled)")
            else:
                # Check metadata for original file path
                metadata_file = Path("/var/www/pinetap-portal/portal_metadata.json")
                if metadata_file.exists():
                    try:
                        metadata = json.loads(metadata_file.read_text())
                        original_file = metadata.get('services_file')
                        if original_file and Path(original_file).exists():
                            print(f"   7. Update services: edit {original_file}")
                            print("      Changes take effect on next page load (auto-reload enabled)")
                    except Exception:
                        pass

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
            print("   ⛔ Not running")
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
                print(f"   ⛔ Not active")
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
            print(f"⚠️ Fixed {issues_fixed}/{issues_found} issue(s)")
        print("="*70)