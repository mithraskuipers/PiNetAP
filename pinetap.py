#!/usr/bin/env python3
"""
PiNetAP - Dual WiFi Access Point Manager for Raspberry Pi
Main CLI interface

ENHANCED: Captive portal with automatic service JSON reloading

Usage: sudo python pinetap.py [command] [options]
"""

import argparse
import sys
import json
from pathlib import Path

from pinetap_core import SecurityMode
from pinetap_ap import PiNetAPManager


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

  # With captive portal and auto-reload services
  sudo python pinetap.py install --ssid MyServices --password Pass12345 \\
       --security wpa2-psk --ap-interface wlan0 --no-share --autoconnect \\
       --captive-portal --services-file ./services.json

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
    install_parser.add_argument("--portal-services", type=str, help="(Deprecated) Use --services-file instead")
    install_parser.add_argument("--services-file", type=str, help="Path to JSON file with custom services for captive portal (auto-reload enabled)")

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

    manager = PiNetAPManager(verbose=args.verbose)

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

        # CRITICAL FIX: We use a STANDALONE dnsmasq service that runs independently
        # DO NOT modify NetworkManager's config as this breaks the host's DNS
        # The standalone dnsmasq only binds to the AP interface
        if args.captive_portal:
            manager.log("🔧 Captive portal will use standalone dnsmasq service", "INFO")
            manager.log("  Host DNS will NOT be affected", "INFO")
        else:
            manager.log("Using NetworkManager's built-in DHCP (no dnsmasq needed)")

        # Handle services file (new method) or portal_services (deprecated)
        portal_services = None
        services_file = None
        
        if args.services_file:
            # New method: use services_file parameter
            services_file = args.services_file
            manager.log(f"Using services file: {services_file}")
            manager.log("⚡ Auto-reload enabled: portal updates when JSON changes", "INFO")
        elif args.portal_services:
            # Deprecated method: load JSON directly
            try:
                with open(args.portal_services, 'r') as f:
                    portal_services = json.load(f)
                manager.log(f"Loaded {len(portal_services)} service(s) from {args.portal_services}")
                manager.log("⚠️ --portal-services is deprecated, use --services-file instead", "WARN")
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
            internet_interface=getattr(args, 'uplink_interface', None),
            security_mode=security_mode,
            captive_portal=args.captive_portal,
            portal_services=portal_services,
            services_file=services_file
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