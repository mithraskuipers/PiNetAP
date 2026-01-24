#!/usr/bin/env python3
"""
PiNetAP Captive Portal - DNS Configuration and HTTP Server Management
Contains captive portal setup, DNS hijacking, and portal server management

FIXED: DNS configuration uses standalone dnsmasq instance that ONLY serves the AP interface
This prevents breaking the host's DNS resolution while still providing captive portal DNS
"""

import time
import json
from typing import Optional, List, Dict
from pathlib import Path
from pinetap_core import PiNetAPCore
from pinetap_firewall import PiNetAPFirewall
from pinetap_portal_template import get_captive_portal_html, get_portal_server_script


class PiNetAPCaptivePortal(PiNetAPCore):
    """Captive portal and DNS management"""

    def __init__(self, firewall=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Use provided firewall instance or create new one
        self.firewall = firewall if firewall is not None else PiNetAPFirewall(*args, **kwargs)
        # Path for standalone dnsmasq config
        self.STANDALONE_DNSMASQ_CONF = self.PINETAP_CONFIG_DIR / "dnsmasq-captive.conf"
        self.STANDALONE_DNSMASQ_SERVICE = Path("/etc/systemd/system/pinetap-dnsmasq.service")

    def verify_dns_hijacking(self, ap_ip: str) -> bool:
        """Verify DNS hijacking is working"""
        try:
            self.log("Testing DNS hijacking...", "DEBUG")
            
            # Try to resolve a common domain using the AP's DNS
            ret, stdout, _ = self.run_command([
                "nslookup", "google.com", ap_ip
            ], check=False)
            
            if ret == 0 and ap_ip in stdout:
                return True
            
            return False
            
        except Exception as e:
            self.log(f"DNS verification failed: {e}", "DEBUG")
            return False

    def verify_captive_portal_working(self, ap_ip: str) -> bool:
        """Verify captive portal HTTP server is responding correctly"""
        try:
            # Test main portal page
            ret, stdout, _ = self.run_command([
                "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                f"http://{ap_ip}/"
            ], check=False)
            
            if ret != 0 or stdout.strip() != "200":
                return False
            
            # Test Android detection endpoint
            ret, stdout, _ = self.run_command([
                "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                f"http://{ap_ip}/generate_204"
            ], check=False)
            
            if ret != 0 or stdout.strip() != "200":
                return False
            
            return True
            
        except Exception as e:
            self.log(f"Portal verification failed: {e}", "DEBUG")
            return False

    def setup_standalone_dnsmasq(self, ap_interface: str, ap_ip: str, share_internet: bool = False) -> bool:
        """
        Setup a STANDALONE dnsmasq instance that ONLY serves the AP interface.
        This prevents breaking the host's DNS while still providing captive portal DNS.
        
        CRITICAL FIX: When share_internet=True, we CANNOT use ipv4.method=shared because
        NetworkManager's dnsmasq conflicts with ours. Instead, we provide DHCP ourselves.
        
        Args:
            ap_interface: The AP interface
            ap_ip: The AP IP address (should be clean, no /24)
            share_internet: If True, forward non-captive DNS to real DNS servers
        """
        try:
            self.log(f"Setting up standalone dnsmasq for {ap_interface}...")
            
            # For BOTH modes, we need to provide DHCP because:
            # - NetworkManager's ipv4.method=shared creates its own dnsmasq that conflicts
            # - We need full control over DNS settings
            
            if share_internet:
                # Mode: Captive portal WITH internet access
                # We provide DHCP + DNS, and forward DNS queries
                dnsmasq_conf = f"""# [PiNetAP] Standalone dnsmasq for captive portal WITH internet
# This runs separately from NetworkManager and system DNS

# CRITICAL: Only listen on AP interface, use bind-dynamic for flexibility
interface={ap_interface}
bind-dynamic
listen-address={ap_ip}

# Don't use system-wide DNS settings
no-resolv
no-poll

# Use Google DNS for forwarding (for non-hijacked queries)
server=8.8.8.8
server=8.8.4.4
server=1.1.1.1

# Hijack ONLY captive portal detection domains
address=/connectivitycheck.android.com/{ap_ip}
address=/connectivitycheck.gstatic.com/{ap_ip}
address=/clients3.google.com/{ap_ip}
address=/clients4.google.com/{ap_ip}
address=/captive.apple.com/{ap_ip}
address=/www.apple.com/{ap_ip}
address=/www.msftconnecttest.com/{ap_ip}
address=/www.msftncsi.com/{ap_ip}
address=/ipv6.msftconnecttest.com/{ap_ip}
address=/detectportal.firefox.com/{ap_ip}

# DHCP server for AP clients (we must provide this ourselves)
dhcp-range={ap_ip.rsplit('.', 1)[0]}.50,{ap_ip.rsplit('.', 1)[0]}.150,12h
dhcp-option=option:router,{ap_ip}
dhcp-option=option:dns-server,{ap_ip}
dhcp-authoritative

# Logging
log-queries
log-dhcp
"""
            else:
                # Mode: Captive portal WITHOUT internet (standalone)
                # We provide both DNS and DHCP since there's no uplink
                dnsmasq_conf = f"""# [PiNetAP] Standalone dnsmasq for captive portal WITHOUT internet
# This runs separately from NetworkManager and system DNS

# CRITICAL: Only listen on AP interface, use bind-dynamic for flexibility
interface={ap_interface}
bind-dynamic
listen-address={ap_ip}

# Don't forward to upstream DNS - completely isolated
no-resolv
no-poll

# Hijack ALL DNS queries from AP clients
address=/#/{ap_ip}

# DHCP server for AP clients
dhcp-range={ap_ip.rsplit('.', 1)[0]}.50,{ap_ip.rsplit('.', 1)[0]}.150,12h
dhcp-option=option:router,{ap_ip}
dhcp-option=option:dns-server,{ap_ip}
dhcp-authoritative

# Don't read /etc/hosts
no-hosts

# Logging
log-queries
log-dhcp
"""
            
            # Write config
            self.PINETAP_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            self.STANDALONE_DNSMASQ_CONF.write_text(dnsmasq_conf)
            self.log(f"✓ Created dnsmasq config: {self.STANDALONE_DNSMASQ_CONF}")
            
            if share_internet:
                self.log("  Mode: DNS + DHCP with internet forwarding", "INFO")
            else:
                self.log("  Mode: DNS + DHCP (standalone, no internet)", "INFO")
            
            # Create systemd service for standalone dnsmasq
            service_content = f"""[Unit]
Description=[PiNetAP] Standalone dnsmasq for Captive Portal
After=network.target NetworkManager.service
BindsTo=sys-subsystem-net-devices-{ap_interface}.device
After=sys-subsystem-net-devices-{ap_interface}.device

[Service]
Type=forking
ExecStart=/usr/sbin/dnsmasq --conf-file={self.STANDALONE_DNSMASQ_CONF} --pid-file=/run/pinetap-dnsmasq.pid
ExecReload=/bin/kill -HUP $MAINPID
PIDFile=/run/pinetap-dnsmasq.pid
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
"""
            
            self.STANDALONE_DNSMASQ_SERVICE.write_text(service_content)
            self.log(f"✓ Created systemd service: {self.STANDALONE_DNSMASQ_SERVICE}")
            
            # Reload systemd and start service
            self.run_command(["systemctl", "daemon-reload"], check=False)
            
            # Stop any existing instance
            self.run_command(["systemctl", "stop", "pinetap-dnsmasq"], check=False)
            time.sleep(1)
            
            # Start the service
            self.run_command(["systemctl", "enable", "pinetap-dnsmasq"], check=False)
            ret, stdout, stderr = self.run_command(["systemctl", "start", "pinetap-dnsmasq"], check=False)
            
            if ret != 0:
                self.log(f"Failed to start standalone dnsmasq: {stderr}", "ERROR")
                # Check if dnsmasq is installed
                ret2, _, _ = self.run_command(["which", "dnsmasq"], check=False)
                if ret2 != 0:
                    self.log("dnsmasq not found! Install with: sudo apt-get install dnsmasq", "ERROR")
                return False
            
            # Verify it's running
            time.sleep(2)
            ret, _, _ = self.run_command(["systemctl", "is-active", "pinetap-dnsmasq"], check=False)
            if ret == 0:
                self.log("✓ Standalone dnsmasq service is running", "SUCCESS")
                
                # Verify it's listening on the correct interface
                ret2, stdout2, _ = self.run_command([
                    "ss", "-lunp", f"sport = :53"
                ], check=False)
                
                if ret2 == 0 and ap_ip in stdout2:
                    self.log(f"✓ dnsmasq listening on {ap_ip}:53", "SUCCESS")
                else:
                    self.log(f"⚠️ Warning: dnsmasq may not be listening on {ap_ip}:53", "WARN")
                    if stdout2:
                        self.log(f"  Current DNS listeners:\n{stdout2}", "DEBUG")
                
                # Also check DHCP is listening
                ret3, stdout3, _ = self.run_command([
                    "ss", "-lunp", f"sport = :67"
                ], check=False)
                
                if ret3 == 0 and "dnsmasq" in stdout3:
                    self.log(f"✓ dnsmasq DHCP server active on port 67", "SUCCESS")
                else:
                    self.log(f"⚠️ DHCP server may not be running", "WARN")
                
                return True
            else:
                self.log("Failed to start standalone dnsmasq", "ERROR")
                ret2, stdout2, _ = self.run_command(["systemctl", "status", "pinetap-dnsmasq", "--no-pager"], check=False)
                if stdout2:
                    self.log(f"Status:\n{stdout2}", "DEBUG")
                return False
                
        except Exception as e:
            self.log(f"Failed to setup standalone dnsmasq: {e}", "ERROR")
            import traceback
            self.log(traceback.format_exc(), "ERROR")
            return False

    def stop_standalone_dnsmasq(self) -> bool:
        """Stop and remove the standalone dnsmasq service"""
        try:
            self.log("Stopping standalone dnsmasq...")
            
            # Stop and disable service
            self.run_command(["systemctl", "stop", "pinetap-dnsmasq"], check=False)
            self.run_command(["systemctl", "disable", "pinetap-dnsmasq"], check=False)
            
            # Remove service file
            if self.STANDALONE_DNSMASQ_SERVICE.exists():
                self.STANDALONE_DNSMASQ_SERVICE.unlink()
                self.log(f"Removed {self.STANDALONE_DNSMASQ_SERVICE}")
            
            # Remove config file
            if self.STANDALONE_DNSMASQ_CONF.exists():
                self.STANDALONE_DNSMASQ_CONF.unlink()
                self.log(f"Removed {self.STANDALONE_DNSMASQ_CONF}")
            
            # Reload systemd
            self.run_command(["systemctl", "daemon-reload"], check=False)
            
            self.log("✓ Standalone dnsmasq stopped and removed", "SUCCESS")
            return True
            
        except Exception as e:
            self.log(f"Failed to stop standalone dnsmasq: {e}", "WARN")
            return False

    def configure_captive_portal_dns(self, ap_interface: str, ap_ip: str, share_internet: bool = False) -> bool:
        """
        Configure DNS for captive portal using STANDALONE dnsmasq instance.
        This ensures the host's DNS is not affected.
        
        Args:
            ap_interface: Network interface for AP
            ap_ip: IP address of AP (can include /24 notation)
            share_internet: If True, forward DNS to real servers; if False, hijack all DNS
        """
        try:
            # Clean the IP address (remove /24 if present)
            ap_ip_clean = ap_ip.split('/')[0]
            
            self.log(f"Configuring DNS for captive portal on {ap_interface} ({ap_ip_clean})...")
            
            # Setup standalone dnsmasq for the AP interface
            if not self.setup_standalone_dnsmasq(ap_interface, ap_ip_clean, share_internet):
                self.log("Failed to setup standalone dnsmasq", "ERROR")
                return False
            
            self.log("✓ DNS configured for captive portal", "SUCCESS")
            self.log(f"  AP clients will use {ap_ip_clean} as DNS server", "INFO")
            if share_internet:
                self.log("  Non-captive DNS queries will be forwarded to 8.8.8.8", "INFO")
            else:
                self.log("  All DNS queries from AP clients return portal IP", "INFO")
            
            # Verify DNS is working
            if self.verify_dns_hijacking(ap_ip_clean):
                self.log("✓ DNS hijacking verified", "SUCCESS")
            else:
                self.log("⚠️ Could not verify DNS hijacking", "WARN")
            
            return True
            
        except Exception as e:
            self.log(f"Failed to configure DNS: {e}", "ERROR")
            import traceback
            self.log(traceback.format_exc(), "ERROR")
            return False

    def ensure_dnsmasq_active(self) -> bool:
        """Ensure standalone dnsmasq is running for captive portal"""
        try:
            ret, _, _ = self.run_command(["systemctl", "is-active", "pinetap-dnsmasq"], check=False)
            return ret == 0
        except Exception:
            return False

    def _load_services_from_json(self, services_file: str) -> Optional[List[Dict]]:
        """Load and validate services from JSON file"""
        try:
            services_path = Path(services_file)
            if not services_path.exists():
                self.log(f"Services file not found: {services_file}", "ERROR")
                return None
            
            with open(services_path, 'r') as f:
                services = json.load(f)
            
            if not isinstance(services, list):
                self.log("Services file must contain a JSON array", "ERROR")
                return None
            
            # Validate each service has required fields
            for svc in services:
                if 'name' not in svc:
                    self.log("Each service must have a 'name' field", "ERROR")
                    return None
            
            return services
            
        except json.JSONDecodeError as e:
            self.log(f"Invalid JSON in services file: {e}", "ERROR")
            return None
        except Exception as e:
            self.log(f"Failed to load services file: {e}", "ERROR")
            return None

    def setup_captive_portal(self, ap_ip: str, ssid: str, ap_interface: str,
                           services: Optional[List[Dict]] = None, port: int = 80,
                           services_file: Optional[str] = None, share_internet: bool = False) -> bool:
        """Setup captive portal with enhanced detection for auto-popup
        
        Args:
            ap_ip: IP address of the access point
            ssid: SSID of the network
            ap_interface: Network interface for AP
            services: List of service dictionaries (optional)
            port: Port for captive portal (default: 80)
            services_file: Path to JSON file with services (optional, overrides services parameter)
            share_internet: If True, skip HTTP redirect (for internet sharing mode)
        """
        try:
            # Clean the IP address (remove /24 if present)
            ap_ip_clean = ap_ip.split('/')[0]
            
            self.log(f"Setting up captive portal for {ssid} on {ap_ip_clean}:{port}...")
            
            # Load services from file if specified
            portal_services = None
            portal_services_file = None
            
            if services_file:
                portal_services = self._load_services_from_json(services_file)
                if portal_services is None:
                    self.log("Failed to load services from file, using default", "WARN")
                else:
                    # Use the ORIGINAL file path for monitoring
                    portal_services_file = str(Path(services_file).resolve())
                    self.log(f"✓ Loaded {len(portal_services)} service(s) from {services_file}")
            elif services:
                portal_services = services
                self.log(f"Using {len(services)} service(s) from parameter")
            
            # Create portal directory
            self.CAPTIVE_PORTAL_DIR.mkdir(parents=True, exist_ok=True)
            
            # Copy template file to portal directory for server script access
            template_source = Path(__file__).parent / "portal_template.html"
            template_dest = self.CAPTIVE_PORTAL_DIR / "portal_template.html"
            
            if template_source.exists():
                import shutil
                shutil.copy(template_source, template_dest)
                self.log(f"✓ Copied template to {template_dest}")
            else:
                self.log(f"⚠️ Template not found at {template_source}", "WARN")
            
            # Save metadata for portal server
            metadata = {
                'ssid': ssid,
                'ap_ip': ap_ip_clean,
                'port': port,
                'share_internet': share_internet
            }
            
            if portal_services_file:
                metadata['services_file'] = portal_services_file
            
            metadata_file = self.CAPTIVE_PORTAL_DIR / "portal_metadata.json"
            metadata_file.write_text(json.dumps(metadata, indent=2))
            self.log(f"✓ Saved portal metadata")
            
            # If we have a services file, create/copy it to portal directory for the server
            if portal_services_file:
                # Copy to portal directory with standard name
                services_dest = self.CAPTIVE_PORTAL_DIR / "services.json"
                import shutil
                shutil.copy(portal_services_file, services_dest)
                self.log(f"✓ Copied services file to {services_dest}")
            elif portal_services:
                # Create services.json in portal directory
                services_dest = self.CAPTIVE_PORTAL_DIR / "services.json"
                services_dest.write_text(json.dumps(portal_services, indent=2))
                self.log(f"✓ Created services.json")
                # Also set portal_services_file so server can monitor it
                portal_services_file = str(services_dest)
            
            # Generate initial HTML
            html_content = get_captive_portal_html(
                ap_ip=ap_ip_clean,
                ssid=ssid,
                services=portal_services
            )
            
            # Save as both index.html and splash.html for compatibility
            (self.CAPTIVE_PORTAL_DIR / "index.html").write_text(html_content, encoding='utf-8')
            (self.CAPTIVE_PORTAL_DIR / "splash.html").write_text(html_content, encoding='utf-8')
            
            self.log(f"✓ Generated portal pages in {self.CAPTIVE_PORTAL_DIR}")
            
            # Generate Python server script with auto-reload capability
            server_script_content = get_portal_server_script(
                ap_ip=ap_ip_clean,
                port=port,
                portal_dir=self.CAPTIVE_PORTAL_DIR,
                services_json_path=portal_services_file  # Pass original file path for monitoring
            )
            
            self.CAPTIVE_PORTAL_SCRIPT.write_text(server_script_content)
            self.CAPTIVE_PORTAL_SCRIPT.chmod(0o755)
            self.log(f"✓ Created portal server script: {self.CAPTIVE_PORTAL_SCRIPT}")
            
            # Create systemd service
            service_content = f"""[Unit]
Description=[PiNetAP] Captive Portal HTTP Server
After=network.target pinetap-dnsmasq.service
BindsTo=sys-subsystem-net-devices-{ap_interface}.device
After=sys-subsystem-net-devices-{ap_interface}.device

[Service]
Type=simple
ExecStart=/usr/bin/python3 {self.CAPTIVE_PORTAL_SCRIPT}
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"""
            
            self.CAPTIVE_PORTAL_SERVICE.write_text(service_content)
            self.log(f"✓ Created systemd service: {self.CAPTIVE_PORTAL_SERVICE}")
            
            # Configure DNS for captive portal using standalone dnsmasq
            if not self.configure_captive_portal_dns(ap_interface, ap_ip_clean, share_internet):
                self.log("DNS configuration failed, but continuing...", "WARN")
            
            # Setup iptables to intercept HTTP/HTTPS traffic on AP interface
            # Skip HTTP redirect if internet sharing is enabled (would break internet access)
            # CRITICAL FIX: Use ap_ip_clean for iptables!
            self.firewall.setup_captive_portal_iptables(ap_interface, ap_ip_clean, skip_http_redirect=share_internet)
            
            # Reload systemd and start service
            self.run_command(["systemctl", "daemon-reload"], check=False)
            self.run_command(["systemctl", "enable", "pinetap-portal"], check=False)
            
            # Stop any existing instance first
            self.run_command(["systemctl", "stop", "pinetap-portal"], check=False)
            time.sleep(1)
            
            # Start the service
            ret_start, stdout_start, stderr_start = self.run_command(
                ["systemctl", "start", "pinetap-portal"], 
                check=False
            )
            
            if ret_start != 0:
                self.log(f"Failed to start portal service: {stderr_start}", "ERROR")
                self.log("Checking for errors...", "DEBUG")
                
                # Try to get more details
                ret_status, stdout_status, _ = self.run_command(
                    ["systemctl", "status", "pinetap-portal", "--no-pager"],
                    check=False
                )
                if stdout_status:
                    self.log(f"Service status:\n{stdout_status}", "DEBUG")
                
                # Try running the script directly to see the error
                self.log("Testing portal script directly...", "DEBUG")
                ret_test, stdout_test, stderr_test = self.run_command(
                    ["timeout", "2", "python3", str(self.CAPTIVE_PORTAL_SCRIPT)],
                    check=False
                )
                if stderr_test:
                    self.log(f"Direct script error: {stderr_test}", "ERROR")
                if stdout_test:
                    self.log(f"Direct script output: {stdout_test}", "DEBUG")
                
                return False
            
            # Wait and verify
            time.sleep(2)
            ret, _, _ = self.run_command(["systemctl", "is-active", "pinetap-portal"], check=False)
            if ret == 0:
                self.log(f"✓ Captive portal running at http://{ap_ip_clean}:{port}", "SUCCESS")
                self.log(f"  Portal will auto-popup on iOS, Android, Windows devices", "SUCCESS")
                if portal_services_file:
                    self.log(f"  ⚡ Auto-reload enabled: monitoring {portal_services_file}", "SUCCESS")
                    self.log(f"  📝 Edit your services file and refresh browser to see changes!", "INFO")
                
                # Test the portal server
                self.log("\n🧪 Testing portal server...", "INFO")
                ret, stdout, _ = self.run_command([
                    "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                    f"http://{ap_ip_clean}/"
                ], check=False)
                if ret == 0 and stdout.strip() == "200":
                    self.log("  ✓ Portal responds correctly", "SUCCESS")
                else:
                    self.log(f"  ⚠️ Portal response: {stdout}", "WARN")
                
                return True
            else:
                self.log("Failed to start captive portal service", "ERROR")
                ret2, stdout2, stderr2 = self.run_command(["systemctl", "status", "pinetap-portal"], check=False)
                if stdout2:
                    self.log(f"Status: {stdout2}", "DEBUG")
                if stderr2:
                    self.log(f"Error: {stderr2}", "ERROR")
                return False
                
        except Exception as e:
            self.log(f"Failed to setup captive portal: {e}", "ERROR")
            import traceback
            self.log(traceback.format_exc(), "ERROR")
            return False

    def remove_captive_portal(self) -> bool:
        """Remove captive portal files and service"""
        try:
            self.log("Removing captive portal...")
            
            # Stop and disable portal service
            self.run_command(["systemctl", "stop", "pinetap-portal"], check=False)
            self.run_command(["systemctl", "disable", "pinetap-portal"], check=False)
            
            # Stop and remove standalone dnsmasq
            self.stop_standalone_dnsmasq()
            
            # Remove iptables rules
            self.firewall.remove_captive_portal_iptables()
            
            # Remove DNS configs from dnsmasq-shared.d (legacy cleanup)
            dnsmasq_shared_dir = Path("/etc/NetworkManager/dnsmasq-shared.d")
            if dnsmasq_shared_dir.exists():
                for conf_file in dnsmasq_shared_dir.glob("pinetap-captive-*.conf"):
                    try:
                        conf_file.unlink()
                        self.log(f"Removed legacy DNS config: {conf_file}")
                    except Exception as e:
                        self.log(f"Could not remove {conf_file}: {e}", "WARN")
            
            # Remove portal directory
            if self.CAPTIVE_PORTAL_DIR.exists():
                import shutil
                shutil.rmtree(self.CAPTIVE_PORTAL_DIR)
                self.log("Removed portal directory")
            
            # Remove systemd service
            if self.CAPTIVE_PORTAL_SERVICE.exists():
                self.CAPTIVE_PORTAL_SERVICE.unlink()
            
            # Remove portal script
            if self.CAPTIVE_PORTAL_SCRIPT.exists():
                self.CAPTIVE_PORTAL_SCRIPT.unlink()
            
            # Reload systemd
            self.run_command(["systemctl", "daemon-reload"], check=False)
            
            self.log("✓ Captive portal removed", "SUCCESS")
            return True
            
        except Exception as e:
            self.log(f"Failed to remove captive portal: {e}", "WARN")
            return False

    def get_captive_portal_status(self) -> dict:
        """Get status of captive portal service"""
        try:
            ret, stdout, _ = self.run_command(
                ["systemctl", "is-active", "pinetap-portal"],
                check=False
            )
            
            active = (ret == 0 and stdout.strip() == "active")
            
            status = {
                "active": active,
                "service": "pinetap-portal",
            }
            
            if active:
                # Get more details if active
                ret2, stdout2, _ = self.run_command(
                    ["systemctl", "show", "pinetap-portal", "--no-pager"],
                    check=False
                )
                if ret2 == 0:
                    status["details"] = stdout2
                
                # Check metadata for original services file path
                metadata_file = self.CAPTIVE_PORTAL_DIR / "portal_metadata.json"
                if metadata_file.exists():
                    try:
                        import json
                        metadata = json.loads(metadata_file.read_text())
                        services_file = metadata.get('services_file')
                        if services_file and Path(services_file).exists():
                            status["services_file"] = services_file
                            status["auto_reload"] = True
                    except Exception:
                        pass
            
            return status
            
        except Exception as e:
            self.log(f"Failed to get portal status: {e}", "ERROR")
            return {"active": False, "error": str(e)}

    def update_portal_services(self, services_file: str) -> bool:
        """Update the portal services configuration
        
        Note: With the new design, you just edit your original services.json file.
        This method is kept for backward compatibility but is no longer needed.
        
        Args:
            services_file: Path to new services JSON file
            
        Returns:
            True if update successful
        """
        try:
            # Validate the new services file
            services = self._load_services_from_json(services_file)
            if services is None:
                return False
            
            self.log(f"✓ Services file validated: {services_file}", "SUCCESS")
            self.log("  Portal will auto-reload on next request", "INFO")
            self.log("  Simply edit your services.json file to update the portal!", "INFO")
            
            return True
            
        except Exception as e:
            self.log(f"Failed to validate services: {e}", "ERROR")
            return False
