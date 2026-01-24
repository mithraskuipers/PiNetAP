#!/usr/bin/env python3
"""
PiNetAP Captive Portal - DNS Configuration and HTTP Server Management
Contains captive portal setup, DNS hijacking, and portal server management

FIXED: Ensures all {{AP_IP}} placeholders are replaced with actual IP
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

    def ensure_dnsmasq_active(self) -> bool:
        """Ensure dnsmasq is running for NetworkManager (needed for captive portal)"""
        try:
            # Check if dnsmasq is running under NetworkManager
            ret, stdout, _ = self.run_command(["pgrep", "-f", "dnsmasq.*NetworkManager"], check=False)
            
            if ret == 0 and stdout.strip():
                self.log("✓ dnsmasq is active for NetworkManager", "SUCCESS")
                return True
            
            self.log("dnsmasq not detected, attempting to start...", "WARN")
            
            # Try reloading NetworkManager to start dnsmasq
            from pinetap_network import PiNetAPNetwork
            network = PiNetAPNetwork()
            network.reload_networkmanager(delay=3)
            
            # Check again
            ret, stdout, _ = self.run_command(["pgrep", "-f", "dnsmasq.*NetworkManager"], check=False)
            
            if ret == 0 and stdout.strip():
                self.log("✓ dnsmasq started successfully", "SUCCESS")
                return True
            else:
                self.log("⚠️ dnsmasq still not running", "WARN")
                return False
                
        except Exception as e:
            self.log(f"Failed to check dnsmasq: {e}", "ERROR")
            return False

    def configure_captive_portal_dns(self, ap_interface: str, ap_ip: str, share_internet: bool = False) -> bool:
        """
        Configure DNS for the AP interface with captive portal detection.
        
        Args:
            ap_interface: The AP interface
            ap_ip: The AP IP address (should be clean, no /24)
            share_internet: If True, forward non-captive DNS to real DNS servers
        """
        try:
            self.log(f"Configuring captive DNS for {ap_interface} (internet sharing: {share_internet})...")
            
            if share_internet:
                # Mode: Captive portal WITH internet access
                # Only hijack captive portal detection domains, forward everything else
                captive_dns_conf = f"""# PiNetAP Captive Portal DNS - With Internet Access
# Hijack ONLY captive portal detection domains, forward rest to real DNS

# Bind ONLY to the AP interface and its IP
interface={ap_interface}
listen-address={ap_ip}
bind-interfaces

# Forward all other queries to real DNS servers (Google DNS)
server=8.8.8.8
server=8.8.4.4

# ONLY hijack captive portal detection domains (for auto-popup)
# These return our portal IP to trigger detection

# === ANDROID Detection ===
address=/connectivitycheck.android.com/{ap_ip}
address=/connectivitycheck.gstatic.com/{ap_ip}
address=/clients3.google.com/{ap_ip}
address=/clients4.google.com/{ap_ip}

# === iOS/macOS Detection ===
address=/captive.apple.com/{ap_ip}
address=/www.apple.com/{ap_ip}

# === Windows Detection ===
address=/www.msftconnecttest.com/{ap_ip}
address=/www.msftncsi.com/{ap_ip}
address=/ipv6.msftconnecttest.com/{ap_ip}

# === Firefox Detection ===
address=/detectportal.firefox.com/{ap_ip}

# Allow caching for better performance
cache-size=1000

# DHCP options to ensure our DNS is used
dhcp-option={ap_interface},6,{ap_ip}
dhcp-authoritative

# Log queries for debugging
log-queries
log-dhcp
"""
            else:
                # Mode: Captive portal WITHOUT internet (standalone mode)
                # Hijack ALL DNS queries
                captive_dns_conf = f"""# PiNetAP Captive Portal DNS - Standalone Mode (No Internet)
# Hijack ALL DNS queries to show portal

# Bind ONLY to the AP interface and its IP
interface={ap_interface}
listen-address={ap_ip}
bind-interfaces

# Don't use upstream DNS servers - we answer everything
no-resolv
no-poll

# CRITICAL: Explicitly handle captive portal detection domains
# These MUST return our portal IP to trigger the popup

# === ANDROID Detection (MOST CRITICAL) ===
address=/connectivitycheck.android.com/{ap_ip}
address=/connectivitycheck.gstatic.com/{ap_ip}
address=/www.google.com/{ap_ip}
address=/clients3.google.com/{ap_ip}
address=/clients4.google.com/{ap_ip}
address=/play.googleapis.com/{ap_ip}

# === iOS/macOS Detection ===
address=/captive.apple.com/{ap_ip}
address=/www.apple.com/{ap_ip}
address=/www.itools.info/{ap_ip}
address=/www.ibook.info/{ap_ip}
address=/www.airport.us/{ap_ip}
address=/www.thinkdifferent.us/{ap_ip}

# === Windows Detection ===
address=/www.msftconnecttest.com/{ap_ip}
address=/www.msftncsi.com/{ap_ip}
address=/ipv6.msftconnecttest.com/{ap_ip}
address=/dns.msftncsi.com/{ap_ip}

# === Firefox/Chrome Detection ===
address=/detectportal.firefox.com/{ap_ip}
address=/detectportal.cdn.mozilla.net/{ap_ip}

# === Catch-all: Redirect ALL other domains ===
address=/#/{ap_ip}

# Don't read /etc/hosts or other config files
no-hosts
expand-hosts

# Disable caching for immediate response
cache-size=0

# Don't forward to upstream DNS
bogus-priv

# DHCP options to ensure our DNS is used
dhcp-option={ap_interface},3,{ap_ip}
dhcp-option={ap_interface},6,{ap_ip}
dhcp-authoritative

# Log queries for debugging (disable in production if needed)
log-queries
log-dhcp
"""
        
            # CRITICAL: NetworkManager reads dnsmasq config from dnsmasq-shared.d, NOT dnsmasq.d!
            dnsmasq_shared_dir = Path("/etc/NetworkManager/dnsmasq-shared.d")
            dnsmasq_shared_dir.mkdir(parents=True, exist_ok=True)
            captive_dns_file = dnsmasq_shared_dir / f"pinetap-captive-{ap_interface}.conf"
            captive_dns_file.write_text(captive_dns_conf)
            
            if share_internet:
                self.log(f"✓ Captive DNS configured for {ap_interface} (WITH INTERNET)", "SUCCESS")
                self.log(f"  Captive detection domains → {ap_ip}", "INFO")
                self.log(f"  All other DNS → 8.8.8.8, 8.8.4.4", "INFO")
            else:
                self.log(f"✓ Captive DNS configured for {ap_interface} (STANDALONE)", "SUCCESS")
                self.log(f"  ALL DNS queries → {ap_ip}", "INFO")
            
            self.log(f"  Config: {captive_dns_file}", "INFO")
            
            return True
        except Exception as e:
            self.log(f"Failed to configure DNS: {e}", "ERROR")
            return False

    def setup_captive_portal(self, ap_ip: str, ssid: str, ap_interface: str,
                           services: Optional[List[Dict]] = None, port: int = 80,
                           services_file: Optional[str] = None, share_internet: bool = False) -> bool:
        """Setup captive portal using lightweight Python HTTP server with DNS+iptables interception
        
        Args:
            ap_ip: IP address of the access point (may include /24)
            ssid: SSID of the network
            ap_interface: Network interface for AP
            services: List of service dictionaries (optional, deprecated - use services_file)
            port: Port for captive portal (default: 80)
            services_file: Path to JSON file with services (optional, enables auto-reload)
            share_internet: If True, skip HTTP redirect (for internet sharing mode)
        """
        try:
            self.log("Setting up captive portal (pure Python, no additional packages needed)...")
            
            # Load services from JSON file if provided
            if services_file:
                services = self._load_services_from_json(services_file)
            
            return self._setup_offline_captive_portal(ap_ip, ssid, ap_interface, services, port, services_file, share_internet)
        except Exception as e:
            self.log(f"Failed to setup captive portal: {e}", "ERROR")
            return False

    def _load_services_from_json(self, services_file: str) -> Optional[List[Dict]]:
        """Load services configuration from JSON file"""
        try:
            import json
            from pathlib import Path
            
            file_path = Path(services_file)
            if not file_path.exists():
                self.log(f"Services file not found: {services_file}", "ERROR")
                return None
            
            with open(file_path, 'r') as f:
                services = json.load(f)
            
            # Validate the structure
            if not isinstance(services, list):
                self.log("Services file must contain a JSON array", "ERROR")
                return None
            
            for service in services:
                if not isinstance(service, dict):
                    self.log("Each service must be a JSON object", "ERROR")
                    return None
                if 'name' not in service:
                    self.log("Each service must have a 'name' field", "ERROR")
                    return None
            
            self.log(f"✓ Loaded {len(services)} services from {services_file}", "SUCCESS")
            return services
            
        except json.JSONDecodeError as e:
            self.log(f"Invalid JSON in services file: {e}", "ERROR")
            return None
        except Exception as e:
            self.log(f"Failed to load services file: {e}", "ERROR")
            return None

    def _setup_offline_captive_portal(self, ap_ip: str, ssid: str, ap_interface: str,
                                    services: Optional[List[Dict]] = None, port: int = 80, 
                                    services_file: Optional[str] = None, share_internet: bool = False) -> bool:
        """Setup offline captive portal - works like Starbucks WiFi with auto-redirect"""
        try:
            self.log("Setting up captive portal with auto-redirect and auto-reload...")
            
            # CRITICAL FIX: Strip /24 or any CIDR notation from ap_ip FIRST!
            ap_ip_clean = ap_ip.split('/')[0]
            self.log(f"[DEBUG] Original ap_ip: '{ap_ip}' -> Clean: '{ap_ip_clean}'", "DEBUG")
            
            # Create portal directory
            self.CAPTIVE_PORTAL_DIR.mkdir(parents=True, exist_ok=True)
            
            # CRITICAL FIX: Copy portal_template.html to portal directory for regeneration
            import inspect
            import shutil
            
            # Find the directory where the template function is defined
            template_source_dir = Path(inspect.getfile(get_captive_portal_html)).parent
            template_source = template_source_dir / "portal_template.html"
            template_dest = self.CAPTIVE_PORTAL_DIR / "portal_template.html"
            
            if template_source.exists():
                shutil.copy2(template_source, template_dest)
                self.log(f"✓ Copied portal template to {template_dest}", "DEBUG")
            else:
                self.log(f"⚠️ Warning: portal_template.html not found at {template_source}", "WARN")
                self.log(f"  Auto-reload may not work correctly", "WARN")
            
            # Determine services location
            portal_services_file = None
            if services_file:
                # Use the ORIGINAL file path - don't copy!
                services_path = Path(services_file).resolve()
                
                if not services_path.exists():
                    self.log(f"Services file not found: {services_file}", "ERROR")
                    return False
                
                portal_services_file = str(services_path)
                
                self.log(f"✓ Monitoring services file: {portal_services_file}", "SUCCESS")
                self.log("  Portal will auto-reload when you edit this file!", "INFO")
                
                # Load services to validate and create initial HTML
                services = self._load_services_from_json(services_file)
                
            elif services:
                # Save provided services to portal directory
                portal_services_path = self.CAPTIVE_PORTAL_DIR / "services.json"
                portal_services_path.write_text(json.dumps(services, indent=2))
                portal_services_file = str(portal_services_path)
                self.log(f"Services saved to {portal_services_path}")
            else:
                # No services provided - create default services file in portal directory
                portal_services_path = self.CAPTIVE_PORTAL_DIR / "services.json"
                default_services = [
                    {"name": "Router Admin", "port": 80, "path": "/", "description": "Web interface"}
                ]
                portal_services_path.write_text(json.dumps(default_services, indent=2))
                portal_services_file = str(portal_services_path)
                services = default_services
                self.log(f"Created default services file: {portal_services_path}")
            
            # Save portal metadata (SSID, IP, etc.) for dynamic HTML generation
            # CRITICAL FIX: Use ap_ip_clean (without /24) in metadata!
            metadata = {
                'ssid': ssid,
                'ap_ip': ap_ip_clean,
                'ap_interface': ap_interface,
                'share_internet': share_internet,
                'services_file': portal_services_file
            }
            metadata_file = self.CAPTIVE_PORTAL_DIR / "portal_metadata.json"
            metadata_file.write_text(json.dumps(metadata, indent=2))
            self.log(f"[DEBUG] Saved metadata with ap_ip: '{ap_ip_clean}'", "DEBUG")
            
            # Generate initial splash page HTML
            # CRITICAL FIX: Use ap_ip_clean for HTML generation!
            self.log(f"[DEBUG] Generating HTML with ap_ip_clean: '{ap_ip_clean}', ssid: '{ssid}'", "DEBUG")
            html_content = get_captive_portal_html(ap_ip_clean, ssid, services)
            
            # VERIFICATION: Check if placeholders were replaced
            if '{{AP_IP}}' in html_content:
                self.log("[ERROR] HTML still contains {{AP_IP}} placeholder!", "ERROR")
                self.log(f"[DEBUG] ap_ip_clean value: '{ap_ip_clean}'", "DEBUG")
                # Emergency fallback: manually replace
                html_content = html_content.replace('{{AP_IP}}', ap_ip_clean)
                html_content = html_content.replace('{{SSID}}', ssid)
                self.log("[FIX] Applied emergency placeholder replacement", "WARN")
            
            splash_page = self.CAPTIVE_PORTAL_DIR / "splash.html"
            splash_page.write_text(html_content)
            index_page = self.CAPTIVE_PORTAL_DIR / "index.html"
            index_page.write_text(html_content)
            self.log(f"Created initial portal pages: {splash_page} and {index_page}")
            
            # VERIFICATION: Double-check the written files
            with open(index_page, 'r') as f:
                check_content = f.read()
                if '{{AP_IP}}' in check_content:
                    self.log("[ERROR] index.html STILL contains {{AP_IP}} after writing!", "ERROR")
                else:
                    self.log(f"[DEBUG] ✓ index.html verified - no placeholders found", "DEBUG")
            
            # Create SUCCESS page for Android (critical!)
            success_page = self.CAPTIVE_PORTAL_DIR / "success.txt"
            success_page.write_text("success\n")
            
            # Create empty files for detection endpoints
            (self.CAPTIVE_PORTAL_DIR / "generate_204").write_text("")
            (self.CAPTIVE_PORTAL_DIR / "gen_204").write_text("")
            
            # Create captive portal server script with auto-reload
            # CRITICAL FIX: Use ap_ip_clean for server script!
            self.log(f"[DEBUG] Creating server script with ap_ip_clean: '{ap_ip_clean}'", "DEBUG")
            server_script = get_portal_server_script(ap_ip_clean, port, self.CAPTIVE_PORTAL_DIR, portal_services_file)
            
            # VERIFICATION: Check server script has correct IP
            if '{{AP_IP}}' in server_script:
                self.log("[ERROR] Server script still contains {{AP_IP}} placeholder!", "ERROR")
                server_script = server_script.replace('{{AP_IP}}', ap_ip_clean)
                self.log("[FIX] Applied emergency placeholder replacement to server script", "WARN")
            
            self.CAPTIVE_PORTAL_SCRIPT.write_text(server_script)
            self.CAPTIVE_PORTAL_SCRIPT.chmod(0o755)
            self.log(f"Created portal server with auto-reload: {self.CAPTIVE_PORTAL_SCRIPT}")
            
            # Create systemd service
            service_content = f"""[Unit]
Description=PiNetAP Captive Portal (Auto-redirect & Auto-reload)
After=network.target NetworkManager.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 {self.CAPTIVE_PORTAL_SCRIPT}
Restart=always
RestartSec=3
User=root
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"""
            self.CAPTIVE_PORTAL_SERVICE.write_text(service_content)
            self.log(f"Created systemd service: {self.CAPTIVE_PORTAL_SERVICE}")
            
            # Configure iptables to intercept HTTP/HTTPS traffic
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
            
            # Stop and disable service
            self.run_command(["systemctl", "stop", "pinetap-portal"], check=False)
            self.run_command(["systemctl", "disable", "pinetap-portal"], check=False)
            
            # Remove iptables rules
            self.firewall.remove_captive_portal_iptables()
            
            # Remove DNS configs from BOTH directories
            for conf_dir in [self.DNSMASQ_CONF_DIR, Path("/etc/NetworkManager/dnsmasq-shared.d")]:
                if conf_dir.exists():
                    for conf_file in conf_dir.glob("pinetap-captive-*.conf"):
                        try:
                            conf_file.unlink()
                            self.log(f"Removed DNS config: {conf_file}")
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