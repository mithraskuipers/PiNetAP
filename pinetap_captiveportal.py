#!/usr/bin/env python3
"""
PiNetAP Captive Portal - DNS Configuration and HTTP Server Management
Contains captive portal setup, DNS hijacking, and portal server management
"""

import time
from typing import Optional, List, Dict
from pathlib import Path
from pinetap_core import PiNetAPCore
from pinetap_firewall import PiNetAPFirewall
from pinetap_portal_template import get_captive_portal_html, get_portal_server_script


class PiNetAPCaptivePortal(PiNetAPCore):
    """Captive portal and DNS management"""

    def __init__(self):
        super().__init__()
        self.firewall = PiNetAPFirewall()

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

    def configure_captive_portal_dns(self, ap_interface: str, ap_ip: str) -> bool:
        """
        FIXED: Configure DNS ONLY for the AP interface with enhanced detection.
        This is CRITICAL for captive portal detection to work properly.
        """
        try:
            self.log(f"Configuring enhanced captive DNS for {ap_interface}...")
            
            # CRITICAL: Enhanced DNS configuration for reliable captive portal detection
            captive_dns_conf = f"""# PiNetAP Captive Portal DNS - Enhanced for Auto-Detection
# CRITICAL: Only affects {ap_interface}, not other interfaces

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
            
            self.log(f"✓ Enhanced DNS hijacking configured for {ap_interface}", "SUCCESS")
            self.log(f"  ALL DNS queries from {ap_interface} → {ap_ip}", "INFO")
            self.log(f"  This triggers captive portal detection!", "INFO")
            self.log(f"  Config: {captive_dns_file}", "INFO")
            self.log(f"  ⚠️ IMPORTANT: Using dnsmasq-shared.d (required by NetworkManager)", "INFO")
            
            return True
        except Exception as e:
            self.log(f"Failed to configure DNS: {e}", "ERROR")
            return False

    def setup_captive_portal(self, ap_interface: str, ap_ip: str, ssid: str, 
                           services: Optional[List[Dict]] = None, port: int = 80) -> bool:
        """Setup captive portal using lightweight Python HTTP server with DNS+iptables interception"""
        try:
            self.log("Setting up captive portal (pure Python, no additional packages needed)...")
            return self._setup_offline_captive_portal(ap_interface, ap_ip, ssid, services, port)
        except Exception as e:
            self.log(f"Failed to setup captive portal: {e}", "ERROR")
            return False

    def _setup_offline_captive_portal(self, ap_interface: str, ap_ip: str, ssid: str,
                                    services: Optional[List[Dict]] = None, port: int = 80) -> bool:
        """Setup offline captive portal - works like Starbucks WiFi with auto-redirect"""
        try:
            self.log("Setting up captive portal with auto-redirect (like Starbucks WiFi)...")
            
            # Create portal directory
            self.CAPTIVE_PORTAL_DIR.mkdir(parents=True, exist_ok=True)
            
            # Generate splash page HTML
            html_content = get_captive_portal_html(ap_ip, ssid, services)
            splash_page = self.CAPTIVE_PORTAL_DIR / "splash.html"
            splash_page.write_text(html_content)
            index_page = self.CAPTIVE_PORTAL_DIR / "index.html"
            index_page.write_text(html_content)
            self.log(f"Created portal pages: {splash_page} and {index_page}")
            
            # Create SUCCESS page for Android (critical!)
            success_page = self.CAPTIVE_PORTAL_DIR / "success.txt"
            success_page.write_text("success\n")
            
            # Create empty files for detection endpoints
            (self.CAPTIVE_PORTAL_DIR / "generate_204").write_text("")
            (self.CAPTIVE_PORTAL_DIR / "gen_204").write_text("")
            
            # Create captive portal server script
            server_script = get_portal_server_script(ap_ip, port, self.CAPTIVE_PORTAL_DIR)
            self.CAPTIVE_PORTAL_SCRIPT.write_text(server_script)
            self.CAPTIVE_PORTAL_SCRIPT.chmod(0o755)
            self.log(f"Created portal server: {self.CAPTIVE_PORTAL_SCRIPT}")
            
            # Create systemd service
            service_content = f"""[Unit]
Description=PiNetAP Captive Portal (Auto-redirect)
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
            self.firewall.setup_captive_portal_iptables(ap_interface, ap_ip)
            
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
                self.log(f"✓ Captive portal running at http://{ap_ip}:{port}", "SUCCESS")
                self.log(f"  Portal will auto-popup on iOS, Android, Windows devices", "SUCCESS")
                
                # Test the portal server
                self.log("\n🧪 Testing portal server...", "INFO")
                ret, stdout, _ = self.run_command([
                    "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                    f"http://{ap_ip}/"
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
            
            return status
            
        except Exception as e:
            self.log(f"Failed to get portal status: {e}", "ERROR")
            return {"active": False, "error": str(e)}
