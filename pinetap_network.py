#!/usr/bin/env python3
"""
PiNetAP Network - Captive Portal and Network Configuration
Contains all networking, captive portal, DNS, and iptables management
"""

import time
from typing import Optional, List, Dict
from pathlib import Path
from pinetap_core import PiNetAPCore


class PiNetAPNetwork(PiNetAPCore):
    """Network configuration and captive portal management"""

    def get_captive_portal_html(self, ap_ip: str, ssid: str, services: Optional[List[Dict]] = None) -> str:
        """Generate captive portal HTML page"""
        
        if not services:
            services = [
                {"name": "Router Admin", "port": 80, "path": "/", "description": "Web interface"},
            ]
        
        service_cards = ""
        for svc in services:
            port_display = f":{svc['port']}" if svc['port'] != 80 else ""
            url = f"http://{ap_ip}{port_display}{svc.get('path', '/')}"
            service_cards += f"""
                <div class="service-card">
                    <h3>{svc['name']}</h3>
                    <p>{svc.get('description', '')}</p>
                    <a href="{url}" class="service-link">{url}</a>
                </div>
            """
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome to {ssid}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px;
        }}
        .container {{
            background: white; border-radius: 20px; box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            max-width: 600px; width: 100%; padding: 40px; animation: slideUp 0.5s ease;
        }}
        @keyframes slideUp {{ from {{ opacity: 0; transform: translateY(30px); }} to {{ opacity: 1; transform: translateY(0); }} }}
        .header {{ text-align: center; margin-bottom: 30px; }}
        .wifi-icon {{ font-size: 64px; margin-bottom: 10px; }}
        h1 {{ color: #333; font-size: 28px; margin-bottom: 10px; }}
        .ssid {{ color: #667eea; font-weight: bold; }}
        .welcome-text {{ color: #666; font-size: 16px; line-height: 1.6; margin-bottom: 30px; text-align: center; }}
        .ip-box {{
            background: #f7f9fc; border: 2px solid #e1e8ed; border-radius: 12px;
            padding: 20px; margin-bottom: 30px; text-align: center;
        }}
        .ip-label {{ color: #888; font-size: 14px; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px; }}
        .ip-address {{ font-size: 32px; font-weight: bold; color: #667eea; font-family: 'Courier New', monospace; }}
        .services {{ margin-top: 20px; }}
        .services h2 {{ color: #333; font-size: 20px; margin-bottom: 15px; text-align: center; }}
        .service-card {{
            background: #f7f9fc; border-radius: 10px; padding: 20px; margin-bottom: 15px;
            transition: transform 0.2s, box-shadow 0.2s;
        }}
        .service-card:hover {{ transform: translateY(-2px); box-shadow: 0 4px 12px rgba(102, 126, 234, 0.2); }}
        .service-card h3 {{ color: #333; font-size: 18px; margin-bottom: 8px; }}
        .service-card p {{ color: #666; font-size: 14px; margin-bottom: 12px; }}
        .service-link {{
            display: inline-block; color: #667eea; text-decoration: none;
            font-family: 'Courier New', monospace; font-size: 14px; padding: 8px 16px;
            background: white; border-radius: 6px; border: 1px solid #667eea; transition: all 0.2s;
        }}
        .service-link:hover {{ background: #667eea; color: white; }}
        .footer {{
            text-align: center; color: #999; font-size: 12px; margin-top: 30px;
            padding-top: 20px; border-top: 1px solid #e1e8ed;
        }}
        .status-indicator {{
            display: inline-block; width: 8px; height: 8px; background: #4ade80;
            border-radius: 50%; margin-right: 6px; animation: pulse 2s infinite;
        }}
        @keyframes pulse {{ 0%, 100% {{ opacity: 1; }} 50% {{ opacity: 0.5; }} }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="wifi-icon">📡</div>
            <h1>Welcome to <span class="ssid">{ssid}</span></h1>
        </div>
        <p class="welcome-text">
            <span class="status-indicator"></span>
            You're connected! This network provides access to local services.
        </p>
        <div class="ip-box">
            <div class="ip-label">Router IP Address</div>
            <div class="ip-address">{ap_ip}</div>
        </div>
        <div class="services">
            <h2>📦 Available Services</h2>
            {service_cards}
        </div>
        <div class="footer">
            <p>Powered by PiNetAP</p>
            <p>Use the IP address above to access services on this network</p>
        </div>
    </div>
</body>
</html>"""
        return html

    def setup_captive_portal(self, ap_ip: str, ssid: str, ap_interface: str, 
                           services: Optional[List[Dict]] = None, port: int = 80) -> bool:
        """Setup captive portal using lightweight Python HTTP server with DNS+iptables interception"""
        try:
            self.log("Setting up captive portal (pure Python, no additional packages needed)...")
            return self._setup_offline_captive_portal(ap_ip, ssid, ap_interface, services, port)
        except Exception as e:
            self.log(f"Failed to setup captive portal: {e}", "ERROR")
            return False

    def _setup_offline_captive_portal(self, ap_ip: str, ssid: str, ap_interface: str, 
                                    services: Optional[List[Dict]] = None, port: int = 80) -> bool:
        """Setup offline captive portal - works like Starbucks WiFi with auto-redirect"""
        try:
            self.log("Setting up captive portal with auto-redirect (like Starbucks WiFi)...")
            
            # Create portal directory
            self.CAPTIVE_PORTAL_DIR.mkdir(parents=True, exist_ok=True)
            
            # Generate splash page HTML
            html_content = self.get_captive_portal_html(ap_ip, ssid, services)
            splash_page = self.CAPTIVE_PORTAL_DIR / "splash.html"
            splash_page.write_text(html_content)
            index_page = self.CAPTIVE_PORTAL_DIR / "index.html"
            index_page.write_text(html_content)
            self.log(f"Created portal pages: {splash_page} and {index_page}")
            
            # Create SUCCESS page for Android (critical!)
            success_page = self.CAPTIVE_PORTAL_DIR / "success.txt"
            success_page.write_text("success\n")
            
            # Create captive portal server script with PROPER detection
            server_script = f'''#!/usr/bin/env python3
import http.server
import socketserver
import os

PORT = {port}
AP_IP = "{ap_ip}"

class CaptivePortalHandler(http.server.SimpleHTTPRequestHandler):

    def do_HEAD(self):
        """Handle HEAD requests (used by Windows)"""
        path = self.path.lower()
        
        # Windows connectivity check
        if "ncsi.txt" in path or "connecttest.txt" in path:
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", "14")
            self.send_header("Connection", "close")
            self.end_headers()
        else:
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def do_GET(self):
        path = self.path.lower()
        
        # === ANDROID DETECTION (CRITICAL!) ===
        # Android checks these endpoints and expects HTTP 204 or specific responses
        if path in ("/generate_204", "/gen_204"):
            # Return 200 with portal page to trigger captive portal
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            with open("index.html", "rb") as f:
                self.wfile.write(f.read())
            return
            
        # Android success check
        if "success.txt" in path:
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"success\\n")
            return

        # === WINDOWS DETECTION ===
        if "ncsi.txt" in path:
            # Return portal instead of expected "Microsoft NCSI"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            with open("index.html", "rb") as f:
                self.wfile.write(f.read())
            return
            
        if "connecttest.txt" in path:
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            with open("index.html", "rb") as f:
                self.wfile.write(f.read())
            return

        # === APPLE DETECTION ===
        if "hotspot-detect" in path or "hotspot" in path:
            # iOS/macOS expects specific HTML response
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            with open("index.html", "rb") as f:
                self.wfile.write(f.read())
            return
            
        if "success.html" in path or "apple.com" in path:
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            with open("index.html", "rb") as f:
                self.wfile.write(f.read())
            return

        # === FIREFOX DETECTION ===
        if "detectportal.firefox.com" in path or "canonical.html" in path:
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            with open("index.html", "rb") as f:
                self.wfile.write(f.read())
            return

        # === NORMAL BROWSING ===
        if path in ("/", "/index.html", "/splash.html"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            with open("index.html", "rb") as f:
                self.wfile.write(f.read())
            return

        # Everything else: redirect to portal
        self.send_response(302)
        self.send_header("Location", f"http://{{AP_IP}}/")
        self.end_headers()

    def log_message(self, format, *args):
        """Log requests for debugging"""
        print(f"{{self.address_string()}} - {{format % args}}")

if __name__ == "__main__":
    os.chdir("{self.CAPTIVE_PORTAL_DIR}")
    print(f"Starting captive portal on port {{PORT}}...")
    print(f"Portal IP: {{AP_IP}}")
    with socketserver.TCPServer(("", PORT), CaptivePortalHandler) as httpd:
        print(f"Captive portal ready!")
        httpd.serve_forever()
'''
            
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
            
            # Configure interface-specific DNS (CRITICAL for captive portal detection!)
            self._configure_captive_portal_dns(ap_interface, ap_ip)
            
            # Configure iptables to intercept HTTP/HTTPS traffic
            self._setup_captive_portal_iptables(ap_interface, ap_ip)
            
            # Reload systemd and start service
            self.run_command(["systemctl", "daemon-reload"], check=False)
            self.run_command(["systemctl", "enable", "pinetap-portal"], check=False)
            self.run_command(["systemctl", "restart", "pinetap-portal"], check=False)
            
            # Wait and verify
            time.sleep(2)
            ret, _, _ = self.run_command(["systemctl", "is-active", "pinetap-portal"], check=False)
            if ret == 0:
                self.log(f"✓ Captive portal running at http://{ap_ip}:{port}", "SUCCESS")
                self.log(f"  Portal will auto-popup on iOS, Android, Windows devices", "SUCCESS")
                self.log(f"  DNS: Detection domains → {ap_ip}", "INFO")
                self.log(f"  HTTP: Port 80 → Portal", "INFO")
                self.log(f"  HTTPS: Port 443 → Portal (redirected)", "INFO")
                
                # Test the portal server
                self.log("\n🧪 Testing portal server...", "INFO")
                ret, stdout, _ = self.run_command([
                    "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                    f"http://{ap_ip}/"
                ], check=False)
                if ret == 0 and stdout.strip() == "200":
                    self.log("  ✓ Portal responds correctly", "SUCCESS")
                else:
                    self.log(f"  ⚠ Portal response: {stdout}", "WARN")
                
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

    def _configure_captive_portal_dns(self, ap_interface: str, ap_ip: str) -> bool:
        """
        Configure DNS ONLY for the AP interface to redirect ALL queries to portal.
        This is CRITICAL for captive portal detection to work properly.
        """
        try:
            self.log(f"Configuring captive DNS for {ap_interface}...")
            
            # CRITICAL: This config makes ALL DNS queries from AP clients return the portal IP
            # This triggers the captive portal detection on devices
            captive_dns_conf = f"""# PiNetAP Captive Portal DNS - INTERFACE SPECIFIC
# CRITICAL: Only affects {ap_interface}, not other interfaces

# Bind ONLY to the AP interface and its IP
interface={ap_interface}
listen-address={ap_ip}
bind-interfaces

# CRITICAL: Return portal IP for ALL domains (this triggers captive portal detection)
address=/#/{ap_ip}

# Specific overrides for known captive portal detection endpoints
# iOS/macOS
address=/captive.apple.com/{ap_ip}
address=/www.apple.com/{ap_ip}
# Android
address=/connectivitycheck.android.com/{ap_ip}
address=/connectivitycheck.gstatic.com/{ap_ip}
address=/clients3.google.com/{ap_ip}
address=/www.google.com/{ap_ip}
# Windows
address=/www.msftconnecttest.com/{ap_ip}
address=/www.msftncsi.com/{ap_ip}
address=/ipv6.msftconnecttest.com/{ap_ip}
# Firefox
address=/detectportal.firefox.com/{ap_ip}
address=/detectportal.cdn.mozilla.net/{ap_ip}

# Don't forward queries upstream - we answer everything
no-resolv
no-poll
bogus-priv

# Disable caching for immediate response
cache-size=0

# DHCP for this interface (optional, NetworkManager handles this)
# But we can add some options for better compatibility
dhcp-option={ap_interface},3,{ap_ip}
dhcp-option={ap_interface},6,{ap_ip}
"""
            
            captive_dns_file = self.DNSMASQ_CONF_DIR / f"pinetap-captive-{ap_interface}.conf"
            self.DNSMASQ_CONF_DIR.mkdir(parents=True, exist_ok=True)
            captive_dns_file.write_text(captive_dns_conf)
            
            self.log(f"✓ DNS hijacking configured for {ap_interface}", "SUCCESS")
            self.log(f"  ALL DNS queries from {ap_interface} → {ap_ip}", "INFO")
            self.log(f"  This triggers captive portal detection!", "INFO")
            self.log(f"  Config: {captive_dns_file}", "INFO")
            
            return True
        except Exception as e:
            self.log(f"Failed to configure DNS: {e}", "ERROR")
            return False

    def _setup_captive_portal_iptables(self, ap_interface: str, ap_ip: str) -> bool:
        """Setup iptables rules ONLY for the AP interface to intercept HTTP traffic"""
        try:
            self.log(f"Setting up HTTP/HTTPS interception for {ap_interface}...")
            
            ret, _, _ = self.run_command(["which", "iptables"], check=False)
            if ret != 0:
                self.log("iptables not found", "WARN")
                return False
            
            # Remove old rules if they exist (cleanup)
            self.run_command([
                "iptables", "-t", "nat", "-D", "PREROUTING",
                "-i", ap_interface, "-p", "tcp", "--dport", "80",
                "-j", "DNAT", "--to-destination", f"{ap_ip}:80"
            ], check=False)
            
            self.run_command([
                "iptables", "-t", "nat", "-D", "PREROUTING",
                "-i", ap_interface, "-p", "tcp", "--dport", "443",
                "-j", "DNAT", "--to-destination", f"{ap_ip}:80"
            ], check=False)
            
            # CRITICAL: Allow traffic destined for the portal itself FIRST
            # This rule must come before the redirect rules
            ret, _, _ = self.run_command([
                "iptables", "-t", "nat", "-I", "PREROUTING", "1",
                "-i", ap_interface, "-p", "tcp", "-d", ap_ip,
                "-j", "ACCEPT"
            ], check=False)
            
            if ret == 0:
                self.log(f"✓ Allowed direct traffic to portal ({ap_ip})")
            
            # Redirect HTTP (port 80) traffic to portal
            ret, _, stderr = self.run_command([
                "iptables", "-t", "nat", "-A", "PREROUTING",
                "-i", ap_interface, "-p", "tcp", "--dport", "80",
                "-j", "DNAT", "--to-destination", f"{ap_ip}:80"
            ], check=False)
            
            if ret == 0:
                self.log(f"✓ HTTP (80) traffic on {ap_interface} → {ap_ip}:80")
            else:
                self.log(f"Failed to add HTTP redirect: {stderr}", "WARN")
                return False
            
            # Redirect HTTPS (port 443) traffic to portal (will show cert error, but that's expected)
            ret, _, stderr = self.run_command([
                "iptables", "-t", "nat", "-A", "PREROUTING",
                "-i", ap_interface, "-p", "tcp", "--dport", "443",
                "-j", "DNAT", "--to-destination", f"{ap_ip}:80"
            ], check=False)
            
            if ret == 0:
                self.log(f"✓ HTTPS (443) traffic on {ap_interface} → {ap_ip}:80")
            else:
                self.log(f"Warning: Could not redirect HTTPS: {stderr}", "WARN")
            
            # Allow INPUT to portal web server
            self.run_command([
                "iptables", "-I", "INPUT", "1",
                "-i", ap_interface, "-p", "tcp", "--dport", "80",
                "-j", "ACCEPT"
            ], check=False)
            
            self.log("✓ HTTP interception configured", "SUCCESS")
            self.log(f"  Traffic from {ap_interface} will be redirected to portal", "INFO")
            
            # Display current rules for verification
            if self.verbose:
                self.log("\n📋 Current NAT PREROUTING rules:", "DEBUG")
                ret, stdout, _ = self.run_command([
                    "iptables", "-t", "nat", "-L", "PREROUTING", "-n", "-v"
                ], check=False)
                if ret == 0:
                    for line in stdout.split('\n')[:10]:  # First 10 lines
                        self.log(f"  {line}", "DEBUG")
            
            self._save_iptables_rules()
            return True
            
        except Exception as e:
            self.log(f"Failed to setup iptables: {e}", "ERROR")
            import traceback
            self.log(traceback.format_exc(), "ERROR")
            return False

    def _save_iptables_rules(self) -> bool:
        """Save iptables rules to persist across reboots"""
        try:
            ret, _, _ = self.run_command(["which", "iptables-save"], check=False)
            if ret != 0:
                return False
            
            rules_file = Path("/etc/pinetap/iptables-captive.rules")
            self.PINETAP_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            
            ret, stdout, _ = self.run_command(["iptables-save"], check=False)
            if ret == 0 and stdout:
                rules_file.write_text(stdout)
                self.log(f"Saved iptables rules to {rules_file}")
            
            return True
        except Exception as e:
            self.log(f"Failed to save iptables rules: {e}", "WARN")
            return False

    def remove_captive_portal(self) -> bool:
        """Remove captive portal files and service"""
        try:
            self.log("Removing captive portal...")
            
            # Stop and disable service
            self.run_command(["systemctl", "stop", "pinetap-portal"], check=False)
            self.run_command(["systemctl", "disable", "pinetap-portal"], check=False)
            
            # Remove iptables rules
            self._remove_captive_portal_iptables()
            
            # Remove DNS configs
            for conf_file in self.DNSMASQ_CONF_DIR.glob("pinetap-captive-*.conf"):
                conf_file.unlink()
                self.log(f"Removed DNS config: {conf_file}")
            
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

    def _remove_captive_portal_iptables(self) -> bool:
        """Remove iptables HTTP redirect rules"""
        try:
            ret, _, _ = self.run_command(["which", "iptables"], check=False)
            if ret != 0:
                return True
            
            self.log("Removing HTTP redirect iptables rules...")
            
            # Get all WiFi interfaces
            interfaces = self.get_available_interfaces()
            wifi_interfaces = [name for name, info in interfaces.items() if info['type'] == 'wifi']
            
            # Remove rules for each interface
            for iface in wifi_interfaces:
                self.run_command([
                    "iptables", "-t", "nat", "-D", "PREROUTING",
                    "-i", iface, "-p", "tcp", "--dport", "80",
                    "-j", "DNAT"
                ], check=False)
                
                self.run_command([
                    "iptables", "-t", "nat", "-D", "PREROUTING",
                    "-i", iface, "-p", "tcp", "--dport", "443",
                    "-j", "DNAT"
                ], check=False)
            
            self.log("Cleaned up iptables redirect rules")
            return True
        except Exception as e:
            self.log(f"Failed to remove iptables rules: {e}", "WARN")
            return False

    def configure_captive_portal_dns(self, ap_interface: str, ap_ip: str) -> bool:
        """Configure DNS for captive portal - interface specific"""
        return self._configure_captive_portal_dns(ap_interface, ap_ip)

    # IP Forwarding and Firewall Management
    def save_original_system_state(self):
        """Save original system state before making changes"""
        if self.SYSTEM_STATE_CONFIG.exists():
            return
        
        state = {}
        
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "r") as f:
                state['ip_forward'] = int(f.read().strip())
        except Exception:
            state['ip_forward'] = 0
        
        try:
            ret, stdout, _ = self.run_command(["iptables", "-L", "FORWARD", "-n"], check=False)
            if ret == 0:
                for line in stdout.split('\n'):
                    if line.startswith('Chain FORWARD'):
                        if 'policy ACCEPT' in line:
                            state['forward_policy'] = 'ACCEPT'
                        elif 'policy DROP' in line:
                            state['forward_policy'] = 'DROP'
                        else:
                            state['forward_policy'] = 'ACCEPT'
                        break
                else:
                    state['forward_policy'] = 'ACCEPT'
            else:
                state['forward_policy'] = None
        except Exception:
            state['forward_policy'] = None
        
        state['saved_at'] = time.time()
        
        self.PINETAP_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        import json
        self.SYSTEM_STATE_CONFIG.write_text(json.dumps(state, indent=2))
        self.log(f"Saved original system state")

    def restore_original_system_state(self):
        """Restore system to original state"""
        if not self.SYSTEM_STATE_CONFIG.exists():
            self.log("No saved system state, using defaults", "WARN")
            self.enable_ip_forwarding()
            self.restore_iptables_policy('ACCEPT')
            return
        
        try:
            import json
            state = json.loads(self.SYSTEM_STATE_CONFIG.read_text())
            
            if state.get('ip_forward') == 1:
                self.enable_ip_forwarding()
            else:
                self.disable_ip_forwarding()
            
            if state.get('forward_policy'):
                self.restore_iptables_policy(state['forward_policy'])
            
            self.SYSTEM_STATE_CONFIG.unlink()
            
        except Exception as e:
            self.log(f"Failed to restore system state: {e}", "ERROR")

    def restore_iptables_policy(self, policy: str = 'ACCEPT'):
        """Restore iptables FORWARD policy"""
        try:
            ret, _, _ = self.run_command(["which", "iptables"], check=False)
            if ret != 0:
                return
            
            # Clear all custom rules
            self.run_command(["iptables", "-F", "FORWARD"], check=False)
            self.run_command(["iptables", "-t", "nat", "-F"], check=False)
            
            # Set policy
            self.run_command(["iptables", "-P", "FORWARD", policy], check=False)
            self.log(f"iptables FORWARD policy set to {policy}")
            
        except Exception as e:
            self.log(f"Could not restore iptables: {e}", "WARN")

    def disable_ip_forwarding(self) -> bool:
        """Disable IP forwarding"""
        try:
            self.run_command(["sysctl", "-w", "net.ipv4.ip_forward=0"], check=False)
            self.log("IP forwarding disabled")
            return True
        except Exception as e:
            self.log(f"Failed to disable IP forwarding: {e}", "WARN")
            return False

    def enable_ip_forwarding(self) -> bool:
        """Enable IP forwarding for internet sharing"""
        try:
            self.run_command(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=False)
            self.log("IP forwarding enabled")
            return True
        except Exception as e:
            self.log(f"Failed to enable IP forwarding: {e}", "WARN")
            return False

    def setup_nat_rules(self, ap_interface: str) -> bool:
        """Setup NAT/MASQUERADE for internet sharing"""
        try:
            ret, _, _ = self.run_command(["which", "iptables"], check=False)
            if ret != 0:
                self.log("iptables not found", "WARN")
                return False
            
            # Clear old rules
            self.run_command(["iptables", "-t", "nat", "-F"], check=False)
            self.run_command(["iptables", "-F", "FORWARD"], check=False)
            
            # Set FORWARD policy to ACCEPT
            self.run_command(["iptables", "-P", "FORWARD", "ACCEPT"], check=False)
            
            # Add MASQUERADE rule for internet sharing
            ret, _, stderr = self.run_command([
                "iptables", "-t", "nat", "-A", "POSTROUTING",
                "-o", "!", ap_interface,
                "-j", "MASQUERADE"
            ], check=False)
            
            if ret == 0:
                self.log(f"✓ NAT enabled for {ap_interface}")
            else:
                self.log(f"Warning: Failed to add NAT rule: {stderr}", "WARN")
            
            # Allow forwarding from AP interface
            self.run_command([
                "iptables", "-A", "FORWARD",
                "-i", ap_interface,
                "-j", "ACCEPT"
            ], check=False)
            
            # Allow related/established connections
            self.run_command([
                "iptables", "-A", "FORWARD",
                "-m", "state", "--state", "RELATED,ESTABLISHED",
                "-j", "ACCEPT"
            ], check=False)
            
            return True
        except Exception as e:
            self.log(f"Failed to setup NAT: {e}", "ERROR")
            return False

    def block_forwarding_except_local(self, ap_interface: str) -> bool:
        """
        Block all forwarding to prevent internet sharing, but allow local AP network traffic.
        CRITICAL FIX: Only block forwarding FROM ap_interface, not all forwarding.
        """
        try:
            ret, _, _ = self.run_command(["which", "iptables"], check=False)
            if ret != 0:
                self.log("iptables not found, relying on disabled IP forwarding", "WARN")
                return True
            
            # Clear NAT rules
            self.run_command(["iptables", "-t", "nat", "-F"], check=False)
            
            # Clear FORWARD chain
            self.run_command(["iptables", "-F", "FORWARD"], check=False)
            
            # CRITICAL FIX: Set default policy to ACCEPT, then add specific DROP rules
            # This allows other interfaces (like uplink) to work normally
            self.run_command(["iptables", "-P", "FORWARD", "ACCEPT"], check=False)
            
            # Block forwarding FROM the AP interface to other interfaces (prevents internet sharing)
            # But this doesn't affect the uplink interface's ability to reach the internet
            ret, _, stderr = self.run_command([
                "iptables", "-I", "FORWARD", "1",
                "-i", ap_interface, "!", "-o", ap_interface,
                "-j", "DROP"
            ], check=False)
            
            if ret == 0:
                self.log(f"✓ Blocked forwarding from {ap_interface} (standalone mode)")
                self.log(f"  Local AP traffic: ✓ Allowed", "INFO")
                self.log(f"  Internet via AP: ✗ Blocked", "INFO")
                self.log(f"  Other interfaces: ✓ Unaffected", "INFO")
            else:
                self.log(f"Warning: Failed to block forwarding: {stderr}", "WARN")
            
            return True
        except Exception as e:
            self.log(f"Failed to configure iptables: {e}", "WARN")
            return False