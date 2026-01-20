#!/usr/bin/env python3
"""
PiNetAP Network - Captive Portal and Network Configuration
Contains all networking, captive portal, DNS, and iptables management
FIXED: Enhanced captive portal detection for reliable auto-popup
"""

import time
from typing import Optional, List, Dict
from pathlib import Path
from pinetap_core import PiNetAPCore


class PiNetAPNetwork(PiNetAPCore):
    """Network configuration and captive portal management"""

    def enable_ip_forwarding(self) -> bool:
        """Enable IP forwarding for internet sharing"""
        try:
            self.log("Enabling IP forwarding...")
            ret, _, _ = self.run_command([
                "sysctl", "-w", "net.ipv4.ip_forward=1"
            ], check=False)
            
            if ret == 0:
                self.log("✓ IP forwarding enabled", "SUCCESS")
                return True
            else:
                self.log("Failed to enable IP forwarding", "ERROR")
                return False
                
        except Exception as e:
            self.log(f"Failed to enable IP forwarding: {e}", "ERROR")
            return False

    def disable_ip_forwarding(self) -> bool:
        """Disable IP forwarding for standalone mode"""
        try:
            self.log("Disabling IP forwarding...")
            ret, _, _ = self.run_command([
                "sysctl", "-w", "net.ipv4.ip_forward=0"
            ], check=False)
            
            if ret == 0:
                self.log("✓ IP forwarding disabled", "SUCCESS")
                return True
            else:
                self.log("Failed to disable IP forwarding", "ERROR")
                return False
                
        except Exception as e:
            self.log(f"Failed to disable IP forwarding: {e}", "ERROR")
            return False

    def setup_nat_rules(self, ap_interface: str) -> bool:
        """Setup NAT (masquerading) for internet sharing"""
        try:
            self.log(f"Setting up NAT for {ap_interface}...")
            
            # Enable masquerading for the AP interface
            ret, _, _ = self.run_command([
                "iptables", "-t", "nat", "-A", "POSTROUTING",
                "-o", ap_interface, "!", "-d", "192.168.0.0/16",
                "-j", "MASQUERADE"
            ], check=False)
            
            if ret == 0:
                self.log("✓ NAT rules configured", "SUCCESS")
                return True
            else:
                self.log("Failed to setup NAT rules", "ERROR")
                return False
                
        except Exception as e:
            self.log(f"Failed to setup NAT: {e}", "ERROR")
            return False

    def block_forwarding_except_local(self, ap_interface: str) -> bool:
        """Block IP forwarding except for local network (standalone mode)"""
        try:
            self.log(f"Blocking forwarding for {ap_interface} (standalone mode)...")
            
            # Flush FORWARD chain first
            self.run_command([
                "iptables", "-F", "FORWARD"
            ], check=False)
            
            # Allow local network traffic on the AP interface
            self.run_command([
                "iptables", "-A", "FORWARD",
                "-i", ap_interface,
                "-d", "192.168.0.0/16",
                "-j", "ACCEPT"
            ], check=False)
            
            self.run_command([
                "iptables", "-A", "FORWARD",
                "-o", ap_interface,
                "-s", "192.168.0.0/16",
                "-j", "ACCEPT"
            ], check=False)
            
            # Drop everything else (no internet forwarding)
            self.run_command([
                "iptables", "-A", "FORWARD",
                "-i", ap_interface,
                "-j", "DROP"
            ], check=False)
            
            self.log("✓ Firewall configured for standalone mode", "SUCCESS")
            return True
            
        except Exception as e:
            self.log(f"Failed to block forwarding: {e}", "ERROR")
            return False

    def reload_networkmanager(self, delay: int = 2) -> bool:
        """Reload NetworkManager and wait for it to settle"""
        try:
            self.log("Reloading NetworkManager...")
            
            ret, _, _ = self.run_command([
                "systemctl", "reload", "NetworkManager"
            ], check=False)
            
            if ret != 0:
                self.log("Failed to reload NetworkManager", "WARN")
                return False
            
            if delay > 0:
                self.log(f"Waiting {delay} seconds for NetworkManager to settle...")
                time.sleep(delay)
            
            self.log("✓ NetworkManager reloaded", "SUCCESS")
            return True
            
        except Exception as e:
            self.log(f"Failed to reload NetworkManager: {e}", "ERROR")
            return False

    def configure_captive_portal_dns(self, ap_interface: str, ap_ip: str) -> bool:
        """Configure DNS for captive portal - wrapper for _configure_captive_portal_dns"""
        return self._configure_captive_portal_dns(ap_interface, ap_ip)

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
            self.reload_networkmanager(delay=3)
            
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

    def _remove_captive_portal_iptables(self) -> bool:
        """Remove captive portal iptables rules"""
        try:
            self.log("Removing captive portal iptables rules...")
            
            # Flush NAT PREROUTING rules
            self.run_command([
                "iptables", "-t", "nat", "-F", "PREROUTING"
            ], check=False)
            
            # Flush NAT POSTROUTING rules
            self.run_command([
                "iptables", "-t", "nat", "-F", "POSTROUTING"
            ], check=False)
            
            self.log("✓ Captive portal iptables rules removed", "SUCCESS")
            return True
            
        except Exception as e:
            self.log(f"Failed to remove iptables rules: {e}", "WARN")
            return False

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
            
            # Create empty files for detection endpoints
            (self.CAPTIVE_PORTAL_DIR / "generate_204").write_text("")
            (self.CAPTIVE_PORTAL_DIR / "gen_204").write_text("")
            
            # Create captive portal server script with PROPER detection
            # CRITICAL: Use raw string formatting to avoid indentation issues
            server_script = '''#!/usr/bin/env python3
import http.server
import socketserver
import os
import sys
import traceback

PORT = ''' + str(port) + '''
AP_IP = "''' + ap_ip + '''"

# Force unbuffered output so we see logs immediately
sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', buffering=1)
sys.stderr = os.fdopen(sys.stderr.fileno(), 'w', buffering=1)

print("[STARTUP] Captive Portal Server Starting...")
print(f"[STARTUP] Port: {PORT}")
print(f"[STARTUP] AP IP: {AP_IP}")
print(f"[STARTUP] Working directory: {os.getcwd()}")

class CaptivePortalHandler(http.server.SimpleHTTPRequestHandler):

    def log_message(self, format, *args):
        """Log all requests for debugging"""
        print(f"{self.address_string()} - {format % args}")

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
        client_ip = self.client_address[0]
        print(f"[REQUEST] {path} from {client_ip}")
        
        # === CRITICAL: Android Detection (MOST IMPORTANT) ===
        if "/generate_204" in path or "/gen_204" in path or "generate204" in path:
            print("[ANDROID] Detection endpoint hit - returning 200 with portal!")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")
            self.send_header("Connection", "close")
            
            try:
                with open("index.html", "rb") as f:
                    content = f.read()
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
                print(f"[ANDROID] Sent {len(content)} bytes of portal HTML")
            except Exception as e:
                print(f"[ERROR] Reading index.html: {e}")
                error_html = b"<html><body><h1>Captive Portal</h1></body></html>"
                self.send_header("Content-Length", str(len(error_html)))
                self.end_headers()
                self.wfile.write(error_html)
            return
        
        # Android success check (after login)
        if "success.txt" in path:
            print("[ANDROID] Success check - returning 204")
            self.send_response(204)
            self.end_headers()
            return
        
        # === iOS/macOS Detection ===
        if "hotspot-detect" in path or "/library/test/success.html" in path or "success.html" in path:
            print("[iOS] Detection endpoint hit")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
            with open("index.html", "rb") as f:
                content = f.read()
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            return
        
        # === Windows Detection ===
        if "ncsi.txt" in path:
            print("[WINDOWS] Detection endpoint hit (ncsi.txt)")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            with open("index.html", "rb") as f:
                content = f.read()
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            return
            
        if "connecttest.txt" in path:
            print("[WINDOWS] Detection endpoint hit (connecttest.txt)")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            with open("index.html", "rb") as f:
                content = f.read()
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            return

        # === Firefox Detection ===
        if "canonical.html" in path or "detectportal" in path:
            print("[FIREFOX] Detection endpoint hit")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            with open("index.html", "rb") as f:
                content = f.read()
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            return

        # === Normal browsing ===
        if path in ("/", "/index.html", "/splash.html"):
            print("[PORTAL] Serving main page")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            with open("index.html", "rb") as f:
                content = f.read()
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            return

        # === Everything else: redirect to portal ===
        print(f"[REDIRECT] Unknown path {path} -> portal")
        self.send_response(302)
        self.send_header("Location", "http://''' + ap_ip + '''/")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()

if __name__ == "__main__":
    try:
        os.chdir("''' + str(self.CAPTIVE_PORTAL_DIR) + '''")
        print(f"[STARTUP] Changed to directory: {os.getcwd()}")
        
        # Verify files exist
        if not os.path.exists("index.html"):
            print("[ERROR] index.html not found!")
            sys.exit(1)
        else:
            print("[STARTUP] index.html found")
        
        print(f"[STARTUP] Creating server on port {PORT}...")
        with socketserver.TCPServer(("", PORT), CaptivePortalHandler) as httpd:
            print(f"[READY] Captive portal is ACTIVE on {AP_IP}:{PORT}")
            print("[READY] Waiting for connections...")
            print("[READY] Press Ctrl+C to stop")
            sys.stdout.flush()
            httpd.serve_forever()
    except Exception as e:
        print(f"[FATAL ERROR] {e}")
        traceback.print_exc()
        sys.exit(1)
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
            
            # Configure iptables to intercept HTTP/HTTPS traffic
            self._setup_captive_portal_iptables(ap_interface, ap_ip)
            
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

    def _configure_captive_portal_dns(self, ap_interface: str, ap_ip: str) -> bool:
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
            
            # CRITICAL: NetworkManager reads from dnsmasq-shared.d, NOT dnsmasq.d
            dnsmasq_shared_dir = Path("/etc/NetworkManager/dnsmasq-shared.d")
            dnsmasq_shared_dir.mkdir(parents=True, exist_ok=True)
            captive_dns_file = dnsmasq_shared_dir / f"pinetap-captive-{ap_interface}.conf"

            captive_dns_file.write_text(captive_dns_conf)
            
            self.log(f"✓ Enhanced DNS hijacking configured for {ap_interface}", "SUCCESS")
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
            
            # CRITICAL: Flush existing NAT PREROUTING rules for clean slate
            self.log("Flushing NAT PREROUTING rules...")
            self.run_command([
                "iptables", "-t", "nat", "-F", "PREROUTING"
            ], check=False)
            
            # Rule 1: FIRST, allow direct access to portal IP (most important!)
            ret, _, _ = self.run_command([
                "iptables", "-t", "nat", "-A", "PREROUTING",
                "-i", ap_interface, 
                "-d", ap_ip,
                "-j", "ACCEPT"
            ], check=False)
            
            if ret == 0:
                self.log(f"✓ Rule 1: Direct portal access ({ap_ip}) allowed")
            
            # Rule 2: Redirect HTTP (port 80) to portal
            ret, _, stderr = self.run_command([
                "iptables", "-t", "nat", "-A", "PREROUTING",
                "-i", ap_interface, 
                "-p", "tcp", 
                "--dport", "80",
                "!", "-d", ap_ip,  # Don't redirect if already going to portal
                "-j", "DNAT", 
                "--to-destination", f"{ap_ip}:80"
            ], check=False)
            
            if ret == 0:
                self.log(f"✓ Rule 2: HTTP (80) redirect active → {ap_ip}:80")
            else:
                self.log(f"Failed to add HTTP redirect: {stderr}", "ERROR")
                return False
            
            # Rule 3: Redirect HTTPS (port 443) to portal (will show cert error)
            ret, _, _ = self.run_command([
                "iptables", "-t", "nat", "-A", "PREROUTING",
                "-i", ap_interface, 
                "-p", "tcp", 
                "--dport", "443",
                "!", "-d", ap_ip,
                "-j", "DNAT", 
                "--to-destination", f"{ap_ip}:80"
            ], check=False)
            
            if ret == 0:
                self.log(f"✓ Rule 3: HTTPS (443) redirect active → {ap_ip}:80")
            else:
                self.log(f"Warning: Could not redirect HTTPS", "WARN")
            
            # Allow INPUT to portal web server
            self.run_command([
                "iptables", "-A", "INPUT",
                "-i", ap_interface, 
                "-p", "tcp", 
                "--dport", "80",
                "-j", "ACCEPT"
            ], check=False)
            
            self.log("✓ HTTP interception configured", "SUCCESS")
            
            # Display current rules for verification
            self.log("\n📋 Current NAT PREROUTING rules:", "INFO")
            ret, stdout, _ = self.run_command([
                "iptables", "-t", "nat", "-L", "PREROUTING", "-n", "-v", "--line-numbers"
            ], check=False)
            
            if ret == 0:
                for line in stdout.split('\n')[:10]:  # First 10 lines
                    if ap_interface in line or ap_ip in line or "pkts" in line or "Chain" in line:
                        self.log(f"  {line}", "INFO")
            
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
            
            # Remove DNS configs from BOTH directories
            for conf_dir in [self.DNSMASQ_CONF_DIR, Path("/etc/NetworkManager/dnsmasq-shared.d")]:
                if conf_dir.exists():
                    for conf_file in conf_dir.glob("pinetap-captive-*.conf"):
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