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
        """Setup captive portal using lightweight Python HTTP server with iptables interception"""
        try:
            self.log("Setting up captive portal...")
            return self._setup_offline_captive_portal(ap_ip, ssid, ap_interface, services, port)
        except Exception as e:
            self.log(f"Failed to setup captive portal: {e}", "ERROR")
            return False

    def _setup_offline_captive_portal(self, ap_ip: str, ssid: str, ap_interface: str, 
                                     services: Optional[List[Dict]] = None, port: int = 80) -> bool:
        """Setup offline captive portal using Python HTTP server - works without internet"""
        try:
            self.log("Setting up offline captive portal (no nodogsplash needed)...")
            
            self.CAPTIVE_PORTAL_DIR.mkdir(parents=True, exist_ok=True)
            
            html_content = self.get_captive_portal_html(ap_ip, ssid, services)
            splash_page = self.CAPTIVE_PORTAL_DIR / "splash.html"
            splash_page.write_text(html_content)
            self.log(f"Created splash page: {splash_page}")
            
            server_script = f'''#!/usr/bin/env python3
"""Offline Captive Portal Server - Works without internet"""
import http.server
import socketserver
import os
from urllib.parse import urlparse

class CaptivePortalHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        
        detection_endpoints = {{
            '/hotspot-detect.html': 'apple', '/library/test/success.html': 'apple',
            '/generate_204': 'android', '/gen_204': 'android',
            '/ncsi.txt': 'windows', '/connecttest.txt': 'windows',
            '/success.txt': 'firefox', '/canonical.html': 'ubuntu',
        }}
        
        if path in detection_endpoints:
            platform = detection_endpoints[path]
            if platform == 'android':
                self.send_response(302)
                self.send_header('Location', 'http://{ap_ip}/splash.html')
                self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
                self.end_headers()
                return
            elif platform == 'apple':
                self.send_response(200)
                self.send_header('Content-Type', 'text/html')
                self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
                self.end_headers()
                html = '<HTML><HEAD><TITLE>Captive Portal</TITLE></HEAD><BODY>Login Required</BODY></HTML>'
                self.wfile.write(html.encode())
                return
            elif platform == 'windows':
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain')
                self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
                self.end_headers()
                self.wfile.write(b'Captive Portal Active')
                return
        
        if path == '/' or path == '/splash.html':
            self.path = '/splash.html'
            return http.server.SimpleHTTPRequestHandler.do_GET(self)
        
        self.send_response(302)
        self.send_header('Location', 'http://{ap_ip}/splash.html')
        self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
        self.end_headers()
    
    def log_message(self, format, *args):
        pass

def main():
    os.chdir('{self.CAPTIVE_PORTAL_DIR}')
    with socketserver.TCPServer(("{ap_ip}", {port}), CaptivePortalHandler) as httpd:
        print(f"Offline Captive Portal running on {{ap_ip}}:{{port}}")
        httpd.serve_forever()

if __name__ == '__main__':
    main()
'''
            
            self.CAPTIVE_PORTAL_SCRIPT.write_text(server_script)
            self.CAPTIVE_PORTAL_SCRIPT.chmod(0o755)
            self.log(f"Created portal server: {self.CAPTIVE_PORTAL_SCRIPT}")
            
            service_content = f"""[Unit]
Description=PiNetAP Offline Captive Portal
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 {self.CAPTIVE_PORTAL_SCRIPT}
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
"""
            self.CAPTIVE_PORTAL_SERVICE.write_text(service_content)
            self.log(f"Created systemd service: {self.CAPTIVE_PORTAL_SERVICE}")
            
            self._configure_offline_dns(ap_interface, ap_ip)
            
            self.run_command(["systemctl", "daemon-reload"], check=False)
            self.run_command(["systemctl", "enable", "pinetap-portal"], check=False)
            self.run_command(["systemctl", "restart", "pinetap-portal"], check=False)
            
            time.sleep(2)
            ret, _, _ = self.run_command(["systemctl", "is-active", "pinetap-portal"], check=False)
            if ret == 0:
                self.log(f"✓ Offline captive portal running at http://{ap_ip}:{port}", "SUCCESS")
                self.log(f"  Portal uses detection tricks to trigger automatic popup", "INFO")
                self.log(f"  Tip: Forget & reconnect WiFi on your device for best results", "INFO")
                return True
            else:
                self.log("Failed to start captive portal service", "ERROR")
                ret2, stdout2, _ = self.run_command(["systemctl", "status", "pinetap-portal"], check=False)
                if stdout2:
                    self.log(f"Status: {stdout2}", "DEBUG")
                return False
                
        except Exception as e:
            self.log(f"Failed to setup offline captive portal: {e}", "ERROR")
            return False

    def _configure_offline_dns(self, ap_interface: str, ap_ip: str) -> bool:
        """Configure DNS for offline captive portal detection"""
        try:
            captive_dns_conf = f"""# PiNetAP Offline Captive Portal DNS
interface={ap_interface}
bind-dynamic
address=/#/{ap_ip}
address=/captive.apple.com/{ap_ip}
address=/connectivitycheck.android.com/{ap_ip}
address=/connectivitycheck.gstatic.com/{ap_ip}
address=/clients3.google.com/{ap_ip}
address=/www.msftconnecttest.com/{ap_ip}
address=/www.msftncsi.com/{ap_ip}
address=/ipv6.msftconnecttest.com/{ap_ip}
address=/detectportal.firefox.com/{ap_ip}
no-resolv
cache-size=0
log-queries
"""
            
            captive_dns_file = self.DNSMASQ_CONF_DIR / "pinetap-captive.conf"
            self.DNSMASQ_CONF_DIR.mkdir(parents=True, exist_ok=True)
            captive_dns_file.write_text(captive_dns_conf)
            
            self.log("Configured DNS for offline captive portal detection")
            self._setup_captive_portal_iptables(ap_interface, ap_ip)
            
            return True
        except Exception as e:
            self.log(f"Failed to configure DNS: {e}", "ERROR")
            return False

    def _setup_captive_portal_iptables(self, ap_interface: str, ap_ip: str) -> bool:
        """Setup iptables rules to intercept and redirect HTTP traffic to captive portal"""
        try:
            self.log("Setting up HTTP traffic interception for captive portal...")
            
            ret, _, _ = self.run_command(["which", "iptables"], check=False)
            if ret != 0:
                self.log("iptables not found, captive portal may not trigger automatically", "WARN")
                return False
            
            self.run_command([
                "iptables", "-t", "nat", "-D", "PREROUTING",
                "-i", ap_interface, "-p", "tcp", "--dport", "80",
                "-j", "DNAT", "--to-destination", f"{ap_ip}:80"
            ], check=False)
            
            ret, _, stderr = self.run_command([
                "iptables", "-t", "nat", "-A", "PREROUTING",
                "-i", ap_interface, "-p", "tcp", "--dport", "80",
                "-j", "DNAT", "--to-destination", f"{ap_ip}:80"
            ], check=False)
            
            if ret == 0:
                self.log(f"✓ HTTP traffic on {ap_interface}:80 will redirect to {ap_ip}:80")
            else:
                self.log(f"Failed to add HTTP redirect rule: {stderr}", "WARN")
                return False
            
            self.run_command([
                "iptables", "-t", "nat", "-D", "PREROUTING",
                "-i", ap_interface, "-p", "tcp", "--dport", "443",
                "-j", "DNAT", "--to-destination", f"{ap_ip}:80"
            ], check=False)
            
            ret, _, stderr = self.run_command([
                "iptables", "-t", "nat", "-A", "PREROUTING",
                "-i", ap_interface, "-p", "tcp", "--dport", "443",
                "-j", "DNAT", "--to-destination", f"{ap_ip}:80"
            ], check=False)
            
            if ret == 0:
                self.log(f"✓ HTTPS traffic on {ap_interface}:443 will redirect to {ap_ip}:80")
            else:
                self.log(f"Warning: Could not add HTTPS redirect rule: {stderr}", "WARN")
            
            self.run_command([
                "iptables", "-t", "nat", "-I", "PREROUTING", "1",
                "-i", ap_interface, "-p", "tcp", "-d", ap_ip, "--dport", "80",
                "-j", "ACCEPT"
            ], check=False)
            
            self.log("✓ HTTP traffic interception configured", "SUCCESS")
            self.log("  All HTTP requests will redirect to captive portal", "INFO")
            
            self._save_iptables_rules()
            return True
            
        except Exception as e:
            self.log(f"Failed to setup iptables: {e}", "ERROR")
            return False

    def _save_iptables_rules(self) -> bool:
        """Save iptables rules to persist across reboots"""
        try:
            ret, _, _ = self.run_command(["which", "iptables-save"], check=False)
            if ret != 0:
                self.log("iptables-save not found, rules won't persist across reboots", "WARN")
                return False
            
            rules_file = Path("/etc/pinetap/iptables-captive.rules")
            self.PINETAP_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            
            ret, stdout, _ = self.run_command(["iptables-save"], check=False)
            if ret == 0 and stdout:
                rules_file.write_text(stdout)
                self.log(f"Saved iptables rules to {rules_file}")
                
                restore_script = self.PINETAP_CONFIG_DIR / "restore-iptables.sh"
                restore_script.write_text(f"""#!/bin/bash
# Restore PiNetAP captive portal iptables rules
iptables-restore < {rules_file}
""")
                restore_script.chmod(0o755)
                
                rc_local = Path("/etc/rc.local")
                if rc_local.exists():
                    content = rc_local.read_text()
                    restore_line = f"{restore_script}\n"
                    if restore_line not in content:
                        if 'exit 0' in content:
                            content = content.replace('exit 0', f'{restore_line}exit 0')
                        else:
                            content += f"\n{restore_line}"
                        rc_local.write_text(content)
                        self.log("Added iptables restore to /etc/rc.local")
            
            return True
        except Exception as e:
            self.log(f"Failed to save iptables rules: {e}", "WARN")
            return False

    def remove_captive_portal(self) -> bool:
        """Remove captive portal files and service"""
        try:
            self.log("Removing captive portal...")
            
            self.run_command(["systemctl", "stop", "nodogsplash"], check=False)
            self.run_command(["systemctl", "disable", "nodogsplash"], check=False)
            self.run_command(["killall", "nodogsplash"], check=False)
            
            self.run_command(["systemctl", "stop", "pinetap-portal"], check=False)
            self.run_command(["systemctl", "disable", "pinetap-portal"], check=False)
            
            self._remove_captive_portal_iptables()
            
            nds_config = Path("/etc/nodogsplash/nodogsplash.conf")
            nds_backup = Path("/etc/nodogsplash/nodogsplash.conf.backup")
            
            if nds_backup.exists():
                import shutil
                shutil.copy2(nds_backup, nds_config)
                nds_backup.unlink()
                self.log("Restored original nodogsplash config")
            elif nds_config.exists():
                nds_config.unlink()
                self.log("Removed nodogsplash config")
            
            captive_dns_file = self.DNSMASQ_CONF_DIR / "pinetap-captive.conf"
            if captive_dns_file.exists():
                captive_dns_file.unlink()
                self.log("Removed captive portal DNS config")
            
            if self.CAPTIVE_PORTAL_DIR.exists():
                import shutil
                shutil.rmtree(self.CAPTIVE_PORTAL_DIR)
                self.log("Removed portal directory")
            
            if self.CAPTIVE_PORTAL_SERVICE.exists():
                self.CAPTIVE_PORTAL_SERVICE.unlink()
            
            if self.CAPTIVE_PORTAL_SCRIPT.exists():
                self.CAPTIVE_PORTAL_SCRIPT.unlink()
            
            rules_file = Path("/etc/pinetap/iptables-captive.rules")
            if rules_file.exists():
                rules_file.unlink()
            
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
            
            interfaces = self.get_available_interfaces()
            wifi_interfaces = [name for name, info in interfaces.items() if info['type'] == 'wifi']
            
            for iface in wifi_interfaces:
                self.run_command([
                    "iptables", "-t", "nat", "-D", "PREROUTING",
                    "-i", iface, "-p", "tcp", "--dport", "80",
                    "-j", "DNAT", "--to-destination", "192.168.4.1:80"
                ], check=False)
                
                self.run_command([
                    "iptables", "-t", "nat", "-D", "PREROUTING",
                    "-i", iface, "-p", "tcp", "--dport", "443",
                    "-j", "DNAT", "--to-destination", "192.168.4.1:80"
                ], check=False)
                
                self.run_command([
                    "iptables", "-t", "nat", "-D", "PREROUTING",
                    "-i", iface, "-p", "tcp", "-d", "192.168.4.1", "--dport", "80",
                    "-j", "ACCEPT"
                ], check=False)
            
            self.log("Cleaned up iptables redirect rules")
            return True
        except Exception as e:
            self.log(f"Failed to remove iptables rules: {e}", "WARN")
            return False

    def configure_captive_portal_dns(self, ap_interface: str, ap_ip: str) -> bool:
        """Configure DNS for captive portal"""
        self.log("DNS redirection will be handled by nodogsplash")
        return True

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
            self.log("No saved system state found, using safe defaults", "WARN")
            self.enable_ip_forwarding()
            self.restore_iptables_policy('ACCEPT')
            return
        
        try:
            import json
            state = json.loads(self.SYSTEM_STATE_CONFIG.read_text())
            
            if state.get('ip_forward') == 1:
                self.enable_ip_forwarding()
                self.log("Restored IP forwarding: enabled")
            else:
                self.disable_ip_forwarding()
                self.log("Restored IP forwarding: disabled")
            
            if state.get('forward_policy'):
                self.restore_iptables_policy(state['forward_policy'])
                self.log(f"Restored iptables FORWARD policy: {state['forward_policy']}")
            
            self.SYSTEM_STATE_CONFIG.unlink()
            self.log("Removed system state backup")
            
        except Exception as e:
            self.log(f"Failed to restore system state: {e}", "ERROR")
            self.log("Using safe defaults instead", "WARN")
            self.enable_ip_forwarding()
            self.restore_iptables_policy('ACCEPT')

    def restore_iptables_policy(self, policy: str = 'ACCEPT'):
        """Restore iptables FORWARD policy"""
        try:
            ret, _, _ = self.run_command(["which", "iptables"], check=False)
            if ret != 0:
                return
            
            self.run_command(["iptables", "-F", "FORWARD"], check=False)
            self.run_command(["iptables", "-t", "nat", "-F"], check=False)
            self.run_command(["iptables", "-P", "FORWARD", policy], check=False)
            self.log(f"iptables FORWARD policy set to {policy}")
            
        except Exception as e:
            self.log(f"Could not restore iptables: {e}", "WARN")

    def disable_ip_forwarding(self) -> bool:
        """Disable IP forwarding to prevent internet sharing"""
        try:
            self.run_command(["sysctl", "-w", "net.ipv4.ip_forward=0"], check=False)
            
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
            self.run_command(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=False)
            
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

    def clear_iptables_nat_rules(self) -> bool:
        """Clear all NAT/MASQUERADE rules to prevent internet sharing"""
        try:
            ret, _, _ = self.run_command(["which", "iptables"], check=False)
            if ret != 0:
                self.log("iptables not found - using nftables or iptables not installed", "WARN")
                self.log("Internet isolation relies on disabled IP forwarding only", "WARN")
                return True
            
            ret, _, stderr = self.run_command(["iptables", "-t", "nat", "-F"], check=False)
            if ret == 0:
                self.log("Cleared iptables NAT rules")
            else:
                self.log(f"Could not clear NAT rules: {stderr}", "WARN")
            
            ret, _, stderr = self.run_command(["iptables", "-F", "FORWARD"], check=False)
            if ret == 0:
                self.log("Cleared iptables FORWARD rules")
            
            ret, _, stderr = self.run_command(["iptables", "-P", "FORWARD", "DROP"], check=False)
            if ret == 0:
                self.log("Set FORWARD policy to DROP")
            
            ret, _, stderr = self.run_command([
                "iptables", "-I", "FORWARD", "1", "-j", "DROP"
            ], check=False)
            if ret == 0:
                self.log("Added FORWARD DROP rule to block all forwarding")
            
            return True
        except Exception as e:
            self.log(f"Failed to configure iptables: {e}", "WARN")
            self.log("Internet isolation relies on disabled IP forwarding only", "WARN")
            return False

    def setup_standalone_dhcp(self, ap_interface: str, ip_address: str) -> bool:
        """Configure dnsmasq for DHCP in standalone mode"""
        try:
            self.DNSMASQ_CONF_DIR.mkdir(parents=True, exist_ok=True)
            
            if '/' in ip_address:
                ip, prefix = ip_address.split('/')
                prefix = int(prefix)
            else:
                ip = ip_address
                prefix = 24
            
            ip_parts = ip.split('.')
            base_ip = '.'.join(ip_parts[:3])
            dhcp_start = f"{base_ip}.10"
            dhcp_end = f"{base_ip}.250"
            
            dnsmasq_config = f"""# PiNetAP standalone AP configuration
interface={ap_interface}
bind-interfaces
dhcp-range={dhcp_start},{dhcp_end},12h
dhcp-option=option:router,{ip}
dhcp-option=option:dns-server,{ip}
no-resolv
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