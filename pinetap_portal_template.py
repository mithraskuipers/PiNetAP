#!/usr/bin/env python3
"""
PiNetAP Portal Template - HTML and Server Script Generation
Contains HTML template and Python HTTP server script for captive portal
"""

from typing import Optional, List, Dict
from pathlib import Path


def get_captive_portal_html(ap_ip: str, ssid: str, services: Optional[List[Dict]] = None) -> str:
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


def get_portal_server_script(ap_ip: str, port: int, portal_dir: Path, services_json_path: Optional[str] = None) -> str:
    """Generate the Python HTTP server script for captive portal with auto-reload
    
    Args:
        ap_ip: IP address of the AP
        port: Port for the web server
        portal_dir: Directory containing portal files
        services_json_path: Path to ORIGINAL services JSON file (will be monitored directly)
    """
    
    # If no services file specified, create a default one in portal dir
    if not services_json_path:
        services_json_path = str(Path(portal_dir) / "services.json")
    else:
        # Use the absolute path to the original file
        services_json_path = str(Path(services_json_path).resolve())
    
    script = f'''#!/usr/bin/env python3
import http.server
import socketserver
import os
import sys
import traceback
import json
import time
from pathlib import Path

PORT = {port}
AP_IP = "{ap_ip}"
SERVICES_JSON = "{services_json_path}"
PORTAL_DIR = "{portal_dir}"

# Force unbuffered output so we see logs immediately
sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', buffering=1)
sys.stderr = os.fdopen(sys.stderr.fileno(), 'w', buffering=1)

print("[STARTUP] Captive Portal Server Starting...")
print(f"[STARTUP] Port: {{PORT}}")
print(f"[STARTUP] AP IP: {{AP_IP}}")
print(f"[STARTUP] Services JSON: {{SERVICES_JSON}}")
print(f"[STARTUP] Working directory: {{os.getcwd()}}")

# Global variables for services and mtime tracking
CACHED_SERVICES = None
SERVICES_MTIME = 0

def load_services():
    """Load services from JSON file, with caching and auto-reload"""
    global CACHED_SERVICES, SERVICES_MTIME
    
    try:
        services_path = Path(SERVICES_JSON)
        
        # Check if file exists
        if not services_path.exists():
            print(f"[SERVICES] Services file not found: {{SERVICES_JSON}}")
            print(f"[SERVICES] Using default services")
            if CACHED_SERVICES is None:
                CACHED_SERVICES = [
                    {{"name": "Router Admin", "port": 80, "path": "/", "description": "Web interface"}}
                ]
            return CACHED_SERVICES
        
        # Check if file has been modified
        current_mtime = services_path.stat().st_mtime
        
        if CACHED_SERVICES is None or current_mtime > SERVICES_MTIME:
            print(f"[SERVICES] Loading/reloading services from {{SERVICES_JSON}}")
            with open(services_path, 'r') as f:
                services = json.load(f)
            
            # Validate structure
            if not isinstance(services, list):
                print("[SERVICES] ERROR: services.json must contain a JSON array")
                if CACHED_SERVICES:
                    return CACHED_SERVICES
                return [{{"name": "Router Admin", "port": 80, "path": "/", "description": "Web interface"}}]
            
            CACHED_SERVICES = services
            SERVICES_MTIME = current_mtime
            print(f"[SERVICES] Loaded {{len(services)}} service(s)")
            
            # Regenerate HTML with new services
            regenerate_portal_html()
        
        return CACHED_SERVICES
        
    except json.JSONDecodeError as e:
        print(f"[SERVICES] ERROR: Invalid JSON in services file: {{e}}")
        if CACHED_SERVICES:
            return CACHED_SERVICES
        return [{{"name": "Router Admin", "port": 80, "path": "/", "description": "Web interface"}}]
    except Exception as e:
        print(f"[SERVICES] ERROR: Failed to load services: {{e}}")
        if CACHED_SERVICES:
            return CACHED_SERVICES
        return [{{"name": "Router Admin", "port": 80, "path": "/", "description": "Web interface"}}]

def regenerate_portal_html():
    """Regenerate the portal HTML with current services"""
    try:
        services = CACHED_SERVICES or []
        
        # Read SSID from metadata file if exists
        metadata_path = Path(PORTAL_DIR) / "portal_metadata.json"
        ssid = "PiNetAP"
        
        if metadata_path.exists():
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
                ssid = metadata.get('ssid', ssid)
        
        # Generate service cards HTML
        service_cards = ""
        for svc in services:
            port_display = f":{{svc['port']}}" if svc.get('port', 80) != 80 else ""
            url = f"http://{{AP_IP}}{{port_display}}{{svc.get('path', '/')}}"
            service_cards += f"""
            <div class="service-card">
                <h3>{{svc['name']}}</h3>
                <p>{{svc.get('description', '')}}</p>
                <a href="{{url}}" class="service-link">{{url}}</a>
            </div>
        """
        
        # Generate complete HTML - ESCAPE ALL CSS CURLY BRACES
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome to {{ssid}}</title>
    <style>
        * {{{{ margin: 0; padding: 0; box-sizing: border-box; }}}}
        body {{{{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px;
        }}}}
        .container {{{{
            background: white; border-radius: 20px; box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            max-width: 600px; width: 100%; padding: 40px; animation: slideUp 0.5s ease;
        }}}}
        @keyframes slideUp {{{{ from {{{{ opacity: 0; transform: translateY(30px); }}}} to {{{{ opacity: 1; transform: translateY(0); }}}} }}}}
        .header {{{{ text-align: center; margin-bottom: 30px; }}}}
        .wifi-icon {{{{ font-size: 64px; margin-bottom: 10px; }}}}
        h1 {{{{ color: #333; font-size: 28px; margin-bottom: 10px; }}}}
        .ssid {{{{ color: #667eea; font-weight: bold; }}}}
        .welcome-text {{{{ color: #666; font-size: 16px; line-height: 1.6; margin-bottom: 30px; text-align: center; }}}}
        .ip-box {{{{
            background: #f7f9fc; border: 2px solid #e1e8ed; border-radius: 12px;
            padding: 20px; margin-bottom: 30px; text-align: center;
        }}}}
        .ip-label {{{{ color: #888; font-size: 14px; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px; }}}}
        .ip-address {{{{ font-size: 32px; font-weight: bold; color: #667eea; font-family: 'Courier New', monospace; }}}}
        .services {{{{ margin-top: 20px; }}}}
        .services h2 {{{{ color: #333; font-size: 20px; margin-bottom: 15px; text-align: center; }}}}
        .service-card {{{{
            background: #f7f9fc; border-radius: 10px; padding: 20px; margin-bottom: 15px;
            transition: transform 0.2s, box-shadow 0.2s;
        }}}}
        .service-card:hover {{{{ transform: translateY(-2px); box-shadow: 0 4px 12px rgba(102, 126, 234, 0.2); }}}}
        .service-card h3 {{{{ color: #333; font-size: 18px; margin-bottom: 8px; }}}}
        .service-card p {{{{ color: #666; font-size: 14px; margin-bottom: 12px; }}}}
        .service-link {{{{
            display: inline-block; color: #667eea; text-decoration: none;
            font-family: 'Courier New', monospace; font-size: 14px; padding: 8px 16px;
            background: white; border-radius: 6px; border: 1px solid #667eea; transition: all 0.2s;
        }}}}
        .service-link:hover {{{{ background: #667eea; color: white; }}}}
        .footer {{{{
            text-align: center; color: #999; font-size: 12px; margin-top: 30px;
            padding-top: 20px; border-top: 1px solid #e1e8ed;
        }}}}
        .status-indicator {{{{
            display: inline-block; width: 8px; height: 8px; background: #4ade80;
            border-radius: 50%; margin-right: 6px; animation: pulse 2s infinite;
        }}}}
        @keyframes pulse {{{{ 0%, 100% {{{{ opacity: 1; }}}} 50% {{{{ opacity: 0.5; }}}} }}}}
        .auto-update {{{{ 
            display: inline-block; background: #4ade80; color: white; 
            font-size: 10px; padding: 2px 8px; border-radius: 4px; margin-left: 8px;
        }}}}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="wifi-icon">📡</div>
            <h1>Welcome to <span class="ssid">{{ssid}}</span></h1>
        </div>
        <p class="welcome-text">
            <span class="status-indicator"></span>
            You're connected! This network provides access to local services.
        </p>
        <div class="ip-box">
            <div class="ip-label">Router IP Address</div>
            <div class="ip-address">{{AP_IP}}</div>
        </div>
        <div class="services">
            <h2>📦 Available Services<span class="auto-update">AUTO-UPDATED</span></h2>
            {{service_cards}}
        </div>
        <div class="footer">
            <p>Powered by PiNetAP</p>
            <p>Services update automatically when services.json changes</p>
        </div>
    </div>
</body>
</html>"""
        
        # Write to index.html
        index_path = Path(PORTAL_DIR) / "index.html"
        with open(index_path, 'w') as f:
            f.write(html)
        
        print(f"[HTML] Regenerated portal page with {{len(services)}} service(s)")
        
    except Exception as e:
        print(f"[HTML] ERROR: Failed to regenerate HTML: {{e}}")
        traceback.print_exc()

class CaptivePortalHandler(http.server.SimpleHTTPRequestHandler):

    def log_message(self, format, *args):
        """Log all requests for debugging"""
        print(f"{{self.address_string()}} - {{format % args}}")

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
        # Check for services.json updates before serving
        load_services()
        
        path = self.path.lower()
        client_ip = self.client_address[0]
        print(f"[REQUEST] {{path}} from {{client_ip}}")
        
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
                print(f"[ANDROID] Sent {{len(content)}} bytes of portal HTML")
            except Exception as e:
                print(f"[ERROR] Reading index.html: {{e}}")
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
        print(f"[REDIRECT] Unknown path {{path}} -> portal")
        self.send_response(302)
        self.send_header("Location", "http://{ap_ip}/")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()

if __name__ == "__main__":
    try:
        os.chdir("{portal_dir}")
        print(f"[STARTUP] Changed to directory: {{os.getcwd()}}")
        
        # Initial services load and HTML generation
        print("[STARTUP] Loading initial services...")
        load_services()
        
        # Verify files exist
        if not os.path.exists("index.html"):
            print("[ERROR] index.html not found!")
            sys.exit(1)
        else:
            print("[STARTUP] index.html found")
        
        print(f"[STARTUP] Creating server on port {{PORT}}...")
        with socketserver.TCPServer(("", PORT), CaptivePortalHandler) as httpd:
            print(f"[READY] Captive portal is ACTIVE on {{AP_IP}}:{{PORT}}")
            print(f"[READY] Monitoring {{SERVICES_JSON}} for changes")
            print("[READY] Waiting for connections...")
            print("[READY] Press Ctrl+C to stop")
            sys.stdout.flush()
            httpd.serve_forever()
    except Exception as e:
        print(f"[FATAL ERROR] {{e}}")
        traceback.print_exc()
        sys.exit(1)
'''
    return script
