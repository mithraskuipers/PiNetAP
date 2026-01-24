#!/usr/bin/env python3
import http.server
import socketserver
import os
import sys
import traceback
import json
import time
import re
from pathlib import Path

PORT = {{PORT}}
AP_IP = "{{AP_IP}}"
SERVICES_JSON = "{{SERVICES_JSON}}"
PORTAL_DIR = "{{PORTAL_DIR}}"

# Force unbuffered output so we see logs immediately
sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', buffering=1)
sys.stderr = os.fdopen(sys.stderr.fileno(), 'w', buffering=1)

print("[STARTUP] Captive Portal Server Starting...")
print(f"[STARTUP] Port: {PORT}")
print(f"[STARTUP] AP IP: {AP_IP}")
print(f"[STARTUP] Services JSON: {SERVICES_JSON}")
print(f"[STARTUP] Working directory: {os.getcwd()}")

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
            print(f"[SERVICES] Services file not found: {SERVICES_JSON}")
            print(f"[SERVICES] Using default services")
            if CACHED_SERVICES is None:
                CACHED_SERVICES = [
                    {"name": "Router Admin", "port": 80, "path": "/", "description": "Web interface"}
                ]
            return CACHED_SERVICES
        
        # Check if file has been modified
        current_mtime = services_path.stat().st_mtime
        
        if CACHED_SERVICES is None or current_mtime > SERVICES_MTIME:
            print(f"[SERVICES] Loading/reloading services from {SERVICES_JSON}")
            with open(services_path, 'r') as f:
                services = json.load(f)
            
            # Validate structure
            if not isinstance(services, list):
                print("[SERVICES] ERROR: services.json must contain a JSON array")
                if CACHED_SERVICES:
                    return CACHED_SERVICES
                return [{"name": "Router Admin", "port": 80, "path": "/", "description": "Web interface"}]
            
            CACHED_SERVICES = services
            SERVICES_MTIME = current_mtime
            print(f"[SERVICES] Loaded {len(services)} service(s)")
            
            # Regenerate HTML with new services
            regenerate_portal_html()
        
        return CACHED_SERVICES
        
    except json.JSONDecodeError as e:
        print(f"[SERVICES] ERROR: Invalid JSON in services file: {e}")
        if CACHED_SERVICES:
            return CACHED_SERVICES
        return [{"name": "Router Admin", "port": 80, "path": "/", "description": "Web interface"}]
    except Exception as e:
        print(f"[SERVICES] ERROR: Failed to load services: {e}")
        if CACHED_SERVICES:
            return CACHED_SERVICES
        return [{"name": "Router Admin", "port": 80, "path": "/", "description": "Web interface"}]

def regenerate_portal_html():
    """Regenerate the portal HTML with current services - FIXED REPLACEMENT"""
    try:
        services = CACHED_SERVICES or []
        
        # Read SSID from metadata file if exists
        metadata_path = Path(PORTAL_DIR) / "portal_metadata.json"
        ssid = "PiNetAP"
        ap_ip = AP_IP  # Use the global AP_IP constant
        
        if metadata_path.exists():
            try:
                with open(metadata_path, 'r') as f:
                    metadata = json.load(f)
                    ssid = metadata.get('ssid', ssid)
                    ap_ip = metadata.get('ap_ip', AP_IP)  # Fallback to global AP_IP
            except Exception as e:
                print(f"[HTML] Warning: Failed to read metadata: {e}")
                # Continue with defaults
        
        # Read the HTML template
        template_path = Path(PORTAL_DIR) / "portal_template.html"
        if not template_path.exists():
            print(f"[HTML] ERROR: Template not found at {template_path}")
            return
            
        with open(template_path, 'r', encoding='utf-8') as f:
            html = f.read()
        
        # Generate service cards HTML
        service_cards = ""
        for svc in services:
            port_display = f":{svc['port']}" if svc.get('port', 80) != 80 else ""
            url = f"http://{ap_ip}{port_display}{svc.get('path', '/')}"
            service_cards += f"""
            <div class="service-card">
                <h3>{svc['name']}</h3>
                <p>{svc.get('description', '')}</p>
                <a href="{url}" class="service-link">{url}</a>
            </div>
        """
        
        # CRITICAL FIX: Use regex replacement like in pinetap_portal_template.py
        replacements = {
            'SSID': ssid,
            'AP_IP': ap_ip,
            'SERVICE_CARDS': service_cards
        }
        
        # Replace using regex to ensure we catch all instances
        for key, value in replacements.items():
            # Match {{KEY}} with optional whitespace
            pattern = r'\{\{\s*' + key + r'\s*\}\}'
            html = re.sub(pattern, value, html)
        
        # Verify replacement worked
        if '{{AP_IP}}' in html or '{{SSID}}' in html or '{{SERVICE_CARDS}}' in html:
            print("[HTML] WARNING: Some placeholders were not replaced!")
            print(f"[HTML] SSID: {ssid}, AP_IP: {ap_ip}")
        else:
            print(f"[HTML] ✓ All placeholders replaced successfully")
        
        # Add auto-update indicator to the services header
        html = html.replace('📦 Available Services', '📦 Available Services<span class="auto-update">AUTO-UPDATED</span>')
        
        # Add auto-update CSS if not present
        if '.auto-update' not in html:
            auto_update_css = """
        .auto-update { 
            display: inline-block; background: #4ade80; color: white; 
            font-size: 10px; padding: 2px 8px; border-radius: 4px; margin-left: 8px;
        }"""
            html = html.replace('</style>', f'{auto_update_css}\n    </style>')
        
        # Update footer text
        html = html.replace(
            'Use the IP address above to access services on this network',
            'Services update automatically when services.json changes'
        )
        
        # Write to BOTH index.html AND splash.html for compatibility
        for filename in ["index.html", "splash.html"]:
            output_path = Path(PORTAL_DIR) / filename
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html)
        
        print(f"[HTML] Regenerated portal page with {len(services)} service(s)")
        print(f"[HTML] SSID: {ssid}, AP IP: {ap_ip}")
        
    except Exception as e:
        print(f"[HTML] ERROR: Failed to regenerate HTML: {e}")
        traceback.print_exc()

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
        # Check for services.json updates before serving
        load_services()
        
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
        self.send_header("Location", f"http://{AP_IP}/")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()

if __name__ == "__main__":
    try:
        os.chdir(PORTAL_DIR)
        print(f"[STARTUP] Changed to directory: {os.getcwd()}")
        
        # Initial services load and HTML generation
        print("[STARTUP] Loading initial services...")
        load_services()
        
        # Verify files exist
        if not os.path.exists("index.html"):
            print("[ERROR] index.html not found!")
            sys.exit(1)
        else:
            print("[STARTUP] index.html found")
            # Debug: Check if placeholders are still in the file
            with open("index.html", "r") as f:
                content = f.read()
                if "{{AP_IP}}" in content:
                    print("[ERROR] index.html still contains {{AP_IP}} placeholder!")
                    print("[ERROR] Running emergency regeneration...")
                    regenerate_portal_html()
        
        print(f"[STARTUP] Creating server on port {PORT}...")
        with socketserver.TCPServer(("", PORT), CaptivePortalHandler) as httpd:
            print(f"[READY] Captive portal is ACTIVE on {AP_IP}:{PORT}")
            print(f"[READY] Monitoring {SERVICES_JSON} for changes")
            print("[READY] Waiting for connections...")
            print("[READY] Press Ctrl+C to stop")
            sys.stdout.flush()
            httpd.serve_forever()
    except Exception as e:
        print(f"[FATAL ERROR] {e}")
        traceback.print_exc()
        sys.exit(1)