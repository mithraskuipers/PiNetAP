#!/usr/bin/env python3
"""
PiNetAP Portal Template - HTML and Server Script Generation
Contains HTML template and Python HTTP server script for captive portal
"""

from typing import Optional, List, Dict
from pathlib import Path


def get_captive_portal_html(ap_ip: str, ssid: str, services: Optional[List[Dict]] = None) -> str:
    """Generate captive portal HTML page by reading template and replacing variables"""
    
    if not services:
        services = [
            {"name": "Router Admin", "port": 80, "path": "/", "description": "Web interface"},
        ]
    
    # Generate service cards HTML
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
    
    # Read the template file
    template_path = Path(__file__).parent / "portal_template.html"
    with open(template_path, 'r', encoding='utf-8') as f:
        html = f.read()
    
    # Replace placeholders
    html = html.replace('{{SSID}}', ssid)
    html = html.replace('{{AP_IP}}', ap_ip)
    html = html.replace('{{SERVICE_CARDS}}', service_cards)
    
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
    
    # Read the server script template
    template_path = Path(__file__).parent / "portal_server_template.py"
    with open(template_path, 'r', encoding='utf-8') as f:
        script = f.read()
    
    # Replace placeholders
    script = script.replace('{{PORT}}', str(port))
    script = script.replace('{{AP_IP}}', ap_ip)
    script = script.replace('{{SERVICES_JSON}}', services_json_path)
    script = script.replace('{{PORTAL_DIR}}', str(portal_dir))
    
    return script