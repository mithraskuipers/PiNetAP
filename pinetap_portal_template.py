#!/usr/bin/env python3
"""
PiNetAP Portal Template - HTML and Server Script Generation
Uses Jinja2-style manual templating with proper escaping
"""

from typing import Optional, List, Dict
from pathlib import Path
import re


def get_captive_portal_html(ap_ip: str, ssid: str, services: Optional[List[Dict]] = None) -> str:
    """Generate captive portal HTML page by reading template and replacing variables"""
    
    if not services:
        services = [
            {"name": "Router Admin", "port": 80, "path": "/", "description": "Web interface"},
        ]
    
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
    
    # Read the template file
    template_path = Path(__file__).parent / "portal_template.html"
    
    if not template_path.exists():
        raise FileNotFoundError(f"Template not found: {template_path}")
    
    with open(template_path, 'r', encoding='utf-8') as f:
        html = f.read()
    
    # Create replacement mapping
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
    
    return html


def get_portal_server_script(ap_ip: str, port: int, portal_dir: Path, services_json_path: Optional[str] = None) -> str:
    """Generate the Python HTTP server script for captive portal with auto-reload"""
    
    # If no services file specified, create a default one in portal dir
    if not services_json_path:
        services_json_path = str(Path(portal_dir) / "services.json")
    else:
        # Use the absolute path to the original file
        services_json_path = str(Path(services_json_path).resolve())
    
    # Read the server script template
    template_path = Path(__file__).parent / "pinetap_portal_server_template.py"
    
    if not template_path.exists():
        raise FileNotFoundError(f"Server template not found: {template_path}")
    
    with open(template_path, 'r', encoding='utf-8') as f:
        script = f.read()
    
    # Create replacement mapping
    replacements = {
        'PORT': str(port),
        'AP_IP': ap_ip,
        'SERVICES_JSON': services_json_path,
        'PORTAL_DIR': str(portal_dir)
    }
    
    # Replace using regex
    for key, value in replacements.items():
        pattern = r'\{\{\s*' + key + r'\s*\}\}'
        script = re.sub(pattern, value, script)
    
    return script