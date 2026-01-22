# PiNetAP - Raspberry Pi Network Access Point Manager

A powerful Python tool for creating and managing WiFi access points on Raspberry Pi with advanced features like captive portals, custom service pages, and internet sharing.

## Features

- 🔌 **Dual WiFi Support** - Use one WiFi for internet, share via another
- 📱 **Captive Portal** - Auto-popup portal page on connection (iOS, Android, Windows)
- 🎨 **Custom Services** - Display your services via JSON configuration
- 🌐 **Internet Sharing** - Share internet connection through the AP
- 🔒 **Security Options** - Open, WPA2-PSK, or WPA3-SAE
- 🚫 **Standalone Mode** - Create offline-only networks
- 💾 **Persistent Config** - Auto-reconnect on reboot

## Quick Start

### Prerequisites
```bash
# Raspberry Pi with:
- Raspberry Pi OS (Debian-based)
- NetworkManager installed
- At least one WiFi interface
- Root access (sudo)
```

### Installation
```bash
git clone <your-repo>
cd pinetap
```

### Basic Usage

#### 1. List Available Interfaces
```bash
sudo python pinetap.py interfaces -d
```

#### 2. Create a Simple Access Point
```bash
# Standalone AP (no internet)
sudo python pinetap.py install \
    --ssid MyHotspot \
    --password MySecurePass123 \
    --security wpa2-psk \
    --ap-interface wlan0 \
    --no-share \
    --autoconnect
```

#### 3. Create AP with Internet Sharing
```bash
# Share internet from ethernet
sudo python pinetap.py install \
    --ssid MyHotspot \
    --password MySecurePass123 \
    --security wpa2-psk \
    --ap-interface wlan1 \
    --autoconnect

# Share internet from another WiFi
sudo python pinetap.py install \
    --ssid MyHotspot \
    --password MySecurePass123 \
    --security wpa2-psk \
    --ap-interface wlan1 \
    --uplink-interface wlan0 \
    --autoconnect
```

#### 4. Create AP with Captive Portal
```bash
# Standalone with captive portal
sudo python pinetap.py install \
    --ssid MyServices \
    --password MySecurePass123 \
    --security wpa2-psk \
    --ap-interface wlan1 \
    --no-share \
    --autoconnect \
    --captive-portal

# With internet + captive portal + custom services
sudo python pinetap.py install \
    --ssid MyServices \
    --password MySecurePass123 \
    --security wpa2-psk \
    --ap-interface wlan1 \
    --uplink-interface wlan0 \
    --autoconnect \
    --captive-portal \
    --services-file ./services.json
```

## Custom Services

Create a `services.json` file to display custom services on the captive portal:
```json
[
  {
    "name": "Pi Admin",
    "port": 80,
    "path": "/",
    "description": "Raspberry Pi administration"
  },
  {
    "name": "File Server",
    "port": 8000,
    "path": "/files",
    "description": "Access shared files"
  },
  {
    "name": "Media Server",
    "port": 32400,
    "path": "/",
    "description": "Plex media server"
  }
]
```

## Command Reference

### Install/Create AP
```bash
sudo python pinetap.py install [OPTIONS]

Required:
  --ssid SSID                 Network name
  --ap-interface INTERFACE    WiFi interface for AP (e.g., wlan1)

Optional:
  --password PASSWORD         Network password (required for WPA)
  --security {open,wpa2-psk,wpa3-sae}  Security mode (default: wpa2-psk)
  --uplink-interface INTERFACE  Internet source interface (e.g., wlan0, eth0)
  --no-share                  Disable internet sharing (standalone mode)
  --autoconnect               Auto-reconnect on reboot
  --captive-portal            Enable captive portal
  --services-file FILE        JSON file with custom services
  --ip ADDRESS                AP IP address (default: 192.168.4.1/24)
  --channel CHANNEL           WiFi channel (default: 3)
```

### Manage APs
```bash
# List managed connections
sudo python pinetap.py managed

# Remove specific AP
sudo python pinetap.py uninstall --connection MyHotspot-AP

# Remove all APs
sudo python pinetap.py uninstall --all
```

### Diagnostics
```bash
# Diagnose AP issues
sudo python pinetap.py diagnose

# Attempt auto-fix
sudo python pinetap.py fix
```

## Architecture

The codebase is split into focused modules:

- **pinetap.py** (1139 lines) - Main CLI interface
- **pinetap_network.py** (118 lines) - Network coordination
- **pinetap_firewall.py** (355 lines) - iptables/NAT/forwarding
- **pinetap_captiveportal.py** (454 lines) - Captive portal & DNS
- **pinetap_portal_template.py** (290 lines) - HTML templates
- **pinetap_core.py** - Base functionality (not shown)

## How It Works

### Standalone Mode (`--no-share`)
- Creates isolated WiFi network
- No internet access for clients
- Perfect for local services only
- DNS hijacked to portal page

### Internet Sharing Mode
- Enables IP forwarding
- Sets up NAT rules
- Configures FORWARD chain
- Auto-detects internet interface
- Clients have full internet access

### Captive Portal (Dual Mode)
- **With Internet**: Hijacks only detection domains, forwards other DNS to 8.8.8.8
- **Without Internet**: Hijacks all DNS to portal page
- Auto-popup on iOS, Android, Windows
- Custom services display
- No HTTP redirect when internet sharing enabled

## Troubleshooting

### No Internet Access
```bash
# Check IP forwarding
cat /proc/sys/net/ipv4/ip_forward  # Should be 1

# Check NAT rules
sudo iptables -t nat -L POSTROUTING -n -v

# Check FORWARD rules
sudo iptables -L FORWARD -n -v

# Verify internet interface
ip route show default
```

### DNS Not Working
```bash
# Check dnsmasq
sudo pgrep -f dnsmasq

# Restart NetworkManager
sudo systemctl restart NetworkManager

# Check DNS config
ls /etc/NetworkManager/dnsmasq-shared.d/
```

### Captive Portal Not Showing
```bash
# Check portal service
sudo systemctl status pinetap-portal

# View logs
sudo journalctl -u pinetap-portal -f

# Restart portal
sudo systemctl restart pinetap-portal
```

## Examples

### Home WiFi Extender
```bash
sudo python pinetap.py install \
    --ssid HomeExtended \
    --password HomePassword \
    --security wpa2-psk \
    --ap-interface wlan1 \
    --uplink-ssid HomeWiFi \
    --uplink-password OriginalPassword \
    --uplink-interface wlan0 \
    --autoconnect
```

### Offline File Server
```bash
sudo python pinetap.py install \
    --ssid FileServer \
    --password FilePass123 \
    --security wpa2-psk \
    --ap-interface wlan0 \
    --no-share \
    --autoconnect \
    --captive-portal \
    --services-file ./fileserver.json
```

### Public Hotspot with Services
```bash
sudo python pinetap.py install \
    --ssid "Free WiFi" \
    --security open \
    --ap-interface wlan1 \
    --uplink-interface eth0 \
    --autoconnect \
    --captive-portal \
    --services-file ./public-services.json
```

## Requirements

- Python 3.7+
- NetworkManager
- iptables
- dnsmasq (managed by NetworkManager)
- iw / wireless-tools

## License

[Your License Here]

## Contributing

Contributions welcome! Please open an issue or PR.

## Support

For issues, please run diagnostics and include output:
```bash
sudo python pinetap.py diagnose > diagnostics.txt
```