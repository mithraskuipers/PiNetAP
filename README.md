# PiNetAP

Dual WiFi Access Point Manager for Raspberry Pi

Turn your Raspberry Pi into a WiFi hotspot with internet sharing via second WiFi or Ethernet. Built for Raspberry Pi OS Bookworm with NetworkManager.

## Features

- One-command WiFi Access Point setup
- Dual WiFi support (one for AP, one for internet uplink)
- Single WiFi + Ethernet support
- Standalone mode (no internet sharing)
- Password-protected or open networks
- Persistent configuration across reboots (with --autoconnect)
- Built-in diagnostic testing
- Automatic configuration backup and restore
- SSH-safe operations (won't break your connection)
- Clean uninstallation

## Requirements

- Raspberry Pi (any model with WiFi)
- Raspberry Pi OS Bookworm or later
- NetworkManager (default on Bookworm)
- At least one WiFi interface
- Root/sudo access

## Quick Start

### Check Your Interfaces

```bash
python3 pinetap.py interfaces
```

This shows all available network interfaces and provides setup recommendations specific to your hardware.

### Basic Setup Examples

**Dual WiFi Setup** (one WiFi for AP, one for internet):
```bash
sudo python3 pinetap.py install --ssid MyHotspot --password SecurePass123 \
    --ap-interface wlan1 \
    --uplink-ssid HomeWiFi --uplink-password HomePassword \
    --uplink-interface wlan0 \
    --autoconnect
```

**Single WiFi + Ethernet** (WiFi for AP, Ethernet for internet):
```bash
sudo python3 pinetap.py install --ssid MyHotspot --password SecurePass123 \
    --ap-interface wlan0 \
    --autoconnect
```

**Standalone AP** (no internet sharing):
```bash
sudo python3 pinetap.py install --ssid LocalNetwork --password SecurePass123 \
    --ap-interface wlan0 --no-share \
    --autoconnect
```

## Usage

### Commands

#### List Interfaces
```bash
python3 pinetap.py interfaces           # Basic list
python3 pinetap.py interfaces -d        # Detailed with connections
```

#### Install Access Point
```bash
sudo python3 pinetap.py install --ssid NETWORK_NAME --password YOUR_PASSWORD \
    --ap-interface wlan0 [OPTIONS]
```

**Options:**
- `--ssid TEXT` - SSID (network name) - REQUIRED
- `--password TEXT` - WiFi password (omit for open network)
- `--ap-interface TEXT` - WiFi interface for AP - REQUIRED
- `--uplink-ssid TEXT` - Uplink WiFi SSID to connect to
- `--uplink-password TEXT` - Uplink WiFi password
- `--uplink-interface TEXT` - Interface for uplink (wlan0, eth0, etc.)
- `--ip TEXT` - AP IP address (default: 192.168.4.1/24)
- `--channel INT` - WiFi channel (default: 3)
- `--mac TEXT` - Custom MAC address
- `--autoconnect` - Enable autoconnect on boot (RECOMMENDED)
- `--connection TEXT` - Connection name (default: SSID-AP)
- `--no-share` - Don't share internet (standalone AP)
- `--test` - Run tests after installation

## Persistence and Autoconnect

By default, connections are created but do NOT automatically start on reboot. To make your AP persistent across reboots, use the `--autoconnect` flag:

```bash
sudo python3 pinetap.py install --ssid MyHotspot --password Pass123 \
    --ap-interface wlan0 --autoconnect
```

**What happens with --autoconnect:**
- AP automatically starts when Pi boots
- Uplink connection (if configured) automatically reconnects
- Survives reboots, power cycles, and network restarts
- No manual intervention needed

**What happens without --autoconnect:**
- Connections are saved but inactive after reboot
- Must manually start with: `nmcli con up CONNECTION-NAME`
- Useful for testing or temporary setups

**Check autoconnect status:**
```bash
python3 pinetap.py test --type connection --connection MyHotspot-AP
```

This will show "Will reconnect on reboot" if autoconnect is enabled.

#### Remove Access Point
```bash
sudo python3 pinetap.py uninstall --connection MyHotspot-AP
```

**Options:**
- `--keep-config` - Keep NetworkManager configuration changes

#### List Connections
```bash
python3 pinetap.py list
```

#### Show Connection Status
```bash
python3 pinetap.py status --connection MyHotspot-AP
```

#### Run Diagnostic Tests
```bash
python3 pinetap.py test --type all                           # All tests
python3 pinetap.py test --type prerequisites                 # Check requirements
python3 pinetap.py test --type config                        # Check configuration
python3 pinetap.py test --type connection --connection NAME  # Check AP connection
sudo python3 pinetap.py test --type services                 # Check services (requires root)
python3 pinetap.py test --type visibility --ssid NAME        # Check AP visibility
```

## Hardware Setup Scenarios

### Scenario 1: Dual WiFi (Recommended)

**Hardware:**
- Raspberry Pi with built-in WiFi
- USB WiFi adapter

**Setup:**
- wlan0: Connect to home WiFi for internet
- wlan1: Create hotspot

**Advantages:**
- Full mobility (no Ethernet needed)
- Internet sharing through WiFi uplink

### Scenario 2: Single WiFi + Ethernet

**Hardware:**
- Raspberry Pi with built-in WiFi
- Ethernet connection

**Setup:**
- wlan0: Create hotspot
- eth0: Internet connection

**Advantages:**
- More stable internet connection
- Simpler setup

### Scenario 3: Standalone

**Hardware:**
- Raspberry Pi with WiFi

**Setup:**
- wlan0: Create hotspot (no internet)

**Use Cases:**
- Local file sharing
- IoT device configuration
- Isolated networks

## Testing

The built-in testing suite helps diagnose issues:

**Before Installation:**
```bash
python3 pinetap.py test --type prerequisites
```

**After Installation:**
```bash
sudo python3 pinetap.py test --type all --connection MyHotspot-AP --ssid MyHotspot
```

**Test Categories:**
- Prerequisites: Root privileges, NetworkManager, interfaces
- Configuration: Service status, config files, backups
- Connection: AP exists, active, configured correctly
- Services: DHCP, IP forwarding, firewall rules
- Visibility: AP visible in WiFi scans

## Troubleshooting

### AP not visible to clients
```bash
python3 pinetap.py test --type visibility --ssid YourSSID
sudo python3 pinetap.py test --type connection --connection YourSSID-AP
```

### Clients can't get IP address
```bash
sudo python3 pinetap.py test --type services
```

### No internet on clients
```bash
sudo python3 pinetap.py test --type services
```
Check IP forwarding and firewall rules.

### Interface already in use
```bash
python3 pinetap.py interfaces -d
```
Shows which connections are using which interfaces.

### Fresh start
```bash
sudo python3 pinetap.py uninstall --connection YourConnection
sudo python3 pinetap.py install [your options] --test
```

## How It Works

1. Backs up NetworkManager configuration
2. Configures dnsmasq for DHCP (if needed)
3. Connects to uplink network (if specified)
4. Creates WiFi AP connection with NetworkManager
5. Configures IP addressing (shared or manual)
6. Activates the access point
7. Sets up internet sharing (if enabled)

All operations use NetworkManager's built-in features for stability and compatibility.

## Uninstallation

Remove the AP and restore original configuration:

```bash
sudo python3 pinetap.py uninstall --connection MyHotspot-AP
```

This will:
- Delete the AP connection
- Restore original NetworkManager configuration
- Re-enable system dnsmasq if it was disabled
- Reload NetworkManager safely

## Technical Details

**Configuration Files:**
- `/etc/NetworkManager/NetworkManager.conf` - NetworkManager config (backed up)
- `/etc/NetworkManager/NetworkManager.conf.backup` - Automatic backup

**Network Architecture:**
- AP uses NetworkManager's built-in hostapd
- DHCP provided by dnsmasq (managed by NetworkManager)
- Internet sharing via NetworkManager's "shared" IPv4 method
- NAT/firewall rules automatically managed