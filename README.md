# PiNetAP

Dual WiFi Access Point Manager for Raspberry Pi

Turn your Raspberry Pi into a WiFi hotspot with internet sharing via a second WiFi adapter or Ethernet.  
Built for **Raspberry Pi OS Bookworm** using **NetworkManager**.

---

## Features

- One-command WiFi Access Point setup
- Dual WiFi support (one for AP, one for internet uplink)
- Single WiFi + Ethernet support
- Standalone mode (no internet sharing)
- Password-protected or open networks
- Persistent configuration across reboots (`--autoconnect`)
- Built-in diagnostic test suite with PASS / WARN / FAIL semantics
- Automatic NetworkManager configuration backup and restore
- Clean uninstallation
- Simplified and stable AP creation logic
- Clear separation of concerns in internal architecture
- Reduced fragile heuristics and improved runtime correctness

---

## Requirements

- Raspberry Pi (any model with WiFi)
- Raspberry Pi OS Bookworm or later
- NetworkManager (default on Bookworm)
- At least one WiFi interface
- Root / sudo access

---

## Quick Start

### Check Your Interfaces

```bash
python3 pinetap.py interfaces
```

Shows all available interfaces and prints setup recommendations based on detected hardware.

---

### Basic Setup Examples

**Dual WiFi Setup** (one WiFi for AP, one for internet):

```bash
sudo python3 pinetap.py install --ssid MyHotspot --password SecurePass123 \
    --ap-interface wlan1 \
    --uplink-ssid HomeWiFi --uplink-password HomePassword \
    --uplink-interface wlan0 \
    --autoconnect
```

**Single WiFi + Ethernet** (WiFi AP, Ethernet internet):

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

---

## Usage

### Commands

#### List Interfaces

```bash
python3 pinetap.py interfaces
python3 pinetap.py interfaces -d
```

---

#### Install Access Point

```bash
sudo python3 pinetap.py install --ssid NETWORK_NAME --password YOUR_PASSWORD \
    --ap-interface wlan0 [OPTIONS]
```

**Options:**

- `--ssid TEXT` – SSID (network name) **REQUIRED**
- `--password TEXT` – WiFi password (omit for open network)
- `--ap-interface TEXT` – WiFi interface for AP **REQUIRED**
- `--uplink-ssid TEXT` – Uplink WiFi SSID
- `--uplink-password TEXT` – Uplink WiFi password
- `--uplink-interface TEXT` – Interface for uplink (wlan0, eth0, etc.)
- `--ip TEXT` – AP IP address (default: 192.168.4.1/24)
- `--channel INT` – WiFi channel (default: 3)
- `--mac TEXT` – Custom MAC address
- `--autoconnect` – Enable autoconnect on boot (**RECOMMENDED**)
- `--connection TEXT` – Connection name (default: SSID-AP)
- `--no-share` – Disable internet sharing (standalone AP)
- `--test` – Run tests after installation

---

## Persistence and Autoconnect

By default, connections are created but **do not start automatically** on reboot.  
Use `--autoconnect` to make the AP persistent.

```bash
sudo python3 pinetap.py install --ssid MyHotspot --password Pass123 \
    --ap-interface wlan0 --autoconnect
```

**With `--autoconnect`:**
- AP starts automatically on boot
- Uplink reconnects automatically
- Survives reboots and power loss

**Without `--autoconnect`:**
- Connection exists but is inactive after reboot
- Must be started manually:
  ```bash
  nmcli con up CONNECTION-NAME
  ```

**Verify autoconnect:**

```bash
python3 pinetap.py test --type connection --connection MyHotspot-AP
```

---

## Remove Access Point

```bash
sudo python3 pinetap.py uninstall --connection MyHotspot-AP
```

**Options:**
- `--keep-config` – Keep NetworkManager configuration changes

---

## Other Commands

#### List NetworkManager Connections

```bash
python3 pinetap.py list
```

#### Show Connection Status

```bash
python3 pinetap.py status --connection MyHotspot-AP
```

---

## Diagnostic Tests

```bash
python3 pinetap.py test --type all
python3 pinetap.py test --type prerequisites
python3 pinetap.py test --type config
python3 pinetap.py test --type connection --connection NAME
sudo python3 pinetap.py test --type services
python3 pinetap.py test --type visibility --ssid NAME
```

---

## Hardware Setup Scenarios

### Dual WiFi (Recommended)

- wlan0: Internet uplink
- wlan1: Access Point

Best for mobility and full WiFi-based internet sharing.

---

### Single WiFi + Ethernet

- wlan0: Access Point
- eth0: Internet uplink

Most stable setup.

---

### Standalone AP

- wlan0: Access Point only

Use cases:
- Local file sharing
- IoT configuration
- Isolated networks

---

## Troubleshooting

**AP not visible:**
```bash
python3 pinetap.py test --type visibility --ssid YourSSID
```

**Clients not getting IP:**
```bash
sudo python3 pinetap.py test --type services
```

**No internet on clients:**
```bash
sudo python3 pinetap.py test --type services
```

**Interface already in use:**
```bash
python3 pinetap.py interfaces -d
```

**Clean reset:**
```bash
sudo python3 pinetap.py uninstall --connection YourConnection
sudo python3 pinetap.py install [options] --test
```

---

## How It Works

1. Backs up NetworkManager configuration
2. Configures dnsmasq (via NetworkManager)
3. Connects uplink (if specified)
4. Creates AP connection
5. Configures IP addressing
6. Enables sharing (optional)
7. Activates AP

Everything is handled through NetworkManager for stability and compatibility.

---

## Uninstallation

```bash
sudo python3 pinetap.py uninstall --connection MyHotspot-AP
```

This:
- Removes the AP connection
- Restores NetworkManager config
- Re-enables system dnsmasq if needed
- Reloads NetworkManager safely

---

## Technical Details

**Files:**
- `/etc/NetworkManager/NetworkManager.conf`
- `/etc/NetworkManager/NetworkManager.conf.backup`

**Networking:**
- hostapd via NetworkManager
- DHCP via dnsmasq
- NAT via NetworkManager shared IPv4
- Firewall rules managed automatically