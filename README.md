# PiNetAP

Dual WiFi Access Point Manager for Raspberry Pi

Turn your Raspberry Pi into a WiFi hotspot with internet sharing via a second WiFi adapter or Ethernet.
Built for **Raspberry Pi OS Bookworm** using **NetworkManager**.

---

## Features

* One-command WiFi Access Point setup
* **Multiple security modes**: Open, WPA2-PSK, WPA3-SAE
* **Password validation**: Enforces 8–63 character requirement for secured networks
* Dual WiFi support (one for AP, one for internet uplink)
* Single WiFi + Ethernet support
* **True standalone mode** (properly blocks internet sharing)
* **Easy management**: List and remove all managed APs at once
* **MAC address binding**: Survives interface name changes after reboot
* Persistent configuration across reboots (`--autoconnect`)
* Built-in diagnostic test suite with PASS / WARN / FAIL semantics
* Automatic NetworkManager configuration backup and restore
* Clean uninstallation with bulk removal option
* Simplified and stable AP creation logic

---

## Requirements

* Raspberry Pi (any model with WiFi)
* Raspberry Pi OS Bookworm or later
* NetworkManager (default on Bookworm)
* At least one WiFi interface
* Root / sudo access

---

## Quick Start

### Check Your Interfaces

```bash
python pinetap.py interfaces
```

Shows all available interfaces and prints setup recommendations based on detected hardware.

**View detailed info including MAC addresses:**

```bash
python pinetap.py interfaces -d
```

---

### Basic Setup Examples

**Dual WiFi Setup** (one WiFi for AP, one for internet):

```bash
sudo python pinetap.py install --ssid MyHotspot --password SecurePass123 \
    --security wpa2-psk \
    --ap-interface wlan1 \
    --uplink-ssid HomeWiFi --uplink-password HomePassword \
    --uplink-interface wlan0 \
    --autoconnect
```

**Single WiFi + Ethernet** (WiFi AP, Ethernet internet):

```bash
sudo python pinetap.py install --ssid MyHotspot --password SecurePass123 \
    --security wpa2-psk \
    --ap-interface wlan0 \
    --autoconnect
```

**Standalone AP** (no internet sharing):

```bash
sudo python pinetap.py install --ssid LocalNetwork --password SecurePass123 \
    --security wpa2-psk \
    --ap-interface wlan0 --no-share \
    --autoconnect
```

**Open Guest Network** (no password):

```bash
sudo python pinetap.py install --ssid GuestWiFi \
    --security open \
    --ap-interface wlan0 \
    --autoconnect
```

**Maximum Security (WPA3):**

```bash
sudo python pinetap.py install --ssid SecureAP --password SuperSecret123 \
    --security wpa3-sae \
    --ap-interface wlan0 \
    --autoconnect
```

---

## Usage

### Commands

#### List Interfaces

```bash
python pinetap.py interfaces       # Basic view
python pinetap.py interfaces -d    # Detailed view with MAC addresses
```

---

#### List Managed Connections

View all PiNetAP-created access points:

```bash
sudo python pinetap.py managed
```

Shows:

* Connection name
* SSID
* Interface used
* Status (Active / Deleted)

---

#### Install Access Point

```bash
sudo python pinetap.py install --ssid NETWORK_NAME \
    [--password YOUR_PASSWORD] \
    --security SECURITY_MODE \
    --ap-interface wlan0 \
    [OPTIONS]
```

**Required options:**

* `--ssid TEXT` – SSID (network name)
* `--security {open,wpa2-psk,wpa3-sae}` – Security mode (default: wpa2-psk)
* `--ap-interface TEXT` – WiFi interface for AP

**Security & password options:**

* `--password TEXT`

  * Required for `wpa2-psk` and `wpa3-sae`
  * Must be omitted for `open`
  * Length enforced: 8–63 characters

**Uplink options:**

* `--uplink-ssid TEXT`
* `--uplink-password TEXT`
* `--uplink-interface TEXT`

**Configuration options:**

* `--ip TEXT` – AP IP address (default: `192.168.4.1/24`)
* `--channel INT` – WiFi channel (default: `3`)
* `--mac TEXT` – Clone a custom MAC address
* `--autoconnect` – Start automatically on boot
* `--connection TEXT` – Custom connection name (default: `SSID-AP`)
* `--no-share` – Disable internet sharing
* `--test` – Run diagnostics after install

---

## Security Modes

### Open Network

* No password
* No encryption
* Do **not** provide `--password`

### WPA2-PSK (Default)

* Widely supported
* Password required (8–63 characters)

### WPA3-SAE

* Modern security standard
* Requires newer client devices
* Password required (8–63 characters)

---

## Standalone Mode (`--no-share`)

Creates a **local-only network**:

* Clients can connect and get DHCP leases
* Clients can reach the Raspberry Pi
* Clients can talk to each other
* Internet access is **fully blocked**

**Implementation details:**

* IP forwarding disabled persistently
* No NAT or MASQUERADE rules
* Survives reboot

---

## Persistence and Autoconnect

Without `--autoconnect`, connections exist but are inactive after reboot.

With `--autoconnect`:

* AP starts automatically
* Uplink reconnects automatically
* MAC binding ensures interface stability

---

## MAC Address Binding

USB WiFi adapters may change interface names after reboot.

PiNetAP binds connections to MAC addresses so:

* Interface renaming does not break APs
* Hardware identity is preserved

Mappings are stored in:

```
/etc/pinetap/interface_mapping.json
```

---

## Remove Access Points

Remove one connection:

```bash
sudo python pinetap.py uninstall --connection MyHotspot-AP
```

Remove all PiNetAP-managed connections:

```bash
sudo python pinetap.py uninstall --all
```

---

## Diagnostics & Fixes

Run tests:

```bash
python pinetap.py test --type all
```

Diagnose a connection:

```bash
sudo python pinetap.py diagnose --connection MyHotspot-AP
```

Auto-fix common issues:

```bash
sudo python pinetap.py fix --connection MyHotspot-AP
```

---

## How It Works

1. Validates security and password rules
2. Backs up NetworkManager configuration
3. Configures dnsmasq via NetworkManager
4. Creates and activates AP connection
5. Binds connection to interface MAC
6. Configures IP addressing
7. Enables or disables IP forwarding
8. Enables NAT when sharing is active
9. Registers connection as managed

Everything is handled through NetworkManager for stability.

---

## Files & Data

**System:**

* `/etc/NetworkManager/NetworkManager.conf`
* `/etc/NetworkManager/NetworkManager.conf.backup`
* `/etc/sysctl.conf`

**PiNetAP:**

* `/etc/pinetap/interface_mapping.json`
* `/etc/pinetap/managed_connections.json`

---

## FAQ

**Can I run multiple APs at once?**
No. One AP per WiFi interface.

**Does this replace hostapd/dnsmasq?**
No. NetworkManager manages both internally.

**Does `--no-share` break uplinks?**
No. It only blocks client internet access.

**Can I change passwords later?**
Recreate the connection with the same SSID.

**Does WPA3 work with old devices?**
No. Use WPA2-PSK for compatibility.
