# PiNetAP

Dual WiFi Access Point Manager for Raspberry Pi

Turn your Raspberry Pi into a WiFi hotspot with internet sharing via a second WiFi adapter or Ethernet.  
Built for **Raspberry Pi OS Bookworm** using **NetworkManager**.

---

## Features

- One-command WiFi Access Point setup
- **Multiple security modes**: Open, WPA2-PSK, WPA3-SAE
- **Password validation**: Enforces 8-63 character requirement for secured networks
- Dual WiFi support (one for AP, one for internet uplink)
- Single WiFi + Ethernet support
- **True standalone mode** (properly blocks internet sharing)
- **Easy management**: List and remove all managed APs at once
- **MAC address binding**: Survives interface name changes after reboot
- Persistent configuration across reboots (`--autoconnect`)
- Built-in diagnostic test suite with PASS / WARN / FAIL semantics
- Automatic NetworkManager configuration backup and restore
- Clean uninstallation with bulk removal option
- Simplified and stable AP creation logic

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

**Maximum Security** (WPA3):

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

**NEW:** View all PiNetAP-created access points:

```bash
sudo python pinetap.py managed
```

Shows:
- Connection names
- SSID
- Interface used
- Status (Active/Deleted)

---

#### Install Access Point

```bash
sudo python pinetap.py install --ssid NETWORK_NAME \
    [--password YOUR_PASSWORD] \
    --security SECURITY_MODE \
    --ap-interface wlan0 \
    [OPTIONS]
```

**Required Options:**

- `--ssid TEXT` – SSID (network name) **REQUIRED**
- `--security {open,wpa2-psk,wpa3-sae}` – Security mode (default: wpa2-psk)
- `--ap-interface TEXT` – WiFi interface for AP **REQUIRED**

**Security & Password Options:**

- `--password TEXT` – WiFi password
  - **Required** for `wpa2-psk` and `wpa3-sae` (8-63 characters)
  - **Must be omitted** for `open` networks
  - Will show error if password is too short, too long, or incompatible with security mode

**Uplink Options:**

- `--uplink-ssid TEXT` – Uplink WiFi SSID
- `--uplink-password TEXT` – Uplink WiFi password
- `--uplink-interface TEXT` – Interface for uplink (wlan0, eth0, etc.)

**Configuration Options:**

- `--ip TEXT` – AP IP address (default: 192.168.4.1/24)
- `--channel INT` – WiFi channel (default: 3)
- `--mac TEXT` – Custom cloned MAC address
- `--autoconnect` – Enable autoconnect on boot (**RECOMMENDED**)
- `--connection TEXT` – Connection name (default: SSID-AP)
- `--no-share` – Disable internet sharing (standalone AP)
- `--test` – Run tests after installation

---

## Security Modes

### Open Network
- No password required
- Best for: Guest networks, public hotspots, temporary setups
- **Important**: Do NOT provide `--password` parameter

```bash
sudo python pinetap.py install --ssid GuestWiFi \
    --security open --ap-interface wlan0 --autoconnect
```

### WPA2-PSK (Default)
- Industry standard security
- Compatible with all modern devices
- Password: 8-63 characters required
- Best for: Most use cases

```bash
sudo python pinetap.py install --ssid MyNetwork --password MyPass123 \
    --security wpa2-psk --ap-interface wlan0 --autoconnect
```

### WPA3-SAE
- Latest security standard
- Enhanced protection against attacks
- Password: 8-63 characters required
- Best for: Maximum security (requires newer client devices)

```bash
sudo python pinetap.py install --ssid SecureNet --password SecurePass123 \
    --security wpa3-sae --ap-interface wlan0 --autoconnect
```

---

## Password Requirements

| Security Mode | Password Required | Length | Example |
|---------------|-------------------|--------|---------|
| `open` | ❌ No (error if provided) | N/A | `--security open` |
| `wpa2-psk` | ✅ Yes | 8-63 chars | `--password MyPass123` |
| `wpa3-sae` | ✅ Yes | 8-63 chars | `--password SecurePass123` |

**Examples of validation errors:**

```bash
# Too short - FAILS
sudo python pinetap.py install --ssid Test --password short \
    --security wpa2-psk --ap-interface wlan0
# Error: Password too short. WPA2-PSK requires 8-63 characters (current length: 5)

# Password on open network - FAILS
sudo python pinetap.py install --ssid Test --password Pass123 \
    --security open --ap-interface wlan0
# Error: Open network should not have a password

# No password on secured network - FAILS
sudo python pinetap.py install --ssid Test \
    --security wpa2-psk --ap-interface wlan0
# Error: wpa2-psk requires a password
```

---

## Standalone Mode (No Internet Sharing)

The `--no-share` flag creates a **true standalone network** where:
- ✅ Clients can connect to the AP
- ✅ Clients receive IP addresses via DHCP
- ✅ Clients can access services on the Raspberry Pi
- ✅ Clients can communicate with each other on the local network
- ❌ Clients **cannot** access the internet (even if Pi has internet)

**How it works:**
- IP forwarding is explicitly disabled at the system level
- Configuration persists across reboots via `/etc/sysctl.conf`
- Perfect for: File sharing, local services, IoT networks, offline applications

**Example:**

```bash
sudo python pinetap.py install --ssid FileServer --password Local123 \
    --security wpa2-psk --ap-interface wlan0 --no-share --autoconnect
```

**Verify standalone mode:**

```bash
# Check IP forwarding (should show 0)
cat /proc/sys/net/ipv4/ip_forward

# Run diagnostics
sudo python pinetap.py diagnose --connection FileServer-AP
```

---

## Persistence and Autoconnect

By default, connections are created but **do not start automatically** on reboot.  
Use `--autoconnect` to make the AP persistent.

```bash
sudo python pinetap.py install --ssid MyHotspot --password Pass12345 \
    --security wpa2-psk --ap-interface wlan0 --autoconnect
```

**With `--autoconnect`:**
- AP starts automatically on boot
- Uplink reconnects automatically
- Survives reboots and power loss
- **MAC address binding** ensures connection follows hardware even if interface names change

**Without `--autoconnect`:**
- Connection exists but is inactive after reboot
- Must be started manually:
  ```bash
  nmcli con up CONNECTION-NAME
  ```

**Verify autoconnect:**

```bash
python pinetap.py test --type connection --connection MyHotspot-AP
```

---

## MAC Address Binding

**Problem:** USB WiFi adapters may change interface names (wlan0 ↔ wlan1) after reboot.

**Solution:** PiNetAP automatically binds connections to MAC addresses:
- Interface name changes don't break your AP
- Connection "follows" the hardware
- Mappings stored in `/etc/pinetap/interface_mapping.json`

**Check interface consistency:**

```bash
python pinetap.py test --type prerequisites
```

If interface names changed, you'll see a warning but the AP will still work.

---

## Remove Access Point

**Remove specific connection:**

```bash
sudo python pinetap.py uninstall --connection MyHotspot-AP
```

**Remove all PiNetAP-managed connections:**

```bash
sudo python pinetap.py uninstall --all
```

**Options:**
- `--keep-config` – Keep NetworkManager configuration changes (faster)

**Example workflow:**

```bash
# See what's installed
sudo python pinetap.py managed

# Remove everything
sudo python pinetap.py uninstall --all
```

---

## Other Commands

#### List NetworkManager Connections

```bash
python pinetap.py list
```

#### Show Connection Status

```bash
python pinetap.py status --connection MyHotspot-AP
```

#### Diagnose Issues

```bash
sudo python pinetap.py diagnose [--connection NAME]
```

Shows:
- Connection configuration
- Interface status
- IP forwarding state
- DHCP service status
- Recent logs
- Troubleshooting suggestions

#### Auto-Fix Common Issues

```bash
sudo python pinetap.py fix [--connection NAME]
```

Attempts to automatically fix:
- NetworkManager not running
- Inactive connections
- Configuration issues

---

## Diagnostic Tests

```bash
# Run all tests
python pinetap.py test --type all

# Test prerequisites
python pinetap.py test --type prerequisites

# Test configuration
python pinetap.py test --type config

# Test specific connection
python pinetap.py test --type connection --connection MyHotspot-AP

# Test services (requires root)
sudo python pinetap.py test --type services

# Test AP visibility
python pinetap.py test --type visibility --ssid MyHotspot
```

**Test output example:**

```
==============================================================
TEST RESULTS
==============================================================
✓ Root Privileges: Running as root
✓ NetworkManager Installed: nmcli found
✓ NetworkManager Running: Service is active
✓ WiFi Interface (wlan0): Interface exists
✓ Multiple WiFi Interfaces: 2 WiFi interfaces detected
⚠ Interface Consistency: ap: wlan0→wlan1
✓ AP Connection (MyHotspot-AP): Connection exists
✓ AP Active (MyHotspot-AP): Connection is active
✓ IP Forwarding: Disabled
==============================================================
```

---

## Hardware Setup Scenarios

### Dual WiFi (Recommended)

- wlan0: Internet uplink
- wlan1: Access Point

Best for mobility and full WiFi-based internet sharing.

**Setup:**

```bash
sudo python pinetap.py install --ssid MyHotspot --password Pass12345 \
    --security wpa2-psk --ap-interface wlan1 \
    --uplink-ssid HomeWiFi --uplink-password HomePass \
    --uplink-interface wlan0 --autoconnect
```

---

### Single WiFi + Ethernet

- wlan0: Access Point
- eth0: Internet uplink (automatic)

Most stable setup. Ethernet is automatically used for internet.

**Setup:**

```bash
sudo python pinetap.py install --ssid MyHotspot --password Pass12345 \
    --security wpa2-psk --ap-interface wlan0 --autoconnect
```

---

### Standalone AP (No Internet)

- wlan0: Access Point only
- No internet sharing

**Use cases:**
- Local file sharing (Samba, NFS)
- IoT device configuration
- Isolated networks for security
- Offline applications
- Local game servers

**Setup:**

```bash
sudo python pinetap.py install --ssid LocalNet --password Pass12345 \
    --security wpa2-psk --ap-interface wlan0 --no-share --autoconnect
```

---

## Troubleshooting

### AP not visible on phone

```bash
# Check if AP is broadcasting
sudo iwlist wlan0 scan | grep -i "your-ssid"

# Run visibility test
python pinetap.py test --type visibility --ssid YourSSID

# Check interface status
python pinetap.py interfaces -d

# Try auto-fix
sudo python pinetap.py fix --connection YourConnection-AP
```

### Clients not getting IP addresses

```bash
# Test DHCP service
sudo python pinetap.py test --type services

# Check dnsmasq
ps aux | grep dnsmasq

# Diagnose connection
sudo python pinetap.py diagnose --connection YourConnection-AP
```

### No internet on clients (with sharing enabled)

```bash
# Check IP forwarding
cat /proc/sys/net/ipv4/ip_forward  # Should be 1 for sharing

# Test services
sudo python pinetap.py test --type services

# Check NAT rules
sudo iptables -t nat -L

# Verify uplink connection
nmcli con show --active
```

### Internet accessible in standalone mode (bug)

```bash
# Verify IP forwarding is disabled
cat /proc/sys/net/ipv4/ip_forward  # Should be 0

# Check configuration
sudo python pinetap.py diagnose --connection YourConnection-AP

# Recreate with --no-share
sudo python pinetap.py install --ssid YourSSID --password YourPass \
    --security wpa2-psk --ap-interface wlan0 --no-share --autoconnect
```

### Interface name changed after reboot

**This is normal with USB WiFi adapters.**

```bash
# Check interface consistency
python pinetap.py test --type prerequisites

# View MAC bindings
python pinetap.py interfaces -d

# Your AP should still work due to MAC binding
# If not, recreate using the new interface name
```

### Password validation errors

```bash
# Too short
# Error: Password too short. WPA2-PSK requires 8-63 characters (current length: 5)
# Solution: Use a password with at least 8 characters

# Password on open network
# Error: Open network should not have a password
# Solution: Remove --password parameter when using --security open

# No password on secured network
# Error: wpa2-psk requires a password
# Solution: Add --password parameter
```

### Clean reset

```bash
# Remove all PiNetAP connections
sudo python pinetap.py uninstall --all

# Reinstall from scratch
sudo python pinetap.py install [options] --test
```

---

## How It Works

1. **Validates security and password** – Ensures configuration is valid
2. **Backs up NetworkManager configuration** – Safely modifies system settings
3. **Configures dnsmasq** – Sets up DHCP server via NetworkManager
4. **Connects uplink** – Establishes internet connection (if specified)
5. **Creates AP connection** – Configures hostapd through NetworkManager
6. **Binds to MAC address** – Ensures persistence across reboots
7. **Configures IP addressing** – Sets up subnet and gateway
8. **Manages IP forwarding** – Enables/disables based on `--no-share` flag
9. **Enables NAT** – Configures internet sharing (if enabled)
10. **Activates AP** – Brings up the access point
11. **Saves to managed registry** – Tracks connection for easy management

Everything is handled through NetworkManager for stability and compatibility.

---

## Uninstallation

**Remove specific connection:**

```bash
sudo python pinetap.py uninstall --connection MyHotspot-AP
```

**Remove all managed connections:**

```bash
sudo python pinetap.py uninstall --all
```

This:
- Removes the AP connection(s)
- Cleans up managed connections registry
- Restores NetworkManager config (unless `--keep-config`)
- Re-enables system dnsmasq if needed
- Reloads NetworkManager safely
- Removes interface mappings

---

## Technical Details

### Files Modified/Created

**Configuration:**
- `/etc/NetworkManager/NetworkManager.conf` – Modified to use dnsmasq
- `/etc/NetworkManager/NetworkManager.conf.backup` – Backup of original config
- `/etc/sysctl.conf` – Modified for IP forwarding persistence

**PiNetAP Data:**
- `/etc/pinetap/interface_mapping.json` – MAC address to interface mapping
- `/etc/pinetap/managed_connections.json` – Registry of created APs

### Networking Stack

**Access Point:**
- hostapd (via NetworkManager in AP mode)
- DHCP server via dnsmasq (managed by NetworkManager)
- IPv4 subnet: 192.168.4.0/24 (configurable)

**Internet Sharing (when enabled):**
- NAT via NetworkManager's "shared" IPv4 method
- IP forwarding enabled via sysctl
- Firewall rules managed automatically by NetworkManager
- iptables MASQUERADE rules (automatic)

**Standalone Mode (when `--no-share`):**
- DHCP server still active (clients get IPs)
- IP forwarding explicitly disabled
- No NAT/MASQUERADE rules
- Local network access only

### Security Implementation

**Open Network:**
- `wifi-sec.key-mgmt: none`
- No encryption

**WPA2-PSK:**
- `wifi-sec.key-mgmt: wpa-psk`
- `wifi-sec.proto: rsn` (WPA2)
- `wifi-sec.pairwise: ccmp` (AES)
- `wifi-sec.psk: [password]`

**WPA3-SAE:**
- `wifi-sec.key-mgmt: sae`
- `wifi-sec.psk: [password]`
- Enhanced security against brute-force attacks

---

## Examples

### Complete Dual WiFi Setup

```bash
# Step 1: Check available interfaces
python pinetap.py interfaces -d

# Step 2: Install with all features
sudo python pinetap.py install \
    --ssid "MyPiHotspot" \
    --password "SecurePassword123" \
    --security wpa2-psk \
    --ap-interface wlan1 \
    --uplink-ssid "HomeNetwork" \
    --uplink-password "HomePassword" \
    --uplink-interface wlan0 \
    --ip 192.168.50.1/24 \
    --channel 6 \
    --autoconnect \
    --test

# Step 3: Verify it's working
sudo python pinetap.py diagnose --connection MyPiHotspot-AP
```

### Guest Network (Open, No Internet)

```bash
sudo python pinetap.py install \
    --ssid "Guest-WiFi" \
    --security open \
    --ap-interface wlan0 \
    --no-share \
    --autoconnect
```

### File Sharing Network (Secured, No Internet)

```bash
sudo python pinetap.py install \
    --ssid "FileServer" \
    --password "FileShare123" \
    --security wpa2-psk \
    --ap-interface wlan0 \
    --ip 10.0.0.1/24 \
    --no-share \
    --autoconnect
```

### Maximum Security Setup

```bash
sudo python pinetap.py install \
    --ssid "SecureNetwork" \
    --password "VerySecurePassword123" \
    --security wpa3-sae \
    --ap-interface wlan1 \
    --uplink-ssid "HomeWiFi" \
    --uplink-password "HomePass" \
    --uplink-interface wlan0 \
    --autoconnect
```

---

## FAQ

**Q: Can I run multiple APs simultaneously?**  
A: No, each WiFi interface can only host one AP at a time. But you can create multiple connections and switch between them.

**Q: Will this work on Ubuntu/Debian?**  
A: Yes, as long as NetworkManager is installed and active.

**Q: Do I need to disable hostapd/dnsmasq services?**  
A: PiNetAP automatically handles this. It disables standalone dnsmasq and uses NetworkManager's built-in services.

**Q: What if my USB WiFi adapter interface names change?**  
A: PiNetAP uses MAC address binding. Your AP will continue working even if wlan0 becomes wlan1.

**Q: Can clients see each other on the network?**  
A: Yes, by default clients can communicate with each other and the Pi on the local subnet.

**Q: How do I change the AP password after creation?**  
A: Recreate the connection with the same SSID and new password. PiNetAP will automatically replace the old connection.

**Q: Does `--no-share` affect uplink connections?**  
A: No, `--no-share` only prevents clients connected to the AP from accessing the internet. The Pi itself still has internet.

**Q: Can I use WPA3 with older devices?**  
A: No, WPA3 requires client devices from ~2018 or newer. Use WPA2-PSK for broader compatibility.