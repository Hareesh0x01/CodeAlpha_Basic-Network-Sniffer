# Usage Guide

## Table of Contents
- [Interactive Mode](#interactive-mode)
- [CLI Mode](#cli-mode)
- [BPF Filters](#bpf-filters)
- [Exporting Data](#exporting-data)
- [Troubleshooting](#troubleshooting)

---

## Interactive Mode

Run the sniffer without arguments to enter interactive mode:

```bash
# Windows (Admin PowerShell)
python -m sniffer

# Linux/macOS
sudo python -m sniffer
```

The interactive wizard will guide you through:

### Step 1: Interface Selection
```
Select a Network Interface
Choose the interface you want to capture packets on.

  [1] 📡 Wi-Fi  192.168.1.100  UP  Intel Wi-Fi 6
  [2] 📡 Ethernet  10.0.0.50  UP  Realtek PCIe
  [3] 🔁 Loopback  127.0.0.1  UP  Loopback Pseudo-Interface

Enter interface number [1]:
```

### Step 2: Filter Configuration
```
Configure Packet Filter

  [1] All traffic (no filter)
  [2] TCP only
  [3] UDP only
  [4] HTTP (port 80)
  [5] HTTPS (port 443)
  [6] DNS (port 53)
  [7] ICMP (ping)
  [8] Custom filter...

Select filter preset [1]:
```

### Step 3: Live Capture
The Rich dashboard shows packets in real-time with color-coded protocols.
Press **Ctrl+C** to stop.

### Step 4: Export
After stopping, you'll be prompted to export:
```
Export 150 captured packets? [Y/n]:
Select export format:
  [1] CSV  (spreadsheet-friendly)
  [2] JSON (preserves full structure)
  [3] PCAP (open in Wireshark)
  [4] All formats
```

---

## CLI Mode

For scripting and advanced usage:

```bash
# Basic capture
python -m sniffer capture -i "Wi-Fi" -c 100

# With BPF filter
python -m sniffer capture -i eth0 -f "tcp port 80" -t 60

# Auto-export to JSON
python -m sniffer capture -i "Wi-Fi" -c 50 --json -o my_capture.json

# Export to all formats
python -m sniffer capture -i eth0 --csv --json --pcap

# List interfaces
python -m sniffer list-interfaces
```

### All CLI Options
```
-i, --interface    Network interface name
-f, --filter       BPF filter expression
-c, --count        Max packets (0 = unlimited)
-t, --timeout      Timeout in seconds (0 = none)
-o, --output       Output file path
--csv              Export to CSV
--json             Export to JSON
--pcap             Export to PCAP
-v, --verbose      INFO-level logging
-d, --debug        DEBUG-level logging
--no-color         Disable colored output
```

---

## BPF Filters

BPF (Berkeley Packet Filter) expressions filter traffic at the kernel level.

### Common Filters

| Filter | Captures |
|---|---|
| `tcp` | All TCP traffic |
| `udp` | All UDP traffic |
| `icmp` | Ping packets |
| `arp` | ARP requests/replies |
| `tcp port 80` | HTTP traffic |
| `tcp port 443` | HTTPS traffic |
| `udp port 53` | DNS queries |
| `host 192.168.1.1` | Traffic to/from a specific IP |
| `src host 10.0.0.1` | Traffic FROM a specific IP |
| `dst port 22` | Traffic TO SSH port |
| `net 192.168.1.0/24` | Traffic on a subnet |

### Combining Filters

```bash
# HTTP or DNS
-f "tcp port 80 or udp port 53"

# TCP to a specific host
-f "tcp and host 8.8.8.8"

# Not SSH traffic
-f "not tcp port 22"

# Complex combination
-f "(tcp port 80 or tcp port 443) and host 192.168.1.100"
```

---

## Exporting Data

### CSV
- Opens in Excel, Google Sheets, pandas
- Flat structure (nested fields are prefixed)
- File: `output/capture_YYYYMMDD_HHMMSS.csv`

### JSON
- Preserves full nested structure
- Includes metadata (tool version, timestamp, packet count)
- NDJSON option available for streaming
- File: `output/capture_YYYYMMDD_HHMMSS.json`

### PCAP
- Opens in Wireshark for deep analysis
- Contains raw packet bytes (complete data)
- File: `output/capture_YYYYMMDD_HHMMSS.pcap`

---

## Troubleshooting

### "Insufficient privileges" error
- **Windows**: Right-click PowerShell → "Run as Administrator"
- **Linux**: Use `sudo python -m sniffer`

### "Npcap not installed" (Windows)
1. Download from https://npcap.com/
2. Run installer
3. Enable "WinPcap API-compatible Mode"
4. Restart your terminal

### No interfaces found
- Check your network connection
- On Linux: `sudo apt install libpcap-dev`
- Ensure Npcap is installed (Windows)

### No packets captured
- Try removing the BPF filter (capture everything)
- Check if the interface is UP
- Generate traffic: open a browser, run `ping 8.8.8.8`
- Try a different interface
