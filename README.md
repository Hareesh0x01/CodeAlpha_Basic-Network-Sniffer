# 🔍 Basic Network Sniffer

An educational, production-quality network packet sniffer built with **Python 3.11+** and **Scapy**. 

> ⚠️ **Educational Purpose Only.** This tool captures real network packets on YOUR local machine's network interface. Unauthorized packet capture on networks you do not own is illegal. Always obtain proper authorization before using this tool.

---

## 📖 Project Overview

The **Basic Network Sniffer** is designed to teach fundamental networking concepts and Python software engineering best practices. It captures live network traffic passing through your machine, decodes the packets across various OSI layers, and presents the data in a beautiful, real-time terminal dashboard. 

The codebase heavily emphasizes clean architecture, modularity, and comprehensive documentation to serve as a learning resource for aspiring cybersecurity engineers.

---

## ✨ Features

- **Live Packet Capture**: Real-time traffic sniffing using Scapy (no dummy data).
- **8 Protocol Parsers**: Deep packet inspection for Ethernet, IPv4/IPv6, TCP, UDP, DNS, HTTP, ARP, and ICMP.
- **Rich Terminal UI**: A gorgeous, live-updating dashboard featuring a stats panel, instantaneous data rates, and color-coded packet streams.
- **Detailed Statistics**: Tracks top talkers (Source/Destination IPs), protocol distribution, and bandwidth usage.
- **3 Export Formats**: Save captures to CSV (spreadsheets), JSON (nested analysis), or PCAP (for Wireshark).
- **Flexible Configuration**: Supports CLI arguments, environment variables, and a clean `sniffer.toml` config file.
- **Cross-Platform Support**: Works on Windows (via Npcap) and Linux/macOS (via libpcap).
- **Production-Quality Code**: Includes custom exception hierarchies, graceful keyboard interrupt handling, and comprehensive logging.
---

## 📁 Folder Structure

```text
Basic Network Sniffer/
├── sniffer/                    # Main application package
│   ├── __main__.py             # Entry point (python -m sniffer)
│   ├── cli.py                  # CLI parsing & interactive menus
│   ├── config.py               # Config management (CLI > TOML > Env > Defaults)
│   ├── core/                   # Threaded Capture Engine & Interfaces
│   ├── parsers/                # L2-L7 Protocol Decoders Pipeline
│   ├── display/                # Rich Live Dashboard & Formatters
│   ├── export/                 # CSV, JSON, PCAP Exporters
│   └── utils/                  # Exceptions, Loggers, OS Permissions
├── docs/                       # Architecture, Usage, Protocol references
├── .gitignore                  # Git ignore rules
├── requirements.txt            # Production dependencies
├── README.md                   # This file
└── LICENSE                     # MIT License
```

---

## 🛠️ Requirements

| Platform | Requirements |
|---|---|
| **Python** | 3.11 or higher |
| **Windows** | [Npcap](https://npcap.com/) (Ensure "WinPcap API-compatible Mode" is enabled). Must run terminal as **Administrator**. |
| **Linux** | `sudo apt install libpcap-dev`. Must run with `sudo`. |
| **macOS** | Built-in libpcap. Must run with `sudo`. |

---

## 🚀 Installation

1. **Clone the repository**:
   ```bash
   git clone <repo-url>
   cd "Basic Network Sniffer"
   ```

2. **Set up a virtual environment**:
   ```bash
   python -m venv .venv
   
   # Windows:
   .venv\Scripts\activate
   
   # Linux/macOS:
   source .venv/bin/activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

---

## 💻 Usage

### Interactive Mode (Beginner Friendly)
Run the sniffer without any arguments to launch the interactive wizard. It will guide you through interface selection, filter setup, and exporting.
```bash
# Windows (Admin PowerShell):
python -m sniffer

# Linux/macOS:
sudo python -m sniffer
```

### CLI Mode (Advanced)
```bash
# Capture specific protocol (e.g., TCP) on a specific interface
python -m sniffer capture -i "Wi-Fi" --tcp

# Capture 100 packets and auto-save to PCAP and CSV
python -m sniffer capture -c 100 --auto-pcap --auto-csv

# Show post-capture statistics for DNS traffic
python -m sniffer capture --dns --stats

# Use custom BPF filter
python -m sniffer capture -f "tcp port 80 or tcp port 443"
```

> For more detailed usage instructions, check out [docs/USAGE.md](docs/USAGE.md).

---

## 📸 Screenshots

*(Replace these placeholders with actual images once you run the application)*

- **Live Dashboard**: `![Live Capture Dashboard](docs/images/dashboard.png)`
- **Post-Capture Stats**: `![Statistics Table](docs/images/stats.png)`
- **Interactive Menu**: `![Interactive CLI](docs/images/interactive.png)`

---

## 📝 Example Output

### Console Summary (Post-Capture)
```text
✓ Capture Complete

  📦 Total Packets:   1,245
  📊 Total Data:      14.2 MB (568.1 KB/s)
  ⏱️  Duration:        00:00:25
  ⚡ Average Rate:    49.8 packets/sec
```

### JSON Export Format
```json
{
  "metadata": {
    "tool": "Basic Network Sniffer",
    "version": "1.0.0",
    "export_timestamp": "2024-10-25T14:30:00.000000",
    "packet_count": 1
  },
  "packets": [
    {
      "timestamp": 1700000000.123,
      "packet_number": 1,
      "size": 74,
      "layers": ["Ethernet", "IP", "TCP"],
      "ip": {
        "src_ip": "192.168.1.100",
        "dst_ip": "8.8.8.8",
        "protocol_name": "TCP"
      },
      "tcp": {
        "src_port": 54321,
        "dst_port": 443,
        "flags_list": ["SYN"]
      }
    }
  ]
}
```

---

## 🔧 Troubleshooting

- **"Insufficient privileges" error**: 
  - *Windows*: Right-click your terminal (PowerShell/CMD) and select "Run as Administrator".
  - *Linux/macOS*: Prefix your command with `sudo`.
- **"Npcap not installed" (Windows)**: 
  - Download and install from [npcap.com](https://npcap.com/). Make sure to check the box for "WinPcap API-compatible Mode" during installation.
- **No interfaces found**: 
  - Ensure your network adapter is active. On Linux, ensure `libpcap-dev` is installed.
- **No packets captured**: 
  - Remove your BPF filter to ensure basic connectivity. Open a browser and navigate to a website to generate traffic.

---

## 🔮 Future Improvements

While this is an educational project, future iterations could include:
- **HTTPS/TLS Decryption**: Using pre-master secrets (`SSLKEYLOGFILE`) to decrypt application-layer data.
- **GUI Application**: Wrapping the backend in a graphical interface using PySide6 or web technologies.
- **Anomaly Detection**: Basic heuristics to flag unusual traffic patterns (e.g., SYN floods, ARP spoofing).
- **Flow Reconstruction**: Reassembling full TCP streams from individual packets.

---

## 📄 License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.
