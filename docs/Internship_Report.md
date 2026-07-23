# INTERNSHIP REPORT
## Basic Network Sniffer

**Submitted in partial fulfillment of the requirements for the CodeAlpha Cyber Security Internship Program**

**Prepared By:**
[Your Name]
[Your Roll Number/ID]
[Your Degree/Program]

**Under the Guidance of:**
[Supervisor/Manager Name]
[Supervisor Designation]

**Organization:**
CodeAlpha

**Date:** [Date]

<div style="page-break-after: always;"></div>

---

# CERTIFICATE

This is to certify that the internship report entitled **"Basic Network Sniffer"** submitted by **[Your Name]** is a record of original work carried out by them under supervision and guidance during their tenure. 

This report is submitted in partial fulfillment of the requirements for the completion of the Cyber Security Internship Program at **CodeAlpha**. The work presented in this report highlights practical applications of network security concepts and has not been submitted anywhere else for the award of any other degree or diploma.

**Signature of Supervisor:** _______________________

**Name of Supervisor:** [Supervisor Name]
**Designation:** [Supervisor Designation]
**Date:** _______________________

<div style="page-break-after: always;"></div>

---

# ACKNOWLEDGEMENT

I would like to express my deepest gratitude to all those who provided support, guidance, and encouragement during the course of my Cyber Security Internship at CodeAlpha and the development of the "Basic Network Sniffer" project.

First and foremost, I would like to thank the team at **CodeAlpha**, for their invaluable guidance, constant supervision, and constructive feedback. Their expertise and willingness to help have been instrumental in the successful completion of this project. CodeAlpha's commitment to providing hands-on, practical experience in cybersecurity has profoundly shaped my learning journey.

I also extend my sincere thanks to the management and staff of **CodeAlpha** for providing me with the opportunity to undertake this internship and for offering a conducive learning environment that bridged the gap between theoretical knowledge and real-world application. 

Furthermore, I am grateful to my academic institution for equipping me with the foundational knowledge required to tackle complex cybersecurity and networking problems.

Finally, I would like to thank my family and friends for their unwavering support and encouragement throughout my academic and professional journey.

<div style="page-break-after: always;"></div>

---

# TABLE OF CONTENTS

1. **Introduction**
2. **Objective**
3. **Problem Statement**
4. **Software & Hardware Requirements**
5. **Technologies Used**
6. **Project Architecture**
7. **Implementation & Working**
8. **Code Explanation**
9. **Output & Screenshots**
10. **Advantages**
11. **Limitations**
12. **Future Scope**
13. **Conclusion**
14. **References**

<div style="page-break-after: always;"></div>

---

# 1. INTRODUCTION

### About CodeAlpha
CodeAlpha is a forward-thinking organization dedicated to empowering students and emerging professionals through intensive, hands-on internship programs. By focusing on practical skill development in domains like Cyber Security, Web Development, and Software Engineering, CodeAlpha bridges the critical gap between academic theory and industry demands. Their Cyber Security Internship provides a rigorous environment where interns are challenged to build, analyze, and secure real-world systems.

### Project Overview
In the modern digital era, computer networks form the backbone of global communication. As the volume of data transmitted over these networks grows exponentially, so does the need for robust network monitoring and security mechanisms. Network administrators and cybersecurity professionals require deep visibility into network traffic to troubleshoot issues, monitor performance, and detect malicious activities.

A network sniffer, also known as a packet analyzer, is a critical tool used to intercept, log, and analyze network traffic passing over a digital network. As data streams flow across the network, the sniffer captures each packet and decodes the packet's raw binary data, exposing the values of various protocol fields.

The project **"Basic Network Sniffer"** was developed during the CodeAlpha Cyber Security Internship to provide a hands-on, educational approach to understanding how network packets traverse the OSI model. Unlike commercial enterprise solutions that are often bloated and complex, this project focuses on a lightweight, modular, and extensible architecture built entirely in Python. It leverages the powerful Scapy library to interact with low-level network sockets, bypassing the standard operating system network stack to read raw frames directly from the network interface card (NIC).

> ⚠️ **Note on Ethics and Legality:** This tool is intended strictly for educational purposes and authorized network monitoring. Capturing packets on networks without explicit authorization is illegal and unethical.

# 2. OBJECTIVE

The primary objectives of this CodeAlpha internship project were as follows:

1. **Educational Mastery**: To gain a profound understanding of network protocols across the OSI model (Layer 2 to Layer 7) by manually parsing and extracting fields from raw binary packets.
2. **Cybersecurity Application**: To develop a practical cybersecurity tool capable of capturing live network traffic for analysis, debugging, and security auditing.
3. **Software Engineering**: To construct a production-quality, cross-platform Python application adhering to industry best practices, including modularity, strict type hinting, robust error handling, and design patterns.
4. **User Experience**: To design an intuitive, professional Command Line Interface (CLI) and an interactive terminal dashboard that presents complex network data in an easily readable format.
5. **Data Export**: To implement versatile data export mechanisms (CSV, JSON, PCAP) allowing for post-capture analysis in enterprise tools like Wireshark or Pandas.

# 3. PROBLEM STATEMENT

Network troubleshooting and security analysis often require inspecting the exact packets entering and leaving a system. While powerful tools like Wireshark and tcpdump exist, they present a steep learning curve for beginners and are often challenging to integrate directly into custom automated Python pipelines.

Furthermore, students and junior engineers often struggle to bridge the gap between theoretical networking concepts (e.g., the TCP 3-way handshake, DNS resolution) and practical implementation. There is a distinct lack of open-source, beginner-friendly sniffer implementations that are cleanly architected, thoroughly commented, and designed specifically for educational purposes without sacrificing performance or code quality.

Therefore, the problem was to design and develop a custom Python-based network sniffer that acts as a transparent, modular bridge between raw packet capture and high-level human-readable analysis, serving both as an educational reference and a functional utility for the CodeAlpha internship.

# 4. SOFTWARE & HARDWARE REQUIREMENTS

### Software Requirements
- **Operating System**: Windows 10/11, macOS, or a standard Linux distribution (e.g., Ubuntu).
- **Programming Language**: Python 3.11 or higher.
- **Packet Capture Driver (Windows)**: Npcap (with WinPcap API-compatible mode enabled).
- **Packet Capture Driver (Linux/macOS)**: libpcap (usually pre-installed or available via `apt install libpcap-dev`).

### Hardware Requirements
- **Processor**: Intel Core i3 or equivalent AMD processor (1.0 GHz or higher).
- **Memory (RAM)**: Minimum 2 GB (4 GB recommended for capturing high-volume traffic).
- **Storage**: 50 MB of free disk space.
- **Network**: An active Network Interface Card (NIC) (Ethernet or Wi-Fi).

# 5. TECHNOLOGIES USED

### Python 3.11+
Python was chosen as the primary programming language due to its rapid development capabilities, extensive standard library, and unparalleled ecosystem for cybersecurity and data manipulation. 

### Scapy
Scapy is a powerful interactive packet manipulation program and library. It is capable of forging or decoding packets of a wide number of protocols, sending them on the wire, catching them, matching requests and replies, and more. In this project, Scapy is used exclusively for its `sniff()` engine and low-level packet representations.

### Rich
Rich is a Python library for rich text and beautiful formatting in the terminal. The project utilizes Rich's `Live`, `Table`, `Panel`, and `Layout` components to build a flicker-free, scrolling terminal dashboard that updates synchronously with network traffic.

### Colorama
Colorama provides cross-platform support for ANSI escape character sequences, ensuring that the terminal output colors render correctly across Windows, macOS, and Linux command prompts.

### Npcap (Windows)
Npcap is the Nmap Project's packet sniffing library for Windows. It provides the low-level kernel drivers required for the Python application to intercept raw packets directly from the Windows network stack.

# 6. PROJECT ARCHITECTURE

The architecture of the Basic Network Sniffer is strictly modular, separating the capture engine from the display logic and protocol parsing. 

1. **CLI / Entry Point (`__main__.py` & `cli.py`)**: 
   Parses user arguments, checks OS privileges, and initiates the capture process.
   
2. **Core Engine (`core/capture.py`)**:
   Runs Scapy's `sniff()` function in a daemon thread. It uses the Observer design pattern to emit captured packets to registered callbacks, decoupling the network I/O from terminal rendering.

3. **Parser Pipeline (`parsers/*.py`)**:
   A Registry-based pipeline. When a raw packet arrives, it passes through a series of modular parsers (Ethernet, IP, TCP, UDP, DNS, ICMP, ARP). Each parser extracts specific fields into a unified dictionary.

4. **Display Layer (`display/live_view.py`)**:
   Consumes the parsed dictionary and renders it to the screen using the `Rich` library. It calculates instantaneous packet rates and protocol distributions.

5. **Export Layer (`export/*.py`)**:
   Converts the captured data buffers into persistent storage formats (PCAP for raw binary, JSON/CSV for parsed metadata).

# 7. IMPLEMENTATION & WORKING

The lifecycle of a single packet through the application is as follows:

1. **Startup & Configuration**: The user runs the application. The system determines the default active network interface and applies any BPF (Berkeley Packet Filter) rules (e.g., `--tcp`). Privilege checks ensure the app has root/admin access required to open raw sockets.
2. **Background Capture**: The `PacketCapture` class spins up a background thread. Scapy binds to the NIC and listens promiscuously.
3. **Interception**: A packet arrives on the NIC. Scapy intercepts the raw bytes and converts them into an object.
4. **Callback Trigger**: Scapy triggers the custom `_packet_handler` callback.
5. **Parsing**: The packet is passed to the parser registry. The Ethernet parser extracts MAC addresses; the IP parser extracts source/destination IPs; the TCP parser extracts ports and flags. The result is a unified dictionary.
6. **Statistics Update**: Global counters for bytes, packets, and top talkers are atomically updated.
7. **UI Render**: The main thread, running the Rich `Live` display, reads the latest packets from the thread-safe buffer and redraws the terminal table and statistics panel.
8. **Shutdown & Export**: Upon receiving a `Ctrl+C` interrupt, the capture thread is gracefully terminated. If auto-save flags are set, the buffer is dumped to the local disk as PCAP, CSV, and JSON files.

# 8. CODE EXPLANATION

### Capture Engine (`capture.py`)
The core utilizes Python's `threading` module to prevent blocking the UI.
```python
self._capture_thread = threading.Thread(
    target=self._capture_loop,
    daemon=True,
)
self._capture_thread.start()
```

### Protocol Parsers (`ip.py` & `tcp.py`)
Parsers inherit from an abstract base class ensuring a uniform `parse()` interface.
```python
class IPParser(BaseParser):
    def parse(self, packet: Any) -> dict[str, Any]:
        ip_layer = packet["IP"]
        return {
            "src_ip": ip_layer.src,
            "dst_ip": ip_layer.dst,
            "ttl": ip_layer.ttl,
            "protocol": ip_layer.proto,
        }
```

### Data Export (`pcap_export.py`)
Raw Scapy packets are retained alongside parsed dictionaries specifically so they can be written back to standard PCAP format for Wireshark integration.
```python
from scapy.utils import wrpcap
wrpcap("capture.pcap", raw_packets)
```

# 9. OUTPUT & SCREENSHOTS

When the application is run, it displays a dynamic dashboard in the terminal featuring a header summary, live packet stream, and post-capture statistics.

*(Insert your screenshots below replacing the placeholder text)*

### Live Terminal Dashboard
![Insert Live Dashboard Screenshot Here](docs/images/dashboard_placeholder.png)
*Figure 1: The real-time terminal dashboard displaying captured packets and network statistics.*

### Interactive CLI Menu
![Insert Interactive Menu Screenshot Here](docs/images/menu_placeholder.png)
*Figure 2: The beginner-friendly interactive setup wizard.*

### Post-Capture Statistics
![Insert Post-Capture Stats Screenshot Here](docs/images/stats_placeholder.png)
*Figure 3: Summary statistics including top talkers and protocol distribution after capture completion.*

# 10. ADVANTAGES

1. **Lightweight & Fast**: Unlike Java-based or Electron-based GUI sniffers, this terminal application uses minimal RAM and CPU overhead.
2. **Educational Value**: The modular architecture makes it an excellent learning tool for students studying network engineering.
3. **Automated Exports**: The ability to auto-save to JSON/CSV allows for easy integration into data science pipelines for traffic analysis.
4. **Kernel-Level Filtering**: Compiling BPF filters pushes the filtering down to the OS kernel, ensuring high-throughput captures don't overwhelm the Python interpreter.
5. **No Dependencies on GUI Libraries**: Because it runs entirely in the terminal, it is ideal for monitoring headless Linux servers over SSH.

# 11. LIMITATIONS

1. **Decryption**: The sniffer cannot decrypt HTTPS/TLS traffic. Data payloads for secure connections remain encrypted binary blobs.
2. **Throughput at Gigabit Speeds**: While fast, Python is an interpreted language. On heavily saturated Gigabit networks, pure C/C++ sniffers will drop fewer packets than Python/Scapy.
3. **Protocol Support**: Currently parses 8 core protocols. Niche or proprietary industrial protocols will default to showing raw hex dumps.

# 12. FUTURE SCOPE

The architecture of the Basic Network Sniffer was explicitly designed to be extensible. Future iterations of this project could include:
- **Flow Reconstruction**: Reassembling fragmented packets and full TCP streams to extract complete HTTP requests or file downloads from the wire.
- **Anomaly Detection**: Integrating a machine learning model via scikit-learn to flag unusual traffic patterns indicative of malware or DDoS attacks.
- **Graphical User Interface**: Wrapping the Python backend in a web-based frontend for users who prefer mouse-driven applications over CLI tools.
- **Decryption Keys**: Implementing support for the `SSLKEYLOGFILE` environment variable to decrypt captured TLS sessions using pre-master secrets.

# 13. CONCLUSION

The CodeAlpha Cyber Security Internship provided profound insights into the mechanics of computer networking, operating system socket APIs, and robust software engineering practices. The "Basic Network Sniffer" successfully meets all its initial objectives, serving as both a functional cybersecurity utility and a comprehensive educational resource.

By bridging the gap between raw binary network frames and human-readable terminal dashboards, the project demystifies the OSI model. The rigorous implementation of design patterns and clean architecture ensures that the codebase will remain maintainable and extensible for future iterations. This internship experience has significantly fortified my technical capabilities in Python development, network security, and systems architecture, preparing me for complex challenges in the cybersecurity domain.

# 14. REFERENCES

1. CodeAlpha Internship Program Guidelines.
2. Scapy Documentation. *Scapy: Interactive packet manipulation program*. Available at: https://scapy.net/
3. Python Software Foundation. *Python 3.11 Documentation*. Available at: https://docs.python.org/3.11/
4. Rich Library. *Rich: Python library for beautiful formatting in the terminal*. Available at: https://rich.readthedocs.io/
5. Nmap Project. *Npcap: Windows Packet Capture Library*. Available at: https://npcap.com/
6. Wireshark Foundation. *PCAP File Format Specification*. Available at: https://wiki.wireshark.org/Development/LibpcapFileFormat
