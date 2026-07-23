# Network Protocols Reference

A beginner-friendly guide to the protocols parsed by this sniffer.

---

## The OSI Model (Simplified)

| Layer | Name | Protocols | What It Does |
|---|---|---|---|
| **7** | Application | HTTP, DNS | User-facing services |
| **4** | Transport | TCP, UDP | Process-to-process delivery |
| **3** | Network | IP, ICMP, ARP | Host-to-host routing |
| **2** | Data Link | Ethernet | Local network framing |
| **1** | Physical | — | Electrical signals on the wire |

---

## Ethernet (Layer 2)

**Purpose**: Delivers frames between devices on the SAME local network.

**Key Fields**:
- **Source MAC**: Hardware address of the sender (e.g., `aa:bb:cc:dd:ee:ff`)
- **Destination MAC**: Hardware address of the receiver
- **EtherType**: Identifies the Layer 3 protocol (0x0800 = IPv4, 0x0806 = ARP)

**Fun Fact**: MAC addresses are globally unique. The first 3 bytes identify the manufacturer (OUI).

---

## IP — Internet Protocol (Layer 3)

**Purpose**: Routes packets across networks (the internet).

### IPv4
- **Address format**: `192.168.1.1` (32 bits, ~4.3 billion addresses)
- **TTL** (Time To Live): Decremented at each router. Prevents infinite loops.
- **Protocol field**: Identifies Layer 4 (6 = TCP, 17 = UDP, 1 = ICMP)

### IPv6
- **Address format**: `2001:db8::1` (128 bits, practically unlimited)
- **Hop Limit**: Same as TTL in IPv4, just renamed

---

## TCP — Transmission Control Protocol (Layer 4)

**Purpose**: Reliable, ordered, connection-oriented data delivery.

**Key Concepts**:
- **Three-way handshake**: SYN → SYN-ACK → ACK
- **Sequence numbers**: Track byte order in the stream
- **Window size**: Flow control — how much data the receiver can buffer
- **Flags**: SYN (connect), ACK (acknowledge), FIN (close), RST (abort), PSH (push)

**Used by**: HTTP, HTTPS, SSH, FTP, SMTP, databases

---

## UDP — User Datagram Protocol (Layer 4)

**Purpose**: Fast, connectionless, unreliable data delivery.

**Key Concepts**:
- **No handshake** — just send the datagram
- **No guaranteed delivery** — packets may be lost or arrive out of order
- **Minimal overhead** — only 8 bytes of header (vs TCP's 20+)

**Used by**: DNS, DHCP, NTP, video streaming, gaming, VoIP

**Why choose UDP over TCP?** When speed matters more than reliability. A dropped video frame is better than a delayed one.

---

## DNS — Domain Name System (Layer 7)

**Purpose**: Translates domain names to IP addresses.

**How it works**:
1. Your browser wants to visit `www.google.com`
2. Your OS sends a DNS query to your configured DNS server (often `8.8.8.8`)
3. The DNS server responds with the IP address: `142.250.80.46`
4. Your browser connects to that IP address

**Query Types**:
| Type | Purpose | Example |
|---|---|---|
| A | IPv4 address | `google.com → 142.250.80.46` |
| AAAA | IPv6 address | `google.com → 2607:f8b0:4004::200e` |
| CNAME | Alias | `www.example.com → example.com` |
| MX | Mail server | `gmail.com → gmail-smtp-in.l.google.com` |
| TXT | Text record | SPF, DKIM email authentication |

---

## HTTP — HyperText Transfer Protocol (Layer 7)

**Purpose**: The protocol that powers the web.

**Request** (client → server):
```
GET /index.html HTTP/1.1
Host: www.example.com
```

**Response** (server → client):
```
HTTP/1.1 200 OK
Content-Type: text/html
```

**Common Status Codes**:
| Code | Meaning |
|---|---|
| 200 | OK — request succeeded |
| 301 | Moved Permanently — URL changed |
| 404 | Not Found — page doesn't exist |
| 500 | Internal Server Error |

**Note**: Most web traffic today uses HTTPS (HTTP over TLS). This sniffer can only parse plaintext HTTP.

---

## ARP — Address Resolution Protocol (Layer 2/3)

**Purpose**: Maps IP addresses to MAC addresses on a local network.

**How it works**:
1. Device A wants to send to `192.168.1.1` on the LAN
2. A broadcasts: "Who has 192.168.1.1? Tell me (192.168.1.100)"
3. The router responds: "192.168.1.1 is at aa:bb:cc:dd:ee:ff"
4. A caches this mapping and sends the Ethernet frame

**Security Note**: ARP has no authentication. ARP spoofing attacks send fake replies to redirect traffic (Man-in-the-Middle).

---

## ICMP — Internet Control Message Protocol (Layer 3)

**Purpose**: Network diagnostics and error reporting.

**Common Messages**:
| Type | Name | Used By |
|---|---|---|
| 0 | Echo Reply | `ping` response |
| 3 | Destination Unreachable | Router can't deliver |
| 8 | Echo Request | `ping` command |
| 11 | Time Exceeded | `traceroute` |

**Ping** works by sending ICMP Echo Requests and measuring response time:
```
ping 8.8.8.8
Reply from 8.8.8.8: time=12ms TTL=117
```

**Traceroute** sends packets with increasing TTL values. Each router that decrements TTL to 0 sends back a "Time Exceeded" ICMP message, revealing its IP address.
