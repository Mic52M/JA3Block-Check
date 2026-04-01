# JA3Block-Check

![Python](https://img.shields.io/badge/language-Python-blue?style=flat-square)
![Build](https://img.shields.io/badge/build-passing-brightgreen?style=flat-square)
![Status](https://img.shields.io/badge/status-active-brightgreen?style=flat-square)
![Contributions](https://img.shields.io/badge/contributions-welcome-blue?style=flat-square)
![Last Commit](https://img.shields.io/github/last-commit/Mic52M/JA3Block-Check?style=flat-square)

**Realtime and offline TLS fingerprint analysis with automated blacklist-based connection blocking.**

JA3Block-Check is a Python tool for capturing and analyzing TLS handshake packets in real time or from existing pcap files. It extracts JA3 and JA3S fingerprints from Client Hello and Server Hello messages, matches them against customizable blacklists, and automatically blocks malicious source IPs via `iptables`.

---

## How It Works

TLS fingerprinting works by hashing specific fields of the TLS Client Hello or Server Hello message into a short MD5 string — the **JA3** (client) or **JA3S** (server) fingerprint. These fingerprints uniquely identify the TLS client or server configuration, regardless of certificate or payload content.

JA3Block-Check intercepts TLS handshake packets using a BPF filter, parses the handshake layers with Scapy, and computes both the raw fingerprint string and its MD5 hash. If the hash matches an entry in the loaded JA3 blacklist (e.g., from [sslbl.abuse.ch](https://sslbl.abuse.ch/ja3-fingerprints/)), the source IP is immediately blocked via an `iptables` DROP rule and added to a persistent IP blacklist.

GREASE values (RFC 8701) are automatically filtered when computing the `_no_grease` variant of each fingerprint.

---

## Features

- Real-time packet capture across one or all network interfaces
- Offline analysis from `.pcap` files
- JA3 (Client Hello) and JA3S (Server Hello) fingerprint extraction
- GREASE-aware: computes both raw and GREASE-filtered MD5 hashes
- Automatic connection blocking via `iptables` on blacklist match
- Persistent IP blacklist updated on each match
- JSON output for pipeline integration or SIEM ingestion
- Optional pcap saving for forensic purposes
- Customizable BPF filter for advanced capture control

---

## Requirements

- Python 3.x
- Scapy
- Colorama
- Root/sudo privileges (required for raw socket capture and `iptables`)

---

## Installation

```bash
git clone https://github.com/Mic52M/JA3Block-Check.git
cd JA3Block-Check
pip install -r requirements.txt
```

---

## Usage

### Online Mode (live capture)

```bash
sudo python JA3Script.py -i eth0
```

Capture on all interfaces with JSON output and pcap saving:

```bash
sudo python JA3Script.py -i Any --json --savepcap -pf output
```

### Offline Mode (pcap analysis)

```bash
python JA3Script.py -f traffic.pcap
```

With JSON output:

```bash
python JA3Script.py -f traffic.pcap --json -of results.json
```

---

## CLI Reference

| Argument            | Description                                                                 | Default         |
|---------------------|-----------------------------------------------------------------------------|-----------------|
| `-i <iface>`        | Network interface to sniff on. Use `Any` for all interfaces.               | `Any`           |
| `-f <file>`         | Path to a pcap file (offline mode). Mutually exclusive with `-i`.          | —               |
| `-of <file>`        | Output destination. Path to file or `stdout`.                              | `stdout`        |
| `-jtype`            | Fingerprint type to extract: `ja3`, `ja3s`, or `all`.                     | `all`           |
| `--json`            | Print results as JSON.                                                      | disabled        |
| `--savepcap`        | Save captured packets to a `.pcap` file.                                   | disabled        |
| `-pf <prefix>`      | Filename prefix for saved pcap.                                             | timestamp       |
| `--ja3blacklist`    | Path to a JA3 MD5 blacklist (one hash per line).                           | —               |
| `--IPblacklist`     | Path to an IP blacklist for persistent blocking.                           | —               |
| `-bpf <filter>`     | Custom BPF filter string. Do not modify unless necessary.                  | TLS Hello filter|

---

## Output Format

### Plain text (default)

[+] Hello from Client
[-] type: TLSv1.2
[-] src ip: 192.168.1.10
[-] src port: 54312
[-] dst ip: 93.184.216.34 (example.com)
[-] dst port: 443
[-] ja3: 769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0
[-] ja3_no_grease: 769,47-53-5-10-...
[-] md5: abc123def456...
[-] md5_no_grease: 789xyz...
[-] Match: Yes
[-] Second Match: No


### JSON (`--json`)

```json
{
    "from": "Client",
    "type": "TLSv1.2",
    "src": {
        "ip": "192.168.1.10",
        "port": 54312
    },
    "dst": {
        "ip": "93.184.216.34",
        "port": 443,
        "server_name": "example.com"
    },
    "ja3": {
        "str": "769,47-53-5-10-...",
        "md5": "abc123def456...",
        "str_no_grease": "769,47-53-5-10-...",
        "md5_no_grease": "789xyz..."
    },
    "is_match": false,
    "is_second_match": false
}
```

---

## Blacklist Integration

JA3Block-Check supports blacklists in plain-text format with one entry per line.

**JA3 blacklist** (MD5 hashes of known malicious fingerprints):
e7d705a3286e19ea42f587b6e7359d52
6734f37431670b3ab4292b8f60f29984


A continuously updated list of malicious JA3 fingerprints is maintained by the Abuse.ch SSL Blacklist:
[https://sslbl.abuse.ch/ja3-fingerprints/](https://sslbl.abuse.ch/ja3-fingerprints/)

**IP blacklist** (IPv4/IPv6 source addresses to block):
192.168.1.100
10.0.0.55


When a JA3 match is detected, the source IP is automatically appended to the IP blacklist file and an `iptables` DROP rule is inserted:

```bash
iptables -A INPUT -s <src_ip> -j DROP
```

---

## Limitations

- `iptables` blocking requires root privileges and is Linux-only.
- TLS sessions that do not begin with a standard Client/Server Hello (e.g., resumed sessions, 0-RTT) are not fingerprinted.
- Encrypted SNI (ESNI/ECH) will prevent server name extraction from the Client Hello extension.

---

## References

- [JA3 – A Method for Profiling SSL/TLS Client Hello Messages](https://github.com/salesforce/ja3)
- [Abuse.ch SSLBL JA3 Fingerprint Feed](https://sslbl.abuse.ch/ja3-fingerprints/)
- [Scapy Documentation](https://scapy.readthedocs.io/en/latest/)
- [RFC 8701 – GREASE for TLS Extensions](https://datatracker.ietf.org/doc/html/rfc8701)

---

## Author

**Michele Mastroberti (Mic52M)**  
Cybersecurity Researcher

---

## License

MIT License. See [LICENSE](LICENSE) for details.
