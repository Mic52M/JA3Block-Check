# JA3Block-Check ![Python](https://img.shields.io/badge/language-Python-blue?style=flat-square) ![Status](https://img.shields.io/badge/status-active-brightgreen?style=flat-square) 
> **Realtime & offline TLS fingerprint analysis and blacklist blocking **

---

## Overview

**JA3Block-Check** is a powerful Python tool that captures and analyzes TLS packets in real time and from pcap files, focusing on fingerprinting _Client Hello_ and _Server Hello_ messages to detect threats and security anomalies in encrypted traffic.

---

##  Features
-  **Real-time packet capture** and live analysis
-  **Offline support**: analyze pcap files
-  **Customizable output**: stdout or file, JSON format for easy integration
-  **Customizable JA3 blacklist** ([sslbl JA3 fingerprints](https://sslbl.abuse.ch/ja3-fingerprints/))
-  **Block malicious connections** via iptables
-  Compatibility: Python 3.x, Scapy, Colorama

---

##  Installation

git clone https://github.com/Mic52M/JA3Block-Check.git
cd JA3Block-Check
pip install -r requirements.txt


---

##  Usage

### **Online Mode**
python JA3Script.py -i Any --json --savepcap -pf output

text

- **-i**: network interface ("Any" for all)
- **--json**: JSON output
- **--savepcap**: save raw packets
- **-pf**: output pcap file prefix

### **Offline Mode**
python JA3Script.py -f input.pcap --json --savepcap -pf output


- **-f**: path to the pcap file

### **Advanced Options**
- `-jtype`: "ja3", "ja3s", "all" _(default: all)_
- `--ja3blacklist`: path to JA3 blacklist file
- `--IPblacklist`: path to IP blacklist file

### **Examples**
Live scan, JSON output, save pcap files
python JA3Script.py -i Any --json --savepcap -pf results

Analyze a previously captured pcap
python JA3Script.py -f traffic.pcap


---

## 📂 Project Structure

- `JA3Script.py`: main script, CLI parser, core logic
- `requirements.txt`: dependencies (Scapy, Colorama, etc.)
- `README.md`: documentation

---

##  Tags
`#TLS #fingerprinting #JA3 #network-security #pcap #python #Infosec #iptables #cybersecurity #real-time #offline`

---

##  Badges

- ![Build](https://img.shields.io/badge/build-passing-brightgreen?style=flat-square)
- ![Contributions](https://img.shields.io/badge/contributions-welcome-blue?style=flat-square)
- ![License](https://img.shields.io/github/license/Mic52M/JA3Block-Check?style=flat-square)
- ![Last-Commit](https://img.shields.io/github/last-commit/Mic52M/JA3Block-Check?style=flat-square)

---

##  Resources

- [JA3 Fingerprints (sslbl.abuse.ch)](https://sslbl.abuse.ch/ja3-fingerprints/)
- [Scapy documentation](https://scapy.readthedocs.io/en/latest/)
- [Colorama docs](https://pypi.org/project/colorama/)

---

##  Author

**Mic52M**  
> Cybersecurity Researcher.

---

## ⚖️ License

MIT License - see [LICENSE](LICENSE) for details.
