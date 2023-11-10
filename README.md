# JA3Block-Check

[![GitHub license](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/tuononen/ja3er/blob/main/LICENSE)

## Overview

The TLS Fingerprinting Tool is designed for capturing and analyzing TLS handshake packets in real-time or from a pcap file. It focuses on extracting and fingerprinting Client Hello and Server Hello messages to identify potential security threats or anomalies in encrypted network traffic.

## Features

- Real-time packet capturing and analysis
- Support for offline mode (from pcap files)
- Flexible output options (stdout or file)
- JSON format output for easy integration with other tools
- Customizable blacklist for JA3 fingerprints (https://sslbl.abuse.ch/ja3-fingerprints/)
- Blocking malicious connections using iptables

## Installation

1. Clone the repository:
   git clone https://github.com/tuononen/ja3er.git

2. Install required dependencies:
   pip install -r requirements.txt

## Usage
Online Mode:
python ja3er.py -i <interface> -bpf <BPF_filter> --json --savepcap -pf <pcap_filename>

Offline Mode:
python ja3er.py -f <pcap_file> --json --savepcap -pf <pcap_filename>

-i: Specify the network interface for online mode (use "Any" for all interfaces).
-f: Provide the path to the pcap file for offline mode.
--json: Output results in JSON format.
--savepcap: Save the raw pcap file.
-pf: Specify the prefix for saved pcap files.

## Optional Arguments:

-jtype: Choose "ja3", "ja3s", or "all" (default is "all").
--ja3blacklist: Specify the path to a file containing JA3 blacklist entries.
--IPblacklist: Specify the path to a file containing IP blacklist entries.

## Examples:

1. Capture packets on all interfaces, save as JSON, and save the raw pcap:
    python ja3er.py -i Any --json --savepcap -pf output
   
2. Analyze a pcap file, print results to stdout:
   python ja3er.py -f input.pcap











