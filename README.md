# PacketTrace (Tshark Lab)

## Overview
This repository contains a hands-on lab that simulates an end-to-end webshell attack and demonstrates packet-level forensic analysis using **tshark** (the command-line interface to Wireshark).  
The simulated attack covers the full kill chain: **Reconnaissance (port scan) → Exploitation (webshell upload via HTTP POST) → Command & Control (DNS beaconing)**.

> **Educational use only.** The dataset and scripts are synthetic and meant for learning. Do not use these artifacts on production or public networks.

---

## Repository structure
- `generate_pcap.py` — Scapy script used to generate the simulated PCAP (`capture.pcapng`)  
- `analysis_commands.txt` — tshark commands used during analysis  
- `results.txt` — sample outputs / findings extracted from the PCAP  
- `detection_rules/` — example IDS / Zeek / YARA rules (if present)  
- `README.md` — this file

---

## Quick summary of findings
- **Reconnaissance:** Attacker IP scanned the victim on ports `21, 22, 80, 443`.  
- **Exploitation:** HTTP `POST /shell.php` observed; TCP stream contains PHP webshell payload.  
- **C2 / Beaconing:** DNS queries for `malicious.example.com` observed and resolved to `198.51.100.23`; victim later sent UDP callbacks to that IP.

---

## How to reproduce (Kali/Debian)
1. Install dependencies:
```bash
sudo apt update
sudo apt install -y python3-scapy tshark suricata zeek git

