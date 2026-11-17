# PacketTrace

A hands-on packet forensics lab that simulates an end-to-end webshell attack and walks through the analysis with **tshark**, the command-line interface to Wireshark.

The simulated attack follows the full kill chain: **Reconnaissance (port scan) → Exploitation (webshell upload via HTTP POST) → Command & Control (DNS beaconing)**.

> **Educational use only.** The dataset and scripts are synthetic and intended for learning. Do not use these artifacts on production or public networks.

---

## Repository structure

- `generate_pcap.py` — Scapy script that generates the simulated capture (`capture.pcapng`)
- `analysis_commands.txt` — tshark commands used during the investigation
- `results.txt` — sample output and findings extracted from the capture
- `evidence/` — screenshots captured during analysis
- `detection_rules/` — example IDS / Zeek / YARA rules (if present)
- `README.md` — this file

---

## Quick summary of findings

- **Reconnaissance:** The attacker scanned the victim on ports `21, 22, 80, 443`.
- **Exploitation:** An HTTP `POST /shell.php` request was observed; the TCP stream contains a PHP webshell payload.
- **C2 / Beaconing:** DNS queries for `malicious.example.com` were observed and resolved to `198.51.100.23`; the victim later sent UDP callbacks to that address.

---

## How to reproduce (Kali/Debian)

1. Install dependencies:

```bash
sudo apt update
sudo apt install -y python3-scapy tshark suricata zeek git
```

2. Generate the synthetic capture:

```bash
python3 generate_pcap.py
```

3. Follow the tshark workflow in `analysis_commands.txt`, or open `capture.pcapng` in Wireshark to explore interactively.

## Skills demonstrated

- Traffic capture generation with Scapy
- Protocol-level filtering and stream reconstruction with tshark
- Webshell and DNS-beaconing detection
- Mapping observed activity to the cyber kill chain
