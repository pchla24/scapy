#!/usr/local/bin/python
from scapy.all import *

src = 192.168.0.227
dst = 192.168.0.87
sport = random.randint(1024,65535)
dport = 8000

ip=IP(src=src,dst=dst)
SYN=TCP(sport=sport,dport=dport,flags='S',seq=1000)
SYNACK=sr1(ip/SYN)

ACK=TCP(sport=sport, dport=dport, flags='A', seq=SYNACK.ack, ack=SYNACK.seq + 1)
send(ip/ACK)

pkts = rdpcap('pcap_tcp.pcap')
for p in pkts:
    p[TCP].seq=SYNACK.ack
    p[TCP].ack=SYNACK.seq + 1
    sendp(p)
    