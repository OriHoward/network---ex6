from scapy.all import *

def print_pkt(pkt):
    pkt.show()

list_of_sniffing = ['br-3d50edc4535c','enp0s3']

pkt = sniff(iface = list_of_sniffing,filter = 'tcp and src host 10.0.2.15 and dst port 23',prn = print_pkt)
