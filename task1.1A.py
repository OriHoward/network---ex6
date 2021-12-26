from scapy.all import *


def print_pkt(pkt):
    pkt.show()



list_of_sniffing = ['br-3d50edc4535c','enp0s3']
pkt = sniff(iface = list_of_sniffing,filter = 'icmp',prn = print_pkt)



