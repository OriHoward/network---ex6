from scapy.all import *
#todo check if we need snaps of this
ip_obj = IP()
ip_obj.src = '10.10.15.12'
ip_obj.dst = '10.9.0.5'
icmp_obj = ICMP()
pkt_obj = ip_obj/icmp_obj
send(pkt_obj)
ls(pkt_obj)
