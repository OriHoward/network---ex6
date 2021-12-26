from logging import NOTSET
from re import VERBOSE
from scapy.all import *

ip_obj = IP()
ip_obj.dst = '10.9.0.5'
icmp_obj = ICMP()


# We use the function sr1() which is a variant that only returns one packet that answered the packet

recieved = False
ttl_count = 1
while not recieved:
    ip_obj.ttl = ttl_count
    # sending the packet:
    ans = sr1(ip_obj/icmp_obj,verbose = 0,timeout = 5)

    if ans == None:
        print(f"{ttl_count} request timed out")
        ttl_count += 1
        continue
    
    if ans.src == ip_obj.dst:
        print(f"We arrived to our destination in {ttl_count} hops")
        recieved = True

    ttl_count +=1
    