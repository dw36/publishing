#!/usr/bin/env python3
from scapy.all import *
def spoof_pkt(pkt):
	pkt.show()
	ip = IP()
	# To get info for each layer from the sniffed packet you can use pkt[layer_name], e.g. pkt[IP] give you access to the IP layer and pkt[TCP] give you access to the TCP layer 
	ip.src =   
	ip.dst =    
	# create a new TCP object
	tcp = TCP()
	tcp.sport = 
	tcp.dport = 
	tcp.flags=''
	tcp.seq = 
	newpkt = ip/tcp
	send(newpkt)
	ls(newpkt)
pkt = sniff(iface='', filter='', prn=spoof_pkt)
