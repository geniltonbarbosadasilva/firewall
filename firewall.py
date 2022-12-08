from netfilterqueue import NetfilterQueue
from scapy.all import *
import json

def load_conf():
	with open("rules.json","r") as confFile:
		return json.load(confFile)

try:
	rules = load_conf()
	BlockedSourceIPs = rules["BlockedSourceIPs"]
	BlockedDestinationIPs = rules["BlockedDestinationIPs"]
	BlockedSourcePorts = rules["BlockedSourcePorts"]
	BlockedDestinationPorts = rules["BlockedDestinationPorts"]


except Exception:
	print("Arquivo de configuração invalido")
	BlockedSourceIPs = []
	BlockedDestinationIPs = []
	BlockedSourcePorts = []
	BlockedDestinationPorts = []

print("BlockedSourceIPs: ", BlockedSourceIPs)
print("BlockedDestinationIPs: ", BlockedDestinationIPs)
print("BlockedSourcePorts: ", BlockedSourcePorts)
print("BlockedDestinationPorts: ", BlockedDestinationPorts)

def firewall(pkt):
	pkt_info = IP(pkt.get_payload())

	if(pkt_info.src in BlockedSourceIPs):
		print("Source IP: ", pkt_info.src, "foi bloqueado pelo firewall.")
		pkt.drop()
		return

	if(pkt_info.dst in BlockedDestinationIPs):
		print("Destination IP", pkt_info.dst, "foi bloqueado pelo firewall.")
		pkt.drop()
		return

	if(pkt_info.haslayer(TCP)):
		tcp_pkt = pkt_info.getlayer(TCP)

		if(tcp_pkt.sport in BlockedSourcePorts):
			print("Source Port: ", tcp_pkt.sport, "porta bloqueada pelo firewall.")
			pkt.drop()
			return
		
		if(tcp_pkt.dport in BlockedDestinationPorts):
			print("Destination Port: ", tcp_pkt.dport, "porta bloqueada pelo firewall.")
			pkt.drop()
			return

	if(pkt_info.haslayer(UDP)):
		udp_pkt = pkt_info.getlayer(UDP)

		if(udp_pkt.sport in BlockedSourcePorts):
			print("Source Port: ", udp_pkt.sport, "porta bloqueada pelo firewall.")
			pkt.drop()
			return
		
		if(udp_pkt.dport in BlockedDestinationPorts):
			print("Destination Port: ", udp_pkt.dport, "porta bloqueada pelo firewall.")
			pkt.drop()
			return

	# print("Accept= Source: ", pkt_info.src, "Destination", pkt_info.dst)
	pkt.accept()
	return

nfqueue = NetfilterQueue()
nfqueue.bind(1, firewall)

try:
	nfqueue.run()
except KeyboardInterrupt:
	print('KeyboardInterrupt')
except Exception as e:
	print(e)

nfqueue.unbind()