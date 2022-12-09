## Requisitos:
 - [NetfilterQueue](https://pypi.org/project/NetfilterQueue/)
 - [Scapy](https://scapy.net/)

## Execução:
 1. Execute esse comando para redireciona os pacotes para o firewall:

	```sudo iptables -A INPUT -j NFQUEUE --queue-num 1```

	```sudo iptables -A OUTPUT -j NFQUEUE --queue-num 1```