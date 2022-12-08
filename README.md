sudo iptables -L -n -v

sudo iptables -F OUTPUT
sudo iptables -F INPUT

sudo iptables -A INPUT -j NFQUEUE --queue-num 1
sudo iptables -A OUTPUT -j NFQUEUE --queue-num 1