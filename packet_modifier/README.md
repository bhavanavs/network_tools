# network_tools
Scapy script to edit the packets 

1. Install required packages. Run setup.sh. 
2. Script pkt_modifier.py has two basic functionality to add header and remove header
3. Script packet_interceptor.py has basic example of intercepting the udp packets sent by application via netfilter queue and add a header after the udp layer
	1. Check https://pypi.org/project/NetfilterQueue/ for netfilter commands and options
