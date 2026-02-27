#!/usr/bin/env python3
from netfilterqueue import NetfilterQueue
from scapy.all import *
from pkt_modifier import pkt_modifier
import argparse
import os

# Define the custom header (if needed)
class CustomHeader(Packet):
    name = "CustomHeader"
    fields_desc = [ShortField("type", 0x1234), StrFixedLenField("data", "custom", 6)]


class packet_interceptor(pkt_modifier):

    # Callback function to process and send packet
    def modify_and_send(self, packet):
        print("***", type(packet))
        #packet received from netfilter queue is of type netfilterqueue.Packet. payload starts with IP header
        pkt = IP(packet.get_payload())
        if IP in pkt and UDP in pkt:
            new_pkt = self.add_layer(pkt, UDP, CustomHeader)
            print("==>", new_pkt)
            print("Modified packet sent")
            #adding new layers. Have to update the len and checksum fields
            del new_pkt[IP].len
            del new_pkt[IP].chksum
            del new_pkt[UDP].len
            del new_pkt[UDP].chksum
            packet.set_payload(bytes(new_pkt))
            #release the packet to kernel. Other verdict possible are drop and repeat
            packet.accept()


# Sniff on a specific interface for outgoing traffic
#sniff(iface="enp6s0f1", filter="udp dst port 30013", prn=modify_and_send, count=1)

def main():
    # Bind to the queue number specified in the iptables rule (queue-num 1)
    parser = argparse.ArgumentParser()
    parser.add_argument("--dest_port", required=True, help="Destination port to filter packets for netfilter queue", type=int)
    parser.add_argument("--protocol", required=True, help="Transport layer protocol to filter packets for netfilter queue", type=str)
    args = parser.parse_args()
    cmd = 'iptables -A OUTPUT -p %s --dport %d -j NFQUEUE --queue-num 1' %(args.protocol, args.dest_port)
    os.system(cmd)
    nfqueue = NetfilterQueue()
    modifier = packet_interceptor()
    try:
        print("Binding to queue 1. Make sure iptables rule is set.")
        nfqueue.bind(1, modifier.modify_and_send)
        print("Starting packet interception loop...")
        nfqueue.run()
    except KeyboardInterrupt:
        print("Stopping...")
    finally:
        # Unbind the queue and delete the ip table rules on exit
        nfqueue.unbind()
        cmd = 'iptables -D OUTPUT -p %s --dport %d -j NFQUEUE --queue-num 1' %(args.protocol, args.dest_port)
        os.system(cmd)

if __name__ == '__main__':
    main()
