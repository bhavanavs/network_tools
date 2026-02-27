#!/usr/bin/env python3
from netfilterqueue import NetfilterQueue
from scapy.all import *

class pkt_modifier():

    def add_layer(self, orig_pkt, location, new_layer):
        original_payload = orig_pkt[location].payload.copy()
        orig_pkt[location].remove_payload()
        new_pkt = orig_pkt / new_layer() / original_payload
        return new_pkt

    def remove_layer(self, orig_pkt, location):
        new_payload = orig_pkt[location].payload.copy()
        prev_layer = orig_pkt[location].underlayer.name
        orig_pkt[prev_layer].remove_payload()
        new_pkt = orig_pkt / new_payload
        return new_pkt

