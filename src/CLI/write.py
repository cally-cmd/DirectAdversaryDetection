import pyshark
from scapy.all import *

capture = pyshark.LiveCapture(interface='wlp2s0', use_json=True, include_raw=True)

def write(pkt):
    wrpcap('/home/cally/Desktop/intrusion_detection/StaticData/test.pcap', pkt.get_raw_packet(), append=True)

capture.apply_on_packets(write, timeout=100)