#!/usr/bin

import pyshark
import socket
import os
import time
from scapy.all import *
from threading import Thread


s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8", 80))
my_ip = s.getsockname()[0]
s.close()

capture = pyshark.LiveCapture(interface='wlp2s0') #capture filter
#capture = pyshark.FileCapture('/home/cally/Desktop/intrusion_detection/StaticData/AU_RandomTor_Test_1_162.248.11.66.pcap')

captured_syn_packet = {}

def print_callback(pkt):
    #check if the pkt's ip address is new
    #store the current ip address and time stamp for calulating VPN rtt
        #find next corresponding inbound time stamp
    #initiate SSH ping
    #store the outbound SSH ping time stamp
        #find next corresponding inbound time stamp
    try:
        # pkt.ip.src
        # pkt.ip.dst
        # pkt.tcp.seq
        # pkt.tcp.ack
        # pkt.tcp.len
        # pkt.tcp.flags
        # pkt.sniff_time
        # pkt.tcp.analysis_ack_rtt

         #print("Flags:",pkt.tcp.flags,"IP SRC:",pkt.ip.src,"IP DST:",pkt.ip.dst)
        
         #CAPTURE SYN PACKET
        if pkt.ip.src == my_ip and pkt['tcp'].flags == '0x00000002':
            captured_syn_packet[pkt.ip.dst] = {'Status' : 'N'}
            print('Sniffed SYN Packet')
            print(pkt.sniff_time)

        #CAPTURE SYN ACK PACKET
        if pkt.ip.src != my_ip and pkt.ip.dst == my_ip and pkt.ip.src in captured_syn_packet and pkt['tcp'].flags == '0x00000012':
            captured_syn_packet[pkt.ip.src]['SRTT'] = pkt.sniff_time
            print('Sniffed SYN ACK')

        #CAPTURE ACK PACKET
        if pkt.ip.src == my_ip and pkt.ip.dst in captured_syn_packet and pkt['tcp'].flags == '0x00000010':
            if captured_syn_packet[pkt.ip.dst]['Status'] == 'N':
                captured_syn_packet[pkt.ip.dst]['Status'] = 'Y'
                time = captured_syn_packet[pkt.ip.dst]['SRTT']
                captured_syn_packet[pkt.ip.dst]['SRTT'] = pkt.sniff_time - time
                print('SRTT: ')
                print(captured_syn_packet[pkt.ip.dst]['SRTT'])
                print(pkt.ip.dst)

        if pkt.ip.src == my_ip and pkt.ip.dst in captured_syn_packet and captured_syn_packet[pkt.ip.dst]['Status'] == 'Y':
            if 'ssh' in pkt and 'protocol' in pkt['ssh'].field_names:
                print('Client Protocol Version')
                captured_syn_packet[pkt.ip.dst]['ClientProtocol'] = (True, pkt.sniff_time)
                if 'ServerProtocol' in captured_syn_packet[pkt.ip.dst] and captured_syn_packet[pkt.ip.dst]['ServerProtocol'][0] == True:
                    client = captured_syn_packet[pkt.ip.dst]['ClientProtocol'][1]
                    server = captured_syn_packet[pkt.ip.dst]['ServerProtocol'][1]
                    captured_syn_packet[pkt.ip.dst]['PRTT'] = server - client
                    print('PRTT: ', captured_syn_packet[pkt.ip.dst]['PRTT'])

            if 'ssh' in pkt and 'kex_algorithms' in pkt['ssh'].field_names:
                print('Client Algorithm')
                captured_syn_packet[pkt.ip.dst]['ClientAlgorithm'] = (True, pkt.sniff_time)
                if 'ServerAlgorithm' in captured_syn_packet[pkt.ip.dst] and captured_syn_packet[pkt.ip.dst]['ServerAlgorithm'][0] == True:
                    client = captured_syn_packet[pkt.ip.dst]['ClientAlgorithm'][1]
                    server = captured_syn_packet[pkt.ip.dst]['ServerAlgorithm'][1]
                    captured_syn_packet[pkt.ip.dst]['ARTT'] = server - client
                    print('ARTT: ', captured_syn_packet[pkt.ip.dst]['ARTT'])

            if 'ssh' in pkt and '21' == pkt['ssh'].get('message_code'):
                print('Client KEX Reply')
                time = captured_syn_packet[pkt.ip.dst]['KRTT']
                captured_syn_packet[pkt.ip.dst]['KRTT'] = pkt.sniff_time - time
                print('KRTT: ', captured_syn_packet[pkt.ip.dst]['KRTT'])

        if pkt.ip.dst == my_ip and pkt.ip.src in captured_syn_packet and captured_syn_packet[pkt.ip.src]['Status'] == 'Y':
            if 'ssh' in pkt and 'protocol' in pkt['ssh'].field_names:
                print('Server Protocol Version')
                captured_syn_packet[pkt.ip.src]['ServerProtocol'] = (True, pkt.sniff_time)
                if 'ClientProtocol' in captured_syn_packet[pkt.ip.src] and captured_syn_packet[pkt.ip.src]['ClientProtocol'][0] == True:
                    client = captured_syn_packet[pkt.ip.src]['ClientProtocol'][1]
                    server = captured_syn_packet[pkt.ip.src]['ServerProtocol'][1]
                    captured_syn_packet[pkt.ip.src]['PRTT'] = server - client
                    print('PRTT: ', captured_syn_packet[pkt.ip.src]['PRTT'])

            if 'ssh' in pkt and 'kex_algorithms' in pkt['ssh'].field_names:
                print('Server Algorithm')
                captured_syn_packet[pkt.ip.src]['ServerAlgorithm'] = (True, pkt.sniff_time)
                if 'ClientAlgorithm' in captured_syn_packet[pkt.ip.src] and captured_syn_packet[pkt.ip.src]['ClientAlgorithm'][0] == True:
                    client = captured_syn_packet[pkt.ip.src]['ClientAlgorithm'][1]
                    server = captured_syn_packet[pkt.ip.src]['ServerAlgorithm'][1]
                    captured_syn_packet[pkt.ip.src]['ARTT'] = server - client
                    print('ARTT: ', captured_syn_packet[pkt.ip.src]['ARTT'])

            if 'ssh' in pkt and 'host_key_type' in pkt['ssh'].field_names:
                print('Server KEX Reply')
                captured_syn_packet[pkt.ip.src]['KRTT'] = pkt.sniff_time
                print(captured_syn_packet[pkt.ip.src]['KRTT'])
        
    except AttributeError as e:
        print(e)
        print('+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++')
        print(pkt)
        print('+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++')


def start():
    print("starting capture")

    try:
        capture.apply_on_packets(print_callback, timeout=1000)
    except Exception as e:
        print("oops")
        print('Error:', e)
        start()


if __name__ == "__main__":
    start()
 
