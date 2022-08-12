#!/usr/bin

import pyshark
import socket
import os
from queue import Queue
from scapy.all import *
from threading import Thread
import logging

logging.basicConfig(filename='app.log', filemode='w', format='%(name)s - %(levelname)s - %(message)s', level=10)

HEADERSIZE = 10

queue = Queue()

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8", 80))
my_ip = s.getsockname()[0]
s.close()

file = '/home/ec2-user/intrusion/ServerTest.pcap'

f = open(file, 'w')

capture = pyshark.LiveCapture(interface='eth0', bpf_filter='tcp port 22') #capture filter
#capture = pyshark.FileCapture('/home/cally/Desktop/intrusion_detection/StaticData/AU_RandomTor_Test_1_162.248.11.66.pcap')

captured_syn_packet = {}

def print_callback(pkt):
    DATA = ''
    
    f.write(str(pkt))

    #check if the pkt's ip address is new
    #store the current ip address and time stamp for calulating VPN rtt
        #find next corresponding inbound time stamp
    #initiate SSH ping
    #store the outbound SSH ping time stamp
        #find next corresponding inbound time stamp
    try:

        timestamp = pkt.sniff_time
        
        if pkt.ip.dst == my_ip and pkt.ip.src not in captured_syn_packet and (pkt['tcp'].flags == '2' or pkt['tcp'].flags == '0x00000002'):
            captured_syn_packet[pkt.ip.src] = {'Status' : 'N'}
            captured_syn_packet[pkt.ip.src]['SYN'] = timestamp
            logging.debug('Caputred SYN Packet')

        #CAPTURE SYN ACK PACKET
        if pkt.ip.dst != my_ip and pkt.ip.src == my_ip and pkt.ip.dst in captured_syn_packet and (pkt['tcp'].flags == '18' or pkt['tcp'].flags == '0x00000012'):
            captured_syn_packet[pkt.ip.dst]['SRTT'] = timestamp
            captured_syn_packet[pkt.ip.dst]['SYN/ACK'] = timestamp
            logging.debug('Caputred SYN/ACK Packet')
            
        #CAPTURE ACK PACKET
        if pkt.ip.dst == my_ip and pkt.ip.src in captured_syn_packet and (pkt['tcp'].flags == '16' or pkt['tcp'].flags == '0x00000010'):
            if captured_syn_packet[pkt.ip.src]['Status'] == 'N':
                captured_syn_packet[pkt.ip.src]['Status'] = 'Y'
                time = captured_syn_packet[pkt.ip.src]['SRTT']
                captured_syn_packet[pkt.ip.src]['SRTT'] = timestamp - time
                captured_syn_packet[pkt.ip.src]['ACK'] = timestamp
                logging.debug('Caputred ACK Packet')

        if 'ssh' in pkt and pkt.ip.dst == my_ip and pkt.ip.src in captured_syn_packet and captured_syn_packet[pkt.ip.src]['Status'] == 'Y':
            if 'protocol' in pkt['ssh'].field_names:
                captured_syn_packet[pkt.ip.src]['ClientProtocol'] = (True, timestamp)
                if 'ServerProtocol' in captured_syn_packet[pkt.ip.src] and captured_syn_packet[pkt.ip.src]['ServerProtocol'][0] == True:
                    client = captured_syn_packet[pkt.ip.src]['ClientProtocol'][1]
                    server = captured_syn_packet[pkt.ip.src]['ServerProtocol'][1]
                    captured_syn_packet[pkt.ip.src]['PRTT'] = client - server
                logging.debug('Caputred Client Protocol Packet')
            
            if '20' == pkt['ssh'].get('message_code'):
                captured_syn_packet[pkt.ip.src]['ClientAlgorithm'] = (True, timestamp)
                if 'ServerAlgorithm' in captured_syn_packet[pkt.ip.src] and captured_syn_packet[pkt.ip.src]['ServerAlgorithm'][0] == True:
                    client = captured_syn_packet[pkt.ip.src]['ClientAlgorithm'][1]
                    server = captured_syn_packet[pkt.ip.src]['ServerAlgorithm'][1]
                    captured_syn_packet[pkt.ip.src]['ARTT'] = client - server
                logging.debug('Caputred Client Algorithm Packet')         

            if '21' == pkt['ssh'].get('message_code'):
                logging.debug('Caputred Client KEX Packet')
                DATA += 'IP\n'
                DATA += pkt.ip.src + '\n'
                DATA += 'SYN Packet\n'
                DATA += str(captured_syn_packet[pkt.ip.src]['SYN']) + '\n'
                DATA += 'SYN/ACK Packet\n'
                DATA += str(captured_syn_packet[pkt.ip.src]['SYN/ACK']) + '\n'
                DATA += 'ACK Packet\n'
                DATA += str(captured_syn_packet[pkt.ip.src]['ACK']) + '\n'
                DATA += 'Client Protocol\n'
                DATA += str(captured_syn_packet[pkt.ip.src]['ClientProtocol'][1]) + '\n'
                DATA += 'Server Protocol\n'
                DATA += str(captured_syn_packet[pkt.ip.src]['ServerProtocol'][1]) + '\n'
                DATA += 'Client Algorithm\n'
                DATA += str(captured_syn_packet[pkt.ip.src]['ClientAlgorithm']) + '\n'
                DATA += 'Server Algorithm\n'
                DATA += str(captured_syn_packet[pkt.ip.src]['ServerAlgorithm']) + '\n'
                DATA += 'Server KEX Reply\n'
                DATA += str(captured_syn_packet[pkt.ip.src]['ServerKEX']) + '\n'
                DATA += 'Client KEX Reply\n'            
                DATA += str(timestamp) + '\n'

                captured_syn_packet[pkt.ip.src]['ClientKEX'] = timestamp
                time = captured_syn_packet[pkt.ip.src]['KRTT']
                captured_syn_packet[pkt.ip.src]['KRTT'] = timestamp - time
                captured_syn_packet[pkt.ip.src]['Status'] = 'C'

                DATA += 'SRTT\n'
                DATA += str(captured_syn_packet[pkt.ip.src]['SRTT']) + '\n'

                DATA += 'PRTT\n'
                DATA += str(captured_syn_packet[pkt.ip.src]['PRTT']) + '\n'

                DATA += 'ARTT\n'
                DATA += str(captured_syn_packet[pkt.ip.src]['ARTT']) + '\n'

                DATA += 'KRTT\n'
                DATA += str(captured_syn_packet[pkt.ip.src]['KRTT']) + '\n'
                
                r_p = captured_syn_packet[pkt.ip.src]['PRTT'] / captured_syn_packet[pkt.ip.src]['SRTT']
                r_a = captured_syn_packet[pkt.ip.src]['ARTT'] / captured_syn_packet[pkt.ip.src]['SRTT']
                r_k = captured_syn_packet[pkt.ip.src]['KRTT'] / captured_syn_packet[pkt.ip.src]['SRTT']

                DATA += 'R_P\n'
                DATA += str(r_p) + '\n'
                DATA += 'R_A\n'
                DATA += str(r_a) + '\n'
                DATA += 'R_K\n'
                DATA += str(r_k) + '\n'

                queue.put(DATA)
                logging.debug('Added DATA to queue')
                print('SanityCheck')

        if 'ssh' in pkt and pkt.ip.src == my_ip and pkt.ip.dst in captured_syn_packet and captured_syn_packet[pkt.ip.dst]['Status'] == 'Y':
            if 'protocol' in pkt['ssh'].field_names:
                captured_syn_packet[pkt.ip.dst]['ServerProtocol'] = (True, timestamp)
                if 'ClientProtocol' in captured_syn_packet[pkt.ip.dst] and captured_syn_packet[pkt.ip.dst]['ClientProtocol'][0] == True:
                    client = captured_syn_packet[pkt.ip.dst]['ClientProtocol'][1]
                    server = captured_syn_packet[pkt.ip.dst]['ServerProtocol'][1]
                    captured_syn_packet[pkt.ip.dst]['PRTT'] = client - server
                logging.debug('Caputred Server Protocol Packet')

            if '20' == pkt['ssh'].get('message_code'):
                captured_syn_packet[pkt.ip.dst]['ServerAlgorithm'] = (True, timestamp)
                if 'ClientAlgorithm' in captured_syn_packet[pkt.ip.dst] and captured_syn_packet[pkt.ip.dst]['ClientAlgorithm'][0] == True:
                    client = captured_syn_packet[pkt.ip.dst]['ClientAlgorithm'][1]
                    server = captured_syn_packet[pkt.ip.dst]['ServerAlgorithm'][1]
                    captured_syn_packet[pkt.ip.dst]['ARTT'] = client - server
                logging.debug('Caputred Server Algorithm Packet')
            
            if 'message_code' in pkt['ssh'].field_names and 30 <= int(pkt['ssh'].get('message_code')) <= 49:
                captured_syn_packet[pkt.ip.dst]['KRTT'] = timestamp
                captured_syn_packet[pkt.ip.dst]['ServerKEX'] = timestamp
                logging.debug('Caputred Server KEX Packet')
        
    except AttributeError as e:
        # print(e)
        # print('+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++')
        # print(pkt)
        # print('+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++')
        logging.error(e)
        pass

def server():
    logging.debug('Running server script')
    global HEADERSIZE
    logging.info(f'Headersize value: {HEADERSIZE}')

    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    logging.debug('Made socket')
    s.bind((socket.gethostname(), 12345))
    logging.debug('Bound socket')
    s.listen(5)
    logging.debug('Listening...')

    while True:
        # now our endpoint knows about the OTHER endpoint.
        logging.debug('Before client accepted')
        clientsocket, address = s.accept()
        logging.info(f'Clientsocket: {clientsocket}')
        logging.info(f"Connection from {address} has been established.")

        msg = "Welcome to the server!"
        msg = f"{len(msg):<{HEADERSIZE}}"+msg

        clientsocket.send(bytes(msg,"utf-8"))
        logging.debug('Sent welcome message')

        while True:
            DATA = queue.get()
            DATA = f"{len(DATA):<{HEADERSIZE}}"+DATA
            clientsocket.send(bytes(DATA, "utf-8"))
            logging.info(f'DATA Sent: {DATA}')
            logging.debug('Sent sniffed timestamps and ratios')

def start():
    logging.debug('Starting Script')

    try:
        logging.debug('Creating Server Thread')
        x = threading.Thread(target=server)
        logging.debug('Starting Server Thread')
        x.start()
        logging.debug('Starting Capture')
        capture.apply_on_packets(print_callback, timeout=1000)
        
    except Exception as e:
        logging.error(e)
        start()
        f.close()

if __name__ == "__main__":
    start()
    f.close()
f.close()