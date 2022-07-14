import sys, os
sys.path.append("src/CLI/Core")
import pyshark

unique_ip = {}

def read_file(filename):

    pcap = pyshark.FileCapture(filename)

    return pcap


def extract(capture):

    packets = [packet for packet in capture if 'tcp' in packet]

    return packets
    

def tcp_pair(capture):

    tcp_packets = extract(capture)
    tcp = [layer for packet in tcp_packets for layer in packet if layer.layer_name == 'tcp']
    ip  = [layer for packet in tcp_packets for layer in packet if layer.layer_name == 'ip']

    assert len(tcp) == len(ip)

    return tcp, ip

def build_ip(tcps, ips):

    for (t, i) in zip(tcps, ips):

        src_ip = i.get('src')
        dst_ip = i.get('dst')
        key = (src_ip, dst_ip)

        if key in unique_ip:
            unique_ip[key].append(t)
        elif reversed(key) in unique_ip:
            unique_ip[key].append(t)
        else:
            unique_ip[key] = [t]

def weed_ip():
    for key in unique_ip.keys():
        for i, layer in enumerate(unique_ip[key]):
            if layer.get('flags') not in ['0x00000002', '0x00000012', '0x00000010']:
                unique_ip[key].pop(i)

def compute_lrrt():

    for key in unique_ip.keys():
        for layer in unique_ip[key]:
            print(layer.get('analysis_ack_rtt'))

def lrrt(capture, ip='none'):

    tcps, ips = tcp_pair(capture)

    if ip == 'none':

        build_ip(tcps, ips)
        weed_ip()
        compute_lrrt()
    else:

        pass


def main():

    pcap_name = sys.argv[1]

    data = []

    if os.path.isdir(pcap_name):
        for file in os.listdir(pcap_name):
            data = read_file(os.path.join(pcap_name, file))
            
    else:
        datum = read_file(pcap_name)
        lrrt(datum)

if __name__ == "__main__":
    main()