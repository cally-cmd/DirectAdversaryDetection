import sys, os, pyshark

def read_file(filename):

    pcap = pyshark.FileCapture(filename)

    return pcap

def extract_tcp(capture):

    tcp = [layer for packet in capture for layer in packet if layer.layer_name == 'tcp']

    return tcp

def extract_ip(capture):

    ip = [layer for packet in capture for layer in packet if layer.layer_name == 'ip']

    return ip

def zip_ip_tcp(tcp, ip):

    zipped = [(t, i) for (t, i) in zip(tcp, ip)]
    
    return zipped

def main():

    pcap_name = sys.argv[1]

    data = []

    if os.path.isdir(pcap_name):
        for file in os.listdir(pcap_name):
            data = read_file(os.path.join(pcap_name, file))
            tcp = extract_tcp(data)
    else:
        datum = read_file(pcap_name)
        tcp = extract_tcp(datum)
        ip = extract_ip(datum)
        zipped = zip_ip_tcp(tcp, ip)
        print(zipped[0][1].get('src'))
        print(zipped[0][1].get('dst'))

if __name__ == "__main__":
    main()