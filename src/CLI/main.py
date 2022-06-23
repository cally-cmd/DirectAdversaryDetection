import sys, os
sys.path.append("src/CLI/Core")
from Capture import Capture

def read_file(filename):

    pcap = Capture(filename)

    return pcap


def main():

    pcap_name = sys.argv[1]

    data = []

    if os.path.isdir(pcap_name):
        for file in os.listdir(pcap_name):
            data = read_file(os.path.join(pcap_name, file))
            
    else:
        datum = read_file(pcap_name)
        datum.extract()
        datum.packet_wrapper()
        

if __name__ == "__main__":
    main()