import sys
sys.path.append("src/CLI/Core")
import pyshark as ps
from pyshark.capture.file_capture import FileCapture
from packet import Packet

class Capture(FileCapture):

    def __init__(self, filename):
        super(Capture, self).__init__(filename, keep_packets=False)
        self.tcp = []
        self.ip = []
        self.pair = []
        self.packets = []

    def packet_wrapper(self):

        print(len(self))

        self.packets = [Packet(pkt) for pkt in super(Capture, self).__iter__()]

        print(super(Capture, self).__repr__())
        print(len(self.packets))

        # assert len(self.packets) == int(super(Capture, self).__repr__().split()[-1])
    
    def extract_tcp(self):

        self.tcp = [layer for packet in self.packets for layer in packet.get_layers() if layer.layer_name == 'tcp']

    def extract_ip(self):

        self.ip = [layer for packet in self.packets for layer in packet.get_layers() if layer.layer_name == 'ip']

    def extract(self):

        self.extract_tcp()
        self.extract_ip()

    def pair(self):

        self.pair = [(t, i) for (t, i) in zip(self.tcp, self.ip)]
    

    def get_ip(self):
        return self.ip

    def get_tcp(self):
        return self.tcp

    def packet_count(self):
        return len(self.packets)

    def __iter__(self):
        return iter(self.packets)
    
