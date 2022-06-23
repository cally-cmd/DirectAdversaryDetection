import sys
sys.path.append("src/CLI/Core")
import pyshark as ps
from pyshark.capture.file_capture import FileCapture
from Packet import Packet

class Capture(FileCapture):

    def __init__(self, filename):
        super().__init__(filename)
        self.tcp = []
        self.ip = []
        self.pair = []
        self.packets = []

    def packet_wrapper(self):

        self.packets = [Packet(packet) for packet in self]
    
    def extract_tcp(self):

        self.tcp = [layer for packet in self for layer in packet if layer.layer_name == 'tcp']

    def extract_ip(self):

        self.ip = [layer for packet in self for layer in packet if layer.layer_name == 'ip']

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

    
