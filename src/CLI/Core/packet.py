import sys
sys.path.append("src/CLI/Core")
import pyshark as ps
from layer import Layer

class Packet():

    def __init__(self, packet):
        self.packet = packet
        self.layers = []

    def layer_wrapper(self):

        self.layers = [Layer(layer) for layer in self]

    def get_layers(self):

        return self.layers
