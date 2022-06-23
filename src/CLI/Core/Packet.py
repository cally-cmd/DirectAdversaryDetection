import sys

import pyshark as ps

class Packet():

    def __init__(self, packet):
        self.packet = packet
