import pyshark
from scapy.all import *
import sys


def main():

    filename = sys.argv[1]

    count = 0

    capture = pyshark.FileCapture(filename)

    for pkt in capture:
        for layer in pkt:
            print('layer_name: \n', layer.layer_name)
            if layer.layer_name == 'ssh':
                print('layer: \n', layer)
                for field in layer.field_names:
                    print('field: ', field)
                    print(layer.get(field))
                count += 1
            
            if count == 25:
                return


main()