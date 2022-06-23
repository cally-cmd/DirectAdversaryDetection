import time
import pyshark

def listen_on_interface(interface='wlp2s0', timeout=60):
    """
    :param interface: The name of the interface on which to capture traffic
    :return: generator containing live packets
    """

    start = time.time()
    capture = pyshark.LiveCapture(interface=interface)

    for item in capture.sniff_continuously():
        if timeout and time.time() - start > timeout:
            break
        yield item 

for pkt in listen_on_interface():
    print(pkt)