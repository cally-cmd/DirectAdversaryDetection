import sys

import pyshark as ps

class Layer():

    def __init__(self, layer):
        self.layer = layer

    def get_ip(self):

        return self.layer.get('ip')

    def get_fields(self):

        return self.layer.field_names