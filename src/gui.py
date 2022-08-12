import threading
import kivy
from kivy.app import App
from kivy.uix.label import Label
from kivy.uix.gridlayout import GridLayout
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.uix.widget import Widget
from kivy.properties import ObjectProperty
from kivy.lang import Builder
from kivy.core.window import Window
from kivy.clock import Clock
import socket
import sys

HEADERSIZE = 10
THRESHOLD = 0.841841618

kv = Builder.load_file("gui.kv")

count = 0

class MyGrid(Widget):

    ip1 = ObjectProperty(None)
    ip2 = ObjectProperty(None)
    ip3 = ObjectProperty(None)
    ip4 = ObjectProperty(None)
    ip5 = ObjectProperty(None)

    r_p1 = ObjectProperty(None)
    r_p2 = ObjectProperty(None)
    r_p3 = ObjectProperty(None)
    r_p4 = ObjectProperty(None)
    r_p5 = ObjectProperty(None)

    r_a1 = ObjectProperty(None)
    r_a2 = ObjectProperty(None)
    r_a3 = ObjectProperty(None)
    r_a4 = ObjectProperty(None)
    r_a5 = ObjectProperty(None)

    r_k1 = ObjectProperty(None)
    r_k2 = ObjectProperty(None)
    r_k3 = ObjectProperty(None)
    r_k4 = ObjectProperty(None)
    r_k5 = ObjectProperty(None)

    decision1 = ObjectProperty(None)
    decision2 = ObjectProperty(None)
    decision3 = ObjectProperty(None)
    decision4 = ObjectProperty(None)
    decision5 = ObjectProperty(None)

    connection_count = 0

    def __init__(self, **kwargs):
        super(MyGrid, self).__init__(**kwargs)
        self.register_event_type('on_update')
        self.ip1.bind(text=self.on_update)
        self.r_p1.bind(text=self.on_update)
        self.r_a1.bind(text=self.on_update)
        self.r_k1.bind(text=self.on_update)
        self.decision1.bind(text=self.on_update)
        # event = Clock.schedule_interval(self.clear_text, 60)
        self.container = [[self.ids.ip1, self.ids.r_p1, self.ids.r_a1, self.ids.r_k1, self.ids.decision1], 
                          [self.ids.ip2, self.ids.r_p2, self.ids.r_a2, self.ids.r_k2, self.ids.decision2], 
                          [self.ids.ip3, self.ids.r_p3, self.ids.r_a3, self.ids.r_k3, self.ids.decision3], 
                          [self.ids.ip4, self.ids.r_p4, self.ids.r_a4, self.ids.r_k4, self.ids.decision4], 
                          [self.ids.ip5, self.ids.r_p5, self.ids.r_a5, self.ids.r_k5, self.ids.decision5]]


    def update(self, ip, r_k, r_p, r_a):
        global THRESHOLD
        self.on_update(self.container[self.connection_count][0], ip)
        self.on_update(self.container[self.connection_count][1], r_p)
        self.on_update(self.container[self.connection_count][2], r_a)
        self.on_update(self.container[self.connection_count][3], r_k)
        if float(r_p) < THRESHOLD:
            self.on_update(self.container[self.connection_count][4], "DIRECT!")
        else:
            self.on_update(self.container[self.connection_count][4], "TOR!")

        self.connection_count += 1
        self.connection_count %= 5

    def on_update(self, var, val):
        var.text = val

class IntrusionApp(App):
    def build(self):
        Window.clearcolor = kivy.utils.get_color_from_hex('#77cccc')
        return MyGrid()

    def close_app(self):
        # closing application
        App.get_running_app().stop()
        # removing window
        Window.close()
        # quitting threads
        sys.exit()

def parseData(s):
    
    lst = s.split('\n')

    ip = ''
    r_p = ''
    r_a = ''
    r_k = ''

    i = 0

    while i < len(lst):
        print(lst[i])
        if 'IP' in lst[i]:
            ip = lst[i+1]
        if lst[i] == 'R_P':
            r_p = lst[i+1]
        if lst[i] == 'R_A':
            r_a = lst[i+1]
        if lst[i] == 'R_K':
            r_k = lst[i+1]

        i += 1

    return [ip, r_p, r_a, r_k]

def client():
    global HEADERSIZE
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('18.116.241.221', 12345))

    while True:
        full_msg = ''
        new_msg = True
        while True:
            msg = s.recv(2048)
            if new_msg:
                print("new msg len:",msg[:HEADERSIZE])
                msglen = int(msg[:HEADERSIZE])
                new_msg = False

            full_msg += msg.decode("utf-8")

            print(full_msg)
            print('End Message')

            if 'KEX' in full_msg:
                full_msg = full_msg[msglen:]
                data = parseData(full_msg)
                ip = data[0]
                r_p = data[1]
                r_a = data[2]
                r_k = data[3]
                temp = IntrusionApp.get_running_app()
                temp.root.update(ip, r_k, r_p, r_a)

if __name__ == "__main__":
    x = threading.Thread(target=client, daemon=True)
    x.start()
    IntrusionApp().run()