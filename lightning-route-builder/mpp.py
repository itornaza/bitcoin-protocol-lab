#
#  mpp.py
#  itornaza@gmail.com
#

import csv
from route import Route
from channel import Channel

# Constants for parsing csv headers
ID: str = "path_id"
NAME: str = "channel_name"
CTLV: str = "cltv_delta"
FEE: str = "base_fee_msat"
PPM: str = "proportional_fee_ppm"

class MPP:
    
    routes_: list[Route] 
    channels_: list[Channel] 

    def __init__(self, file_path, height, secret, amount, expiry):
        self.routes_ = []
        self.channels_ = []
        self.import_from_csv(file_path)
        self.init_routes()
        self.channels_to_routes()
        self.set(height, expiry, secret, amount)
    
    def length(self):
        return len(self.routes_)

    def import_from_csv(self, file_path):
        with open(file_path, newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                channel = Channel(int(row[ID]), str(row[NAME]), int(row[CTLV]), 
                                  int(row[FEE]), int(row[PPM]))
                self.channels_.append(channel)

    def init_routes(self):
        max_route_channel: Channel = max(self.channels_, key=lambda Channel: Channel.path_id_)
        n_routes: int = max_route_channel.path_id_ + 1
        for i in range(n_routes):
            route = Route()
            self.routes_.append(route)

    def channels_to_routes(self):
        for channel in self.channels_:
            index: int = channel.path_id_
            self.routes_[index].append(channel)

    def set(self, height, expiry, secret, invoice_amount):
        amount = invoice_amount // self.length()
        for route in self.routes_:
            route.set_htlc(height, amount, expiry)
            if self.length() > 1: 
                route.set_tlv(secret, invoice_amount)

    def print(self):
        for route in self.routes_:
            route.print()