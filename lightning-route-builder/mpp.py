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
    
    #---------------
    # Variables
    #---------------

    routes_: list[Route] = [] # List of routes contained in the MPP
    channels_: list[Channel] = [] # List of channels retreived from the csv file

    #---------------
    # Constructor
    #---------------

    def __init__(self, file_path, height, expiry, secret, amount_msat):
        self.import_from_csv(file_path)
        self.init_routes()
        self.channels_to_routes()
        self.set(height, expiry, secret, amount_msat)

    #---------------
    # Accessor
    #---------------
                
    def length(self):
        """ Return the total number of routes in our MPP """
        return len(self.routes_)
    
    #---------------
    # Mutators
    #---------------

    def import_from_csv(self, file_path):
        """ Get all the channels from the csv file """
        with open(file_path, newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                channel = Channel(row[ID], row[NAME], row[CTLV], row[FEE], row[PPM])
                self.channels_.append(channel)

    def init_routes(self):
        """ Create the appropriate number of routes """
        max_route_channel = max(self.channels_, key=lambda Channel: Channel.path_id_)
        n_routes = max_route_channel.path_id_ + 1
        for i in range(n_routes):
            route = Route()
            self.routes_.append(route)

    def channels_to_routes(self):
        """ Collect channels into the respective routes """
        for channel in self.channels_:
            index = channel.path_id_
            self.routes_[index].append(channel)

    def set(self, height, expiry, secret, invoice_amount):
        """ Performs all the calculations for the mpp. Splits the amount to 
        send with each route in the MPP amount divisible by the number of its 
        routes, enforced with integet division. If there are more than one 
        route, it adds the tlv field """
        partial_amount = invoice_amount // self.length()
        for route in self.routes_:
            route.set_expiry(height, expiry)
            route.set_amount(partial_amount)
            if self.length() > 1: 
                route.set_tlv(secret, invoice_amount)

    #---------------
    # Output
    #---------------

    def print(self):
        for route in self.routes_:
            route.print()