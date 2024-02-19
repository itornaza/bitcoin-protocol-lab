#
#  mpp.py
#  itornaza@gmail.com
#

import csv
from route import Route
from channel import Channel

# Constants for parsing csv headers
ID = "path_id"
NAME = "channel_name"
CTLV = "cltv_delta"
FEE = "base_fee_msat"
PPM = "proportional_fee_ppm"

class MPP:
    
    routes_ = [] # List of routes contained in the MPP
    channels_ = [] # List of channels retreived from the csv file

    def __init__(self, file_path):
        """ Groups the channels into routes depending on their path_id value """
        self.import_from_csv(file_path)
        
        # Create the number of empty routes that we are going to need
        max_route_channel = max(self.channels_, key=lambda Channel: Channel.path_id_)
        n_routes = int(max_route_channel.path_id_) + 1
        for i in range(n_routes):
            route = Route()
            self.routes_.append(route)

        # Collect channels into the respective route 
        for channel in self.channels_:
            index = int(channel.path_id_)
            self.routes_[index].append(channel)

    def import_from_csv(self, file_path):
        """ Get the channels from the csv file """
        with open(file_path, newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                channel = Channel(row[ID], row[NAME], row[CTLV], row[FEE], row[PPM])
                self.channels_.append(channel)
 
    def length(self):
        """ Return the total number of routes in our MPP """
        return len(self.routes_)
    