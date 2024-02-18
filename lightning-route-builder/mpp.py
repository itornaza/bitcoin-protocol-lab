#
# mpp.py
# itornaza@gmail.com
#

import csv
from route import Route
from channel import Channel

class MPP:

    routes_ = []
    channels_ = []

    def __init__(self, file_path):
        """ Default constructor reads the csv files and groups the channels 
            into routes depending on their path_id value """
        
        # Get the channels from the csv file
        with open(file_path, newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                channel = Channel(row['path_id'], row['channel_name'], row['cltv_delta'], 
                                  row['base_fee_msat'], row['proportional_fee_ppm'])
                self.channels_.append(channel)
        
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

    def length(self):
        """ Return the total number of routes in our MPP """
        return len(self.routes_)