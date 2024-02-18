#
# route.py
# itornaza@gmail.com
#

import csv
from channel import Channel

class Route:

    # List of channels contained in this route
    channels_ = []

    def __init__(self, file_path):
        with open(file_path, newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                channel = Channel(row['path_id'], row['channel_name'], row['cltv_delta'], 
                                  row['base_fee_msat'], row['proportional_fee_ppm'])
                self.channels_.append(channel)

    def calculate_htlc_expiry(self, height: int, min_ctlv: int):
        # Trasverse the route in the reverse order
        predecessor = int(height) + int(min_ctlv)
        for i in range(len(self.channels_) - 1, -1, -1):
            self.channels_[i].calculate_htlc_expiry(predecessor)
            if i == len(self.channels_) - 1:
                # The last channel (normal order) does not add the ctlv_delta to 
                # the calculation
                self.channels_[i].htlc_expiry_ -= int(self.channels_[i].cltv_delta_)
            predecessor = self.channels_[i].htlc_expiry_

    def calculate_htlc_fee(self, amount: int):
        # Trasverse the route in the reverse order
        for i in range(len(self.channels_) - 1, -1, -1):
            self.channels_[i].calculate_htlc_fee(amount)
            amount = self.channels_[i].htlc_amount_msat_
            if i == 0:
                # Exclude the last channel because we do not pay any fees for it
                self.channels_[i].htlc_amount_msat_ =  self.channels_[i+1].htlc_amount_msat_

    def print_htlc(self):
        for channel in self.channels_:
            channel.print_htlc()

    def print(self):
        for channel in self.channels_:
            channel.print()