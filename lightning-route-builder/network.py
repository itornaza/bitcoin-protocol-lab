#
# channel.py
# itornaza@gmail.com
#

import csv

class Channel:
    
    # Current block height
    height_ = 0

    # path_id: a uint32
    path_id_ = 0

    # channel_name: a string identifying the channel
    channel_name_ = ""

    # cltv_delta: a uint32 representing the required delta for the hop
    cltv_delta_ = int(0)

    # base_fee_msat: a uint64 fee expressed in millisatoshis charged 
    # per-htlc that uses the channel as an outgoing hop
    base_fee_msat_ = 0
    
    # proportional_fee_ppm: a uint64 representing the parts per million 
    # proportional fee on the htlc's amount charged to use the channel as 
    # an outgoing hop
    proportional_fee_ppm_ = 0
    
    # htlc_amount_msat: a uint64 representing the htlc amount on that channel
    htlc_amount_msat_ = 0

    # htlc_expiry: a uint32 representing the expiry height of the htlc
    htlc_expiry_ = int(0)

    # tlv: a string, hardcoded to NULL
    tlv_ = "NULL"

    def __init__(self, height, path_id=0, channel_name="", cltv_delta=0, base_fee_msat=0, proportional_fee_ppm=0):
        self.height_ = height
        self.path_id_ = path_id
        self.channel_name_ = channel_name
        self.cltv_delta_ = cltv_delta
        self.base_fee_msat_ = base_fee_msat
        self.proportional_fee_ppm_ = proportional_fee_ppm

    def print(self):
        print(f"{self.path_id_},{self.channel_name_},{self.cltv_delta_},{self.base_fee_msat_},{self.proportional_fee_ppm_}")

    def calculate_htlc_expiry(self, predecessor: int):  
        """ Using the routing policies of the channels provided, produce the values for the 
            HTLCs that will be used to make a payment for the amount and block height 
            provided """
        self.htlc_expiry_ += int(self.cltv_delta_) + int(predecessor)

    def calculate_htlc_fee(self, amount: int):
        self.htlc_amount_msat_ = int(self.base_fee_msat_) + \
                                (amount * int(self.proportional_fee_ppm_) / int(1000000))

    def print_htlc(self): 
        """ Output the HTLC values for each hop to stdout
            *** Sample output (trim all whitespace) ***
            path_id, channel_name, htlc_amount_msat, htlc_expiry, tlv
            0,AliceBob,amount,expiry,NULL
            0,BobCarol,amount,expiry,NULL
            0,CarolDave,amount,expiry,NULL """
        print(f"{self.path_id_},{self.channel_name_},{self.htlc_amount_msat_},{self.htlc_expiry_},{self.tlv_}")

class Route:

    # Current block height
    height_ = 0

    # List of channels contained in this route
    channels_ = []

    def __init__(self, file_path, current_block_height):
        self.height_ = current_block_height
        with open(file_path, newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                channel = Channel(self.height_, row['path_id'], row['channel_name'], row['cltv_delta'], 
                                  row['base_fee_msat'], row['proportional_fee_ppm'])
                self.channels_.append(channel)

    def print(self):
        for channel in self.channels_:
            channel.print()

    def calculate_htlc_expiry(self):
        predecessor = 0
        for index, channel in enumerate(self.channels_):
            if index == 0:
                # For the first channel add the block height only
                channel.htlc_expiry_ = int(self.height_)
            else:
                # For the rest of the channels append the cltv_delta for that channel
                channel.calculate_htlc_expiry(predecessor)
            predecessor = channel.htlc_expiry_

    def calculate_htlc_fee(self, amount):
        # Exclude the last channel because we do not pay any fees for it
        for i in range(len(self.channels_) - 1, -1, -1):
            self.channels_[i].calculate_htlc_fee(amount)
            amount += self.channels_[i].htlc_amount_msat_
            # TODO: Debug!!!
            
        # The payee and the other node of the channel have the same amount
        self.channels_[0].htlc_amount_msat_ = self.channels_[1].htlc_amount_msat_ 

    def print_htlc(self):
        for channel in self.channels_:
            channel.print_htlc()