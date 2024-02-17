#
# channel.py
# itornaza@gmail.com
#

import csv

class Channel:

    # htlc_amount_msat: a uint64 representing the htlc amount on that channel
    htlc_amount_msat_ = 0

    # htlc_expiry: a uint32 representing the expiry height of the htlc
    htlc_expiry_ = 0

    # tlv: a string, hardcoded to NULL
    tlv_ = "NULL"

    def __init__(self, path_id=0, channel_name="", cltv_delta=0, base_fee_msat=0, proportional_fee_ppm=0):
        
        # path_id: a uint32
        self.path_id_ = path_id
        
        # channel_name: a string identifying the channel
        self.channel_name_ = channel_name
        
        # cltv_delta: a uint32 representing the required delta for the hop
        self.cltv_delta_ = cltv_delta
        
        # base_fee_msat: a uint64 fee expressed in millisatoshis charged 
        # per-htlc that uses the channel as an outgoing hop
        self.base_fee_msat_ = base_fee_msat
        
        # proportional_fee_ppm: a uint64 representing the parts per million 
        # proportional fee on the htlc's amount charged to use the channel as 
        # an outgoing hop
        self.proportional_fee_ppm_ = proportional_fee_ppm

    def print(self):
        print(f"{self.path_id_},{self.channel_name_},{self.cltv_delta_},{self.base_fee_msat_},{self.proportional_fee_ppm_}")

    def calculate_htlc(self):  
        pass

    def print_htlc(self): 
        """Output the HTLC values for each hop to stdout
            *** Sample output (trim all whitespace) ***
            path_id, channel_name, htlc_amount_msat, htlc_expiry, tlv
            0,AliceBob,amount,expiry,NULL
            0,BobCarol,amount,expiry,NULL
            0,CarolDave,amount,expiry,NULL  
        """
        print(f"{self.path_id_},{self.channel_name_},{self.htlc_amount_msat_},{self.htlc_expiry_},{self.tlv_}")

class Route:

    channels_ = []

    def __init__(self, file_path):
        with open(file_path, newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                hop = Channel(row['path_id'], row['channel_name'], row['cltv_delta'], 
                                  row['base_fee_msat'], row['proportional_fee_ppm'])
                self.channels_.append(hop)

    def print(self):
        for channel in self.channels_:
            channel.print()

    def print_htlc(self):
        for channel in self.channels_:
            channel.print_htlc()