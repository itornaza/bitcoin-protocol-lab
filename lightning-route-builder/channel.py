#
#  channel.py
#  itornaza@gmail.com
#

class Channel:
    
    # path_id: a uint32 used in MPP
    path_id_ = int(0)
    
    # channel_name: a string identifying the channel
    channel_name_ = ""
    
    # cltv_delta: a uint32 representing the required delta for the hop
    cltv_delta_ = int(0)

    # base_fee_msat: a uint64 fee expressed in millisatoshis charged 
    # per-htlc that uses the channel as an outgoing hop
    base_fee_msat_ = int(0)
    
    # proportional_fee_ppm: a uint64 representing the parts per million 
    # proportional fee on the htlc's amount charged to use the channel as 
    # an outgoing hop
    proportional_fee_ppm_ = int(0)
    
    # htlc_amount_msat: a uint64 representing the htlc amount on that channel
    htlc_amount_msat_ = int(0)

    # htlc_expiry: a uint32 representing the expiry height of the htlc
    htlc_expiry_ = int(0)

    # tlv: a string, hardcoded to NULL
    tlv_ = "NULL"

    def __init__(self, path_id, channel_name, cltv_delta, base_fee_msat, 
                 proportional_fee_ppm):
        self.path_id_ = path_id
        self.channel_name_ = channel_name
        self.cltv_delta_ = cltv_delta
        self.base_fee_msat_ = base_fee_msat
        self.proportional_fee_ppm_ = proportional_fee_ppm

    def calculate_htlc_expiry(self, prev_expiry: int):  
        """ Using the routing policies of the channels provided, produce the 
            values for the HTLCs that will be used to make a payment for the 
            amount and block height provided """
        self.htlc_expiry_ += int(self.cltv_delta_) + int(prev_expiry)

    def calculate_htlc_fee(self, amount_to_forward: int, total_amount: int):
        """ Calculates fees as described in bolt7, using integer division. 
            Assuming that payment requests will always have a non-zero amount
            specified. Takes into account ACCUMULATED amount from other channels:
            total_amount + base_fee_msat + amount_to_forward * ppm / 1000000 """
        self.htlc_amount_msat_ = int(total_amount) + \
                                 int(self.base_fee_msat_) + \
            int(amount_to_forward) * int(self.proportional_fee_ppm_) // int(1000000)

    def print(self):
        print(f"{self.path_id_},{self.channel_name_},{self.cltv_delta_},{self.base_fee_msat_},{self.proportional_fee_ppm_}")

    def print_htlc(self): 
        """ Output the HTLC values for each hop to stdout and trim all 
            whitespaces """
        print(f"{self.path_id_},{self.channel_name_},{self.htlc_amount_msat_},{self.htlc_expiry_},{self.tlv_}")
