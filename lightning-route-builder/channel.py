#
#  channel.py
#  itornaza@gmail.com
#

# Constants
BIG_ENDIAN: str = "big"

class Channel:
    
    #---------------
    # Variables
    #---------------

    path_id_: int = 0
    channel_name_: str = ""
    cltv_delta_: int = 0
    base_fee_msat_: int = 0
    proportional_fee_ppm_: int = 0
    htlc_amount_msat_: int = 0
    htlc_expiry_: int = 0
    tlv_: str = "NULL"

    #---------------
    # Constructor
    #---------------
    def __init__(self, path_id, channel_name, cltv_delta, base_fee_msat, 
                 proportional_fee_ppm):
        self.path_id_ = int(path_id)
        self.channel_name_ = str(channel_name)
        self.cltv_delta_ = int(cltv_delta)
        self.base_fee_msat_ = int(base_fee_msat)
        self.proportional_fee_ppm_ = int(proportional_fee_ppm)

    #---------------
    # Accessors
    #---------------

    def get_amount(self):
        return self.htlc_amount_msat_

    def get_expiry(self):
        return self.htlc_expiry_
    
    #---------------
    # Mutators
    #---------------
        
    def set_expiry(self, prev_expiry: int):  
        """ Using the routing policies of the channels provided, produce the 
            values for the HTLCs that will be used to make a payment for the 
            amount and block height provided """
        self.htlc_expiry_ = self.cltv_delta_ + prev_expiry

    def set_amount(self, amount: int):
        """ Calculates fees as described in bolt7, using integer division. 
            Assuming that payment requests will always have a non-zero amount
            specified. Takes into account accumulated amount with fees from other 
            channels on top of it. """
        self.htlc_amount_msat_ = amount + \
                                 self.base_fee_msat_ + \
                                 amount * self.proportional_fee_ppm_ // 1000000        

    def set_tlv(self, secret: str, amount: int):
        """ Constructs and serializes the tlv """
        amount_msat_bytes = amount.to_bytes(8, byteorder=BIG_ENDIAN)
        tlv_type_and_length= int(8).to_bytes(8)
        tlv_body = bytes.fromhex(secret) + amount_msat_bytes
        tlv_body_length = len(tlv_body).to_bytes(8)
        tlv = tlv_type_and_length + tlv_body_length + tlv_body
        self.tlv_ = tlv.hex()

    #---------------
    # Output
    #---------------

    def print(self): 
        """ Output the HTLC values for each hop to stdout and trim all 
            whitespaces """
        print(f"{self.path_id_},{self.channel_name_},{self.htlc_amount_msat_},{self.htlc_expiry_},{self.tlv_}")
