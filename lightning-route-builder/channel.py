#
#  channel.py
#  itornaza@gmail.com
#

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

    def get_cltv_delta(self):
        return self.cltv_delta_

    def get_amount(self):
        return self.htlc_amount_msat_

    def get_fees(self, amount: int):
        """ Calculates fees as described in bolt7, using integer division. 
            Assuming that payment requests will always have a non-zero amount
            specified """
        return self.base_fee_msat_ + amount * self.proportional_fee_ppm_ // 1000000

    def get_expiry(self):
        return self.htlc_expiry_
    
    def get_tlv(self):
        return self.tlv_
    
    #---------------
    # Mutators
    #---------------
        
    def set_expiry(self, expiry: int):  
        self.htlc_expiry_ = expiry

    def set_amount(self, amount: int):
        self.htlc_amount_msat_ = amount    

    def set_tlv(self, secret: str, amount: int):
        tlv_type_bytes = b'\x00\x00\x00\x00\x00\x00\x00\x08'
        tlv_body_bytes = bytes.fromhex(secret) + amount.to_bytes(8, 'big')
        tlv_body_length = len(tlv_body_bytes)
        tlv_body_length_bytes = tlv_body_length.to_bytes(8)
        tlv = tlv_type_bytes + tlv_body_length_bytes + tlv_body_bytes
        self.tlv_ = tlv.hex()

    def test_set_tlv(self):
        # Get object state
        orig_tlv = self.get_tlv(self)
        # Execute test
        expected = "00000000000000080000000000000028b3c3965128b05c96d76348158f8f3a1b92e2847172f9adebb400a9e83e62f0660000000000000078"
        secret = "b3c3965128b05c96d76348158f8f3a1b92e2847172f9adebb400a9e83e62f066"
        amount = 120
        self.set_tlv(self, secret, amount)
        calculated = self.get_tlv(self)
        assert calculated == expected, "TLV not as expected"
        # Reset initial object state
        self.tlv_ = orig_tlv

    #---------------
    # Output
    #---------------

    def print(self): 
        """ Output the HTLC values for each hop to stdout and trim all 
            whitespaces """
        print(f"{self.path_id_},{self.channel_name_},{self.htlc_amount_msat_},{self.htlc_expiry_},{self.tlv_}")
