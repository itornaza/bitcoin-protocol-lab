#
#  channel.py
#  itornaza@gmail.com
#

class Channel:

    path_id_: int 
    channel_name_: str 
    cltv_delta_: int 
    base_fee_msat_: int 
    proportional_fee_ppm_: int 
    htlc_amount_msat_: int 
    htlc_expiry_: int 
    tlv_: str
    
    def __init__(self, path_id, channel_name, cltv_delta, base_fee_msat, 
                 proportional_fee_ppm):
        self.path_id_ = path_id
        self.channel_name_ = channel_name
        self.cltv_delta_ = cltv_delta
        self.base_fee_msat_ = base_fee_msat
        self.proportional_fee_ppm_ = proportional_fee_ppm
        self.htlc_amount_msat_ = 0
        self.htlc_expiry_ = 0
        self.tlv_ = "NULL"

    def get_cltv_delta(self) -> int:
        return self.cltv_delta_

    def get_amount(self) -> int:
        return self.htlc_amount_msat_

    def get_fees(self, amount: int) -> int:
        return self.base_fee_msat_ + amount * self.proportional_fee_ppm_ // 1000000

    def get_expiry(self) -> int:
        return self.htlc_expiry_
        
    def set_expiry(self, expiry: int):  
        self.htlc_expiry_ = expiry

    def set_amount(self, amount: int):
        self.htlc_amount_msat_ = amount    

    def set_tlv(self, secret: str, amount: int, type: int = 8):
        tlv_type: bytes = type.to_bytes(8, 'big')
        tlv_body: bytes = bytes.fromhex(secret) + amount.to_bytes(8, 'big')
        length: int = len(tlv_body)
        tlv_body_length: bytes = length.to_bytes(8)
        tlv: bytes = tlv_type + tlv_body_length + tlv_body
        self.tlv_ = tlv.hex()

    def print(self): 
        print(f"{self.path_id_},{self.channel_name_},{self.htlc_amount_msat_},{self.htlc_expiry_},{self.tlv_}")
