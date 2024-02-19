#
#  route.py
#  itornaza@gmail.com
#

from channel import Channel

# Constants
BIG_ENDIAN = "big"

class Route:
    
    channels_ = [] # List of channels contained in this route

    def __init__(self):
        self.channels_ = []

    def calculate_htlc_expiry(self, height: int, min_ctlv: int):
        """ Calculates the expiry of the channel. The last channel (in normal 
            order) does not add the ctlv_delta to the calculation because it 
            will not forward the payment to another channel """
        # The minimum expiry is set by the height and the receivers min ctlv
        expiry = int(height) + int(min_ctlv)
        
        # The route is trasversed in reverse order starting from the receiver
        # to the payee and ctlv_delta is accumulated
        for i in range(len(self.channels_) - 1, -1, -1):
            
            # Set the expiration to the current channel
            self.channels_[i].calculate_htlc_expiry(expiry)
            
            # Update the expiry to feed as a base for the next channels calculations
            expiry = self.channels_[i].htlc_expiry_

    def calculate_htlc_fee(self, amount_to_forward: int):
        """ Calculates the htlc fees for the channel. The calculatioin excludes
            the first channel (in normal order) because the payee is a node of 
            this channel and does not pay fees for its use """
        # We start from the amount to forward and add all fees on top of it
        total_amount = amount_to_forward
        
        # The route is trasversed in reverse order starting from the receiver
        # to the payee and fees are accumulated
        for i in range(len(self.channels_) - 1, -1, -1):

            # Set the fees to the current channel
            self.channels_[i].calculate_htlc_fee(amount_to_forward, total_amount)

            # Update the running total to use in the next channel
            total_amount = self.channels_[i].htlc_amount_msat_

    def calculate_tlv(self, payment_secret: str, amount_msat: int):
        """ The tlv value gets assigned to the last channel of the route """
        amount_msat_bytes = amount_msat.to_bytes(8, byteorder=BIG_ENDIAN)
        self.channels_[len(self.channels_) - 1].tlv_ = payment_secret + amount_msat_bytes.hex()

    def append(self, channel: Channel):
        self.channels_.append(channel)

    def print_htlc(self):
        for channel in self.channels_:
            channel.print_htlc()

    def print(self):
        for channel in self.channels_:
            channel.print()
