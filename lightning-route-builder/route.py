#
# route.py
# itornaza@gmail.com
#

from channel import Channel

class Route:

    # List of channels contained in this route
    channels_ = []

    def __init__(self):
        self.channels_ = []

    def append(self, channel: Channel):
        self.channels_.append(channel)

    def calculate_htlc_expiry(self, height: int, min_ctlv: int):
        # Trasverse the route in the reverse order
        predecessor = int(height) + int(min_ctlv)
        for i in range(len(self.channels_) - 1, -1, -1):
            self.channels_[i].calculate_htlc_expiry(predecessor)
            if i == len(self.channels_) - 1:
                # The last channel (normal order) does not add the ctlv_delta 
                # to the calculation
                self.channels_[i].htlc_expiry_ -= int(self.channels_[i].cltv_delta_)
            predecessor = self.channels_[i].htlc_expiry_

    def calculate_htlc_fee(self, amount: int):
        # Trasverse the route in the reverse order
        for i in range(len(self.channels_) - 1, -1, -1):
            self.channels_[i].calculate_htlc_fee(amount)
            amount = self.channels_[i].htlc_amount_msat_
            if i == 0:
                # Exclude the last channel because we do not pay any fees for it
                self.channels_[i].htlc_amount_msat_ = self.channels_[i+1].htlc_amount_msat_

    def calculate_tlv(self, payment_secret: str, amount_msat: int):
        """ The tlv value gets assigned to the last channel of the route """
        amount_msat_bytes = amount_msat.to_bytes(8, byteorder='big')
        self.channels_[len(self.channels_) - 1].tlv_ = payment_secret + amount_msat_bytes.hex()

    def print_htlc(self):
        for channel in self.channels_:
            channel.print_htlc()

    def print(self):
        for channel in self.channels_:
            channel.print()