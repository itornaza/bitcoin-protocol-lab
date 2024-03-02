#
#  route.py
#  itornaza@gmail.com
#

from channel import Channel

class Route:

    channels_: list[Channel]

    def __init__(self):
        self.channels_ = []

    def set_htlc(self, height, amount, min_cltv):
        expiry: int = height + min_cltv
        for i in range((len(self.channels_) - 1), -1, -1):
            self.channels_[i].set_amount(amount)
            amount += self.channels_[i].get_fees(amount)
            self.channels_[i].set_expiry(expiry)
            expiry += self.channels_[i].get_cltv_delta()

    def set_tlv(self, secret: str, amount: int):
        self.channels_[len(self.channels_) - 1].set_tlv(secret, amount)
        
    def append(self, channel: Channel):
        self.channels_.append(channel)
    
    def print(self):
        for channel in self.channels_:
            channel.print()
