#
#  route.py
#  itornaza@gmail.com
#

from channel import Channel

class Route:

    channels_: list[Channel]

    def __init__(self):
        self.channels_ = []
        
    def set_expiry(self, height: int, min_ctlv: int):
        expiry: int = height + min_ctlv
        for i in range((len(self.channels_) - 1), -1, -1):
            self.channels_[i].set_expiry(expiry)
            expiry += self.channels_[i].get_cltv_delta()

    def set_amount(self, amount: int):
        for i in range((len(self.channels_) - 1), -1, -1):
            self.channels_[i].set_amount(amount)
            amount += self.channels_[i].get_fees(amount)

    def set_tlv(self, secret: str, amount: int):
        self.channels_[len(self.channels_) - 1].set_tlv(secret, amount)
        
    def append(self, channel: Channel):
        self.channels_.append(channel)
    
    def print(self):
        for channel in self.channels_:
            channel.print()
