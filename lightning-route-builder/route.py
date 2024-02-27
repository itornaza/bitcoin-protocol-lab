#
#  route.py
#  itornaza@gmail.com
#

from channel import Channel

class Route:
    
    #---------------
    # Variables
    #---------------

    channels_: list[Channel] = [] # List of channels contained in this route

    #---------------
    # Constructor
    #---------------

    def __init__(self):
        self.channels_ = []

    #---------------
    # Mutators
    #---------------
        
    def set_expiry(self, height: int, min_ctlv: int):
        """ Calculates the expiry of the channel. The last channel (in normal 
            order) does not add the ctlv_delta to the calculation because it 
            will not forward the payment to another channel """
        expiry = height + min_ctlv
        for i in range((len(self.channels_) - 1), -1, -1):
            self.channels_[i].set_expiry(expiry)
            expiry += self.channels_[i].get_cltv_delta()

    def set_amount(self, amount: int):
        """ Calculates the htlc fees for the route. The calculatioin excludes
            the first channel (in normal order) because the payee is a node of 
            this channel and does not pay fees for its use """
        for i in range((len(self.channels_) - 1), -1, -1):
            self.channels_[i].set_amount(amount)
            amount += self.channels_[i].get_fees(amount)

    def set_tlv(self, secret: str, amount: int):
        """ The tlv value gets assigned to the last channel of the route """
        self.channels_[len(self.channels_) - 1].set_tlv(secret, amount)
        
    def append(self, channel: Channel):
        self.channels_.append(channel)

    #---------------
    # Output
    #---------------
    
    def print(self):
        for channel in self.channels_:
            channel.print()
