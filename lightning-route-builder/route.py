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
        # The minimum expiry is set by the height and the receivers min ctlv
        expiry = height + min_ctlv
        
        # The route is trasversed in reverse order starting from the receiver
        # to the payee and ctlv_delta is accumulated
        for i in range(len(self.channels_) - 1, -1, -1):
            
            # Set the expiration to the current channel
            self.channels_[i].set_expiry(expiry)
            
            # Update the expiry to feed as a base for the next channels calculations
            expiry = self.channels_[i].get_expiry()

    def set_amount(self, amount: int):
        """ Calculates the htlc fees for the channel. The calculatioin excludes
            the first channel (in normal order) because the payee is a node of 
            this channel and does not pay fees for its use """
        # We start from the amount from the invoice and add fees on top of it
        amount_with_fees = amount
        
        # The route is trasversed in reverse order starting from the receiver
        # to the payee and fees are accumulated
        for i in range(len(self.channels_) - 1, -1, -1):

            # Set the fees to the current channel
            self.channels_[i].set_amount(amount_with_fees)

            # Update the running total to use in the next channel
            amount_with_fees = self.channels_[i].get_amount()

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
