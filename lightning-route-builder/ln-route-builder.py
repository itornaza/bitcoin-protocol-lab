#
# ln-route-builder.py
# itornaza@gmail.com  
#
# - Produce the HTLC values for a given route.
#

import sys # argv
import bolt11 # parse payment requests

DEBUG = True

class Hop:
    def __init__(self, path_id, channel_name, cltv_delta, base_fee_msat, proportional_fee_ppm):
        self.path_id = path_id
        self.channel_name = channel_name
        self.cltv_delta = cltv_delta
        self.base_fee_msat = base_fee_msat
        self.proportional_fee_ppm = proportional_fee_ppm

    def print(self):
        print(f"{self.path_id},{self.channel_name},{self.cltv_delta},{self.base_fee_msat},{self.proportional_fee_ppm}")

    # Output the HTLC values for each hop to stdout 
    # path_id: a uint32, hardcoded to 0 for this step
    # channel_name: the string identifying the channel
    # htlc_amount_msat: a uint64 representing the htlc amount on that channel
    # htlc_expiry: a uint32 representing the expiry height of the htlc
    # tlv: a string, hardcoded to NULL
    # - Sample output (trim all whitespace)
    #   0,AliceBob,amount,expiry,NULL
    #   0,BobCarol,amount,expiry,NULL
    #   0,CarolDave,amount,expiry,NULL    
    def print_output(self):
        print(f"{self.path_id},{self.channel_name},{self.htlc_amount_msat},{self.htlc_expiry},{self.tlv}")

def print_arguments():
    print(f"Input File Path: {input_file_path}")
    print(f"Payment Request bech32: {payment_request_bech32}")
    print(f"Current Block Height: {current_block_height}")

def parse_csv(file_path):
    """Parse a CSV file and return a list of Hops"""
    hops = [Hop]

    # TODO: load the hop with the appropriate class members

    with open(file_path) as f:
        hops.append(Hop(*line.strip().split(',')) for line in f.readlines())
    # Discard the header line
    return hops[1:]

# Use the routing policies of the hops provided to produce the values for the 
# HTLCs that will be used to make a payment for the amount and block height 
# provided
def get_htlc_values():
    pass

# Calculate fees as described in bolt7, using integer division
# Assuming that payment requests will always have a non-zero amount specified
def get_fees():
    pass

# Obtain payment details (such as payment amount and minimum final CLTV delta) 
# from the payment request
def get_payment_details():
    pass

if __name__ == "__main__":
   
    # 1. Get the parameters passed from run.sh
    if len(sys.argv) == 4:    
        # Absolute path to a csv file containing a set of hops in a lightning network route
        input_file_path = sys.argv[1]
        # bech32-encoded regtest payment request, which provides the details of the payment to be made over the route
        payment_request_bech32 = sys.argv[2]        
        # Current block height, expressed as a uint32
        current_block_height = sys.argv[3]    
    else:
        raise Exception("ln-route-builder.py requires exactly 3 arguments")
    
    if DEBUG: print_arguments()
    
    hops = parse_csv(input_file_path)
    for hop in hops:
        hop.print()
    
    


