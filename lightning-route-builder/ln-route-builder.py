#
# ln-route-builder.py
# itornaza@gmail.com  
#
# - Produce the HTLC values for a given route.
#

import sys # argv
import bolt11 # parse payment requests
from network import Channel, Route # my classes

DEBUG = False

def print_arguments():
    print(f"Input File Path: {input_file_path}")
    print(f"Payment Request bech32: {payment_request_bech32}")
    print(f"Current Block Height: {current_block_height}")

def get_amount_from_invoice(invoice: str):
    invoice_decoded = bolt11.decode(invoice)    
    return invoice_decoded.amount_msat

# 2. Calculate fees as described in bolt7, using integer division
# Assuming that payment requests will always have a non-zero amount specified
def get_fees():
    pass

# 3. Obtain payment details (such as payment amount and minimum final CLTV delta) 
# from the payment request
def get_payment_details():
    pass

if __name__ == "__main__":
   
    # 1. Get the parameters passed from run.sh
    if len(sys.argv) == 4:    
        
        # 1. Absolute path to a csv file containing a set of hops in a lightning network route
        input_file_path = sys.argv[1]
        
        # 2. bech32-encoded regtest payment request, which provides the details of the payment to be made over the route
        payment_request_bech32 = sys.argv[2]        
        
        # 3. Current block height, expressed as a uint32
        current_block_height = sys.argv[3]    
    
    else:
        raise Exception("ln-route-builder.py requires exactly 3 arguments")
    
    if DEBUG: print_arguments()
    
    route = Route(input_file_path, current_block_height)
    amount = get_amount_from_invoice(payment_request_bech32)
    route.calculate_htlc_expiry()
    route.calculate_htlc_fee(amount)
    route.print_htlc()


