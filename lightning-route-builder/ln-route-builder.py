#
# ln-route-builder.py
# itornaza@gmail.com  
#
# Produce the HTLC values for a given route
#

import sys
from invoice import Invoice
from mpp import MPP

def print_arguments():
    print(f"Input File Path: {input_file_path}")
    print(f"Payment Request bech32: {payment_request_bech32}")
    print(f"Current Block Height: {current_block_height}")

if __name__ == "__main__":
    # Get the parameters passed from run.sh
    if len(sys.argv) == 4:    
        # Absolute path to a csv file containing a set of hops in a lightning network route
        input_file_path = sys.argv[1]
        # bech32-encoded regtest payment request, which provides the details of the payment to be made over the route
        payment_request_bech32 = sys.argv[2]        
        # Current block height, expressed as a uint32
        current_block_height = sys.argv[3]    
    else:
        raise Exception("ln-route-builder.py requires exactly 3 arguments")
    
    # Get the MPP containing all the routes
    mpp = MPP(input_file_path)

    # Get payment information from the invoice
    invoice = Invoice(payment_request_bech32)
    expiry = invoice.get_min_final_cltv_expiry()
    amount_msat = invoice.get_amount_msat()
    payment_secret = invoice.get_payment_secret()
    
    # Split the amount to send with each route in the MPP
    amount = int(amount_msat) / int(mpp.length())

    # Do the HTLV calculations for all the routes and print the results
    for route in mpp.routes_:
        route.calculate_htlc_expiry(current_block_height, expiry)
        route.calculate_htlc_fee(amount)
        route.calculate_tlv(payment_secret, amount_msat)
        route.print_htlc()
