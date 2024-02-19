#
#  ln-route-builder.py
#  itornaza@gmail.com  
#

import sys
from invoice import Invoice
from mpp import MPP

if __name__ == "__main__":
    
    # Grab the parameters passed from run.sh
    if len(sys.argv) == 4:    
        
        # Absolute path to a csv file containing a set of hops in a lightning 
        # network route
        file_path = sys.argv[1]
        
        # bech32-encoded regtest payment request, which provides the details 
        # of the payment to be made over the route
        payment_request = sys.argv[2]        
        
        # Current block height, expressed as a uint32
        height = sys.argv[3]    

    else:
        raise Exception("ln-route-builder.py requires exactly 3 arguments")

    # Get the MPP containing all the routes and how many they are
    mpp = MPP(file_path)
    n_routes = mpp.length()

    # Get payment information from the invoice
    invoice = Invoice(payment_request)
    amount_msat = invoice.get_amount()
    expiry = invoice.get_min_cltv()
    payment_secret = invoice.get_secret()
    
    # Split the amount to send with each route in the MPP
    # Under the assumptionn that the amount will be divisible from the number 
    # of routes (enforcing the assuption with integet division)
    amount = int(amount_msat) // int(n_routes)

    # Do the HTLV calculations for all the routes and display the results
    for route in mpp.routes_:
        route.calculate_htlc_expiry(height, expiry)
        route.calculate_htlc_fee(amount)
        
        # If we have an MPP with more than one routes, add the tlv
        if n_routes > 1: 
            route.calculate_tlv(payment_secret, amount_msat)
        
        route.print_htlc()
