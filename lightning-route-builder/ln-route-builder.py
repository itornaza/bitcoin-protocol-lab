#
#  ln-route-builder.py
#  itornaza@gmail.com  
#

import sys
from invoice import Invoice
from mpp import MPP

# Constants
ARGV_ERROR: str = "ln-route-builder.py requires exactly 3 arguments"

if __name__ == "__main__":
    
    # 1. Grab the parameters passed from run.sh
    if len(sys.argv) == 4:    
        file_path = sys.argv[1]
        payment_request = sys.argv[2]        
        height = int(sys.argv[3])
    else:
        raise Exception(ARGV_ERROR)

    # 2. Get payment information
    invoice = Invoice(payment_request)
    expiry = invoice.get_min_cltv()
    secret = invoice.get_secret()
    invoice_amount = invoice.get_amount()
    
    # 3. Create MPP and print results
    mpp = MPP(file_path, height, expiry, secret, invoice_amount)
    mpp.print()
