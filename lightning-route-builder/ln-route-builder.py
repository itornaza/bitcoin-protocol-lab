#
#  ln-route-builder.py
#  itornaza@gmail.com  
#

import sys
from invoice import Invoice
from mpp import MPP

ARGV_ERROR: str = "ln-route-builder.py requires exactly 3 arguments"

if __name__ == "__main__":

    if len(sys.argv) == 4:    
        path: str = sys.argv[1]
        payment: str = sys.argv[2]        
        height: int = int(sys.argv[3])
    else:
        raise Exception(ARGV_ERROR)
    
    inv = Invoice(payment)
    mpp = MPP(path, height, inv.get_secret(), inv.get_amount(), inv.get_min_cltv())
    mpp.print()
