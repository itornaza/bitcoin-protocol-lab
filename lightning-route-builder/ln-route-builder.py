#
#  ln-route-builder.py
#  itornaza@gmail.com  
#

import sys
from invoice import Invoice
from mpp import MPP
from channel import Channel

# Constants
ARGV_ERROR: str = "ln-route-builder.py requires exactly 3 arguments"
RUN_TESTS: bool = False

def test_suite():
    Channel.test_set_tlv(Channel)

if __name__ == "__main__":
    
    # 0. Optionally run some basic tests first
    if RUN_TESTS: 
        test_suite()

    # 1. Grab the parameters passed from run.sh
    if len(sys.argv) == 4:    
        file_path: str = sys.argv[1]
        payment_request: str = sys.argv[2]        
        height: int = int(sys.argv[3])
    else:
        raise Exception(ARGV_ERROR)

    # 2. Get payment information
    inv = Invoice(payment_request)
    
    # 3. Create MPP 
    mpp = MPP(file_path, height, inv.get_secret(), inv.get_amount(), 
              inv.get_min_cltv())
    
    # 4. Print results
    mpp.print()
