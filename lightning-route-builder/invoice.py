#
#  invoice.py
#  itornaza@gmail.com
#

import bolt11

class Invoice:
    
    #---------------
    # Variables
    #---------------

    amount_msat_: int = 0
    min_final_cltv_expiry_: int = 0
    payment_secret_: int = 0
    amount_msat_: int = 0
    
    #---------------
    # Constructor
    #---------------

    def __init__(self, invoice: str):
        invoice_decoded = bolt11.decode(invoice)
        self.amount_msat_ = invoice_decoded.amount_msat
        self.min_final_cltv_expiry_ = invoice_decoded.min_final_cltv_expiry
        self.payment_secret_ = invoice_decoded.payment_secret

    #---------------    
    # Accessors
    #---------------
        
    def get_amount(self):
        return self.amount_msat_
  
    def get_min_cltv(self):
        return self.min_final_cltv_expiry_
  
    def get_secret(self):
        return self.payment_secret_
