#
#  invoice.py
#  itornaza@gmail.com
#

import bolt11

class Invoice:

    payment_secret_: str 
    amount_msat_: int 
    min_final_cltv_expiry_: int 

    def __init__(self, invoice: str):
        invoice_decoded = bolt11.decode(invoice)
        self.payment_secret_ = str(invoice_decoded.payment_secret)
        self.amount_msat_ = int(invoice_decoded.amount_msat)
        self.min_final_cltv_expiry_ = int(invoice_decoded.min_final_cltv_expiry)
        
    def get_amount(self):
        return self.amount_msat_
  
    def get_min_cltv(self):
        return self.min_final_cltv_expiry_
  
    def get_secret(self):
        return self.payment_secret_
