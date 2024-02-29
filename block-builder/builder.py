#
# builder.py
# itornaza@gmail.com  
#

from operator import attrgetter

# Constants
DEBUG: bool = False
MAX_BLOCK_SIZE: int = 4000000
MEMPOOL_PATH_DEV: str = "../../mempool.csv"
MEMPOOL_PATH: str = "mempool.csv"
OUTPUT_PATH: str = "../block.txt"

class MempoolTransaction():
    def __init__(self, txid, fee, weight, parents):
        self.txid = txid
        self.fee = int(fee)
        self.weight = float(weight)
        self.parents = parents.split(';')
        self.rate = self.fee / self.weight

def parse_mempool_csv(path):
    """Parse the CSV file and return a list of MempoolTransactions."""
    with open(path) as f:
        return [MempoolTransaction(*line.strip().split(',')) for line in f.readlines()]

def dump(mempool):
    """Dump the contents of the mempool for debuging"""
    for tx in mempool:
        print(tx.txid, " ", 
              tx.fee, " ", 
              tx.weight, " ", 
              tx.parents, " ",
              tx.rate)

def get_parents(txid, mempool):
    """Get the parents list for a given txid of the mempool"""
    for tx in mempool:
        if tx.txid == txid:
            if DEBUG: print(tx.parents)
            return tx.parents

def erase_output_file():
    """Erase the contents of the file for a fresh run"""
    with open(OUTPUT_PATH, 'w') as file: 
        pass

def print_to_file(txid):
    """Append a txid in the file"""
    with open(OUTPUT_PATH, 'a') as f:  # Appending to the file
        f.write(f"{txid}\n")

def get_max_rates(mempool):
    ordered_mempool = sorted(mempool, key=attrgetter('rate'), reverse=True)
    
    block_reward: int = 0
    block_weight: int = 0
    skipped: int = 0
    added: int = 0
    
    for tx in ordered_mempool:
        if (block_weight + tx.weight) <= MAX_BLOCK_SIZE:
            if tx.parents == ['']:
                block_reward += tx.fee
                block_weight += tx.weight
                print_to_file(tx.txid)
                added += 1
            else:
                skipped += 1

    if DEBUG: 
        print("Block reward: ", block_reward)
        print("Block weight: ", block_weight)
        print("Added: ", added)
        print("Skipped: ", skipped) 
    
    return block_reward

if __name__ == "__main__":
    path = MEMPOOL_PATH
    erase_output_file()
    mempool = parse_mempool_csv(path)
    block_reward = get_max_rates(mempool)
