#
# builder.py
# itornaza@gmail.com  
#

from operator import attrgetter
from collections import Counter

DEBUG: bool = False
VERBOSE: bool = False
MAX_BLOCK_SIZE: int = 4000000
MEMPOOL_PATH_DEV: str = "../../mempool.csv"
MEMPOOL_PATH_TEST: str = "../../test_mempool.csv"
MEMPOOL_PATH: str = "mempool.csv"
OUTPUT_PATH: str = "../block.txt"

class MempoolTransaction():
    def __init__(self, txid, fee, weight, parents):
        self.txid = txid
        self.fee = int(fee)
        self.weight = float(weight)
        self.parents = parents.split(';')
        self.rate = self.fee / self.weight
        self.mined = False

def parse_mempool_csv(path):
    """ Parse the CSV file and return a list of MempoolTransactions """
    with open(path) as f:
        return [MempoolTransaction(*line.strip().split(',')) for line in f.readlines()]

def dump(mempool):
    """ Dump the contents of the mempool for debuging """
    for tx in mempool:
        print(tx.txid, " ", tx.fee, " ", tx.weight, " ", tx.parents, " ", tx.rate)

def get_family(txid, mempool) -> list[MempoolTransaction]:
    """ Get the family list for a given txid of the mempool in order, contains the
        given txid as well as a family member

                            (ancestor) G
                                       |
                                / D1 - E1 (child)
        (ancestor)  A -> B -> C     
                                \ D2 - E2 - F2 (child)
                                   |                  
                    (ancestor) I - H
    """
    stack = [txid]
    family = []
    while len(stack) > 0:
        txid = stack.pop(0)
        for tx in mempool:
            if tx.txid == txid:
                for p in tx.parents:
                    stack.insert(0, p)
                    if tx not in family:
                        family.insert(0, tx)
            continue
    return family

def remove_duplicates(list) -> list:
    seen = set()
    result = []
    for item in list:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result

def erase_output_file():
    """ Erase the contents of the file for a fresh run """
    with open(OUTPUT_PATH, 'w') as file: 
        pass

def print_to_file(txid):
    """ Append a txid in the file """
    with open(OUTPUT_PATH, 'a') as f:  # Appending to the file
        f.write(f"{txid}\n")

def get_max_rates(mempool):
    block_reward: int = 0
    block_weight: int = 0
    singles: int = 0
    families: int = 0
    
    ordered_mempool = sorted(mempool, key=attrgetter('rate'), reverse=True)
    for tx in ordered_mempool:

        # Check whether a tx fits in our block
        if (block_weight + tx.weight) <= MAX_BLOCK_SIZE:
            
            # If the tx is a singleton and has not been yet included
            if (tx.parents == ['']) and (tx.mined == False):
                tx.mined = True
                block_reward += tx.fee
                block_weight += tx.weight
                print_to_file(tx.txid)
                if VERBOSE: print(tx.txid)
                singles += 1
            
            else:
                collective_fee: float = 0
                collective_weight: float = 0
                acceptable_rate: bool = True
                
                # Get all the family including the tx
                family = get_family(tx.txid, mempool)
                for f in family:

                    # Calculate fees and weights of the unmined members
                    if f.mined == False:
                        collective_fee += f.fee
                        collective_weight += f.weight

                # Optimization option: Decide whether the family deserves inclusion in the block
                if collective_weight != 0:
                    collective_rate = collective_fee / collective_weight
                    if collective_rate < tx.rate * 0.2:
                        acceptable_rate = False

                # If we still have space for all the family
                if (block_weight + collective_weight) <= MAX_BLOCK_SIZE and acceptable_rate:
                    for f in family:

                        # Include the unmined members in the block
                        if f.mined == False:
                            f.mined = True
                            block_reward += f.fee
                            block_weight += f.weight
                            print_to_file(f.txid)
                            if VERBOSE: print(f.txid)

                    families += 1

    if DEBUG: 
        print("Block reward: ", block_reward)
        print("Block weight: ", block_weight)
        print("Singles: ", singles)
        print("Families: ", families) 
    
    return block_reward

def test_find_duplicates(filename):
    word_counts = Counter()
    with open(filename, 'r') as file:
        for line in file:
            words = line.split()
            word_counts.update(words)
    duplicates = [word for word, count in word_counts.items() if count > 1]
    if duplicates:
        raise Exception("Duplicates found")

if __name__ == "__main__":
    
    # Set path = MEMPOOL_PATH and DEBUG, VERBOSE = False before submitting
    path = MEMPOOL_PATH
    
    erase_output_file()
    mempool = parse_mempool_csv(path)
    block_reward = get_max_rates(mempool)
    if DEBUG: test_find_duplicates(OUTPUT_PATH)
