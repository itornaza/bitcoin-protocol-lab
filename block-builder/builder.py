#
# builder.py
# itornaza@gmail.com  
#

from operator import attrgetter
from collections import Counter
import sys

DEBUG: bool = False
VERBOSE: bool = False

MAX_BLOCK_SIZE: int = 4000000

MEMPOOL_PATH: str = "mempool.csv"
OUTPUT_PATH: str = "block.txt"

class MempoolTransaction():
    def __init__(self, txid, fee, weight, parents):
        self.txid = txid
        self.fee = int(fee)
        self.weight = float(weight)
        self.parents = parents.split(';')
        self.rate = self.fee / self.weight
        self.mined = False

def parse_mempool_csv(path) -> list[MempoolTransaction]:
    """ Parse the CSV file and return a list of MempoolTransactions """
    with open(path) as f:
        return [MempoolTransaction(*line.strip().split(',')) for line in f.readlines()]

def erase_output_file():
    """ Erase the contents of the file for a fresh run """
    with open(OUTPUT_PATH, 'w') as file: 
        pass

def print_to_file(txid):
    """ Append a txid in the file """
    with open(OUTPUT_PATH, 'a') as f:
        f.write(f"{txid}\n")

def print_metrics(block_reward, block_weight, singles, families):
    print("Block reward: ", block_reward)
    print("Block weight: ", block_weight)
    print("Singles: ", singles)
    print("Families: ", families) 

def test_find_duplicates(filename):
    """ Test that there are no duplicates in the given file """
    word_counts = Counter()
    with open(filename, 'r') as file:
        for line in file:
            words = line.split()
            word_counts.update(words)
    duplicates = [word for word, count in word_counts.items() if count > 1]
    if duplicates:
        raise Exception("Duplicates found")

def get_family(txid: str, mempool: list[MempoolTransaction]) -> list[MempoolTransaction]:
    """ Returns the family list for a given txid of the mempool in ascending order i.e.
        Ancestors first, childern later, contains the given txid as well

                            (ancestor) G
                                       |
                                / D1 - E1 (child)
        (ancestor)  A -> B -> C     
                                \ D2 - E2 - F2 (child)
                                   |                  
                    (ancestor) I - H
    """
    stack: list[str] = [txid]
    family: list[MempoolTransaction] = []
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

def build_block(mempool: list[MempoolTransaction]) -> int:
    """ Fills the block.txt file with a selection of transactions with the goal 
        of maximizing the fee for the miner """
    block_reward: int = 0
    block_weight: int = 0
    singles: int = 0    
    families: int = 0
    factor: float = 0.3
    
    ordered_mempool = sorted(mempool, key=attrgetter('rate'), reverse=True)
    for tx in ordered_mempool:
        if (block_weight + tx.weight) <= MAX_BLOCK_SIZE:
            if (tx.parents == ['']) and (tx.mined == False):
                
                # The tx is a singleton and has not been yet included
                tx.mined = True
                block_reward += tx.fee
                block_weight += tx.weight
                print_to_file(tx.txid)
                if VERBOSE: print(tx.txid)
                singles += 1

            else:
                
                # The tx belongs to a family
                collective_fee: float = 0
                collective_weight: float = 0
                acceptable_rate: bool = True
                
                # Get all the members of family inclusive
                family = get_family(tx.txid, mempool)
                
                # Calculate fees and weights of the unmined members
                for f in family:
                    if f.mined == False:
                        collective_fee += f.fee
                        collective_weight += f.weight

                # Brutal optimization decides whether the family deserves inclusion.
                # If the unmined family members have a very low rate compared to 
                # the current transaction, we do not accept it
                if collective_weight != 0:
                    collective_rate = collective_fee / collective_weight
                    if collective_rate < (tx.rate * factor):
                        acceptable_rate = False

                # If we have space for all the family
                if (block_weight + collective_weight) <= MAX_BLOCK_SIZE and \
                    acceptable_rate:
                    
                    # Include the unmined members in the block
                    for f in family:
                        if f.mined == False:
                            f.mined = True
                            block_reward += f.fee
                            block_weight += f.weight
                            print_to_file(f.txid)
                            if VERBOSE: print(f.txid)

                    families += 1

    if DEBUG: print_metrics(block_reward, block_weight, singles, families)
    return block_reward

if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else MEMPOOL_PATH

    erase_output_file()
    mempool = parse_mempool_csv(path)
    block_reward = build_block(mempool)
    if DEBUG: test_find_duplicates(OUTPUT_PATH)
