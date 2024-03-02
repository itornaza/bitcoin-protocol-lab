from decimal import Decimal
from ecdsa import SigningKey, SECP256k1
from subprocess import run
from typing import List, Tuple
import hashlib
import hmac
import json




#--------------
# Constants
#--------------

DEBUG: bool = False

WALLET_NAME: str = "wallet_201"
EXTENDED_PRIVATE_KEY: str = "CHANGEME_EXTENDED_PRIVATE_KEY"
KEY_BYTE_LENGTH: int = 32
BYTE_ORDER: str = 'big'
BTC2SAT: int = 100000000

#--------------
# Utilities
#--------------

def ion_assert(calculated, expected, test_name):
    assert calculated == expected, f"calculated and expected should match\ncalculated:\n{calculated}\nexpected:\n{expected}"
    print(test_name, " - [ok]")

def ion_int_to_bytes(index: int, n_bytes: int) -> bytes:
    index_bytes = index.to_bytes(n_bytes, byteorder=BYTE_ORDER)
    return index_bytes

def hash160(pubKey: bytes) -> bytes:
    return hashlib.new('ripemd160', hashlib.sha256(pubKey).digest()).digest()

#--------------
# Functions
#--------------

# Decode a base58 string into an array of bytes
def base58_decode(base58_string: str) -> bytes:
    base58_alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    base58_length = len(base58_alphabet)

    # Convert Base58 string to a big integer
    value = 0
    for char in base58_string:
        value = value * base58_length + base58_alphabet.index(char)

    # Convert the integer to bytes
    bytes_with_checksum = bytearray()
    while value > 0:
        value, remainder = divmod(value, 256)
        bytes_with_checksum.insert(0, remainder)

    # Chop off the 32 checksum bits from the array
    result = bytes_with_checksum[:-4]

    # Get the given checksum
    checksum = bytes_with_checksum[-4:]
    
    # Calculate the checksum of the resulting byte array
    sha256_hash1 = hashlib.sha256(result).digest()
    sha256_hash2 = hashlib.sha256(sha256_hash1).digest()
    sha256_hash2 = sha256_hash2[0:4]

    # BONUS POINTS: Verify the checksum!
    if sha256_hash2 != checksum:
        raise Exception("\n->Failed: Checksums do not match!\n")

    # Resulting as bytes, should contain 78 bytes according to spec
    return bytes(result)

def test_base58_decode():
    # Test case (https://privatekeys.pw/calc)
    expected = "043583940000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001"
    calculated = base58_decode(EXTENDED_PRIVATE_KEY).hex()
    ion_assert(calculated, expected, "test_base58_decode")

# Deserialize the extended key bytes and return a JSON object
# https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#serialization-format
# 4 byte:   version bytes (mainnet: 0x0488B21E public, 0x0488ADE4 private; 
#           testnet: 0x043587CF public, 0x04358394 private)
# 1 byte:   depth: 0x00 for master nodes, 0x01 for level-1 derived keys, ....
# 4 bytes:  the fingerprint of the parent's key (0x00000000 if master key)
# 4 bytes:  child number. This is ser32(i) for i in xi = xpar/i, with xi the 
#           key being serialized. (0x00000000 if master key)
# 32 bytes: the chain code
# 33 bytes: the public key or private key data (serP(K) for public keys, 
#           0x00 || ser256(k) for private keys)
def deserialize_key(b: bytes) -> object:
    data = {
        "version": b[:4].hex(),
        "depth": b[4:5].hex(),
        "fingerprint": b[5:9].hex(),
        "child": b[9:13].hex(),
        "chain_code": b[13:45].hex(),
        "key": b[46:].hex() # Skip the leading 0x00 at the index 45
    }
    json_object = json.dumps(data)
    return json_object

def test_deserialize_key():
    # Get our own key derived data using (https://bip32jp.github.io/english/)
    pri = "CHANGEME_EXTENDED_PRIVATE_KEY"
    expected_key = "0000000000000000000000000000000000000000000000000000000000000001"
    expected_chain_code = "0000000000000000000000000000000000000000000000000000000000000000"
    # Calculate our own key
    pri = base58_decode(pri).hex()
    pri_bytes = bytes.fromhex(pri)
    json_object = deserialize_key(pri_bytes)
    data = json.loads(json_object)
    calculated_key_bytes = bytes.fromhex(data['key'])
    calculated_key = calculated_key_bytes.hex()
    calculated_chain_code = data['chain_code']
    ion_assert(calculated_chain_code, expected_chain_code, "test_deserialize_key-chain_code")
    ion_assert(calculated_key, expected_key, "test_deserialize_key-key")

# Derive the secp256k1 compressed public key from a given private key
# BONUS POINTS: Implement ECDSA yourself and multiply you key by the generator
# point!
def get_pub_from_priv(priv: bytes) -> bytes:
    signing_key = SigningKey.from_string(priv, curve=SECP256k1)
    public_key = signing_key.get_verifying_key()
    compressed_public_key = public_key.to_string("compressed") # return bytes
    return compressed_public_key

def test_get_pub_from_priv():
    # Test case (https://en.bitcoin.it/wiki/BIP_0032_TestVectors)
    pri =  bytes.fromhex("e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35")
    expected = "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2"
    calculated = get_pub_from_priv(pri).hex()
    ion_assert(calculated, expected, "test_get_pub_from_priv")

# Perform a BIP32 parent private key -> child private key operation
# Return a JSON object with "key" and "chain_code" properties as bytes
# https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#user-content-Private_parent_key_rarr_private_child_key
def derive_priv_child(key: bytes, chain_code: bytes, index: int, hardened: bool) -> object:
    # Set up the index
    index = (int(0x80000000) + index) if hardened else index
    index_bytes = ion_int_to_bytes(index, 4)

    # Prepare the data depending on the child type
    if (hardened):
        data = b'\x00' + key + index_bytes
    else:
        pub = get_pub_from_priv(key)
        data = pub + index_bytes
    output_512 = hmac.new(chain_code, data, hashlib.sha512).digest()
    
    # Right 256 bits is the chain_code
    child_chain_code = output_512[KEY_BYTE_LENGTH:]
    
    # Left 256 bits, derive the child pri
    left_256_int = int.from_bytes(output_512[:KEY_BYTE_LENGTH], byteorder=BYTE_ORDER)
    key_int = int.from_bytes(key, byteorder=BYTE_ORDER)
    child_private_key_int = (left_256_int + key_int) % SECP256k1.order
    child_private_key = child_private_key_int.to_bytes(KEY_BYTE_LENGTH, byteorder=BYTE_ORDER)

    # Prepare for json
    data = {
        "chain_code": child_chain_code.hex(),
        "key": child_private_key.hex() 
    }
    json_object = json.dumps(data)
    return json_object

def test_derive_priv_child():
    # Normal - Test vector 2 (https://en.bitcoin.it/wiki/BIP_0032_TestVectors)
    pri = bytes.fromhex("4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e")
    chain_code = bytes.fromhex("60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689")
    expected_normal = "abe74a98f6c7eabee0428f53798f0ab8aa1bd37873999041703c742f15ac7e1e"
    expected_chain_code = "f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c"
    calculated_json = derive_priv_child(pri, chain_code, 0, False)
    calculated_data = json.loads(calculated_json)
    calculated_pri = bytes.fromhex(calculated_data['key'])
    calculated_chain_code = bytes.fromhex(calculated_data['chain_code'])
    ion_assert(calculated_pri.hex(), expected_normal, "test_derive_priv_child-normal-chain_code")
    ion_assert(calculated_chain_code.hex(), expected_chain_code, "test_derive_priv_child-normal-key")
    # Hardened - Test vector 1 (https://en.bitcoin.it/wiki/BIP_0032_TestVectors)
    pri = bytes.fromhex("e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35")
    chain_code = bytes.fromhex("873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508")
    expected_hardened = "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea"
    expected_chain_code = "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141"
    calculated_json = derive_priv_child(pri, chain_code, 0, True)
    calculated_data = json.loads(calculated_json)
    calculated_pri = bytes.fromhex(calculated_data['key'])
    calculated_chain_code = bytes.fromhex(calculated_data['chain_code'])
    ion_assert(calculated_chain_code.hex(), expected_chain_code, "test_derive_priv_child-hardened-chain_code")
    ion_assert(calculated_pri.hex(), expected_hardened, "test_derive_priv_child-hardened-key")

# Given an extended private key and a BIP32 derivation path,
# compute the first 2000 child private keys.
# Return an array of keys encoded as bytes.
# The derivation path is formatted as an array of (index: int, hardened: bool) tuples.
# Notes: 
# - My example would be for `84h/1h/0h/0/*` : [(84, True), (1, True), (0, True), (0, False)]
# - The key in the function argument corresponds to the master (m)
def get_wallet_privs(key: bytes, chain_code: bytes, path: List[Tuple[int, bool]]) -> List[bytes]:
    # 1. Move through the path to locate the last parent
    current_key = key
    current_chain_code = chain_code
    for item in path:
        # Get next key to use as parent
        index, hardened = item
        
        # Get the child data
        child_json = derive_priv_child(current_key, current_chain_code, index, hardened)
        child_data = json.loads(child_json)
        
        # Update key and chain_code for the next child calculation
        current_key = bytes.fromhex(child_data['key'])
        current_chain_code = bytes.fromhex(child_data['chain_code'])

    # 2. Get the first 2000 normal children private keys of that last parent
    children_keys = []
    hardened = False
    for child_index in range(0, 2000):
        child_json = derive_priv_child(current_key, current_chain_code, child_index, hardened)
        child_data = json.loads(child_json)
        child_key = bytes.fromhex(child_data['key'])
        children_keys.append(child_key)
    return children_keys

def test_get_wallet_privs():
     # Chain m/0'/1/2'/2 - (https://en.bitcoin.it/wiki/BIP_0032_TestVectors)
    path = [(0, True), (1, False), (2, True)]
    expected = "0f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4"
    pri = "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
    chain_code = "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508"
    pri_bytes = bytes.fromhex(pri)
    chain_code_bytes = bytes.fromhex(chain_code)
    children_keys = get_wallet_privs(pri_bytes, chain_code_bytes, path)
    ion_assert(children_keys[2].hex(), expected, "test_get_wallet_privs")

# Derive the p2wpkh witness program (aka scriptPubKey) for a given compressed 
# public key. Return a bytes array to be compared with the JSON output of Bitcoin 
# Core RPC getblock so we can find our received transactions in blocks.
# These are segwit version 0 pay-to-public-key-hash witness programs.
# https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#user-content-P2WPKH
def get_p2wpkh_program(pubkey: bytes, version: int=0) -> bytes:
    OP_0 = version.to_bytes(1, byteorder=BYTE_ORDER)
    OP_PUSHBYTES_20 = b'\x14'
    witness_program = hash160(pubkey)
    scriptPubKey = OP_0 + OP_PUSHBYTES_20 + witness_program
    return scriptPubKey

def test_p2wpkh_program():
    # Test first test case master pub key (https://en.bitcoin.it/wiki/BIP_0032_TestVectors)
    # Manualy construct the script using (https://privatekeys.pw/calc)
    pub = "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2"
    expected = "00143442193e1bb70916e914552172cd4e2dbc9df811"
    calculated = get_p2wpkh_program(bytes.fromhex(pub), 0)
    ion_assert(calculated.hex(), expected, "test_p2wpkh_program")

# Assuming Bitcoin Core is running and connected to signet using default 
# datadir, execute an RPC and return its value or error message.
# https://github.com/bitcoin/bitcoin/blob/master/doc/bitcoin-conf.md#configuration-file-path
# Examples: bcli("getblockcount")
#           bcli("getblockhash 100")
def bcli(cmd: str):
    res = run(
            ["bitcoin-cli", "-signet"] + cmd.split(" "),
            capture_output=True,
            encoding="utf-8")
    if res.returncode == 0:
        return res.stdout.strip()
    else:
        raise Exception(res.stderr.strip())

# Recover the wallet state from the blockchain:
# - Parse xprv and path from descriptor and derive 2000 key pairs and witness 
#   programs
# - Request blocks 0-310 from Bitcoin Core via RPC and scan all transactions
# - Return a state object with all the derived keys and total wallet balance
def recover_wallet_state(xprv: str):
    #---------------------------------------------------------------
    # Generate all the keypairs and witness programs to search for
    #---------------------------------------------------------------

    # Extract the pri and chain_code from the given extended private key
    key_json = deserialize_key(base58_decode(EXTENDED_PRIVATE_KEY))
    key_data = json.loads(key_json)
    pri = bytes.fromhex(key_data['key'])
    chain_code = bytes.fromhex(key_data['chain_code'])

    # My wallet path is m/84'/1'/0'/0/*
    path = [(84, True), (1, True), (0, True), (0, False)] 
    privs = get_wallet_privs(pri, chain_code, path)

    # For every private key get the coresponding public key and witness program
    pubs = []
    programs = []
    for child_priv in privs:
        child_pub = get_pub_from_priv(child_priv)
        pubs.append(child_pub)
        programs.append(get_p2wpkh_program(child_pub, 0))

    # Prepare a wallet state data structure
    state = {
        "utxo": {},
        "balance": 0,
        "privs": privs, 
        "pubs": pubs, # Manually checked, are ok
        "programs": programs
    }

    #---------------------------------------------------------------
    # Scan blocks 0-310
    #---------------------------------------------------------------
    
    height = 310
    for h in range(0, height + 1):
        # Block ops
        block_hash = bcli(f"getblockhash {h}")
        block = bcli(f"getblock {block_hash} 2")
        block_data = json.loads(block)
        tx_header = block_data["tx"]

        # Transactions ops
        for tx in tx_header[1:]: # Ignore the coinbase transactions in each block
            txid = tx['txid']

            # Money flowing in
            for vout in tx['vout']:
                scriptPubKeys = vout['scriptPubKey']['hex']
                for program in state['programs']:
                    if program.hex() in scriptPubKeys:
                        # Implement UTXO as a hashmap using txid
                        state['utxo'][txid] = { 
                            'value' : vout['value'] * BTC2SAT,
                            'n' : vout['n'],
                            'scriptPubKey' : vout['scriptPubKey']['hex']
                        }

            # Money given out
            for vin in tx['vin']:
                txid = vin['txid']
                witness = vin['txinwitness'][1]
                for pub in state['pubs']:
                    if pub.hex() == witness:
                        if txid in state['utxo']:
                            del state['utxo'][txid]

    #--------------------------------------
    # Extract the total value from UTXOs
    #--------------------------------------
                            
    for txid in state['utxo']:
        state['balance'] += state['utxo'][txid]['value']
    state['balance'] /= BTC2SAT
    return state

def test_suite():
    print("\nRunning test suite ...")
    test_base58_decode()
    test_deserialize_key()
    test_get_pub_from_priv()
    test_derive_priv_child()
    test_get_wallet_privs()
    test_p2wpkh_program()
    print("Test suite [ok]\n")

#--------------
# Main
#--------------

if __name__ == "__main__":
    print(f"{WALLET_NAME} {recover_wallet_state(EXTENDED_PRIVATE_KEY)['balance']}")
