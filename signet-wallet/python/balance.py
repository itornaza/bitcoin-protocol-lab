from decimal import Decimal
from re import I
from ecdsa import SigningKey, SECP256k1
from subprocess import run
from typing import List, Tuple
import hashlib
import hmac
import json

# Given:
# wpkh(CHANGEME_EXTENDED_PRIVATE_KEY/84h/1h/0h/0/*)#tj8algkg

#--------------
# Constants
#--------------

# Output control
VERBOSE = True
MUTE = False 
KEY_BYTE_LENGTH = 32
BYTE_ORDER = 'big'

# Elliptic curve
ORDER_N_OF_G = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


# Signet specific
WALLET_NAME = "wallet_201"
EXTENDED_PRIVATE_KEY = "CHANGEME_EXTENDED_PRIVATE_KEY"

#--------------
# Utilities
#--------------

def ion_assert(calculated, expected, test_name):
    assert calculated == expected, f"calculated and expected should match\ncalculated:\n{calculated}\nexpected:\n{expected}"
    if (VERBOSE): print(test_name, " ... [ok]")
    pass

def ion_int_to_bytes(index: int, n_bytes: int) -> bytes:
    index_bytes = index.to_bytes(n_bytes, byteorder=BYTE_ORDER)
    return index_bytes

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
        if (MUTE): print("\n->Failed: Checksums do not match!\n")
        return None
    
    if (MUTE):
        print("\n*** base58_decode_2() ***\n")
        print("--> base58_string:", base58_string, "\n")
        print("--> byte_array:", result.hex(), "\n")
        print("--> len: ", len(result), "\n")
        print("--> Checksum verified:", checksum.hex(), "\n")

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
        "chain_code": b[13:46].hex(),
        "key": b[46:].hex()
    }
    json_object = json.dumps(data)
    
    if (MUTE):
        print("*** deserialize_key() ***\n") 
        print(json_object, "\n")
    
    return json_object

# Derive the secp256k1 compressed public key from a given private key
# BONUS POINTS: Implement ECDSA yourself and multiply you key by the generator
# point!
def get_pub_from_priv(priv: bytes) -> bytes:
    signing_key = SigningKey.from_string(priv, curve=SECP256k1)
    public_key = signing_key.get_verifying_key()

    # Note: is called `to_string()` the type they return is actually bytes
    compressed_public_key = public_key.to_string("compressed")

    if (MUTE):
        print("\n*** get_pub_from_priv() ***")
        print("\nCompressed public key: ", compressed_public_key.hex(), "\n")

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
    
    # From the left 256 bits, derive the child pri
    left_256_int = int.from_bytes(output_512[:KEY_BYTE_LENGTH], byteorder=BYTE_ORDER)
    key_int = int.from_bytes(key, byteorder=BYTE_ORDER)
    child_private_key_int = (left_256_int + key_int) % ORDER_N_OF_G
    child_private_key = child_private_key_int.to_bytes(KEY_BYTE_LENGTH, byteorder=BYTE_ORDER)

    # Prepare for json
    data = {
        "chain_code": child_chain_code.hex(),
        "key": child_private_key.hex() 
    }
    json_object = json.dumps(data)
    
    if (MUTE): 
        print("\n*** derive_priv_child() ***\n")
        print("Hardened") if hardened else print("Normal")
        print("Child index: ", hex(index))
        print(json_object, "\n")

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
    v = version.to_bytes(1, byteorder=BYTE_ORDER)
    scriptPubKey = hashlib.new('ripemd160', hashlib.sha256(v + pubkey).digest()).digest()
    
    if (MUTE):
        print("\n*** get_p2wpkh_program() ***\n")
        print("version: ", v)
        print("expected scriptPubKey: ", scriptPubKey)
    
    return scriptPubKey

def test_p2wpkh_program():
    # Test first test case master pub key (https://en.bitcoin.it/wiki/BIP_0032_TestVectors)
    # Manualy construct the script using (https://privatekeys.pw/calc)
    pub = "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2"
    expected = "8d0182320d1bc0c7da470bd95117d7c2ec76d239"
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
    # Generate all the keypairs and witness programs to search for
    # privs = 
    # pubs = 
    # programs = 

    # Prepare a wallet state data structure
    # state = {
    #     "utxo": {},
    #     "balance": 0,
    #     "privs": privs,
    #     "pubs": pubs,
    #     "programs": programs
    # }

    # Scan blocks 0-310
    # height = 310
    # for h in range(height + 1):

    #     # Scan every tx in every block
    #     for tx in txs:
    #         # Check every tx input (witness) for our own compressed public 
    #         # keys. These are coins we have spent.
    #
    #         for inp in tx["vin"]:

    #                 # Remove this coin from our wallet state utxo pool
    #                 # so we don't double spend it later

    #         # Check every tx output for our own witness programs.
    #         # These are coins we have received.
    #         for out in tx["vout"]:
    #                 # Add to our total balance

    #                 # Keep track of this UTXO by its outpoint in case we 
    #                 # spend it later

    # return state
    pass

#--------------
# Main
#--------------

if __name__ == "__main__":
    # Test base58_decode() and deserialize_key() 
    # json_object = deserialize_key(base58_decode(EXTENDED_PRIVATE_KEY))
    # data = json.loads(json_object)

    # # Test get_pub_from_priv()
    # pri = bytes.fromhex(data['key'])
    # pub = get_pub_from_priv(pri)
    
    # # Test derive_priv_child()
    # chain_code = bytes.fromhex(data['chain_code'])
    # derive_priv_child(pri, chain_code, 1, False)
    # derive_priv_child(pri, chain_code, 1, True)

    # # Test get_wallet_privs
    # path = [(84, True), (1, True), (0, True), (0, False)]
    # get_wallet_privs(pri, chain_code, path)

    # # Test get_p2wpkh_program()
    # get_p2wpkh_program(pub, 0)

    # Run the tests
    test_base58_decode()
    test_get_pub_from_priv()
    test_derive_priv_child()
    test_get_wallet_privs()
    test_p2wpkh_program()

    # TODO: Uncomment for submission
    # print(f"{WALLET_NAME} {recover_wallet_state(EXTENDED_PRIVATE_KEY)['balance']}")