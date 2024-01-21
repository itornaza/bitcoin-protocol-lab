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

# Constants
VERBOSE = 1 # TODO: Set to False for submission
MUTE = False 

WALLET_NAME = "wallet_201"
EXTENDED_PRIVATE_KEY = "CHANGEME_EXTENDED_PRIVATE_KEY"
ORDER_N_OF_G = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

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
        if (VERBOSE): print("\n->Failed: Checksums do not match!\n")
        return None
    
    if (VERBOSE):
        print("\n*** base58_decode_2() ***\n")
        print("--> base58_string:", base58_string, "\n")
        print("--> byte_array:", result.hex(), "\n")
        print("--> len: ", len(result), "\n")
        print("--> Checksum verified:", checksum.hex(), "\n")

    # Resulting as bytes, should contain 78 bytes according to spec
    return bytes(result)

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
    
    if (VERBOSE):
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

    if (VERBOSE):
        print("\n*** get_pub_from_priv() ***")
        print("\nCompressed public key: ", compressed_public_key.hex(), "\n")

    return compressed_public_key

# Perform a BIP32 parent private key -> child private key operation
# Return a JSON object with "key" and "chain_code" properties as bytes
# https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#user-content-Private_parent_key_rarr_private_child_key
def derive_priv_child(key: bytes, chain_code: bytes, index: int, hardened: bool) -> object:
    if (VERBOSE): print("\n*** derive_priv_child() ***\n")

    # Prepare the data depending on the child type
    if (hardened):
        index = int(0x80000000) + index
        if (VERBOSE): print("Hardened child index: ", hex(index))
        data = b'\x00' + key + index.to_bytes(4, byteorder='big')
    else:
        if (VERBOSE): print("Normal child index: ", hex(index))
        pub = get_pub_from_priv(key)
        data = pub + index.to_bytes(4, byteorder='big')
    output_512 = hmac.new(key, data, hashlib.sha512).digest()
    
    # Right 256 bits is the chain_code
    child_chain_code = output_512[32:]
    
    # From the left 256 bits, derive the child pri
    left_256_int = int.from_bytes(output_512[:32], byteorder='big')
    key_int = int.from_bytes(key, byteorder='big')
    child_private_key_int = (left_256_int + key_int) % ORDER_N_OF_G
    child_private_key = child_private_key_int.to_bytes(32, byteorder='big')

    # Prepare for json
    data = {
        "chain_code": child_chain_code.hex(),
        "key": child_private_key.hex() 
    }
    json_object = json.dumps(data)
    
    if (VERBOSE): print(json_object, "\n")
    
    return json_object

# Given an extended private key and a BIP32 derivation path,
# compute the first 2000 child private keys.
# Return an array of keys encoded as bytes.
# The derivation path is formatted as an array of (index: int, hardened: bool) tuples.
# Notes: 
# - My example would be for `84h/1h/0h/0/*` : [(84, True), (1, True), (0, True), (0, False)]
# - The key in the function argument corresponds to the master (m)
def get_wallet_privs(key: bytes, chain_code: bytes, path: List[Tuple[int, bool]]) -> List[bytes]:
    if (VERBOSE): print("\n*** get_wallet_privs() ***\n")

    # 1. Move through the path to locate the last parent
    current_key = key
    for item in path:
        child_index, hardened = item
        child_json = derive_priv_child(current_key, chain_code, child_index, hardened)
        child_data = json.loads(child_json)
        current_key = bytes.fromhex(child_data['key'])
    
    if (VERBOSE): print(current_key.hex(), "\n")

    # 2. Get the first 2000 children private keys of that last parent
    children_keys = []
    hardened = False
    for child_index in range(0, 2000):
        child_json = derive_priv_child(current_key, chain_code, child_index, hardened)
        child_data = json.loads(child_json)
        child_key = bytes.fromhex(child_data['key'])
        children_keys.append(child_key)

    if (MUTE): 
        i = 0
        for child_key in children_keys:
            i = i + 1
            if i > 1950:
                print(child_key.hex())
    
    return children_keys

# Derive the p2wpkh witness program (aka scriptPubKey) for a given compressed 
# public key.Return a bytes array to be compared with the JSON output of Bitcoin 
# Core RPC getblock so we can find our received transactions in blocks.
# These are segwit version 0 pay-to-public-key-hash witness programs.
# https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#user-content-P2WPKH
def get_p2wpkh_program(pubkey: bytes, version: int=0) -> bytes:
    pass

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

if __name__ == "__main__":
    # Test base58_decode() and deserialize_key() 
    json_object = deserialize_key(base58_decode(EXTENDED_PRIVATE_KEY))
    data = json.loads(json_object)

    # Test get_pub_from_priv()
    pri = bytes.fromhex(data['key'])
    pub = get_pub_from_priv(pri)
    chain_code = bytes.fromhex(data['chain_code'])

    # Test derive_priv_child()
    derive_priv_child(pri, chain_code, 1, False)
    derive_priv_child(pri, chain_code, 1, True)

    # Test get_wallet_privs
    path = [(84, True), (1, True), (0, True), (0, False)]
    get_wallet_privs(pri, chain_code, path)

    # TODO: Uncomment for submission
    # print(f"{WALLET_NAME} {recover_wallet_state(EXTENDED_PRIVATE_KEY)['balance']}")