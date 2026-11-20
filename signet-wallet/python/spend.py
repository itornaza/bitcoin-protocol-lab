import hashlib
import binascii
import json
from ecdsa import SigningKey, SECP256k1, util
from typing import List
import os
import sys
from balance import (
    ion_assert,
    bcli,
    get_pub_from_priv,
    get_p2wpkh_program,
    recover_wallet_state,
    load_wallet_config,
    deserialize_key,
    base58_decode,
    get_wallet_privs)

#------------
# Constants
#------------

BIG_ENDIAN = 'big'
LITTLE_ENDIAN = 'little'

VERSION = b'\x02\x00\x00\x00'
FLAGS = b'\x00\x01'
LOCKTIME = b'\x00\x00\x00\x00'
SEQUENCE = b'\xff\xff\xff\xff'

SIGHASH_ALL = b'\x01\x00\x00\x00'
SIGHASH_ALL_ONE_BYTE = b'\x01'

OP_0 = b'\x00'
OP_2 = b'\x52'
OP_3 = b'\x53'
OP_CHECKMULTISIG = b'\xae'
OP_RETURN = b'\x6a'

#------------
# Utilities
#------------

def dsha256(data: bytes) -> bytes:
    return hashlib.new("sha256", hashlib.new("sha256", data).digest()).digest()

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def length(data: bytes) -> bytes:
    return (len(data)).to_bytes(1, byteorder=LITTLE_ENDIAN)

def int_to_bytes(number: int, n_bytes: int):
    return number.to_bytes(n_bytes, byteorder=LITTLE_ENDIAN)

def reverse_endian(seq: bytes) -> bytes:
    return seq[::-1]

def test_reverse_endian():
    calculated = reverse_endian(b'\x01\x02\x03\x04')
    expected = b'\x04\x03\x02\x01'
    ion_assert(calculated, expected, "test_reverse_endian")

#------------
# Functions
#------------

# Given 2 compressed public keys as byte arrays, construct
# a 2-of-2 multisig output script. No length byte prefix is necessary.
def create_multisig_script(keys: List[bytes]) -> bytes:
    if len(keys) != 2:
        raise Exception("\n-> create_multisig_script expects a two element list!\n")
    script = OP_2 + \
             length(keys[0]) + keys[0] + \
             length(keys[1]) + keys[1] + \
             OP_2 + OP_CHECKMULTISIG
    return script

def test_create_multisig_script():
    # Actual 84h/1h/0h/0/0 and 84h/1h/0h/0/1 pubs from (https://bip32jp.github.io/english/)
    # and confirmed from balance.py
    pub_0 = bytes.fromhex("0235e46cac834362fe6f6a6bed1b1424932f0bcd6f5bdec5b4422730749aca0c7b")
    pub_1 = bytes.fromhex("02810bf1d5666343229f43d00de990de8053cf4f111dd0d98993c64980acd067fe")
    List = [pub_0, pub_1]
    calculated = create_multisig_script(List)
    json_string = bcli(f"createmultisig 2 [\"{pub_0.hex()}\",\"{pub_1.hex()}\"]")
    data = json.loads(json_string)
    expected = bytes.fromhex("52210235e46cac834362fe6f6a6bed1b1424932f0bcd6f5bdec5b4422730749aca0c7b2102810bf1d5666343229f43d00de990de8053cf4f111dd0d98993c64980acd067fe52ae")
    ion_assert(calculated, expected, "test_create_multisig_script")

# Given an output script as a byte array, compute the p2wsh witness program
# This is a segwit version 0 pay-to-script-hash witness program.
# https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#p2wsh
def get_p2wsh_program(script: bytes, version: int=0) -> bytes:
    version = int_to_bytes(version, 1)
    witness_program = sha256(script)
    return version + length(witness_program) + witness_program

def test_get_p2wsh_program():
    redeemScript = bytes.fromhex("52210235e46cac834362fe6f6a6bed1b1424932f0bcd6f5bdec5b4422730749aca0c7b2102810bf1d5666343229f43d00de990de8053cf4f111dd0d98993c64980acd067fe52ae")
    expected = b'\x00\x20' + sha256(redeemScript)
    calculated = get_p2wsh_program(redeemScript)
    ion_assert(calculated, expected, "test_get_p2wsh_program")

# Given an outpoint, return a serialized transaction input spending it
# Use hard-coded defaults for sequence and scriptSig
def input_from_utxo(txid: bytes, index: int) -> bytes:
    # 1. previous_output outpoint, the previous output transaction reference, as an OutPoint structure
    # 1.1 hash, the hash of the referenced transaction (32 bytes)
    # 1.2 index, the index of the specific output in the transaction
    input = txid + int_to_bytes(index, 4)
    # 2. script length, the length of the signature script (1+ bytes)
    input += b'\x00'
    # 3. signature script, computational Script for confirming transaction authorization (? bytes)
    # 4. sequence (4 bytes)
    input += SEQUENCE
    return input

def test_input_from_utxo():
    txid = bytes.fromhex("ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a")
    index = 1
    calculated = input_from_utxo(txid, index)
    expected = "ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff"
    ion_assert(calculated.hex(), expected, "test_input_from_utxo")

# Given an output script and value (in satoshis), return a serialized transaction output
def output_from_options(script: bytes, value: int) -> bytes:
    # 1. value, transaction Value (8 bytes)
    output = int_to_bytes(value, 8)
    # 2. pk_script length, ength of the pk_script (1+ bytes)
    output += length(script)
    # 3. pk_script, public key as script setting up conditions to claim this output (? bytes)
    output += script
    return output

def test_output_from_options():
    # Test data from (https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#specification)
    script = bytes.fromhex("1976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac")
    value = 112340000
    expected =  "202cb20600000000" + "1a" + "1976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac"
    calculated = output_from_options(script, value)
    ion_assert(calculated.hex(), expected, "test_output_from_options")

# Given a JSON utxo object, extract the public key hash from the output script
# and assemble the p2wpkh scriptcode as defined in BIP143
# <script length> OP_DUP OP_HASH160 <pubkey hash> OP_EQUALVERIFY OP_CHECKSIG
# https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#specification
def get_p2wpkh_scriptcode(utxo: dict) -> bytes:
    data = utxo
    script_pub_key = bytes.fromhex(data['scriptPubKey'])
    pub_key_hash = script_pub_key[2:]
    return b'\x19\x76\xa9\x14' + pub_key_hash + b'\x88\xac'

def test_get_p2wpkh_scriptcode():
    # Test data from (https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#specification)
    calculated = get_p2wpkh_scriptcode({'scriptPubKey' : "00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1"})
    expected = "1976a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac"
    ion_assert(calculated.hex(), expected, "test_get_p2wpkh_scriptcode")

# Compute the commitment hash for a single input and return bytes to sign.
# This implements the BIP 143 transaction digest algorithm
# https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#specification
# We assume only a single input and two outputs,
# as well as constant default values for sequence and locktime
def get_commitment_hash(outpoint: bytes, scriptcode: bytes, value: int, outputs: List[bytes]) -> bytes:
    # 1. nVersion of the transaction (4-byte little endian)
    seq = VERSION
    # 2. hashPrevouts (32-byte hash)
    seq += dsha256(outpoint)
    # 3. hashSequence (32-byte hash)
    seq += dsha256(SEQUENCE)
    # 4. outpoint (32-byte hash + 4-byte little endian) 
    seq += outpoint
    # 5. scriptCode of the input (serialized as scripts inside CTxOuts)
    seq += scriptcode
    # 6. value of the output spent by this input (8-byte little endian)
    seq += int_to_bytes(value, 8)
    # 7. nSequence of the input (4-byte little endian)
    seq += SEQUENCE
    # 8. hashOutputs (32-byte hash)
    outputs_seq = bytes()
    for output in outputs:
        outputs_seq += output
    seq += dsha256(outputs_seq)
    # 9. nLocktime of the transaction (4-byte little endian)
    seq += LOCKTIME
    # 10. sighash type of the signature (4-byte little endian)
    seq += SIGHASH_ALL
    return dsha256(seq)

def test_get_commitment_hash():
    '''
    Manual computation
	nVersion:     02000000
    hashPrevouts: 6d478c2c1c0fed58185dc352abd766b7c53ec5c8ecd340c88de70ddabb6dfe1
    hashSequence: 3bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e70665044
    outpoint:     ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a01000000
    scriptCode:   1976a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac
    amount:       0046c32300000000
    nSequence:    ffffffff
    hashOutputs:  de984f44532e2173ca0d64314fcefe6d30da6f8cf27bafa706da61df8a226c83
    nLockTime:    00000000
    nHashType:    01000000
    Pre-image 
    0200000006d478c2c1c0fed58185dc352abd766b7c53ec5c8ecd340c88de70ddabb6dfe13bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e70665044ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a010000001976a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac0046c32300000000ffffffffde984f44532e2173ca0d64314fcefe6d30da6f8cf27bafa706da61df8a226c830000000001000000
    sigHash
    70ac047ede42809fe673e05923289b980808fc176376ee2c16656252fe44e109
    '''
    outpoint = bytes.fromhex("ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a01000000")
    outputs = [bytes.fromhex("b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac"),
               bytes.fromhex("0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac")]
    scriptcode = bytes.fromhex("1976a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac")
    hex_bytes = bytes.fromhex("0046c32300000000")
    big_endian_bytes = reverse_endian(hex_bytes)
    value = int.from_bytes(big_endian_bytes, byteorder='big')
    calculated = get_commitment_hash(outpoint, scriptcode, value, outputs)
    expected = bytes.fromhex("70ac047ede42809fe673e05923289b980808fc176376ee2c16656252fe44e109")
    ion_assert(calculated.hex(), expected.hex(), "test_get_commitment_hash")
    
# Given a JSON utxo object and a list of all of our wallet's witness programs,
# return the index of the derived key that can spend the coin.
# This index should match the corresponding private key in our wallet's list.
def get_key_index(state: dict) -> int:
    # Chosen UTXO
    # txid : e361e4e92a159688b840b013bf22be8a609fadc24ff45338a9ea8c506051da53 
    # value : 9094113.0   
    # n : 67 
    # scriptPubKey : 0014e1e4b0a27b3d5d3eea5f844fbec0d4c314aad7a6
    txid = "e361e4e92a159688b840b013bf22be8a609fadc24ff45338a9ea8c506051da53"

    # Calculate the programs locally
    programs = []
    for pub in state['pubs']:
        program = get_p2wpkh_program(pub, 0)
        programs.append(program.hex())
    
    # Find the matching pub key index
    scriptPubKey = state['utxo'][txid]['scriptPubKey']
    for index, program in enumerate(programs):
        if scriptPubKey == program:
            return index
    
    raise Exception("\n-> get_key_index did not find a matching witness index!\n")

# Requires to know the state
def test_get_key_index(state): 
    calculated = get_key_index(state)
    expected = 447
    ion_assert(calculated, expected, "test_get_key_index")

# Given a private key and message digest as bytes, compute the ECDSA signature.
# Bitcoin signatures:
# - Must be strict-DER encoded
# - Must have the SIGHASH_ALL byte (0x01) appended
# - Must have a low s value as defined by BIP 62:
#   https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki#user-content-Low_S_values_in_signatures
def sign(priv: bytes, msg: bytes) -> bytes:
    # ECDSA makes sure to produce an appropriate low s value
    # Notice that we need to sha256 the mesage before signing it
    # Format: 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S] [sighash]
    # Caution! The message has to be already double sha256 digested
    for i in range(100):
        sk = SigningKey.from_string(priv, curve=SECP256k1)
        signature = sk.sign_digest(msg, sigencode=util.sigencode_der)
        r, s = util.sigdecode_der(signature, SECP256k1.order)
        if s < sk.curve.order / 2:
            return signature + SIGHASH_ALL_ONE_BYTE
    raise Exception("\n-> cannot get a proper s value for signature!\n")

# Given a private key and transaction commitment hash to sign,
# compute the signature and assemble the serialized p2pkh witness
# as defined in BIP 141 (2 stack items: signature, compressed public key)
# https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#specification
def get_p2wpkh_witness(priv: bytes, msg: bytes) -> bytes:
    n_items = b'\x02'
    sig = sign(priv, msg)
    pub = get_pub_from_priv(priv)
    return n_items + length(sig) + sig + length(pub) + pub

# Given two private keys and a transaction commitment hash to sign,
# compute both signatures and assemble the serialized p2pkh witness
# as defined in BIP 141
# Remember to add a 0x00 byte as the first witness element for CHECKMULTISIG bug
# https://github.com/bitcoin/bips/blob/master/bip-0147.mediawiki
def get_p2wsh_witness(privs: List[bytes], msg: bytes) -> bytes:
    n_items = b'\x04'
    sig_1 = sign(privs[0], msg)
    sig_2 = sign(privs[1], msg)
    pub_1 = get_pub_from_priv(privs[0])
    pub_2 = get_pub_from_priv(privs[1])
    
    witness_script = OP_2 + \
                     length(pub_1) + pub_1 + \
                     length(pub_2) + pub_2 + \
                     OP_2 + OP_CHECKMULTISIG
    
    witness = n_items + OP_0 + \
              length(sig_1) + sig_1 + \
              length(sig_2) + sig_2 + \
              length(witness_script) + witness_script
    
    return witness

# Given arrays of inputs, outputs, and witnesses, assemble the complete
# transaction and serialize it for broadcast. Return bytes as hex-encoded string
# suitable to broadcast with Bitcoin Core RPC.
# https://en.bitcoin.it/wiki/Protocol_documentation#tx
def assemble_transaction(inputs: List[bytes], outputs: List[bytes], witnesses: List[bytes]) -> str:
    # 1. version, transaction data format version (4 bytes)
    seq = VERSION
    # 2. flag, always 0001, and indicates the presence of witness data (2 bytes)
    seq += FLAGS
    # 3. tx_in count, number of Transaction inputs (1+ bytes) 
    seq += length(inputs)
    # 4. tx_in[], a list of 1 or more transaction inputs (41+ bytes)
    for input in inputs:
        seq += input
    # 5. tx_out count, number of Transaction outputs (1+ bytes)
    seq += length(outputs)
    # 6. tx_out[], a list of 1 or more transaction outputs (9+ bytes)
    for output in outputs:
        seq += output
    # 7. tx_witness[], a list of witnesses, one for each input (0+ bytes)
    for witness in witnesses:
        seq += witness
    # 8. lock_time (4 bytes)
    seq += LOCKTIME
    return seq

# Given arrays of inputs and outputs (no witnesses!) compute the txid.
# Return the 32 byte txid as a *reversed* hex-encoded string.
# https://developer.bitcoin.org/reference/transactions.html#raw-transaction-format
def get_txid(inputs: List[bytes], outputs: List[bytes]) -> str:
    # 1. Version (4 bytes)
    seq = VERSION
    # 2. tx_in count
    seq += length(inputs)
    # 3. tx_in[], transaction inputs
    for input in inputs:
        seq += input
    # 4. tx_out count
    seq += length(outputs)
    # 5. tx_out[], transaction outputs 
    for output in outputs:
        seq += output
    # 6. lock_time (4 bytes)
    seq += LOCKTIME
    txid = dsha256(seq)
    return (reverse_endian(txid)).hex()


def derived_account_keys(xprv: str, count: int = 2):
    """Derive the first `count` BIP84 signet receive keys from an extended private key."""
    key_data = json.loads(deserialize_key(base58_decode(xprv)))
    pri = bytes.fromhex(key_data['key'])
    chain_code = bytes.fromhex(key_data['chain_code'])
    path = [(84, True), (1, True), (0, True), (0, False)]
    privs = get_wallet_privs(pri, chain_code, path)
    pubs = [get_pub_from_priv(p) for p in privs[:count]]
    return privs[:count], pubs


def load_spend_utxo() -> dict:
    """Read the coin to spend from the environment (signet/regtest test coin)."""
    txid = os.environ.get("SPEND_TXID", "")
    script = os.environ.get("SPEND_SCRIPTPUBKEY", "")
    if not txid or not script:
        raise SystemExit(
            "Set EXTENDED_PRIVATE_KEY (or pass it as argv[1]) and the coin to spend:\n"
            "  SPEND_TXID, SPEND_VOUT, SPEND_VALUE_SATS, SPEND_SCRIPTPUBKEY\n"
            "Optional: SPEND_KEY_INDEX (default 0) selects which derived child signs."
        )
    return {
        "txid": bytes.fromhex(txid),
        "n": int(os.environ.get("SPEND_VOUT", "0")),
        "value": int(os.environ.get("SPEND_VALUE_SATS", "0")),
        "scriptPubKey": script,
        "key_index": int(os.environ.get("SPEND_KEY_INDEX", "0")),
    }


# Spend a p2wpkh utxo to a 2 of 2 multisig p2wsh and return the txid
def spend_p2wpkh(xprv: str, utxo: dict) -> str:
    FEE = 1000
    AMT = 1000000

    privs, pubs = derived_account_keys(xprv, count=max(2, utxo["key_index"] + 1))
    pub_0, pub_1 = pubs[0], pubs[1]
    utxo = dict(utxo)
    utxo["pri"] = privs[utxo["key_index"]]
    utxo["pub"] = pubs[utxo["key_index"]].hex()

    # 1. Inputs

    # Reverse the txid hash so it's little-endian
    utxo_txid = reverse_endian(utxo['txid'])
    input = input_from_utxo(utxo_txid, utxo['n'])

    # 2. Outputs

    # Compute destination output (0.01 btc) script and output (from keys 0 and 1)
    multisig_script = create_multisig_script([pub_0, pub_1])
    p2wsh_witness_program = get_p2wsh_program(multisig_script, 0)
    output_1 = output_from_options(p2wsh_witness_program, AMT)

    # Compute change output script and output (from key 0)
    p2wpkh_witness_program = get_p2wpkh_program(pub_0, 0)
    change = utxo['value'] - AMT - FEE
    output_2 = output_from_options(p2wpkh_witness_program, change)

    # 3. sigHash and Witness

    # Get the message to sign
    outpoint = utxo_txid + int_to_bytes(utxo['n'], 4)
    scriptcode = get_p2wpkh_scriptcode(utxo)
    value = utxo['value']
    sighash = get_commitment_hash(outpoint, scriptcode, value, [output_1, output_2])

    # Create a transaction witness with the signature and private key
    # Sign the digest with the private key for the coin we are spending!
    p2wpkh_witness = get_p2wpkh_witness(utxo['pri'], sighash)

    # 4. Serialize

    # Assembly
    final = assemble_transaction([input], [output_1, output_2], [p2wpkh_witness])

    # Reserialize without witness data and double-SHA256 to get the txid
    txid = get_txid([input], [output_1, output_2])

    # For debugging you can use RPC: bitcoin-cli testmempoolaccept '["<final hex>"]'
    return txid, final.hex()

def test_txid():
    # Requires EXTENDED_PRIVATE_KEY and SPEND_* in the environment to reproduce a signed spend.
    if not os.environ.get("EXTENDED_PRIVATE_KEY") or not os.environ.get("SPEND_TXID"):
        print("test_spend_p2wpkh / txid - [skipped]")
        return
    _, xprv = load_wallet_config()
    calculated_txid, _calculated_tx = spend_p2wpkh(xprv, load_spend_utxo())
    expected_txid = os.environ.get("EXPECTED_SPEND_TXID")
    if expected_txid:
        ion_assert(calculated_txid, expected_txid, "test_spend_p2wpkh / txid")

# Spend a 2-of-2 multisig p2wsh utxo and return the txid
def spend_p2wsh(xprv: str, txid: str, value: int = 1000000) -> str:
    FEE = 1000
    AMT = 0

    privs, pubs = derived_account_keys(xprv, count=2)
    pub_0, pub_1 = pubs[0], pubs[1]
    pri_0, pri_1 = privs[0], privs[1]
    # scriptPubKey is the p2wsh program of the 2-of-2 script from those keys
    multisig_script = create_multisig_script([pub_0, pub_1])
    utxo = {
        "txid": bytes.fromhex(txid),
        "n": 0,
        "value": int(value),
        "scriptPubKey": get_p2wsh_program(multisig_script, 0).hex(),
    }

    # 1. Input

    # Reverse the txid hash so it's little-endian
    txid_bytes = bytes.fromhex(txid)
    txid_bytes = reverse_endian(txid_bytes)

    # Create the input from the utxo
    input = input_from_utxo(txid_bytes, utxo['n'])

    # 2. Output

    # Compute destination output script and output
    nym_string = "ion- (aka itornaza)"    
    nym_hex_string = ''.join(format(ord(c), '02x') for c in nym_string)
    nym = bytes.fromhex(nym_hex_string)
    null_witness_program = OP_RETURN + length(nym) + nym
    output_1 = output_from_options(null_witness_program, 0)

    # Compute change output script and output (from key 0)
    p2wpkh_witness_program = get_p2wpkh_program(pub_0, 0)
    change = utxo['value'] - AMT - FEE
    output_2 = output_from_options(p2wpkh_witness_program, change)

    # 3. sigHash and Witness

    # Get the message to sign
    outpoint = txid_bytes + int_to_bytes(utxo['n'], 4)

    # Scriptcode is length + multisig script (because there is no OP_CODESEPARATOR)
    multisig_script = create_multisig_script([pub_0, pub_1])
    scriptcode = length(multisig_script) + multisig_script
    
    value = utxo['value']
    sighash = get_commitment_hash(outpoint, scriptcode, value, [output_1, output_2])

    # Create a transaction witness with the signature and private keys
    # Sign the digest with the private key for the coin we are spending!
    p2wsh_witness = get_p2wsh_witness([pri_0, pri_1], sighash)

    # 4. Serialize
    final = assemble_transaction([input], [output_1, output_2], [p2wsh_witness])

    # For debugging you can use RPC: bitcoin-cli testmempoolaccept '["<final hex>"]'
    return final.hex()

def test_suite():
    print("\nRunning test suite ...")
    test_reverse_endian()
    test_create_multisig_script()
    test_get_p2wsh_program()
    test_input_from_utxo()
    test_output_from_options()
    test_get_p2wpkh_scriptcode()
    test_get_commitment_hash()
    test_txid()
    # test_get_key_index(state)
    print("Test suite - [ok]\n")

if __name__ == "__main__":
    # test_suite()

    # Recover wallet state: We will need all key pairs and unspent coins
    # state = recover_wallet_state(EXTENDED_PRIVATE_KEY)
    # spending_index = get_key_index(state)

    txid1, tx1 = spend_p2wpkh() # Original: `spend_p2wpkh(state)`
    print(tx1)

    tx2 = spend_p2wsh(txid1) # Original: `spend_p2wsh(state, txid1)`
    print(tx2)
    