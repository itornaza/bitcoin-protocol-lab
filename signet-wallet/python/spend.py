import hashlib
import binascii
import json
from ecdsa import SigningKey, SECP256k1, util
from typing import List
from balance import (
    EXTENDED_PRIVATE_KEY,
    ion_assert,
    bcli,
    get_pub_from_priv,
    get_p2wpkh_program,
    recover_wallet_state)

#------------
# Constants
#------------

DEBUG = True

# Attributes
BIG_ENDIAN = 'big'
LITTLE_ENDIAN = 'little'

# Bytes
VERSION = b'\x02\x00\x00\x00'
FLAGS = b'\x00\x00\x00\x01'
LOCKTIME = b'\x00\x00\x00\x00'
SEQUENCE = b'\xff\xff\xff\xff'
SIGHASH_ALL = b'\x01\x00\x00\x00'
SIGHASH_ALL_ONE_BYTE = b'\x01'
OP_0 = b'\x00'
OP_2 = b'\x52'
OP_PUSHBYTES_20 = b'\x20'
OP_CHECKMULTISIG = b'\xae'

#------------
# Utilities
#------------

def dsha256(data: bytes) -> bytes:
    return hashlib.new("sha256", hashlib.new("sha256", data).digest()).digest()

#------------
# Functions
#------------

# Given 2 compressed public keys as byte arrays, construct
# a 2-of-2 multisig output script. No length byte prefix is necessary.
def create_multisig_script(keys: List[bytes]) -> bytes:
    if len(keys) != 2:
        raise Exception("\n->create_multisig_script expects a two element list!\n")
    key_0_length = (len(keys[0])).to_bytes(1, byteorder=LITTLE_ENDIAN)
    key_1_length = (len(keys[1])).to_bytes(1, byteorder=LITTLE_ENDIAN)
    return OP_2 + key_0_length + keys[0] + key_1_length + keys[1] + OP_2 + OP_CHECKMULTISIG

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
    version = version.to_bytes(1, byteorder=LITTLE_ENDIAN)
    witness_program = hashlib.sha256(script).digest()
    witness_program_length = (len(witness_program)).to_bytes(1, byteorder=LITTLE_ENDIAN)
    return version + witness_program_length + witness_program

def test_get_p2wsh_program():
    redeemScript = bytes.fromhex("52210235e46cac834362fe6f6a6bed1b1424932f0bcd6f5bdec5b4422730749aca0c7b2102810bf1d5666343229f43d00de990de8053cf4f111dd0d98993c64980acd067fe52ae")
    expected = b'\x00\x20' + hashlib.sha256(redeemScript).digest() 
    calculated = get_p2wsh_program(redeemScript)
    ion_assert(calculated, expected, "test_get_p2wsh_program")

# Given an outpoint, return a serialized transaction input spending it
# Use hard-coded defaults for sequence and scriptSig
def input_from_utxo(txid: bytes, index: int) -> bytes:
    index_bytes = index.to_bytes(4, byteorder=LITTLE_ENDIAN)
    length = b'\x00'
    return txid + index_bytes + length + SEQUENCE

def test_input_from_utxo():
    txid = bytes.fromhex("ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a")
    index = 1
    calculated = input_from_utxo(txid, index)
    expected = "ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff"
    ion_assert(calculated.hex(), expected, "test_input_from_utxo")

# Given an output script and value (in satoshis), return a serialized transaction output
def output_from_options(script: bytes, value: int) -> bytes:
    amount = value.to_bytes(8, LITTLE_ENDIAN)
    return amount + script # TODO Length is embedded in the script

def test_output_from_options():
    # Test data from (https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#specification)
    script = bytes.fromhex("1976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac")
    value = 112340000
    expected = "202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac"
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
    sequence = VERSION
    sequence += dsha256(outpoint)
    sequence += dsha256(SEQUENCE)
    sequence += outpoint
    sequence += scriptcode
    sequence += (value).to_bytes(8, LITTLE_ENDIAN)
    sequence += SEQUENCE
    sequence += dsha256(outputs[0] + outputs[1])
    sequence += (0).to_bytes(4, LITTLE_ENDIAN)
    sequence += SIGHASH_ALL
    return dsha256(sequence)

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
    big_endian_bytes = hex_bytes[::-1]
    value = int.from_bytes(big_endian_bytes, byteorder='big')
    calculated = get_commitment_hash(outpoint, scriptcode, value, outputs)
    expected = bytes.fromhex("70ac047ede42809fe673e05923289b980808fc176376ee2c16656252fe44e109")
    ion_assert(calculated.hex(), expected.hex(), "test_get_commitment_hash")
    
# Given a JSON utxo object and a list of all of our wallet's witness programs,
# return the index of the derived key that can spend the coin.
# This index should match the corresponding private key in our wallet's list.
def get_key_index(utxo: dict, programs: List[str]) -> int:
    for txid in utxo:
        version_and_witness = bytes.fromhex(txid['scriptPubKey'])
        witness = version_and_witness[2:]
        for index, program in enumerate(programs):
            if witness == program:
                return index
    raise Exception("\n->get_key_index did not find a matching witness index!\n")

def test_get_key_index():
    state = recover_wallet_state(EXTENDED_PRIVATE_KEY)
    programs = []
    for txid in state['utxo']:
        print(state['utxo'][txid]['scriptPubKey'])
    #     programs.append(txid['scriptPubKey'][:2])
    # calculated = get_key_index(state['utxo'], programs)
    # expected = 447
    # print(calculated)
    # ion_assert(calculated, expected, "test_get_key_index")

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
    sk = SigningKey.from_string(priv, curve=SECP256k1)
    signature = sk.sign_digest(msg, sigencode=util.sigencode_der)
    r, s = util.sigdecode_der(signature, SECP256k1.order)
    if s > sk.curve.order / 2:
        s = sk.curve.order - s
    return signature + SIGHASH_ALL_ONE_BYTE

# Given a private key and transaction commitment hash to sign,
# compute the signature and assemble the serialized p2pkh witness
# as defined in BIP 141 (2 stack items: signature, compressed public key)
# https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#specification
def get_p2wpkh_witness(priv: bytes, msg: bytes) -> bytes:
    n_items = b'\x02'
    sig = sign(priv, msg)
    sig_length = (len(sig)).to_bytes(1, byteorder=LITTLE_ENDIAN)
    pub = get_pub_from_priv(priv)
    pub_length = (len(pub)).to_bytes(1, byteorder=LITTLE_ENDIAN)
    # Manually verified the the structure against the result of bip143
    return n_items + sig_length + sig + pub_length + pub

# Given two private keys and a transaction commitment hash to sign,
# compute both signatures and assemble the serialized p2pkh witness
# as defined in BIP 141
# Remember to add a 0x00 byte as the first witness element for CHECKMULTISIG bug
# https://github.com/bitcoin/bips/blob/master/bip-0147.mediawiki
def get_p2wsh_witness(privs: List[bytes], msg: bytes) -> bytes:
    sig_1 = sign(privs[0], msg)
    pub_1 = get_pub_from_priv(privs[0])
    sig_2 = sign(privs[1], msg)
    pub_2 = get_pub_from_priv(privs[1])
    return b'\x00' + sig_1 + sig_2 + b'\x02' + pub_1 + pub_2 + b'\x02' + OP_CHECKMULTISIG

# Given arrays of inputs, outputs, and witnesses, assemble the complete
# transaction and serialize it for broadcast. Return bytes as hex-encoded string
# suitable to broadcast with Bitcoin Core RPC.
# https://en.bitcoin.it/wiki/Protocol_documentation#tx
def assemble_transaction(inputs: List[bytes], outputs: List[bytes], witnesses: List[bytes]) -> str:
    seq = VERSION + FLAGS + (len(inputs)).to_bytes(1, LITTLE_ENDIAN)
    for input in inputs:
        seq = seq + input
    seq = seq + (len(outputs)).to_bytes(1, LITTLE_ENDIAN)
    for output in outputs:
        seq = seq + output
    for witness in witnesses:
        seq = seq + witness
    seq = seq + LOCKTIME
    return seq

# Given arrays of inputs and outputs (no witnesses!) compute the txid.
# Return the 32 byte txid as a *reversed* hex-encoded string.
# https://developer.bitcoin.org/reference/transactions.html#raw-transaction-format
def get_txid(inputs: List[bytes], outputs: List[bytes]) -> str:
    seq = VERSION + FLAGS + (len(inputs)).to_bytes(1, LITTLE_ENDIAN)
    for input in inputs:
        seq = seq + input
    seq = seq + (len(outputs)).to_bytes(1, LITTLE_ENDIAN)
    for output in outputs:
        seq = seq + output
    seq = seq + LOCKTIME
    txid = dsha256(seq) # CAUTION! the string is already little endian
    return txid.hex()

def test_get_txid():
    inputs = [bytes.fromhex("ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a")]
    outputs = [bytes.fromhex("b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac"),
               bytes.fromhex("0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac")]
    expected = "8f7aaad9a7e5b4263b6504479d8e8c730cc551e9137f57f95b229ba1d6ab0a6d"
    calculated = get_txid(inputs, outputs)
    ion_assert(calculated, expected, "test_get_txid")

# Spend a p2wpkh utxo to a 2 of 2 multisig p2wsh and return the txid
def spend_p2wpkh() -> str: # TODO replace original after dev: def spend_p2wpkh(state: object) -> str:
    FEE = 1000
    AMT = 1000000
    
    # Choose an unspent coin worth more than 0.01 BTC
    # Reverse the txid hash so it's little-endian
    # I have extracted it mannualy not to break the balance.py for the moment
    utxo = {
        "txid": bytes.fromhex("e361e4e92a159688b840b013bf22be8a609fadc24ff45338a9ea8c506051da53")[::-1],
        "n" : int("67"), # i.e 0000000043 in big endian
        "value" : int("9094113"),
        "scriptPubKey" : "0014e1e4b0a27b3d5d3eea5f844fbec0d4c314aad7a6",
        "pub" : "02c0fad28fd3c95d6ee5de621e5a47fe0ca1a9c421161df61de029df76c192c6a9",
        "pri" : None
    }
    pub_0 = bytes.fromhex("0235e46cac834362fe6f6a6bed1b1424932f0bcd6f5bdec5b4422730749aca0c7b")
    pub_1 = bytes.fromhex("02810bf1d5666343229f43d00de990de8053cf4f111dd0d98993c64980acd067fe")

    pri_0 = bytes(32)
    pri_1 = bytes(32)

    #-------------
    # 1. Input
    #-------------

    input = input_from_utxo(utxo['txid'], utxo['n'])
    inputs = [input]
    
    if (DEBUG):
        print("\n\n> INPUT\n")
        print("Input = ", input.hex())

    #--------------
    # 2. Output
    #--------------

    # Compute destination output (0.01 btc) script and output (from keys 0 and 1)
    multisig_script = create_multisig_script([pub_0, pub_1])
    p2wsh_witness_program = get_p2wsh_program(multisig_script, 0)
    output_1 = output_from_options(p2wsh_witness_program, AMT)

    # Compute change output script and output (from key 0)
    p2wpkh_witness_program = get_p2wpkh_program(pub_0, 0)
    change = utxo['value'] - AMT - FEE
    output_2 = output_from_options(p2wpkh_witness_program, change)
    
    outputs = [output_1, output_2]

    if (DEBUG):
        print("\n> OUPUT\n")
        print("Multisig output = ", output_1.hex())
        print("Change output = ", output_2.hex())

    # Get the message to sign
    outpoint = utxo['txid'] + (utxo['n']).to_bytes(8, LITTLE_ENDIAN)
    scriptcode = get_p2wpkh_scriptcode(utxo)
    value = utxo['value']
    sighash = get_commitment_hash(outpoint, scriptcode, value, outputs)

    if (DEBUG):
        print("\n> MESSAGE\n")
        print("Outpoint = ", outpoint.hex())
        print("\nUTXO Scriptcode = ", scriptcode.hex())
        print("\nMessage sighash = ", sighash.hex())

    # Sign the digest with the private key for the coin we are spending!
    signature = sign(utxo['pri'], sighash)

    # Create a transaction witness with the signature and public key
    p2wpkh_witness = get_p2wpkh_witness(utxo['pri'], sighash)
    if (DEBUG):
        print("\np2wpkh_witness = ", p2wpkh_witness.hex())
        print("\n\n")

    # Assemble
    final = assemble_transaction(inputs, outputs, [p2wpkh_witness])

    # Reserialize without witness data and double-SHA256 to get the txid
    txid = get_txid(inputs, outputs)

    # For debugging you can use RPC `testmempoolaccept ["<final hex>"]` here
    return txid, final.hex()

# Spend a 2-of-2 multisig p2wsh utxo and return the txid
def spend_p2wsh(txid: str) -> str: # def spend_p2wsh(state: object, txid: str) -> str:
    COIN_VALUE = 1000000
    FEE = 1000
    AMT = 0
    # Create the input from the utxo
    # Reverse the txid hash so it's little-endian

    # Compute destination output script and output

    # Compute change output script and output

    # Get the message to sign

    # Sign!

    # Assemble

    # For debugging you can use RPC `testmempoolaccept ["<final hex>"]` here
    
    # return finalhex
    pass

def test_suite():
    print("\nRunning test suite ...")
    test_create_multisig_script()
    test_get_p2wsh_program()
    test_input_from_utxo()
    test_output_from_options()
    test_get_p2wpkh_scriptcode()
    test_get_commitment_hash()
    # test_get_key_index()
    # test_get_txid()
    print("Test suite [ok]\n")

if __name__ == "__main__":
    test_suite()

    # Recover wallet state: We will need all key pairs and unspent coins
    # state = recover_wallet_state(EXTENDED_PRIVATE_KEY)
    txid1, tx1 = spend_p2wpkh() # Original: `spend_p2wpkh(state)`
    print(txid1)
    print(tx1)

    tx2 = spend_p2wsh(txid1) # Original: `spend_p2wsh(state, txid1)`
    print(tx2)