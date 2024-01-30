import hashlib
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

BIG_ENDIAN = 'big'
LITTLE_ENDIAN = 'little'
OP_0 = b'\x00'
OP_PUSHBYTES_20 = b'\x20'
SEQUENCE = b'\xff\xff\xff\xff'
SIGHASH_ALL = b'\x01\x00\x00\x00'

#------------
# Functions
#------------

# Given 2 compressed public keys as byte arrays, construct
# a 2-of-2 multisig output script. No length byte prefix is necessary.
def create_multisig_script(keys: List[bytes]) -> bytes:
    if len(keys) != 2:
        raise Exception("\n->create_multisig_script expects a two element list!\n")
    json_string = bcli(f"createmultisig 2 [\"{keys[0].hex()}\",\"{keys[1].hex()}\"]")
    data = json.loads(json_string)
    redeemScript = bytes.fromhex(data['redeemScript'])
    return redeemScript

def test_create_multisig_script():
    # Actual 84h/1h/0h/0/0 and 84h/1h/0h/0/1 pubs from (https://bip32jp.github.io/english/)
    # and confirmed from balance.py
    pub_0 = bytes.fromhex("0235e46cac834362fe6f6a6bed1b1424932f0bcd6f5bdec5b4422730749aca0c7b")
    pub_1 = bytes.fromhex("02810bf1d5666343229f43d00de990de8053cf4f111dd0d98993c64980acd067fe")
    List = [pub_0, pub_1]
    calculated = create_multisig_script(List)
    expected = bytes.fromhex("52210235e46cac834362fe6f6a6bed1b1424932f0bcd6f5bdec5b4422730749aca0c7b2102810bf1d5666343229f43d00de990de8053cf4f111dd0d98993c64980acd067fe52ae")
    ion_assert(calculated, expected, "test_create_multisig_script")

# Given an output script as a byte array, compute the p2wsh witness program
# This is a segwit version 0 pay-to-script-hash witness program.
# https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#p2wsh
def get_p2wsh_program(script: bytes, version: int=0) -> bytes:
    version = version.to_bytes(1, byteorder=LITTLE_ENDIAN)
    witnessProgram = hashlib.sha256(script).digest()
    return version + witnessProgram

def test_get_p2wsh_program():
    redeemScript = bytes.fromhex("52210235e46cac834362fe6f6a6bed1b1424932f0bcd6f5bdec5b4422730749aca0c7b2102810bf1d5666343229f43d00de990de8053cf4f111dd0d98993c64980acd067fe52ae")
    expected = b'\00' + hashlib.sha256(redeemScript).digest() # TODO 0020 instead of 00????
    calculated = get_p2wsh_program(redeemScript)
    ion_assert(calculated, expected, "test_get_p2wsh_program")

# Given an outpoint, return a serialized transaction input spending it
# Use hard-coded defaults for sequence and scriptSig
def input_from_utxo(txid: bytes, index: int) -> bytes:
    count = b'\x01'
    index_bytes = index.to_bytes(4, byteorder=LITTLE_ENDIAN)
    length = b'\x00'
    sequence = b'\xff\xff\xff\xff'
    return count + txid + index_bytes + length + sequence

def test_input_from_utxo():
    txid = bytes.fromhex("cd67afd1602424c42cd2b1f0d711600978cb17b1bf045103893002b3b8c52c5a")
    index = 0
    calculated = input_from_utxo(txid, index)
    print(calculated.hex())

# Given an output script and value (in satoshis), return a serialized transaction output
def output_from_options(script: bytes, value: int) -> bytes:
    count = b'\x01'
    amount_bytes = value.to_bytes(8, LITTLE_ENDIAN)
    length = len(script).to_bytes(1, LITTLE_ENDIAN) # TODO dynamically aadjust size???
    return count + amount_bytes + length + script

def test_output_from_options():
    script = bytes.fromhex("cd67")
    value = 1234
    calculated = output_from_options(script, value)
    print(calculated.hex())

# Given a JSON utxo object, extract the public key hash from the output script
# and assemble the p2wpkh scriptcode as defined in BIP143
# <script length> OP_DUP OP_HASH160 <pubkey hash> OP_EQUALVERIFY OP_CHECKSIG
# https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#specification
def get_p2wpkh_scriptcode(utxo: object) -> bytes:
    data = json.loads(utxo)
    script_pub_key = bytes.fromhex(data['scriptPubKey'])
    pub_key_hash = script_pub_key[2:]
    return b'\x19\x76\xa9\x14' + pub_key_hash + b'\x88\xac'

# Compute the commitment hash for a single input and return bytes to sign.
# This implements the BIP 143 transaction digest algorithm
# https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#specification
# We assume only a single input and two outputs,
# as well as constant default values for sequence and locktime
def get_commitment_hash(outpoint: bytes, scriptcode: bytes, value: int, outputs: List[bytes]) -> bytes:
    def dsha256(data: bytes) -> bytes:
        return hashlib.new("sha256", hashlib.new("sha256", data).digest()).digest()

    # Version
    version = (2).to_bytes(4, LITTLE_ENDIAN)
    sequence = version

    # All TX input outpoints (only one in our case)
    sequence = sequence + dsha256(outpoint)

    # All TX input sequences (only one for us, always default value)
    sequence = sequence + dsha256(SEQUENCE)

    # Single outpoint being spent
    sequence = sequence + outpoint + (0).to_bytes(4, LITTLE_ENDIAN)

    # Scriptcode (the scriptPubKey in/implied by the output being spent, see BIP 143)
    sequence = sequence + scriptcode

    # Value of output being spent
    sequence = sequence + (value).to_bytes(8, LITTLE_ENDIAN)

    # Sequence of output being spent (always default for us)
    sequence = sequence + SEQUENCE

    # All TX outputs
    sequence = sequence + dsha256(outputs[0] + outputs[1])

    # Locktime (always default for us)
    sequence = sequence + (0).to_bytes(4, LITTLE_ENDIAN)

    # SIGHASH_ALL (always default for us)
    sequence = sequence + SIGHASH_ALL

    return dsha256(sequence)

def test_get_commitment_hash():
    outpoint = bytes.fromhex("db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a5477")
    outputs = [bytes.fromhex("b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac"),
                bytes.fromhex("0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac")]
    scriptcode = bytes.fromhex("1976a91479091972186c449eb1ded22b78e40d009bdf008988ac")
    value = int("00ca9a3b00000000", 16)
    calculated = get_commitment_hash(outpoint, scriptcode, value, outputs)
    expected = bytes.fromhex("64f3b0f4dd2bb3aa1ce8566d220cc74dda9df97d8490cc81d89d735c92e59fb6")
    ion_assert(calculated.hex(), expected.hex(), "test_get_commitment_hash")
    
# Given a JSON utxo object and a list of all of our wallet's witness programs,
# return the index of the derived key that can spend the coin.
# This index should match the corresponding private key in our wallet's list.
def get_key_index(utxo: object, programs: List[str]) -> int:
    pass

# Given a private key and message digest as bytes, compute the ECDSA signature.
# Bitcoin signatures:
# - Must be strict-DER encoded
# - Must have the SIGHASH_ALL byte (0x01) appended
# - Must have a low s value as defined by BIP 62:
#   https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki#user-content-Low_S_values_in_signatures
def sign(priv: bytes, msg: bytes) -> bytes:

    # Keep signing until we produce a signature with "low s value"
    # We will have to decode the DER-encoded signature and extract the s value to check it
    # Format: 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S] [sighash]
    pass

# Given a private key and transaction commitment hash to sign,
# compute the signature and assemble the serialized p2pkh witness
# as defined in BIP 141 (2 stack items: signature, compressed public key)
# https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#specification
def get_p2wpkh_witness(priv: bytes, msg: bytes) -> bytes:
    pass

# Given two private keys and a transaction commitment hash to sign,
# compute both signatures and assemble the serialized p2pkh witness
# as defined in BIP 141
# Remember to add a 0x00 byte as the first witness element for CHECKMULTISIG bug
# https://github.com/bitcoin/bips/blob/master/bip-0147.mediawiki
def get_p2wsh_witness(privs: List[bytes], msg: bytes) -> bytes:
    pass

# Given arrays of inputs, outputs, and witnesses, assemble the complete
# transaction and serialize it for broadcast. Return bytes as hex-encoded string
# suitable to broadcast with Bitcoin Core RPC.
# https://en.bitcoin.it/wiki/Protocol_documentation#tx
def assemble_transaction(inputs: List[bytes], outputs: List[bytes], witnesses: List[bytes]) -> str:
    version = (2).to_bytes(4, "little")
    flags = bytes.fromhex("0001")
    locktime = bytes.fromhex("00000000")

# Given arrays of inputs and outputs (no witnesses!) compute the txid.
# Return the 32 byte txid as a *reversed* hex-encoded string.
# https://developer.bitcoin.org/reference/transactions.html#raw-transaction-format
def get_txid(inputs: List[bytes], outputs: List[bytes]) -> str:
    version = (2).to_bytes(4, "little")
    locktime = bytes.fromhex("00000000")

# Spend a p2wpkh utxo to a 2 of 2 multisig p2wsh and return the txid
def spend_p2wpkh(state: object) -> str:
    FEE = 1000
    AMT = 1000000
    # Choose an unspent coin worth more than 0.01 BTC

    # Create the input from the utxo
    # Reverse the txid hash so it's little-endian

    # Compute destination output script and output

    # Compute change output script and output

    # Get the message to sign

    # Fetch the private key we need to sign with

    # Sign!

    # Assemble

    # Reserialize without witness data and double-SHA256 to get the txid

    # For debugging you can use RPC `testmempoolaccept ["<final hex>"]` here

    # return txid, final
    pass


# Spend a 2-of-2 multisig p2wsh utxo and return the txid
def spend_p2wsh(state: object, txid: str) -> str:
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
    test_get_commitment_hash()
    print("Test suite [ok]\n")

if __name__ == "__main__":
    test_suite()

    # Recover wallet state: We will need all key pairs and unspent coins
    # state = recover_wallet_state(EXTENDED_PRIVATE_KEY)
    # txid1, tx1 = spend_p2wpkh(state)
    # print(tx1)
    # tx2 = spend_p2wsh(state, txid1)
    # print(tx2)