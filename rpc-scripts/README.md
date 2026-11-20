# rpc-scripts

Bash scripts that query a Bitcoin Core node with `bitcoin-cli` and `jq`.

They look up a block hash, verify a signed message, count outputs in a block, derive a taproot address from an extended public key, build a 1-of-4 P2SH multisig from public keys in a transaction's inputs, find the spend of a coinbase, locate an unspent output from a historical block, and read a signing public key from a transaction witness.

## How to run

Point `bitcoin-cli` at a Bitcoin Core node with the transaction index enabled (`-txindex=1`), then run any script in this folder, for example:

```sh
./001.sh
```

`jq` is required for the scripts that parse JSON RPC results.
