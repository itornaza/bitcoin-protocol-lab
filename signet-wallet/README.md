# signet-wallet

A signet wallet in Python that works from an extended private key, without using Bitcoin Core's wallet.

`python/balance.py` decodes a BIP32 extended private key, derives BIP84 child keys, computes p2wpkh witness programs, and scans signet blocks over `bitcoin-cli` to recover received and spent coins and print a confirmed balance.

`python/spend.py` builds and signs a p2wpkh spend into a 2-of-2 p2wsh output, then spends that output, using BIP143 commitment hashes and low-S signatures. An `OP_RETURN` output carries a short nym.

## How to run

Needs Python 3, the `ecdsa` package, and `bitcoin-cli` talking to a synced signet node.

```sh
# Recover a balance (key from argv or EXTENDED_PRIVATE_KEY)
./run_balance.sh <extended_private_key> [wallet_name]

# Build and sign spends. Also set the coin being spent:
#   SPEND_TXID, SPEND_VOUT, SPEND_VALUE_SATS, SPEND_SCRIPTPUBKEY
# Optional: SPEND_KEY_INDEX (derived child that owns the coin, default 0)
EXTENDED_PRIVATE_KEY=<extended_private_key> \
  SPEND_TXID=... SPEND_VOUT=0 SPEND_VALUE_SATS=... SPEND_SCRIPTPUBKEY=... \
  ./run_spend.sh
```

Do not hard-code an extended private key in the source. Use a signet or regtest key you control.
