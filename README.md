# bitcoin-protocol-lab

Bitcoin protocol implementations from the byte level up: RPC, wallets, transactions, block building and Lightning routing (2024).

![bitcoin-protocol-lab](docs/social.jpg)

## Projects

| Folder | What it does | Language |
| --- | --- | --- |
| [rpc-scripts](rpc-scripts/) | `bitcoin-cli` scripts that inspect blocks and transactions, derive a taproot address, build a multisig, and read a witness public key | Bash |
| [signet-wallet](signet-wallet/) | Signet wallet that derives keys, scans for its coins, and builds and signs p2wpkh and 2-of-2 multisig spends | Python |
| [block-builder](block-builder/) | Selects mempool transactions under the weight limit, maximizing fees while respecting parent/child order | Python |
| [lightning-node-ops](lightning-node-ops/) | Looks up a channel's advertised base fee with `lncli`, plus preimages from settled signet payments | Bash |
| [lightning-route-builder](lightning-route-builder/) | Computes per-hop fees, CLTV deltas and HTLCs, including multi-part payments | Python |

## How to run

- **rpc-scripts** — with `bitcoin-cli` pointed at a node that has `-txindex=1`, run e.g. `./rpc-scripts/001.sh`. Several scripts also need `jq`.
- **signet-wallet** — `./signet-wallet/run_balance.sh <extended_private_key> [wallet_name]` against a synced signet node. Spending needs `SPEND_TXID`, `SPEND_VOUT`, `SPEND_VALUE_SATS` and `SPEND_SCRIPTPUBKEY` in the environment as well; see [signet-wallet/README.md](signet-wallet/README.md).
- **block-builder** — `python block-builder/builder.py block-builder/test_mempool.csv`. For a full run, pass your own `mempool.csv` (`txid,fee,weight,parent_txids`).
- **lightning-node-ops** — `./lightning-node-ops/002.sh <node_pubkey> <channel_id>` (optional `LNCLI=...` for cert and macaroon paths).
- **lightning-route-builder** — `./lightning-route-builder/run.sh lightning-route-builder/example-route.csv <bolt11_invoice> <current_block_height>`.

Each folder has a short README with details.

## Related open-source work

Contributions:

- [bitcoin/bitcoin#30840](https://github.com/bitcoin/bitcoin/pull/30840)
- [bitcoin/bitcoin#30953](https://github.com/bitcoin/bitcoin/pull/30953)
- [bitcoin/bitcoin#30994](https://github.com/bitcoin/bitcoin/pull/30994)
- [stratum-mining/sv2-spec#91](https://github.com/stratum-mining/sv2-spec/pull/91)
- [stratum-mining/sv2-spec#92](https://github.com/stratum-mining/sv2-spec/pull/92)
