# lightning-node-ops

Small Lightning node helpers.

`002.sh` asks `lncli getchaninfo` for a channel and prints the base fee (msat) advertised by a chosen peer on that channel.

`001-preimage.txt` and `003-preimage.txt` are payment preimages from invoices settled while operating a signet Lightning node.

## How to run

```sh
# Default: lncli -n=signet on the local node
./002.sh <node_pubkey> <channel_id>

# Or, for a remote node, pass your own lncli invocation (including TLS cert and macaroon paths):
LNCLI="lncli -n=signet --rpcserver=host:port --tlscertpath=/path/tls.cert --macaroonpath=/path/admin.macaroon" \
  ./002.sh <node_pubkey> <channel_id>
```
