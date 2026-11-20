#!/bin/bash
# Look up the base fee (msat) a node advertises on a given channel.
# Usage:
#   ./002.sh <node_pubkey> <channel_id>
#   NODE=... CHANNEL_ID=... ./002.sh
# Optional: LNCLI="lncli -n=signet --rpcserver=... --tlscertpath=... --macaroonpath=..."

set -euo pipefail

node="${1:-${NODE:-}}"
channel_id="${2:-${CHANNEL_ID:-}}"
if [ -z "$node" ] || [ -z "$channel_id" ]; then
    echo "Usage: $0 <node_pubkey> <channel_id>" >&2
    echo "Or set NODE and CHANNEL_ID. Optionally set LNCLI." >&2
    exit 1
fi

lncli="${LNCLI:-lncli -n=signet}"

# 1. Get the number of the node with the given node number
chaininfo=$(echo "$lncli getchaninfo $channel_id")
node_number_line=$($chaininfo | grep $node)
node_number_element=$(echo $node_number_line | grep -oE 'node[0-9]+')
node_number=$(echo "$node_number_element" | sed "s/"node"//g")

# 2. Get the respective fee_base_msat
fee_lines=$($chaininfo | grep "fee_base_msat")
sed_parameter=$(echo $node_number'p')
echo $fee_lines | grep -oE '[0-9]+' | sed -n $sed_parameter
