# Build a 1-of-4 P2SH multisig address from public keys in a transaction's inputs.
#   `37d966a263350fe747f1c606b159987545844a493dd38d84b070027a895c4517`

txid="37d966a263350fe747f1c606b159987545844a493dd38d84b070027a895c4517"

tx=$(bitcoin-cli getrawtransaction $txid true)

txids=$(echo "$tx" | jq  -r '.vin[].txid')
echo $txids

