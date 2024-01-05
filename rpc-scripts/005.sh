# Build a 1-of-4 P2SH multisig address from public keys in a transaction's inputs.
#   `37d966a263350fe747f1c606b159987545844a493dd38d84b070027a895c4517`

txid="37d966a263350fe747f1c606b159987545844a493dd38d84b070027a895c4517"

# Get the transaction from the txid
tx=$(bitcoin-cli getrawtransaction $txid true)

# From the input transactions get the public keys from witness
pubs=$(echo "$tx" | jq  -r '.vin[].txinwitness[1]')

pks=()
i=0
for pub in $pubs
do
    pks[i]=$pub
    ((i++))
done

multisig=$(bitcoin-cli createmultisig 1 "[\"${pks[0]}\",\"${pks[1]}\",\"${pks[2]}\",\"${pks[3]}\"]")
echo "$multisig" | jq -r '.address'
