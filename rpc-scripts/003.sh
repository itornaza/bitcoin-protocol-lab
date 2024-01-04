# Count transaction outputs created in a given block.

# Get the hash of the block 123456
hash=$(bitcoin-cli getblockhash 123456)

# Get the block from the hash
block=$(bitcoin-cli getblock $hash)

# Get all transactions from the block
txids=$(echo "$block" | jq -r '.tx[]')

# Calculate all outputs contained in all transactions
new_outputs=0
for txid in $txids
do
    # Get transaction from txid
    tx=$(bitcoin-cli getrawtransaction $txid true)
    
    # Get transaction outputs
    tx_outputs=$(echo "$tx" | jq '.vout | length')

    # Increment new outputs
    new_outputs=$(($new_outputs + $tx_outputs))
done

echo $new_outputs
