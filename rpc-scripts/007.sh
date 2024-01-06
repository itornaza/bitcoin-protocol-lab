# Find the address of an unspent output from a given block.

blk_hash=$(bitcoin-cli getblockhash 123321)
blk=$(bitcoin-cli getblock $blk_hash)
txids=$(echo "$blk" | jq -r '.tx[]')

for txid in $txids
do
  tx=$(bitcoin-cli getrawtransaction $txid true)
  vouts=$(echo "$tx" | jq '.vout | length')
  vouts=$(($vouts - 1)) # it will be used as the maximum index

  for i in $(seq 0 $vouts)
  do
    utxo=$(bitcoin-cli gettxout $txid $i)
    echo "$utxo" | jq -r '.scriptPubKey.address'
  done

done