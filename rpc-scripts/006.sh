# Find the transaction that spends a previous block's coinbase.

# Get the coinbase transaction output of Block 256128 (i.e. the txid)
blk_a_hash=$(bitcoin-cli getblockhash 256128)
blk_a=$(bitcoin-cli getblock $blk_a_hash)
coinbase_txid=$(echo "$blk_a" | jq -r '.tx[0]')

# Get the input transactions of Block 257343
blk_2_hash=$(bitcoin-cli getblockhash 257343)
blk_2=$(bitcoin-cli getblock $blk_2_hash)
txids=$(echo "$blk_2" | jq -r '.tx[]')

# Locate the txid in Block 257343 that contains the coinbase txid
i=false
for txid in $txids
do
  # echo $txid # This is the transaction that might contain the result
  tx=$(bitcoin-cli getrawtransaction $txid true)
  test_txid=$(echo "$tx" | jq  -r '.vin[].txid')

  if [ $i == true ]
  then 
    break
  fi

  for id in $test_txid
  do
    if [ $id == $coinbase_txid ]
    then
      echo $txid
      i=true
      break
    fi
  done

done
