# Build a 1-of-4 P2SH multisig address from public keys in a transaction's inputs.
#   `37d966a263350fe747f1c606b159987545844a493dd38d84b070027a895c4517`

# Expected: %0A3GyWg1CCD3RDpbwCbuk9TTRQptkRfczDz8

# 02bbb4ba3f39b5f3258f0014d5e4eab5a6990009e3e1dba6e8eaff10b3832394f7
# 03aaf17b1a7b4108f7e5bc4f7d59c20f7fb1a72dbc74a9a3d6d1f8488df159c760
# 03a6d919c76d9117c23570a767450013edf31cf6be7d3b5a881c06a9aa1f2c24ce
# 0383d12258e3e294a6d7754336f6b4baef992ec4b91694d3460bcb022b11da8cd2

txid="37d966a263350fe747f1c606b159987545844a493dd38d84b070027a895c4517"

# Get the transaction from the txid
tx=$(bitcoin-cli getrawtransaction $txid true)

# Get the input transactions to this transaction
pubs=$(echo "$tx" | jq  -r '.vin[].txinwitness[1]')

pub_1="${pubs[0]}"
pub_2="${pubs[1]}"
pub_3="${pubs[2]}"
pub_4="${pubs[3]}"

# echo $pub_1
# echo $pub_2
# echo $pub_3
# echo $pub_4

# echo "["$pub_1","$pub_2","$pub_3","$pub_4"]"
# multisig=$(bitcoin-cli createmultisig 4 "[\"$pub_1\",\"$pub_2\",\"$pub_3\",\"$pub_4\"]" p2sh-segwit)

multisig=$(bitcoin-cli createmultisig 1 "[\"02bbb4ba3f39b5f3258f0014d5e4eab5a6990009e3e1dba6e8eaff10b3832394f7\",\"03aaf17b1a7b4108f7e5bc4f7d59c20f7fb1a72dbc74a9a3d6d1f8488df159c760\",\"03a6d919c76d9117c23570a767450013edf31cf6be7d3b5a881c06a9aa1f2c24ce\",\"0383d12258e3e294a6d7754336f6b4baef992ec4b91694d3460bcb022b11da8cd2\"]")
echo "$multisig" | jq -r '.address'
