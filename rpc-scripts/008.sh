# Identify the public key that signed a given transaction input.
#   `e5969add849689854ac7f28e45628b89f7454b83e9699e551ce14b6f90c86163`

txid="e5969add849689854ac7f28e45628b89f7454b83e9699e551ce14b6f90c86163"

tx=$(bitcoin-cli getrawtransaction $txid true)
witness=$(echo "$tx" | jq -r '.vin[0].txinwitness[]')

# Get a dump of the witness to extract the public key
# echo $witness 

# Mannual extraction of the public key
echo 025d524ac7ec6501d018d322334f142c7c11aa24b9cffec03161eca35a1e32a71f

# Check the result