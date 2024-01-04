# Derive a taproot address from an extended public key via descriptors.
#   `xpub6Cx5tvq6nACSLJdra1A6WjqTo1SgeUZRFqsX5ysEtVBMwhCCRa4kfgFqaT2o1kwL3esB1PsYr3CUdfRZYfLHJunNWUABKftK2NjHUtzDms2`

xpub="xpub6Cx5tvq6nACSLJdra1A6WjqTo1SgeUZRFqsX5ysEtVBMwhCCRa4kfgFqaT2o1kwL3esB1PsYr3CUdfRZYfLHJunNWUABKftK2NjHUtzDms2"

# Construct the descriptor
descriptor="tr($xpub/*)#q4q7qurj"

# Get the 100th Taproot derived addresses array
addresses=$(bitcoin-cli deriveaddresses "$descriptor" "[100,100]")
echo $addresses

# Get the lone address from the addresses array
address=$(echo "$addresses" | jq -r '.[0]')
echo $address
