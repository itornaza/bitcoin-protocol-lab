#!/bin/bash
# Fill in lncli commands to lookup the base fee of the node below broadcast for the channel id provided.

# Get the base fee rate the node advertises in its forwarding policy for a channel
# base_fee_msat and bitcoin.basefee in LND

node="0325ecd6d2d8739681e2f7644f4221ed942b76d6b7825d4e730671ad17fb0d50e5"
channel_id="2811451232288768"

# This lncli command allows the script to run against signet nodes for testing purposes, refer to it using $lncli.
# You may comment it out and use your own testing node if you would like, but this line *must* be uncommented when you push to test.
wd=$(pwd)
lncli="${LNCLI:-lncli -n=signet}"
# lncli="lncli -n=signet "

# 1. Get the number of the node with the given node number
chaininfo=$(echo "$lncli getchaninfo $channel_id")
node_number_line=$($chaininfo | grep $node) 
node_number_element=$(echo $node_number_line | grep -oE 'node[0-9]+')
node_number=$(echo "$node_number_element" | sed "s/"node"//g")

# 2. Get the respective fee_base_msat
fee_lines=$($chaininfo | grep "fee_base_msat") 
sed_parameter=$(echo $node_number'p')
echo $fee_lines | grep -oE '[0-9]+' | sed -n $sed_parameter
