# block-builder

A block template builder that reads a mempool snapshot and writes an ordered list of transaction IDs.

It sorts transactions by fee rate, includes standalone transactions when they fit, and otherwise pulls in a transaction together with its unconfirmed ancestors. A family is skipped when the unmined members' combined fee rate is far below the current transaction's rate. Parents are always written before children. The default weight limit is 4,000,000.

## How to run

```sh
python builder.py                  # reads mempool.csv, writes block.txt
python builder.py test_mempool.csv # small fixture included in this folder
./run_builder.sh test_mempool.csv
```

Input format, one transaction per line, no header:

```
txid,fee,weight,parent_txids
```

`fee` is in satoshis, `weight` is transaction weight, and `parent_txids` is a semicolon-separated list of immediate unconfirmed parents (empty if there are none). See `test_mempool.csv` for a tiny example. The program does not ship a full mempool dump; point it at your own snapshot in that format.
