# lightning-route-builder

A Python program that, given a route and a BOLT 11 invoice, computes the HTLC amount and expiry at each hop, including multi-part payments.

It reads a CSV of hops (`path_id`, `channel_name`, `cltv_delta`, `base_fee_msat`, `proportional_fee_ppm`), decodes the invoice for amount, payment secret and minimum final CLTV, then walks each path backwards to apply fees (`base + amount * ppm / 1_000_000`, integer division) and CLTV deltas. For a multi-part payment it splits the amount across paths and attaches a TLV payload with the payment secret on the last hop.

## How to run

Needs Python 3 and the `bolt11` package (`./run.sh` installs it if needed).

```sh
./run.sh example-route.csv <bolt11_invoice> <current_block_height>
```

`example-route.csv` is a tiny self-made sample that shows the input columns. The invoice should be a bech32 BOLT 11 payment request with a non-zero amount (for example one you create on regtest or signet). Output is one CSV line per hop: `path_id,channel_name,htlc_amount_msat,htlc_expiry,tlv`.
