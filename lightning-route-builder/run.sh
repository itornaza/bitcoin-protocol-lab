#!/bin/bash
# Usage: ./run.sh <route.csv> <bolt11_invoice> <current_block_height>
if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <input_file_path> <bolt11_invoice> <current_block_height>"
    exit 1
fi

input_file_path="$1"
payment_request="$2"
current_block_height="$3"

if ! python -c "import bolt11" &> /dev/null; then
    pip install bolt11
fi

python ln-route-builder.py "$input_file_path" "$payment_request" "$current_block_height"
