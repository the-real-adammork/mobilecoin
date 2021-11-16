#!/bin/bash

NETWORK_ENVIRONMENT="$1"

echo -e "\nDownloading MrEnclave values for $NETWORK_ENVIRONMENT\n"
export NETWORK=$NETWORK_ENVIRONMENT; ./download_sigstruct.sh 

echo -e "\nConsensus Enclave"
cargo run -p mc-sgx-css-dump --release 2>/dev/null < ./consensus-enclave.css | grep MRENCLAVE | sed 's/,//'
echo -e "\nView Enclave"
cargo run -p mc-sgx-css-dump --release 2>/dev/null < ./view-enclave.css | grep MRENCLAVE | sed 's/,//'
echo -e "\nIngest Enclave"
cargo run -p mc-sgx-css-dump --release 2>/dev/null < ./ingest-enclave.css  | grep MRENCLAVE | sed 's/,//'
echo -e "\nLedger Enclave"
cargo run -p mc-sgx-css-dump --release 2>/dev/null < ./ledger-enclave.css  | grep MRENCLAVE | sed 's/,//'
echo -e "\n"
