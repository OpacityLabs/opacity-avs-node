#!/bin/bash
set -e
# make register-opacity-node
make generate-notary-keys
gramine-sgx opacity-avs-node