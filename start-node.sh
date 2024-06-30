#!/bin/bash
set -e
make register-opacity-node
make generate-notary-keys
./target/release/opacity-avs-node --config-file ./config/config.yaml