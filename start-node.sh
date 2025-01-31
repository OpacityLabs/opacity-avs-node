#!/bin/sh
set -e  # Exit on any error

# Verify binaries exist
if [ ! -f "/opacity-avs-node/target/release/register" ]; then
    echo "Error: register binary not found"
    exit 1
fi

if [ ! -f "/opacity-avs-node/target/release/opacity-avs-node" ]; then
    echo "Error: opacity-avs-node binary not found"
    exit 1
fi

/opacity-avs-node/target/release/register /opacity-avs-node/config/opacity.config.yaml 
/opacity-avs-node/target/release/opacity-avs-node --config-file /opacity-avs-node/config/config.yaml