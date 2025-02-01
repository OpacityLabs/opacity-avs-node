#!/bin/sh
set -e  # Exit on any error

if [ ! -f "/opacity-avs-node/target/release/register" ]; then
    echo "Error: register binary not found"
    exit 1
fi

/opacity-avs-node/target/release/register /opacity-avs-node/config/opacity.config.yaml 