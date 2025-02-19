#!/bin/sh
set -e  # Exit immediately if a command exits with a non-zero status

echo "Starting registration process..."
/opacity-avs-node/target/release/register /opacity-avs-node/config/opacity.config.yaml
if [ $? -ne 0 ]; then
    echo "Registration failed"
    exit 1
fi
echo "Registration completed successfully"

echo "Starting opacity-avs-node..."
/opacity-avs-node/target/release/opacity-avs-node --config-file /opacity-avs-node/config/config.yaml