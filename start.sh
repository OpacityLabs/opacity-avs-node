#!/bin/sh
set -e  # Exit immediately if a command exits with a non-zero status

echo "Starting registration process..."
OUTPUT=$(/opacity-avs-node/target/release/register /opacity-avs-node/config/opacity.config.yaml 2>&1)
EXIT_CODE=$?
if echo "$OUTPUT" | grep -q "already registered"; then
    echo "Operator is already registered, continuing setup..."
    EXIT_CODE=0
elif [ $EXIT_CODE -ne 0 ]; then
    echo "Registration failed: $OUTPUT"
    exit 1
fi
echo "Registration completed successfully"

echo "Starting opacity-avs-node..."
/opacity-avs-node/target/release/opacity-avs-node --config-file /opacity-avs-node/config/config.yaml
