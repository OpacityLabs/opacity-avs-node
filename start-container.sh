set -e
make register-opacity-node
make generate-notary-keys
./opacity-avs-node --config-file ./config/config.yaml