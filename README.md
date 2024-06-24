# Opacity AVS Node

For support contact @EulerLagrange217 on telegram

## Introduction

The Opacity node must be run with a Intel SGX with SGX2 enabled. If you want to use a cloud provider, please use one of these:

- Azure (https://learn.microsoft.com/en-us/azure/confidential-computing/quick-create-portal)
- OVH (https://help.ovhcloud.com/csm/en-dedicated-servers-intel-sgx?id=kb_article_view&sysparm_article=KB0044005)

We recommend you use Ubuntu 22.04

We DO NOT support AWS Enclaves!

## Clone this repo

`git clone https://github.com/OpacityLabs/opacity-avs-node && cd opacity-avs-node`

## Check SGX

First we should check you are on a valid SGX machine.

Head over to https://support.fortanix.com/hc/en-us/articles/4414753648788-SGX-Detect-Tool and download the binary for your operating system.

Ubuntu 22.04:
`wget https://download.fortanix.com/sgx-detect/ubuntu22.04/sgx-detect?_gl=1*1j4w6dh*_gcl_au*MTM1MDY4MDQ2NS4xNzE4ODUwMTk1 -O sgx-detect`

`chmod +x sgx-detect`

`sudo ./sgx-detect`

You should see:
<img width="527" alt="Screenshot 2024-06-20 at 1 39 41 PM" src="https://github.com/OpacityLabs/opacity-avs-node/assets/76923506/2cdd75c3-c426-4619-a9cc-a9455b715dc0">

If you see any red on the output, please contact @EulerLagrange217 on telegram

## Register Node Operator with EigenLayer

The following is not Opacity specific but for EigenLayer. We will be summarizing the following verbose guide: https://docs.eigenlayer.xyz/eigenlayer/operator-guides/operator-installation (see this guide for software requirements)

1. Install EigenLayer-CLI

For Ubuntu 22.04:
`make install-eigenlayer-cli`

2. Create ECDSA and BLS keys

`make generate-keys`

OR

`eigenlayer operator keys create --key-type ecdsa opacity`

`eigenlayer operator keys create --key-type bls opacity`

To check if you did it right you can run:

`make list-keys`

<img width="1487" alt="Screenshot 2024-06-20 at 1 40 44 PM" src="https://github.com/OpacityLabs/opacity-avs-node/assets/76923506/5b96937d-fa79-4d68-9a5a-d86785536c4c">

3. Fund ECDSA Wallet with testnet ETH

We need to load your operator wallet with some holesky eth to submit transactions. See: https://docs.eigenlayer.xyz/eigenlayer/restaking-guides/restaking-user-guide/testnet/obtaining-testnet-eth-and-liquid-staking-tokens-lsts

4. Operator config

We need to generate some metadata so eigenlayer can show you nicely in their UI.

I would recommend forking this repo: https://github.com/Hmac512/eigenpod and changing the values to what you want.

Run:

`eigenlayer operator config create`

Say yes to populating the config

```
Enter your operator address: 0xfe8463ca0a9b436fdc5f75709ad5a43961802d68
Enter your earnings address (default to your operator address): 0xfe8463ca0a9b436fdc5f75709ad5a43961802d68
Enter your ETH rpc url: https://ethereum-holesky.publicnode.com
Select your network: holesky
Select your signer type: local_keystore
Enter your ecdsa key path: /home/ubuntu/.eigenlayer/operator_keys/opacity.ecdsa.key.json
```

This will generate a operator.yaml file that should look like:

```operator:
    address: 0xFE8463CA0A9b436FdC5f75709AD5a43961802d68
    earnings_receiver_address: 0xFE8463CA0A9b436FdC5f75709AD5a43961802d68
    delegation_approver_address: "0x0000000000000000000000000000000000000000"
    staker_opt_out_window_blocks: 0
    metadata_url: "https://raw.githubusercontent.com/Hmac512/eigenpod/main/metadata.json?"
el_delegation_manager_address: 0xA44151489861Fe9e3055d95adC98FbD462B948e7
eth_rpc_url: https://ethereum-holesky.publicnode.com
private_key_store_path: /home/ubuntu/.eigenlayer/operator_keys/opacity.ecdsa.key.json
signer_type: local_keystore
chain_id: 17000
fireblocks:
    api_key: ""
    secret_key: ""
    base_url: ""
    vault_account_name: ""
    secret_storage_type: ""
    aws_region: ""
    timeout: 0
web3:
    url: ""
```

Remember to fill out the metadata_url to your forked repo.

Run `eigenlayer operator keys list` and check that the private_key_store_path matches the ECDSA Key location in operator.yaml. In ./config/opacity.config.yaml check that ecdsa_private_key_store_path and bls_private_key_store_path also match the expected values.

Make a backup of your operator.yaml for convenience

5. Register Node Operator

run:

`make register-eigen-operator`
OR
`eigenlayer operator register operator.yaml`

You should see:
<img width="1572" alt="Screenshot 2024-06-20 at 1 35 59 PM" src="https://github.com/OpacityLabs/opacity-avs-node/assets/76923506/4645e4b4-3599-4b65-a0e3-a6baa34af987">

6. Use some Holesky eth to get holesky stETH:

https://stake-holesky.testnet.fi/

7. Retstake the stETH:

https://holesky.eigenlayer.xyz/restake/stETH/deposit
NOTE: the website may direct you to select an operator before depositing (and yours may not be on the list). select an operator at random, they will request 3 signatures (approve, deposit, delegate) sign the first two, and reject the third.

8. Delegate to your operator:

navigate to https://holesky.eigenlayer.xyz/operator/<your operator address>
and push the delegate button.

## Install Docker

See: https://docs.docker.com/engine/install

For Ubuntu 22.04:

`sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin`

## Register Node to Opacity AVS

Run:

`OPERATOR_ECDSA_KEY_PASSWORD="" make register-opacity-node`
