package actions

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"

	sdkecdsa "github.com/Layr-Labs/eigensdk-go/crypto/ecdsa"
	sdkutils "github.com/Layr-Labs/eigensdk-go/utils"
	"github.com/Layr-Labs/incredible-squaring-avs/core/config"
	contractAVSDirectory "github.com/OpacityLabs/opacity-avs-node/cli/bindings/AVSDirectory"
	contractDelegationManager "github.com/OpacityLabs/opacity-avs-node/cli/bindings/DelegationManager"
	contractOpacityServiceManager "github.com/OpacityLabs/opacity-avs-node/cli/bindings/OpacityServiceManager"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/urfave/cli"
)

type OpacityConfig struct {
	// used to set the logger level (true = info, false = debug)
	Production                  bool   `yaml:"production"`
	OpacityAVSAddress           string `yaml:"opacity_avs_address"`
	AVSDirectoryAddress         string `yaml:"avs_directory_address"`
	EigenLayerDelegationManager string `yaml:"eigenlayer_delegation_manager"`
	ChainId                     int    `yaml:"chain_id"`
	EthRpcUrl                   string `yaml:"eth_rpc_url"`
	ECDSAPrivateKeyStorePath    string `yaml:"ecdsa_private_key_store_path"`
}

func FailIfNoFile(path string) error {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		log.Panicln("File does not exist:", path)
	}
	return nil
}

func RegisterOperatorWithAvs(ctx *cli.Context) error {

	configPath := ctx.GlobalString(config.ConfigFileFlag.Name)
	fmt.Println("Config Path:", configPath)

	FailIfNoFile(configPath)

	nodeConfig := OpacityConfig{}
	err := sdkutils.ReadYamlConfig(configPath, &nodeConfig)
	if err != nil {
		return err
	}

	configJson, err := json.MarshalIndent(nodeConfig, "", "  ")
	if err != nil {
		log.Fatalf(err.Error())
	}
	fmt.Println("Config:", string(configJson))

	ecdsaKeyPassword, ok := os.LookupEnv("OPERATOR_ECDSA_KEY_PASSWORD")
	if !ok {
		log.Panicln("OPERATOR_ECDSA_KEY_PASSWORD env var not set. using empty string")
	}

	FailIfNoFile(nodeConfig.ECDSAPrivateKeyStorePath)

	operatorEcdsaPrivKey, err := sdkecdsa.ReadKey(
		nodeConfig.ECDSAPrivateKeyStorePath,
		ecdsaKeyPassword,
	)

	if operatorEcdsaPrivKey == nil {
		log.Panicln("Unable to decrypt operator private key.")
	}

	fmt.Println(crypto.PubkeyToAddress(operatorEcdsaPrivKey.PublicKey).Hex())
	if err != nil {
		return err
	}
	client, err := ethclient.Dial(nodeConfig.EthRpcUrl)
	if err != nil {
		return err
	}
	opacityAddress := common.HexToAddress(nodeConfig.OpacityAVSAddress)
	avsDirectoryAddress := common.HexToAddress(nodeConfig.AVSDirectoryAddress)
	delegationManagerAddress := common.HexToAddress(nodeConfig.EigenLayerDelegationManager)
	operatorAddress := crypto.PubkeyToAddress(operatorEcdsaPrivKey.PublicKey)
	operator2Address := common.HexToAddress("0xFE8463CA0A9b436FdC5f75709AD5a43961802d69")
	avsDirectoryContract, err := contractAVSDirectory.NewContractAVSDirectoryCaller(avsDirectoryAddress, client)
	delegationManager, err := contractDelegationManager.NewContractDelegationManagerCaller(delegationManagerAddress, client)
	if err != nil {
		log.Fatal(err)
	}
	opacityServiceManagerContract, err := contractOpacityServiceManager.NewContractOpacityServiceManager(opacityAddress, client)
	if err != nil {
		log.Fatal(err)
	}

	// Check if operator registered to EigenLayer
	isOperatorRegistered, err := delegationManager.IsOperator(nil, operatorAddress)
	if err != nil {
		log.Fatal(err)
		return err
	}
	fmt.Println("Operator registered:", isOperatorRegistered)
	isOperatorRegistered2, err := delegationManager.IsOperator(nil, operator2Address)
	if err != nil {
		log.Fatal(err)
		return err
	}
	fmt.Println("Operator2 registered:", isOperatorRegistered2)

	// Check if operator registered to avs
	operatorStatus, err := avsDirectoryContract.AvsOperatorStatus(nil, opacityAddress, operatorAddress)
	if err != nil {
		log.Fatal(err)
		return err
	}
	fmt.Println("Operator status:", operatorStatus)
	operator2Status, err := avsDirectoryContract.AvsOperatorStatus(nil, opacityAddress, operator2Address)
	if err != nil {
		log.Fatal(err)
		return err
	}
	fmt.Println("Operator2 status:", operator2Status)
	return nil

	saltBytes := make([]byte, 32)
	var salt [32]byte
	rand.Read(saltBytes)
	copy(salt[:], saltBytes)

	expiry := time.Now().UTC().Unix()
	expiry += 60 * 60 * 24

	expiryBigInt := big.NewInt(int64(expiry))
	fmt.Println("Expiry:", expiryBigInt)
	fmt.Println("operatorAddress:", operatorAddress)
	fmt.Println("avsAddress:", opacityAddress)

	hash, err := avsDirectoryContract.CalculateOperatorAVSRegistrationDigestHash(nil, operatorAddress, opacityAddress, salt, expiryBigInt)
	if err != nil {
		log.Fatal(err)

	}
	fmt.Println("Registering operator with Hash", hash)
	operatorSignature, err := crypto.Sign(hash[:], operatorEcdsaPrivKey)
	operatorSignature[64] += 27
	if err != nil {
		log.Fatal(err)
	}

	var signature = contractOpacityServiceManager.ISignatureUtilsSignatureWithSaltAndExpiry{
		Signature: operatorSignature,
		Salt:      salt,
		Expiry:    expiryBigInt,
	}

	fmt.Println("Signature:", signature)

	nonce, err := client.PendingNonceAt(context.Background(), operatorAddress)
	if err != nil {
		log.Fatal(err)
	}

	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	auth, err := bind.NewKeyedTransactorWithChainID(operatorEcdsaPrivKey, big.NewInt(int64(nodeConfig.ChainId)))

	if err != nil {
		log.Fatal(err)

	}

	auth.Nonce = big.NewInt(int64(nonce))
	auth.Value = big.NewInt(0)     // in wei
	auth.GasLimit = uint64(300000) // in units
	auth.GasPrice = gasPrice

	res, err := opacityServiceManagerContract.RegisterOperatorToAVS(auth, operatorAddress, signature)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("Register Operator to AVS TX:", res.Hash().Hex())

	return nil
}
