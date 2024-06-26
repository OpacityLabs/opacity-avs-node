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

	"github.com/Layr-Labs/eigenlayer-cli/pkg/types"
	sdkecdsa "github.com/Layr-Labs/eigensdk-go/crypto/ecdsa"
	"github.com/Layr-Labs/eigensdk-go/utils"

	sdkutils "github.com/Layr-Labs/eigensdk-go/utils"

	contractAVSDirectory "github.com/OpacityLabs/opacity-avs-node/cli/bindings/AVSDirectory"
	contractDelegationManager "github.com/OpacityLabs/opacity-avs-node/cli/bindings/DelegationManager"
	contractOpacityServiceManager "github.com/OpacityLabs/opacity-avs-node/cli/bindings/OpacityServiceManager"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/urfave/cli"
)

var (
	/* Required Flags */
	ConfigFileFlag = cli.StringFlag{
		Name:     "config",
		Required: true,
		Usage:    "Load configuration from `FILE`",
	}
	/* Optional Flags */
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
	OperatorConfig              string `yaml:"operator_config"`
}

func FailIfNoFile(path string) error {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		log.Panicln("File does not exist:", path)
	}
	return nil
}

func RegisterOperatorWithAvs(ctx *cli.Context) error {

	configPath := ctx.GlobalString(ConfigFileFlag.Name)
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

	if err != nil {
		return err
	}
	opacityAddress := common.HexToAddress(nodeConfig.OpacityAVSAddress)
	avsDirectoryAddress := common.HexToAddress(nodeConfig.AVSDirectoryAddress)
	delegationManagerAddress := common.HexToAddress(nodeConfig.EigenLayerDelegationManager)
	operatorAddress := crypto.PubkeyToAddress(operatorEcdsaPrivKey.PublicKey)
	avsDirectoryContract, err := contractAVSDirectory.NewContractAVSDirectoryCaller(avsDirectoryAddress, client)
	delegationManagerContract, err := contractDelegationManager.NewContractDelegationManager(delegationManagerAddress, client)
	if err != nil {
		log.Fatal(err)
	}
	opacityServiceManagerContract, err := contractOpacityServiceManager.NewContractOpacityServiceManager(opacityAddress, client)
	if err != nil {
		log.Fatal(err)
	}

	FailIfNoFile(nodeConfig.OperatorConfig)
	operatorConfig, err := readConfigFile(nodeConfig.OperatorConfig, nodeConfig.AVSDirectoryAddress)
	if err != nil {
		log.Fatal(err)
		return err
	}
	fmt.Println("Operator Config:", operatorConfig)

	// Check if operator registered to EigenLayer
	isOperatorRegistered, err := delegationManagerContract.IsOperator(nil, operatorAddress)
	if err != nil {
		log.Fatal(err)
		return err
	}
	if !isOperatorRegistered {
		// Register operator to EigenLayer
		fmt.Println("Operator not registered to EigenLayer, registering...")
		if len(operatorConfig.Operator.MetadataUrl) == 0 {
			log.Panicln("Metadata URL not set in operator config file. Exiting...")
		}

		opDetails := contractDelegationManager.IDelegationManagerOperatorDetails{
			EarningsReceiver:         common.HexToAddress(operatorConfig.Operator.EarningsReceiverAddress),
			StakerOptOutWindowBlocks: operatorConfig.Operator.StakerOptOutWindowBlocks,
			DelegationApprover:       common.HexToAddress(operatorConfig.Operator.DelegationApproverAddress),
		}
		res, err := delegationManagerContract.RegisterAsOperator(nil, opDetails, operatorConfig.Operator.MetadataUrl)
		if err != nil {
			log.Fatal(err)
			return err
		}
		fmt.Println("Register Operator to EigenLayer TX:", res.Hash().Hex())
		time.Sleep(5 * time.Second)
	} else {
		fmt.Println("Operator already registered to EigenLayer")
	}

	// Check if operator registered to AVS
	operatorStatus, err := avsDirectoryContract.AvsOperatorStatus(nil, opacityAddress, operatorAddress)
	if err != nil {
		log.Fatal(err)
		return err
	}

	if operatorStatus == 0 {
		// Register operator to AVS

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

	} else {
		fmt.Println("Operator already registered to AVS")
		return nil
	}

}

func readConfigFile(path string, avsDirectoryAddress string) (*types.OperatorConfig, error) {
	var operatorCfg types.OperatorConfig
	err := utils.ReadYamlConfig(path, &operatorCfg)
	if err != nil {
		return nil, err
	}

	operatorCfg.ELAVSDirectoryAddress = avsDirectoryAddress
	return &operatorCfg, nil
}
