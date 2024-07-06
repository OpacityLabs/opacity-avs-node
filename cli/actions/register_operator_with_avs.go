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

	chainioutils "github.com/Layr-Labs/eigensdk-go/chainio/utils"
	contractRegistryCoordinator "github.com/Layr-Labs/eigensdk-go/contracts/bindings/RegistryCoordinator"
	"github.com/Layr-Labs/eigensdk-go/crypto/bls"
	sdkecdsa "github.com/Layr-Labs/eigensdk-go/crypto/ecdsa"
	sdktypes "github.com/Layr-Labs/eigensdk-go/types"
	sdkutils "github.com/Layr-Labs/eigensdk-go/utils"
	contractAVSDirectory "github.com/OpacityLabs/opacity-avs-node/cli/bindings/AVSDirectory"
	contractDelegationManager "github.com/OpacityLabs/opacity-avs-node/cli/bindings/DelegationManager"
	contractOpacityServiceManager "github.com/OpacityLabs/opacity-avs-node/cli/bindings/OpacityServiceManager"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
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

const (
	// ReceiptStatusFailed is the status code of a transaction if execution failed.
	ReceiptStatusFailed = uint64(0)

	// ReceiptStatusSuccessful is the status code of a transaction if execution succeeded.
	ReceiptStatusSuccessful = uint64(1)
)

var (
	ErrInvalidNumberOfArgs   = errors.New("invalid number of arguments")
	ErrNoECDSAKeyPassword    = errors.New("ecdsa key password env var not set")
	ErrNoBLSKeyPassword      = errors.New("bls key password env var not set")
	ErrInvalidYamlFile       = errors.New("invalid yaml file")
	ErrInvalidMetadata       = errors.New("invalid metadata")
	ErrOperatorNotRegistered = errors.New("operator not registered to eigenlayer, please register operator to eigenlayer first")
)

type OpacityConfig struct {
	// used to set the logger level (true = info, false = debug)
	Production                  bool   `yaml:"production"`
	OpacityAVSAddress           string `yaml:"opacity_avs_address"`
	RegistryCoordinatorAddress  string `yaml:"registry_coordinator_address"`
	AVSDirectoryAddress         string `yaml:"avs_directory_address"`
	EigenLayerDelegationManager string `yaml:"eigenlayer_delegation_manager"`
	ChainId                     int    `yaml:"chain_id"`
	ECDSAPrivateKeyStorePath    string `yaml:"ecdsa_private_key_store_path"`
	BLSPrivateKeyStorePath      string `yaml:"bls_private_key_store_path"`
	EthRpcUrl                   string `yaml:"eth_rpc_url"`
	OperatorAddress             string `yaml:"operator_address"`
	NodePublicIP                string `yaml:"node_public_ip"`
}

func FailIfNoFile(path string) error {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		log.Fatalln("File does not exist:", path)
		return err
	}
	return nil
}

func RegisterOperatorWithAvs(ctx *cli.Context) error {

	configPath := ctx.GlobalString(ConfigFileFlag.Name)
	fmt.Println("Config Path:", configPath)

	FailIfNoFile(configPath)

	nodeConfig := OpacityConfig{
		ECDSAPrivateKeyStorePath: "/opacity-avs-node/opacity.ecdsa.key.json",
		BLSPrivateKeyStorePath:   "/opacity-avs-node/opacity.bls.key.json",
	}
	err := sdkutils.ReadYamlConfig(configPath, &nodeConfig)
	if err != nil {
		log.Fatalln(err)
		return err
	}

	configJson, err := json.MarshalIndent(nodeConfig, "", "  ")
	if err != nil {
		log.Fatalln(err)
		return err
	}
	fmt.Println("Config:", string(configJson))

	if nodeConfig.NodePublicIP == "" {
		log.Fatalln("NodePublicIP not set in config file")
		return errors.New("NodePublicIP not set in config file")

	}

	client, err := ethclient.Dial(nodeConfig.EthRpcUrl)
	if err != nil {
		log.Fatal(err)
		return err
	}

	opacityAddress := common.HexToAddress(nodeConfig.OpacityAVSAddress)
	registryCoordinatorAddress := common.HexToAddress(nodeConfig.RegistryCoordinatorAddress)
	avsDirectoryAddress := common.HexToAddress(nodeConfig.AVSDirectoryAddress)
	delegationManagerAddress := common.HexToAddress(nodeConfig.EigenLayerDelegationManager)
	operatorAddress := common.HexToAddress(nodeConfig.OperatorAddress)
	avsDirectoryContract, err := contractAVSDirectory.NewContractAVSDirectoryCaller(avsDirectoryAddress, client)
	if err != nil {
		log.Fatal(err)
		return err
	}
	delegationManagerContract, err := contractDelegationManager.NewContractDelegationManager(delegationManagerAddress, client)
	if err != nil {
		log.Fatal(err)
		return err
	}
	registryCoordinatorContract, err := contractRegistryCoordinator.NewContractRegistryCoordinator(registryCoordinatorAddress, client)
	if err != nil {
		log.Fatal(err)
		return err
	}
	opacityServiceContract, err := contractOpacityServiceManager.NewContractOpacityServiceManager(opacityAddress, client)
	if err != nil {
		log.Fatal(err)
		return err
	}

	// Check if operator registered to EigenLayer
	isOperatorRegistered, err := delegationManagerContract.IsOperator(nil, operatorAddress)
	if err != nil {
		log.Fatal(err)
		return err
	}
	if !isOperatorRegistered {
		log.Fatalln(ErrOperatorNotRegistered)
		return ErrOperatorNotRegistered

	} else {
		fmt.Println("Operator is registered to EigenLayer")
	}

	// Check if operator registered to AVS
	operatorStatus, err := avsDirectoryContract.AvsOperatorStatus(nil, opacityAddress, operatorAddress)
	if err != nil {
		log.Fatal(err)
		return err
	}

	if operatorStatus == 0 {
		// Register operator to AVS

		ecdsaKeyPassword, ok := os.LookupEnv("OPERATOR_ECDSA_KEY_PASSWORD")
		if !ok {
			log.Fatalln("OPERATOR_ECDSA_KEY_PASSWORD env var not set. using empty string")
			return ErrNoECDSAKeyPassword
		}

		FailIfNoFile(nodeConfig.ECDSAPrivateKeyStorePath)

		operatorEcdsaPrivKey, err := sdkecdsa.ReadKey(
			nodeConfig.ECDSAPrivateKeyStorePath,
			ecdsaKeyPassword,
		)

		if operatorEcdsaPrivKey == nil {
			log.Panicln("Unable to decrypt operator ecdsa private key.")
			return errors.New("Unable to decrypt operator ecdsa private key.")
		}
		if err != nil {
			log.Fatalln("Unable to decrypt operator ecdsa private key.")
			return err
		}

		operatorAddress2 := crypto.PubkeyToAddress(operatorEcdsaPrivKey.PublicKey)
		if operatorAddress2 != operatorAddress {
			log.Fatalln("Operator address in private key file does not match operator address in config file.")
			return errors.New("Operator address in private key file does not match operator address in config file.")
		}

		blsKeyPassword, ok := os.LookupEnv("OPERATOR_BLS_KEY_PASSWORD")
		if !ok {
			log.Fatalln("OPERATOR_BLS_KEY_PASSWORD env var not set. using empty string")
			return ErrNoBLSKeyPassword
		}
		blsKeyPair, err := bls.ReadPrivateKeyFromFile(nodeConfig.BLSPrivateKeyStorePath, blsKeyPassword)

		if blsKeyPair == nil {
			log.Panicln("Unable to decrypt operator private key.")
			return errors.New("Unable to decrypt operator bls private key.")
		}
		if err != nil {
			log.Fatalln("Unable to decrypt operator bls private key.")
			return err
		}

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
			log.Fatalln(err)
			return err
		}

		var operatorSignatureWithSaltAndExpiry = contractRegistryCoordinator.ISignatureUtilsSignatureWithSaltAndExpiry{
			Signature: operatorSignature,
			Salt:      salt,
			Expiry:    expiryBigInt,
		}

		nonce, err := client.PendingNonceAt(context.Background(), operatorAddress)
		if err != nil {
			log.Fatalln(err)
			return err
		}

		gasPrice, err := client.SuggestGasPrice(context.Background())
		if err != nil {
			log.Fatalln(err)
			return err
		}

		auth, err := bind.NewKeyedTransactorWithChainID(operatorEcdsaPrivKey, big.NewInt(int64(nodeConfig.ChainId)))

		if err != nil {
			log.Fatalln(err)
			return err

		}

		auth.Nonce = big.NewInt(int64(nonce))
		auth.Value = big.NewInt(0)      // in wei
		auth.GasLimit = uint64(1500000) // in units
		auth.GasPrice = gasPrice

		g1HashedMsgToSign, err := registryCoordinatorContract.PubkeyRegistrationMessageHash(nil, operatorAddress)
		if err != nil {
			log.Fatalln(err)
			return err
		}

		signedMsg := chainioutils.ConvertToBN254G1Point(
			blsKeyPair.SignHashedToCurveMessage(chainioutils.ConvertBn254GethToGnark(g1HashedMsgToSign)).G1Point,
		)

		G1pubkeyBN254 := chainioutils.ConvertToBN254G1Point(blsKeyPair.GetPubKeyG1())
		G2pubkeyBN254 := chainioutils.ConvertToBN254G2Point(blsKeyPair.GetPubKeyG2())
		pubkeyRegParams := contractRegistryCoordinator.IBLSApkRegistryPubkeyRegistrationParams{
			PubkeyRegistrationSignature: signedMsg,
			PubkeyG1:                    G1pubkeyBN254,
			PubkeyG2:                    G2pubkeyBN254,
		}

		fmt.Println("Registering Operator to AVS", pubkeyRegParams)

		quorumNumbers := sdktypes.QuorumNums{0}

		var tx *types.Transaction

		if nodeConfig.ChainId == 1 {
			tx, err = registryCoordinatorContract.RegisterOperator(
				auth,
				quorumNumbers.UnderlyingType(),
				nodeConfig.NodePublicIP,
				pubkeyRegParams,
				operatorSignatureWithSaltAndExpiry,
			)
		} else {
			tx, err = opacityServiceContract.RegisterOperatorToAVS(auth, operatorAddress, contractOpacityServiceManager.ISignatureUtilsSignatureWithSaltAndExpiry(operatorSignatureWithSaltAndExpiry))
		}

		if err != nil {
			fmt.Println(err)
			return err
		}

		fmt.Println("Register operator to AVS TX broadcasted")
		fmt.Println("Etherscan URL: https://etherscan.io/tx/" + tx.Hash().Hex())

		var foundTx bool = false

		for !foundTx {
			txReceipt, err := client.TransactionReceipt(context.Background(), tx.Hash())
			if err != nil {
				fmt.Println("Transaction not mined yet")
				time.Sleep(5 * time.Second)
			}
			fmt.Println("Transaction included in block ", txReceipt.BlockNumber)
			if txReceipt.Status == ReceiptStatusFailed {
				log.Fatalln("error: transaction reverted, failed to register operator to AVS")
				return errors.New("error: transaction reverted, failed to register operator to AVS")
			}
			if txReceipt.Status == ReceiptStatusSuccessful {
				foundTx = true
			}
		}

		return nil

	} else {
		fmt.Println("Operator is registered to AVS")
		return nil
	}

}
