package actions

import (
	"encoding/json"
	"fmt"
	"log"

	sdkutils "github.com/Layr-Labs/eigensdk-go/utils"
	"github.com/Layr-Labs/incredible-squaring-avs/core/config"
	"github.com/urfave/cli"
)

type OpacityConfig struct {
	// used to set the logger level (true = info, false = debug)
	Production                   bool   `yaml:"production"`
	opacity_avs_address          string `yaml:"opacity_avs_address"`
	avs_directory_address        string `yaml:"avs_directory_address"`
	chain_id                     int    `yaml:"chain_id"`
	eth_rpc_url                  string `yaml:"eth_rpc_url"`
	ecdsa_private_key_store_path string `yaml:"ecdsa_private_key_store_path"`
}

func RegisterOperatorWithAvs(ctx *cli.Context) error {

	configPath := ctx.GlobalString(config.ConfigFileFlag.Name)
	nodeConfig := OpacityConfig{}
	fmt.Println("Config Path:", string(configPath))
	err := sdkutils.ReadYamlConfig(configPath, &nodeConfig)
	if err != nil {
		return err
	}

	configJson, err := json.MarshalIndent(nodeConfig, "", "  ")
	if err != nil {
		log.Fatalf(err.Error())
	}
	fmt.Println("Config:", string(configJson))
	return nil
	// ecdsaKeyPassword, ok := os.LookupEnv("OPERATOR_ECDSA_KEY_PASSWORD")
	// if !ok {
	// 	log.Printf("OPERATOR_ECDSA_KEY_PASSWORD env var not set. using empty string")
	// }

	// operatorEcdsaPrivKey, err := sdkecdsa.ReadKey(
	// 	nodeConfig.ecdsa_private_key_store_path,
	// 	ecdsaKeyPassword,
	// )

	// fmt.Println("Operator ECDSA Private Key:", operatorEcdsaPrivKey)
	// fmt.Println(crypto.PubkeyToAddress(operatorEcdsaPrivKey.PublicKey).Hex())
	// if err != nil {
	// 	return err
	// }
	// client, err := ethclient.Dial(nodeConfig.eth_rpc_url)
	// if err != nil {
	// 	return err
	// }
	// opacityAddress := common.HexToAddress(nodeConfig.opacity_avs_address)
	// avsDirectoryAddress := common.HexToAddress(nodeConfig.avs_directory_address)
	// operatorAddress := crypto.PubkeyToAddress(operatorEcdsaPrivKey.PublicKey)
	// avsDirectoryContract, err := contractAVSDirectory.NewContractAVSDirectoryCaller(avsDirectoryAddress, client)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// opacityServiceManagerContract, err := contractOpacityServiceManager.NewContractOpacityServiceManager(opacityAddress, client)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// saltBytes := make([]byte, 32)
	// var salt [32]byte
	// rand.Read(saltBytes)
	// copy(salt[:], saltBytes)

	// expiry := time.Now().UTC().Unix()
	// expiry += 60 * 60 * 24

	// expiryBigInt := big.NewInt(int64(expiry))
	// fmt.Println("Expiry:", expiryBigInt)
	// fmt.Println("operatorAddress:", operatorAddress)
	// fmt.Println("avsAddress:", opacityAddress)

	// hash, err := avsDirectoryContract.CalculateOperatorAVSRegistrationDigestHash(nil, operatorAddress, opacityAddress, salt, expiryBigInt)
	// if err != nil {
	// 	log.Fatal(err)

	// }
	// fmt.Println("Registering operator with Hash", hash)
	// operatorSignature, err := crypto.Sign(hash[:], operatorEcdsaPrivKey)
	// operatorSignature[64] += 27
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// fmt.Println("Operator Signature:", operatorSignature)

	// var signature = contractOpacityServiceManager.ISignatureUtilsSignatureWithSaltAndExpiry{
	// 	Signature: operatorSignature,
	// 	Salt:      salt,
	// 	Expiry:    expiryBigInt,
	// }

	// fmt.Println("Signature:", signature)

	// nonce, err := client.PendingNonceAt(context.Background(), operatorAddress)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// gasPrice, err := client.SuggestGasPrice(context.Background())
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// auth, err := bind.NewKeyedTransactorWithChainID(operatorEcdsaPrivKey, big.NewInt(int64(nodeConfig.chain_id)))

	// if err != nil {
	// 	log.Fatal(err)

	// }

	// auth.Nonce = big.NewInt(int64(nonce))
	// auth.Value = big.NewInt(0)     // in wei
	// auth.GasLimit = uint64(300000) // in units
	// auth.GasPrice = gasPrice

	// res, err := opacityServiceManagerContract.RegisterOperatorToAVS(auth, operatorAddress, signature)
	// if err != nil {
	// 	fmt.Println(err)
	// }
	// fmt.Println("Register Operator to AVS TX:", res.Hash().Hex())

	// return nil
}
