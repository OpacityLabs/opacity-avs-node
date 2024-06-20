// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package contractIOpacityServiceManager

import (
	"errors"
	"math/big"
	"strings"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
)

// Reference imports to suppress errors if they are not otherwise used.
var (
	_ = errors.New
	_ = big.NewInt
	_ = strings.NewReader
	_ = ethereum.NotFound
	_ = bind.Bind
	_ = common.Big1
	_ = types.BloomLookup
	_ = event.NewSubscription
	_ = abi.ConvertType
)

// ISignatureUtilsSignatureWithSaltAndExpiry is an auto generated low-level Go binding around an user-defined struct.
type ISignatureUtilsSignatureWithSaltAndExpiry struct {
	Signature []byte
	Salt      [32]byte
	Expiry    *big.Int
}

// ContractIOpacityServiceManagerMetaData contains all meta data concerning the ContractIOpacityServiceManager contract.
var ContractIOpacityServiceManagerMetaData = &bind.MetaData{
	ABI: "[{\"type\":\"function\",\"name\":\"avsDirectory\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"address\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"deregisterOperatorFromAVS\",\"inputs\":[{\"name\":\"operator\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"getOperatorRestakedStrategies\",\"inputs\":[{\"name\":\"operator\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[{\"name\":\"\",\"type\":\"address[]\",\"internalType\":\"address[]\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getRestakeableStrategies\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"address[]\",\"internalType\":\"address[]\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"registerOperatorToAVS\",\"inputs\":[{\"name\":\"operator\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"operatorSignature\",\"type\":\"tuple\",\"internalType\":\"structISignatureUtils.SignatureWithSaltAndExpiry\",\"components\":[{\"name\":\"signature\",\"type\":\"bytes\",\"internalType\":\"bytes\"},{\"name\":\"salt\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"expiry\",\"type\":\"uint256\",\"internalType\":\"uint256\"}]}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"updateAVSMetadataURI\",\"inputs\":[{\"name\":\"_metadataURI\",\"type\":\"string\",\"internalType\":\"string\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"}]",
}

// ContractIOpacityServiceManagerABI is the input ABI used to generate the binding from.
// Deprecated: Use ContractIOpacityServiceManagerMetaData.ABI instead.
var ContractIOpacityServiceManagerABI = ContractIOpacityServiceManagerMetaData.ABI

// ContractIOpacityServiceManager is an auto generated Go binding around an Ethereum contract.
type ContractIOpacityServiceManager struct {
	ContractIOpacityServiceManagerCaller     // Read-only binding to the contract
	ContractIOpacityServiceManagerTransactor // Write-only binding to the contract
	ContractIOpacityServiceManagerFilterer   // Log filterer for contract events
}

// ContractIOpacityServiceManagerCaller is an auto generated read-only Go binding around an Ethereum contract.
type ContractIOpacityServiceManagerCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ContractIOpacityServiceManagerTransactor is an auto generated write-only Go binding around an Ethereum contract.
type ContractIOpacityServiceManagerTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ContractIOpacityServiceManagerFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type ContractIOpacityServiceManagerFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ContractIOpacityServiceManagerSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type ContractIOpacityServiceManagerSession struct {
	Contract     *ContractIOpacityServiceManager // Generic contract binding to set the session for
	CallOpts     bind.CallOpts                   // Call options to use throughout this session
	TransactOpts bind.TransactOpts               // Transaction auth options to use throughout this session
}

// ContractIOpacityServiceManagerCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type ContractIOpacityServiceManagerCallerSession struct {
	Contract *ContractIOpacityServiceManagerCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts                         // Call options to use throughout this session
}

// ContractIOpacityServiceManagerTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type ContractIOpacityServiceManagerTransactorSession struct {
	Contract     *ContractIOpacityServiceManagerTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts                         // Transaction auth options to use throughout this session
}

// ContractIOpacityServiceManagerRaw is an auto generated low-level Go binding around an Ethereum contract.
type ContractIOpacityServiceManagerRaw struct {
	Contract *ContractIOpacityServiceManager // Generic contract binding to access the raw methods on
}

// ContractIOpacityServiceManagerCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type ContractIOpacityServiceManagerCallerRaw struct {
	Contract *ContractIOpacityServiceManagerCaller // Generic read-only contract binding to access the raw methods on
}

// ContractIOpacityServiceManagerTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type ContractIOpacityServiceManagerTransactorRaw struct {
	Contract *ContractIOpacityServiceManagerTransactor // Generic write-only contract binding to access the raw methods on
}

// NewContractIOpacityServiceManager creates a new instance of ContractIOpacityServiceManager, bound to a specific deployed contract.
func NewContractIOpacityServiceManager(address common.Address, backend bind.ContractBackend) (*ContractIOpacityServiceManager, error) {
	contract, err := bindContractIOpacityServiceManager(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &ContractIOpacityServiceManager{ContractIOpacityServiceManagerCaller: ContractIOpacityServiceManagerCaller{contract: contract}, ContractIOpacityServiceManagerTransactor: ContractIOpacityServiceManagerTransactor{contract: contract}, ContractIOpacityServiceManagerFilterer: ContractIOpacityServiceManagerFilterer{contract: contract}}, nil
}

// NewContractIOpacityServiceManagerCaller creates a new read-only instance of ContractIOpacityServiceManager, bound to a specific deployed contract.
func NewContractIOpacityServiceManagerCaller(address common.Address, caller bind.ContractCaller) (*ContractIOpacityServiceManagerCaller, error) {
	contract, err := bindContractIOpacityServiceManager(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &ContractIOpacityServiceManagerCaller{contract: contract}, nil
}

// NewContractIOpacityServiceManagerTransactor creates a new write-only instance of ContractIOpacityServiceManager, bound to a specific deployed contract.
func NewContractIOpacityServiceManagerTransactor(address common.Address, transactor bind.ContractTransactor) (*ContractIOpacityServiceManagerTransactor, error) {
	contract, err := bindContractIOpacityServiceManager(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &ContractIOpacityServiceManagerTransactor{contract: contract}, nil
}

// NewContractIOpacityServiceManagerFilterer creates a new log filterer instance of ContractIOpacityServiceManager, bound to a specific deployed contract.
func NewContractIOpacityServiceManagerFilterer(address common.Address, filterer bind.ContractFilterer) (*ContractIOpacityServiceManagerFilterer, error) {
	contract, err := bindContractIOpacityServiceManager(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &ContractIOpacityServiceManagerFilterer{contract: contract}, nil
}

// bindContractIOpacityServiceManager binds a generic wrapper to an already deployed contract.
func bindContractIOpacityServiceManager(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := ContractIOpacityServiceManagerMetaData.GetAbi()
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, *parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_ContractIOpacityServiceManager *ContractIOpacityServiceManagerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _ContractIOpacityServiceManager.Contract.ContractIOpacityServiceManagerCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_ContractIOpacityServiceManager *ContractIOpacityServiceManagerRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _ContractIOpacityServiceManager.Contract.ContractIOpacityServiceManagerTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_ContractIOpacityServiceManager *ContractIOpacityServiceManagerRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _ContractIOpacityServiceManager.Contract.ContractIOpacityServiceManagerTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_ContractIOpacityServiceManager *ContractIOpacityServiceManagerCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _ContractIOpacityServiceManager.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_ContractIOpacityServiceManager *ContractIOpacityServiceManagerTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _ContractIOpacityServiceManager.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_ContractIOpacityServiceManager *ContractIOpacityServiceManagerTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _ContractIOpacityServiceManager.Contract.contract.Transact(opts, method, params...)
}

// AvsDirectory is a free data retrieval call binding the contract method 0x6b3aa72e.
//
// Solidity: function avsDirectory() view returns(address)
func (_ContractIOpacityServiceManager *ContractIOpacityServiceManagerCaller) AvsDirectory(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _ContractIOpacityServiceManager.contract.Call(opts, &out, "avsDirectory")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// AvsDirectory is a free data retrieval call binding the contract method 0x6b3aa72e.
//
// Solidity: function avsDirectory() view returns(address)
func (_ContractIOpacityServiceManager *ContractIOpacityServiceManagerSession) AvsDirectory() (common.Address, error) {
	return _ContractIOpacityServiceManager.Contract.AvsDirectory(&_ContractIOpacityServiceManager.CallOpts)
}

// AvsDirectory is a free data retrieval call binding the contract method 0x6b3aa72e.
//
// Solidity: function avsDirectory() view returns(address)
func (_ContractIOpacityServiceManager *ContractIOpacityServiceManagerCallerSession) AvsDirectory() (common.Address, error) {
	return _ContractIOpacityServiceManager.Contract.AvsDirectory(&_ContractIOpacityServiceManager.CallOpts)
}

// GetOperatorRestakedStrategies is a free data retrieval call binding the contract method 0x33cfb7b7.
//
// Solidity: function getOperatorRestakedStrategies(address operator) view returns(address[])
func (_ContractIOpacityServiceManager *ContractIOpacityServiceManagerCaller) GetOperatorRestakedStrategies(opts *bind.CallOpts, operator common.Address) ([]common.Address, error) {
	var out []interface{}
	err := _ContractIOpacityServiceManager.contract.Call(opts, &out, "getOperatorRestakedStrategies", operator)

	if err != nil {
		return *new([]common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new([]common.Address)).(*[]common.Address)

	return out0, err

}

// GetOperatorRestakedStrategies is a free data retrieval call binding the contract method 0x33cfb7b7.
//
// Solidity: function getOperatorRestakedStrategies(address operator) view returns(address[])
func (_ContractIOpacityServiceManager *ContractIOpacityServiceManagerSession) GetOperatorRestakedStrategies(operator common.Address) ([]common.Address, error) {
	return _ContractIOpacityServiceManager.Contract.GetOperatorRestakedStrategies(&_ContractIOpacityServiceManager.CallOpts, operator)
}

// GetOperatorRestakedStrategies is a free data retrieval call binding the contract method 0x33cfb7b7.
//
// Solidity: function getOperatorRestakedStrategies(address operator) view returns(address[])
func (_ContractIOpacityServiceManager *ContractIOpacityServiceManagerCallerSession) GetOperatorRestakedStrategies(operator common.Address) ([]common.Address, error) {
	return _ContractIOpacityServiceManager.Contract.GetOperatorRestakedStrategies(&_ContractIOpacityServiceManager.CallOpts, operator)
}

// GetRestakeableStrategies is a free data retrieval call binding the contract method 0xe481af9d.
//
// Solidity: function getRestakeableStrategies() view returns(address[])
func (_ContractIOpacityServiceManager *ContractIOpacityServiceManagerCaller) GetRestakeableStrategies(opts *bind.CallOpts) ([]common.Address, error) {
	var out []interface{}
	err := _ContractIOpacityServiceManager.contract.Call(opts, &out, "getRestakeableStrategies")

	if err != nil {
		return *new([]common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new([]common.Address)).(*[]common.Address)

	return out0, err

}

// GetRestakeableStrategies is a free data retrieval call binding the contract method 0xe481af9d.
//
// Solidity: function getRestakeableStrategies() view returns(address[])
func (_ContractIOpacityServiceManager *ContractIOpacityServiceManagerSession) GetRestakeableStrategies() ([]common.Address, error) {
	return _ContractIOpacityServiceManager.Contract.GetRestakeableStrategies(&_ContractIOpacityServiceManager.CallOpts)
}

// GetRestakeableStrategies is a free data retrieval call binding the contract method 0xe481af9d.
//
// Solidity: function getRestakeableStrategies() view returns(address[])
func (_ContractIOpacityServiceManager *ContractIOpacityServiceManagerCallerSession) GetRestakeableStrategies() ([]common.Address, error) {
	return _ContractIOpacityServiceManager.Contract.GetRestakeableStrategies(&_ContractIOpacityServiceManager.CallOpts)
}

// DeregisterOperatorFromAVS is a paid mutator transaction binding the contract method 0xa364f4da.
//
// Solidity: function deregisterOperatorFromAVS(address operator) returns()
func (_ContractIOpacityServiceManager *ContractIOpacityServiceManagerTransactor) DeregisterOperatorFromAVS(opts *bind.TransactOpts, operator common.Address) (*types.Transaction, error) {
	return _ContractIOpacityServiceManager.contract.Transact(opts, "deregisterOperatorFromAVS", operator)
}

// DeregisterOperatorFromAVS is a paid mutator transaction binding the contract method 0xa364f4da.
//
// Solidity: function deregisterOperatorFromAVS(address operator) returns()
func (_ContractIOpacityServiceManager *ContractIOpacityServiceManagerSession) DeregisterOperatorFromAVS(operator common.Address) (*types.Transaction, error) {
	return _ContractIOpacityServiceManager.Contract.DeregisterOperatorFromAVS(&_ContractIOpacityServiceManager.TransactOpts, operator)
}

// DeregisterOperatorFromAVS is a paid mutator transaction binding the contract method 0xa364f4da.
//
// Solidity: function deregisterOperatorFromAVS(address operator) returns()
func (_ContractIOpacityServiceManager *ContractIOpacityServiceManagerTransactorSession) DeregisterOperatorFromAVS(operator common.Address) (*types.Transaction, error) {
	return _ContractIOpacityServiceManager.Contract.DeregisterOperatorFromAVS(&_ContractIOpacityServiceManager.TransactOpts, operator)
}

// RegisterOperatorToAVS is a paid mutator transaction binding the contract method 0x9926ee7d.
//
// Solidity: function registerOperatorToAVS(address operator, (bytes,bytes32,uint256) operatorSignature) returns()
func (_ContractIOpacityServiceManager *ContractIOpacityServiceManagerTransactor) RegisterOperatorToAVS(opts *bind.TransactOpts, operator common.Address, operatorSignature ISignatureUtilsSignatureWithSaltAndExpiry) (*types.Transaction, error) {
	return _ContractIOpacityServiceManager.contract.Transact(opts, "registerOperatorToAVS", operator, operatorSignature)
}

// RegisterOperatorToAVS is a paid mutator transaction binding the contract method 0x9926ee7d.
//
// Solidity: function registerOperatorToAVS(address operator, (bytes,bytes32,uint256) operatorSignature) returns()
func (_ContractIOpacityServiceManager *ContractIOpacityServiceManagerSession) RegisterOperatorToAVS(operator common.Address, operatorSignature ISignatureUtilsSignatureWithSaltAndExpiry) (*types.Transaction, error) {
	return _ContractIOpacityServiceManager.Contract.RegisterOperatorToAVS(&_ContractIOpacityServiceManager.TransactOpts, operator, operatorSignature)
}

// RegisterOperatorToAVS is a paid mutator transaction binding the contract method 0x9926ee7d.
//
// Solidity: function registerOperatorToAVS(address operator, (bytes,bytes32,uint256) operatorSignature) returns()
func (_ContractIOpacityServiceManager *ContractIOpacityServiceManagerTransactorSession) RegisterOperatorToAVS(operator common.Address, operatorSignature ISignatureUtilsSignatureWithSaltAndExpiry) (*types.Transaction, error) {
	return _ContractIOpacityServiceManager.Contract.RegisterOperatorToAVS(&_ContractIOpacityServiceManager.TransactOpts, operator, operatorSignature)
}

// UpdateAVSMetadataURI is a paid mutator transaction binding the contract method 0xa98fb355.
//
// Solidity: function updateAVSMetadataURI(string _metadataURI) returns()
func (_ContractIOpacityServiceManager *ContractIOpacityServiceManagerTransactor) UpdateAVSMetadataURI(opts *bind.TransactOpts, _metadataURI string) (*types.Transaction, error) {
	return _ContractIOpacityServiceManager.contract.Transact(opts, "updateAVSMetadataURI", _metadataURI)
}

// UpdateAVSMetadataURI is a paid mutator transaction binding the contract method 0xa98fb355.
//
// Solidity: function updateAVSMetadataURI(string _metadataURI) returns()
func (_ContractIOpacityServiceManager *ContractIOpacityServiceManagerSession) UpdateAVSMetadataURI(_metadataURI string) (*types.Transaction, error) {
	return _ContractIOpacityServiceManager.Contract.UpdateAVSMetadataURI(&_ContractIOpacityServiceManager.TransactOpts, _metadataURI)
}

// UpdateAVSMetadataURI is a paid mutator transaction binding the contract method 0xa98fb355.
//
// Solidity: function updateAVSMetadataURI(string _metadataURI) returns()
func (_ContractIOpacityServiceManager *ContractIOpacityServiceManagerTransactorSession) UpdateAVSMetadataURI(_metadataURI string) (*types.Transaction, error) {
	return _ContractIOpacityServiceManager.Contract.UpdateAVSMetadataURI(&_ContractIOpacityServiceManager.TransactOpts, _metadataURI)
}
