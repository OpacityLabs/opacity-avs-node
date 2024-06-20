// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package contractIndexRegistry

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

// IIndexRegistryOperatorUpdate is an auto generated low-level Go binding around an user-defined struct.
type IIndexRegistryOperatorUpdate struct {
	FromBlockNumber uint32
	OperatorId      [32]byte
}

// IIndexRegistryQuorumUpdate is an auto generated low-level Go binding around an user-defined struct.
type IIndexRegistryQuorumUpdate struct {
	FromBlockNumber uint32
	NumOperators    uint32
}

// ContractIndexRegistryMetaData contains all meta data concerning the ContractIndexRegistry contract.
var ContractIndexRegistryMetaData = &bind.MetaData{
	ABI: "[{\"type\":\"constructor\",\"inputs\":[{\"name\":\"_registryCoordinator\",\"type\":\"address\",\"internalType\":\"contractIRegistryCoordinator\"}],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"OPERATOR_DOES_NOT_EXIST_ID\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"currentOperatorIndex\",\"inputs\":[{\"name\":\"\",\"type\":\"uint8\",\"internalType\":\"uint8\"},{\"name\":\"\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"outputs\":[{\"name\":\"\",\"type\":\"uint32\",\"internalType\":\"uint32\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"deregisterOperator\",\"inputs\":[{\"name\":\"operatorId\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"quorumNumbers\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"getLatestOperatorUpdate\",\"inputs\":[{\"name\":\"quorumNumber\",\"type\":\"uint8\",\"internalType\":\"uint8\"},{\"name\":\"operatorIndex\",\"type\":\"uint32\",\"internalType\":\"uint32\"}],\"outputs\":[{\"name\":\"\",\"type\":\"tuple\",\"internalType\":\"structIIndexRegistry.OperatorUpdate\",\"components\":[{\"name\":\"fromBlockNumber\",\"type\":\"uint32\",\"internalType\":\"uint32\"},{\"name\":\"operatorId\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}]}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getLatestQuorumUpdate\",\"inputs\":[{\"name\":\"quorumNumber\",\"type\":\"uint8\",\"internalType\":\"uint8\"}],\"outputs\":[{\"name\":\"\",\"type\":\"tuple\",\"internalType\":\"structIIndexRegistry.QuorumUpdate\",\"components\":[{\"name\":\"fromBlockNumber\",\"type\":\"uint32\",\"internalType\":\"uint32\"},{\"name\":\"numOperators\",\"type\":\"uint32\",\"internalType\":\"uint32\"}]}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getOperatorListAtBlockNumber\",\"inputs\":[{\"name\":\"quorumNumber\",\"type\":\"uint8\",\"internalType\":\"uint8\"},{\"name\":\"blockNumber\",\"type\":\"uint32\",\"internalType\":\"uint32\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bytes32[]\",\"internalType\":\"bytes32[]\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getOperatorUpdateAtIndex\",\"inputs\":[{\"name\":\"quorumNumber\",\"type\":\"uint8\",\"internalType\":\"uint8\"},{\"name\":\"operatorIndex\",\"type\":\"uint32\",\"internalType\":\"uint32\"},{\"name\":\"arrayIndex\",\"type\":\"uint32\",\"internalType\":\"uint32\"}],\"outputs\":[{\"name\":\"\",\"type\":\"tuple\",\"internalType\":\"structIIndexRegistry.OperatorUpdate\",\"components\":[{\"name\":\"fromBlockNumber\",\"type\":\"uint32\",\"internalType\":\"uint32\"},{\"name\":\"operatorId\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}]}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getQuorumUpdateAtIndex\",\"inputs\":[{\"name\":\"quorumNumber\",\"type\":\"uint8\",\"internalType\":\"uint8\"},{\"name\":\"quorumIndex\",\"type\":\"uint32\",\"internalType\":\"uint32\"}],\"outputs\":[{\"name\":\"\",\"type\":\"tuple\",\"internalType\":\"structIIndexRegistry.QuorumUpdate\",\"components\":[{\"name\":\"fromBlockNumber\",\"type\":\"uint32\",\"internalType\":\"uint32\"},{\"name\":\"numOperators\",\"type\":\"uint32\",\"internalType\":\"uint32\"}]}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"initializeQuorum\",\"inputs\":[{\"name\":\"quorumNumber\",\"type\":\"uint8\",\"internalType\":\"uint8\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"registerOperator\",\"inputs\":[{\"name\":\"operatorId\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"quorumNumbers\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"outputs\":[{\"name\":\"\",\"type\":\"uint32[]\",\"internalType\":\"uint32[]\"}],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"registryCoordinator\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"address\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"totalOperatorsForQuorum\",\"inputs\":[{\"name\":\"quorumNumber\",\"type\":\"uint8\",\"internalType\":\"uint8\"}],\"outputs\":[{\"name\":\"\",\"type\":\"uint32\",\"internalType\":\"uint32\"}],\"stateMutability\":\"view\"},{\"type\":\"event\",\"name\":\"Initialized\",\"inputs\":[{\"name\":\"version\",\"type\":\"uint8\",\"indexed\":false,\"internalType\":\"uint8\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"QuorumIndexUpdate\",\"inputs\":[{\"name\":\"operatorId\",\"type\":\"bytes32\",\"indexed\":true,\"internalType\":\"bytes32\"},{\"name\":\"quorumNumber\",\"type\":\"uint8\",\"indexed\":false,\"internalType\":\"uint8\"},{\"name\":\"newOperatorIndex\",\"type\":\"uint32\",\"indexed\":false,\"internalType\":\"uint32\"}],\"anonymous\":false}]",
	Bin: "0x60a060405234801561001057600080fd5b506040516113a63803806113a683398101604081905261002f9161010c565b6001600160a01b0381166080528061004561004c565b505061013c565b600054610100900460ff16156100b85760405162461bcd60e51b815260206004820152602760248201527f496e697469616c697a61626c653a20636f6e747261637420697320696e697469604482015266616c697a696e6760c81b606482015260840160405180910390fd5b60005460ff908116101561010a576000805460ff191660ff9081179091556040519081527f7f26b83ff96e1f2b6a682f133852f6798a09c465da95921460cefb38474024989060200160405180910390a15b565b60006020828403121561011e57600080fd5b81516001600160a01b038116811461013557600080fd5b9392505050565b60805161123a61016c60003960008181610142015281816102750152818161040f01526107d6015261123a6000f3fe608060405234801561001057600080fd5b50600436106100b35760003560e01c8063890262451161007157806389026245146101b3578063a48bb0ac146101d3578063bd29b8cd146101e6578063caa3cd76146101f9578063e2e685801461020f578063f34109221461025557600080fd5b8062bff04d146100b857806312d1d74d146100e157806326d941f2146101155780632ed583e51461012a5780636d14a9871461013d5780638121906f1461017c575b600080fd5b6100cb6100c6366004610eac565b610268565b6040516100d89190610f28565b60405180910390f35b6100f46100ef366004610f9c565b6103be565b60408051825163ffffffff16815260209283015192810192909252016100d8565b610128610123366004610fcf565b610404565b005b6100f4610138366004610fea565b610528565b6101647f000000000000000000000000000000000000000000000000000000000000000081565b6040516001600160a01b0390911681526020016100d8565b61018f61018a366004610fcf565b6105ae565b60408051825163ffffffff90811682526020938401511692810192909252016100d8565b6101c66101c1366004610f9c565b6105f5565b6040516100d8919061102d565b61018f6101e1366004610f9c565b610754565b6101286101f4366004610eac565b6107cb565b610201600081565b6040519081526020016100d8565b61024061021d366004611065565b600160209081526000928352604080842090915290825290205463ffffffff1681565b60405163ffffffff90911681526020016100d8565b610240610263366004610fcf565b6108d5565b6060336001600160a01b037f000000000000000000000000000000000000000000000000000000000000000016146102bb5760405162461bcd60e51b81526004016102b29061108f565b60405180910390fd5b60008267ffffffffffffffff8111156102d6576102d6611102565b6040519080825280602002602001820160405280156102ff578160200160208202803683370190505b50905060005b838110156103b357600085858381811061032157610321611118565b919091013560f81c60008181526003602052604081205491935090915081900361035d5760405162461bcd60e51b81526004016102b29061112e565b6000610368836108f4565b905061037f898461037a600185611199565b6109f1565b8085858151811061039257610392611118565b63ffffffff9290921660209283029190910190910152505050600101610305565b5090505b9392505050565b60408051808201909152600080825260208201526103dc8383610a7b565b60408051808201909152815463ffffffff168152600190910154602082015290505b92915050565b336001600160a01b037f0000000000000000000000000000000000000000000000000000000000000000161461044c5760405162461bcd60e51b81526004016102b29061108f565b60ff8116600090815260036020526040902054156104c65760405162461bcd60e51b815260206004820152603160248201527f496e64657852656769737472792e63726561746551756f72756d3a2071756f72604482015270756d20616c72656164792065786973747360781b60648201526084016102b2565b60ff166000908152600360209081526040808320815180830190925263ffffffff438116835282840185815282546001810184559286529390942091519101805492518416600160201b0267ffffffffffffffff199093169190931617179055565b604080518082019091526000808252602082015260ff8416600090815260026020908152604080832063ffffffff8088168552925290912080549091841690811061057557610575611118565b600091825260209182902060408051808201909152600290920201805463ffffffff168252600101549181019190915290509392505050565b60408051808201909152600080825260208201526105cb82610ad3565b60408051808201909152905463ffffffff8082168352600160201b90910416602082015292915050565b606060006106038484610b15565b905060008163ffffffff1667ffffffffffffffff81111561062657610626611102565b60405190808252806020026020018201604052801561064f578160200160208202803683370190505b50905060005b8263ffffffff1681101561074b5761066e868287610c4a565b82828151811061068057610680611118565b6020026020010181815250506000801b8282815181106106a2576106a2611118565b6020026020010151036107435760405162461bcd60e51b815260206004820152605d60248201527f496e64657852656769737472792e6765744f70657261746f724c69737441744260448201527f6c6f636b4e756d6265723a206f70657261746f7220646f6573206e6f7420657860648201527f6973742061742074686520676976656e20626c6f636b206e756d626572000000608482015260a4016102b2565b600101610655565b50949350505050565b604080518082019091526000808252602082015260ff83166000908152600360205260409020805463ffffffff841690811061079257610792611118565b60009182526020918290206040805180820190915291015463ffffffff8082168352600160201b90910416918101919091529392505050565b336001600160a01b037f000000000000000000000000000000000000000000000000000000000000000016146108135760405162461bcd60e51b81526004016102b29061108f565b60005b818110156108cf57600083838381811061083257610832611118565b919091013560f81c60008181526003602052604081205491935090915081900361086e5760405162461bcd60e51b81526004016102b29061112e565b60ff8216600090815260016020908152604080832089845290915281205463ffffffff169061089c84610d21565b905060006108aa8583610d5b565b90508089146108be576108be8186856109f1565b505060019093019250610816915050565b50505050565b60006108e082610ad3565b54600160201b900463ffffffff1692915050565b60008061090083610ad3565b805490915060009061092090600160201b900463ffffffff1660016111bd565b905061092d848383610d85565b60ff841660009081526002602052604081209061094b600184611199565b63ffffffff168152602081019190915260400160009081205490036103b75760ff8416600090815260026020526040812090610988600184611199565b63ffffffff908116825260208083019390935260409182016000908120835180850190945243831684528385018281528154600180820184559284529590922093516002909502909301805463ffffffff19169490921693909317815591519101559392505050565b60006109fd8383610a7b565b9050610a0b83838387610e23565b60ff83166000818152600160209081526040808320888452825291829020805463ffffffff191663ffffffff871690811790915582519384529083015285917f6ee1e4f4075f3d067176140d34e87874244dd273294c05b2218133e49a2ba6f6910160405180910390a250505050565b60ff8216600090815260026020908152604080832063ffffffff851684529091528120805490610aac6001836111da565b81548110610abc57610abc611118565b906000526020600020906002020191505092915050565b60ff81166000908152600360205260408120805490610af36001836111da565b81548110610b0357610b03611118565b90600052602060002001915050919050565b60ff8216600090815260036020526040812054805b8015610bbd5760ff85166000908152600360205260408120610b4d6001846111da565b81548110610b5d57610b5d611118565b60009182526020918290206040805180820190915291015463ffffffff808216808452600160201b90920481169383019390935290925090861610610baa576020015192506103fe915050565b5080610bb5816111ed565b915050610b2a565b5060405162461bcd60e51b815260206004820152605560248201527f496e64657852656769737472792e5f6f70657261746f72436f756e744174426c60448201527f6f636b4e756d6265723a2071756f72756d20646964206e6f742065786973742060648201527430ba1033b4bb32b710313637b1b590373ab6b132b960591b608482015260a4016102b2565b60ff8316600090815260026020908152604080832063ffffffff86168452909152812054805b8015610d155760ff8616600090815260026020908152604080832063ffffffff891684529091528120610ca46001846111da565b81548110610cb457610cb4611118565b600091825260209182902060408051808201909152600290920201805463ffffffff9081168084526001909201549383019390935290925090861610610d02576020015192506103b7915050565b5080610d0d816111ed565b915050610c70565b50600095945050505050565b600080610d2d83610ad3565b8054909150600090610d4e90600190600160201b900463ffffffff16611199565b90506103b7848383610d85565b600080610d688484610a7b565b6001810154909150610d7d8585846000610e23565b949350505050565b815463ffffffff438116911603610dba57815463ffffffff8216600160201b0267ffffffff0000000019909116178255505050565b60ff83166000908152600360209081526040808320815180830190925263ffffffff438116835285811683850190815282546001810184559286529390942091519101805492518416600160201b0267ffffffffffffffff199093169190931617179055505050565b815463ffffffff438116911603610e4057600182018190556108cf565b60ff93909316600090815260026020818152604080842063ffffffff968716855282528084208151808301909252438716825281830197885280546001808201835591865292909420905191909202909101805463ffffffff1916919094161783559251919092015550565b600080600060408486031215610ec157600080fd5b83359250602084013567ffffffffffffffff80821115610ee057600080fd5b818601915086601f830112610ef457600080fd5b813581811115610f0357600080fd5b876020828501011115610f1557600080fd5b6020830194508093505050509250925092565b6020808252825182820181905260009190848201906040850190845b81811015610f6657835163ffffffff1683529284019291840191600101610f44565b50909695505050505050565b803560ff81168114610f8357600080fd5b919050565b803563ffffffff81168114610f8357600080fd5b60008060408385031215610faf57600080fd5b610fb883610f72565b9150610fc660208401610f88565b90509250929050565b600060208284031215610fe157600080fd5b6103b782610f72565b600080600060608486031215610fff57600080fd5b61100884610f72565b925061101660208501610f88565b915061102460408501610f88565b90509250925092565b6020808252825182820181905260009190848201906040850190845b81811015610f6657835183529284019291840191600101611049565b6000806040838503121561107857600080fd5b61108183610f72565b946020939093013593505050565b6020808252604d908201527f496e64657852656769737472792e6f6e6c795265676973747279436f6f72646960408201527f6e61746f723a2063616c6c6572206973206e6f7420746865207265676973747260608201526c3c9031b7b7b93234b730ba37b960991b608082015260a00190565b634e487b7160e01b600052604160045260246000fd5b634e487b7160e01b600052603260045260246000fd5b60208082526035908201527f496e64657852656769737472792e72656769737465724f70657261746f723a206040820152741c5d5bdc9d5b48191bd95cc81b9bdd08195e1a5cdd605a1b606082015260800190565b634e487b7160e01b600052601160045260246000fd5b63ffffffff8281168282160390808211156111b6576111b6611183565b5092915050565b63ffffffff8181168382160190808211156111b6576111b6611183565b818103818111156103fe576103fe611183565b6000816111fc576111fc611183565b50600019019056fea2646970667358221220737acece18bc0d04c35f64f3bfcef6467e46426684f5f540b7b957a65c5d437164736f6c63430008170033",
}

// ContractIndexRegistryABI is the input ABI used to generate the binding from.
// Deprecated: Use ContractIndexRegistryMetaData.ABI instead.
var ContractIndexRegistryABI = ContractIndexRegistryMetaData.ABI

// ContractIndexRegistryBin is the compiled bytecode used for deploying new contracts.
// Deprecated: Use ContractIndexRegistryMetaData.Bin instead.
var ContractIndexRegistryBin = ContractIndexRegistryMetaData.Bin

// DeployContractIndexRegistry deploys a new Ethereum contract, binding an instance of ContractIndexRegistry to it.
func DeployContractIndexRegistry(auth *bind.TransactOpts, backend bind.ContractBackend, _registryCoordinator common.Address) (common.Address, *types.Transaction, *ContractIndexRegistry, error) {
	parsed, err := ContractIndexRegistryMetaData.GetAbi()
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	if parsed == nil {
		return common.Address{}, nil, nil, errors.New("GetABI returned nil")
	}

	address, tx, contract, err := bind.DeployContract(auth, *parsed, common.FromHex(ContractIndexRegistryBin), backend, _registryCoordinator)
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	return address, tx, &ContractIndexRegistry{ContractIndexRegistryCaller: ContractIndexRegistryCaller{contract: contract}, ContractIndexRegistryTransactor: ContractIndexRegistryTransactor{contract: contract}, ContractIndexRegistryFilterer: ContractIndexRegistryFilterer{contract: contract}}, nil
}

// ContractIndexRegistry is an auto generated Go binding around an Ethereum contract.
type ContractIndexRegistry struct {
	ContractIndexRegistryCaller     // Read-only binding to the contract
	ContractIndexRegistryTransactor // Write-only binding to the contract
	ContractIndexRegistryFilterer   // Log filterer for contract events
}

// ContractIndexRegistryCaller is an auto generated read-only Go binding around an Ethereum contract.
type ContractIndexRegistryCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ContractIndexRegistryTransactor is an auto generated write-only Go binding around an Ethereum contract.
type ContractIndexRegistryTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ContractIndexRegistryFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type ContractIndexRegistryFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ContractIndexRegistrySession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type ContractIndexRegistrySession struct {
	Contract     *ContractIndexRegistry // Generic contract binding to set the session for
	CallOpts     bind.CallOpts          // Call options to use throughout this session
	TransactOpts bind.TransactOpts      // Transaction auth options to use throughout this session
}

// ContractIndexRegistryCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type ContractIndexRegistryCallerSession struct {
	Contract *ContractIndexRegistryCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts                // Call options to use throughout this session
}

// ContractIndexRegistryTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type ContractIndexRegistryTransactorSession struct {
	Contract     *ContractIndexRegistryTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts                // Transaction auth options to use throughout this session
}

// ContractIndexRegistryRaw is an auto generated low-level Go binding around an Ethereum contract.
type ContractIndexRegistryRaw struct {
	Contract *ContractIndexRegistry // Generic contract binding to access the raw methods on
}

// ContractIndexRegistryCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type ContractIndexRegistryCallerRaw struct {
	Contract *ContractIndexRegistryCaller // Generic read-only contract binding to access the raw methods on
}

// ContractIndexRegistryTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type ContractIndexRegistryTransactorRaw struct {
	Contract *ContractIndexRegistryTransactor // Generic write-only contract binding to access the raw methods on
}

// NewContractIndexRegistry creates a new instance of ContractIndexRegistry, bound to a specific deployed contract.
func NewContractIndexRegistry(address common.Address, backend bind.ContractBackend) (*ContractIndexRegistry, error) {
	contract, err := bindContractIndexRegistry(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &ContractIndexRegistry{ContractIndexRegistryCaller: ContractIndexRegistryCaller{contract: contract}, ContractIndexRegistryTransactor: ContractIndexRegistryTransactor{contract: contract}, ContractIndexRegistryFilterer: ContractIndexRegistryFilterer{contract: contract}}, nil
}

// NewContractIndexRegistryCaller creates a new read-only instance of ContractIndexRegistry, bound to a specific deployed contract.
func NewContractIndexRegistryCaller(address common.Address, caller bind.ContractCaller) (*ContractIndexRegistryCaller, error) {
	contract, err := bindContractIndexRegistry(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &ContractIndexRegistryCaller{contract: contract}, nil
}

// NewContractIndexRegistryTransactor creates a new write-only instance of ContractIndexRegistry, bound to a specific deployed contract.
func NewContractIndexRegistryTransactor(address common.Address, transactor bind.ContractTransactor) (*ContractIndexRegistryTransactor, error) {
	contract, err := bindContractIndexRegistry(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &ContractIndexRegistryTransactor{contract: contract}, nil
}

// NewContractIndexRegistryFilterer creates a new log filterer instance of ContractIndexRegistry, bound to a specific deployed contract.
func NewContractIndexRegistryFilterer(address common.Address, filterer bind.ContractFilterer) (*ContractIndexRegistryFilterer, error) {
	contract, err := bindContractIndexRegistry(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &ContractIndexRegistryFilterer{contract: contract}, nil
}

// bindContractIndexRegistry binds a generic wrapper to an already deployed contract.
func bindContractIndexRegistry(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := ContractIndexRegistryMetaData.GetAbi()
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, *parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_ContractIndexRegistry *ContractIndexRegistryRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _ContractIndexRegistry.Contract.ContractIndexRegistryCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_ContractIndexRegistry *ContractIndexRegistryRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _ContractIndexRegistry.Contract.ContractIndexRegistryTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_ContractIndexRegistry *ContractIndexRegistryRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _ContractIndexRegistry.Contract.ContractIndexRegistryTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_ContractIndexRegistry *ContractIndexRegistryCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _ContractIndexRegistry.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_ContractIndexRegistry *ContractIndexRegistryTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _ContractIndexRegistry.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_ContractIndexRegistry *ContractIndexRegistryTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _ContractIndexRegistry.Contract.contract.Transact(opts, method, params...)
}

// OPERATORDOESNOTEXISTID is a free data retrieval call binding the contract method 0xcaa3cd76.
//
// Solidity: function OPERATOR_DOES_NOT_EXIST_ID() view returns(bytes32)
func (_ContractIndexRegistry *ContractIndexRegistryCaller) OPERATORDOESNOTEXISTID(opts *bind.CallOpts) ([32]byte, error) {
	var out []interface{}
	err := _ContractIndexRegistry.contract.Call(opts, &out, "OPERATOR_DOES_NOT_EXIST_ID")

	if err != nil {
		return *new([32]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([32]byte)).(*[32]byte)

	return out0, err

}

// OPERATORDOESNOTEXISTID is a free data retrieval call binding the contract method 0xcaa3cd76.
//
// Solidity: function OPERATOR_DOES_NOT_EXIST_ID() view returns(bytes32)
func (_ContractIndexRegistry *ContractIndexRegistrySession) OPERATORDOESNOTEXISTID() ([32]byte, error) {
	return _ContractIndexRegistry.Contract.OPERATORDOESNOTEXISTID(&_ContractIndexRegistry.CallOpts)
}

// OPERATORDOESNOTEXISTID is a free data retrieval call binding the contract method 0xcaa3cd76.
//
// Solidity: function OPERATOR_DOES_NOT_EXIST_ID() view returns(bytes32)
func (_ContractIndexRegistry *ContractIndexRegistryCallerSession) OPERATORDOESNOTEXISTID() ([32]byte, error) {
	return _ContractIndexRegistry.Contract.OPERATORDOESNOTEXISTID(&_ContractIndexRegistry.CallOpts)
}

// CurrentOperatorIndex is a free data retrieval call binding the contract method 0xe2e68580.
//
// Solidity: function currentOperatorIndex(uint8 , bytes32 ) view returns(uint32)
func (_ContractIndexRegistry *ContractIndexRegistryCaller) CurrentOperatorIndex(opts *bind.CallOpts, arg0 uint8, arg1 [32]byte) (uint32, error) {
	var out []interface{}
	err := _ContractIndexRegistry.contract.Call(opts, &out, "currentOperatorIndex", arg0, arg1)

	if err != nil {
		return *new(uint32), err
	}

	out0 := *abi.ConvertType(out[0], new(uint32)).(*uint32)

	return out0, err

}

// CurrentOperatorIndex is a free data retrieval call binding the contract method 0xe2e68580.
//
// Solidity: function currentOperatorIndex(uint8 , bytes32 ) view returns(uint32)
func (_ContractIndexRegistry *ContractIndexRegistrySession) CurrentOperatorIndex(arg0 uint8, arg1 [32]byte) (uint32, error) {
	return _ContractIndexRegistry.Contract.CurrentOperatorIndex(&_ContractIndexRegistry.CallOpts, arg0, arg1)
}

// CurrentOperatorIndex is a free data retrieval call binding the contract method 0xe2e68580.
//
// Solidity: function currentOperatorIndex(uint8 , bytes32 ) view returns(uint32)
func (_ContractIndexRegistry *ContractIndexRegistryCallerSession) CurrentOperatorIndex(arg0 uint8, arg1 [32]byte) (uint32, error) {
	return _ContractIndexRegistry.Contract.CurrentOperatorIndex(&_ContractIndexRegistry.CallOpts, arg0, arg1)
}

// GetLatestOperatorUpdate is a free data retrieval call binding the contract method 0x12d1d74d.
//
// Solidity: function getLatestOperatorUpdate(uint8 quorumNumber, uint32 operatorIndex) view returns((uint32,bytes32))
func (_ContractIndexRegistry *ContractIndexRegistryCaller) GetLatestOperatorUpdate(opts *bind.CallOpts, quorumNumber uint8, operatorIndex uint32) (IIndexRegistryOperatorUpdate, error) {
	var out []interface{}
	err := _ContractIndexRegistry.contract.Call(opts, &out, "getLatestOperatorUpdate", quorumNumber, operatorIndex)

	if err != nil {
		return *new(IIndexRegistryOperatorUpdate), err
	}

	out0 := *abi.ConvertType(out[0], new(IIndexRegistryOperatorUpdate)).(*IIndexRegistryOperatorUpdate)

	return out0, err

}

// GetLatestOperatorUpdate is a free data retrieval call binding the contract method 0x12d1d74d.
//
// Solidity: function getLatestOperatorUpdate(uint8 quorumNumber, uint32 operatorIndex) view returns((uint32,bytes32))
func (_ContractIndexRegistry *ContractIndexRegistrySession) GetLatestOperatorUpdate(quorumNumber uint8, operatorIndex uint32) (IIndexRegistryOperatorUpdate, error) {
	return _ContractIndexRegistry.Contract.GetLatestOperatorUpdate(&_ContractIndexRegistry.CallOpts, quorumNumber, operatorIndex)
}

// GetLatestOperatorUpdate is a free data retrieval call binding the contract method 0x12d1d74d.
//
// Solidity: function getLatestOperatorUpdate(uint8 quorumNumber, uint32 operatorIndex) view returns((uint32,bytes32))
func (_ContractIndexRegistry *ContractIndexRegistryCallerSession) GetLatestOperatorUpdate(quorumNumber uint8, operatorIndex uint32) (IIndexRegistryOperatorUpdate, error) {
	return _ContractIndexRegistry.Contract.GetLatestOperatorUpdate(&_ContractIndexRegistry.CallOpts, quorumNumber, operatorIndex)
}

// GetLatestQuorumUpdate is a free data retrieval call binding the contract method 0x8121906f.
//
// Solidity: function getLatestQuorumUpdate(uint8 quorumNumber) view returns((uint32,uint32))
func (_ContractIndexRegistry *ContractIndexRegistryCaller) GetLatestQuorumUpdate(opts *bind.CallOpts, quorumNumber uint8) (IIndexRegistryQuorumUpdate, error) {
	var out []interface{}
	err := _ContractIndexRegistry.contract.Call(opts, &out, "getLatestQuorumUpdate", quorumNumber)

	if err != nil {
		return *new(IIndexRegistryQuorumUpdate), err
	}

	out0 := *abi.ConvertType(out[0], new(IIndexRegistryQuorumUpdate)).(*IIndexRegistryQuorumUpdate)

	return out0, err

}

// GetLatestQuorumUpdate is a free data retrieval call binding the contract method 0x8121906f.
//
// Solidity: function getLatestQuorumUpdate(uint8 quorumNumber) view returns((uint32,uint32))
func (_ContractIndexRegistry *ContractIndexRegistrySession) GetLatestQuorumUpdate(quorumNumber uint8) (IIndexRegistryQuorumUpdate, error) {
	return _ContractIndexRegistry.Contract.GetLatestQuorumUpdate(&_ContractIndexRegistry.CallOpts, quorumNumber)
}

// GetLatestQuorumUpdate is a free data retrieval call binding the contract method 0x8121906f.
//
// Solidity: function getLatestQuorumUpdate(uint8 quorumNumber) view returns((uint32,uint32))
func (_ContractIndexRegistry *ContractIndexRegistryCallerSession) GetLatestQuorumUpdate(quorumNumber uint8) (IIndexRegistryQuorumUpdate, error) {
	return _ContractIndexRegistry.Contract.GetLatestQuorumUpdate(&_ContractIndexRegistry.CallOpts, quorumNumber)
}

// GetOperatorListAtBlockNumber is a free data retrieval call binding the contract method 0x89026245.
//
// Solidity: function getOperatorListAtBlockNumber(uint8 quorumNumber, uint32 blockNumber) view returns(bytes32[])
func (_ContractIndexRegistry *ContractIndexRegistryCaller) GetOperatorListAtBlockNumber(opts *bind.CallOpts, quorumNumber uint8, blockNumber uint32) ([][32]byte, error) {
	var out []interface{}
	err := _ContractIndexRegistry.contract.Call(opts, &out, "getOperatorListAtBlockNumber", quorumNumber, blockNumber)

	if err != nil {
		return *new([][32]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([][32]byte)).(*[][32]byte)

	return out0, err

}

// GetOperatorListAtBlockNumber is a free data retrieval call binding the contract method 0x89026245.
//
// Solidity: function getOperatorListAtBlockNumber(uint8 quorumNumber, uint32 blockNumber) view returns(bytes32[])
func (_ContractIndexRegistry *ContractIndexRegistrySession) GetOperatorListAtBlockNumber(quorumNumber uint8, blockNumber uint32) ([][32]byte, error) {
	return _ContractIndexRegistry.Contract.GetOperatorListAtBlockNumber(&_ContractIndexRegistry.CallOpts, quorumNumber, blockNumber)
}

// GetOperatorListAtBlockNumber is a free data retrieval call binding the contract method 0x89026245.
//
// Solidity: function getOperatorListAtBlockNumber(uint8 quorumNumber, uint32 blockNumber) view returns(bytes32[])
func (_ContractIndexRegistry *ContractIndexRegistryCallerSession) GetOperatorListAtBlockNumber(quorumNumber uint8, blockNumber uint32) ([][32]byte, error) {
	return _ContractIndexRegistry.Contract.GetOperatorListAtBlockNumber(&_ContractIndexRegistry.CallOpts, quorumNumber, blockNumber)
}

// GetOperatorUpdateAtIndex is a free data retrieval call binding the contract method 0x2ed583e5.
//
// Solidity: function getOperatorUpdateAtIndex(uint8 quorumNumber, uint32 operatorIndex, uint32 arrayIndex) view returns((uint32,bytes32))
func (_ContractIndexRegistry *ContractIndexRegistryCaller) GetOperatorUpdateAtIndex(opts *bind.CallOpts, quorumNumber uint8, operatorIndex uint32, arrayIndex uint32) (IIndexRegistryOperatorUpdate, error) {
	var out []interface{}
	err := _ContractIndexRegistry.contract.Call(opts, &out, "getOperatorUpdateAtIndex", quorumNumber, operatorIndex, arrayIndex)

	if err != nil {
		return *new(IIndexRegistryOperatorUpdate), err
	}

	out0 := *abi.ConvertType(out[0], new(IIndexRegistryOperatorUpdate)).(*IIndexRegistryOperatorUpdate)

	return out0, err

}

// GetOperatorUpdateAtIndex is a free data retrieval call binding the contract method 0x2ed583e5.
//
// Solidity: function getOperatorUpdateAtIndex(uint8 quorumNumber, uint32 operatorIndex, uint32 arrayIndex) view returns((uint32,bytes32))
func (_ContractIndexRegistry *ContractIndexRegistrySession) GetOperatorUpdateAtIndex(quorumNumber uint8, operatorIndex uint32, arrayIndex uint32) (IIndexRegistryOperatorUpdate, error) {
	return _ContractIndexRegistry.Contract.GetOperatorUpdateAtIndex(&_ContractIndexRegistry.CallOpts, quorumNumber, operatorIndex, arrayIndex)
}

// GetOperatorUpdateAtIndex is a free data retrieval call binding the contract method 0x2ed583e5.
//
// Solidity: function getOperatorUpdateAtIndex(uint8 quorumNumber, uint32 operatorIndex, uint32 arrayIndex) view returns((uint32,bytes32))
func (_ContractIndexRegistry *ContractIndexRegistryCallerSession) GetOperatorUpdateAtIndex(quorumNumber uint8, operatorIndex uint32, arrayIndex uint32) (IIndexRegistryOperatorUpdate, error) {
	return _ContractIndexRegistry.Contract.GetOperatorUpdateAtIndex(&_ContractIndexRegistry.CallOpts, quorumNumber, operatorIndex, arrayIndex)
}

// GetQuorumUpdateAtIndex is a free data retrieval call binding the contract method 0xa48bb0ac.
//
// Solidity: function getQuorumUpdateAtIndex(uint8 quorumNumber, uint32 quorumIndex) view returns((uint32,uint32))
func (_ContractIndexRegistry *ContractIndexRegistryCaller) GetQuorumUpdateAtIndex(opts *bind.CallOpts, quorumNumber uint8, quorumIndex uint32) (IIndexRegistryQuorumUpdate, error) {
	var out []interface{}
	err := _ContractIndexRegistry.contract.Call(opts, &out, "getQuorumUpdateAtIndex", quorumNumber, quorumIndex)

	if err != nil {
		return *new(IIndexRegistryQuorumUpdate), err
	}

	out0 := *abi.ConvertType(out[0], new(IIndexRegistryQuorumUpdate)).(*IIndexRegistryQuorumUpdate)

	return out0, err

}

// GetQuorumUpdateAtIndex is a free data retrieval call binding the contract method 0xa48bb0ac.
//
// Solidity: function getQuorumUpdateAtIndex(uint8 quorumNumber, uint32 quorumIndex) view returns((uint32,uint32))
func (_ContractIndexRegistry *ContractIndexRegistrySession) GetQuorumUpdateAtIndex(quorumNumber uint8, quorumIndex uint32) (IIndexRegistryQuorumUpdate, error) {
	return _ContractIndexRegistry.Contract.GetQuorumUpdateAtIndex(&_ContractIndexRegistry.CallOpts, quorumNumber, quorumIndex)
}

// GetQuorumUpdateAtIndex is a free data retrieval call binding the contract method 0xa48bb0ac.
//
// Solidity: function getQuorumUpdateAtIndex(uint8 quorumNumber, uint32 quorumIndex) view returns((uint32,uint32))
func (_ContractIndexRegistry *ContractIndexRegistryCallerSession) GetQuorumUpdateAtIndex(quorumNumber uint8, quorumIndex uint32) (IIndexRegistryQuorumUpdate, error) {
	return _ContractIndexRegistry.Contract.GetQuorumUpdateAtIndex(&_ContractIndexRegistry.CallOpts, quorumNumber, quorumIndex)
}

// RegistryCoordinator is a free data retrieval call binding the contract method 0x6d14a987.
//
// Solidity: function registryCoordinator() view returns(address)
func (_ContractIndexRegistry *ContractIndexRegistryCaller) RegistryCoordinator(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _ContractIndexRegistry.contract.Call(opts, &out, "registryCoordinator")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// RegistryCoordinator is a free data retrieval call binding the contract method 0x6d14a987.
//
// Solidity: function registryCoordinator() view returns(address)
func (_ContractIndexRegistry *ContractIndexRegistrySession) RegistryCoordinator() (common.Address, error) {
	return _ContractIndexRegistry.Contract.RegistryCoordinator(&_ContractIndexRegistry.CallOpts)
}

// RegistryCoordinator is a free data retrieval call binding the contract method 0x6d14a987.
//
// Solidity: function registryCoordinator() view returns(address)
func (_ContractIndexRegistry *ContractIndexRegistryCallerSession) RegistryCoordinator() (common.Address, error) {
	return _ContractIndexRegistry.Contract.RegistryCoordinator(&_ContractIndexRegistry.CallOpts)
}

// TotalOperatorsForQuorum is a free data retrieval call binding the contract method 0xf3410922.
//
// Solidity: function totalOperatorsForQuorum(uint8 quorumNumber) view returns(uint32)
func (_ContractIndexRegistry *ContractIndexRegistryCaller) TotalOperatorsForQuorum(opts *bind.CallOpts, quorumNumber uint8) (uint32, error) {
	var out []interface{}
	err := _ContractIndexRegistry.contract.Call(opts, &out, "totalOperatorsForQuorum", quorumNumber)

	if err != nil {
		return *new(uint32), err
	}

	out0 := *abi.ConvertType(out[0], new(uint32)).(*uint32)

	return out0, err

}

// TotalOperatorsForQuorum is a free data retrieval call binding the contract method 0xf3410922.
//
// Solidity: function totalOperatorsForQuorum(uint8 quorumNumber) view returns(uint32)
func (_ContractIndexRegistry *ContractIndexRegistrySession) TotalOperatorsForQuorum(quorumNumber uint8) (uint32, error) {
	return _ContractIndexRegistry.Contract.TotalOperatorsForQuorum(&_ContractIndexRegistry.CallOpts, quorumNumber)
}

// TotalOperatorsForQuorum is a free data retrieval call binding the contract method 0xf3410922.
//
// Solidity: function totalOperatorsForQuorum(uint8 quorumNumber) view returns(uint32)
func (_ContractIndexRegistry *ContractIndexRegistryCallerSession) TotalOperatorsForQuorum(quorumNumber uint8) (uint32, error) {
	return _ContractIndexRegistry.Contract.TotalOperatorsForQuorum(&_ContractIndexRegistry.CallOpts, quorumNumber)
}

// DeregisterOperator is a paid mutator transaction binding the contract method 0xbd29b8cd.
//
// Solidity: function deregisterOperator(bytes32 operatorId, bytes quorumNumbers) returns()
func (_ContractIndexRegistry *ContractIndexRegistryTransactor) DeregisterOperator(opts *bind.TransactOpts, operatorId [32]byte, quorumNumbers []byte) (*types.Transaction, error) {
	return _ContractIndexRegistry.contract.Transact(opts, "deregisterOperator", operatorId, quorumNumbers)
}

// DeregisterOperator is a paid mutator transaction binding the contract method 0xbd29b8cd.
//
// Solidity: function deregisterOperator(bytes32 operatorId, bytes quorumNumbers) returns()
func (_ContractIndexRegistry *ContractIndexRegistrySession) DeregisterOperator(operatorId [32]byte, quorumNumbers []byte) (*types.Transaction, error) {
	return _ContractIndexRegistry.Contract.DeregisterOperator(&_ContractIndexRegistry.TransactOpts, operatorId, quorumNumbers)
}

// DeregisterOperator is a paid mutator transaction binding the contract method 0xbd29b8cd.
//
// Solidity: function deregisterOperator(bytes32 operatorId, bytes quorumNumbers) returns()
func (_ContractIndexRegistry *ContractIndexRegistryTransactorSession) DeregisterOperator(operatorId [32]byte, quorumNumbers []byte) (*types.Transaction, error) {
	return _ContractIndexRegistry.Contract.DeregisterOperator(&_ContractIndexRegistry.TransactOpts, operatorId, quorumNumbers)
}

// InitializeQuorum is a paid mutator transaction binding the contract method 0x26d941f2.
//
// Solidity: function initializeQuorum(uint8 quorumNumber) returns()
func (_ContractIndexRegistry *ContractIndexRegistryTransactor) InitializeQuorum(opts *bind.TransactOpts, quorumNumber uint8) (*types.Transaction, error) {
	return _ContractIndexRegistry.contract.Transact(opts, "initializeQuorum", quorumNumber)
}

// InitializeQuorum is a paid mutator transaction binding the contract method 0x26d941f2.
//
// Solidity: function initializeQuorum(uint8 quorumNumber) returns()
func (_ContractIndexRegistry *ContractIndexRegistrySession) InitializeQuorum(quorumNumber uint8) (*types.Transaction, error) {
	return _ContractIndexRegistry.Contract.InitializeQuorum(&_ContractIndexRegistry.TransactOpts, quorumNumber)
}

// InitializeQuorum is a paid mutator transaction binding the contract method 0x26d941f2.
//
// Solidity: function initializeQuorum(uint8 quorumNumber) returns()
func (_ContractIndexRegistry *ContractIndexRegistryTransactorSession) InitializeQuorum(quorumNumber uint8) (*types.Transaction, error) {
	return _ContractIndexRegistry.Contract.InitializeQuorum(&_ContractIndexRegistry.TransactOpts, quorumNumber)
}

// RegisterOperator is a paid mutator transaction binding the contract method 0x00bff04d.
//
// Solidity: function registerOperator(bytes32 operatorId, bytes quorumNumbers) returns(uint32[])
func (_ContractIndexRegistry *ContractIndexRegistryTransactor) RegisterOperator(opts *bind.TransactOpts, operatorId [32]byte, quorumNumbers []byte) (*types.Transaction, error) {
	return _ContractIndexRegistry.contract.Transact(opts, "registerOperator", operatorId, quorumNumbers)
}

// RegisterOperator is a paid mutator transaction binding the contract method 0x00bff04d.
//
// Solidity: function registerOperator(bytes32 operatorId, bytes quorumNumbers) returns(uint32[])
func (_ContractIndexRegistry *ContractIndexRegistrySession) RegisterOperator(operatorId [32]byte, quorumNumbers []byte) (*types.Transaction, error) {
	return _ContractIndexRegistry.Contract.RegisterOperator(&_ContractIndexRegistry.TransactOpts, operatorId, quorumNumbers)
}

// RegisterOperator is a paid mutator transaction binding the contract method 0x00bff04d.
//
// Solidity: function registerOperator(bytes32 operatorId, bytes quorumNumbers) returns(uint32[])
func (_ContractIndexRegistry *ContractIndexRegistryTransactorSession) RegisterOperator(operatorId [32]byte, quorumNumbers []byte) (*types.Transaction, error) {
	return _ContractIndexRegistry.Contract.RegisterOperator(&_ContractIndexRegistry.TransactOpts, operatorId, quorumNumbers)
}

// ContractIndexRegistryInitializedIterator is returned from FilterInitialized and is used to iterate over the raw logs and unpacked data for Initialized events raised by the ContractIndexRegistry contract.
type ContractIndexRegistryInitializedIterator struct {
	Event *ContractIndexRegistryInitialized // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *ContractIndexRegistryInitializedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(ContractIndexRegistryInitialized)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(ContractIndexRegistryInitialized)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *ContractIndexRegistryInitializedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *ContractIndexRegistryInitializedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// ContractIndexRegistryInitialized represents a Initialized event raised by the ContractIndexRegistry contract.
type ContractIndexRegistryInitialized struct {
	Version uint8
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterInitialized is a free log retrieval operation binding the contract event 0x7f26b83ff96e1f2b6a682f133852f6798a09c465da95921460cefb3847402498.
//
// Solidity: event Initialized(uint8 version)
func (_ContractIndexRegistry *ContractIndexRegistryFilterer) FilterInitialized(opts *bind.FilterOpts) (*ContractIndexRegistryInitializedIterator, error) {

	logs, sub, err := _ContractIndexRegistry.contract.FilterLogs(opts, "Initialized")
	if err != nil {
		return nil, err
	}
	return &ContractIndexRegistryInitializedIterator{contract: _ContractIndexRegistry.contract, event: "Initialized", logs: logs, sub: sub}, nil
}

// WatchInitialized is a free log subscription operation binding the contract event 0x7f26b83ff96e1f2b6a682f133852f6798a09c465da95921460cefb3847402498.
//
// Solidity: event Initialized(uint8 version)
func (_ContractIndexRegistry *ContractIndexRegistryFilterer) WatchInitialized(opts *bind.WatchOpts, sink chan<- *ContractIndexRegistryInitialized) (event.Subscription, error) {

	logs, sub, err := _ContractIndexRegistry.contract.WatchLogs(opts, "Initialized")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(ContractIndexRegistryInitialized)
				if err := _ContractIndexRegistry.contract.UnpackLog(event, "Initialized", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseInitialized is a log parse operation binding the contract event 0x7f26b83ff96e1f2b6a682f133852f6798a09c465da95921460cefb3847402498.
//
// Solidity: event Initialized(uint8 version)
func (_ContractIndexRegistry *ContractIndexRegistryFilterer) ParseInitialized(log types.Log) (*ContractIndexRegistryInitialized, error) {
	event := new(ContractIndexRegistryInitialized)
	if err := _ContractIndexRegistry.contract.UnpackLog(event, "Initialized", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// ContractIndexRegistryQuorumIndexUpdateIterator is returned from FilterQuorumIndexUpdate and is used to iterate over the raw logs and unpacked data for QuorumIndexUpdate events raised by the ContractIndexRegistry contract.
type ContractIndexRegistryQuorumIndexUpdateIterator struct {
	Event *ContractIndexRegistryQuorumIndexUpdate // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *ContractIndexRegistryQuorumIndexUpdateIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(ContractIndexRegistryQuorumIndexUpdate)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(ContractIndexRegistryQuorumIndexUpdate)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *ContractIndexRegistryQuorumIndexUpdateIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *ContractIndexRegistryQuorumIndexUpdateIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// ContractIndexRegistryQuorumIndexUpdate represents a QuorumIndexUpdate event raised by the ContractIndexRegistry contract.
type ContractIndexRegistryQuorumIndexUpdate struct {
	OperatorId       [32]byte
	QuorumNumber     uint8
	NewOperatorIndex uint32
	Raw              types.Log // Blockchain specific contextual infos
}

// FilterQuorumIndexUpdate is a free log retrieval operation binding the contract event 0x6ee1e4f4075f3d067176140d34e87874244dd273294c05b2218133e49a2ba6f6.
//
// Solidity: event QuorumIndexUpdate(bytes32 indexed operatorId, uint8 quorumNumber, uint32 newOperatorIndex)
func (_ContractIndexRegistry *ContractIndexRegistryFilterer) FilterQuorumIndexUpdate(opts *bind.FilterOpts, operatorId [][32]byte) (*ContractIndexRegistryQuorumIndexUpdateIterator, error) {

	var operatorIdRule []interface{}
	for _, operatorIdItem := range operatorId {
		operatorIdRule = append(operatorIdRule, operatorIdItem)
	}

	logs, sub, err := _ContractIndexRegistry.contract.FilterLogs(opts, "QuorumIndexUpdate", operatorIdRule)
	if err != nil {
		return nil, err
	}
	return &ContractIndexRegistryQuorumIndexUpdateIterator{contract: _ContractIndexRegistry.contract, event: "QuorumIndexUpdate", logs: logs, sub: sub}, nil
}

// WatchQuorumIndexUpdate is a free log subscription operation binding the contract event 0x6ee1e4f4075f3d067176140d34e87874244dd273294c05b2218133e49a2ba6f6.
//
// Solidity: event QuorumIndexUpdate(bytes32 indexed operatorId, uint8 quorumNumber, uint32 newOperatorIndex)
func (_ContractIndexRegistry *ContractIndexRegistryFilterer) WatchQuorumIndexUpdate(opts *bind.WatchOpts, sink chan<- *ContractIndexRegistryQuorumIndexUpdate, operatorId [][32]byte) (event.Subscription, error) {

	var operatorIdRule []interface{}
	for _, operatorIdItem := range operatorId {
		operatorIdRule = append(operatorIdRule, operatorIdItem)
	}

	logs, sub, err := _ContractIndexRegistry.contract.WatchLogs(opts, "QuorumIndexUpdate", operatorIdRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(ContractIndexRegistryQuorumIndexUpdate)
				if err := _ContractIndexRegistry.contract.UnpackLog(event, "QuorumIndexUpdate", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseQuorumIndexUpdate is a log parse operation binding the contract event 0x6ee1e4f4075f3d067176140d34e87874244dd273294c05b2218133e49a2ba6f6.
//
// Solidity: event QuorumIndexUpdate(bytes32 indexed operatorId, uint8 quorumNumber, uint32 newOperatorIndex)
func (_ContractIndexRegistry *ContractIndexRegistryFilterer) ParseQuorumIndexUpdate(log types.Log) (*ContractIndexRegistryQuorumIndexUpdate, error) {
	event := new(ContractIndexRegistryQuorumIndexUpdate)
	if err := _ContractIndexRegistry.contract.UnpackLog(event, "QuorumIndexUpdate", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}
