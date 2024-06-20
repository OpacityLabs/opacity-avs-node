// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package contractOperatorStateRetriever

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

// OperatorStateRetrieverCheckSignaturesIndices is an auto generated low-level Go binding around an user-defined struct.
type OperatorStateRetrieverCheckSignaturesIndices struct {
	NonSignerQuorumBitmapIndices []uint32
	QuorumApkIndices             []uint32
	TotalStakeIndices            []uint32
	NonSignerStakeIndices        [][]uint32
}

// OperatorStateRetrieverOperator is an auto generated low-level Go binding around an user-defined struct.
type OperatorStateRetrieverOperator struct {
	Operator   common.Address
	OperatorId [32]byte
	Stake      *big.Int
}

// ContractOperatorStateRetrieverMetaData contains all meta data concerning the ContractOperatorStateRetriever contract.
var ContractOperatorStateRetrieverMetaData = &bind.MetaData{
	ABI: "[{\"type\":\"function\",\"name\":\"getCheckSignaturesIndices\",\"inputs\":[{\"name\":\"registryCoordinator\",\"type\":\"address\",\"internalType\":\"contractIRegistryCoordinator\"},{\"name\":\"referenceBlockNumber\",\"type\":\"uint32\",\"internalType\":\"uint32\"},{\"name\":\"quorumNumbers\",\"type\":\"bytes\",\"internalType\":\"bytes\"},{\"name\":\"nonSignerOperatorIds\",\"type\":\"bytes32[]\",\"internalType\":\"bytes32[]\"}],\"outputs\":[{\"name\":\"\",\"type\":\"tuple\",\"internalType\":\"structOperatorStateRetriever.CheckSignaturesIndices\",\"components\":[{\"name\":\"nonSignerQuorumBitmapIndices\",\"type\":\"uint32[]\",\"internalType\":\"uint32[]\"},{\"name\":\"quorumApkIndices\",\"type\":\"uint32[]\",\"internalType\":\"uint32[]\"},{\"name\":\"totalStakeIndices\",\"type\":\"uint32[]\",\"internalType\":\"uint32[]\"},{\"name\":\"nonSignerStakeIndices\",\"type\":\"uint32[][]\",\"internalType\":\"uint32[][]\"}]}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getOperatorState\",\"inputs\":[{\"name\":\"registryCoordinator\",\"type\":\"address\",\"internalType\":\"contractIRegistryCoordinator\"},{\"name\":\"quorumNumbers\",\"type\":\"bytes\",\"internalType\":\"bytes\"},{\"name\":\"blockNumber\",\"type\":\"uint32\",\"internalType\":\"uint32\"}],\"outputs\":[{\"name\":\"\",\"type\":\"tuple[][]\",\"internalType\":\"structOperatorStateRetriever.Operator[][]\",\"components\":[{\"name\":\"operator\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"operatorId\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"stake\",\"type\":\"uint96\",\"internalType\":\"uint96\"}]}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getOperatorState\",\"inputs\":[{\"name\":\"registryCoordinator\",\"type\":\"address\",\"internalType\":\"contractIRegistryCoordinator\"},{\"name\":\"operatorId\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"blockNumber\",\"type\":\"uint32\",\"internalType\":\"uint32\"}],\"outputs\":[{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"\",\"type\":\"tuple[][]\",\"internalType\":\"structOperatorStateRetriever.Operator[][]\",\"components\":[{\"name\":\"operator\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"operatorId\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"stake\",\"type\":\"uint96\",\"internalType\":\"uint96\"}]}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getQuorumBitmapsAtBlockNumber\",\"inputs\":[{\"name\":\"registryCoordinator\",\"type\":\"address\",\"internalType\":\"contractIRegistryCoordinator\"},{\"name\":\"operatorIds\",\"type\":\"bytes32[]\",\"internalType\":\"bytes32[]\"},{\"name\":\"blockNumber\",\"type\":\"uint32\",\"internalType\":\"uint32\"}],\"outputs\":[{\"name\":\"\",\"type\":\"uint256[]\",\"internalType\":\"uint256[]\"}],\"stateMutability\":\"view\"}]",
	Bin: "0x608060405234801561001057600080fd5b506119ce806100206000396000f3fe608060405234801561001057600080fd5b506004361061004c5760003560e01c80633563b0d1146100515780634f739f741461007a5780635c1556621461009a578063cefdc1d4146100ba575b600080fd5b61006461005f366004611140565b6100db565b604051610071919061129e565b60405180910390f35b61008d610088366004611303565b61055b565b6040516100719190611407565b6100ad6100a83660046114e5565b610c73565b6040516100719190611596565b6100cd6100c83660046115da565b610e31565b60405161007192919061161c565b60606000846001600160a01b031663683048356040518163ffffffff1660e01b8152600401602060405180830381865afa15801561011d573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190610141919061163d565b90506000856001600160a01b0316639e9923c26040518163ffffffff1660e01b8152600401602060405180830381865afa158015610183573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906101a7919061163d565b90506000866001600160a01b0316635df459466040518163ffffffff1660e01b8152600401602060405180830381865afa1580156101e9573d6000803e3d6000fd5b505050506040513d601f19601f8201168201806040525081019061020d919061163d565b9050600086516001600160401b0381111561022a5761022a6110d8565b60405190808252806020026020018201604052801561025d57816020015b60608152602001906001900390816102485790505b50905060005b875181101561054f5760008882815181106102805761028061165a565b0160200151604051638902624560e01b815260f89190911c6004820181905263ffffffff8a16602483015291506000906001600160a01b03871690638902624590604401600060405180830381865afa1580156102e1573d6000803e3d6000fd5b505050506040513d6000823e601f3d908101601f191682016040526103099190810190611670565b905080516001600160401b03811115610324576103246110d8565b60405190808252806020026020018201604052801561036f57816020015b60408051606081018252600080825260208083018290529282015282526000199092019101816103425790505b508484815181106103825761038261165a565b602002602001018190525060005b8151811015610544576040518060600160405280876001600160a01b03166347b314e88585815181106103c5576103c561165a565b60200260200101516040518263ffffffff1660e01b81526004016103eb91815260200190565b602060405180830381865afa158015610408573d6000803e3d6000fd5b505050506040513d601f19601f8201168201806040525081019061042c919061163d565b6001600160a01b0316815260200183838151811061044c5761044c61165a565b60200260200101518152602001896001600160a01b031663fa28c62785858151811061047a5761047a61165a565b60209081029190910101516040516001600160e01b031960e084901b168152600481019190915260ff8816602482015263ffffffff8f166044820152606401602060405180830381865afa1580156104d6573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906104fa9190611700565b6001600160601b03168152508585815181106105185761051861165a565b602002602001015182815181106105315761053161165a565b6020908102919091010152600101610390565b505050600101610263565b50979650505050505050565b6105866040518060800160405280606081526020016060815260200160608152602001606081525090565b6000876001600160a01b031663683048356040518163ffffffff1660e01b8152600401602060405180830381865afa1580156105c6573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906105ea919061163d565b90506106176040518060800160405280606081526020016060815260200160608152602001606081525090565b6040516361c8a12f60e11b81526001600160a01b038a169063c391425e90610647908b9089908990600401611729565b600060405180830381865afa158015610664573d6000803e3d6000fd5b505050506040513d6000823e601f3d908101601f1916820160405261068c9190810190611770565b81526040516340e03a8160e11b81526001600160a01b038316906381c07502906106be908b908b908b90600401611827565b600060405180830381865afa1580156106db573d6000803e3d6000fd5b505050506040513d6000823e601f3d908101601f191682016040526107039190810190611770565b6040820152856001600160401b03811115610720576107206110d8565b60405190808252806020026020018201604052801561075357816020015b606081526020019060019003908161073e5790505b50606082015260005b60ff8116871115610b84576000856001600160401b03811115610781576107816110d8565b6040519080825280602002602001820160405280156107aa578160200160208202803683370190505b5083606001518360ff16815181106107c4576107c461165a565b602002602001018190525060005b86811015610a8e5760008c6001600160a01b03166304ec63518a8a858181106107fd576107fd61165a565b905060200201358e8860000151868151811061081b5761081b61165a565b60200260200101516040518463ffffffff1660e01b81526004016108589392919092835263ffffffff918216602084015216604082015260600190565b602060405180830381865afa158015610875573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906108999190611850565b9050806001600160c01b03166000036109445760405162461bcd60e51b815260206004820152605c60248201527f4f70657261746f7253746174655265747269657665722e676574436865636b5360448201527f69676e617475726573496e64696365733a206f70657261746f72206d7573742060648201527f6265207265676973746572656420617420626c6f636b6e756d62657200000000608482015260a40160405180910390fd5b8a8a8560ff168181106109595761095961165a565b60016001600160c01b038516919093013560f81c1c82169091039050610a8557856001600160a01b031663dd9846b98a8a8581811061099a5761099a61165a565b905060200201358d8d8860ff168181106109b6576109b661165a565b6040516001600160e01b031960e087901b1681526004810194909452919091013560f81c60248301525063ffffffff8f166044820152606401602060405180830381865afa158015610a0c573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190610a309190611879565b85606001518560ff1681518110610a4957610a4961165a565b60200260200101518481518110610a6257610a6261165a565b63ffffffff9092166020928302919091019091015282610a81816118ac565b9350505b506001016107d2565b506000816001600160401b03811115610aa957610aa96110d8565b604051908082528060200260200182016040528015610ad2578160200160208202803683370190505b50905060005b82811015610b495784606001518460ff1681518110610af957610af961165a565b60200260200101518181518110610b1257610b1261165a565b6020026020010151828281518110610b2c57610b2c61165a565b63ffffffff90921660209283029190910190910152600101610ad8565b508084606001518460ff1681518110610b6457610b6461165a565b602002602001018190525050508080610b7c906118c5565b91505061075c565b506000896001600160a01b0316635df459466040518163ffffffff1660e01b8152600401602060405180830381865afa158015610bc5573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190610be9919061163d565b60405163354952a360e21b81529091506001600160a01b0382169063d5254a8c90610c1c908b908b908e906004016118e4565b600060405180830381865afa158015610c39573d6000803e3d6000fd5b505050506040513d6000823e601f3d908101601f19168201604052610c619190810190611770565b60208301525098975050505050505050565b60606000846001600160a01b031663c391425e84866040518363ffffffff1660e01b8152600401610ca592919061190e565b600060405180830381865afa158015610cc2573d6000803e3d6000fd5b505050506040513d6000823e601f3d908101601f19168201604052610cea9190810190611770565b9050600084516001600160401b03811115610d0757610d076110d8565b604051908082528060200260200182016040528015610d30578160200160208202803683370190505b50905060005b8551811015610e2757866001600160a01b03166304ec6351878381518110610d6057610d6061165a565b602002602001015187868581518110610d7b57610d7b61165a565b60200260200101516040518463ffffffff1660e01b8152600401610db89392919092835263ffffffff918216602084015216604082015260600190565b602060405180830381865afa158015610dd5573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190610df99190611850565b6001600160c01b0316828281518110610e1457610e1461165a565b6020908102919091010152600101610d36565b5095945050505050565b6040805160018082528183019092526000916060918391602080830190803683370190505090508481600081518110610e6c57610e6c61165a565b60209081029190910101526040516361c8a12f60e11b81526000906001600160a01b0388169063c391425e90610ea8908890869060040161190e565b600060405180830381865afa158015610ec5573d6000803e3d6000fd5b505050506040513d6000823e601f3d908101601f19168201604052610eed9190810190611770565b600081518110610eff57610eff61165a565b60209081029190910101516040516304ec635160e01b81526004810188905263ffffffff87811660248301529091166044820181905291506000906001600160a01b038916906304ec635190606401602060405180830381865afa158015610f6b573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190610f8f9190611850565b6001600160c01b031690506000610fa582610fc3565b905081610fb38a838a6100db565b9550955050505050935093915050565b6060600080610fd18461108f565b61ffff166001600160401b03811115610fec57610fec6110d8565b6040519080825280601f01601f191660200182016040528015611016576020820181803683370190505b5090506000805b82518210801561102e575061010081105b15611085576001811b935085841615611075578060f81b8383815181106110575761105761165a565b60200101906001600160f81b031916908160001a9053508160010191505b61107e816118ac565b905061101d565b5090949350505050565b6000805b82156110ba576110a4600184611964565b90921691806110b281611977565b915050611093565b92915050565b6001600160a01b03811681146110d557600080fd5b50565b634e487b7160e01b600052604160045260246000fd5b604051601f8201601f191681016001600160401b0381118282101715611116576111166110d8565b604052919050565b63ffffffff811681146110d557600080fd5b803561113b8161111e565b919050565b60008060006060848603121561115557600080fd5b8335611160816110c0565b92506020848101356001600160401b038082111561117d57600080fd5b818701915087601f83011261119157600080fd5b8135818111156111a3576111a36110d8565b6111b5601f8201601f191685016110ee565b915080825288848285010111156111cb57600080fd5b80848401858401376000848284010152508094505050506111ee60408501611130565b90509250925092565b600082825180855260208086019550808260051b8401018186016000805b8581101561129057868403601f19018a52825180518086529086019086860190845b8181101561127b57835180516001600160a01b03168452898101518a8501526040908101516001600160601b03169084015292880192606090920191600101611237565b50509a86019a94505091840191600101611215565b509198975050505050505050565b6020815260006112b160208301846111f7565b9392505050565b60008083601f8401126112ca57600080fd5b5081356001600160401b038111156112e157600080fd5b6020830191508360208260051b85010111156112fc57600080fd5b9250929050565b6000806000806000806080878903121561131c57600080fd5b8635611327816110c0565b955060208701356113378161111e565b945060408701356001600160401b038082111561135357600080fd5b818901915089601f83011261136757600080fd5b81358181111561137657600080fd5b8a602082850101111561138857600080fd5b6020830196508095505060608901359150808211156113a657600080fd5b506113b389828a016112b8565b979a9699509497509295939492505050565b60008151808452602080850194506020840160005b838110156113fc57815163ffffffff16875295820195908201906001016113da565b509495945050505050565b60006020808352835160808285015261142360a08501826113c5565b905081850151601f198086840301604087015261144083836113c5565b9250604087015191508086840301606087015261145d83836113c5565b60608801518782038301608089015280518083529194508501925084840190600581901b8501860160005b828110156114b457848783030184526114a28287516113c5565b95880195938801939150600101611488565b509998505050505050505050565b60006001600160401b038211156114db576114db6110d8565b5060051b60200190565b6000806000606084860312156114fa57600080fd5b8335611505816110c0565b92506020848101356001600160401b0381111561152157600080fd5b8501601f8101871361153257600080fd5b8035611545611540826114c2565b6110ee565b81815260059190911b8201830190838101908983111561156457600080fd5b928401925b8284101561158257833582529284019290840190611569565b80965050505050506111ee60408501611130565b6020808252825182820181905260009190848201906040850190845b818110156115ce578351835292840192918401916001016115b2565b50909695505050505050565b6000806000606084860312156115ef57600080fd5b83356115fa816110c0565b92506020840135915060408401356116118161111e565b809150509250925092565b82815260406020820152600061163560408301846111f7565b949350505050565b60006020828403121561164f57600080fd5b81516112b1816110c0565b634e487b7160e01b600052603260045260246000fd5b6000602080838503121561168357600080fd5b82516001600160401b0381111561169957600080fd5b8301601f810185136116aa57600080fd5b80516116b8611540826114c2565b81815260059190911b820183019083810190878311156116d757600080fd5b928401925b828410156116f5578351825292840192908401906116dc565b979650505050505050565b60006020828403121561171257600080fd5b81516001600160601b03811681146112b157600080fd5b63ffffffff84168152604060208201819052810182905260006001600160fb1b0383111561175657600080fd5b8260051b8085606085013791909101606001949350505050565b6000602080838503121561178357600080fd5b82516001600160401b0381111561179957600080fd5b8301601f810185136117aa57600080fd5b80516117b8611540826114c2565b81815260059190911b820183019083810190878311156117d757600080fd5b928401925b828410156116f55783516117ef8161111e565b825292840192908401906117dc565b81835281816020850137506000828201602090810191909152601f909101601f19169091010190565b63ffffffff841681526040602082015260006118476040830184866117fe565b95945050505050565b60006020828403121561186257600080fd5b81516001600160c01b03811681146112b157600080fd5b60006020828403121561188b57600080fd5b81516112b18161111e565b634e487b7160e01b600052601160045260246000fd5b6000600182016118be576118be611896565b5060010190565b600060ff821660ff81036118db576118db611896565b60010192915050565b6040815260006118f86040830185876117fe565b905063ffffffff83166020830152949350505050565b60006040820163ffffffff8516835260206040602085015281855180845260608601915060208701935060005b818110156119575784518352938301939183019160010161193b565b5090979650505050505050565b818103818111156110ba576110ba611896565b600061ffff80831681810361198e5761198e611896565b600101939250505056fea2646970667358221220bc4ae1f58f033eecb51dec24837788487a910c21aae6e877310aaf1927ef125c64736f6c63430008170033",
}

// ContractOperatorStateRetrieverABI is the input ABI used to generate the binding from.
// Deprecated: Use ContractOperatorStateRetrieverMetaData.ABI instead.
var ContractOperatorStateRetrieverABI = ContractOperatorStateRetrieverMetaData.ABI

// ContractOperatorStateRetrieverBin is the compiled bytecode used for deploying new contracts.
// Deprecated: Use ContractOperatorStateRetrieverMetaData.Bin instead.
var ContractOperatorStateRetrieverBin = ContractOperatorStateRetrieverMetaData.Bin

// DeployContractOperatorStateRetriever deploys a new Ethereum contract, binding an instance of ContractOperatorStateRetriever to it.
func DeployContractOperatorStateRetriever(auth *bind.TransactOpts, backend bind.ContractBackend) (common.Address, *types.Transaction, *ContractOperatorStateRetriever, error) {
	parsed, err := ContractOperatorStateRetrieverMetaData.GetAbi()
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	if parsed == nil {
		return common.Address{}, nil, nil, errors.New("GetABI returned nil")
	}

	address, tx, contract, err := bind.DeployContract(auth, *parsed, common.FromHex(ContractOperatorStateRetrieverBin), backend)
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	return address, tx, &ContractOperatorStateRetriever{ContractOperatorStateRetrieverCaller: ContractOperatorStateRetrieverCaller{contract: contract}, ContractOperatorStateRetrieverTransactor: ContractOperatorStateRetrieverTransactor{contract: contract}, ContractOperatorStateRetrieverFilterer: ContractOperatorStateRetrieverFilterer{contract: contract}}, nil
}

// ContractOperatorStateRetriever is an auto generated Go binding around an Ethereum contract.
type ContractOperatorStateRetriever struct {
	ContractOperatorStateRetrieverCaller     // Read-only binding to the contract
	ContractOperatorStateRetrieverTransactor // Write-only binding to the contract
	ContractOperatorStateRetrieverFilterer   // Log filterer for contract events
}

// ContractOperatorStateRetrieverCaller is an auto generated read-only Go binding around an Ethereum contract.
type ContractOperatorStateRetrieverCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ContractOperatorStateRetrieverTransactor is an auto generated write-only Go binding around an Ethereum contract.
type ContractOperatorStateRetrieverTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ContractOperatorStateRetrieverFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type ContractOperatorStateRetrieverFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ContractOperatorStateRetrieverSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type ContractOperatorStateRetrieverSession struct {
	Contract     *ContractOperatorStateRetriever // Generic contract binding to set the session for
	CallOpts     bind.CallOpts                   // Call options to use throughout this session
	TransactOpts bind.TransactOpts               // Transaction auth options to use throughout this session
}

// ContractOperatorStateRetrieverCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type ContractOperatorStateRetrieverCallerSession struct {
	Contract *ContractOperatorStateRetrieverCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts                         // Call options to use throughout this session
}

// ContractOperatorStateRetrieverTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type ContractOperatorStateRetrieverTransactorSession struct {
	Contract     *ContractOperatorStateRetrieverTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts                         // Transaction auth options to use throughout this session
}

// ContractOperatorStateRetrieverRaw is an auto generated low-level Go binding around an Ethereum contract.
type ContractOperatorStateRetrieverRaw struct {
	Contract *ContractOperatorStateRetriever // Generic contract binding to access the raw methods on
}

// ContractOperatorStateRetrieverCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type ContractOperatorStateRetrieverCallerRaw struct {
	Contract *ContractOperatorStateRetrieverCaller // Generic read-only contract binding to access the raw methods on
}

// ContractOperatorStateRetrieverTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type ContractOperatorStateRetrieverTransactorRaw struct {
	Contract *ContractOperatorStateRetrieverTransactor // Generic write-only contract binding to access the raw methods on
}

// NewContractOperatorStateRetriever creates a new instance of ContractOperatorStateRetriever, bound to a specific deployed contract.
func NewContractOperatorStateRetriever(address common.Address, backend bind.ContractBackend) (*ContractOperatorStateRetriever, error) {
	contract, err := bindContractOperatorStateRetriever(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &ContractOperatorStateRetriever{ContractOperatorStateRetrieverCaller: ContractOperatorStateRetrieverCaller{contract: contract}, ContractOperatorStateRetrieverTransactor: ContractOperatorStateRetrieverTransactor{contract: contract}, ContractOperatorStateRetrieverFilterer: ContractOperatorStateRetrieverFilterer{contract: contract}}, nil
}

// NewContractOperatorStateRetrieverCaller creates a new read-only instance of ContractOperatorStateRetriever, bound to a specific deployed contract.
func NewContractOperatorStateRetrieverCaller(address common.Address, caller bind.ContractCaller) (*ContractOperatorStateRetrieverCaller, error) {
	contract, err := bindContractOperatorStateRetriever(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &ContractOperatorStateRetrieverCaller{contract: contract}, nil
}

// NewContractOperatorStateRetrieverTransactor creates a new write-only instance of ContractOperatorStateRetriever, bound to a specific deployed contract.
func NewContractOperatorStateRetrieverTransactor(address common.Address, transactor bind.ContractTransactor) (*ContractOperatorStateRetrieverTransactor, error) {
	contract, err := bindContractOperatorStateRetriever(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &ContractOperatorStateRetrieverTransactor{contract: contract}, nil
}

// NewContractOperatorStateRetrieverFilterer creates a new log filterer instance of ContractOperatorStateRetriever, bound to a specific deployed contract.
func NewContractOperatorStateRetrieverFilterer(address common.Address, filterer bind.ContractFilterer) (*ContractOperatorStateRetrieverFilterer, error) {
	contract, err := bindContractOperatorStateRetriever(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &ContractOperatorStateRetrieverFilterer{contract: contract}, nil
}

// bindContractOperatorStateRetriever binds a generic wrapper to an already deployed contract.
func bindContractOperatorStateRetriever(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := ContractOperatorStateRetrieverMetaData.GetAbi()
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, *parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_ContractOperatorStateRetriever *ContractOperatorStateRetrieverRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _ContractOperatorStateRetriever.Contract.ContractOperatorStateRetrieverCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_ContractOperatorStateRetriever *ContractOperatorStateRetrieverRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _ContractOperatorStateRetriever.Contract.ContractOperatorStateRetrieverTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_ContractOperatorStateRetriever *ContractOperatorStateRetrieverRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _ContractOperatorStateRetriever.Contract.ContractOperatorStateRetrieverTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_ContractOperatorStateRetriever *ContractOperatorStateRetrieverCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _ContractOperatorStateRetriever.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_ContractOperatorStateRetriever *ContractOperatorStateRetrieverTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _ContractOperatorStateRetriever.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_ContractOperatorStateRetriever *ContractOperatorStateRetrieverTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _ContractOperatorStateRetriever.Contract.contract.Transact(opts, method, params...)
}

// GetCheckSignaturesIndices is a free data retrieval call binding the contract method 0x4f739f74.
//
// Solidity: function getCheckSignaturesIndices(address registryCoordinator, uint32 referenceBlockNumber, bytes quorumNumbers, bytes32[] nonSignerOperatorIds) view returns((uint32[],uint32[],uint32[],uint32[][]))
func (_ContractOperatorStateRetriever *ContractOperatorStateRetrieverCaller) GetCheckSignaturesIndices(opts *bind.CallOpts, registryCoordinator common.Address, referenceBlockNumber uint32, quorumNumbers []byte, nonSignerOperatorIds [][32]byte) (OperatorStateRetrieverCheckSignaturesIndices, error) {
	var out []interface{}
	err := _ContractOperatorStateRetriever.contract.Call(opts, &out, "getCheckSignaturesIndices", registryCoordinator, referenceBlockNumber, quorumNumbers, nonSignerOperatorIds)

	if err != nil {
		return *new(OperatorStateRetrieverCheckSignaturesIndices), err
	}

	out0 := *abi.ConvertType(out[0], new(OperatorStateRetrieverCheckSignaturesIndices)).(*OperatorStateRetrieverCheckSignaturesIndices)

	return out0, err

}

// GetCheckSignaturesIndices is a free data retrieval call binding the contract method 0x4f739f74.
//
// Solidity: function getCheckSignaturesIndices(address registryCoordinator, uint32 referenceBlockNumber, bytes quorumNumbers, bytes32[] nonSignerOperatorIds) view returns((uint32[],uint32[],uint32[],uint32[][]))
func (_ContractOperatorStateRetriever *ContractOperatorStateRetrieverSession) GetCheckSignaturesIndices(registryCoordinator common.Address, referenceBlockNumber uint32, quorumNumbers []byte, nonSignerOperatorIds [][32]byte) (OperatorStateRetrieverCheckSignaturesIndices, error) {
	return _ContractOperatorStateRetriever.Contract.GetCheckSignaturesIndices(&_ContractOperatorStateRetriever.CallOpts, registryCoordinator, referenceBlockNumber, quorumNumbers, nonSignerOperatorIds)
}

// GetCheckSignaturesIndices is a free data retrieval call binding the contract method 0x4f739f74.
//
// Solidity: function getCheckSignaturesIndices(address registryCoordinator, uint32 referenceBlockNumber, bytes quorumNumbers, bytes32[] nonSignerOperatorIds) view returns((uint32[],uint32[],uint32[],uint32[][]))
func (_ContractOperatorStateRetriever *ContractOperatorStateRetrieverCallerSession) GetCheckSignaturesIndices(registryCoordinator common.Address, referenceBlockNumber uint32, quorumNumbers []byte, nonSignerOperatorIds [][32]byte) (OperatorStateRetrieverCheckSignaturesIndices, error) {
	return _ContractOperatorStateRetriever.Contract.GetCheckSignaturesIndices(&_ContractOperatorStateRetriever.CallOpts, registryCoordinator, referenceBlockNumber, quorumNumbers, nonSignerOperatorIds)
}

// GetOperatorState is a free data retrieval call binding the contract method 0x3563b0d1.
//
// Solidity: function getOperatorState(address registryCoordinator, bytes quorumNumbers, uint32 blockNumber) view returns((address,bytes32,uint96)[][])
func (_ContractOperatorStateRetriever *ContractOperatorStateRetrieverCaller) GetOperatorState(opts *bind.CallOpts, registryCoordinator common.Address, quorumNumbers []byte, blockNumber uint32) ([][]OperatorStateRetrieverOperator, error) {
	var out []interface{}
	err := _ContractOperatorStateRetriever.contract.Call(opts, &out, "getOperatorState", registryCoordinator, quorumNumbers, blockNumber)

	if err != nil {
		return *new([][]OperatorStateRetrieverOperator), err
	}

	out0 := *abi.ConvertType(out[0], new([][]OperatorStateRetrieverOperator)).(*[][]OperatorStateRetrieverOperator)

	return out0, err

}

// GetOperatorState is a free data retrieval call binding the contract method 0x3563b0d1.
//
// Solidity: function getOperatorState(address registryCoordinator, bytes quorumNumbers, uint32 blockNumber) view returns((address,bytes32,uint96)[][])
func (_ContractOperatorStateRetriever *ContractOperatorStateRetrieverSession) GetOperatorState(registryCoordinator common.Address, quorumNumbers []byte, blockNumber uint32) ([][]OperatorStateRetrieverOperator, error) {
	return _ContractOperatorStateRetriever.Contract.GetOperatorState(&_ContractOperatorStateRetriever.CallOpts, registryCoordinator, quorumNumbers, blockNumber)
}

// GetOperatorState is a free data retrieval call binding the contract method 0x3563b0d1.
//
// Solidity: function getOperatorState(address registryCoordinator, bytes quorumNumbers, uint32 blockNumber) view returns((address,bytes32,uint96)[][])
func (_ContractOperatorStateRetriever *ContractOperatorStateRetrieverCallerSession) GetOperatorState(registryCoordinator common.Address, quorumNumbers []byte, blockNumber uint32) ([][]OperatorStateRetrieverOperator, error) {
	return _ContractOperatorStateRetriever.Contract.GetOperatorState(&_ContractOperatorStateRetriever.CallOpts, registryCoordinator, quorumNumbers, blockNumber)
}

// GetOperatorState0 is a free data retrieval call binding the contract method 0xcefdc1d4.
//
// Solidity: function getOperatorState(address registryCoordinator, bytes32 operatorId, uint32 blockNumber) view returns(uint256, (address,bytes32,uint96)[][])
func (_ContractOperatorStateRetriever *ContractOperatorStateRetrieverCaller) GetOperatorState0(opts *bind.CallOpts, registryCoordinator common.Address, operatorId [32]byte, blockNumber uint32) (*big.Int, [][]OperatorStateRetrieverOperator, error) {
	var out []interface{}
	err := _ContractOperatorStateRetriever.contract.Call(opts, &out, "getOperatorState0", registryCoordinator, operatorId, blockNumber)

	if err != nil {
		return *new(*big.Int), *new([][]OperatorStateRetrieverOperator), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)
	out1 := *abi.ConvertType(out[1], new([][]OperatorStateRetrieverOperator)).(*[][]OperatorStateRetrieverOperator)

	return out0, out1, err

}

// GetOperatorState0 is a free data retrieval call binding the contract method 0xcefdc1d4.
//
// Solidity: function getOperatorState(address registryCoordinator, bytes32 operatorId, uint32 blockNumber) view returns(uint256, (address,bytes32,uint96)[][])
func (_ContractOperatorStateRetriever *ContractOperatorStateRetrieverSession) GetOperatorState0(registryCoordinator common.Address, operatorId [32]byte, blockNumber uint32) (*big.Int, [][]OperatorStateRetrieverOperator, error) {
	return _ContractOperatorStateRetriever.Contract.GetOperatorState0(&_ContractOperatorStateRetriever.CallOpts, registryCoordinator, operatorId, blockNumber)
}

// GetOperatorState0 is a free data retrieval call binding the contract method 0xcefdc1d4.
//
// Solidity: function getOperatorState(address registryCoordinator, bytes32 operatorId, uint32 blockNumber) view returns(uint256, (address,bytes32,uint96)[][])
func (_ContractOperatorStateRetriever *ContractOperatorStateRetrieverCallerSession) GetOperatorState0(registryCoordinator common.Address, operatorId [32]byte, blockNumber uint32) (*big.Int, [][]OperatorStateRetrieverOperator, error) {
	return _ContractOperatorStateRetriever.Contract.GetOperatorState0(&_ContractOperatorStateRetriever.CallOpts, registryCoordinator, operatorId, blockNumber)
}

// GetQuorumBitmapsAtBlockNumber is a free data retrieval call binding the contract method 0x5c155662.
//
// Solidity: function getQuorumBitmapsAtBlockNumber(address registryCoordinator, bytes32[] operatorIds, uint32 blockNumber) view returns(uint256[])
func (_ContractOperatorStateRetriever *ContractOperatorStateRetrieverCaller) GetQuorumBitmapsAtBlockNumber(opts *bind.CallOpts, registryCoordinator common.Address, operatorIds [][32]byte, blockNumber uint32) ([]*big.Int, error) {
	var out []interface{}
	err := _ContractOperatorStateRetriever.contract.Call(opts, &out, "getQuorumBitmapsAtBlockNumber", registryCoordinator, operatorIds, blockNumber)

	if err != nil {
		return *new([]*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new([]*big.Int)).(*[]*big.Int)

	return out0, err

}

// GetQuorumBitmapsAtBlockNumber is a free data retrieval call binding the contract method 0x5c155662.
//
// Solidity: function getQuorumBitmapsAtBlockNumber(address registryCoordinator, bytes32[] operatorIds, uint32 blockNumber) view returns(uint256[])
func (_ContractOperatorStateRetriever *ContractOperatorStateRetrieverSession) GetQuorumBitmapsAtBlockNumber(registryCoordinator common.Address, operatorIds [][32]byte, blockNumber uint32) ([]*big.Int, error) {
	return _ContractOperatorStateRetriever.Contract.GetQuorumBitmapsAtBlockNumber(&_ContractOperatorStateRetriever.CallOpts, registryCoordinator, operatorIds, blockNumber)
}

// GetQuorumBitmapsAtBlockNumber is a free data retrieval call binding the contract method 0x5c155662.
//
// Solidity: function getQuorumBitmapsAtBlockNumber(address registryCoordinator, bytes32[] operatorIds, uint32 blockNumber) view returns(uint256[])
func (_ContractOperatorStateRetriever *ContractOperatorStateRetrieverCallerSession) GetQuorumBitmapsAtBlockNumber(registryCoordinator common.Address, operatorIds [][32]byte, blockNumber uint32) ([]*big.Int, error) {
	return _ContractOperatorStateRetriever.Contract.GetQuorumBitmapsAtBlockNumber(&_ContractOperatorStateRetriever.CallOpts, registryCoordinator, operatorIds, blockNumber)
}
