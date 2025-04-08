package utils

import (
	"bitgo.com/proof_of_reserves/circuit"
	"github.com/consensys/gnark-crypto/ecc"
	mimcCrypto "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"math/big"
)

var ModBytes = len(ecc.BN254.ScalarField().Bytes())

type GoBalance struct {
	Bitcoin  uint64
	Ethereum uint64
}

type GoAccount struct {
	UserId  []byte
	Balance GoBalance
}

func goConvertBalanceToBytes(balance GoBalance) (value []byte) {
	value = make([]byte, 0)
	b := new(big.Int).SetUint64(balance.Bitcoin).Bytes()
	value = append(value, padToModBytes(b)...)

	b = new(big.Int).SetUint64(balance.Ethereum).Bytes()
	value = append(value, padToModBytes(b)...)

	return value
}

func padToModBytes(value []byte) (paddedValue []byte) {
	paddedValue = make([]byte, ModBytes-len(value))
	paddedValue = append(paddedValue, value...)
	return paddedValue
}

func goComputeMiMCHashForAccount(account GoAccount) []byte {
	hasher := mimcCrypto.NewMiMC()
	_, err := hasher.Write(goConvertBalanceToBytes(account.Balance))
	if err != nil {
		panic(err)
	}
	balanceHash := hasher.Sum(nil)
	hasher.Reset()
	_, err = hasher.Write(account.UserId)
	if err != nil {
		panic(err)
	}
	_, err = hasher.Write(balanceHash)
	return hasher.Sum(nil)
}

func goComputeMerkleRootFromAccounts(accounts []GoAccount) (rootHash []byte) {
	hasher := mimcCrypto.NewMiMC()
	nodes := make([][]byte, circuit.PowOfTwo(circuit.TreeDepth))
	for i := 0; i < circuit.PowOfTwo(circuit.TreeDepth); i++ {
		if i < len(accounts) {
			nodes[i] = goComputeMiMCHashForAccount(accounts[i])
		} else {
			nodes[i] = padToModBytes([]byte{})
		}
	}
	for i := circuit.TreeDepth - 1; i >= 0; i-- {
		for j := 0; j < circuit.PowOfTwo(i); j++ {
			hasher.Reset()
			_, err := hasher.Write(nodes[j*2])
			if err != nil {
				panic(err)
			}
			_, err = hasher.Write(nodes[j*2+1])
			if err != nil {
				panic(err)
			}
			nodes[j] = hasher.Sum(nil)
		}
	}
	return nodes[0]
}

func ConvertGoBalanceToBalance(goBalance GoBalance) circuit.Balance {
	return circuit.Balance{
		Bitcoin:  new(big.Int).SetUint64(goBalance.Bitcoin),
		Ethereum: new(big.Int).SetUint64(goBalance.Ethereum),
	}
}

func convertGoAccountToAccount(goAccount GoAccount) circuit.Account {
	return circuit.Account{
		UserId:  new(big.Int).SetBytes(goAccount.UserId),
		Balance: ConvertGoBalanceToBalance(goAccount.Balance),
	}
}

func ConvertGoAccountsToAccounts(goAccounts []GoAccount) (accounts []circuit.Account) {
	accounts = make([]circuit.Account, len(goAccounts))
	for i, goAccount := range goAccounts {
		accounts[i] = convertGoAccountToAccount(goAccount)
	}
	return accounts
}

func GenerateTestData(count int) (accounts []GoAccount, assetSum GoBalance, merkleRoot []byte, merkleRootWithAssetSumHash []byte) {
	assetSum = GoBalance{Bitcoin: 0, Ethereum: 0}
	for i := 0; i < count; i++ {
		btcCount, ethCount := uint64(i+45*i+39), uint64(i*2+i+1001)
		accounts = append(accounts, GoAccount{UserId: []byte("foo"), Balance: GoBalance{Bitcoin: btcCount, Ethereum: ethCount}})
		assetSum = GoBalance{Bitcoin: assetSum.Bitcoin + btcCount, Ethereum: assetSum.Ethereum + ethCount}
	}
	merkleRoot = goComputeMerkleRootFromAccounts(accounts)
	merkleRootWithAssetSumHash = goComputeMiMCHashForAccount(GoAccount{UserId: merkleRoot, Balance: assetSum})
	return accounts, assetSum, merkleRoot, merkleRootWithAssetSumHash
}
