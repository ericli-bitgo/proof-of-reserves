package circuit

import (
	"github.com/consensys/gnark-crypto/ecc"
	mimcCrypto "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"math/big"
)

var ModBytes = len(ecc.BN254.ScalarField().Bytes())

type GoBalance struct {
	Bitcoin  big.Int
	Ethereum big.Int
}

type GoAccount struct {
	UserId  []byte
	Balance GoBalance
}

func goConvertBalanceToBytes(balance GoBalance) (value []byte) {
	value = make([]byte, 0)
	value = append(value, padToModBytes(balance.Bitcoin.Bytes())...)
	value = append(value, padToModBytes(balance.Ethereum.Bytes())...)

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
	nodes := make([][]byte, PowOfTwo(TreeDepth))
	for i := 0; i < PowOfTwo(TreeDepth); i++ {
		if i < len(accounts) {
			nodes[i] = goComputeMiMCHashForAccount(accounts[i])
		} else {
			nodes[i] = padToModBytes([]byte{})
		}
	}
	for i := TreeDepth - 1; i >= 0; i-- {
		for j := 0; j < PowOfTwo(i); j++ {
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

func ConvertGoBalanceToBalance(goBalance GoBalance) Balance {
	return Balance{
		Bitcoin:  goBalance.Bitcoin.Bytes(),
		Ethereum: goBalance.Ethereum.Bytes(),
	}
}

func convertGoAccountToAccount(goAccount GoAccount) Account {
	return Account{
		UserId:  new(big.Int).SetBytes(goAccount.UserId),
		Balance: ConvertGoBalanceToBalance(goAccount.Balance),
	}
}

func ConvertGoAccountsToAccounts(goAccounts []GoAccount) (accounts []Account) {
	accounts = make([]Account, len(goAccounts))
	for i, goAccount := range goAccounts {
		accounts[i] = convertGoAccountToAccount(goAccount)
	}
	return accounts
}

func SumGoAccountBalances(accounts []GoAccount) GoBalance {
	assetSum := GoBalance{Bitcoin: *big.NewInt(0), Ethereum: *big.NewInt(0)}
	for _, account := range accounts {
		assetSum.Bitcoin.Add(&assetSum.Bitcoin, &account.Balance.Bitcoin)
		assetSum.Ethereum.Add(&assetSum.Ethereum, &account.Balance.Ethereum)
	}
	return assetSum
}

func GenerateTestData(count int) (accounts []GoAccount, assetSum GoBalance, merkleRoot []byte, merkleRootWithAssetSumHash []byte) {
	for i := 0; i < count; i++ {
		btcCount, ethCount := int64(i+45*i+39), int64(i*2+i+1001)
		accounts = append(accounts, GoAccount{UserId: []byte("foo"), Balance: GoBalance{Bitcoin: *big.NewInt(btcCount), Ethereum: *big.NewInt(ethCount)}})
	}
	goAccountBalanceSum := SumGoAccountBalances(accounts)
	merkleRoot = goComputeMerkleRootFromAccounts(accounts)
	merkleRootWithAssetSumHash = goComputeMiMCHashForAccount(GoAccount{UserId: merkleRoot, Balance: goAccountBalanceSum})
	return accounts, goAccountBalanceSum, merkleRoot, merkleRootWithAssetSumHash
}
