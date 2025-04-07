package main

import (
	"github.com/consensys/gnark-crypto/ecc"
	mimcCrypto "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/hash/mimc"
	"math/big"
)

const TreeDepth = 10

var modBytes = len(ecc.BN254.ScalarField().Bytes())

type GoBalance struct {
	Bitcoin  uint64
	Ethereum uint64
}

type GoAccount struct {
	UserId  []byte
	Balance GoBalance
}

type Balance struct {
	Bitcoin  frontend.Variable
	Ethereum frontend.Variable
}

type Account struct {
	UserId  frontend.Variable
	Balance Balance
}

type Circuit struct {
	Accounts []Account `gnark:""`
	AssetSum Balance   `gnark:""`
	// right now we don't actually merkle it, we just sequentially hash it
	MerkleRoot                 frontend.Variable `gnark:",public"`
	MerkleRootWithAssetSumHash frontend.Variable `gnark:",public"`
}

func assertBalanceNonNegative(api frontend.API, balances Balance) {
	// TODO: don't manually enumerate
	api.AssertIsLessOrEqual(0, balances.Bitcoin)
	api.AssertIsLessOrEqual(0, balances.Ethereum)
}

func addBalance(api frontend.API, a, b Balance) Balance {
	return Balance{
		Bitcoin:  api.Add(a.Bitcoin, b.Bitcoin),
		Ethereum: api.Add(a.Ethereum, b.Ethereum),
	}
}

func hashBalance(hasher mimc.MiMC, balances Balance) (hash frontend.Variable) {
	hasher.Reset()
	// TODO: don't manually enumerate
	hasher.Write(balances.Bitcoin, balances.Ethereum)
	return hasher.Sum()
}

func hashAccount(hasher mimc.MiMC, account Account) (hash frontend.Variable) {
	hasher.Reset()
	hasher.Write(account.UserId, hashBalance(hasher, account.Balance))
	return hasher.Sum()
}

func computeMerkleRoot(api frontend.API, hasher mimc.MiMC, node frontend.Variable, proofs [TreeDepth]frontend.Variable, directions []frontend.Variable) (rootHash frontend.Variable) {
	for i := 0; i < len(proofs); i++ {
		proof := proofs[i]
		direction := directions[i]
		api.AssertIsBoolean(direction)
		// maybe swapped
		left, right := api.Select(direction, proof, node), api.Select(direction, node, proof)
		hasher.Reset()
		hasher.Write(left, right)
		node = hasher.Sum()
	}
	return node
}

func powOfTwo(n int) (result int) {
	result = 1
	for i := 0; i < n; i++ {
		result *= 2
	}
	return result
}

func computeMerkleRootFromAccounts(api frontend.API, hasher mimc.MiMC, accounts []Account) (rootHash frontend.Variable) {
	nodes := make([]frontend.Variable, powOfTwo(TreeDepth))
	for i := 0; i < powOfTwo(TreeDepth); i++ {
		if i < len(accounts) {
			nodes[i] = hashAccount(hasher, accounts[i])
		} else {
			nodes[i] = 0
		}
	}
	for i := TreeDepth - 1; i >= 0; i-- {
		for j := 0; j < powOfTwo(i); j++ {
			hasher.Reset()
			hasher.Write(nodes[j*2], nodes[j*2+1])
			nodes[j] = hasher.Sum()
		}
	}
	return nodes[0]
}

func generateDirectionsFromIndex(api frontend.API, index int) (directions []frontend.Variable) {
	return api.ToBinary(index, TreeDepth)
}

func assertBalancesAreEqual(api frontend.API, a, b Balance) {
	api.AssertIsEqual(a.Bitcoin, b.Bitcoin)
	api.AssertIsEqual(a.Ethereum, b.Ethereum)
}

func (circuit *Circuit) Define(api frontend.API) error {
	if len(circuit.Accounts) > powOfTwo(TreeDepth) {
		panic("number of accounts exceeds the maximum number of leaves in the Merkle tree")
	}
	var runningBalance = Balance{Bitcoin: 0, Ethereum: 0}
	hasher, err := mimc.NewMiMC(api)
	if err != nil {
		panic(err)
	}
	for i := 0; i < len(circuit.Accounts); i++ {
		account := circuit.Accounts[i]
		assertBalanceNonNegative(api, account.Balance)
		runningBalance = addBalance(api, runningBalance, account.Balance)
	}
	assertBalancesAreEqual(api, runningBalance, circuit.AssetSum)
	root := computeMerkleRootFromAccounts(api, hasher, circuit.Accounts)
	api.AssertIsEqual(root, circuit.MerkleRoot)
	rootWithSum := hashAccount(hasher, Account{UserId: circuit.MerkleRoot, Balance: circuit.AssetSum})
	api.AssertIsEqual(rootWithSum, circuit.MerkleRootWithAssetSumHash)
	return nil
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
	paddedValue = make([]byte, modBytes-len(value))
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
	nodes := make([][]byte, powOfTwo(TreeDepth))
	for i := 0; i < powOfTwo(TreeDepth); i++ {
		if i < len(accounts) {
			nodes[i] = goComputeMiMCHashForAccount(accounts[i])
		} else {
			nodes[i] = padToModBytes([]byte{})
		}
	}
	for i := TreeDepth - 1; i >= 0; i-- {
		for j := 0; j < powOfTwo(i); j++ {
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

func convertGoBalanceToBalance(goBalance GoBalance) Balance {
	return Balance{
		Bitcoin:  new(big.Int).SetUint64(goBalance.Bitcoin),
		Ethereum: new(big.Int).SetUint64(goBalance.Ethereum),
	}
}

func convertGoAccountToAccount(goAccount GoAccount) Account {
	return Account{
		UserId:  new(big.Int).SetBytes(goAccount.UserId),
		Balance: convertGoBalanceToBalance(goAccount.Balance),
	}
}

func convertGoAccountsToAccounts(goAccounts []GoAccount) (accounts []Account) {
	accounts = make([]Account, len(goAccounts))
	for i, goAccount := range goAccounts {
		accounts[i] = convertGoAccountToAccount(goAccount)
	}
	return accounts
}

func generateTestData(count int) (accounts []GoAccount, assetSum GoBalance, merkleRoot []byte, merkleRootWithAssetSumHash []byte) {
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

func main() {
	count := 1024
	circuit := &Circuit{
		Accounts: make([]Account, count),
	}
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		panic(err)
	}
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		panic(err)
	}
	goAccounts, assetSum, merkleRoot, merkleRootWithAssetSumHash := generateTestData(count)
	var witnessInput Circuit
	witnessInput.Accounts = convertGoAccountsToAccounts(goAccounts)
	witnessInput.MerkleRoot = merkleRoot
	witnessInput.AssetSum = convertGoBalanceToBalance(assetSum)
	witnessInput.MerkleRootWithAssetSumHash = merkleRootWithAssetSumHash
	witness, err := frontend.NewWitness(&witnessInput, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	publicWitness, err := witness.Public()
	if err != nil {
		panic(err)
	}
	proof, err := groth16.Prove(cs, pk, witness)
	if err != nil {
		panic(err)
	}
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		panic(err)
	} else {
		print("proof success")
	}
}
