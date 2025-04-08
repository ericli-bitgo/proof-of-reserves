package circuit

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

const TreeDepth = 10

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

func PowOfTwo(n int) (result int) {
	result = 1
	for i := 0; i < n; i++ {
		result *= 2
	}
	return result
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

func computeMerkleRootFromAccounts(api frontend.API, hasher mimc.MiMC, accounts []Account) (rootHash frontend.Variable) {
	nodes := make([]frontend.Variable, PowOfTwo(TreeDepth))
	for i := 0; i < PowOfTwo(TreeDepth); i++ {
		if i < len(accounts) {
			nodes[i] = hashAccount(hasher, accounts[i])
		} else {
			nodes[i] = 0
		}
	}
	for i := TreeDepth - 1; i >= 0; i-- {
		for j := 0; j < PowOfTwo(i); j++ {
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
	if len(circuit.Accounts) > PowOfTwo(TreeDepth) {
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
