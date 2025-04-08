package circuit

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/test"
	"math/big"
	"testing"
)

const count = 16

var baseCircuit = initBaseCircuit(count)

func initBaseCircuit(count int) *Circuit {
	return &Circuit{
		Accounts: make([]Account, count),
	}
}

func TestCircuitWorks(t *testing.T) {
	assert := test.NewAssert(t)

	var c Circuit
	goAccounts, goAssetSum, goMerkleRoot, goMerkleRootWithHash := GenerateTestData(count) // Generate test data for 128 accounts
	c.Accounts = ConvertGoAccountsToAccounts(goAccounts)
	c.AssetSum = ConvertGoBalanceToBalance(goAssetSum)
	c.MerkleRoot = goMerkleRoot
	c.MerkleRootWithAssetSumHash = goMerkleRootWithHash

	assert.ProverSucceeded(baseCircuit, &c, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))
}

func TestCircuitDoesNotAcceptNegativeAccounts(t *testing.T) {
	assert := test.NewAssert(t)

	var c Circuit
	goAccounts, _, _, _ := GenerateTestData(count)
	goAccounts[0].Balance.Bitcoin = *big.NewInt(-1)
	c.Accounts = ConvertGoAccountsToAccounts(goAccounts)
	goAssetSum := SumGoAccountBalancesIncludingNegatives(goAccounts)
	c.AssetSum = ConvertGoBalanceToBalance(goAssetSum)
	merkleRoot := goComputeMerkleRootFromAccounts(goAccounts)
	c.MerkleRoot = merkleRoot
	c.MerkleRootWithAssetSumHash = goComputeMiMCHashForAccount(GoAccount{merkleRoot, goAssetSum})

	assert.ProverSucceeded(baseCircuit, &c, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))
}
