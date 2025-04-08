package circuit

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/test"
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
	goAccounts, goAssetSum, _, _ := GenerateTestData(count)
	c.Accounts = ConvertGoAccountsToAccounts(goAccounts)
	c.Accounts[0].Balance.Bitcoin = -1
	// fix the balance
	goAssetSum.Bitcoin -= 1 + goAccounts[0].Balance.Bitcoin
	c.AssetSum = ConvertGoBalanceToBalance(goAssetSum)
	merkleRoot := "21875610370320048097190280594176833536697223607785798369247081808956128461944"
	c.MerkleRoot = merkleRoot
	c.MerkleRootWithAssetSumHash = goComputeMiMCHashForAccount(GoAccount{[]byte(merkleRoot), goAssetSum})

	assert.ProverSucceeded(baseCircuit, &c, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))
}
