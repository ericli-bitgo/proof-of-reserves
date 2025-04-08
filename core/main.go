package main

import (
	"bitgo.com/proof_of_reserves/circuit"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func main() {
	count := 128
	c := &circuit.Circuit{
		Accounts: make([]circuit.Account, count),
	}
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, c)
	if err != nil {
		panic(err)
	}
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		panic(err)
	}
	goAccounts, assetSum, merkleRoot, merkleRootWithAssetSumHash := circuit.GenerateTestData(count)
	var witnessInput circuit.Circuit
	witnessInput.Accounts = circuit.ConvertGoAccountsToAccounts(goAccounts)
	witnessInput.MerkleRoot = merkleRoot
	witnessInput.AssetSum = circuit.ConvertGoBalanceToBalance(assetSum)
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
