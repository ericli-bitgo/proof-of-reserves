package main

import (
	"bitgo.com/proof_of_reserves/circuit"
	"bytes"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"strconv"
)

func generateProof(elements ProofElements) CompletedProof {
	c := &circuit.Circuit{
		Accounts: make([]circuit.Account, len(elements.accounts)),
	}
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, c)
	if err != nil {
		panic(err)
	}
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		panic(err)
	}
	var witnessInput circuit.Circuit
	witnessInput.Accounts = circuit.ConvertGoAccountsToAccounts(elements.accounts)
	witnessInput.MerkleRoot = elements.merkleRoot
	witnessInput.AssetSum = circuit.ConvertGoBalanceToBalance(elements.assetSum)
	witnessInput.MerkleRootWithAssetSumHash = elements.merkleRootWithAssetSumHash
	witness, err := frontend.NewWitness(&witnessInput, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	proof, err := groth16.Prove(cs, pk, witness)
	if err != nil {
		panic(err)
	}

	var completedProof CompletedProof
	completedProof.Proof = proof
	completedProof.VK = vk
	completedProof.AccountLeaves = computeAccountLeavesFromAccounts(elements.accounts)
	completedProof.MerkleRoot = circuit.GoComputeMerkleRootFromAccounts(elements.accounts)
	completedProof.MerkleRootWithAssetSumHash = circuit.GoComputeMiMCHashForAccount(circuit.GoAccount{UserId: completedProof.MerkleRoot, Balance: elements.assetSum})
	return completedProof
}

func generateProofs(proofElements []ProofElements) []CompletedProof {
	completedProofs := make([]CompletedProof, len(proofElements))
	for i := 0; i < len(proofElements); i++ {
		completedProofs[i] = generateProof(proofElements[i])
	}
	return completedProofs
}

func writeProofsToFiles(proofs []CompletedProof, prefix string) {
	for i, proof := range proofs {
		filePath := prefix + strconv.Itoa(i) + ".json"
		err := writeJson(filePath, proof)
		if err != nil {
			panic(err)
		}
	}
}

func Prove(batchCount int) (bottomLevelProofs []CompletedProof, topLevelProof CompletedProof) {
	// low level proofs
	proofElements := getDataFromFiles[ProofElements](batchCount, "out/secret/test_data_")
	bottomLevelProofs = generateProofs(proofElements)
	writeProofsToFiles(bottomLevelProofs, "out/public/test_proof_")

	// top level proof
	var topLevelProofElements ProofElements
	topLevelProofElements.accounts = make([]circuit.GoAccount, len(proofElements))

	for i := 0; i < len(proofElements); i++ {
		topLevelProofElements.accounts[i] = circuit.GoAccount{UserId: proofElements[i].merkleRoot, Balance: proofElements[i].assetSum}
		if !bytes.Equal(proofElements[i].merkleRootWithAssetSumHash, circuit.GoComputeMiMCHashForAccount(topLevelProofElements.accounts[i])) {
			panic("Merkle root with asset sum hash does not match")
		}
	}
	topLevelProofElements.merkleRoot = circuit.GoComputeMerkleRootFromAccounts(topLevelProofElements.accounts)
	topLevelProofElements.assetSum = circuit.SumGoAccountBalances(topLevelProofElements.accounts)
	topLevelProofElements.merkleRootWithAssetSumHash = circuit.GoComputeMiMCHashForAccount(circuit.GoAccount{UserId: topLevelProofElements.merkleRoot, Balance: topLevelProofElements.assetSum})
	topLevelProof = generateProof(topLevelProofElements)
	writeProofsToFiles([]CompletedProof{topLevelProof}, "out/public/test_top_level_proof_")

	return bottomLevelProofs, topLevelProof
}
