package main

import (
	"bitgo.com/proof_of_reserves/circuit"
	"bytes"
	"encoding/base64"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"strconv"
)

type PartialProof struct {
	pk groth16.ProvingKey
	vk groth16.VerifyingKey
	cs constraint.ConstraintSystem
}

var cachedProofs = make(map[int]PartialProof)

func generateProof(elements ProofElements) CompletedProof {
	proofLen := len(elements.Accounts)
	if _, ok := cachedProofs[proofLen]; !ok {
		var err error
		c := &circuit.Circuit{
			Accounts: make([]circuit.Account, len(elements.Accounts)),
		}
		cachedProof := PartialProof{}
		cachedProof.cs, err = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, c)
		if err != nil {
			panic(err)
		}
		cachedProof.pk, cachedProof.vk, err = groth16.Setup(cachedProof.cs)
		if err != nil {
			panic(err)
		}
		cachedProofs[proofLen] = cachedProof
	}
	cachedProof := cachedProofs[proofLen]
	var witnessInput circuit.Circuit
	witnessInput.Accounts = circuit.ConvertGoAccountsToAccounts(elements.Accounts)
	witnessInput.MerkleRoot = elements.MerkleRoot
	if elements.AssetSum == nil {
		panic("AssetSum is nil")
	}
	witnessInput.AssetSum = circuit.ConvertGoBalanceToBalance(*elements.AssetSum)
	witnessInput.MerkleRootWithAssetSumHash = elements.MerkleRootWithAssetSumHash
	witness, err := frontend.NewWitness(&witnessInput, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	proof, err := groth16.Prove(cachedProof.cs, cachedProof.pk, witness, backend.WithIcicleAcceleration())
	if err != nil {
		panic(err)
	}

	var completedProof CompletedProof
	b1 := bytes.Buffer{}
	_, err = proof.WriteTo(&b1)
	if err != nil {
		panic(err)
	}
	completedProof.Proof = base64.StdEncoding.EncodeToString(b1.Bytes())
	b2 := bytes.Buffer{}
	_, err = cachedProof.vk.WriteTo(&b2)
	if err != nil {
		panic(err)
	}
	completedProof.VK = base64.StdEncoding.EncodeToString(b2.Bytes())
	completedProof.AccountLeaves = computeAccountLeavesFromAccounts(elements.Accounts)
	completedProof.MerkleRoot = circuit.GoComputeMerkleRootFromAccounts(elements.Accounts)
	if elements.AssetSum == nil {
		panic("AssetSum is nil")
	}
	completedProof.AssetSum = elements.AssetSum
	completedProof.MerkleRootWithAssetSumHash = circuit.GoComputeMiMCHashForAccount(circuit.GoAccount{UserId: completedProof.MerkleRoot, Balance: *elements.AssetSum})
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
	proofElements := readDataFromFiles[ProofElements](batchCount, "out/secret/test_data_")
	bottomLevelProofs = generateProofs(proofElements)
	writeProofsToFiles(bottomLevelProofs, "out/public/test_proof_")

	// top level proof
	var topLevelProofElements ProofElements
	topLevelProofElements.Accounts = make([]circuit.GoAccount, len(proofElements))

	for i := 0; i < len(proofElements); i++ {
		if proofElements[i].AssetSum == nil {
			panic("AssetSum is nil")
		}
		topLevelProofElements.Accounts[i] = circuit.GoAccount{UserId: proofElements[i].MerkleRoot, Balance: *proofElements[i].AssetSum}
		if !bytes.Equal(proofElements[i].MerkleRootWithAssetSumHash, circuit.GoComputeMiMCHashForAccount(topLevelProofElements.Accounts[i])) {
			panic("Merkle root with asset sum hash does not match")
		}
	}
	topLevelProofElements.MerkleRoot = circuit.GoComputeMerkleRootFromAccounts(topLevelProofElements.Accounts)
	assetSum := circuit.SumGoAccountBalances(topLevelProofElements.Accounts)
	topLevelProofElements.AssetSum = &assetSum
	topLevelProofElements.MerkleRootWithAssetSumHash = circuit.GoComputeMiMCHashForAccount(circuit.GoAccount{UserId: topLevelProofElements.MerkleRoot, Balance: *topLevelProofElements.AssetSum})
	topLevelProof = generateProof(topLevelProofElements)
	writeProofsToFiles([]CompletedProof{topLevelProof}, "out/public/test_top_level_proof_")

	return bottomLevelProofs, topLevelProof
}
