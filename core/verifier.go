package main

import (
	"bitgo.com/proof_of_reserves/circuit"
	"bytes"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
)

func verifyProof(proof CompletedProof) bool {
	// first, verify snark
	var publicCircuit circuit.Circuit
	publicCircuit.MerkleRoot = proof.MerkleRoot
	publicCircuit.MerkleRootWithAssetSumHash = proof.MerkleRootWithAssetSumHash
	publicWitness, err := frontend.NewWitness(&publicCircuit, ecc.BN254.ScalarField(), frontend.PublicOnly())
	err = groth16.Verify(proof.Proof, proof.VK, publicWitness)
	if err != nil {
		panic(err)
	}

	// next, verify the account leaves hash to the merkle root
	if !bytes.Equal(circuit.GoComputeMerkleRootFromHashes(proof.AccountLeaves), proof.MerkleRoot) {
		panic("account leaves do not hash to the merkle root")
	}
	return true
}

func verifyProofs(bottomLayerProofs []CompletedProof, topLayerProof CompletedProof) {
	// first, verify the proofs are valid
	for _, proof := range bottomLayerProofs {
		if !verifyProof(proof) {
			panic("bottom layer proof verification failed")
		}
	}
	if !verifyProof(topLayerProof) {
		panic("top layer proof verification failed")
	}

	// next, verify that the bottom layer proofs lead to the top layer proof
	bottomLayerHashes := make([]circuit.Hash, len(bottomLayerProofs))
	for i, proof := range bottomLayerProofs {
		bottomLayerHashes[i] = proof.MerkleRoot
	}
	if !bytes.Equal(circuit.GoComputeMerkleRootFromHashes(bottomLayerHashes), topLayerProof.MerkleRoot) {
		panic("top layer proof does not match bottom layer proofs")
	}
	if !bytes.Equal(circuit.GoComputeMiMCHashForAccount(circuit.GoAccount{UserId: topLayerProof.MerkleRoot, Balance: *topLayerProof.AssetSum}), topLayerProof.MerkleRootWithAssetSumHash) {
		panic("top layer hash with asset sum does not match published asset sum")
	}
}

func verifyInclusionInProof(accountHash circuit.Hash, bottomLayerProofs []CompletedProof) {
	for _, proof := range bottomLayerProofs {
		for _, leaf := range proof.AccountLeaves {
			if bytes.Equal(leaf, accountHash) {
				return
			}
		}
	}
	panic("account not found in any proof")
}

func Verify(batchCount int, account circuit.GoAccount) {
	bottomLevelProofs := getDataFromFiles[CompletedProof](batchCount, "out/public/test_proof_")
	topLevelProof := getDataFromFiles[CompletedProof](1, "out/public/test_top_level_proof_")[0]
	verifyProofs(bottomLevelProofs, topLevelProof)

	accountHash := circuit.GoComputeMiMCHashForAccount(account)
	verifyInclusionInProof(accountHash, bottomLevelProofs)
}
