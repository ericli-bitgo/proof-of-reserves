package main

import (
	"bitgo.com/proof_of_reserves/circuit"
	"encoding/json"
	"github.com/consensys/gnark/backend/groth16"
	"os"
	"strconv"
)

func writeJson(filePath string, data interface{}) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			panic(err)
		}
	}(file)

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(data)
}

func readJson(filePath string, data interface{}) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			panic(err)
		}
	}(file)

	decoder := json.NewDecoder(file)
	return decoder.Decode(data)
}

type ProofElements struct {
	Accounts                   []circuit.GoAccount
	AssetSum                   *circuit.GoBalance
	MerkleRoot                 []byte
	MerkleRootWithAssetSumHash []byte
}

type AccountLeaf = []byte

type CompletedProof struct {
	Proof                      groth16.Proof
	VK                         groth16.VerifyingKey
	AccountLeaves              []AccountLeaf
	MerkleRoot                 []byte
	MerkleRootWithAssetSumHash []byte
	AssetSum                   *circuit.GoBalance
}

func writeTestDataToFile(batchCount int, countPerBatch int) {
	for i := 0; i < batchCount; i++ {
		filePath := "out/secret/test_data_" + strconv.Itoa(i) + ".json"
		var secretData ProofElements
		var assetSum circuit.GoBalance
		secretData.Accounts, assetSum, secretData.MerkleRoot, secretData.MerkleRootWithAssetSumHash = circuit.GenerateTestData(countPerBatch)
		secretData.AssetSum = &assetSum
		err := writeJson(filePath, secretData)
		if err != nil {
			panic(err)
		}

		//filePath = "../out/public/test_data_" + string(rune(i)) + ".json"
		//var publicData PublicProofElements
		//_, _, publicData.MerkleRoot, publicData.MerkleRootWithAssetSumHash = circuit.GenerateTestData(countPerBatch)
		//err = writeJson(filePath, publicData)
		//if err != nil {
		//	panic(err)
		//}
	}
}

func readDataFromFile[D ProofElements | CompletedProof](filePath string) (D, error) {
	var data D
	err := readJson(filePath, &data)
	if err != nil {
		return data, err
	}
	return data, nil
}

func getDataFromFiles[D ProofElements | CompletedProof](batchCount int, prefix string) []D {
	proofElements := make([]D, batchCount)
	for i := 0; i < batchCount; i++ {
		file, err := readDataFromFile[D](prefix + strconv.Itoa(i) + ".json")
		if err != nil {
			panic(err)
		}
		proofElements[i] = file
	}
	return proofElements
}

func computeAccountLeavesFromAccounts(accounts []circuit.GoAccount) (accountLeaves []AccountLeaf) {
	accountLeaves = make([]AccountLeaf, len(accounts))
	for i, account := range accounts {
		accountLeaves[i] = circuit.GoComputeMiMCHashForAccount(account)
	}
	return accountLeaves
}
