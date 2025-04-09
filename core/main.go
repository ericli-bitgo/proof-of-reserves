package main

func main() {
	batchCount := 5
	GenerateData(batchCount)
	Prove(batchCount)
	proofElement := getDataFromFiles[ProofElements](1, "out/secret/test_data_")
	Verify(batchCount, proofElement[0].accounts[0])
}
