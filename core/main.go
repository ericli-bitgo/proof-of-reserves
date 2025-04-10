package main

func main() {
	batchCount := 3
	GenerateData(batchCount)
	Prove(batchCount)
	proofElement := getDataFromFiles[ProofElements](1, "out/secret/test_data_")
	Verify(batchCount, proofElement[0].Accounts[0])
	print("Proof succeeded!")
}
