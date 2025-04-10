package main

import "bitgo.com/proof_of_reserves/circuit"

func main() {
	batchCount := 3
	GenerateData(batchCount)
	Prove(batchCount)
	account := readDataFromFile[circuit.GoAccount]("out/secret/test_account.json")
	Verify(batchCount, account)
	print("Proof succeeded!")
}
