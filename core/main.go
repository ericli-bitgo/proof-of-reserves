package main

import "bitgo.com/proof_of_reserves/circuit"

func main() {
	batchCount := 3
	GenerateData(batchCount)
	Prove(batchCount)
	account, err := readDataFromFile[circuit.GoAccount]("out/secret/test_account.json")
	if err != nil {
		panic(err)
	}
	Verify(batchCount, account)
	print("Proof succeeded!")
}
