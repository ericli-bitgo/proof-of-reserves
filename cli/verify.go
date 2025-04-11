package cli

import (
	"bitgo.com/proof_of_reserves/circuit"
	"fmt"
	"strconv"

	"bitgo.com/proof_of_reserves/core"
	"github.com/spf13/cobra"
)

var verifyCmd = &cobra.Command{
	Use:   "verify [BatchCount]",
	Short: "Verifies proofs using the public data in 'out/public/' and the user data in 'out/user/'",
	Long:  "Verifies proofs using the public data in 'out/public/' and the user data in 'out/user/'. This function takes 1 argument: the number of batches.",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		batchCount, err := strconv.Atoi(args[0])
		if err != nil {
			fmt.Println("Error parsing batchCount:", err)
			return
		}
		account := core.ReadDataFromFile[circuit.GoAccount]("out/user/test_account.json")
		core.Verify(batchCount, account)
		println("Verification succeeded!")
	},
}

func init() {
	rootCmd.AddCommand(verifyCmd)
}
