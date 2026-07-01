package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
)

var sysCmd = &cobra.Command{
	Use:   "sys",
	Short: "System administration commands",
}

var sysRotateMasterKeyCmd = &cobra.Command{
	Use:   "rotate-master-key [base64-key]",
	Short: "Rotate the envelope master key",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		resp, err := apiClient().RotateMasterKey(args[0])
		if err != nil {
			return err
		}
		out, _ := json.MarshalIndent(resp, "", "  ")
		fmt.Println(string(out))
		return nil
	},
}

var sysSealCmd = &cobra.Command{
	Use:   "seal",
	Short: "Seal the vault (block mutating operations)",
	RunE: func(_ *cobra.Command, _ []string) error {
		resp, err := apiClient().Seal()
		if err != nil {
			return err
		}
		out, _ := json.MarshalIndent(resp, "", "  ")
		fmt.Println(string(out))
		return nil
	},
}

var sysUnsealCmd = &cobra.Command{
	Use:   "unseal [base64-key]",
	Short: "Unseal the vault",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		resp, err := apiClient().Unseal(args[0])
		if err != nil {
			return err
		}
		out, _ := json.MarshalIndent(resp, "", "  ")
		fmt.Println(string(out))
		return nil
	},
}

func init() {
	sysCmd.AddCommand(sysRotateMasterKeyCmd)
	sysCmd.AddCommand(sysSealCmd)
	sysCmd.AddCommand(sysUnsealCmd)
	rootCmd.AddCommand(sysCmd)
}
