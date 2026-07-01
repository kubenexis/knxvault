package cmd

import (
	"encoding/base64"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/kubenexis/knxvault/internal/crypto/shamir"
)

var (
	shamirShares    int
	shamirThreshold int
)

var sysInitShamirCmd = &cobra.Command{
	Use:   "init-shamir [base64-unseal-key]",
	Short: "Split an unseal key into Shamir shares (stdout only; never persisted)",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		secret, err := base64.StdEncoding.DecodeString(args[0])
		if err != nil {
			return fmt.Errorf("decode unseal key: %w", err)
		}
		shares, err := shamir.Split(secret, shamirShares, shamirThreshold)
		if err != nil {
			return err
		}
		for i, share := range shares {
			fmt.Printf("share_id=%d key=%s\n", i+1, base64.StdEncoding.EncodeToString(share))
		}
		return nil
	},
}

func init() {
	sysInitShamirCmd.Flags().IntVar(&shamirShares, "shares", 5, "Total number of shares")
	sysInitShamirCmd.Flags().IntVar(&shamirThreshold, "threshold", 3, "Shares required to unseal")
	sysCmd.AddCommand(sysInitShamirCmd)
}
