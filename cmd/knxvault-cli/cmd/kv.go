package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var showSecrets bool

var kvCmd = &cobra.Command{
	Use:   "kv",
	Short: "KV secret commands",
}

var kvGetCmd = &cobra.Command{
	Use:   "get <path>",
	Short: "Read a secret path",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		resp, err := apiClient().KVGet(cmd.Context(), args[0])
		if err != nil {
			return err
		}
		if !showSecrets && resp.Data != nil {
			redacted := make(map[string]any, len(resp.Data))
			for key := range resp.Data {
				redacted[key] = "[REDACTED]"
			}
			resp.Data = redacted
		}
		return encodeJSON(os.Stdout, resp)
	},
}

var kvPutCmd = &cobra.Command{
	Use:   "put <path> <key=value>...",
	Short: "Write a secret path",
	Args:  cobra.MinimumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		data := make(map[string]any)
		for _, pair := range args[1:] {
			key, value, ok := strings.Cut(pair, "=")
			if !ok {
				return fmt.Errorf("invalid pair %q, expected key=value", pair)
			}
			data[key] = value
		}
		return apiClient().KVPut(cmd.Context(), args[0], data)
	},
}

func init() {
	kvGetCmd.Flags().BoolVar(&showSecrets, "show-secrets", false, "Print secret values (default: redacted)")
	kvCmd.AddCommand(kvGetCmd, kvPutCmd)
}