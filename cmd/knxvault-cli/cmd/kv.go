package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// RedactedValue is the placeholder printed for secret values when --show-secrets is not set.
const RedactedValue = "[REDACTED]"

// RedactionHint is written to stderr after a redacted kv get so operators know how to reveal values.
const RedactionHint = "note: secret values redacted; use --show-secrets to reveal"

var showSecrets bool

var kvCmd = &cobra.Command{
	Use:   "kv",
	Short: "KV secret commands",
}

var kvGetCmd = &cobra.Command{
	Use:   "get <path>",
	Short: "Read a secret path (values redacted by default; use --show-secrets)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		resp, err := apiClient().KVGet(cmd.Context(), args[0])
		if err != nil {
			return err
		}
		if !showSecrets && resp.Data != nil {
			if len(resp.Data) > 0 {
				resp.Data = redactKVData(resp.Data)
				// Keep JSON on stdout valid; teach the default behavior on stderr.
				fmt.Fprintln(os.Stderr, RedactionHint)
			}
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

// redactKVData returns a copy of data with every value replaced by RedactedValue.
func redactKVData(data map[string]any) map[string]any {
	if data == nil {
		return nil
	}
	redacted := make(map[string]any, len(data))
	for key := range data {
		redacted[key] = RedactedValue
	}
	return redacted
}

func init() {
	kvGetCmd.Flags().BoolVar(&showSecrets, "show-secrets", false, "Print secret values (default: redacted)")
	kvCmd.AddCommand(kvGetCmd, kvPutCmd)
}
