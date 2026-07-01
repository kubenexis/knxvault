package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/kubenexis/knxvault/pkg/client"
)

var databaseCmd = &cobra.Command{
	Use:   "database",
	Short: "Dynamic database credentials",
}

var (
	dbTTL             int
	dbUsernamePrefix  string
	dbCreationSQL     []string
	dbRevocationSQL   []string
	dbExecutionMode   string
	dbAdminCredsPath  string
)

var databaseRolePutCmd = &cobra.Command{
	Use:   "role-put <name>",
	Short: "Create or update a database credentials role",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := apiClient().PutDatabaseRole(cmd.Context(), args[0], client.DatabaseRoleRequest{
			TTLSeconds:           dbTTL,
			UsernamePrefix:       dbUsernamePrefix,
			CreationStatements:   dbCreationSQL,
			RevocationStatements: dbRevocationSQL,
			ExecutionMode:        dbExecutionMode,
			AdminCredentialsPath: dbAdminCredsPath,
		}); err != nil {
			return err
		}
		fmt.Println("database role saved")
		return nil
	},
}

var databaseCredsCmd = &cobra.Command{
	Use:   "creds <role>",
	Short: "Generate short-lived database credentials",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		result, err := apiClient().GenerateDatabaseCreds(cmd.Context(), args[0])
		if err != nil {
			return err
		}
		out, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(out))
		return nil
	},
}

var databaseRevokeCmd = &cobra.Command{
	Use:   "revoke <lease-id>",
	Short: "Revoke a database lease",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		result, err := apiClient().RevokeDatabaseLease(cmd.Context(), args[0])
		if err != nil {
			return err
		}
		out, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(out))
		return nil
	},
}

func init() {
	databaseRolePutCmd.Flags().IntVar(&dbTTL, "ttl", 3600, "Lease TTL in seconds")
	databaseRolePutCmd.Flags().StringVar(&dbUsernamePrefix, "username-prefix", "v-", "Username prefix")
	databaseRolePutCmd.Flags().StringSliceVar(&dbCreationSQL, "creation-sql", nil, "Creation SQL statement (repeatable)")
	databaseRolePutCmd.Flags().StringSliceVar(&dbRevocationSQL, "revocation-sql", nil, "Revocation SQL statement (repeatable)")
	databaseRolePutCmd.Flags().StringVar(&dbExecutionMode, "execution-mode", "", "Execution mode (client|managed)")
	databaseRolePutCmd.Flags().StringVar(&dbAdminCredsPath, "admin-creds-path", "", "KV path for managed-mode admin credentials")

	databaseCmd.AddCommand(databaseRolePutCmd, databaseCredsCmd, databaseRevokeCmd)
	secretsCmd := &cobra.Command{Use: "secrets", Short: "Secrets engines"}
	secretsCmd.AddCommand(databaseCmd)
	rootCmd.AddCommand(secretsCmd)
}