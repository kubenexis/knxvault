package dto

// DatabaseRoleRequest configures a database credential role.
type DatabaseRoleRequest struct {
	TTLSeconds           int            `json:"ttl_seconds"`
	DefaultTTL           int            `json:"default_ttl,omitempty"`
	MaxTTL               int            `json:"max_ttl,omitempty"`
	Period               int            `json:"period,omitempty"`
	Renewable            *bool          `json:"renewable,omitempty"`
	MaxLeases            int            `json:"max_leases,omitempty"`
	UsernamePrefix       string         `json:"username_prefix"`
	DefaultUsername      string         `json:"default_username"`
	CreationStatements   []string       `json:"creation_statements"`
	RevocationStatements []string       `json:"revocation_statements"`
	ExecutionMode        string         `json:"execution_mode,omitempty"`
	AdminCredentialsPath string         `json:"admin_credentials_path,omitempty"`
	Config               map[string]any `json:"config"`
}

// DatabaseRoleResponse returns role configuration.
type DatabaseRoleResponse struct {
	Name                 string         `json:"name"`
	TTLSeconds           int            `json:"ttl_seconds"`
	DefaultTTL           int            `json:"default_ttl,omitempty"`
	MaxTTL               int            `json:"max_ttl,omitempty"`
	Period               int            `json:"period,omitempty"`
	Renewable            bool           `json:"renewable"`
	MaxLeases            int            `json:"max_leases,omitempty"`
	UsernamePrefix       string         `json:"username_prefix"`
	DefaultUsername      string         `json:"default_username"`
	CreationStatements   []string       `json:"creation_statements"`
	RevocationStatements []string       `json:"revocation_statements"`
	ExecutionMode        string         `json:"execution_mode,omitempty"`
	AdminCredentialsPath string         `json:"admin_credentials_path,omitempty"`
	Config               map[string]any `json:"config"`
}

// DatabaseCredsRequest configures credential generation.
type DatabaseCredsRequest struct {
	TTLSeconds int `json:"ttl_seconds"`
}

// DatabaseCredsResponse returns generated credentials.
type DatabaseCredsResponse struct {
	LeaseFields
	Username   string   `json:"username"`
	Password   string   `json:"password"`
	Role       string   `json:"role"`
	TTLSeconds int      `json:"ttl_seconds"`
	Statements []string `json:"creation_statements,omitempty"`
}

// DatabaseRenewRequest configures lease renewal.
type DatabaseRenewRequest struct {
	TTLSeconds int `json:"ttl_seconds"`
}

// DatabaseRevokeResponse returns client-mode revocation SQL (W36-19).
type DatabaseRevokeResponse struct {
	RevocationStatements []string `json:"revocation_statements"`
}
